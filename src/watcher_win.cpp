// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#ifdef _WIN32
// Windows backend: one overlapped ReadDirectoryChangesW on the root (bWatchSubtree), own thread.
#include <windows.h>

#include <atomic>
#include <filesystem>
#include <thread>
#include <vector>

#include "mysync/util.h"
#include "watcher_backend.h"

namespace fs = std::filesystem;

namespace mysync::detail {
namespace {

constexpr size_t kBufDwords = 64 * 1024;  // 256 KiB (DWORD-aligned as the API requires)

std::string wide_to_utf8(const wchar_t* w, size_t n) {
    if (n == 0) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(n), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(n), s.data(), len, nullptr, nullptr);
    return s;
}

class WinBackend final : public WatchBackend {
public:
    WinBackend(WatcherOptions opt, BackendSink sink) : opt_(std::move(opt)), sink_(std::move(sink)) {
        root_ = fs::u8path(opt_.root_utf8);
    }
    ~WinBackend() override { stop(); }

    void start() override {
        if (th_.joinable()) return;
        dir_ = open_dir();
        if (dir_ == INVALID_HANDLE_VALUE)
            throw Error("cannot watch directory: " + opt_.root_utf8 + " (Windows error " +
                        std::to_string(GetLastError()) + ")");
        stop_ev_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        io_ev_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_ev_ || !io_ev_) {
            cleanup();
            throw Error("CreateEvent failed (Windows error " + std::to_string(GetLastError()) + ")");
        }
        th_ = std::thread([this] { run(); });
    }

    void stop() override {
        if (stop_ev_) SetEvent(stop_ev_);
        if (th_.joinable()) th_.join();
        cleanup();
    }

private:
    HANDLE open_dir() const {
        return CreateFileW(root_.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    }

    void cleanup() {
        if (dir_ != INVALID_HANDLE_VALUE) { CloseHandle(dir_); dir_ = INVALID_HANDLE_VALUE; }
        if (stop_ev_) { CloseHandle(stop_ev_); stop_ev_ = nullptr; }
        if (io_ev_) { CloseHandle(io_ev_); io_ev_ = nullptr; }
    }

    void emit(WatchEvent::Kind k, std::string rel, std::string from, bool is_dir) {
        RawEvent ev;
        ev.kind = k;
        ev.rel = std::move(rel);
        ev.rel_from = std::move(from);
        ev.is_dir = is_dir;
        sink_.push(std::move(ev));
    }

    bool path_is_dir(const std::string& rel) const {
        DWORD a = GetFileAttributesW((root_ / fs::u8path(rel)).c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    }

    // Returns true if the wait was interrupted by stop.
    bool sleep_or_stop(DWORD ms) { return WaitForSingleObject(stop_ev_, ms) == WAIT_OBJECT_0; }

    void parse(const BYTE* buf, DWORD total) {
        std::string old_name;
        bool have_old = false;
        DWORD off = 0;
        while (off < total) {
            auto* fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buf + off);
            std::string rel = wide_to_utf8(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
            for (char& c : rel) if (c == '\\') c = '/';
            switch (fni->Action) {
            case FILE_ACTION_ADDED:
                emit(WatchEvent::Modified, rel, "", path_is_dir(rel));
                break;
            case FILE_ACTION_REMOVED:
                emit(WatchEvent::Deleted, rel, "", false);  // kind of object is unknowable once gone
                break;
            case FILE_ACTION_MODIFIED:
                if (!path_is_dir(rel)) emit(WatchEvent::Modified, rel, "", false);  // dir mtime noise dropped
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
                if (have_old) emit(WatchEvent::Deleted, old_name, "", false);
                old_name = rel;
                have_old = true;
                break;
            case FILE_ACTION_RENAMED_NEW_NAME: {
                bool d = path_is_dir(rel);
                if (have_old) emit(WatchEvent::Renamed, rel, old_name, d);
                else emit(WatchEvent::Modified, rel, "", d);
                have_old = false;
                break;
            }
            default:
                break;
            }
            if (fni->NextEntryOffset == 0) break;
            off += fni->NextEntryOffset;
        }
        if (have_old) emit(WatchEvent::Deleted, old_name, "", false);  // moved out of the tree
    }

    void run() {
        std::vector<DWORD> buf(kBufDwords);
        const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                             FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION;
        for (;;) {
            if (dir_ == INVALID_HANDLE_VALUE) {  // lost the directory: retry until it is back
                if (sleep_or_stop(2000)) return;
                dir_ = open_dir();
                if (dir_ == INVALID_HANDLE_VALUE) continue;
                emit(WatchEvent::Overflow, "", "", false);
            }
            OVERLAPPED ov{};
            ov.hEvent = io_ev_;
            ResetEvent(io_ev_);
            if (!ReadDirectoryChangesW(dir_, buf.data(), static_cast<DWORD>(buf.size() * sizeof(DWORD)),
                                       opt_.recursive ? TRUE : FALSE, filter, nullptr, &ov, nullptr)) {
                DWORD e = GetLastError();
                log_error("watcher: ReadDirectoryChangesW failed (Windows error " + std::to_string(e) + ")");
                CloseHandle(dir_);
                dir_ = INVALID_HANDLE_VALUE;
                continue;
            }
            HANDLE hs[2] = {stop_ev_, io_ev_};
            DWORD w = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
            if (w != WAIT_OBJECT_0 + 1) {  // stop (or wait failure): cancel and drain before buf goes away
                CancelIoEx(dir_, &ov);
                DWORD n = 0;
                GetOverlappedResult(dir_, &ov, &n, TRUE);
                return;
            }
            DWORD n = 0;
            if (!GetOverlappedResult(dir_, &ov, &n, FALSE)) {
                DWORD e = GetLastError();
                if (e == ERROR_NOTIFY_ENUM_DIR) {
                    emit(WatchEvent::Overflow, "", "", false);
                    continue;
                }
                if (e == ERROR_OPERATION_ABORTED) continue;
                log_error("watcher: directory watch failed (Windows error " + std::to_string(e) + "), reopening");
                CloseHandle(dir_);
                dir_ = INVALID_HANDLE_VALUE;
                continue;
            }
            if (n == 0) {  // kernel buffer overflowed: everything since the last read is lost
                emit(WatchEvent::Overflow, "", "", false);
                continue;
            }
            parse(reinterpret_cast<const BYTE*>(buf.data()), n);
        }
    }

    WatcherOptions opt_;
    BackendSink sink_;
    fs::path root_;
    HANDLE dir_ = INVALID_HANDLE_VALUE;
    HANDLE stop_ev_ = nullptr;
    HANDLE io_ev_ = nullptr;
    std::thread th_;
};

}  // namespace

std::unique_ptr<WatchBackend> make_watch_backend(const WatcherOptions& opt, BackendSink sink) {
    return std::make_unique<WinBackend>(opt, std::move(sink));
}

}  // namespace mysync::detail
#endif  // _WIN32
