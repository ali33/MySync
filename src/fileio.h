// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// fileio.h - internal helpers for server/nettarget: lstat-style stat, mtime setting, exclusive temp files.
// Not part of the public contract (lives in src/).
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "mysync/util.h"

namespace mysync::fio {

namespace fs = std::filesystem;

constexpr const char* kTmpPrefix = ".mysync-tmp-";

struct StatInfo {
    bool exists = false;
    bool is_dir = false;
    bool is_symlink = false;
    bool is_regular = false;
    uint64_t size = 0;
    int64_t mtime_ns = 0;  // unix epoch
};

inline StatInfo stat_path(const fs::path& p) {
    StatInfo si;
    std::error_code ec;
    fs::file_status st = fs::symlink_status(p, ec);
    if (ec || st.type() == fs::file_type::not_found) return si;
    si.exists = true;
    si.is_symlink = st.type() == fs::file_type::symlink;
    si.is_dir = st.type() == fs::file_type::directory;
    si.is_regular = st.type() == fs::file_type::regular;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) {
        si.size = (uint64_t(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
        uint64_t ft = (uint64_t(d.ftLastWriteTime.dwHighDateTime) << 32) | d.ftLastWriteTime.dwLowDateTime;
        si.mtime_ns = (static_cast<int64_t>(ft) - 116444736000000000LL) * 100;
    }
#else
    struct stat sb;
    if (::lstat(p.c_str(), &sb) == 0) {
        si.size = uint64_t(sb.st_size);
#ifdef __APPLE__
        si.mtime_ns = int64_t(sb.st_mtimespec.tv_sec) * 1000000000LL + sb.st_mtimespec.tv_nsec;
#else
        si.mtime_ns = int64_t(sb.st_mtim.tv_sec) * 1000000000LL + sb.st_mtim.tv_nsec;
#endif
    }
#endif
    return si;
}

// Returns false on failure (caller decides how serious that is).
inline bool set_mtime(const fs::path& p, int64_t mtime_ns) {
#ifdef _WIN32
    HANDLE h = CreateFileW(p.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint64_t ft = uint64_t(mtime_ns / 100 + 116444736000000000LL);
    FILETIME f;
    f.dwLowDateTime = DWORD(ft & 0xFFFFFFFFu);
    f.dwHighDateTime = DWORD(ft >> 32);
    BOOL ok = SetFileTime(h, nullptr, nullptr, &f);
    CloseHandle(h);
    return ok != 0;
#else
    struct timespec ts[2];
    ts[0].tv_sec = 0;
    ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = time_t(mtime_ns / 1000000000LL);
    ts[1].tv_nsec = long(mtime_ns % 1000000000LL);
    return ::utimensat(AT_FDCWD, p.c_str(), ts, 0) == 0;
#endif
}

// Exclusive temp file `.mysync-tmp-<rand>` in `dir`, owner-only permissions on POSIX. Removed on destruction
// unless release()d (after a successful rename).
class TmpFile {
public:
    TmpFile() = default;
    TmpFile(const TmpFile&) = delete;
    TmpFile& operator=(const TmpFile&) = delete;
    TmpFile(TmpFile&& o) noexcept { *this = std::move(o); }
    TmpFile& operator=(TmpFile&& o) noexcept {
        if (this != &o) {
            discard();
            path_ = std::move(o.path_);
            h_ = o.h_;
            o.h_ = kInvalid;
            owned_ = o.owned_;
            o.owned_ = false;
        }
        return *this;
    }
    ~TmpFile() { discard(); }

    static TmpFile create(const fs::path& dir) {
        for (int attempt = 0; attempt < 8; attempt++) {
            uint8_t r[8];
            random_bytes(r, sizeof r);
            TmpFile t;
            t.path_ = dir / (std::string(kTmpPrefix) + to_hex(r, sizeof r));
#ifdef _WIN32
            HANDLE h = CreateFileW(t.path_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                if (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS) continue;
                throw Error("cannot create temp file");
            }
            t.h_ = h;
#else
            int fd = ::open(t.path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd < 0) {
                if (errno == EEXIST) continue;
                throw Error("cannot create temp file");
            }
            t.h_ = fd;
#endif
            t.owned_ = true;
            return t;
        }
        throw Error("cannot create temp file");
    }

    bool open() const { return h_ != kInvalid; }
    const fs::path& path() const { return path_; }

    void write(const void* data, size_t n) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        while (n) {
#ifdef _WIN32
            DWORD w = 0;
            DWORD want = DWORD(n > (1u << 30) ? (1u << 30) : n);
            if (!WriteFile(h_, p, want, &w, nullptr) || w == 0) throw Error("write failed (disk full?)");
#else
            ssize_t w = ::write(h_, p, n);
            if (w < 0) {
                if (errno == EINTR) continue;
                throw Error("write failed (disk full?)");
            }
#endif
            p += size_t(w);
            n -= size_t(w);
        }
    }
    // Flushes data to stable storage, stamps the modification time (when mtime_ns >= 0, on the open handle so no
    // second open is needed) and closes the handle; the file stays on disk. Returns false if only the stamp failed.
    bool sync_and_close(int64_t mtime_ns = -1) {
        if (h_ == kInvalid) return true;
        bool stamped = true;
#ifdef _WIN32
        bool ok = FlushFileBuffers(h_) != 0;
        if (mtime_ns >= 0) {
            uint64_t ft = uint64_t(mtime_ns / 100 + 116444736000000000LL);
            FILETIME f;
            f.dwLowDateTime = DWORD(ft & 0xFFFFFFFFu);
            f.dwHighDateTime = DWORD(ft >> 32);
            stamped = SetFileTime(h_, nullptr, nullptr, &f) != 0;
        }
        CloseHandle(h_);
#else
        ::fchmod(h_, 0644);
        bool ok = ::fsync(h_) == 0;
        if (mtime_ns >= 0) {
            struct timespec ts[2];
            ts[0].tv_sec = 0;
            ts[0].tv_nsec = UTIME_OMIT;
            ts[1].tv_sec = time_t(mtime_ns / 1000000000LL);
            ts[1].tv_nsec = long(mtime_ns % 1000000000LL);
            stamped = ::futimens(h_, ts) == 0;
        }
        ::close(h_);
#endif
        h_ = kInvalid;
        if (!ok) throw Error("fsync failed");
        return stamped;
    }
    // The temp file now has its final name: do not delete it.
    void release() { owned_ = false; }
    void discard() {
        if (h_ != kInvalid) {
#ifdef _WIN32
            CloseHandle(h_);
#else
            ::close(h_);
#endif
            h_ = kInvalid;
        }
        if (owned_) {
            std::error_code ec;
            fs::remove(path_, ec);
            owned_ = false;
        }
    }

private:
#ifdef _WIN32
    using Handle = HANDLE;
    static inline const Handle kInvalid = INVALID_HANDLE_VALUE;
#else
    using Handle = int;
    static constexpr Handle kInvalid = -1;
#endif
    fs::path path_;
    Handle h_ = kInvalid;
    bool owned_ = false;
};

}  // namespace mysync::fio
