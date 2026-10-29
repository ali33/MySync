// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Debounce / batching core shared by the platform backends (watcher_win.cpp, watcher_linux.cpp).
#include "mysync/watcher.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#endif

#include "mysync/util.h"
#include "watcher_backend.h"

namespace fs = std::filesystem;

namespace mysync {
namespace {

using Clock = std::chrono::steady_clock;
using detail::RawEvent;

constexpr size_t kMaxPending = 100000;
constexpr auto kMaxLockedWait = std::chrono::seconds(30);
constexpr auto kLockedRetry = std::chrono::milliseconds(200);

enum class Probe { Ok, Locked, Gone };

}  // namespace

struct Watcher::Impl {
    struct Entry {
        WatchEvent::Kind kind = WatchEvent::Modified;
        std::string rel_from;
        bool is_dir = false;
        bool also_mod = false;  // Renamed whose destination was also written
        bool locked = false;
        bool probed = false;  // a (size, mtime) signature from an earlier probe is stored
        int64_t psize = 0, pmtime = 0;
        Clock::time_point first{}, last{}, locked_since{}, retry_at{};
        uint64_t seq = 0;
    };

    WatcherOptions opt;
    BatchCallback cb;
    std::mutex mu;
    std::condition_variable cv;
    std::thread th;
    std::unique_ptr<detail::WatchBackend> backend;
    bool started = false;
    bool stopping = false;

    std::unordered_map<std::string, Entry> pending;
    std::vector<std::string> scan_dirs;
    bool overflow = false;
    Clock::time_point overflow_at{};
    bool periodic_flag = false;
    std::chrono::seconds period{0};
    Clock::time_point next_periodic{};
    uint64_t next_seq = 0;
    std::atomic<bool> stop_flag{false};

    Impl(WatcherOptions o, BatchCallback c) : opt(std::move(o)), cb(std::move(c)) {
        if (opt.quiet_ms < 0) opt.quiet_ms = 0;
        period = std::chrono::seconds(std::max(0, opt.periodic_scan_s));
    }

    // ---- filtering (no lock needed; opt is immutable after construction) ----
    bool is_ignored(const std::string& rel, bool is_dir) const {
        if (rel.empty()) return true;
        size_t pos = 0;
        while ((pos = rel.find('/', pos)) != std::string::npos) {
            std::string prefix = rel.substr(0, pos);
            if (prefix == "__sync") return true;
            if (opt.ignore && opt.ignore(prefix, true)) return true;
            ++pos;
        }
        if (rel == "__sync") return true;
        return opt.ignore && opt.ignore(rel, is_dir);
    }

    // Returns false when the event must be dropped. May rewrite a Renamed into Modified / Deleted when
    // only one side is ignored (e.g. "doc.tmp" -> "doc" is, for the consumer, a new/changed "doc").
    bool filter(RawEvent& ev) const {
        switch (ev.kind) {
        case WatchEvent::Overflow:
            return true;
        case WatchEvent::Renamed: {
            bool to_ign = is_ignored(ev.rel, ev.is_dir);
            bool from_ign = is_ignored(ev.rel_from, ev.is_dir);
            if (to_ign && from_ign) return false;
            if (to_ign) {
                ev.kind = WatchEvent::Deleted;
                ev.rel = ev.rel_from;
                ev.rel_from.clear();
                return true;
            }
            if (from_ign) {
                ev.kind = WatchEvent::Modified;
                ev.rel_from.clear();
            }
            return true;
        }
        default:
            return !is_ignored(ev.rel, ev.is_dir);
        }
    }

    // ---- state mutation (lock held) ----
    void mark_overflow(Clock::time_point now) {
        pending.clear();
        scan_dirs.clear();
        if (!overflow) overflow_at = now;
        overflow = true;
    }

    void apply_locked(RawEvent&& ev, Clock::time_point now, bool rescan) {
        switch (ev.kind) {
        case WatchEvent::Overflow:
            mark_overflow(now);
            return;
        case WatchEvent::Modified: {
            if (ev.is_dir && rescan) scan_dirs.push_back(ev.rel);
            auto it = pending.find(ev.rel);
            if (it == pending.end()) {
                Entry e;
                e.kind = WatchEvent::Modified;
                e.is_dir = ev.is_dir;
                e.first = e.last = now;
                e.seq = ++next_seq;
                pending.emplace(std::move(ev.rel), std::move(e));
            } else {
                Entry& e = it->second;
                if (e.kind == WatchEvent::Renamed) {
                    e.also_mod = true;
                } else if (e.kind == WatchEvent::Deleted) {
                    e.kind = WatchEvent::Modified;
                    e.first = now;
                    e.is_dir = ev.is_dir;
                }
                e.last = now;
                e.seq = ++next_seq;
                e.locked = false;
                e.probed = false;
                e.retry_at = Clock::time_point{};
            }
            break;
        }
        case WatchEvent::Deleted: {
            auto it = pending.find(ev.rel);
            if (it != pending.end() && it->second.kind == WatchEvent::Renamed) {
                // x renamed from w, then x deleted: both w and x are gone.
                Entry d;
                d.kind = WatchEvent::Deleted;
                d.is_dir = it->second.is_dir;
                d.first = d.last = now;
                d.seq = ++next_seq;
                pending[it->second.rel_from] = d;
                it = pending.find(ev.rel);
            }
            if (it == pending.end()) {
                Entry e;
                e.kind = WatchEvent::Deleted;
                e.is_dir = ev.is_dir;
                e.first = e.last = now;
                e.seq = ++next_seq;
                pending.emplace(std::move(ev.rel), std::move(e));
            } else {
                Entry& e = it->second;
                if (e.kind != WatchEvent::Deleted) e.first = now;
                e.kind = WatchEvent::Deleted;
                e.rel_from.clear();
                e.also_mod = false;
                e.last = now;
                e.seq = ++next_seq;
            }
            break;
        }
        case WatchEvent::Renamed: {
            if (ev.is_dir && rescan) scan_dirs.push_back(ev.rel);
            Entry e;
            e.is_dir = ev.is_dir;
            e.first = e.last = now;
            e.seq = ++next_seq;
            auto src = pending.find(ev.rel_from);
            if (src != pending.end()) {
                if (src->second.kind == WatchEvent::Renamed) {
                    // chain a->b->c collapses to a->c
                    e.kind = WatchEvent::Renamed;
                    e.rel_from = src->second.rel_from;
                    e.also_mod = src->second.also_mod;
                    e.first = src->second.first;
                    pending.erase(src);
                } else if (src->second.kind == WatchEvent::Modified) {
                    // created/changed then moved before it settled: just a (new) file at the target
                    e.kind = WatchEvent::Modified;
                    pending.erase(src);
                } else {
                    e.kind = WatchEvent::Renamed;
                    e.rel_from = ev.rel_from;
                    pending.erase(src);
                }
            } else {
                e.kind = WatchEvent::Renamed;
                e.rel_from = ev.rel_from;
            }
            if (e.kind == WatchEvent::Renamed && ev.rel == e.rel_from) {
                // a->b->a
                break;
            }
            pending[ev.rel] = std::move(e);
            break;
        }
        }
        if (pending.size() > kMaxPending) {
            log_warn("watcher: more than 100000 pending changes, degrading to a full rescan request");
            mark_overflow(now);
        }
    }

    void push(RawEvent&& ev) {
        if (!filter(ev)) return;
        std::lock_guard<std::mutex> lk(mu);
        if (stopping) return;
        apply_locked(std::move(ev), Clock::now(), true);
        cv.notify_one();
    }

    void on_degraded() {
        std::lock_guard<std::mutex> lk(mu);
        if (period.count() == 0) period = std::chrono::seconds(300);
        else period = std::min(period, std::chrono::seconds(60));
        next_periodic = Clock::now() + period;
        log_warn("watcher: real-time watching is incomplete; relying on periodic rescans every " +
                 std::to_string(period.count()) + " s");
        apply_locked(RawEvent{WatchEvent::Overflow, "", "", false}, Clock::now(), false);
        cv.notify_one();
    }

    // ---- probes / scans (no lock) ----
    fs::path full_path(const std::string& rel) const {
        return fs::u8path(opt.root_utf8) / fs::u8path(rel);
    }

    // Opens the file for reading (share-all, so it only fails if someone holds it exclusively) and returns
    // a (size, mtime) signature taken from the handle. NTFS publishes directory-entry updates and change
    // notifications lazily while a writer keeps its handle open, so "no events for quiet_ms" alone does
    // not prove a file is finished; the signature is compared across two probes quiet_ms apart.
    Probe probe_file(const std::string& rel, int64_t& sig_size, int64_t& sig_mtime) const {
        fs::path p = full_path(rel);
        sig_size = sig_mtime = 0;
#ifdef _WIN32
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND || e == ERROR_INVALID_NAME) return Probe::Gone;
            return Probe::Locked;  // sharing/lock violation, access denied: retry, then give up after ~30 s
        }
        BY_HANDLE_FILE_INFORMATION info;
        if (GetFileInformationByHandle(h, &info)) {
            sig_size = static_cast<int64_t>((static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow);
            sig_mtime = static_cast<int64_t>((static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
                                             info.ftLastWriteTime.dwLowDateTime);
        }
        CloseHandle(h);
        return Probe::Ok;
#else
        int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0) {
            if (errno == ENOENT || errno == ENOTDIR) return Probe::Gone;
            return Probe::Ok;  // symlink / unreadable for permission reasons: report, the consumer decides
        }
        struct stat st;
        if (::fstat(fd, &st) == 0) {
            sig_size = static_cast<int64_t>(st.st_size);
            sig_mtime = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
        }
        ::close(fd);
        return Probe::Ok;
#endif
    }

    // Lists everything below rel (files and directories) so objects created before a watch attached
    // (or moved in from outside the tree) are not missed. Symlinks are not followed.
    void scan_dir(const std::string& rel, std::vector<RawEvent>& out) const {
        std::error_code ec;
        std::vector<std::pair<fs::path, std::string>> stack;
        stack.emplace_back(full_path(rel), rel);
        while (!stack.empty() && !stop_flag.load()) {
            auto [dir, drel] = std::move(stack.back());
            stack.pop_back();
            fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
            if (ec) { ec.clear(); continue; }
            for (; it != end && !stop_flag.load(); it.increment(ec)) {
                if (ec) break;
                std::string name = it->path().filename().u8string();
                std::string crel = drel + "/" + name;
                std::error_code ec2;
                fs::file_status st = it->symlink_status(ec2);
                if (ec2) continue;
                bool is_dir = fs::is_directory(st);
                if (!is_dir && !fs::is_regular_file(st)) continue;
                if (is_ignored(crel, is_dir)) continue;
                RawEvent ev;
                ev.kind = WatchEvent::Modified;
                ev.rel = crel;
                ev.is_dir = is_dir;
                out.push_back(std::move(ev));
                if (is_dir && opt.recursive) stack.emplace_back(it->path(), crel);
                if (out.size() > kMaxPending) return;
            }
            ec.clear();
        }
    }

    // ---- thread ----
    Clock::time_point ready_at(const Entry& e) const {
        auto quiet = std::chrono::milliseconds(opt.quiet_ms);
        auto base = e.kind == WatchEvent::Modified ? e.last : e.first;
        return std::max(base + quiet, e.retry_at);
    }

    void loop() {
        std::unique_lock<std::mutex> lk(mu);
        const auto quiet = std::chrono::milliseconds(opt.quiet_ms);
        while (!stopping) {
            auto now = Clock::now();
            if (period.count() > 0 && now >= next_periodic) {
                periodic_flag = true;
                next_periodic = now + period;
            }
            bool unlocked_work = false;

            if (!scan_dirs.empty()) {
                auto dirs = std::move(scan_dirs);
                scan_dirs.clear();
                lk.unlock();
                std::vector<RawEvent> found;
                for (auto& d : dirs) scan_dir(d, found);
                lk.lock();
                if (stopping) break;
                now = Clock::now();
                for (auto& ev : found) apply_locked(std::move(ev), now, false);
                unlocked_work = true;
            }

            now = Clock::now();
            Clock::time_point wake = now + std::chrono::milliseconds(1000);
            auto consider = [&](Clock::time_point t) { if (t < wake) wake = t; };
            if (period.count() > 0) consider(next_periodic);

            std::vector<WatchEvent> renamed, deleted, modified;
            struct ProbeReq { std::string rel; uint64_t seq; };
            std::vector<ProbeReq> probes;

            for (auto it = pending.begin(); it != pending.end();) {
                Entry& e = it->second;
                auto t = ready_at(e);
                if (now < t) { consider(t); ++it; continue; }
                switch (e.kind) {
                case WatchEvent::Deleted:
                    deleted.push_back({WatchEvent::Deleted, it->first, "", e.is_dir});
                    it = pending.erase(it);
                    break;
                case WatchEvent::Renamed:
                    renamed.push_back({WatchEvent::Renamed, it->first, e.rel_from, e.is_dir});
                    if (e.also_mod) {
                        e.kind = WatchEvent::Modified;
                        e.rel_from.clear();
                        e.also_mod = false;
                        consider(now);
                        ++it;
                    } else {
                        it = pending.erase(it);
                    }
                    break;
                case WatchEvent::Modified:
                    if (e.is_dir) {
                        std::error_code ec;
                        if (fs::is_directory(full_path(it->first), ec))
                            modified.push_back({WatchEvent::Modified, it->first, "", true});
                        else
                            deleted.push_back({WatchEvent::Deleted, it->first, "", true});
                        it = pending.erase(it);
                    } else {
                        probes.push_back({it->first, e.seq});
                        ++it;
                    }
                    break;
                default:
                    it = pending.erase(it);
                    break;
                }
            }

            if (!probes.empty()) {
                lk.unlock();
                std::vector<Probe> results;
                std::vector<std::pair<int64_t, int64_t>> sigs(probes.size());
                results.reserve(probes.size());
                for (size_t i = 0; i < probes.size(); ++i)
                    results.push_back(probe_file(probes[i].rel, sigs[i].first, sigs[i].second));
                lk.lock();
                if (stopping) break;
                auto now2 = Clock::now();
                for (size_t i = 0; i < probes.size(); ++i) {
                    auto it = pending.find(probes[i].rel);
                    if (it == pending.end() || it->second.seq != probes[i].seq) {
                        consider(now2 + quiet);  // changed while probing: its own timer applies
                        continue;
                    }
                    Entry& e = it->second;
                    if (results[i] == Probe::Ok) {
                        e.locked = false;
                        bool stable = opt.quiet_ms == 0 || (e.probed && e.psize == sigs[i].first && e.pmtime == sigs[i].second);
                        if (stable) {
                            modified.push_back({WatchEvent::Modified, it->first, "", false});
                            pending.erase(it);
                        } else {  // first look, or still changing: look again one quiet period later
                            e.probed = true;
                            e.psize = sigs[i].first;
                            e.pmtime = sigs[i].second;
                            e.retry_at = now2 + quiet;
                            consider(e.retry_at);
                        }
                    } else if (results[i] == Probe::Gone) {
                        deleted.push_back({WatchEvent::Deleted, it->first, "", false});
                        pending.erase(it);
                    } else {
                        if (!e.locked) { e.locked = true; e.locked_since = now2; }
                        if (now2 - e.locked_since >= kMaxLockedWait) {
                            log_warn("watcher: file still locked after 30 s, reporting anyway: " + it->first);
                            modified.push_back({WatchEvent::Modified, it->first, "", false});
                            pending.erase(it);
                        } else {
                            e.retry_at = now2 + kLockedRetry;
                            consider(e.retry_at);
                        }
                    }
                }
                unlocked_work = true;
            }

            std::vector<WatchEvent> batch;
            if (overflow && now >= overflow_at + quiet) {
                batch.push_back({WatchEvent::Overflow, "", "", false});
                overflow = false;
            } else if (overflow) {
                consider(overflow_at + quiet);
            }
            if (periodic_flag) {
                if (batch.empty()) batch.push_back({WatchEvent::Overflow, "", "", false});
                periodic_flag = false;
            }
            for (auto* v : {&renamed, &deleted, &modified})
                for (auto& e : *v) batch.push_back(std::move(e));

            if (!batch.empty()) {
                lk.unlock();
                try {
                    cb(std::move(batch));
                } catch (const std::exception& ex) {
                    log_error(std::string("watcher: batch callback threw: ") + ex.what());
                } catch (...) {
                    log_error("watcher: batch callback threw an unknown exception");
                }
                lk.lock();
                continue;
            }
            if (unlocked_work) continue;
            cv.wait_until(lk, wake);
        }
    }
};

Watcher::Watcher(WatcherOptions opt, BatchCallback on_batch)
    : p_(std::make_unique<Impl>(std::move(opt), std::move(on_batch))) {}

Watcher::~Watcher() {
    try { stop(); } catch (...) {}
}

void Watcher::start() {
    Impl& s = *p_;
    {
        std::lock_guard<std::mutex> lk(s.mu);
        if (s.started) return;
    }
    detail::BackendSink sink;
    sink.push = [&s](RawEvent&& ev) { s.push(std::move(ev)); };
    sink.degraded = [&s]() { s.on_degraded(); };
    auto backend = detail::make_watch_backend(s.opt, std::move(sink));
    backend->start();  // throws on failure; nothing else to undo
    {
        std::lock_guard<std::mutex> lk(s.mu);
        s.backend = std::move(backend);
        s.started = true;
        s.stopping = false;
        s.stop_flag = false;
        s.next_periodic = Clock::now() + s.period;
    }
    s.th = std::thread([&s] { s.loop(); });
}

void Watcher::stop() {
    Impl& s = *p_;
    std::unique_ptr<detail::WatchBackend> backend;
    {
        std::lock_guard<std::mutex> lk(s.mu);
        if (!s.started) return;
        s.started = false;
        backend = std::move(s.backend);
    }
    if (backend) backend->stop();  // no more pushes after this
    {
        std::lock_guard<std::mutex> lk(s.mu);
        s.stopping = true;
        s.stop_flag = true;
    }
    s.cv.notify_all();
    if (s.th.joinable()) {
        if (s.th.get_id() == std::this_thread::get_id()) s.th.detach();  // called from the callback: best effort
        else s.th.join();
    }
    std::lock_guard<std::mutex> lk(s.mu);
    s.pending.clear();
    s.scan_dirs.clear();
    s.overflow = false;
    s.periodic_flag = false;
}

}  // namespace mysync

#if !defined(_WIN32) && !defined(__linux__)
namespace mysync::detail {
std::unique_ptr<WatchBackend> make_watch_backend(const WatcherOptions&, BackendSink) {
    throw Error("file watching is not supported on this platform");
}
}  // namespace mysync::detail
#endif
