// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#ifdef __linux__
// Linux backend: inotify with recursive watches. Directory renames keep their watches (inotify follows
// inodes), so only the wd->path table is rewritten. Unpaired IN_MOVED_FROM is flushed as Deleted after
// a short grace period.
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <thread>
#include <unordered_map>
#include <vector>

#include "mysync/util.h"
#include "watcher_backend.h"

namespace fs = std::filesystem;

namespace mysync::detail {
namespace {

using Clock = std::chrono::steady_clock;

class LinuxBackend final : public WatchBackend {
public:
    LinuxBackend(WatcherOptions opt, BackendSink sink) : opt_(std::move(opt)), sink_(std::move(sink)) {
        root_ = fs::u8path(opt_.root_utf8);
    }
    ~LinuxBackend() override { stop(); }

    void start() override {
        if (th_.joinable()) return;
        std::error_code ec;
        if (!fs::is_directory(root_, ec)) throw Error("cannot watch directory (not a directory): " + opt_.root_utf8);
        ifd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (ifd_ < 0) throw Error(std::string("inotify_init1 failed: ") + std::strerror(errno));
        evfd_ = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (evfd_ < 0) {
            int e = errno;
            cleanup();
            throw Error(std::string("eventfd failed: ") + std::strerror(e));
        }
        int wd = add_watch("");
        if (wd < 0) {
            int e = errno;
            cleanup();
            throw Error(std::string("inotify_add_watch failed for ") + opt_.root_utf8 + ": " + std::strerror(e));
        }
        if (opt_.recursive) add_subdirs("");
        th_ = std::thread([this] { run(); });
    }

    void stop() override {
        if (evfd_ >= 0) {
            uint64_t one = 1;
            ssize_t r = ::write(evfd_, &one, sizeof one);
            (void)r;
        }
        if (th_.joinable()) th_.join();
        cleanup();
    }

private:
    void cleanup() {
        if (ifd_ >= 0) { ::close(ifd_); ifd_ = -1; }
        if (evfd_ >= 0) { ::close(evfd_); evfd_ = -1; }
        wd2rel_.clear();
    }

    void emit(WatchEvent::Kind k, std::string rel, std::string from, bool is_dir) {
        RawEvent ev;
        ev.kind = k;
        ev.rel = std::move(rel);
        ev.rel_from = std::move(from);
        ev.is_dir = is_dir;
        sink_.push(std::move(ev));
    }

    void note_no_space() {
        if (no_space_) return;
        no_space_ = true;
        log_warn("watcher: inotify watch limit reached (fs.inotify.max_user_watches); "
                 "new directories are no longer watched, falling back to periodic scans");
        sink_.degraded();
    }

    // Adds one watch; returns wd or -1 (errno set). ENOSPC flips the degraded mode.
    int add_watch(const std::string& rel) {
        if (no_space_) { errno = ENOSPC; return -1; }
        fs::path p = rel.empty() ? root_ : root_ / fs::u8path(rel);
        uint32_t mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
                        IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK;
        int wd = inotify_add_watch(ifd_, p.c_str(), mask);
        if (wd < 0) {
            if (errno == ENOSPC) note_no_space();
            return -1;
        }
        wd2rel_[wd] = rel;
        return wd;
    }

    // Watch every directory below rel (not following symlinks, honouring ignore()).
    void add_subdirs(const std::string& rel) {
        std::vector<std::string> stack{rel};
        while (!stack.empty() && !no_space_) {
            std::string cur = std::move(stack.back());
            stack.pop_back();
            std::error_code ec;
            fs::path dir = cur.empty() ? root_ : root_ / fs::u8path(cur);
            fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
            if (ec) continue;
            for (; it != end; it.increment(ec)) {
                if (ec) break;
                std::error_code ec2;
                fs::file_status st = it->symlink_status(ec2);
                if (ec2 || !fs::is_directory(st)) continue;
                std::string name = it->path().filename().u8string();
                std::string crel = cur.empty() ? name : cur + "/" + name;
                if (crel == "__sync" || (opt_.ignore && opt_.ignore(crel, true))) continue;
                if (add_watch(crel) < 0 && no_space_) return;
                stack.push_back(std::move(crel));
            }
        }
    }

    bool ignored_dir(const std::string& rel) const {
        if (rel == "__sync" || rel.rfind("__sync/", 0) == 0) return true;
        return opt_.ignore && opt_.ignore(rel, true);
    }

    void remove_tree(const std::string& rel) {
        std::string pre = rel + "/";
        for (auto it = wd2rel_.begin(); it != wd2rel_.end();) {
            if (it->second == rel || it->second.compare(0, pre.size(), pre) == 0) {
                inotify_rm_watch(ifd_, it->first);
                it = wd2rel_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void rename_tree(const std::string& from, const std::string& to) {
        std::string pre = from + "/";
        for (auto& kv : wd2rel_) {
            if (kv.second == from) kv.second = to;
            else if (kv.second.compare(0, pre.size(), pre) == 0) kv.second = to + "/" + kv.second.substr(pre.size());
        }
    }

    struct MovedFrom {
        std::string rel;
        bool is_dir;
        Clock::time_point at;
    };

    void flush_moved_from(bool all) {
        auto now = Clock::now();
        for (auto it = moved_from_.begin(); it != moved_from_.end();) {
            if (all || now - it->second.at >= std::chrono::milliseconds(20)) {
                if (it->second.is_dir) remove_tree(it->second.rel);  // left the tree: drop its watches
                emit(WatchEvent::Deleted, it->second.rel, "", it->second.is_dir);
                it = moved_from_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void handle(const inotify_event* ev) {
        if (ev->mask & IN_Q_OVERFLOW) {
            emit(WatchEvent::Overflow, "", "", false);
            return;
        }
        if (ev->mask & IN_IGNORED) {
            wd2rel_.erase(ev->wd);
            return;
        }
        auto dit = wd2rel_.find(ev->wd);
        if (dit == wd2rel_.end()) return;
        const std::string dirrel = dit->second;
        if (ev->len == 0 || ev->name[0] == '\0') {  // event on the watched directory itself
            if ((ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) && dirrel.empty()) {
                log_warn("watcher: watched root was removed or moved");
                emit(WatchEvent::Overflow, "", "", false);
            }
            return;
        }
        std::string name = ev->name;
        std::string rel = dirrel.empty() ? name : dirrel + "/" + name;
        bool is_dir = (ev->mask & IN_ISDIR) != 0;

        if (ev->mask & IN_CREATE) {
            if (is_dir) {
                if (opt_.recursive && !ignored_dir(rel)) {
                    add_watch(rel);
                    add_subdirs(rel);  // before the event goes out, so the rescan cannot race the watches
                }
                emit(WatchEvent::Modified, rel, "", true);
            } else {
                emit(WatchEvent::Modified, rel, "", false);
            }
        } else if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB)) {
            if (!is_dir) emit(WatchEvent::Modified, rel, "", false);
        } else if (ev->mask & IN_DELETE) {
            emit(WatchEvent::Deleted, rel, "", is_dir);
        } else if (ev->mask & IN_MOVED_FROM) {
            moved_from_[ev->cookie] = MovedFrom{rel, is_dir, Clock::now()};
        } else if (ev->mask & IN_MOVED_TO) {
            auto mf = moved_from_.find(ev->cookie);
            if (mf != moved_from_.end()) {
                std::string from = mf->second.rel;
                moved_from_.erase(mf);
                if (is_dir) rename_tree(from, rel);
                emit(WatchEvent::Renamed, rel, from, is_dir);
            } else if (is_dir) {  // moved in from outside the tree
                if (opt_.recursive && !ignored_dir(rel)) {
                    add_watch(rel);
                    add_subdirs(rel);
                }
                emit(WatchEvent::Modified, rel, "", true);
            } else {
                emit(WatchEvent::Modified, rel, "", false);
            }
        }
    }

    void run() {
        alignas(inotify_event) char buf[64 * 1024];
        for (;;) {
            pollfd fds[2] = {{ifd_, POLLIN, 0}, {evfd_, POLLIN, 0}};
            int timeout = moved_from_.empty() ? -1 : 20;
            int pr = ::poll(fds, 2, timeout);
            if (pr < 0) {
                if (errno == EINTR) continue;
                log_error(std::string("watcher: poll failed: ") + std::strerror(errno));
                emit(WatchEvent::Overflow, "", "", false);
                return;
            }
            if (fds[1].revents & POLLIN) { flush_moved_from(true); return; }
            if (fds[0].revents & POLLIN) {
                for (;;) {
                    ssize_t n = ::read(ifd_, buf, sizeof buf);
                    if (n <= 0) {
                        if (n < 0 && errno == EINTR) continue;
                        break;  // EAGAIN: drained
                    }
                    for (char* p = buf; p < buf + n;) {
                        auto* ev = reinterpret_cast<const inotify_event*>(p);
                        handle(ev);
                        p += sizeof(inotify_event) + ev->len;
                    }
                }
            }
            if (!moved_from_.empty()) flush_moved_from(false);
        }
    }

    WatcherOptions opt_;
    BackendSink sink_;
    fs::path root_;
    int ifd_ = -1;
    int evfd_ = -1;
    bool no_space_ = false;
    std::thread th_;
    std::unordered_map<int, std::string> wd2rel_;
    std::unordered_map<uint32_t, MovedFrom> moved_from_;
};

}  // namespace

std::unique_ptr<WatchBackend> make_watch_backend(const WatcherOptions& opt, BackendSink sink) {
    return std::make_unique<LinuxBackend>(opt, std::move(sink));
}

}  // namespace mysync::detail
#endif  // __linux__
