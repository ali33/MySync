// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/localtarget.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <vector>

#include "fileio.h"
#include "fsutil.h"
#include "mysync/linkcheck.h"
#include "mysync/filter.h"
#include "mysync/hash.h"
#include "mysync/index.h"
#include "mysync/pathsafe.h"
#include "mysync/ratelimit.h"

namespace fs = std::filesystem;

namespace mysync {
namespace {

constexpr size_t kCopyBuf = 1024 * 1024;

// Destination hash cache, shared by every LocalTarget instance of one destination in this process.
struct DestState {
    std::mutex mu;
    IndexCache cache;
    std::string cache_file;  // empty = memory only
    bool dirty = false;
    bool loaded = false;
};

std::mutex g_reg_mu;
std::map<std::string, std::shared_ptr<DestState>>& registry() {
    static std::map<std::string, std::shared_ptr<DestState>> r;
    return r;
}

std::shared_ptr<DestState> get_state(const std::string& base_utf8, const std::string& state_dir) {
    std::lock_guard<std::mutex> lk(g_reg_mu);
    auto& slot = registry()[base_utf8];
    if (!slot) {
        slot = std::make_shared<DestState>();
        if (!state_dir.empty()) {
            Hash256 h = hash_bytes(base_utf8.data(), base_utf8.size());
            slot->cache_file = (fs::u8path(state_dir) / ("dest-" + hash_hex(h).substr(0, 16) + ".bin")).u8string();
        }
    }
    return slot;
}

std::string utc_stamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

class LocalTarget : public ITarget {
public:
    LocalTarget(const TargetConfig& cfg, std::shared_ptr<RateLimiter> lim, const std::string& state_dir)
        : cfg_(cfg), limiter_(std::move(lim)), state_dir_(state_dir) {
        // Links in any component of the destination root are not followed (checked at every connection of this target).
        std::string lr = link_refusal_text(cfg_.path);
        if (!lr.empty()) throw Error("destination " + lr);
        base_ = cfg_.path;
        if (!cfg_.remote_prefix.empty()) base_ = safe_join(cfg_.path, cfg_.remote_prefix).u8string();
        state_ = get_state(base_, state_dir_);
    }

    ~LocalTarget() override { try { close(); } catch (...) {} }

    void open() override {
        fs::path root = fs::u8path(cfg_.path);
        std::error_code ec;
        if (!fs::is_directory(root, ec)) {
            // Create only the last component: a missing parent usually means an unmounted drive / share.
            fs::path parent = root.parent_path();
            if (parent.empty() || !fs::is_directory(parent, ec))
                throw Error("destination unavailable: " + cfg_.path);
            fs::create_directory(root, ec);
            if (ec) throw Error("cannot create destination " + cfg_.path + ": " + ec.message());
        }
        fio::create_dirs(fs::u8path(base_), cfg_.dir_mode, ec);
        if (ec) throw Error("cannot create destination " + base_ + ": " + ec.message());
        std::lock_guard<std::mutex> lk(state_->mu);
        if (!state_->loaded) {
            if (!state_->cache_file.empty()) state_->cache.load(state_->cache_file);
            state_->loaded = true;
        }
    }

    void close() override { save_cache(); }

    PutResult put_file(const std::string& rel, const std::string& abs_src, const FileMeta& meta) override {
        PutResult r;
        fs::path tmp;
        // Removes the temp file on every way out that has not renamed it into place (tmp is cleared then):
        // the early returns after the temp file exists, and any exception.
        struct TmpGuard {
            fs::path& p;
            ~TmpGuard() {
                if (p.empty()) return;
                std::error_code ec;
                fs::remove(p, ec);
            }
        } tmp_guard{tmp};
        try {
            require_root();
            fs::path dest = safe_join(base_, rel);
            std::string key = normalize_rel(rel);
            fs::path src = fs::u8path(abs_src);
            fsutil::FsStat ss = fsutil::stat_path(src);
            if (!ss.ok || !ss.is_file) { r.error = "source missing or not a regular file"; return r; }
            if (ss.size != meta.size || ss.mtime_ns != meta.mtime_ns) { r.error = "source changed before copy"; return r; }

            fsutil::FsStat ds = fsutil::stat_path(dest);
            if (ds.ok && ds.is_dir) { r.error = "destination is a directory"; return r; }
            if (ds.ok && ds.is_file && ds.size == meta.size) {
                Hash256 dh = dest_hash(key, dest, ds);
                if (dh == meta.hash) {
                    if (ds.mtime_ns != meta.mtime_ns && fsutil::set_mtime_ns(dest, meta.mtime_ns)) ds.mtime_ns = meta.mtime_ns;
                    cache_put(key, ds, meta.hash);
                    r.status = PutResult::Skipped;
                    return r;
                }
            }

            std::error_code ec;
            fio::create_dirs(dest.parent_path(), cfg_.dir_mode, ec);
            if (ec) { r.error = "cannot create directory: " + ec.message(); return r; }
            uint8_t rnd[8];
            random_bytes(rnd, sizeof rnd);
            tmp = dest.parent_path() / fs::u8path(".mysync-tmp-" + to_hex(rnd, sizeof rnd));
#ifndef _WIN32
            {
                // Create the temp file private (0600) before ofstream opens it: no window with the default umask.
                int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (fd < 0) { r.error = "cannot create temp file in destination"; tmp.clear(); return r; }
                ::close(fd);
            }
#endif

            uint64_t total = 0;
            Hash256 got{};
            {
                std::ifstream in(src, std::ios::binary);
                if (!in) { r.error = "cannot open source"; return r; }
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out) { r.error = "cannot create temp file in destination"; return r; }
                Hasher hs;
                std::vector<char> buf(kCopyBuf);
                while (in) {
                    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
                    std::streamsize n = in.gcount();
                    if (n <= 0) break;
                    hs.update(buf.data(), static_cast<size_t>(n));
                    out.write(buf.data(), n);
                    if (!out) { out.close(); r.error = "write error in destination (disk full?)"; cleanup(tmp); tmp.clear(); return r; }
                    total += static_cast<uint64_t>(n);
                    if (limiter_) limiter_->acquire(static_cast<size_t>(n));
                }
                if (in.bad()) { out.close(); r.error = "read error on source"; cleanup(tmp); tmp.clear(); return r; }
                got = hs.finish();
                out.flush();
                if (!out) { out.close(); r.error = "write error in destination"; cleanup(tmp); tmp.clear(); return r; }
            }
            fsutil::FsStat s2 = fsutil::stat_path(src);
            if (total != meta.size || got != meta.hash || !s2.ok || s2.size != ss.size || s2.mtime_ns != ss.mtime_ns) {
                r.error = "source changed during copy";
                cleanup(tmp);
                tmp.clear();
                return r;
            }
            fsutil::fsync_path(tmp);
            fio::set_mode(tmp, cfg_.file_mode);
            fsutil::set_mtime_ns(tmp, meta.mtime_ns);
            // The previous content of an overwritten file goes to the trash first (rename, no copy).
            fs::path trashed;
            if (ds.ok && ds.is_file) trashed = move_to_trash(rel, dest);
            fs::rename(tmp, dest, ec);
            if (ec) {
                std::error_code e2;
                if (!trashed.empty()) fs::rename(trashed, dest, e2);  // put the old version back
                r.error = "rename failed: " + ec.message();
                cleanup(tmp);
                tmp.clear();
                return r;
            }
            tmp.clear();
            fsutil::FsStat fin = fsutil::stat_path(dest);
            if (fin.ok) cache_put(key, fin, meta.hash);
            r.status = PutResult::Sent;
            r.bytes_on_wire = total;
            return r;
        } catch (const Error& e) {
            if (!tmp.empty()) cleanup(tmp);
            if (!root_ok()) throw;
            r.error = e.what();
            return r;
        } catch (const std::exception& e) {
            if (!tmp.empty()) cleanup(tmp);
            r.error = e.what();
            return r;
        }
    }

    void remove_path(const std::string& rel, bool is_dir) override {
        require_root();
        fs::path p = safe_join(base_, rel);
        fsutil::FsStat st = fsutil::stat_path(p);
        if (!st.ok) return;
        move_to_trash(rel, p);
        std::string key = normalize_rel(rel);
        std::lock_guard<std::mutex> lk(state_->mu);
        state_->cache.erase(key);
        if (st.is_dir || is_dir) {
            std::string pre = key + "/";
            std::vector<std::string> gone;
            for (const auto& e : state_->cache.entries())
                if (e.first.compare(0, pre.size(), pre) == 0) gone.push_back(e.first);
            for (const auto& g : gone) state_->cache.erase(g);
        }
        state_->dirty = true;
    }

    // Moves `p` (the destination path of `rel`) to <dest>/__sync/__trash/<UTC timestamp>/<rel> by rename and returns
    // the new location. Throws Error.
    fs::path move_to_trash(const std::string& rel, const fs::path& p) {
        {   // a `__sync` (or `__trash`) that is a link would send the old data wherever it points
            for (const fs::path& q : {fs::u8path(base_) / "__sync", fs::u8path(base_) / "__sync" / "__trash"}) {
                fsutil::FsStat si = fsutil::stat_path(q);
                if (si.ok && (si.is_link || !si.is_dir)) throw Error("refusing the trash: '" + q.u8string() + "' is a link or not a folder");
            }
        }
        fs::path trash_root = fs::u8path(base_) / "__sync" / "__trash";
        fs::path stamp_dir = trash_root / fs::u8path(utc_stamp());
        std::error_code ec;
        for (int i = 2; fs::exists(stamp_dir, ec) && i < 1000; ++i)
            stamp_dir = trash_root / fs::u8path(utc_stamp() + "-" + std::to_string(i));
        fio::create_dirs(stamp_dir, cfg_.dir_mode, ec);
        if (ec) throw Error("cannot create trash directory: " + ec.message());
        fs::path to = safe_join(stamp_dir.u8string(), rel);
        fio::create_dirs(to.parent_path(), cfg_.dir_mode, ec);
        if (ec) throw Error("cannot create trash directory: " + ec.message());
        fs::rename(p, to, ec);
        if (ec) throw Error("cannot move to trash: " + ec.message());
        return to;
    }

    void rename_path(const std::string& from, const std::string& to) override {
        require_root();
        fs::path a = safe_join(base_, from);
        fs::path b = safe_join(base_, to);
        if (!fsutil::stat_path(a).ok) return;  // already gone: the engine re-sends `to` if needed
        std::error_code ec;
        fio::create_dirs(b.parent_path(), cfg_.dir_mode, ec);
        if (ec) throw Error("cannot create directory: " + ec.message());
        fs::rename(a, b, ec);
        if (ec) throw Error("rename failed: " + ec.message());
        std::lock_guard<std::mutex> lk(state_->mu);
        state_->cache.rename_prefix(normalize_rel(from), normalize_rel(to));
        state_->dirty = true;
    }

    void make_dir(const std::string& rel) override {
        require_root();
        fs::path p = safe_join(base_, rel);
        std::error_code ec;
        fio::create_dirs(p, cfg_.dir_mode, ec);
        if (ec) throw Error("cannot create directory: " + ec.message());
    }

    std::map<std::string, FileMeta> list_remote() override {
        require_root();
        std::map<std::string, FileMeta> out;
        {
            std::lock_guard<std::mutex> lk(state_->mu);
            std::vector<FileMeta> v = scan_tree(base_, Filter(), state_->cache, 0);
            for (auto& m : v) out.emplace(m.rel, std::move(m));
            state_->dirty = true;
        }
        save_cache();
        return out;
    }

    std::string description() const override { return "dir://" + cfg_.path; }

private:
    bool root_ok() const {
        std::error_code ec;
        return fs::is_directory(fs::u8path(base_), ec);
    }
    void require_root() const {
        if (!root_ok()) throw Error("destination unavailable: " + cfg_.path);
    }
    static void cleanup(const fs::path& p) {
        std::error_code ec;
        fs::remove(p, ec);
    }
    void save_cache() {
        std::lock_guard<std::mutex> lk(state_->mu);
        if (!state_->dirty || state_->cache_file.empty()) return;
        try {
            std::error_code ec;
            fs::create_directories(fs::u8path(state_->cache_file).parent_path(), ec);
            state_->cache.save(state_->cache_file);
            state_->dirty = false;
        } catch (const std::exception& e) {
            log_warn(std::string("cannot save destination index: ") + e.what());
        }
    }
    Hash256 dest_hash(const std::string& key, const fs::path& dest, const fsutil::FsStat& ds) {
        {
            std::lock_guard<std::mutex> lk(state_->mu);
            const FileMeta* c = state_->cache.find(key);
            if (c && !c->is_dir && c->size == ds.size && c->mtime_ns == ds.mtime_ns) return c->hash;
        }
        return hash_file(dest.u8string());
    }
    void cache_put(const std::string& key, const fsutil::FsStat& ds, const Hash256& h) {
        FileMeta m;
        m.rel = key;
        m.size = ds.size;
        m.mtime_ns = ds.mtime_ns;
        m.hash = h;
        std::lock_guard<std::mutex> lk(state_->mu);
        state_->cache.put(m);
        state_->dirty = true;
    }

    TargetConfig cfg_;
    std::shared_ptr<RateLimiter> limiter_;
    std::string state_dir_;
    std::string base_;
    std::shared_ptr<DestState> state_;
};

}  // namespace

std::unique_ptr<ITarget> make_local_target(const TargetConfig& cfg, std::shared_ptr<RateLimiter> limiter,
                                           const std::string& state_dir) {
    if (!cfg.is_local()) throw Error("make_local_target: target has no path");
    return std::unique_ptr<ITarget>(new LocalTarget(cfg, std::move(limiter), state_dir));
}

}  // namespace mysync
