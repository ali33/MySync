// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/client_engine.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <thread>
#include <unordered_set>

#include "fsutil.h"
#include "mysync/filter.h"
#include "mysync/hash.h"
#include "mysync/index.h"
#include "mysync/keys.h"
#include "mysync/localtarget.h"
#include "mysync/nettarget.h"
#include "mysync/pathsafe.h"
#include "mysync/ratelimit.h"
#include "mysync/scheduler.h"
#include "mysync/target.h"
#include "mysync/watcher.h"

namespace fs = std::filesystem;

namespace mysync {
namespace {

using Clock = std::chrono::steady_clock;

constexpr uint64_t kSmallFile = 1024 * 1024;
constexpr size_t kMaxBatch = 32;
constexpr int kOnceMaxAttempts = 3;

std::string resolve_path(const std::string& dir, const std::string& p) {
    if (p.empty() || dir.empty()) return p;
    fs::path q = fs::u8path(p);
    if (q.is_absolute() || q.has_root_name() || q.has_root_directory()) return p;
    return (fs::u8path(dir) / q).u8string();
}

std::string fmt_bytes(uint64_t b) {
    char buf[48];
    if (b < 1024) std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(b));
    else if (b < 1024ull * 1024) std::snprintf(buf, sizeof buf, "%.1f KiB", b / 1024.0);
    else if (b < 1024ull * 1024 * 1024) std::snprintf(buf, sizeof buf, "%.1f MiB", b / 1048576.0);
    else std::snprintf(buf, sizeof buf, "%.2f GiB", b / 1073741824.0);
    return buf;
}

std::string base_name(const std::string& rel) {
    size_t p = rel.find_last_of('/');
    return p == std::string::npos ? rel : rel.substr(p + 1);
}

struct Counters {
    std::atomic<uint64_t> sent{0}, skipped{0}, failed{0}, gave_up{0}, deleted{0}, renamed{0}, bytes{0}, hashed{0}, reused{0};
    EngineStats load() const {
        EngineStats s;
        s.sent = sent; s.skipped = skipped; s.failed = failed; s.gave_up = gave_up; s.deleted = deleted;
        s.renamed = renamed; s.bytes = bytes; s.hashed = hashed; s.reused = reused;
        return s;
    }
};

std::mt19937_64& rng() {
    thread_local std::mt19937_64 g([] {
        uint64_t s = 0;
        try { random_bytes(&s, sizeof s); } catch (...) { s = static_cast<uint64_t>(now_unix_ns()); }
        return s;
    }());
    return g;
}

struct Snapshot {
    std::vector<FileMeta> files;
    ScanStats stats;
    Clock::time_point taken;
};

enum class Kind { Put, Delete, MkDir, Rename };

struct Op {
    Kind kind = Kind::Put;
    std::string rel;
    std::string from;  // Rename only
    bool is_dir = false;
    int attempts = 0;
    Clock::time_point not_before{};
    uint64_t gen = 0;
    bool inflight = false;
    bool redo = false;  // changed again while in flight
    Kind redo_kind = Kind::Put;
    bool redo_is_dir = false;
};

class TargetRunner;

// ---------------------------------------------------------------------------------------------- one [[watch]]
class WatchCtx {
public:
    WatchCtx(const WatchConfig& w, std::string root, std::string index_file, Counters& global)
        : w_(w), root_(std::move(root)), index_file_(std::move(index_file)), filter_(w.filter), global_(global) {
        cache_.load(index_file_);
    }
    ~WatchCtx() { stop(); }

    const WatchConfig& cfg() const { return w_; }
    const std::string& root() const { return root_; }
    const Filter& filter() const { return filter_; }
    const std::string& name() const { return w_.name; }
    void add_runner(TargetRunner* r) { runners_.push_back(r); }
    const std::vector<TargetRunner*>& runners() const { return runners_; }
    uint64_t hashed() const { return hashed_; }
    uint64_t reused() const { return reused_; }

    std::string abs_of(const std::string& rel) const { return (fs::u8path(root_) / fs::u8path(rel)).u8string(); }

    // Full scan, shared by the targets: a scan taken after `requested` is reused.
    std::shared_ptr<const Snapshot> snapshot(Clock::time_point requested) {
        std::lock_guard<std::mutex> sl(snap_mu_);
        if (snap_ && snap_->taken >= requested) return snap_;
        auto s = std::make_shared<Snapshot>();
        s->taken = Clock::now();
        {
            std::lock_guard<std::mutex> il(idx_mu_);
            s->files = scan_tree(root_, filter_, cache_, 0, &s->stats);
            save_index_locked();
        }
        hashed_ += s->stats.hashed;
        reused_ += s->stats.reused;
        global_.hashed += s->stats.hashed;
        global_.reused += s->stats.reused;
        snap_ = s;
        return snap_;
    }

    // Metadata (with hash) of a source file; reuses the index when size/mtime still match and the file is not racy.
    FileMeta meta_for(const std::string& rel, const std::string& abs, const fsutil::FsStat& st) {
        const int64_t racy = now_unix_ns() - 2000000000LL;
        {
            std::lock_guard<std::mutex> il(idx_mu_);
            const FileMeta* c = cache_.find(rel);
            if (c && !c->is_dir && c->size == st.size && c->mtime_ns == st.mtime_ns && st.mtime_ns < racy) {
                ++reused_;
                ++global_.reused;
                return *c;
            }
        }
        uint64_t sz = 0;
        Hash256 h = hash_file(abs, &sz);
        fsutil::FsStat s2 = fsutil::stat_path(fs::u8path(abs));
        if (!s2.ok || sz != st.size || s2.size != st.size || s2.mtime_ns != st.mtime_ns)
            throw Error("file changed while hashing");
        ++hashed_;
        ++global_.hashed;
        FileMeta m;
        m.rel = rel;
        m.size = st.size;
        m.mtime_ns = st.mtime_ns;
        m.hash = h;
        if (st.mtime_ns < racy) {
            std::lock_guard<std::mutex> il(idx_mu_);
            cache_.put(m);
        }
        return m;
    }

    void index_erase(const std::string& rel) {
        std::lock_guard<std::mutex> il(idx_mu_);
        cache_.erase(rel);
    }
    void index_rename(const std::string& from, const std::string& to) {
        std::lock_guard<std::mutex> il(idx_mu_);
        cache_.rename_prefix(from, to);
    }
    void save_index() {
        std::lock_guard<std::mutex> il(idx_mu_);
        save_index_locked();
    }

    // ---- event handling (defined after TargetRunner) ----
    void start_watching();
    bool watching() const { return watcher_ != nullptr; }
    void start_scheduler();
    void stop();
    void on_batch(std::vector<WatchEvent>&& batch);
    void handle_modified(const std::string& rel, bool is_dir, bool delayed);
    void enqueue_tree(const std::string& rel_dir, bool delayed);
    void request_all();

private:
    void save_index_locked() {
        try {
            std::error_code ec;
            fs::create_directories(fs::u8path(index_file_).parent_path(), ec);
            cache_.save(index_file_);
        } catch (const std::exception& e) {
            log_warn("[" + w_.name + "] cannot save the source index: " + e.what());
        }
    }

    WatchConfig w_;
    std::string root_;
    std::string index_file_;
    Filter filter_;
    Counters& global_;
    std::vector<TargetRunner*> runners_;

    std::mutex snap_mu_;
    std::shared_ptr<const Snapshot> snap_;
    std::mutex idx_mu_;
    IndexCache cache_;
    std::atomic<uint64_t> hashed_{0}, reused_{0};

    std::unique_ptr<Watcher> watcher_;
    std::unique_ptr<Scheduler> sched_;
};

// -------------------------------------------------------------------------------------- one (watch, target) pair
class TargetRunner {
public:
    using Factory = std::function<std::unique_ptr<ITarget>()>;

    TargetRunner(WatchCtx& watch, const TargetConfig& t, const ClientConfig& cc, Factory f, std::string label,
                 bool once, Counters& global)
        : watch_(watch), tcfg_(t), conns_(std::max<uint32_t>(1, cc.connections)),
          retry_min_(std::max<uint32_t>(1, cc.retry_min_ms)),
          retry_max_(std::max<uint32_t>(cc.retry_min_ms, cc.retry_max_ms)), factory_(std::move(f)),
          label_(std::move(label)), once_(once), global_(global) {}

    ~TargetRunner() { stop(); }

    const std::string& label() const { return label_; }
    EngineStats stats() const { return c_.load(); }

    void start(bool initial_reconcile) {
        if (initial_reconcile) request_reconcile();
        controller_ = std::thread([this] { controller_loop(); });
        for (uint32_t i = 0; i < conns_; ++i) workers_.emplace_back([this] { worker_loop(); });
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stopping_) return;
            stopping_ = true;
        }
        cv_.notify_all();
        if (controller_.joinable()) controller_.join();
        for (auto& t : workers_)
            if (t.joinable()) t.join();
        workers_.clear();
    }

    void request_reconcile() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            reconcile_req_ = true;
            reconcile_time_ = Clock::now();
        }
        cv_.notify_all();
    }

    void enqueue(Kind kind, const std::string& rel, bool is_dir, uint32_t delay_ms = 0) {
        std::lock_guard<std::mutex> lk(mu_);
        Op op;
        op.kind = kind;
        op.rel = rel;
        op.is_dir = is_dir;
        op.not_before = Clock::now() + std::chrono::milliseconds(delay_ms);
        enqueue_locked(op);
        cv_.notify_all();
    }

    void enqueue_rename(const std::string& from, const std::string& to) {
        std::lock_guard<std::mutex> lk(mu_);
        Op op;
        op.kind = Kind::Rename;
        op.from = from;
        op.rel = to;
        renames_.push_back(op);
        cv_.notify_all();
    }

    bool idle() {
        std::lock_guard<std::mutex> lk(mu_);
        return idle_locked();
    }
    bool finished() {  // idle or abandoned (once mode)
        std::lock_guard<std::mutex> lk(mu_);
        return gave_up_ || idle_locked();
    }

private:
    bool idle_locked() const {
        return reconcile_done_ && !reconcile_req_ && !reconciling_ && ops_.empty() && renames_.empty() && inflight_ == 0 &&
               !struct_busy_;
    }

    uint32_t backoff_ms(int n) {
        uint64_t v = static_cast<uint64_t>(retry_min_) << std::min(std::max(n, 0), 20);
        v = std::min<uint64_t>(v, retry_max_);
        std::uniform_int_distribution<uint64_t> d(v / 2, v);
        return static_cast<uint32_t>(d(rng()));
    }

    // Interruptible sleep. Returns false when stopping.
    bool sleep_ms(uint32_t ms) {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, std::chrono::milliseconds(ms), [&] { return stopping_; });
        return !stopping_;
    }

    // ---- queue (all *_locked need mu_) ----
    void push_key_locked(const std::string& key, uint64_t gen, Clock::time_point nb, bool front = false) {
        if (nb <= Clock::now()) {
            if (front) ready_.push_front({key, gen});
            else ready_.push_back({key, gen});
        } else {
            delayed_.emplace(nb, std::make_pair(key, gen));
        }
    }

    void enqueue_locked(const Op& in) {
        auto it = ops_.find(in.rel);
        if (it == ops_.end()) {
            Op op = in;
            op.gen = ++gen_;
            ops_[op.rel] = op;
            push_key_locked(op.rel, op.gen, op.not_before);
            return;
        }
        Op& cur = it->second;
        if (cur.inflight) {
            cur.redo = true;
            cur.redo_kind = in.kind;
            cur.redo_is_dir = in.is_dir;
            return;
        }
        cur.kind = in.kind;
        cur.is_dir = in.is_dir;
        cur.attempts = 0;
        cur.not_before = in.not_before;
        cur.gen = ++gen_;
        push_key_locked(cur.rel, cur.gen, cur.not_before);
    }

    void promote_delayed_locked() {
        auto now = Clock::now();
        while (!delayed_.empty() && delayed_.begin()->first <= now) {
            ready_.push_back(delayed_.begin()->second);
            delayed_.erase(delayed_.begin());
        }
    }

    bool take_ready_locked(Op& out, bool put_only) {
        promote_delayed_locked();
        while (!ready_.empty()) {
            auto key = ready_.front();
            auto it = ops_.find(key.first);
            if (it == ops_.end() || it->second.inflight || it->second.gen != key.second) {
                ready_.pop_front();
                continue;
            }
            if (put_only && it->second.kind != Kind::Put) return false;
            ready_.pop_front();
            it->second.inflight = true;
            ++inflight_;
            out = it->second;
            return true;
        }
        return false;
    }

    // Blocks for the next unit of work. Renames run alone (no put may be in flight or start meanwhile).
    bool next_batch(std::vector<Op>& batch) {
        std::unique_lock<std::mutex> lk(mu_);
        for (;;) {
            if (stopping_) return false;
            if (!renames_.empty()) {
                if (inflight_ == 0 && !struct_busy_) {
                    batch.push_back(renames_.front());
                    renames_.pop_front();
                    struct_busy_ = true;
                    return true;
                }
            } else if (!struct_busy_) {
                Op op;
                if (take_ready_locked(op, false)) {
                    batch.push_back(op);
                    break;
                }
            }
            auto wake = Clock::now() + std::chrono::seconds(1);
            if (!delayed_.empty()) wake = std::min(wake, delayed_.begin()->first);
            cv_.wait_until(lk, wake);
        }
        lk.unlock();
        // Group small files into one put_batch.
        if (batch[0].kind == Kind::Put && is_small(batch[0])) {
            while (batch.size() < kMaxBatch) {
                Op op;
                {
                    std::lock_guard<std::mutex> l2(mu_);
                    if (stopping_ || !renames_.empty() || !take_ready_locked(op, true)) break;
                }
                if (!is_small(op)) {
                    std::lock_guard<std::mutex> l2(mu_);
                    unpop_locked(op);
                    break;
                }
                batch.push_back(op);
            }
        }
        return true;
    }

    bool is_small(const Op& op) {
        fsutil::FsStat st = fsutil::stat_path(fs::u8path(watch_.abs_of(op.rel)));
        return !st.ok || st.size < kSmallFile;
    }

    void unpop_locked(const Op& op) {
        auto it = ops_.find(op.rel);
        if (it == ops_.end()) return;
        --inflight_;
        Op& cur = it->second;
        cur.inflight = false;
        if (cur.redo) {
            cur.redo = false;
            cur.kind = cur.redo_kind;
            cur.is_dir = cur.redo_is_dir;
            cur.attempts = 0;
        }
        cur.gen = ++gen_;
        push_key_locked(cur.rel, cur.gen, Clock::time_point{}, true);
        cv_.notify_all();
    }

    enum class Outcome { Done, Retry };

    // Called by the worker when an op is finished. retry_in_ms is used for Retry.
    void finish(const Op& op, Outcome oc, uint32_t retry_in_ms = 0, bool count_attempt = true) {
        bool report = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            --inflight_;
            auto it = ops_.find(op.rel);
            if (it != ops_.end()) {
                Op& cur = it->second;
                cur.inflight = false;
                if (cur.redo) {
                    cur.redo = false;
                    cur.kind = cur.redo_kind;
                    cur.is_dir = cur.redo_is_dir;
                    cur.attempts = 0;
                    cur.not_before = Clock::now();
                    cur.gen = ++gen_;
                    push_key_locked(cur.rel, cur.gen, cur.not_before);
                } else if (oc == Outcome::Retry) {
                    int next = op.attempts + (count_attempt ? 1 : 0);
                    if (once_ && next >= kOnceMaxAttempts) {
                        ++c_.gave_up;
                        ++global_.gave_up;
                        log_error(prefix() + "giving up on " + op.rel);
                        ops_.erase(it);
                    } else {
                        cur.attempts = next;
                        cur.not_before = Clock::now() + std::chrono::milliseconds(retry_in_ms);
                        cur.gen = ++gen_;
                        push_key_locked(cur.rel, cur.gen, cur.not_before);
                    }
                } else {
                    ops_.erase(it);
                }
            }
            report = settle_locked();
        }
        cv_.notify_all();
        if (report) log_summary();
    }

    void finish_struct() {
        bool report;
        {
            std::lock_guard<std::mutex> lk(mu_);
            struct_busy_ = false;
            report = settle_locked();
        }
        cv_.notify_all();
        if (report) log_summary();
    }

    // Returns true when the queue just became idle after activity.
    bool settle_locked() {
        if (inflight_ == 0 && ops_.empty() && renames_.empty() && !struct_busy_ && reconcile_done_ && !reconciling_ &&
            !reconcile_req_) {
            EngineStats now = c_.load();
            if (now.sent != logged_.sent || now.skipped != logged_.skipped || now.deleted != logged_.deleted ||
                now.failed != logged_.failed || now.renamed != logged_.renamed) {
                return true;
            }
        }
        return false;
    }

    void log_summary() {
        EngineStats s = c_.load();
        EngineStats d;
        {
            std::lock_guard<std::mutex> lk(mu_);
            d = logged_;
            logged_ = s;
        }
        log_info(prefix() + "idle: sent " + std::to_string(s.sent - d.sent) + " files (" + fmt_bytes(s.bytes - d.bytes) +
                 "), skipped " + std::to_string(s.skipped - d.skipped) + ", deleted " + std::to_string(s.deleted - d.deleted) +
                 ", renamed " + std::to_string(s.renamed - d.renamed) + ", errors " + std::to_string(s.failed - d.failed) +
                 " | total sent " + std::to_string(s.sent) + ", skipped " + std::to_string(s.skipped) + ", " + fmt_bytes(s.bytes));
    }

    std::string prefix() const { return "[" + watch_.name() + " -> " + label_ + "] "; }

    // ---- controller: reconcile ----
    void controller_loop() {
        int fails = 0;
        for (;;) {
            Clock::time_point req;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&] { return stopping_ || reconcile_req_; });
                if (stopping_) return;
                reconcile_req_ = false;
                reconciling_ = true;
                req = reconcile_time_;
            }
            bool ok = false;
            try {
                do_reconcile(req);
                ok = true;
            } catch (const std::exception& e) {
                log_error(prefix() + "reconcile failed: " + e.what());
            }
            if (ok) {
                fails = 0;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    reconciling_ = false;
                    reconcile_done_ = true;
                }
                cv_.notify_all();
                bool report;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    report = settle_locked();
                }
                if (report) log_summary();
                continue;
            }
            ++fails;
            ++c_.failed;
            ++global_.failed;
            {
                std::lock_guard<std::mutex> lk(mu_);
                reconciling_ = false;
                if (once_ && fails >= kOnceMaxAttempts) {
                    gave_up_ = true;
                    ++c_.gave_up;
                    ++global_.gave_up;
                }
            }
            cv_.notify_all();
            if (once_ && fails >= kOnceMaxAttempts) {
                log_error(prefix() + "target unreachable, giving up");
                return;
            }
            if (!sleep_ms(backoff_ms(fails))) return;
            request_reconcile();
        }
    }

    void do_reconcile(Clock::time_point requested) {
        std::shared_ptr<const Snapshot> snap = watch_.snapshot(requested);
        std::map<std::string, FileMeta> remote;
        {
            std::unique_ptr<ITarget> t = factory_();
            t->open();
            remote = t->list_remote();
            t->close();
        }
        const WatchConfig& w = watch_.cfg();
        const Filter& filter = watch_.filter();
        std::unordered_set<std::string> src;
        src.reserve(snap->files.size());
        size_t puts = 0, mkdirs = 0;
        for (const FileMeta& f : snap->files) {
            src.insert(f.rel);
            auto it = remote.find(f.rel);
            if (f.is_dir) {
                if (it == remote.end() || !it->second.is_dir) {
                    enqueue(Kind::MkDir, f.rel, true);
                    ++mkdirs;
                }
                continue;
            }
            if (it == remote.end() || it->second.is_dir || it->second.size != f.size || it->second.hash != f.hash) {
                enqueue(Kind::Put, f.rel, false);
                ++puts;
            }
        }
        size_t dels = 0;
        if (w.propagate_delete) {
            if (snap->stats.failed > 0) {
                log_warn(prefix() + "source scan had " + std::to_string(snap->stats.failed) +
                         " unreadable entries: deletions skipped in this pass");
            } else {
                std::vector<std::string> gone;
                size_t remote_files = 0, gone_files = 0;
                for (const auto& kv : remote) {
                    const FileMeta& r = kv.second;
                    if (!r.is_dir) ++remote_files;
                    if (is_internal_dir(r.rel) || src.count(r.rel)) continue;
                    if (r.is_dir) {
                        if (!filter.includes_all()) continue;
                    } else if (!filter.match(r.rel, r.size, r.mtime_ns)) {
                        continue;  // never synced by this filter: not ours to delete
                    }
                    if (fsutil::stat_path(fs::u8path(watch_.abs_of(r.rel))).ok) continue;  // still on disk
                    gone.push_back(r.rel);
                    if (!r.is_dir) ++gone_files;
                }
                if (gone_files > 100 && gone_files * 2 > remote_files) {
                    log_error(prefix() + "REFUSING to delete " + std::to_string(gone_files) + " of " +
                              std::to_string(remote_files) +
                              " files on the target: the source looks empty or unavailable. Nothing was removed.");
                } else {
                    std::sort(gone.begin(), gone.end());
                    std::string last_dir;
                    for (const std::string& g : gone) {
                        if (!last_dir.empty() && g.compare(0, last_dir.size(), last_dir) == 0) continue;  // inside a removed dir
                        enqueue(Kind::Delete, g, remote.at(g).is_dir);
                        ++dels;
                        if (remote.at(g).is_dir) last_dir = g + "/";
                    }
                }
            }
        }
        log_info(prefix() + "reconcile: source " + std::to_string(snap->files.size()) + " entries (hashed " +
                 std::to_string(snap->stats.hashed) + ", from index " + std::to_string(snap->stats.reused) + "), target " +
                 std::to_string(remote.size()) + "; to send " + std::to_string(puts) + ", mkdir " + std::to_string(mkdirs) +
                 ", delete " + std::to_string(dels));
    }

    // ---- workers ----
    void worker_loop() {
        std::unique_ptr<ITarget> tgt;
        bool opened = false;
        auto reset = [&] {
            if (tgt) {
                try { tgt->close(); } catch (...) {}
            }
            tgt.reset();
            opened = false;
        };
        for (;;) {
            std::vector<Op> batch;
            if (!next_batch(batch)) break;
            std::vector<char> done(batch.size(), 0);
            try {
                if (!tgt) tgt = factory_();
                if (!opened) {
                    tgt->open();
                    opened = true;
                }
                run_batch(*tgt, batch, done);
                streak_ = 0;
            } catch (const std::exception& e) {
                int streak = ++streak_;
                uint32_t delay = backoff_ms(streak);
                log_warn(prefix() + "error: " + e.what() + " (retry in " + std::to_string(delay) + " ms)");
                ++c_.failed;
                ++global_.failed;
                for (size_t i = 0; i < batch.size(); ++i) {
                    if (done[i]) continue;
                    if (batch[i].kind == Kind::Rename) {
                        // A failed rename is not retried: a full reconcile puts the target right.
                        finish_struct();
                        request_reconcile();
                    } else {
                        finish(batch[i], Outcome::Retry, delay, once_ || batch.size() == 1);
                    }
                }
                reset();
                if (!sleep_ms(delay)) break;
            }
        }
        reset();
    }

    void run_batch(ITarget& t, std::vector<Op>& batch, std::vector<char>& done) {
        const WatchConfig& w = watch_.cfg();
        if (batch.size() == 1 && batch[0].kind == Kind::Rename) {
            t.rename_path(batch[0].from, batch[0].rel);
            ++c_.renamed;
            ++global_.renamed;
            done[0] = 1;
            finish_struct();
            return;
        }
        std::vector<PutItem> items;
        std::vector<size_t> item_op;
        for (size_t i = 0; i < batch.size(); ++i) {
            const Op& op = batch[i];
            std::string abs = watch_.abs_of(op.rel);
            fsutil::FsStat st = fsutil::stat_path(fs::u8path(abs));
            switch (op.kind) {
            case Kind::Put: {
                if (!st.ok || st.is_link) {  // vanished (a Deleted event follows) or a symlink: nothing to send
                    finish(op, Outcome::Done);
                    done[i] = 1;
                    break;
                }
                if (st.is_dir) {
                    if (watch_.filter().includes_all()) t.make_dir(op.rel);
                    watch_.enqueue_tree(op.rel, false);
                    finish(op, Outcome::Done);
                    done[i] = 1;
                    break;
                }
                if (!watch_.filter().match(op.rel, st.size, st.mtime_ns)) {
                    finish(op, Outcome::Done);
                    done[i] = 1;
                    break;
                }
                PutItem it;
                try {
                    it.meta = watch_.meta_for(op.rel, abs, st);
                } catch (const std::exception& e) {
                    log_warn(prefix() + "cannot read " + op.rel + ": " + e.what());
                    ++c_.failed;
                    ++global_.failed;
                    watch_.index_erase(op.rel);
                    finish(op, Outcome::Retry, backoff_ms(op.attempts + 1));
                    done[i] = 1;
                    break;
                }
                it.rel = op.rel;
                it.abs_src = abs;
                items.push_back(std::move(it));
                item_op.push_back(i);
                break;
            }
            case Kind::Delete:
                if (!w.propagate_delete || st.ok) {  // came back meanwhile: a Put is queued for it
                    finish(op, Outcome::Done);
                    done[i] = 1;
                    break;
                }
                t.remove_path(op.rel, op.is_dir);
                ++c_.deleted;
                ++global_.deleted;
                finish(op, Outcome::Done);
                done[i] = 1;
                break;
            case Kind::MkDir:
                t.make_dir(op.rel);
                finish(op, Outcome::Done);
                done[i] = 1;
                break;
            case Kind::Rename:
                break;
            }
        }
        if (items.empty()) return;
        std::vector<PutResult> res;
        if (items.size() == 1) res.push_back(t.put_file(items[0].rel, items[0].abs_src, items[0].meta));
        else res = t.put_batch(items);
        if (res.size() != items.size()) throw Error("target returned a wrong number of results");
        for (size_t k = 0; k < items.size(); ++k) {
            size_t i = item_op[k];
            const PutResult& r = res[k];
            if (r.status == PutResult::Sent) {
                ++c_.sent;
                ++global_.sent;
                c_.bytes += r.bytes_on_wire;
                global_.bytes += r.bytes_on_wire;
                finish(batch[i], Outcome::Done);
            } else if (r.status == PutResult::Skipped) {
                ++c_.skipped;
                ++global_.skipped;
                finish(batch[i], Outcome::Done);
            } else {
                ++c_.failed;
                ++global_.failed;
                if (batch[i].attempts == 0 || (batch[i].attempts & (batch[i].attempts - 1)) == 0)
                    log_warn(prefix() + "failed " + batch[i].rel + ": " + r.error + " (attempt " +
                             std::to_string(batch[i].attempts + 1) + ")");
                watch_.index_erase(batch[i].rel);
                finish(batch[i], Outcome::Retry, backoff_ms(batch[i].attempts + 1));
            }
            done[i] = 1;
        }
    }

    WatchCtx& watch_;
    TargetConfig tcfg_;
    uint32_t conns_, retry_min_, retry_max_;
    Factory factory_;
    std::string label_;
    bool once_;
    Counters& global_;
    Counters c_;
    EngineStats logged_;

    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
    bool reconcile_req_ = false, reconciling_ = false, reconcile_done_ = false, gave_up_ = false;
    Clock::time_point reconcile_time_{};
    std::map<std::string, Op> ops_;
    std::deque<std::pair<std::string, uint64_t>> ready_;
    std::multimap<Clock::time_point, std::pair<std::string, uint64_t>> delayed_;
    std::deque<Op> renames_;
    uint64_t gen_ = 0;
    int inflight_ = 0;
    bool struct_busy_ = false;
    std::atomic<int> streak_{0};

    std::thread controller_;
    std::vector<std::thread> workers_;
};

// ------------------------------------------------------------------------------------------- WatchCtx (events)
void WatchCtx::request_all() {
    for (TargetRunner* r : runners_) r->request_reconcile();
}

void WatchCtx::enqueue_tree(const std::string& rel_dir, bool delayed) {
    std::error_code ec;
    fs::path base = fs::u8path(abs_of(rel_dir));
    fs::recursive_directory_iterator it(base, fs::directory_options::skip_permission_denied, ec), end;
    uint32_t dl = delayed ? w_.sync_delay_ms : 0;
    while (!ec && it != end) {
        const fs::directory_entry& e = *it;
        std::error_code e2;
        std::string rel = rel_dir + "/" + e.path().lexically_relative(base).generic_u8string();
        bool is_link = e.is_symlink(e2);
        bool is_dir = !is_link && e.is_directory(e2);
        if (is_link) {
        } else if (is_dir) {
            if (!filter_.match_dir(rel)) {
                it.disable_recursion_pending();
            } else if (filter_.includes_all()) {
                for (TargetRunner* r : runners_) r->enqueue(Kind::MkDir, rel, true, dl);
            }
        } else if (e.is_regular_file(e2)) {
            fsutil::FsStat st = fsutil::stat_path(e.path());
            if (st.ok && filter_.match(rel, st.size, st.mtime_ns))
                for (TargetRunner* r : runners_) r->enqueue(Kind::Put, rel, false, dl);
        }
        it.increment(ec);
    }
}

void WatchCtx::handle_modified(const std::string& rel, bool is_dir, bool delayed) {
    fsutil::FsStat st = fsutil::stat_path(fs::u8path(abs_of(rel)));
    if (!st.ok || st.is_link) return;
    uint32_t dl = delayed ? w_.sync_delay_ms : 0;
    if (st.is_dir || is_dir) {
        if (!filter_.match_dir(rel)) return;
        if (filter_.includes_all())
            for (TargetRunner* r : runners_) r->enqueue(Kind::MkDir, rel, true, dl);
        enqueue_tree(rel, delayed);
        return;
    }
    if (!filter_.match(rel, st.size, st.mtime_ns)) return;
    for (TargetRunner* r : runners_) r->enqueue(Kind::Put, rel, false, dl);
}

void WatchCtx::on_batch(std::vector<WatchEvent>&& batch) {
    bool overflow = false;
    for (const WatchEvent& ev : batch) {
        try {
            switch (ev.kind) {
            case WatchEvent::Overflow:
                overflow = true;
                break;
            case WatchEvent::Modified:
                handle_modified(ev.rel, ev.is_dir, true);
                break;
            case WatchEvent::Deleted:
                index_erase(ev.rel);
                if (w_.propagate_delete)
                    for (TargetRunner* r : runners_) r->enqueue(Kind::Delete, ev.rel, ev.is_dir, w_.sync_delay_ms);
                break;
            case WatchEvent::Renamed: {
                if (!w_.propagate_delete) {
                    handle_modified(ev.rel, ev.is_dir, true);
                    break;
                }
                fsutil::FsStat st = fsutil::stat_path(fs::u8path(abs_of(ev.rel)));
                bool wanted = st.ok && !st.is_link &&
                              ((st.is_dir || ev.is_dir) ? filter_.match_dir(ev.rel) : filter_.match(ev.rel, st.size, st.mtime_ns));
                if (wanted) {
                    index_rename(ev.rel_from, ev.rel);
                    for (TargetRunner* r : runners_) r->enqueue_rename(ev.rel_from, ev.rel);
                    handle_modified(ev.rel, ev.is_dir, true);
                } else {
                    index_erase(ev.rel_from);
                    for (TargetRunner* r : runners_)
                        r->enqueue(Kind::Delete, ev.rel_from, ev.is_dir, w_.sync_delay_ms);
                }
                break;
            }
            }
        } catch (const std::exception& e) {
            log_warn("[" + w_.name + "] cannot handle event for " + ev.rel + ": " + e.what() + " - rescanning");
            overflow = true;
        }
    }
    if (overflow) request_all();
}

void WatchCtx::start_watching() {
    if (watcher_) return;
    WatcherOptions o;
    o.root_utf8 = root_;
    o.recursive = w_.recursive;
    o.quiet_ms = static_cast<int>(w_.quiet_ms);
    o.periodic_scan_s = static_cast<int>(w_.periodic_scan_s);
    const Filter* f = &filter_;
    o.ignore = [f](const std::string& rel, bool is_dir) {
        if (is_dir) return !f->match_dir(rel);
        return is_temp_name(base_name(rel));
    };
    auto w = std::make_unique<Watcher>(o, [this](std::vector<WatchEvent>&& b) { on_batch(std::move(b)); });
    w->start();  // throws Error if the root cannot be watched
    watcher_ = std::move(w);
}

void WatchCtx::start_scheduler() {
    if (w_.schedule_at.empty() && w_.schedule_interval_s == 0) return;
    SchedulerOptions so;
    so.times = w_.schedule_at;
    so.interval_s = static_cast<int>(w_.schedule_interval_s);
    sched_ = std::make_unique<Scheduler>(so, [this] {
        log_info("[" + w_.name + "] scheduled full sync");
        request_all();
    });
    sched_->start();
}

void WatchCtx::stop() {
    if (sched_) sched_->stop();
    if (watcher_) watcher_->stop();
    sched_.reset();
    watcher_.reset();
}

}  // namespace

// ---------------------------------------------------------------------------------------------------- engine
struct SyncEngine::Impl {
    ClientConfig cfg;
    std::string config_dir;
    std::string state_dir;
    std::shared_ptr<RateLimiter> limiter;
    Counters global;
    std::map<std::string, std::shared_ptr<KeyPair>> keys;
    std::vector<std::unique_ptr<WatchCtx>> watches;
    std::vector<std::unique_ptr<TargetRunner>> runners;
    bool once = false;

    void build() {
        watches.clear();
        runners.clear();
        keys.clear();
        cfg.key_file = resolve_path(config_dir, cfg.key_file);
        state_dir = cfg.state_dir.empty() ? (fs::u8path(config_dir.empty() ? "." : config_dir) / "state").u8string()
                                          : resolve_path(config_dir, cfg.state_dir);
        std::error_code ec;
        fs::create_directories(fs::u8path(state_dir), ec);
        limiter = std::make_shared<RateLimiter>(cfg.max_bandwidth_kbps);

        std::set<std::string> names;
        for (const WatchConfig& w0 : cfg.watches) {
            if (!w0.enabled) continue;
            WatchConfig w = w0;
            w.path = resolve_path(config_dir, w.path);
            std::vector<TargetConfig> targets;
            for (TargetConfig t : w.targets) {
                if (!t.enabled) continue;
                if (t.is_local()) t.path = resolve_path(config_dir, t.path);
                else t.key_file = resolve_path(config_dir, t.key_file);
                targets.push_back(t);
            }
            if (targets.empty()) {
                log_warn("watch '" + w.name + "' has no enabled target: skipped");
                continue;
            }
            std::string nm = w.name.empty() ? "watch" + std::to_string(watches.size() + 1) : w.name;
            std::string safe;
            for (char c : nm) safe += (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') ? c : '_';
            while (names.count(safe)) safe += "_";
            names.insert(safe);
            w.name = nm;
            auto ctx = std::make_unique<WatchCtx>(w, w.path, (fs::u8path(state_dir) / ("index-" + safe + ".bin")).u8string(),
                                                  global);
            for (const TargetConfig& t : targets) {
                TargetRunner::Factory f;
                std::string label;
                if (t.is_local()) {
                    label = "dir://" + t.path;
                    std::string sd = state_dir;
                    auto lim = limiter;
                    f = [t, lim, sd] { return make_local_target(t, lim, sd); };
                } else {
                    std::string kf = t.key_file.empty() ? cfg.key_file : t.key_file;
                    if (kf.empty()) throw Error("watch '" + nm + "': no key_file for the target " + t.host);
                    auto& slot = keys[kf];
                    if (!slot) slot = std::make_shared<KeyPair>(load_keypair(kf));
                    label = "net://" + t.host + ":" + std::to_string(t.port);
                    std::shared_ptr<KeyPair> kp = slot;
                    ClientConfig cc = cfg;
                    cc.watches.clear();
                    auto lim = limiter;
                    f = [t, cc, kp, lim] { return make_net_target(t, cc, *kp, lim); };
                }
                auto r = std::make_unique<TargetRunner>(*ctx, t, cfg, f, label, once, global);
                ctx->add_runner(r.get());
                runners.push_back(std::move(r));
            }
            watches.push_back(std::move(ctx));
        }
        if (watches.empty()) throw Error("the client configuration has no enabled [[watch]] with an enabled target");
    }

    void shutdown() {
        for (auto& w : watches) w->stop();
        for (auto& r : runners) r->stop();
        for (auto& w : watches) w->save_index();
        runners.clear();
        watches.clear();
    }
};

SyncEngine::SyncEngine(ClientConfig cfg, std::string config_dir) : p_(new Impl) {
    p_->cfg = std::move(cfg);
    p_->config_dir = std::move(config_dir);
}

SyncEngine::~SyncEngine() {
    if (p_) p_->shutdown();
}

EngineStats SyncEngine::stats() const {
    EngineStats s = p_->global.load();
    return s;
}

bool SyncEngine::idle() const {
    if (p_->runners.empty()) return false;
    for (auto& r : p_->runners)
        if (!r->idle()) return false;
    return true;
}

void SyncEngine::start_watchers(bool first) {
    for (auto& w : p_->watches) {
        if (w->watching()) continue;
        try {
            w->start_watching();
            log_info("[" + w->name() + "] watching " + w->root());
            if (!first) w->request_all();
        } catch (const std::exception& e) {
            log_error("[" + w->name() + "] cannot watch " + w->root() + ": " + e.what() + " (retrying)");
        }
    }
}

void SyncEngine::run(std::atomic<bool>& stop) {
    p_->once = false;
    p_->build();
    log_info("sync engine: " + std::to_string(p_->watches.size()) + " watch(es), " + std::to_string(p_->runners.size()) +
             " target(s), state in " + p_->state_dir);
    // Watchers first, so no change can fall between the initial scan and the start of watching.
    start_watchers(true);
    for (auto& w : p_->watches) w->start_scheduler();
    for (auto& r : p_->runners) {
        // Initial reconcile when start_sync is on (the periodic safety scan of the watcher covers the other case).
        bool init = true;
        for (auto& w : p_->watches)
            for (TargetRunner* tr : w->runners())
                if (tr == r.get()) init = w->cfg().start_sync;
        r->start(init);
    }
    auto last_retry = Clock::now();
    auto last_save = Clock::now();
    while (!stop.load()) {
        // Watchers that could not start (source not available yet) are retried every few seconds.
        auto now = Clock::now();
        if (now - last_retry >= std::chrono::seconds(5)) {
            last_retry = now;
            start_watchers(false);
        }
        if (now - last_save >= std::chrono::minutes(5)) {
            last_save = now;
            for (auto& w : p_->watches) w->save_index();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    log_info("sync engine: stopping");
    p_->shutdown();
}

void SyncEngine::sync_once(std::atomic<bool>& stop) {
    p_->once = true;
    p_->build();
    for (auto& r : p_->runners) r->start(true);
    for (;;) {
        if (stop.load()) break;
        bool all = true;
        for (auto& r : p_->runners)
            if (!r->finished()) { all = false; break; }
        if (all) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    EngineStats s = p_->global.load();
    log_info("sync once done: sent " + std::to_string(s.sent) + " files (" + fmt_bytes(s.bytes) + "), skipped " +
             std::to_string(s.skipped) + ", deleted " + std::to_string(s.deleted) + ", errors " + std::to_string(s.failed) +
             ", abandoned " + std::to_string(s.gave_up));
    p_->shutdown();
}

}  // namespace mysync
