// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/server.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <optional>
#include <thread>

#include "fileio.h"  // includes <windows.h> on Windows: keep before winsock
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include "mysync/compress.h"
#include "mysync/delta.h"
#include "mysync/filter.h"
#include "mysync/hash.h"
#include "mysync/index.h"
#include "mysync/net.h"
#include "mysync/pathsafe.h"
#include "mysync/protocol.h"
#include "mysync/ratelimit.h"
#include "mysync/secure_channel.h"

namespace mysync {

namespace fs = std::filesystem;
using namespace proto;

namespace {

constexpr uint64_t kDeltaMinFile = 1024 * 1024;  // existing file size from which NEED_DELTA is offered
constexpr size_t kMaxPending = 4096;             // pipelined NEED_* offers awaiting data per session
constexpr int64_t kMtimeTolNs = 1000;
constexpr size_t kMaxTrees = 64;
constexpr int64_t kOrphanAgeSec = 3600;
constexpr int kHelloTimeoutMs = 5000;           // first record (HELLO) after the handshake
constexpr int kMaxUnauthPerIp = 4;              // connections that have not finished the handshake, per source
constexpr int64_t kThrottleWindowMs = 60000;
constexpr int64_t kThrottleSweepMs = 10000;
constexpr int64_t kRacyNs = 2000000000LL;  // files younger than this are never cached (same rule as scan_tree)

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = char(c + 32);
    return s;
}

// Canonical text of a peer address: IPv4-mapped IPv6 becomes plain IPv4, scope id dropped, lower case.
std::string norm_ip(std::string ip) {
    ip = lower(ip);
    auto pct = ip.find('%');
    if (pct != std::string::npos) ip.resize(pct);
    if (ip.rfind("::ffff:", 0) == 0 && ip.find('.') != std::string::npos) ip = ip.substr(7);
    return ip;
}

std::string utc_stamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    std::time_t t = system_clock::to_time_t(now);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d%02d%02dT%02d%02d%02d.%03dZ", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec, int(ms));
    return buf;
}

fs::path u8(const std::string& s) { return fs::u8path(s); }

// Wakes a thread blocked in recv/send on `s` (shutdown_both also cancels pending I/O on Windows; the caller holds the session's mutex, so the socket is alive). Only
// shutdown(): closing from this thread would race the owner's use of the descriptor; the owning thread sees the
// failed recv and closes the socket itself.
void wake(net::Socket& s) { s.shutdown_both(); }

void clean_orphans(const std::string& root) {
    std::error_code ec;
    fs::recursive_directory_iterator it(u8(root), fs::directory_options::skip_permission_denied, ec), end;
    size_t removed = 0;
    int64_t now_ns = now_unix_ns();
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        if (it->is_symlink(e2)) {
            it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file(e2)) continue;
        std::string name = it->path().filename().u8string();
        if (name.rfind(fio::kTmpPrefix, 0) != 0) continue;
        fio::StatInfo si = fio::stat_path(it->path());
        if ((now_ns - si.mtime_ns) / 1000000000LL >= kOrphanAgeSec && fs::remove(it->path(), e2)) removed++;
    }
    if (removed) log_info("removed " + std::to_string(removed) + " orphaned temp file(s)");
}

KeyPair key_from_file(const std::string& path) {
    Bytes b = load_secret_key_file(path);
    if (b.size() != 32) throw Error("bad key length");
    PubKey sk;
    std::copy(b.begin(), b.end(), sk.begin());
    secure_wipe(b.data(), b.size());
    KeyPair kp = keypair_from_secret(sk);
    secure_wipe(sk.data(), sk.size());
    return kp;
}

}  // namespace

// ---------------------------------------------------------------- IpFilter

bool IpFilter::parse_ip(const std::string& s, std::array<uint8_t, 16>& out) {
    in6_addr a6;
    if (inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        std::memcpy(out.data(), &a6, 16);
        return true;
    }
    in_addr a4;
    if (inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        out.fill(0);
        out[10] = out[11] = 0xff;
        std::memcpy(out.data() + 12, &a4, 4);
        return true;
    }
    return false;
}

IpFilter::Net IpFilter::parse_net(const std::string& text) {
    std::string s = text;
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    Net n;
    std::string ip = s;
    int bits = -1;
    auto slash = s.find('/');
    if (slash != std::string::npos) {
        ip = s.substr(0, slash);
        std::string b = s.substr(slash + 1);
        if (b.empty() || b.size() > 3 || b.find_first_not_of("0123456789") != std::string::npos)
            throw Error("bad CIDR prefix length in '" + text + "'");
        bits = std::stoi(b);
    }
    if (!parse_ip(ip, n.addr)) throw Error("bad IP address in '" + text + "'");
    bool v4 = ip.find(':') == std::string::npos;
    if (bits < 0) {
        n.bits = 128;
    } else {
        if (bits > (v4 ? 32 : 128)) throw Error("CIDR prefix length out of range in '" + text + "'");
        n.bits = v4 ? bits + 96 : bits;
    }
    return n;
}

bool IpFilter::match(const Net& n, const std::array<uint8_t, 16>& ip) {
    int full = n.bits / 8, rem = n.bits % 8;
    for (int i = 0; i < full; i++)
        if (n.addr[size_t(i)] != ip[size_t(i)]) return false;
    if (rem) {
        uint8_t mask = uint8_t(0xff << (8 - rem));
        if ((n.addr[size_t(full)] & mask) != (ip[size_t(full)] & mask)) return false;
    }
    return true;
}

IpFilter::IpFilter(const std::vector<std::string>& allow, const std::vector<std::string>& deny) {
    for (const auto& a : allow) {
        if (a == "*") allow_all_ = true;
        else allow_.push_back(parse_net(a));
    }
    for (const auto& d : deny) {
        if (d == "*") deny_.push_back(Net{});  // bits = 0 matches everything
        else deny_.push_back(parse_net(d));
    }
}

bool IpFilter::permits(const std::string& ip) const {
    std::array<uint8_t, 16> a;
    if (!parse_ip(norm_ip(ip), a)) return false;
    for (const auto& d : deny_)
        if (match(d, a)) return false;
    if (allow_all_) return true;
    for (const auto& n : allow_)
        if (match(n, a)) return true;
    return false;
}

// ---------------------------------------------------------------- AuthThrottle

namespace {

// Key under which a source is throttled: IPv4 as is, IPv6 reduced to its /64 prefix.
std::string throttle_key(const std::string& ip) {
    in6_addr a6;
    if (ip.find(':') == std::string::npos || inet_pton(AF_INET6, ip.c_str(), &a6) != 1) return ip;
    uint8_t b[16];
    std::memcpy(b, &a6, 16);
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::memcmp(b, mapped, 12) == 0)  // ::ffff:a.b.c.d is the IPv4 host
        return std::to_string(b[12]) + "." + std::to_string(b[13]) + "." + std::to_string(b[14]) + "." +
               std::to_string(b[15]);
    return "v6/64:" + to_hex(b, 8);
}

}  // namespace

bool AuthThrottle::blocked(const std::string& ip, int64_t now_ms) {
    if (max_ == 0) return false;
    std::string key = throttle_key(ip);
    std::lock_guard<std::mutex> lk(m_);
    auto it = fails_.find(key);
    if (it == fails_.end()) return false;
    auto& q = it->second.q;
    while (!q.empty() && now_ms - q.front() >= kThrottleWindowMs) q.pop_front();
    if (q.empty()) {
        order_.erase(it->second.pos);
        fails_.erase(it);
        return false;
    }
    return q.size() >= max_;
}

void AuthThrottle::record_failure(const std::string& ip, int64_t now_ms) {
    if (max_ == 0) return;
    std::string key = throttle_key(ip);
    std::lock_guard<std::mutex> lk(m_);
    if (now_ms - last_sweep_ms_ >= kThrottleSweepMs) {  // order_ is by last failure: stop at the first live source
        last_sweep_ms_ = now_ms;
        while (!order_.empty()) {
            auto it = fails_.find(order_.front());
            if (it != fails_.end() && !it->second.q.empty() && now_ms - it->second.q.back() < kThrottleWindowMs) break;
            if (it != fails_.end()) fails_.erase(it);
            order_.pop_front();
        }
    }
    auto it = fails_.find(key);
    if (it == fails_.end()) {
        while (fails_.size() >= kMaxEntries && !order_.empty()) {  // hard cap: drop the longest-quiet source
            fails_.erase(order_.front());
            order_.pop_front();
        }
        it = fails_.emplace(key, Entry{}).first;
        order_.push_back(key);
        it->second.pos = std::prev(order_.end());
    } else {
        order_.splice(order_.end(), order_, it->second.pos);
    }
    auto& q = it->second.q;
    q.push_back(now_ms);
    while (q.size() > size_t(max_) + 8) q.pop_front();
}

size_t AuthThrottle::tracked() {
    std::lock_guard<std::mutex> lk(m_);
    return fails_.size();
}

// ---------------------------------------------------------------- WriteQuota

uint64_t WriteQuota::used_locked(int64_t now_min) const {
    uint64_t sum = 0;
    for (size_t i = 0; i < 60; i++)
        if (minute_[i] >= 0 && now_min >= minute_[i] && now_min - minute_[i] < 60) sum += bytes_[i];
    return sum;
}

bool WriteQuota::would_exceed(uint64_t add, int64_t now_ms) {
    if (limit_ == 0) return false;
    std::lock_guard<std::mutex> lk(m_);
    uint64_t u = used_locked(now_ms / 60000);
    return u > limit_ || add > limit_ - u;
}

bool WriteQuota::charge(uint64_t add, int64_t now_ms) {
    if (limit_ == 0) return true;
    std::lock_guard<std::mutex> lk(m_);
    int64_t cur = now_ms / 60000;
    uint64_t u = used_locked(cur);
    if (u > limit_ || add > limit_ - u) return false;
    size_t i = size_t(cur % 60);
    if (minute_[i] != cur) {
        minute_[i] = cur;
        bytes_[i] = 0;
    }
    bytes_[i] += add;
    return true;
}

uint64_t WriteQuota::used(int64_t now_ms) {
    std::lock_guard<std::mutex> lk(m_);
    return used_locked(now_ms / 60000);
}

// ---------------------------------------------------------------- server core

namespace detail {

struct Tree {
    std::mutex m;
    IndexCache cache;
    std::string file;
    bool dirty = false;
    int64_t last_save_ms = 0;
};

struct SessRec {
    std::thread th;
    std::atomic<bool> done{false};
    std::mutex m;
    net::Socket* sock = nullptr;
};

struct ClientState {
    std::atomic<int> sessions{0};
    WriteQuota quota;
    RateLimiter bandwidth;  // shared by every connection of this client (received + sent bytes)
    uint64_t quota_limit;   // identity of the limits, so a reload keeps the live state when they did not change
    uint32_t kbps;
    std::atomic<uint64_t> bytes_rx{0}, bytes_tx{0};  // for the GUI status only
    gui::RateMeter rx_meter, tx_meter;
    ClientState(uint64_t bytes_per_hour, uint32_t kbps_)
        : quota(bytes_per_hour), bandwidth(kbps_), quota_limit(bytes_per_hour), kbps(kbps_) {}
};

// Everything a RELOAD can change, as one immutable snapshot: a session keeps the Policy it started with, so a
// reload only affects sessions that start afterwards (plus the revocation check in Session::serve).
struct Policy {
    ServerConfig cfg;
    IpFilter ipf;
    std::vector<std::shared_ptr<ClientState>> cstate;  // parallel to cfg.clients
    std::shared_ptr<RateLimiter> total_bw;              // all clients together
    explicit Policy(ServerConfig c)
        : cfg(std::move(c)), ipf(cfg.allow, cfg.deny), total_bw(std::make_shared<RateLimiter>(cfg.max_bandwidth_kbps)) {}
};

struct ServerCore {
    ServerConfig cfg;  // as started: bind / port / root / key_file never change; the rest lives in `pol`
    KeyPair key;
    AuthThrottle thr;
    net::Socket lsock;
    std::string root;
    fs::path state_dir;
    std::mutex tm;
    std::map<std::string, std::shared_ptr<Tree>> trees;
    std::atomic<int> active{0};  // authenticated sessions (cfg.max_connections caps these)
    std::mutex um;               // connections still in the handshake
    std::map<std::string, int> unauth_by_key;
    size_t unauth_total = 0;
    mutable std::mutex pm;
    std::shared_ptr<const Policy> pol;
    std::atomic<uint32_t> max_conn{0};
    std::atomic<uint64_t> total_rx{0}, total_tx{0};  // bytes through the sessions, for the GUI status
    gui::RateMeter rx_meter, tx_meter;
    const std::atomic<bool>* stop_flag = nullptr;  // set by Server::run before any session starts; cuts bandwidth sleeps
    std::shared_ptr<const Policy> policy() const {
        std::lock_guard<std::mutex> lk(pm);
        return pol;
    }
    // False when the client was removed from the allowlist, or its access / prefix changed, by a reload.
    bool still_permitted(const ClientAcl& a) const {
        auto p = policy();
        for (const ClientAcl& n : p->cfg.clients)
            if (n.public_key == a.public_key) return n.read_only == a.read_only && n.prefix == a.prefix;
        return false;
    }
    std::mutex trash_mu;           // serialises moves into / purges of <root>/__sync/__trash
    bool trash_scanned = false;    // trash_bytes is valid (computed lazily, only when max_trash_bytes != 0)
    uint64_t trash_bytes = 0;

    size_t unauth_cap() const { return std::max<size_t>(8, max_conn.load() / 2); }
    bool unauth_acquire(const std::string& key) {
        std::lock_guard<std::mutex> lk(um);
        if (unauth_total >= unauth_cap()) return false;
        int& n = unauth_by_key[key];
        if (n >= kMaxUnauthPerIp) {
            if (n == 0) unauth_by_key.erase(key);
            return false;
        }
        n++;
        unauth_total++;
        return true;
    }
    void unauth_release(const std::string& key) {
        std::lock_guard<std::mutex> lk(um);
        auto it = unauth_by_key.find(key);
        if (it == unauth_by_key.end()) return;
        if (--it->second <= 0) unauth_by_key.erase(it);
        if (unauth_total > 0) unauth_total--;
    }
    bool session_acquire() {
        int cur = active.load();
        while (cur < int(max_conn.load()))
            if (active.compare_exchange_weak(cur, cur + 1)) return true;
        return false;
    }

    ServerCore(ServerConfig c, const KeyPair& k)
        : cfg(std::move(c)), key(k), thr(cfg.max_auth_failures_per_min) {
        if (cfg.root.empty()) throw Error("server root is not set");
        net::init();
        std::error_code ec;
        fio::create_dirs(u8(cfg.root), cfg.dir_mode, ec);
        if (!fs::is_directory(u8(cfg.root), ec)) throw Error("server root is not a directory");
        root = fs::weakly_canonical(u8(cfg.root), ec).u8string();
        if (ec) throw Error("cannot resolve server root");
        state_dir = cfg.state_dir.empty() ? (u8(root) / "__sync" / "__meta") : u8(cfg.state_dir);
        fio::create_dirs(state_dir, cfg.dir_mode, ec);
        if (ec) throw Error("cannot create state directory");
        {
            auto p = std::make_shared<Policy>(cfg);
            for (size_t i = 0; i < cfg.clients.size(); i++)
                p->cstate.push_back(std::make_shared<ClientState>(cfg.clients[i].max_write_bytes_per_hour,
                                                                  cfg.clients[i].max_bandwidth_kbps));
            pol = p;
            max_conn = cfg.max_connections;
        }
        lsock = net::Socket::listen(cfg.bind, cfg.port);
        clean_orphans(root);
    }

    std::shared_ptr<Tree> tree_for(const std::string& prefix) {
        std::lock_guard<std::mutex> lk(tm);
        auto it = trees.find(prefix);
        if (it != trees.end()) return it->second;
        auto t = std::make_shared<Tree>();
        Hash256 h = hash_bytes(prefix.data(), prefix.size());
        t->file = (state_dir / ("server-index-" + to_hex(h.data(), 8) + ".bin")).u8string();
        t->cache.load(t->file);
        if (trees.size() < kMaxTrees) trees[prefix] = t;  // beyond the cap the tree is private to the caller
        return t;
    }

    void save_tree(Tree& t, bool force) {
        std::lock_guard<std::mutex> lk(t.m);
        if (!t.dirty) return;
        int64_t now = steady_ms();
        if (!force && now - t.last_save_ms < 10000) return;
        try {
            t.cache.save(t.file);
            t.dirty = false;
            t.last_save_ms = now;
        } catch (const std::exception& e) {
            log_warn(std::string("cannot save index cache: ") + e.what());
        }
    }
    void save_all() {
        std::vector<std::shared_ptr<Tree>> v;
        {
            std::lock_guard<std::mutex> lk(tm);
            for (auto& kv : trees) v.push_back(kv.second);
        }
        for (auto& t : v) save_tree(*t, true);
    }
};

}  // namespace detail

namespace {

using detail::ClientState;
using detail::Policy;
using detail::ServerCore;
using detail::SessRec;
using detail::Tree;

// A failure with a protocol error code that is reported to the client as FILE_ERR.
struct OpError : Error {
    ErrCode code;
    OpError(ErrCode c, const std::string& m) : Error(m), code(c) {}
};

// Size in bytes of a file, or of every regular file below a directory (symlinks are not followed).
uint64_t tree_bytes(const fs::path& p) {
    std::error_code ec;
    fs::file_status st = fs::symlink_status(p, ec);
    if (ec) return 0;
    if (st.type() == fs::file_type::regular) {
        auto n = fs::file_size(p, ec);
        return ec ? 0 : uint64_t(n);
    }
    if (st.type() != fs::file_type::directory) return 0;
    uint64_t sum = 0;
    fs::recursive_directory_iterator it(p, fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        if (it->is_regular_file(e2) && !it->is_symlink(e2)) {
            auto n = it->file_size(e2);
            if (!e2) sum += uint64_t(n);
        }
    }
    return sum;
}

// Frees trash until trash_bytes <= target by deleting whole timestamp directories, oldest name first (the names are
// UTC timestamps, so they sort by age). Caller holds c.trash_mu.
void trash_purge_to(ServerCore& c, uint64_t target) {
    fs::path troot = u8(c.root) / "__sync" / "__trash";
    std::error_code ec;
    std::vector<fs::path> dirs;
    for (fs::directory_iterator it(troot, ec), end; !ec && it != end; it.increment(ec)) dirs.push_back(it->path());
    std::sort(dirs.begin(), dirs.end());
    size_t purged = 0;
    uint64_t freed = 0;
    for (const auto& d : dirs) {
        if (c.trash_bytes <= target) break;
        uint64_t sz = tree_bytes(d);
        std::error_code e2;
        fs::remove_all(d, e2);
        if (e2) throw OpError(ErrCode::IoError, "cannot free trash space");
        c.trash_bytes -= std::min(sz, c.trash_bytes);
        freed += sz;
        purged++;
    }
    if (purged)
        log_info("trash over max_trash_bytes: purged " + std::to_string(purged) + " oldest entr" +
                 (purged == 1 ? "y" : "ies") + " (" + std::to_string(freed) + " bytes)");
    if (c.trash_bytes > target) c.trash_bytes = tree_bytes(troot);  // accounting drifted: resynchronise
    if (c.trash_bytes > target) throw OpError(ErrCode::IoError, "cannot free enough trash space");
}

// Moves `abs` (file or directory) into <root>/__sync/__trash/<UTC timestamp>/<real> by rename and returns the new
// location. Enforces max_trash_bytes: older entries are purged first; an item larger than the cap is refused.
fs::path trash_move(ServerCore& c, const ServerConfig& cfg, const fs::path& abs, const std::string& real) {
    std::lock_guard<std::mutex> lk(c.trash_mu);
    const uint64_t limit = cfg.max_trash_bytes;
    uint64_t sz = 0;
    if (limit) {
        sz = tree_bytes(abs);
        if (sz > limit)
            throw OpError(ErrCode::TooLarge, "item is larger than the trash limit (max_trash_bytes); not removed");
        if (!c.trash_scanned) {
            c.trash_bytes = tree_bytes(u8(c.root) / "__sync" / "__trash");
            c.trash_scanned = true;
        }
        if (c.trash_bytes + sz > limit) trash_purge_to(c, limit - sz);
    }
    fs::path base = u8(c.root) / "__sync" / "__trash" / utc_stamp() / u8(real);
    std::error_code ec;
    fio::create_dirs(base.parent_path(), cfg.dir_mode, ec);
    if (ec) throw OpError(ErrCode::IoError, "cannot create trash directory");
    fs::path cand = base;
    for (int n = 1; fio::stat_path(cand).exists || fs::is_symlink(cand, ec); n++)
        cand = fs::path(base.u8string() + "-" + std::to_string(n));
    fs::rename(abs, cand, ec);
    if (ec) throw OpError(ErrCode::IoError, "cannot move to trash");
    if (limit) c.trash_bytes += sz;
    return cand;
}

struct Resolved {
    fs::path abs;
    std::string vrel;  // normalised path in the client's virtual root
    std::string real;  // path relative to the server root
};

struct Pending {
    Resolved r;
    uint64_t size = 0;
    int64_t mtime_ns = 0;
    Hash256 offer_hash{};
    bool is_delta = false;
    uint32_t block_size = 0;
    std::string old_path;
    // runtime
    bool started = false;
    bool failed = false;  // FILE_ERR already sent; swallow the rest up to ENDFILE
    fio::TmpFile tmp;
    std::unique_ptr<Hasher> hasher;
    std::unique_ptr<delta::DeltaApplier> applier;
    uint64_t received = 0;
    uint64_t next_seq = 0;
};

class Session {
public:
    Session(ServerCore& c, SecureChannel& ch, const ClientAcl& acl, std::string ip, ClientState& cs,
            std::shared_ptr<const Policy> pol)
        : c_(c), pol_(std::move(pol)), ch_(ch), acl_(acl), ip_(std::move(ip)), cs_(cs) {}

    // Reads and validates the first record. Runs while the connection still holds its "unauthenticated" place,
    // so a replayed msg1 (valid handshake, no HELLO) cannot take a session slot of the client it impersonates.
    // Returns false when the peer was told why it is refused.
    bool read_hello() {
        prefix_ = normalize_rel(acl_.prefix);
        while (!prefix_.empty() && prefix_.back() == '/') prefix_.pop_back();
        if (!prefix_.empty()) {
            if (is_internal_dir(prefix_)) throw Error("client prefix points into the internal directory");
            fs::path p = safe_join(c_.root, prefix_);  // throws on a malicious prefix: session refused
            std::error_code ec;
            fio::create_dirs(p, pol_->cfg.dir_mode, ec);
        }
        tree_ = c_.tree_for(prefix_);

        // The first record must arrive promptly: a replayed msg1 completes the handshake but cannot produce it.
        hello_pending_ = true;
        Bytes raw_first = ch_.recv_msg_within(kHelloTimeoutMs);
        int io_ms = int(pol_->cfg.io_timeout_s ? pol_->cfg.io_timeout_s : 60) * 1000;
        ch_.socket().set_timeouts(io_ms, io_ms);
        Message first = decode(raw_first);
        hello_pending_ = false;
        const Hello* h = std::get_if<Hello>(&first);
        if (!h) {
            send(FileErr{ErrCode::BadRequest, "HELLO expected"});
            return false;
        }
        if (h->proto_ver != kProtoVersion) {
            send(FileErr{ErrCode::Unsupported, "unsupported protocol version"});
            return false;
        }
        caps_ = h->caps & (kCapLz4 | kCapDelta);
        return true;
    }

    // After a valid HELLO (and the session slots): answers it and serves requests until the peer leaves.
    void serve() {
        send(HelloOk{kCapLz4 | kCapDelta, kDefaultMaxChunk});
        log_info("client '" + acl_.name + "' connected from " + ip_);

        for (;;) {
            Message m = decode(recv());
            if (!c_.still_permitted(acl_)) {  // removed from the allowlist (or access changed) by a reload
                log_warn("client '" + acl_.name + "' is no longer permitted by the configuration: session closed");
                break;
            }
            if (!dispatch(m)) break;
        }
        c_.save_tree(*tree_, false);
    }

    // True until the first record was received and decoded: a failure in that window counts against the source.
    bool hello_pending() const { return hello_pending_; }

private:
    bool hello_pending_ = false;
    ServerCore& c_;
    std::shared_ptr<const Policy> pol_;  // the policy this session started with
    SecureChannel& ch_;
    ClientAcl acl_;
    std::string ip_;
    ClientState& cs_;
    std::string prefix_;
    std::shared_ptr<Tree> tree_;
    uint32_t caps_ = 0;
    std::deque<std::unique_ptr<Pending>> pending_;

    // Bandwidth caps: the client's own bucket first, then the server-wide one (the lower cap wins).
    void throttle(size_t n) {
        cs_.bandwidth.acquire(n, c_.stop_flag);
        pol_->total_bw->acquire(n, c_.stop_flag);
    }
    Bytes recv() {
        Bytes b = ch_.recv_msg();
        throttle(b.size());
        cs_.bytes_rx += b.size();
        c_.total_rx += b.size();
        return b;
    }
    void send(const Message& m) {
        Bytes b = encode(m);
        throttle(b.size());
        ch_.send_msg(b);
        cs_.bytes_tx += b.size();
        c_.total_tx += b.size();
    }
    void ok() { send(FileOk{}); }
    void err(ErrCode code, const std::string& msg) { send(FileErr{code, msg}); }

    // Runs one request handler; per-request failures become FILE_ERR and keep the session alive.
    // (If the channel itself is dead, the follow-up send throws and ends the session.)
    template <class F>
    bool guard(F f) {
        try {
            f();
        } catch (const OpError& e) {
            err(e.code, e.what());
        } catch (const std::exception& e) {
            log_warn("request from '" + acl_.name + "' failed: " + e.what());
            err(ErrCode::IoError, "i/o error");
        }
        return true;
    }

    bool dispatch(const Message& m) {
        if (auto* p = std::get_if<Ping>(&m)) {
            send(Pong{p->token});
            return true;
        }
        if (std::get_if<Bye>(&m)) return false;
        if (auto* o = std::get_if<Offer>(&m)) return guard([&] { on_offer(*o); });
        if (auto* d = std::get_if<Data>(&m)) return on_data(*d);
        if (auto* d = std::get_if<DeltaOps>(&m)) return on_delta(*d);
        if (auto* e = std::get_if<EndFile>(&m)) return on_end(*e);
        if (auto* d = std::get_if<Delete>(&m)) return guard([&] { on_delete(*d); });
        if (auto* r = std::get_if<Rename>(&m)) return guard([&] { on_rename(*r); });
        if (auto* k = std::get_if<Mkdir>(&m)) return guard([&] { on_mkdir(*k); });
        if (auto* l = std::get_if<ListReq>(&m)) return guard([&] { on_list(*l); });
        err(ErrCode::BadRequest, "unexpected message");
        return false;
    }

    // ---- paths ----
    Resolved resolve(const std::string& in) const {
        std::string v = normalize_rel(in);
        while (!v.empty() && v.back() == '/') v.pop_back();
        if (v.empty() || v[0] == '/') throw OpError(ErrCode::PathDenied, "path denied");
        std::string real = prefix_.empty() ? v : prefix_ + "/" + v;
        if (is_internal_dir(v) || is_internal_dir(real) || has_tmp_component(v))
            throw OpError(ErrCode::PathDenied, "path denied");
        try {
            return Resolved{safe_join(c_.root, real), v, real};
        } catch (const Error&) {
            throw OpError(ErrCode::PathDenied, "path denied");
        }
    }
    void recheck(const Resolved& r) const {
        try {
            safe_join(c_.root, r.real);
        } catch (const Error&) {
            throw OpError(ErrCode::PathDenied, "path denied");
        }
    }

    // ---- hashing with the persistent cache ----
    Hash256 file_hash(const Resolved& r, const fio::StatInfo& st) {
        {
            std::lock_guard<std::mutex> lk(tree_->m);
            const FileMeta* e = tree_->cache.find(r.vrel);
            if (e && !e->is_dir && e->size == st.size && e->mtime_ns == st.mtime_ns) return e->hash;
        }
        Hash256 h = hash_file(r.abs.u8string());
        cache_put(r, st, h);
        return h;
    }
    void cache_put(const Resolved& r, const fio::StatInfo& st, const Hash256& h) {
        if (st.mtime_ns >= now_unix_ns() - kRacyNs) return;
        FileMeta m;
        m.rel = r.vrel;
        m.size = st.size;
        m.mtime_ns = st.mtime_ns;
        m.hash = h;
        std::lock_guard<std::mutex> lk(tree_->m);
        tree_->cache.put(m);
        tree_->dirty = true;
    }

    // ---- OFFER ----
    void on_offer(const Offer& o) {
        if (acl_.read_only) throw OpError(ErrCode::PathDenied, "read-only client");
        if (pending_.size() >= kMaxPending) throw OpError(ErrCode::Busy, "too many pending files");
        Resolved r = resolve(o.path);
        if (pol_->cfg.max_file_size && o.size > pol_->cfg.max_file_size) throw OpError(ErrCode::TooLarge, "file too large");
        fio::StatInfo st = fio::stat_path(r.abs);
        if (st.is_symlink) throw OpError(ErrCode::PathDenied, "symlink at destination");
        if (st.exists && !st.is_regular) throw OpError(ErrCode::IoError, "destination is not a regular file");

        if (st.exists && st.size == o.size) {
            Hash256 h = file_hash(r, st);
            if (ct_equal(h.data(), o.hash.data(), 32)) {
                if (std::llabs(st.mtime_ns - o.mtime_ns) > kMtimeTolNs) {
                    if (fio::set_mtime(r.abs, std::max<int64_t>(0, o.mtime_ns))) {
                        fio::StatInfo s2 = fio::stat_path(r.abs);
                        cache_put(r, s2, h);
                    }
                }
                send(Skip{});
                return;
            }
        }

        if (cs_.quota.would_exceed(o.size, steady_ms())) {
            log_warn("client '" + acl_.name + "' exceeded max_write_bytes_per_hour; refusing " + r.real);
            throw OpError(ErrCode::Busy, "write quota exceeded (max_write_bytes_per_hour); try again later");
        }

        auto p = std::make_unique<Pending>();
        p->r = r;
        p->size = o.size;
        p->mtime_ns = o.mtime_ns;
        p->offer_hash = o.hash;

        if (st.exists && (caps_ & kCapDelta) && st.size >= kDeltaMinFile && o.size > 0) {
            try {
                delta::Signature sig = delta::make_signature(r.abs.u8string());
                if (!sig.blocks.empty() && sig.blocks.size() <= kMaxNeedDeltaBlocks) {
                    p->is_delta = true;
                    p->block_size = sig.block_size;
                    p->old_path = r.abs.u8string();
                    NeedDelta nd;
                    nd.block_size = sig.block_size;
                    nd.sigs = std::move(sig.blocks);
                    send(nd);
                    pending_.push_back(std::move(p));
                    return;
                }
            } catch (const Error&) {
                // fall back to a full transfer
            }
        }
        send(NeedFull{});
        pending_.push_back(std::move(p));
    }

    // ---- file body ----
    void ensure_started(Pending& p) {
        if (p.started) return;
        fs::path dir = p.r.abs.parent_path();
        std::error_code ec;
        // The parent was validated by safe_join in resolve(); only a directory we create now needs a second look
        // (a symlinked ancestor could have appeared in between).
        bool existed = fs::is_directory(dir, ec);
        if (!existed) {
            fio::create_dirs(dir, pol_->cfg.dir_mode, ec);
            if (ec) throw OpError(ErrCode::IoError, "cannot create directory");
            recheck(p.r);
        }
        p.tmp = fio::TmpFile::create(dir);
        p.hasher = std::make_unique<Hasher>();
        p.started = true;
    }
    void write_body(Pending& p, const void* d, size_t n) {
        if (n > p.size - p.received) throw OpError(ErrCode::TooLarge, "more data than announced");
        ensure_started(p);
        if (!cs_.quota.charge(n, steady_ms())) {
            log_warn("client '" + acl_.name + "' exceeded max_write_bytes_per_hour while writing " + p.r.real);
            throw OpError(ErrCode::Busy, "write quota exceeded (max_write_bytes_per_hour); try again later");
        }
        p.tmp.write(d, n);
        p.hasher->update(d, n);
        p.received += n;
    }
    void fail(Pending& p, ErrCode code, const std::string& msg) {
        p.tmp.discard();
        p.applier.reset();
        p.failed = true;
        err(code, msg);
    }

    bool on_data(const Data& d) {
        if (pending_.empty()) {
            err(ErrCode::BadRequest, "DATA without OFFER");
            return false;
        }
        Pending& p = *pending_.front();
        if (p.failed) return true;
        try {
            if (p.is_delta) throw OpError(ErrCode::BadRequest, "DATA during a delta transfer");
            if (d.seq != p.next_seq) throw OpError(ErrCode::BadRequest, "bad sequence number");
            p.next_seq++;
            if (d.flags & ~kDataLz4) throw OpError(ErrCode::BadRequest, "bad flags");
            if (d.flags & kDataLz4) {
                if (!(caps_ & kCapLz4)) throw OpError(ErrCode::Unsupported, "compression not negotiated");
                size_t limit = size_t(std::min<uint64_t>(kMaxChunk, p.size - p.received));
                Bytes plain;
                try {
                    plain = lz4_decompress(d.bytes.data(), d.bytes.size(), limit);
                } catch (const Error&) {
                    throw OpError(ErrCode::BadRequest, "bad compressed data");
                }
                write_body(p, plain.data(), plain.size());
            } else {
                write_body(p, d.bytes.data(), d.bytes.size());
            }
        } catch (const OpError& e) {
            fail(p, e.code, e.what());
        } catch (const std::exception& e) {
            log_warn(std::string("receive failed: ") + e.what());
            fail(p, ErrCode::IoError, "i/o error");
        }
        return true;
    }

    bool on_delta(const DeltaOps& d) {
        if (pending_.empty()) {
            err(ErrCode::BadRequest, "DELTA_OPS without OFFER");
            return false;
        }
        Pending& p = *pending_.front();
        if (p.failed) return true;
        try {
            if (!p.is_delta) throw OpError(ErrCode::BadRequest, "DELTA_OPS without NEED_DELTA");
            ensure_started(p);
            if (!p.applier) p.applier = std::make_unique<delta::DeltaApplier>(p.old_path, p.block_size);
            auto sink = [&](const void* data, size_t n) { write_body(p, data, n); };
            for (const auto& op : d.ops) p.applier->apply(op, sink);
        } catch (const OpError& e) {
            fail(p, e.code, e.what());
        } catch (const std::exception& e) {
            log_warn(std::string("delta failed: ") + e.what());
            fail(p, ErrCode::BadRequest, "bad delta");
        }
        return true;
    }

    bool on_end(const EndFile& e) {
        if (pending_.empty()) {
            err(ErrCode::BadRequest, "ENDFILE without OFFER");
            return false;
        }
        std::unique_ptr<Pending> p = std::move(pending_.front());
        pending_.pop_front();
        if (p->failed) return true;
        try {
            if (p->received != p->size) throw OpError(ErrCode::BadRequest, "size differs from the announced size");
            ensure_started(*p);
            Hash256 h = p->hasher->finish();
            bool a = ct_equal(h.data(), e.hash.data(), 32);
            bool b = ct_equal(h.data(), p->offer_hash.data(), 32);
            if (!(a && b)) throw OpError(ErrCode::HashMismatch, "hash mismatch");
            p->applier.reset();
            const int64_t mtime = std::max<int64_t>(0, p->mtime_ns);
            if (!p->tmp.sync_and_close(mtime, pol_->cfg.file_mode)) log_debug("cannot set modification time");
            // The previous content of an overwritten file goes to the trash first (rename, no copy).
            fs::path trashed;
            if (pol_->cfg.trash) {
                fio::StatInfo old = fio::stat_path(p->r.abs);
                if (old.exists && old.is_regular) trashed = trash_move(c_, pol_->cfg, p->r.abs, p->r.real);
            }
            std::error_code ec;
            fs::rename(p->tmp.path(), p->r.abs, ec);  // atomic replace; a directory at the destination fails here
            if (ec) {
                if (!trashed.empty()) {
                    std::error_code e2;
                    fs::rename(trashed, p->r.abs, e2);  // put the old version back
                }
                throw OpError(ErrCode::IoError, "cannot replace destination");
            }
            p->tmp.release();
            fio::StatInfo ns;
            ns.size = p->size;
            ns.mtime_ns = mtime;
            cache_put(p->r, ns, h);
            ok();
        } catch (const OpError& oe) {
            p->tmp.discard();
            err(oe.code, oe.what());
        } catch (const std::exception& ex) {
            p->tmp.discard();
            log_warn(std::string("commit failed: ") + ex.what());
            err(ErrCode::IoError, "i/o error");
        }
        return true;
    }

    // ---- DELETE / RENAME / MKDIR ----
    void require_rw() const {
        if (acl_.read_only) throw OpError(ErrCode::PathDenied, "read-only client");
    }

    void move_to_trash(const Resolved& r) { trash_move(c_, pol_->cfg, r.abs, r.real); }

    void on_delete(const Delete& d) {
        require_rw();
        Resolved r = resolve(d.path);
        fio::StatInfo st = fio::stat_path(r.abs);
        if (!st.exists) {
            ok();
            return;
        }
        if (pol_->cfg.trash) {
            move_to_trash(r);
        } else {
            std::error_code ec;
            if (st.is_dir) fs::remove_all(r.abs, ec);
            else fs::remove(r.abs, ec);
            if (ec) throw OpError(ErrCode::IoError, "cannot delete");
        }
        {
            std::lock_guard<std::mutex> lk(tree_->m);
            tree_->cache.erase(r.vrel);
        }
        ok();
    }

    void on_rename(const Rename& rn) {
        require_rw();
        Resolved from = resolve(rn.from), to = resolve(rn.to);
        fio::StatInfo sf = fio::stat_path(from.abs);
        if (!sf.exists) throw OpError(ErrCode::NotFound, "source not found");
        if (from.real != to.real) {
            fio::StatInfo stt = fio::stat_path(to.abs);
            if (stt.exists) {
                if (stt.is_dir || sf.is_dir || stt.is_symlink)
                    throw OpError(ErrCode::IoError, "destination exists");
                if (pol_->cfg.trash) move_to_trash(to);
            }
            std::error_code ec;
            fio::create_dirs(to.abs.parent_path(), pol_->cfg.dir_mode, ec);
            if (ec) throw OpError(ErrCode::IoError, "cannot create directory");
            recheck(to);
            fs::rename(from.abs, to.abs, ec);
            if (ec) throw OpError(ErrCode::IoError, "cannot rename");
            std::lock_guard<std::mutex> lk(tree_->m);
            tree_->cache.rename_prefix(from.vrel, to.vrel);
            tree_->dirty = true;
        }
        ok();
    }

    void on_mkdir(const Mkdir& k) {
        require_rw();
        Resolved r = resolve(k.path);
        fio::StatInfo st = fio::stat_path(r.abs);
        if (st.exists && !st.is_dir) throw OpError(ErrCode::IoError, "a file exists at this path");
        if (st.is_symlink) throw OpError(ErrCode::PathDenied, "symlink");
        std::error_code ec;
        fio::create_dirs(r.abs, pol_->cfg.dir_mode, ec);
        if (ec) throw OpError(ErrCode::IoError, "cannot create directory");
        recheck(r);
        ok();
    }

    // ---- LIST ----
    void on_list(const ListReq& l) {
        std::string lp = normalize_rel(l.prefix);
        while (!lp.empty() && lp.back() == '/') lp.pop_back();
        fs::path scan_root;
        std::string key;
        if (lp.empty()) {
            key = prefix_;
            scan_root = prefix_.empty() ? u8(c_.root) : safe_join(c_.root, prefix_);
        } else {
            Resolved r = resolve(lp);
            key = r.real;
            scan_root = r.abs;
        }
        std::error_code ec;
        if (!fs::is_directory(scan_root, ec)) {
            send(ListEnd{0});
            return;
        }
        std::shared_ptr<Tree> t = (key == prefix_) ? tree_ : c_.tree_for(key);
        std::vector<FileMeta> metas;
        {
            std::lock_guard<std::mutex> lk(t->m);
            metas = scan_tree(scan_root.u8string(), Filter(), t->cache, 0);
            t->dirty = true;
        }
        c_.save_tree(*t, false);
        uint64_t count = 0;
        for (const auto& m : metas) {
            if (is_internal_dir(m.rel) || has_tmp_component(m.rel)) continue;
            ListEntry e;
            e.path = m.rel;
            e.size = m.size;
            e.mtime_ns = m.mtime_ns;
            e.hash = m.hash;
            e.is_dir = m.is_dir;
            send(e);
            count++;
        }
        send(ListEnd{count});
    }
};

void session_main(ServerCore& c, net::Socket sock, const std::string& ip, SessRec& rec, std::atomic<bool>& stop) {
    struct Done {
        SessRec& rec;
        ~Done() { rec.done = true; }
    } done{rec};
    // Holds one place of the "not yet authenticated" budget until the handshake is over (either way).
    struct Unauth {
        ServerCore& c;
        std::string key;
        bool held = true;
        void release() {
            if (held) c.unauth_release(key);
            held = false;
        }
        ~Unauth() { release(); }
    } unauth{c, throttle_key(ip)};

    std::optional<SecureChannel> ch;
    int idx = -1;
    std::shared_ptr<const Policy> pol = c.policy();  // fixed for this session, whatever a reload does meanwhile
    try {
        ch.emplace(SecureChannel::server(std::move(sock), c.key, [&](const PubKey& k) {
            int found = -1;
            for (size_t i = 0; i < pol->cfg.clients.size(); i++) {  // no early exit: time does not reveal the position
                bool eq = ct_equal(k.data(), pol->cfg.clients[i].public_key.data(), 32);
                if (eq && found < 0) found = int(i);
            }
            idx = found;
            return found >= 0;
        }));
    } catch (const std::exception&) {  // refused, torn, or out of time: all count against the source
        unauth.release();
        c.thr.record_failure(ip, steady_ms());
        log_warn("authentication failed from " + ip);
        return;
    }
    // The unauthenticated place is kept until a valid HELLO arrives: only then does the connection count
    // against max_connections / max_sessions.
    ClientState& cs = *pol->cstate[size_t(idx)];
    const ClientAcl& acl = pol->cfg.clients[size_t(idx)];
    std::optional<Session> sess;
    try {
        ch->socket().set_timeouts(kHelloTimeoutMs, kHelloTimeoutMs);
        {
            std::lock_guard<std::mutex> lk(rec.m);
            rec.sock = &ch->socket();
        }
        struct Unreg {
            SessRec& rec;
            ~Unreg() {
                std::lock_guard<std::mutex> lk(rec.m);
                rec.sock = nullptr;
            }
        } unreg{rec};
        if (stop.load()) return;
        sess.emplace(c, *ch, acl, ip, cs, pol);
        if (!sess->read_hello()) return;
        unauth.release();
        if (!c.session_acquire()) {
            log_warn("too many connections; refusing " + ip);
            return;
        }
        struct Active {
            ServerCore& c;
            ~Active() { c.active--; }
        } active{c};
        struct Slot {
            ClientState& cs;
            bool held = false;
            ~Slot() {
                if (held) cs.sessions--;
            }
        } slot{cs};
        if (acl.max_sessions && cs.sessions.fetch_add(1) >= int(acl.max_sessions)) {
            cs.sessions--;
            log_warn("client '" + acl.name + "' already has " + std::to_string(acl.max_sessions) +
                     " sessions (max_sessions); refusing " + ip);
            try {
                ch->send_msg(encode(FileErr{ErrCode::Busy, "too many sessions for this client (max_sessions)"}));
            } catch (const std::exception&) {
            }
            return;
        }
        slot.held = acl.max_sessions != 0;
        sess->serve();
    } catch (const std::exception& e) {
        if (!stop.load()) {
            if (sess && sess->hello_pending()) {
                c.thr.record_failure(ip, steady_ms());
                log_warn("no valid HELLO from " + ip + ": " + e.what());
            } else {
                log_debug("session from " + ip + " ended: " + e.what());
            }
        }
    }
}

}  // namespace

// ---------------------------------------------------------------- Server

Server::Server(ServerConfig cfg) {
    KeyPair kp = key_from_file(cfg.key_file);
    p_ = std::make_unique<detail::ServerCore>(std::move(cfg), kp);
}

Server::Server(ServerConfig cfg, const KeyPair& key) : p_(std::make_unique<detail::ServerCore>(std::move(cfg), key)) {}

Server::~Server() = default;

uint16_t Server::port() const { return p_->lsock.local_port(); }

const PubKey& Server::public_key() const { return p_->key.pub; }

gui::StatusSnapshot Server::snapshot() const {
    ServerCore& c = *p_;
    std::shared_ptr<const detail::Policy> pol = c.policy();
    gui::StatusSnapshot s;
    s.role = gui::Role::Server;
    s.listen = c.cfg.bind + ":" + std::to_string(c.lsock.local_port());
    s.sessions = static_cast<uint32_t>(std::max(0, c.active.load()));
    s.max_connections = c.max_conn.load();
    s.total_rx_bps = c.rx_meter.update(c.total_rx.load());
    s.total_tx_bps = c.tx_meter.update(c.total_tx.load());
    for (size_t i = 0; i < pol->cfg.clients.size(); i++) {
        detail::ClientState& cs = *pol->cstate[i];
        gui::PeerStatus ps;
        ps.name = pol->cfg.clients[i].name;
        ps.sessions = static_cast<uint32_t>(std::max(0, cs.sessions.load()));
        ps.bytes_rx = cs.bytes_rx.load();
        ps.bytes_tx = cs.bytes_tx.load();
        ps.rx_bps = cs.rx_meter.update(ps.bytes_rx);
        ps.tx_bps = cs.tx_meter.update(ps.bytes_tx);
        s.peers.push_back(std::move(ps));
    }
    return s;
}

void Server::apply_config(const ServerConfig& n) {
    ServerCore& c = *p_;
    if (n.bind != c.cfg.bind || n.port != c.lsock.local_port())
        throw Error("changing bind / port needs a restart of the server (reload refused, the running configuration is unchanged)");
    if (n.root != c.cfg.root || n.key_file != c.cfg.key_file || n.state_dir != c.cfg.state_dir)
        throw Error("changing root / key_file / state_dir needs a restart of the server (reload refused, the running "
                    "configuration is unchanged)");
    std::shared_ptr<const detail::Policy> old = c.policy();
    auto np = std::make_shared<detail::Policy>(n);  // throws Error on a malformed allow / deny entry, nothing swapped yet
    for (const ClientAcl& a : n.clients) {
        std::shared_ptr<detail::ClientState> reuse;
        for (size_t i = 0; i < old->cfg.clients.size(); i++) {
            const ClientAcl& o = old->cfg.clients[i];
            if (o.public_key == a.public_key && old->cstate[i]->quota_limit == a.max_write_bytes_per_hour &&
                old->cstate[i]->kbps == a.max_bandwidth_kbps)
                reuse = old->cstate[i];
        }
        np->cstate.push_back(reuse ? reuse
                                   : std::make_shared<detail::ClientState>(a.max_write_bytes_per_hour, a.max_bandwidth_kbps));
    }
    if (old->cfg.max_bandwidth_kbps == n.max_bandwidth_kbps) np->total_bw = old->total_bw;
    {
        std::lock_guard<std::mutex> lk(c.pm);
        c.pol = np;
    }
    c.max_conn = n.max_connections;
    c.thr.set_max(n.max_auth_failures_per_min);
}

void Server::run(std::atomic<bool>& stop) {
    ServerCore& c = *p_;
    c.stop_flag = &stop;
    std::vector<std::unique_ptr<SessRec>> recs;
    auto reap = [&] {
        for (auto it = recs.begin(); it != recs.end();) {
            if ((*it)->done.load()) {
                (*it)->th.join();
                it = recs.erase(it);
            } else {
                ++it;
            }
        }
    };
    log_info("server listening on port " + std::to_string(c.lsock.local_port()));
    while (!stop.load()) {
        reap();
        std::string ip;
        net::Socket s;
        try {
            s = c.lsock.accept(200, &ip);
        } catch (const std::exception& e) {
            log_error(std::string("accept failed: ") + e.what());
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        if (!s.valid()) continue;
        ip = norm_ip(ip);
        if (!c.policy()->ipf.permits(ip)) {
            log_warn("connection from " + ip + " refused by access list");
            continue;
        }
        if (c.thr.blocked(ip, steady_ms())) {
            log_debug("connection from " + ip + " refused: too many failed authentications");
            continue;
        }
        if (!c.unauth_acquire(throttle_key(ip))) {
            log_warn("too many unauthenticated connections; refusing " + ip);
            continue;
        }
        auto rec = std::make_unique<SessRec>();
        SessRec* rp = rec.get();
        try {
            rec->th = std::thread([&c, sk = std::move(s), ip, rp, &stop]() mutable {
                session_main(c, std::move(sk), ip, *rp, stop);
            });
        } catch (const std::exception& e) {
            c.unauth_release(throttle_key(ip));
            log_error(std::string("cannot start session thread: ") + e.what());
            continue;
        }
        recs.push_back(std::move(rec));
    }
    for (auto& r : recs) {
        std::lock_guard<std::mutex> lk(r->m);
        if (r->sock) wake(*r->sock);
    }
    for (auto& r : recs) {
        // a session registering its socket right now sees `stop` and leaves; keep nudging until it is done
        while (!r->done.load()) {
            {
                std::lock_guard<std::mutex> lk(r->m);
                if (r->sock) wake(*r->sock);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        r->th.join();
    }
    c.save_all();
}

}  // namespace mysync
