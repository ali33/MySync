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

// Wakes a thread blocked in recv/send on `s`. shutdown() alone does not wake a blocked recv on accepted Winsock
// sockets (observed), so Windows also closes the handle; the owning thread then fails with an Error.
void wake(net::Socket& s) {
    s.shutdown_both();
#ifdef _WIN32
    s.close();
#endif
}

// True when any '/'-separated component is one of our temp files (clients must not address them).
bool has_tmp_component(const std::string& rel) {
    const std::string pre = fio::kTmpPrefix;
    size_t pos = 0;
    while (pos <= rel.size()) {
        size_t e = rel.find('/', pos);
        if (e == std::string::npos) e = rel.size();
        if (lower(rel.substr(pos, std::min(pre.size(), e - pos))) == pre) return true;
        pos = e + 1;
    }
    return false;
}

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

bool AuthThrottle::blocked(const std::string& ip, int64_t now_ms) {
    if (max_ == 0) return false;
    std::lock_guard<std::mutex> lk(m_);
    auto it = fails_.find(ip);
    if (it == fails_.end()) return false;
    auto& q = it->second;
    while (!q.empty() && now_ms - q.front() >= 60000) q.pop_front();
    if (q.empty()) {
        fails_.erase(it);
        return false;
    }
    return q.size() >= max_;
}

void AuthThrottle::record_failure(const std::string& ip, int64_t now_ms) {
    if (max_ == 0) return;
    std::lock_guard<std::mutex> lk(m_);
    if (fails_.size() > 4096) {  // sweep so a scan from many addresses cannot grow memory without bound
        for (auto it = fails_.begin(); it != fails_.end();) {
            while (!it->second.empty() && now_ms - it->second.front() >= 60000) it->second.pop_front();
            it = it->second.empty() ? fails_.erase(it) : std::next(it);
        }
    }
    auto& q = fails_[ip];
    q.push_back(now_ms);
    while (q.size() > size_t(max_) + 8) q.pop_front();
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

struct ServerCore {
    ServerConfig cfg;
    KeyPair key;
    IpFilter ipf;
    AuthThrottle thr;
    net::Socket lsock;
    std::string root;
    fs::path state_dir;
    std::mutex tm;
    std::map<std::string, std::shared_ptr<Tree>> trees;
    std::atomic<int> active{0};

    ServerCore(ServerConfig c, const KeyPair& k)
        : cfg(std::move(c)), key(k), ipf(cfg.allow, cfg.deny), thr(cfg.max_auth_failures_per_min) {
        if (cfg.root.empty()) throw Error("server root is not set");
        net::init();
        std::error_code ec;
        fs::create_directories(u8(cfg.root), ec);
        if (!fs::is_directory(u8(cfg.root), ec)) throw Error("server root is not a directory");
        root = fs::weakly_canonical(u8(cfg.root), ec).u8string();
        if (ec) throw Error("cannot resolve server root");
        state_dir = cfg.state_dir.empty() ? (u8(root) / "__sync" / "__meta") : u8(cfg.state_dir);
        fs::create_directories(state_dir, ec);
        if (ec) throw Error("cannot create state directory");
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

using detail::ServerCore;
using detail::SessRec;
using detail::Tree;

// A failure with a protocol error code that is reported to the client as FILE_ERR.
struct OpError : Error {
    ErrCode code;
    OpError(ErrCode c, const std::string& m) : Error(m), code(c) {}
};

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
    Session(ServerCore& c, SecureChannel& ch, const ClientAcl& acl, std::string ip)
        : c_(c), ch_(ch), acl_(acl), ip_(std::move(ip)) {}

    void run() {
        prefix_ = normalize_rel(acl_.prefix);
        while (!prefix_.empty() && prefix_.back() == '/') prefix_.pop_back();
        if (!prefix_.empty()) {
            if (is_internal_dir(prefix_)) throw Error("client prefix points into the internal directory");
            fs::path p = safe_join(c_.root, prefix_);  // throws on a malicious prefix: session refused
            std::error_code ec;
            fs::create_directories(p, ec);
        }
        tree_ = c_.tree_for(prefix_);

        Message first = decode(ch_.recv_msg());
        const Hello* h = std::get_if<Hello>(&first);
        if (!h) {
            send(FileErr{ErrCode::BadRequest, "HELLO expected"});
            return;
        }
        if (h->proto_ver != kProtoVersion) {
            send(FileErr{ErrCode::Unsupported, "unsupported protocol version"});
            return;
        }
        caps_ = h->caps & (kCapLz4 | kCapDelta);
        send(HelloOk{kCapLz4 | kCapDelta, kDefaultMaxChunk});
        log_info("client '" + acl_.name + "' connected from " + ip_);

        for (;;) {
            Message m = decode(ch_.recv_msg());
            if (!dispatch(m)) break;
        }
        c_.save_tree(*tree_, false);
    }

private:
    ServerCore& c_;
    SecureChannel& ch_;
    const ClientAcl& acl_;
    std::string ip_;
    std::string prefix_;
    std::shared_ptr<Tree> tree_;
    uint32_t caps_ = 0;
    std::deque<std::unique_ptr<Pending>> pending_;

    void send(const Message& m) { ch_.send_msg(encode(m)); }
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
        if (c_.cfg.max_file_size && o.size > c_.cfg.max_file_size) throw OpError(ErrCode::TooLarge, "file too large");
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
            fs::create_directories(dir, ec);
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
            if (!p->tmp.sync_and_close(mtime)) log_debug("cannot set modification time");
            std::error_code ec;
            fs::rename(p->tmp.path(), p->r.abs, ec);  // atomic replace; a directory at the destination fails here
            if (ec) throw OpError(ErrCode::IoError, "cannot replace destination");
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

    void move_to_trash(const Resolved& r) {
        fs::path base = u8(c_.root) / "__sync" / "__trash" / utc_stamp() / u8(r.real);
        std::error_code ec;
        fs::create_directories(base.parent_path(), ec);
        if (ec) throw OpError(ErrCode::IoError, "cannot create trash directory");
        fs::path cand = base;
        for (int n = 1; fio::stat_path(cand).exists || fs::is_symlink(cand, ec); n++)
            cand = fs::path(base.u8string() + "-" + std::to_string(n));
        fs::rename(r.abs, cand, ec);
        if (ec) throw OpError(ErrCode::IoError, "cannot move to trash");
    }

    void on_delete(const Delete& d) {
        require_rw();
        Resolved r = resolve(d.path);
        fio::StatInfo st = fio::stat_path(r.abs);
        if (!st.exists) {
            ok();
            return;
        }
        if (c_.cfg.trash) {
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
                if (c_.cfg.trash) move_to_trash(to);
            }
            std::error_code ec;
            fs::create_directories(to.abs.parent_path(), ec);
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
        fs::create_directories(r.abs, ec);
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
        ServerCore& c;
        SessRec& rec;
        ~Done() {
            c.active--;
            rec.done = true;
        }
    } done{c, rec};

    std::optional<SecureChannel> ch;
    int idx = -1;
    try {
        ch.emplace(SecureChannel::server(std::move(sock), c.key, [&](const PubKey& k) {
            int found = -1;
            for (size_t i = 0; i < c.cfg.clients.size(); i++) {  // no early exit: time does not reveal the position
                bool eq = ct_equal(k.data(), c.cfg.clients[i].public_key.data(), 32);
                if (eq && found < 0) found = int(i);
            }
            idx = found;
            return found >= 0;
        }));
    } catch (const std::exception&) {
        c.thr.record_failure(ip, steady_ms());
        log_warn("authentication failed from " + ip);
        return;
    }
    try {
        int to = int(c.cfg.io_timeout_s ? c.cfg.io_timeout_s : 60) * 1000;
        ch->socket().set_timeouts(to, to);
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
        Session s(c, *ch, c.cfg.clients[size_t(idx)], ip);
        s.run();
    } catch (const std::exception& e) {
        if (!stop.load()) log_debug("session from " + ip + " ended: " + e.what());
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

void Server::run(std::atomic<bool>& stop) {
    ServerCore& c = *p_;
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
        if (!c.ipf.permits(ip)) {
            log_warn("connection from " + ip + " refused by access list");
            continue;
        }
        if (c.thr.blocked(ip, steady_ms())) {
            log_debug("connection from " + ip + " refused: too many failed authentications");
            continue;
        }
        if (c.active.load() >= int(c.cfg.max_connections)) {
            log_warn("too many connections; refusing " + ip);
            continue;
        }
        c.active++;
        auto rec = std::make_unique<SessRec>();
        SessRec* rp = rec.get();
        try {
            rec->th = std::thread([&c, sk = std::move(s), ip, rp, &stop]() mutable {
                session_main(c, std::move(sk), ip, *rp, stop);
            });
        } catch (const std::exception& e) {
            c.active--;
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
