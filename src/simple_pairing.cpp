// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/pairing.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <deque>
#include <map>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include "monocypher.h"
#include "mysync/net.h"
#include "mysync/protocol.h"
#include "mysync/secure_channel.h"

namespace mysync::simple {
namespace {

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// ---- UTF-8
bool next_cp(const std::string& s, size_t& i, uint32_t& cp) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (n == 0 || i + n > s.size()) return false;
    cp = n == 1 ? c : (c & (0xFFu >> (n + 1)));
    for (size_t k = 1; k < n; ++k) {
        unsigned char d = static_cast<unsigned char>(s[i + k]);
        if ((d & 0xC0) != 0x80) return false;
        cp = (cp << 6) | (d & 0x3F);
    }
    i += n;
    return true;
}

bool forbidden_cp(uint32_t cp) {
    if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return true;             // controls
    if (cp >= 0x200B && cp <= 0x200F) return true;                       // zero width, direction marks
    if (cp >= 0x2028 && cp <= 0x202E) return true;                       // line / paragraph separators, bidi embeds
    if (cp >= 0x2060 && cp <= 0x206F) return true;                       // word joiner, isolates, invisible operators
    if (cp == 0xFEFF || cp == 0x00AD || cp == 0x061C || cp == 0x180E) return true;
    if (cp >= 0xD800 && cp <= 0xDFFF) return true;
    if (cp >= 0xFFF0 && cp <= 0xFFFF) return true;                       // specials, noncharacters
    if (cp >= 0xE0000 && cp <= 0xE007F) return true;                     // tag characters
    if (cp > 0x10FFFF) return true;
    return false;
}

// Base ASCII letter for the Latin / Vietnamese letters we can transliterate (both cases map to lower case).
const std::map<uint32_t, char>& translit() {
    static const std::map<uint32_t, char> m = [] {
        std::map<uint32_t, char> t;
        struct G { char base; const char* letters; };
        static const G groups[] = {
            {'a', "aAàÀáÁạẠảẢãÃâÂầẦấẤậẬẩẨẫẪăĂằẰắẮặẶẳẲẵẴäÄåÅ"},
            {'d', "dDđĐ"},
            {'e', "eEèÈéÉẹẸẻẺẽẼêÊềỀếẾệỆểỂễỄëË"},
            {'i', "iIìÌíÍịỊỉỈĩĨïÏ"},
            {'o', "oOòÒóÓọỌỏỎõÕôÔồỒốỐộỘổỔỗỖơƠờỜớỚợỢởỞỡỠöÖ"},
            {'u', "uUùÙúÚụỤủỦũŨưƯừỪứỨựỰửỬữỮüÜ"},
            {'y', "yYỳỲýÝỵỴỷỶỹỸ"},
            {'c', "cCçÇ"},
            {'n', "nNñÑ"},
        };
        for (const G& g : groups) {
            std::string s = g.letters;
            for (size_t i = 0; i < s.size();) {
                uint32_t cp = 0;
                if (!next_cp(s, i, cp)) break;
                t[cp] = g.base;
            }
        }
        return t;
    }();
    return m;
}

}  // namespace

// ============================================================================================ wire
bool is_pair_wire(const Bytes& b) { return !b.empty() && b[0] >= 0x40; }

Bytes encode_pair_wire(const PairWire& m) {
    proto::Writer w;
    w.u8(uint8_t(m.type));
    switch (m.type) {
        case PairMsg::Request:
            w.str(m.name);
            w.raw(m.token.data(), m.token.size());
            break;
        case PairMsg::Wait: w.u32(m.seconds_left); break;
        case PairMsg::Error: w.u32(m.seconds_left); break;  // reason: 0 generic, 1 expired
        default: break;
    }
    return w.take();
}

PairWire decode_pair_wire(const Bytes& b) {
    proto::Reader r(b);
    PairWire m;
    uint8_t t = r.u8();
    switch (t) {
        case uint8_t(PairMsg::Request):
            m.type = PairMsg::Request;
            m.name = r.str();
            r.raw(m.token.data(), m.token.size());
            break;
        case uint8_t(PairMsg::Poll): m.type = PairMsg::Poll; break;
        case uint8_t(PairMsg::Wait): m.type = PairMsg::Wait; m.seconds_left = r.u32(); break;
        case uint8_t(PairMsg::Ok): m.type = PairMsg::Ok; break;
        case uint8_t(PairMsg::Denied): m.type = PairMsg::Denied; break;
        case uint8_t(PairMsg::Busy): m.type = PairMsg::Busy; break;
        case uint8_t(PairMsg::Error): m.type = PairMsg::Error; m.seconds_left = r.u32(); break;
        default: throw Error("unknown pairing message");
    }
    r.expect_end();
    return m;
}

std::string clean_display_name(const std::string& name) {
    if (name.size() > kPairNameMaxChars * 4 || !proto::valid_utf8(name)) return {};
    size_t b = 0, e = name.size();
    while (b < e && name[b] == ' ') ++b;
    while (e > b && name[e - 1] == ' ') --e;
    std::string t = name.substr(b, e - b);
    if (t.empty()) return {};
    size_t chars = 0;
    for (size_t i = 0; i < t.size();) {
        uint32_t cp = 0;
        if (!next_cp(t, i, cp) || forbidden_cp(cp)) return {};
        if (++chars > kPairNameMaxChars) return {};
    }
    return t;
}

std::string safe_pair_prefix(const std::string& display_name, const std::set<std::string>& existing) {
    std::string body;
    for (size_t i = 0; i < display_name.size();) {
        uint32_t cp = 0;
        if (!next_cp(display_name, i, cp)) break;
        char c = '-';
        if (cp < 0x80) {
            if (cp >= 'A' && cp <= 'Z') c = char(cp - 'A' + 'a');
            else if ((cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '_') c = char(cp);
            else if (cp == '.' || cp == '-') c = char(cp);
        } else {
            auto it = translit().find(cp);
            if (it != translit().end()) c = it->second;
        }
        if (c == '-' && !body.empty() && body.back() == '-') continue;
        body += c;
    }
    auto trim = [](std::string& s) {
        while (!s.empty() && (s.back() == '-' || s.back() == '.')) s.pop_back();
        size_t k = 0;
        while (k < s.size() && (s[k] == '-' || s[k] == '.')) ++k;
        s.erase(0, k);
    };
    trim(body);
    while (body.find("..") != std::string::npos) body.erase(body.find(".."), 1);
    if (body.empty()) body = "device";
    if (body.size() > 40) { body.resize(40); trim(body); if (body.empty()) body = "device"; }
    std::string base = "from-" + body;
    auto taken = [&](const std::string& p) {
        for (const std::string& x : existing) {
            if (x.size() != p.size()) continue;
            bool eq = true;
            for (size_t k = 0; k < x.size(); ++k)
                if (std::tolower(static_cast<unsigned char>(x[k])) != std::tolower(static_cast<unsigned char>(p[k]))) { eq = false; break; }
            if (eq) return true;
        }
        return false;
    };
    std::string cand = base;
    for (int n = 2; taken(cand) && n < 10000; ++n) cand = base + "-" + std::to_string(n);
    return cand;
}

// ============================================================================================ manager
namespace {
struct Window {
    std::deque<int64_t> q;
    // Counts one event now; false when it would exceed `max` within `win_ms`.
    bool allow(int64_t now, size_t max, int64_t win_ms = 60000) {
        while (!q.empty() && now - q.front() >= win_ms) q.pop_front();
        if (q.size() >= max) return false;
        q.push_back(now);
        return true;
    }
    bool empty_after(int64_t now, int64_t win_ms = 60000) {
        while (!q.empty() && now - q.front() >= win_ms) q.pop_front();
        return q.empty();
    }
};
std::string key_str(const PubKey& k) { return std::string(reinterpret_cast<const char*>(k.data()), k.size()); }
}  // namespace

struct PairingManager::Impl {
    enum class St { Waiting, Approved, Denied };
    struct Req {
        uint32_t id = 0;
        std::string name;
        PubKey key{};
        std::string ip;
        int64_t expires = 0;       // Waiting: request deadline
        int64_t keep_until = 0;    // decided: how long the verdict stays available to a poll
        St st = St::Waiting;
    };

    PubKey server_pub;
    ClockMs clock;
    std::mutex m;
    std::mutex approve_mu;  // serialises approve / deny against each other (the handler runs outside `m`)
    ApproveFn on_approve;
    RevokeFn on_revoke;
    int64_t enabled_until = 0;   // 0 = off
    bool token_live = false;     // a one-time token exists and was not used yet
    Hash256 token_hash{};        // BLAKE2b of it (the token itself is never stored)
    uint32_t next_id = 1;
    std::vector<Req> reqs;
    std::map<std::string, int64_t> blocked;        // key -> until
    std::map<std::string, Window> ip_hs, ip_req;   // handshakes / requests per IP
    std::map<std::string, Window> key_req;         // requests per key
    Window global_hs, global_req;
    int active = 0;                       // unpaired sessions alive
    std::map<std::string, int> active_ip;

    int64_t now() const { return clock ? clock() : steady_ms(); }

    bool on_locked(int64_t t) const { return enabled_until != 0 && t < enabled_until; }

    // Switching off / the end of the window cancels what still WAITS. A verdict already given (approved: the peer is in
    // the allowlist) is kept for a while so the sender is told the truth instead of "expired".
    void drop_waiting() {
        reqs.erase(std::remove_if(reqs.begin(), reqs.end(), [](const Req& r) { return r.st == St::Waiting; }), reqs.end());
    }

    void purge(int64_t t) {
        if (enabled_until != 0 && t >= enabled_until) { enabled_until = 0; token_live = false; drop_waiting(); }
        reqs.erase(std::remove_if(reqs.begin(), reqs.end(),
                                  [&](const Req& r) { return r.st == St::Waiting ? t >= r.expires : t >= r.keep_until; }),
                   reqs.end());
        for (auto it = blocked.begin(); it != blocked.end();) it = t >= it->second ? blocked.erase(it) : std::next(it);
        // bound the tables
        for (auto* tbl : {&ip_hs, &ip_req, &key_req})
            for (auto it = tbl->begin(); it != tbl->end();) it = it->second.empty_after(t) ? tbl->erase(it) : std::next(it);
    }
    bool is_blocked(const PubKey& k, int64_t t) const {
        auto it = blocked.find(key_str(k));
        return it != blocked.end() && t < it->second;
    }
    void block(const PubKey& k, int64_t t) {
        if (blocked.size() > 1000) blocked.clear();  // bounded memory; worst case a blocked key may retry earlier
        blocked[key_str(k)] = t + int64_t(kPairDenyBlockSeconds) * 1000;
    }
    Req* find_key(const PubKey& k) {
        for (Req& r : reqs)
            if (ct_equal(r.key.data(), k.data(), 32)) return &r;
        return nullptr;
    }
    Req* find_id(uint32_t id) {
        for (Req& r : reqs)
            if (r.id == id) return &r;
        return nullptr;
    }
    static Bytes wire(PairMsg t, uint32_t n = 0) {
        PairWire w;
        w.type = t;
        w.seconds_left = n;
        return encode_pair_wire(w);
    }
    static uint32_t secs_left(int64_t deadline, int64_t t) { return deadline > t ? uint32_t((deadline - t + 999) / 1000) : 0; }
};

PairingManager::PairingManager(const PubKey& server_pub, ClockMs clock) : p_(std::make_shared<Impl>()) {
    p_->server_pub = server_pub;
    p_->clock = std::move(clock);
}

void PairingManager::set_revoke_handler(RevokeFn fn) {
    std::lock_guard<std::mutex> lk(p_->m);
    p_->on_revoke = std::move(fn);
}

void PairingManager::set_approve_handler(ApproveFn fn) {
    std::lock_guard<std::mutex> lk(p_->m);
    p_->on_approve = std::move(fn);
}

PairToken PairingManager::enable(int seconds) {
    if (seconds < 1) seconds = 1;
    if (seconds > kPairWindowSeconds) seconds = kPairWindowSeconds;
    PairToken tok{};
    random_bytes(tok.data(), tok.size());
    std::lock_guard<std::mutex> lk(p_->m);
    p_->enabled_until = p_->now() + int64_t(seconds) * 1000;
    crypto_blake2b(p_->token_hash.data(), 32, tok.data(), tok.size());
    p_->token_live = true;
    return tok;
}

void PairingManager::disable() {
    std::lock_guard<std::mutex> lk(p_->m);
    p_->enabled_until = 0;
    p_->token_live = false;
    secure_wipe(p_->token_hash.data(), 32);
    p_->drop_waiting();
}

bool PairingManager::enabled() const {
    std::lock_guard<std::mutex> lk(p_->m);
    p_->purge(p_->now());
    return p_->enabled_until != 0;
}

int PairingManager::seconds_left() const {
    std::lock_guard<std::mutex> lk(p_->m);
    int64_t t = p_->now();
    p_->purge(t);
    return p_->enabled_until == 0 ? 0 : int(Impl::secs_left(p_->enabled_until, t));
}

std::vector<PendingPair> PairingManager::pending() const {
    std::lock_guard<std::mutex> lk(p_->m);
    int64_t t = p_->now();
    p_->purge(t);
    std::vector<PendingPair> out;
    if (p_->enabled_until == 0) return out;
    for (const auto& r : p_->reqs) {
        if (r.st != Impl::St::Waiting) continue;
        PendingPair pp;
        pp.id = r.id;
        pp.name = r.name;
        pp.key = r.key;
        pp.sas = pair_sas(r.key, p_->server_pub);
        pp.ip = r.ip;
        pp.seconds_left = int(Impl::secs_left(r.expires, t));
        out.push_back(pp);
    }
    return out;
}

std::string PairingManager::approve(uint32_t id) {
    std::lock_guard<std::mutex> ap(p_->approve_mu);
    std::string name;
    PubKey key{};
    ApproveFn fn;
    {
        std::lock_guard<std::mutex> lk(p_->m);
        int64_t t = p_->now();
        p_->purge(t);
        Impl::Req* r = p_->find_id(id);
        if (p_->enabled_until == 0 || !r || r->st != Impl::St::Waiting)
            throw Error("this pairing request no longer exists (it expired or pairing was switched off)");
        name = r->name;
        key = r->key;
        fn = p_->on_approve;
    }
    if (!fn) throw Error("pairing is not available");
    std::string prefix = fn(name, key);  // adds the client to the allowlist; throws to refuse
    std::lock_guard<std::mutex> lk(p_->m);
    int64_t t = p_->now();
    if (Impl::Req* r = p_->find_id(id)) {
        r->st = Impl::St::Approved;
        r->keep_until = t + 30000;
    } else {
        // The window closed while the peer was being written: it IS in the allowlist now, so the sender is told so.
        Impl::Req done;
        done.id = id;
        done.name = name;
        done.key = key;
        done.st = Impl::St::Approved;
        done.keep_until = t + 30000;
        p_->reqs.push_back(done);
    }
    return prefix;
}

void PairingManager::deny(uint32_t id) {
    std::lock_guard<std::mutex> ap(p_->approve_mu);
    PubKey key{};
    RevokeFn revoke;
    {
        std::lock_guard<std::mutex> lk(p_->m);
        int64_t t = p_->now();
        p_->purge(t);
        Impl::Req* r = p_->find_id(id);
        if (!r || r->st != Impl::St::Waiting) throw Error("this pairing request no longer exists");
        r->st = Impl::St::Denied;
        r->keep_until = t + 30000;
        p_->block(r->key, t);  // the same key cannot ask again for a while
        key = r->key;
        revoke = p_->on_revoke;
    }
    // Whatever an earlier, half-failed approval may have left in the allowlist goes now, with its open sessions.
    if (revoke) {
        try {
            revoke(key);
        } catch (const std::exception& e) {
            log_error(std::string("could not make sure a denied computer is not in the allowlist: ") + e.what());
        }
    }
}

bool PairingManager::admit_handshake(const std::string& ip, const PubKey& key) {
    std::lock_guard<std::mutex> lk(p_->m);
    int64_t t = p_->now();
    p_->purge(t);
    if (p_->enabled_until == 0 || !p_->token_live || p_->is_blocked(key, t)) return false;
    if (!p_->ip_hs[ip].allow(t, 12)) return false;       // 12 handshakes / minute / IP
    if (!p_->global_hs.allow(t, 40)) return false;       // 40 / minute overall
    // Unpaired sessions get a small budget of their own, so they can never crowd out the normal connections.
    int& per_ip = p_->active_ip[ip];
    if (p_->active >= kPairMaxSessions || per_ip >= kPairMaxSessionsPerIp) return false;
    ++p_->active;
    ++per_ip;
    return true;
}

void PairingManager::session_ended(const std::string& ip) {
    std::lock_guard<std::mutex> lk(p_->m);
    auto it = p_->active_ip.find(ip);
    if (it != p_->active_ip.end() && --it->second <= 0) p_->active_ip.erase(it);
    if (p_->active > 0) --p_->active;
}

PairingManager::Reply PairingManager::on_message(const std::string& ip, const PubKey& key, const Bytes& raw) {
    Reply rep;
    auto fail = [&](uint32_t reason = 0) {
        rep.msg = Impl::wire(PairMsg::Error, reason);
        rep.close = true;
        return rep;
    };
    try {
        // BYE of the normal protocol (one byte, type 20): leave quietly. Anything else outside the pairing range is
        // refused: an unpaired session may not say HELLO / OFFER / LIST ... nor anything else.
        if (raw.size() == 1 && raw[0] == uint8_t(proto::MsgType::Bye)) {
            rep.close = true;
            return rep;
        }
        if (!is_pair_wire(raw)) return fail();
        PairWire in = decode_pair_wire(raw);
        std::lock_guard<std::mutex> lk(p_->m);
        int64_t t = p_->now();
        p_->purge(t);
        {   // with the mode off only a verdict that was already given can still be collected
            Impl::Req* ex = p_->find_key(key);
            if (p_->enabled_until == 0 && !(ex && ex->st != Impl::St::Waiting)) return fail();
        }
        if (in.type == PairMsg::Poll) {
            Impl::Req* r = p_->find_key(key);
            if (!r) return fail(1);  // expired (or never asked)
            if (r->st == Impl::St::Approved) { rep.msg = Impl::wire(PairMsg::Ok); rep.close = true; return rep; }
            if (r->st == Impl::St::Denied) { rep.msg = Impl::wire(PairMsg::Denied); rep.close = true; return rep; }
            rep.msg = Impl::wire(PairMsg::Wait, Impl::secs_left(r->expires, t));
            return rep;
        }
        if (in.type != PairMsg::Request) return fail();
        if (Impl::Req* r0 = p_->find_key(key)) {  // the same key coming back: resume (the token was spent by its first request)
            if (r0->st == Impl::St::Approved) { rep.msg = Impl::wire(PairMsg::Ok); rep.close = true; return rep; }
            if (r0->st == Impl::St::Denied) { rep.msg = Impl::wire(PairMsg::Denied); rep.close = true; return rep; }
            rep.msg = Impl::wire(PairMsg::Wait, Impl::secs_left(r0->expires, t));
            return rep;
        }
        // A new request must prove it was handed the code: the one-time token, compared in constant time on hashes.
        {
            Hash256 h{};
            crypto_blake2b(h.data(), 32, in.token.data(), in.token.size());
            bool ok = p_->token_live && ct_equal(h.data(), p_->token_hash.data(), 32);
            if (!ok) return fail();  // counted by the session as a failed authentication; nothing is said about why
        }
        std::string name = clean_display_name(in.name);
        if (name.empty()) return fail();
        if (Impl::Req* r = p_->find_key(key)) {  // the same key coming back: resume, not a new request
            if (r->st == Impl::St::Approved) { rep.msg = Impl::wire(PairMsg::Ok); rep.close = true; return rep; }
            if (r->st == Impl::St::Denied) { rep.msg = Impl::wire(PairMsg::Denied); rep.close = true; return rep; }
            rep.msg = Impl::wire(PairMsg::Wait, Impl::secs_left(r->expires, t));
            return rep;
        }
        if (p_->is_blocked(key, t)) return fail();  // a new request from a blocked key
        // Rate limits count every NEW request, answered or not.
        if (!p_->key_req[key_str(key)].allow(t, 4)) {  // a key that keeps asking is abusive: block it
            p_->block(key, t);
            return fail();
        }
        bool ip_ok = p_->ip_req[ip].allow(t, size_t(kPairRequestsPerIpPerMin));
        bool gl_ok = ip_ok && p_->global_req.allow(t, size_t(kPairRequestsGlobalPerMin));
        if (!ip_ok || !gl_ok) { rep.msg = Impl::wire(PairMsg::Busy); rep.close = true; return rep; }
        for (const auto& r : p_->reqs)
            if (r.st == Impl::St::Waiting) { rep.msg = Impl::wire(PairMsg::Busy); rep.close = true; return rep; }
        Impl::Req r;
        r.id = p_->next_id++;
        r.name = name;
        r.key = key;
        r.ip = ip;
        r.expires = t + int64_t(kPairRequestTtlSeconds) * 1000;
        p_->reqs.push_back(r);
        p_->token_live = false;  // one use only: granted, denied or expired, this token is gone
        secure_wipe(p_->token_hash.data(), 32);
        log_info("pairing request from '" + name + "' (" + ip + ") is waiting for approval");
        rep.msg = Impl::wire(PairMsg::Wait, uint32_t(kPairRequestTtlSeconds));
        return rep;
    } catch (const std::exception&) {
        return fail();
    }
}

// ============================================================================================ sender
std::string default_device_name() {
    char buf[256] = {};
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    if (::gethostname(buf, sizeof buf - 1) != 0) buf[0] = 0;
    std::string n = clean_display_name(buf);
    return n.empty() ? "MySync" : n;
}

PairingClient::PairingClient(const PairCode& code, const KeyPair& self, const std::string& display_name)
    : code_(code), self_(self), name_(clean_display_name(display_name)) {
    if (name_.empty()) throw Error("the name of this computer cannot be used for pairing (empty, too long or has control characters)");
}

std::string PairingClient::sas() const { return pair_sas(self_.pub, code_.server_key); }

PairOutcome PairingClient::run(const std::atomic<bool>& cancel, const std::function<void(int)>& progress, int timeout_s) {
    auto out = [](PairOutcome::Kind k, const char* msg) { PairOutcome o; o.kind = k; o.message = msg; return o; };
    try {
        net::init();
        const int64_t deadline = steady_ms() + int64_t(timeout_s) * 1000;
        net::Socket s = net::Socket::connect(code_.host, code_.port, 10000);
        // Pinned to the key from the code: a different machine on that address fails the handshake.
        SecureChannel ch = SecureChannel::client(std::move(s), self_, code_.server_key);
        ch.socket().set_timeouts(15000, 15000);
        PairWire req;
        req.type = PairMsg::Request;
        req.name = name_;
        req.token = code_.token;
        ch.send_msg(encode_pair_wire(req));
        for (;;) {
            if (cancel.load()) {
                try { ch.send_msg(Bytes{uint8_t(proto::MsgType::Bye)}); } catch (const std::exception&) {}
                return out(PairOutcome::Cancelled, "cancelled");
            }
            if (steady_ms() >= deadline) return out(PairOutcome::Expired, "no answer in time");
            // The answer to the request (first iteration) or to the previous poll.
            PairWire a = decode_pair_wire(ch.recv_msg_within(20000));
            switch (a.type) {
                case PairMsg::Ok: return out(PairOutcome::Approved, "approved");
                case PairMsg::Denied: return out(PairOutcome::Denied, "the other computer refused");
                case PairMsg::Busy: return out(PairOutcome::Busy, "the other computer is busy with another request; try again in a minute");
                case PairMsg::Error:
                    return a.seconds_left == 1 ? out(PairOutcome::Expired, "the request expired")
                                               : out(PairOutcome::Failed, "the other computer did not accept the pairing");
                case PairMsg::Wait: if (progress) progress(int(a.seconds_left)); break;
                default: return out(PairOutcome::Failed, "unexpected answer");
            }
            for (int i = 0; i < 20 && !cancel.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            PairWire poll;
            poll.type = PairMsg::Poll;
            ch.send_msg(encode_pair_wire(poll));
        }
    } catch (const std::exception&) {
        // One generic text: the reason (wrong key, nobody listening, timeout) is deliberately not told apart.
        return out(PairOutcome::Failed,
                   "could not pair: the other computer is not reachable, pairing mode is off, or the code is not for it");
    }
}

}  // namespace mysync::simple
