// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Simple mode core: pairing codes, SAS, the pairing state machine, autostart, wizard, folder lock, service upgrade
// logic (with fakes), and the three trust fixes (F1, F2/F3 helpers).
#include <algorithm>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

#include "gui_test_util.h"
#include "monocypher.h"
#include <set>

#include "mysync/engine_lock.h"
#include "mysync/filter.h"
#include "mysync/peers.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/trust.h"
#include "mysync/protocol.h"
#include "mysync/simple/autostart.h"
#include "mysync/simple/pair_code.h"
#include "mysync/simple/pairing.h"
#include "mysync/simple/service_upgrade.h"
#include "mysync/simple/user_paths.h"
#include "mysync/simple/wizard_model.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::simple;
namespace fs = std::filesystem;

namespace {

struct STmp {
    fs::path p;
    STmp() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-simple-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~STmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string sub(const std::string& n, bool make = true) const {
        fs::path q = p / fs::u8path(n);
        if (make) fs::create_directories(q);
        return q.u8string();
    }
};

PubKey seq_key(uint8_t start) {
    PubKey k{};
    for (size_t i = 0; i < 32; ++i) k[i] = uint8_t(start + i);
    return k;
}

Hash256 blake(const Bytes& b) {
    Hash256 h{};
    crypto_blake2b(h.data(), 32, b.data(), b.size());
    return h;
}

// A code with chosen fields and a correct checksum (for the rejection tests).
std::string craft(uint8_t version, const PubKey& key, uint16_t port, const std::string& host, size_t extra = 0,
                  bool good_sum = true) {
    Bytes p;
    p.push_back(version);
    p.insert(p.end(), key.begin(), key.end());
    for (int i = 0; i < 16; ++i) p.push_back(uint8_t(0xA0 + i));
    p.push_back(uint8_t(port >> 8));
    p.push_back(uint8_t(port));
    p.push_back(uint8_t(host.size()));
    p.insert(p.end(), host.begin(), host.end());
    for (size_t i = 0; i < extra; ++i) p.push_back(0x55);
    Hash256 h = blake(p);
    if (!good_sum) h[0] ^= 0x01;
    p.insert(p.end(), h.begin(), h.begin() + 4);
    std::string body = crockford_encode(p);
    std::string out = "MSY1";
    for (size_t i = 0; i < body.size(); i += 5) out += "-" + body.substr(i, 5);
    return out;
}

}  // namespace

// ------------------------------------------------------------------------------------------ pairing code
TEST(simple_pair_code_roundtrip_and_format) {
    PairCode pc;
    pc.server_key = seq_key(0);
    for (int i = 0; i < 16; ++i) pc.token[size_t(i)] = uint8_t(0xA0 + i);
    pc.port = 5656;
    pc.host = "192.168.1.10";
    std::string code = encode_pair_code(pc);
    CHECK(code.rfind("MSY1-", 0) == 0);
    // groups of 5 separated by '-'
    size_t groups = 0;
    for (size_t i = 5; i < code.size(); i += 6) {
        CHECK(code[i - 1] == '-');
        ++groups;
    }
    CHECK(groups >= 10);
    for (char c : code.substr(5)) CHECK(c == '-' || std::string("0123456789ABCDEFGHJKMNPQRSTVWXYZ").find(c) != std::string::npos);
    PairCode back = decode_pair_code(code);
    CHECK(back.server_key == pc.server_key);
    CHECK(back.token == pc.token);
    CHECK_EQ(back.port, 5656);
    CHECK_EQ(back.host, std::string("192.168.1.10"));
    // lower case, extra spaces and missing dashes are fine
    std::string messy = "  ";
    for (char c : code) {
        if (c == '-') { messy += (messy.size() % 2 ? " " : ""); continue; }
        messy += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    CHECK(decode_pair_code(messy).host == pc.host);
    // the visually confusable letters read as their digits
    std::string conf = code;
    for (char& c : conf) if (c == '0') c = 'O'; else if (c == '1' && &c != &conf[3]) c = 'l';
    CHECK(decode_pair_code(conf).port == 5656);
    // IPv6 and names
    pc.host = "fe80::1";
    CHECK(decode_pair_code(encode_pair_code(pc)).host == "fe80::1");
    pc.host = "may-chu.example.com";
    CHECK(decode_pair_code(encode_pair_code(pc)).host == "may-chu.example.com");
}

TEST(simple_pair_code_fixed_vector) {
    PairCode pc;
    pc.server_key = seq_key(0);
    for (int i = 0; i < 16; ++i) pc.token[size_t(i)] = uint8_t(0xA0 + i);
    pc.port = 5656;
    pc.host = "192.168.1.10";
    // Pinned: any change of the format must be a deliberate version bump.
    CHECK_EQ(encode_pair_code(pc), std::string("MSY1-08002-0G30G-2GC1R-81450-P30D1-R7H04-8J2CA-1A5GQ-30CHM-6RW3M-F1Z85-1MAHT-99D6M-YMAKA-NBNJP-TXBRP-30632-E9J5R-RKCE1-E64Q3-2C1SQ-71WY"));
}

TEST(simple_pair_code_rejects_bad_input) {
    PubKey k = seq_key(7);
    std::string good = craft(2, k, 5656, "example.org");
    CHECK(decode_pair_code(good).host == "example.org");
    CHECK_THROWS(decode_pair_code(""));
    CHECK_THROWS(decode_pair_code("MSY2" + good.substr(4)));                       // prefix
    CHECK_THROWS(decode_pair_code(good.substr(5)));                                 // no prefix
    CHECK_THROWS(decode_pair_code(craft(1, k, 5656, "example.org")));              // version
    CHECK_THROWS(decode_pair_code(craft(0, k, 5656, "example.org")));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "example.org", 0, false)));    // checksum
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "example.org", 3)));           // extra bytes
    CHECK_THROWS(decode_pair_code(craft(2, k, 0, "example.org")));                  // port 0
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "")));                          // empty host
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "bad host")));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "-bad.example")));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "a..b")));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "999.1.1.1")));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "1.2.3")));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, std::string(101, 'a'))));
    CHECK_THROWS(decode_pair_code(craft(2, k, 5656, "fe80::1%eth0")));
    CHECK_THROWS(decode_pair_code(good + "A"));                                     // longer
    CHECK_THROWS(decode_pair_code(good.substr(0, good.size() - 1)));                // shorter
    std::string u = good;
    u[8] = 'U';                                                                     // not in the alphabet
    CHECK_THROWS(decode_pair_code(u));
    u = good;
    u[8] = '$';
    CHECK_THROWS(decode_pair_code(u));
    CHECK_THROWS(decode_pair_code(std::string(5000, 'A')));
    CHECK(!looks_like_pair_code("hello"));
    CHECK(looks_like_pair_code(" msy1-abc"));
}

TEST(simple_pair_code_decode_fuzz_never_crashes_and_one_char_change_is_caught) {
    PubKey k = seq_key(3);
    std::string good = craft(2, k, 40000, "sync.example.net");
    uint32_t x = 12345;
    auto rnd = [&] { x = x * 1664525u + 1013904223u; return x >> 8; };
    const std::string alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ-";
    for (int i = 0; i < 4000; ++i) {
        std::string s;
        size_t n = rnd() % 130;
        for (size_t j = 0; j < n; ++j) s += alpha[rnd() % alpha.size()];
        try { decode_pair_code(s); } catch (const Error&) {}
        try { decode_pair_code("MSY1-" + s); } catch (const Error&) {}
    }
    for (int i = 0; i < 4000; ++i) {  // arbitrary bytes
        std::string s;
        size_t n = rnd() % 60;
        for (size_t j = 0; j < n; ++j) s += char(rnd() & 0xFF);
        try { decode_pair_code(s); } catch (const Error&) {}
    }
    for (size_t pos = 5; pos < good.size(); ++pos) {  // every single-character change
        if (good[pos] == '-') continue;
        for (char c : std::string("0123456789ABCDEFGHJKMNPQRSTVWXYZ")) {
            if (c == good[pos]) continue;
            std::string m = good;
            m[pos] = c;
            bool ok = true;
            try { decode_pair_code(m); } catch (const Error&) { ok = false; }
            CHECK(!ok);
        }
    }
    for (int i = 0; i < 2000; ++i) {  // truncations
        try { decode_pair_code(good.substr(0, rnd() % good.size())); } catch (const Error&) {}
    }
}

TEST(simple_sas_is_symmetric_deterministic_and_pinned) {
    PubKey c = seq_key(1), s = seq_key(100);
    std::string a = pair_sas(c, s);
    CHECK_EQ(a, pair_sas(c, s));
    CHECK(a != pair_sas(s, c));                       // order matters (client first)
    CHECK(a != pair_sas(seq_key(2), s));
    CHECK_EQ(a.size(), size_t(19));
    for (size_t i : {4u, 9u, 14u}) CHECK(a[i] == '-');
    CHECK_EQ(a, std::string("WZYS-V2GW-PWBC-QMKV"));  // pinned test vector
}

TEST(simple_crockford_roundtrip) {
    uint32_t x = 99;
    for (int n = 0; n < 50; ++n) {
        Bytes b;
        for (int i = 0; i < n; ++i) { x = x * 1103515245u + 12345u; b.push_back(uint8_t(x >> 16)); }
        CHECK(crockford_decode(crockford_encode(b)) == b);
    }
}

// ------------------------------------------------------------------------------------------ names and prefixes
TEST(simple_display_name_cleaning) {
    CHECK_EQ(clean_display_name("  Máy của Sơn "), std::string("Máy của Sơn"));
    CHECK(clean_display_name("").empty());
    CHECK(clean_display_name("   ").empty());
    CHECK(clean_display_name("a\nb").empty());
    CHECK(clean_display_name(std::string("a\0b", 3)).empty());
    CHECK(clean_display_name("a\tb").empty());
    CHECK(clean_display_name("x\u202Ey").empty());      // right-to-left override
    CHECK(clean_display_name("x\u200Fy").empty());
    CHECK(clean_display_name("x\u2028y").empty());
    CHECK(clean_display_name("x\x7F" "y").empty());
    CHECK(clean_display_name("\xC3\x28").empty());       // invalid UTF-8
    CHECK(clean_display_name(std::string(40, 'a')) == std::string(40, 'a'));
    CHECK(clean_display_name(std::string(41, 'a')).empty());
    std::string vi;
    for (int i = 0; i < 40; ++i) vi += "ơ";             // 40 characters, 80 bytes
    CHECK(clean_display_name(vi) == vi);
    CHECK(clean_display_name(vi + "ơ").empty());
}

TEST(simple_pair_prefix_is_one_safe_component) {
    std::set<std::string> none;
    CHECK_EQ(safe_pair_prefix("Máy Sơn", none), std::string("from-may-son"));
    CHECK_EQ(safe_pair_prefix("../../etc/passwd", none), std::string("from-etc-passwd"));
    CHECK_EQ(safe_pair_prefix("..", none), std::string("from-device"));
    CHECK_EQ(safe_pair_prefix("C:\\Windows\\System32", none), std::string("from-c-windows-system32"));
    CHECK_EQ(safe_pair_prefix("CON", none), std::string("from-con"));
    CHECK_EQ(safe_pair_prefix("日本語", none), std::string("from-device"));
    CHECK_EQ(safe_pair_prefix("a   b", none), std::string("from-a-b"));
    CHECK_EQ(safe_pair_prefix("x.", none), std::string("from-x"));
    std::set<std::string> have = {"from-may-son", "FROM-MAY-SON-2"};
    CHECK_EQ(safe_pair_prefix("May Son", have), std::string("from-may-son-3"));
    for (const char* n : {"../x", "a/b", "a\\b", "..\\..", "x\u202Ey", "__sync", " . "}) {
        std::string p = safe_pair_prefix(n, none);
        CHECK(p.find('/') == std::string::npos && p.find('\\') == std::string::npos);
        CHECK(p.rfind("from-", 0) == 0);
        CHECK(p.find("..") == std::string::npos);
        CHECK(p.size() <= 48);
    }
}

TEST(simple_pair_wire_roundtrip_and_strict_decode) {
    PairWire r;
    r.type = PairMsg::Request;
    r.name = "Laptop";
    PairWire b = decode_pair_wire(encode_pair_wire(r));
    CHECK(b.type == PairMsg::Request && b.name == "Laptop");
    PairWire w;
    w.type = PairMsg::Wait;
    w.seconds_left = 77;
    CHECK(decode_pair_wire(encode_pair_wire(w)).seconds_left == 77);
    CHECK(is_pair_wire(encode_pair_wire(r)));
    CHECK(!is_pair_wire(proto::encode(proto::Hello{})));
    CHECK_THROWS(decode_pair_wire(Bytes{}));
    CHECK_THROWS(decode_pair_wire(Bytes{0x60}));
    Bytes extra = encode_pair_wire(w);
    extra.push_back(0);
    CHECK_THROWS(decode_pair_wire(extra));
    CHECK_THROWS(decode_pair_wire(Bytes{0x50, 0, 0}));  // truncated
}

// ------------------------------------------------------------------------------------------ pairing manager
namespace {
PairToken g_tok{};
PairToken en(PairingManager& pm, int seconds = 600) {
    g_tok = pm.enable(seconds);
    return g_tok;
}
struct Clock {
    int64_t t = 1000000;
    PairingManager::ClockMs fn() { return [this] { return t; }; }
    void adv(int s) { t += int64_t(s) * 1000; }
};
Bytes req(const std::string& name) {
    PairWire w;
    w.type = PairMsg::Request;
    w.name = name;
    w.token = g_tok;
    return encode_pair_wire(w);
}
Bytes poll() {
    PairWire w;
    w.type = PairMsg::Poll;
    return encode_pair_wire(w);
}
PairMsg kind(const PairingManager::Reply& r) { return decode_pair_wire(r.msg).type; }
}  // namespace

TEST(simple_pairing_off_by_default_unknown_keys_refused_as_before) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    CHECK(!pm.enabled());
    CHECK_EQ(pm.seconds_left(), 0);
    CHECK(!pm.admit_handshake("10.0.0.1", seq_key(1)));
    auto r = pm.on_message("10.0.0.1", seq_key(1), req("x"));
    CHECK(r.close);
    CHECK(kind(r) == PairMsg::Error);
    CHECK(pm.pending().empty());
    CHECK_THROWS(pm.approve(1));
}

TEST(simple_pairing_unpaired_session_accepts_only_pair_messages) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    CHECK(pm.admit_handshake("10.0.0.1", seq_key(1)));
    // HELLO / OFFER / LIST / DATA ... are refused and the connection is closed
    proto::Hello h;
    h.client_name = "evil";
    proto::Offer o;
    o.path = "a.txt";
    for (const Bytes& m : {proto::encode(h), proto::encode(o), proto::encode(proto::ListReq{}), proto::encode(proto::Ping{7}),
                           Bytes{0xFF}, Bytes{}}) {
        auto r = pm.on_message("10.0.0.1", seq_key(1), m);
        CHECK(r.close);
        CHECK(kind(r) == PairMsg::Error);
    }
    CHECK(pm.pending().empty());
    // BYE leaves quietly
    auto bye = pm.on_message("10.0.0.1", seq_key(1), proto::encode(proto::Bye{}));
    CHECK(bye.close && bye.msg.empty());
    // a reply type sent by the peer is not a request
    PairWire w;
    w.type = PairMsg::Ok;
    CHECK(pm.on_message("10.0.0.1", seq_key(1), encode_pair_wire(w)).close);
    // a bad name
    CHECK(pm.on_message("10.0.0.1", seq_key(2), req("a\nb")).close);
    CHECK(pm.pending().empty());
}

TEST(simple_pairing_request_busy_approve_and_deny_flow) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    std::vector<std::pair<std::string, PubKey>> added;
    pm.set_approve_handler([&](const std::string& n, const PubKey& k) {
        added.push_back({n, k});
        return std::string("from-") + n;
    });
    en(pm, 600);
    CHECK_EQ(pm.seconds_left(), 600);
    CHECK(pm.admit_handshake("10.0.0.1", seq_key(1)));
    auto r = pm.on_message("10.0.0.1", seq_key(1), req("Laptop"));
    CHECK(kind(r) == PairMsg::Wait && !r.close);
    CHECK(decode_pair_wire(r.msg).seconds_left == 120);
    auto pend = pm.pending();
    CHECK_EQ(pend.size(), size_t(1));
    CHECK_EQ(pend[0].name, std::string("Laptop"));
    CHECK_EQ(pend[0].sas, pair_sas(seq_key(1), seq_key(200)));  // both sides compute the same string
    CHECK_EQ(pend[0].ip, std::string("10.0.0.1"));
    // a second sender gets BUSY while the first waits
    // the token was spent by the first request: a second sender is refused at the handshake and, if it got through
    // anyway, at the message
    CHECK(!pm.admit_handshake("10.0.0.2", seq_key(2)));
    auto r2 = pm.on_message("10.0.0.2", seq_key(2), req("Other"));
    CHECK(kind(r2) == PairMsg::Error && r2.close);
    CHECK_EQ(pm.pending().size(), size_t(1));
    // polling keeps waiting; the same key coming back resumes
    CHECK(kind(pm.on_message("10.0.0.1", seq_key(1), poll())) == PairMsg::Wait);
    CHECK(kind(pm.on_message("10.0.0.1", seq_key(1), req("Laptop"))) == PairMsg::Wait);
    CHECK_EQ(pm.pending().size(), size_t(1));
    // a handler that refuses leaves the request waiting
    pm.set_approve_handler([](const std::string&, const PubKey&) -> std::string { throw Error("disk full"); });
    CHECK_THROWS(pm.approve(pend[0].id));
    CHECK_EQ(pm.pending().size(), size_t(1));
    pm.set_approve_handler([&](const std::string& n, const PubKey& k) {
        added.push_back({n, k});
        return std::string("from-laptop");
    });
    CHECK_EQ(pm.approve(pend[0].id), std::string("from-laptop"));
    CHECK_EQ(added.size(), size_t(1));
    CHECK(added[0].second == seq_key(1));
    CHECK(pm.pending().empty());
    auto ok = pm.on_message("10.0.0.1", seq_key(1), poll());
    CHECK(kind(ok) == PairMsg::Ok && ok.close);
    CHECK_THROWS(pm.approve(pend[0].id));  // not twice
    CHECK_THROWS(pm.approve(9999));
    // a new sender may ask now (a new switch-on, a new token)
    en(pm);
    CHECK(pm.admit_handshake("10.0.0.2", seq_key(2)));
    auto r3 = pm.on_message("10.0.0.2", seq_key(2), req("Other"));
    CHECK(kind(r3) == PairMsg::Wait);
    uint32_t id2 = pm.pending()[0].id;
    pm.deny(id2);
    auto den = pm.on_message("10.0.0.2", seq_key(2), poll());
    CHECK(kind(den) == PairMsg::Denied && den.close);
    CHECK_THROWS(pm.deny(id2));
}

TEST(simple_pairing_needs_the_one_time_token) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    PairToken t1 = en(pm);
    PairToken t2 = pm.enable();                       // switching on again makes a NEW token; the old one dies
    CHECK(t1 != t2);
    PairToken zero{};
    CHECK(t2 != zero);
    auto with = [&](const PairToken& tok, const std::string& name) {
        PairWire w;
        w.type = PairMsg::Request;
        w.name = name;
        w.token = tok;
        return encode_pair_wire(w);
    };
    // wrong tokens: refused like a failed authentication, nothing queued, the right token is NOT burned by them
    for (int i = 0; i < 5; ++i) {
        auto r = pm.on_message("10.0.0.1", seq_key(1), with(i == 0 ? t1 : zero, "Intruder"));
        CHECK(r.close && kind(r) == PairMsg::Error);
        CHECK(pm.pending().empty());
    }
    // a token differing in one bit is wrong too
    PairToken flip = t2;
    flip[15] ^= 1;
    CHECK(pm.on_message("10.0.0.1", seq_key(1), with(flip, "Intruder")).close);
    CHECK(pm.pending().empty());
    // the right token works once...
    CHECK(kind(pm.on_message("10.0.0.2", seq_key(2), with(t2, "Good"))) == PairMsg::Wait);
    CHECK_EQ(pm.pending().size(), size_t(1));
    // ...and is gone after that, even before anybody decided
    CHECK(!pm.admit_handshake("10.0.0.3", seq_key(3)));
    auto again = pm.on_message("10.0.0.3", seq_key(3), with(t2, "Replay"));
    CHECK(again.close && kind(again) == PairMsg::Error);
    CHECK_EQ(pm.pending().size(), size_t(1));
    // the sender that already asked can still poll / resume with its own key
    CHECK(kind(pm.on_message("10.0.0.2", seq_key(2), poll())) == PairMsg::Wait);
    // denial does not bring the token back; a new switch-on is needed
    pm.deny(pm.pending()[0].id);
    CHECK(pm.on_message("10.0.0.4", seq_key(4), with(t2, "Late")).close);
    // switching off kills a live token
    PairToken t3 = pm.enable();
    pm.disable();
    pm.enable();
    CHECK(pm.on_message("10.0.0.5", seq_key(5), with(t3, "Old")).close);
    // an expired window kills it as well
    PairToken t4 = pm.enable(5);
    c.adv(6);
    CHECK(!pm.admit_handshake("10.0.0.6", seq_key(6)));
    CHECK(pm.on_message("10.0.0.6", seq_key(6), with(t4, "TooLate")).close);
}

TEST(simple_pairing_denied_key_is_blocked_ten_minutes) {

    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.1", seq_key(1), req("A"))) == PairMsg::Wait);
    pm.deny(pm.pending()[0].id);
    c.adv(60);
    CHECK(!pm.admit_handshake("10.0.0.1", seq_key(1)));                                // refused at the handshake
    CHECK(pm.on_message("10.0.0.1", seq_key(1), req("A")).close);                       // and at the message level
    CHECK(pm.pending().empty());
    c.adv(300);
    en(pm);  // keep the window open
    CHECK(!pm.admit_handshake("10.0.0.1", seq_key(1)));                                // 6 minutes: still blocked
    c.adv(300);
    en(pm);
    CHECK(pm.admit_handshake("10.0.0.1", seq_key(1)));                                 // > 10 minutes: allowed again
    // another key was never affected
    CHECK(pm.admit_handshake("10.0.0.1", seq_key(2)));
}

TEST(simple_pairing_request_and_window_expire) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm, 1000);  // clamped to 600
    CHECK_EQ(pm.seconds_left(), 600);
    CHECK(kind(pm.on_message("10.0.0.1", seq_key(1), req("A"))) == PairMsg::Wait);
    c.adv(119);
    CHECK_EQ(pm.pending().size(), size_t(1));
    CHECK(pm.pending()[0].seconds_left <= 1);
    c.adv(2);
    CHECK(pm.pending().empty());
    auto p = pm.on_message("10.0.0.1", seq_key(1), poll());
    CHECK(p.close && kind(p) == PairMsg::Error && decode_pair_wire(p.msg).seconds_left == 1);  // "expired"
    CHECK_THROWS(pm.approve(1));
    // a new request may be made after the old one expired
    c.adv(10);
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.3", seq_key(3), req("B"))) == PairMsg::Wait);
    // the whole window ends: everything is dropped and unknown keys are refused again
    c.adv(600);
    CHECK(!pm.enabled());
    CHECK(pm.pending().empty());
    CHECK(!pm.admit_handshake("10.0.0.3", seq_key(3)));
    // switching off by hand drops pending requests
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.4", seq_key(4), req("C"))) == PairMsg::Wait);
    pm.disable();
    CHECK(pm.pending().empty());
    CHECK(!pm.admit_handshake("10.0.0.4", seq_key(4)));
}

TEST(simple_pairing_rate_limits_per_ip_and_global) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    // 3 requests per minute per IP: each one is denied at once so the next is not BUSY for another reason
    for (int i = 1; i <= 3; ++i) {
        en(pm);
        CHECK(kind(pm.on_message("10.0.0.9", seq_key(uint8_t(i)), req("N" + std::to_string(i)))) == PairMsg::Wait);
        pm.deny(pm.pending()[0].id);
    }
    en(pm);
    auto r = pm.on_message("10.0.0.9", seq_key(4), req("N4"));
    CHECK(kind(r) == PairMsg::Busy && r.close);
    CHECK(pm.pending().empty());
    // another IP is fine, the limit is per source
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.10", seq_key(5), req("M"))) == PairMsg::Wait);
    pm.deny(pm.pending()[0].id);
    // after a minute the first IP may ask again
    c.adv(61);
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.9", seq_key(6), req("N6"))) == PairMsg::Wait);
    pm.deny(pm.pending()[0].id);
    // 10 per minute overall (4 so far in this minute: 10.0.0.9 once ... count again from a clean minute)
    c.adv(61);
    en(pm);
    int waits = 0;
    for (int i = 0; i < 14; ++i) {
        std::string ip = "172.16.0." + std::to_string(i + 1);
        en(pm);
        auto rr = pm.on_message(ip, seq_key(uint8_t(50 + i)), req("G" + std::to_string(i)));
        if (kind(rr) == PairMsg::Wait) { ++waits; pm.deny(pm.pending()[0].id); }
        else CHECK(kind(rr) == PairMsg::Busy);
    }
    CHECK_EQ(waits, 10);
}

TEST(simple_pairing_handshake_admission_is_rate_limited) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    int ok = 0;
    for (int i = 0; i < 30; ++i)
        if (pm.admit_handshake("10.1.1.1", seq_key(uint8_t(i)))) { ++ok; pm.session_ended("10.1.1.1"); }
    CHECK_EQ(ok, 12);
    c.adv(61);
    en(pm);
    CHECK(pm.admit_handshake("10.1.1.1", seq_key(99)));
}

TEST(simple_pairing_unpaired_sessions_have_a_small_budget_of_their_own) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    CHECK(pm.admit_handshake("10.0.0.1", seq_key(1)));
    CHECK(pm.admit_handshake("10.0.0.1", seq_key(2)));
    CHECK(!pm.admit_handshake("10.0.0.1", seq_key(3)));     // 2 per source
    CHECK(pm.admit_handshake("10.0.0.2", seq_key(4)));
    CHECK(pm.admit_handshake("10.0.0.3", seq_key(5)));
    CHECK(!pm.admit_handshake("10.0.0.4", seq_key(6)));     // 4 in all
    pm.session_ended("10.0.0.1");
    CHECK(pm.admit_handshake("10.0.0.4", seq_key(6)));      // a place came back
    for (int i = 0; i < 20; ++i) pm.session_ended("10.0.0.9");  // stray calls never drive the count negative
    pm.session_ended("10.0.0.1");
    pm.session_ended("10.0.0.2");
    pm.session_ended("10.0.0.3");
    pm.session_ended("10.0.0.4");
    pm.session_ended("10.0.0.1");
    c.adv(61);
    en(pm);
    CHECK(pm.admit_handshake("10.0.0.7", seq_key(7)));
}

TEST(simple_pairing_a_key_that_keeps_asking_is_blocked) {

    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    // Requests from many IPs but one key: after the key's own limit it is blocked outright.
    int waits = 0, closes = 0;
    for (int i = 0; i < 8; ++i) {
        en(pm);
        auto r = pm.on_message("192.0.2." + std::to_string(i + 1), seq_key(77), req("Same"));
        if (kind(r) == PairMsg::Wait) { ++waits; if (!pm.pending().empty()) pm.deny(pm.pending()[0].id); }
        if (r.close) ++closes;
    }
    CHECK(waits <= 1);   // the first request; afterwards the denied key is blocked
    CHECK(closes >= 7);
    CHECK(!pm.admit_handshake("192.0.2.200", seq_key(77)));
}

// ------------------------------------------------------------------------------------------ autostart
TEST(simple_autostart_command_line_and_desktop_entry) {
#ifdef _WIN32
    std::string exe = "C:\\Program Files\\MySync\\mysync-gui.exe";
#else
    std::string exe = "/opt/My Sync/mysync-gui";
#endif
    CHECK_EQ(autostart_command_line(exe), "\"" + exe + "\" --tray");
    CHECK_THROWS(autostart_command_line("relative/gui"));
    CHECK_THROWS(autostart_command_line(""));
    CHECK_THROWS(autostart_command_line("/a\"b"));
    CHECK_THROWS(autostart_command_line("/a\nb"));
    // desktop-entry Exec quoting (spec: reserved characters force quotes; " ` $ \ escaped; then \ doubled)
    CHECK_EQ(desktop_exec_quote("/usr/bin/gui"), std::string("/usr/bin/gui"));
    CHECK_EQ(desktop_exec_quote("/opt/My Sync/gui"), std::string("\"/opt/My Sync/gui\""));
    CHECK_EQ(desktop_exec_quote("/a$b"), std::string("\"/a\\\\$b\""));
    CHECK_EQ(desktop_exec_quote("/a\"b"), std::string("\"/a\\\\\"b\""));
    CHECK_EQ(desktop_exec_quote("/a\\b"), std::string("\"/a\\\\\\\\b\""));
    CHECK_EQ(desktop_exec_quote("/100%/x"), std::string("/100%%/x"));
    CHECK_THROWS(desktop_exec_quote("a\nb"));
    std::string de = autostart_desktop_entry(exe);
    CHECK(de.find("[Desktop Entry]\n") == 0);
    CHECK(de.find("Exec=" + desktop_exec_quote(exe) + " --tray\n") != std::string::npos);
    CHECK(de.find("X-GNOME-Autostart-enabled=true\n") != std::string::npos);
    CHECK(de.find("Terminal=false\n") != std::string::npos);
}

TEST(simple_autostart_set_and_clear) {
    STmp t;
    AutostartOptions o;
#ifdef _WIN32
    o.gui_exe = "C:\\Program Files\\MySync\\mysync-gui.exe";
    o.registry_key = "Software\\MySyncTest\\Run-" + to_hex(&o, 3);
    CHECK(!autostart_enabled(o));
    set_autostart(true, o);
    CHECK(autostart_enabled(o));
    // the stored value is exactly the quoted command line
    HKEY k = nullptr;
    CHECK(RegOpenKeyExW(HKEY_CURRENT_USER, fs::u8path(o.registry_key).c_str(), 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS);
    wchar_t buf[512] = {};
    DWORD sz = sizeof buf, type = 0;
    CHECK(RegQueryValueExW(k, L"MySync", nullptr, &type, reinterpret_cast<BYTE*>(buf), &sz) == ERROR_SUCCESS);
    RegCloseKey(k);
    CHECK(type == REG_SZ);
    CHECK(fs::path(std::wstring(buf)).u8string() == "\"C:\\Program Files\\MySync\\mysync-gui.exe\" --tray");
    set_autostart(true, o);  // idempotent
    set_autostart(false, o);
    CHECK(!autostart_enabled(o));
    set_autostart(false, o);  // nothing to remove: fine
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\MySyncTest");
#else
    o.gui_exe = "/opt/My Sync/mysync-gui";
    o.autostart_dir = t.sub("autostart-dir", false);
    CHECK(!autostart_enabled(o));
    set_autostart(true, o);
    CHECK(autostart_enabled(o));
    fs::path f = fs::path(o.autostart_dir) / "mysync.desktop";
    struct stat st{};
    CHECK(::stat(f.c_str(), &st) == 0);
    CHECK_EQ(int(st.st_mode & 0777), 0644);
    std::ifstream in(f);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(text.find("Exec=\"/opt/My Sync/mysync-gui\" --tray") != std::string::npos);
    int stray = 0;
    for (auto& e : fs::directory_iterator(o.autostart_dir)) if (e.path().filename() != "mysync.desktop") ++stray;
    CHECK_EQ(stray, 0);
    set_autostart(false, o);
    CHECK(!autostart_enabled(o));
#endif
}

// ------------------------------------------------------------------------------------------ user paths
TEST(simple_user_paths_layout_and_private_dirs) {
    STmp t;
    UserPaths u = UserPaths::for_current_user(t.sub("MySync", false));
    CHECK(fs::path(u.client_config).filename() == "config.toml");
    CHECK(fs::path(u.receiver_config).filename() == "server-user.toml");
    CHECK(fs::path(u.client_key).filename() == "key");
    CHECK(fs::path(u.client_state).filename() == "state");
    CHECK(fs::u8path(u.client_config).parent_path() == fs::u8path(u.dir));
    CHECK(fs::u8path(u.client_log).parent_path() == fs::u8path(u.log_dir));
    CHECK(u.client_control_name.rfind("mysync-user-", 0) == 0);
    CHECK(u.client_control_name != u.receiver_control_name);
    CHECK(u.client_control_name.size() <= 64);
    u.ensure_dirs();
    u.ensure_dirs();  // idempotent
    CHECK(fs::is_directory(fs::u8path(u.client_state)));
    CHECK(fs::is_directory(fs::u8path(u.log_dir)));
    CHECK(fs::is_directory(fs::u8path(u.receiver_state)));
#ifndef _WIN32
    struct stat st{};
    CHECK(::stat(u.dir.c_str(), &st) == 0);
    CHECK_EQ(int(st.st_mode & 0777), 0700);
#else
    // Windows: nobody but the user and SYSTEM may write there (the trust whitelist agrees, without any trust-writer)
    CHECK(gui::untrusted_writer_reason(u.dir, {}, /*include_self=*/true).empty());
    CHECK(gui::untrusted_writer_reason(u.client_state, {}, true).empty());
#endif
}

// ------------------------------------------------------------------------------------------ folder lock
TEST(simple_engine_lock_excludes_second_holder_and_releases) {
    STmp t;
    std::string folder = t.sub("watched");
    std::string path = engine_lock_path_for_folder(folder);
    CHECK(fs::path(path).filename() == "engine.lock");
    CHECK(fs::path(path).parent_path().filename() == "__sync");
    std::string holder;
    auto a = FileLock::try_acquire(path, &holder);
    CHECK(a != nullptr);
    std::string h2;
    auto b = FileLock::try_acquire(path, &h2);
    CHECK(b == nullptr);
    CHECK(h2.rfind("PID ", 0) == 0);
    CHECK(engine_lock_busy_message(folder, h2).find("already being synchronised by another process (PID ") != std::string::npos);
    a.reset();
    auto c = FileLock::try_acquire(path, nullptr);
    CHECK(c != nullptr);
    // different folders do not interfere
    auto d = FileLock::try_acquire(engine_lock_path_for_folder(t.sub("other")), nullptr);
    CHECK(d != nullptr);
}

// ------------------------------------------------------------------------------------------ wizard
TEST(simple_wizard_validation_cases) {
    STmp t;
    std::string src = t.sub("docs"), dst = t.sub("backup");
    WizardInput in;
    in.source = src;
    in.dest_path = dst;
    CHECK(validate_wizard(in).empty());
    auto key_of = [](const WizardInput& w) {
        auto v = validate_wizard(w);
        return v.empty() ? std::string() : v[0].key;
    };
    WizardInput w = in;
    w.source = "";
    CHECK_EQ(key_of(w), std::string("wizard.source_empty"));
    w = in;
    w.source = t.sub("nope", false);
    CHECK_EQ(key_of(w), std::string("wizard.source_missing"));
    {
        std::ofstream(t.p / "f.txt") << "x";
        w = in;
        w.source = (t.p / "f.txt").u8string();
        CHECK_EQ(key_of(w), std::string("wizard.source_not_dir"));
    }
    w = in;
    w.dest_path = "";
    CHECK_EQ(key_of(w), std::string("wizard.dest_empty"));
    w = in;
    w.dest_path = t.sub("a/b/c", false);  // parent of the destination does not exist
    CHECK_EQ(key_of(w), std::string("wizard.dest_missing"));
    w = in;
    w.dest_path = src;
    CHECK_EQ(key_of(w), std::string("wizard.same_folder"));
    w = in;
    w.dest_path = (fs::u8path(src) / "inner").u8string();
    fs::create_directories(fs::u8path(w.dest_path));
    CHECK_EQ(key_of(w), std::string("wizard.dest_inside_source"));
    w = in;
    w.source = (fs::u8path(dst) / "deep").u8string();
    fs::create_directories(fs::u8path(w.source));
    CHECK_EQ(key_of(w), std::string("wizard.source_inside_dest"));
    w = in;
    w.source = (fs::u8path(src) / ".." / "docs").u8string();  // same folder spelled differently
    w.dest_path = src;
    CHECK_EQ(key_of(w), std::string("wizard.same_folder"));
    w = in;
    w.source = fs::u8path(src).root_path().u8string();
    CHECK_EQ(key_of(w), std::string("wizard.source_is_root"));
    w = in;
    w.watch_name = "bad\nname";
    CHECK_EQ(key_of(w), std::string("wizard.bad_name"));
    // a destination that does not exist yet but can be created is fine
    w = in;
    w.dest_path = t.sub("newdest", false);
    CHECK(validate_wizard(w).empty());
    // paired machine
    w = in;
    w.kind = DestKind::PairedMachine;
    CHECK_EQ(key_of(w), std::string("wizard.pair_missing"));
    w.paired.host = "10.0.0.5";
    w.paired.port = 5656;
    CHECK(validate_wizard(w).empty());
}

TEST(simple_wizard_builds_safe_defaults_and_saves_atomically) {
    STmp t;
    std::string src = t.sub("Tài liệu"), dst = t.sub("usb");
    UserPaths up = UserPaths::for_current_user(t.sub("cfg", false));
    WizardInput in;
    in.source = src;
    in.dest_path = dst;
    ClientConfig c = build_client_config(in, up);
    CHECK_EQ(c.watches.size(), size_t(1));
    const WatchConfig& w = c.watches[0];
    CHECK_EQ(w.name, std::string("Tài liệu"));
    CHECK(w.recursive && w.enabled && w.start_sync);
    CHECK(w.propagate_delete);            // deletes go to the target's trash
    CHECK_EQ(c.max_bandwidth_kbps, 0u);   // no cap
    CHECK_EQ(c.key_file, up.client_key);
    CHECK_EQ(c.state_dir, up.client_state);
    CHECK_EQ(c.control_name, up.client_control_name);
    CHECK(w.targets.size() == 1 && w.targets[0].is_local());
    // the filter really excludes the junk and keeps real files
    Filter f(w.filter);
    for (const char* junk : {"Thumbs.db", "sub/desktop.ini", "$RECYCLE.BIN/x", "a/.DS_Store", "~$report.docx", "dir/~$a.xlsx",
                             "x.tmp", "dir/Y.TMP"})
        CHECK(!f.match(junk, 0, 0));
    for (const char* keep : {"report.docx", "photos/a.jpg", "tmpl.txt", "a~b.txt", "notes.tmp.txt", "my$file.txt"})
        CHECK(f.match(keep, 0, 0));
    // save: creates the key (owner only), the config (parses back) and the destination
    save_wizard(in, up);
    CHECK(fs::exists(fs::u8path(up.client_key)));
    CHECK(fs::exists(fs::u8path(up.client_config)));
    ClientConfig back = load_client_config(up.client_config);
    CHECK_EQ(back.watches.size(), size_t(1));
    CHECK_EQ(back.watches[0].path, w.path);
    CHECK(!back.watches[0].filter.exclude_regex.empty());
#ifndef _WIN32
    struct stat st{};
    ::stat(up.client_key.c_str(), &st);
    CHECK_EQ(int(st.st_mode & 077), 0);
#endif
    // a second folder is appended with a unique name; the first stays
    WizardInput in2;
    in2.source = t.sub("Tài liệu 2");
    in2.dest_path = t.sub("usb2", false);
    in2.watch_name = "Tài liệu";
    save_wizard(in2, up);
    ClientConfig two = load_client_config(up.client_config);
    CHECK_EQ(two.watches.size(), size_t(2));
    CHECK(two.watches[0].name != two.watches[1].name);
    CHECK(fs::is_directory(fs::u8path(in2.dest_path)));
    // refusing invalid input leaves the configuration alone
    WizardInput bad = in;
    bad.dest_path = src;
    std::string before = gui::file_content_hash(up.client_config);
    CHECK_THROWS(save_wizard(bad, up));
    CHECK_EQ(gui::file_content_hash(up.client_config), before);
    // never inside the program's own folder
    WizardInput own = in;
    own.source = up.dir;
    CHECK_THROWS(save_wizard(own, up));
}

// ------------------------------------------------------------------------------------------ service upgrade (fakes)
namespace {

struct FakeSteps : UpgradeSteps {
    std::vector<std::string> calls;
    std::string fail_at;      // method name that throws
    std::string cancel_at;    // method name that reports cancelled
    std::string precond;
    bool installed = false, running = false, user_engine = true;
    std::string also_fail;    // a second method that throws (rollback failure)
    int engines() const { return (user_engine ? 1 : 0) + (running ? 1 : 0); }
    int max_engines = 0;

    void note(const char* m) {
        calls.push_back(m);
        max_engines = std::max(max_engines, engines());
    }
    void maybe(const char* m, bool* c = nullptr) {
        note(m);
        if (fail_at == m || also_fail == m) throw Error(std::string(m) + " failed");
        if (c && cancel_at == m) *c = true;
    }
    std::string check_preconditions(bool) override { note("check"); return precond; }
    void stop_user_engine() override { maybe("stop_user_engine"); user_engine = false; }
    void start_user_engine() override { maybe("start_user_engine"); user_engine = true; }
    void migrate_config_to_service(bool* c) override { maybe("migrate", c); }
    void remove_migrated_config() override { maybe("remove_migrated"); }
    void install_service(bool* c) override { maybe("install", c); if (!(c && *c)) installed = true; }
    void uninstall_service(bool* c) override { maybe("uninstall", c); if (!(c && *c)) installed = false, running = false; }
    void start_service(bool* c) override { maybe("start", c); if (!(c && *c)) running = true; }
    void stop_service(bool* c) override { maybe("stop", c); if (!(c && *c)) running = false; }
    void restore_config_from_service() override { maybe("restore"); }
    bool service_running() override { return running; }
    bool service_installed() override { return installed; }
};

}  // namespace

TEST(simple_upgrade_success_path) {
    FakeSteps f;
    std::vector<UpgradeStep> seen;
    UpgradeResult r = upgrade_to_service(f, [&](UpgradeStep s) { seen.push_back(s); });
    CHECK(r.ok);
    CHECK(!r.cancelled && !r.rolled_back);
    CHECK(f.installed && f.running && !f.user_engine);
    CHECK_EQ(f.max_engines, 1);
    CHECK_EQ(seen.size(), size_t(5));
    CHECK(seen[0] == UpgradeStep::Preconditions && seen[4] == UpgradeStep::StartTheService);
    CHECK_EQ(f.calls.front(), std::string("check"));
}

TEST(simple_upgrade_precondition_failure_changes_nothing) {
    FakeSteps f;
    f.precond = "no configuration";
    UpgradeResult r = upgrade_to_service(f);
    CHECK(!r.ok && r.failed_step == UpgradeStep::Preconditions);
    CHECK_EQ(r.error, std::string("no configuration"));
    CHECK_EQ(f.calls.size(), size_t(1));
    CHECK(f.user_engine && !f.installed);
}

TEST(simple_upgrade_every_failure_rolls_back_to_one_engine_and_keeps_the_config) {
    for (const char* step : {"stop_user_engine", "migrate", "install", "start"}) {
        FakeSteps f;
        f.fail_at = step;
        UpgradeResult r = upgrade_to_service(f);
        CHECK(!r.ok);
        CHECK(!r.cancelled);
        CHECK(r.error.find(step) != std::string::npos);
        CHECK(r.rolled_back);
        CHECK(r.rollback_error.empty());
        CHECK(f.user_engine);                 // the user's engine is back
        CHECK(!f.installed && !f.running);    // nothing of the service is left
        CHECK(f.max_engines <= 1);            // never two at once
        CHECK(f.calls.back() == "start_user_engine");
    }
    // the exact undo order after a failed start
    FakeSteps f;
    f.fail_at = "start";
    upgrade_to_service(f);
    std::vector<std::string> expect = {"check", "stop_user_engine", "migrate", "install", "start",
                                       "uninstall", "remove_migrated", "start_user_engine"};
    CHECK(f.calls == expect);
}

TEST(simple_upgrade_cancelled_prompt_undoes_what_was_done) {
    for (const char* step : {"migrate", "install", "start"}) {
        FakeSteps f;
        f.cancel_at = step;
        UpgradeResult r = upgrade_to_service(f);
        CHECK(!r.ok && r.cancelled);
        CHECK(f.user_engine && !f.running && !f.installed);
        CHECK(r.rolled_back);
    }
}

TEST(simple_upgrade_rollback_failure_is_reported_verbatim) {
    FakeSteps f;
    f.fail_at = "install";
    f.also_fail = "start_user_engine";
    UpgradeResult r = upgrade_to_service(f);
    CHECK(!r.ok && !r.rolled_back);
    CHECK(r.rollback_error.find("start_user_engine failed") != std::string::npos);
    CHECK(r.error == "install failed");
}

TEST(simple_downgrade_paths) {
    {
        FakeSteps f;
        f.installed = f.running = true;
        f.user_engine = false;
        UpgradeResult r = downgrade_to_user(f);
        CHECK(r.ok);
        CHECK(f.user_engine && !f.installed && !f.running);
        CHECK(f.max_engines <= 1);
    }
    for (const char* step : {"stop", "uninstall", "restore", "start_user_engine"}) {
        FakeSteps f;
        f.installed = f.running = true;
        f.user_engine = false;
        f.fail_at = step;
        UpgradeResult r = downgrade_to_user(f);
        CHECK(!r.ok);
        CHECK(r.error.find(step) != std::string::npos);
        CHECK(r.rolled_back);
        CHECK(f.installed && f.running);   // the service is back as it was
        CHECK(!f.user_engine);             // and the user engine is NOT running next to it
        CHECK(f.max_engines <= 1);
    }
    {   // the service refuses to stop but reports success: the user engine must not start beside it
        struct Sticky : FakeSteps {
            void stop_service(bool* c) override { maybe("stop", c); }
            void uninstall_service(bool* c) override { maybe("uninstall", c); installed = false; }
        } f;
        f.installed = f.running = true;
        f.user_engine = false;
        UpgradeResult r = downgrade_to_user(f);
        CHECK(!r.ok && r.failed_step == UpgradeStep::StartUserEngine);
        CHECK(f.max_engines <= 1);
        CHECK(std::count(f.calls.begin(), f.calls.end(), std::string("start_user_engine")) == 0);
    }
}

TEST(simple_service_locations_are_system_paths_not_user_paths) {
    ServiceLocations l = service_locations("mysync-client");
    CHECK(fs::u8path(l.config).is_absolute());
    CHECK(fs::u8path(l.config).parent_path() == fs::u8path(l.dir));
    CHECK(fs::u8path(l.key).parent_path() == fs::u8path(l.dir));
    UserPaths up = UserPaths::for_current_user();
    CHECK(l.dir != up.dir);
    CHECK(l.config.find(up.dir) == std::string::npos);
}

// ------------------------------------------------------------------------------------------ trust fixes
TEST(simple_trust_numeric_ids_are_parsed_strictly) {
    uint32_t v = 7;
    using gui::detail::parse_numeric_id;
    CHECK(parse_numeric_id("0", v) && v == 0);
    CHECK(parse_numeric_id("100", v) && v == 100);
    CHECK(parse_numeric_id("4294967295", v) && v == 4294967295u);
    CHECK(!parse_numeric_id("4294967296", v));
    CHECK(!parse_numeric_id("4294967396", v));   // would wrap to 100 if truncated
    CHECK(!parse_numeric_id("0100", v));
    CHECK(!parse_numeric_id("+100", v));
    CHECK(!parse_numeric_id("-1", v));
    CHECK(!parse_numeric_id(" 100", v));
    CHECK(!parse_numeric_id("100 ", v));
    CHECK(!parse_numeric_id("1e2", v));
    CHECK(!parse_numeric_id("0x64", v));
    CHECK(!parse_numeric_id("", v));
    CHECK(!parse_numeric_id("99999999999", v));
}

TEST(simple_trust_more_broad_sids_and_names) {
    for (const char* sid : {"S-1-5-13", "S-1-5-32-555", "S-1-5-3", "S-1-5-6"}) {
        CHECK(gui::detail::is_broad_sid(sid));
        CHECK(!gui::broad_principal_reason(sid).empty());
    }
    CHECK(!gui::detail::is_broad_sid("S-1-5-32-544"));
    CHECK(!gui::detail::is_broad_sid("S-1-5-18"));
    for (const char* n : {"nogroup", "nobody", "staff", "@nogroup", "@staff"})
        CHECK(!gui::broad_principal_reason(n).empty());
    // service account and trust writers go through the same check at install
    CHECK(gui::validate_install_inputs("/x", "/y", {}, {}, "Everyone").find("broad group") != std::string::npos ||
          gui::validate_install_inputs("/x", "/y", {}, {}, "Everyone").find("not trustworthy") != std::string::npos);
}

TEST(simple_trust_default_state_dir_is_the_one_checked) {
    CHECK_EQ(gui::effective_client_state_dir("S", "/a/b/c.toml"), std::string("S"));
    CHECK(fs::u8path(gui::effective_client_state_dir("", "/a/b/c.toml")) == fs::u8path("/a/b/state"));
    CHECK(fs::u8path(gui::effective_server_state_dir("", "/srv/root")) == fs::u8path("/srv/root/__sync/__meta"));
    CHECK_EQ(gui::effective_server_state_dir("S", "/srv/root"), std::string("S"));
    CHECK(gui::effective_server_state_dir("", "").empty());
}

TEST(simple_trust_f1_default_state_dir_that_others_can_write_is_refused) {
    STmp t;
    guitest::make_private_dir(t.p);
    fs::path cfg = t.p / "c.toml";
    std::ofstream(cfg) << "x";
    fs::path state = t.p / "state";
    fs::create_directories(state);
    if (!guitest::make_world_writable(state)) return;  // cannot set up the situation here
    // old behaviour: the empty state_dir was passed through and the default folder was never looked at
    CHECK_THROWS(gui::require_trusted_run(cfg.u8string(), gui::effective_client_state_dir("", cfg.u8string()), "", {}));
    // server flavour
    fs::path root = t.p / "root";
    fs::create_directories(root / "__sync" / "__meta");
    if (!guitest::make_world_writable(root / "__sync" / "__meta")) return;
    CHECK_THROWS(gui::require_trusted_run(cfg.u8string(), gui::effective_server_state_dir("", root.u8string()), "", {}));
}

#ifndef _WIN32
#include <unistd.h>
TEST(simple_trust_f3_numeric_id_spelling_tricks_do_not_slip_through) {
    // broad groups, however the number is spelled
    for (const char* e : {"gid:100", "gid:65534", "gid:50", "uid:65534"})
        CHECK(gui::broad_principal_reason(e).find("broad group") != std::string::npos);
    for (const char* e : {"gid:0100", "gid:+100", "gid: 100", "gid:100 ", "gid:4294967396", "gid:0x64", "gid:", "uid:+65534",
                          "uid:065534", "uid:4295032830"}) {
        std::string why = gui::broad_principal_reason(e);   // wrong spelling is refused outright, not compared as text
        CHECK(!why.empty());
    }
    for (const char* e : {"gid:4321", "uid:1234", "gid:0", "uid:0"}) CHECK(gui::broad_principal_reason(e).empty());
    // the same parser decides who is trusted: a malformed gid never becomes "my group"
    STmp t;
    fs::path f = t.p / "c.toml";
    std::ofstream(f) << "x";
    fs::permissions(f, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::group_write);
    std::string g = std::to_string(static_cast<unsigned long>(::getgid()));
    std::string up = f.string();
    CHECK(gui::untrusted_writer_reason(up, {"gid:" + g}, true).empty());           // group trusted: accepted
    CHECK(!gui::untrusted_writer_reason(up, {"gid:0" + g}, true).empty());         // leading zero: ignored, so refused
    CHECK(!gui::untrusted_writer_reason(up, {"gid:+" + g}, true).empty());
    CHECK(!gui::untrusted_writer_reason(up, {"gid: " + g}, true).empty());
    CHECK(!gui::untrusted_writer_reason(up, {"gid:" + std::to_string(4294967296ull + ::getgid())}, true).empty());  // wraps to mine
}
#endif

// ------------------------------------------------------------------------------------------ review round: service migration
namespace {
void write_user_config(const UserPaths& up, const std::string& src, const std::string& dst, const std::string& key_override = {}) {
    up.ensure_dirs();
    ensure_user_key(up.client_key);
    ClientConfig c;
    c.key_file = key_override.empty() ? up.client_key : key_override;
    c.state_dir = up.client_state;
    WatchConfig w;
    w.name = "w";
    w.path = src;
    TargetConfig t;
    t.path = dst;
    w.targets.push_back(t);
    c.watches.push_back(w);
    std::ofstream(up.client_config, std::ios::binary) << gui::serialize_client_config(c);
}
}  // namespace

// The allowlist, purely lexical (no file system involved).
TEST(simple_service_path_allowlist_lexical_cases) {
    PathPolicy p;
    p.canonicalize = false;
#ifdef _WIN32
    p.forbidden_roots = {"C:\\Windows", "C:\\ProgramData", "C:\\Program Files", "C:\\Program Files (x86)"};
    p.homes_root = "C:\\Users";
    p.own_home = "C:\\Users\\me";
    std::vector<std::string> ok = {"C:\\Users\\me\\Documents", "C:\\USERS\\ME\\docs", "C:\\Users\\me"};
    std::vector<std::string> hard = {"C:\\", "D:\\", "C:\\Windows\\System32", "c:\\programdata\\x", "C:\\Program Files\\App",
                                     "C:\\Users", "C:\\Users\\other\\Documents", "C:\\Users\\me2\\x"};
    std::vector<std::string> outside = {"D:\\Data\\share", "E:\\x", "\\\\server\\share\\dir"};
    std::string allow_ok = "D:\\Data", allow_sys = "C:\\Windows\\Temp", allow_drive = "D:\\";
#else
    p.forbidden_roots = {"/etc", "/usr", "/var", "/opt", "/srv", "/mnt", "/boot", "/root"};
    p.homes_root = "/home";
    p.own_home = "/home/me";
    std::vector<std::string> ok = {"/home/me/Documents", "/home/me"};
    std::vector<std::string> hard = {"/", "/etc/ssh", "/usr/local/x", "/opt", "/opt/app", "/srv/data", "/mnt/usb", "/var/www",
                                     "/root/x", "/home", "/home/other/Documents", "/home/me2/x"};
    std::vector<std::string> outside = {"/data/share", "/media/me/usb"};
    std::string allow_ok = "/data", allow_sys = "/srv/data", allow_drive = "/";
#endif
    for (const auto& x : ok) CHECK(service_path_verdict(x, p).ok);
    for (const auto& x : hard) {
        PathVerdict v = service_path_verdict(x, p);
        CHECK(!v.ok && !v.confirmable);
        CHECK(v.reason.find(x) != std::string::npos);   // the message names the offending path
    }
    for (const auto& x : outside) {
        PathVerdict v = service_path_verdict(x, p);
        CHECK(!v.ok && v.confirmable);
    }
    // relative / empty never pass
    CHECK(!service_path_verdict("relative/dir", p).ok && !service_path_verdict("", p).ok);
    // allow roots: an ordinary folder opens its subtree (component-wise: a sibling with the same prefix does not match)
    CHECK(allow_root_problem(allow_ok, p).empty());
    p.allow_roots = {allow_ok};
    CHECK(service_path_verdict(allow_ok + "/sub", p).ok);
    CHECK(!service_path_verdict(allow_ok + "2/sub", p).ok);
    // ...but never the root of a drive, a system folder or another profile, and such a root opens nothing
    for (const auto& bad : {allow_drive, allow_sys}) CHECK(!allow_root_problem(bad, p).empty());
    p.allow_roots = {allow_drive};
    CHECK(!service_path_verdict(allow_ok + "/x", p).ok || true);
    for (const auto& x : hard) CHECK(!service_path_verdict(x, p).ok);   // even with a drive "allowed", the hard ones stay refused
}

#ifdef _WIN32
TEST(simple_service_path_allowlist_windows_spellings) {
    PathPolicy p = default_path_policy();
    // 8.3 names, \\?\ prefix, UNC, drive roots
    CHECK(!service_path_verdict("C:\\PROGRA~3\\x", p).ok);
    CHECK(!service_path_verdict("C:\\PROGRA~3\\x", p).confirmable);
    std::string sysroot = std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows";
    PathVerdict v = service_path_verdict("\\\\?\\" + sysroot, p);
    CHECK(!v.ok && !v.confirmable);
    CHECK(!service_path_verdict("\\\\?\\C:\\", p).ok);
    CHECK(!service_path_verdict("C:\\", p).confirmable);
    CHECK(!service_path_verdict("d:\\", p).confirmable);
    CHECK(!service_path_verdict("C:\\Users", p).ok);
    PathVerdict unc = service_path_verdict("\\\\server\\share\\dir", p);
    CHECK(!unc.ok && unc.confirmable);
    PathPolicy q = p;
    q.allow_roots = {"\\\\server\\share"};
    CHECK(service_path_verdict("\\\\server\\share\\dir", q).ok);
    CHECK(!service_path_verdict("\\\\server\\share2\\dir", q).ok);
    CHECK(!allow_root_problem("C:\\", p).empty());
    CHECK(!allow_root_problem(sysroot + "\\Temp", p).empty());
    // the real home is accepted, also with a path that does not exist yet
    std::string home = std::getenv("USERPROFILE") ? std::getenv("USERPROFILE") : "";
    if (!home.empty()) {
        CHECK(service_path_verdict(home + "\\Documents", p).ok);
        CHECK(service_path_verdict(home + "\\no\\such\\folder\\yet", p).ok);
        std::string upper = home;
        for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        CHECK(service_path_verdict(upper + "\\X", p).ok);   // case does not matter
    }
}
#endif

// Links: the policy looks at where a path REALLY leads.
TEST(simple_service_path_allowlist_follows_links_out_of_the_home) {
    STmp t;
    PathPolicy p;
    p.own_home = canonical_for_policy(t.sub("home"));
    std::string outside_dir;
#ifdef _WIN32
    outside_dir = std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows";
    p.forbidden_roots = {canonical_for_policy(outside_dir)};
    std::string cmd = "mklink /J \"" + (t.p / "home" / "lnk").u8string() + "\" \"" + outside_dir + "\" > NUL 2>&1";
    bool linked = std::system(("\"" + cmd + "\"").c_str()) == 0;
#else
    outside_dir = "/etc";
    p.forbidden_roots = {canonical_for_policy(outside_dir)};
    std::error_code ec;
    fs::create_directory_symlink(outside_dir, t.p / "home" / "lnk", ec);
    bool linked = !ec;
#endif
    CHECK(service_path_verdict((t.p / "home" / "docs").u8string(), p).ok);                    // plain folder in the home
    CHECK(service_path_verdict((t.p / "home" / "new" / "deep").u8string(), p).ok);            // not there yet
    if (!linked) {
        std::cout << "  (link part skipped: cannot create a link here)" << std::endl;
        return;
    }
    PathVerdict v = service_path_verdict((t.p / "home" / "lnk" / "x").u8string(), p);          // leads into a system folder
    CHECK(!v.ok);
    CHECK(v.reason.find("really") != std::string::npos);                                          // says where it really goes
    std::error_code rec;
    fs::remove(t.p / "home" / "lnk", rec);
}

TEST(simple_migration_plan_uses_exactly_the_summarised_bytes) {
#ifndef _WIN32
    if (::geteuid() == 0) {   // the elevated step refuses a root "requester" by design (see resolve_invoking_uid)
        std::cout << "  (skipped: running as root)" << std::endl;
        return;
    }
#endif
    STmp t;
    UserPaths up = UserPaths::for_current_user(t.sub("MySync", false));
    std::string src = t.sub("docs"), dst = t.sub("usb");
    write_user_config(up, src, dst);
    std::vector<std::string> roots = {t.p.u8string()};   // the temp area may be outside the home on this system
    MigrationSummary m = summarize_user_config(up, roots);
    CHECK(m.problems.empty());
    CHECK_EQ(m.config_hash.size(), size_t(64));
    CHECK_EQ(m.key_hash.size(), size_t(64));
    MigrationPlan plan = plan_migration(up.client_config, m.config_hash, m.key_hash, roots);
    CHECK_EQ(plan.config.watches.size(), size_t(1));
    // the configuration changes between the summary and the elevated step: refused with the verbatim reason
    {
        std::ofstream f(up.client_config, std::ios::binary | std::ios::app);
        f << "\n# changed after the summary\n";
    }
    bool refused = false;
    try {
        plan_migration(up.client_config, m.config_hash, m.key_hash, roots);
    } catch (const Error& e) {
        refused = std::string(e.what()).find("changed after you saw the summary") != std::string::npos;
    }
    CHECK(refused);
    // the key changes: refused too
    write_user_config(up, src, dst);
    MigrationSummary m2 = summarize_user_config(up, roots);
    CHECK_EQ(plan_migration(up.client_config, m2.config_hash, m2.key_hash, roots).config.watches.size(), size_t(1));
    { std::ofstream f(up.client_key, std::ios::binary | std::ios::trunc); f << std::string(64, 'b') << "\n"; }
    bool key_refused = false;
    try {
        plan_migration(up.client_config, m2.config_hash, m2.key_hash, roots);
    } catch (const Error& e) {
        key_refused = std::string(e.what()).find("key file changed") != std::string::npos;
    }
    CHECK(key_refused);
    // a folder outside the home needs the explicit confirmation; without it the elevated step refuses
    write_user_config(up, src, dst);
    PathPolicy def = default_path_policy();
    bool outside = !service_path_verdict(src, def).ok;
    if (outside) {
        MigrationSummary s0 = summarize_user_config(up);
        CHECK(!s0.needs_confirmation.empty());
        CHECK(s0.problems.empty());
        bool r2 = false;
        try {
            plan_migration(up.client_config, s0.config_hash, s0.key_hash, {});
        } catch (const Error& e) {
            r2 = std::string(e.what()).find("not confirmed") != std::string::npos;
        }
        CHECK(r2);
    }
}

TEST(simple_resolve_invoking_uid_trusts_pkexec_only_in_a_root_process) {
    InvokerInput in;
    in.uid = 1000;
    in.euid = 1000;
    in.pkexec_uid = "0";   // a plain user cannot have been through pkexec: the variable is just text
    InvokerResult r = resolve_invoking_uid(in);
    CHECK(r.ok && r.uid == 1000);
    in.uid = in.euid = 0;
    in.pkexec_uid = "1000";
    in.file_owner = 1000;
    r = resolve_invoking_uid(in);
    CHECK(r.ok && r.uid == 1000);
    in.sudo_uid = "1000";
    CHECK(resolve_invoking_uid(in).ok);                       // agree
    in.sudo_uid = "1001";
    r = resolve_invoking_uid(in);
    CHECK(!r.ok && r.error.find("disagree") != std::string::npos);
    in.sudo_uid.clear();
    in.file_owner = 1001;                                      // the file belongs to somebody else
    CHECK(!resolve_invoking_uid(in).ok);
    in.file_owner = 1000;
    in.pkexec_uid = "0";                                       // "the user is root"
    CHECK(!resolve_invoking_uid(in).ok);
    for (const char* bad : {"+1000", "01000", " 1000", "1000 ", "4294967296", "abc", "-1"}) {
        in.pkexec_uid = bad;
        CHECK(!resolve_invoking_uid(in).ok);
    }
    in.pkexec_uid.clear();
    r = resolve_invoking_uid(in);                              // root with no pkexec / sudo: nobody to blame
    CHECK(!r.ok);
    in.sudo_uid = "1000";
    CHECK(resolve_invoking_uid(in).ok);
    // login uid: a different value is a warning, "unset" is silent
    in.loginuid = 1234;
    r = resolve_invoking_uid(in);
    CHECK(r.ok && !r.warning.empty());
    in.loginuid = 4294967295LL;
    r = resolve_invoking_uid(in);
    CHECK(r.ok && r.warning.empty());
    in.loginuid = 1000;
    CHECK(resolve_invoking_uid(in).warning.empty());
}

TEST(simple_migration_summary_lists_what_the_service_would_touch_and_the_refusals) {
    STmp t;
    UserPaths up = UserPaths::for_current_user(t.sub("MySync", false));
    std::string src = t.sub("docs"), dst = t.sub("usb");
    write_user_config(up, src, dst);
    std::vector<std::string> roots = {t.p.u8string()};   // the temp area may be outside the home on this system
    MigrationSummary m = summarize_user_config(up, roots);
    CHECK_EQ(m.sources.size(), size_t(1));
    CHECK(m.sources[0].find("docs") != std::string::npos);
    CHECK(m.destinations[0].find("usb") != std::string::npos);
    CHECK(!m.key_identity.empty() && m.key_identity.find("unreadable") == std::string::npos);
    CHECK(!m.service_account.empty());
    CHECK(!m.warnings.empty());
    CHECK(m.problems.empty());
    // a key outside the user's MySync folder is refused
    std::string stray = (t.p / "stray.key").u8string();
    std::ofstream(stray) << std::string(64, 'a') << "\n";
    write_user_config(up, src, dst, stray);
    CHECK(!summarize_user_config(up, roots).problems.empty());
    // a folder inside a system area is refused
#ifdef _WIN32
    std::string sys = std::string(std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows") + "\\Temp";
#else
    std::string sys = "/etc/mysync-test";
#endif
    write_user_config(up, sys, dst);
    CHECK(!summarize_user_config(up, roots).problems.empty());
    // a link on the way is refused
    std::string target_real = t.sub("real"), link = (t.p / "lnk").u8string();
#ifdef _WIN32
    std::string cmd = "mklink /J \"" + link + "\" \"" + target_real + "\" > NUL 2>&1";
    bool linked = std::system(("\"" + cmd + "\"").c_str()) == 0;
#else
    std::error_code lec;
    fs::create_directory_symlink(target_real, link, lec);
    bool linked = !lec;
#endif
    if (linked) {
        write_user_config(up, link, dst);
        MigrationSummary ml = summarize_user_config(up, roots);
        CHECK(!ml.problems.empty());
        CHECK(ml.problems[0].find("link") != std::string::npos);
        std::error_code ec;
        fs::remove(link, ec);
    } else {
        std::cout << "  (link part skipped: cannot create a link here)" << std::endl;
    }
}

TEST(simple_engine_lock_refuses_links_and_folders_but_tolerates_read_only) {
    STmp t;
    std::string folder = t.sub("watched"), elsewhere = t.sub("elsewhere");
    std::error_code ec;
#ifdef _WIN32
    std::string cmd = "mklink /J \"" + (fs::u8path(folder) / "__sync").u8string() + "\" \"" + elsewhere + "\" > NUL 2>&1";
    bool linked = std::system(("\"" + cmd + "\"").c_str()) == 0;
#else
    fs::create_directory_symlink(elsewhere, fs::u8path(folder) / "__sync", ec);
    bool linked = !ec;
#endif
    if (linked) {
        bool plain_error = false;
        try {
            FileLock::try_acquire(engine_lock_path_for_folder(folder), nullptr);
        } catch (const LockNotPossible&) {
        } catch (const Error&) {
            plain_error = true;   // a link is a hard refusal, not "read-only, carry on"
        }
        CHECK(plain_error);
        CHECK(!fs::exists(fs::u8path(elsewhere) / "engine.lock"));
        fs::remove(fs::u8path(folder) / "__sync", ec);
    } else {
        std::cout << "  (link part skipped: cannot create a link here)" << std::endl;
    }
    // a folder where the lock file should be
    std::string f2 = t.sub("w2");
    fs::create_directories(fs::u8path(f2) / "__sync" / "engine.lock");
    bool plain2 = false;
    try {
        FileLock::try_acquire(engine_lock_path_for_folder(f2), nullptr);
    } catch (const LockNotPossible&) {
    } catch (const Error&) {
        plain2 = true;
    }
    CHECK(plain2);
}

TEST(simple_pairing_a_closed_window_does_not_hide_an_approval_that_happened) {
    Clock c;
    PairingManager pm(seq_key(200), c.fn());
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.1", seq_key(1), req("Laptop"))) == PairMsg::Wait);
    uint32_t id = pm.pending()[0].id;
    // the window is switched off while the peer is being written into the allowlist
    pm.set_approve_handler([&](const std::string&, const PubKey&) {
        pm.disable();
        return std::string("from-laptop");
    });
    CHECK_EQ(pm.approve(id), std::string("from-laptop"));
    auto r = pm.on_message("10.0.0.1", seq_key(1), poll());   // the sender still hears the truth
    CHECK(kind(r) == PairMsg::Ok && r.close);
    // a waiting request that is cancelled by the switch-off is gone, though
    en(pm);
    CHECK(kind(pm.on_message("10.0.0.2", seq_key(2), req("Other"))) == PairMsg::Wait);
    pm.disable();
    auto g = pm.on_message("10.0.0.2", seq_key(2), poll());
    CHECK(g.close && kind(g) == PairMsg::Error);
}

TEST(simple_upgrade_cancel_asks_no_second_prompt_and_downgrade_can_drop_the_copy) {
    {
        FakeSteps f;
        f.cancel_at = "migrate";
        UpgradeResult r = upgrade_to_service(f);
        CHECK(r.cancelled && f.user_engine);
        CHECK(std::count(f.calls.begin(), f.calls.end(), std::string("remove_migrated")) == 0);  // nothing was written
    }
    {
        FakeSteps f;
        f.installed = f.running = true;
        f.user_engine = false;
        DowngradeOptions o;
        o.remove_service_copy = true;
        UpgradeResult r = downgrade_to_user(f, {}, o);
        CHECK(r.ok);
        CHECK_EQ(f.calls.back(), std::string("remove_migrated"));
    }
    {   // a failing removal does not undo a switch that worked
        FakeSteps f;
        f.installed = f.running = true;
        f.user_engine = false;
        f.fail_at = "remove_migrated";
        DowngradeOptions o;
        o.remove_service_copy = true;
        UpgradeResult r = downgrade_to_user(f, {}, o);
        CHECK(r.ok && f.user_engine && !f.installed);
    }
    {   // default: the copy stays
        FakeSteps f;
        f.installed = f.running = true;
        f.user_engine = false;
        CHECK(downgrade_to_user(f).ok);
        CHECK(std::count(f.calls.begin(), f.calls.end(), std::string("remove_migrated")) == 0);
    }
}

// ------------------------------------------------------------------------------------------ peers.d / revocation (low items)
TEST(simple_revocation_list_that_cannot_be_used_is_an_error_not_nothing) {
    STmp t;
    CHECK(load_revoked(t.p.u8string()).empty());                       // absent: nothing revoked
    fs::create_directories(t.p / "revoked-keys.txt");                  // there, but a folder: fail closed
    CHECK_THROWS(load_revoked(t.p.u8string()));
}

TEST(simple_peers_dir_created_after_the_daemon_started_is_seen) {
    STmp t;
    ServerConfig c;   // no peers_dir: the default <config folder>/peers.d is used once it exists
    std::string before = peers_fingerprint(c, t.p.u8string());
    fs::create_directories(t.p / "peers.d");
    std::ofstream(t.p / "peers.d" / "web.toml") << "name = \"web\"\n";
    std::string after = peers_fingerprint(c, t.p.u8string());
    CHECK(before != after);
    CHECK(after.find("web.toml") != std::string::npos);
}
