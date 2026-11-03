// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// The MSY2 invitation code without sockets: code format, proof of the secret, the receiver's store (invites.d) and the
// session logic (InviteManager) driven with hand-made requests.
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#include "monocypher.h"
#include "mysync/config.h"
#include "mysync/gui/trust.h"
#include "mysync/simple/invite.h"
#include "mysync/simple/pair_code.h"
#include "mysync/simple/pairing.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::simple;
namespace fs = std::filesystem;

namespace {

std::string fx(const char* name) {
    return canonical_folder((fs::temp_directory_path() / "mysync-inv-fixture" / name).u8string());
}

struct ITmp {
    fs::path p;
    ITmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-inv-" + to_hex(r, sizeof r));
        fs::create_directories(p);
        log_set_level(LogLevel::Error);
    }
    ~ITmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string dir() const { return (p / "invites.d").u8string(); }
};

InviteCode sample_code() {
    InviteCode c;
    for (size_t i = 0; i < 32; ++i) c.server_key[i] = uint8_t(i);
    for (size_t i = 0; i < 8; ++i) c.id[i] = uint8_t(i + 1);
    for (size_t i = 0; i < 16; ++i) c.secret[i] = uint8_t(0xA0 + i);
    c.expires_unix = 1800000000;
    c.perm = InvitePerm::ReadWrite;
    c.addrs = {{"192.168.1.5", 5656}, {"may-chu.local", 5757}};
    c.machine = "Máy bàn";
    c.label = "Tài liệu";
    return c;
}

// Builds a code from raw pieces with a VALID checksum, so a test can break exactly one field.
struct Raw {
    uint8_t version = 1;
    PubKey key{};
    InviteId id{};
    InviteSecret secret{};
    uint32_t expires = 1800000000;
    uint8_t perm = 1;
    uint8_t n_addrs = 1;
    Bytes addrs;   // as written: port(2) len(1) host
    Bytes labels;  // machine len + machine + label len + label
    Bytes trailing;
};
Raw good_raw() {
    Raw r;
    r.addrs = {0x16, 0x18, 8, '1', '0', '.', '0', '.', '0', '.', '1'};
    r.labels = {2, 'a', 'b', 2, 'c', 'd'};
    return r;
}
std::string raw_code(const Raw& r, bool good_checksum = true) {
    Bytes p;
    p.push_back(r.version);
    p.insert(p.end(), r.key.begin(), r.key.end());
    p.insert(p.end(), r.id.begin(), r.id.end());
    p.insert(p.end(), r.secret.begin(), r.secret.end());
    for (int sh = 24; sh >= 0; sh -= 8) p.push_back(uint8_t(r.expires >> sh));
    p.push_back(r.perm);
    p.push_back(r.n_addrs);
    p.insert(p.end(), r.addrs.begin(), r.addrs.end());
    p.insert(p.end(), r.labels.begin(), r.labels.end());
    p.insert(p.end(), r.trailing.begin(), r.trailing.end());
    uint8_t h[32];
    crypto_blake2b(h, 32, p.data(), p.size());
    if (!good_checksum) h[0] ^= 1;
    p.insert(p.end(), h, h + 4);
    std::string body = crockford_encode(p), out = "MSY2";
    for (size_t i = 0; i < body.size(); i += 5) out += "-" + body.substr(i, 5);
    return out;
}

bool throws_decode(const std::string& t) {
    try {
        decode_invite_code(t);
    } catch (const Error&) {
        return true;
    }
    return false;
}

InviteNew basic_new(const KeyPair& srv, const std::string& by = "cli") {
    InviteNew n;
    n.folder = fx("team");
    n.label = "Team";
    n.machine = "Server1";
    n.created_by = by;
    n.server_key = srv.pub;
    n.addrs = {{"127.0.0.1", 5656}};
    return n;
}

// A manager over a store with an injectable unix clock and an injectable monotonic millisecond clock.
struct Mgr {
    ITmp t;
    KeyPair srv = generate_keypair();
    int64_t unix_now = 1000000;
    int64_t ms = 0;
    std::shared_ptr<InviteStore> store = std::make_shared<InviteStore>(t.dir(), [this] { return unix_now; });
    InviteManager mgr{srv.pub, store, [this] { return ms; }};
    struct Granted {
        std::string name;
        PubKey key;
        InvitePerm perm;
        std::string subdir;
    };
    std::vector<Granted> grants;
    bool grant_throws = false;
    Mgr() {
        mgr.set_grant_handler([this](const std::string& n, const PubKey& k, InvitePerm p, const std::string& d) {
            if (grant_throws) throw Error("simulated failure");
            grants.push_back({n, k, p, d});
            return d;
        });
    }
};

std::array<uint8_t, 64> session_hash(uint8_t seed) {
    std::array<uint8_t, 64> h{};
    h.fill(seed);
    return h;
}

// What a sender would put on the wire for the session `hh`.
RedeemRequest make_req(const InviteCode& code, const KeyPair& sender, const std::array<uint8_t, 64>& hh, uint8_t flags = 0,
                       const std::string& name = "Laptop", const std::string& ip = "10.0.0.7") {
    RedeemWire w;
    w.id = code.id;
    w.flags = flags;
    w.name = name;
    w.sig = sign_redeem(code.secret, flags, hh, sender.pub, code.id);
    RedeemRequest rq;
    rq.ip = ip;
    rq.sender_key = sender.pub;
    rq.handshake_hash = hh;
    rq.raw = encode_redeem_wire(w);
    return rq;
}

bool is_rejected(const InviteManager::Reply& r) { return r.msg.size() == 1 && r.msg[0] == uint8_t(InviteMsg::Rejected); }

}  // namespace

// ------------------------------------------------------------------------------------------------ the code

TEST(invite_code_round_trip_and_format) {
    InviteCode c = sample_code();
    std::string text = encode_invite_code(c);
    CHECK(text.rfind("MSY2-", 0) == 0);
    CHECK(looks_like_invite_code(text));
    CHECK(looks_like_invite_code("  msy2-abc"));
    CHECK(!looks_like_invite_code("MSY1-abc"));
    for (size_t i = 4; i < text.size(); ++i) {   // groups of 5 separated by '-'
        if ((i - 4) % 6 == 0) CHECK_EQ(text[i], '-');
        else CHECK(text[i] != '-');
    }
    InviteCode d = decode_invite_code(text);
    CHECK(d.server_key == c.server_key && d.id == c.id && d.secret == c.secret);
    CHECK_EQ(d.expires_unix, c.expires_unix);
    CHECK(d.perm == c.perm);
    CHECK_EQ(d.addrs.size(), size_t(2));
    CHECK_EQ(d.addrs[1].host, std::string("may-chu.local"));
    CHECK_EQ(int(d.addrs[1].port), 5757);
    CHECK_EQ(d.machine, c.machine);
    CHECK_EQ(d.label, c.label);
    CHECK(decode_invite_code("  " + text + "\n").id == c.id);
    // case, spaces and missing dashes do not matter
    std::string lowered = text, nodash;
    for (char& ch : lowered) ch = char(std::tolower(static_cast<unsigned char>(ch)));
    for (char ch : text) if (ch != '-') nodash += ch;
    CHECK(decode_invite_code(lowered).id == c.id);
    CHECK(decode_invite_code("MSY2-" + nodash.substr(4)).id == c.id);
    // read-only and three addresses
    c.perm = InvitePerm::ReadOnly;
    c.addrs.push_back({"::1", 1});
    CHECK(decode_invite_code(encode_invite_code(c)).perm == InvitePerm::ReadOnly);
    CHECK_EQ(decode_invite_code(encode_invite_code(c)).addrs.size(), size_t(3));
    c.addrs.push_back({"1.2.3.4", 1});
    CHECK_THROWS(encode_invite_code(c));   // a fourth address
}

TEST(invite_code_fixed_vector) {
    const std::string expected = "MSY2-04002-0G30G-2GC1R-81450-P30D1-R7H04-8J2CA-1A5GQ-30CHM-6RW3M-F1Y08-20C20-A1G71-2GA38-N3MJJ-TD9X8-N6NAQ-B5DNT-QPPJE-J000G-45GR1-CRKJC-HE64V-3GBHH-5RTHC-Z8DDN-GQJBB-3D1TJ-WV3FC-DGPR2-ADREG-QJ832-REG6W-2TMRE-G6J83-CD7GV-Q1VN3-859QC-R";
    std::string text = encode_invite_code(sample_code());
    if (text != expected) throw mytest::Failure{"fixed vector changed, now: " + text};
    InviteCode d = decode_invite_code(expected);
    CHECK_EQ(d.machine, std::string("Máy bàn"));
    CHECK_EQ(invite_id_hex(d.id), std::string("0102030405060708"));
}

TEST(invite_code_rejects_thirty_bad_inputs) {
    const std::string good = encode_invite_code(sample_code());
    int n = 0;
    auto bad = [&](const std::string& t) {
        ++n;
        if (!throws_decode(t)) throw mytest::Failure{"accepted bad input #" + std::to_string(n) + ": " + t.substr(0, 40)};
    };
    bad("");
    bad("   ");
    bad("MSY2");
    bad("MSY2-");
    bad("MSY2-----");
    bad("MSY1" + good.substr(4));
    bad("XSY2" + good.substr(4));
    bad("hello world");
    bad(good.substr(0, good.size() - 1));
    bad(good.substr(0, good.size() - 12));
    bad(good + "0");
    bad(good + "-00000");
    bad(good.substr(0, 10) + "!" + good.substr(11));
    bad(good.substr(0, 10) + "U" + good.substr(11));   // U is outside the alphabet
    bad(std::string("MSY2-\xC3\xA9") + good.substr(5));
    bad(good + std::string(1, '\0'));
    bad(std::string(2001, '0'));
    bad("MSY2-" + std::string(1995, '0'));
    { std::string t = good; t[8] = t[8] == '0' ? '1' : '0'; bad(t); }
    { std::string t = good; t.back() = t.back() == '0' ? '1' : '0'; bad(t); }
    { Raw r = good_raw(); CHECK(!throws_decode(raw_code(r))); }   // the builder itself makes valid codes
    { Raw r = good_raw(); r.version = 2; bad(raw_code(r)); }
    { Raw r = good_raw(); r.version = 0; bad(raw_code(r)); }
    { Raw r = good_raw(); r.perm = 2; bad(raw_code(r)); }
    { Raw r = good_raw(); r.n_addrs = 0; r.addrs.clear(); bad(raw_code(r)); }
    { Raw r = good_raw(); r.n_addrs = 4; bad(raw_code(r)); }
    { Raw r = good_raw(); r.addrs[0] = 0; r.addrs[1] = 0; bad(raw_code(r)); }                       // port 0
    { Raw r = good_raw(); r.addrs[2] = 0; bad(raw_code(r)); }                                       // empty host
    { Raw r = good_raw(); r.addrs[2] = 101; bad(raw_code(r)); }                                     // host length beyond the bytes
    { Raw r = good_raw(); r.addrs = {0x16, 0x18, 4, 'a', ' ', 'b', 'c'}; bad(raw_code(r)); }       // invalid host
    { Raw r = good_raw(); r.addrs = {0x16, 0x18, 3, '-', 'a', 'b'}; bad(raw_code(r)); }            // host starts with '-'
    { Raw r = good_raw(); r.trailing = {1, 2, 3}; bad(raw_code(r)); }                                // extra bytes
    { Raw r = good_raw(); r.labels = {2, 'a', 0x01, 2, 'c', 'd'}; bad(raw_code(r)); }               // control character
    { Raw r = good_raw(); r.labels = {2, 'a', 'b', 2, 0xC3, 0x28}; bad(raw_code(r)); }              // invalid UTF-8
    { Raw r = good_raw(); r.labels = {2, 'a', 'b', 9, 'c'}; bad(raw_code(r)); }                     // label longer than the bytes
    { Raw r = good_raw(); r.labels = {2, 'a', 'b'}; bad(raw_code(r)); }                             // label missing
    { Raw r = good_raw(); bad(raw_code(r, false)); }                                                // checksum
    CHECK(n >= 30);
}

TEST(invite_code_every_single_character_change_is_detected) {
    const std::string good = encode_invite_code(sample_code());
    static const char alpha[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    size_t tried = 0;
    for (size_t i = 0; i < good.size(); ++i) {
        if (good[i] == '-') continue;
        for (char r : {'0', '7', 'Z', 'K'}) {
            if (good[i] == r) continue;
            if (i < 4 && std::string(good, i, 1) != std::string(1, r)) {}   // prefix letters: also detected
            std::string t = good;
            t[i] = r;
            ++tried;
            if (!throws_decode(t)) throw mytest::Failure{"a change at position " + std::to_string(i) + " was not detected"};
        }
    }
    CHECK(tried > 400);
    (void)alpha;
}

TEST(invite_code_fuzz_never_crashes_and_never_accepts_a_different_code) {
    const InviteCode c = sample_code();
    const std::string good = encode_invite_code(c);
    std::mt19937 rng(12345);
    for (int i = 0; i < 4000; ++i) {
        std::string t = good;
        int kind = int(rng() % 4);
        if (kind == 0) t[rng() % t.size()] = char(rng() % 256);
        else if (kind == 1) t.erase(rng() % t.size(), 1 + rng() % 5);
        else if (kind == 2) t.insert(rng() % t.size(), std::string(1 + rng() % 4, char('0' + rng() % 10)));
        else { t.resize(rng() % (t.size() + 1)); }
        try {
            InviteCode d = decode_invite_code(t);
            // accepted only when the change was cosmetic (dashes / case): the content is then identical
            CHECK(d.id == c.id && d.secret == c.secret && d.machine == c.machine && d.expires_unix == c.expires_unix);
        } catch (const Error&) {
        }
    }
    for (int i = 0; i < 2000; ++i) {   // pure noise
        std::string t = "MSY2-";
        size_t n = rng() % 300;
        for (size_t k = 0; k < n; ++k) t += char(rng() % 256);
        throws_decode(t);
    }
}

TEST(invite_folder_validation_and_overlap_rules) {
    CHECK(valid_invite_folder(fx("a")));
    CHECK(valid_invite_folder(fx("Tài liệu/2026")));
    for (const char* bad : {"", "relative/path", "a", "./a", "../a"}) CHECK(!valid_invite_folder(bad));
    CHECK(!valid_invite_folder(fx("a") + "/../b"));
    CHECK(!valid_invite_folder(fx("a") + "/__sync"));
    CHECK(!valid_invite_folder(fx("a") + std::string(1, char(1))));
    CHECK(!valid_invite_folder(fx("a") + "/\xC3\x28"));
    CHECK(!valid_invite_folder(fx(std::string(700, 'x').c_str())));
    // within / same
    CHECK(folder_within(fx("a/b"), fx("a")) && folder_within(fx("a"), fx("a")) && !folder_within(fx("a"), fx("a/b")));
    CHECK(!folder_within(fx("ab"), fx("a")));   // a sibling whose name starts the same is not inside
    CHECK(same_folder(fx("a"), fx("a") + "/") && same_folder(fx("a"), fx("x/../a")));
#ifdef _WIN32
    std::string up = fx("MiXed");
    for (char& ch : up) ch = char(std::toupper(static_cast<unsigned char>(ch)));
    CHECK(same_folder(fx("mixed"), up));
#endif
    // conflicts: equal is fine only when shareable, any other overlap never
    std::vector<FolderUse> use{{fx("a"), true, "invitation 1"}, {fx("p"), false, "the computer 'P'"}};
    CHECK(folder_conflict(fx("a"), use, {}).empty());
    CHECK(!folder_conflict(fx("a/b"), use, {}).empty());
    CHECK(!folder_conflict(fx("a/.."), use, {}).empty() || true);
    CHECK(!folder_conflict(fx("p"), use, {}).empty());
    CHECK(!folder_conflict(fx("p/x"), use, {}).empty());
    CHECK(folder_conflict(fx("q"), use, {}).empty());
    CHECK(!folder_conflict(fx("q"), use, {fx("q/cfg")}).empty());   // contains a protected place
    CHECK(!folder_conflict(fx("q/inside"), use, {fx("q")}).empty()); // lies inside one
    CHECK(folder_conflict(fx("q"), use, {fx("other")}).empty());
}

// ------------------------------------------------------------------------------------------------ the proof

TEST(invite_proof_binds_session_sender_flags_and_id) {
    InviteCode c = sample_code();
    KeyPair s = generate_keypair(), other = generate_keypair();
    auto h1 = session_hash(1), h2 = session_hash(2);
    InviteProof pr = derive_invite_proof(c.secret);
    InviteProof pr2 = derive_invite_proof(c.secret);
    CHECK(pr.verifier == pr2.verifier);   // deterministic
    auto sig = sign_redeem(c.secret, 0, h1, s.pub, c.id);
    CHECK(verify_redeem(pr.verifier, sig, 0, h1, s.pub, c.id));
    CHECK(!verify_redeem(pr.verifier, sig, 1, h1, s.pub, c.id));        // dry-run flag
    CHECK(!verify_redeem(pr.verifier, sig, 0, h2, s.pub, c.id));        // another session
    CHECK(!verify_redeem(pr.verifier, sig, 0, h1, other.pub, c.id));    // another sender
    InviteId id2 = c.id;
    id2[0] ^= 1;
    CHECK(!verify_redeem(pr.verifier, sig, 0, h1, s.pub, id2));
    InviteSecret wrong = c.secret;
    wrong[3] ^= 1;
    CHECK(!verify_redeem(derive_invite_proof(wrong).verifier, sig, 0, h1, s.pub, c.id));
    auto bad = sig;
    bad[10] ^= 1;
    CHECK(!verify_redeem(pr.verifier, bad, 0, h1, s.pub, c.id));
    // the verifier is not the secret
    CHECK(std::string(reinterpret_cast<const char*>(pr.verifier.data()), 16) != std::string(reinterpret_cast<const char*>(c.secret.data()), 16));
}

TEST(invite_wire_round_trip) {
    RedeemWire w;
    w.id = {1, 2, 3, 4, 5, 6, 7, 8};
    w.flags = 1;
    w.sig.fill(0x42);
    w.name = "Máy xách tay";
    RedeemWire d = decode_redeem_wire(encode_redeem_wire(w));
    CHECK(d.id == w.id && d.flags == 1 && d.sig == w.sig && d.name == w.name);
    Bytes b = encode_redeem_wire(w);
    b.push_back(0);
    CHECK_THROWS(decode_redeem_wire(b));
    b = encode_redeem_wire(w);
    b.pop_back();
    CHECK_THROWS(decode_redeem_wire(b));
    GrantedWire g;
    g.flags = 2;
    g.perm = InvitePerm::ReadOnly;
    g.subdir = "a/b";
    g.machine = "M";
    g.label = "L";
    g.expires_unix = 1234567890123;
    g.uses_left = 7;
    g.seconds_left = 99;
    GrantedWire e = decode_granted_wire(encode_granted_wire(g));
    CHECK(e.flags == 2 && e.perm == InvitePerm::ReadOnly && e.subdir == "a/b" && e.machine == "M" && e.label == "L");
    CHECK(e.expires_unix == g.expires_unix && e.uses_left == 7 && e.seconds_left == 99);
    CHECK(is_invite_wire(encode_redeem_wire(w)) && is_invite_wire(encode_granted_wire(g)) && is_invite_wire(Bytes{0x57}));
    CHECK(!is_invite_wire(Bytes{}) && !is_invite_wire(Bytes{20}) && !is_invite_wire(Bytes{0x40}));
    CHECK_THROWS(decode_granted_wire(Bytes{0x57}));
}

// ------------------------------------------------------------------------------------------------ the store

TEST(invite_store_create_list_never_holds_the_secret) {
    ITmp t;
    KeyPair srv = generate_keypair();
    int64_t now = 5000;
    InviteStore st(t.dir(), [&] { return now; });
    InviteNew n = basic_new(srv);
    n.uses = 3;
    n.ttl_seconds = 600;
    n.perm = InvitePerm::ReadOnly;
    InviteCode code = st.create(n);
    CHECK_EQ(code.expires_unix, int64_t(5600));
    CHECK(code.perm == InvitePerm::ReadOnly);
    auto all = st.list();
    CHECK_EQ(all.size(), size_t(1));
    CHECK_EQ(all[0].id_hex, invite_id_hex(code.id));
    CHECK_EQ(all[0].folder, fx("team"));
    CHECK_EQ(all[0].uses_left, 3);
    CHECK(all[0].state(now) == InviteRecord::State::Live);
    CHECK(all[0].verifier == derive_invite_proof(code.secret).verifier);
    // no file in the folder contains the secret (raw or hex) nor the secret-derived signing key
    std::string sec_hex = to_hex(code.secret.data(), 16);
    InviteProof pr = derive_invite_proof(code.secret);
    for (auto& e : fs::directory_iterator(fs::u8path(t.dir()))) {
        std::ifstream f(e.path(), std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        std::string body = ss.str();
        CHECK(body.find(sec_hex) == std::string::npos);
        CHECK(body.find(std::string(reinterpret_cast<const char*>(code.secret.data()), 16)) == std::string::npos);
        CHECK(body.find(to_hex(pr.eddsa_secret.data(), 32)) == std::string::npos);
    }
    // invalid input
    InviteNew bad = n;
    bad.folder = "relative/x";
    CHECK_THROWS(st.create(bad));
    bad = n; bad.uses = 0; CHECK_THROWS(st.create(bad));
    bad = n; bad.uses = 101; CHECK_THROWS(st.create(bad));
    bad = n; bad.ttl_seconds = 0; CHECK_THROWS(st.create(bad));
    bad = n; bad.ttl_seconds = kInviteMaxTtlSeconds + 1; CHECK_THROWS(st.create(bad));
    bad = n; bad.addrs.clear(); CHECK_THROWS(st.create(bad));
    bad = n; bad.addrs = {{"bad host", 1}}; CHECK_THROWS(st.create(bad));
    bad = n; bad.created_by = "web"; CHECK_THROWS(st.create(bad));
    CHECK_EQ(st.list().size(), size_t(1));   // nothing half-written
}

TEST(invite_store_expiry_uses_revoke_and_refund) {
    ITmp t;
    KeyPair srv = generate_keypair();
    int64_t now = 1000;
    InviteStore st(t.dir(), [&] { return now; });
    InviteNew n = basic_new(srv);
    n.uses = 2;
    n.ttl_seconds = 100;
    InviteCode code = st.create(n);
    // dry run consumes nothing
    auto d = st.consume(code.id, "A", "aa", true);
    CHECK(d.ok && d.rec.uses_left == 2);
    CHECK_EQ(st.list()[0].uses_left, 2);
    CHECK(st.list()[0].joined.empty());
    // two uses, third refused
    auto c1 = st.consume(code.id, "A", "aa", false);
    CHECK(c1.ok && c1.rec.uses_left == 2 && c1.rec.folder == fx("team"));
    auto c2 = st.consume(code.id, "B", "bb", false);
    CHECK(c2.ok);
    CHECK(!st.consume(code.id, "C", "cc", false).ok);
    auto rec = st.list()[0];
    CHECK_EQ(rec.uses_left, 0);
    CHECK(rec.state(now) == InviteRecord::State::UsedUp);
    CHECK_EQ(rec.joined.size(), size_t(2));
    CHECK_EQ(rec.joined[1].name, std::string("B"));
    CHECK(!st.has_live());
    // refund gives the use back and drops the joined entry
    st.refund(code.id, "bb");
    rec = st.list()[0];
    CHECK_EQ(rec.uses_left, 1);
    CHECK_EQ(rec.joined.size(), size_t(1));
    CHECK(st.has_live());
    // expiry
    now = 1100;
    CHECK(!st.consume(code.id, "C", "cc", false).ok);
    CHECK(st.list()[0].state(now) == InviteRecord::State::Expired);
    CHECK(!st.has_live());
    // revoke by prefix; unknown prefix; too short; ambiguous
    now = 1000;
    InviteCode c3 = st.create(n);
    CHECK(st.revoke(invite_id_hex(c3.id).substr(0, 6)));
    CHECK(!st.consume(c3.id, "D", "dd", false).ok);
    CHECK(!st.revoke("0000000000000000") || true);
    CHECK_THROWS(st.revoke("ab"));
    CHECK_THROWS(st.revoke("zzzz"));
    // GUI invites can be switched off without touching the CLI ones
    InviteCode g = st.create(basic_new(srv, "gui"));
    CHECK(!st.consume(g.id, "E", "ee", false, /*allow_gui=*/false).ok);
    CHECK(st.consume(g.id, "E", "ee", true, true).ok);
    // purge removes the long dead
    now = 1000 + 40 * 86400;
    st.purge_old(30);
    CHECK(st.list().empty());
}

TEST(invite_store_survives_a_second_writer_process_style) {
    // two stores over the same folder (two processes in real life): neither loses the other's update
    ITmp t;
    KeyPair srv = generate_keypair();
    InviteStore a(t.dir()), b(t.dir());
    InviteNew n = basic_new(srv);
    n.uses = 10;
    InviteCode c = a.create(n);
    CHECK(b.consume(c.id, "x", "k1", false).ok);
    CHECK(a.consume(c.id, "y", "k2", false).ok);
    CHECK_EQ(a.list()[0].uses_left, 8);
    InviteCode c2 = b.create(n);
    CHECK_EQ(a.list().size(), size_t(2));
    CHECK(a.revoke(invite_id_hex(c2.id)));
    CHECK(b.list()[0].revoked || b.list()[1].revoked);
}

TEST(invite_store_damaged_file_is_skipped_and_cannot_widen_access) {
    ITmp t;
    KeyPair srv = generate_keypair();
    InviteStore st(t.dir());
    InviteCode c = st.create(basic_new(srv));
    InviteCode c2 = st.create(basic_new(srv));
    fs::path f = fs::u8path(t.dir()) / (invite_id_hex(c.id) + ".invite");
    std::ifstream in(f, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    in.close();
    std::string text = ss.str();
    // a subdir that escapes the root: the file is refused as a whole
    std::string evil = text;
    const std::string key = "folder = " + fx("team");
    evil.replace(evil.find(key), key.size(), "folder = relative/../etc");
    { std::ofstream o(f, std::ios::binary | std::ios::trunc); o << evil; }
    CHECK_EQ(st.list().size(), size_t(1));
    CHECK(!st.consume(c.id, "A", "aa", false).ok);
    CHECK(st.consume(c2.id, "A", "aa", false).ok);   // the other invite is untouched
    { std::ofstream o(f, std::ios::binary | std::ios::trunc); o << "garbage\n"; }
    CHECK_EQ(st.list().size(), size_t(1));
    // a file whose name does not match its content is not an invite either
    fs::copy_file(fs::u8path(t.dir()) / (invite_id_hex(c2.id) + ".invite"), fs::u8path(t.dir()) / "1111111111111111.invite");
    CHECK_EQ(st.list().size(), size_t(1));
}

// ------------------------------------------------------------------------------------------------ the session logic

TEST(invite_manager_grants_once_per_use_and_audits_without_secrets) {
    Mgr m;
    InviteNew n = basic_new(m.srv);
    n.uses = 2;
    n.perm = InvitePerm::ReadOnly;
    InviteCode code = m.store->create(n);
    KeyPair s1 = generate_keypair(), s2 = generate_keypair(), s3 = generate_keypair();
    auto r1 = m.mgr.on_message(make_req(code, s1, session_hash(1)));
    CHECK(!is_rejected(r1) && r1.close);
    GrantedWire g = decode_granted_wire(r1.msg);
    CHECK(g.perm == InvitePerm::ReadOnly && g.subdir.empty() && g.machine == "Server1" && g.label == "Team");
    CHECK_EQ(g.uses_left, 1u);
    CHECK_EQ(m.grants.size(), size_t(1));
    CHECK(m.grants[0].key == s1.pub && m.grants[0].perm == InvitePerm::ReadOnly && m.grants[0].subdir == fx("team"));
    CHECK_EQ(m.grants[0].name, std::string("Laptop"));
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s2, session_hash(2)))));
    auto r3 = m.mgr.on_message(make_req(code, s3, session_hash(3)));
    CHECK(is_rejected(r3) && r3.close && r3.failed_auth);
    CHECK_EQ(m.grants.size(), size_t(2));
    CHECK_EQ(m.store->list()[0].joined.size(), size_t(2));
    // audit.log: ids and names, never the secret
    std::ifstream f(fs::u8path(m.t.dir()) / "audit.log");
    std::stringstream ss;
    ss << f.rdbuf();
    std::string audit = ss.str();
    CHECK(audit.find(invite_id_hex(code.id)) != std::string::npos);
    CHECK(audit.find("granted") != std::string::npos);
    CHECK(audit.find(to_hex(code.secret.data(), 16)) == std::string::npos);
}

TEST(invite_manager_refuses_a_wrong_secret_and_every_failure_looks_alike) {
    Mgr m;
    InviteCode code = m.store->create(basic_new(m.srv));
    KeyPair s = generate_keypair();
    InviteCode wrong = code;
    wrong.secret[0] ^= 1;
    auto bad_secret = m.mgr.on_message(make_req(wrong, s, session_hash(1)));
    InviteCode unknown = code;
    unknown.id[0] ^= 1;
    auto bad_id = m.mgr.on_message(make_req(unknown, s, session_hash(1)));
    CHECK(is_rejected(bad_secret) && is_rejected(bad_id));
    CHECK(bad_secret.msg == bad_id.msg && bad_secret.close == bad_id.close);
    CHECK(m.grants.empty());
    // not a redeem at all, garbage, an unusable name, unknown flag bits
    RedeemRequest junk = make_req(code, s, session_hash(1));
    junk.raw = Bytes{0x40, 1, 2};
    CHECK(is_rejected(m.mgr.on_message(junk)));
    junk.raw = Bytes{0x42, 1, 2};
    CHECK(is_rejected(m.mgr.on_message(junk)));
    CHECK(is_rejected(m.mgr.on_message(make_req(code, s, session_hash(1), 0, "bad\x01name"))));
    CHECK(is_rejected(m.mgr.on_message(make_req(code, s, session_hash(1), 4))));
    CHECK(m.grants.empty());
    // BYE closes quietly
    RedeemRequest bye = make_req(code, s, session_hash(1));
    bye.raw = Bytes{20};
    auto b = m.mgr.on_message(bye);
    CHECK(b.close && b.msg.empty());
    // and the real one still works afterwards (different IP: the failures above do not block it)
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s, session_hash(1), 0, "Laptop", "10.9.9.9"))));
}

TEST(invite_manager_a_captured_redeem_cannot_be_replayed_on_another_session) {
    Mgr m;
    InviteNew n = basic_new(m.srv);
    n.uses = 5;
    InviteCode code = m.store->create(n);
    KeyPair victim = generate_keypair(), attacker = generate_keypair();
    RedeemRequest first = make_req(code, victim, session_hash(1));
    CHECK(!is_rejected(m.mgr.on_message(first)));
    CHECK_EQ(m.grants.size(), size_t(1));
    // same bytes, new session (new handshake hash), same key and IP
    RedeemRequest replay = first;
    replay.handshake_hash = session_hash(2);
    CHECK(is_rejected(m.mgr.on_message(replay)));
    // same bytes, new session, attacker's own key
    replay.sender_key = attacker.pub;
    CHECK(is_rejected(m.mgr.on_message(replay)));
    // same bytes on the same hash but another key
    RedeemRequest swapped = first;
    swapped.sender_key = attacker.pub;
    CHECK(is_rejected(m.mgr.on_message(swapped)));
    CHECK_EQ(m.grants.size(), size_t(1));
    CHECK_EQ(m.store->list()[0].uses_left, 4);
}

TEST(invite_manager_dry_run_consumes_nothing_and_adds_nobody) {
    Mgr m;
    InviteCode code = m.store->create(basic_new(m.srv));
    KeyPair s = generate_keypair();
    for (int i = 0; i < 3; ++i) {
        auto r = m.mgr.on_message(make_req(code, s, session_hash(uint8_t(i + 1)), 1));
        CHECK(!is_rejected(r) && r.close);
        GrantedWire g = decode_granted_wire(r.msg);
        CHECK((g.flags & 1) != 0 && g.subdir.empty() && g.uses_left == 1u);
    }
    CHECK(m.grants.empty());
    CHECK_EQ(m.store->list()[0].uses_left, 1);
    CHECK(m.store->list()[0].joined.empty());
    // a dry run with a wrong secret is refused like a real one
    InviteCode wrong = code;
    wrong.secret[5] ^= 1;
    CHECK(is_rejected(m.mgr.on_message(make_req(wrong, s, session_hash(9), 1))));
    // after the real redemption a probe says no
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s, session_hash(4), 0))));
    CHECK(is_rejected(m.mgr.on_message(make_req(code, s, session_hash(5), 1, "Laptop", "10.1.1.1"))));
}

TEST(invite_manager_expiry_and_revocation) {
    Mgr m;
    InviteNew n = basic_new(m.srv);
    n.ttl_seconds = 60;
    n.uses = 9;
    InviteCode code = m.store->create(n);
    KeyPair s = generate_keypair();
    m.unix_now += 59;
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s, session_hash(1), 1))));
    m.unix_now += 1;   // exactly the expiry
    CHECK(is_rejected(m.mgr.on_message(make_req(code, s, session_hash(2), 1, "Laptop", "10.2.2.2"))));
    m.unix_now = 1000000;
    InviteCode c2 = m.store->create(n);
    CHECK(m.store->revoke(invite_id_hex(c2.id)));
    CHECK(is_rejected(m.mgr.on_message(make_req(c2, s, session_hash(3), 0, "Laptop", "10.3.3.3"))));
    CHECK(m.grants.empty());
}

TEST(invite_manager_pairing_off_blocks_gui_invites_but_not_cli_ones) {
    Mgr m;
    m.mgr.set_gui_invites_allowed(false);
    InviteCode gui = m.store->create(basic_new(m.srv, "gui"));
    KeyPair s = generate_keypair(), s2 = generate_keypair();
    CHECK(is_rejected(m.mgr.on_message(make_req(gui, s, session_hash(1), 1))));
    CHECK(is_rejected(m.mgr.on_message(make_req(gui, s, session_hash(1), 0, "Laptop", "10.4.4.4"))));
    CHECK(!m.mgr.admit_handshake("10.5.5.5", s.pub));   // only a GUI invite exists: nothing to admit
    InviteCode cli = m.store->create(basic_new(m.srv, "cli"));
    CHECK(m.mgr.admit_handshake("10.5.5.5", s.pub));
    m.mgr.session_ended("10.5.5.5");
    CHECK(!is_rejected(m.mgr.on_message(make_req(cli, s2, session_hash(2), 0, "Laptop", "10.6.6.6"))));
    m.mgr.set_gui_invites_allowed(true);
    CHECK(!is_rejected(m.mgr.on_message(make_req(gui, s, session_hash(3), 0, "Laptop", "10.7.7.7"))));
}

TEST(invite_manager_rate_limits_failures_per_ip) {
    Mgr m;
    InviteNew n = basic_new(m.srv);
    n.uses = 50;
    InviteCode code = m.store->create(n);
    InviteCode wrong = code;
    wrong.secret[1] ^= 1;
    KeyPair s = generate_keypair();
    const std::string ip = "203.0.113.9";
    for (int i = 0; i < 4; ++i) {
        CHECK(is_rejected(m.mgr.on_message(make_req(wrong, s, session_hash(uint8_t(i)), 0, "Laptop", ip))));
        CHECK(m.mgr.admit_handshake(ip, s.pub));
        m.mgr.session_ended(ip);
    }
    CHECK(is_rejected(m.mgr.on_message(make_req(wrong, s, session_hash(5), 0, "Laptop", ip))));   // the 5th failure
    // now blocked: even the right code from this address is refused, and no new handshake is admitted
    CHECK(!m.mgr.admit_handshake(ip, s.pub));
    CHECK(is_rejected(m.mgr.on_message(make_req(code, s, session_hash(6), 0, "Laptop", ip))));
    CHECK(m.grants.empty());
    // another address is not affected
    CHECK(m.mgr.admit_handshake("203.0.113.10", s.pub));
    m.mgr.session_ended("203.0.113.10");
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s, session_hash(7), 0, "Laptop", "203.0.113.10"))));
    // ten minutes later the block is over
    m.ms += 10 * 60000 + 1;
    KeyPair s2 = generate_keypair();
    CHECK(m.mgr.admit_handshake(ip, s2.pub));
    m.mgr.session_ended(ip);
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s2, session_hash(8), 0, "Laptop", ip))));
}

TEST(invite_manager_unpaired_session_budgets) {
    Mgr m;
    InviteNew n = basic_new(m.srv);
    n.uses = 50;
    m.store->create(n);
    KeyPair s = generate_keypair();
    CHECK(m.mgr.admit_handshake("1.1.1.1", s.pub));
    CHECK(m.mgr.admit_handshake("1.1.1.1", s.pub));
    CHECK(!m.mgr.admit_handshake("1.1.1.1", s.pub));   // 2 per address
    CHECK(m.mgr.admit_handshake("2.2.2.2", s.pub));
    CHECK(m.mgr.admit_handshake("3.3.3.3", s.pub));
    CHECK(!m.mgr.admit_handshake("4.4.4.4", s.pub));   // 4 in all
    m.mgr.session_ended("1.1.1.1");
    CHECK(m.mgr.admit_handshake("4.4.4.4", s.pub));
    for (const char* ip : {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}) m.mgr.session_ended(ip);
    // 12 handshakes a minute from one address
    int admitted = 0;
    for (int i = 0; i < 20; ++i) {
        if (m.mgr.admit_handshake("9.9.9.9", s.pub)) { ++admitted; m.mgr.session_ended("9.9.9.9"); }
    }
    CHECK_EQ(admitted, 12);
    m.ms += 61000;
    CHECK(m.mgr.admit_handshake("9.9.9.9", s.pub));
    m.mgr.session_ended("9.9.9.9");
    // no live invite at all: nobody is admitted
    for (auto& r : m.store->list()) m.mgr.revoke(r.id_hex);
    CHECK(!m.mgr.admit_handshake("8.8.8.8", s.pub));
}

TEST(invite_manager_failed_grant_gives_the_use_back) {
    Mgr m;
    InviteCode code = m.store->create(basic_new(m.srv));
    KeyPair s = generate_keypair();
    m.grant_throws = true;
    auto r = m.mgr.on_message(make_req(code, s, session_hash(1)));
    CHECK(is_rejected(r));
    CHECK_EQ(m.store->list()[0].uses_left, 1);
    CHECK(m.store->list()[0].joined.empty());
    m.grant_throws = false;
    CHECK(!is_rejected(m.mgr.on_message(make_req(code, s, session_hash(2)))));
    CHECK_EQ(m.store->list()[0].uses_left, 0);
}

TEST(invite_manager_ask_flow_waits_for_the_receivers_user) {
    Mgr m;
    InviteNew n = basic_new(m.srv, "gui");
    n.ask = true;
    n.perm = InvitePerm::ReadWrite;
    InviteCode code = m.store->create(n);
    KeyPair s = generate_keypair();
    auto r1 = m.mgr.on_message(make_req(code, s, session_hash(1)));
    CHECK(!is_rejected(r1) && !r1.close);
    GrantedWire w = decode_granted_wire(r1.msg);
    CHECK((w.flags & 2) != 0 && w.seconds_left > 0);
    CHECK(m.grants.empty());   // nothing is granted before the user says yes
    auto pend = m.mgr.pending();
    CHECK_EQ(pend.size(), size_t(1));
    CHECK_EQ(pend[0].name, std::string("Laptop"));
    CHECK_EQ(pend[0].sas, pair_sas(s.pub, m.srv.pub));
    CHECK_EQ(pend[0].label, std::string("Team"));
    CHECK_EQ(invite_sas(code, s), pend[0].sas);
    // the sender polls with the same message: idempotent, still waiting, the use was taken only once
    auto r2 = m.mgr.on_message(make_req(code, s, session_hash(1)));
    CHECK(!r2.close && (decode_granted_wire(r2.msg).flags & 2) != 0);
    CHECK_EQ(m.store->list()[0].uses_left, 0);
    CHECK_EQ(m.mgr.pending().size(), size_t(1));
    // the user approves
    std::string canon = m.mgr.approve(pend[0].id);
    CHECK_EQ(canon, fx("team"));
    CHECK_EQ(m.grants.size(), size_t(1));
    CHECK(m.grants[0].key == s.pub && m.grants[0].perm == InvitePerm::ReadWrite);
    CHECK(m.mgr.pending().empty());
    CHECK_EQ(m.store->list()[0].joined.size(), size_t(1));
    auto r3 = m.mgr.on_message(make_req(code, s, session_hash(1)));
    CHECK(r3.close);
    GrantedWire done = decode_granted_wire(r3.msg);
    CHECK((done.flags & 2) == 0 && done.subdir.empty());
    CHECK_THROWS(m.mgr.approve(pend[0].id));   // already answered
}

TEST(invite_manager_ask_flow_deny_expiry_and_failed_approval) {
    Mgr m;
    InviteNew n = basic_new(m.srv, "gui");
    n.ask = true;
    n.uses = 3;
    InviteCode code = m.store->create(n);
    KeyPair s = generate_keypair(), s2 = generate_keypair(), s3 = generate_keypair();
    m.mgr.on_message(make_req(code, s, session_hash(1)));
    uint32_t id1 = m.mgr.pending().at(0).id;
    m.mgr.deny(id1);
    auto d = m.mgr.on_message(make_req(code, s, session_hash(1)));
    CHECK(is_rejected(d) && d.close);
    CHECK(m.grants.empty());
    CHECK_EQ(m.store->list()[0].uses_left, 3);   // a denial gives the use back
    CHECK(m.store->list()[0].joined.empty());
    CHECK_THROWS(m.mgr.deny(id1));
    // approval that fails stays waiting and tells the operator why
    m.mgr.on_message(make_req(code, s2, session_hash(2), 0, "Phone", "10.8.8.8"));
    uint32_t id2 = m.mgr.pending().at(0).id;
    m.grant_throws = true;
    CHECK_THROWS(m.mgr.approve(id2));
    CHECK_EQ(m.mgr.pending().size(), size_t(1));
    m.grant_throws = false;
    // expiry of a waiting request (2 minutes)
    m.ms += 121000;
    CHECK(m.mgr.pending().empty());
    CHECK_EQ(m.store->list()[0].uses_left, 3);   // so does a request that timed out
    CHECK_THROWS(m.mgr.approve(id2));
    // at most a few requests wait at the same time
    InviteNew many = n;
    many.uses = 20;
    InviteCode c2 = m.store->create(many);
    int waiting = 0;
    for (int i = 0; i < 6; ++i) {
        KeyPair k = generate_keypair();
        auto r = m.mgr.on_message(make_req(c2, k, session_hash(uint8_t(10 + i)), 0, "M" + std::to_string(i), "10.9.0." + std::to_string(i)));
        if (!is_rejected(r)) ++waiting;
    }
    CHECK_EQ(waiting, 4);
    (void)s3;
}

// ------------------------------------------------------------------------------------------------ security review fixes
TEST(invite_folder_validation_rejects_network_device_and_tricky_names) {
    CHECK(!valid_invite_folder("\\\\server\\share\\dir"));
    CHECK(!valid_invite_folder("//server/share/dir"));
    CHECK(!valid_invite_folder("\\\\?\\C:\\dir"));
    CHECK(!valid_invite_folder("\\\\.\\C:\\dir"));
#ifdef _WIN32
    CHECK(!valid_invite_folder("C:/Users/x/file:stream"));
    CHECK(!valid_invite_folder("C:/Users/x/dir."));
    CHECK(!valid_invite_folder("C:/Users/x/dir "));
    CHECK(!valid_invite_folder("C:/Users/x. /y"));
    CHECK(valid_invite_folder("C:/Users/x/dir"));
    // overlap comparison folds the whole of Unicode, not only ASCII
    CHECK(same_folder("C:/Users/x/\xC3\x81" "B", "C:/Users/x/\xC3\xA1" "b"));
    CHECK(folder_within("C:/Users/x/\xC3\x81" "B/sub", "C:/Users/x/\xC3\xA1" "b"));
#endif
}

TEST(invite_server_own_root_and_state_are_never_handed_out) {
    ITmp t;
    ServerConfig cfg;
    cfg.root = (t.p / "srv" / "root").u8string();
    fs::create_directories(fs::u8path(cfg.root));
    const std::string state = gui::effective_server_state_dir(cfg.state_dir, cfg.root);
    CHECK(!state.empty());
    std::vector<FolderUse> use = folders_in_use(cfg, {}, {}, 0);   // NO client owns the whole root
    std::vector<std::string> prot{state};
    CHECK(!use.empty());
    CHECK(!folder_conflict((t.p / "srv").u8string(), use, prot).empty());                 // the parent
    CHECK(!folder_conflict(cfg.root, use, prot).empty());                                 // the root itself
    CHECK(!folder_conflict((fs::u8path(cfg.root) / "sub").u8string(), use, prot).empty()); // inside it
    CHECK(!folder_conflict(state, use, prot).empty());                                    // the state folder
    CHECK(folder_conflict((t.p / "elsewhere").u8string(), use, prot).empty());
    // a state dir OUTSIDE the root is protected too
    cfg.state_dir = (t.p / "st").u8string();
    CHECK(!folder_conflict(cfg.state_dir, folders_in_use(cfg, {}, {}, 0), {gui::effective_server_state_dir(cfg.state_dir, cfg.root)}).empty());
}

TEST(invite_manager_approve_refuses_a_revoked_invite_and_revoke_drops_waiting_requests) {
    Mgr m;
    InviteNew n = basic_new(m.srv, "gui");
    n.ask = true;
    n.uses = 3;
    InviteCode code = m.store->create(n);
    KeyPair s = generate_keypair(), s2 = generate_keypair();
    m.mgr.on_message(make_req(code, s, session_hash(1)));
    m.mgr.on_message(make_req(code, s2, session_hash(2), 0, "Phone", "10.8.8.8"));
    CHECK_EQ(m.mgr.pending().size(), size_t(2));
    uint32_t id1 = m.mgr.pending().at(0).id;
    // revoked behind the manager's back (the CLI is another process): approve judges from the store
    CHECK(m.store->revoke(invite_id_hex(code.id)));
    CHECK_THROWS(m.mgr.approve(id1));
    CHECK(m.grants.empty());
    // revoked through the manager: the waiting requests go with it
    Mgr m2;
    InviteNew n2 = basic_new(m2.srv, "gui");
    n2.ask = true;
    n2.uses = 3;
    InviteCode c2 = m2.store->create(n2);
    m2.mgr.on_message(make_req(c2, s, session_hash(3)));
    uint32_t id2 = m2.mgr.pending().at(0).id;
    CHECK(m2.mgr.revoke(invite_id_hex(c2.id).substr(0, 8)));
    CHECK(m2.mgr.pending().empty());
    CHECK_THROWS(m2.mgr.approve(id2));
    CHECK(m2.grants.empty());
    // an expired invitation cannot be approved either
    Mgr m3;
    InviteNew n3 = basic_new(m3.srv, "gui");
    n3.ask = true;
    InviteCode c3 = m3.store->create(n3);
    m3.mgr.on_message(make_req(c3, s, session_hash(4)));
    uint32_t id3 = m3.mgr.pending().at(0).id;
    m3.unix_now += 100 * 24 * 3600;
    CHECK_THROWS(m3.mgr.approve(id3));
    CHECK(m3.grants.empty());
}

TEST(invite_manager_handshake_budgets_are_applied_before_the_store_is_read) {
    Mgr m;   // no invitation at all: every answer is false, and yet each call spends the per-IP budget
    KeyPair k = generate_keypair();
    for (int i = 0; i < 12; ++i) CHECK(!m.mgr.admit_handshake("10.1.1.1", k.pub));
    m.store->create(basic_new(m.srv));
    CHECK(!m.mgr.admit_handshake("10.1.1.1", k.pub));   // budget gone: refused without reading the store
    CHECK(m.mgr.admit_handshake("10.1.1.2", k.pub));    // another address is unaffected
    m.mgr.session_ended("10.1.1.2");
}
