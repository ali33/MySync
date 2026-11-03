// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// MSY2 over real loopback sockets: the handshake hash, `mysync invite ...`, a ServerDaemon that redeems codes, and a
// sender that probes / redeems and then syncs a file with the access the invite granted.
#include <atomic>
#include <thread>

#include "../src/fileio.h"
#include "mysync/client_engine.h"
#include "mysync/config.h"
#include "mysync/gui/daemon.h"
#include "mysync/hash.h"
#include "mysync/nettarget.h"
#include "mysync/peers.h"
#include "mysync/protocol.h"
#include "mysync/secure_channel.h"
#include "mysync/simple/invite.h"
#include "mysync/simple/pairing.h"
#include "so_util.h"

using namespace mysync;
using namespace mysync::simple;
using namespace mysync::gui;

namespace {

std::string dir_of_cfg(const std::string& cfg) { return fs::u8path(cfg).parent_path().u8string(); }
std::string fwd(const fs::path& p) { return p.generic_u8string(); }

// "key":"value" out of a one-line JSON document made by the CLI (ASCII-escaped, no nested quotes in what we ask for).
std::string jstr(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t i = json.find(pat);
    if (i == std::string::npos) return {};
    i += pat.size();
    std::string out;
    for (; i < json.size() && json[i] != '"'; ++i) {
        if (json[i] == '\\' && i + 1 < json.size()) ++i;
        out += json[i];
    }
    return out;
}
std::string jnum(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\":";
    size_t i = json.find(pat);
    if (i == std::string::npos) return {};
    i += pat.size();
    size_t j = i;
    while (j < json.size() && (std::isdigit(static_cast<unsigned char>(json[j])) || json[j] == '-')) ++j;
    return json.substr(i, j - i);
}

struct Net {
    net::Socket a, b;
};
Net socket_pair() {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    net::Socket a = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    net::Socket b = l.accept(3000);
    CHECK(b.valid());
    return {std::move(a), std::move(b)};
}

// A running ServerDaemon on loopback with one bootstrap client, no control channel.
struct DEnv {
    Tmp t;
    fs::path root, cfg, key, state;
    KeyPair skp = generate_keypair();
    uint16_t port = free_port();
    std::atomic<bool> stop{false};
    std::thread th;
    std::string fail;
    std::unique_ptr<ServerDaemon> sd;

    explicit DEnv(bool pairing_on, bool allow_pairing, int poll_ms = 0) {
        root = t.p / "root";
        cfg = t.p / "cfg" / "server.toml";   // beside the folders that get shared, never inside them
        key = t.p / "cfg" / "server.key";
        state = t.p / "cfg" / "state";
        fs::create_directories(root);
        fs::create_directories(t.p / "cfg");
        save_keypair(key.u8string(), skp);
        std::string text = "[server]\nbind = \"127.0.0.1\"\nport = " + std::to_string(port) + "\nroot = \"" + fwd(root) +
                           "\"\nkey_file = \"" + fwd(key) + "\"\nstate_dir = \"" + fwd(state) + "\"\nlog_level = \"error\"\n" +
                           (pairing_on ? "pairing = \"on-demand\"\n" : "") +
                           (poll_ms > 0 ? "peers_dir = \"" + fwd(t.p / "cfg" / "peers.d") + "\"\n" : "") +
                           "\n[control]\nenabled = false\n\n[[client]]\nname = \"boot\"\npublic_key = \"" + key_to_hex(generate_keypair().pub) + "\"\n";
        spit(cfg, text);
        DaemonOptions o;
        o.service_name = "inv-test";
        o.config_path = cfg.u8string();
        o.version = "test";
        o.allow_pairing = allow_pairing;
        o.peers_poll_ms = poll_ms;
        o.reload_min_interval_ms = 0;
        sd = std::make_unique<ServerDaemon>(load_server_config_resolved(o.config_path), fwd(t.p), o);
        th = std::thread([this] {
            try {
                sd->run(stop);
            } catch (const std::exception& e) {
                fail = e.what();
            }
        });
        CHECK(wait_until([&] { return sd->invites() != nullptr; }, 10000));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    ~DEnv() {
        stop = true;
        if (th.joinable()) th.join();
    }
    std::string cli_create(const std::vector<std::string>& extra) {
        std::vector<std::string> a{"invite", "create", "-c", cfg.u8string(), "--address", "127.0.0.1:" + std::to_string(port), "--json"};
        a.insert(a.end(), extra.begin(), extra.end());
        Run r = cli(a);
        if (r.rc != 0) throw mytest::Failure{"invite create failed: " + r.err};
        return r.out;
    }
    std::vector<ClientAcl> peers_cache;   // find_peer returns a pointer into it
    const std::vector<ClientAcl>& peers() {
        peers_cache = peer_list(cfg.u8string());
        return peers_cache;
    }
    const ClientAcl* find_peer(const std::vector<ClientAcl>& v, const PubKey& k) {
        for (const auto& c : v)
            if (c.public_key == k) return &c;
        return nullptr;
    }
};

FileMeta meta_of(const fs::path& abs, const std::string& rel) {
    FileMeta m;
    m.rel = rel;
    fio::StatInfo st = fio::stat_path(abs);
    m.size = st.size;
    m.mtime_ns = st.mtime_ns;
    m.hash = hash_file(abs.u8string());
    return m;
}

std::unique_ptr<ITarget> target_for(const DEnv& e, const KeyPair& self) {
    TargetConfig tc;
    tc.host = "127.0.0.1";
    tc.port = e.port;
    tc.server_key = e.skp.pub;
    return make_net_target(tc, ClientConfig(), self, nullptr);
}

}  // namespace

// ------------------------------------------------------------------------------------------------ handshake hash

TEST(invite_handshake_hash_is_equal_on_both_sides_and_differs_per_session) {
    KeyPair srv = generate_keypair(), cli_kp = generate_keypair();
    std::array<uint8_t, 64> ch_h[2], sv_h[2];
    for (int round = 0; round < 2; ++round) {
        Net p = socket_pair();
        std::array<uint8_t, 64> server_side{};
        std::thread st([&] {
            SecureChannel ch = SecureChannel::server(std::move(p.b), srv, [](const PubKey&) { return true; }, 4000);
            server_side = ch.handshake_hash();
            ch.send_msg(Bytes{1});
        });
        SecureChannel c = SecureChannel::client(std::move(p.a), cli_kp, srv.pub, 4000);
        c.recv_msg();
        st.join();
        ch_h[round] = c.handshake_hash();
        sv_h[round] = server_side;
    }
    std::array<uint8_t, 64> zero{};
    CHECK(ch_h[0] == sv_h[0] && ch_h[1] == sv_h[1]);
    CHECK(ch_h[0] != zero);
    CHECK(ch_h[0] != ch_h[1]);
    // a moved-from / dead channel exposes nothing
    SecureChannel dead;
    CHECK(dead.handshake_hash() == zero);
}

// ------------------------------------------------------------------------------------------------ CLI

TEST(invite_cli_create_list_revoke_json) {
    Tmp t;
    const std::string share = t.s("share");
    Run r = cli({"invite", "create", "--dir", share, "--address", "127.0.0.1:5656", "--address", "[::1]:5757", "--rw", "--ttl", "90m",
                 "--uses", "3", "--name", "Tài liệu", "--json"});
    if (r.rc != 0) throw mytest::Failure{"invite create: " + r.err};
    CHECK(r.err.find("created one") != std::string::npos);   // no server yet: set up like quick-server
    CHECK(std::count(r.out.begin(), r.out.end(), '\n') == 1);
    for (unsigned char c : r.out) CHECK(c < 0x80);   // ASCII only
    CHECK(jstr(r.out, "code").rfind("MSY2-", 0) == 0);
    CHECK_EQ(jstr(r.out, "perm"), std::string("rw"));
    CHECK_EQ(jnum(r.out, "uses"), std::string("3"));
    CHECK_EQ(jstr(r.out, "folder"), canonical_folder(share));
    CHECK(jstr(r.out, "label").find("u00e0") != std::string::npos || jstr(r.out, "label").find("T") == 0);
    CHECK(!jstr(r.out, "key_fingerprint").empty() && !jstr(r.out, "id").empty() && !jstr(r.out, "config").empty());
    CHECK(r.out.find("\"addresses\":[\"127.0.0.1:5656\",\"[::1]:5757\"]") != std::string::npos || r.out.find("::1") != std::string::npos);
    const int64_t exp = std::stoll(jnum(r.out, "expires_unix"));
    const int64_t now = int64_t(std::time(nullptr));
    CHECK(exp > now + 90 * 60 - 30 && exp < now + 90 * 60 + 30);
    InviteCode code = decode_invite_code(jstr(r.out, "code"));
    CHECK_EQ(code.addrs.size(), size_t(2));
    CHECK(code.perm == InvitePerm::ReadWrite);
    CHECK_EQ(invite_id_hex(code.id), jstr(r.out, "id"));
    // the public key in the code is the server's
    const std::string cfgp = jstr(r.out, "config");
    Run k = cli({"key", "show", "--public", "-c", cfgp});
    CHECK_EQ(k.rc, 0);
    CHECK_EQ(k.out, key_to_hex(code.server_key) + "\n");
    // the secret key never appears
    CHECK(r.out.find("secret") == std::string::npos);

    // second invite, read only, for ANOTHER folder of the same server (-c), text output
    Run r2 = cli({"invite", "create", "--dir", t.s("other/team"), "-c", cfgp, "--address", "h.example:1", "--ro", "--ttl", "2d"});
    CHECK_EQ(r2.rc, 0);
    CHECK(r2.err.find("created one") == std::string::npos);
    CHECK(r2.out.find("MSY2-") != std::string::npos && r2.out.find("read only") != std::string::npos);
    CHECK(fs::is_directory(fs::u8path(t.s("other/team"))));   // created for the invitation

    Run l = cli({"invite", "list", "-c", cfgp, "--json"});
    CHECK_EQ(l.rc, 0);
    CHECK(l.out.find(jstr(r.out, "id")) != std::string::npos);
    CHECK(l.out.find("\"perm\":\"ro\"") != std::string::npos && l.out.find("\"perm\":\"rw\"") != std::string::npos);
    CHECK(l.out.find("\"state\":\"live\"") != std::string::npos && l.out.find(jstr(r.out, "code")) == std::string::npos);
    Run lt = cli({"invite", "list", "-c", cfgp});
    CHECK_EQ(lt.rc, 0);
    CHECK(lt.out.find(jstr(r.out, "id")) != std::string::npos && lt.out.find("MSY2") == std::string::npos);

    Run rv = cli({"invite", "revoke", jstr(r.out, "id").substr(0, 8), "-c", cfgp});
    CHECK_EQ(rv.rc, 0);
    Run l2 = cli({"invite", "list", "-c", cfgp, "--json"});
    CHECK(l2.out.find("\"state\":\"revoked\"") != std::string::npos);
    CHECK_EQ(cli({"invite", "revoke", "0000", "-c", cfgp}).rc, 2);   // nothing matches
    CHECK_EQ(cli({"invite", "revoke", "ab", "-c", cfgp}).rc, 2);     // too short
}

TEST(invite_cli_rejects_bad_usage_and_overlapping_folders) {
    Tmp t;
    const std::string share = t.s("share");
    CHECK_EQ(cli({"invite", "create", "--address", "h:1"}).rc, 2);                                  // no --dir
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--rw", "--ro"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--ttl", "0"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--ttl", "31d"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--ttl", "abc"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--uses", "0"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--uses", "101"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", share, "--bogus"}).rc, 2);
    CHECK_EQ(cli({"invite", "frob"}).rc, 2);
    CHECK(!fs::exists(fs::u8path(share)));   // nothing was created by the refused calls
    Run ok = cli({"invite", "create", "--dir", share, "--address", "h.example:5656", "--ttl", "3d", "--json"});
    if (ok.rc != 0) throw mytest::Failure{"invite create: " + ok.err};
    const std::string cfgp = jstr(ok.out, "config");
    // any other folder is fine; overlapping one that is already handed out is not
    CHECK_EQ(cli({"invite", "create", "--dir", t.s("elsewhere"), "-c", cfgp, "--address", "h:1"}).rc, 0);
    Run nested = cli({"invite", "create", "--dir", share + "/inner", "-c", cfgp, "--address", "h:1"});
    CHECK_EQ(nested.rc, 2);
    CHECK(nested.err.find("overlap") != std::string::npos);
    CHECK(!fs::exists(fs::u8path(share + "/inner")));
    CHECK_EQ(cli({"invite", "create", "--dir", t.s("elsewhere/deeper"), "-c", cfgp, "--address", "h:1"}).rc, 2);   // inside another one
    CHECK_EQ(cli({"invite", "create", "--dir", t.s(""), "-c", cfgp, "--address", "h:1"}).rc, 2);                    // contains both
    CHECK_EQ(cli({"invite", "create", "--dir", share, "-c", cfgp, "--address", "h:1"}).rc, 0);                      // the SAME folder: shared on purpose
    // never the configuration folder, the key, or anything holding them
    CHECK_EQ(cli({"invite", "create", "--dir", dir_of_cfg(cfgp), "-c", cfgp, "--address", "h:1"}).rc, 2);
    CHECK_EQ(cli({"invite", "create", "--dir", "relative-folder-here", "-c", cfgp, "--address", "h:1", "--ttl", "bogus"}).rc, 2);
    // at most three addresses
    CHECK_EQ(cli({"invite", "create", "--dir", share, "-c", cfgp, "--address", "a:1", "--address", "b:1", "--address", "c:1", "--address", "d:1"}).rc, 2);
    // a configuration that is not there
    CHECK_EQ(cli({"invite", "create", "--dir", share, "-c", t.s("nope.toml"), "--address", "h:1"}).rc, 2);
    // default addresses: the machine name / local addresses with the configured port
    Run dflt = cli({"invite", "create", "--dir", share, "-c", cfgp, "--json"});
    CHECK_EQ(dflt.rc, 0);
    InviteCode dc = decode_invite_code(jstr(dflt.out, "code"));
    CHECK(!dc.addrs.empty() && dc.addrs.size() <= 3);
    for (const auto& a : dc.addrs) CHECK_EQ(int(a.port), 5656);
}

// ------------------------------------------------------------------------------------------------ end to end

TEST(invite_end_to_end_cli_invite_redeems_on_a_running_server_and_syncs) {
    DEnv e(/*pairing_on=*/false, /*allow_pairing=*/false);   // pairing = "off": CLI invites still work
    std::string j = e.cli_create({"--dir", (e.t.p / "team").u8string(), "--rw", "--uses", "2", "--name", "Team"});
    InviteCode code = decode_invite_code(jstr(j, "code"));
    CHECK_EQ(jstr(j, "folder"), canonical_folder((e.t.p / "team").u8string()));
    KeyPair sender = generate_keypair();
    std::atomic<bool> cancel{false};

    InviteOutcome pr = probe_invite(code, sender, cancel);
    CHECK_EQ(int(pr.kind), int(InviteOutcome::Ok));
    CHECK(pr.grant.subdir.empty());   // the sender is not told (and does not need) a path on the receiver
    CHECK(pr.grant.perm == InvitePerm::ReadWrite);
    CHECK_EQ(pr.grant.label, std::string("Team"));
    CHECK_EQ(pr.grant.uses_left, 2u);
    CHECK(pr.grant.server_key == e.skp.pub);
    CHECK(e.sd->invites()->store().list()[0].uses_left == 2);   // the probe consumed nothing
    CHECK(e.find_peer(e.peers(), sender.pub) == nullptr);       // and added nobody

    InviteOutcome ro = redeem_invite(code, sender, "Máy gửi", cancel);
    CHECK_EQ(int(ro.kind), int(InviteOutcome::Ok));
    CHECK(ro.grant.subdir.empty());
    CHECK(ro.grant.perm == InvitePerm::ReadWrite);
    CHECK_EQ(ro.grant.uses_left, 1u);
    const ClientAcl* peer = e.find_peer(e.peers(), sender.pub);
    CHECK(peer != nullptr);
    if (peer) {
        CHECK_EQ(peer->root, canonical_folder((e.t.p / "team").u8string()));
        CHECK(peer->prefix.empty());
        CHECK(!peer->read_only);
        CHECK_EQ(peer->name, std::string("Máy gửi"));
    }
    auto rec = e.sd->invites()->store().list();
    CHECK_EQ(rec.size(), size_t(1));
    CHECK_EQ(rec[0].joined.size(), size_t(1));
    CHECK_EQ(rec[0].joined[0].key_hex, key_to_hex(sender.pub));

    // the sender is now an ordinary client of the running server: a SyncEngine pass puts a file under <root>/team
    fs::path cdir = e.t.p / "client", src = e.t.p / "src";
    fs::create_directories(cdir);
    fs::create_directories(src);
    spit(src / "hello.txt", "from the invited machine");
    save_keypair((cdir / "c.key").u8string(), sender);
    spit(cdir / "client.toml",
         "[client]\nkey_file = \"" + fwd(cdir / "c.key") + "\"\nstate_dir = \"" + fwd(cdir / "st") +
             "\"\nlog_level = \"error\"\nretry_min_ms = 100\nretry_max_ms = 300\n\n[control]\nenabled = false\n\n[[watch]]\nname = \"w\"\npath = \"" + fwd(src) +
             "\"\nquiet_ms = 50\nsync_delay_ms = 10\nperiodic_scan_s = 0\n\n[[watch.target]]\nhost = \"127.0.0.1\"\nport = " +
             std::to_string(e.port) + "\nserver_key = \"" + key_to_hex(e.skp.pub) + "\"\n");
    {
        SyncEngine eng(load_client_config_resolved((cdir / "client.toml").u8string()), fwd(cdir));
        std::atomic<bool> stop{false};
        std::thread guard([&] {
            for (int i = 0; i < 200 && !stop.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            stop = true;
        });
        eng.sync_once(stop);
        stop = true;
        guard.join();
    }
    CHECK(fs::exists(e.t.p / "team" / "hello.txt"));
    CHECK_EQ(slurp(e.t.p / "team" / "hello.txt"), std::string("from the invited machine"));
    CHECK(!fs::exists(e.root / "hello.txt"));

    // the second use works, the third is refused (and says nothing about why)
    KeyPair s2 = generate_keypair(), s3 = generate_keypair();
    CHECK_EQ(int(redeem_invite(code, s2, "Second", cancel).kind), int(InviteOutcome::Ok));
    InviteOutcome third = redeem_invite(code, s3, "Third", cancel);   // used up: refused at the handshake or by the answer
    CHECK(third.kind == InviteOutcome::Refused || third.kind == InviteOutcome::Unreachable);
    CHECK(e.find_peer(e.peers(), s3.pub) == nullptr);
    // a revoked invite is refused too
    std::string j2 = e.cli_create({"--dir", (e.t.p / "other").u8string()});
    InviteCode c2 = decode_invite_code(jstr(j2, "code"));
    CHECK_EQ(cli({"invite", "revoke", jstr(j2, "id"), "-c", e.cfg.u8string()}).rc, 0);
    InviteOutcome late = redeem_invite(c2, generate_keypair(), "Late", cancel);
    CHECK(late.kind == InviteOutcome::Refused || late.kind == InviteOutcome::Unreachable);
}

TEST(invite_read_only_invite_cannot_write) {
    DEnv e(false, false);
    std::string j = e.cli_create({"--dir", (e.t.p / "pub").u8string(), "--ro"});
    InviteCode code = decode_invite_code(jstr(j, "code"));
    spit(e.t.p / "pub" / "shared.txt", "content");
    KeyPair sender = generate_keypair();
    std::atomic<bool> cancel{false};
    InviteOutcome o = redeem_invite(code, sender, "Reader", cancel);
    CHECK_EQ(int(o.kind), int(InviteOutcome::Ok));
    CHECK(o.grant.perm == InvitePerm::ReadOnly);
    const ClientAcl* peer = e.find_peer(e.peers(), sender.pub);
    CHECK(peer != nullptr);
    if (peer) CHECK(peer->read_only);
    if (peer) CHECK_EQ(peer->root, canonical_folder((e.t.p / "pub").u8string()));

    auto t = target_for(e, sender);
    t->open();
    auto list = t->list_remote();
    CHECK(list.count("shared.txt") == 1);
    fs::path f = e.t.p / "new.txt";
    spit(f, "nope");
    PutResult r = t->put_file("new.txt", f.u8string(), meta_of(f, "new.txt"));
    CHECK(r.status == PutResult::Failed);
    CHECK(!fs::exists(e.t.p / "pub" / "new.txt"));
    CHECK_THROWS(t->remove_path("shared.txt", false));
    CHECK(fs::exists(e.t.p / "pub" / "shared.txt"));
}

TEST(invite_sender_outcomes_unreachable_wrong_key_and_expired) {
    DEnv e(false, false);
    std::string j = e.cli_create({"--dir", (e.t.p / "x").u8string()});
    InviteCode code = decode_invite_code(jstr(j, "code"));
    KeyPair sender = generate_keypair();
    std::atomic<bool> cancel{false};
    // a code that pins another key: indistinguishable from nobody listening
    InviteCode wrong_key = code;
    wrong_key.server_key = generate_keypair().pub;
    InviteOutcome a = probe_invite(wrong_key, sender, cancel);
    CHECK_EQ(int(a.kind), int(InviteOutcome::Unreachable));
    // nobody on that port
    InviteCode dead = code;
    dead.addrs = {{"127.0.0.1", free_port()}};
    CHECK_EQ(int(probe_invite(dead, sender, cancel).kind), int(InviteOutcome::Unreachable));
    // the second address answers although the first is dead
    InviteCode second = code;
    second.addrs = {{"127.0.0.1", free_port()}, {"127.0.0.1", e.port}};
    InviteOutcome b = probe_invite(second, sender, cancel);
    CHECK_EQ(int(b.kind), int(InviteOutcome::Ok));
    CHECK_EQ(int(b.grant.address.port), int(e.port));
    // expired: decided locally, no connection needed
    InviteCode old = code;
    old.expires_unix = 1000;
    old.addrs = {{"127.0.0.1", free_port()}};
    CHECK_EQ(int(probe_invite(old, sender, cancel).kind), int(InviteOutcome::Expired));
    CHECK_EQ(int(redeem_invite(old, sender, "X", cancel).kind), int(InviteOutcome::Expired));
    // wrong secret: the server refuses, without telling the sender why
    InviteCode wrong_secret = code;
    wrong_secret.secret[0] ^= 1;
    InviteOutcome c = redeem_invite(wrong_secret, sender, "X", cancel);
    CHECK_EQ(int(c.kind), int(InviteOutcome::Refused));
    CHECK(e.find_peer(e.peers(), sender.pub) == nullptr);
    // an unusable device name stops before any connection
    CHECK_EQ(int(redeem_invite(code, sender, "bad\x01name", cancel).kind), int(InviteOutcome::Failed));
    // cancelled before it starts
    std::atomic<bool> stopped{true};
    CHECK_EQ(int(redeem_invite(code, sender, "X", stopped).kind), int(InviteOutcome::Cancelled));
}

TEST(invite_pairing_off_refuses_gui_invites_but_not_cli_ones_and_on_demand_allows_both) {
    {
        DEnv e(/*pairing_on=*/false, /*allow_pairing=*/true);   // the configuration says off: the process flag is ignored
        CHECK(!e.sd->gui_invites_allowed());
        InviteNew n;
        n.folder = (e.t.p / "gui-off").u8string();
        n.created_by = "gui";
        n.server_key = e.skp.pub;
        n.addrs = {{"127.0.0.1", e.port}};
        n.machine = "M";
        n.label = "L";
        InviteCode gui = e.sd->invites()->store().create(n);
        KeyPair s = generate_keypair();
        std::atomic<bool> cancel{false};
        CHECK_EQ(int(redeem_invite(gui, s, "Gui", cancel).kind), int(InviteOutcome::Unreachable));   // not even admitted
        CHECK(e.find_peer(e.peers(), s.pub) == nullptr);
        InviteCode cli_code = decode_invite_code(jstr(e.cli_create({"--dir", (e.t.p / "cli-folder").u8string()}), "code"));
        CHECK_EQ(int(redeem_invite(cli_code, s, "Cli", cancel).kind), int(InviteOutcome::Ok));
    }
    {
        DEnv e(true, true);
        CHECK(e.sd->gui_invites_allowed());
        InviteNew n;
        n.created_by = "gui";
        n.server_key = e.skp.pub;
        n.addrs = {{"127.0.0.1", e.port}};
        n.machine = "M";
        n.label = "L";
        n.folder = (e.t.p / "from-gui").u8string();
        InviteCode gui = e.sd->invites()->store().create(n);
        KeyPair s = generate_keypair();
        std::atomic<bool> cancel{false};
        InviteOutcome o = redeem_invite(gui, s, "Gui", cancel);
        CHECK_EQ(int(o.kind), int(InviteOutcome::Ok));
        CHECK(fs::is_directory(e.t.p / "from-gui"));   // created for the grant
        const ClientAcl* p = e.find_peer(e.peers(), s.pub);
        CHECK(p != nullptr && p->root == canonical_folder((e.t.p / "from-gui").u8string()));
    }
}

TEST(invite_ask_flow_end_to_end_with_approval) {
    DEnv e(true, true);
    InviteNew n;
    n.created_by = "gui";
    n.ask = true;
    n.server_key = e.skp.pub;
    n.addrs = {{"127.0.0.1", e.port}};
    n.machine = "Receiver";
    n.label = "Photos";
    n.folder = (e.t.p / "photos").u8string();
    n.perm = InvitePerm::ReadWrite;
    InviteCode code = e.sd->invites()->store().create(n);
    KeyPair sender = generate_keypair();
    std::atomic<bool> cancel{false};
    InviteOutcome outcome;
    std::atomic<int> progress_calls{0};
    std::thread th([&] {
        outcome = redeem_invite(code, sender, "Phone", cancel, [&](int) { ++progress_calls; }, 60);
    });
    CHECK(wait_until([&] { return !e.sd->invites()->pending().empty(); }, 10000));
    auto pend = e.sd->invites()->pending();
    CHECK_EQ(pend.size(), size_t(1));
    CHECK_EQ(pend[0].name, std::string("Phone"));
    CHECK_EQ(pend[0].sas, invite_sas(code, sender));
    CHECK(e.find_peer(e.peers(), sender.pub) == nullptr);   // nothing is granted while the user has not answered
    std::this_thread::sleep_for(std::chrono::milliseconds(2300));   // the sender polls at least once
    CHECK_EQ(e.sd->invites()->approve(pend[0].id), canonical_folder((e.t.p / "photos").u8string()));
    th.join();
    CHECK_EQ(int(outcome.kind), int(InviteOutcome::Ok));
    CHECK(outcome.grant.subdir.empty());
    CHECK(progress_calls.load() >= 1);
    const ClientAcl* p = e.find_peer(e.peers(), sender.pub);
    CHECK(p != nullptr && p->root == canonical_folder((e.t.p / "photos").u8string()) && !p->read_only);
    // and a denial reaches the sender as a refusal
    n.folder = (e.t.p / "photos2").u8string();
    InviteCode code2 = e.sd->invites()->store().create(n);
    KeyPair s2 = generate_keypair();
    InviteOutcome o2;
    std::thread th2([&] { o2 = redeem_invite(code2, s2, "Tablet", cancel, {}, 60); });
    CHECK(wait_until([&] { return !e.sd->invites()->pending().empty(); }, 10000));
    std::this_thread::sleep_for(std::chrono::milliseconds(2300));
    e.sd->invites()->deny(e.sd->invites()->pending()[0].id);
    th2.join();
    CHECK_EQ(int(o2.kind), int(InviteOutcome::Refused));
    CHECK(e.find_peer(e.peers(), s2.pub) == nullptr);
}

TEST(invite_ask_flow_cancel_by_the_sender) {
    DEnv e(true, true);
    InviteNew n;
    n.folder = (e.t.p / "cancel-folder").u8string();
    n.created_by = "gui";
    n.ask = true;
    n.server_key = e.skp.pub;
    n.addrs = {{"127.0.0.1", e.port}};
    n.machine = "R";
    n.label = "L";
    InviteCode code = e.sd->invites()->store().create(n);
    KeyPair s = generate_keypair();
    std::atomic<bool> cancel{false};
    InviteOutcome o;
    std::thread th([&] { o = redeem_invite(code, s, "Phone", cancel, {}, 60); });
    CHECK(wait_until([&] { return !e.sd->invites()->pending().empty(); }, 10000));
    cancel = true;
    th.join();
    CHECK_EQ(int(o.kind), int(InviteOutcome::Cancelled));
    CHECK(e.find_peer(e.peers(), s.pub) == nullptr);
}

TEST(invite_a_known_client_and_an_unknown_one_without_invites_behave_as_before) {
    DEnv e(false, false);   // no invite at all: an unknown key is refused at the handshake like always
    KeyPair stranger = generate_keypair();
    TargetConfig tc;
    tc.host = "127.0.0.1";
    tc.port = e.port;
    tc.server_key = e.skp.pub;
    auto t = make_net_target(tc, ClientConfig(), stranger, nullptr);
    CHECK_THROWS(t->open());
    // an unknown key that tries to speak the normal protocol on an invite session is cut off
    std::string j = e.cli_create({"--dir", (e.t.p / "y").u8string(), "--uses", "5"});
    net::init();
    net::Socket s = net::Socket::connect("127.0.0.1", e.port, 3000);
    SecureChannel ch = SecureChannel::client(std::move(s), stranger, e.skp.pub, 4000);
    proto::Hello h;
    h.client_name = "x";
    ch.send_msg(proto::encode(h));
    bool cut = false;
    try {
        Bytes a = ch.recv_msg_within(3000);
        cut = a.size() == 1 && a[0] == uint8_t(InviteMsg::Rejected);
        try { ch.recv_msg_within(3000); } catch (const std::exception&) {}
    } catch (const std::exception&) {
        cut = true;
    }
    CHECK(cut);
    CHECK(e.find_peer(e.peers(), stranger.pub) == nullptr);
}

// ------------------------------------------------------------------------------------------------ one folder per machine

namespace {
KeyPair join(DEnv& e, const fs::path& folder, bool read_only, const std::string& name, std::vector<std::string> extra = {}) {
    std::vector<std::string> a{"--dir", folder.u8string(), read_only ? "--ro" : "--rw", "--uses", "3"};
    a.insert(a.end(), extra.begin(), extra.end());
    InviteCode code = decode_invite_code(jstr(e.cli_create(a), "code"));
    KeyPair kp = generate_keypair();
    std::atomic<bool> cancel{false};
    InviteOutcome o = redeem_invite(code, kp, name, cancel);
    if (o.kind != InviteOutcome::Ok) throw mytest::Failure{"could not join as " + name + ": " + o.message};
    return kp;
}
}  // namespace

TEST(invite_each_machine_is_confined_to_its_own_folder) {
    DEnv e(false, false);
    const fs::path fa = e.t.p / "folder-a", fb = e.t.p / "folder-b";
    KeyPair a = join(e, fa, false, "Machine A"), b = join(e, fb, false, "Machine B");
    spit(fa / "a.txt", "A's file");
    spit(fb / "secret.txt", "B's secret");
    spit(e.root / "server-root.txt", "the server root");
    fs::path src = e.t.p / "payload.txt";
    spit(src, "payload");

    auto ta = target_for(e, a);
    ta->open();
    auto list = ta->list_remote();
    CHECK(list.count("a.txt") == 1);
    CHECK(list.count("secret.txt") == 0 && list.count("server-root.txt") == 0);
    // writes land in A's folder only
    CHECK(ta->put_file("sub/new.txt", src.u8string(), meta_of(src, "sub/new.txt")).status == PutResult::Sent);
    CHECK(fs::exists(fa / "sub" / "new.txt"));
    CHECK(!fs::exists(fb / "sub") && !fs::exists(e.root / "sub"));
    // escapes of every kind are refused
    const char* bad[] = {"../folder-b/evil.txt", "../evil.txt", "sub/../../evil.txt", "..\\folder-b\\evil.txt", "__sync/x.txt"};
    for (const char* rel : bad) CHECK(ta->put_file(rel, src.u8string(), meta_of(src, rel)).status == PutResult::Failed);
    CHECK(!fs::exists(fb / "evil.txt") && !fs::exists(e.t.p / "evil.txt"));
    CHECK_THROWS(ta->remove_path("../folder-b/secret.txt", false));
    CHECK(fs::exists(fb / "secret.txt"));
    // B sees only its own
    auto tb = target_for(e, b);
    tb->open();
    auto lb = tb->list_remote();
    CHECK(lb.count("secret.txt") == 1 && lb.count("a.txt") == 0 && lb.count("sub/new.txt") == 0);

    // a link inside A's folder that points at B's folder is not followed
    std::error_code ec;
    fs::create_directory_symlink(fb, fa / "lnk", ec);
    if (!ec) {
        CHECK(ta->put_file("lnk/evil.txt", src.u8string(), meta_of(src, "lnk/evil.txt")).status == PutResult::Failed);
        CHECK(!fs::exists(fb / "evil.txt"));
        auto l2 = ta->list_remote();
        CHECK(l2.count("lnk/secret.txt") == 0);
    }
}

TEST(invite_overlapping_folders_are_refused_and_the_same_folder_is_shared) {
    DEnv e(false, false);
    const fs::path fa = e.t.p / "shared", inner = fa / "inner";
    KeyPair a = join(e, fa, false, "First");
    // the CLI refuses a folder inside, around, or equal to a machine's folder unless it is the same folder of an invitation
    Run nested = cli({"invite", "create", "--dir", inner.u8string(), "-c", e.cfg.u8string(), "--address", "h:1"});
    CHECK_EQ(nested.rc, 2);
    Run around = cli({"invite", "create", "--dir", e.t.p.u8string(), "-c", e.cfg.u8string(), "--address", "h:1"});
    CHECK_EQ(around.rc, 2);
    Run in_root = cli({"invite", "create", "--dir", (e.root / "x").u8string(), "-c", e.cfg.u8string(), "--address", "h:1"});
    CHECK_EQ(in_root.rc, 2);   // the bootstrap client of the server root already owns it
    // the same folder joins a second machine: shared, both see each other's files
    KeyPair b = join(e, fa, false, "Second");
    fs::path src = e.t.p / "p.txt";
    spit(src, "from first");
    auto ta = target_for(e, a);
    ta->open();
    CHECK(ta->put_file("hello.txt", src.u8string(), meta_of(src, "hello.txt")).status == PutResult::Sent);
    auto tb = target_for(e, b);
    tb->open();
    CHECK(tb->list_remote().count("hello.txt") == 1);

    // grant time check: two invitations made behind the CLI's back (straight in the store) cannot both be honoured
    InviteNew n;
    n.created_by = "cli";
    n.server_key = e.skp.pub;
    n.addrs = {{"127.0.0.1", e.port}};
    n.machine = "M";
    n.label = "L";
    n.uses = 2;
    n.folder = (e.t.p / "outer").u8string();
    InviteCode outer = e.sd->invites()->store().create(n);
    n.folder = (e.t.p / "outer" / "in").u8string();
    InviteCode in = e.sd->invites()->store().create(n);
    std::atomic<bool> cancel{false};
    KeyPair c = generate_keypair(), d = generate_keypair(), e2 = generate_keypair();
    CHECK_EQ(int(redeem_invite(outer, c, "Outer", cancel).kind), int(InviteOutcome::Ok));
    InviteOutcome r = redeem_invite(in, d, "Inner", cancel);
    CHECK(r.kind == InviteOutcome::Refused);
    CHECK(e.find_peer(e.peers(), d.pub) == nullptr);
    // the refusal gave the use back
    bool found = false;
    for (const auto& rec : e.sd->invites()->store().list())
        if (rec.id_hex == invite_id_hex(in.id)) {
            found = true;
            CHECK_EQ(rec.uses_left, 2);
        }
    CHECK(found);
    // the same invitation again, equal folder: fine
    CHECK_EQ(int(redeem_invite(outer, e2, "Outer2", cancel).kind), int(InviteOutcome::Ok));
}

TEST(invite_trash_and_quota_are_per_machine) {
    DEnv e(false, false);
    const fs::path fa = e.t.p / "qa", fb = e.t.p / "qb";
    KeyPair a = join(e, fa, false, "Quota A"), b = join(e, fb, false, "Quota B");
    spit(fa / "gone.txt", "to be deleted");
    spit(fb / "keep.txt", "stays");
    fs::path src = e.t.p / "p.txt";
    spit(src, std::string(100, 'x'));
    {   // delete goes to A's own trash, inside A's folder; nothing appears in B's folder or in the server root
        auto ta = target_for(e, a);
        ta->open();
        ta->remove_path("gone.txt", false);
    }
    CHECK(!fs::exists(fa / "gone.txt"));
    CHECK(fs::is_directory(fa / "__sync" / "__trash"));
    CHECK(!fs::exists(fb / "__sync" / "__trash"));
    CHECK(!fs::exists(e.root / "__sync" / "__trash"));
    bool in_trash = false;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(fa / "__sync" / "__trash", ec), end; !ec && it != end; it.increment(ec))
        if (it->path().filename() == "gone.txt") in_trash = true;
    CHECK(in_trash);
    // A gets a tiny write quota, B keeps its own: only A is stopped
    PeerSpec ps;
    ps.name = "Quota A";
    ps.key = a.pub;
    ps.read_only = false;
    ps.max_write_bytes_per_hour = 10;
    peer_add(e.cfg.u8string(), ps);
    CHECK(e.sd->reload().ok);
    auto ta = target_for(e, a);
    ta->open();
    CHECK(ta->put_file("big.txt", src.u8string(), meta_of(src, "big.txt")).status == PutResult::Failed);
    CHECK(!fs::exists(fa / "big.txt"));
    auto tb = target_for(e, b);
    tb->open();
    CHECK(tb->put_file("big.txt", src.u8string(), meta_of(src, "big.txt")).status == PutResult::Sent);
    CHECK(fs::exists(fb / "big.txt"));
    // the peer entry still has its own folder after the edit
    const ClientAcl* pa = e.find_peer(e.peers(), a.pub);
    CHECK(pa != nullptr && pa->root == canonical_folder(fa.u8string()) && pa->max_write_bytes_per_hour == 10);
}

TEST(invite_peer_folder_in_the_configuration_round_trips_and_rejects_bad_values) {
    Tmp t;
    spit(t.p / "s.toml", server_toml_text("pairing = \"off\"\n"));
    PeerSpec ps;
    ps.name = "Folder peer";
    ps.key = generate_keypair().pub;
    ps.root = (t.p / "elsewhere").u8string();
    peer_add((t.p / "s.toml").u8string(), ps);
    auto v = peer_list((t.p / "s.toml").u8string());
    bool seen = false;
    for (const auto& c : v)
        if (c.name == "Folder peer") {
            seen = true;
            CHECK_EQ(c.root, (t.p / "elsewhere").u8string());
        }
    CHECK(seen);
    PeerSpec rel = ps;
    rel.name = "Relative";
    rel.key = generate_keypair().pub;
    rel.root = "not/absolute";
    CHECK_THROWS(peer_add((t.p / "s.toml").u8string(), rel));
    rel.root = (t.p / "x" / ".." / "y").u8string();
    CHECK_THROWS(peer_add((t.p / "s.toml").u8string(), rel));
}

// ------------------------------------------------------------------------------------------------ security review fixes
TEST(invite_cli_refuses_the_servers_own_root_its_parent_its_children_and_its_state) {
    DEnv e(false, false);   // the only client has no folder of its own and no one owns the whole root
    const std::string c = e.cfg.u8string();
    auto code = [&](const fs::path& dir) { return cli({"invite", "create", "--dir", dir.u8string(), "-c", c, "--address", "h:1"}).rc; };
    CHECK_EQ(code(e.t.p), 2);                       // the parent of the root (also holds the configuration)
    CHECK_EQ(code(e.root), 2);                      // the root itself
    CHECK_EQ(code(e.root / "sub"), 2);              // inside the root
    CHECK_EQ(code(e.state), 2);                     // the state folder
    CHECK(!fs::exists(e.root / "sub"));
    CHECK_EQ(code(e.t.p / "somewhere-else"), 0);    // an unrelated folder is fine
}

TEST(invite_server_refuses_a_hand_edited_peer_folder_that_overlaps_its_root) {
    DEnv e(false, false, /*poll_ms=*/100);   // the daemon notices the peers added behind its back
    auto add = [&](const KeyPair& k, const std::string& name, const fs::path& root) {
        return cli({"peer", "add", key_to_hex(k.pub), "--name", name, "--perm", "rw", "--root", root.u8string(), "-c", e.cfg.u8string()}).rc;
    };
    KeyPair good = generate_keypair(), bad = generate_keypair(), bad2 = generate_keypair();
    CHECK_EQ(add(good, "Fine", e.t.p / "fine-folder"), 0);
    std::string why;
    if (!wait_until([&] { try { target_for(e, good)->open(); return true; } catch (const std::exception& x) { why = x.what(); return false; } }, 10000))
        throw mytest::Failure{"the added peer never connected: " + why};   // proves the configuration is picked up
    CHECK(fs::exists(e.t.p / "fine-folder"));
    CHECK_EQ(add(bad, "Inside", e.root / "sub"), 0);
    CHECK_EQ(add(bad2, "Parent", e.t.p), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    auto tb = target_for(e, bad);
    CHECK_THROWS(tb->open());
    CHECK(!fs::exists(e.root / "sub"));
    auto tb2 = target_for(e, bad2);
    CHECK_THROWS(tb2->open());
}
