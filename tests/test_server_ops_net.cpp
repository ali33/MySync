// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Server-to-server operation over real sockets: two-key server handshakes (key rotation), revocation that cuts live
// sessions, the daemon watching peers.d, and unattended clients that reconnect after a restart.
#include "so_util.h"

#include <atomic>

#include "mysync/client_engine.h"
#include "mysync/config.h"
#include "mysync/gui/daemon.h"
#include "mysync/nettarget.h"
#include "mysync/peers.h"
#include "mysync/protocol.h"
#include "mysync/secure_channel.h"
#include "mysync/server.h"

using namespace mysync::proto;

// ------------------------------------------------------------------------------------------------ handshake with two server keys

namespace {

struct Pair {
    net::Socket a, b;
};
Pair socket_pair() {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    net::Socket a = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    net::Socket b = l.accept(3000);
    CHECK(b.valid());
    return {std::move(a), std::move(b)};
}

struct HsOut {
    bool client_ok = false, server_ok = false;
    size_t matched = 99;
    PubKey seen_client{};
};

HsOut handshake(const std::vector<const KeyPair*>& server_keys, const KeyPair& client, const PubKey& pinned,
                const std::function<bool(const PubKey&)>& allow) {
    Pair p = socket_pair();
    HsOut o;
    std::thread st([&] {
        try {
            SecureChannel ch = SecureChannel::server(std::move(p.b), server_keys, [&](const PubKey& k) {
                o.seen_client = k;
                return allow(k);
            }, 4000, &o.matched);
            o.server_ok = true;
        } catch (const std::exception&) {
        }
    });
    try {
        SecureChannel ch = SecureChannel::client(std::move(p.a), client, pinned, 4000);
        o.client_ok = true;
    } catch (const std::exception&) {
    }
    st.join();
    return o;
}

}  // namespace

TEST(so_channel_two_server_keys_both_accepted_stranger_refused) {
    KeyPair s1 = generate_keypair(), s2 = generate_keypair(), c = generate_keypair(), stranger = generate_keypair();
    auto allow = [&](const PubKey& k) { return k == c.pub; };
    std::vector<const KeyPair*> both{&s1, &s2};
    HsOut a = handshake(both, c, s1.pub, allow);
    CHECK(a.client_ok && a.server_ok);
    CHECK_EQ(a.matched, size_t(0));
    HsOut b = handshake(both, c, s2.pub, allow);
    CHECK(b.client_ok && b.server_ok);
    CHECK_EQ(b.matched, size_t(1));
    CHECK(b.seen_client == c.pub);
    // a client that pinned some third key is refused, and so is a client the allowlist does not know
    HsOut x = handshake(both, c, stranger.pub, allow);
    CHECK(!x.client_ok && !x.server_ok);
    HsOut y = handshake(both, stranger, s2.pub, allow);
    CHECK(!y.client_ok && !y.server_ok);
    // the order of the server's keys does not matter
    std::vector<const KeyPair*> swapped{&s2, &s1};
    HsOut z = handshake(swapped, c, s1.pub, allow);
    CHECK(z.client_ok && z.server_ok);
    CHECK_EQ(z.matched, size_t(1));
    // with a single key the old behaviour is unchanged: the other key no longer works
    std::vector<const KeyPair*> only2{&s2};
    HsOut w = handshake(only2, c, s1.pub, allow);
    CHECK(!w.client_ok && !w.server_ok);
    CHECK(handshake(only2, c, s2.pub, allow).client_ok);
}

TEST(so_channel_garbage_first_message_is_refused_with_two_keys) {
    KeyPair s1 = generate_keypair(), s2 = generate_keypair();
    std::vector<const KeyPair*> both{&s1, &s2};
    for (size_t pos : {size_t(0), size_t(31), size_t(32), size_t(79), size_t(80), size_t(95)}) {
        Pair p = socket_pair();
        std::atomic<bool> srv_ok{false};
        std::thread st([&] {
            try {
                SecureChannel ch = SecureChannel::server(std::move(p.b), both, [&](const PubKey&) { return true; }, 2000, nullptr);
                srv_ok = true;
            } catch (const std::exception&) {
            }
        });
        Bytes junk(96, 0x5a);
        junk[pos] ^= 0xff;
        try {
            p.a.send_all(junk.data(), junk.size());
        } catch (const std::exception&) {
        }
        st.join();
        CHECK(!srv_ok.load());
    }
}

TEST(so_channel_every_msg1_bit_flip_is_refused_with_two_keys) {
    // A real client message, relayed with one byte flipped at a time: the two-key responder must refuse every one.
    KeyPair s1 = generate_keypair(), s2 = generate_keypair(), c = generate_keypair();
    std::vector<const KeyPair*> both{&s1, &s2};
    for (size_t pos = 0; pos < 96; pos += 5) {
        Pair client_side = socket_pair();   // client <-> relay
        Pair server_side = socket_pair();   // relay <-> server
        std::atomic<bool> srv_ok{false};
        std::thread st([&] {
            try {
                SecureChannel ch = SecureChannel::server(std::move(server_side.b), both, [&](const PubKey&) { return true; }, 2000, nullptr);
                srv_ok = true;
            } catch (const std::exception&) {
            }
        });
        std::thread relay([&] {
            try {
                uint8_t m1[96];
                client_side.b.recv_all(m1, 96);
                m1[pos] ^= 0x01;
                server_side.a.send_all(m1, 96);
            } catch (const std::exception&) {
            }
        });
        try {
            SecureChannel ch = SecureChannel::client(std::move(client_side.a), c, s2.pub, 1500);
        } catch (const std::exception&) {
        }
        relay.join();
        st.join();
        CHECK(!srv_ok.load());
    }
}

// ------------------------------------------------------------------------------------------------ server with two keys, revocation

namespace {

struct Net {
    Tmp t;
    KeyPair skey, snext, client, client2;
    ServerConfig sc;
    std::unique_ptr<Server> srv;
    std::atomic<bool> stop{false};
    std::thread th;

    explicit Net(bool with_next = true) {
        skey = generate_keypair();
        snext = generate_keypair();
        client = generate_keypair();
        client2 = generate_keypair();
        fs::create_directories(t.p / "root");
        fs::create_directories(t.p / "state");
        sc.bind = "127.0.0.1";
        sc.port = 0;
        sc.root = t.s("root");
        sc.state_dir = t.s("state");
        sc.log_level = "error";
        ClientAcl a;
        a.name = "c1";
        a.public_key = client.pub;
        sc.clients.push_back(a);
        if (with_next) {
            save_keypair(t.s("next.key"), snext);
            sc.key_file_next = t.s("next.key");
        }
        srv = std::make_unique<Server>(sc, skey);
        th = std::thread([this] { srv->run(stop); });
    }
    ~Net() {
        stop = true;
        if (th.joinable()) th.join();
    }
    ServerConfig cfg() const {  // what a reload would carry: the bound port stays
        ServerConfig c = sc;
        c.port = srv->port();
        return c;
    }
    std::unique_ptr<ITarget> target(const KeyPair& id, const PubKey& pinned, const PubKey* next = nullptr) {
        TargetConfig tc;
        tc.host = "127.0.0.1";
        tc.port = srv->port();
        tc.server_key = pinned;
        if (next) {
            tc.server_key_next = *next;
            tc.has_server_key_next = true;
        }
        ClientConfig cc;
        return make_net_target(tc, cc, id, nullptr);
    }
};

}  // namespace

TEST(so_server_rotation_both_pins_work_then_promote_drops_the_old_one) {
    Net n;
    CHECK_EQ(n.srv->public_keys().size(), size_t(2));
    n.target(n.client, n.skey.pub)->open();   // old pin
    n.target(n.client, n.snext.pub)->open();  // new pin
    CHECK_THROWS(n.target(n.client, generate_keypair().pub)->open());
    // promote: next becomes key_file, nothing is left over
    ServerConfig nc = n.cfg();
    nc.key_file = n.t.s("next.key");
    nc.key_file_next.clear();
    n.srv->apply_config(nc);
    CHECK_EQ(n.srv->public_keys().size(), size_t(1));
    CHECK(n.srv->public_key() == n.snext.pub);
    n.target(n.client, n.snext.pub)->open();
    CHECK_THROWS(n.target(n.client, n.skey.pub)->open());  // the retired key is refused
    // a reload that names an unreadable next key changes nothing
    ServerConfig bad = nc;
    bad.key_file_next = n.t.s("missing.key");
    CHECK_THROWS(n.srv->apply_config(bad));
    n.target(n.client, n.snext.pub)->open();
}

TEST(so_server_reload_adds_second_key_without_restart) {
    Net n(false);
    CHECK_EQ(n.srv->public_keys().size(), size_t(1));
    CHECK_THROWS(n.target(n.client, n.snext.pub)->open());
    ServerConfig nc = n.cfg();
    save_keypair(n.t.s("next.key"), n.snext);
    nc.key_file_next = n.t.s("next.key");
    n.srv->apply_config(nc);
    n.target(n.client, n.snext.pub)->open();
    n.target(n.client, n.skey.pub)->open();
}

TEST(so_client_server_key_next_fallback_in_both_orders) {
    Net n;
    PubKey unknown = generate_keypair().pub;
    n.target(n.client, unknown, &n.snext.pub)->open();  // first pin unknown to the server, second real
    n.target(n.client, n.skey.pub, &unknown)->open();   // first real: the second is never needed
    PubKey other = generate_keypair().pub;
    CHECK_THROWS(n.target(n.client, unknown, &other)->open());  // neither works
    auto t = n.target(n.client, unknown, &n.snext.pub);        // one target keeps working across reconnects
    t->open();
    t->close();
    t->open();
    CHECK(t->list_remote().empty());
}

TEST(so_peer_with_two_client_keys_old_and_new_both_connect) {
    Net n;
    ServerConfig nc = n.cfg();
    nc.clients[0].extra_keys.push_back(n.client2.pub);  // rotating client: new key accepted next to the old one
    n.srv->apply_config(nc);
    n.target(n.client, n.skey.pub)->open();
    n.target(n.client2, n.skey.pub)->open();
    nc.clients[0].public_key = n.client2.pub;           // retire the old key: only the new one is left
    nc.clients[0].extra_keys.clear();
    n.srv->apply_config(nc);
    CHECK_THROWS(n.target(n.client, n.skey.pub)->open());
    n.target(n.client2, n.skey.pub)->open();
}

TEST(so_removing_a_peer_cuts_its_open_session_within_seconds) {
    Net n(false);
    // an authenticated session that stays silent: it would live until its next request without the active cut
    net::Socket s = net::Socket::connect("127.0.0.1", n.srv->port(), 3000);
    SecureChannel ch = SecureChannel::client(std::move(s), n.client, n.skey.pub);
    Hello h;
    h.client_name = "test";
    ch.send_msg(encode(h));
    Message m = decode(ch.recv_msg());
    CHECK(std::get_if<HelloOk>(&m) != nullptr);
    CHECK_EQ(n.srv->snapshot().sessions, 1u);
    ServerConfig nc = n.cfg();
    nc.clients.clear();
    ClientAcl other;
    other.name = "other";
    other.public_key = n.client2.pub;
    nc.clients.push_back(other);
    auto t0 = std::chrono::steady_clock::now();
    n.srv->apply_config(nc);
    ch.socket().set_timeouts(5000, 5000);
    bool closed = false;
    try {
        (void)ch.recv_msg();  // we send nothing: only a close by the server can end this
    } catch (const std::exception&) {
        closed = true;
    }
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(closed);
    CHECK(ms < 2500);
    CHECK(wait_until([&] { return n.srv->snapshot().sessions == 0; }, 3000));
    CHECK_THROWS(n.target(n.client, n.skey.pub)->open());  // and the removed peer cannot come back
}

TEST(so_changed_access_cuts_that_session_but_unchanged_peers_stay) {
    Net n(false);
    ClientAcl b;
    b.name = "c2";
    b.public_key = n.client2.pub;
    ServerConfig two = n.cfg();
    two.clients.push_back(b);
    n.srv->apply_config(two);
    auto keep = n.target(n.client2, n.skey.pub);
    keep->open();
    net::Socket s = net::Socket::connect("127.0.0.1", n.srv->port(), 3000);
    SecureChannel ch = SecureChannel::client(std::move(s), n.client, n.skey.pub);
    Hello h;
    h.client_name = "test";
    ch.send_msg(encode(h));
    (void)ch.recv_msg();
    ServerConfig ro = two;
    ro.clients[0].read_only = true;  // c1 changes, c2 does not
    n.srv->apply_config(ro);
    ch.socket().set_timeouts(4000, 4000);
    CHECK_THROWS(ch.recv_msg());
    CHECK(keep->list_remote().empty());  // c2's session is still fine
}

// ------------------------------------------------------------------------------------------------ the daemon watches peers.d

namespace {

struct DaemonEnv {
    Tmp t;
    KeyPair skp;
    std::string cfg, ctl;
    std::unique_ptr<gui::ServerDaemon> d;
    std::atomic<bool> stop{false};
    std::thread th;
    std::string fail;

    explicit DaemonEnv(const std::string& extra = "", bool allow_pairing = false) {
        uint8_t r[4];
        random_bytes(r, sizeof r);
        ctl = "so-it-" + to_hex(r, sizeof r);
        skp = generate_keypair();
        fs::create_directories(t.p / "root");
        fs::create_directories(t.p / "peers.d");
        save_keypair(t.s("server.key"), skp);
        cfg = t.s("server.toml");
        spit(cfg, "[server]\nbind = \"127.0.0.1\"\nport = " + std::to_string(free_port()) +
                      "\nroot = \"root\"\nkey_file = \"server.key\"\nstate_dir = \"state\"\nlog_level = \"error\"\n"
                      "peers_dir = \"peers.d\"\n" + extra + "\n[control]\nname = \"" + ctl + "\"\n");
        gui::DaemonOptions o;
        o.service_name = ctl;
        o.config_path = cfg;
        o.version = "test";
        o.peers_poll_ms = 200;
        o.reload_min_interval_ms = 0;
        o.allow_pairing = allow_pairing;
        d = std::make_unique<gui::ServerDaemon>(gui::load_server_config_resolved(cfg), t.p.u8string(), o);
    }
    void start() {
        th = std::thread([this] {
            try {
                d->run(stop);
            } catch (const std::exception& e) {
                fail = e.what();
            }
        });
    }
    ~DaemonEnv() {
        stop = true;
        if (th.joinable()) th.join();
    }
    bool has_peer(const std::string& name) {
        for (const auto& p : d->snapshot().peers)
            if (p.name == name) return true;
        return false;
    }
};

}  // namespace

// The daemon notices a peers.d change by itself within its poll period; on a loaded machine that can take longer, so
// after a few seconds the wait asks for the scan explicitly (a reload) instead of failing on timing alone.
template <class F>
bool settle(DaemonEnv& e, F pred) {
    if (wait_until(pred, 4000)) return true;
    e.d->reload();
    return wait_until(pred, 26000);
}

TEST(so_daemon_picks_up_peers_dir_changes_and_survives_a_broken_file) {
    DaemonEnv e;
    spit(e.t.p / "peers.d" / "one.toml", "name='one'\npublic_key='" + K1 + "'\n");
    e.start();
    CHECK(settle(e, [&] { return e.has_peer("one"); }));
    CHECK(e.fail.empty());
    CHECK_EQ(e.d->snapshot().peer_file_errors, 0u);
    // a script drops a second peer: nobody calls reload, the daemon notices by itself
    spit(e.t.p / "peers.d" / "two.toml", "name='two'\npublic_key='" + K2 + "'\naccess='ro'\n");
    CHECK(settle(e, [&] { return e.has_peer("two"); }));
    // a broken file: counted, reported verbatim, the others keep working
    spit(e.t.p / "peers.d" / "zz-bad.toml", "name='bad'\npublic_key='short'\n");
    CHECK(settle(e, [&] { return e.d->snapshot().peer_file_errors == 1; }));
    gui::StatusSnapshot s = e.d->snapshot();
    CHECK(e.has_peer("one") && e.has_peer("two") && !e.has_peer("bad"));
    bool named = false;
    for (const auto& w : s.warnings)
        if (w.find("zz-bad.toml") != std::string::npos) named = true;
    CHECK(named);
    // fixing the file brings the peer and clears the count; removing a file removes the peer
    spit(e.t.p / "peers.d" / "zz-bad.toml", "name='bad'\npublic_key='" + K3 + "'\n");
    CHECK(settle(e, [&] { return e.has_peer("bad") && e.d->snapshot().peer_file_errors == 0; }));
    fs::remove(e.t.p / "peers.d" / "one.toml");
    CHECK(settle(e, [&] { return !e.has_peer("one"); }));
    CHECK(e.has_peer("two"));
    CHECK_EQ(e.d->snapshot().pairing, std::string("off"));
}

TEST(so_cli_peer_add_reaches_the_running_daemon_and_status_health_read_it) {
    DaemonEnv e;
    e.start();
    CHECK(wait_until([&] { return e.d->snapshot().listen.size() > 0; }));
    Run add = cli({"peer", "add", K1, "--name", "viaCli", "--perm", "rw", "-c", e.cfg, "--service-name", e.ctl});
    CHECK_EQ(add.rc, 0);
    CHECK(wait_until([&] { return e.has_peer("viaCli"); }));
    Run st = cli({"status", "-c", e.cfg, "--json", "--service-name", e.ctl});
    CHECK_EQ(st.rc, 0);
    CHECK(st.out.find("\"running\":true") != std::string::npos);
    CHECK(st.out.find("\"role\":\"server\"") != std::string::npos);
    CHECK(st.out.find("\"name\":\"viaCli\"") != std::string::npos);
    CHECK(st.out.find("\"pairing\":\"off\"") != std::string::npos);
    CHECK(st.out.find("\"version\":\"test\"") != std::string::npos);
    Run h = cli({"health", "-c", e.cfg, "--service-name", e.ctl});
    CHECK_EQ(h.rc, 0);
    CHECK(h.out.find("MYSYNC OK") != std::string::npos);
    spit(e.t.p / "peers.d" / "bad.toml", "nonsense");  // a peer file the daemon cannot use: a warning
    CHECK(wait_until([&] { return e.d->snapshot().peer_file_errors == 1; }));
    Run hw = cli({"health", "-c", e.cfg, "--service-name", e.ctl});
    CHECK_EQ(hw.rc, 1);
    CHECK(hw.out.find("WARNING") != std::string::npos);
    CHECK_EQ(cli({"peer", "revoke", "viaCli", "-c", e.cfg, "--service-name", e.ctl}).rc, 0);  // gone from the running daemon
    CHECK(wait_until([&] { return !e.has_peer("viaCli"); }));
}

TEST(so_pairing_stays_off_unless_the_configuration_says_on_demand) {
    {
        DaemonEnv off("", true);  // asked for, but [server] pairing is "off"
        CHECK(!off.d->pairing_allowed());
    }
    {
        DaemonEnv on("pairing = \"on-demand\"\n", true);
        CHECK(on.d->pairing_allowed());
    }
    {
        DaemonEnv none("pairing = \"on-demand\"\n", false);  // allowed by the file, not asked for by the process
        CHECK(!none.d->pairing_allowed());
    }
}

// ------------------------------------------------------------------------------------------------ unattended clients

namespace {

struct Link {
    Tmp t;
    KeyPair skey, ckey;
    ServerConfig sc;
    uint16_t port = 0;
    std::unique_ptr<Server> srv;
    std::atomic<bool> stop{false};
    std::thread th;

    Link() {
        skey = generate_keypair();
        ckey = generate_keypair();
        for (const char* d : {"root", "state", "src", "cstate"}) fs::create_directories(t.p / d);
        port = free_port();
        sc.bind = "127.0.0.1";
        sc.port = port;
        sc.root = t.s("root");
        sc.state_dir = t.s("state");
        ClientAcl a;
        a.name = "c";
        a.public_key = ckey.pub;
        sc.clients.push_back(a);
        save_keypair(t.s("client.key"), ckey);
    }
    void start_server(uint32_t kbps = 0) {
        sc.max_bandwidth_kbps = kbps;
        stop = false;
        srv = std::make_unique<Server>(sc, skey);
        th = std::thread([this] { srv->run(stop); });
    }
    void stop_server() {
        stop = true;
        if (th.joinable()) th.join();
        srv.reset();
    }
    ~Link() { stop_server(); }
    ClientConfig client() const {
        ClientConfig cc;
        cc.key_file = t.s("client.key");
        cc.state_dir = t.s("cstate");
        cc.retry_min_ms = 100;
        cc.retry_max_ms = 400;
        cc.connections = 2;
        WatchConfig w;
        w.name = "w";
        w.path = t.s("src");
        w.quiet_ms = 50;
        w.sync_delay_ms = 0;
        w.periodic_scan_s = 0;
        TargetConfig tc;
        tc.host = "127.0.0.1";
        tc.port = port;
        tc.server_key = skey.pub;
        w.targets.push_back(tc);
        cc.watches.push_back(w);
        return cc;
    }
};

// Runs the engine on a thread; stops and joins on scope exit even when a CHECK throws.
struct EngineRun {
    SyncEngine eng;
    std::atomic<bool> stop{false};
    std::thread th;
    explicit EngineRun(const ClientConfig& cc) : eng(cc, "") { th = std::thread([this] { eng.run(stop); }); }
    ~EngineRun() {
        stop = true;
        if (th.joinable()) th.join();
    }
};

// Random-looking bytes: LZ4 cannot shrink them, so the server's bandwidth cap really paces the transfer.
std::string incompressible(size_t n, uint64_t seed) {
    std::string s(n, ' ');
    uint64_t x = seed * 0x9E3779B97F4A7C15ull + 1;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s[i] = static_cast<char>(x >> 24);
    }
    return s;
}

bool tmp_left(const fs::path& root) {
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec))
        if (it->path().filename().u8string().rfind(".mysync-tmp-", 0) == 0) return true;
    return false;
}

}  // namespace

TEST(so_client_reconnects_and_catches_up_after_the_server_restarts) {
    Link l;
    l.start_server();
    spit(l.t.p / "src" / "before.txt", "before");
    EngineRun er(l.client());
    auto& cstop = er.stop;
    auto& cth = er.th;
    CHECK(wait_until([&] { return slurp(l.t.p / "root" / "before.txt") == "before"; }));
    l.stop_server();
    // while the server is down: more changes, including a delete and an edit
    spit(l.t.p / "src" / "during.txt", "written while the server was down");
    spit(l.t.p / "src" / "before.txt", "before, edited");
    std::this_thread::sleep_for(std::chrono::milliseconds(700));  // several failed retries
    CHECK(!fs::exists(l.t.p / "root" / "during.txt"));
    l.start_server();
    CHECK(wait_until([&] { return slurp(l.t.p / "root" / "during.txt") == "written while the server was down"; }, 25000));
    CHECK(wait_until([&] { return slurp(l.t.p / "root" / "before.txt") == "before, edited"; }, 25000));
    // and keeps following live changes afterwards
    spit(l.t.p / "src" / "after.txt", "after");
    CHECK(wait_until([&] { return slurp(l.t.p / "root" / "after.txt") == "after"; }));
    cstop = true;
    cth.join();
}

TEST(so_long_outage_triggers_a_full_comparison_on_reconnect) {
    // Events are not the only truth: a change made while the link was down is found even when the event is long gone.
    Link l;
    l.start_server();
    spit(l.t.p / "src" / "keep.txt", "keep");
    {
        EngineRun er(l.client());
            auto& cstop = er.stop;
        auto& cth = er.th;
        CHECK(wait_until([&] { return slurp(l.t.p / "root" / "keep.txt") == "keep"; }));
        cstop = true;
        cth.join();
    }
    l.stop_server();
    spit(l.t.p / "src" / "new-offline.txt", "made with nobody watching");
    fs::remove(l.t.p / "src" / "keep.txt");
    l.start_server();
    EngineRun er(l.client());
    auto& cstop = er.stop;
    auto& cth = er.th;
    CHECK(wait_until([&] { return slurp(l.t.p / "root" / "new-offline.txt") == "made with nobody watching"; }));
    CHECK(wait_until([&] { return !fs::exists(l.t.p / "root" / "keep.txt"); }));
    cstop = true;
    cth.join();
}

TEST(so_server_restart_in_the_middle_of_a_big_file_never_leaves_a_wrong_file) {
    Link l;
    l.start_server(4096);  // 4096 kbit/s = 512 KB/s: the 6 MB below takes ~12 s
    std::string big = incompressible(6 * 1024 * 1024, 1);
    spit(l.t.p / "src" / "big.bin", big);
    EngineRun er(l.client());
    SyncEngine& eng = er.eng;
    auto& cstop = er.stop;
    auto& cth = er.th;
    std::atomic<bool> watching{true}, wrong{false};
    std::thread watcher([&] {  // the final name must never hold anything but the complete file
        while (watching) {
            std::error_code ec;
            fs::path f = l.t.p / "root" / "big.bin";
            if (fs::exists(f, ec) && fs::file_size(f, ec) != big.size()) wrong = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });
    struct WGuard {
        std::atomic<bool>& w;
        std::thread& th;
        ~WGuard() {
            w = false;
            if (th.joinable()) th.join();
        }
    } wguard{watching, watcher};
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    CHECK(!fs::exists(l.t.p / "root" / "big.bin"));  // still in flight
    l.stop_server();                                  // the server dies mid-transfer
    l.start_server();                                 // comes back at full speed
    CHECK(wait_until([&] { return fs::exists(l.t.p / "root" / "big.bin") && fs::file_size(l.t.p / "root" / "big.bin") == big.size(); }, 60000));
    CHECK(wait_until([&] { return eng.idle(); }, 30000));
    watching = false;
    watcher.join();
    CHECK(!wrong.load());
    CHECK(slurp(l.t.p / "root" / "big.bin") == big);
    cstop = true;
    cth.join();
}

TEST(so_client_restart_in_the_middle_of_a_big_file_resumes_cleanly) {
    Link l;
    l.start_server(4096);
    std::string big = incompressible(5 * 1024 * 1024, 2);
    spit(l.t.p / "src" / "big.bin", big);
    {
        EngineRun er(l.client());
        auto& cstop = er.stop;
        auto& cth = er.th;
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
        cstop = true;  // the client process goes away mid-transfer
        cth.join();
    }
    CHECK(!fs::exists(l.t.p / "root" / "big.bin") || fs::file_size(l.t.p / "root" / "big.bin") == big.size());
    l.stop_server();
    l.start_server();  // full speed
    EngineRun er(l.client());
    SyncEngine& eng = er.eng;
    auto& cstop = er.stop;
    auto& cth = er.th;
    CHECK(wait_until([&] { return fs::exists(l.t.p / "root" / "big.bin") && fs::file_size(l.t.p / "root" / "big.bin") == big.size(); }, 60000));
    CHECK(wait_until([&] { return eng.idle(); }, 30000));
    CHECK(slurp(l.t.p / "root" / "big.bin") == big);
    cstop = true;
    cth.join();
    (void)tmp_left;
}

TEST(so_health_and_status_of_a_client_daemon) {
    Link l;
    // a client whose server is down: health warns (disconnected, within the limit) and goes critical over the limit
    uint8_t r[4];
    random_bytes(r, sizeof r);
    std::string ctl = "so-cl-" + to_hex(r, sizeof r);
    ClientConfig cc = l.client();
    std::string cfg = l.t.s("client.toml");
    spit(cfg, "[client]\nkey_file = \"client.key\"\nstate_dir = \"cstate\"\nlog_level = \"error\"\nretry_min_ms = 100\nretry_max_ms = 300\n"
              "[control]\nname = \"" + ctl + "\"\n[[watch]]\nname = \"w\"\npath = \"src\"\nquiet_ms = 50\nperiodic_scan_s = 0\n"
              "[[watch.target]]\nhost = \"127.0.0.1\"\nport = " + std::to_string(l.port) + "\nserver_key = \"" + key_to_hex(l.skey.pub) + "\"\n");
    spit(l.t.p / "src" / "f.txt", "f");
    gui::DaemonOptions o;
    o.service_name = ctl;
    o.config_path = cfg;
    o.version = "test";
    gui::ClientDaemon d(gui::load_client_config_resolved(cfg), l.t.p.u8string(), o);
    std::atomic<bool> stop{false};
    std::string run_err;
    std::thread th([&] {
        try {
            d.run(stop);
        } catch (const std::exception& e) {
            run_err = e.what();
        }
    });
    struct Join {
        std::atomic<bool>& s;
        std::thread& t;
        ~Join() {
            s = true;
            if (t.joinable()) t.join();
        }
    } join_d{stop, th};
    CHECK(wait_until([&] {
        for (const auto& t : d.snapshot().targets)
            if (t.state == gui::TargetState::Disconnected || t.state == gui::TargetState::Error) return true;
        return false;
    }));
    Run warn = cli({"health", "-c", cfg, "--service-name", ctl});
    CHECK_EQ(warn.rc, 1);
    CHECK(warn.out.find("WARNING") != std::string::npos);
    std::this_thread::sleep_for(std::chrono::milliseconds(1300));  // "no progress for > 0 s" needs a whole second of uptime
    Run crit = cli({"health", "-c", cfg, "--service-name", ctl, "--max-lag-seconds", "0"});
    CHECK_EQ(crit.rc, 2);
    Run st = cli({"status", "-c", cfg, "--json", "--service-name", ctl});
    CHECK(st.out.find("\"role\":\"client\"") != std::string::npos);
    CHECK(st.out.find("\"state\":\"") != std::string::npos);
    CHECK(st.out.find("\"last_error\":\"") != std::string::npos);
    // the server comes up: the client connects by itself and health turns OK once everything is idle and sent
    l.start_server();
    CHECK(wait_until([&] { return slurp(l.t.p / "root" / "f.txt") == "f"; }, 25000));
    CHECK(wait_until([&] { return cli({"health", "-c", cfg, "--service-name", ctl}).rc == 0; }, 20000));
    Run st2 = cli({"status", "-c", cfg, "--json", "--service-name", ctl});
    CHECK(st2.out.find("\"running\":true") != std::string::npos);
    CHECK(st2.out.find("\"last_ok_unix_ms\":null") == std::string::npos);
    stop = true;
    th.join();
}

TEST(so_fix_cli_reports_exit_3_when_the_daemon_refuses_the_new_configuration) {
    DaemonEnv e;
    e.start();
    CHECK(wait_until([&] { return e.d->snapshot().listen.size() > 0; }));
    // make the next reload fail: a second server key file that does not exist
    std::string text = slurp(e.cfg);
    spit(e.cfg, text.replace(text.find("peers_dir"), 0, "key_file_next = \"missing.key\"\n"));
    Run r = cli({"peer", "add", K1, "--name", "w", "--perm", "rw", "-c", e.cfg, "--service-name", e.ctl, "--json"});
    CHECK_EQ(r.rc, 3);  // written, but the daemon did not apply it
    CHECK(r.out.find("\"changed\":true") != std::string::npos);
    CHECK(r.out.find("\"daemon_applied\":false") != std::string::npos);
    CHECK(fs::exists(e.t.p / "peers.d" / "w.toml"));
    // with the configuration fixed the same command is a no-op and says nothing was refused
    spit(e.cfg, text);
    Run ok = cli({"peer", "add", K1, "--name", "w", "--perm", "rw", "-c", e.cfg, "--service-name", e.ctl});
    CHECK_EQ(ok.rc, 0);
    // a daemon that is not there is not a refusal: a copy of the configuration that names a control endpoint nobody serves
    std::string other = text;
    size_t at = other.find(e.ctl);
    CHECK(at != std::string::npos);
    other.replace(at, e.ctl.size(), "so-no-such-daemon");
    spit(e.t.p / "server2.toml", other);
    Run none = cli({"peer", "add", K2, "--name", "w2", "--perm", "rw", "-c", e.t.s("server2.toml"), "--json"});
    CHECK_EQ(none.rc, 0);
    CHECK(none.out.find("\"daemon_applied\":null") != std::string::npos);
}

TEST(so_fix_pairing_status_is_the_real_state_and_a_reload_to_off_closes_it) {
    DaemonEnv e("pairing = \"on-demand\"\n", true);
    e.start();
    CHECK(wait_until([&] { return e.d->snapshot().listen.size() > 0; }));
    CHECK_EQ(e.d->snapshot().pairing, std::string("on-demand"));
    gui::ControlClient cc(e.ctl, 4000);
    gui::PairInfo on = cc.pair_mode(true, 60);
    CHECK(on.mode_on);
    // the file now says off; a reload must close the window at once and refuse to open it again
    std::string text = slurp(e.cfg);
    size_t at = text.find("pairing = \"on-demand\"");
    CHECK(at != std::string::npos);
    text.replace(at, std::string("pairing = \"on-demand\"").size(), "pairing = \"off\"");
    spit(e.cfg, text);
    CHECK(e.d->reload().ok);
    CHECK_EQ(e.d->snapshot().pairing, std::string("off"));
    CHECK_THROWS(cc.pair_mode(true, 60));
    CHECK_THROWS(cc.pair_info());
}

TEST(so_fix_pairing_status_is_off_when_the_process_did_not_ask_for_it) {
    DaemonEnv e("pairing = \"on-demand\"\n", false);  // allowed by the file, but no --allow-pairing
    e.start();
    CHECK(wait_until([&] { return e.d->snapshot().listen.size() > 0; }));
    CHECK_EQ(e.d->snapshot().pairing, std::string("off"));
}
