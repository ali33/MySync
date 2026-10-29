// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Headless integration: a real Server and a real SyncEngine run behind the control channel; a ControlClient (what the
// GUI uses) reads their status and reloads their configuration.
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <thread>

#include "mysync/gui/config_io.h"
#include "mysync/gui/daemon.h"
#include "mysync/gui/ipc.h"
#include "gui_test_util.h"
#include "mysync/keys.h"
#include "mysync/client_engine.h"
#include "mysync/net.h"
#include "mysync/ratelimit.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {

struct DTmp {
    fs::path p;
    DTmp() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-guid-" + to_hex(r, sizeof r));
        fs::create_directories(p);
        guitest::make_private_dir(p);
    }
    ~DTmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
};

std::string fwd(const fs::path& p) { return p.generic_u8string(); }

void spit(const fs::path& p, const std::string& text) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << text;
}

std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

uint16_t free_port() {
    net::init();
    net::Socket s = net::Socket::listen("127.0.0.1", 0);
    uint16_t p = s.local_port();
    s.close();
    return p;
}

bool wait_until(const std::function<bool()>& f, int seconds) {
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < until) {
        try {
            if (f()) return true;
        } catch (const std::exception&) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

bool contains(const std::vector<std::string>& v, const std::string& prefix) {
    for (const auto& s : v)
        if (s.rfind(prefix, 0) == 0) return true;
    return false;
}

struct Daemons {
    DTmp t;
    fs::path root, src, src2, dst2, sstate, cstate, scfg, ccfg, skey, ckey;
    KeyPair skp, ckp, c2kp;
    uint16_t port = 0;
    std::string sctl, cctl, cdir, sdir;
    std::atomic<bool> sstop{false}, cstop{false};
    std::thread sth, cth;
    std::string sfail, cfail;
    std::string ctl_extra;
    int reload_gap = 0;
    std::unique_ptr<ServerDaemon> sd;
    std::unique_ptr<ClientDaemon> cd;

    std::string server_text(bool with_c1, bool with_c2, uint16_t listen_port, const std::string& extra = "") const {
        std::string s = "[server]\nbind = \"127.0.0.1\"\nport = " + std::to_string(listen_port) + "\nroot = \"" + fwd(root) +
                        "\"\nkey_file = \"" + fwd(skey) + "\"\nstate_dir = \"" + fwd(sstate) +
                        "\"\nlog_level = \"warn\"\nmax_connections = 20\n\n[control]\nname = \"" + sctl + "\"\n" + ctl_extra;
        if (with_c1) s += "\n[[client]]\nname = \"c1\"\npublic_key = \"" + key_to_hex(ckp.pub) + "\"\n";
        if (with_c2) s += "\n[[client]]\nname = \"c2\"\naccess = \"ro\"\npublic_key = \"" + key_to_hex(c2kp.pub) + "\"\n";
        return s + extra;
    }

    std::string client_text(bool second_watch, const std::string& key_file_override = "") const {
        std::string s = "[client]\nkey_file = \"" + (key_file_override.empty() ? fwd(ckey) : key_file_override) +
                        "\"\nstate_dir = \"" + fwd(cstate) +
                        "\"\nlog_level = \"warn\"\nretry_min_ms = 200\nretry_max_ms = 1000\n\n[control]\nname = \"" + cctl +
                        "\"\n\n[[watch]]\nname = \"w1\"\npath = \"" + fwd(src) +
                        "\"\nquiet_ms = 50\nsync_delay_ms = 10\nperiodic_scan_s = 0\n\n[[watch.target]]\nhost = \"127.0.0.1\"\nport = " +
                        std::to_string(port) + "\nserver_key = \"" + key_to_hex(skp.pub) + "\"\n";
        if (second_watch)
            s += "\n[[watch]]\nname = \"w2\"\npath = \"" + fwd(src2) +
                 "\"\nquiet_ms = 50\nsync_delay_ms = 10\nperiodic_scan_s = 0\n\n[[watch.target]]\npath = \"" + fwd(dst2) + "\"\n";
        return s;
    }

    Daemons() {
        uint8_t r[4];
        random_bytes(r, sizeof r);
        sctl = "gui-it-s-" + to_hex(r, sizeof r);
        cctl = "gui-it-c-" + to_hex(r, sizeof r);
        root = t.p / "root";
        src = t.p / "src";
        src2 = t.p / "src2";
        dst2 = t.p / "dst2";
        sstate = t.p / "sstate";
        cstate = t.p / "cstate";
        scfg = t.p / "server.toml";
        ccfg = t.p / "client.toml";
        skey = t.p / "server.key";
        ckey = t.p / "client.key";
        for (auto* d : {&root, &src, &src2, &dst2}) fs::create_directories(*d);
        skp = generate_keypair();
        ckp = generate_keypair();
        c2kp = generate_keypair();
        save_keypair(skey.u8string(), skp);
        save_keypair(ckey.u8string(), ckp);
        port = free_port();
#ifndef _WIN32
        sdir = (t.p / "s").u8string();
        cdir = (t.p / "c").u8string();
#endif
    }

    void start_server(bool c1, bool c2) {
        spit(scfg, server_text(c1, c2, port));
        DaemonOptions o;
        o.service_name = sctl;
        o.config_path = scfg.u8string();
        o.version = "test";
        o.control_dir_override = sdir;
        o.enforce_config_trust = true;
        o.reload_min_interval_ms = reload_gap;
        sd = std::make_unique<ServerDaemon>(load_server_config_resolved(o.config_path), fwd(t.p), o);
        sth = std::thread([this] {
            try {
                sd->run(sstop);
            } catch (const std::exception& e) {
                sfail = e.what();
            }
        });
    }

    void start_client() {
        spit(ccfg, client_text(false));
        DaemonOptions o;
        o.service_name = cctl;
        o.config_path = ccfg.u8string();
        o.version = "test";
        o.control_dir_override = cdir;
        o.enforce_config_trust = true;
        o.reload_min_interval_ms = reload_gap;
        cd = std::make_unique<ClientDaemon>(load_client_config_resolved(o.config_path), fwd(t.p), o);
        cth = std::thread([this] {
            try {
                cd->run(cstop);
            } catch (const std::exception& e) {
                cfail = e.what();
            }
        });
    }

    ~Daemons() {
        cstop = true;
        sstop = true;
        if (cth.joinable()) cth.join();
        if (sth.joinable()) sth.join();
    }
};

bool has_secret(const Bytes& wire, const KeyPair& kp) {
    std::string hay(wire.begin(), wire.end());
    std::string raw(reinterpret_cast<const char*>(kp.secret.data()), kp.secret.size());
    std::string hex = key_to_hex(kp.secret);
    return hay.find(raw) != std::string::npos || hay.find(hex) != std::string::npos;
}

}  // namespace

TEST(gui_daemon_status_and_reload_end_to_end) {
    Daemons d;
    d.start_server(true, false);
    ControlClient sc(d.sctl, 5000, d.sdir);
    CHECK(wait_until([&] { return sc.ping(); }, 10));
    CHECK(d.sfail.empty());

    // ---- server status
    StatusSnapshot ss = sc.get_status();
    CHECK(ss.role == Role::Server);
    CHECK_EQ(ss.version, std::string("test"));
    CHECK_EQ(ss.service_name, d.sctl);
    CHECK(ss.listen.find(std::to_string(d.port)) != std::string::npos);
    CHECK_EQ(ss.peers.size(), size_t(1));
    CHECK_EQ(ss.peers[0].name, std::string("c1"));
    CHECK(ss.config_loaded_unix_ms > 0);

    // ---- a real client syncs a file; its status is readable through the channel
    spit(d.src / "a.txt", "hello from the gui test\n");
    d.start_client();
    ControlClient cc(d.cctl, 5000, d.cdir);
    CHECK(wait_until([&] { return cc.ping(); }, 10));
    CHECK(wait_until(
        [&] {
            StatusSnapshot s = cc.get_status();
            return s.targets.size() == 1 && s.targets[0].sent >= 1 && s.targets[0].state == TargetState::Idle;
        },
        40));
    CHECK(d.cfail.empty());
    CHECK_EQ(slurp(d.root / "a.txt"), std::string("hello from the gui test\n"));
    StatusSnapshot cs = cc.get_status();
    CHECK(cs.role == Role::Client);
    CHECK_EQ(cs.targets[0].watch, std::string("w1"));
    CHECK_EQ(cs.targets[0].target, "net://127.0.0.1:" + std::to_string(d.port));
    CHECK(cs.targets[0].bytes > 0);
    CHECK(cs.total_sent >= 1);

    // ---- the channel never carries a secret key (checked on the raw wire bytes of both statuses)
    ControlResponse sr, cr;
    sr.op = cr.op = ControlOp::GetStatus;
    sr.snapshot = sc.get_status();
    cr.snapshot = cc.get_status();
    for (const ControlResponse* r : {&sr, &cr}) {
        Bytes wire = encode_response(*r);
        CHECK(!has_secret(wire, d.skp));
        CHECK(!has_secret(wire, d.ckp));
    }
    ControlRequest er;
    er.op = ControlOp::GetRecentErrors;
    for (const ControlResponse& r : {sc.call(er), cc.call(er)}) {
        Bytes wire = encode_response(r);
        CHECK(!has_secret(wire, d.skp));
        CHECK(!has_secret(wire, d.ckp));
    }
    CHECK(wait_until([&] { return sc.get_status().peers[0].bytes_rx > 0; }, 5));

    // ---- server RELOAD_CONFIG: a second client is admitted without a restart
    int64_t loaded_before = sc.get_status().config_loaded_unix_ms;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    spit(d.scfg, d.server_text(true, true, d.port));
    ReloadResult rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(contains(rr.applied, "clients added: c2"));
    CHECK(rr.needs_restart.empty());
    StatusSnapshot s2 = sc.get_status();
    CHECK_EQ(s2.peers.size(), size_t(2));
    CHECK(s2.config_loaded_unix_ms >= loaded_before);
    CHECK(s2.config_error.empty());
    CHECK_EQ(s2.peers[1].name, std::string("c2"));

    // a changed port needs a restart: refused, nothing changes
    spit(d.scfg, d.server_text(true, true, uint16_t(d.port == 65535 ? 65534 : d.port + 1)));
    rr = sc.reload_config();
    CHECK(!rr.ok);
    CHECK(rr.message.find("restart") != std::string::npos);
    s2 = sc.get_status();
    CHECK_EQ(s2.peers.size(), size_t(2));
    CHECK(s2.config_error.find("restart") != std::string::npos);
    CHECK(s2.listen.find(std::to_string(d.port)) != std::string::npos);

    // a syntax error comes back verbatim, with its line number
    spit(d.scfg, d.server_text(true, true, d.port, "\nbogus_setting = 1\n"));
    rr = sc.reload_config();
    CHECK(!rr.ok);
    CHECK(rr.message.find("bogus_setting") != std::string::npos);
    CHECK(rr.message.find("line") != std::string::npos);
    CHECK_EQ(sc.get_status().peers.size(), size_t(2));

    // a [control] change is accepted but is reported as needing a restart
    d.ctl_extra = "allow = [\"S-1-5-21-1-2-3-1001\"]\n";
    spit(d.scfg, d.server_text(true, true, d.port));
    rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(contains(rr.needs_restart, "[control] allow"));
    d.ctl_extra.clear();
    spit(d.scfg, d.server_text(true, true, d.port));
    rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(sc.get_status().config_error.empty());

    // ---- client RELOAD_CONFIG: a second watch appears, the first keeps its index (nothing is sent twice)
    spit(d.src2 / "b.txt", "second watch\n");
    spit(d.ccfg, d.client_text(true));
    ReloadResult cr2 = cc.reload_config();
    CHECK(cr2.ok);
    CHECK(contains(cr2.applied, "watches added: w2"));
    CHECK(wait_until(
        [&] {
            StatusSnapshot s = cc.get_status();
            return s.targets.size() == 2 && s.targets[1].sent >= 1 && s.targets[0].state == TargetState::Idle &&
                   s.targets[1].state == TargetState::Idle;
        },
        40));
    CHECK_EQ(slurp(d.dst2 / "b.txt"), std::string("second watch\n"));
    StatusSnapshot cs2 = cc.get_status();
    CHECK_EQ(cs2.targets[0].sent, uint64_t(0));  // a.txt was not transferred again
    CHECK(cs2.targets[1].target.rfind("dir://", 0) == 0);

    // an unusable client configuration is refused; the running one keeps working
    spit(d.ccfg, d.client_text(true, fwd(d.t.p / "no-such.key")));
    cr2 = cc.reload_config();
    CHECK(!cr2.ok);
    CHECK(!cr2.message.empty());
    CHECK_EQ(cc.get_status().targets.size(), size_t(2));
    spit(d.src / "c.txt", "still alive\n");
    CHECK(wait_until([&] { return fs::exists(d.root / "c.txt"); }, 30));
    spit(d.ccfg, d.client_text(true));
    CHECK(cc.reload_config().ok);

    // ---- recent errors include the refused reloads, verbatim
    auto errs = sc.recent_errors(100);
    bool saw = false;
    for (const auto& e : errs)
        if (e.message.find("reload refused") != std::string::npos) saw = true;
    CHECK(saw);

    // ---- removing a client from the allowlist cuts it off: its next request fails and nothing more arrives
    spit(d.scfg, d.server_text(false, true, d.port));
    rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(contains(rr.applied, "clients removed: c1"));
    spit(d.src / "after-revoke.txt", "must not arrive\n");
    CHECK(wait_until(
        [&] {
            StatusSnapshot s = cc.get_status();
            return !s.targets.empty() && (s.targets[0].state == TargetState::Disconnected || s.targets[0].state == TargetState::Error) &&
                   !s.targets[0].last_error.empty();
        },
        40));
    CHECK(!fs::exists(d.root / "after-revoke.txt"));
    CHECK_EQ(sc.get_status().peers.size(), size_t(1));
}

TEST(gui_ratelimiter_cancel_ends_a_throttled_transfer_and_counts_bytes) {
    RateLimiter lim(64);  // 64 kbit/s: a MiB would take minutes
    std::atomic<bool> threw{false}, finished{false};
    std::thread th([&] {
        try {
            lim.acquire(1 << 20);
        } catch (const Error&) {
            threw = true;
        }
        finished = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK(!finished.load());
    auto t0 = std::chrono::steady_clock::now();
    lim.cancel();
    th.join();
    CHECK(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() < 2.0);
    CHECK(threw.load());
    CHECK(lim.total_bytes() >= (1u << 20));
    RateLimiter unlimited(0);
    unlimited.acquire(1000);
    CHECK_EQ(unlimited.total_bytes(), uint64_t(1000));
    unlimited.cancel();
    CHECK_THROWS(unlimited.acquire(1));
}

TEST(gui_engine_stops_promptly_under_a_bandwidth_cap_and_reports_progress) {
    DTmp t;
    fs::path src = t.p / "src", dst = t.p / "dst";
    fs::create_directories(src);
    fs::create_directories(dst);
    std::string big(3 << 20, 'q');
    spit(src / "big.bin", big);
    ClientConfig cc;
    cc.max_bandwidth_kbps = 64;
    cc.state_dir = fwd(t.p / "state");
    WatchConfig w;
    w.name = "w";
    w.path = fwd(src);
    w.quiet_ms = 20;
    w.periodic_scan_s = 0;
    TargetConfig tg;
    tg.path = fwd(dst);
    w.targets.push_back(tg);
    cc.watches.push_back(w);
    SyncEngine eng(cc, fwd(t.p));
    std::atomic<bool> stop{false};
    std::string fail;
    std::thread th([&] {
        try {
            eng.run(stop);
        } catch (const std::exception& e) {
            fail = e.what();
        }
    });
    bool saw = wait_until(
        [&] {
            gui::StatusSnapshot s = eng.snapshot();
            return s.targets.size() == 1 && s.targets[0].state == gui::TargetState::Syncing &&
                   s.targets[0].active_files.size() == 1 && s.targets[0].active_files[0] == "big.bin" &&
                   s.targets[0].target.rfind("dir://", 0) == 0;
        },
        10);
    CHECK(saw);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    auto t0 = std::chrono::steady_clock::now();
    stop = true;
    th.join();
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    CHECK(fail.empty());
    CHECK(secs < 5.0);
    CHECK(eng.snapshot().targets.empty());  // after run() the engine has been torn down
}

TEST(gui_daemon_reload_is_spaced_out_and_a_noop_is_free) {
    Daemons d;
    d.reload_gap = 700;
    d.start_server(true, false);
    ControlClient sc(d.sctl, 5000, d.sdir);
    CHECK(wait_until([&] { return sc.ping(); }, 10));
    // unchanged file: ok, "unchanged", and it does not use up the allowance
    ReloadResult rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(rr.applied.empty());
    rr = sc.reload_config();
    CHECK(rr.ok);
    // a real change goes through ...
    spit(d.scfg, d.server_text(true, true, d.port));
    rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(contains(rr.applied, "clients added: c2"));
    // ... a second real change right after is refused ...
    spit(d.scfg, d.server_text(true, false, d.port));
    rr = sc.reload_config();
    CHECK(!rr.ok);
    CHECK(rr.message.find("too quickly") != std::string::npos);
    CHECK_EQ(sc.get_status().peers.size(), size_t(2));
    // ... and is accepted once the gap has passed
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK_EQ(sc.get_status().peers.size(), size_t(1));
    // more than three reload requests on one connection are refused (a fresh connection starts again)
    ControlRequest q;
    q.op = ControlOp::ReloadConfig;
    for (int i = 0; i < 4; ++i) {
        q.token = uint64_t(i + 1);
        ControlResponse r = sc.call(q);  // each call() is its own connection: never denied
        CHECK(r.status == ControlStatus::Ok);
    }
}

TEST(gui_daemon_refuses_a_configuration_others_can_edit) {
    Daemons d;
    d.start_server(true, false);
    ControlClient sc(d.sctl, 5000, d.sdir);
    CHECK(wait_until([&] { return sc.ping(); }, 10));
    // someone makes the config writable by everybody: the next reload keeps the running configuration
    spit(d.scfg, d.server_text(true, true, d.port));
    CHECK(guitest::make_world_writable(d.scfg));
    ReloadResult rr = sc.reload_config();
    CHECK(!rr.ok);
    CHECK(rr.message.find("refusing to trust") != std::string::npos);
    CHECK_EQ(sc.get_status().peers.size(), size_t(1));
    CHECK(sc.get_status().config_error.find("refusing to trust") != std::string::npos);
}

TEST(gui_daemon_will_not_start_on_a_configuration_others_can_edit) {
    Daemons d;
    spit(d.scfg, d.server_text(true, false, d.port));
    CHECK(guitest::make_world_writable(d.scfg));
    DaemonOptions o;
    o.service_name = d.sctl;
    o.config_path = d.scfg.u8string();
    o.version = "test";
    o.control_dir_override = d.sdir;
    o.enforce_config_trust = true;
    ServerDaemon sd(load_server_config_resolved(o.config_path), fwd(d.t.p), o);
    std::atomic<bool> stop{false};
    bool threw = false;
    try {
        sd.run(stop);
    } catch (const Error& e) {
        threw = true;
        CHECK(std::string(e.what()).find("refusing to trust") != std::string::npos);
    }
    CHECK(threw);
    ControlClient sc(d.sctl, 800, d.sdir);
    CHECK(!sc.ping());  // nothing was started
}

TEST(gui_daemon_key_file_change_is_noticed_and_a_failed_reload_does_not_lock_out_the_next) {
    Daemons d;
    d.reload_gap = 5000;
    d.start_server(true, false);
    ControlClient sc(d.sctl, 5000, d.sdir);
    CHECK(wait_until([&] { return sc.ping(); }, 10));
    // the server key file is replaced in place (same path): only a restart picks it up, and the reload says so
    {
        std::ofstream(d.skey, std::ios::binary | std::ios::app) << "\n";
    }
    ReloadResult rr = sc.reload_config();
    CHECK(rr.ok);
    CHECK(contains(rr.needs_restart, "key_file contents"));

    d.start_client();
    ControlClient cc(d.cctl, 5000, d.cdir);
    CHECK(wait_until([&] { return cc.ping(); }, 10));
    // a reload that fails its vetting must not start the 5 s clock
    spit(d.ccfg, d.client_text(true, fwd(d.t.p / "no-such.key")));
    ReloadResult bad = cc.reload_config();
    CHECK(!bad.ok);
    spit(d.src2 / "z.txt", "z\n");
    spit(d.ccfg, d.client_text(true));
    ReloadResult good = cc.reload_config();
    CHECK(good.ok);
    CHECK(contains(good.applied, "watches added: w2"));
    // and now the clock is running
    spit(d.ccfg, d.client_text(false));
    ReloadResult fast = cc.reload_config();
    CHECK(!fast.ok);
    CHECK(fast.message.find("too quickly") != std::string::npos);
}
