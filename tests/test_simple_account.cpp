// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// The service that runs as the user: names, unit text, the private password channel (with a fake "elevated" end in
// this process), command lines, and the "no link on the way to a root" rule of the engine. Nothing here installs a
// service, touches the LSA or asks Windows for a logon of a real account.
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "mysync/client_engine.h"
#include "mysync/gui/daemon.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/linkcheck.h"
#include "mysync/service.h"
#include "mysync/simple/pairing.h"
#include "mysync/simple/service_account.h"
#include "mysync/simple/service_upgrade.h"
#include "testing.h"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace mysync;
using namespace mysync::simple;
namespace fs = std::filesystem;

namespace {

struct ATmp {
    fs::path p;
    ATmp() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-acct-" + to_hex(r, sizeof r));
        fs::create_directories(p);
        log_set_level(LogLevel::Warn);
    }
    ~ATmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string sub(const std::string& n) const {
        fs::path q = p / fs::u8path(n);
        fs::create_directories(q);
        return q.u8string();
    }
};

// A link (junction on Windows - no privilege needed, symbolic link elsewhere). False if it cannot be made here.
bool make_link(const fs::path& link, const fs::path& target) {
#ifdef _WIN32
    std::string cmd = "mklink /J \"" + link.u8string() + "\" \"" + target.u8string() + "\" > NUL 2>&1";
    return std::system(("\"" + cmd + "\"").c_str()) == 0;
#else
    std::error_code ec;
    fs::create_directory_symlink(target, link, ec);
    if (ec) return false;
    // Links made by root count as "the system's" in the ancestors of a root; hand this one to an ordinary account so the
    // test is the same whoever runs it (a container runs as root).
    if (::geteuid() == 0 && ::lchown(link.c_str(), 65534, 65534) != 0) return false;
    return true;
#endif
}

bool wait_for(const std::function<bool()>& cond, int ms = 15000) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    return cond();
}

}  // namespace

// ------------------------------------------------------------------------------------------ names
TEST(account_service_names_are_safe_and_per_user) {
    CHECK_EQ(user_service_name("DESKTOP-1\\Alice"), std::string("mysync-alice"));
    CHECK_EQ(user_service_name(".\\Bob Smith"), std::string("mysync-bob-smith"));
    CHECK_EQ(user_service_name("carol@example.com"), std::string("mysync-carol"));
    CHECK_EQ(user_service_name("MicrosoftAccount\\dave@outlook.com"), std::string("mysync-dave"));
    CHECK_EQ(user_service_name("a_b-c"), std::string("mysync-a_b-c"));
    CHECK_EQ(user_service_name("!!!"), std::string("mysync-user"));
    CHECK(user_service_name(std::string(300, 'x')).size() <= 56);
    for (const char* n : {"../x", "a b/c", "x\"y", "x\ny"}) {
        std::string s = user_service_name(n);
        CHECK(gui::ServiceController::valid_name(s));
    }
    CHECK(user_service_name("alice") != user_service_name("bob"));
    CHECK(valid_account_name("DOMAIN\\alice") && valid_account_name("alice@example.com") && valid_account_name(".\\alice"));
    CHECK(!valid_account_name("") && !valid_account_name("-x") && !valid_account_name("a\\b\\c") && !valid_account_name("a\"b") &&
          !valid_account_name("a\nb") && !valid_account_name("a/b") && !valid_account_name(std::string(257, 'a')));
}

TEST(account_logon_errors_are_explained_in_plain_words_and_never_hold_a_password) {
    CHECK(explain_logon_error(1326).find("Hello PIN") != std::string::npos);   // Microsoft account: the account password
    CHECK(explain_logon_error(1327).find("without a password") != std::string::npos);
    CHECK(explain_logon_error(1909).find("locked") != std::string::npos);
    CHECK(explain_logon_error(1385).find("policy") != std::string::npos);
    CHECK(explain_logon_error(99999).find("99999") != std::string::npos);
#ifdef _WIN32
    // a name that does not exist: refused with the plain text, and the password appears nowhere in the answer
    SecretString pw(std::string("S3cret!Pass-xyz"));
    AccountCheck c = check_service_account(".\\no-such-user-" + to_hex("ab", 2), pw);
    CHECK(!c.ok);
    CHECK(!c.error.empty());
    CHECK(c.error.find("S3cret") == std::string::npos);
    AccountCheck blank = check_service_account(".\\x", SecretString());
    CHECK(!blank.ok && blank.error.find("without a password") != std::string::npos);
    CHECK(!check_service_account("bad\"name", pw).ok);
#endif
}

TEST(account_secret_string_moves_and_clears) {
    SecretString a(std::string("hunter2"));
    CHECK_EQ(a.size(), size_t(7));
    SecretString b(std::move(a));
    CHECK(a.empty());
    CHECK_EQ(b.reveal(), std::string("hunter2"));
    SecretString c;
    c = std::move(b);
    CHECK(b.empty() && !c.empty());
    c.clear();
    CHECK(c.empty());
}

// ------------------------------------------------------------------------------------------ systemd unit, user flavour
TEST(account_user_unit_text_runs_as_the_user_and_stays_hardened) {
    SystemdOptions o;
    o.group = "alice";
    o.runtime_dir = "mysync-alice";
    o.runtime_dir_mode = "0700";
    std::string u = systemd_unit_text("mysync-alice", "/usr/bin/mysync",
                                      {"run", "-c", "/var/lib/mysync/mysync-alice/config.toml", "--role", "client", "--service"},
                                      "alice", {"/var/lib/mysync/mysync-alice/state", "/home/alice/docs", "/mnt/usb/backup"}, "", o);
    CHECK(u.find("\nUser=alice\n") != std::string::npos);
    CHECK(u.find("\nGroup=alice\n") != std::string::npos);
    CHECK(u.find("\nRuntimeDirectory=mysync-alice\nRuntimeDirectoryMode=0700\n") != std::string::npos);
    for (const char* h : {"NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=true", "PrivateDevices=true",
                          "RestrictSUIDSGID=true", "ProtectKernelTunables=true"})
        CHECK(u.find(h) != std::string::npos);
    CHECK(u.find("ReadWritePaths=/var/lib/mysync/mysync-alice/state /home/alice/docs /mnt/usb/backup\n") != std::string::npos);
    CHECK(u.find("User=root") == std::string::npos);
    // the default flavour is unchanged
    std::string d = systemd_unit_text("mysync-server", "/usr/bin/mysync", {"run"}, "", {}, "");
    CHECK(d.find("RuntimeDirectory=mysync\nRuntimeDirectoryMode=0750\n") != std::string::npos);
    CHECK(d.find("Group=") == std::string::npos);
    // injection guards
    SystemdOptions bad = o;
    bad.group = "a b";
    CHECK_THROWS(systemd_unit_text("x", "/usr/bin/mysync", {}, "alice", {}, "", bad));
    bad = o;
    bad.runtime_dir = "../x";
    CHECK_THROWS(systemd_unit_text("x", "/usr/bin/mysync", {}, "alice", {}, "", bad));
    bad = o;
    bad.runtime_dir_mode = "0777\nExecStart=/bin/sh";
    CHECK_THROWS(systemd_unit_text("x", "/usr/bin/mysync", {}, "alice", {}, "", bad));
    bad = o;
    bad.runtime_dir_mode = "0780";
    CHECK_THROWS(systemd_unit_text("x", "/usr/bin/mysync", {}, "alice", {}, "", bad));
}

TEST(account_user_service_locations_belong_to_the_service_not_to_the_admin_area) {
    ServiceLocations l = user_service_locations("mysync-alice");
    CHECK(fs::u8path(l.config).parent_path() == fs::u8path(l.dir));
    CHECK(fs::u8path(l.key).parent_path() == fs::u8path(l.dir));
    CHECK(l.dir.find("mysync-alice") != std::string::npos);
    CHECK(user_service_locations("mysync-bob").dir != l.dir);
#ifndef _WIN32
    CHECK(l.dir == "/var/lib/mysync/mysync-alice");
    CHECK(l.config.rfind("/etc", 0) != 0);   // not the root-owned system-wide place
#endif
}

// ------------------------------------------------------------------------------------------ the private password channel
#ifdef _WIN32
TEST(account_password_channel_hands_the_password_over_once_to_a_client_with_the_nonce) {
    auto ch = PasswordChannel::create();
    CHECK(ch->pipe_name().rfind("mysync-pw-", 0) == 0);
    CHECK_EQ(ch->nonce_hex().size(), size_t(32));
    SecretString secret(std::string("Pa55w0rd-with-ünïcode"));
    SecretString got;
    std::string cerr_text, derr;
    bool client_ok = false, delivered = false;
    std::thread client([&] { client_ok = receive_password(ch->pipe_name(), ch->nonce_hex(), &got, &cerr_text); });
    std::thread server([&] { delivered = ch->deliver(secret, 15000, &derr); });
    client.join();
    server.join();
    CHECK(delivered && client_ok);
    CHECK_EQ(got.reveal(), secret.reveal());
    // the password was never in what travels in a command line
    CHECK(ch->pipe_name().find("Pa55") == std::string::npos && ch->nonce_hex().find("Pa55") == std::string::npos);
    // replay: the pipe is gone
    SecretString again;
    std::string e2;
    CHECK(!receive_password(ch->pipe_name(), ch->nonce_hex(), &again, &e2));
    CHECK(again.empty());
    std::string e3;
    CHECK(!ch->deliver(secret, 100, &e3));    // and it cannot be used twice
}

TEST(account_password_channel_drops_a_wrong_nonce_and_still_serves_the_right_one) {
    auto ch = PasswordChannel::create();
    SecretString secret(std::string("correct horse"));
    std::string derr;
    bool delivered = false;
    std::thread server([&] { delivered = ch->deliver(secret, 20000, &derr); });
    std::string wrong = ch->nonce_hex();
    wrong[0] = wrong[0] == 'a' ? 'b' : 'a';
    SecretString none;
    std::string e1;
    CHECK(!receive_password(ch->pipe_name(), wrong, &none, &e1));    // dropped, nothing received
    CHECK(none.empty());
    SecretString got;
    std::string e2;
    CHECK(receive_password(ch->pipe_name(), ch->nonce_hex(), &got, &e2));
    server.join();
    CHECK(delivered);
    CHECK_EQ(got.reveal(), std::string("correct horse"));
}

TEST(account_password_channel_gives_up_and_can_be_cancelled) {
    auto ch = PasswordChannel::create();
    SecretString secret(std::string("x"));
    std::string e;
    auto t0 = std::chrono::steady_clock::now();
    CHECK(!ch->deliver(secret, 300, &e));                            // nobody comes: bounded wait
    CHECK(e.find("did not connect") != std::string::npos);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));
    auto ch2 = PasswordChannel::create();
    std::string e2;
    bool r = true;
    std::thread th([&] { r = ch2->deliver(secret, 60000, &e2); });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ch2->cancel();                                                     // the elevated step never started (UAC refused)
    th.join();
    CHECK(!r && e2 == "cancelled");
    // bad coordinates are refused before touching anything
    SecretString out;
    std::string e3;
    CHECK(!receive_password("not-ours", ch->nonce_hex(), &out, &e3));
    CHECK(!receive_password("mysync-pw-../x", ch->nonce_hex(), &out, &e3));
    CHECK(!receive_password("mysync-pw-0000", "zz", &out, &e3));
}

TEST(account_password_channel_pipe_is_private_to_the_user) {
    auto ch = PasswordChannel::create();
    // Only this user (+ SYSTEM + Administrators) may even open it, and a second server cannot take the name.
    std::wstring path = L"\\\\.\\pipe\\" + fs::u8path(ch->pipe_name()).wstring();
    HANDLE squat = CreateNamedPipeW(path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                    PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 512, 512, 0, nullptr);
    CHECK(squat == INVALID_HANDLE_VALUE);
    if (squat != INVALID_HANDLE_VALUE) CloseHandle(squat);
    ch->cancel();
}
#else
TEST(account_password_channel_is_windows_only) {
    CHECK_THROWS(PasswordChannel::create());
    SecretString s;
    std::string e;
    CHECK(!receive_password("x", "y", &s, &e));
    CHECK(check_service_account("alice", SecretString(std::string("x"))).ok);   // nothing to check on this system
}
#endif

// ------------------------------------------------------------------------------------------ command lines
TEST(account_controller_arguments_carry_the_channel_never_the_password) {
    std::string self;
#ifdef _WIN32
    wchar_t buf[1024];
    DWORD n = GetModuleFileNameW(nullptr, buf, 1024);
    self = fs::path(std::wstring(buf, n)).u8string();
    std::string exe = (fs::u8path(self).parent_path() / "mysync.exe").u8string();
#else
    self = fs::read_symlink("/proc/self/exe").string();
    std::string exe = (fs::u8path(self).parent_path() / "mysync").u8string();
#endif
    std::unique_ptr<gui::ServiceController> ctl;
    try {
        ctl = std::make_unique<gui::ServiceController>(exe);
    } catch (const std::exception&) {
        SKIP_TEST("no suitable mysync next to the tests");
    }
    ATmp t;
    std::string cfg = (t.p / "config.toml").u8string();
    std::ofstream(cfg) << "x";
    SecretString pw(std::string("TopSecret-Password"));
    gui::ServiceRequest rq;
    rq.name = "mysync-alice";
    rq.config_path = cfg;
    rq.role = "client";
    rq.run_as = ".\\alice";
    rq.user_service = true;
    rq.password = &pw;
    rq.password_pipe = "mysync-pw-0123456789abcdef";
    rq.password_nonce = std::string(32, 'a');
    std::vector<std::string> a = ctl->build_args(gui::ServiceAction::Install, rq);
    auto has = [&](const std::string& s) { return std::find(a.begin(), a.end(), s) != a.end(); };
    CHECK(has("--password-pipe") && has("--password-nonce") && has("--user-service") && has(".\\alice"));
    for (const auto& x : a) CHECK(x.find("TopSecret") == std::string::npos);
    // invalid coordinates
    gui::ServiceRequest bad = rq;
    bad.password_pipe = "other-name";
    CHECK_THROWS(ctl->build_args(gui::ServiceAction::Install, bad));
    bad = rq;
    bad.password_nonce = "short";
    CHECK_THROWS(ctl->build_args(gui::ServiceAction::Install, bad));
    // set-password
    gui::ServiceRequest sp;
    sp.name = "mysync-alice";
    sp.run_as = ".\\alice";
    sp.password_pipe = rq.password_pipe;
    sp.password_nonce = rq.password_nonce;
    std::vector<std::string> b = ctl->build_args(gui::ServiceAction::SetPassword, sp);
    CHECK_EQ(b[1], std::string("set-password"));
    CHECK(std::find(b.begin(), b.end(), "--password-pipe") != b.end());
    sp.password_pipe.clear();
    CHECK_THROWS(ctl->build_args(gui::ServiceAction::SetPassword, sp));
#ifdef _WIN32
    // a user account without a password is refused BEFORE any elevation prompt
    gui::ServiceRequest nop = rq;
    nop.password = nullptr;
    nop.password_pipe.clear();
    gui::ServiceResult r = ctl->run(gui::ServiceAction::Install, nop);
    CHECK(!r.ok && r.exit_code == gui::kServiceBadArguments);
    CHECK(r.message.find("password") != std::string::npos);
#endif
}

TEST(account_cli_set_password_and_install_need_the_channel) {
    // The command line of `mysync service set-password` takes the channel, not a password: an attempt to give one is an
    // unknown option.
    std::string exe;
#ifdef _WIN32
    wchar_t buf[1024];
    DWORD n = GetModuleFileNameW(nullptr, buf, 1024);
    exe = (fs::path(std::wstring(buf, n)).parent_path() / "mysync.exe").string();
#else
    exe = (fs::read_symlink("/proc/self/exe").parent_path() / "mysync").string();
#endif
    if (!fs::exists(exe)) SKIP_TEST("no mysync next to the tests");
    ATmp t;
    auto run = [&](const std::string& args) {
        std::string cmd = "\"" + exe + "\" " + args + " > \"" + (t.p / "o.txt").string() + "\" 2>&1";
#ifdef _WIN32
        cmd = "\"" + cmd + "\"";
#endif
        int rc = std::system(cmd.c_str());
#ifndef _WIN32
        rc = WIFEXITED(rc) ? WEXITSTATUS(rc) : -2;
#endif
        return rc;
    };
    CHECK_EQ(run("service set-password --name mysync-x --user .\\\\x --password hunter2"), 2);       // unknown option
    CHECK_EQ(run("service set-password --name mysync-x --user .\\\\x"), 20);                          // needs the channel (bad arguments)
}

// ------------------------------------------------------------------------------------------ no links on the way to a root
TEST(account_link_component_finds_links_anywhere_on_the_way) {
    ATmp t;
    std::string real = t.sub("real/deep/er");
    CHECK(link_component(real).empty());
    CHECK(link_component((t.p / "does" / "not" / "exist").u8string()).empty());
    fs::path lnk = t.p / "lnk";
    if (!make_link(lnk, t.p / "real")) SKIP_TEST("cannot create a link here");
    CHECK_EQ(link_component((lnk / "deep" / "er").u8string()), lnk.u8string());    // the middle of the path
    CHECK_EQ(link_component(lnk.u8string()), lnk.u8string());                       // the root itself
    CHECK(!link_refusal_text((lnk / "deep").u8string()).empty());
    CHECK(link_refusal_text(real).empty());
    std::error_code ec;
    fs::remove(lnk, ec);
}

namespace {
ClientConfig plain_cfg(const fs::path& src, const fs::path& dst, const fs::path& state) {
    ClientConfig cc;
    cc.state_dir = state.u8string();
    cc.connections = 2;
    cc.retry_min_ms = 100;
    cc.retry_max_ms = 400;
    WatchConfig w;
    w.name = "w";
    w.path = src.u8string();
    w.quiet_ms = 100;
    w.sync_delay_ms = 50;
    w.start_sync = true;
    w.periodic_scan_s = 3600;
    TargetConfig tc;
    tc.path = dst.u8string();
    w.targets.push_back(tc);
    cc.watches.push_back(w);
    return cc;
}
}  // namespace

TEST(account_engine_refuses_a_source_root_that_is_a_link_and_says_so) {
    ATmp t;
    fs::path real = t.p / "real", dst = t.p / "dst", lnk = t.p / "lnk";
    fs::create_directories(real);
    fs::create_directories(dst);
    std::ofstream(real / "a.txt") << "secret";
    if (!make_link(lnk, real)) SKIP_TEST("cannot create a link here");
    SyncEngine e(plain_cfg(lnk, dst, t.p / "state"), t.p.u8string());
    std::atomic<bool> stop{false};
    std::thread th([&] {
        try {
            e.run(stop);
        } catch (const std::exception&) {
        }
    });
    struct J {
        std::thread& t;
        std::atomic<bool>& s;
        ~J() { s = true; if (t.joinable()) t.join(); }
    } guard{th, stop};
    CHECK(wait_for([&] {
        auto s = e.snapshot();
        return !s.targets.empty() && s.targets[0].state == gui::TargetState::Error &&
               s.targets[0].last_error.find("is a link") != std::string::npos;
    }, 10000));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    CHECK(!fs::exists(dst / "a.txt"));                      // nothing was copied through the link
    CHECK(!fs::exists(real / "__sync"));                    // and no lock file was dropped behind it
    stop = true;
    th.join();
    std::error_code ec;
    fs::remove(lnk, ec);
}

TEST(account_local_target_root_that_is_a_link_is_refused) {
    ATmp t;
    fs::path src = t.p / "src", real = t.p / "elsewhere", lnk = t.p / "dstlink";
    fs::create_directories(src);
    fs::create_directories(real);
    std::ofstream(src / "a.txt") << "data";
    if (!make_link(lnk, real)) SKIP_TEST("cannot create a link here");
    SyncEngine e(plain_cfg(src, lnk, t.p / "state"), t.p.u8string());
    std::atomic<bool> stop{false};
    std::thread th([&] {
        try {
            e.run(stop);
        } catch (const std::exception&) {
        }
    });
    struct J {
        std::thread& t;
        std::atomic<bool>& s;
        ~J() { s = true; if (t.joinable()) t.join(); }
    } guard{th, stop};
    CHECK(wait_for([&] {
        auto s = e.snapshot();
        return !s.targets.empty() && s.targets[0].last_error.find("link") != std::string::npos;
    }, 10000));
    CHECK(!fs::exists(real / "a.txt"));
    stop = true;
    th.join();
    std::error_code ec;
    fs::remove(lnk, ec);
}

// ------------------------------------------------------------------------------------------ deny must not hide a failed cleanup
TEST(account_deny_reports_a_failed_cleanup_with_the_manual_command) {
    PubKey srv{};
    srv[0] = 1;
    PairingManager pm(srv);
    PairToken tok = pm.enable();
    PubKey k{};
    k[0] = 9;
    PairWire w;
    w.type = PairMsg::Request;
    w.name = "Laptop";
    w.token = tok;
    auto r = pm.on_message("10.0.0.1", k, encode_pair_wire(w));
    CHECK(decode_pair_wire(r.msg).type == PairMsg::Wait);
    pm.set_revoke_handler([](const PubKey&) { throw Error("disk is read-only"); });
    uint32_t id = pm.pending()[0].id;
    std::string msg;
    try {
        pm.deny(id);
    } catch (const Error& e) {
        msg = e.what();
    }
    CHECK(msg.find("disk is read-only") != std::string::npos);
    CHECK(msg.find("mysync peer remove " + key_to_hex(k)) != std::string::npos);
    // the request IS denied all the same
    PairWire poll;
    poll.type = PairMsg::Poll;
    auto d = pm.on_message("10.0.0.1", k, encode_pair_wire(poll));
    CHECK(decode_pair_wire(d.msg).type == PairMsg::Denied);
}

// ------------------------------------------------------------------------------------------ 7c
TEST(account_service_names_are_unique_per_owner_and_labelled) {
    std::string a = user_service_name("PC\\alice", "S-1-5-21-1-2-3-1001");
    std::string b = user_service_name("PC\\alice", "S-1-5-21-1-2-3-1002");   // another user whose name reduces to the same text
    CHECK(a != b);
    CHECK(a.rfind("mysync-alice-", 0) == 0 && a.size() == std::string("mysync-alice-xxxx").size());
    CHECK(gui::ServiceController::valid_name(a));
    CHECK(a != "mysync-client" && a != "mysync-server");
    CHECK(user_service_name("client", "x") != "mysync-client");
    CHECK_EQ(user_service_name("PC\\alice", "S-1-5-21-1-2-3-1001"), a);   // stable
    CHECK_EQ(owner_label("1000"), std::string("[owner 1000]"));
    CHECK(!current_owner_id().empty());
}

TEST(account_password_attempts_are_limited) {
    PasswordAttemptLimiter l;
    int64_t t = 1000000;
    for (int i = 0; i < 4; ++i) {
        CHECK(l.allowed(t));
        l.failed(t);
    }
    CHECK(l.allowed(t));
    l.failed(t);                                  // the 5th wrong password
    CHECK(!l.allowed(t));
    CHECK(l.seconds_left(t) > 0 && l.seconds_left(t) <= 30);
    CHECK(!l.allowed(t + 29000));
    CHECK(l.allowed(t + 30001));
    l.failed(t + 31000);
    l.succeeded();
    for (int i = 0; i < 4; ++i) l.failed(t + 40000);
    CHECK(l.allowed(t + 40000));                  // the counter restarted after a success
}

TEST(account_strict_user_unit_adds_the_extra_hardening_only_when_asked) {
    SystemdOptions o;
    o.strict_user = true;
    o.group = "alice";
    o.runtime_dir = "mysync-alice-3f9a";
    o.runtime_dir_mode = "0700";
    std::string u = systemd_unit_text("mysync-alice-3f9a", "/usr/bin/mysync", {"run"}, "alice", {}, "MySync [owner 1000]", o);
    for (const char* h : {"CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "RestrictNamespaces=yes", "ProtectKernelLogs=yes", "ProtectClock=yes",
                          "ProtectProc=invisible", "ProtectHostname=yes", "UMask=0077", "NoNewPrivileges=true"})
        CHECK(u.find(h) != std::string::npos);
    CHECK(u.find("Description=MySync [owner 1000]\n") != std::string::npos);
    CHECK(u.find("SystemCallFilter") == std::string::npos);   // deliberately not set (see DESIGN.md)
    std::string plain = systemd_unit_text("mysync-server", "/usr/bin/mysync", {"run"}, "", {}, "");
    CHECK(plain.find("CapabilityBoundingSet") == std::string::npos && plain.find("UMask") == std::string::npos);
}

TEST(account_service_dir_acls_let_the_account_read_the_config_but_not_write_it) {
    std::string sid = "S-1-5-21-1111-2222-3333-1001";
    std::string top = service_dir_sddl(ServiceDirKind::ServiceTop, sid), full = service_dir_sddl(ServiceDirKind::UserFull, sid),
                admin = service_dir_sddl(ServiceDirKind::Admin, sid);
    CHECK(top.rfind("D:P", 0) == 0 && full.rfind("D:P", 0) == 0);                       // protected: nothing inherited from outside
    CHECK(top.find(";;;BA)") != std::string::npos && top.find(";;;SY)") != std::string::npos);
    CHECK(top.find("(A;OICI;0x1200a9;;;" + sid + ")") != std::string::npos);            // read + traverse only
    CHECK(top.find("FA;;;" + sid) == std::string::npos);
    CHECK(full.find("(A;OICI;FA;;;" + sid + ")") != std::string::npos);                // state / log: the account writes
    CHECK(admin.find(sid) == std::string::npos);
}

#ifdef _WIN32
TEST(account_service_top_folder_really_refuses_writes_by_the_account) {
    if (gui::ServiceController::is_elevated()) SKIP_TEST("running as an administrator: the Administrators ACE applies to this token");
    ATmp t;
    std::string sid = current_user_sid();
    std::string top = (t.p / "svc").u8string();
    // (create_service_dir itself refuses a folder whose OWNER is this unprivileged user - see the d7d test below - so the
    // folders are made here straight from the SDDL text, as an administrator would make them)
    auto make = [&](const fs::path& d, ServiceDirKind k) {
        std::wstring w = fs::u8path(service_dir_sddl(k, sid)).wstring();
        PSECURITY_DESCRIPTOR psd = nullptr;
        CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(w.c_str(), SDDL_REVISION_1, &psd, nullptr));
        SECURITY_ATTRIBUTES sa{sizeof sa, psd, FALSE};
        CHECK(CreateDirectoryW(d.c_str(), &sa));
        LocalFree(psd);
    };
    make(t.p / "svc", ServiceDirKind::ServiceTop);
    make(t.p / "st", ServiceDirKind::UserFull);
    // the account cannot create or replace anything directly in the folder holding the configuration...
    std::ofstream bad(t.p / "svc" / "config.toml", std::ios::binary);
    CHECK(!bad.is_open());
    // ...but can use state/
    {
        std::ofstream ok(t.p / "st" / "index.bin", std::ios::binary);
        CHECK(ok.is_open());
        ok << "x";
    }
    CHECK(fs::exists(t.p / "st" / "index.bin"));
}
#endif

TEST(account_apply_config_arguments_need_the_shown_hash_and_no_key) {
    std::string self;
#ifdef _WIN32
    wchar_t buf[1024];
    DWORD n = GetModuleFileNameW(nullptr, buf, 1024);
    self = fs::path(std::wstring(buf, n)).u8string();
    std::string exe = (fs::u8path(self).parent_path() / "mysync.exe").u8string();
#else
    self = fs::read_symlink("/proc/self/exe").string();
    std::string exe = (fs::u8path(self).parent_path() / "mysync").u8string();
#endif
    std::unique_ptr<gui::ServiceController> ctl;
    try {
        ctl = std::make_unique<gui::ServiceController>(exe);
    } catch (const std::exception&) {
        SKIP_TEST("no suitable mysync next to the tests");
    }
    ATmp t;
    gui::ServiceRequest rq;
    rq.name = "mysync-alice-3f9a";
    rq.user_config = (t.p / "config.toml").u8string();
    rq.run_as = ".\\alice";
    CHECK_THROWS(ctl->build_args(gui::ServiceAction::ApplyConfig, rq));       // the shown hash is mandatory
    rq.expect_config_hash = std::string(64, 'c');
    std::vector<std::string> a = ctl->build_args(gui::ServiceAction::ApplyConfig, rq);
    CHECK_EQ(a[1], std::string("apply-config"));
    CHECK(std::find(a.begin(), a.end(), "--expect-hash") != a.end());
    CHECK(std::find(a.begin(), a.end(), "--expect-key-hash") == a.end());     // the key stays as it is
    CHECK(std::find(a.begin(), a.end(), "--account") != a.end());
}

TEST(account_service_config_rules_are_applied_by_the_daemon_at_every_load) {
    ClientConfig c;
    WatchConfig w;
    w.name = "w";
#ifdef _WIN32
    std::string sysdir = std::string(std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows") + "\\Temp";
#else
    std::string sysdir = "/etc/mysync-test";
#endif
    w.path = sysdir;
    TargetConfig tc;
    tc.path = (fs::temp_directory_path() / "dst").u8string();
    w.targets.push_back(tc);
    c.watches.push_back(w);
    std::string why = service_config_path_problem(c, fs::temp_directory_path().u8string(), {});
    CHECK(!why.empty());
    CHECK(why.find("folder") != std::string::npos);
    // a destination outside the home needs an allow root the service was installed with
    c.watches[0].path = (fs::temp_directory_path() / "src").u8string();
    std::string temp_in_home = service_config_path_problem(c, fs::temp_directory_path().u8string(), {});
    std::string with_root = service_config_path_problem(c, fs::temp_directory_path().u8string(), {fs::temp_directory_path().u8string()});
    CHECK(with_root.empty() || with_root.find("allowed folder") != std::string::npos);   // (a temp folder may itself be refused as a root)
    (void)temp_in_home;
    // a daemon with such a rule refuses to load the configuration
    c.watches[0].path = sysdir;
    gui::DaemonOptions dopt;
    dopt.config_check = [](const ClientConfig& cc) { return service_config_path_problem(cc, "/", {}); };
    CHECK(!dopt.config_check(c).empty());
}

TEST(account_link_check_refuses_doubt_and_reads_through_trailing_separators) {
    ATmp t;
#ifdef _WIN32
    CHECK(!link_component((t.p / "bad|name" / "x").u8string()).empty());   // cannot be examined: refused, not skipped
#endif
    fs::path lnk = t.p / "lnk";
    if (!make_link(lnk, t.p)) SKIP_TEST("cannot create a link here");
    CHECK(!link_component(lnk.u8string() + "/").empty());                    // a trailing separator does not hide the link
    std::error_code ec;
    fs::remove(lnk, ec);
}

#ifndef _WIN32
TEST(account_links_made_by_root_in_the_ancestors_are_part_of_the_machine_but_the_root_itself_never) {
    if (::geteuid() != 0) SKIP_TEST("needs root to make a root-owned link");
    ATmp t;
    fs::create_directories(t.p / "real" / "deep");
    std::error_code ec;
    fs::create_directory_symlink(t.p / "real", t.p / "anc", ec);               // owned by root, like /home -> /var/home
    CHECK(!ec);
    CHECK(link_component((t.p / "anc" / "deep").u8string()).empty());           // an ancestor made by root: tolerated
    CHECK(!link_component((t.p / "anc").u8string()).empty());                    // but a root folder that IS a link: refused
    CHECK(::lchown((t.p / "anc").c_str(), 65534, 65534) == 0);                    // the same link made by an ordinary user
    CHECK(!link_component((t.p / "anc" / "deep").u8string()).empty());
}

TEST(account_posix_install_hands_files_over_by_descriptor_and_follows_nothing) {
    if (::geteuid() != 0) SKIP_TEST("the root step is only exercised as root");
    std::string name = "mysync-test-" + to_hex("zz", 2) + std::to_string(::getpid());
    ServiceLocations loc = user_service_locations(name);
    fs::path victim = fs::temp_directory_path() / ("mysync-victim-" + std::to_string(::getpid()));
    fs::create_directories(victim);
    std::ofstream(victim / "precious") << "keep";
    std::ofstream(victim / "precious2") << "keep2";
    ::chmod((victim / "precious").c_str(), 0640);
    auto cleanup = [&] {
        std::error_code ec;
        fs::remove_all(fs::u8path(loc.dir), ec);
        fs::remove_all(victim, ec);
    };
    struct stat before{};
    ::stat((victim / "precious").c_str(), &before);
    try {
        // the user's old service folder, with links planted in it
        fs::create_directories(fs::u8path(loc.dir));
        ::chown(loc.dir.c_str(), 65534, 65534);
        fs::create_symlink(victim / "precious", fs::u8path(loc.dir) / "config.toml");
        ::link((victim / "precious2").c_str(), (fs::u8path(loc.dir) / "key").c_str());
        std::string key = std::string(64, 'a') + "\n";
        install_service_files(loc, 65534, 65534, "# config\n", &key);
        // what the user planted pointed at root's files: untouched
        struct stat after{};
        ::stat((victim / "precious").c_str(), &after);
        CHECK(after.st_uid == before.st_uid && after.st_mode == before.st_mode);
        std::ifstream pv(victim / "precious");
        std::string pvs((std::istreambuf_iterator<char>(pv)), std::istreambuf_iterator<char>());
        CHECK_EQ(pvs, std::string("keep"));
        struct stat s2{};
        ::stat((victim / "precious2").c_str(), &s2);
        CHECK(s2.st_uid == 0 && s2.st_nlink == 1);
        // the new files are plain, private, and the user's
        struct stat cs{}, ks{}, ds{};
        CHECK(::lstat(loc.config.c_str(), &cs) == 0 && S_ISREG(cs.st_mode) && cs.st_nlink == 1 && cs.st_uid == 65534 && (cs.st_mode & 0777) == 0600);
        CHECK(::lstat(loc.key.c_str(), &ks) == 0 && S_ISREG(ks.st_mode) && ks.st_nlink == 1 && ks.st_uid == 65534 && (ks.st_mode & 0777) == 0600);
        CHECK(::lstat(loc.dir.c_str(), &ds) == 0 && S_ISDIR(ds.st_mode) && ds.st_uid == 65534 && (ds.st_mode & 0777) == 0700);
        // a state/ that is a link is refused outright
        fs::remove_all(fs::u8path(loc.dir) / "state");
        fs::create_directory_symlink(victim, fs::u8path(loc.dir) / "state");
        CHECK_THROWS(install_service_files(loc, 65534, 65534, "# config\n", &key));
        struct stat vs{};
        ::stat(victim.c_str(), &vs);
        CHECK(vs.st_uid == 0);                                                   // the link target was not given away
    } catch (...) {
        cleanup();
        throw;
    }
    cleanup();
}
#endif

// ---- d7d ----

TEST(d7d_logon_right_is_revoked_on_every_rollback_path) {
    std::vector<std::string> revoked;
    auto rev = [&](const std::string& sid) { revoked.push_back(sid); };
    {   // an early return / exception after the grant: the guard takes the right away again
        LogonRightGuard g(rev);
        g.granted("S-1-5-21-1-2-3-1001");
    }
    CHECK_EQ(revoked.size(), size_t(1));
    CHECK_EQ(revoked[0], std::string("S-1-5-21-1-2-3-1001"));
    {   // the right was already there (we did not add it): nothing to take away
        LogonRightGuard g(rev);
    }
    CHECK_EQ(revoked.size(), size_t(1));
    {   // a working, recorded service owns the right now
        LogonRightGuard g(rev);
        g.granted("S-1-5-21-1-2-3-1002");
        g.release();
    }
    CHECK_EQ(revoked.size(), size_t(1));
    try {   // an exception unwinding through the scope
        LogonRightGuard g(rev);
        g.granted("S-1-5-21-1-2-3-1003");
        throw Error("install failed");
    } catch (const Error&) {
    }
    CHECK_EQ(revoked.size(), size_t(2));
    CHECK_EQ(revoked[1], std::string("S-1-5-21-1-2-3-1003"));
}

TEST(d7d_elevated_step_accepts_only_service_names_of_the_requester) {
    std::string owner = "S-1-5-21-1-2-3-1001";
    std::string good = user_service_name("PC\alice", owner);
    CHECK(user_service_name_matches_owner(good, owner));
    CHECK(!user_service_name_matches_owner(good, "S-1-5-21-1-2-3-1002"));   // somebody else's service
    CHECK(!user_service_name_matches_owner("mysync-server", owner));
    CHECK(!user_service_name_matches_owner("mysync-client", owner));
    CHECK(!user_service_name_matches_owner("Spooler", owner));
    CHECK(!user_service_name_matches_owner("mysync-alice", owner));          // no owner code
    CHECK(!user_service_name_matches_owner(good, ""));
}

TEST(d7d_state_and_log_of_an_administrator_account_are_not_user_writable) {
    // unknown account: judged as an administrator
    CHECK(data_dir_kind_for_account("S-1-5-21-9-9-9-1001") == ServiceDirKind::ServiceTop);
    CHECK(data_dir_kind_for_account("") == ServiceDirKind::ServiceTop);
#ifdef _WIN32
    std::string me = current_user_sid();
    CHECK(data_dir_kind_for_account(me) == (account_is_administrator(me) ? ServiceDirKind::ServiceTop : ServiceDirKind::UserFull));
    // and the ACL of that kind gives the account no write access
    CHECK(service_dir_sddl(ServiceDirKind::ServiceTop, me).find("FA;;;" + me) == std::string::npos);
#endif
}

TEST(d7d_service_files_must_stay_inside_the_service_folder) {
    ATmp t;
    std::string dir = t.sub("svc");
    ClientConfig c;
    auto problem = [&](const ClientConfig& cc) { return service_config_path_problem(cc, dir, {}); };
    CHECK(problem(c).empty());
    c.state_dir = "state";
    c.log_file = "log/mysync.log";
    c.key_file = "key";
    CHECK(problem(c).empty());                                               // relative: inside the folder
    ClientConfig bad = c;
    bad.log_file = (fs::path(dir).parent_path() / "elsewhere" / "mysync.log").u8string();
    std::string why = problem(bad);
    CHECK(why.find("log_file") != std::string::npos && why.find("outside the service folder") != std::string::npos);
    bad = c;
    bad.state_dir = (fs::path(dir).parent_path() / "elsewhere").u8string();
    CHECK(problem(bad).find("state_dir") != std::string::npos);
    bad = c;
    bad.key_file = "../other-key";
    CHECK(problem(bad).find("key_file") != std::string::npos);
    // a link inside the folder that leads out of it
    fs::path lnk = fs::path(dir) / "state";
    if (make_link(lnk, t.p)) {
        CHECK(problem(c).find("link") != std::string::npos);
        std::error_code ec;
        fs::remove(lnk, ec);
    }
    // the daemon applies the same rule at every load
    gui::DaemonOptions dopt;
    dopt.config_check = [dir](const ClientConfig& cc) { return service_config_path_problem(cc, dir, {}); };
    CHECK(!dopt.config_check(bad).empty());
}

#ifdef _WIN32
TEST(d7d_a_service_folder_made_beforehand_by_the_user_is_refused) {
    ATmp t;
    std::string sid = current_user_sid();
    std::string pre = t.sub("pre-made");                                     // inherits the temp folder's ACL: the user can write
    CHECK_THROWS(create_service_dir(pre, ServiceDirKind::ServiceTop, sid));
    CHECK_THROWS(create_service_dir(pre, ServiceDirKind::Admin, sid));
    std::string mine = (t.p / "mine").u8string();
    if (gui::ServiceController::is_elevated()) {
        // made by an administrator (owner = Administrators): accepted now and again later (an older install of ours)
        create_service_dir(mine, ServiceDirKind::ServiceTop, sid);
        create_service_dir(mine, ServiceDirKind::ServiceTop, sid);
    } else {
        // an unprivileged creator OWNS what it creates and so can always rewrite its permissions: not an administrator-only
        // folder, and refused as such (the real step runs elevated)
        CHECK_THROWS(create_service_dir(mine, ServiceDirKind::ServiceTop, sid));
    }
}
#endif

#ifndef _WIN32
TEST(d7d_posix_install_refuses_a_folder_of_another_account_or_with_foreign_content) {
    if (::geteuid() != 0) SKIP_TEST("the root step is only exercised as root");
    std::string name = "mysync-test-" + to_hex("yy", 2) + std::to_string(::getpid());
    ServiceLocations loc = user_service_locations(name);
    auto cleanup = [&] {
        std::error_code ec;
        fs::remove_all(fs::u8path(loc.dir), ec);
    };
    std::string key = std::string(64, 'b') + "\n";
    try {
        // somebody else's folder (uid 1234 is neither the owner 65534 nor root)
        fs::create_directories(fs::u8path(loc.dir));
        ::chown(loc.dir.c_str(), 1234, 1234);
        CHECK_THROWS(install_service_files(loc, 65534, 65534, "# config\n", &key));
        struct stat s{};
        ::stat(loc.dir.c_str(), &s);
        CHECK(s.st_uid == 1234);                                             // not taken
        // a root-owned folder that holds something that is not ours
        ::chown(loc.dir.c_str(), 0, 0);
        std::ofstream(fs::u8path(loc.dir) / "authorized_keys") << "x";
        CHECK_THROWS(install_service_files(loc, 65534, 65534, "# config\n", &key));
        fs::remove(fs::u8path(loc.dir) / "authorized_keys");
        // root-owned and holding only our own names (an interrupted earlier run): accepted
        install_service_files(loc, 65534, 65534, "# config\n", &key);
        ::stat(loc.dir.c_str(), &s);
        CHECK(s.st_uid == 65534);
    } catch (...) {
        cleanup();
        throw;
    }
    cleanup();
}
#endif

// ---- d7e ----


// ---- d7e / d7f: who may get a Simple-mode service ----

TEST(d7f_token_facts_decide_fail_closed) {
    TokenFacts f;
    CHECK(admin_state_from_facts(f) == AdminState::Unknown);                 // nothing could be read
    f.readable = true;
    CHECK(admin_state_from_facts(f) == AdminState::No);                      // an ordinary token
    TokenFacts a = f; a.in_admins = true;
    CHECK(admin_state_from_facts(a) == AdminState::Yes);                     // (deny-only / disabled is still 'in_admins')
    TokenFacts o = f; o.in_operator_group = true;
    CHECK(admin_state_from_facts(o) == AdminState::Yes);                     // Backup / Server / Account operators ...
    TokenFacts p = f; p.powerful_privilege = true;
    CHECK(admin_state_from_facts(p) == AdminState::Yes);                     // SeDebug, SeBackup ...
    TokenFacts l = f; l.linked_elevated = true;
    CHECK(admin_state_from_facts(l) == AdminState::Yes);                     // the elevated half of a split token
    TokenFacts u = f; u.linked_unreadable = true;
    CHECK(admin_state_from_facts(u) == AdminState::Unknown);                 // cannot tell: refused as well
#ifdef _WIN32
    CHECK(account_admin_state("S-1-5-21-9-9-9-1001") == AdminState::Unknown);   // not the running user: cannot be judged
    CHECK(account_admin_state("") == AdminState::Unknown);
    CHECK(account_is_administrator("S-1-5-21-9-9-9-1001"));                  // so it counts as an administrator
#else
    CHECK(account_admin_state("1000") == AdminState::No);
#endif
}

TEST(d7f_install_set_password_and_start_decisions_need_a_clear_no) {
    const AdminState No = AdminState::No, Yes = AdminState::Yes, Unk = AdminState::Unknown;
    CHECK(service_account_refusal(No, No).empty());
    CHECK(!service_account_refusal(Yes, No).empty());                        // the target's NEW token says administrator
    CHECK(!service_account_refusal(No, Yes).empty());                        // this process says so
    CHECK(!service_account_refusal(Unk, No).empty());                        // an API failed: refused
    CHECK(!service_account_refusal(No, Unk).empty());
    CHECK(admin_refusal_for(Yes) != admin_refusal_for(Unk));                 // different words, both with the way out
    CHECK(admin_refusal_for(Unk).find("Start when I log in") != std::string::npos);
    CHECK(admin_refusal_for(Yes).find("Start when I log in") != std::string::npos);
    CHECK(service_start_refusal(No).empty());                                // a normal start
    CHECK(service_start_refusal(Yes).find("does not start") != std::string::npos);   // joined Administrators after the install
    CHECK(!service_start_refusal(Unk).empty());
}

TEST(d7f_simple_service_names_are_only_valid_with_user_service) {
    std::string good = user_service_name("PC\alice", "S-1-5-21-1-2-3-1001");
    CHECK(looks_like_user_service_name(good));
    CHECK(!looks_like_user_service_name("mysync-server"));
    CHECK(!looks_like_user_service_name("mysync-client"));
    CHECK(!looks_like_user_service_name("mysync-alice"));
    CHECK(!looks_like_user_service_name("mysync-alice-zzzz"));
    CHECK(!looks_like_user_service_name("other-alice-3f9a"));
    CHECK(looks_like_user_service_name("mysync-alice-3f9a"));
}

#ifdef _WIN32
TEST(d7f_migrate_step_refuses_administrators_and_unknowns_before_creating_anything) {
    ATmp t;
    std::string name = user_service_name("PC\alice", current_user_sid());
    std::string cfg = (t.p / "config.toml").u8string();
    std::string h64(64, 'c');
    std::vector<std::string> args = {"--user-config", cfg, "--expect-hash", h64, "--expect-key-hash", h64, "--name", name};
    auto run = [&](AdminState st, std::string* err) {
        std::ostringstream cap;
        std::streambuf* old = std::cerr.rdbuf(cap.rdbuf());
        int code = run_migrate_from_user(args, [st](const std::string&) { return st; });
        std::cerr.rdbuf(old);
        *err = cap.str();
        return code;
    };
    std::string err;
    CHECK_EQ(run(AdminState::Yes, &err), int(gui::kServiceAccessDenied));
    CHECK(err.find("administrator") != std::string::npos);
    CHECK(!fs::exists(fs::u8path(user_service_locations(name).dir)));         // nothing created
    CHECK_EQ(run(AdminState::Unknown, &err), int(gui::kServiceAccessDenied));
    CHECK(err.find("could not be verified") != std::string::npos);
    CHECK(!fs::exists(fs::u8path(user_service_locations(name).dir)));
    // an ordinary account gets past this gate (the next refusal here is the missing elevation, a different message)
    run(AdminState::No, &err);
    CHECK(err.find("could not be verified") == std::string::npos && err.find("is an administrator") == std::string::npos);
}
#endif
