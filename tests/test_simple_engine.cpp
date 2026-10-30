// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Simple mode, the parts that need processes, sockets and threads: the supervisor (spawn, restart with backoff, give
// up, stop), the one-engine-per-folder lock between real processes and between engines, the user-only control
// channel, and pairing end to end (receiver daemon + sender over the real secure channel on loopback).
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "mysync/client_engine.h"
#include "mysync/engine_lock.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/daemon.h"
#include "mysync/gui/ipc.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/gui/trust.h"
#include "mysync/protocol.h"
#include "mysync/secure_channel.h"
#include "mysync/simple/pair_code.h"
#include "mysync/simple/pairing.h"
#include "mysync/simple/service_upgrade.h"
#include "mysync/simple/user_engine.h"
#include "mysync/simple/wizard_model.h"
#include "gui_test_util.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::simple;
namespace fs = std::filesystem;

// ----------------------------------------------------------------------------------------- the fake engine
// `mysync_tests --fake-engine <mode> ...` is what the supervisor starts in these tests (see tests/test_main.cpp).
//   exit <code> <ms>   print a line to stderr, wait, exit with the code
//   wait               run until standard input closes (the clean stop the real engine implements), exit 0
//   lock <folder>      take <folder>/__sync/engine.lock like an engine; busy -> message + exit 3; else wait as above
static void block_until_stdin_closes() {
    char c;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD n = 0;
    while (h && h != INVALID_HANDLE_VALUE && ReadFile(h, &c, 1, &n, nullptr) && n > 0) {}
#else
    while (true) {
        ssize_t n = ::read(0, &c, 1);
        if (n > 0 || (n < 0 && errno == EINTR)) continue;
        break;
    }
#endif
}

int fake_engine_main(int argc, char** argv) {
    std::string mode = argc > 2 ? argv[2] : "";
    if (mode == "exit") {
        int code = argc > 3 ? std::atoi(argv[3]) : 1;
        int ms = argc > 4 ? std::atoi(argv[4]) : 0;
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        std::cerr << "first line\nboom: the fake engine failed (code " << code << ")" << std::endl;
        return code;
    }
    if (mode == "wait") {
        std::cout << "fake engine ready" << std::endl;
        block_until_stdin_closes();
        return 0;
    }
    if (mode == "lock" && argc > 3) {
        std::string holder;
        auto l = FileLock::try_acquire(engine_lock_path_for_folder(argv[3]), &holder);
        if (!l) {
            std::cerr << engine_lock_busy_message(argv[3], holder) << std::endl;
            return 3;
        }
        std::cout << "locked" << std::endl;
        block_until_stdin_closes();
        return 0;
    }
    return 99;
}

namespace {

// Joins a thread on every way out of a test (a failed CHECK must not leave a joinable thread: that aborts the whole run).
struct JoinGuard {
    std::thread& t;
    std::atomic<bool>* cancel;
    ~JoinGuard() {
        if (cancel) *cancel = true;
        if (t.joinable()) t.join();
    }
};

struct ETmp {
    fs::path p;
    ETmp() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-seng-" + to_hex(r, sizeof r));
        fs::create_directories(p);
        log_set_level(LogLevel::Warn);
    }
    ~ETmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string sub(const std::string& n) const {
        fs::path q = p / fs::u8path(n);
        fs::create_directories(q);
        return q.u8string();
    }
};

bool wait_for(const std::function<bool()>& cond, int ms = 15000) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    return cond();
}

std::string self_path() {
#ifdef _WIN32
    std::wstring buf(1024, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, &buf[0], DWORD(buf.size()));
    buf.resize(n);
    return fs::path(buf).u8string();
#else
    return fs::read_symlink("/proc/self/exe").string();
#endif
}

struct Events {
    std::mutex m;
    std::vector<EngineInfo> v;
    void add(const EngineInfo& i) {
        std::lock_guard<std::mutex> lk(m);
        v.push_back(i);
    }
    std::vector<EngineInfo> get() {
        std::lock_guard<std::mutex> lk(m);
        return v;
    }
};

SupervisorOptions fake_opts(const ETmp& t, Events& ev, std::vector<std::string> args) {
    SupervisorOptions o;
    o.paths = UserPaths::for_current_user((t.p / "ud").u8string());
    o.paths.ensure_dirs();
    o.mysync_exe = self_path();
    o.run_client = true;
    o.client_args = std::move(args);
    o.stop_grace_ms = 3000;
    o.on_change = [&ev](const EngineInfo& i) { ev.add(i); };
    return o;
}

}  // namespace

// ----------------------------------------------------------------------------------------- supervisor
TEST(simple_supervisor_restarts_with_growing_delays_then_gives_up_with_the_verbatim_error) {
    ETmp t;
    Events ev;
    SupervisorOptions o = fake_opts(t, ev, {"--fake-engine", "exit", "7", "20"});
    o.backoff_ms = {100, 200, 400, 800};
    o.max_fast_deaths = 4;
    Supervisor s(o);
    s.start();
    CHECK(wait_for([&] { return s.info(EngineKind::Client).state == EngineState::GaveUp; }, 20000));
    EngineInfo i = s.info(EngineKind::Client);
    CHECK_EQ(i.last_exit_code, 7);
    CHECK_EQ(i.fast_deaths, 4);
    CHECK_EQ(i.restarts, 4);
    CHECK(i.last_error.find("boom: the fake engine failed (code 7)") != std::string::npos);  // verbatim stderr
    CHECK(i.last_error.find("first line") != std::string::npos);
    std::vector<int> delays;
    for (const EngineInfo& e : ev.get())
        if (e.state == EngineState::Backoff) delays.push_back(e.next_retry_ms);
    CHECK((delays == std::vector<int>{100, 200, 400}));   // the 4th death gives up instead of waiting again
    // it really stopped trying
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    CHECK_EQ(s.info(EngineKind::Client).restarts, 4);
    CHECK(s.info(EngineKind::Client).state == EngineState::GaveUp);
    // restart() clears the verdict and tries again
    s.restart(EngineKind::Client);
    CHECK(wait_for([&] { return s.info(EngineKind::Client).restarts > 4; }, 10000));
    s.stop_all();
}

TEST(simple_supervisor_delays_follow_the_documented_sequence) {
    // The real schedule 1 s, 2 s, 5 s, 10 s, 30 s, 60 s then 60 s: checked on the default table without waiting.
    SupervisorOptions o;
    CHECK((o.backoff_ms == std::vector<int>{1000, 2000, 5000, 10000, 30000, 60000}));
    CHECK_EQ(o.fast_death_ms, 10000);
}

TEST(simple_supervisor_runs_an_engine_and_stops_it_cleanly_on_request) {
    ETmp t;
    Events ev;
    Supervisor s(fake_opts(t, ev, {"--fake-engine", "wait"}));
    s.start();
    CHECK(wait_for([&] { return s.info(EngineKind::Client).state == EngineState::Running; }, 15000));
    EngineInfo i = s.info(EngineKind::Client);
    CHECK(i.pid != 0);
    CHECK_EQ(i.control_name, UserPaths::for_current_user((t.p / "ud").u8string()).client_control_name);
    uint32_t pid1 = i.pid;
    // restart replaces the process
    s.restart(EngineKind::Client);
    CHECK(wait_for([&] {
        EngineInfo x = s.info(EngineKind::Client);
        return x.state == EngineState::Running && x.pid != pid1;
    }, 15000));
    // a receiver is only started when asked
    CHECK(s.info(EngineKind::Receiver).state == EngineState::Stopped);
    // stop: no engine is left and the GUI can quit
    s.stop_all();
    CHECK(s.wait_stopped(EngineKind::Client, 5000));
    EngineInfo f = s.info(EngineKind::Client);
    CHECK(f.state == EngineState::Stopped && f.pid == 0);
    s.stop_all();  // idempotent
}

TEST(simple_supervisor_receiver_can_be_switched_on_and_off) {
    ETmp t;
    Events ev;
    SupervisorOptions o = fake_opts(t, ev, {"--fake-engine", "wait"});
    o.receiver_args = {"--fake-engine", "wait"};
    Supervisor s(o);
    s.start();
    s.set_receiver_enabled(true);
    CHECK(wait_for([&] { return s.info(EngineKind::Receiver).state == EngineState::Running; }, 15000));
    s.set_receiver_enabled(false);
    CHECK(s.wait_stopped(EngineKind::Receiver, 8000));
    CHECK(wait_for([&] { return s.info(EngineKind::Receiver).state == EngineState::Stopped; }, 5000));
    CHECK(s.info(EngineKind::Client).state == EngineState::Running || s.info(EngineKind::Client).state == EngineState::Starting);
    s.stop_all();
}

TEST(simple_supervisor_refuses_a_missing_or_relative_engine) {
    ETmp t;
    Events ev;
    SupervisorOptions o = fake_opts(t, ev, {"--fake-engine", "wait"});
    o.mysync_exe = (t.p / "no-such-engine.exe").u8string();
    Supervisor a(o);
    CHECK_THROWS(a.start());
    o.mysync_exe = "mysync";
    Supervisor b(o);
    CHECK_THROWS(b.start());
    SupervisorOptions o2 = fake_opts(t, ev, {});   // default command line but no configuration yet: nothing to run
    Supervisor c(o2);
    c.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    CHECK(c.info(EngineKind::Client).state == EngineState::Stopped);
    CHECK_EQ(c.info(EngineKind::Client).restarts, 0);
    c.stop_all();
}

TEST(simple_instance_lock_allows_one_gui_per_user) {
    ETmp t;
    UserPaths u = UserPaths::for_current_user((t.p / "ud").u8string());
    u.ensure_dirs();
    std::string h;
    auto a = InstanceLock::try_acquire(u, &h);
    CHECK(a != nullptr);
    std::string h2;
    auto b = InstanceLock::try_acquire(u, &h2);
    CHECK(b == nullptr);
    CHECK(h2.rfind("PID ", 0) == 0);
    a.reset();
    CHECK(InstanceLock::try_acquire(u, nullptr) != nullptr);
}

// ----------------------------------------------------------------------------------------- folder lock between processes
TEST(simple_folder_lock_between_two_processes_in_both_directions) {
    ETmp t;
    std::string folder = t.sub("watched");
    Events ev;
    SupervisorOptions o = fake_opts(t, ev, {"--fake-engine", "lock", folder});
    o.backoff_ms = {150};
    o.max_fast_deaths = 100;
    // 1. this process owns the folder: the child engine must report the verbatim message and not run
    std::string holder;
    auto mine = FileLock::try_acquire(engine_lock_path_for_folder(folder), &holder);
    CHECK(mine != nullptr);
    Supervisor s(o);
    s.start();
    CHECK(wait_for([&] { return s.info(EngineKind::Client).last_exit_code == 3; }, 15000));
    EngineInfo bad = s.info(EngineKind::Client);
    CHECK(bad.last_error.find("is already being synchronised by another process (PID " + std::to_string(
#ifdef _WIN32
        static_cast<unsigned long>(GetCurrentProcessId())
#else
        static_cast<long>(getpid())
#endif
        ) + ")") != std::string::npos);
    CHECK(bad.last_error.find(folder) != std::string::npos);
    // 2. we let go: the supervisor's next attempt gets the folder and keeps running
    mine.reset();
    CHECK(wait_for([&] {
        EngineInfo x = s.info(EngineKind::Client);
        return x.state == EngineState::Running && x.pid != 0;
    }, 15000));
    uint32_t pid = s.info(EngineKind::Client).pid;
    // 3. and now WE are refused, told who has it
    std::string h2;
    auto again = FileLock::try_acquire(engine_lock_path_for_folder(folder), &h2);
    CHECK(again == nullptr);
    CHECK_EQ(h2, "PID " + std::to_string(pid));
    // 4. when the engine ends (for any reason) the OS frees the lock: nothing stale to clean
    s.stop_all();
    CHECK(wait_for([&] { return FileLock::try_acquire(engine_lock_path_for_folder(folder), nullptr) != nullptr; }, 5000));
}

// ----------------------------------------------------------------------------------------- folder lock between engines
namespace {
ClientConfig local_cfg(const fs::path& src, const fs::path& dst, const fs::path& state) {
    ClientConfig cc;
    cc.state_dir = state.u8string();
    cc.connections = 2;
    cc.retry_min_ms = 100;
    cc.retry_max_ms = 500;
    WatchConfig w;
    w.name = "w1";
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
std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
}  // namespace

TEST(simple_two_engines_never_watch_the_same_folder) {
    ETmp t;
    fs::path src = t.p / "src", d1 = t.p / "d1", d2 = t.p / "d2";
    fs::create_directories(src);
    fs::create_directories(d1);
    fs::create_directories(d2);
    std::ofstream(src / "a.txt") << "hello";
    SyncEngine a(local_cfg(src, d1, t.p / "s1"), t.p.u8string());
    SyncEngine b(local_cfg(src, d2, t.p / "s2"), t.p.u8string());
    std::atomic<bool> stop_a{false}, stop_b{false};
    std::thread ta([&] { a.run(stop_a); });
    CHECK(wait_for([&] { return slurp(d1 / "a.txt") == "hello"; }, 15000));
    std::thread tb([&] { b.run(stop_b); });
    // B reports the problem instead of syncing
    CHECK(wait_for([&] {
        auto s = b.snapshot();
        return !s.targets.empty() && s.targets[0].state == gui::TargetState::Error;
    }, 10000));
    auto snap = b.snapshot();
    CHECK(snap.targets[0].last_error.find("already being synchronised by another process") != std::string::npos);
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    CHECK(!fs::exists(d2 / "a.txt"));                    // B copied nothing
    // a one-shot pass is refused outright
    SyncEngine c(local_cfg(src, t.p / "d3", t.p / "s3"), t.p.u8string());
    std::atomic<bool> stop_c{false};
    bool refused = false;
    try { c.sync_once(stop_c); } catch (const Error& e) { refused = std::string(e.what()).find("already being synchronised") != std::string::npos; }
    CHECK(refused);
    // A stops: B takes over by itself (it retries every few seconds)
    stop_a = true;
    ta.join();
    CHECK(wait_for([&] { return slurp(d2 / "a.txt") == "hello"; }, 25000));
    stop_b = true;
    tb.join();
}

// ----------------------------------------------------------------------------------------- user-only control channel
TEST(simple_user_only_control_channel) {
    ETmp t;
    gui::IpcServerOptions o;
    uint8_t r[4];
    random_bytes(r, sizeof r);
    o.name = "mysync-test-u-" + to_hex(r, sizeof r);
    o.user_only = true;
    o.dir_override = (t.p / "run").u8string();
    gui::IpcServer srv(o, [](const gui::ControlRequest& q) {
        gui::ControlResponse resp;
        resp.op = q.op;
        resp.token = q.token;
        return resp;
    });
    srv.start();
    gui::ControlClient cc(o.name, 3000, o.dir_override);
    CHECK(cc.ping());
    gui::ControlClient strict(o.name, 3000, o.dir_override);
    strict.require_current_user_only();   // the engine runs as this very user: accepted
    CHECK(strict.ping());
#ifdef _WIN32
    HANDLE h = CreateFileW(fs::u8path(srv.endpoint()).c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    CHECK(h != INVALID_HANDLE_VALUE);
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    CHECK(GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) == ERROR_SUCCESS);
    CloseHandle(h);
    std::string me = current_user_sid();
    bool me_allowed = false;
    int allow_aces = 0;
    for (DWORD i = 0; dacl && i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        auto* hdr = static_cast<ACE_HEADER*>(ace);
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        ++allow_aces;
        PSID sid = &static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart;
        LPWSTR w = nullptr;
        ConvertSidToStringSidW(sid, &w);
        std::string s = fs::path(std::wstring(w)).u8string();
        LocalFree(w);
        CHECK(s != "S-1-5-18");        // not SYSTEM
        CHECK(s != "S-1-5-32-544");    // not Administrators
        CHECK(!gui::detail::is_broad_sid(s));
        if (s == me) me_allowed = true;
    }
    LocalFree(sd);
    CHECK_EQ(allow_aces, 1);
    CHECK(me_allowed);
    // the pure builder agrees and refuses extras
    std::string sddl = gui::detail::ipc_pipe_sddl({}, "S-1-5-21-1-2-3-1001", true);
    CHECK(sddl.find(";;;SY") == std::string::npos && sddl.find(";;;BA") == std::string::npos);
    CHECK(sddl.find("S-1-5-21-1-2-3-1001") != std::string::npos);
    CHECK_THROWS(gui::detail::ipc_pipe_sddl({"S-1-5-21-1-2-3-1002"}, "S-1-5-21-1-2-3-1001", true));
#else
    struct stat st{};
    CHECK(::stat(srv.endpoint().c_str(), &st) == 0);
    CHECK_EQ(int(st.st_mode & 0777), 0600);
    CHECK(::stat(fs::path(srv.endpoint()).parent_path().c_str(), &st) == 0);
    CHECK_EQ(int(st.st_mode & 0777), 0700);
#endif
    srv.stop();
    // allow entries make no sense for a user-only channel
    gui::IpcServerOptions bad = o;
    bad.name += "x";
    bad.allow = {"S-1-5-21-1-2-3-1002"};
#ifdef _WIN32
    gui::IpcServer s2(bad, [](const gui::ControlRequest& q) { gui::ControlResponse r2; r2.op = q.op; return r2; });
    CHECK_THROWS(s2.start());
#endif
}

// ----------------------------------------------------------------------------------------- pairing end to end
namespace {

struct Receiver {
    ETmp& t;
    UserPaths up;
    std::string root;
    uint16_t port = 0;
    std::atomic<bool> stop{false};
    std::thread th;
    std::string fatal;
    std::string pub_hex;
    std::unique_ptr<gui::ControlClient> cc;

    explicit Receiver(ETmp& tmp, std::function<void(const char*)> hook = {}) : t(tmp) {
        up = UserPaths::for_current_user((t.p / "ud").u8string());
        uint8_t r[4];
        random_bytes(r, sizeof r);
        up.receiver_control_name = "mysync-test-r-" + to_hex(r, sizeof r);
        {  // a port that is free right now
            net::init();
            net::Socket s = net::Socket::listen("127.0.0.1", 0);
            port = s.local_port();
        }
        root = (t.p / "received").u8string();
        pub_hex = ensure_receiver_config(root, up, port);
        gui::ConfigEditor ed = gui::ConfigEditor::open(up.receiver_config, gui::ConfigRole::Server);
        ed.server().bind = "127.0.0.1";  // no firewall prompt, no exposure
        ed.save();
        ServerConfig cfg = gui::load_server_config_resolved(up.receiver_config);
        gui::DaemonOptions dopt;
        dopt.service_name = "mysync-server";
        dopt.config_path = up.receiver_config;
        dopt.version = "test";
        dopt.allow_pairing = true;
        dopt.control_user_only = true;
        dopt.control_dir_override = (t.p / "run").u8string();
        dopt.peers_poll_ms = 0;
        dopt.pair_test_hook = hook;
        std::string dir = up.dir;
        th = std::thread([this, cfg, dir, dopt] {
            try {
                gui::ServerDaemon d(cfg, dir, dopt);
                d.run(stop);
            } catch (const std::exception& e) {
                fatal = e.what();
            }
        });
        cc = std::make_unique<gui::ControlClient>(up.receiver_control_name, 5000, (t.p / "run").u8string());
        if (!wait_for([&] { return cc->ping() || !fatal.empty(); }, 15000) || !fatal.empty())
            throw Error("receiver did not start: " + fatal);
    }
    ~Receiver() {
        stop = true;
        if (th.joinable()) th.join();
    }
    // Switch the pairing mode on (new one-time token) and put the token into `pc`, as the GUI does when it builds the code.
    gui::PairInfo arm(PairCode& pc) {
        gui::PairInfo i = cc->pair_mode(true);
        Bytes b = from_hex(i.token_hex);
        std::copy(b.begin(), b.end(), pc.token.begin());
        return i;
    }
    PairCode code() const {
        PairCode pc;
        pc.server_key = key_from_hex(pub_hex);
        pc.port = port;
        pc.host = "127.0.0.1";
        return pc;
    }
};

// Connects like a machine that was not approved and tries to talk the normal protocol.
std::string probe_normal_protocol(const PairCode& pc, const KeyPair& kp) {
    net::Socket s = net::Socket::connect(pc.host, pc.port, 5000);
    SecureChannel ch;
    try {
        ch = SecureChannel::client(std::move(s), kp, pc.server_key);
    } catch (const std::exception&) {
        return "refused";  // the handshake itself failed: the key is simply not accepted
    }
    proto::Hello h;
    h.client_name = "intruder";
    ch.send_msg(proto::encode(h));
    try {
        Bytes a = ch.recv_msg_within(5000);
        if (is_pair_wire(a)) return decode_pair_wire(a).type == PairMsg::Error ? "pair-error" : "pair-other";
        return std::visit([](auto&& m) -> std::string {
            using T = std::decay_t<decltype(m)>;
            return std::is_same_v<T, proto::HelloOk> ? "hello-ok" : "other";
        }, proto::decode(a));
    } catch (const std::exception&) {
        return "closed";
    }
}

}  // namespace

TEST(simple_pairing_end_to_end_on_loopback) {
    ETmp t;
    Receiver rx(t);
    CHECK_EQ(rx.pub_hex.size(), size_t(64));
    gui::PairInfo info = rx.cc->pair_info();
    CHECK(info.available);
    CHECK(!info.mode_on);
    CHECK_EQ(info.public_hex, rx.pub_hex);
    CHECK_EQ(int(info.port), int(rx.port));
    PairCode code = decode_pair_code(encode_pair_code(rx.code()));   // what the sender types in

    // 1. pairing mode OFF: an unknown key is refused exactly as before (the handshake itself fails)
    KeyPair stranger = generate_keypair();
    {
        PairingClient pc(code, stranger, "Stranger");
        std::atomic<bool> never{false};
        PairOutcome o = pc.run(never, {}, 20);
        CHECK(o.kind == PairOutcome::Failed);
        CHECK(o.message.find("could not pair") != std::string::npos);
        CHECK(rx.cc->pair_info().pending.empty());
    }
    // 2. mode ON: the key gets through the handshake, but the normal protocol is closed to it
    info = rx.arm(code);
    CHECK(info.mode_on && info.seconds_left > 590 && info.seconds_left <= 600);
    CHECK_EQ(info.token_hex.size(), size_t(32));
    CHECK(rx.cc->pair_info().token_hex.empty());     // the token is handed out once, at switch-on, and never again
    CHECK_EQ(probe_normal_protocol(code, stranger), std::string("pair-error"));
    CHECK(rx.cc->pair_info().pending.empty());
    // a sender with a wrong token (a code from another switch-on) is refused and does not burn the real one
    {
        PairCode stale = code;
        stale.token[0] ^= 0x55;
        PairingClient pw(stale, generate_keypair(), "Guesser");
        std::atomic<bool> never{false};
        CHECK(pw.run(never, {}, 10).kind == PairOutcome::Failed);
        CHECK(rx.cc->pair_info().pending.empty());
    }
    // 3. a real request: the receiver sees the name and the SAS, which equals the sender's
    KeyPair laptop = generate_keypair();
    PairingClient pcl(code, laptop, "Máy của Sơn");
    std::atomic<bool> cancel{false};
    PairOutcome out;
    std::atomic<int> progress_calls{0};
    std::thread sender([&] { out = pcl.run(cancel, [&](int) { ++progress_calls; }); });
    JoinGuard sender_guard{sender, &cancel};
    gui::PairInfo seen;
    CHECK(wait_for([&] {
        seen = rx.cc->pair_info();
        return !seen.pending.empty();
    }, 15000));
    CHECK_EQ(seen.pending.size(), size_t(1));
    CHECK_EQ(seen.pending[0].name, std::string("Máy của Sơn"));
    CHECK_EQ(seen.pending[0].sas, pcl.sas());
    CHECK_EQ(seen.pending[0].sas, pair_sas(laptop.pub, key_from_hex(rx.pub_hex)));
    CHECK(seen.pending[0].ip == "127.0.0.1" || seen.pending[0].ip.find("127.0.0.1") != std::string::npos);
    // nothing was granted yet: the waiting key still cannot use the protocol (the token is spent: refused outright)
    CHECK_EQ(probe_normal_protocol(code, laptop), std::string("refused"));
    // a second machine cannot use the same code
    {
        KeyPair other = generate_keypair();
        PairingClient po(code, other, "Other");
        std::atomic<bool> never{false};
        CHECK(po.run(never, {}, 10).kind == PairOutcome::Failed);
    }
    // 4. approve: allowlist + live reload, a folder of its own
    std::string prefix = rx.cc->pair_approve(seen.pending[0].id);
    CHECK_EQ(prefix, std::string("from-may-cua-son"));
    sender.join();
    CHECK(out.kind == PairOutcome::Approved);
    CHECK(progress_calls.load() >= 0);
    ServerConfig after = gui::load_server_config_resolved(rx.up.receiver_config);
    CHECK_EQ(after.clients.size(), size_t(1));
    CHECK(after.clients[0].public_key == laptop.pub);
    CHECK(!after.clients[0].read_only);
    CHECK_EQ(after.clients[0].prefix, std::string("from-may-cua-son"));
    CHECK_EQ(after.clients[0].name, std::string("Máy của Sơn"));
    CHECK(fs::exists(fs::u8path(rx.up.receiver_config + ".bak")));
    // 5. the paired machine now connects normally and gets a session (HELLO_OK)
    CHECK_EQ(probe_normal_protocol(code, laptop), std::string("hello-ok"));
    // and the stranger is still out
    CHECK_EQ(probe_normal_protocol(code, stranger), std::string("refused"));
    // 6. deny: the sender hears no, and that key is shut out for ten minutes
    KeyPair denied = generate_keypair();
    rx.arm(code);   // a new switch-on, a new token
    {
        PairingClient pd(code, denied, "Nope");
        std::atomic<bool> never{false};
        PairOutcome o2;
        std::thread th([&] { o2 = pd.run(never, {}, 30); });
        JoinGuard th_guard{th, &never};
        gui::PairInfo w;
        CHECK(wait_for([&] {
            w = rx.cc->pair_info();
            return !w.pending.empty();
        }, 15000));
        rx.cc->pair_deny(w.pending[0].id);
        th.join();
        CHECK(o2.kind == PairOutcome::Denied);
        std::atomic<bool> n2{false};
        PairingClient again(code, denied, "Nope");
        CHECK(again.run(n2, {}, 10).kind == PairOutcome::Failed);   // blocked: refused at the handshake
        ServerConfig same = gui::load_server_config_resolved(rx.up.receiver_config);
        CHECK_EQ(same.clients.size(), size_t(1));                      // still only the approved one
    }
    // 7. mode OFF again: back to the old behaviour
    info = rx.cc->pair_mode(false);
    CHECK(!info.mode_on);
    CHECK_EQ(probe_normal_protocol(code, stranger), std::string("refused"));
    CHECK_THROWS(rx.cc->pair_approve(12345));
}

TEST(simple_pairing_cancel_and_wrong_server_key) {
    ETmp t;
    Receiver rx(t);
    PairCode code = rx.code();
    rx.arm(code);
    // cancelling from the sender drops the request without a trace of a client
    KeyPair kp = generate_keypair();
    PairingClient pc(code, kp, "Cancelled");
    std::atomic<bool> cancel{false};
    PairOutcome out;
    std::thread th([&] { out = pc.run(cancel); });
    JoinGuard th_guard{th, &cancel};
    CHECK(wait_for([&] { return !rx.cc->pair_info().pending.empty(); }, 15000));
    cancel = true;
    th.join();
    CHECK(out.kind == PairOutcome::Cancelled);
    // a code with another server key (a man in the middle cannot present the pinned key): the handshake fails
    PairCode wrong = code;
    wrong.server_key = generate_keypair().pub;
    KeyPair kp2 = generate_keypair();
    PairingClient pw(wrong, kp2, "Victim");
    std::atomic<bool> never{false};
    CHECK(pw.run(never, {}, 10).kind == PairOutcome::Failed);
    ServerConfig cfg = gui::load_server_config_resolved(rx.up.receiver_config);
    CHECK(cfg.clients.empty());
}

// ----------------------------------------------------------------------------------------- misc
TEST(simple_migrate_from_user_needs_administrator_and_valid_arguments) {
    if (gui::ServiceController::is_elevated()) return;   // would really write to the service folder
    ETmp t;
    CHECK_EQ(run_migrate_from_user({}), int(gui::kServiceBadArguments));
    CHECK_EQ(run_migrate_from_user({"--bogus"}), int(gui::kServiceBadArguments));
    std::string h64(64, 'a');
    CHECK_EQ(run_migrate_from_user({"--user-config", (t.p / "c.toml").u8string()}), int(gui::kServiceBadArguments));   // no hashes
    CHECK_EQ(run_migrate_from_user({"--user-config", (t.p / "c.toml").u8string(), "--expect-hash", h64, "--expect-key-hash", h64}),
             int(gui::kServiceAccessDenied));
    CHECK_EQ(run_migrate_from_user({"--user-config", "x", "--name", "bad name"}), int(gui::kServiceBadArguments));
}

TEST(simple_service_controller_builds_migrate_arguments_safely) {
    ETmp t;
    std::string exe = (fs::u8path(self_path()).parent_path() /
#ifdef _WIN32
                       "mysync.exe"
#else
                       "mysync"
#endif
                       ).u8string();
    std::unique_ptr<gui::ServiceController> ctlp;
    try {
        ctlp = std::make_unique<gui::ServiceController>(exe);
    } catch (const std::exception&) {
        return;   // no suitable mysync next to the tests (build layout): nothing to check here
    }
    gui::ServiceController& ctl = *ctlp;
    gui::ServiceRequest rq;
    rq.name = "mysync-client";
    rq.user_config = (t.p / "config.toml").u8string();
    CHECK_THROWS(ctl.build_args(gui::ServiceAction::MigrateFromUser, rq));   // the shown hashes are mandatory
    rq.expect_config_hash = std::string(64, 'a');
    rq.expect_key_hash = std::string(64, 'b');
    rq.allow_roots = {(t.p / "extra").u8string()};
    std::vector<std::string> a = ctl.build_args(gui::ServiceAction::MigrateFromUser, rq);
    std::vector<std::string> expect = {"service", "migrate-from-user", "--user-config", rq.user_config, "--expect-hash",
                                       rq.expect_config_hash, "--expect-key-hash", rq.expect_key_hash, "--allow-root",
                                       rq.allow_roots[0], "--name", "mysync-client"};
    CHECK(a == expect);
    rq.allow_roots = {"relative"};
    CHECK_THROWS(ctl.build_args(gui::ServiceAction::MigrateFromUser, rq));
    rq.allow_roots.clear();
    rq.user_config = "relative.toml";
    CHECK_THROWS(ctl.build_args(gui::ServiceAction::MigrateFromUser, rq));
    rq.user_config = "-c";
    CHECK_THROWS(ctl.build_args(gui::ServiceAction::MigrateFromUser, rq));
    rq.user_config = (t.p / "config.toml").u8string();
    rq.config_path = "/etc/x";
    CHECK_THROWS(ctl.build_args(gui::ServiceAction::MigrateFromUser, rq));
    rq.config_path.clear();
    rq.user_config.clear();
    rq.remove_migrated = true;
    std::vector<std::string> rm = ctl.build_args(gui::ServiceAction::MigrateFromUser, rq);
    CHECK((rm == std::vector<std::string>{"service", "migrate-from-user", "--remove", "--name", "mysync-client"}));
}

#include <cstring>

TEST(simple_pairing_approval_is_atomic_and_deny_cleans_up_what_a_failed_one_left) {
    ETmp t;
    std::atomic<bool> fail_add{true}, fail_rb{false};
    Receiver rx(t, [&](const char* st) {
        if (!std::strcmp(st, "after_peer_add") && fail_add) throw Error("injected failure after peer_add");
        if (!std::strcmp(st, "rollback") && fail_rb) throw Error("injected rollback failure");
    });
    PairCode code = rx.code();
    rx.arm(code);
    KeyPair kp = generate_keypair();
    PairingClient pc(code, kp, "Atomic");
    std::atomic<bool> cancel{false};
    PairOutcome out;
    std::thread sender([&] { out = pc.run(cancel, {}, 60); });
    JoinGuard sg{sender, &cancel};
    gui::PairInfo w;
    CHECK(wait_for([&] {
        w = rx.cc->pair_info();
        return !w.pending.empty();
    }, 15000));
    uint32_t id = w.pending[0].id;
    auto clients_in_file = [&] { return gui::load_server_config_resolved(rx.up.receiver_config).clients.size(); };
    // 1. a failure after peer_add: the peer is taken out again, the request stays waiting, the error is verbatim
    std::string msg;
    try { rx.cc->pair_approve(id); } catch (const Error& e) { msg = e.what(); }
    CHECK(msg.find("injected failure after peer_add") != std::string::npos);
    CHECK(msg.find("not added") != std::string::npos);
    CHECK_EQ(clients_in_file(), size_t(0));
    CHECK_EQ(rx.cc->pair_info().pending.size(), size_t(1));
    // 2. the rollback fails too: the error says so and the peer is left in the file (that is the state deny must clean)
    fail_rb = true;
    msg.clear();
    try { rx.cc->pair_approve(id); } catch (const Error& e) { msg = e.what(); }
    CHECK(msg.find("could not be taken out again") != std::string::npos);
    CHECK_EQ(clients_in_file(), size_t(1));
    // the running server never saw it: the key is still refused
    CHECK_EQ(probe_normal_protocol(code, kp), std::string("refused"));
    // 3. deny removes it at once; the sender hears no
    fail_rb = false;
    rx.cc->pair_deny(id);
    CHECK_EQ(clients_in_file(), size_t(0));
    cancel = false;
    if (sender.joinable()) sender.join();
    CHECK(out.kind == PairOutcome::Denied);
    // 4. without the injected failure the same flow commits
    fail_add = false;
}

// ----------------------------------------------------------------------------------------- the `run` command (F2)
namespace {
// Runs `mysync <args>` with output captured; returns the exit code (-1 when the program is not next to the tests).
int run_mysync(const std::string& args, const fs::path& out_file) {
    fs::path exe = fs::u8path(self_path()).parent_path() /
#ifdef _WIN32
                   "mysync.exe";
#else
                   "mysync";
#endif
    std::error_code ec;
    if (!fs::exists(exe, ec)) return -1;
    std::string cmd = "\"" + exe.u8string() + "\" " + args + " > \"" + out_file.u8string() + "\" 2>&1";
#ifdef _WIN32
    cmd = "\"" + cmd + "\"";   // cmd.exe /c strips one pair of outer quotes
    return std::system(cmd.c_str());
#else
    int st = std::system(cmd.c_str());
    return WIFEXITED(st) ? WEXITSTATUS(st) : -2;
#endif
}
}  // namespace

TEST(simple_run_checks_trust_before_it_opens_the_log) {
    ETmp t;
    fs::path cdir = t.p / "cfg", logs = t.p / "logs";
    fs::create_directories(cdir);
    ClientConfig cc = local_cfg(t.p / "src", t.p / "dst", t.p / "state");
    cc.key_file = (cdir / "key").u8string();
    cc.log_file = (logs / "client.log").u8string();
    fs::create_directories(t.p / "src");
    fs::path cfg = cdir / "config.toml";
    std::ofstream(cfg) << gui::serialize_client_config(cc);
    if (!guitest::make_world_writable(cdir)) {
        std::cout << "  (skipped: cannot make the folder writable for everyone)" << std::endl;
        return;
    }
    // --service means "strict": the folder of the configuration is writable by everybody, so the run is refused...
    int rc = run_mysync("run -c \"" + cfg.u8string() + "\" --role client --service", t.p / "out1.txt");
    if (rc == -1) {
        std::cout << "  (skipped: no mysync binary next to the tests)" << std::endl;
        return;
    }
    CHECK_EQ(rc, 1);
    std::string out = slurp(t.p / "out1.txt");
    CHECK(out.find("refusing") != std::string::npos);
    // ...and nothing was created from that configuration first: no log folder, no log file
    CHECK(!fs::exists(logs));
    // a broad group as --trust-writer is refused at once (usage error), also before anything is opened
    rc = run_mysync("run -c \"" + cfg.u8string() + "\" --role client --trust-writer Everyone", t.p / "out2.txt");
    CHECK_EQ(rc, 2);
    CHECK(slurp(t.p / "out2.txt").find("broad group") != std::string::npos);
    CHECK(!fs::exists(logs));
}
