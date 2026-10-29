// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Local control channel over a real named pipe (Windows) / unix socket (Linux).
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "mysync/gui/ipc.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {

struct IpcEnv {
    std::string name;
    std::string dir;  // Linux socket directory ("" on Windows)
    IpcEnv() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        name = "gui-test-" + to_hex(r, sizeof r);
#ifndef _WIN32
        dir = (fs::temp_directory_path() / ("mysync-ipc-" + to_hex(r, sizeof r))).string();
#endif
    }
    ~IpcEnv() {
        std::error_code ec;
        if (!dir.empty()) fs::remove_all(dir, ec);
    }
    IpcServerOptions opts() const {
        IpcServerOptions o;
        o.name = name;
        o.dir_override = dir;
        o.read_timeout_ms = 500;
        return o;
    }
};

ControlResponse default_handler(const ControlRequest& q, std::atomic<int>* calls = nullptr) {
    if (calls) ++*calls;
    ControlResponse r;
    r.op = q.op;
    r.token = q.token;
    if (q.op == ControlOp::GetStatus) {
        r.snapshot.role = Role::Server;
        r.snapshot.version = "t";
        r.snapshot.sessions = 5;
    }
    if (q.op == ControlOp::ReloadConfig) {
        r.reload.ok = true;
        r.reload.message = "reloaded";
    }
    if (q.op == ControlOp::GetRecentErrors) r.errors.push_back({1, "WARN", "something"});
    return r;
}

// A raw byte connection to the endpoint, to send malformed traffic.
class RawConn {
public:
    explicit RawConn(const IpcEnv& e) {
#ifdef _WIN32
        std::string path = control_endpoint_path(e.name);
        std::wstring wp(path.begin(), path.end());
        auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            h_ = CreateFileW(wp.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
            if (h_ != INVALID_HANDLE_VALUE) break;
            if (GetLastError() == ERROR_PIPE_BUSY && std::chrono::steady_clock::now() < until) {
                WaitNamedPipeW(wp.c_str(), 200);
                continue;
            }
            throw Error("raw connect failed: " + std::to_string(GetLastError()));
        }
#else
        std::string path = control_endpoint_path(e.name, e.dir);
        fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un a{};
        a.sun_family = AF_UNIX;
        std::strncpy(a.sun_path, path.c_str(), sizeof a.sun_path - 1);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
            ::close(fd_);
            fd_ = -1;
            throw Error("raw connect failed");
        }
#endif
    }
    ~RawConn() {
#ifdef _WIN32
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
#else
        if (fd_ >= 0) ::close(fd_);
#endif
    }
    void send(const void* d, size_t n) {
#ifdef _WIN32
        DWORD w = 0;
        WriteFile(h_, d, static_cast<DWORD>(n), &w, nullptr);
#else
        ssize_t w = ::send(fd_, d, n, MSG_NOSIGNAL);
        (void)w;
#endif
    }
    // Reads exactly n bytes with a ~3 s budget; returns the number actually read (short = closed / timeout).
    size_t recv(void* d, size_t n) {
        size_t got = 0;
        auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (got < n && std::chrono::steady_clock::now() < until) {
#ifdef _WIN32
            DWORD avail = 0, r = 0;
            if (!PeekNamedPipe(h_, nullptr, 0, nullptr, &avail, nullptr)) break;
            if (avail == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }
            if (!ReadFile(h_, static_cast<char*>(d) + got, std::min<DWORD>(avail, DWORD(n - got)), &r, nullptr)) break;
            got += r;
#else
            ssize_t r = ::recv(fd_, static_cast<char*>(d) + got, n - got, MSG_DONTWAIT);
            if (r > 0) {
                got += size_t(r);
            } else if (r == 0) {
                break;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
#endif
        }
        return got;
    }
    // Reads one framed response; false if the server closed without one.
    bool read_response(ControlResponse& out) {
        uint8_t hdr[4];
        if (recv(hdr, 4) != 4) return false;
        uint32_t n = parse_frame_length(hdr);
        Bytes p(n);
        if (recv(p.data(), n) != n) return false;
        out = decode_response(p);
        return true;
    }
    // True when the server end is closed (read returns EOF / error) within the budget.
    bool closed_by_peer() {
        uint8_t b;
        return recv(&b, 1) == 0;
    }

private:
#ifdef _WIN32
    HANDLE h_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
};

bool ping_retry(ControlClient& c, int seconds = 6) {
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < until) {
        if (c.ping()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
}

}  // namespace

TEST(gui_ipc_valid_client_roundtrip) {
    IpcEnv e;
    std::atomic<int> calls{0};
    IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q, &calls); });
    srv.start();
    ControlClient c(e.name, 3000, e.dir);
    CHECK(c.ping());
    StatusSnapshot s = c.get_status();
    CHECK(s.role == Role::Server);
    CHECK_EQ(s.sessions, 5u);
    ReloadResult rr = c.reload_config();
    CHECK(rr.ok);
    CHECK_EQ(rr.message, std::string("reloaded"));
    auto errs = c.recent_errors(10);
    CHECK_EQ(errs.size(), size_t(1));
    CHECK_EQ(errs[0].message, std::string("something"));
    CHECK_EQ(calls.load(), 4);
    srv.stop();
    CHECK(!c.ping());
}

TEST(gui_ipc_no_daemon_gives_a_readable_error) {
    IpcEnv e;
    ControlClient c(e.name, 800, e.dir);
    CHECK(!c.ping());
    bool threw = false;
    try {
        c.get_status();
    } catch (const Error& x) {
        threw = true;
        CHECK(std::string(x.what()).find("not running") != std::string::npos);
    }
    CHECK(threw);
}

TEST(gui_ipc_oversized_message_is_refused_before_reading_it) {
    IpcEnv e;
    std::atomic<int> calls{0};
    IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q, &calls); });
    srv.start();
    {
        RawConn rc(e);
        uint8_t hdr[4] = {0x00, 0x10, 0x00, 0x00};  // 1 MiB announced, nothing follows
        rc.send(hdr, 4);
        ControlResponse r;
        CHECK(rc.read_response(r));
        CHECK(r.status == ControlStatus::BadRequest);
        CHECK(rc.closed_by_peer());
    }
    {
        RawConn rc(e);
        uint8_t hdr[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        rc.send(hdr, 4);
        ControlResponse r;
        CHECK(rc.read_response(r));
        CHECK(r.status == ControlStatus::BadRequest);
    }
    {
        RawConn rc(e);
        uint8_t hdr[4] = {0, 0, 0, 0};  // empty message
        rc.send(hdr, 4);
        ControlResponse r;
        CHECK(rc.read_response(r));
        CHECK(r.status == ControlStatus::BadRequest);
    }
    CHECK_EQ(calls.load(), 0);
    ControlClient c(e.name, 3000, e.dir);
    CHECK(ping_retry(c));  // the server is still healthy
}

TEST(gui_ipc_garbage_payload_gets_bad_request) {
    IpcEnv e;
    std::atomic<int> calls{0};
    IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q, &calls); });
    srv.start();
    RawConn rc(e);
    uint8_t msg[4 + 6] = {0, 0, 0, 6, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2};
    rc.send(msg, sizeof msg);
    ControlResponse r;
    CHECK(rc.read_response(r));
    CHECK(r.status == ControlStatus::BadRequest);
    CHECK_EQ(calls.load(), 0);
}

TEST(gui_ipc_handler_exception_becomes_failed_status) {
    IpcEnv e;
    IpcServer srv(e.opts(), [&](const ControlRequest& q) -> ControlResponse {
        if (q.op == ControlOp::ReloadConfig) throw Error("boom: bad config at line 7");
        return default_handler(q);
    });
    srv.start();
    ControlClient c(e.name, 3000, e.dir);
    ControlRequest q;
    q.op = ControlOp::ReloadConfig;
    q.token = 9;
    ControlResponse r = c.call(q);
    CHECK(r.status == ControlStatus::Failed);
    CHECK(r.error.find("line 7") != std::string::npos);
    ReloadResult rr = c.reload_config();  // the convenience wrapper turns it into a failed result with the text
    CHECK(!rr.ok);
    CHECK(rr.message.find("boom") != std::string::npos);
    CHECK(c.ping());
}

TEST(gui_ipc_stalled_and_half_closed_peers_are_dropped) {
    IpcEnv e;
    IpcServerOptions o = e.opts();
    o.max_connections = 1;  // a stalled peer would block everybody if it were never dropped
    o.read_timeout_ms = 300;
    IpcServer srv(o, [&](const ControlRequest& q) { return default_handler(q); });
    srv.start();
    {
        RawConn rc(e);
        uint8_t half[2] = {0, 0};
        rc.send(half, 2);  // half a header, then silence
        ControlClient c(e.name, 5000, e.dir);
        CHECK(ping_retry(c, 8));  // only possible once the stalled peer was dropped
        CHECK(rc.closed_by_peer());
    }
    {
        RawConn rc(e);
        uint8_t part[4 + 3] = {0, 0, 0, 20, 1, 2, 3};  // announces 20 bytes, sends 3, then closes
        rc.send(part, sizeof part);
    }
    ControlClient c(e.name, 5000, e.dir);
    CHECK(ping_retry(c, 8));
}

TEST(gui_ipc_many_connections_at_once) {
    IpcEnv e;
    IpcServerOptions o = e.opts();
    o.max_connections = 3;
    std::atomic<int> calls{0};
    IpcServer srv(o, [&](const ControlRequest& q) { return default_handler(q, &calls); });
    srv.start();
    std::atomic<int> okc{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < 8; ++t)
        ts.emplace_back([&, t] {
            ControlClient c(e.name, 5000, e.dir);
            for (int i = 0; i < 15; ++i) {
                bool ok = false;
                for (int attempt = 0; attempt < 400 && !ok; ++attempt) {
                    try {
                        ControlRequest q;
                        q.op = ControlOp::GetStatus;
                        q.token = uint64_t(t) * 1000 + uint64_t(i);
                        ControlResponse r = c.call(q);
                        ok = r.status == ControlStatus::Ok && r.token == q.token && r.snapshot.sessions == 5;
                    } catch (const Error&) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    }
                }
                if (ok) ++okc;
            }
        });
    for (auto& t : ts) t.join();
    CHECK_EQ(okc.load(), 8 * 15);
    CHECK(calls.load() >= 8 * 15);
}

TEST(gui_ipc_second_server_cannot_take_the_name) {
    IpcEnv e;
    IpcServer a(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
    a.start();
    IpcServer b(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
    CHECK_THROWS(b.start());
    ControlClient c(e.name, 3000, e.dir);
    CHECK(c.ping());  // the first one is untouched
}

TEST(gui_ipc_stop_is_prompt_and_restartable) {
    IpcEnv e;
    {
        IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
        srv.start();
        RawConn idle(e);  // a connected, silent peer must not delay stop()
        auto t0 = std::chrono::steady_clock::now();
        srv.stop();
        double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        CHECK(secs < 3.0);
    }
    IpcServer again(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
    again.start();
    ControlClient c(e.name, 3000, e.dir);
    CHECK(c.ping());
}

TEST(gui_ipc_rejects_bad_names_and_allow_entries) {
    IpcEnv e;
    IpcServerOptions o = e.opts();
    o.name = "bad name";
    CHECK_THROWS(IpcServer(o, [&](const ControlRequest& q) { return default_handler(q); }));
    CHECK_THROWS(ControlClient("../x"));
#ifdef _WIN32
    o = e.opts();
    o.allow = {"S-1-1-0"};  // Everyone
    IpcServer s1(o, [&](const ControlRequest& q) { return default_handler(q); });
    CHECK_THROWS(s1.start());
    o.allow = {"Everyone"};
    IpcServer s2(o, [&](const ControlRequest& q) { return default_handler(q); });
    CHECK_THROWS(s2.start());
    o.allow = {"S-1-5-not-a-sid"};
    IpcServer s3(o, [&](const ControlRequest& q) { return default_handler(q); });
    CHECK_THROWS(s3.start());
    o.allow = {"S-1-5-21-111-222-333-1234"};  // a well-formed SID nobody owns is accepted
    IpcServer s4(o, [&](const ControlRequest& q) { return default_handler(q); });
    s4.start();
    ControlClient c(e.name, 3000);
    CHECK(c.ping());
#endif
}

#ifdef _WIN32
TEST(gui_ipc_windows_pipe_dacl_has_no_broad_principals) {
    IpcEnv e;
    IpcServerOptions o = e.opts();
    o.allow = {"S-1-5-21-111-222-333-1234"};
    IpcServer srv(o, [&](const ControlRequest& q) { return default_handler(q); });
    srv.start();
    std::string path = srv.endpoint();
    std::wstring wp(path.begin(), path.end());
    HANDLE h = CreateFileW(wp.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, nullptr, OPEN_EXISTING,
                           SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    CHECK(h != INVALID_HANDLE_VALUE);
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    DWORD rc = GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd);
    CHECK_EQ(rc, DWORD(ERROR_SUCCESS));
    LPWSTR text = nullptr;
    CHECK(ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, nullptr));
    std::wstring w(text);
    std::string s(w.begin(), w.end());
    LocalFree(text);
    LocalFree(sd);
    CloseHandle(h);
    CHECK(s.rfind("D:P", 0) == 0);  // protected DACL: nothing inherited from the parent
    for (const char* bad : {";;;WD)", ";;;BU)", ";;;AU)", ";;;AN)", ";;;IU)"}) CHECK(s.find(bad) == std::string::npos);
    CHECK(s.find(";;;SY)") != std::string::npos);
    CHECK(s.find(";;;BA)") != std::string::npos);
    CHECK(s.find("S-1-5-21-111-222-333-1234") != std::string::npos);
}
#else
TEST(gui_ipc_linux_modes_and_symlink_refusal) {
    IpcEnv e;
    IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
    srv.start();
    struct stat st{};
    CHECK_EQ(::stat(srv.endpoint().c_str(), &st), 0);
    CHECK(S_ISSOCK(st.st_mode));
    CHECK_EQ(int(st.st_mode & 07777), 0600);
    CHECK_EQ(::stat(e.dir.c_str(), &st), 0);
    CHECK_EQ(int(st.st_mode & 07777), 0750);
    srv.stop();
    // the socket file is removed when the server stops
    CHECK(::access(srv.endpoint().c_str(), F_OK) != 0);

    // a symbolic link as the socket directory is refused
    std::string real = e.dir + "-real", link = e.dir + "-link";
    fs::create_directories(real);
    CHECK_EQ(::symlink(real.c_str(), link.c_str()), 0);
    IpcServerOptions o = e.opts();
    o.dir_override = link;
    IpcServer s2(o, [&](const ControlRequest& q) { return default_handler(q); });
    CHECK_THROWS(s2.start());
    // a symbolic link in place of the socket file is refused too
    fs::create_directories(e.dir);
    std::string sock = e.dir + "/" + e.name + ".sock";
    CHECK_EQ(::symlink("/etc/passwd", sock.c_str()), 0);
    IpcServer s3(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
    CHECK_THROWS(s3.start());
    ::unlink(sock.c_str());
    ::unlink(link.c_str());
    fs::remove_all(real);
}

TEST(gui_ipc_linux_unprivileged_user_is_refused) {
    if (::geteuid() != 0) return;  // needs root to switch identity
    IpcEnv e;
    IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
    srv.start();
    // the directory is 0750 root: a process with another uid cannot even traverse it
    pid_t pid = ::fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (::setgid(65534) != 0 || ::setuid(65534) != 0) _exit(3);
        ControlClient c(e.name, 800, e.dir);
        _exit(c.ping() ? 1 : 0);  // must NOT reach the daemon
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 0);
    ControlClient c(e.name, 3000, e.dir);
    CHECK(c.ping());  // root still can
}
#endif

TEST(gui_ipc_connection_limits_idle_lifetime_and_reload_quota) {
    {   // a silent peer is dropped after the idle timeout and frees the only slot
        IpcEnv e;
        IpcServerOptions o = e.opts();
        o.max_connections = 1;
        o.idle_timeout_ms = 300;
        IpcServer srv(o, [&](const ControlRequest& q) { return default_handler(q); });
        srv.start();
        RawConn silent(e);
        ControlClient c(e.name, 5000, e.dir);
        CHECK(ping_retry(c, 8));
        CHECK(silent.closed_by_peer());
    }
    {   // a connection that keeps talking is still closed when its lifetime is over
        IpcEnv e;
        IpcServerOptions o = e.opts();
        o.max_lifetime_ms = 500;
        IpcServer srv(o, [&](const ControlRequest& q) { return default_handler(q); });
        srv.start();
        RawConn rc(e);
        ControlRequest q;
        q.op = ControlOp::Ping;
        Bytes f = frame_message(encode_request(q));
        bool closed = false;
        auto until = std::chrono::steady_clock::now() + std::chrono::seconds(4);
        while (std::chrono::steady_clock::now() < until && !closed) {
            rc.send(f.data(), f.size());
            ControlResponse r;
            if (!rc.read_response(r)) closed = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        CHECK(closed);
    }
    {   // at most three reloads per connection
        IpcEnv e;
        IpcServer srv(e.opts(), [&](const ControlRequest& q) { return default_handler(q); });
        srv.start();
        RawConn rc(e);
        ControlRequest q;
        q.op = ControlOp::ReloadConfig;
        for (int i = 0; i < 4; ++i) {
            q.token = uint64_t(i + 1);
            Bytes f = frame_message(encode_request(q));
            rc.send(f.data(), f.size());
            ControlResponse r;
            CHECK(rc.read_response(r));
            CHECK(r.status == (i < 3 ? ControlStatus::Ok : ControlStatus::Denied));
        }
    }
}
