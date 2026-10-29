// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/ipc.h"
#include "mysync/gui/trust.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "mysync/util.h"

namespace mysync::gui {

// ---------------------------------------------------------------------------------------------- names
bool valid_control_name(const std::string& n) {
    if (n.empty() || n.size() > 64 || n[0] == '-' || n[0] == '.') return false;
    for (unsigned char c : n)
        if (!(std::isalnum(c) || c == '_' || c == '.' || c == '-')) return false;
    return true;
}

std::string effective_control_name(const std::string& configured, const std::string& service, bool is_server) {
    if (!configured.empty()) return configured;
    if (!service.empty()) return service;
    return is_server ? "mysync-server" : "mysync-client";
}

namespace detail {

bool ipc_peer_allowed(uint32_t peer_uid, uint32_t self_uid, const std::vector<uint32_t>& peer_gids, bool has_group,
                      uint32_t group_gid) {
    if (peer_uid == 0 || peer_uid == self_uid) return true;
    if (has_group)
        for (uint32_t g : peer_gids)
            if (g == group_gid) return true;
    return false;
}

std::string ipc_pipe_sddl(const std::vector<std::string>& extra_sids, const std::string& owner_sid) {
    static const char* const kForbidden[] = {
        "S-1-1-0",       // Everyone
        "S-1-5-11",      // Authenticated Users
        "S-1-5-32-545",  // Users
        "S-1-5-32-546",  // Guests
        "S-1-5-7",       // Anonymous
        "S-1-5-2",       // Network
        "S-1-5-4",       // Interactive
        "S-1-2-0",       // Local
        "S-1-2-1",       // Console logon
        "S-1-5-14",      // Remote interactive logon
        "S-1-5-15",      // This organization
    };
    // Deny network logons first (canonical order), then grant. SY and BA get full control, the others read/write.
    std::string s = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)";
    std::vector<std::string> seen;
    // Allowed principals get FILE_GENERIC_READ|WRITE minus FILE_APPEND_DATA (= CREATE_PIPE_INSTANCE): they can talk
    // to the pipe but never create a competing instance of it. The daemon's own account keeps the full right
    // because it creates the further instances.
    auto add = [&](const std::string& sid, const char* rights) {
        if (sid.empty()) return;
        for (const char* f : kForbidden)
            if (sid == f) throw Error("control allow: refusing broad principal " + sid);
        if (sid == "S-1-5-18" || sid == "S-1-5-32-544") return;  // SYSTEM / Administrators already present
        if (std::find(seen.begin(), seen.end(), sid) != seen.end()) return;
        seen.push_back(sid);
        s += std::string("(A;;") + rights + ";;;" + sid + ")";
    };
    add(owner_sid, "GRGW");
    for (const auto& x : extra_sids) add(x, "0x12019b");
    return s;
}

}  // namespace detail

// ---------------------------------------------------------------------------------------------- channel abstraction
namespace {

struct IpcTimeout : Error {
    using Error::Error;
};

class Channel {
public:
    virtual ~Channel() = default;
    // Reads 1..n bytes; returns 0 at end of stream. Throws Error (IpcTimeout on timeout).
    virtual size_t read_some(void* buf, size_t n, int timeout_ms) = 0;
    virtual void write_all(const void* buf, size_t n, int timeout_ms) = 0;
};

using SteadyClock = std::chrono::steady_clock;

int ms_left(SteadyClock::time_point deadline) {
    auto d = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - SteadyClock::now()).count();
    return d < 0 ? 0 : static_cast<int>(std::min<long long>(d, 1 << 30));
}

// True = got n bytes, false = clean end of stream before the first byte. Throws on truncation / error / timeout.
bool read_exact(Channel& ch, void* buf, size_t n, int timeout_ms) {
    auto deadline = SteadyClock::now() + std::chrono::milliseconds(timeout_ms);
    size_t got = 0;
    auto* p = static_cast<uint8_t*>(buf);
    while (got < n) {
        size_t r = ch.read_some(p + got, n - got, ms_left(deadline));
        if (r == 0) {
            if (got == 0) return false;
            throw Error("control channel: connection closed in the middle of a message");
        }
        got += r;
    }
    return true;
}

void send_response(Channel& ch, const ControlResponse& resp, int timeout_ms) {
    Bytes payload;
    try {
        payload = encode_response(resp);
    } catch (const Error& e) {  // too big to fit one frame: the peer still gets an answer
        ControlResponse f;
        f.op = resp.op;
        f.token = resp.token;
        f.status = ControlStatus::Failed;
        f.error = std::string("the response could not be built: ") + e.what();
        payload = encode_response(f);
    }
    Bytes f = frame_message(payload);
    ch.write_all(f.data(), f.size(), timeout_ms);
}

// Serves requests on one connection until the peer leaves, stalls or the server stops.
struct ServeLimits {
    int read_ms = 5000;        // once a message has started, the rest must arrive within this
    int idle_ms = 60000;       // waiting for the next message
    int lifetime_ms = 600000;  // whole connection
};
constexpr int kMaxRequestsPerConnection = 1000;
constexpr int kMaxReloadsPerConnection = 3;

void serve_channel(Channel& ch, const ControlHandler& handler, const ServeLimits& lim, const std::atomic<bool>& stop) {
    const int timeout_ms = lim.read_ms;
    const auto life_end = SteadyClock::now() + std::chrono::milliseconds(lim.lifetime_ms);
    int requests = 0, reloads = 0;
    while (!stop.load()) {
        if (ms_left(life_end) <= 0 || ++requests > kMaxRequestsPerConnection) return;
        uint8_t hdr[4];
        if (ch.read_some(hdr, 1, std::min(lim.idle_ms, ms_left(life_end))) == 0) return;
        if (!read_exact(ch, hdr + 1, 3, timeout_ms)) throw Error("control channel: truncated message");
        uint32_t n = 0;
        try {
            n = parse_frame_length(hdr);
        } catch (const Error& e) {  // too large (or empty): refused before reading or allocating anything
            ControlResponse r;
            r.status = ControlStatus::BadRequest;
            r.error = std::string(e.what()) + " (limit " + std::to_string(kMaxMessageBytes) + " bytes)";
            try {
                send_response(ch, r, 1000);
                // Let the peer read the answer before the connection is torn down (a pipe disconnect would discard it).
                uint8_t b;
                ch.read_some(&b, 1, 1000);
            } catch (...) {
            }
            return;
        }
        Bytes payload(n);
        if (!read_exact(ch, payload.data(), n, timeout_ms)) throw Error("control channel: truncated message");
        ControlResponse resp;
        ControlRequest req;
        bool decoded = false;
        try {
            req = decode_request(payload);
            decoded = true;
            if (req.op == ControlOp::ReloadConfig && ++reloads > kMaxReloadsPerConnection) {
                resp.op = req.op;
                resp.token = req.token;
                resp.status = ControlStatus::Denied;
                resp.error = "too many reload requests on one connection; open a new one";
                send_response(ch, resp, timeout_ms);
                continue;
            }
            resp = handler(req);
            resp.op = req.op;
            resp.token = req.token;
        } catch (const std::exception& e) {
            resp = ControlResponse();
            if (decoded) {
                resp.op = req.op;
                resp.token = req.token;
                resp.status = ControlStatus::Failed;
            } else {
                resp.status = ControlStatus::BadRequest;
            }
            resp.error = e.what();
        }
        send_response(ch, resp, timeout_ms);
    }
}

ControlResponse client_exchange(Channel& ch, const ControlRequest& req, int timeout_ms) {
    Bytes f = frame_message(encode_request(req));
    ch.write_all(f.data(), f.size(), timeout_ms);
    uint8_t hdr[4];
    if (!read_exact(ch, hdr, 4, timeout_ms)) throw Error("the daemon closed the connection without answering");
    uint32_t n = parse_frame_length(hdr);
    Bytes payload(n);
    if (!read_exact(ch, payload.data(), n, timeout_ms)) throw Error("the daemon closed the connection");
    ControlResponse r = decode_response(payload);
    // Only the daemon's "I could not even decode that" answer may carry another token (it cannot know it).
    bool anonymous_refusal = r.status == ControlStatus::BadRequest && r.token == 0;
    if (r.token != req.token && !anonymous_refusal) throw Error("control reply does not match the request");
    if (r.status == ControlStatus::Ok && r.op != req.op) throw Error("control reply is for another operation");
    return r;
}

}  // namespace

// ============================================================================================= Windows
#ifdef _WIN32
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string win_msg(DWORD code) {
    char buf[300] = {0};
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0, buf,
                             sizeof buf - 1, nullptr);
    std::string t(buf, n);
    while (!t.empty() && (t.back() == '\r' || t.back() == '\n' || t.back() == ' ' || t.back() == '.')) t.pop_back();
    return "error " + std::to_string(code) + (t.empty() ? "" : " (" + t + ")");
}

struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE x) : h(x) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& o) noexcept {
        if (this != &o) {
            reset();
            h = o.h;
            o.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ~Handle() { reset(); }
    void reset() {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
    bool ok() const { return h != INVALID_HANDLE_VALUE && h != nullptr; }
};

// Overlapped pipe I/O with a timeout and an optional stop event.
class PipeChannel : public Channel {
public:
    PipeChannel(HANDLE pipe, HANDLE stop_event) : pipe_(pipe), stop_(stop_event) {
        ev_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ev_) throw Error("cannot create an event: " + win_msg(GetLastError()));
    }
    ~PipeChannel() override {
        if (ev_) CloseHandle(ev_);
    }

    size_t read_some(void* buf, size_t n, int timeout_ms) override {
        DWORD want = static_cast<DWORD>(std::min<size_t>(n, 1u << 20)), got = 0;
        OVERLAPPED ov{};
        ov.hEvent = ev_;
        ResetEvent(ev_);
        if (!ReadFile(pipe_, buf, want, nullptr, &ov)) {
            DWORD e = GetLastError();
            if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED) return 0;
            if (e != ERROR_IO_PENDING) throw Error("control pipe read failed: " + win_msg(e));
            wait_or_cancel(ov, timeout_ms, "read");
        }
        if (!GetOverlappedResult(pipe_, &ov, &got, FALSE)) {
            DWORD e = GetLastError();
            if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED) return 0;
            if (e == ERROR_OPERATION_ABORTED) throw Error("control pipe: stopped");
            throw Error("control pipe read failed: " + win_msg(e));
        }
        return got;
    }

    void write_all(const void* buf, size_t n, int timeout_ms) override {
        auto deadline = SteadyClock::now() + std::chrono::milliseconds(timeout_ms);
        const auto* p = static_cast<const uint8_t*>(buf);
        size_t done = 0;
        while (done < n) {
            DWORD want = static_cast<DWORD>(std::min<size_t>(n - done, 1u << 20)), got = 0;
            OVERLAPPED ov{};
            ov.hEvent = ev_;
            ResetEvent(ev_);
            if (!WriteFile(pipe_, p + done, want, nullptr, &ov)) {
                DWORD e = GetLastError();
                if (e != ERROR_IO_PENDING) throw Error("control pipe write failed: " + win_msg(e));
                wait_or_cancel(ov, ms_left(deadline), "write");
            }
            if (!GetOverlappedResult(pipe_, &ov, &got, FALSE))
                throw Error("control pipe write failed: " + win_msg(GetLastError()));
            done += got;
        }
    }

    // Waits for the overlapped operation; on timeout / stop cancels it and throws.
    void wait_or_cancel(OVERLAPPED& ov, int timeout_ms, const char* what) {
        HANDLE hs[2] = {ev_, stop_};
        DWORD w = WaitForMultipleObjects(stop_ ? 2 : 1, hs, FALSE, static_cast<DWORD>(timeout_ms));
        if (w == WAIT_OBJECT_0) return;
        CancelIoEx(pipe_, &ov);
        DWORD tmp = 0;
        GetOverlappedResult(pipe_, &ov, &tmp, TRUE);
        if (w == WAIT_TIMEOUT) throw IpcTimeout(std::string("control pipe ") + what + " timed out");
        throw Error("control pipe: stopped");
    }

private:
    HANDLE pipe_;
    HANDLE stop_;
    HANDLE ev_ = nullptr;
};

std::string current_user_sid() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return {};
    Handle t(tok);
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    if (len == 0) return {};
    std::vector<uint8_t> buf(len);
    if (!GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) return {};
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s)) return {};
    std::string r = narrow(s);
    LocalFree(s);
    return r;
}

// "S-1-5-21-..." is checked and normalised, anything else is looked up as an account name.
std::string resolve_allow_entry(const std::string& entry) {
    if (entry.empty()) throw Error("empty control allow entry");
    PSID sid = nullptr;
    if (entry.size() > 4 && (entry[0] == 'S' || entry[0] == 's') && entry[1] == '-') {
        if (!ConvertStringSidToSidW(widen(entry).c_str(), &sid))
            throw Error("control allow: '" + entry + "' is not a valid SID");
        LPWSTR s = nullptr;
        std::string out;
        if (ConvertSidToStringSidW(sid, &s)) {
            out = narrow(s);
            LocalFree(s);
        }
        LocalFree(sid);
        if (out.empty()) throw Error("control allow: cannot normalise SID '" + entry + "'");
        return out;
    }
    std::wstring wn = widen(entry);
    DWORD sl = 0, dl = 0;
    SID_NAME_USE use;
    LookupAccountNameW(nullptr, wn.c_str(), nullptr, &sl, nullptr, &dl, &use);
    if (sl == 0) throw Error("control allow: cannot resolve account '" + entry + "': " + win_msg(GetLastError()));
    std::vector<uint8_t> sb(sl);
    std::wstring dom(dl, L'\0');
    if (!LookupAccountNameW(nullptr, wn.c_str(), sb.data(), &sl, dom.data(), &dl, &use))
        throw Error("control allow: cannot resolve account '" + entry + "': " + win_msg(GetLastError()));
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sb.data(), &s)) throw Error("control allow: cannot convert the SID of '" + entry + "'");
    std::string out = narrow(s);
    LocalFree(s);
    return out;
}

// Who runs the process that owns the pipe? Refuse to talk to anybody but the expected kinds of account.
bool account_expected(const std::string& sid, const std::vector<std::string>& extra) {
    if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || sid == "S-1-5-32-544" || sid == current_user_sid())
        return true;
    for (const auto& x : extra) {
        try {
            if (resolve_allow_entry(x) == sid) return true;
        } catch (const std::exception&) {
        }
    }
    return false;
}

// When the process cannot be inspected (a service of another account, a protected process) the decision falls back to
// the owner recorded in the security descriptor of the pipe itself, which only the creating account can have set.
// Failing to verify never means "trust".
void verify_by_pipe_owner(HANDLE pipe, const std::vector<std::string>& extra, const std::string& name) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD rc = GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd);
    if (rc != ERROR_SUCCESS || !owner)
        throw Error("cannot verify who runs the control pipe of '" + name + "' (" + win_msg(rc) + "): not talking to it");
    LPWSTR s = nullptr;
    std::string sid;
    if (ConvertSidToStringSidW(owner, &s)) {
        sid = narrow(s);
        LocalFree(s);
    }
    LocalFree(sd);
    if (!account_expected(sid, extra))
        throw Error("the control pipe of '" + name + "' is owned by an unexpected account (" + sid +
                    "): not talking to it. For a service that runs under its own account, trust that account explicitly.");
}

void verify_server_process(HANDLE pipe, const std::vector<std::string>& extra, const std::string& name) {
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid)) throw Error("cannot identify the process behind the control pipe");
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!ph) return verify_by_pipe_owner(pipe, extra, name);
    Handle hp(ph);
    HANDLE tok = nullptr;
    if (!OpenProcessToken(ph, TOKEN_QUERY, &tok)) return verify_by_pipe_owner(pipe, extra, name);
    Handle ht(tok);
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::vector<uint8_t> buf(len ? len : 1);
    if (!len || !GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) return verify_by_pipe_owner(pipe, extra, name);
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s))
        return verify_by_pipe_owner(pipe, extra, name);
    std::string sid = narrow(s);
    LocalFree(s);
    if (account_expected(sid, extra)) return;
    // an elevated administrator running the daemon in the foreground
    DWORD gl = 0;
    GetTokenInformation(tok, TokenGroups, nullptr, 0, &gl);
    if (gl) {
        std::vector<uint8_t> gb(gl);
        if (GetTokenInformation(tok, TokenGroups, gb.data(), gl, &gl)) {
            auto* g = reinterpret_cast<TOKEN_GROUPS*>(gb.data());
            for (DWORD i = 0; i < g->GroupCount; ++i) {
                LPWSTR gs = nullptr;
                if (!ConvertSidToStringSidW(g->Groups[i].Sid, &gs)) continue;
                std::string t = narrow(gs);
                LocalFree(gs);
                if (t == "S-1-5-32-544" && (g->Groups[i].Attributes & SE_GROUP_ENABLED)) return;
            }
        }
    }
    throw Error("the control pipe of '" + name + "' is served by an unexpected account (" + sid +
                "): not talking to it. If this is the account of the MySync service, trust it explicitly.");
}

}  // namespace

std::string detail::resolve_principal_sid(const std::string& entry) { return resolve_allow_entry(entry); }

std::string control_endpoint_path(const std::string& name, const std::string&) {
    if (!valid_control_name(name)) throw Error("invalid control name (allowed: A-Z a-z 0-9 _ . -)");
    return "\\\\.\\pipe\\mysync-" + name;
}

std::vector<std::string> control_endpoint_candidates(const std::string& name, const std::string& dir) {
    return {control_endpoint_path(name, dir)};
}

struct IpcServer::Impl {
    IpcServerOptions opts;
    ControlHandler handler;
    std::string path;
    std::string sddl;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> rejected{0};
    HANDLE stop_event = nullptr;
    std::vector<std::thread> workers;
    bool started = false;

    HANDLE create_instance(bool first) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof sa;
        sa.bInheritHandle = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(widen(sddl).c_str(), SDDL_REVISION_1,
                                                                  &sa.lpSecurityDescriptor, nullptr))
            throw Error("cannot build the pipe security descriptor: " + win_msg(GetLastError()));
        DWORD flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
        DWORD mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        HANDLE h = CreateNamedPipeW(widen(path).c_str(), flags, mode, static_cast<DWORD>(opts.max_connections),
                                    128 * 1024, 128 * 1024, 0, &sa);
        DWORD err = GetLastError();
        LocalFree(sa.lpSecurityDescriptor);
        if (h == INVALID_HANDLE_VALUE) {
            if (first && (err == ERROR_ACCESS_DENIED || err == ERROR_PIPE_BUSY || err == ERROR_ALREADY_EXISTS))
                throw Error("the control pipe " + path + " already exists (another MySync daemon with this name is running, "
                            "or another program holds the name): " + win_msg(err));
            throw Error("cannot create the control pipe " + path + ": " + win_msg(err));
        }
        return h;
    }

    void worker(HANDLE pipe) {
        Handle hp(pipe);
        while (!stop.load()) {
            if (!hp.ok()) {
                try {
                    hp.h = create_instance(false);
                } catch (const std::exception& e) {
                    log_debug(std::string("control pipe: ") + e.what());
                    WaitForSingleObject(stop_event, 500);
                    continue;
                }
            }
            HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ev) {
                WaitForSingleObject(stop_event, 500);
                continue;
            }
            Handle hev(ev);
            OVERLAPPED ov{};
            ov.hEvent = ev;
            bool connected = false;
            if (!ConnectNamedPipe(hp.h, &ov)) {
                DWORD e = GetLastError();
                if (e == ERROR_PIPE_CONNECTED) {
                    connected = true;
                } else if (e == ERROR_IO_PENDING) {
                    HANDLE hs[2] = {ev, stop_event};
                    DWORD w = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
                    if (w == WAIT_OBJECT_0) {
                        DWORD tmp = 0;
                        connected = GetOverlappedResult(hp.h, &ov, &tmp, FALSE) != 0;
                    } else {
                        CancelIoEx(hp.h, &ov);
                        DWORD tmp = 0;
                        GetOverlappedResult(hp.h, &ov, &tmp, TRUE);
                        break;
                    }
                } else {
                    hp.reset();  // broken instance: build a new one
                    continue;
                }
            } else {
                connected = true;
            }
            if (connected && !stop.load()) {
                try {
                    PipeChannel ch(hp.h, stop_event);
                    ServeLimits lim;
                    lim.read_ms = opts.read_timeout_ms;
                    lim.idle_ms = opts.idle_timeout_ms;
                    lim.lifetime_ms = opts.max_lifetime_ms;
                    serve_channel(ch, handler, lim, stop);
                } catch (const std::exception& e) {
                    log_debug(std::string("control connection ended: ") + e.what());
                }
            }
            DisconnectNamedPipe(hp.h);
        }
    }
};

IpcServer::IpcServer(IpcServerOptions opts, ControlHandler handler) : p_(new Impl) {
    p_->opts = std::move(opts);
    p_->handler = std::move(handler);
    if (p_->opts.max_connections < 1) p_->opts.max_connections = 1;
    if (p_->opts.max_connections > 32) p_->opts.max_connections = 32;
    p_->path = control_endpoint_path(p_->opts.name);
}

IpcServer::~IpcServer() { stop(); }

const std::string& IpcServer::endpoint() const { return p_->path; }
uint64_t IpcServer::rejected_peers() const { return p_->rejected.load(); }

void IpcServer::start() {
    Impl& s = *p_;
    if (s.started) return;
    std::vector<std::string> sids;
    for (const auto& a : s.opts.allow) sids.push_back(resolve_allow_entry(a));
    s.sddl = detail::ipc_pipe_sddl(sids, current_user_sid());
    s.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!s.stop_event) throw Error("cannot create an event");
    HANDLE first = INVALID_HANDLE_VALUE;
    try {
        first = s.create_instance(true);  // FILE_FLAG_FIRST_PIPE_INSTANCE: fails if the name is taken
    } catch (...) {
        CloseHandle(s.stop_event);
        s.stop_event = nullptr;
        throw;
    }
    s.started = true;
    s.stop = false;
    for (size_t i = 0; i < s.opts.max_connections; ++i) {
        HANDLE h = i == 0 ? first : INVALID_HANDLE_VALUE;
        s.workers.emplace_back([&s, h] { s.worker(h); });
    }
}

void IpcServer::stop() {
    Impl& s = *p_;
    if (!s.started) return;
    s.stop = true;
    SetEvent(s.stop_event);
    for (auto& t : s.workers)
        if (t.joinable()) t.join();
    s.workers.clear();
    CloseHandle(s.stop_event);
    s.stop_event = nullptr;
    s.started = false;
}

ControlResponse ControlClient::call(const ControlRequest& req) {
    std::lock_guard<std::mutex> lk(m_);
    std::string path = control_endpoint_path(name_);
    std::wstring wp = widen(path);
    auto deadline = SteadyClock::now() + std::chrono::milliseconds(timeout_ms_);
    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;) {
        // SECURITY_IDENTIFICATION: whoever owns the pipe can learn who we are but never act as us.
        h = CreateFileW(wp.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD e = GetLastError();
        if (e == ERROR_PIPE_BUSY) {
            int left = ms_left(deadline);
            if (left <= 0 || !WaitNamedPipeW(wp.c_str(), static_cast<DWORD>(std::min(left, 1000)))) {
                if (ms_left(deadline) <= 0) throw Error("the MySync daemon is busy (all control connections in use)");
            }
            continue;
        }
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            throw Error("the MySync daemon '" + name_ + "' is not running (no control pipe " + path + ")");
        if (e == ERROR_ACCESS_DENIED)
            throw Error("no permission to talk to the MySync daemon '" + name_ +
                        "': ask an administrator to add your account to [control] allow in the configuration");
        throw Error("cannot open the control pipe " + path + ": " + win_msg(e));
    }
    Handle hh(h);
    verify_server_process(h, trusted_accounts_, name_);
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
    PipeChannel ch(h, nullptr);
    try {
        return client_exchange(ch, req, std::max(100, ms_left(deadline)));
    } catch (const IpcTimeout&) {
        throw Error("the MySync daemon '" + name_ + "' did not answer in time");
    }
}

// ============================================================================================= POSIX
#else
namespace {

std::string errno_text(int e) { return std::string(std::strerror(e)); }

class FdChannel : public Channel {
public:
    explicit FdChannel(int fd) : fd_(fd) {}
    size_t read_some(void* buf, size_t n, int timeout_ms) override {
        for (;;) {
            struct pollfd p{fd_, POLLIN, 0};
            int r = ::poll(&p, 1, timeout_ms);
            if (r < 0) {
                if (errno == EINTR) continue;
                throw Error("control socket poll failed: " + errno_text(errno));
            }
            if (r == 0) throw IpcTimeout("control socket read timed out");
            ssize_t k = ::recv(fd_, buf, n, 0);
            if (k < 0) {
                if (errno == EINTR) continue;
                if (errno == ECONNRESET) return 0;
                throw Error("control socket read failed: " + errno_text(errno));
            }
            return static_cast<size_t>(k);
        }
    }
    void write_all(const void* buf, size_t n, int timeout_ms) override {
        auto deadline = SteadyClock::now() + std::chrono::milliseconds(timeout_ms);
        const auto* p = static_cast<const uint8_t*>(buf);
        size_t done = 0;
        while (done < n) {
            struct pollfd pf{fd_, POLLOUT, 0};
            int r = ::poll(&pf, 1, ms_left(deadline));
            if (r < 0) {
                if (errno == EINTR) continue;
                throw Error("control socket poll failed: " + errno_text(errno));
            }
            if (r == 0) throw IpcTimeout("control socket write timed out");
            ssize_t k = ::send(fd_, p + done, n - done, MSG_NOSIGNAL);
            if (k < 0) {
                if (errno == EINTR) continue;
                throw Error("control socket write failed: " + errno_text(errno));
            }
            done += static_cast<size_t>(k);
        }
    }

private:
    int fd_;
};

struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int f) : fd(f) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
    int release() {
        int f = fd;
        fd = -1;
        return f;
    }
};

std::string runtime_dir(const std::string& override_dir) {
    if (!override_dir.empty()) return override_dir;
    // systemd (RuntimeDirectory=mysync) hands a non-root service its directory through this variable
    if (const char* rd = std::getenv("RUNTIME_DIRECTORY")) {
        std::string first(rd);
        first = first.substr(0, first.find(':'));
        if (!first.empty() && first[0] == '/') return first;
    }
    if (::geteuid() == 0) return "/run/mysync";
    const char* x = std::getenv("XDG_RUNTIME_DIR");
    if (!x || !*x || x[0] != '/') throw Error("XDG_RUNTIME_DIR is not set: cannot place the control socket");
    return std::string(x) + "/mysync";
}

sockaddr_un make_addr(const std::string& path) {
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    if (path.size() + 1 > sizeof a.sun_path) throw Error("control socket path is too long: " + path);
    std::memcpy(a.sun_path, path.c_str(), path.size() + 1);
    return a;
}

bool peer_cred(int fd, uid_t& uid, gid_t& gid) {
#ifdef SO_PEERCRED
    struct ucred c{};
    socklen_t len = sizeof c;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &c, &len) != 0) return false;
    uid = c.uid;
    gid = c.gid;
    return true;
#else
    (void)fd; (void)uid; (void)gid;
    return false;
#endif
}

std::vector<uint32_t> groups_of_user(uid_t uid, gid_t primary) {
    std::vector<uint32_t> out{static_cast<uint32_t>(primary)};
    struct passwd pw{}, *res = nullptr;
    char buf[4096];
    if (::getpwuid_r(uid, &pw, buf, sizeof buf, &res) != 0 || !res) return out;
    int n = 64;
    std::vector<gid_t> gs(static_cast<size_t>(n));
    int r = ::getgrouplist(pw.pw_name, pw.pw_gid, gs.data(), &n);
    if (r < 0 && n > 0) {
        gs.resize(static_cast<size_t>(n));
        r = ::getgrouplist(pw.pw_name, pw.pw_gid, gs.data(), &n);
    }
    if (r >= 0)
        for (int i = 0; i < n; ++i) out.push_back(static_cast<uint32_t>(gs[static_cast<size_t>(i)]));
    return out;
}

}  // namespace

std::string detail::resolve_principal_sid(const std::string& entry) { return entry; }

std::string control_endpoint_path(const std::string& name, const std::string& dir_override) {
    if (!valid_control_name(name)) throw Error("invalid control name (allowed: A-Z a-z 0-9 _ . -)");
    return runtime_dir(dir_override) + "/" + name + ".sock";
}

std::vector<std::string> control_endpoint_candidates(const std::string& name, const std::string& dir_override) {
    if (!valid_control_name(name)) throw Error("invalid control name (allowed: A-Z a-z 0-9 _ . -)");
    std::vector<std::string> v;
    if (!dir_override.empty()) {
        v.push_back(dir_override + "/" + name + ".sock");
        return v;
    }
    v.push_back("/run/mysync/" + name + ".sock");
    const char* x = std::getenv("XDG_RUNTIME_DIR");
    if (x && *x == '/') v.push_back(std::string(x) + "/mysync/" + name + ".sock");
    return v;
}

struct IpcServer::Impl {
    struct Conn {
        std::thread th;
        std::atomic<bool> done{false};
        int fd = -1;  // guarded by mu
    };

    IpcServerOptions opts;
    ControlHandler handler;
    std::string path, dir;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> rejected{0};
    int listen_fd = -1;
    int wake_r = -1, wake_w = -1;
    std::thread acceptor;
    std::mutex mu;
    std::list<std::unique_ptr<Conn>> conns;
    uid_t self_uid = 0;
    bool has_group = false;
    gid_t group_gid = 0;
    bool started = false;
    bool created_socket = false;

    // ---- directory / socket preparation (symlinks refused, ownership and mode verified on the open descriptor)
    void prepare_dir() {
        struct stat lst{};
        if (::lstat(dir.c_str(), &lst) == 0) {
            if (S_ISLNK(lst.st_mode)) throw Error("refusing a symbolic link as the control directory: " + dir);
        } else if (errno == ENOENT) {
            if (::mkdir(dir.c_str(), 0750) != 0 && errno != EEXIST)
                throw Error("cannot create the control directory " + dir + ": " + errno_text(errno));
        } else {
            throw Error("cannot inspect the control directory " + dir + ": " + errno_text(errno));
        }
        Fd d(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (d.fd < 0) throw Error("cannot open the control directory " + dir + ": " + errno_text(errno));
        struct stat st{};
        if (::fstat(d.fd, &st) != 0) throw Error("cannot stat the control directory");
        if (st.st_uid != self_uid && st.st_uid != 0)
            throw Error("the control directory " + dir + " belongs to another user");
        if (has_group && st.st_uid == self_uid) {
            if (::fchown(d.fd, static_cast<uid_t>(-1), group_gid) != 0 && ::geteuid() == 0)
                throw Error("cannot set the group of " + dir + ": " + errno_text(errno));
        }
        if (st.st_uid == self_uid && (st.st_mode & 07777) != 0750 && ::fchmod(d.fd, 0750) != 0)
            throw Error("cannot set mode 0750 on " + dir + ": " + errno_text(errno));
        if (::fstat(d.fd, &st) == 0 && (st.st_mode & 0022) != 0)
            throw Error("the control directory " + dir + " is writable by group or others");
        // no symbolic link anywhere on the way (the descriptor above only proves the last component)
        char rp[PATH_MAX];
        if (!::realpath(dir.c_str(), rp)) throw Error("cannot resolve the control directory " + dir);
        std::string want = dir;
        while (want.size() > 1 && want.back() == '/') want.pop_back();
        if (want != rp) throw Error("the control directory path " + dir + " goes through a symbolic link (" + rp + ")");
    }

    void prepare_socket_name() {
        struct stat st{};
        if (::lstat(path.c_str(), &st) != 0) {
            if (errno == ENOENT) return;
            throw Error("cannot inspect " + path + ": " + errno_text(errno));
        }
        if (S_ISLNK(st.st_mode)) throw Error("refusing a symbolic link at the control socket path " + path);
        if (!S_ISSOCK(st.st_mode)) throw Error(path + " exists and is not a socket");
        // A live daemon answers: refuse to take the name. A stale socket (nobody listening) is removed.
        Fd probe(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (probe.fd >= 0) {
            sockaddr_un a = make_addr(path);
            if (::connect(probe.fd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0)
                throw Error("another MySync daemon is already listening on " + path);
        }
        if (::unlink(path.c_str()) != 0 && errno != ENOENT)
            throw Error("cannot remove the stale socket " + path + ": " + errno_text(errno));
    }

    bool admit(int fd) {
        uid_t uid = 0;
        gid_t gid = 0;
        if (!peer_cred(fd, uid, gid)) return false;  // cannot tell who it is: refuse
        std::vector<uint32_t> gs;
        if (has_group) gs = groups_of_user(uid, gid);
        return detail::ipc_peer_allowed(uid, self_uid, gs, has_group, group_gid);
    }

    void reap_locked() {
        for (auto it = conns.begin(); it != conns.end();) {
            if ((*it)->done.load()) {
                if ((*it)->th.joinable()) (*it)->th.join();
                it = conns.erase(it);
            } else {
                ++it;
            }
        }
    }

    void accept_loop() {
        while (!stop.load()) {
            struct pollfd p[2] = {{listen_fd, POLLIN, 0}, {wake_r, POLLIN, 0}};
            int r = ::poll(p, 2, 500);
            if (r < 0 && errno != EINTR) break;
            if (stop.load()) break;
            {
                std::lock_guard<std::mutex> lk(mu);
                reap_locked();
            }
            if (r <= 0 || !(p[0].revents & POLLIN)) continue;
            int fd = ::accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0) continue;
            if (!admit(fd)) {
                ++rejected;
                ::close(fd);
                continue;
            }
            std::lock_guard<std::mutex> lk(mu);
            if (conns.size() >= opts.max_connections) {
                ++rejected;
                ::close(fd);
                continue;
            }
            auto c = std::make_unique<Conn>();
            c->fd = fd;
            Conn* cp = c.get();
            try {
                c->th = std::thread([this, cp, fd] {
                    try {
                        FdChannel ch(fd);
                        ServeLimits lim;
                        lim.read_ms = opts.read_timeout_ms;
                        lim.idle_ms = opts.idle_timeout_ms;
                        lim.lifetime_ms = opts.max_lifetime_ms;
                        serve_channel(ch, handler, lim, stop);
                    } catch (const std::exception& e) {
                        log_debug(std::string("control connection ended: ") + e.what());
                    }
                    {
                        std::lock_guard<std::mutex> lk2(mu);
                        ::close(fd);
                        cp->fd = -1;
                    }
                    cp->done = true;
                });
            } catch (const std::exception&) {
                ::close(fd);
                continue;
            }
            conns.push_back(std::move(c));
        }
    }
};

IpcServer::IpcServer(IpcServerOptions opts, ControlHandler handler) : p_(new Impl) {
    p_->opts = std::move(opts);
    p_->handler = std::move(handler);
    if (p_->opts.max_connections < 1) p_->opts.max_connections = 1;
    if (p_->opts.max_connections > 32) p_->opts.max_connections = 32;
    p_->path = control_endpoint_path(p_->opts.name, p_->opts.dir_override);
    p_->dir = runtime_dir(p_->opts.dir_override);
}

IpcServer::~IpcServer() { stop(); }

const std::string& IpcServer::endpoint() const { return p_->path; }
uint64_t IpcServer::rejected_peers() const { return p_->rejected.load(); }

void IpcServer::start() {
    Impl& s = *p_;
    if (s.started) return;
    s.self_uid = ::geteuid();
    if (!s.opts.group.empty()) {
        struct group gr{}, *res = nullptr;
        char buf[4096];
        if (::getgrnam_r(s.opts.group.c_str(), &gr, buf, sizeof buf, &res) != 0 || !res)
            throw Error("control group '" + s.opts.group + "' does not exist");
        s.has_group = true;
        s.group_gid = gr.gr_gid;
    }
    s.prepare_dir();
    s.prepare_socket_name();
    Fd lf(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (lf.fd < 0) throw Error("cannot create the control socket: " + errno_text(errno));
    sockaddr_un a = make_addr(s.path);
    mode_t old_umask = ::umask(0177);  // the socket never exists with looser permissions than 0600
    int bind_rc = ::bind(lf.fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    int bind_errno = errno;
    ::umask(old_umask);
    if (bind_rc != 0) throw Error("cannot bind the control socket " + s.path + ": " + errno_text(bind_errno));
    s.created_socket = true;
    try {
        if (s.has_group && ::chown(s.path.c_str(), static_cast<uid_t>(-1), s.group_gid) != 0 && ::geteuid() == 0)
            throw Error("cannot set the group of " + s.path + ": " + errno_text(errno));
        if (::chmod(s.path.c_str(), s.has_group ? 0660 : 0600) != 0)
            throw Error("cannot set the mode of " + s.path + ": " + errno_text(errno));
        if (::listen(lf.fd, 8) != 0) throw Error("cannot listen on the control socket: " + errno_text(errno));
        int pf[2];
        if (::pipe2(pf, O_CLOEXEC) != 0) throw Error("cannot create a pipe: " + errno_text(errno));
        s.wake_r = pf[0];
        s.wake_w = pf[1];
    } catch (...) {
        ::unlink(s.path.c_str());
        s.created_socket = false;
        throw;
    }
    s.listen_fd = lf.release();
    s.stop = false;
    s.started = true;
    s.acceptor = std::thread([&s] { s.accept_loop(); });
}

void IpcServer::stop() {
    Impl& s = *p_;
    if (!s.started) return;
    s.stop = true;
    if (s.wake_w >= 0) {
        char c = 1;
        ssize_t ignored = ::write(s.wake_w, &c, 1);
        (void)ignored;
    }
    if (s.acceptor.joinable()) s.acceptor.join();
    {
        std::lock_guard<std::mutex> lk(s.mu);
        for (auto& c : s.conns)
            if (c->fd >= 0) ::shutdown(c->fd, SHUT_RDWR);
    }
    for (;;) {
        std::unique_ptr<Impl::Conn> c;
        {
            std::lock_guard<std::mutex> lk(s.mu);
            if (s.conns.empty()) break;
            c = std::move(s.conns.front());
            s.conns.pop_front();
        }
        if (c->th.joinable()) c->th.join();
    }
    if (s.listen_fd >= 0) ::close(s.listen_fd);
    if (s.wake_r >= 0) ::close(s.wake_r);
    if (s.wake_w >= 0) ::close(s.wake_w);
    s.listen_fd = s.wake_r = s.wake_w = -1;
    if (s.created_socket) ::unlink(s.path.c_str());
    s.created_socket = false;
    s.started = false;
}

ControlResponse ControlClient::call(const ControlRequest& req) {
    std::lock_guard<std::mutex> lk(m_);
    std::vector<std::string> cands = control_endpoint_candidates(name_, dir_override_);
    std::string last_err = "the MySync daemon '" + name_ + "' is not running (no control socket)";
    for (const std::string& path : cands) {
        struct stat st{};
        if (::lstat(path.c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode) || !S_ISSOCK(st.st_mode)) {
            last_err = "refusing " + path + ": not a plain socket";
            continue;
        }
        Fd f(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (f.fd < 0) throw Error("cannot create a socket: " + errno_text(errno));
        sockaddr_un a = make_addr(path);
        if (::connect(f.fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
            int e = errno;
            if (e == EACCES || e == EPERM)
                last_err = "no permission to talk to the MySync daemon at " + path +
                           ": ask an administrator to add your group to [control] group";
            else if (e == ECONNREFUSED)
                last_err = "the MySync daemon '" + name_ + "' is not running (stale socket " + path + ")";
            else
                last_err = "cannot connect to " + path + ": " + errno_text(e);
            continue;
        }
        // The server must be root or whoever owns the socket file, not some other local user's look-alike.
        uid_t puid = 0;
        gid_t pgid = 0;
        if (peer_cred(f.fd, puid, pgid) && puid != 0 && puid != st.st_uid) {
            last_err = "the process behind " + path + " is not the owner of the socket: refusing";
            continue;
        }
        FdChannel ch(f.fd);
        try {
            return client_exchange(ch, req, timeout_ms_);
        } catch (const IpcTimeout&) {
            throw Error("the MySync daemon '" + name_ + "' did not answer in time");
        }
    }
    throw Error(last_err);
}
#endif

// ============================================================================================= ControlClient (shared)
void ControlClient::trust_server_account(const std::string& sid_or_name) { trusted_accounts_.push_back(sid_or_name); }

ControlClient::ControlClient(std::string name, int timeout_ms, std::string dir_override)
    : name_(std::move(name)), timeout_ms_(timeout_ms < 100 ? 100 : timeout_ms), dir_override_(std::move(dir_override)) {
    if (!valid_control_name(name_)) throw Error("invalid control name (allowed: A-Z a-z 0-9 _ . -)");
}

bool ControlClient::ping() {
    try {
        ControlRequest q;
        q.op = ControlOp::Ping;
        {
            std::lock_guard<std::mutex> lk(m_);
            q.token = next_token_++;
        }
        return call(q).status == ControlStatus::Ok;
    } catch (const std::exception&) {
        return false;
    }
}

namespace {
uint64_t take_token(std::mutex& m, uint64_t& t) {
    std::lock_guard<std::mutex> lk(m);
    return t++;
}
void require_ok(const ControlResponse& r) {
    if (r.status != ControlStatus::Ok)
        throw Error(r.error.empty() ? std::string("the daemon refused the request") : r.error);
}
}  // namespace

StatusSnapshot ControlClient::get_status() {
    ControlRequest q;
    q.op = ControlOp::GetStatus;
    q.token = take_token(m_, next_token_);
    ControlResponse r = call(q);
    require_ok(r);
    return std::move(r.snapshot);
}

ReloadResult ControlClient::reload_config() {
    ControlRequest q;
    q.op = ControlOp::ReloadConfig;
    q.token = take_token(m_, next_token_);
    ControlResponse r = call(q);
    if (r.status != ControlStatus::Ok) {
        // A refused reload is a result, not a transport failure: the verbatim reason goes to the caller.
        if (r.status == ControlStatus::Failed) {
            ReloadResult rr;
            rr.ok = false;
            rr.message = r.error.empty() ? r.reload.message : r.error;
            return rr;
        }
        require_ok(r);
    }
    return std::move(r.reload);
}

std::vector<ErrorEntry> ControlClient::recent_errors(uint32_t max) {
    ControlRequest q;
    q.op = ControlOp::GetRecentErrors;
    q.token = take_token(m_, next_token_);
    q.arg = max;
    ControlResponse r = call(q);
    require_ok(r);
    return std::move(r.errors);
}

}  // namespace mysync::gui
