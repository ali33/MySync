// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/service_ctl.h"

#include "mysync/gui/trust.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#endif

namespace fs = std::filesystem;

namespace mysync::gui {
namespace {

constexpr int kChildTimeoutS = 180;  // UAC prompt + service control

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool has_ctl(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f) return true;
    return false;
}

bool name_ok(const std::string& n) {
    if (n.empty() || n.size() > 64 || n[0] == '-' || n[0] == '.') return false;
    for (unsigned char c : n)
        if (!(std::isalnum(c) || c == '_' || c == '.' || c == '-')) return false;
    return true;
}

// Windows account (DOMAIN\user, NT AUTHORITY\LocalService, LocalSystem) or POSIX user name.
bool account_ok(const std::string& a) {
    if (a.empty() || a.size() > 128 || a[0] == '-') return false;
    for (unsigned char c : a)
        if (!(std::isalnum(c) || c == '_' || c == '.' || c == '-' || c == '\\' || c == '$' || c == ' ' || c == '@')) return false;
    return true;
}

// SID text or account name for [control] allow; no quotes, control characters or option-looking text.
bool allow_ok(const std::string& a) {
    if (a.empty() || a.size() > 256 || a[0] == '-') return false;
    for (unsigned char c : a)
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\'' || c == '`') return false;
    return true;
}

}  // namespace

bool valid_control_allow_entry(const std::string& a) { return allow_ok(a); }

const char* service_action_name(ServiceAction a) {
    switch (a) {
    case ServiceAction::Install: return "install";
    case ServiceAction::Uninstall: return "uninstall";
    case ServiceAction::Start: return "start";
    case ServiceAction::Stop: return "stop";
    case ServiceAction::MigrateFromUser: return "migrate-from-user";
    }
    return "?";
}

int service_exit_code_for_error(const std::string& err) {
    std::string e = lower(err);
    auto has = [&](const char* s) { return e.find(s) != std::string::npos; };
    if (has("(access is denied") || has("root required") || has("permission denied") || has("operation not permitted") ||
        has("administrator"))
        return kServiceAccessDenied;
    if (has("does not exist as an installed service") || has("not installed") || has("unit file") ||
        (has("not found") && has("service")))
        return kServiceNotInstalled;
    if (has("already exists") || has("already installed")) return kServiceAlreadyInstalled;
    if (has("timed out") || has("timeout")) return kServiceTimeout;
    if (has("invalid service") || has("invalid name")) return kServiceBadArguments;
    return kServiceGenericFailure;
}

std::string service_exit_message(int code) {
    switch (code) {
    case kServiceOk: return "done";
    case kServiceBadArguments: return "the service request was rejected as invalid";
    case kServiceAccessDenied: return "access denied: administrator / root rights are required";
    case kServiceNotInstalled: return "the service is not installed";
    case kServiceAlreadyInstalled: return "the service is already installed";
    case kServiceTimeout: return "the service did not change state in time";
    case kServiceConfigError: return "the configuration file could not be used";
    case kServiceCancelled: return "cancelled: the elevation prompt was dismissed";
    default: return "the service operation failed (exit code " + std::to_string(code) + ")";
    }
}

bool ServiceController::valid_name(const std::string& n) { return name_ok(n); }

// =========================================================================================== platform parts
#ifdef _WIN32
namespace {

std::wstring widen(const std::string& s) { return fs::u8path(s).wstring(); }

std::string narrow(const std::wstring& w) { return fs::path(w).u8string(); }

std::string win_err(DWORD c) { return "error " + std::to_string(c); }

// CommandLineToArgvW-compatible quoting of one argument.
std::wstring quote_arg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
    std::wstring r = L"\"";
    size_t bs = 0;
    for (wchar_t c : a) {
        if (c == L'\\') {
            ++bs;
        } else if (c == L'"') {
            r.append(bs * 2 + 1, L'\\');
            r += L'"';
            bs = 0;
        } else {
            r.append(bs, L'\\');
            bs = 0;
            r += c;
        }
    }
    r.append(bs * 2, L'\\');
    r += L'"';
    return r;
}

std::wstring join_args(const std::vector<std::string>& args) {
    std::wstring s;
    for (size_t i = 0; i < args.size(); ++i) s += (i ? L" " : L"") + quote_arg(widen(args[i]));
    return s;
}

std::string self_dir() {
    std::wstring buf(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return narrow(fs::path(buf).parent_path().wstring());
}

struct ChildResult {
    bool started = false;
    bool timed_out = false;
    DWORD exit_code = 0;
    DWORD error = 0;
    std::string output;
};

// Already elevated: run the child directly with stdout/stderr captured through an anonymous pipe.
ChildResult spawn_captured(const std::string& exe, const std::vector<std::string>& args) {
    ChildResult r;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        r.error = GetLastError();
        return r;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = INVALID_HANDLE_VALUE;
    std::wstring cmd = quote_arg(widen(exe));
    std::wstring a = join_args(args);
    if (!a.empty()) cmd += L" " + a;
    PROCESS_INFORMATION pi{};
    std::wstring dir = widen(fs::u8path(exe).parent_path().u8string());
    BOOL ok = CreateProcessW(widen(exe).c_str(), cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                             dir.empty() ? nullptr : dir.c_str(), &si, &pi);
    CloseHandle(wr);
    if (!ok) {
        r.error = GetLastError();
        CloseHandle(rd);
        return r;
    }
    r.started = true;
    std::string out;
    std::thread reader([&] {
        char buf[2048];
        DWORD n = 0;
        while (ReadFile(rd, buf, sizeof buf, &n, nullptr) && n > 0) {
            if (out.size() < 16384) out.append(buf, n);
        }
    });
    DWORD w = WaitForSingleObject(pi.hProcess, kChildTimeoutS * 1000);
    if (w == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, kServiceTimeout);
        WaitForSingleObject(pi.hProcess, 5000);
        r.timed_out = true;
    }
    GetExitCodeProcess(pi.hProcess, &r.exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    reader.join();
    CloseHandle(rd);
    r.output = out;
    return r;
}

// Not elevated: UAC prompt through ShellExecuteEx "runas". Output cannot be captured: the exit code is the report.
ChildResult spawn_elevated(const std::string& exe, const std::vector<std::string>& args) {
    ChildResult r;
    HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    std::wstring file = widen(exe), params = join_args(args), dir = widen(fs::u8path(exe).parent_path().u8string());
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas";
    sei.lpFile = file.c_str();
    sei.lpParameters = params.c_str();
    sei.lpDirectory = dir.empty() ? nullptr : dir.c_str();
    sei.nShow = SW_HIDE;
    BOOL ok = ShellExecuteExW(&sei);
    if (!ok) {
        r.error = GetLastError();
    } else if (sei.hProcess) {
        r.started = true;
        DWORD w = WaitForSingleObject(sei.hProcess, kChildTimeoutS * 1000);
        if (w == WAIT_TIMEOUT) {
            r.timed_out = true;  // the elevated process cannot be terminated from here
            r.exit_code = kServiceTimeout;
        } else {
            GetExitCodeProcess(sei.hProcess, &r.exit_code);
        }
        CloseHandle(sei.hProcess);
    } else {
        r.error = ERROR_INVALID_HANDLE;
    }
    if (SUCCEEDED(co)) CoUninitialize();
    return r;
}

}  // namespace

bool ServiceController::is_elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{};
    DWORD len = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof el, &len);
    CloseHandle(tok);
    return ok && el.TokenIsElevated != 0;
}

ServiceState ServiceController::query(const std::string& name) const {
    ServiceState st;
    if (!name_ok(name)) {
        st.error = "invalid service name";
        return st;
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        st.error = "cannot reach the service manager (" + win_err(GetLastError()) + ")";
        return st;
    }
    SC_HANDLE svc = OpenServiceW(scm, widen(name).c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!svc) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_DOES_NOT_EXIST) st.error = "cannot open the service (" + win_err(e) + ")";
        CloseServiceHandle(scm);
        return st;
    }
    st.installed = true;
    SERVICE_STATUS s{};
    if (QueryServiceStatus(svc, &s)) {
        switch (s.dwCurrentState) {
        case SERVICE_RUNNING: st.detail = "RUNNING"; st.running = true; break;
        case SERVICE_START_PENDING: st.detail = "START_PENDING"; st.running = true; break;
        case SERVICE_STOP_PENDING: st.detail = "STOP_PENDING"; break;
        case SERVICE_STOPPED: st.detail = "STOPPED"; break;
        default: st.detail = "state " + std::to_string(s.dwCurrentState); break;
        }
    }
    DWORD need = 0;
    QueryServiceConfigW(svc, nullptr, 0, &need);
    if (need > 0) {
        std::vector<uint8_t> buf(need);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(svc, cfg, need, &need)) st.auto_start = cfg->dwStartType == SERVICE_AUTO_START;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return st;
}

static std::string default_exe() { return self_dir() + "\\mysync.exe"; }

static ServiceResult run_child(const std::string& exe, const std::vector<std::string>& args) {
    ServiceResult res;
    // Held for the whole run: while this read-only handle is open nobody can write to or replace the file between
    // the trust check and the moment Windows starts it. (The folder could still be renamed away by an administrator;
    // a non-administrator cannot, by the check above.)
    struct Pin {
        HANDLE h;
        explicit Pin(const std::string& p)
            : h(CreateFileW(widen(p).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {}
        ~Pin() {
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
    } pin(exe);
    bool elevated_now = ServiceController::is_elevated();
    res.elevated = !elevated_now;
    ChildResult c = elevated_now ? spawn_captured(exe, args) : spawn_elevated(exe, args);
    if (!c.started) {
        if (c.error == ERROR_CANCELLED) {
            res.cancelled = true;
            res.exit_code = kServiceCancelled;
            res.message = "Cancelled: the administrator prompt (UAC) was dismissed. Nothing was changed.";
        } else {
            res.exit_code = kServiceGenericFailure;
            res.message = "Could not start the elevated process (" + win_err(c.error) + ")";
        }
        return res;
    }
    res.exit_code = static_cast<int>(c.exit_code);
    res.ok = c.exit_code == 0 && !c.timed_out;
    res.message = c.timed_out ? "Timed out waiting for the service operation." : service_exit_message(res.exit_code);
    if (!c.output.empty()) res.message += "\n" + c.output;
    return res;
}

#else  // ------------------------------------------------------------------------------------------ POSIX
namespace {

struct Captured {
    bool started = false;
    bool timed_out = false;
    int exit_code = -1;
    int err = 0;
    std::string output;
};

Captured run_argv(const std::vector<std::string>& argv, int timeout_s) {
    Captured r;
    int pf[2];
    if (::pipe2(pf, O_CLOEXEC) != 0) {
        r.err = errno;
        return r;
    }
    std::vector<char*> av;
    for (const auto& a : argv) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    pid_t pid = ::fork();
    if (pid < 0) {
        r.err = errno;
        ::close(pf[0]);
        ::close(pf[1]);
        return r;
    }
    if (pid == 0) {
        ::dup2(pf[1], 1);
        ::dup2(pf[1], 2);
        int nul = ::open("/dev/null", O_RDONLY);
        if (nul >= 0) ::dup2(nul, 0);
        ::execv(av[0], av.data());  // argv[0] is always an absolute path: PATH is never consulted
        _exit(127);
    }
    ::close(pf[1]);
    r.started = true;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    char buf[2048];
    for (;;) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            r.timed_out = true;
            ::kill(pid, SIGKILL);
            break;
        }
        struct pollfd p{pf[0], POLLIN, 0};
        int pr = ::poll(&p, 1, static_cast<int>(std::min<long long>(left, 1000)));
        if (pr < 0 && errno != EINTR) break;
        if (pr > 0) {
            ssize_t n = ::read(pf[0], buf, sizeof buf);
            if (n > 0) {
                if (r.output.size() < 16384) r.output.append(buf, static_cast<size_t>(n));
            } else if (n == 0) {
                break;  // EOF: the child (and everything it started with our pipe) closed it
            }
        }
    }
    ::close(pf[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    r.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return r;
}

std::string first_existing(std::initializer_list<const char*> paths) {
    for (const char* p : paths)
        if (::access(p, X_OK) == 0) return p;
    return {};
}

[[maybe_unused]] bool in_path(const std::string& prog) {
    const char* p = std::getenv("PATH");
    std::string path = p ? p : "/usr/bin:/bin";
    size_t i = 0;
    while (i <= path.size()) {
        size_t e = path.find(':', i);
        std::string dir = path.substr(i, e == std::string::npos ? std::string::npos : e - i);
        if (!dir.empty() && dir[0] == '/' && ::access((dir + "/" + prog).c_str(), X_OK) == 0) return true;
        if (e == std::string::npos) break;
        i = e + 1;
    }
    return false;
}

}  // namespace

bool ServiceController::is_elevated() { return ::geteuid() == 0; }

ServiceState ServiceController::query(const std::string& name) const {
    ServiceState st;
    if (!name_ok(name)) {
        st.error = "invalid service name";
        return st;
    }
    std::error_code ec;
    st.installed = fs::exists(fs::path("/etc/systemd/system/" + name + ".service"), ec);
    const std::string systemctl = first_existing({"/usr/bin/systemctl", "/bin/systemctl"});
    if (systemctl.empty()) {
        st.error = "systemctl is not available on this system";
        return st;
    }
    Captured a = run_argv({systemctl, "is-active", name + ".service"}, 10);
    std::string act = a.output;
    while (!act.empty() && std::isspace(static_cast<unsigned char>(act.back()))) act.pop_back();
    st.detail = act;
    st.running = act == "active" || act == "activating";
    if (!st.installed && act != "inactive" && act != "unknown" && act != "failed" && !act.empty() && st.running) st.installed = true;
    Captured e = run_argv({systemctl, "is-enabled", name + ".service"}, 10);
    std::string en = e.output;
    while (!en.empty() && std::isspace(static_cast<unsigned char>(en.back()))) en.pop_back();
    st.auto_start = en == "enabled";
    return st;
}

static std::string default_exe() {
    std::error_code ec;
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    if (ec) return {};
    return (p.parent_path() / "mysync").u8string();
}

static ServiceResult run_child(const std::string& exe, const std::vector<std::string>& args) {
    ServiceResult res;
    std::vector<std::string> argv;
    if (::geteuid() != 0) {
        const std::string pkexec = first_existing({"/usr/bin/pkexec"});
        if (pkexec.empty()) {
            res.exit_code = kServiceGenericFailure;
            res.message = "pkexec (polkit) is not installed: run the same command as root instead: " + exe + " " +
                          (args.empty() ? "" : args[0] + " " + (args.size() > 1 ? args[1] : ""));
            return res;
        }
        argv.push_back(pkexec);
        res.elevated = true;
    }
    argv.push_back(exe);
    for (const auto& a : args) argv.push_back(a);
    Captured c = run_argv(argv, kChildTimeoutS);
    if (!c.started) {
        res.exit_code = kServiceGenericFailure;
        res.message = std::string("Could not start the process: ") + std::strerror(c.err);
        return res;
    }
    res.exit_code = c.exit_code;
    if (res.elevated && (c.exit_code == 126 || c.exit_code == 127)) {
        // pkexec: 126 = dismissed / not authorised, 127 = authentication failed
        res.cancelled = true;
        res.exit_code = kServiceCancelled;
        res.message = "Cancelled: the authorisation prompt (pkexec) was dismissed or refused. Nothing was changed.";
        return res;
    }
    res.ok = c.exit_code == 0 && !c.timed_out;
    res.message = c.timed_out ? "Timed out waiting for the service operation." : service_exit_message(res.exit_code);
    if (!c.output.empty()) res.message += "\n" + c.output;
    return res;
}

#endif

// =========================================================================================== shared logic
ServiceController::ServiceController(std::string exe) : exe_(std::move(exe)) {
    if (exe_.empty()) exe_ = default_exe();
    if (exe_.empty()) throw Error("cannot locate the mysync executable");
    fs::path p = fs::u8path(exe_);
    if (!p.is_absolute() || has_ctl(exe_)) throw Error("the mysync executable must be given as an absolute path");
    std::string stem = lower(p.stem().u8string());
    if (stem != "mysync") throw Error("refusing to run '" + p.filename().u8string() + "' with elevated rights: expected mysync");
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) throw Error("the mysync executable does not exist: " + exe_);
#ifndef _WIN32
    struct stat st{};
    if (::stat(exe_.c_str(), &st) != 0) throw Error("cannot inspect " + exe_);
    if ((st.st_mode & 022) != 0) throw Error(exe_ + " is writable by group/others: refusing to run it with elevated rights");
    if (st.st_uid != 0 && st.st_uid != ::geteuid()) throw Error(exe_ + " is owned by another user: refusing to elevate it");
#endif
}

std::vector<std::string> ServiceController::build_args(ServiceAction act, const ServiceRequest& rq) const {
    if (!name_ok(rq.name)) throw Error("invalid service name (allowed: A-Z a-z 0-9 _ . -, at most 64)");
    std::vector<std::string> a{"service", service_action_name(act)};
    if (act == ServiceAction::Install) {
        fs::path cp = fs::u8path(rq.config_path);
        if (rq.config_path.empty() || !cp.is_absolute() || has_ctl(rq.config_path) || rq.config_path[0] == '-')
            throw Error("the configuration path must be absolute");
        std::error_code ec;
        if (!fs::is_regular_file(cp, ec)) throw Error("the configuration file does not exist: " + rq.config_path);
        a.push_back("-c");
        a.push_back(rq.config_path);
        if (!rq.role.empty()) {
            if (rq.role != "server" && rq.role != "client") throw Error("role must be 'server' or 'client'");
            a.push_back("--role");
            a.push_back(rq.role);
        }
        if (!rq.run_as.empty()) {
            if (!account_ok(rq.run_as)) throw Error("invalid service account name");
            a.push_back("--user");
            a.push_back(rq.run_as);
        }
        for (const auto& x : rq.control_allow) {
            if (!allow_ok(x)) throw Error("invalid control allow entry");
            std::string broad = broad_principal_reason(x);
            if (!broad.empty()) throw Error(broad);
            a.push_back("--control-allow");
            a.push_back(x);
        }
        for (const auto& x : rq.trust_writers) {
            if (!allow_ok(x)) throw Error("invalid trust-writer entry");
            std::string broad = broad_principal_reason(x);
            if (!broad.empty()) throw Error(broad);
            a.push_back("--trust-writer");
            a.push_back(x);
        }
    } else if (act == ServiceAction::MigrateFromUser) {
        if (!rq.config_path.empty() || !rq.role.empty() || !rq.run_as.empty() || !rq.control_allow.empty() ||
            !rq.trust_writers.empty())
            throw Error("migrate-from-user takes only the user configuration and the service name");
        if (rq.remove_migrated) {
            if (!rq.user_config.empty()) throw Error("remove_migrated takes no user configuration");
            a.push_back("--remove");
            a.push_back("--name");
            a.push_back(rq.name);
            return a;
        }
        fs::path up = fs::u8path(rq.user_config);
        if (rq.user_config.empty() || !up.is_absolute() || has_ctl(rq.user_config) || rq.user_config[0] == '-')
            throw Error("the user configuration path must be absolute");
        a.push_back("--user-config");
        a.push_back(rq.user_config);
    } else if (!rq.config_path.empty() || !rq.role.empty() || !rq.run_as.empty() || !rq.control_allow.empty() ||
               !rq.trust_writers.empty()) {
        // not needed for these actions; ignoring silently would hide a caller mistake
        throw Error(std::string("the options config/role/account/allow only apply to install, not ") + service_action_name(act));
    }
    a.push_back("--name");
    a.push_back(rq.name);
    return a;
}

ServiceResult ServiceController::run(ServiceAction act, const ServiceRequest& rq) {
    std::vector<std::string> args = build_args(act, rq);
    // Nothing is elevated unless the program (and the folder it sits in) can only be changed by administrators.
    std::string why = untrusted_executable_reason(exe_);
    if (!why.empty()) {
        ServiceResult r;
        r.exit_code = kServiceAccessDenied;
        r.message = "Refusing to run with elevated rights: " + why +
#ifdef _WIN32
                    ". Install MySync under C:\\Program Files (only administrators can write there) and start the GUI from there.";
#else
                    ". Install MySync as root (for example /usr/local/bin/mysync owned by root, no group/other write access).";
#endif
        r.state_after = query(rq.name);
        return r;
    }
    if (act == ServiceAction::Install) {
        // same vetting as the command line (one function), before the UAC / pkexec prompt
        std::string bad = validate_install_inputs(exe_, rq.config_path, rq.trust_writers, rq.control_allow, rq.run_as);
        if (!bad.empty()) {
            ServiceResult r;
            r.exit_code = kServiceConfigError;
            r.message = bad;
            r.state_after = query(rq.name);
            return r;
        }
    }
    ServiceResult res = run_child(exe_, args);
    res.state_after = query(rq.name);
    if (res.ok) {
        bool mismatch = (act == ServiceAction::Install && !res.state_after.installed) ||
                        (act == ServiceAction::Uninstall && res.state_after.installed) ||
                        (act == ServiceAction::Start && !res.state_after.running && res.state_after.error.empty()) ||
                        (act == ServiceAction::Stop && res.state_after.running);
        if (mismatch) res.message += "\nNote: the service state afterwards (" + res.state_after.detail + ") is not the expected one.";
    }
    return res;
}

}  // namespace mysync::gui
