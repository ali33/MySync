// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/service.h"

#include <cctype>
#include <chrono>
#include <csignal>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#endif

#include "mysync/util.h"

namespace mysync {
namespace {

void set_err(std::string* err, const std::string& m) {
    if (err) *err = m;
}

bool valid_service_name(const std::string& n) {
    if (n.empty() || n.size() > 64 || n[0] == '-' || n[0] == '.') return false;
    for (unsigned char c : n)
        if (!(std::isalnum(c) || c == '_' || c == '.' || c == '-')) return false;
    return true;
}

bool has_ctl(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f) return true;
    return false;
}

// systemd ExecStart word: always double-quoted; \ and " escaped; % and $ doubled (specifiers / env expansion).
std::string systemd_quote(const std::string& s) {
    std::string r = "\"";
    for (char c : s) {
        if (c == '\\' || c == '"') { r += '\\'; r += c; }
        else if (c == '%') r += "%%";
        else if (c == '$') r += "$$";
        else r += c;
    }
    r += '"';
    return r;
}

std::atomic<bool>* g_stop_flag = nullptr;

}  // namespace

std::string systemd_unit_text(const std::string& name, const std::string& exe, const std::vector<std::string>& args,
                              const std::string& user, const std::vector<std::string>& rw_paths,
                              const std::string& description) {
    if (!valid_service_name(name)) throw Error("invalid service name (allowed: A-Z a-z 0-9 _ . -)");
    if (exe.empty() || exe[0] != '/' || has_ctl(exe)) throw Error("service executable must be an absolute path");
    if (!user.empty() && !valid_service_name(user)) throw Error("invalid service user name");
    for (auto& a : args)
        if (has_ctl(a)) throw Error("control characters are not allowed in service arguments");
    if (has_ctl(description)) throw Error("control characters are not allowed in the service description");
    for (auto& p : rw_paths) {
        if (p.empty() || p[0] != '/' || has_ctl(p)) throw Error("ReadWritePaths entries must be absolute paths");
        for (unsigned char c : p)
            if (c == ' ' || c == '"' || c == '\'' || c == '\\' || c == '%' || c == '$')
                throw Error("ReadWritePaths entries must not contain spaces, quotes, backslashes, % or $: " + p);
    }
    std::string u;
    u += "[Unit]\n";
    u += "Description=" + (description.empty() ? "MySync (" + name + ")" : description) + "\n";
    u += "After=network-online.target\nWants=network-online.target\n\n";
    u += "[Service]\nType=simple\n";
    if (!user.empty()) u += "User=" + user + "\n";
    u += "ExecStart=" + systemd_quote(exe);
    for (auto& a : args) u += " " + systemd_quote(a);
    u += "\n";
    u += "Restart=on-failure\nRestartSec=5\nTimeoutStopSec=30\n";
    u += "NoNewPrivileges=true\n";
    u += "ProtectSystem=strict\n";
    u += "ProtectHome=read-only\n";
    u += "PrivateTmp=true\n";
    u += "PrivateDevices=true\n";
    u += "ProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\n";
    u += "RestrictSUIDSGID=true\nRestrictRealtime=true\nLockPersonality=true\n";
    u += "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n";
    u += "SystemCallArchitectures=native\n";
    if (!rw_paths.empty()) {
        u += "ReadWritePaths=";
        for (size_t i = 0; i < rw_paths.size(); ++i) u += (i ? " " : "") + rw_paths[i];
        u += "\n";
    }
    u += "\n[Install]\nWantedBy=multi-user.target\n";
    return u;
}

bool service_install(const std::string& name, const std::string& display, const std::string& exe_path,
                     const std::vector<std::string>& args, ServiceStartType start_type, std::string* err) {
    ServiceSpec s;
    s.name = name;
    s.display = display;
    s.exe_path = exe_path;
    s.args = args;
    s.start = start_type;
    return service_install(s, err);
}

// ============================================================================================
#ifdef _WIN32
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string win_error(const std::string& what, DWORD code = GetLastError()) {
    char buf[512] = {0};
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0, buf,
                             sizeof buf - 1, nullptr);
    std::string text(buf, n);
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) text.pop_back();
    return what + " failed: error " + std::to_string(code) + (text.empty() ? "" : " (" + text + ")");
}

// CommandLineToArgvW-compatible quoting.
std::wstring quote_arg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
    std::wstring r = L"\"";
    for (size_t i = 0;; ++i) {
        size_t bs = 0;
        while (i < a.size() && a[i] == L'\\') { ++i; ++bs; }
        if (i == a.size()) { r.append(bs * 2, L'\\'); break; }
        if (a[i] == L'"') { r.append(bs * 2 + 1, L'\\'); r += L'"'; }
        else { r.append(bs, L'\\'); r += a[i]; }
    }
    r += L'"';
    return r;
}

struct ScHandle {
    SC_HANDLE h = nullptr;
    ScHandle() = default;
    explicit ScHandle(SC_HANDLE x) : h(x) {}
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    ~ScHandle() { if (h) CloseServiceHandle(h); }
    explicit operator bool() const { return h != nullptr; }
};

bool wait_state(SC_HANDLE svc, DWORD want, DWORD timeout_ms) {
    DWORD t0 = GetTickCount();
    for (;;) {
        SERVICE_STATUS_PROCESS st{};
        DWORD need = 0;
        if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&st), sizeof st, &need))
            return false;
        if (st.dwCurrentState == want) return true;
        if (GetTickCount() - t0 > timeout_ms) return false;
        Sleep(250);
    }
}

// ---- run_as_service state (one service per process) ----
struct SvcCtx {
    std::wstring name;
    SERVICE_STATUS_HANDLE h = nullptr;
    std::atomic<bool> stop{false};
    std::function<void(std::atomic<bool>&)> body;
    int exit_code = 0;
    DWORD checkpoint = 1;
} g_svc;

void report(DWORD state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0) {
    SERVICE_STATUS s{};
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwControlsAccepted = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
                               ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    s.dwWin32ExitCode = exit_code;
    s.dwWaitHint = wait_hint;
    s.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : g_svc.checkpoint++;
    if (g_svc.h) SetServiceStatus(g_svc.h, &s);
}

DWORD WINAPI svc_handler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        report(SERVICE_STOP_PENDING, NO_ERROR, 30000);
        g_svc.stop = true;
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI svc_main(DWORD, LPWSTR*) {
    g_svc.h = RegisterServiceCtrlHandlerExW(g_svc.name.c_str(), svc_handler, nullptr);
    if (!g_svc.h) { g_svc.exit_code = 1; return; }
    report(SERVICE_START_PENDING, NO_ERROR, 10000);
    report(SERVICE_RUNNING);
    DWORD win_code = NO_ERROR;
    try {
        g_svc.body(g_svc.stop);
    } catch (const std::exception& e) {
        log_error(std::string("service body failed: ") + e.what());
        g_svc.exit_code = 1;
        win_code = ERROR_SERVICE_SPECIFIC_ERROR;
    } catch (...) {
        log_error("service body failed with an unknown exception");
        g_svc.exit_code = 1;
        win_code = ERROR_SERVICE_SPECIFIC_ERROR;
    }
    report(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    SERVICE_STATUS s{};
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = SERVICE_STOPPED;
    s.dwWin32ExitCode = win_code;
    s.dwServiceSpecificExitCode = win_code == NO_ERROR ? 0 : 1;
    SetServiceStatus(g_svc.h, &s);
}

BOOL WINAPI console_handler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_stop_flag) g_stop_flag->store(true);
        if (type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) Sleep(5000);  // Windows kills us after ~5 s anyway
        return TRUE;
    default:
        return FALSE;
    }
}

}  // namespace

bool service_install(const ServiceSpec& spec, std::string* err) {
    if (!valid_service_name(spec.name)) { set_err(err, "invalid service name (allowed: A-Z a-z 0-9 _ . -)"); return false; }
    if (spec.exe_path.empty() || has_ctl(spec.exe_path)) { set_err(err, "invalid executable path"); return false; }
    for (auto& a : spec.args) if (has_ctl(a)) { set_err(err, "control characters in service arguments"); return false; }

    std::wstring cmd = quote_arg(widen(spec.exe_path));
    for (auto& a : spec.args) cmd += L" " + quote_arg(widen(a));
    std::wstring account = widen(spec.run_as.empty() ? "NT AUTHORITY\\LocalService" : spec.run_as);
    DWORD start = spec.start == ServiceStartType::Auto ? SERVICE_AUTO_START
                  : spec.start == ServiceStartType::Manual ? SERVICE_DEMAND_START : SERVICE_DISABLED;

    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!scm) { set_err(err, win_error("OpenSCManager (administrator rights required)")); return false; }
    std::wstring wname = widen(spec.name);
    std::wstring wdisplay = widen(spec.display.empty() ? spec.name : spec.display);
    ScHandle svc(CreateServiceW(scm.h, wname.c_str(), wdisplay.c_str(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                start, SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, nullptr, account.c_str(),
                                nullptr));
    if (!svc) { set_err(err, win_error("CreateService")); return false; }

    if (!spec.description.empty()) {
        std::wstring d = widen(spec.description);
        SERVICE_DESCRIPTIONW sd{const_cast<LPWSTR>(d.c_str())};
        ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_DESCRIPTION, &sd);  // cosmetic: failure is not fatal
    }
    if (spec.start == ServiceStartType::Auto) {
        SERVICE_DELAYED_AUTO_START_INFO di{TRUE};  // let the network come up first
        ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &di);
    }
    if (spec.restart_on_failure) {
        SC_ACTION acts[3] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}};
        SERVICE_FAILURE_ACTIONSW fa{};
        fa.dwResetPeriod = 86400;
        fa.cActions = 3;
        fa.lpsaActions = acts;
        if (!ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) {
            set_err(err, win_error("Set recovery actions"));
            return false;  // the service exists but without auto-restart; tell the caller
        }
        SERVICE_FAILURE_ACTIONS_FLAG flag{TRUE};  // also restart after a non-zero exit, not only a crash
        ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
    }
    return true;
}

bool service_uninstall(const std::string& name, std::string* err) {
    if (!valid_service_name(name)) { set_err(err, "invalid service name"); return false; }
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { set_err(err, win_error("OpenSCManager")); return false; }
    ScHandle svc(OpenServiceW(scm.h, widen(name).c_str(), DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!svc) { set_err(err, win_error("OpenService")); return false; }
    SERVICE_STATUS st{};
    if (ControlService(svc.h, SERVICE_CONTROL_STOP, &st)) wait_state(svc.h, SERVICE_STOPPED, 30000);
    if (!DeleteService(svc.h)) { set_err(err, win_error("DeleteService")); return false; }
    return true;
}

bool service_start(const std::string& name, std::string* err) {
    if (!valid_service_name(name)) { set_err(err, "invalid service name"); return false; }
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { set_err(err, win_error("OpenSCManager")); return false; }
    ScHandle svc(OpenServiceW(scm.h, widen(name).c_str(), SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc) { set_err(err, win_error("OpenService")); return false; }
    if (!StartServiceW(svc.h, 0, nullptr)) { set_err(err, win_error("StartService")); return false; }
    if (!wait_state(svc.h, SERVICE_RUNNING, 30000)) { set_err(err, "service did not reach the running state within 30 s"); return false; }
    return true;
}

bool service_stop(const std::string& name, std::string* err) {
    if (!valid_service_name(name)) { set_err(err, "invalid service name"); return false; }
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { set_err(err, win_error("OpenSCManager")); return false; }
    ScHandle svc(OpenServiceW(scm.h, widen(name).c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!svc) { set_err(err, win_error("OpenService")); return false; }
    SERVICE_STATUS st{};
    if (!ControlService(svc.h, SERVICE_CONTROL_STOP, &st)) { set_err(err, win_error("ControlService(STOP)")); return false; }
    if (!wait_state(svc.h, SERVICE_STOPPED, 30000)) { set_err(err, "service did not stop within 30 s"); return false; }
    return true;
}

int run_as_service(const std::string& name, std::function<void(std::atomic<bool>& stop)> body) {
    g_svc.name = widen(name);
    g_svc.body = std::move(body);
    g_svc.stop = false;
    g_svc.exit_code = 0;
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(g_svc.name.c_str()), svc_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        DWORD e = GetLastError();
        if (e == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            log_error("not started by the Service Control Manager; run in the foreground instead");
        else
            log_error(win_error("StartServiceCtrlDispatcher", e));
        return 1;
    }
    return g_svc.exit_code;
}

void install_signal_handlers(std::atomic<bool>& stop) {
    g_stop_flag = &stop;
    SetConsoleCtrlHandler(console_handler, TRUE);
}

// ============================================================================================
#else  // POSIX
namespace {

// fork + execvp with an argv array (never a shell string): no injection through names or paths.
bool run_cmd(const std::vector<std::string>& argv, std::string* err) {
    std::vector<char*> av;
    for (auto& a : argv) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    pid_t pid = fork();
    if (pid < 0) { set_err(err, std::string("fork failed: ") + std::strerror(errno)); return false; }
    if (pid == 0) {
        execvp(av[0], av.data());
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) { set_err(err, std::string("waitpid failed: ") + std::strerror(errno)); return false; }
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return true;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
        set_err(err, argv[0] + ": command not found or not executable");
    else
        set_err(err, argv[0] + " " + (argv.size() > 1 ? argv[1] : "") + " failed (exit status " +
                         std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) + ")");
    return false;
}

std::string unit_path(const std::string& name) { return "/etc/systemd/system/" + name + ".service"; }

void on_signal(int) {
    if (g_stop_flag) g_stop_flag->store(true);
}

}  // namespace

bool service_install(const ServiceSpec& spec, std::string* err) {
    std::string text;
    try {
        text = systemd_unit_text(spec.name, spec.exe_path, spec.args, spec.run_as, spec.read_write_paths,
                                 spec.display);
    } catch (const std::exception& e) {
        set_err(err, e.what());
        return false;
    }
    std::string path = unit_path(spec.name), tmp = path + ".tmp";
    {
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) { set_err(err, "cannot write " + tmp + ": " + std::strerror(errno) + " (root required)"); return false; }
        size_t off = 0;
        while (off < text.size()) {
            ssize_t n = ::write(fd, text.data() + off, text.size() - off);
            if (n < 0) {
                if (errno == EINTR) continue;
                set_err(err, std::string("write failed: ") + std::strerror(errno));
                ::close(fd);
                ::unlink(tmp.c_str());
                return false;
            }
            off += static_cast<size_t>(n);
        }
        ::fsync(fd);
        ::close(fd);
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        set_err(err, std::string("rename failed: ") + std::strerror(errno));
        ::unlink(tmp.c_str());
        return false;
    }
    if (!run_cmd({"systemctl", "daemon-reload"}, err)) return false;
    if (spec.start == ServiceStartType::Auto) return run_cmd({"systemctl", "enable", spec.name + ".service"}, err);
    return true;
}

bool service_uninstall(const std::string& name, std::string* err) {
    if (!valid_service_name(name)) { set_err(err, "invalid service name"); return false; }
    std::string ignore;
    run_cmd({"systemctl", "stop", name + ".service"}, &ignore);
    run_cmd({"systemctl", "disable", name + ".service"}, &ignore);
    if (::unlink(unit_path(name).c_str()) != 0 && errno != ENOENT) {
        set_err(err, "cannot remove " + unit_path(name) + ": " + std::strerror(errno));
        return false;
    }
    return run_cmd({"systemctl", "daemon-reload"}, err);
}

bool service_start(const std::string& name, std::string* err) {
    if (!valid_service_name(name)) { set_err(err, "invalid service name"); return false; }
    return run_cmd({"systemctl", "start", name + ".service"}, err);
}

bool service_stop(const std::string& name, std::string* err) {
    if (!valid_service_name(name)) { set_err(err, "invalid service name"); return false; }
    return run_cmd({"systemctl", "stop", name + ".service"}, err);
}

int run_as_service(const std::string&, std::function<void(std::atomic<bool>& stop)> body) {
    std::atomic<bool> stop{false};
    install_signal_handlers(stop);
    try {
        body(stop);
    } catch (const std::exception& e) {
        log_error(std::string("service body failed: ") + e.what());
        return 1;
    } catch (...) {
        log_error("service body failed with an unknown exception");
        return 1;
    }
    return 0;
}

void install_signal_handlers(std::atomic<bool>& stop) {
    g_stop_flag = &stop;
    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
}
#endif

}  // namespace mysync
