// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// service.h - run as a Windows service (SCM) or a systemd unit; shared signal handling.
// Installing/removing requires administrator / root. See docs/SERVICE.md for the permissions the
// service account needs.
#include <atomic>
#include <functional>
#include <string>
#include <vector>

namespace mysync {

enum class ServiceStartType { Auto, Manual, Disabled };

struct ServiceSpec {
    std::string name;                       // [A-Za-z0-9_.-], max 64, must not start with '-'
    std::string display;                    // Windows display name / systemd Description
    std::string description;                // optional longer description
    std::string exe_path;                   // absolute path to mysync
    std::vector<std::string> args;          // arguments after the exe
    ServiceStartType start = ServiceStartType::Auto;
    bool restart_on_failure = true;         // Windows Recovery actions / systemd Restart=on-failure
    // Windows: account; empty = "NT AUTHORITY\\LocalService" (no password). LocalSystem is
    // "LocalSystem". Linux: user for User=; empty = root.
    std::string run_as;
    // Windows, a user account in run_as: its password, handed to CreateService and then WIPED by service_install. It must
    // never travel by command line, environment, log or file (see simple/service_account.h for the channel).
    std::string run_as_password;
    // Linux, per-user units: Group= and the RuntimeDirectory of the unit (the control socket lives there). Defaults keep
    // the old system-wide behaviour ("mysync", 0750).
    std::string run_group;
    std::string runtime_dir = "mysync";
    std::string runtime_dir_mode = "0750";
    bool strict_user = false;   // per-user flavour: see SystemdOptions::strict_user
    // Linux: directories the service may write (ProtectSystem=strict). No whitespace/quotes allowed.
    std::vector<std::string> read_write_paths;
};

// All functions return false on failure and put a readable reason in *err (if given). On a platform
// that lacks the facility they return false with err = "not supported on this platform".
bool service_install(const ServiceSpec& spec, std::string* err = nullptr);
bool service_install(const std::string& name, const std::string& display, const std::string& exe_path,
                     const std::vector<std::string>& args, ServiceStartType start_type = ServiceStartType::Auto,
                     std::string* err = nullptr);
bool service_uninstall(const std::string& name, std::string* err = nullptr);  // stops first
bool service_start(const std::string& name, std::string* err = nullptr);
bool service_stop(const std::string& name, std::string* err = nullptr);      // Windows: waits up to 30 s
// Windows: is the service `name` really one that runs `exe_path ... run ... --service`? (set-password must not be turned into
// "change the password of any service"). False + reason otherwise; always true elsewhere.
// The description text of an installed service (Windows: SERVICE_CONFIG_DESCRIPTION; elsewhere empty). Empty when unreadable.
std::string service_description(const std::string& name);
bool service_runs_program(const std::string& name, const std::string& exe_path, std::string* err = nullptr);
// Windows: gives an existing service a new password for its account (the user changed it). Wipes `password`.
bool service_set_password(const std::string& name, const std::string& account, std::string& password, std::string* err = nullptr);

// Pure text generator (available on every platform, used by service_install on Linux and by tests).
// Throws Error on an invalid name/user/path/exe (injection guard).
struct SystemdOptions {
    std::string group;                       // Group= ("" = none)
    std::string runtime_dir = "mysync";      // RuntimeDirectory= (one path component)
    std::string runtime_dir_mode = "0750";
    // Per-user flavour (Simple mode): the extra hardening a service that runs as an ordinary user can afford - no capabilities,
    // no namespaces, kernel log / clock / hostname / foreign /proc untouchable, umask 0077. (SystemCallFilter=-service is
    // deliberately NOT set: it could not be validated against the engine's inotify / flock / socket use without a real systemd,
    // and an unvalidated filter would make a working service fail in the field.)
    bool strict_user = false;
};
std::string systemd_unit_text(const std::string& name, const std::string& exe,
                              const std::vector<std::string>& args, const std::string& user,
                              const std::vector<std::string>& read_write_paths = {},
                              const std::string& description = "", const SystemdOptions& opts = {});

// Windows: connects to the SCM (StartServiceCtrlDispatcher), runs body on the service thread with a
// stop flag that STOP/SHUTDOWN sets, reports status. Returns the process exit code (0 ok, 1 error or
// not launched by the SCM). Linux: runs body in the foreground (systemd supervises), SIGTERM/SIGINT
// set stop. Body exceptions are logged and give exit code 1.
int run_as_service(const std::string& name, std::function<void(std::atomic<bool>& stop)> body);

// Stand-alone mode: Ctrl+C / Ctrl+Break / console close (Windows) or SIGINT / SIGTERM / SIGHUP
// (POSIX) set `stop` (which must outlive the process' signal handling); SIGPIPE is ignored.
void install_signal_handlers(std::atomic<bool>& stop);

}  // namespace mysync
