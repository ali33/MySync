// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/service_ctl.h - query and control the MySync service (Windows SCM / systemd) from an unprivileged GUI.
//
// query() never needs elevation. install / uninstall / start / stop run in-process when the GUI is already
// administrator / root; otherwise the controller re-runs `mysync service <action> ...` elevated:
//   Windows: ShellExecuteExW verb "runas" (UAC prompt), waits for the child, reads its exit code.
//   Linux  : `pkexec <mysync> service <action> ...` with stdout+stderr captured through a pipe.
// No shell is ever involved: the argument vector is built from validated pieces (service name [A-Za-z0-9_.-],
// absolute existing config path, whitelisted role / account / control-allow characters) and, on Windows, quoted
// with CommandLineToArgvW rules. The elevated child reports through a NAMED EXIT CODE (ServiceExit) and the
// controller re-queries the real state afterwards; no temp file or pipe name that a lower-privileged process could
// plant is used on Windows. The executable that gets elevated must be an absolute path to a file called
// mysync / mysync.exe (on POSIX not writable by group/other).
// A cancelled UAC / pkexec prompt gives ServiceResult::cancelled = true (never an exception).
#include <string>
#include <vector>

#include "mysync/simple/service_account.h"
#include "mysync/util.h"

namespace mysync::gui {

// Entry for `[control] allow` / `--control-allow`: a SID ("S-1-5-...") or an account name; no quotes, control
// characters, option-looking text, at most 256 bytes.
bool valid_control_allow_entry(const std::string& entry);

// MigrateFromUser: `mysync service migrate-from-user` - copies a per-user configuration (and its key) into the trusted
// service location (simple mode, see simple/service_upgrade.h). It needs ServiceRequest::user_config and name.
// SetPassword (Windows): gives the service a new password for its account after the user changed theirs; the password
// goes through the private channel of simple/service_account.h, like at install.
// ApplyConfig: a new configuration for a Windows service that runs as an administrator-capable account. Its folder is
// writable only by administrators, so a changed configuration is checked (allowlist, hash) and installed by the elevated step
// (`mysync service apply-config`), exactly like migrate-from-user but keeping the key.
enum class ServiceAction { Install, Uninstall, Start, Stop, MigrateFromUser, SetPassword, ApplyConfig };
const char* service_action_name(ServiceAction);  // "install" ...

// Exit codes of `mysync service <action>` (0 = success). Stable: the GUI maps them to messages.
enum ServiceExit : int {
    kServiceOk = 0,
    kServiceGenericFailure = 1,
    kServiceBadArguments = 20,
    kServiceAccessDenied = 21,
    kServiceNotInstalled = 22,
    kServiceAlreadyInstalled = 23,
    kServiceTimeout = 24,
    kServiceConfigError = 25,
    kServiceCancelled = 126,   // pkexec: dismissed / not authorised (also used for UAC cancel internally)
};
// Classifies the error text of service_install/start/... (service.h) into a ServiceExit code.
int service_exit_code_for_error(const std::string& err);
// Human message for a code (English; the GUI may translate by code).
std::string service_exit_message(int code);

struct ServiceState {
    bool installed = false;
    bool running = false;
    bool auto_start = false;     // starts at boot
    std::string description;     // Windows service description / Linux unit Description= (carries the owner label)
    // Windows: the service stopped with "logon failure" (1069): the account's password changed. The GUI shows how to fix
    // it and calls run(ServiceAction::SetPassword, ...) with the new password.
    bool needs_password_update = false;
    std::string detail;          // raw one-liner, e.g. "RUNNING" / "active" ("" when unknown)
    std::string error;           // set when the state could not be determined
};

struct ServiceRequest {
    std::string name;                         // service name, required
    // migrate-from-user: the elevated step uses exactly the bytes that were summarised (BLAKE3 hex of the configuration and
    // of the key file) and only the extra folders the user confirmed.
    std::string expect_config_hash, expect_key_hash;
    std::vector<std::string> allow_roots;
    bool remove_migrated = false;             // migrate-from-user: delete the service's copy instead (no user_config)
    std::string user_config;                  // migrate-from-user: absolute path of the user's configuration file
    std::string config_path;                  // install: absolute path of the config file
    std::string role;                         // install: "server" | "client" | "" (auto from the config)
    std::string run_as;                       // install: Windows account / Linux user ("" = default)
    // Windows, Install / SetPassword for a user account: the password (borrowed, not copied; the caller wipes it). It is
    // NEVER put on a command line: run() hands it to the elevated step through a private pipe.
    const simple::SecretString* password = nullptr;
    // Install: the Simple-mode flavour (a service that runs as the user, with its own runtime folder). The system-wide
    // flavour installed by an administrator with `mysync service install` is not touched by this.
    bool user_service = false;
    std::string password_pipe, password_nonce;   // set by run() itself (public so build_args can be tested)
    // d8 (Windows): the account of the user who pressed the button in the GUI. The elevated step may run under another
    // administrator's account; it takes THIS SID as the account the service belongs to and proves it (the private pipe's
    // server process must carry it; the password must log on as it). Set by run() from the current user.
    std::string requester_sid;
    std::vector<std::string> control_allow;   // install: SIDs / accounts to add to [control] allow (and to the trusted writers)
    std::vector<std::string> trust_writers;   // install: further accounts allowed to change the configuration (--trust-writer)
};

struct ServiceResult {
    bool ok = false;
    bool cancelled = false;      // the user dismissed the UAC / pkexec prompt
    bool elevated = false;       // had to go through UAC / pkexec
    int exit_code = 0;           // ServiceExit
    std::string message;         // human text; on Linux also the verbatim output of the child
    ServiceState state_after;    // re-queried after the action
};

class ServiceController {
public:
    // mysync_exe: absolute path of the mysync executable ("" = the file called mysync[.exe] next to this process).
    // Throws Error when it does not pass the checks above.
    explicit ServiceController(std::string mysync_exe = "");

    static bool valid_name(const std::string& name);
    static bool is_elevated();   // administrator (Windows token) / euid 0

    ServiceState query(const std::string& name) const;   // thread-safe, no elevation

    // Validated argument vector after the executable: {"service", "install", "-c", cfg, "--role", ..., "--name", n,
    // "--user", u, "--control-allow", x ...}. Throws Error for any invalid piece. Pure: usable in tests.
    std::vector<std::string> build_args(ServiceAction, const ServiceRequest&) const;

    ServiceResult run(ServiceAction, const ServiceRequest&);   // blocks until the child ends; call from a worker thread

    const std::string& exe() const { return exe_; }

private:
    std::string exe_;
};

}  // namespace mysync::gui
