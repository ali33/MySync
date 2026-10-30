// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/service_upgrade.h - "Keep syncing even when nobody is logged in": move from the per-user engine to the
// system service, and back.
//   user -> service: preconditions -> stop the user engine and wait until its folder locks are free -> migrate the
//   configuration to the trusted service location through an ELEVATED `mysync service migrate-from-user` (UAC /
//   pkexec via ServiceController) -> service install (validate_install_inputs) -> start -> report; the GUI then
//   watches the service.
//   service -> user: stop and uninstall the service, copy the configuration back to the user folder, start the
//   user engine.
// Every step can fail; the failure undoes what was done so that there are never two engines and no configuration is
// lost. The steps are behind an interface so the logic is tested with a fake (the real service is never installed in
// tests).
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "mysync/config.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/keys.h"
#include "mysync/simple/user_engine.h"
#include "mysync/simple/user_paths.h"

namespace mysync::simple {

enum class UpgradeStep {
    Preconditions, StopUserEngine, MigrateConfig, InstallService, StartTheService,  // user -> service
    StopService, UninstallService, RestoreConfig, StartUserEngine,               // service -> user
    Done,
};
const char* upgrade_step_name(UpgradeStep);

struct UpgradeResult {
    bool ok = false;
    bool cancelled = false;  // the user dismissed UAC / pkexec; nothing was changed
    UpgradeStep failed_step = UpgradeStep::Done;
    std::string error;           // verbatim
    bool rolled_back = false;    // the previous arrangement is running again
    std::string rollback_error;  // set if the rollback itself failed (then the text tells what is left)
    std::vector<std::string> log;  // one line per step taken / undone
};

// The side effects, replaceable by a fake in tests. Every method throws Error with a verbatim message.
class UpgradeSteps {
public:
    virtual ~UpgradeSteps() = default;
    virtual std::string check_preconditions(bool to_service) = 0;  // "" or the reason (no config, already a service ...)
    virtual void stop_user_engine() = 0;                            // returns when the folder locks are released
    virtual void start_user_engine() = 0;
    // Elevated. *cancelled = true means the prompt was dismissed (nothing changed).
    virtual void migrate_config_to_service(bool* cancelled) = 0;
    virtual void remove_migrated_config() = 0;  // undo of the above (the real one leaves the private copy: harmless)
    virtual void install_service(bool* cancelled) = 0;
    virtual void uninstall_service(bool* cancelled) = 0;
    virtual void start_service(bool* cancelled) = 0;
    virtual void stop_service(bool* cancelled) = 0;
    virtual void restore_config_from_service() = 0;  // copy back to the user folder
    virtual bool service_running() = 0;
    virtual bool service_installed() = 0;
};

UpgradeResult upgrade_to_service(UpgradeSteps& s, const std::function<void(UpgradeStep)>& progress = {});
struct DowngradeOptions {
    // After the switch back, also delete the service's private copy of the configuration and the key (one more
    // elevation prompt; best effort - a failure is only noted in the log).
    bool remove_service_copy = false;
};
UpgradeResult downgrade_to_user(UpgradeSteps& s, const std::function<void(UpgradeStep)>& progress = {},
                                const DowngradeOptions& opts = {});

// What the service would be allowed to touch, as plain data for the GUI to show BEFORE the UAC / pkexec prompt, and the
// reasons it would be refused. The elevated helper repeats the same checks on its own.
// Who really asked for an elevated action (Linux). pkexec execs the target directly (a parent check proves nothing) but it
// sets PKEXEC_UID itself and cleans the rest of the environment, so the variable is believed only by a process that IS
// root (uid and euid 0) - a plain user cannot have been through pkexec - and then cross-checked: a number, not 0, equal to
// SUDO_UID when that is set too, equal to the owner of the configuration file being migrated, and (if the kernel keeps
// it) to /proc/self/loginuid, which only disagrees with a warning (su / ssh sessions).
struct InvokerInput {
    std::string sudo_uid, pkexec_uid;  // the environment variables ("" = not set)
    uint32_t uid = 0, euid = 0;
    int64_t loginuid = -1;             // -1 = unknown; 4294967295 = "unset" in the kernel
    int64_t file_owner = -1;           // owner of the file being migrated, -1 = unknown
};
struct InvokerResult {
    bool ok = false;
    uint32_t uid = 0;
    std::string error, warning;
};
InvokerResult resolve_invoking_uid(const InvokerInput& in);

struct MigrationSummary {

    std::vector<std::string> sources;       // folders that would be read with the service's rights
    std::vector<std::string> destinations;  // folders / machines written to
    std::string key_identity;               // short fingerprint of the key the service would use
    std::string service_account;            // "LocalSystem" / "root"
    std::vector<std::string> warnings;      // plain-language cautions to show
    std::vector<std::string> problems;      // non-empty = the migration will be refused; first one is shown to the user
    // Local folders outside the user's home that are otherwise acceptable: the GUI lists them, and only when the user
    // agrees passes them as allow roots (make_real_upgrade_steps / ServiceRequest::allow_roots).
    std::vector<std::string> needs_confirmation;
    std::string config_hash, key_hash;      // BLAKE3 hex of the exact bytes the summary was made from (see --expect-hash)
};
// Everything the elevated step decides BEFORE it writes anything, as one function (so it can be tested without admin
// rights): one checked read of the configuration, the hash against what the user was shown, the parse FROM THOSE BYTES, the
// path allowlist, one checked read of the key and its hash. Throws Error with the verbatim reason.
struct MigrationPlan {
    ClientConfig config;   // absolute paths, still the user's key / state / log
    std::string user_key;  // absolute path of the key the configuration names
    KeyPair key;
    uint32_t who = 0;      // POSIX: the uid of the user who asked (from resolve_invoking_uid); 0 on Windows
};
MigrationPlan plan_migration(const std::string& user_config, const std::string& expect_hash, const std::string& expect_key_hash,
                             const std::vector<std::string>& allow_roots);

MigrationSummary summarize_user_config(const UserPaths& paths, const std::vector<std::string>& allow_roots = {});  // throws Error when the configuration cannot be read

// ALLOWLIST of the folders a user configuration may hand to the service. After canonicalisation (links, junctions, 8.3
// names and \\?\ resolved; a part that does not exist yet is appended to its deepest existing parent) a local folder
// must lie, by path components and without regard to case on Windows, inside
//   (a) the user's own home / profile, or
//   (b) one of `allow_roots`, folders the user confirmed explicitly.
// Never allowed, whatever the allow roots say: a whole drive or "/", system folders (/etc /usr /var /opt /srv /mnt /boot
// /root ..., Windows SystemRoot, Program Files*, ProgramData), the folder of all profiles and the profile of another user.
// UNC paths are outside (a) and need (b). Links on the way are refused separately, on the real file system.
struct PathPolicy {
    std::vector<std::string> forbidden_roots;
    std::string homes_root;  // parent of all profiles ("C:\\Users", "/home")
    std::string own_home;    // the profile of the user who asked
    std::vector<std::string> allow_roots;
    bool canonicalize = true;  // false: purely lexical (unit tests)
};
struct PathVerdict {
    bool ok = false;
    bool confirmable = false;  // refused only for being outside the home: an allow root could fix that
    std::string reason;
};
std::string canonical_for_policy(const std::string& path);
PathVerdict service_path_verdict(const std::string& path, const PathPolicy& policy);
// "" or why `root` cannot be an allow root (drive root, system folder, another profile ...).
std::string allow_root_problem(const std::string& root, const PathPolicy& policy);
PathPolicy default_path_policy();
std::string forbidden_service_path_reason(const std::string& path, const PathPolicy& policy);  // "" = acceptable


// The real implementation (Supervisor + ServiceController). service_name defaults to "mysync-client".
std::unique_ptr<UpgradeSteps> make_real_upgrade_steps(Supervisor& sup, gui::ServiceController& ctl, const UserPaths& paths,
                                                      const std::string& service_name = "mysync-client",
                                                      const std::vector<std::string>& allow_roots = {});

// The service-side locations used by migration (Windows %ProgramData%\MySync\, Linux /etc/mysync + /var/lib/mysync).
struct ServiceLocations {
    std::string dir, config, key, state, log;
};
ServiceLocations service_locations(const std::string& service_name);

// `mysync service migrate-from-user --user-config <path> [--name n]` (or `--remove --name n` to delete the private copy): runs ELEVATED. Verifies that the source is
// a regular file owned by the calling (original) user and parses, then writes the copy (config, key) into the trusted
// location with an admin-only ACL / root ownership. Returns the process exit code (ServiceExit values).
int run_migrate_from_user(const std::vector<std::string>& args);

}  // namespace mysync::simple
