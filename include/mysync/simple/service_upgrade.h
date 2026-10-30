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

#include "mysync/gui/service_ctl.h"
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
struct MigrationSummary {
    std::vector<std::string> sources;       // folders that would be read with the service's rights
    std::vector<std::string> destinations;  // folders / machines written to
    std::string key_identity;               // short fingerprint of the key the service would use
    std::string service_account;            // "LocalSystem" / "root"
    std::vector<std::string> warnings;      // plain-language cautions to show
    std::vector<std::string> problems;      // non-empty = the migration will be refused; first one is shown to the user
};
MigrationSummary summarize_user_config(const UserPaths& paths);  // throws Error when the configuration cannot be read

// Folders a user configuration may not hand to the service: inside a system folder, or inside the profile of ANOTHER
// user. (Links anywhere on the way are refused separately, on the real file system.)
struct PathPolicy {
    std::vector<std::string> forbidden_roots;
    std::string homes_root;  // parent of all profiles ("C:\Users", "/home")
    std::string own_home;    // the profile of the user who asked
};
PathPolicy default_path_policy();
std::string forbidden_service_path_reason(const std::string& path, const PathPolicy& policy);  // "" = acceptable


// The real implementation (Supervisor + ServiceController). service_name defaults to "mysync-client".
std::unique_ptr<UpgradeSteps> make_real_upgrade_steps(Supervisor& sup, gui::ServiceController& ctl, const UserPaths& paths,
                                                      const std::string& service_name = "mysync-client");

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
