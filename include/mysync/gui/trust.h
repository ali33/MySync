// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/trust.h - who may change what a privileged daemon / installer trusts.
//
// A daemon that runs as a service (or as root / administrator) must not obey a configuration that an unrelated user
// can edit. Invariant (a WHITELIST): the configuration FILE and its PARENT DIRECTORY (and state_dir / the folder of
// log_file) may be changed only by the set T:
//   built in : the account running the daemon, SYSTEM / root, Administrators (Windows also TrustedInstaller);
//   by the administrator at install time : the `--trust-writer` entries of the service's command line
//   (`service install --control-allow X` adds X to them). The file being checked can NEVER enlarge T, and neither does
//   `[control] allow/group`: those only decide who may use the control pipe/socket.
// Entry syntax. Windows: "S-1-5-..." or an account/group name. POSIX: "uid:N", "gid:N", a user name, or "@group".
// POSIX rule: owner in T (root, the daemon's uid, a trusted uid); no write bit for "other"; a write bit for "group"
//   only when the file's group is a trusted gid; a symbolic link is refused; a sticky directory (like /tmp) is tolerated.
// Windows rule: every ACE that allows write / delete / change-permissions / take-ownership (incl. GENERIC_WRITE and
//   GENERIC_ALL) must belong to T, the owner must be in T, and conditional / object ACEs are refused outright.
// A violation is an Error whose message names the object, the offender and how to fix it.

#include <string>
#include <vector>

#include "mysync/util.h"

namespace mysync::gui {

// Returns "" when `path` (a file or a directory) is acceptable, else the reason.
// `include_self` = the account running this process counts as trusted (the normal case; tests turn it off).
std::string untrusted_writer_reason(const std::string& path, const std::vector<std::string>& trusted_writers,
                                    bool include_self = true);

// File + parent directory. Throws Error with the reason prefixed by what the file is ("configuration file ...").
// `include_self` as in untrusted_writer_reason.
void require_trusted_config(const std::string& config_path, const std::vector<std::string>& trusted_writers,
                            bool include_self = true);
// A directory the daemon writes into (state_dir) or whose child it writes (log_file's parent). A missing one is ignored.
void require_trusted_dir(const std::string& dir, const std::string& what, const std::vector<std::string>& trusted_writers);

// The one trust check a daemon / one-shot run performs: configuration file + folder, state_dir, folder of log_file.
// Used by ClientDaemon / ServerDaemon (start and every reload) and by `mysync run --once`.
void require_trusted_run(const std::string& config_path, const std::string& state_dir, const std::string& log_file,
                         const std::vector<std::string>& trusted_writers);

// Policy: the strict check applies when the process runs with high rights (Windows elevated token or SYSTEM / service,
// POSIX euid 0) or as a service (--service). A plain account running its own files keeps working (e.g. `run --once`).
bool need_strict_trust(bool elevated, bool service);

// A group that (nearly) every local user belongs to. Windows: SID or name, resolved to a SID and compared by SID
// (Everyone, Authenticated Users, BUILTIN\Users, Guests, Power Users, INTERACTIVE, Network, Anonymous, Local,
// Domain Users / Guests / Computers ...); POSIX: "users" / gid 100, "other(s)", "*", "everyone". Returns "" when the
// entry is not broad, else the reason (names the entry and why).
std::string broad_principal_reason(const std::string& entry);

// Everything `service install` must vet before anything is written, shared by the command line and ServiceController:
// the mysync executable (untrusted_executable_reason), no broad principal among trust_writers / control_allow, and the
// configuration (require_trusted_config, judged as the SERVICE will see it: the installing administrator does not
// count as trusted unless named; the service account `run_as` does). Returns "" or the reason.
std::string validate_install_inputs(const std::string& exe, const std::string& config_path,
                                    const std::vector<std::string>& trust_writers,
                                    const std::vector<std::string>& control_allow, const std::string& run_as);

// Syntax check of one --trust-writer entry (no quotes / control characters / leading '-', at most 256 bytes).
bool valid_trust_writer_entry(const std::string& entry);

// Same invariant for the executable that gets elevated: owned and writable only by the administrators.
// Windows: file and parent writable only by SYSTEM / Administrators / TrustedInstaller, owned by one of them.
// POSIX: the real path equals the given path (no symlink anywhere), file and every parent directory owned by root and
// not writable by group/other. Returns "" or the reason.
std::string untrusted_executable_reason(const std::string& exe);

namespace detail {
// True for the SID text of a broad group (also used by the control pipe's DACL builder).
bool is_broad_sid(const std::string& sid);
// Windows: normalised SID string for "S-1-5-..." or an account name; elsewhere returns the input.
std::string resolve_principal_sid(const std::string& entry);
}

}  // namespace mysync::gui
