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
void require_trusted_config(const std::string& config_path, const std::vector<std::string>& trusted_writers);
// A directory the daemon writes into (state_dir) or whose child it writes (log_file's parent). A missing one is ignored.
void require_trusted_dir(const std::string& dir, const std::string& what, const std::vector<std::string>& trusted_writers);

// Syntax check of one --trust-writer entry (no quotes / control characters / leading '-', at most 256 bytes).
bool valid_trust_writer_entry(const std::string& entry);

// Same invariant for the executable that gets elevated: owned and writable only by the administrators.
// Windows: file and parent writable only by SYSTEM / Administrators / TrustedInstaller, owned by one of them.
// POSIX: the real path equals the given path (no symlink anywhere), file and every parent directory owned by root and
// not writable by group/other. Returns "" or the reason.
std::string untrusted_executable_reason(const std::string& exe);

namespace detail {
// Windows: normalised SID string for "S-1-5-..." or an account name; elsewhere returns the input.
std::string resolve_principal_sid(const std::string& entry);
}

}  // namespace mysync::gui
