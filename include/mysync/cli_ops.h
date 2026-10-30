// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// cli_ops.h - the scriptable, non-interactive commands for running MySync between servers (Ansible, shell, cron,
// monitoring): keygen, key show / key rotate, peer add|remove|revoke|retire-key|list, status --json, health.
//
// Exit codes (stable, documented in docs/SERVER-TO-SERVER.md):
//   0  success (including "nothing to change": every command that edits is idempotent)
//   1  runtime failure (a file could not be written, ...)
//   2  wrong arguments, conflicting or invalid configuration
//   10 something changed - ONLY when --changed-exit is given (otherwise 0)
// `health` has its own scale: 0 healthy, 1 warning, 2 critical.
#include <string>
#include <vector>

namespace mysync {

// args[0] = program, args[1] = the command (keygen | key | peer | status | health), the rest its arguments.
int cli_ops_main(const std::vector<std::string>& args);

}  // namespace mysync
