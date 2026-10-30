// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// linkcheck.h - "no links on the way to a synchronised root".
// A symbolic link, junction or mount point in ANY component of a watch / target root could send the engine anywhere, so
// the roots are checked component by component (lstat on POSIX; on Windows only reparse points that are name
// redirections - symbolic links and junctions/mount points - count: cloud-files placeholders such as OneDrive are NOT
// links). This is a check, not a sandbox: a swap between the check and the use is narrower but not impossible (the lock
// file and the scan use openat/O_NOFOLLOW where they can; see docs/DESIGN.md).
#include <string>

namespace mysync {

// "" when no existing component of `path` is a link; else the offending path (the first one, from the root down).
std::string link_component(const std::string& utf8_path);
// Like link_component but for the verdict text a user reads: "'X' is a link (symbolic link / junction); links are not
// followed" or "".
std::string link_refusal_text(const std::string& utf8_path);

}  // namespace mysync
