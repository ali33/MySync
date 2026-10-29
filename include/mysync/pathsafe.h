// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// pathsafe.h - CONTRACT header: safe handling of relative paths received from the peer.
// All inputs/outputs that are strings are UTF-8 with '/' separators.
#include <filesystem>
#include <string>

#include "mysync/util.h"

namespace mysync {

// Joins an untrusted relative path onto root. Throws Error when rel is: empty (or only "."), absolute,
// contains ".." / drive letter / UNC / ':' (ADS) / NUL / control characters / characters <>"|?* ,
// a Windows reserved device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, also COM/LPT + superscript 1/2/3
// (U+00B9 U+00B2 U+00B3), any case, also with an extension) in any component, a component ending in space or '.', or invalid UTF-8. '\\' is treated as a separator.
// After joining, symlinks of the deepest existing ancestor are resolved (weakly_canonical) and the
// result must still lie inside root; a dangling symlink as the last component is checked the same way.
std::filesystem::path safe_join(const std::string& root_utf8, const std::string& rel_utf8);

// '\\' -> '/', drops "." components and duplicate/trailing '/'. Does NOT resolve or hide "..".
// A leading '/' is preserved so that absolute paths stay recognisable.
std::string normalize_rel(const std::string& rel_utf8);

// True when the first component of rel is "__sync" (compared case-insensitively: Windows/macOS file
// systems would otherwise let "__SYNC" reach the same directory). U+017F (long s) and U+212A (Kelvin sign) count as
// 's' / 'k' because case-insensitive file systems fold them to those letters.
bool is_internal_dir(const std::string& rel_utf8);

// True when any component of rel starts with ".mysync-tmp-" (our temp files; same folding as is_internal_dir).
bool has_tmp_component(const std::string& rel_utf8);

// Relative UTF-8 path with '/' of abs under root. Throws Error when abs is not inside root.
std::string to_rel(const std::filesystem::path& root, const std::filesystem::path& abs);

} // namespace mysync
