// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// filter.h - decides which files take part in a sync.
#include <regex>
#include <string>
#include <vector>

#include "mysync/config.h"

namespace mysync {

class Filter {
public:
    // Throws Error on a bad regex, size or time expression.
    explicit Filter(const FilterConfig& cfg = FilterConfig());

    // rel_path_utf8 uses '/' separators. Always false for temp files and anything under "__sync".
    bool match(const std::string& rel_path_utf8, uint64_t size, int64_t mtime_ns) const;

    // Whether a directory may be descended into: false for "__sync", ".mysync-tmp-*" and when an
    // exclude substring already matches the directory path (then it matches everything below too).
    bool match_dir(const std::string& rel_path_utf8) const;

    // True when no include rule exists, i.e. empty directories may be mirrored too.
    bool includes_all() const { return include_ext_.empty() && include_glob_.empty() && include_re_.empty(); }

private:
    struct TimeBound {
        bool set = false;
        bool relative = false;  // value is a span in ns subtracted from "now" at match time
        int64_t value = 0;
    };
    std::vector<std::string> include_ext_;   // lower-case ".txt"
    std::vector<std::string> include_glob_;  // lower-case
    std::vector<std::regex> include_re_;
    std::vector<std::string> exclude_;       // lower-case substrings
    std::vector<std::regex> exclude_re_;
    bool has_size_min_ = false, has_size_max_ = false;
    uint64_t size_min_ = 0, size_max_ = 0;
    TimeBound after_, before_;
};

// Editor/Office/our own temporary names: ".mysync-tmp-*", "~$x", "x~", "x.tmp", extension containing '$' or '#'.
bool is_temp_name(const std::string& name);

// "1.5GB", "10MB", "512", "64 KiB" (units are 1024-based, case-insensitive). Throws Error.
uint64_t parse_size(const std::string& text);

} // namespace mysync
