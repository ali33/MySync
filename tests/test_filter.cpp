// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/filter.h"
#include "testing.h"

using namespace mysync;

namespace {
constexpr int64_t kSec = 1000000000LL;
}

TEST(filter_default_takes_everything_but_temp_and_internal) {
    Filter f;
    CHECK(f.match("a.txt", 1, 0));
    CHECK(f.match("dir/sub/readme", 1, 0));
    CHECK(!f.match("a.tmp", 1, 0));
    CHECK(!f.match("A.TMP", 1, 0));
    CHECK(!f.match("dir/~$report.docx", 1, 0));
    CHECK(!f.match("dir/file.txt~", 1, 0));
    CHECK(!f.match("x.d$c", 1, 0));
    CHECK(!f.match("x.d#c", 1, 0));
    CHECK(!f.match(".mysync-tmp-1234", 1, 0));
    CHECK(!f.match("d/.mysync-tmp-abc", 1, 0));
    CHECK(!f.match("__sync/trash/a.txt", 1, 0));
    CHECK(!f.match("d/__sync/a.txt", 1, 0));
    CHECK(f.match("__sync2/a.txt", 1, 0));
    CHECK(!f.match("", 1, 0));
    CHECK(!f.match_dir("__sync"));
    CHECK(!f.match_dir("a/__sync"));
    CHECK(f.match_dir("a/b"));
}

TEST(filter_is_temp_name) {
    CHECK(is_temp_name("~$a.docx"));
    CHECK(is_temp_name("a.tmp"));
    CHECK(is_temp_name("a.txt~"));
    CHECK(is_temp_name(".#lock"));
    CHECK(is_temp_name("#auto#"));
    CHECK(is_temp_name(".mysync-tmp-9"));
    CHECK(!is_temp_name("a.txt"));
    CHECK(!is_temp_name("tmp"));
    CHECK(!is_temp_name("C#notes"));  // '#' before the extension dot only
    CHECK(!is_temp_name(""));
}

TEST(filter_include_extension_and_glob) {
    FilterConfig c;
    c.include = {".txt", "*.docx", "docs/**/*.pdf", "Makefile"};
    Filter f(c);
    CHECK(f.match("a.txt", 1, 0));
    CHECK(f.match("deep/dir/A.TXT", 1, 0));
    CHECK(f.match("x/report.docx", 1, 0));
    CHECK(f.match("docs/a.pdf", 1, 0));
    CHECK(f.match("docs/x/y/a.pdf", 1, 0));
    CHECK(!f.match("other/a.pdf", 1, 0));
    CHECK(!f.match("a.png", 1, 0));
    CHECK(f.match("sub/makefile", 1, 0));
    CHECK(!f.includes_all());
}

TEST(filter_glob_semantics) {
    FilterConfig c;
    c.include = {"src/*.cpp", "a?c.h", "**/gen/*.c"};
    Filter f(c);
    CHECK(f.match("src/x.cpp", 1, 0));
    CHECK(!f.match("src/sub/x.cpp", 1, 0));  // '*' does not cross '/'
    CHECK(f.match("abc.h", 1, 0));
    CHECK(f.match("d/a_c.h", 1, 0));
    CHECK(!f.match("abbc.h", 1, 0));
    CHECK(f.match("gen/a.c", 1, 0));
    CHECK(f.match("x/y/gen/a.c", 1, 0));
    CHECK(!f.match("xgen/a.c", 1, 0));
}

TEST(filter_regex_on_relative_path) {
    FilterConfig c;
    c.include_regex = {"^reports/.*\\.csv$"};
    c.exclude_regex = {"/old/"};
    Filter f(c);
    CHECK(f.match("reports/2026/a.csv", 1, 0));
    CHECK(!f.match("reports/old/a.csv", 1, 0));
    CHECK(!f.match("other/a.csv", 1, 0));
    FilterConfig bad;
    bad.exclude_regex = {"(unclosed"};
    CHECK_THROWS(Filter(bad));
    FilterConfig bad2;
    bad2.include_regex = {"[a-"};
    CHECK_THROWS(Filter(bad2));
}

TEST(filter_exclude_substring_case_insensitive) {
    FilterConfig c;
    c.exclude = {"Backup", "node_modules"};
    Filter f(c);
    CHECK(!f.match("my/BACKUP/a.txt", 1, 0));
    CHECK(!f.match("x/Node_Modules/y.js", 1, 0));
    CHECK(f.match("x/y.js", 1, 0));
    CHECK(!f.match_dir("proj/node_modules"));
    CHECK(f.match_dir("proj/src"));
}

TEST(filter_size_bounds) {
    FilterConfig c;
    c.size_min = "1KB";
    c.size_max = "2MB";
    Filter f(c);
    CHECK(!f.match("a", 1023, 0));
    CHECK(f.match("a", 1024, 0));
    CHECK(f.match("a", 2 * 1024 * 1024, 0));
    CHECK(!f.match("a", 2 * 1024 * 1024 + 1, 0));
    CHECK_EQ(parse_size("1.5GB"), uint64_t(1610612736));
    CHECK_EQ(parse_size("512"), uint64_t(512));
    CHECK_EQ(parse_size("64 KiB"), uint64_t(65536));
    CHECK_THROWS(parse_size("10XB"));
    CHECK_THROWS(parse_size(""));
    CHECK_THROWS(parse_size("MB"));
    FilterConfig inverted;
    inverted.size_min = "2MB";
    inverted.size_max = "1MB";
    CHECK_THROWS(Filter(inverted));
}

TEST(filter_mtime_relative_and_absolute) {
    int64_t now = now_unix_ns();
    FilterConfig c;
    c.mtime_after = "7d";
    Filter recent(c);
    CHECK(recent.match("a", 1, now - 3 * 86400 * kSec));
    CHECK(!recent.match("a", 1, now - 9 * 86400 * kSec));

    FilterConfig o;
    o.mtime_before = "12h";
    Filter old(o);
    CHECK(old.match("a", 1, now - 13 * 3600 * kSec));
    CHECK(!old.match("a", 1, now - 1 * 3600 * kSec));

    FilterConfig a;
    a.mtime_after = "2026-01-01T00:00:00";
    Filter abs(a);
    CHECK(abs.match("a", 1, now));  // today is after 2026-01-01
    CHECK(!abs.match("a", 1, 1000 * kSec));
    CHECK_THROWS(Filter([] { FilterConfig b; b.mtime_after = "yesterday"; return b; }()));
    CHECK_THROWS(Filter([] { FilterConfig b; b.mtime_after = "2026-13-01T00:00:00"; return b; }()));
}
