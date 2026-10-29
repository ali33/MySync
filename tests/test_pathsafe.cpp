// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>

#include "mysync/pathsafe.h"
#include "testing.h"

using namespace mysync;
namespace fs = std::filesystem;

namespace {
struct TmpDir {
    fs::path p;
    TmpDir() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~TmpDir() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
};
}  // namespace

TEST(pathsafe_accepts_normal) {
    TmpDir t;
    std::string root = t.p.u8string();
    fs::path r = safe_join(root, "a/b/c.txt");
    CHECK(r == t.p / "a" / "b" / "c.txt");
    CHECK(safe_join(root, "./a//b/./c.txt") == t.p / "a" / "b" / "c.txt");
    CHECK(safe_join(root, "a\\b") == t.p / "a" / "b");
    CHECK(safe_join(root, "tệp/ảnh ✓.png") == t.p / fs::u8path("tệp") / fs::u8path("ảnh ✓.png"));
}

TEST(pathsafe_attacks) {
    TmpDir t;
    std::string root = t.p.u8string();
    const char* bad[] = {
        "",
        ".",
        "./",
        "../x",
        "a/../../x",
        "a/..",
        "..",
        "/etc/passwd",
        "\\windows\\system32",
        "C:\\x",
        "C:x",
        "c:/x",
        "\\\\server\\share\\x",
        "//server/share/x",
        "a/CON",
        "con",
        "a/con.txt",
        "NUL.tar.gz",
        "a/PRN",
        "AUX",
        "COM1",
        "a/com9.txt",
        "LPT1",
        "lpt9.log",
        "a/b:stream",
        "a/b:$DATA",
        "a\\..\\..\\x",
        "a/b./c",
        "a/b /c",
        "a/b.",
        "a/b ",
        "a/<b",
        "a/b>",
        "a/b|c",
        "a/b?c",
        "a/b*c",
        "a/\"b",
    };
    for (const char* b : bad) {
        bool threw = false;
        try {
            safe_join(root, b);
        } catch (const Error&) {
            threw = true;
        }
        if (!threw) throw mytest::Failure{std::string("accepted bad path: ") + b};
    }
    CHECK_THROWS(safe_join(root, std::string("a\0b", 3)));
    CHECK_THROWS(safe_join(root, "a/\x01" "b"));
    CHECK_THROWS(safe_join(root, "a/\x7f"));
    CHECK_THROWS(safe_join(root, "a/\xff\xfe"));            // invalid UTF-8
    CHECK_THROWS(safe_join(root, "a/\xc0\xaf"));            // overlong '/'
    CHECK_THROWS(safe_join(root, "a/\xed\xa0\x80"));        // surrogate
    CHECK_THROWS(safe_join(root, "a/\xf4\x90\x80\x80"));    // > U+10FFFF
    CHECK_THROWS(safe_join(root, "a/\xe2\x82"));            // truncated
    CHECK_THROWS(safe_join("", "a"));
}

TEST(pathsafe_names_that_look_bad_but_are_fine) {
    TmpDir t;
    std::string root = t.p.u8string();
    CHECK_EQ(safe_join(root, "console.txt").filename().string(), std::string("console.txt"));
    CHECK_EQ(safe_join(root, "COM10").filename().string(), std::string("COM10"));
    CHECK_EQ(safe_join(root, "a..b").filename().string(), std::string("a..b"));
    CHECK_EQ(safe_join(root, "..a").filename().string(), std::string("..a"));
    CHECK_EQ(safe_join(root, "nul_file").filename().string(), std::string("nul_file"));
}

TEST(pathsafe_normalize_rel) {
    CHECK_EQ(normalize_rel("a\\b\\c"), std::string("a/b/c"));
    CHECK_EQ(normalize_rel("./a//b/./c/"), std::string("a/b/c"));
    CHECK_EQ(normalize_rel("a/../b"), std::string("a/../b"));  // must not hide ".."
    CHECK_EQ(normalize_rel("../x"), std::string("../x"));
    CHECK_EQ(normalize_rel("/etc/passwd"), std::string("/etc/passwd"));
    CHECK_EQ(normalize_rel(""), std::string(""));
    CHECK_EQ(normalize_rel("."), std::string(""));
}

TEST(pathsafe_is_internal_dir) {
    CHECK(is_internal_dir("__sync"));
    CHECK(is_internal_dir("__sync/__trash/x"));
    CHECK(is_internal_dir("./__sync/a"));
    CHECK(is_internal_dir("__sync\\a"));
    CHECK(is_internal_dir("__SYNC/a"));
    CHECK(!is_internal_dir("a/__sync"));
    CHECK(!is_internal_dir("__syncx/a"));
    CHECK(!is_internal_dir(""));
}

TEST(pathsafe_to_rel) {
    TmpDir t;
    fs::create_directories(t.p / "a" / "b");
    CHECK_EQ(to_rel(t.p, t.p / "a" / "b" / "c.txt"), std::string("a/b/c.txt"));
    CHECK_EQ(to_rel(t.p, t.p / fs::u8path("tệp") / "x"), std::string("tệp/x"));
    CHECK_THROWS(to_rel(t.p, t.p.parent_path() / "other"));
    CHECK_THROWS(to_rel(t.p, t.p));
    // sibling directory sharing a name prefix must not count as inside
    CHECK_THROWS(to_rel(t.p, fs::path(t.p.string() + "-evil") / "x"));
}

TEST(pathsafe_symlink_escape) {
    TmpDir t, outside;
    fs::path root = t.p / "root";
    fs::create_directories(root);
    std::error_code ec;
    fs::create_directory_symlink(outside.p, root / "link", ec);
    if (ec) {
        std::cout << "  (symlink creation not permitted here: " << ec.message() << " - skipped)\n";
        return;
    }
    std::string r = root.u8string();
    CHECK_THROWS(safe_join(r, "link/secret.txt"));
    CHECK_THROWS(safe_join(r, "link/new/deeper/file"));
    CHECK_THROWS(safe_join(r, "link"));

    // symlink to a directory inside root is fine
    fs::create_directories(root / "real");
    fs::create_directory_symlink(root / "real", root / "inlink", ec);
    if (!ec) CHECK(safe_join(r, "inlink/f.txt") == root / "inlink" / "f.txt");

    // dangling symlink pointing outside root
    fs::create_symlink(outside.p / "not-yet", root / "dangling", ec);
    if (!ec) CHECK_THROWS(safe_join(r, "dangling"));

    // existing normal paths still fine
    fs::create_directories(root / "sub");
    CHECK(safe_join(r, "sub/new.txt") == root / "sub" / "new.txt");
}
