// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>
#include <sstream>

#include "../src/fsutil.h"
#include "mysync/hash.h"
#include "mysync/localtarget.h"
#include "mysync/pathsafe.h"
#include "mysync/ratelimit.h"
#include "testing.h"

namespace fs = std::filesystem;
using namespace mysync;

namespace {

struct Tmp {
    fs::path root;
    Tmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        root = fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
        fs::create_directories(root);
    }
    ~Tmp() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    std::string sub(const std::string& n) const {
        fs::create_directories(root / n);
        return (root / n).u8string();
    }
};

void write_file(const fs::path& p, const std::string& data, bool old_mtime = true) {
    fs::create_directories(p.parent_path());
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f << data;
    }
    if (old_mtime) fs::last_write_time(p, fs::file_time_type::clock::now() - std::chrono::hours(2));
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

FileMeta meta_of(const std::string& rel, const fs::path& p) {
    FileMeta m;
    m.rel = rel;
    fsutil::FsStat st = fsutil::stat_path(p);
    m.size = st.size;
    m.mtime_ns = st.mtime_ns;
    m.hash = hash_file(p.u8string());
    return m;
}

size_t count_tmp(const fs::path& dir) {
    size_t n = 0;
    for (auto& e : fs::recursive_directory_iterator(dir))
        if (e.path().filename().u8string().rfind(".mysync-tmp-", 0) == 0) ++n;
    return n;
}

std::unique_ptr<ITarget> open_target(const std::string& dst, const std::string& state = "") {
    TargetConfig tc;
    tc.path = dst;
    auto t = make_local_target(tc, nullptr, state);
    t->open();
    return t;
}

}  // namespace

TEST(local_put_then_skip_identical) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "a" / "hello.txt";
    write_file(f, "hello world");
    FileMeta m = meta_of("a/hello.txt", f);
    auto t = open_target(dst);
    PutResult r1 = t->put_file("a/hello.txt", f.u8string(), m);
    CHECK(r1.status == PutResult::Sent);
    CHECK_EQ(r1.bytes_on_wire, 11u);
    CHECK_EQ(read_file(fs::u8path(dst) / "a" / "hello.txt"), std::string("hello world"));
    CHECK_EQ(fsutil::stat_path(fs::u8path(dst) / "a" / "hello.txt").mtime_ns, m.mtime_ns);
    PutResult r2 = t->put_file("a/hello.txt", f.u8string(), m);
    CHECK(r2.status == PutResult::Skipped);
    CHECK_EQ(r2.bytes_on_wire, 0u);
    CHECK_EQ(count_tmp(fs::u8path(dst)), 0u);
}

TEST(local_skip_fixes_mtime_only) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "x.txt";
    write_file(f, "same content");
    write_file(fs::u8path(dst) / "x.txt", "same content", false);  // identical bytes, different mtime
    FileMeta m = meta_of("x.txt", f);
    auto t = open_target(dst);
    PutResult r = t->put_file("x.txt", f.u8string(), m);
    CHECK(r.status == PutResult::Skipped);
    CHECK_EQ(fsutil::stat_path(fs::u8path(dst) / "x.txt").mtime_ns, m.mtime_ns);
}

TEST(local_changed_content_is_sent_and_replaces) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "d.bin";
    write_file(f, std::string(3 * 1024 * 1024 + 17, 'a'));  // > 1 MiB: several buffer rounds
    auto t = open_target(dst);
    CHECK(t->put_file("d.bin", f.u8string(), meta_of("d.bin", f)).status == PutResult::Sent);
    write_file(f, std::string(3 * 1024 * 1024 + 17, 'b'));
    FileMeta m2 = meta_of("d.bin", f);
    PutResult r = t->put_file("d.bin", f.u8string(), m2);
    CHECK(r.status == PutResult::Sent);
    CHECK_EQ(read_file(fs::u8path(dst) / "d.bin"), read_file(f));
    CHECK_EQ(count_tmp(fs::u8path(dst)), 0u);
}

TEST(local_source_changed_is_failed_without_leftovers) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "c.txt";
    write_file(f, "version one");
    FileMeta m = meta_of("c.txt", f);
    write_file(f, "version two!");  // changed after the caller hashed it
    auto t = open_target(dst);
    PutResult r = t->put_file("c.txt", f.u8string(), m);
    CHECK(r.status == PutResult::Failed);
    CHECK(!r.error.empty());
    CHECK(!fs::exists(fs::u8path(dst) / "c.txt"));
    CHECK_EQ(count_tmp(fs::u8path(dst)), 0u);
    // same size and mtime but different bytes: caught by the hash computed while copying
    write_file(f, "VERSION ONE");
    fs::last_write_time(f, fs::file_time_type::clock::now() - std::chrono::hours(2));
    FileMeta stale = meta_of("c.txt", f);
    stale.hash = hash_bytes("version one", 11);
    CHECK(t->put_file("c.txt", f.u8string(), stale).status == PutResult::Failed);
    CHECK(!fs::exists(fs::u8path(dst) / "c.txt"));
    CHECK_EQ(count_tmp(fs::u8path(dst)), 0u);
}

TEST(local_path_traversal_is_blocked) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("deep/dst");
    fs::path f = fs::u8path(src) / "e.txt";
    write_file(f, "evil");
    FileMeta m = meta_of("e.txt", f);
    auto t = open_target(dst);
    for (const char* bad : {"../escape.txt", "a/../../escape.txt", "..\\escape.txt", "/etc/escape.txt", "C:/escape.txt",
                            "a/b:ads", "CON"}) {
        PutResult r = t->put_file(bad, f.u8string(), m);
        CHECK(r.status == PutResult::Failed);
    }
    CHECK(!fs::exists(tmp.root / "deep" / "escape.txt"));
    CHECK(!fs::exists(tmp.root / "escape.txt"));
    CHECK_THROWS(t->remove_path("../src/e.txt", false));
    CHECK_THROWS(t->rename_path("../src/e.txt", "stolen.txt"));
    CHECK_THROWS(t->make_dir("../newdir"));
    CHECK(fs::exists(f));
    CHECK(!fs::exists(tmp.root / "deep" / "newdir"));
}

TEST(local_remove_goes_to_trash) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "dir" / "gone.txt";
    write_file(f, "bye");
    auto t = open_target(dst);
    CHECK(t->put_file("dir/gone.txt", f.u8string(), meta_of("dir/gone.txt", f)).status == PutResult::Sent);
    t->remove_path("dir/gone.txt", false);
    CHECK(!fs::exists(fs::u8path(dst) / "dir" / "gone.txt"));
    fs::path trash = fs::u8path(dst) / "__sync" / "__trash";
    CHECK(fs::exists(trash));
    bool found = false;
    for (auto& e : fs::recursive_directory_iterator(trash))
        if (e.path().filename() == "gone.txt") {
            found = true;
            CHECK_EQ(read_file(e.path()), std::string("bye"));
            CHECK(e.path().parent_path().filename() == "dir");
        }
    CHECK(found);
    t->remove_path("dir/gone.txt", false);  // already gone: no error
    // a whole directory
    write_file(fs::u8path(src) / "tree" / "one.txt", "1");
    write_file(fs::u8path(src) / "tree" / "sub" / "two.txt", "2");
    for (const char* r : {"tree/one.txt", "tree/sub/two.txt"})
        CHECK(t->put_file(r, (fs::u8path(src) / r).u8string(), meta_of(r, fs::u8path(src) / r)).status == PutResult::Sent);
    t->remove_path("tree", true);
    CHECK(!fs::exists(fs::u8path(dst) / "tree"));
    // the trash is internal: never listed
    for (auto& kv : t->list_remote()) CHECK(!is_internal_dir(kv.first));
}

TEST(local_rename_mkdir_list_and_prefix) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "old.txt";
    write_file(f, "content");
    TargetConfig tc;
    tc.path = dst;
    tc.remote_prefix = "backup/pc1";
    auto t = make_local_target(tc);
    t->open();
    CHECK(t->put_file("old.txt", f.u8string(), meta_of("old.txt", f)).status == PutResult::Sent);
    CHECK(fs::exists(fs::u8path(dst) / "backup" / "pc1" / "old.txt"));
    t->make_dir("empty/inner");
    t->rename_path("old.txt", "moved/new.txt");
    auto l = t->list_remote();
    CHECK(l.count("moved/new.txt") == 1);
    CHECK(l.count("old.txt") == 0);
    CHECK(l.count("empty/inner") == 1 && l["empty/inner"].is_dir);
    CHECK(l["moved/new.txt"].hash == hash_bytes("content", 7));
    CHECK_EQ(l["moved/new.txt"].size, 7u);
    t->rename_path("missing.txt", "x.txt");  // missing source: no-op
}

TEST(local_dest_index_persists_in_state_dir) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst"), st = tmp.sub("state");
    fs::path f = fs::u8path(src) / "p.txt";
    write_file(f, "persist me");
    {
        auto t = open_target(dst, st);
        CHECK(t->put_file("p.txt", f.u8string(), meta_of("p.txt", f)).status == PutResult::Sent);
        t->list_remote();
        t->close();
    }
    size_t files = 0;
    for (auto& e : fs::directory_iterator(fs::u8path(st))) {
        ++files;
        CHECK(e.path().filename().u8string().rfind("dest-", 0) == 0);
    }
    CHECK(files >= 1);
    for (auto& e : fs::recursive_directory_iterator(fs::u8path(dst)))
        CHECK(e.path().filename().u8string().find("dest-") != 0);  // never inside the destination
}

TEST(local_unavailable_destination_throws) {
    Tmp tmp;
    TargetConfig tc;
    tc.path = (tmp.root / "no" / "such" / "dir").u8string();
    auto t = make_local_target(tc);
    CHECK_THROWS(t->open());
}

namespace {
std::vector<std::pair<std::string, std::string>> local_trash(const std::string& dst) {
    std::vector<std::pair<std::string, std::string>> out;
    fs::path tr = fs::u8path(dst) / "__sync" / "__trash";
    std::error_code ec;
    for (fs::recursive_directory_iterator it(tr, ec), end; !ec && it != end; it.increment(ec))
        if (it->is_regular_file()) out.emplace_back(it->path().lexically_relative(tr).generic_string(), read_file(it->path()));
    return out;
}
}  // namespace

TEST(local_overwrite_moves_old_version_to_trash) {
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "sub" / "doc.txt";
    write_file(f, "first version");
    auto t = open_target(dst);
    CHECK(t->put_file("sub/doc.txt", f.u8string(), meta_of("sub/doc.txt", f)).status == PutResult::Sent);
    CHECK(local_trash(dst).empty());
    CHECK(t->put_file("sub/doc.txt", f.u8string(), meta_of("sub/doc.txt", f)).status == PutResult::Skipped);
    CHECK(local_trash(dst).empty());  // identical content: no trash entry

    write_file(f, "second, different version");
    CHECK(t->put_file("sub/doc.txt", f.u8string(), meta_of("sub/doc.txt", f)).status == PutResult::Sent);
    CHECK_EQ(read_file(fs::u8path(dst) / "sub" / "doc.txt"), std::string("second, different version"));
    auto tf = local_trash(dst);
    CHECK_EQ(tf.size(), size_t(1));
    CHECK_EQ(tf[0].second, std::string("first version"));
    CHECK(tf[0].first.find("/sub/doc.txt") != std::string::npos);
    CHECK_EQ(count_tmp(fs::u8path(dst)), 0u);
}

#ifndef _WIN32
TEST(local_created_files_and_dirs_use_configured_modes) {
    auto perms = [](const fs::path& p) { return unsigned(fs::status(p).permissions() & fs::perms::mask); };
    Tmp tmp;
    std::string src = tmp.sub("src"), dst = tmp.sub("dst");
    fs::path f = fs::u8path(src) / "a.txt";
    write_file(f, "payload");
    {
        auto t = open_target(dst);  // defaults
        CHECK(t->put_file("x/y/a.txt", f.u8string(), meta_of("x/y/a.txt", f)).status == PutResult::Sent);
        CHECK_EQ(perms(fs::u8path(dst) / "x" / "y" / "a.txt"), 0640u);
        CHECK_EQ(perms(fs::u8path(dst) / "x" / "y"), 0750u);
        t->make_dir("m/n");
        CHECK_EQ(perms(fs::u8path(dst) / "m" / "n"), 0750u);
    }
    std::string dst2 = tmp.sub("dst2");
    TargetConfig tc;
    tc.path = dst2;
    tc.file_mode = 0600;
    tc.dir_mode = 0700;
    auto t = make_local_target(tc, nullptr, "");
    t->open();
    CHECK(t->put_file("p/a.txt", f.u8string(), meta_of("p/a.txt", f)).status == PutResult::Sent);
    CHECK_EQ(perms(fs::u8path(dst2) / "p" / "a.txt"), 0600u);
    CHECK_EQ(perms(fs::u8path(dst2) / "p"), 0700u);
}
#endif
