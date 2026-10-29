// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>

#include "mysync/hash.h"
#include "mysync/index.h"
#include "testing.h"

namespace fs = std::filesystem;
using namespace mysync;

namespace {

struct TmpDir {
    fs::path p;
    TmpDir() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~TmpDir() { std::error_code ec; fs::remove_all(p, ec); }
    std::string root() const { return p.u8string(); }
};

void write_file(const fs::path& f, const std::string& content) {
    fs::create_directories(f.parent_path());
    std::ofstream o(f, std::ios::binary | std::ios::trunc);
    o << content;
}

void set_age(const fs::path& f, int seconds_ago) {
    fs::last_write_time(f, fs::file_time_type::clock::now() - std::chrono::seconds(seconds_ago));
}

const FileMeta* find_meta(const std::vector<FileMeta>& v, const std::string& rel) {
    for (const auto& m : v)
        if (m.rel == rel) return &m;
    return nullptr;
}

} // namespace

TEST(index_scan_reuses_cache_second_time) {
    TmpDir d;
    write_file(d.p / "a.txt", "hello");
    write_file(d.p / "sub" / "b.bin", "0123456789");
    write_file(d.p / "sub" / "deeper" / "c.txt", "ccc");
    for (auto* n : {"a.txt", "sub/b.bin", "sub/deeper/c.txt"}) set_age(d.p / n, 3600);

    Filter f;
    IndexCache cache;
    ScanStats s1;
    auto r1 = scan_tree(d.root(), f, cache, 2, &s1);
    CHECK_EQ(s1.files, uint64_t(3));
    CHECK_EQ(s1.hashed, uint64_t(3));
    CHECK_EQ(s1.reused, uint64_t(0));
    CHECK_EQ(s1.bytes_hashed, uint64_t(18));
    const FileMeta* a = find_meta(r1, "a.txt");
    CHECK(a != nullptr);
    CHECK_EQ(a->size, uint64_t(5));
    CHECK(a->hash == hash_bytes("hello", 5));
    CHECK(find_meta(r1, "sub") != nullptr && find_meta(r1, "sub")->is_dir);
    CHECK(find_meta(r1, "sub/deeper/c.txt") != nullptr);

    ScanStats s2;
    auto r2 = scan_tree(d.root(), f, cache, 2, &s2);
    CHECK_EQ(s2.hashed, uint64_t(0));
    CHECK_EQ(s2.reused, uint64_t(3));
    CHECK_EQ(r2.size(), r1.size());
    for (size_t i = 0; i < r1.size(); ++i) CHECK(r1[i].hash == r2[i].hash && r1[i].rel == r2[i].rel);
}

TEST(index_same_size_different_mtime_is_rehashed) {
    TmpDir d;
    fs::path f = d.p / "x.dat";
    write_file(f, "aaaa");
    set_age(f, 7200);
    Filter flt;
    IndexCache cache;
    ScanStats s;
    auto r1 = scan_tree(d.root(), flt, cache, 1, &s);
    CHECK_EQ(s.hashed, uint64_t(1));
    Hash256 h1 = r1[0].hash;

    write_file(f, "bbbb");  // same size
    set_age(f, 3600);       // different mtime
    auto r2 = scan_tree(d.root(), flt, cache, 1, &s);
    CHECK_EQ(s.hashed, uint64_t(1));
    CHECK(r2[0].hash != h1);
    CHECK(r2[0].hash == hash_bytes("bbbb", 4));

    // untouched again -> reused
    scan_tree(d.root(), flt, cache, 1, &s);
    CHECK_EQ(s.hashed, uint64_t(0));
}

TEST(index_recent_files_are_always_rehashed_and_not_cached) {
    TmpDir d;
    write_file(d.p / "new.txt", "fresh");  // mtime = now, inside the 2 s window
    Filter flt;
    IndexCache cache;
    ScanStats s;
    scan_tree(d.root(), flt, cache, 1, &s);
    CHECK_EQ(s.hashed, uint64_t(1));
    CHECK(cache.find("new.txt") == nullptr);
    scan_tree(d.root(), flt, cache, 1, &s);
    CHECK_EQ(s.hashed, uint64_t(1));
}

TEST(index_vanished_files_leave_cache_and_filter_applies) {
    TmpDir d;
    write_file(d.p / "keep.txt", "k");
    write_file(d.p / "gone.txt", "g");
    write_file(d.p / "skip.tmp", "t");
    write_file(d.p / "__sync" / "trash.txt", "x");
    for (auto* n : {"keep.txt", "gone.txt"}) set_age(d.p / n, 600);
    Filter flt;
    IndexCache cache;
    auto r1 = scan_tree(d.root(), flt, cache, 2);
    CHECK(find_meta(r1, "skip.tmp") == nullptr);
    CHECK(find_meta(r1, "__sync/trash.txt") == nullptr);
    CHECK(find_meta(r1, "__sync") == nullptr);
    CHECK(cache.find("gone.txt") != nullptr);
    fs::remove(d.p / "gone.txt");
    auto r2 = scan_tree(d.root(), flt, cache, 2);
    CHECK(cache.find("gone.txt") == nullptr);
    CHECK(cache.find("keep.txt") != nullptr);
    CHECK(find_meta(r2, "gone.txt") == nullptr);
}

TEST(index_include_filter_hides_directories) {
    TmpDir d;
    write_file(d.p / "a.txt", "a");
    write_file(d.p / "b.png", "b");
    fs::create_directories(d.p / "emptydir");
    FilterConfig c;
    c.include = {".txt"};
    Filter flt(c);
    IndexCache cache;
    auto r = scan_tree(d.root(), flt, cache, 1);
    CHECK_EQ(r.size(), size_t(1));
    CHECK_EQ(r[0].rel, std::string("a.txt"));
    auto all = scan_tree(d.root(), Filter(), cache, 1);
    CHECK(find_meta(all, "emptydir") != nullptr);
}

TEST(index_symlinks_are_skipped) {
    TmpDir d;
    write_file(d.p / "real" / "f.txt", "f");
    std::error_code ec;
    fs::create_directory_symlink(d.p / "real", d.p / "linkdir", ec);
    bool dir_link = !ec;
    ec.clear();
    fs::create_symlink(d.p / "real" / "f.txt", d.p / "linkfile", ec);
    bool file_link = !ec;
    if (!dir_link && !file_link) return;  // no symlink privilege here: nothing to verify
    IndexCache cache;
    auto r = scan_tree(d.root(), Filter(), cache, 1);
    CHECK(find_meta(r, "real/f.txt") != nullptr);
    CHECK(find_meta(r, "linkdir") == nullptr);
    CHECK(find_meta(r, "linkdir/f.txt") == nullptr);
    CHECK(find_meta(r, "linkfile") == nullptr);
}

TEST(index_missing_root_throws) {
    TmpDir d;
    IndexCache cache;
    FileMeta m;
    m.rel = "x";
    cache.put(m);
    CHECK_THROWS(scan_tree((d.p / "nope").u8string(), Filter(), cache, 1));
    CHECK(cache.find("x") != nullptr);  // a failed scan must not wipe the cache
}

TEST(index_cache_roundtrip_and_corruption) {
    TmpDir d;
    IndexCache c;
    FileMeta a;
    a.rel = "dir/ä-file.txt";
    a.size = 42;
    a.mtime_ns = 1700000000123456789LL;
    a.hash = hash_bytes("abc", 3);
    c.put(a);
    FileMeta b;
    b.rel = "z";
    b.size = 0;
    b.mtime_ns = -5;
    c.put(b);
    std::string path = (d.p / "state" / "index-1.bin").u8string();
    c.save(path);
    CHECK(!fs::exists(d.p / "state" / "index-1.bin.tmp"));

    IndexCache l;
    CHECK(l.load(path));
    CHECK_EQ(l.size(), size_t(2));
    const FileMeta* g = l.find("dir/ä-file.txt");
    CHECK(g != nullptr);
    CHECK_EQ(g->size, uint64_t(42));
    CHECK_EQ(g->mtime_ns, int64_t(1700000000123456789LL));
    CHECK(g->hash == a.hash);
    CHECK_EQ(l.find("z")->mtime_ns, int64_t(-5));

    // flip one byte in the middle -> checksum fails -> empty, no throw
    {
        std::fstream f(fs::u8path(path), std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(20);
        char ch = 0x55;
        f.write(&ch, 1);
    }
    IndexCache bad;
    bad.put(a);
    CHECK(!bad.load(path));
    CHECK_EQ(bad.size(), size_t(0));

    // truncated, empty, missing, garbage
    write_file(d.p / "trunc.bin", "MSIX");
    CHECK(!bad.load((d.p / "trunc.bin").u8string()));
    write_file(d.p / "empty.bin", "");
    CHECK(!bad.load((d.p / "empty.bin").u8string()));
    CHECK(!bad.load((d.p / "missing.bin").u8string()));
    write_file(d.p / "junk.bin", std::string(500, 'x'));
    CHECK(!bad.load((d.p / "junk.bin").u8string()));
}

TEST(index_cache_other_version_is_ignored) {
    TmpDir d;
    IndexCache c;
    FileMeta a;
    a.rel = "a";
    c.put(a);
    std::string path = (d.p / "i.bin").u8string();
    c.save(path);
    // rewrite version field and recompute checksum
    std::ifstream in(fs::u8path(path), std::ios::binary);
    Bytes buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    buf.resize(buf.size() - 32);
    buf[7] = 99;
    Hash256 h = hash_bytes(buf.data(), buf.size());
    buf.insert(buf.end(), h.begin(), h.end());
    std::ofstream out(fs::u8path(path), std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    out.close();
    IndexCache l;
    CHECK(!l.load(path));
    CHECK_EQ(l.size(), size_t(0));
}

TEST(index_rename_prefix) {
    IndexCache c;
    for (auto* r : {"a", "a/x", "a/y/z", "ab/q", "b"}) {
        FileMeta m;
        m.rel = r;
        m.size = 1;
        c.put(m);
    }
    CHECK_EQ(c.rename_prefix("a", "c/d"), size_t(3));
    CHECK(c.find("a") == nullptr);
    CHECK(c.find("a/x") == nullptr);
    CHECK(c.find("c/d") != nullptr);
    CHECK(c.find("c/d/x") != nullptr);
    CHECK_EQ(c.find("c/d/y/z")->rel, std::string("c/d/y/z"));
    CHECK(c.find("ab/q") != nullptr);
    CHECK(c.find("b") != nullptr);
    CHECK(c.erase("b"));
    CHECK(!c.erase("b"));
}
