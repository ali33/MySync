// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#ifdef _WIN32
#include <windows.h>
#endif
#include <thread>

#include "mysync/util.h"
#include "mysync/watcher.h"
#include "testing.h"

namespace fs = std::filesystem;
using namespace mysync;
using namespace std::chrono_literals;

namespace {

struct TempDir {
    fs::path p;
    TempDir() {
        std::random_device rd;
        p = fs::temp_directory_path() / ("mysync-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(p);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string u8() const { return p.u8string(); }
};

struct Collector {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<WatchEvent> all;
    int batches = 0;

    void add(std::vector<WatchEvent>&& b) {
        std::lock_guard<std::mutex> lk(mu);
        ++batches;
        for (auto& e : b) all.push_back(std::move(e));
        cv.notify_all();
    }
    template <class Pred>
    bool wait(Pred pred, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(mu);
        return cv.wait_for(lk, timeout, [&] { return pred(all); });
    }
    int count(WatchEvent::Kind k, const std::string& rel) {
        std::lock_guard<std::mutex> lk(mu);
        int n = 0;
        for (auto& e : all) if (e.kind == k && e.rel == rel) ++n;
        return n;
    }
    int count_kind(WatchEvent::Kind k) {
        std::lock_guard<std::mutex> lk(mu);
        int n = 0;
        for (auto& e : all) if (e.kind == k) ++n;
        return n;
    }
    bool has(WatchEvent::Kind k, const std::string& rel) { return count(k, rel) > 0; }
    void clear() {
        std::lock_guard<std::mutex> lk(mu);
        all.clear();
    }
};

void write_file(const fs::path& p, const std::string& data, bool append = false) {
    std::ofstream f(p, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    f << data;
}

WatcherOptions base_opts(const TempDir& d) {
    WatcherOptions o;
    o.root_utf8 = d.u8();
    o.quiet_ms = 100;
    o.periodic_scan_s = 0;
    return o;
}

}  // namespace

TEST(watcher_create_modify_delete_rename) {
    TempDir d;
    fs::create_directories(d.p / "sub");
    Collector c;
    Watcher w(base_opts(d), [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    std::this_thread::sleep_for(200ms);

    write_file(d.p / "a.txt", "hello");
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Modified && e.rel == "a.txt") return true; return false; }, 5000ms));

    write_file(d.p / "sub" / "b.txt", "nested");
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Modified && e.rel == "sub/b.txt") return true; return false; }, 5000ms));

    c.clear();
    fs::rename(d.p / "a.txt", d.p / "renamed.txt");
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Renamed) return true; return false; }, 5000ms));
    {
        std::lock_guard<std::mutex> lk(c.mu);
        bool found = false;
        for (auto& e : c.all)
            if (e.kind == WatchEvent::Renamed && e.rel == "renamed.txt" && e.rel_from == "a.txt") found = true;
        CHECK(found);
    }

    c.clear();
    fs::remove(d.p / "renamed.txt");
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Deleted && e.rel == "renamed.txt") return true; return false; }, 5000ms));
    w.stop();
}

TEST(watcher_coalesces_100_writes_into_one_modified) {
    TempDir d;
    Collector c;
    Watcher w(base_opts(d), [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    std::this_thread::sleep_for(200ms);
    {
        // one open handle, 100 flushed writes: re-opening per write is dominated by antivirus latency
        std::ofstream f(d.p / "burst.dat", std::ios::binary | std::ios::trunc);
        for (int i = 0; i < 100; ++i) {
            f << std::string(64, 'x');
            f.flush();
            std::this_thread::sleep_for(2ms);
        }
    }
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Modified && e.rel == "burst.dat") return true; return false; }, 5000ms));
    std::this_thread::sleep_for(600ms);  // anything extra would arrive by now
    CHECK_EQ(c.count(WatchEvent::Modified, "burst.dat"), 1);
    w.stop();
}

TEST(watcher_no_modified_before_quiet_period) {
    TempDir d;
    Collector c;
    auto o = base_opts(d);
    o.quiet_ms = 400;
    Watcher w(o, [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    std::this_thread::sleep_for(200ms);
    auto t0 = std::chrono::steady_clock::now();
    write_file(d.p / "q.txt", "x");
    CHECK(c.wait([](auto& v) { return !v.empty(); }, 5000ms));
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms >= 380);
    w.stop();
}

TEST(watcher_ignore_and_sync_dir) {
    TempDir d;
    fs::create_directories(d.p / "__sync" / "trash");
    fs::create_directories(d.p / "skip");
    Collector c;
    auto o = base_opts(d);
    o.ignore = [](const std::string& rel, bool) { return rel == "skip" || (rel.size() > 4 && rel.compare(rel.size() - 4, 4, ".tmp") == 0); };
    Watcher w(o, [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    std::this_thread::sleep_for(200ms);
    write_file(d.p / "__sync" / "trash" / "x.bin", "x");
    write_file(d.p / "skip" / "y.txt", "y");
    write_file(d.p / "z.tmp", "z");
    write_file(d.p / "keep.txt", "k");
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.rel == "keep.txt") return true; return false; }, 5000ms));
    std::this_thread::sleep_for(400ms);
    std::lock_guard<std::mutex> lk(c.mu);
    for (auto& e : c.all) {
        CHECK(e.rel != "__sync/trash/x.bin");
        CHECK(e.rel != "skip/y.txt");
        CHECK(e.rel != "z.tmp");
    }
    w.stop();
}

TEST(watcher_new_directory_contents_are_reported) {
    TempDir d;
    Collector c;
    Watcher w(base_opts(d), [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    std::this_thread::sleep_for(200ms);
    // build the tree elsewhere, then move it in: no per-file events exist for its contents
    fs::path outside = d.p.parent_path() / (d.p.filename().string() + "-staging");
    fs::create_directories(outside / "inner");
    write_file(outside / "f1.txt", "1");
    write_file(outside / "inner" / "f2.txt", "2");
    fs::rename(outside, d.p / "moved");
    bool ok = c.wait([](auto& v) {
        bool a = false, b = false;
        for (auto& e : v) {
            if (e.kind == WatchEvent::Modified && e.rel == "moved/f1.txt") a = true;
            if (e.kind == WatchEvent::Modified && e.rel == "moved/inner/f2.txt") b = true;
        }
        return a && b;
    }, 5000ms);
    CHECK(ok);
    // and a file written later in the new subdirectory is still seen
    c.clear();
    write_file(d.p / "moved" / "inner" / "late.txt", "3");
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.rel == "moved/inner/late.txt") return true; return false; }, 5000ms));
    w.stop();
}

TEST(watcher_periodic_overflow) {
    TempDir d;
    Collector c;
    auto o = base_opts(d);
    o.periodic_scan_s = 1;
    Watcher w(o, [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Overflow) return true; return false; }, 3500ms));
    w.stop();
}

TEST(watcher_start_stop_clean_and_repeatable) {
    TempDir d;
    for (int i = 0; i < 5; ++i) {
        Watcher w(base_opts(d), [](std::vector<WatchEvent>&&) {});
        w.start();
        w.start();  // no-op
        write_file(d.p / "x.txt", "x");
        w.stop();
        w.stop();  // idempotent
    }
    Watcher w(base_opts(d), [](std::vector<WatchEvent>&&) {});
    w.start();
    w.stop();
    w.start();  // restartable
    w.stop();
}

TEST(watcher_missing_root_throws) {
    WatcherOptions o;
    o.root_utf8 = (fs::temp_directory_path() / "mysync-test-definitely-missing-dir").u8string();
    Watcher w(o, [](std::vector<WatchEvent>&&) {});
    CHECK_THROWS(w.start());
}

#ifdef _WIN32
TEST(watcher_waits_while_file_is_exclusively_locked) {
    TempDir d;
    Collector c;
    Watcher w(base_opts(d), [&](std::vector<WatchEvent>&& b) { c.add(std::move(b)); });
    w.start();
    std::this_thread::sleep_for(200ms);
    fs::path p = d.p / "locked.bin";
    std::wstring wp = p.wstring();
    HANDLE h = CreateFileW(wp.c_str(), GENERIC_WRITE, 0 /* no sharing */, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(h != INVALID_HANDLE_VALUE);
    DWORD wr = 0;
    WriteFile(h, "data", 4, &wr, nullptr);
    std::this_thread::sleep_for(1200ms);
    CHECK_EQ(c.count(WatchEvent::Modified, "locked.bin"), 0);  // held back while locked
    CloseHandle(h);
    CHECK(c.wait([](auto& v) { for (auto& e : v) if (e.kind == WatchEvent::Modified && e.rel == "locked.bin") return true; return false; }, 5000ms));
    w.stop();
}
#endif
