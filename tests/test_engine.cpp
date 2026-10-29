// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <thread>

#include "mysync/client_engine.h"
#include "mysync/hash.h"
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
        log_set_level(LogLevel::Warn);
    }
    ~Tmp() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    fs::path dir(const std::string& n) const {
        fs::create_directories(root / n);
        return root / n;
    }
};

void write_file(const fs::path& p, const std::string& data, bool old_mtime) {
    fs::create_directories(p.parent_path());
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f << data;
    }
    if (old_mtime) fs::last_write_time(p, fs::file_time_type::clock::now() - std::chrono::hours(3));
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool wait_for(const std::function<bool()>& cond, int ms = 15000) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return cond();
}

bool has_content(const fs::path& p, const std::string& s) {
    std::error_code ec;
    return fs::is_regular_file(p, ec) && read_file(p) == s;
}

ClientConfig make_cfg(const fs::path& src, const fs::path& dst, const fs::path& state) {
    ClientConfig cc;
    cc.state_dir = state.u8string();
    cc.connections = 3;
    cc.retry_min_ms = 100;
    cc.retry_max_ms = 500;
    WatchConfig w;
    w.name = "w1";
    w.path = src.u8string();
    w.quiet_ms = 100;
    w.sync_delay_ms = 0;
    w.periodic_scan_s = 0;
    TargetConfig t;
    t.path = dst.u8string();
    w.targets.push_back(t);
    cc.watches.push_back(w);
    return cc;
}

struct Running {
    SyncEngine eng;
    std::atomic<bool> stop{false};
    std::thread th;
    Running(ClientConfig cc) : eng(std::move(cc), "") { th = std::thread([this] { eng.run(stop); }); }
    void halt() {
        stop = true;
        if (th.joinable()) th.join();
    }
    ~Running() { halt(); }
};

}  // namespace

TEST(engine_initial_scan_live_events_and_filter) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), dst = tmp.dir("dst"), state = tmp.dir("state");
    write_file(src / "a.txt", "alpha", true);
    write_file(src / "sub" / "b.txt", "beta", true);
    write_file(src / "skipme" / "c.txt", "gamma", true);
    write_file(src / "pic.bin", "binary", true);
    ClientConfig cc = make_cfg(src, dst, state);
    cc.watches[0].filter.include = {".txt"};
    cc.watches[0].filter.exclude = {"skipme"};
    Running run(cc);
    // initial scan
    CHECK(wait_for([&] { return has_content(dst / "a.txt", "alpha") && has_content(dst / "sub" / "b.txt", "beta"); }));
    CHECK(wait_for([&] { return run.eng.idle(); }));
    CHECK(!fs::exists(dst / "skipme"));
    CHECK(!fs::exists(dst / "pic.bin"));

    // create
    write_file(src / "new.txt", "fresh", false);
    CHECK(wait_for([&] { return has_content(dst / "new.txt", "fresh"); }));
    write_file(src / "ignored.bin", "x", false);
    write_file(src / "~$lock.txt", "x", false);
    // modify
    write_file(src / "a.txt", "alpha v2 longer", false);
    CHECK(wait_for([&] { return has_content(dst / "a.txt", "alpha v2 longer"); }));
    // new file in a new directory
    write_file(src / "dir1" / "deep" / "f.txt", "deep", false);
    CHECK(wait_for([&] { return has_content(dst / "dir1" / "deep" / "f.txt", "deep"); }));
    // rename a file
    fs::rename(src / "new.txt", src / "renamed.txt");
    CHECK(wait_for([&] { return has_content(dst / "renamed.txt", "fresh") && !fs::exists(dst / "new.txt"); }));
    // rename a directory
    fs::rename(src / "dir1", src / "dir2");
    CHECK(wait_for([&] { return has_content(dst / "dir2" / "deep" / "f.txt", "deep") && !fs::exists(dst / "dir1"); }));
    // delete a file (goes to the trash on the target)
    fs::remove(src / "sub" / "b.txt");
    CHECK(wait_for([&] { return !fs::exists(dst / "sub" / "b.txt"); }));
    CHECK(fs::exists(dst / "__sync" / "__trash"));
    CHECK(wait_for([&] { return run.eng.idle(); }));
    CHECK(!fs::exists(dst / "ignored.bin"));
    CHECK(!fs::exists(dst / "~$lock.txt"));
    EngineStats s = run.eng.stats();
    CHECK(s.sent >= 5);
    CHECK(s.deleted >= 1);
    run.halt();
}

TEST(engine_restart_does_not_hash_or_send_again) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), dst = tmp.dir("dst"), state = tmp.dir("state");
    for (int i = 0; i < 20; ++i) write_file(src / ("d" + std::to_string(i % 3)) / ("f" + std::to_string(i) + ".dat"),
                                           "content " + std::to_string(i), true);
    ClientConfig cc = make_cfg(src, dst, state);
    {
        Running run(cc);
        CHECK(wait_for([&] { return fs::exists(dst / "d2" / "f17.dat") && run.eng.idle(); }));
        EngineStats s = run.eng.stats();
        CHECK_EQ(s.sent, 20u);
        CHECK_EQ(s.hashed, 20u);
        run.halt();
    }
    {
        Running run(cc);
        CHECK(wait_for([&] { return run.eng.idle(); }));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        EngineStats s = run.eng.stats();
        CHECK_EQ(s.hashed, 0u);
        CHECK_EQ(s.sent, 0u);
        CHECK_EQ(s.skipped, 0u);
        CHECK_EQ(s.reused, 20u);
        run.halt();
    }
}

TEST(engine_once_syncs_deletes_and_keeps_filtered) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), dst = tmp.dir("dst"), state = tmp.dir("state");
    write_file(src / "keep.txt", "keep", true);
    write_file(dst / "stale.txt", "stale", true);          // not in source: removed (propagate_delete)
    write_file(dst / "other.bin", "foreign", true);        // outside the include filter: left alone
    write_file(dst / "keep.txt", "old data", true);        // differs: replaced
    ClientConfig cc = make_cfg(src, dst, state);
    cc.watches[0].filter.include = {".txt"};
    SyncEngine eng(cc, "");
    std::atomic<bool> stop{false};
    eng.sync_once(stop);
    CHECK(has_content(dst / "keep.txt", "keep"));
    CHECK(!fs::exists(dst / "stale.txt"));
    CHECK(has_content(dst / "other.bin", "foreign"));
    CHECK_EQ(eng.stats().gave_up, 0u);

    // propagate_delete = false keeps extras
    write_file(dst / "extra.txt", "extra", true);
    cc.watches[0].propagate_delete = false;
    SyncEngine eng2(cc, "");
    eng2.sync_once(stop);
    CHECK(has_content(dst / "extra.txt", "extra"));
}

TEST(engine_refuses_mass_delete_when_source_is_empty) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), dst = tmp.dir("dst"), state = tmp.dir("state");
    for (int i = 0; i < 150; ++i) write_file(dst / ("f" + std::to_string(i) + ".txt"), "x" + std::to_string(i), true);
    ClientConfig cc = make_cfg(src, dst, state);
    SyncEngine eng(cc, "");
    std::atomic<bool> stop{false};
    eng.sync_once(stop);
    size_t n = 0;
    for (int i = 0; i < 150; ++i) n += fs::exists(dst / ("f" + std::to_string(i) + ".txt"));
    CHECK_EQ(n, 150u);
    CHECK_EQ(eng.stats().deleted, 0u);
}

TEST(engine_one_dead_target_does_not_block_another) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), dst = tmp.dir("dst"), state = tmp.dir("state");
    write_file(src / "z.txt", "zed", true);
    ClientConfig cc = make_cfg(src, dst, state);
    TargetConfig dead;
    dead.path = (tmp.root / "missing-drive" / "x").u8string();  // parent does not exist: cannot be opened
    cc.watches[0].targets.insert(cc.watches[0].targets.begin(), dead);
    Running run(cc);
    CHECK(wait_for([&] { return has_content(dst / "z.txt", "zed"); }));
    run.halt();
    CHECK(!fs::exists(tmp.root / "missing-drive"));
}

TEST(engine_target_that_appears_later_is_retried) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), state = tmp.dir("state");
    fs::path late_parent = tmp.root / "later";
    fs::path dst = late_parent / "dst";
    write_file(src / "w.txt", "wait for me", true);
    ClientConfig cc = make_cfg(src, dst, state);
    Running run(cc);
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    CHECK(!fs::exists(dst / "w.txt"));
    fs::create_directories(late_parent);
    CHECK(wait_for([&] { return has_content(dst / "w.txt", "wait for me"); }));
    run.halt();
}
