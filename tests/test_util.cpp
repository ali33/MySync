// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>

#include "mysync/util.h"
#include "testing.h"

using namespace mysync;

TEST(util_hex_roundtrip) {
    uint8_t d[5] = {0x00, 0x01, 0xab, 0xff, 0x7e};
    std::string h = to_hex(d, sizeof d);
    CHECK_EQ(h, std::string("0001abff7e"));
    Bytes b = from_hex(h);
    CHECK_EQ(b.size(), size_t(5));
    CHECK(std::equal(b.begin(), b.end(), d));
    Bytes up = from_hex("ABFF");
    CHECK_EQ(up[0], uint8_t(0xab));
    CHECK_EQ(from_hex("").size(), size_t(0));
}

TEST(util_hex_rejects_bad_input) {
    CHECK_THROWS(from_hex("abc"));
    CHECK_THROWS(from_hex("zz"));
    CHECK_THROWS(from_hex("0g"));
}

TEST(util_random_bytes) {
    uint8_t a[32] = {0}, b[32] = {0};
    random_bytes(a, sizeof a);
    random_bytes(b, sizeof b);
    CHECK(!ct_equal(a, b, sizeof a));
    uint8_t zero[32] = {0};
    CHECK(!ct_equal(a, zero, sizeof a));
    random_bytes(a, 0);  // no-op
    std::vector<uint8_t> big(1 << 20);
    random_bytes(big.data(), big.size());
    std::set<uint8_t> seen(big.begin(), big.end());
    CHECK(seen.size() > 200);
}

TEST(util_ct_equal) {
    uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 4}, c[4] = {1, 2, 3, 5};
    CHECK(ct_equal(a, b, 4));
    CHECK(!ct_equal(a, c, 4));
    CHECK(ct_equal(a, c, 3));
    CHECK(ct_equal(a, c, 0));
}

TEST(util_secure_wipe) {
    uint8_t a[64];
    for (auto& x : a) x = 0xAA;
    secure_wipe(a, sizeof a);
    for (auto x : a) CHECK_EQ(x, uint8_t(0));
    secure_wipe(nullptr, 0);
}

TEST(util_now_unix_ns) {
    int64_t t1 = now_unix_ns();
    int64_t t2 = now_unix_ns();
    CHECK(t1 > 1700000000LL * 1000000000LL);
    CHECK(t2 >= t1);
}

TEST(util_log_file_threadsafe) {
    namespace fs = std::filesystem;
    uint8_t r[6];
    random_bytes(r, sizeof r);
    fs::path dir = fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
    fs::create_directories(dir);
    fs::path lf = dir / "log.txt";
    log_set_level(LogLevel::Info);
    log_set_file(lf.u8string());
    std::vector<std::thread> ts;
    for (int t = 0; t < 4; ++t)
        ts.emplace_back([t] {
            for (int i = 0; i < 50; ++i) log_info("thread " + std::to_string(t) + " line " + std::to_string(i));
        });
    for (auto& t : ts) t.join();
    log_debug("this debug line must be filtered");
    log_warn("warn line");
    log_set_file("");
    std::ifstream in(lf, std::ios::binary);
    std::string line;
    int n = 0;
    bool warn = false, dbg = false;
    while (std::getline(in, line)) {
        ++n;
        // "YYYY-MM-DD HH:MM:SS.mmm [LEVEL] msg"
        CHECK(line.size() > 28 && line[4] == '-' && line[10] == ' ' && line[13] == ':');
        if (line.find("warn line") != std::string::npos) warn = true;
        if (line.find("must be filtered") != std::string::npos) dbg = true;
    }
    CHECK_EQ(n, 201);
    CHECK(warn);
    CHECK(!dbg);
    in.close();
    std::error_code ec;
    fs::remove_all(dir, ec);
}
