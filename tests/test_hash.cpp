// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>

#include "mysync/hash.h"
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

TEST(hash_empty_vector) {
    CHECK_EQ(hash_hex(hash_bytes("", 0)), std::string("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"));
}

TEST(hash_streaming_equals_oneshot) {
    std::vector<uint8_t> d(300000);
    for (size_t i = 0; i < d.size(); ++i) d[i] = static_cast<uint8_t>(i * 7 + 3);
    Hasher h;
    size_t off = 0, step = 1;
    while (off < d.size()) {
        size_t n = std::min(step, d.size() - off);
        h.update(d.data() + off, n);
        off += n;
        step = step * 3 + 1;
    }
    CHECK(h.finish() == hash_bytes(d.data(), d.size()));
}

TEST(hash_block16_is_prefix) {
    const char* m = "hello world";
    Hash256 f = hash_bytes(m, 11);
    auto b = hash_block16(m, 11);
    CHECK(std::equal(b.begin(), b.end(), f.begin()));
}

TEST(hash_file_large_matches_bytes) {
    TmpDir t;
    const size_t N = 5u * (1u << 20) + 12345;
    std::vector<uint8_t> d(N);
    for (size_t i = 0; i < N; ++i) d[i] = static_cast<uint8_t>((i * 2654435761u) >> 13);
    fs::path f = t.p / "big.bin";
    {
        std::ofstream o(f, std::ios::binary);
        o.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(N));
    }
    uint64_t sz = 0;
    Hash256 h = hash_file(f.u8string(), &sz);
    CHECK_EQ(sz, uint64_t(N));
    CHECK(h == hash_bytes(d.data(), d.size()));
}

TEST(hash_file_empty_and_unicode_name) {
    TmpDir t;
    fs::path f = t.p / fs::u8path("tệp tin ✓.txt");
    { std::ofstream o(f, std::ios::binary); }
    uint64_t sz = 99;
    Hash256 h = hash_file(f.u8string(), &sz);
    CHECK_EQ(sz, uint64_t(0));
    CHECK_EQ(hash_hex(h), std::string("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"));
}

TEST(hash_file_missing_throws) {
    TmpDir t;
    CHECK_THROWS(hash_file((t.p / "nope").u8string()));
}
