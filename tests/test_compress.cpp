// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <random>

#include "mysync/compress.h"
#include "testing.h"

using namespace mysync;

namespace {
Bytes random_buf(size_t n, uint32_t seed) {
    std::mt19937 g(seed);
    Bytes b(n);
    for (auto& x : b) x = uint8_t(g());
    return b;
}
}  // namespace

TEST(lz4_roundtrip_compressible) {
    Bytes in(1 << 20);
    for (size_t i = 0; i < in.size(); i++) in[i] = uint8_t("MySync-MySync-"[i % 14]);
    Bytes c = lz4_compress(in.data(), in.size());
    CHECK(c.size() < in.size() / 10);
    CHECK(lz4_decompress(c.data(), c.size(), in.size()) == in);
    CHECK(lz4_decompress(c.data(), c.size(), in.size() + 1000) == in);
}

TEST(lz4_roundtrip_random_and_sizes) {
    for (size_t n : {size_t(1), size_t(2), size_t(15), size_t(16), size_t(17), size_t(1000), size_t(65536)}) {
        Bytes in = random_buf(n, uint32_t(n));
        Bytes c = lz4_compress(in.data(), in.size());
        CHECK(lz4_decompress(c.data(), c.size(), n) == in);
    }
}

TEST(lz4_empty) {
    CHECK(lz4_compress(nullptr, 0).empty());
    CHECK(lz4_decompress(nullptr, 0, 10).empty());
}

TEST(lz4_decompress_limit_enforced) {
    Bytes in(100000, 0);  // compresses to a tiny stream that expands 100000 bytes
    Bytes c = lz4_compress(in.data(), in.size());
    CHECK(c.size() < 1000);
    CHECK_THROWS(lz4_decompress(c.data(), c.size(), in.size() - 1));
    CHECK_THROWS(lz4_decompress(c.data(), c.size(), 10));
    CHECK_THROWS(lz4_decompress(c.data(), c.size(), 0));
}

TEST(lz4_corrupt_data_rejected_without_crash) {
    Bytes in(50000);
    for (size_t i = 0; i < in.size(); i++) in[i] = uint8_t(i * 7 / 3);
    Bytes c = lz4_compress(in.data(), in.size());
    std::mt19937 g(5);
    int rejected = 0;
    for (int t = 0; t < 300; t++) {
        Bytes m = c;
        size_t k = g() % m.size();
        m[k] = uint8_t(m[k] ^ (1 + g() % 255));
        try {
            Bytes out = lz4_decompress(m.data(), m.size(), in.size());
            CHECK(out.size() <= in.size());
        } catch (const Error&) {
            rejected++;
        }
    }
    // truncation and pure garbage
    for (size_t cut = 0; cut < c.size(); cut += 97) {
        try { (void)lz4_decompress(c.data(), cut, in.size()); } catch (const Error&) {}
    }
    Bytes junk = random_buf(4096, 99);
    for (int t = 0; t < 50; t++) {
        junk = random_buf(4096, 100 + t);
        try { (void)lz4_decompress(junk.data(), junk.size(), 1 << 16); } catch (const Error&) {}
    }
    CHECK(rejected > 0);
}

TEST(lz4_compress_if_smaller_flag) {
    Bytes zeros(10000, 0);
    auto a = lz4_compress_if_smaller(zeros.data(), zeros.size());
    CHECK(a.compressed);
    CHECK(a.data.size() < zeros.size());
    CHECK(lz4_decompress(a.data.data(), a.data.size(), zeros.size()) == zeros);

    Bytes rnd = random_buf(10000, 3);
    auto b = lz4_compress_if_smaller(rnd.data(), rnd.size());
    CHECK(!b.compressed);
    CHECK(b.data == rnd);

    auto c = lz4_compress_if_smaller(rnd.data(), 0);
    CHECK(!c.compressed);
    CHECK(c.data.empty());
}
