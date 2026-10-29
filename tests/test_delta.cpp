// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>
#include <random>

#include "mysync/delta.h"
#include "mysync/hash.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::delta;
namespace fs = std::filesystem;

namespace {

struct TmpDir {
    fs::path p;
    TmpDir() {
        std::random_device rd;
        p = fs::temp_directory_path() / ("mysync-test-delta-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(p);
    }
    ~TmpDir() { std::error_code ec; fs::remove_all(p, ec); }
    std::string file(const char* name) const { return (p / name).u8string(); }
};

void write_file(const std::string& path, const Bytes& b) {
    std::ofstream o(fs::u8path(path), std::ios::binary | std::ios::trunc);
    o.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

Bytes random_buf(size_t n, uint64_t seed) {
    std::mt19937_64 g(seed);
    Bytes b(n);
    for (size_t i = 0; i < n; i += 8) {
        uint64_t v = g();
        for (size_t k = 0; k < 8 && i + k < n; k++) b[i + k] = uint8_t(v >> (8 * k));
    }
    return b;
}

struct Stats { size_t literal = 0, copies = 0; };

Stats stats_of(const std::vector<DeltaOp>& ops) {
    Stats s;
    for (const auto& op : ops) {
        if (op.kind == DeltaOp::Literal) s.literal += op.data.size();
        else s.copies++;
    }
    return s;
}

// Run the full cycle and require the rebuilt file to equal new_path by BLAKE3.
Stats cycle(const TmpDir& d, const Bytes& old_b, const Bytes& new_b, uint32_t forced_bs = 0) {
    std::string o = d.file("old.bin"), n = d.file("new.bin"), r = d.file("rebuilt.bin");
    write_file(o, old_b);
    write_file(n, new_b);
    Signature sig = forced_bs ? make_signature(o, forced_bs) : make_signature(o);
    CHECK_EQ(sig.file_size, uint64_t(old_b.size()));
    auto ops = compute_delta(sig, n);
    apply_delta_to_file(o, sig.block_size, ops, r);
    CHECK(hash_file(r) == hash_file(n));
    CHECK(hash_file(r) == hash_bytes(new_b.data(), new_b.size()));
    return stats_of(ops);
}

}  // namespace

TEST(delta_block_size_choice) {
    CHECK_EQ(choose_block_size(0), kMinBlockSize);
    CHECK_EQ(choose_block_size(1000), kMinBlockSize);
    CHECK_EQ(choose_block_size(uint64_t(1) << 20), kMinBlockSize);
    CHECK_EQ(choose_block_size(uint64_t(20) << 20), 4096u);
    CHECK_EQ(choose_block_size(uint64_t(1) << 40), kMaxBlockSize);
    uint32_t prev = 0;
    for (uint64_t s = 1; s < (uint64_t(1) << 42); s <<= 1) {
        uint32_t b = choose_block_size(s);
        CHECK(b >= kMinBlockSize && b <= kMaxBlockSize && b >= prev);
        prev = b;
    }
}

TEST(delta_weak_checksum_rolls) {
    Bytes b = random_buf(5000, 1);
    for (size_t n : {size_t(64), size_t(2048)}) {
        // recompute-from-scratch at each offset must equal the value the delta engine finds via rolling
        // (validated indirectly: a shifted copy must be found at every alignment, see delta_insert_at_start).
        CHECK(weak_checksum(b.data(), n) != weak_checksum(b.data() + 1, n));
    }
    CHECK_EQ(weak_checksum(b.data(), 0), 0u);
}

TEST(delta_identical_file_is_all_copies) {
    TmpDir d;
    Bytes b = random_buf(300000, 2);
    Stats s = cycle(d, b, b);
    CHECK_EQ(s.literal, size_t(0));
    CHECK(s.copies >= 300000 / 4096);
}

TEST(delta_empty_files) {
    TmpDir d;
    Bytes empty;
    Bytes some = random_buf(10000, 3);
    Stats a = cycle(d, empty, empty);
    CHECK_EQ(a.literal + a.copies, size_t(0));
    Stats b = cycle(d, empty, some);   // no old data: everything literal
    CHECK_EQ(b.literal, some.size());
    CHECK_EQ(b.copies, size_t(0));
    Stats c = cycle(d, some, empty);   // new file empty: no ops
    CHECK_EQ(c.literal + c.copies, size_t(0));
}

TEST(delta_20mib_one_byte_changed_in_middle) {
    TmpDir d;
    Bytes old_b = random_buf(size_t(20) << 20, 4);
    Bytes new_b = old_b;
    new_b[new_b.size() / 2] ^= 0x5A;
    uint32_t bs = choose_block_size(old_b.size());
    Stats s = cycle(d, old_b, new_b);
    CHECK(s.literal <= size_t(2) * bs);
    CHECK(s.literal >= 1);
    CHECK(s.copies >= old_b.size() / bs - 2);
}

TEST(delta_insert_byte_at_start) {
    TmpDir d;
    Bytes old_b = random_buf(5 << 20, 5);
    Bytes new_b;
    new_b.push_back(0xAB);
    new_b.insert(new_b.end(), old_b.begin(), old_b.end());
    uint32_t bs = choose_block_size(old_b.size());
    Stats s = cycle(d, old_b, new_b);
    // 1 inserted byte; the short tail block may also be re-sent only if it was not matched
    CHECK(s.literal <= size_t(bs) + 1);
    CHECK(s.copies >= old_b.size() / bs - 1);
}

TEST(delta_insert_and_delete_in_middle_and_append) {
    TmpDir d;
    Bytes old_b = random_buf(1 << 20, 6);
    uint32_t bs = choose_block_size(old_b.size());
    Bytes ins(old_b.begin(), old_b.begin() + 400000);
    ins.insert(ins.end(), {1, 2, 3, 4, 5, 6, 7});
    ins.insert(ins.end(), old_b.begin() + 400000, old_b.end());
    Stats a = cycle(d, old_b, ins);
    CHECK(a.literal <= size_t(bs) + 7);

    Bytes del(old_b.begin(), old_b.begin() + 300000);
    del.insert(del.end(), old_b.begin() + 300100, old_b.end());
    Stats b = cycle(d, old_b, del);
    CHECK(b.literal <= size_t(bs) * 2);

    Bytes app = old_b;
    Bytes extra = random_buf(1000, 66);
    app.insert(app.end(), extra.begin(), extra.end());
    Stats c = cycle(d, old_b, app);
    CHECK(c.literal <= 1000 + size_t(bs));  // the old short tail block cannot match a longer file's block
}

TEST(delta_unaligned_sizes_and_tail_block) {
    TmpDir d;
    for (size_t size : {size_t(1), size_t(63), size_t(64), size_t(65), size_t(2047), size_t(2048), size_t(2049),
                        size_t(10000), size_t(4096 * 3 + 17)}) {
        Bytes b = random_buf(size, size);
        Stats s = cycle(d, b, b, 64);   // small block size exercises many blocks + a short tail
        CHECK_EQ(s.literal, size_t(0));
        Bytes m = b;
        m[size / 2] ^= 1;
        cycle(d, b, m, 64);
        cycle(d, b, m);
    }
}

TEST(delta_repetitive_data_and_zero_files) {
    TmpDir d;
    Bytes zeros(1 << 20, 0);
    Stats s = cycle(d, zeros, zeros);
    CHECK_EQ(s.literal, size_t(0));
    Bytes pat(1 << 20);
    for (size_t i = 0; i < pat.size(); i++) pat[i] = uint8_t((i / 3) % 7);
    Bytes pat2 = pat;
    pat2[500000] = 99;
    cycle(d, pat, pat2);
    cycle(d, zeros, pat);
    cycle(d, pat, zeros);
}

TEST(delta_unrelated_files_all_literal_and_bounded_ops) {
    TmpDir d;
    Bytes a = random_buf(1 << 20, 10), b = random_buf(1 << 20, 11);
    std::string o = d.file("o"), n = d.file("n");
    write_file(o, a);
    write_file(n, b);
    Signature sig = make_signature(o);
    size_t lit = 0;
    compute_delta(sig, n, [&](DeltaOp&& op) {
        CHECK(op.kind == DeltaOp::Literal);
        CHECK(op.data.size() <= kMaxLiteralOp);
        lit += op.data.size();
    });
    CHECK_EQ(lit, b.size());
}

TEST(delta_apply_rejects_bad_copy_and_missing_file) {
    TmpDir d;
    Bytes a = random_buf(10000, 12);
    write_file(d.file("o"), a);
    DeltaOp c;
    c.kind = DeltaOp::Copy;
    c.block_idx = 1000000;
    CHECK_THROWS(apply_delta(d.file("o"), 2048, {c}, [](const void*, size_t) {}));
    c.block_idx = 0;
    CHECK_THROWS(apply_delta(d.file("missing"), 2048, {c}, [](const void*, size_t) {}));
    CHECK_THROWS(DeltaApplier(d.file("o"), 0));
    CHECK_THROWS(make_signature(d.file("missing")));
    CHECK_THROWS(make_signature(d.file("o"), 1));
    // literal-only ops need no old file at all
    DeltaOp l;
    l.kind = DeltaOp::Literal;
    l.data = {1, 2, 3};
    Bytes out;
    apply_delta(d.file("missing"), 2048, {l}, [&](const void* p, size_t n) {
        out.insert(out.end(), static_cast<const uint8_t*>(p), static_cast<const uint8_t*>(p) + n);
    });
    CHECK(out == (Bytes{1, 2, 3}));
    // inconsistent signature
    Signature bad;
    bad.block_size = 2048;
    bad.file_size = 10000;
    CHECK_THROWS(compute_delta(bad, d.file("o")));
}
