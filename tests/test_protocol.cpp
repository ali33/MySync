// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <random>

#include "mysync/protocol.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::proto;

namespace {

Hash256 hash_of(uint8_t v) {
    Hash256 h;
    for (size_t i = 0; i < 32; i++) h[i] = uint8_t(v + i);
    return h;
}

std::vector<Message> sample_messages() {
    std::vector<Message> v;
    v.push_back(Hello{1, "may-ke-toan Đức Sơn", kCapLz4 | kCapDelta});
    v.push_back(HelloOk{kCapLz4, 262144});
    v.push_back(ListReq{"docs/tài liệu"});
    v.push_back(ListEntry{"a/b/c.txt", 123456789012ull, -5, hash_of(1), false});
    v.push_back(ListEntry{"a/b", 0, 1700000000000000000ll, hash_of(2), true});
    v.push_back(ListEnd{42});
    v.push_back(Offer{"x/y.bin", 99, 1234567890123456789ll, hash_of(3), 0x1A4});
    v.push_back(Skip{});
    v.push_back(NeedFull{});
    NeedDelta nd;
    nd.block_size = 2048;
    for (uint32_t i = 0; i < 10; i++) {
        delta::BlockSig s;
        s.weak = 0xAABB0000u + i;
        for (size_t k = 0; k < 16; k++) s.strong[k] = uint8_t(i * 16 + k);
        nd.sigs.push_back(s);
    }
    v.push_back(nd);
    v.push_back(NeedDelta{4096, {}});
    v.push_back(Data{7, kDataLz4, Bytes{1, 2, 3, 4, 5}});
    v.push_back(Data{0, 0, Bytes{}});
    DeltaOps ops;
    delta::DeltaOp c; c.kind = delta::DeltaOp::Copy; c.block_idx = 77;
    delta::DeltaOp l; l.kind = delta::DeltaOp::Literal; l.data = Bytes{9, 8, 7};
    delta::DeltaOp l0; l0.kind = delta::DeltaOp::Literal;
    ops.ops = {c, l, l0, c};
    v.push_back(ops);
    v.push_back(DeltaOps{});
    v.push_back(EndFile{hash_of(4)});
    v.push_back(FileOk{});
    v.push_back(FileErr{ErrCode::HashMismatch, "hash mismatch"});
    v.push_back(Delete{"old/file.txt"});
    v.push_back(Rename{"a.txt", "b/c.txt"});
    v.push_back(Mkdir{"new/dir"});
    v.push_back(Ping{0xFFFFFFFFFFFFFFFFull});
    v.push_back(Pong{5});
    v.push_back(Bye{});
    return v;
}

}  // namespace

TEST(protocol_roundtrip_all_messages) {
    auto msgs = sample_messages();
    std::vector<bool> seen(msgs.size() + 32, false);
    for (const auto& m : msgs) {
        Bytes b = encode(m);
        CHECK(b[0] == uint8_t(type_of(m)));
        Message d = decode(b);
        CHECK(d.index() == m.index());
        CHECK(encode(d) == b);  // canonical: re-encoding yields identical bytes
        seen[m.index()] = true;
    }
    for (size_t i = 0; i < std::variant_size_v<Message>; i++) CHECK(seen[i]);

    auto e = std::get<ListEntry>(decode(encode(ListEntry{"p", 5, -7, hash_of(9), true})));
    CHECK_EQ(e.path, std::string("p"));
    CHECK_EQ(e.size, uint64_t(5));
    CHECK_EQ(e.mtime_ns, int64_t(-7));
    CHECK(e.hash == hash_of(9));
    CHECK(e.is_dir);
    auto fe = std::get<FileErr>(decode(encode(FileErr{ErrCode::PathDenied, "nope"})));
    CHECK(fe.code == ErrCode::PathDenied);
    CHECK_EQ(fe.message, std::string("nope"));
}

TEST(protocol_every_truncation_rejected) {
    for (const auto& m : sample_messages()) {
        Bytes b = encode(m);
        for (size_t cut = 0; cut < b.size(); cut++) {
            Bytes t(b.begin(), b.begin() + cut);
            bool threw = false;
            try { (void)decode(t); } catch (const Error&) { threw = true; }
            // Messages with an empty body decode fine at cut==1 only if they are the full message.
            CHECK(threw);
        }
        Bytes extra = b;
        extra.push_back(0);
        CHECK_THROWS(decode(extra));
    }
}

TEST(protocol_random_bytes_never_crash) {
    std::mt19937_64 g(12345);
    for (int i = 0; i < 20000; i++) {
        Bytes b(g() % 80);
        for (auto& x : b) x = uint8_t(g());
        if (!b.empty() && i % 2) b[0] = uint8_t(1 + g() % 20);  // plausible type byte
        try { (void)decode(b); } catch (const Error&) {}
    }
    // bit flips of valid messages
    for (const auto& m : sample_messages()) {
        Bytes b = encode(m);
        for (int i = 0; i < 300; i++) {
            Bytes x = b;
            x[g() % x.size()] ^= uint8_t(1 + g() % 255);
            try { (void)decode(x); } catch (const Error&) {}
        }
    }
}

TEST(protocol_absurd_lengths_rejected_before_allocation) {
    // DATA with blob length 0xFFFFFFFF but only a few bytes present
    Writer w;
    w.u8(uint8_t(MsgType::Data)); w.u64(0); w.u8(0); w.u32(0xFFFFFFFFu); w.u8(1);
    CHECK_THROWS(decode(w.bytes()));
    // DELTA_OPS with a huge op count
    Writer w2;
    w2.u8(uint8_t(MsgType::DeltaOps)); w2.u32(0xFFFFFFFFu);
    CHECK_THROWS(decode(w2.bytes()));
    // DELTA_OPS literal with huge length
    Writer w3;
    w3.u8(uint8_t(MsgType::DeltaOps)); w3.u32(1); w3.u8(1); w3.u32(0x7FFFFFFFu);
    CHECK_THROWS(decode(w3.bytes()));
    // NEED_DELTA with huge signature count / count not matching the body
    Writer w4;
    w4.u8(uint8_t(MsgType::NeedDelta)); w4.u32(2048); w4.u32(0xFFFFFFFFu);
    CHECK_THROWS(decode(w4.bytes()));
    Writer w5;
    w5.u8(uint8_t(MsgType::NeedDelta)); w5.u32(2048); w5.u32(1000);
    CHECK_THROWS(decode(w5.bytes()));
    // NEED_DELTA with silly block size
    Writer w6;
    w6.u8(uint8_t(MsgType::NeedDelta)); w6.u32(0); w6.u32(0);
    CHECK_THROWS(decode(w6.bytes()));
    Writer w7;
    w7.u8(uint8_t(MsgType::NeedDelta)); w7.u32(0xFFFFFFFFu); w7.u32(0);
    CHECK_THROWS(decode(w7.bytes()));
    // string length beyond the data
    Writer w8;
    w8.u8(uint8_t(MsgType::Mkdir)); w8.u16(60000); w8.u8('a');
    CHECK_THROWS(decode(w8.bytes()));
    // HELLO_OK with a chunk size above the ceiling
    Writer w9;
    w9.u8(uint8_t(MsgType::HelloOk)); w9.u32(0); w9.u32(0xFFFFFFFFu);
    CHECK_THROWS(decode(w9.bytes()));
}

TEST(protocol_rejects_bad_strings_and_values) {
    // invalid UTF-8
    Writer w;
    w.u8(uint8_t(MsgType::Mkdir)); w.u16(2); w.u8(0xC3); w.u8(0x28);
    CHECK_THROWS(decode(w.bytes()));
    // overlong encoding of '/'
    Writer w2;
    w2.u8(uint8_t(MsgType::Mkdir)); w2.u16(2); w2.u8(0xC0); w2.u8(0xAF);
    CHECK_THROWS(decode(w2.bytes()));
    // NUL inside
    Writer w3;
    w3.u8(uint8_t(MsgType::Mkdir)); w3.u16(3); w3.u8('a'); w3.u8(0); w3.u8('b');
    CHECK_THROWS(decode(w3.bytes()));
    // surrogate
    Writer w4;
    w4.u8(uint8_t(MsgType::Mkdir)); w4.u16(3); w4.u8(0xED); w4.u8(0xA0); w4.u8(0x80);
    CHECK_THROWS(decode(w4.bytes()));
    // unknown type / empty
    CHECK_THROWS(decode(Bytes{}));
    CHECK_THROWS(decode(Bytes{0}));
    CHECK_THROWS(decode(Bytes{200}));
    // bad bool, bad error code, bad DATA flags, bad op kind
    Writer w5;
    w5.u8(uint8_t(MsgType::ListEntry)); w5.str("a"); w5.u64(0); w5.u64(0);
    for (int i = 0; i < 32; i++) w5.u8(0);
    w5.u8(2);
    CHECK_THROWS(decode(w5.bytes()));
    Writer w6;
    w6.u8(uint8_t(MsgType::FileErr)); w6.u16(999); w6.str("x");
    CHECK_THROWS(decode(w6.bytes()));
    Writer w7;
    w7.u8(uint8_t(MsgType::Data)); w7.u64(1); w7.u8(0x80); w7.blob(Bytes{1});
    CHECK_THROWS(decode(w7.bytes()));
    Writer w8;
    w8.u8(uint8_t(MsgType::DeltaOps)); w8.u32(1); w8.u8(9); w8.u32(0);
    CHECK_THROWS(decode(w8.bytes()));
    // encode-side limits
    CHECK_THROWS(encode(Message(Mkdir{std::string(70000, 'a')})));
    CHECK_THROWS(encode(Message(NeedDelta{10, {}})));
    CHECK_THROWS(encode(Message(Data{0, 0, Bytes(kMaxChunk + 1)})));
    // valid non-ASCII passes
    CHECK(valid_utf8("Nguyễn Đức Sơn \xF0\x9F\x98\x80"));
    CHECK(!valid_utf8("\xFF"));
}
