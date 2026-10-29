// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// protocol.h - binary message encoding (see docs/DESIGN.md, "Thong diep").
// Integers are big-endian; string = u16 len + valid UTF-8 (no NUL); blob = u32 len + bytes.
// Every length read from the wire is checked against the bytes actually remaining before allocating.
#include <array>
#include <string>
#include <variant>
#include <vector>

#include "mysync/delta.h"
#include "mysync/util.h"

namespace mysync::proto {

constexpr uint16_t kProtoVersion = 1;
constexpr uint32_t kCapLz4 = 1u << 0;
constexpr uint32_t kCapDelta = 1u << 1;
constexpr uint32_t kDefaultMaxChunk = 256 * 1024;  // DATA payload per message
constexpr uint32_t kMaxChunk = 768 * 1024;          // hard ceiling so a message always fits one channel frame
// A NEED_DELTA must fit one channel frame (20 bytes per block); the server falls back to NEED_FULL above this.
constexpr size_t kMaxNeedDeltaBlocks = 50000;

enum class MsgType : uint8_t {
    Hello = 1, HelloOk, ListReq, ListEntry, ListEnd, Offer, Skip, NeedFull, NeedDelta,
    Data, DeltaOps, EndFile, FileOk, FileErr, Delete, Rename, Mkdir, Ping, Pong, Bye,
};

enum class ErrCode : uint16_t {
    Ok = 0, PathDenied = 1, TooLarge = 2, HashMismatch = 3, IoError = 4, Busy = 5, BadRequest = 6,
    Unsupported = 7, NotFound = 8, Internal = 9,
};
const char* err_name(ErrCode);

// ---- bounds-checked binary writer / reader ----
class Writer {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v);
    void u32(uint32_t v);
    void u64(uint64_t v);
    void i64(int64_t v) { u64(uint64_t(v)); }
    void boolean(bool v) { u8(v ? 1 : 0); }
    void str(const std::string& s);  // throws Error if > 65535 bytes
    void blob(const void* d, size_t n);  // throws Error if > 0xFFFFFFFF
    void blob(const Bytes& b) { blob(b.data(), b.size()); }
    void raw(const void* d, size_t n);
    const Bytes& bytes() const { return buf_; }
    Bytes take() { return std::move(buf_); }
private:
    Bytes buf_;
};

class Reader {
public:
    Reader(const void* d, size_t n) : p_(static_cast<const uint8_t*>(d)), n_(n) {}
    explicit Reader(const Bytes& b) : Reader(b.data(), b.size()) {}
    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    int64_t i64() { return int64_t(u64()); }
    bool boolean();                   // only 0 / 1 accepted
    std::string str();                // validates UTF-8, rejects NUL
    Bytes blob();                     // length checked against remaining before allocating
    void raw(void* out, size_t n);
    size_t remaining() const { return n_ - pos_; }
    void expect_end() const;          // throws Error on trailing bytes
private:
    void need(size_t n) const;
    const uint8_t* p_;
    size_t n_;
    size_t pos_ = 0;
};

bool valid_utf8(const std::string& s);

// ---- messages ----
struct Hello { uint16_t proto_ver = kProtoVersion; std::string client_name; uint32_t caps = 0; };
struct HelloOk { uint32_t server_caps = 0; uint32_t max_chunk = kDefaultMaxChunk; };
struct ListReq { std::string prefix; };
struct ListEntry {
    std::string path; uint64_t size = 0; int64_t mtime_ns = 0; Hash256 hash{}; bool is_dir = false;
};
struct ListEnd { uint64_t count = 0; };
struct Offer {
    std::string path; uint64_t size = 0; int64_t mtime_ns = 0; Hash256 hash{}; uint32_t mode_flags = 0;
};
struct Skip {};
struct NeedFull {};
struct NeedDelta { uint32_t block_size = 0; std::vector<delta::BlockSig> sigs; };
struct Data { uint64_t seq = 0; uint8_t flags = 0; Bytes bytes; };  // flags bit0 = lz4
constexpr uint8_t kDataLz4 = 1;
struct DeltaOps { std::vector<delta::DeltaOp> ops; };
struct EndFile { Hash256 hash{}; };
struct FileOk {};
struct FileErr { ErrCode code = ErrCode::Internal; std::string message; };
struct Delete { std::string path; };
struct Rename { std::string from, to; };
struct Mkdir { std::string path; };
struct Ping { uint64_t token = 0; };
struct Pong { uint64_t token = 0; };
struct Bye {};

using Message = std::variant<Hello, HelloOk, ListReq, ListEntry, ListEnd, Offer, Skip, NeedFull, NeedDelta, Data,
                             DeltaOps, EndFile, FileOk, FileErr, Delete, Rename, Mkdir, Ping, Pong, Bye>;

MsgType type_of(const Message&);
Bytes encode(const Message&);          // throws Error if a field is out of range
Message decode(const Bytes&);          // throws Error on unknown type, truncation, trailing bytes, bad values
Message decode(const void* d, size_t n);

} // namespace mysync::proto
