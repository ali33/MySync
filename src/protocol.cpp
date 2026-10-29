// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/protocol.h"

#include <cstring>

namespace mysync::proto {

const char* err_name(ErrCode c) {
    switch (c) {
        case ErrCode::Ok: return "OK";
        case ErrCode::PathDenied: return "PATH_DENIED";
        case ErrCode::TooLarge: return "TOO_LARGE";
        case ErrCode::HashMismatch: return "HASH_MISMATCH";
        case ErrCode::IoError: return "IO_ERROR";
        case ErrCode::Busy: return "BUSY";
        case ErrCode::BadRequest: return "BAD_REQUEST";
        case ErrCode::Unsupported: return "UNSUPPORTED";
        case ErrCode::NotFound: return "NOT_FOUND";
        case ErrCode::Internal: return "INTERNAL";
    }
    return "UNKNOWN";
}

bool valid_utf8(const std::string& s) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(s.data());
    size_t n = s.size(), i = 0;
    while (i < n) {
        uint8_t c = p[i];
        if (c < 0x80) { i++; continue; }
        size_t len;
        uint32_t cp;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else return false;
        if (n - i < len) return false;
        for (size_t k = 1; k < len; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;  // overlong
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

// ---- Writer ----
void Writer::u16(uint16_t v) { buf_.push_back(uint8_t(v >> 8)); buf_.push_back(uint8_t(v)); }
void Writer::u32(uint32_t v) { for (int s = 24; s >= 0; s -= 8) buf_.push_back(uint8_t(v >> s)); }
void Writer::u64(uint64_t v) { for (int s = 56; s >= 0; s -= 8) buf_.push_back(uint8_t(v >> s)); }
void Writer::str(const std::string& s) {
    if (s.size() > 0xFFFF) throw Error("proto: string too long");
    u16(uint16_t(s.size()));
    raw(s.data(), s.size());
}
void Writer::blob(const void* d, size_t n) {
    if (n > 0xFFFFFFFFu) throw Error("proto: blob too long");
    u32(uint32_t(n));
    raw(d, n);
}
void Writer::raw(const void* d, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(d);
    buf_.insert(buf_.end(), p, p + n);
}

// ---- Reader ----
void Reader::need(size_t n) const {
    if (n > n_ - pos_) throw Error("proto: truncated message");
}
uint8_t Reader::u8() { need(1); return p_[pos_++]; }
uint16_t Reader::u16() { need(2); uint16_t v = uint16_t((p_[pos_] << 8) | p_[pos_ + 1]); pos_ += 2; return v; }
uint32_t Reader::u32() {
    need(4);
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | p_[pos_ + i];
    pos_ += 4;
    return v;
}
uint64_t Reader::u64() {
    need(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p_[pos_ + i];
    pos_ += 8;
    return v;
}
bool Reader::boolean() {
    uint8_t v = u8();
    if (v > 1) throw Error("proto: bad boolean");
    return v == 1;
}
std::string Reader::str() {
    uint16_t len = u16();
    need(len);
    std::string s(reinterpret_cast<const char*>(p_ + pos_), len);
    pos_ += len;
    if (s.find('\0') != std::string::npos) throw Error("proto: NUL in string");
    if (!valid_utf8(s)) throw Error("proto: invalid UTF-8");
    return s;
}
Bytes Reader::blob() {
    uint32_t len = u32();
    need(len);  // checked against what is actually left before allocating
    Bytes b(p_ + pos_, p_ + pos_ + len);
    pos_ += len;
    return b;
}
void Reader::raw(void* out, size_t n) {
    need(n);
    std::memcpy(out, p_ + pos_, n);
    pos_ += n;
}
void Reader::expect_end() const {
    if (pos_ != n_) throw Error("proto: trailing bytes");
}

// ---- messages ----
namespace {

void check_block_size(uint32_t bs) {
    if (bs < delta::kMinAcceptedBlock || bs > delta::kMaxAcceptedBlock) throw Error("proto: bad block size");
}

struct Enc {
    Writer& w;
    void operator()(const Hello& m) { w.u16(m.proto_ver); w.str(m.client_name); w.u32(m.caps); }
    void operator()(const HelloOk& m) { w.u32(m.server_caps); w.u32(m.max_chunk); }
    void operator()(const ListReq& m) { w.str(m.prefix); }
    void operator()(const ListEntry& m) {
        w.str(m.path); w.u64(m.size); w.i64(m.mtime_ns); w.raw(m.hash.data(), 32); w.boolean(m.is_dir);
    }
    void operator()(const ListEnd& m) { w.u64(m.count); }
    void operator()(const Offer& m) {
        w.str(m.path); w.u64(m.size); w.i64(m.mtime_ns); w.raw(m.hash.data(), 32); w.u32(m.mode_flags);
    }
    void operator()(const Skip&) {}
    void operator()(const NeedFull&) {}
    void operator()(const NeedDelta& m) {
        check_block_size(m.block_size);
        if (m.sigs.size() > kMaxNeedDeltaBlocks) throw Error("proto: too many block signatures");
        w.u32(m.block_size);
        w.u32(uint32_t(m.sigs.size()));
        for (const auto& s : m.sigs) { w.u32(s.weak); w.raw(s.strong.data(), 16); }
    }
    void operator()(const Data& m) {
        if (m.flags & ~kDataLz4) throw Error("proto: bad DATA flags");
        if (m.bytes.size() > kMaxChunk) throw Error("proto: DATA chunk too large");
        w.u64(m.seq); w.u8(m.flags); w.blob(m.bytes);
    }
    void operator()(const DeltaOps& m) {
        w.u32(uint32_t(m.ops.size()));
        for (const auto& op : m.ops) {
            w.u8(uint8_t(op.kind));
            if (op.kind == delta::DeltaOp::Copy) w.u32(op.block_idx);
            else w.blob(op.data);
        }
    }
    void operator()(const EndFile& m) { w.raw(m.hash.data(), 32); }
    void operator()(const FileOk&) {}
    void operator()(const FileErr& m) { w.u16(uint16_t(m.code)); w.str(m.message); }
    void operator()(const Delete& m) { w.str(m.path); }
    void operator()(const Rename& m) { w.str(m.from); w.str(m.to); }
    void operator()(const Mkdir& m) { w.str(m.path); }
    void operator()(const Ping& m) { w.u64(m.token); }
    void operator()(const Pong& m) { w.u64(m.token); }
    void operator()(const Bye&) {}
};

ErrCode to_err(uint16_t v) {
    if (v > uint16_t(ErrCode::Internal)) throw Error("proto: unknown error code");
    return ErrCode(v);
}

}  // namespace

MsgType type_of(const Message& m) { return MsgType(m.index() + 1); }

Bytes encode(const Message& m) {
    Writer w;
    w.u8(uint8_t(type_of(m)));
    std::visit(Enc{w}, m);
    return w.take();
}

Message decode(const Bytes& b) { return decode(b.data(), b.size()); }

Message decode(const void* d, size_t n) {
    Reader r(d, n);
    uint8_t t = r.u8();
    Message out;
    switch (MsgType(t)) {
        case MsgType::Hello: {
            Hello m;
            m.proto_ver = r.u16(); m.client_name = r.str(); m.caps = r.u32();
            out = std::move(m);
            break;
        }
        case MsgType::HelloOk: {
            HelloOk m;
            m.server_caps = r.u32(); m.max_chunk = r.u32();
            if (m.max_chunk == 0 || m.max_chunk > kMaxChunk) throw Error("proto: bad max_chunk");
            out = m;
            break;
        }
        case MsgType::ListReq: { ListReq m; m.prefix = r.str(); out = std::move(m); break; }
        case MsgType::ListEntry: {
            ListEntry m;
            m.path = r.str(); m.size = r.u64(); m.mtime_ns = r.i64(); r.raw(m.hash.data(), 32); m.is_dir = r.boolean();
            out = std::move(m);
            break;
        }
        case MsgType::ListEnd: { ListEnd m; m.count = r.u64(); out = m; break; }
        case MsgType::Offer: {
            Offer m;
            m.path = r.str(); m.size = r.u64(); m.mtime_ns = r.i64(); r.raw(m.hash.data(), 32); m.mode_flags = r.u32();
            out = std::move(m);
            break;
        }
        case MsgType::Skip: out = Skip{}; break;
        case MsgType::NeedFull: out = NeedFull{}; break;
        case MsgType::NeedDelta: {
            NeedDelta m;
            m.block_size = r.u32();
            check_block_size(m.block_size);
            uint32_t cnt = r.u32();
            if (cnt > kMaxNeedDeltaBlocks || size_t(cnt) * 20 != r.remaining()) throw Error("proto: bad signature count");
            m.sigs.resize(cnt);
            for (auto& s : m.sigs) { s.weak = r.u32(); r.raw(s.strong.data(), 16); }
            out = std::move(m);
            break;
        }
        case MsgType::Data: {
            Data m;
            m.seq = r.u64(); m.flags = r.u8();
            if (m.flags & ~kDataLz4) throw Error("proto: bad DATA flags");
            m.bytes = r.blob();
            if (m.bytes.size() > kMaxChunk) throw Error("proto: DATA chunk too large");
            out = std::move(m);
            break;
        }
        case MsgType::DeltaOps: {
            DeltaOps m;
            uint32_t cnt = r.u32();
            if (size_t(cnt) * 5 > r.remaining()) throw Error("proto: bad op count");  // every op is >= 5 bytes
            m.ops.reserve(cnt);
            for (uint32_t i = 0; i < cnt; i++) {
                delta::DeltaOp op;
                uint8_t k = r.u8();
                if (k == delta::DeltaOp::Copy) { op.kind = delta::DeltaOp::Copy; op.block_idx = r.u32(); }
                else if (k == delta::DeltaOp::Literal) { op.kind = delta::DeltaOp::Literal; op.data = r.blob(); }
                else throw Error("proto: bad delta op");
                m.ops.push_back(std::move(op));
            }
            out = std::move(m);
            break;
        }
        case MsgType::EndFile: { EndFile m; r.raw(m.hash.data(), 32); out = m; break; }
        case MsgType::FileOk: out = FileOk{}; break;
        case MsgType::FileErr: {
            FileErr m;
            m.code = to_err(r.u16()); m.message = r.str();
            out = std::move(m);
            break;
        }
        case MsgType::Delete: { Delete m; m.path = r.str(); out = std::move(m); break; }
        case MsgType::Rename: { Rename m; m.from = r.str(); m.to = r.str(); out = std::move(m); break; }
        case MsgType::Mkdir: { Mkdir m; m.path = r.str(); out = std::move(m); break; }
        case MsgType::Ping: { Ping m; m.token = r.u64(); out = m; break; }
        case MsgType::Pong: { Pong m; m.token = r.u64(); out = m; break; }
        case MsgType::Bye: out = Bye{}; break;
        default: throw Error("proto: unknown message type");
    }
    r.expect_end();
    return out;
}

}  // namespace mysync::proto
