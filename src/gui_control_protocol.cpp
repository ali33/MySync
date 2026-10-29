// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/control_protocol.h"

#include <algorithm>

#include "mysync/protocol.h"

namespace mysync::gui {

using proto::Reader;
using proto::Writer;

namespace {

constexpr size_t kMaxTargets = 1024;
constexpr size_t kMaxPeers = 1024;
constexpr size_t kMaxListed = 64;       // strings in one list (active files, applied, needs_restart)
constexpr size_t kMaxText = 4000;       // longest free text we encode (bytes)

// Valid UTF-8 without NUL, at most `max` bytes (cut on a character boundary). Invalid bytes become '?'.
std::string clean(const std::string& s, size_t max = kMaxText) {
    std::string out;
    out.reserve(std::min(s.size(), max));
    size_t i = 0;
    while (i < s.size() && out.size() < max) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        bool ok = len != 0 && i + len <= s.size() && c != 0;
        for (size_t k = 1; ok && k < len; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) ok = false;
        if (ok && len > 1) ok = proto::valid_utf8(s.substr(i, len));
        if (!ok) {
            out += '?';
            ++i;
            continue;
        }
        if (out.size() + len > max) break;
        out.append(s, i, len);
        i += len;
    }
    return out;
}

void put_u64s(Writer& w, std::initializer_list<uint64_t> v) {
    for (uint64_t x : v) w.u64(x);
}

void put_strings(Writer& w, const std::vector<std::string>& v, size_t max_items, size_t max_len) {
    size_t n = std::min(v.size(), max_items);
    w.u16(static_cast<uint16_t>(n));
    for (size_t i = 0; i < n; ++i) w.str(clean(v[i], max_len));
}

std::vector<std::string> get_strings(Reader& r, size_t cap) {
    size_t n = r.u16();
    if (n > cap) throw Error("control message: list too long");
    std::vector<std::string> v;
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) v.push_back(r.str());
    return v;
}

struct Limits {
    size_t active_files = kMaxActiveFiles, file_len = 300, text_len = kMaxText, items = 1024, errors = kMaxErrorsReturned;
};

void put_target(Writer& w, const TargetStatus& t, const Limits& lim) {
    w.str(clean(t.watch, 200));
    w.str(clean(t.target, 400));
    w.u8(static_cast<uint8_t>(t.state));
    put_u64s(w, {t.queued, t.tx_bps, t.rx_bps, t.sent, t.skipped, t.failed, t.bytes});
    w.str(clean(t.last_error, lim.text_len));
    w.i64(t.last_error_unix_ms);
    size_t n = std::min({t.active_files.size(), lim.active_files, size_t(kMaxActiveFiles)});
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) w.str(clean(t.active_files[i], lim.file_len));
}

TargetStatus get_target(Reader& r) {
    TargetStatus t;
    t.watch = r.str();
    t.target = r.str();
    uint8_t st = r.u8();
    if (st > static_cast<uint8_t>(TargetState::Disconnected)) throw Error("control message: bad target state");
    t.state = static_cast<TargetState>(st);
    t.queued = r.u64();
    t.tx_bps = r.u64();
    t.rx_bps = r.u64();
    t.sent = r.u64();
    t.skipped = r.u64();
    t.failed = r.u64();
    t.bytes = r.u64();
    t.last_error = r.str();
    t.last_error_unix_ms = r.i64();
    size_t n = r.u8();
    if (n > kMaxActiveFiles) throw Error("control message: too many active files");
    for (size_t i = 0; i < n; ++i) t.active_files.push_back(r.str());
    return t;
}

void put_snapshot(Writer& w, const StatusSnapshot& s, const Limits& lim) {
    w.u8(static_cast<uint8_t>(s.role));
    w.str(clean(s.version, 64));
    w.str(clean(s.service_name, 128));
    w.str(clean(s.config_path, 1024));
    w.u64(s.uptime_s);
    w.i64(s.taken_unix_ms);
    put_u64s(w, {s.total_tx_bps, s.total_rx_bps, s.total_sent, s.total_skipped, s.total_failed});
    w.str(clean(s.listen, 300));
    w.u32(s.sessions);
    w.u32(s.max_connections);
    w.i64(s.config_loaded_unix_ms);
    w.str(clean(s.config_error, lim.text_len));
    size_t nt = std::min(s.targets.size(), lim.items);
    w.u32(static_cast<uint32_t>(nt));
    for (size_t i = 0; i < nt; ++i) put_target(w, s.targets[i], lim);
    size_t np = std::min(s.peers.size(), lim.items);
    w.u32(static_cast<uint32_t>(np));
    for (size_t i = 0; i < np; ++i) {
        const PeerStatus& p = s.peers[i];
        w.str(clean(p.name, 200));
        w.u32(p.sessions);
        put_u64s(w, {p.rx_bps, p.tx_bps, p.bytes_rx, p.bytes_tx});
    }
}

StatusSnapshot get_snapshot(Reader& r) {
    StatusSnapshot s;
    uint8_t role = r.u8();
    if (role != static_cast<uint8_t>(Role::Server) && role != static_cast<uint8_t>(Role::Client))
        throw Error("control message: bad role");
    s.role = static_cast<Role>(role);
    s.version = r.str();
    s.service_name = r.str();
    s.config_path = r.str();
    s.uptime_s = r.u64();
    s.taken_unix_ms = r.i64();
    s.total_tx_bps = r.u64();
    s.total_rx_bps = r.u64();
    s.total_sent = r.u64();
    s.total_skipped = r.u64();
    s.total_failed = r.u64();
    s.listen = r.str();
    s.sessions = r.u32();
    s.max_connections = r.u32();
    s.config_loaded_unix_ms = r.i64();
    s.config_error = r.str();
    size_t nt = r.u32();
    if (nt > kMaxTargets) throw Error("control message: too many targets");
    for (size_t i = 0; i < nt; ++i) s.targets.push_back(get_target(r));
    size_t np = r.u32();
    if (np > kMaxPeers) throw Error("control message: too many peers");
    for (size_t i = 0; i < np; ++i) {
        PeerStatus p;
        p.name = r.str();
        p.sessions = r.u32();
        p.rx_bps = r.u64();
        p.tx_bps = r.u64();
        p.bytes_rx = r.u64();
        p.bytes_tx = r.u64();
        s.peers.push_back(std::move(p));
    }
    return s;
}

Bytes encode_once(const ControlResponse& m, const Limits& lim) {
    Writer w;
    w.u16(kControlVersion);
    w.u8(static_cast<uint8_t>(m.op));
    w.u64(m.token);
    w.u8(static_cast<uint8_t>(m.status));
    w.str(clean(m.error, lim.text_len));
    switch (m.op) {
    case ControlOp::Ping:
        break;
    case ControlOp::GetStatus:
        put_snapshot(w, m.snapshot, lim);
        break;
    case ControlOp::ReloadConfig:
        w.boolean(m.reload.ok);
        w.str(clean(m.reload.message, lim.text_len));
        put_strings(w, m.reload.applied, kMaxListed, 300);
        put_strings(w, m.reload.needs_restart, kMaxListed, 300);
        break;
    case ControlOp::GetRecentErrors: {
        size_t n = std::min<size_t>(m.errors.size(), lim.errors);
        w.u16(static_cast<uint16_t>(n));
        for (size_t i = 0; i < n; ++i) {
            const ErrorEntry& e = m.errors[i];
            w.i64(e.unix_ms);
            w.str(clean(e.level, 16));
            w.str(clean(e.message, std::min<size_t>(lim.text_len, 1000)));
        }
        break;
    }
    }
    return w.take();
}

bool known_op(uint8_t op) { return op >= 1 && op <= 4; }

}  // namespace

const char* control_op_name(ControlOp op) {
    switch (op) {
    case ControlOp::Ping: return "PING";
    case ControlOp::GetStatus: return "GET_STATUS";
    case ControlOp::ReloadConfig: return "RELOAD_CONFIG";
    case ControlOp::GetRecentErrors: return "GET_RECENT_ERRORS";
    }
    return "?";
}

Bytes encode_request(const ControlRequest& q) {
    Writer w;
    w.u16(kControlVersion);
    w.u8(static_cast<uint8_t>(q.op));
    w.u64(q.token);
    w.u32(q.arg);
    return w.take();
}

ControlRequest decode_request(const void* data, size_t n) {
    Reader r(data, n);
    if (r.u16() != kControlVersion) throw Error("control message: unsupported version");
    uint8_t op = r.u8();
    if (!known_op(op)) throw Error("control message: unknown operation");
    ControlRequest q;
    q.op = static_cast<ControlOp>(op);
    q.token = r.u64();
    q.arg = r.u32();
    r.expect_end();
    return q;
}

Bytes encode_response(const ControlResponse& m) {
    const size_t budget = kMaxMessageBytes;
    Limits lim;
    Bytes b = encode_once(m, lim);
    if (b.size() <= budget) return b;
    lim.active_files = 5;
    lim.file_len = 120;
    lim.text_len = 1000;
    b = encode_once(m, lim);
    if (b.size() <= budget) return b;
    lim.active_files = 0;
    lim.text_len = 300;
    lim.errors = 40;
    b = encode_once(m, lim);
    for (size_t items = 256; b.size() > budget && items >= 1; items /= 2) {
        lim.items = items;
        lim.errors = std::min<size_t>(lim.errors, items);
        b = encode_once(m, lim);
    }
    if (b.size() > budget) throw Error("control message: response does not fit one frame");
    return b;
}

ControlResponse decode_response(const void* data, size_t n) {
    Reader r(data, n);
    if (r.u16() != kControlVersion) throw Error("control message: unsupported version");
    uint8_t op = r.u8();
    if (!known_op(op)) throw Error("control message: unknown operation");
    ControlResponse m;
    m.op = static_cast<ControlOp>(op);
    m.token = r.u64();
    uint8_t st = r.u8();
    if (st > static_cast<uint8_t>(ControlStatus::Denied)) throw Error("control message: bad status");
    m.status = static_cast<ControlStatus>(st);
    m.error = r.str();
    switch (m.op) {
    case ControlOp::Ping:
        break;
    case ControlOp::GetStatus:
        m.snapshot = get_snapshot(r);
        break;
    case ControlOp::ReloadConfig:
        m.reload.ok = r.boolean();
        m.reload.message = r.str();
        m.reload.applied = get_strings(r, kMaxListed);
        m.reload.needs_restart = get_strings(r, kMaxListed);
        break;
    case ControlOp::GetRecentErrors: {
        size_t cnt = r.u16();
        if (cnt > kMaxErrorsReturned) throw Error("control message: too many errors");
        for (size_t i = 0; i < cnt; ++i) {
            ErrorEntry e;
            e.unix_ms = r.i64();
            e.level = r.str();
            e.message = r.str();
            m.errors.push_back(std::move(e));
        }
        break;
    }
    }
    r.expect_end();
    return m;
}

Bytes frame_message(const Bytes& payload) {
    if (payload.empty() || payload.size() > kMaxMessageBytes) throw Error("control frame: bad payload size");
    Bytes out;
    out.reserve(payload.size() + 4);
    uint32_t n = static_cast<uint32_t>(payload.size());
    out.push_back(static_cast<uint8_t>(n >> 24));
    out.push_back(static_cast<uint8_t>(n >> 16));
    out.push_back(static_cast<uint8_t>(n >> 8));
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

uint32_t parse_frame_length(const uint8_t h[4]) {
    uint32_t n = (uint32_t(h[0]) << 24) | (uint32_t(h[1]) << 16) | (uint32_t(h[2]) << 8) | uint32_t(h[3]);
    if (n == 0 || n > kMaxMessageBytes) throw Error("control frame: bad length");
    return n;
}

}  // namespace mysync::gui
