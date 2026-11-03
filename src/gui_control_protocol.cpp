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
    w.i64(t.last_ok_unix_ms);
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
    t.last_ok_unix_ms = r.i64();
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
    w.str(clean(s.pairing, 32));
    w.u32(s.peer_file_errors);
    size_t nw = std::min<size_t>(s.warnings.size(), 8);
    w.u8(static_cast<uint8_t>(nw));
    for (size_t i = 0; i < nw; ++i) w.str(clean(s.warnings[i], 400));
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
    s.pairing = r.str();
    s.peer_file_errors = r.u32();
    size_t nw = r.u8();
    if (nw > 8) throw Error("control message: too many warnings");
    for (size_t i = 0; i < nw; ++i) s.warnings.push_back(r.str());
    return s;
}

constexpr size_t kMaxPending = 8;

void put_pair(Writer& w, const PairInfo& p, const Limits& lim) {
    w.boolean(p.available);
    w.boolean(p.mode_on);
    w.u32(p.seconds_left);
    w.str(clean(p.public_hex, 64));
    w.u16(p.port);
    w.str(clean(p.message, std::min<size_t>(lim.text_len, 300)));
    w.str(clean(p.token_hex, 64));
    size_t n = std::min(p.pending.size(), kMaxPending);
    w.u16(static_cast<uint16_t>(n));
    for (size_t i = 0; i < n; ++i) {
        const PairPendingInfo& q = p.pending[i];
        w.u32(q.id);
        w.str(clean(q.name, 200));
        w.str(clean(q.sas, 40));
        w.str(clean(q.ip, 64));
        w.u32(q.seconds_left);
    }
}

PairInfo get_pair(Reader& r) {
    PairInfo p;
    p.available = r.boolean();
    p.mode_on = r.boolean();
    p.seconds_left = r.u32();
    p.public_hex = r.str();
    p.port = r.u16();
    p.message = r.str();
    p.token_hex = r.str();
    size_t n = r.u16();
    if (n > kMaxPending) throw Error("control message: too many pairing requests");
    for (size_t i = 0; i < n; ++i) {
        PairPendingInfo q;
        q.id = r.u32();
        q.name = r.str();
        q.sas = r.str();
        q.ip = r.str();
        q.seconds_left = r.u32();
        p.pending.push_back(std::move(q));
    }
    return p;
}

constexpr size_t kMaxPendingInvites = 8;

void put_invites(Writer& w, const InviteListInfo& v, const Limits& lim) {
    w.boolean(v.allowed);
    w.str(clean(v.machine, 200));
    w.str(clean(v.fingerprint, 40));
    w.u16(v.port);
    w.str(clean(v.root, 1024));
    w.str(clean(v.created_code, 1500));
    size_t ni = std::min({v.invites.size(), lim.items, kMaxInviteRows});
    w.u16(static_cast<uint16_t>(ni));
    for (size_t i = 0; i < ni; ++i) {
        const InviteView& x = v.invites[i];
        w.str(clean(x.id_hex, 16));
        w.str(clean(x.label, 200));
        w.str(clean(x.folder, 400));
        w.str(clean(x.created_by, 16));
        w.u8(static_cast<uint8_t>(x.perm));
        w.str(clean(x.state, 16));
        w.u32(x.uses_left);
        w.u32(x.uses_total);
        w.i64(x.expires_unix);
        w.boolean(x.ask);
    }
    size_t nj = std::min({v.joined.size(), lim.items, kMaxInviteRows});
    w.u16(static_cast<uint16_t>(nj));
    for (size_t i = 0; i < nj; ++i) {
        const JoinedMachineView& x = v.joined[i];
        w.str(clean(x.name, 200));
        w.str(clean(x.key_hex, 64));
        w.str(clean(x.when_utc, 32));
        w.str(clean(x.invite_id_hex, 16));
        w.str(clean(x.folder, 400));
        w.u8(static_cast<uint8_t>(x.perm));
    }
    size_t np = std::min(v.pending.size(), kMaxPendingInvites);
    w.u16(static_cast<uint16_t>(np));
    for (size_t i = 0; i < np; ++i) {
        const simple::PendingInvite& q = v.pending[i];
        w.u32(q.id);
        w.str(clean(q.name, 200));
        w.str(clean(q.sas, 40));
        w.str(clean(q.ip, 64));
        w.u32(static_cast<uint32_t>(std::max(0, q.seconds_left)));
        w.str(clean(q.label, 200));
    }
}

simple::InvitePerm get_perm(Reader& r) {
    uint8_t p = r.u8();
    if (p > 1) throw Error("control message: bad permission");
    return static_cast<simple::InvitePerm>(p);
}

InviteListInfo get_invites(Reader& r) {
    InviteListInfo v;
    v.allowed = r.boolean();
    v.machine = r.str();
    v.fingerprint = r.str();
    v.port = r.u16();
    v.root = r.str();
    v.created_code = r.str();
    size_t ni = r.u16();
    if (ni > kMaxInviteRows) throw Error("control message: too many invites");
    for (size_t i = 0; i < ni; ++i) {
        InviteView x;
        x.id_hex = r.str();
        x.label = r.str();
        x.folder = r.str();
        x.created_by = r.str();
        x.perm = get_perm(r);
        x.state = r.str();
        x.uses_left = r.u32();
        x.uses_total = r.u32();
        x.expires_unix = r.i64();
        x.ask = r.boolean();
        v.invites.push_back(std::move(x));
    }
    size_t nj = r.u16();
    if (nj > kMaxInviteRows) throw Error("control message: too many joined machines");
    for (size_t i = 0; i < nj; ++i) {
        JoinedMachineView x;
        x.name = r.str();
        x.key_hex = r.str();
        x.when_utc = r.str();
        x.invite_id_hex = r.str();
        x.folder = r.str();
        x.perm = get_perm(r);
        v.joined.push_back(std::move(x));
    }
    size_t np = r.u16();
    if (np > kMaxPendingInvites) throw Error("control message: too many waiting invites");
    for (size_t i = 0; i < np; ++i) {
        simple::PendingInvite q;
        q.id = r.u32();
        q.name = r.str();
        q.sas = r.str();
        q.ip = r.str();
        q.seconds_left = static_cast<int>(std::min<uint32_t>(r.u32(), 86400));
        q.label = r.str();
        v.pending.push_back(std::move(q));
    }
    return v;
}

bool needs_payload(ControlOp op) {
    return op == ControlOp::InviteCreate || op == ControlOp::InviteRevoke || op == ControlOp::InviteRemoveMachine;
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
    case ControlOp::PairModeOn:
    case ControlOp::PairModeOff:
    case ControlOp::PairList:
    case ControlOp::PairApprove:
    case ControlOp::PairDeny:
        put_pair(w, m.pair, lim);
        break;
    case ControlOp::InviteCreate:
    case ControlOp::InviteList:
    case ControlOp::InviteRevoke:
    case ControlOp::InviteRemoveMachine:
    case ControlOp::InviteApprove:
    case ControlOp::InviteDeny:
        put_invites(w, m.invites, lim);
        break;
    }
    return w.take();
}

bool known_op(uint8_t op) { return op >= 1 && op <= 15; }

}  // namespace

const char* control_op_name(ControlOp op) {
    switch (op) {
    case ControlOp::Ping: return "PING";
    case ControlOp::GetStatus: return "GET_STATUS";
    case ControlOp::ReloadConfig: return "RELOAD_CONFIG";
    case ControlOp::GetRecentErrors: return "GET_RECENT_ERRORS";
    case ControlOp::PairModeOn: return "PAIR_MODE_ON";
    case ControlOp::PairModeOff: return "PAIR_MODE_OFF";
    case ControlOp::PairList: return "PAIR_LIST";
    case ControlOp::PairApprove: return "PAIR_APPROVE";
    case ControlOp::PairDeny: return "PAIR_DENY";
    case ControlOp::InviteCreate: return "INVITE_CREATE";
    case ControlOp::InviteList: return "INVITE_LIST";
    case ControlOp::InviteRevoke: return "INVITE_REVOKE";
    case ControlOp::InviteRemoveMachine: return "INVITE_REMOVE_MACHINE";
    case ControlOp::InviteApprove: return "INVITE_APPROVE";
    case ControlOp::InviteDeny: return "INVITE_DENY";
    }
    return "?";
}

Bytes encode_request(const ControlRequest& q) {
    Writer w;
    w.u16(kControlVersion);
    w.u8(static_cast<uint8_t>(q.op));
    w.u64(q.token);
    w.u32(q.arg);
    if (needs_payload(q.op)) {
        if (q.payload.empty() || q.payload.size() > kMaxRequestPayload) throw Error("control message: bad payload size");
        w.u32(static_cast<uint32_t>(q.payload.size()));
        w.raw(q.payload.data(), q.payload.size());
    } else if (!q.payload.empty()) {
        throw Error("control message: this operation takes no payload");
    }
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
    if (needs_payload(q.op)) {   // required for these ops and forbidden for all others, so old requests stay strict
        uint32_t len = r.u32();
        if (len == 0 || len > kMaxRequestPayload || len > r.remaining()) throw Error("control message: bad payload size");
        q.payload.resize(len);
        r.raw(q.payload.data(), len);
    }
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
    case ControlOp::PairModeOn:
    case ControlOp::PairModeOff:
    case ControlOp::PairList:
    case ControlOp::PairApprove:
    case ControlOp::PairDeny:
        m.pair = get_pair(r);
        break;
    case ControlOp::InviteCreate:
    case ControlOp::InviteList:
    case ControlOp::InviteRevoke:
    case ControlOp::InviteRemoveMachine:
    case ControlOp::InviteApprove:
    case ControlOp::InviteDeny:
        m.invites = get_invites(r);
        break;
    }
    r.expect_end();
    return m;
}

Bytes encode_invite_create(const InviteCreateReq& q) {
    Writer w;
    w.str(clean(q.folder, 400));
    w.str(clean(q.label, 200));
    w.u8(static_cast<uint8_t>(q.perm));
    w.u32(q.ttl_seconds);
    w.u32(q.uses);
    w.boolean(q.ask);
    size_t n = std::min(q.addrs.size(), simple::kInviteMaxAddrs);
    w.u8(static_cast<uint8_t>(n));
    for (size_t i = 0; i < n; ++i) {
        w.str(clean(q.addrs[i].host, 255));
        w.u16(q.addrs[i].port);
    }
    return w.take();
}

InviteCreateReq decode_invite_create(const Bytes& b) {
    Reader r(b);
    InviteCreateReq q;
    q.folder = r.str();
    q.label = r.str();
    q.perm = get_perm(r);
    q.ttl_seconds = r.u32();
    q.uses = r.u32();
    q.ask = r.boolean();
    size_t n = r.u8();
    if (n > simple::kInviteMaxAddrs) throw Error("control message: too many addresses");
    for (size_t i = 0; i < n; ++i) {
        simple::InviteAddr a;
        a.host = r.str();
        a.port = r.u16();
        q.addrs.push_back(std::move(a));
    }
    r.expect_end();
    return q;
}

Bytes encode_invite_text(const std::string& s) {
    Writer w;
    w.str(clean(s, 200));
    return w.take();
}

std::string decode_invite_text(const Bytes& b) {
    Reader r(b);
    std::string s = r.str();
    r.expect_end();
    return s;
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
