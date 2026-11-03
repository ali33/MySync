// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/control_protocol.h - binary request/response of the local control channel (GUI <-> daemon).
//
// Frame on the wire: u32 big-endian length N (1..kMaxMessageBytes) followed by N payload bytes. A frame larger
// than kMaxMessageBytes is refused BEFORE any allocation. Payloads use proto::Writer / proto::Reader (big-endian).
//   request : u16 version, u8 op, u64 token, u32 arg           (arg = max entries for GET_RECENT_ERRORS)
//             [, u32 n, n bytes payload]                       (ONLY Invite{Create,Revoke,RemoveMachine}; the other ops have none)
//   response: u16 version, u8 op, u64 token (echo), u8 status, str error, then the body of the op
// The channel never carries secret keys, in either direction. Decoders throw mysync::Error on any malformed
// input (truncation, trailing bytes, unknown op, absurd counts) and never allocate from an unchecked length.
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/gui/invite_ops.h"
#include "mysync/gui/status.h"
#include "mysync/util.h"

namespace mysync::gui {

constexpr uint32_t kMaxMessageBytes = 64 * 1024;
constexpr uint16_t kControlVersion = 1;
constexpr uint32_t kMaxErrorsReturned = 100;

enum class ControlOp : uint8_t {
    Ping = 1, GetStatus = 2, ReloadConfig = 3, GetRecentErrors = 4,
    // Pairing (receiver daemon started with --allow-pairing; others answer Unsupported):
    PairModeOn = 5,   // arg = seconds (0 = 600, capped at 600)
    PairModeOff = 6,
    PairList = 7,     // doubles as GET_PAIR_CODE: the answer carries the public key and port
    PairApprove = 8,  // arg = request id
    PairDeny = 9,     // arg = request id
    // Invites (MSY2, gui/invite_ops.h). All answer Denied unless the daemon allows pairing; the answer carries `invites`.
    InviteCreate = 10,         // payload = encode_invite_create(...); the answer's created_code holds the code (once)
    InviteList = 11,
    InviteRevoke = 12,         // payload = invite id (16 hex, or a prefix of at least 4)
    InviteRemoveMachine = 13,  // payload = the machine's key (64 hex): taken out of the allowlist and revoked at once
    InviteApprove = 14,        // arg = pending id (the `ask` confirmation)
    InviteDeny = 15,
};
constexpr uint32_t kMaxRequestPayload = 2048;
constexpr size_t kMaxInviteRows = 50;      // invites / joined machines in one answer
enum class ControlStatus : uint8_t { Ok = 0, Failed = 1, BadRequest = 2, Unsupported = 3, Denied = 4 };
const char* control_op_name(ControlOp);

struct ControlRequest {
    ControlOp op = ControlOp::Ping;
    uint64_t token = 0;   // echoed back (PING uses it as the nonce)
    uint32_t arg = 0;     // GET_RECENT_ERRORS: how many (0 = default 50, capped at kMaxErrorsReturned)
    Bytes payload;        // InviteCreate / InviteRevoke / InviteRemoveMachine: required, <= kMaxRequestPayload; other ops: empty
};

struct ControlResponse {
    ControlOp op = ControlOp::Ping;
    uint64_t token = 0;
    ControlStatus status = ControlStatus::Ok;
    std::string error;                    // set when status != Ok (verbatim, no secrets)
    StatusSnapshot snapshot;              // GetStatus
    ReloadResult reload;                  // ReloadConfig
    std::vector<ErrorEntry> errors;       // GetRecentErrors (oldest first)
    PairInfo pair;                        // Pair* ops
    InviteListInfo invites;               // Invite* ops
};

// The payload of InviteCreate. Decoding throws Error on truncation / trailing bytes / absurd counts.
Bytes encode_invite_create(const InviteCreateReq&);
InviteCreateReq decode_invite_create(const Bytes&);
// The payload of InviteRevoke / InviteRemoveMachine: one short text.
Bytes encode_invite_text(const std::string&);
std::string decode_invite_text(const Bytes&);

Bytes encode_request(const ControlRequest&);
ControlRequest decode_request(const void* data, size_t n);
inline ControlRequest decode_request(const Bytes& b) { return decode_request(b.data(), b.size()); }

// Encoding truncates over-long free text (errors, file names, messages) and drops entries from the end of
// lists so a response always fits one frame.
Bytes encode_response(const ControlResponse&);
ControlResponse decode_response(const void* data, size_t n);
inline ControlResponse decode_response(const Bytes& b) { return decode_response(b.data(), b.size()); }

// 4-byte length prefix + payload. Throws Error when the payload is empty or larger than kMaxMessageBytes.
Bytes frame_message(const Bytes& payload);
// Validates a received length prefix; throws Error for 0 or > kMaxMessageBytes.
uint32_t parse_frame_length(const uint8_t header[4]);

}  // namespace mysync::gui
