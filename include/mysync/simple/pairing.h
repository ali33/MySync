// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/pairing.h - pairing two machines with a code, no administrator and no copy-pasting of keys.
// Design and threat model: docs/DESIGN.md, "Ghép máy bằng mã". In short:
//  * The RECEIVER turns "pairing mode" on on purpose (default off, switches itself off after 10 minutes). While on, a
//    key that is NOT in the allowlist may complete the Noise handshake, but its session is "unpaired": the only
//    messages accepted are PAIR_REQUEST / PAIR_POLL / BYE. Anything else (HELLO, OFFER, LIST ...) is refused and the
//    connection closed. No right whatsoever is granted before the receiver's user approves.
//  * Only 1 request waits for approval (a second one gets BUSY); it expires after 2 minutes; 3 requests/min per IP and
//    10/min overall; a denied key is blocked for 10 minutes.
//  * The SENDER pins the receiver's key taken from the code, so a man in the middle cannot answer. Both screens show
//    the same SAS (pair_sas) computed from the two public keys; the receiver's user compares before approving.
//  * Approval adds a [[client]] (name, public_key, access "rw", prefix "from-<name>") through the ConfigEditor and
//    applies it live (Server::apply_config).
// Thread-safe. Errors thrown are mysync::Error with generic text (no information about other keys / requests).
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "mysync/keys.h"
#include "mysync/simple/pair_code.h"
#include "mysync/util.h"

namespace mysync::simple {

constexpr int kPairWindowSeconds = 600;      // pairing mode lasts at most this long
constexpr int kPairRequestTtlSeconds = 120;  // a pending request expires
constexpr int kPairDenyBlockSeconds = 600;   // a denied key is blocked
constexpr int kPairRequestsPerIpPerMin = 3;
constexpr int kPairRequestsGlobalPerMin = 10;
constexpr size_t kPairNameMaxChars = 40;
// Unpaired sessions alive at once (they do not use the normal connection budget): overall and per source address.
constexpr int kPairMaxSessions = 4;
constexpr int kPairMaxSessionsPerIp = 2;

// ---- wire (carried inside the normal SecureChannel; first byte >= 0x40 so it can never be a proto::MsgType)
enum class PairMsg : uint8_t { Request = 0x40, Poll = 0x41, Wait = 0x50, Ok = 0x51, Denied = 0x52, Busy = 0x53, Error = 0x54 };
using PairToken = std::array<uint8_t, 16>;
struct PairWire {
    PairMsg type = PairMsg::Poll;
    std::string name;            // Request: display name of the sending machine
    PairToken token{};           // Request: the one-time token from the pairing code (travels inside the encrypted channel)
    uint32_t seconds_left = 0;   // Wait: how long the request stays valid
};
Bytes encode_pair_wire(const PairWire&);
PairWire decode_pair_wire(const Bytes&);  // throws Error (truncation, trailing bytes, bad name, unknown type)
bool is_pair_wire(const Bytes&);          // first byte in the pairing range (cheap test)

// Returns the name trimmed, or "" when it is not acceptable: empty, more than kPairNameMaxChars code points,
// invalid UTF-8, any control / format / line-separator / bidi-override character.
std::string clean_display_name(const std::string& name);
// "from-<name>" reduced to [a-z0-9._-] (letters lower-cased, Vietnamese diacritics removed, other characters
// become '-'), never "." / ".." / leading dot, at most 48 bytes, made unique against `existing` with "-2", "-3"...
// Safe as a one-component folder name under the receiving root.
std::string safe_pair_prefix(const std::string& display_name, const std::set<std::string>& existing);

// ---- receiver side
struct PendingPair {
    uint32_t id = 0;
    std::string name;
    PubKey key{};
    std::string sas;
    std::string ip;
    int seconds_left = 0;
};

class PairingManager {
public:
    using ClockMs = std::function<int64_t()>;  // monotonic milliseconds (tests inject)
    // Called on approval, under no lock of the manager: must add the client to the allowlist and apply it live.
    // Returns the prefix granted. Throws Error to refuse (the request then stays pending).
    using ApproveFn = std::function<std::string(const std::string& name, const PubKey& key)>;

    explicit PairingManager(const PubKey& server_pub, ClockMs clock = {});
    void set_approve_handler(ApproveFn fn);
    // Called by deny() (and only then) to make sure the key is NOT in the allowlist any more - e.g. an approval that failed
    // half way and could not be rolled back. Must also cut any open session of that key. Errors are logged, not thrown.
    using RevokeFn = std::function<void(const PubKey& key)>;
    void set_revoke_handler(RevokeFn fn);

    // Operator (reached through the control channel)
    // Turns the mode on and creates a NEW one-time token (any earlier one dies). Only the BLAKE2b hash of the token is
    // kept; the caller (the GUI, through the user-only control channel) is the only one who ever sees it, to build the
    // code. The token is burned by the first request that proves it (granted, denied or expired alike), by disable()
    // and when the window ends: one pairing per switch-on. Without a live token unknown keys are refused at the handshake.
    PairToken enable(int seconds = kPairWindowSeconds);  // seconds clamped to 1..kPairWindowSeconds
    void disable();                                 // also drops every pending request
    bool enabled() const;
    int seconds_left() const;                       // 0 when off
    std::vector<PendingPair> pending() const;
    std::string approve(uint32_t id);               // returns the prefix; throws Error if unknown / expired / mode off
    void deny(uint32_t id);                         // blocks the key for kPairDenyBlockSeconds; throws Error if unknown

    // Server session side
    // Handshake admission for a key that is NOT in the allowlist. False = behave exactly as before pairing existed.
    // A true answer takes one of the kPairMaxSessions places: the caller MUST call session_ended(ip) exactly once.
    bool admit_handshake(const std::string& ip, const PubKey& key);
    void session_ended(const std::string& ip);
    struct Reply {
        Bytes msg;           // empty = send nothing
        bool close = false;  // close the connection after sending
    };
    // One message (undecoded) from an unpaired session. Never throws.
    Reply on_message(const std::string& ip, const PubKey& key, const Bytes& raw);

private:
    struct Impl;
    std::shared_ptr<Impl> p_;
};

// ---- sender side
struct PairOutcome {
    enum Kind { Approved, Denied, Busy, Expired, Cancelled, Failed } kind = Failed;
    std::string message;  // human text (English); the GUI translates by `kind`
};

class PairingClient {
public:
    // `self` is the sending machine's identity (generate_keypair / load_keypair). display_name goes through
    // clean_display_name (throws Error if unusable).
    PairingClient(const PairCode& code, const KeyPair& self, const std::string& display_name);
    // The confirmation string to show before / while waiting; equals the receiver's.
    std::string sas() const;
    // Connects with the server key pinned from the code, sends PAIR_REQUEST, polls until approved / denied / expired /
    // cancelled / timeout_s. progress(seconds_left) is called after each poll answer (from the calling thread).
    PairOutcome run(const std::atomic<bool>& cancel, const std::function<void(int)>& progress = {},
                    int timeout_s = kPairRequestTtlSeconds + 5);

private:
    PairCode code_;
    KeyPair self_;
    std::string name_;
};

// This machine's name for the other side to read (host name cleaned by clean_display_name; falls back to "MySync").
std::string default_device_name();

}  // namespace mysync::simple
