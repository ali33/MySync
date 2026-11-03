// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/invite.h - the ONE invite code (MSY2) that connects a sending machine to a receiving one.
// Whatever the receiving side produces is exactly what the sending side's UI consumes: a single code.
// Design and threat model: docs/DESIGN.md, "Mã mời MSY2". In short:
//  * The receiver (desktop GUI via the control channel, or `mysync invite create` on a server) creates an invite:
//    a random 64-bit id and a random 128-bit secret. The receiver stores ONLY a verifier derived from the secret
//    (an Ed25519 public key whose seed is BLAKE2b("MSY2-seed" || secret)), never the secret.
//  * The code carries the receiver's PUBLIC key, 1..3 host:port addresses, the id, the secret, the expiry, perm and labels.
//    It never carries a private key.
//  * Redemption: the sender connects with Noise IK pinned to the key from the code (so a man in the middle cannot answer)
//    and, inside the encrypted channel, sends REDEEM(id, flags, signature, device name). The signature (made with the
//    key derived from the secret) covers "MSY2-redeem-v1" || flags || handshake hash || sender public key || id: it is bound
//    to THIS session and cannot be replayed on another one. The receiver verifies it, checks (constant time where it
//    matters) not expired / uses left / not revoked, then adds the sender to the allowlist with the invite's perm and
//    subdir through peer_add (atomic, same code path as `mysync peer add`), decrements the uses and writes an audit line.
//  * Failed attempts are rate limited per IP. An unpaired session may say only REDEEM / POLL / BYE.
//  * [server] pairing = "off" switches off ONLY the invites created through the GUI / control channel; an invite an
//    administrator created with `mysync invite create` keeps working (the administrator is the one who made it).
//  * Accepting an invite on a server never asks anybody: confirmation exists only for GUI invites with `ask` set (the
//    receiver's user then sees the SAS string and clicks Đồng ý, as before).
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mysync/keys.h"
#include "mysync/util.h"

namespace mysync {
struct ServerConfig;
struct ClientAcl;
}

namespace mysync::simple {

constexpr int kInviteDefaultTtlSeconds = 24 * 3600;
constexpr int kInviteMaxTtlSeconds = 30 * 24 * 3600;
constexpr int kInviteDefaultUses = 1;
constexpr int kInviteMaxUses = 100;
constexpr size_t kInviteMaxAddrs = 3;
constexpr size_t kInviteLabelMaxChars = 40;

enum class InvitePerm : uint8_t { ReadOnly = 0, ReadWrite = 1 };
const char* invite_perm_name(InvitePerm);   // "ro" | "rw"

using InviteId = std::array<uint8_t, 8>;
using InviteSecret = std::array<uint8_t, 16>;

struct InviteAddr {
    std::string host;   // IPv4 / IPv6 literal or DNS name (valid_pair_host)
    uint16_t port = 0;
};

// What the code carries.
struct InviteCode {
    PubKey server_key{};
    InviteId id{};
    InviteSecret secret{};
    int64_t expires_unix = 0;        // seconds since 1970 (UTC), fits u32
    InvitePerm perm = InvitePerm::ReadWrite;
    std::vector<InviteAddr> addrs;   // 1..kInviteMaxAddrs, most useful first
    std::string machine;             // the receiver's machine name, for the sender to read (cleaned display text)
    std::string label;               // the folder label, for the sender to read
};

// "MSY2-" + Crockford base32 (as simple/pair_code.h) in groups of 5 separated by '-' of:
//   version(1)=1 | server key (32) | id (8) | secret (16) | expires u32 BE | perm (1) | n_addrs (1) |
//   n x [port u16 BE | host len (1) | host] | machine len (1) | machine | label len (1) | label | checksum (4)
// checksum = first 4 bytes of BLAKE2b-256 of every byte before it. decode throws Error with generic text (never echoes the
// input) for: wrong prefix/version, characters outside the alphabet, wrong length, bad checksum, absurd host/port/count,
// invalid UTF-8 or control characters in the labels, extra bytes, perm other than 0/1.
std::string encode_invite_code(const InviteCode&);   // throws Error for an invalid field
InviteCode decode_invite_code(const std::string& text);
bool looks_like_invite_code(const std::string& text);  // cheap prefix test for the GUI (no checksum)
std::string invite_id_hex(const InviteId&);            // 16 hex
bool parse_invite_id(const std::string& hex16, InviteId& out);
// The folder an invite hands out: an ABSOLUTE path (of any folder on this machine, not necessarily under the server's root),
// 1..600 bytes of valid UTF-8, no control character, no ".." / "__sync" component. Each machine that joins is confined to it.
bool valid_invite_folder(const std::string&);
std::string canonical_folder(const std::string&);                  // weakly_canonical, no trailing separator
bool folder_within(const std::string& inner, const std::string& outer);   // equal counts as within (case-insensitive on Windows)
bool same_folder(const std::string& a, const std::string& b);
// Which folders are taken, to keep two machines from ever getting overlapping ones. `shareable` = another invitation may hand
// out exactly the same folder (equal is allowed, any other overlap is not).
struct FolderUse {
    std::string path;
    bool shareable = false;
    std::string what;   // for the message
};
// "" when `folder` may be handed out; else why not. protected_paths = configuration folder, key files, state folder ...: the
// folder may neither contain nor lie inside them.
std::string folder_conflict(const std::string& folder, const std::vector<FolderUse>& in_use, const std::vector<std::string>& protected_paths);
// 5 groups of 4 hex of BLAKE2b(public key): "aaaa-bbbb-cccc-dddd-eeee" (the same function the key tab shows).
std::string invite_fingerprint(const PubKey&);

// The keys derived from the secret (exposed for tests).
struct InviteProof {
    std::array<uint8_t, 32> verifier{};   // stored by the receiver
    std::array<uint8_t, 64> eddsa_secret{};  // kept by the sender only for the moment of signing; wipe after use
};
InviteProof derive_invite_proof(const InviteSecret&);
// 64-byte signature over the session binding described above.
std::array<uint8_t, 64> sign_redeem(const InviteSecret&, uint8_t flags, const std::array<uint8_t, 64>& handshake_hash,
                                    const PubKey& sender_pub, const InviteId&);
bool verify_redeem(const std::array<uint8_t, 32>& verifier, const std::array<uint8_t, 64>& sig, uint8_t flags,
                   const std::array<uint8_t, 64>& handshake_hash, const PubKey& sender_pub, const InviteId&);

// ---------------------------------------------------------------- the receiver's store (invites.d)
// One file <id>.invite per invite in `dir` (created 0700 / private), text "key = value" lines, written atomically
// (temp file + rename) under a cross-process lock (a lock file in `dir`), so `mysync invite create` in one process and the
// running server redeeming in another never lose an update. Never holds a secret.
struct InviteJoined {
    std::string name;       // device name the sender gave
    std::string key_hex;    // its public key (64 hex)
    std::string when_utc;   // "YYYY-MM-DD HH:MM"
};

struct InviteRecord {
    std::string id_hex;                 // 16 hex
    std::string label;                  // folder label
    std::string machine;                // receiver machine name
    std::string folder;                 // absolute folder this invite grants (canonical); the machine is confined to it
    InvitePerm perm = InvitePerm::ReadWrite;
    std::array<uint8_t, 32> verifier{};
    int uses_total = 1;
    int uses_left = 1;
    int64_t created_unix = 0;
    int64_t expires_unix = 0;
    std::string created_by;             // "cli" | "gui"
    bool ask = false;                   // GUI only: the receiver's user confirms (SAS) before the sender is let in
    bool revoked = false;
    std::vector<InviteJoined> joined;
    // Derived for display; not stored.
    enum class State { Live, Expired, UsedUp, Revoked };
    State state(int64_t now_unix) const;
};

struct InviteNew {
    std::string folder;                 // absolute folder to hand out (valid_invite_folder)
    std::string label;
    std::string machine;
    InvitePerm perm = InvitePerm::ReadWrite;
    int ttl_seconds = kInviteDefaultTtlSeconds;   // 1..kInviteMaxTtlSeconds
    int uses = kInviteDefaultUses;                // 1..kInviteMaxUses
    std::string created_by = "cli";
    bool ask = false;
    PubKey server_key{};
    std::vector<InviteAddr> addrs;
};

class InviteStore {
public:
    using Clock = std::function<int64_t()>;   // unix seconds (tests inject)
    explicit InviteStore(std::string dir, Clock clock = {});
    const std::string& dir() const { return dir_; }

    // Creates the invite and returns the code (the ONLY place the secret exists besides the code itself). Throws Error.
    InviteCode create(const InviteNew&);
    std::vector<InviteRecord> list() const;           // newest first; unreadable files are skipped with a log_warn
    // By full id or unique prefix (>= 4 hex). false when nothing matched; Error when the prefix is ambiguous.
    bool revoke(const std::string& id_or_prefix);
    bool has_live(bool include_cli_only = true, bool include_gui = true) const;   // cheap: any invite that could still be redeemed
    // Atomically: finds the invite, checks not revoked / not expired / uses left, and (unless dry_run) decrements the uses
    // and appends `joined`. Returns the record AS IT WAS BEFORE the change (so subdir/perm are the granted ones), or an
    // empty optional when it cannot be redeemed (the reason is deliberately not told to the caller).
    struct Consumed { bool ok = false; InviteRecord rec; };
    // joiner_key_hex empty = no `joined` entry is written (the `ask` flow adds it with note_joined once approved).
    // allow_gui=false: an invite created by "gui" cannot be redeemed (pairing = "off").
    Consumed consume(const InviteId&, const std::string& joiner_name, const std::string& joiner_key_hex, bool dry_run,
                     bool allow_gui = true);
    // Gives one use back (an approval that failed after consume) and drops the `joined` entry of that key. No-op when unknown.
    void refund(const InviteId&, const std::string& joiner_key_hex = {});
    void note_joined(const InviteId&, const std::string& joiner_name, const std::string& joiner_key_hex);
    // One invite by full id (no secrets in it); empty optional when unknown / unreadable.
    bool get(const InviteId&, InviteRecord& out) const;
    void purge_old(int64_t keep_days = 30);           // removes invites expired / used up / revoked for more than keep_days
    int64_t now() const;

private:
    std::string dir_;
    Clock clock_;
};

std::vector<FolderUse> folders_in_use(const ServerConfig& cfg, const std::vector<ClientAcl>& peers, const std::vector<InviteRecord>& invites,
                                      int64_t now_unix);

// ---------------------------------------------------------------- wire (inside the SecureChannel; first byte >= 0x40)
// Extends simple/pairing.h's PairMsg range: 0x42 Redeem, 0x56 Granted, 0x57 Rejected. (0x40..0x41, 0x50..0x54 are taken.)
enum class InviteMsg : uint8_t { Redeem = 0x42, Granted = 0x56, Rejected = 0x57 };
struct RedeemWire {
    InviteId id{};
    uint8_t flags = 0;                  // bit0 = dry run (probe: nothing is consumed, nothing is added)
    std::array<uint8_t, 64> sig{};
    std::string name;                   // device name (clean_display_name)
};
struct GrantedWire {
    uint8_t flags = 0;                  // bit0 = dry run answer; bit1 = waiting for the receiver's user to confirm (poll)
    InvitePerm perm = InvitePerm::ReadWrite;
    std::string subdir;                 // no longer used (always empty): the receiver confines the sender to its own folder
    std::string machine, label;
    int64_t expires_unix = 0;
    uint32_t uses_left = 0;
    uint32_t seconds_left = 0;          // when waiting for confirmation
};
Bytes encode_redeem_wire(const RedeemWire&);
RedeemWire decode_redeem_wire(const Bytes&);       // throws Error
Bytes encode_granted_wire(const GrantedWire&);
GrantedWire decode_granted_wire(const Bytes&);     // throws Error
bool is_invite_wire(const Bytes&);                 // first byte is a RedeemWire / GrantedWire / Rejected type

// ---------------------------------------------------------------- the receiver's session logic
struct RedeemRequest {
    std::string ip;
    PubKey sender_key{};
    std::array<uint8_t, 64> handshake_hash{};   // SecureChannel::handshake_hash() of THIS session
    Bytes raw;                                   // the message as received
};

struct PendingInvite {      // an `ask` invite waiting for the receiver's user
    uint32_t id = 0;
    std::string name;
    std::string sas;        // pair_sas(sender, server): both screens show the same string
    std::string ip;
    int seconds_left = 0;
    std::string label;
};

class InviteManager {
public:
    // GrantFn adds the sender to the allowlist with perm/folder ATOMICALLY (peer_add + reload + apply, rolled back on error) and
    // returns the canonical subdir. Throws Error to refuse (the use is then refunded).
    using GrantFn = std::function<std::string(const std::string& name, const PubKey& key, InvitePerm perm, const std::string& folder)>;
    using ClockMs = std::function<int64_t()>;
    InviteManager(const PubKey& server_pub, std::shared_ptr<InviteStore> store, ClockMs clock = {});
    void set_grant_handler(GrantFn);
    // pairing = "off" in the configuration: GUI invites (created_by == "gui") are then refused, CLI ones keep working.
    void set_gui_invites_allowed(bool allowed);

    // Handshake admission for a key NOT in the allowlist: true when some invite could be redeemed AND the per-IP / global
    // budgets allow. A true answer takes one of the unpaired-session places: the caller MUST call session_ended(ip) once.
    bool admit_handshake(const std::string& ip, const PubKey& key);
    void session_ended(const std::string& ip);

    struct Reply { Bytes msg; bool close = false; bool failed_auth = false; };
    Reply on_message(const RedeemRequest&);           // never throws. A bad id / signature / expired / used up / revoked: the same generic Rejected
    // Operator side of the `ask` flow
    std::vector<PendingInvite> pending() const;
    std::string approve(uint32_t id);                 // runs GrantFn; returns the canonical subdir; throws Error
    void deny(uint32_t id);
    // Revokes in the store AND drops the waiting requests of that invitation (they could otherwise still be approved).
    bool revoke(const std::string& id_or_prefix);

    InviteStore& store() { return *store_; }

private:
    struct Impl;
    std::shared_ptr<Impl> p_;
    void flush_refunds() const;   // gives back the uses of waiting requests that timed out (store I/O, outside the lock)
    std::shared_ptr<InviteStore> store_;
};

// ---------------------------------------------------------------- the sender's side
// What the receiver says it will grant (from the code, confirmed by the receiver on a dry run / on redemption).
struct InviteGrant {
    std::string machine;            // receiver machine name
    std::string label;              // folder label
    InvitePerm perm = InvitePerm::ReadWrite;
    std::string subdir;             // canonical (known only after the receiver answered)
    int64_t expires_unix = 0;
    uint32_t uses_left = 0;
    std::string fingerprint;        // of the receiver key (for "Chi tiet")
    InviteAddr address;             // the address that answered
    PubKey server_key{};
};

struct InviteOutcome {
    enum Kind {
        Ok,           // probe: the code works; redeem: joined (grant is the canonical result)
        BadCode,      // cannot be decoded (checksum, format)
        Expired,      // past its expiry (checked locally first, then by the receiver)
        Unreachable,  // none of the addresses answered / pinned key mismatch (the two are NOT told apart)
        Refused,      // the receiver rejected it: used up, revoked, wrong secret, the user said no, pairing off ...
        Busy,         // too many attempts / another request waiting: try again in a minute
        Cancelled,
        Failed
    } kind = Failed;
    std::string message;            // English, verbatim detail; the GUI translates by `kind`
    InviteGrant grant;
};

// Dry run: decodes nothing (takes an already decoded code), tries each address in order with Noise IK pinned to the code's
// key, sends REDEEM with the dry-run flag and consumes nothing. Fast (connect timeout ~5 s per address).
InviteOutcome probe_invite(const InviteCode&, const KeyPair& self, const std::atomic<bool>& cancel);
// The real thing: as above, not dry run. When the receiver set `ask`, it waits (poll) up to timeout_s and calls
// progress(seconds_left). On Ok the receiver already let this machine in; the caller now adds the target to its own config.
InviteOutcome redeem_invite(const InviteCode&, const KeyPair& self, const std::string& device_name, const std::atomic<bool>& cancel,
                            const std::function<void(int)>& progress = {}, int timeout_s = 130);
// The confirmation string for `ask` invites (equal to the receiver's).
std::string invite_sas(const InviteCode&, const KeyPair& self);

}  // namespace mysync::simple
