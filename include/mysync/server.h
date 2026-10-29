// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// server.h - MySync server: accepts SecureChannel sessions, enforces per-client ACL (prefix / read-only),
// applies files atomically under `root` (temp file + BLAKE3 check + fsync + rename).
//
// Wire semantics worth knowing (see protocol.h):
//  - Paths from a client are relative to its virtual root = <root>/<ClientAcl::prefix>.
//  - OFFERs may be pipelined: the server answers each OFFER at once (SKIP / NEED_* / FILE_ERR), and for every
//    NEED_* answers once more (FILE_OK / FILE_ERR) after the matching ENDFILE. DATA / DELTA_OPS / ENDFILE apply to the
//    oldest unfinished NEED_* offer, so the client sends file contents in OFFER order.
//  - LIST_REQ{prefix}: entry paths are relative to <virtual root>/<prefix>.
//  - DELETE of a missing path succeeds (idempotent). With trash=true the path is moved to
//    <root>/__sync/__trash/<UTC timestamp>/<path relative to root>. The same happens to the old content of a file
//    that an upload overwrites (moved by rename, before the new content is renamed into place). The trash is capped
//    by ServerConfig::max_trash_bytes: older timestamp directories are purged first; a single item larger than the
//    cap is refused (FILE_ERR TooLarge) instead of being deleted or overwritten.
//  - Per client (ClientAcl): max_sessions caps its concurrent sessions (extra ones are answered with FILE_ERR Busy and
//    closed), max_write_bytes_per_hour caps received bytes in any sliding hour (FILE_ERR Busy, logged).
#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mysync/config.h"
#include "mysync/gui/status.h"
#include "mysync/keys.h"

namespace mysync {

namespace detail { struct ServerCore; }

// allow/deny lists of "*", IP or CIDR (IPv4 and IPv6; IPv4-mapped IPv6 addresses are treated as IPv4).
// Deny wins. An empty allow list permits nobody. Throws Error on a malformed entry.
class IpFilter {
public:
    IpFilter(const std::vector<std::string>& allow, const std::vector<std::string>& deny);
    bool permits(const std::string& ip) const;  // unparsable ip => false

private:
    struct Net {
        std::array<uint8_t, 16> addr{};
        int bits = 0;
    };
    static bool parse_ip(const std::string& s, std::array<uint8_t, 16>& out);
    static bool match(const Net& n, const std::array<uint8_t, 16>& ip);
    static Net parse_net(const std::string& s);
    bool allow_all_ = false;
    std::vector<Net> allow_, deny_;
};

// Sliding-window limiter of failed authentications per source (60 s window). Thread-safe. IPv4 addresses are keyed
// as is, IPv6 addresses by their /64 (a single host owns a whole /64, so per-address keys are free to rotate).
// At most kMaxEntries sources are tracked (the least recently failing one is dropped first) and expired entries
// are swept periodically, never by an O(n) scan on every call.
class AuthThrottle {
public:
    static constexpr size_t kMaxEntries = 10000;
    explicit AuthThrottle(uint32_t max_failures_per_min) : max_(max_failures_per_min) {}
    void set_max(uint32_t v) { max_ = v; }  // takes effect for the next call (config reload)
    bool blocked(const std::string& ip, int64_t now_ms);
    void record_failure(const std::string& ip, int64_t now_ms);
    size_t tracked();  // number of sources currently held

private:
    struct Entry {
        std::deque<int64_t> q;
        std::list<std::string>::iterator pos;  // place in order_
    };
    std::atomic<uint32_t> max_;
    std::mutex m_;
    std::map<std::string, Entry> fails_;
    std::list<std::string> order_;  // oldest last-failure first
    int64_t last_sweep_ms_ = INT64_MIN / 2;
};

// Sliding-window (one hour, minute buckets) budget of bytes a client may write. Thread-safe. limit 0 = unlimited.
// `now_ms` is any monotonic millisecond clock (the server passes steady_clock).
class WriteQuota {
public:
    explicit WriteQuota(uint64_t limit_per_hour) : limit_(limit_per_hour) { minute_.fill(-1); bytes_.fill(0); }
    bool would_exceed(uint64_t add, int64_t now_ms);  // true when charging `add` now would pass the limit
    bool charge(uint64_t add, int64_t now_ms);        // false (and nothing charged) when it would pass the limit
    uint64_t used(int64_t now_ms);                    // bytes charged within the last hour

private:
    uint64_t used_locked(int64_t now_min) const;
    uint64_t limit_;
    std::mutex m_;
    std::array<int64_t, 60> minute_;
    std::array<uint64_t, 60> bytes_;
};

class Server {
public:
    // Loads the server secret key from cfg.key_file. Creates root if missing, binds the listening socket
    // (cfg.port may be 0 here: pick a free port, see port()) and removes orphaned temp files older than 1 hour.
    // Throws Error.
    explicit Server(ServerConfig cfg);
    // Same, with an explicit identity (tests, embedding); cfg.key_file is ignored.
    Server(ServerConfig cfg, const KeyPair& key);
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Blocks, serving until stop becomes true; then wakes and joins every session. An authentication handshake
    // still in progress can delay the return by up to SecureChannel::kHandshakeTimeoutMs (a total budget).
    // Connections that have not finished the handshake are limited separately from cfg.max_connections (which caps
    // authenticated sessions): at most 4 per source and max(8, max_connections / 2) in all.
    void run(std::atomic<bool>& stop);
    uint16_t port() const;
    const PubKey& public_key() const;

    // Lightweight, thread-safe status for the GUI (role Server): listen address, sessions, per-client name /
    // sessions / bytes / rates. Carries no key material.
    gui::StatusSnapshot snapshot() const;
    // Hot reload: swaps the allowlist, ip allow/deny, limits, quotas, trash / mode / size settings and the
    // auth-failure throttle for sessions that start afterwards. A live session keeps its policy, except that it is
    // closed at its next request when its client was removed from the allowlist or its access / prefix changed.
    // Throws Error (and changes nothing) when bind / port / root / key_file / state_dir differ from the running
    // values: those need a restart. Paths in `n` must be resolved the same way as for the constructor.
    void apply_config(const ServerConfig& n);

private:

    std::unique_ptr<detail::ServerCore> p_;
};

} // namespace mysync
