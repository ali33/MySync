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
//    <root>/__sync/__trash/<UTC timestamp>/<path relative to root>.
#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mysync/config.h"
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

// Sliding-window limiter of failed authentications per source IP (60 s window). Thread-safe.
class AuthThrottle {
public:
    explicit AuthThrottle(uint32_t max_failures_per_min) : max_(max_failures_per_min) {}
    bool blocked(const std::string& ip, int64_t now_ms);
    void record_failure(const std::string& ip, int64_t now_ms);

private:
    uint32_t max_;
    std::mutex m_;
    std::map<std::string, std::deque<int64_t>> fails_;
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
    // still in progress can delay the return by up to SecureChannel::kHandshakeTimeoutMs.
    void run(std::atomic<bool>& stop);
    uint16_t port() const;
    const PubKey& public_key() const;

private:

    std::unique_ptr<detail::ServerCore> p_;
};

} // namespace mysync
