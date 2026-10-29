// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// net.h - CONTRACT header: thin blocking TCP socket wrapper (Winsock / BSD).
#include <memory>
#include <string>

#include "mysync/util.h"

namespace mysync::net {

// Call once per process before any socket use (WSAStartup on Windows; ignores SIGPIPE on Linux). Idempotent.
void init();

class Socket {
public:
    Socket() = default;
    ~Socket();
    Socket(Socket&&) noexcept;
    Socket& operator=(Socket&&) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    // Client: resolve host (IPv4/IPv6), connect with timeout, set TCP_NODELAY. Throws Error.
    static Socket connect(const std::string& host, uint16_t port, int timeout_ms);
    // Server: bind+listen. bind_addr "*" or "" = all interfaces (prefers dual-stack ::), else literal IP.
    static Socket listen(const std::string& bind_addr, uint16_t port, int backlog = 128);
    // Wait up to timeout_ms for a connection; returns invalid Socket on timeout. Throws Error on failure.
    Socket accept(int timeout_ms, std::string* peer_ip = nullptr);

    bool valid() const;
    uint16_t local_port() const;                // useful when listen(…, 0)
    void set_timeouts(int recv_ms, int send_ms); // 0 = none
    void set_buffers(int bytes);                 // SO_SNDBUF/SO_RCVBUF hint
    void send_all(const void* data, size_t n);   // throws Error on failure/timeout
    void recv_all(void* data, size_t n);         // exactly n bytes; throws Error on EOF/timeout
    size_t recv_some(void* data, size_t max);    // 0 = orderly EOF
    void shutdown_both();                        // wakes blocked threads
    void close();

private:
    intptr_t fd_ = -1;
};

} // namespace mysync::net
