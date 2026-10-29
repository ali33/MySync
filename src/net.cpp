// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/net.h"

#include <cerrno>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
static const sock_t kBad = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <csignal>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
using sock_t = int;
static const sock_t kBad = -1;
#endif

namespace mysync::net {

namespace {

int last_err() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string err_str(int e) {
#ifdef _WIN32
    return "winsock error " + std::to_string(e);
#else
    return std::strerror(e);
#endif
}

bool is_timeout(int e) {
#ifdef _WIN32
    return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK;
#else
    return e == EAGAIN || e == EWOULDBLOCK || e == ETIMEDOUT;
#endif
}

bool is_intr(int e) {
#ifdef _WIN32
    return e == WSAEINTR;
#else
    return e == EINTR;
#endif
}

void close_sock(sock_t s) {
#ifdef _WIN32
    ::closesocket(s);
#else
    ::close(s);
#endif
}

void set_nonblock(sock_t s, bool nb) {
#ifdef _WIN32
    u_long m = nb ? 1 : 0;
    ::ioctlsocket(s, FIONBIO, &m);
#else
    int fl = ::fcntl(s, F_GETFL, 0);
    ::fcntl(s, F_SETFL, nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
#endif
}

// Waits for readability (write=false) or writability. Returns 1 ready, 0 timeout.
int wait_fd(sock_t s, bool write, int timeout_ms) {
#ifdef _WIN32
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    // Winsock reports failed non-blocking connects through the except set.
    fd_set exc;
    FD_ZERO(&exc);
    FD_SET(s, &exc);
    int r = ::select(0, write ? nullptr : &set, write ? &set : nullptr, write ? &exc : nullptr,
                     timeout_ms < 0 ? nullptr : &tv);
    if (r == SOCKET_ERROR) throw Error("select failed: " + err_str(last_err()));
    return r > 0 ? 1 : 0;
#else
    pollfd p{};
    p.fd = s;
    p.events = write ? POLLOUT : POLLIN;
    for (;;) {
        int r = ::poll(&p, 1, timeout_ms);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw Error("poll failed: " + err_str(errno));
        }
        return r > 0 ? 1 : 0;
    }
#endif
}

struct AddrInfo {
    addrinfo* ai = nullptr;
    ~AddrInfo() {
        if (ai) ::freeaddrinfo(ai);
    }
};

std::string ip_of(const sockaddr* sa) {
    char buf[INET6_ADDRSTRLEN + 1] = {0};
    if (sa->sa_family == AF_INET) {
        ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, buf, sizeof buf);
    } else if (sa->sa_family == AF_INET6) {
        ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, buf, sizeof buf);
    }
    std::string s = buf;
    // dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d
    if (s.rfind("::ffff:", 0) == 0 && s.find('.') != std::string::npos) s = s.substr(7);
    return s;
}

void tune(sock_t s) {
    int one = 1;
    ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof one);
}

void apply_timeout(sock_t s, int opt, int ms) {
#ifdef _WIN32
    DWORD v = static_cast<DWORD>(ms);
    ::setsockopt(s, SOL_SOCKET, opt, reinterpret_cast<const char*>(&v), sizeof v);
#else
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, opt, &tv, sizeof tv);
#endif
}

}  // namespace

void init() {
    static std::once_flag once;
    std::call_once(once, [] {
#ifdef _WIN32
        WSADATA d;
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0) throw Error("WSAStartup failed");
#else
        std::signal(SIGPIPE, SIG_IGN);
#endif
    });
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }

Socket& Socket::operator=(Socket&& o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        o.fd_ = -1;
    }
    return *this;
}

bool Socket::valid() const { return fd_ != -1; }

void Socket::close() {
    if (fd_ != -1) {
        close_sock(static_cast<sock_t>(fd_));
        fd_ = -1;
    }
}

void Socket::shutdown_both() {
    if (fd_ == -1) return;
#ifdef _WIN32
    ::shutdown(static_cast<sock_t>(fd_), SD_BOTH);
    // shutdown() alone does not wake a recv blocked on an accepted Winsock socket; cancelling the pending I/O does,
    // without closing the handle under the thread that owns it.
    ::CancelIoEx(reinterpret_cast<HANDLE>(static_cast<sock_t>(fd_)), nullptr);
#else
    ::shutdown(static_cast<sock_t>(fd_), SHUT_RDWR);
#endif
}

Socket Socket::connect(const std::string& host, uint16_t port, int timeout_ms) {
    init();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    AddrInfo res;
    std::string svc = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), svc.c_str(), &hints, &res.ai);
    if (rc != 0 || !res.ai) throw Error("cannot resolve host '" + host + "'");
    std::string last = "no address";
    for (addrinfo* a = res.ai; a; a = a->ai_next) {
        sock_t s = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == kBad) {
            last = err_str(last_err());
            continue;
        }
        set_nonblock(s, true);
        int r = ::connect(s, a->ai_addr, static_cast<int>(a->ai_addrlen));
        if (r != 0) {
            int e = last_err();
#ifdef _WIN32
            bool inprog = (e == WSAEWOULDBLOCK);
#else
            bool inprog = (e == EINPROGRESS || e == EINTR);
#endif
            if (!inprog) {
                last = err_str(e);
                close_sock(s);
                continue;
            }
            int w = 0;
            try {
                w = wait_fd(s, true, timeout_ms);
            } catch (...) {
                close_sock(s);
                throw;
            }
            if (!w) {
                last = "connect timeout";
                close_sock(s);
                continue;
            }
            int soerr = 0;
#ifdef _WIN32
            int len = sizeof soerr;
#else
            socklen_t len = sizeof soerr;
#endif
            ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len);
            if (soerr != 0) {
                last = err_str(soerr);
                close_sock(s);
                continue;
            }
        }
        set_nonblock(s, false);
        tune(s);
        Socket out;
        out.fd_ = static_cast<intptr_t>(s);
        return out;
    }
    throw Error("connect to " + host + ":" + svc + " failed: " + last);
}

Socket Socket::listen(const std::string& bind_addr, uint16_t port, int backlog) {
    init();
    bool any = bind_addr.empty() || bind_addr == "*";
    std::string svc = std::to_string(port);

    auto try_bind = [&](addrinfo* a, bool dual, std::string& err) -> sock_t {
        sock_t s = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == kBad) {
            err = err_str(last_err());
            return kBad;
        }
#ifndef _WIN32
        int one = 1;
        ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
        if (a->ai_family == AF_INET6) {
            int v6only = dual ? 0 : 1;
            ::setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof v6only);
        }
        if (::bind(s, a->ai_addr, static_cast<int>(a->ai_addrlen)) != 0 || ::listen(s, backlog) != 0) {
            err = err_str(last_err());
            close_sock(s);
            return kBad;
        }
        return s;
    };

    auto bind_family = [&](int family, const char* node, bool dual, std::string& err) -> sock_t {
        addrinfo hints{};
        hints.ai_family = family;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        AddrInfo res;
        int rc = ::getaddrinfo(node, svc.c_str(), &hints, &res.ai);
        if (rc != 0 || !res.ai) {
            err = "cannot resolve bind address";
            return kBad;
        }
        sock_t s = kBad;
        for (addrinfo* a = res.ai; a && s == kBad; a = a->ai_next) s = try_bind(a, dual, err);
        return s;
    };

    std::string err = "no address";
    sock_t s = kBad;
    if (any) {
        s = bind_family(AF_INET6, nullptr, true, err);
        if (s == kBad) s = bind_family(AF_INET, nullptr, false, err);  // host without IPv6
    } else {
        s = bind_family(AF_UNSPEC, bind_addr.c_str(), false, err);
    }
    if (s == kBad) throw Error("listen on " + (any ? std::string("*") : bind_addr) + ":" + svc + " failed: " + err);
    Socket out;
    out.fd_ = static_cast<intptr_t>(s);
    return out;
}

Socket Socket::accept(int timeout_ms, std::string* peer_ip) {
    if (fd_ == -1) throw Error("accept on invalid socket");
    sock_t ls = static_cast<sock_t>(fd_);
    if (!wait_fd(ls, false, timeout_ms)) return Socket();
    sockaddr_storage ss{};
#ifdef _WIN32
    int len = sizeof ss;
#else
    socklen_t len = sizeof ss;
#endif
    sock_t c = ::accept(ls, reinterpret_cast<sockaddr*>(&ss), &len);
    if (c == kBad) {
        int e = last_err();
        if (is_intr(e) || is_timeout(e)) return Socket();
#ifndef _WIN32
        if (e == ECONNABORTED) return Socket();
#endif
        throw Error("accept failed: " + err_str(e));
    }
    set_nonblock(c, false);
    tune(c);
    if (peer_ip) *peer_ip = ip_of(reinterpret_cast<sockaddr*>(&ss));
    Socket out;
    out.fd_ = static_cast<intptr_t>(c);
    return out;
}

uint16_t Socket::local_port() const {
    if (fd_ == -1) return 0;
    sockaddr_storage ss{};
#ifdef _WIN32
    int len = sizeof ss;
#else
    socklen_t len = sizeof ss;
#endif
    if (::getsockname(static_cast<sock_t>(fd_), reinterpret_cast<sockaddr*>(&ss), &len) != 0) return 0;
    if (ss.ss_family == AF_INET) return ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
    return 0;
}

void Socket::set_timeouts(int recv_ms, int send_ms) {
    if (fd_ == -1) return;
    apply_timeout(static_cast<sock_t>(fd_), SO_RCVTIMEO, recv_ms < 0 ? 0 : recv_ms);
    apply_timeout(static_cast<sock_t>(fd_), SO_SNDTIMEO, send_ms < 0 ? 0 : send_ms);
}

void Socket::set_buffers(int bytes) {
    if (fd_ == -1 || bytes <= 0) return;
    ::setsockopt(static_cast<sock_t>(fd_), SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bytes), sizeof bytes);
    ::setsockopt(static_cast<sock_t>(fd_), SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bytes), sizeof bytes);
}

void Socket::send_all(const void* data, size_t n) {
    if (fd_ == -1) throw Error("send on invalid socket");
    const char* p = static_cast<const char*>(data);
    size_t done = 0;
    while (done < n) {
        size_t chunk = n - done;
        if (chunk > (1u << 30)) chunk = 1u << 30;
#ifdef _WIN32
        int r = ::send(static_cast<sock_t>(fd_), p + done, static_cast<int>(chunk), 0);
        if (r == SOCKET_ERROR) {
#else
        int flags = 0;
#ifdef MSG_NOSIGNAL
        flags = MSG_NOSIGNAL;
#endif
        ssize_t r = ::send(static_cast<sock_t>(fd_), p + done, chunk, flags);
        if (r < 0) {
#endif
            int e = last_err();
            if (is_intr(e)) continue;
            if (is_timeout(e)) throw Error("send timeout");
            throw Error("send failed: " + err_str(e));
        }
        done += static_cast<size_t>(r);
    }
}

size_t Socket::recv_some(void* data, size_t max) {
    if (fd_ == -1) throw Error("recv on invalid socket");
    if (max == 0) return 0;
    if (max > (1u << 30)) max = 1u << 30;
    for (;;) {
#ifdef _WIN32
        int r = ::recv(static_cast<sock_t>(fd_), static_cast<char*>(data), static_cast<int>(max), 0);
        if (r == SOCKET_ERROR) {
#else
        ssize_t r = ::recv(static_cast<sock_t>(fd_), data, max, 0);
        if (r < 0) {
#endif
            int e = last_err();
            if (is_intr(e)) continue;
            if (is_timeout(e)) throw Error("recv timeout");
            throw Error("recv failed: " + err_str(e));
        }
        return static_cast<size_t>(r);
    }
}

void Socket::recv_all(void* data, size_t n) {
    char* p = static_cast<char*>(data);
    size_t done = 0;
    while (done < n) {
        size_t r = recv_some(p + done, n - done);
        if (r == 0) throw Error("connection closed by peer");
        done += r;
    }
}

}  // namespace mysync::net
