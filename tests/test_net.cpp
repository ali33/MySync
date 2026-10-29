// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <atomic>
#include <chrono>
#include <thread>

#include "mysync/net.h"
#include "testing.h"

using namespace mysync;

TEST(net_init_idempotent) {
    net::init();
    net::init();
}

TEST(net_accept_timeout) {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    CHECK(l.valid());
    CHECK(l.local_port() != 0);
    auto t0 = std::chrono::steady_clock::now();
    net::Socket c = l.accept(200);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(!c.valid());
    CHECK(ms >= 150 && ms < 3000);
}

TEST(net_loopback_10mib) {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    uint16_t port = l.local_port();
    const size_t N = 10u << 20;
    std::vector<uint8_t> src(N);
    for (size_t i = 0; i < N; ++i) src[i] = static_cast<uint8_t>((i * 131 + (i >> 8)) & 0xff);

    std::vector<uint8_t> got(N);
    std::string peer;
    std::string srv_err;
    std::thread srv([&] {
        try {
            net::Socket s = l.accept(5000, &peer);
            if (!s.valid()) {
                srv_err = "no connection";
                return;
            }
            s.set_timeouts(5000, 5000);
            s.recv_all(got.data(), got.size());
            uint8_t ack = 0x42;
            s.send_all(&ack, 1);
        } catch (const std::exception& e) {
            srv_err = e.what();
        }
    });
    net::Socket c = net::Socket::connect("127.0.0.1", port, 3000);
    CHECK(c.valid());
    c.set_timeouts(5000, 5000);
    c.send_all(src.data(), src.size());
    uint8_t ack = 0;
    c.recv_all(&ack, 1);
    srv.join();
    CHECK(srv_err.empty());
    CHECK_EQ(ack, uint8_t(0x42));
    CHECK(got == src);
    CHECK_EQ(peer, std::string("127.0.0.1"));
}

TEST(net_recv_eof_and_close) {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    net::Socket c = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    net::Socket s = l.accept(3000);
    CHECK(s.valid());
    c.close();
    CHECK(!c.valid());
    uint8_t b[4];
    CHECK_EQ(s.recv_some(b, sizeof b), size_t(0));
    CHECK_THROWS(s.recv_all(b, sizeof b));
}

TEST(net_recv_timeout) {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    net::Socket c = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    net::Socket s = l.accept(3000);
    c.set_timeouts(150, 0);
    uint8_t b;
    auto t0 = std::chrono::steady_clock::now();
    CHECK_THROWS(c.recv_all(&b, 1));
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 3000);
}

TEST(net_shutdown_wakes_blocked_reader) {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    net::Socket c = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    net::Socket s = l.accept(3000);
    std::atomic<bool> threw{false};
    std::thread t([&] {
        uint8_t b;
        try {
            c.recv_all(&b, 1);
        } catch (const std::exception&) {
            threw = true;
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    c.shutdown_both();
    t.join();
    CHECK(threw.load());
}

TEST(net_connect_refused) {
    net::init();
    uint16_t port;
    {
        net::Socket l = net::Socket::listen("127.0.0.1", 0);
        port = l.local_port();
    }
    CHECK_THROWS(net::Socket::connect("127.0.0.1", port, 1000));
}

TEST(net_dualstack_listen_any) {
    net::init();
    net::Socket l = net::Socket::listen("*", 0);
    CHECK(l.valid());
    net::Socket c = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    std::string peer;
    net::Socket s = l.accept(3000, &peer);
    CHECK(s.valid());
    CHECK_EQ(peer, std::string("127.0.0.1"));
}

TEST(net_move_semantics) {
    net::init();
    net::Socket a = net::Socket::listen("127.0.0.1", 0);
    uint16_t p = a.local_port();
    net::Socket b = std::move(a);
    CHECK(!a.valid());
    CHECK(b.valid());
    CHECK_EQ(b.local_port(), p);
}
