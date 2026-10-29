// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <random>
#include <thread>

#include "mysync/net.h"
#include "mysync/secure_channel.h"
#include "testing.h"

using namespace mysync;

namespace {

struct SockPair {
    net::Socket a, b;
};

SockPair direct_pair() {
    net::init();
    net::Socket l = net::Socket::listen("127.0.0.1", 0);
    net::Socket a = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
    net::Socket b = l.accept(3000);
    CHECK(b.valid());
    return {std::move(a), std::move(b)};
}

// Deterministic test identities.
KeyPair make_kp(uint8_t seed) {
    PubKey sk;
    for (size_t i = 0; i < 32; i++) sk[i] = uint8_t(seed * 31 + i * 7 + 1);
    return keypair_from_secret(sk);
}

using AllowFn = std::function<bool(const PubKey&)>;

struct Ident {
    KeyPair client, server;
    PubKey pinned;       // what the client believes the server's public key is
    AllowFn allow;       // server allowlist
};

Ident good_ident(uint8_t seed = 1) {
    Ident id;
    id.client = make_kp(uint8_t(seed * 2));
    id.server = make_kp(uint8_t(seed * 2 + 1));
    id.pinned = id.server.pub;
    PubKey cpub = id.client.pub;
    id.allow = [cpub](const PubKey& k) { return ct_equal(k.data(), cpub.data(), 32); };
    return id;
}

struct HsResult {
    std::optional<SecureChannel> ch;
    std::string err;
};

void run_client(net::Socket&& s, const Ident& id, HsResult& out) {
    try {
        out.ch.emplace(SecureChannel::client(std::move(s), id.client, id.pinned));
        out.ch->socket().set_timeouts(4000, 4000);
    } catch (const std::exception& e) {
        out.err = e.what();
    }
}

void run_server(net::Socket&& s, const Ident& id, HsResult& out) {
    try {
        out.ch.emplace(SecureChannel::server(std::move(s), id.server, id.allow));
        out.ch->socket().set_timeouts(4000, 4000);
    } catch (const std::exception& e) {
        out.err = e.what();
    }
}

// Both ends over a direct connection.
void handshake_pair(HsResult& c, HsResult& s, const Ident& id) {
    SockPair p = direct_pair();
    std::thread t([&] { run_server(std::move(p.b), id, s); });
    run_client(std::move(p.a), id, c);
    t.join();
}

bool forward_exact(net::Socket& from, net::Socket& to, size_t n) {
    Bytes b(n);
    try {
        from.recv_all(b.data(), n);
        to.send_all(b.data(), n);
    } catch (const Error&) {
        return false;
    }
    return true;
}

// Reads frames (hdr+body+tag) from the client side until EOF. A partial trailing frame is kept as-is.
std::vector<Bytes> read_frames(net::Socket& from) {
    std::vector<Bytes> frames;
    Bytes pending;
    uint8_t tmp[4096];
    for (;;) {
        size_t n = 0;
        try { n = from.recv_some(tmp, sizeof tmp); } catch (const Error&) { break; }
        if (n == 0) break;
        pending.insert(pending.end(), tmp, tmp + n);
    }
    size_t pos = 0;
    while (pending.size() - pos >= 4) {
        size_t len = (size_t(pending[pos]) << 24) | (size_t(pending[pos + 1]) << 16) | (size_t(pending[pos + 2]) << 8) |
                     size_t(pending[pos + 3]);
        size_t total = 4 + len + 16;
        if (pending.size() - pos < total) break;
        frames.emplace_back(pending.begin() + pos, pending.begin() + pos + total);
        pos += total;
    }
    if (pos < pending.size()) frames.emplace_back(pending.begin() + pos, pending.end());
    return frames;
}

using Mutator = std::function<Bytes(std::vector<Bytes>&)>;

// client --(relay, mutates the client->server record stream)--> server
struct RelayRun {
    HsResult client, server;
    std::vector<Bytes> seen;   // frames as sent by the client
    std::thread relay;
};

// Runs a session in which the client sends `msgs`; returns what the server got / the error it hit.
struct Outcome {
    std::vector<Bytes> received;
    std::string server_error;   // "" if all `expect_count` messages arrived
    std::vector<Bytes> wire;    // frames as the client produced them
};

Outcome relay_session(const Ident& id, const std::vector<Bytes>& msgs, const Mutator& mut, size_t expect_count) {
    SockPair left = direct_pair();   // left.a = client end, left.b = relay end
    SockPair right = direct_pair();  // right.a = relay end, right.b = server end
    Outcome o;
    std::thread relay([&] {
        net::Socket& rc = left.b;
        net::Socket& rs = right.a;
        if (!forward_exact(rc, rs, 96) || !forward_exact(rs, rc, 48)) {
            rc.close();
            rs.close();
            return;
        }
        std::vector<Bytes> frames = read_frames(rc);
        o.wire = frames;
        Bytes out = mut(frames);
        try { if (!out.empty()) rs.send_all(out.data(), out.size()); } catch (const Error&) {}
        // keep the connection open until the server is done reading, then close
        rs.shutdown_both();
    });
    HsResult c, s;
    std::thread st([&] { run_server(std::move(right.b), id, s); });
    run_client(std::move(left.a), id, c);
    if (c.ch) {
        try {
            for (const auto& m : msgs) c.ch->send_msg(m);
        } catch (const Error&) {}
        c.ch.reset();  // close -> relay sees EOF
    }
    st.join();
    if (s.ch) {
        try {
            for (size_t i = 0; i < expect_count; i++) o.received.push_back(s.ch->recv_msg());
        } catch (const std::exception& e) {
            o.server_error = e.what();
            if (o.server_error.empty()) o.server_error = "error";
        }
        // after one failure the channel must stay dead
        if (!o.server_error.empty()) {
            bool dead = false;
            try { (void)s.ch->recv_msg(); } catch (const Error&) { dead = true; }
            CHECK(dead);
        }
    } else {
        o.server_error = "handshake: " + s.err;
    }
    relay.join();
    return o;
}

Bytes concat(const std::vector<Bytes>& v) {
    Bytes r;
    for (const auto& b : v) r.insert(r.end(), b.begin(), b.end());
    return r;
}

std::vector<Bytes> four_msgs() {
    return {Bytes{'a', 'l', 'p', 'h', 'a'}, Bytes(300, 0x42), Bytes{}, Bytes{'o', 'm', 'e', 'g', 'a'}};
}

}  // namespace

TEST(channel_roundtrip_both_directions_and_big_messages) {
    Ident ident = good_ident(1);
    HsResult c, s;
    handshake_pair(c, s, ident);
    CHECK(c.err.empty() && s.err.empty());
    CHECK(c.ch && s.ch);

    std::mt19937 g(7);
    Bytes big(SecureChannel::kMaxMessage);
    for (auto& x : big) x = uint8_t(g());
    std::thread echo([&] {
        try {
            for (int i = 0; i < 6; i++) s.ch->send_msg(s.ch->recv_msg());
        } catch (const std::exception&) {}
    });
    std::vector<Bytes> msgs = {Bytes{}, Bytes{1}, Bytes(1000, 9), big, Bytes{0, 0, 0}, big};
    for (const auto& m : msgs) {
        c.ch->send_msg(m);
        CHECK(c.ch->recv_msg() == m);
    }
    echo.join();
    CHECK_THROWS(c.ch->send_msg(Bytes(SecureChannel::kMaxMessage + 1)));
}

TEST(channel_peer_public_is_authenticated_identity) {
    Ident ident = good_ident(20);
    HsResult c, s;
    handshake_pair(c, s, ident);
    CHECK(c.ch && s.ch);
    CHECK(c.ch->peer_public() == ident.server.pub);
    CHECK(s.ch->peer_public() == ident.client.pub);
}

TEST(channel_server_with_wrong_key_rejected_by_client) {
    Ident ident = good_ident(21);
    ident.pinned = make_kp(99).pub;  // client pinned someone else's key: the real server is an impostor
    HsResult c, s;
    handshake_pair(c, s, ident);
    CHECK(!c.ch && !s.ch);
    CHECK_EQ(c.err, std::string("authentication failed"));
    CHECK_EQ(s.err, std::string("authentication failed"));
}

TEST(channel_unknown_client_rejected_and_server_sends_nothing) {
    Ident ident = good_ident(22);
    PubKey seen{};
    int calls = 0;
    ident.allow = [&](const PubKey& k) { seen = k; calls++; return false; };
    SockPair p = direct_pair();
    HsResult s;
    std::thread t([&] { run_server(std::move(p.b), ident, s); });
    HsResult c;
    // drive the client by hand so we can observe that the server answers with nothing at all
    {
        try {
            SecureChannel::client(std::move(p.a), ident.client, ident.pinned);
        } catch (const std::exception& e) {
            c.err = e.what();
        }
    }
    t.join();
    CHECK(!c.ch && !s.ch);
    CHECK_EQ(c.err, std::string("authentication failed"));
    CHECK_EQ(s.err, std::string("authentication failed"));
    CHECK_EQ(calls, 1);
    CHECK(seen == ident.client.pub);  // callback got the client's decrypted static key
}

TEST(channel_throwing_allowlist_is_a_rejection) {
    Ident ident = good_ident(23);
    ident.allow = [](const PubKey&) -> bool { throw std::runtime_error("boom"); };
    HsResult c, s;
    handshake_pair(c, s, ident);
    CHECK(!c.ch && !s.ch);
    CHECK_EQ(s.err, std::string("authentication failed"));
}

TEST(channel_server_survives_garbage_and_silent_clients) {
    Ident ident = good_ident(3);
    {
        SockPair p = direct_pair();
        HsResult s;
        std::thread t([&] { run_server(std::move(p.b), ident, s); });
        Bytes junk(96);
        std::mt19937 g(1);
        for (auto& x : junk) x = uint8_t(g());
        p.a.send_all(junk.data(), junk.size());
        t.join();
        CHECK(!s.ch);
        CHECK_EQ(s.err, std::string("authentication failed"));
        // the rejected peer receives nothing, only EOF
        uint8_t b;
        CHECK_EQ(p.a.recv_some(&b, 1), size_t(0));
    }
    {
        SockPair p = direct_pair();
        HsResult s;
        std::thread t([&] { run_server(std::move(p.b), ident, s); });
        p.a.close();
        t.join();
        CHECK(!s.ch);
        CHECK(!s.err.empty());
    }
}

// Flip each single byte of each handshake message on the wire; the handshake must never succeed end to end.
TEST(channel_every_handshake_byte_flip_fails) {
    Ident ident = good_ident(24);
    for (int dir = 0; dir < 2; dir++) {
        size_t len = dir == 0 ? 96 : 48;
        for (size_t i = 0; i < len; i++) {
            SockPair left = direct_pair(), right = direct_pair();
            std::thread relay([&] {
                Bytes m(96);
                try {
                    left.b.recv_all(m.data(), 96);
                    if (dir == 0) m[i] ^= 0x01;
                    right.a.send_all(m.data(), 96);
                    Bytes r(48);
                    right.a.recv_all(r.data(), 48);
                    if (dir == 1) r[i] ^= 0x01;
                    left.b.send_all(r.data(), 48);
                } catch (const Error&) {}
                left.b.close();
                right.a.close();
            });
            HsResult c, s;
            std::thread st([&] { run_server(std::move(right.b), ident, s); });
            run_client(std::move(left.a), ident, c);
            st.join();
            relay.join();
            CHECK(!c.ch);  // the client can never complete on a tampered transcript
            CHECK_EQ(c.err, std::string("authentication failed"));
            if (dir == 0) CHECK(!s.ch);
        }
    }
}

TEST(channel_two_sessions_have_different_ephemeral_exchange) {
    Ident ident = good_ident(25);
    Bytes first[2];
    for (int k = 0; k < 2; k++) {
        SockPair left = direct_pair(), right = direct_pair();
        std::thread relay([&, k] {
            Bytes m(96), r(48);
            try {
                left.b.recv_all(m.data(), 96);
                first[k] = m;
                right.a.send_all(m.data(), 96);
                right.a.recv_all(r.data(), 48);
                left.b.send_all(r.data(), 48);
            } catch (const Error&) {}
            // keep sockets open until channels are torn down
            uint8_t b;
            try { (void)left.b.recv_some(&b, 1); } catch (const Error&) {}
        });
        HsResult c, s;
        std::thread st([&] { run_server(std::move(right.b), ident, s); });
        run_client(std::move(left.a), ident, c);
        st.join();
        CHECK(c.ch && s.ch);
        c.ch.reset();
        relay.join();
    }
    CHECK(first[0] != first[1]);
    CHECK(Bytes(first[0].begin(), first[0].begin() + 32) != Bytes(first[1].begin(), first[1].begin() + 32));
}

TEST(channel_clean_relay_delivers_everything) {
    Ident ident = good_ident(4);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) { return concat(f); }, 4);
    CHECK(o.server_error.empty());
    CHECK(o.received == msgs);
}

TEST(channel_bit_flip_in_ciphertext_rejected) {
    Ident ident = good_ident(5);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        f[1][4 + 10] ^= 0x01;
        return concat(f);
    }, 4);
    CHECK_EQ(o.received.size(), size_t(1));  // frame 0 fine, frame 1 refused, nothing delivered after
    CHECK(o.received[0] == msgs[0]);
    CHECK(!o.server_error.empty());
}

TEST(channel_bit_flip_in_tag_rejected) {
    Ident ident = good_ident(5);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        f[0].back() ^= 0x80;
        return concat(f);
    }, 4);
    CHECK_EQ(o.received.size(), size_t(0));
    CHECK(!o.server_error.empty());
}

TEST(channel_bit_flip_in_length_header_rejected) {
    Ident ident = good_ident(5);
    auto msgs = four_msgs();
    for (int byte = 0; byte < 4; byte++) {
        Outcome o = relay_session(ident, msgs, [byte](std::vector<Bytes>& f) {
            f[0][size_t(byte)] ^= 0x01;
            return concat(f);
        }, 4);
        CHECK_EQ(o.received.size(), size_t(0));
        CHECK(!o.server_error.empty());
    }
}

TEST(channel_oversize_frame_rejected_before_allocation) {
    Ident ident = good_ident(6);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        f[0][0] = 0xFF; f[0][1] = 0xFF; f[0][2] = 0xFF; f[0][3] = 0xFF;
        return concat(f);
    }, 4);
    CHECK_EQ(o.received.size(), size_t(0));
    CHECK(o.server_error.find("frame too large") != std::string::npos);
}

TEST(channel_replayed_frame_rejected) {
    Ident ident = good_ident(7);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        f.insert(f.begin() + 2, f[1]);  // f0 f1 f1 f2 f3
        return concat(f);
    }, 4);
    CHECK_EQ(o.received.size(), size_t(2));
    CHECK(!o.server_error.empty());
}

TEST(channel_reordered_frames_rejected) {
    Ident ident = good_ident(8);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        std::swap(f[0], f[1]);
        return concat(f);
    }, 4);
    CHECK_EQ(o.received.size(), size_t(0));
    CHECK(!o.server_error.empty());
}

TEST(channel_dropped_frame_rejected) {
    Ident ident = good_ident(9);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        f.erase(f.begin() + 1);
        return concat(f);
    }, 4);
    CHECK_EQ(o.received.size(), size_t(1));
    CHECK(!o.server_error.empty());
}

TEST(channel_truncated_stream_rejected) {
    Ident ident = good_ident(10);
    auto msgs = four_msgs();
    Outcome o = relay_session(ident, msgs, [](std::vector<Bytes>& f) {
        Bytes all = concat(f);
        all.resize(all.size() - 5);
        return all;
    }, 4);
    CHECK_EQ(o.received.size(), size_t(3));
    CHECK(!o.server_error.empty());
}

TEST(channel_sessions_with_same_identities_use_different_keys) {
    Ident ident = good_ident(11);
    std::vector<Bytes> msgs = {Bytes(64, 0x55), Bytes(64, 0x55)};
    auto idf = [](std::vector<Bytes>& f) { return concat(f); };
    Outcome a = relay_session(ident, msgs, idf, 2);
    Outcome b = relay_session(ident, msgs, idf, 2);
    CHECK(a.server_error.empty() && b.server_error.empty());
    CHECK_EQ(a.wire.size(), size_t(2));
    CHECK_EQ(b.wire.size(), size_t(2));
    CHECK(a.wire[0] != b.wire[0]);   // different session keys
    CHECK(a.wire[0] != a.wire[1]);   // counter nonce: same plaintext, different ciphertext
}

TEST(channel_frame_from_other_session_rejected) {
    Ident ident = good_ident(12);
    std::vector<Bytes> msgs = {Bytes(32, 1), Bytes(32, 2)};
    Outcome first = relay_session(ident, msgs, [](std::vector<Bytes>& f) { return concat(f); }, 2);
    std::vector<Bytes> old_wire = first.wire;
    Outcome o = relay_session(ident, msgs, [old_wire](std::vector<Bytes>&) { return concat(old_wire); }, 2);
    CHECK_EQ(o.received.size(), size_t(0));  // frames recorded earlier do not authenticate in a new session
    CHECK(!o.server_error.empty());
}

TEST(keys_hex_and_file_roundtrip) {
    KeyPair kp = generate_keypair();
    KeyPair kp2 = generate_keypair();
    CHECK(kp.secret != kp2.secret && kp.pub != kp2.pub);
    CHECK(keypair_from_secret(kp.secret).pub == kp.pub);
    std::string hex = key_to_hex(kp.pub);
    CHECK_EQ(hex.size(), size_t(64));
    CHECK(key_from_hex(hex + "\n") == kp.pub);
    CHECK_THROWS(key_from_hex(hex.substr(1)));
    CHECK_THROWS(key_from_hex(hex + "00"));
    CHECK_THROWS(key_from_hex(std::string(63, 'a') + "g"));
    CHECK_THROWS(key_from_hex(""));

    std::filesystem::path dir = std::filesystem::temp_directory_path() / ("mysync-test-keys-" + std::to_string(std::random_device{}()));
    std::filesystem::create_directories(dir);
    std::string f = (dir / "id.key").u8string(), pf = (dir / "id.pub").u8string();
    save_keypair(f, kp);
    save_public_file(pf, kp.pub);
    KeyPair back = load_keypair(f);
    CHECK(back.secret == kp.secret && back.pub == kp.pub);
    CHECK(load_public_file(pf) == kp.pub);
    CHECK_THROWS(save_keypair(f, kp2));                 // no overwrite
    CHECK_THROWS(load_keypair((dir / "missing").u8string()));
    { std::ofstream o(std::filesystem::u8path((dir / "bad.key").u8string())); o << "not a key"; }
    CHECK_THROWS(load_keypair((dir / "bad.key").u8string()));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
