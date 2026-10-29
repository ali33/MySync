// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/secure_channel.h"

#include <cstring>

#include "monocypher.h"

namespace mysync {

namespace {

constexpr char kProtocolName[] = "MySync_Noise_IK_25519_XChaCha20Poly1305_BLAKE2b";

void put_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
uint32_t get_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

void make_nonce(uint8_t nonce[24], uint64_t ctr) {
    std::memset(nonce, 0, 24);
    for (int i = 0; i < 8; i++) nonce[i] = uint8_t(ctr >> (8 * i));
}

struct AuthFailed {};  // internal marker, always surfaced as Error("authentication failed")

// X25519 that rejects the all-zero output (low-order points).
void dh(uint8_t out[32], const PubKey& sk, const uint8_t pk[32]) {
    static const uint8_t zero[32] = {};
    crypto_x25519(out, sk.data(), pk);
    if (ct_equal(out, zero, 32)) throw AuthFailed{};
}

// Noise SymmetricState with BLAKE2b (keyed-BLAKE2b plays the role of HMAC in HKDF) and XChaCha20-Poly1305.
struct Sym {
    uint8_t h[32], ck[32], k[32];
    uint64_t n = 0;
    ~Sym() {
        secure_wipe(h, sizeof h);
        secure_wipe(ck, sizeof ck);
        secure_wipe(k, sizeof k);
    }

    static void prf(uint8_t out[32], const uint8_t key[32], const uint8_t* msg, size_t n) {
        crypto_blake2b_keyed(out, 32, key, 32, msg, n);
    }
    // HKDF(ck, ikm) -> two outputs
    void hkdf2(const uint8_t* ikm, size_t ikm_n, uint8_t o1[32], uint8_t o2[32]) const {
        uint8_t temp[32], buf[33];
        prf(temp, ck, ikm, ikm_n);
        buf[0] = 1;
        prf(o1, temp, buf, 1);
        std::memcpy(buf, o1, 32);
        buf[32] = 2;
        prf(o2, temp, buf, 33);
        secure_wipe(temp, sizeof temp);
    }

    Sym() {
        crypto_blake2b(h, 32, reinterpret_cast<const uint8_t*>(kProtocolName), std::strlen(kProtocolName));
        std::memcpy(ck, h, 32);
        std::memset(k, 0, 32);
        mix_hash(nullptr, 0);  // empty prologue
    }
    void mix_hash(const uint8_t* d, size_t n_) {
        Bytes b(h, h + 32);
        if (n_) b.insert(b.end(), d, d + n_);
        crypto_blake2b(h, 32, b.data(), b.size());
    }
    void mix_key(const uint8_t dh_out[32]) {
        uint8_t new_ck[32], new_k[32];
        hkdf2(dh_out, 32, new_ck, new_k);
        std::memcpy(ck, new_ck, 32);
        std::memcpy(k, new_k, 32);
        n = 0;
        secure_wipe(new_ck, 32);
        secure_wipe(new_k, 32);
    }
    // out = ciphertext || 16-byte tag
    Bytes encrypt_and_hash(const uint8_t* pt, size_t len) {
        Bytes out(len + 16);
        uint8_t nonce[24];
        make_nonce(nonce, n++);
        crypto_aead_lock(out.data(), out.data() + len, k, nonce, h, 32, pt, len);
        mix_hash(out.data(), out.size());
        return out;
    }
    Bytes decrypt_and_hash(const uint8_t* ct, size_t total) {
        if (total < 16) throw AuthFailed{};
        size_t len = total - 16;
        Bytes pt(len);
        uint8_t nonce[24];
        make_nonce(nonce, n++);
        if (crypto_aead_unlock(pt.data(), ct + len, k, nonce, h, 32, ct, len) != 0) throw AuthFailed{};
        mix_hash(ct, total);
        return pt;
    }
    void split(uint8_t k1[32], uint8_t k2[32]) const { hkdf2(nullptr, 0, k1, k2); }
};

constexpr size_t kMsg1 = 32 + (32 + 16) + 16;  // e, enc(s), enc(empty)
constexpr size_t kMsg2 = 32 + 16;               // e, enc(empty)

}  // namespace

SecureChannel::~SecureChannel() { wipe(); }

void SecureChannel::wipe() {
    secure_wipe(send_key_, sizeof send_key_);
    secure_wipe(recv_key_, sizeof recv_key_);
    send_ctr_ = recv_ctr_ = 0;
    dead_ = true;
}

SecureChannel::SecureChannel(SecureChannel&& o) noexcept
    : sock_(std::move(o.sock_)), send_ctr_(o.send_ctr_), recv_ctr_(o.recv_ctr_), peer_(o.peer_), dead_(o.dead_) {
    std::memcpy(send_key_, o.send_key_, 32);
    std::memcpy(recv_key_, o.recv_key_, 32);
    o.wipe();
}

SecureChannel& SecureChannel::operator=(SecureChannel&& o) noexcept {
    if (this != &o) {
        wipe();
        sock_ = std::move(o.sock_);
        std::memcpy(send_key_, o.send_key_, 32);
        std::memcpy(recv_key_, o.recv_key_, 32);
        send_ctr_ = o.send_ctr_;
        recv_ctr_ = o.recv_ctr_;
        peer_ = o.peer_;
        dead_ = o.dead_;
        o.wipe();
    }
    return *this;
}

SecureChannel SecureChannel::make(net::Socket&& s, const uint8_t send_key[32], const uint8_t recv_key[32],
                                  const PubKey& peer) {
    SecureChannel ch;
    ch.sock_ = std::move(s);
    std::memcpy(ch.send_key_, send_key, 32);
    std::memcpy(ch.recv_key_, recv_key, 32);
    ch.peer_ = peer;
    ch.dead_ = false;
    ch.sock_.set_timeouts(0, 0);
    return ch;
}

SecureChannel SecureChannel::client(net::Socket&& s, const KeyPair& self, const PubKey& server_pub) {
    if (!s.valid()) throw Error("invalid socket");
    KeyPair e;
    uint8_t k_send[32], k_recv[32], d[32];
    auto wipe_all = [&] {
        secure_wipe(k_send, 32);
        secure_wipe(k_recv, 32);
        secure_wipe(d, 32);
    };
    try {
        s.set_timeouts(kHandshakeTimeoutMs, kHandshakeTimeoutMs);
        Sym st;
        st.mix_hash(server_pub.data(), 32);  // pre-message: <- s

        e = generate_keypair();
        Bytes m1(e.pub.begin(), e.pub.end());
        st.mix_hash(e.pub.data(), 32);
        dh(d, e.secret, server_pub.data());  // es
        st.mix_key(d);
        Bytes es = st.encrypt_and_hash(self.pub.data(), 32);  // s
        m1.insert(m1.end(), es.begin(), es.end());
        dh(d, self.secret, server_pub.data());  // ss
        st.mix_key(d);
        Bytes pl = st.encrypt_and_hash(nullptr, 0);
        m1.insert(m1.end(), pl.begin(), pl.end());
        s.send_all(m1.data(), m1.size());

        uint8_t m2[kMsg2];
        s.recv_all(m2, kMsg2);  // EOF here: the server rejected us (or is not who we pinned)
        st.mix_hash(m2, 32);
        dh(d, e.secret, m2);  // ee
        st.mix_key(d);
        dh(d, self.secret, m2);  // se
        st.mix_key(d);
        st.decrypt_and_hash(m2 + 32, 16);

        st.split(k_send, k_recv);
        SecureChannel ch = make(std::move(s), k_send, k_recv, server_pub);
        wipe_all();
        return ch;
    } catch (...) {
        wipe_all();
        s.close();
        throw Error("authentication failed");
    }
}

SecureChannel SecureChannel::server(net::Socket&& s, const KeyPair& self,
                                    const std::function<bool(const PubKey&)>& is_allowed) {
    if (!s.valid()) throw Error("invalid socket");
    KeyPair e;
    uint8_t k_send[32], k_recv[32], d[32];
    auto wipe_all = [&] {
        secure_wipe(k_send, 32);
        secure_wipe(k_recv, 32);
        secure_wipe(d, 32);
    };
    try {
        s.set_timeouts(kHandshakeTimeoutMs, kHandshakeTimeoutMs);
        Sym st;
        st.mix_hash(self.pub.data(), 32);  // pre-message: <- s (ours)

        uint8_t m1[kMsg1];
        s.recv_all(m1, kMsg1);
        const uint8_t* re = m1;
        st.mix_hash(re, 32);
        dh(d, self.secret, re);  // es
        st.mix_key(d);
        Bytes rs_b = st.decrypt_and_hash(m1 + 32, 48);  // s
        PubKey rs;
        std::memcpy(rs.data(), rs_b.data(), 32);
        dh(d, self.secret, rs.data());  // ss
        st.mix_key(d);
        st.decrypt_and_hash(m1 + 80, 16);

        bool ok = false;
        try { ok = is_allowed(rs); } catch (...) { ok = false; }
        if (!ok) throw AuthFailed{};  // close silently: nothing is sent

        e = generate_keypair();
        Bytes m2(e.pub.begin(), e.pub.end());
        st.mix_hash(e.pub.data(), 32);
        dh(d, e.secret, re);  // ee
        st.mix_key(d);
        dh(d, e.secret, rs.data());  // se
        st.mix_key(d);
        Bytes pl = st.encrypt_and_hash(nullptr, 0);
        m2.insert(m2.end(), pl.begin(), pl.end());
        s.send_all(m2.data(), m2.size());

        st.split(k_recv, k_send);
        SecureChannel ch = make(std::move(s), k_send, k_recv, rs);
        wipe_all();
        return ch;
    } catch (...) {
        wipe_all();
        s.close();
        throw Error("authentication failed");
    }
}

void SecureChannel::send_msg(const Bytes& msg) { send_msg(msg.data(), msg.size()); }

void SecureChannel::send_msg(const void* data, size_t n) {
    if (dead_) throw Error("channel closed");
    if (n > kMaxMessage) throw Error("message too large");
    if (send_ctr_ == UINT64_MAX) throw Error("send counter exhausted");
    Bytes frame(4 + n + kTagSize);
    put_be32(frame.data(), uint32_t(n));
    uint8_t nonce[24];
    make_nonce(nonce, send_ctr_);
    crypto_aead_lock(frame.data() + 4, frame.data() + 4 + n, send_key_, nonce, frame.data(), 4,
                     static_cast<const uint8_t*>(data), n);
    send_ctr_++;
    try {
        sock_.send_all(frame.data(), frame.size());
    } catch (...) {
        dead_ = true;
        throw;
    }
}

Bytes SecureChannel::recv_msg() {
    if (dead_) throw Error("channel closed");
    try {
        uint8_t hdr[4];
        sock_.recv_all(hdr, 4);
        uint32_t len = get_be32(hdr);
        if (len > kMaxMessage) throw Error("frame too large");  // checked before allocation
        if (recv_ctr_ == UINT64_MAX) throw Error("receive counter exhausted");
        Bytes buf(size_t(len) + kTagSize);
        sock_.recv_all(buf.data(), buf.size());
        Bytes plain(len);
        uint8_t nonce[24];
        make_nonce(nonce, recv_ctr_);
        if (crypto_aead_unlock(plain.data(), buf.data() + len, recv_key_, nonce, hdr, 4, buf.data(), len) != 0)
            throw Error("record authentication failed");
        recv_ctr_++;
        return plain;
    } catch (...) {
        dead_ = true;
        throw;
    }
}

}  // namespace mysync
