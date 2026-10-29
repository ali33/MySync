// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// secure_channel.h - authenticated + encrypted message channel over a net::Socket.
// Handshake: Noise_IK_25519 (XChaCha20-Poly1305, BLAKE2b) with pinned static public keys, no CA:
//   <- s                       (pre-message: the client already knows the server's public key)
//   -> e, es, s, ss            (client static key is sent encrypted)
//   <- e, ee, se
// then Split() gives one key per direction for the record layer (counter nonce, frames <= 1 MiB).
// Not thread-safe per direction: at most one sender thread and one receiver thread (state is disjoint).
#include <functional>

#include "mysync/keys.h"
#include "mysync/net.h"
#include "mysync/util.h"

namespace mysync {

class SecureChannel {
public:
    static constexpr size_t kMaxMessage = 1024 * 1024;  // plaintext bytes per message
    static constexpr size_t kTagSize = 16;
    static constexpr int kHandshakeTimeoutMs = 10000;

    // Client (initiator): server_pub is the pinned public key of the server.
    // Throws Error("authentication failed") if the server is not the holder of server_pub, we are not allowed
    // by the server, or the handshake is tampered with. The socket is closed on failure.
    static SecureChannel client(net::Socket&& s, const KeyPair& self, const PubKey& server_pub);
    // Server (responder): is_allowed(client_pub) is called after the client's static key was decrypted and
    // authenticated against our key, before any reply. Returning false (or throwing) closes the connection
    // without sending anything and throws Error("authentication failed"). Compare keys with ct_equal.
    static SecureChannel server(net::Socket&& s, const KeyPair& self,
                                const std::function<bool(const PubKey& client_pub)>& is_allowed);

    SecureChannel() = default;
    ~SecureChannel();
    SecureChannel(SecureChannel&&) noexcept;
    SecureChannel& operator=(SecureChannel&&) noexcept;
    SecureChannel(const SecureChannel&) = delete;
    SecureChannel& operator=(const SecureChannel&) = delete;

    void send_msg(const Bytes& msg);
    void send_msg(const void* data, size_t n);
    // Throws Error on bad tag, replay, reorder, truncation, oversize frame. After any failure the channel is dead.
    Bytes recv_msg();
    net::Socket& socket() { return sock_; }
    // The authenticated static public key of the other side (server key for a client; client key for a server).
    const PubKey& peer_public() const { return peer_; }

private:
    static SecureChannel make(net::Socket&& s, const uint8_t send_key[32], const uint8_t recv_key[32], const PubKey& peer);
    void wipe();

    net::Socket sock_;
    uint8_t send_key_[32] = {};
    uint8_t recv_key_[32] = {};
    uint64_t send_ctr_ = 0;
    uint64_t recv_ctr_ = 0;
    PubKey peer_{};
    bool dead_ = true;


};

} // namespace mysync
