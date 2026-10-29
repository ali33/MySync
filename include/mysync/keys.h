// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// keys.h - static X25519 identity keys (pinned public keys, no CA) and their on-disk / hex form.
#include <array>
#include <string>

#include "mysync/util.h"

namespace mysync {

using PubKey = std::array<uint8_t, 32>;

struct KeyPair {
    PubKey secret{};
    PubKey pub{};
    KeyPair() = default;
    KeyPair(const KeyPair&) = default;
    KeyPair& operator=(const KeyPair&) = default;
    ~KeyPair() { secure_wipe(secret.data(), secret.size()); }
};

KeyPair generate_keypair();                       // random secret from the OS CSPRNG
KeyPair keypair_from_secret(const PubKey& secret);  // derives the public half

std::string key_to_hex(const PubKey&);            // 64 lowercase hex chars
PubKey key_from_hex(const std::string& hex);      // trims whitespace; throws Error unless exactly 64 hex chars

// Key file = one line with the 64-hex secret. save_keypair refuses to overwrite an existing file and creates it
// 0600 on POSIX (on Windows the ACL is not changed: keep it in a user-private directory).
// load_keypair on POSIX throws Error if the file is readable by group/other.
void save_keypair(const std::string& utf8_path, const KeyPair&);
KeyPair load_keypair(const std::string& utf8_path);
// Public key file / string: 64 hex chars (e.g. the value printed by `mysync keygen`).
PubKey load_public_file(const std::string& utf8_path);
void save_public_file(const std::string& utf8_path, const PubKey&);

} // namespace mysync
