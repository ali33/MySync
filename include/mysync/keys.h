// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// keys.h - static X25519 identity keys (pinned public keys, no CA) and their on-disk / hex form.
#include <array>
#include <string>
#include <vector>

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

// Key file = one line with the 64-hex secret. save_keypair refuses to overwrite an existing file (and never follows
// a symlink): it is created exclusively, 0600 on POSIX, and on Windows with a protected DACL granting only the
// owner, SYSTEM and Administrators.
// load_keypair / read_secret_file on POSIX open with O_NOFOLLOW and check the OPEN descriptor (no stat/open race):
// must be a regular file owned by the effective user (or root) with no group/other permission bits, else Error.
// On Windows a DACL that grants Everyone / Users / Authenticated Users only logs a warning.
void save_keypair(const std::string& utf8_path, const KeyPair&);
KeyPair load_keypair(const std::string& utf8_path);
// Raw contents (<= 4096 bytes) of a secret file after the checks above. The caller must secure_wipe the result.
// load_keypair and config's load_secret_key_file both read through this single path.
std::string read_secret_file(const std::string& utf8_path);
// Names of broad principals ("Everyone", "Users", "Authenticated Users") that the file's DACL allows access to.
// Windows only; always empty on POSIX and when the DACL cannot be read.
std::vector<std::string> key_file_broad_acl(const std::string& utf8_path);
// Public key file / string: 64 hex chars (e.g. the value printed by `mysync keygen`).
PubKey load_public_file(const std::string& utf8_path);
void save_public_file(const std::string& utf8_path, const PubKey&);

} // namespace mysync
