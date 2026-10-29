// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/key_mgr.h - identity keys and the server allowlist, for pairing two machines.
//
// The secret key never leaves its file: nothing here returns, logs or copies secret bytes. generate_key_file()
// creates the file (refuses to overwrite; 0600 on POSIX, owner/SYSTEM/Administrators DACL on Windows) and returns
// only the PUBLIC key. public_key_of_file() derives the public half and discards the secret at once.
// Public keys are 64 hex characters. fingerprint() is a short, readable digest for comparing two keys by eye
// (BLAKE3 of the 32 key bytes, first 10 bytes as 5 groups of 4 hex: "a1b2-c3d4-e5f6-0718-293a").
#include <string>
#include <vector>

#include "mysync/gui/config_io.h"
#include "mysync/keys.h"

namespace mysync::gui {

struct GeneratedKey {
    std::string key_file;      // absolute path written
    std::string public_hex;    // 64 lowercase hex
    std::string fingerprint;   // see above
    std::string pub_file;      // "<key_file>.pub" if it could be written, else ""
};

struct AllowedClient {
    std::string name;
    std::string public_hex;
    std::string fingerprint;
    bool read_only = false;
    std::string prefix;
    uint32_t max_sessions = 4;
    uint64_t max_write_bytes_per_hour = 0;
    uint32_t max_bandwidth_kbps = 0;
};

class KeyManager {
public:
    // ---- identity keys
    // Creates a new key pair file. Throws Error if the file exists or cannot be created securely.
    static GeneratedKey generate_key_file(const std::string& utf8_path, bool write_pub_file = true);
    // Public key (64 hex) of an existing secret key file. Throws Error with a message that never echoes key bytes.
    static std::string public_key_of_file(const std::string& utf8_key_file);
    // Windows: broad principals ("Everyone", "Users"...) that can read the key file; empty on POSIX.
    static std::vector<std::string> key_file_exposure(const std::string& utf8_key_file);

    // ---- public key text
    static bool is_valid_public_hex(const std::string& text);
    // Accepts what a user pastes: surrounding whitespace/newlines, upper case, optional "0x", spaces or ':' between
    // bytes. Returns 64 lowercase hex or throws Error ("not a valid public key: need 64 hex characters").
    static std::string normalize_public_hex(const std::string& pasted);
    static std::string fingerprint(const std::string& public_hex);   // normalises first
    static std::string fingerprint(const PubKey& key);

    // ---- server allowlist ([[client]] entries); these only edit the ConfigEditor, call save() afterwards
    static std::vector<AllowedClient> list_clients(const ConfigEditor& server_cfg);
    // Throws Error on a duplicate name or public key, an invalid key, a bad prefix.
    static void add_client(ConfigEditor& server_cfg, const AllowedClient& c);
    // Replaces the entry called `name` (the entry may be renamed / re-keyed). Throws Error if it does not exist.
    static void update_client(ConfigEditor& server_cfg, const std::string& name, const AllowedClient& c);
    static void remove_client(ConfigEditor& server_cfg, const std::string& name);  // Error if missing or last one

    // ---- client side: pin the server's public key on a target
    static void set_target_server_key(ConfigEditor& client_cfg, size_t watch_index, size_t target_index,
                                      const std::string& pasted_public_hex);
};

}  // namespace mysync::gui
