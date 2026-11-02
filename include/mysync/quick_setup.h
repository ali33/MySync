// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// quick_setup.h - "stand up a server / a client in one step". The ONE core behind `mysync quick-server`,
// `mysync quick-client` and the GUI's "Dựng máy chủ" wizard (the GUI calls these functions, not the command line).
//
// What it does: creates the identity key when missing (gui::KeyManager::generate_key_file - never overwrites), writes
// server.toml / client.toml with safe defaults through gui::ConfigEditor (validated by the real parser before it is
// written), and returns what the person must hand to the other machine. What it never does:
//   * print, return or write the secret key (only its PATH and the public half);
//   * overwrite an existing key (not even with `force`: rotate keys with `mysync key rotate`);
//   * overwrite an existing configuration unless `force` (then the old file is kept as <config>.bak);
//   * switch pairing on (the server is written with pairing = "off"), or open any service-install path of its own:
//     installing a service is done by the caller through gui::ServiceController (all trust / hash checks stay there).
// Idempotent: running it again changes nothing and reports what already exists.
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/util.h"

namespace mysync {

constexpr uint16_t kQuickDefaultPort = 5656;   // as in examples/server.toml

// Thrown when a run with high rights (administrator / root) meets a folder that other local accounts can write into.
// `path` is the folder; the GUI explains it in plain words and offers make_folder_private() (fix_permissions).
struct UntrustedFolderError : Error {
    std::string path;
    UntrustedFolderError(const std::string& p, const std::string& msg) : Error(msg), path(p) {}
};

// Gives `dir` private permissions: Windows = protected DACL (no inheritance from the parent) for the current account,
// SYSTEM and Administrators, inherited by what is inside; POSIX = group/other may not write (chmod go-w).
// Used for folders quick_server / quick_client create, and for existing ones when fix_permissions is set.
void make_folder_private(const std::string& dir);

struct QuickServerOptions {
    std::string dir;           // the folder that receives files (server root); created when missing
    std::string config_dir;    // where server.toml / server.key / peers.d live; "" = <dir>.mysync (beside the root, NOT inside it)
    uint16_t port = kQuickDefaultPort;
    std::string name;          // label used in the client snippet and the suggested `peer add` ("" = "may-khach")
    bool force = false;        // rewrite an existing server.toml (old one kept as .bak); the key is always kept
    bool vietnamese_comments = false;   // language of the comments inside the client snippet (the GUI sets it from its language; the CLI stays English)
    bool fix_permissions = false;       // existing shared / configuration folder: make it private first (--fix-permissions)
};

struct QuickClientOptions {
    std::string server;        // "host:port" or "[v6]:port" (port optional = 5656)
    std::string server_key;    // the server's PUBLIC key, 64 hex (pasted text is normalised)
    std::string dir;           // the folder to synchronise (watched)
    std::string config_dir;    // "" = <dir>.mysync
    std::string name;          // label for the suggested `peer add` ("" = "may-khach")
    bool force = false;
    bool fix_permissions = false;  // existing configuration folder: make it private first (--fix-permissions)
};

struct QuickResult {
    std::string role;              // "server" | "client"
    std::string dir;               // absolute root (server) / watched folder (client)
    std::string config_dir;
    std::string config_file;       // absolute
    std::string key_file;          // absolute PATH of the secret key (the key itself is never exposed)
    std::string public_key;        // 64 hex
    std::string fingerprint;       // aaaa-bbbb-cccc-dddd-eeee
    uint16_t port = 0;             // server: listening port actually in the configuration
    std::string server_address;    // client: "host:port"
    std::string pairing;           // server: "off" ...
    bool dir_created = false;
    bool key_created = false;
    bool key_existed = false;
    bool config_created = false;
    bool config_existed = false;    // a configuration was already there (kept unless `force`)
    bool config_replaced = false;   // force: the old one was replaced (.bak written)
    std::string client_snippet;     // server: client.toml to paste on the client machine
    std::string peer_add_command;   // server: with a placeholder for the client's key; client: with the real key
    std::vector<std::string> notes; // one-line remarks (e.g. "the port in the existing file differs")
    bool changed() const { return dir_created || key_created || config_created || config_replaced; }
};

// Throws Error (wrong argument, refused path, invalid result) - never leaves a half-written configuration.
QuickResult quick_server(const QuickServerOptions&);
QuickResult quick_client(const QuickClientOptions&);

// Pure helpers (tested directly).
// "host:port" / "[::1]:5656" / "host" -> host, port. Throws Error.
void parse_host_port(const std::string& text, std::string& host, uint16_t& port);
std::string default_quick_config_dir(const std::string& dir);   // <dir>.mysync, absolute
// The client.toml text printed for a server (placeholders for the host and the folder). Parses with parse_client_config_text.
std::string make_client_snippet(const std::string& host, uint16_t port, const std::string& server_public_hex,
                                const std::string& watch_name, bool vietnamese_comments = false);
std::string make_peer_add_command(const std::string& client_public_hex_or_placeholder, const std::string& name,
                                  const std::string& server_config_path);
// Machine-readable form (stable keys), one line + "\n".
std::string quick_result_json(const QuickResult&);

}  // namespace mysync
