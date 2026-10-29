// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// config.h - server/client configuration (TOML subset parser written in-house).
//
// Accepted syntax: [table], [[array of tables]] (incl. nested [[watch.target]] and [watch.filter]),
// "basic strings" (escapes \\ \" \n \t \r \b \f \uXXXX), 'literal strings', integers (with '_'),
// true/false, arrays (single or multi line, comments allowed inside), '#' comments.
// Not supported: floats, dates, inline tables, dotted keys, multi-line strings.
// Server file: keys at top level (optionally under a [server] table) plus [[client]] entries
// (name, public_key, access = "rw"|"ro", prefix).
// Client file: keys at top level (optionally under [client]), then [[watch]], [watch.filter], [[watch.target]] (network: host/server_key, or local: path).
// Every error is thrown as Error with the offending line ("unknown key 'x' at line N").
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/util.h"

namespace mysync {

struct FilterConfig {
    std::vector<std::string> include;        // ".txt" (extension) or glob "*.docx"; empty = everything
    std::vector<std::string> include_regex;  // applied to the '/'-separated relative path
    std::vector<std::string> exclude;        // case-insensitive substring of the relative path
    std::vector<std::string> exclude_regex;
    std::string size_min;     // "10MB", "1.5GB" or a plain number of bytes; empty = no bound
    std::string size_max;
    std::string mtime_after;  // "2026-01-01T00:00:00" (local time) or relative "7d", "12h"; empty = no bound
    std::string mtime_before;
};

using PublicKey = std::array<uint8_t, 32>;

// Two mutually exclusive kinds of destination:
//  - network: host + port + server_key (+ optional key_file overriding ClientConfig::key_file)
//  - local copy: `path` (other drive, UNC share, mount point); host/port/key_file/server_key must be absent
struct TargetConfig {
    std::string host;
    uint16_t port = 5656;
    PublicKey server_key{};   // pinned server public key (network targets)
    std::string key_file;     // client secret key override; empty = ClientConfig::key_file
    std::string path;         // local destination directory
    std::string remote_prefix;
    bool enabled = true;
    bool is_local() const { return !path.empty(); }
};

struct WatchConfig {
    std::string name;
    std::string path;
    bool enabled = true;
    bool recursive = true;
    FilterConfig filter;
    uint32_t quiet_ms = 300;
    uint32_t sync_delay_ms = 100;
    bool start_sync = true;
    bool propagate_delete = true;
    std::vector<std::string> schedule_at;  // "HH:MM"
    uint32_t schedule_interval_s = 0;
    uint32_t periodic_scan_s = 300;
    std::vector<TargetConfig> targets;
};

struct ClientAcl {
    std::string name;
    PublicKey public_key{};
    bool read_only = false;   // access = "ro"
    std::string prefix;       // sub-directory of root this client may see ("" = whole root), no leading/trailing '/'
};

struct ServerConfig {
    std::string bind = "*";
    uint16_t port = 5656;
    std::string root;
    std::string key_file;     // server secret key (hex, 64 chars)
    std::vector<ClientAcl> clients;  // [[client]] entries; at least one required
    uint32_t max_auth_failures_per_min = 10;  // per source IP
    uint32_t max_connections = 20;
    bool trash = true;
    std::vector<std::string> allow{"*"};  // IP, CIDR or "*"
    std::vector<std::string> deny;
    std::string state_dir;
    std::string log_file;
    std::string log_level = "info";
    uint64_t max_file_size = 0;  // 0 = unlimited; accepts "10GB" style strings
    uint32_t io_timeout_s = 60;
};

struct ClientConfig {
    std::string key_file;     // client secret key (hex, 64 chars); targets may override
    std::string state_dir;
    std::string log_file;
    std::string log_level = "info";
    uint32_t connections = 4;
    std::string compress = "lz4";  // "none" | "lz4"
    uint32_t max_bandwidth_kbps = 0;
    uint32_t retry_min_ms = 1000;
    uint32_t retry_max_ms = 60000;
    // files with these extensions are sent without LZ4 (already compressed)
    std::vector<std::string> compress_skip_ext{".zip", ".gz", ".7z", ".rar", ".xz", ".zst", ".bz2", ".jpg",
                                               ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi",
                                               ".mov", ".docx", ".xlsx", ".pptx", ".pdf"};
    std::vector<WatchConfig> watches;
};

// Parse + validate (port 1..65535, key_file required, connections 1..64 ...).
// Existence of root/path on disk is NOT checked here.
ServerConfig parse_server_config_text(const std::string& text);
ClientConfig parse_client_config_text(const std::string& text);
ServerConfig load_server_config(const std::string& utf8_path);
ClientConfig load_client_config(const std::string& utf8_path);

// Reads a secret key file: exactly 64 hex characters (trailing newline allowed) -> 32 bytes.
// Linux: refused when group/other can access the file. Windows: read only.
// Errors never contain the key material.
Bytes load_secret_key_file(const std::string& utf8_path);

// 64 hex characters -> 32 bytes. Throws Error (message never echoes the input).
PublicKey parse_public_key_hex(const std::string& hex);

} // namespace mysync
