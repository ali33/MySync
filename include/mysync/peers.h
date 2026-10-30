// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// peers.h - the server's peers kept OUTSIDE the main configuration file, and the non-interactive edits behind
// `mysync peer ...` (usable from Ansible / shell: idempotent, no prompts).
//
// peers.d: a directory with one <machine>.toml per peer (top-level keys of a [[client]]: name, public_key,
// public_keys, access, prefix, max_sessions ...). `[server] peers_dir` names it (relative to the configuration
// folder); without it <config folder>/peers.d is used when that directory exists.
//
// Merge rules (deterministic, the same on every reload):
//   * the [[client]] entries of the main file come first and always win;
//   * peers.d files are read in file-name order and ADD peers; a file whose name or any key repeats an entry already
//     taken (main file or an earlier file) is skipped with a warning - the first one keeps its place;
//   * a file that cannot be read / parsed, or that the trust check refuses, is skipped with a warning (verbatim
//     message, file name included) and counted: it never disables the other peers;
//   * keys on the revocation list (<config folder>/revoked-keys.txt, written by `mysync peer revoke`) are dropped
//     from every entry, wherever it comes from.
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "mysync/config.h"
#include "mysync/util.h"

namespace mysync {

// A failure of the machine (cannot write / read a file) as opposed to a wrong argument or a conflicting
// configuration (plain Error). The command line maps it to exit code 1 instead of 2.
struct RuntimeFailure : Error {
    using Error::Error;
};

struct PeerLoad {
    std::string dir;                    // the directory looked at ("" = none)
    size_t files = 0;                   // *.toml files found
    size_t loaded = 0;                  // merged into the configuration
    size_t bad = 0;                     // skipped (unreadable, invalid, refused, repeating another peer)
    std::vector<std::string> warnings;  // verbatim, one per problem (also written with log_warn by load_peers)
};

// The peers directory for a configuration: peers_dir (resolved against `config_dir`) when set, else
// <config_dir>/peers.d when it exists, else "".
std::string peers_dir_path(const ServerConfig& cfg, const std::string& config_dir);
// True when peers_dir is set explicitly in the configuration.
inline bool peers_dir_explicit(const ServerConfig& cfg) { return !cfg.peers_dir.empty(); }

// Merges peers.d into cfg.clients and applies the revocation list. A revocation list that exists but cannot be read or
// has a malformed line THROWS Error (fail closed: it must never silently mean "nothing revoked"). `file_check(path)` returns "" to accept a file or a
// reason to refuse it (the trust check of a daemon). Never throws for a bad peer file.
PeerLoad load_peers(ServerConfig& cfg, const std::string& config_dir,
                    const std::function<std::string(const std::string& path)>& file_check = {}, bool log_warnings = true);

// "name:size:mtime;..." of the peers directory and the revocation list: changes when a peer is added / edited / removed.
std::string peers_fingerprint(const ServerConfig& cfg, const std::string& config_dir);

// File name (without directory) used for a peer: <name>.toml when the name is made of [A-Za-z0-9._-], else p-<hash>.toml.
std::string peer_file_name(const std::string& peer_name);
// Text of a peers.d file. Throws Error for a name / prefix that cannot be written.
std::string serialize_peer_file(const ClientAcl& a);

// ---- revocation list ----
struct RevokedKey {
    PublicKey key{};
    std::string name;  // the peer it belonged to
    std::string when;  // UTC date
};
std::string revoked_list_path(const std::string& config_dir);
// Missing file = empty list. Unreadable file / malformed line = Error. A UTF-8 BOM is accepted.
std::vector<RevokedKey> load_revoked(const std::string& config_dir);

// ---- non-interactive edits (the `mysync peer` command). All take the PATH of the server configuration file. ----
struct PeerSpec {
    std::string name;
    PublicKey key{};
    bool read_only = false;
    std::optional<std::string> prefix;           // absent = keep the peer's current folder (a new peer: whole root); "" = whole root
    std::optional<uint32_t> max_sessions;
    std::optional<uint32_t> max_bandwidth_kbps;
    std::optional<uint64_t> max_write_bytes_per_hour;
    bool rotate = false;         // the name exists with ANOTHER key: add this one as the new primary, keep the old as an extra
    bool allow_revoked = false;  // take the key off the revocation list first
};

struct PeerEdit {
    bool changed = false;
    std::string where;    // "peers.d/web2.toml" or "server.toml [[client]]"
    std::string message;  // one line: what happened (or why nothing did)
    std::vector<std::string> revoked_keys;  // revoke: hex keys now on the list
};

// Same peer (same key) with the same parameters = unchanged. Same key, other parameters = updated. Same name, other
// key = Error (unless spec.rotate). Writes into peers.d when the configuration declares peers_dir (or the default
// directory exists), else into a [[client]] of the main file (atomic, .bak). Throws Error (conflict, bad value) or
// RuntimeFailure (cannot write).
PeerEdit peer_add(const std::string& config_path, const PeerSpec& spec);
// By name or by 64-hex key. A peer that is not there is "unchanged", not an error (idempotent).
// revoke = also put every key of the peer on the revocation list.
PeerEdit peer_remove(const std::string& config_path, const std::string& name_or_key, bool revoke);
// Drops one extra key (the old key left over from `peer add --rotate`). The primary key cannot be retired this way.
PeerEdit peer_retire_key(const std::string& config_path, const std::string& name, const PublicKey& key);
// The merged list as the daemon sees it (entries carry `source`).
std::vector<ClientAcl> peer_list(const std::string& config_path, PeerLoad* report = nullptr);

}  // namespace mysync
