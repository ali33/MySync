// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/config_io.h - load, edit, validate and safely write a MySync TOML configuration.
//
// ConfigEditor keeps the parsed ServerConfig / ClientConfig; the GUI edits the struct and calls save():
//   1. serialise the whole struct to canonical TOML (header comment + every field),
//   2. validate by parsing that text again with parse_*_config_text (a file that would not load is never written),
//   3. refuse when the file on disk changed since it was read (content hash) unless SaveOptions::force,
//   4. copy the previous file to "<path>.bak" (hand-written comments are lost in the new file, the .bak keeps them),
//   5. write "<path>.tmp-<rand>" in the same directory, give it the permissions / ACL of the old file, fsync and
//      rename over the target atomically.
// Secret keys are never read, held or logged here: the config only carries the PATH of the key file.
// Not thread-safe: use one ConfigEditor from one thread (the GUI thread); copying is allowed.
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/config.h"
#include "mysync/util.h"

namespace mysync::gui {

enum class ConfigRole { Server, Client };

// Canonical TOML for a configuration (every field, header comment). Round-trips through the parsers:
// parse_*_config_text(serialize_*(c)) is equal to c. Throws Error for values that cannot be written (control chars).
std::string serialize_server_config(const ServerConfig&);
std::string serialize_client_config(const ClientConfig&);

struct SaveOptions {
    bool make_backup = true;   // "<path>.bak" of the previous content (only when the file existed)
    bool force = false;        // write even if the file changed on disk since it was read
};

class ConfigEditor {
public:
    // Role from the tables present: [server]/[[client]] = server, [client]/[[watch]] = client.
    // Throws Error when the text mixes both or has neither (and `fallback` says nothing).
    static ConfigRole detect_role(const std::string& toml_text);

    // Reads and parses the file. Errors carry the file name and the line number ("... at line 12").
    static ConfigEditor open(const std::string& utf8_path);
    static ConfigEditor open(const std::string& utf8_path, ConfigRole role);
    // A new in-memory configuration with defaults; save() creates the file and refuses to overwrite an existing one
    // unless SaveOptions::force.
    static ConfigEditor create(const std::string& utf8_path, ConfigRole role);

    ConfigRole role() const { return role_; }
    const std::string& path() const { return path_; }

    // Throws Error when the role does not match.
    ServerConfig& server();
    const ServerConfig& server() const;
    ClientConfig& client();
    const ClientConfig& client() const;

    // Canonical text of the current in-memory configuration.
    std::string to_toml() const;
    // Throws Error (verbatim parser message) when the current configuration would not load.
    void validate() const;

    // True when the in-memory configuration differs from what was loaded / last saved.
    bool dirty() const;
    // True when the file on disk no longer has the content read by open()/save(). A missing file counts as changed
    // when it existed before.
    bool changed_on_disk() const;
    // SHA-style hex digest (BLAKE3) of the file content as last read or written ("" = file did not exist).
    const std::string& disk_hash() const { return disk_hash_; }

    void save(const SaveOptions& opts = SaveOptions());
    // Discards edits and reads the file again.
    void reload();

private:
    ConfigRole role_ = ConfigRole::Client;
    std::string path_;
    ServerConfig server_;
    ClientConfig client_;
    std::string disk_hash_;       // hash of the file when read/written
    std::string clean_text_;      // canonical text of the configuration as loaded / saved (for dirty())
    bool existed_ = false;
};

// Atomic replacement helper (also used by key management): writes `content` to `utf8_path` through a temp file in
// the same directory, copying permissions/ACL from the existing file (if any), fsync, rename. Throws Error.
void write_file_atomic(const std::string& utf8_path, const std::string& content, bool keep_permissions = true);

// Hex BLAKE3 of a file's content, "" when the file does not exist. Throws Error on other read failures.
std::string file_content_hash(const std::string& utf8_path);

}  // namespace mysync::gui
