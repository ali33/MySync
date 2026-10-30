// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/wizard_model.h - the first-run wizard without any UI: everyday choices in, a safe ClientConfig out.
// Safe defaults: skips temporary and system files (Thumbs.db, desktop.ini, $RECYCLE.BIN, .DS_Store, ~$*, *.tmp),
// deletes / overwrites go to the trash of the target, no bandwidth cap, real-time watch, initial sync on start.
// Problems are reported as KEYS the GUI translates (vi / en); `detail` is the verbatim path / system text.
#include <string>
#include <vector>

#include "mysync/config.h"
#include "mysync/keys.h"
#include "mysync/simple/pair_code.h"
#include "mysync/simple/user_paths.h"

namespace mysync::simple {

enum class DestKind {
    Folder,         // another folder, a USB drive or a shared folder (local copy: LocalTarget path)
    PairedMachine,  // another machine running MySync, reached with a pairing code (already approved)
};

struct WizardInput {
    std::string source;      // folder to protect
    std::string watch_name;  // "" = derived from the folder name
    DestKind kind = DestKind::Folder;
    std::string dest_path;   // Folder
    PairCode paired;         // PairedMachine: host / port / server key from the code
};

struct WizardIssue {
    std::string key;     // "wizard.source_empty" | "wizard.source_missing" | "wizard.source_not_dir" |
                         // "wizard.dest_empty" | "wizard.dest_missing" | "wizard.dest_not_writable" |
                         // "wizard.dest_inside_source" | "wizard.source_inside_dest" | "wizard.same_folder" |
                         // "wizard.source_is_root" | "wizard.source_internal" | "wizard.pair_missing" |
                         // "wizard.bad_name"
    std::string detail;  // verbatim path / system message ("" if none)
};

// Empty = acceptable. Touches the disk only to read (exists / is a directory) and to test writability of a folder
// destination (creates and removes a small probe file).
std::vector<WizardIssue> validate_wizard(const WizardInput&);

// Pure: the configuration for `in` (paths made absolute and normalised). Throws Error if the structure is unusable
// (e.g. empty source).
ClientConfig build_client_config(const WizardInput& in, const UserPaths& paths);

// Validate, make the directories, create the client key if missing (owner-only) and write the configuration with
// ConfigEditor (atomic, .bak). If the configuration file already exists the new watch is APPENDED (names made unique).
// Throws Error "<issue key>: <detail>" when invalid.
void save_wizard(const WizardInput& in, const UserPaths& paths);

// Where a folder-name-derived watch name comes from.
std::string default_watch_name(const std::string& source_folder);

// Creates the secret key file when it is missing (owner-only) and returns its PUBLIC key (64 hex). Call it before
// pairing, which needs this machine's identity.
std::string ensure_user_key(const std::string& key_file);

// ensure_dirs() + the client key when missing (owner-only); returns the identity. Call before pairing (it runs before
// save_wizard). Never logs or copies the secret.
KeyPair ensure_client_key(const UserPaths& paths);

// What server-user.toml currently says (the GUI shows / edits it). False when the file does not exist or cannot be read.
struct ReceiverSettings {
    std::string root;
    uint16_t port = 5656;
};
bool read_receiver_settings(const UserPaths& paths, ReceiverSettings* out);

// ---- "Receive from other machines" (the receiver / server side of simple mode)
// Issue keys: "receiver.root_empty" | "receiver.root_missing" | "receiver.root_not_writable" | "receiver.root_internal"
// (inside / containing the program's own folder) | "receiver.root_is_source" (a folder this computer already
// synchronises: would loop) | "receiver.root_is_root".
std::vector<WizardIssue> validate_receiver_root(const std::string& receive_root, const UserPaths& paths);
// Creates or updates <dir>/server-user.toml: listens on `port`, stores into `receive_root`, own key (receiver.key,
// owner-only), pairing = "on-demand" (switched on from the GUI only), control channel under the receiver name, and an
// (empty) peers.d next to it so a receiver with nobody paired yet is a valid configuration. Paired machines are
// added to this file when the user approves them. Throws Error "<issue key>: <detail>" for an unusable folder.
// Returns the receiver's PUBLIC key (64 hex).
std::string ensure_receiver_config(const std::string& receive_root, const UserPaths& paths, uint16_t port = 5656);

}  // namespace mysync::simple
