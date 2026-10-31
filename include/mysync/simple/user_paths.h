// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/user_paths.h - where "Simple mode" keeps its files. All of them belong to the CURRENT user and are never
// readable by anyone else: no administrator rights are needed to create or use them.
//   Windows : %APPDATA%\MySync\          Linux : $XDG_CONFIG_HOME/mysync or ~/.config/mysync
//     config.toml        client configuration (what is synchronised, and to where)
//     server-user.toml   receiver configuration (only when "receive from other machines" is on)
//     key                client secret key (owner-only: Windows protected DACL, Linux 0600)
//     receiver.key       receiver (server) secret key
//     state/  receiver-state/   index caches        log/  engine logs
// Trust of these files uses the "plain account, own files" branch of gui/trust.h (need_strict_trust is false).
#include <string>

#include "mysync/util.h"

namespace mysync::simple {

struct UserPaths {
    std::string dir;                 // absolute, no trailing separator
    std::string client_config;       // <dir>/config.toml
    std::string receiver_config;     // <dir>/server-user.toml
    std::string client_key;          // <dir>/key
    std::string receiver_key;        // <dir>/receiver.key
    std::string client_state;        // <dir>/state
    std::string receiver_state;      // <dir>/receiver-state
    std::string log_dir;             // <dir>/log
    std::string client_log;          // <dir>/log/client.log
    std::string receiver_log;        // <dir>/log/receiver.log
    std::string instance_lock;       // <dir>/gui.lock (one GUI+engines per user)
    // Control endpoint names (valid_control_name): "mysync-user-<short user id>" and "...-recv".
    std::string client_control_name;
    std::string receiver_control_name;

    // dir_override: tests / portable use ("" = the standard per-user location). Throws Error when it cannot be
    // determined. Pure: creates nothing.
    static UserPaths for_current_user(const std::string& dir_override = "");
    // Creates dir, state, receiver-state, log with access for the current user only (Windows: protected DACL with
    // owner + SYSTEM; Linux: 0700). Idempotent. Throws Error.
    void ensure_dirs() const;
};

// Short, filesystem-safe id of the current user (Windows: tail of the SID; POSIX: uid) used in endpoint names.
std::string current_user_short_id();

// Full SID text of the current user on Windows ("S-1-5-21-..."), "" elsewhere.
std::string current_user_sid();

// d8: the elevated step may run under ANOTHER account than the user who asked (UAC with an administrator's credentials). The
// requester is named explicitly (--requester-sid) and every place of the elevated step that used to mean 'the current user'
// uses effective_user_sid() instead. valid_user_sid accepts only a plain account SID (S-1-5-21-... or S-1-12-1-...).
bool valid_user_sid(const std::string& sid);
// The profile folder of the account with this SID (Windows: ProfileList in the registry); "" when there is none / elsewhere.
// The elevated step takes the home of the REQUESTER from here, not the profile of the process it runs in.
std::string profile_path_for_sid(const std::string& sid);
void set_requester_sid(const std::string& sid);   // "" = none (effective_user_sid() is then the current user)
std::string effective_user_sid();

// Makes an existing file or directory owner-only (Windows: protected DACL owner+SYSTEM; POSIX: 0600 / 0700).
void restrict_to_current_user(const std::string& utf8_path, bool is_dir);

}  // namespace mysync::simple
