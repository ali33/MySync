// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/status.h - what a running daemon reports to the GUI. Plain data, no wx types.
//
// SECURITY: nothing in this header (nor anything that travels over the control channel) may carry a secret key,
// a key file's contents or a PSK. Public keys are not carried either: the GUI reads them from the config.
// Everything is copied by value, so a snapshot is safe to hand to another thread.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace mysync::gui {

enum class Role : uint8_t { Server = 1, Client = 2 };
const char* role_name(Role);  // "server" / "client"

enum class TargetState : uint8_t {
    Idle = 0,          // nothing queued, nothing in flight, last attempt fine
    Syncing = 1,       // reconcile running, files queued or in flight
    Error = 2,         // last attempt failed, retrying (see last_error)
    Disconnected = 3,  // target unreachable (network target, connection refused/lost)
};
const char* target_state_name(TargetState);

constexpr size_t kMaxActiveFiles = 20;  // names listed in TargetStatus::active_files

// One (watch, target) pair of a client daemon.
struct TargetStatus {
    std::string watch;                       // [[watch]] name
    std::string target;                      // "net://host:port" or "dir://path" (never a key)
    TargetState state = TargetState::Idle;
    uint64_t queued = 0;                     // files waiting (not counting the ones in flight)
    std::vector<std::string> active_files;   // relative paths being transferred (at most kMaxActiveFiles)
    uint64_t tx_bps = 0;                     // bytes/s sent (smoothed)
    uint64_t rx_bps = 0;                     // bytes/s received (smoothed)
    uint64_t sent = 0, skipped = 0, failed = 0;
    uint64_t bytes = 0;                      // payload bytes transferred so far
    std::string last_error;                  // verbatim, no secrets; empty = none
    int64_t last_error_unix_ms = 0;          // 0 = none
};

// One [[client]] of a server daemon (by name only: no key).
struct PeerStatus {
    std::string name;
    uint32_t sessions = 0;
    uint64_t rx_bps = 0, tx_bps = 0;         // from the server's point of view (rx = received from that client)
    uint64_t bytes_rx = 0, bytes_tx = 0;
};

struct StatusSnapshot {
    Role role = Role::Client;
    std::string version;
    std::string service_name;                // control name the daemon listens under
    std::string config_path;                 // absolute path of the config file it was started with ("" = unknown)
    uint64_t uptime_s = 0;
    int64_t taken_unix_ms = 0;
    uint64_t total_tx_bps = 0, total_rx_bps = 0;
    uint64_t total_sent = 0, total_skipped = 0, total_failed = 0;  // client: files; server: sessions' totals unused (0)
    // client
    std::vector<TargetStatus> targets;
    // server
    std::string listen;                      // "bind:port"
    uint32_t sessions = 0;                   // authenticated sessions now
    uint32_t max_connections = 0;
    std::vector<PeerStatus> peers;
    // both
    int64_t config_loaded_unix_ms = 0;       // when the running configuration was (re)loaded
    std::string config_error;                // why the last RELOAD_CONFIG was refused ("" = none)
};

struct ErrorEntry {
    int64_t unix_ms = 0;
    std::string level;                       // "WARN" | "ERROR"
    std::string message;                     // verbatim log message
};

struct ReloadResult {
    bool ok = false;
    std::string message;                     // ok: summary; failure: verbatim error (with line number for syntax errors)
    std::vector<std::string> applied;        // settings now in effect
    std::vector<std::string> needs_restart;  // settings changed in the file but only a process restart applies them
};

// Smoothed rate from a monotonically growing byte counter. Thread-safe.
class RateMeter {
public:
    // Call with the counter's current value; returns bytes/s. Cheap; recomputes at most every 500 ms.
    uint64_t update(uint64_t counter);

private:
    std::chrono::steady_clock::time_point last_{};
    uint64_t last_counter_ = 0;
    uint64_t bps_ = 0;
    bool init_ = false;
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
};

}  // namespace mysync::gui
