// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// client_engine.h - the client side: watches folders and mirrors them to the configured targets.
//
// Per [[watch]] (enabled): Filter -> initial reconcile (scan_tree + IndexCache in state_dir, compared with the target's
// list_remote: only what is missing/different is sent; extra files on the target are removed ONLY when propagate_delete
// is on, and never when that would wipe more than half of the target (> 100 files) - a temporarily empty source) ->
// Watcher -> one de-duplicated queue per (watch, target) -> `connections` worker threads, each with its own ITarget.
// Every target is independent: a dead target never blocks another. Failures are retried with exponential backoff
// (retry_min_ms .. retry_max_ms, jittered); an event is never dropped, it stays queued.
// Relative paths in the configuration (key_file, state_dir, watch path, local target path) are resolved against
// `config_dir`. The source index of a watch is state_dir/index-<watch name>.bin (shared by all its targets).
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "mysync/config.h"
#include "mysync/gui/status.h"

namespace mysync {

struct EngineStats {
    uint64_t sent = 0;      // files whose content was transferred
    uint64_t skipped = 0;   // files already identical on the target
    uint64_t failed = 0;    // failed attempts (each retry counts)
    uint64_t gave_up = 0;   // operations/targets abandoned (sync_once only: retries exhausted)
    uint64_t deleted = 0;   // paths removed (trashed) on targets
    uint64_t renamed = 0;
    uint64_t bytes = 0;     // payload bytes transferred
    uint64_t hashed = 0;    // source files actually read and hashed
    uint64_t reused = 0;    // source files whose hash came from the index cache
};

class SyncEngine {
public:
    SyncEngine(ClientConfig cfg, std::string config_dir);
    ~SyncEngine();
    SyncEngine(const SyncEngine&) = delete;
    SyncEngine& operator=(const SyncEngine&) = delete;

    // Continuous mode: initial sync (when start_sync), then watch + schedule + periodic rescans until `stop`.
    // Throws Error when the configuration has nothing to do or a key file cannot be read.
    void run(std::atomic<bool>& stop);
    // One reconcile of every watch/target, then returns (after the queues drained, or `stop`, or retries exhausted:
    // see EngineStats::gave_up).
    void sync_once(std::atomic<bool>& stop);

    EngineStats stats() const;
    // Light, thread-safe status for the GUI (role Client): per (watch, target) state, queue length, files in flight
    // (at most 20 names), rates, totals and the last error. Safe to call while run() starts or stops; carries no secrets.
    // Empty `targets` before run()/sync_once() has built the engine.
    gui::StatusSnapshot snapshot() const;
    // Builds the engine from the configuration without starting anything (reads the key files and the index) and
    // throws Error exactly as run() would for an unusable configuration. Used to vet a reloaded configuration.
    void check_config();
    // True when the initial reconcile of every target is finished and nothing is queued or in flight.
    bool idle() const;

private:
    void start_watchers(bool first);
    struct Impl;
    std::unique_ptr<Impl> p_;
};

}  // namespace mysync
