// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// watcher.h - recursive file-system watcher with debounce + batching (see docs/DESIGN.md).
//
// Windows: ReadDirectoryChangesW (overlapped, own thread, 256 KiB buffer, bWatchSubtree).
// Linux:   inotify with recursive watches (new directories are watched + rescanned).
//
// Semantics of the callback batches:
//  * Modified is emitted for a path only after it has been quiet for `quiet_ms` AND it can be opened
//    for reading (not exclusively locked), and its (size, mtime) is unchanged across two looks one
//    quiet period apart (NTFS reports a still-open writer lazily). A file locked for ~30 s is emitted anyway (with a warning).
//    A Modified whose file vanished before it settled is reported as Deleted.
//  * Deleted / Renamed are emitted within ~quiet_ms of the first event, grouped into one batch.
//  * Overflow means "events were lost, rescan everything" (OS buffer overflow, > 100k queued items,
//    inotify limit reached, or the periodic safety scan). When present it is the first element.
//  * Callbacks run on the watcher's own thread, never concurrently with each other.
// Known limits: on Windows Deleted.is_dir is always false (the kernel does not say); when a
// directory is renamed, queued-but-unflushed events below it keep their old prefix (the consumer is
// expected to verify against the file system anyway).
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mysync {

struct WatchEvent {
    enum Kind { Modified, Deleted, Renamed, Overflow } kind = Modified;
    std::string rel;       // path relative to root, '/' separated, UTF-8 (new path for Renamed)
    std::string rel_from;  // Renamed only: old path
    bool is_dir = false;
};

struct WatcherOptions {
    std::string root_utf8;
    bool recursive = true;
    int quiet_ms = 100;         // debounce window ("timeActionAfterChanged")
    int periodic_scan_s = 300;  // emit Overflow every N seconds so the owner rescans; 0 = off
    // Return true to drop a path ("__sync" is always dropped). Also consulted for each ancestor
    // directory of an event path, and by the Linux backend to decide which directories to watch.
    std::function<bool(const std::string& rel, bool is_dir)> ignore;
};

class Watcher {
public:
    using BatchCallback = std::function<void(std::vector<WatchEvent>&&)>;
    Watcher(WatcherOptions opt, BatchCallback on_batch);
    ~Watcher();  // calls stop()
    Watcher(const Watcher&) = delete;
    Watcher& operator=(const Watcher&) = delete;

    void start();  // throws Error if the root cannot be watched; no-op if already started
    void stop();   // idempotent, joins all threads, closes all handles; safe from any thread except the callback

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

}  // namespace mysync
