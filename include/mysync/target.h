// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// target.h - CONTRACT header: a sync destination (MySync server over network, or a local/UNC directory).
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "mysync/index.h"   // FileMeta
#include "mysync/util.h"

namespace mysync {

struct PutResult {
    enum Status { Sent, Skipped, Failed } status = Failed;
    uint64_t bytes_on_wire = 0;  // payload bytes actually transferred (0 when Skipped)
    bool used_delta = false;
    std::string error;           // set when Failed (no secrets)
};

struct PutItem {
    std::string rel;
    std::string abs_src;
    FileMeta meta;
};

// Thread-compatible: one ITarget instance is used by ONE worker thread at a time.
// Implementations: NetTarget (SecureChannel to a MySync server), LocalTarget (directory / UNC / mounted share).
class ITarget {
public:
    virtual ~ITarget() = default;
    // Establish connection / validate destination root. Throws Error. May be called again after failure.
    virtual void open() = 0;
    virtual void close() = 0;
    // Make `rel` on the destination equal to the local file `abs_src` (meta already hashed by caller).
    // Skips (Skipped) when destination already holds identical content (same hash), then only fixes mtime.
    // Writes to a temp file in the destination dir, verifies BLAKE3, fsync, atomic rename. Never throws for per-file
    // problems (returns Failed); throws Error for connection-level failure.
    virtual PutResult put_file(const std::string& rel, const std::string& abs_src, const FileMeta& meta) = 0;
    // Batch form: lets a network target pipeline many small-file OFFERs without waiting for each reply.
    // Default = sequential put_file. Result vector has one entry per item, same order.
    virtual std::vector<PutResult> put_batch(const std::vector<PutItem>& items) {
        std::vector<PutResult> r;
        r.reserve(items.size());
        for (const auto& it : items) r.push_back(put_file(it.rel, it.abs_src, it.meta));
        return r;
    }
    virtual void remove_path(const std::string& rel, bool is_dir) = 0;   // trash if configured
    virtual void rename_path(const std::string& from, const std::string& to) = 0;
    virtual void make_dir(const std::string& rel) = 0;
    // Snapshot of what the destination holds under the root (rel -> meta with hash), used for initial reconcile.
    virtual std::map<std::string, FileMeta> list_remote() = 0;
    virtual std::string description() const = 0;  // for logs, e.g. "net://host:5656" / "dir://D:/Backup" (no secrets)
};

}  // namespace mysync
