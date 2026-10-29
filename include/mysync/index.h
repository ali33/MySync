// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// index.h - persistent (path -> size, mtime, hash) cache and the parallel tree scanner.
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "mysync/filter.h"
#include "mysync/util.h"

namespace mysync {

struct FileMeta {
    std::string rel;       // '/'-separated, relative to the scanned root, UTF-8
    uint64_t size = 0;
    int64_t mtime_ns = 0;  // unix epoch
    Hash256 hash{};        // all zero for directories
    bool is_dir = false;
};

// Not thread-safe; scan_tree touches it only from the calling thread.
class IndexCache {
public:
    // Corrupt, truncated, checksum-mismatching or other-version files give an empty cache and
    // return false; a missing file also returns false. Never throws.
    bool load(const std::string& utf8_path);
    // Atomic: writes <path>.tmp (with trailing BLAKE3 checksum) then renames over <path>. Throws Error.
    void save(const std::string& utf8_path) const;

    const FileMeta* find(const std::string& rel) const;
    void put(const FileMeta& m);
    bool erase(const std::string& rel);
    // Renames entry `from` and every entry under "from/" to the matching name under `to`. Returns count.
    size_t rename_prefix(const std::string& from, const std::string& to);

    void clear() { map_.clear(); }
    size_t size() const { return map_.size(); }
    const std::map<std::string, FileMeta>& entries() const { return map_; }

private:
    std::map<std::string, FileMeta> map_;
};

struct ScanStats {
    uint64_t files = 0;         // regular files returned
    uint64_t hashed = 0;        // files actually read and hashed
    uint64_t reused = 0;        // files whose hash came from the cache
    uint64_t bytes_hashed = 0;
    uint64_t failed = 0;        // unreadable files / directories (logged, skipped)
};

// Walks root recursively (symlinks are skipped, not followed), applies `filter`, hashes in parallel
// only files whose size/mtime differ from the cache (or whose mtime is < 2 s old; such files are
// never cached, so a later same-mtime edit cannot be missed), updates the cache and drops cache
// entries of vanished files. Directories are returned (is_dir) only when filter.includes_all().
// Result sorted by rel. threads == 0 -> hardware concurrency. Throws Error if root is not a directory.
std::vector<FileMeta> scan_tree(const std::string& root_utf8, const Filter& filter, IndexCache& cache,
                                unsigned threads = 0, ScanStats* stats = nullptr);

} // namespace mysync
