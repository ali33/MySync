// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// localtarget.h - ITarget writing into a local directory, another drive, a UNC share (\server\share) or a mounted
// share (CIFS/NFS). Every relative path goes through safe_join(<dest>, rel), so nothing can escape the destination.
//
// put_file: size + mtime are compared first, then the BLAKE3 hash of the destination content (from the destination
// index cache when its size/mtime still match, otherwise by hashing the file). Equal content => Skipped (only the
// mtime is fixed). Otherwise the file is copied to `.mysync-tmp-<rand>` in the destination directory with a 1 MiB
// buffer while hashing, verified against meta.hash, fsync'ed, given the source mtime and renamed atomically. A source
// that changed during the copy gives Failed (the engine retries).
// remove_path moves the entry to <dest>/__sync/__trash/<UTC timestamp>/<rel> (never deletes for real).
#include <memory>
#include <string>

#include "mysync/config.h"
#include "mysync/target.h"

namespace mysync {

class RateLimiter;

// state_dir: where the destination hash cache (dest-<hash of path>.bin) lives; it must NOT be inside the
// destination directory. Empty = in-memory cache only (destination content is hashed again after a restart).
// All instances created for the same destination in this process share one cache.
std::unique_ptr<ITarget> make_local_target(const TargetConfig& cfg, std::shared_ptr<RateLimiter> limiter = nullptr,
                                           const std::string& state_dir = "");

}  // namespace mysync
