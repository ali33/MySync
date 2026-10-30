// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// engine_lock.h - an operating-system file lock that proves "this process is the only engine watching this folder".
// The lock belongs to the process: when it dies (crash, kill) the OS releases it, so there is no stale lock to clean.
// Windows: LockFileEx on one byte far beyond the text (the PID text stays readable by the process that loses);
// POSIX: flock(LOCK_EX|LOCK_NB). The file is created if missing; its parent directory is created too.
// A `__sync` (or lock file) that is a symbolic link / junction / reparse point is refused (it could point anywhere):
// POSIX opens it with openat() from the folder's descriptor with O_NOFOLLOW, Windows checks the attributes before and
// after opening with FILE_FLAG_OPEN_REPARSE_POINT.
// A `__sync` (or lock file) that is a symbolic link / junction / reparse point is refused (it could point anywhere):
// POSIX opens it with openat() from the folder's descriptor with O_NOFOLLOW, Windows checks the attributes before and
// after opening with FILE_FLAG_OPEN_REPARSE_POINT.
#include <memory>
#include <string>

#include "mysync/util.h"

namespace mysync {

// Thrown by try_acquire ONLY when the lock file cannot be created because the folder is read-only / not writable for us
// (a read-only share or medium). The caller may then carry on without protection and must say so. Every other failure
// (the folder `__sync` or the lock file is a link or a directory, I/O error ...) is a plain Error: no engine may start
// on it, or two engines could silently run on one folder.
struct LockNotPossible : Error {
    using Error::Error;
};

class FileLock {
public:
    // Returns nullptr when somebody else holds the lock and sets *holder to "PID n" (or "" when unknown).
    // Throws Error for anything else (cannot create the folder / file).
    static std::unique_ptr<FileLock> try_acquire(const std::string& utf8_path, std::string* holder = nullptr);
    ~FileLock();
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    const std::string& path() const { return path_; }

private:
    FileLock() = default;
    struct Impl;
    std::unique_ptr<Impl> p_;
    std::string path_;
};

// <sync folder>/__sync/engine.lock
std::string engine_lock_path_for_folder(const std::string& utf8_folder);
// "folder X is already being synchronised by another process (PID n)" - the verbatim message every engine uses.
std::string engine_lock_busy_message(const std::string& folder, const std::string& holder);

}  // namespace mysync
