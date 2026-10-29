// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// fsutil.h - internal (not a contract header): stat / set mtime / fsync with nanosecond unix mtime,
// shared by the local target and the client engine. Header-only, inline.
#include <cstdint>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace mysync {
namespace fsutil {

struct FsStat {
    bool ok = false;
    bool is_dir = false;
    bool is_file = false;
    bool is_link = false;
    uint64_t size = 0;
    int64_t mtime_ns = 0;
};

inline FsStat stat_path(const std::filesystem::path& p) {
    FsStat si;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) return si;
    si.ok = true;
    si.is_link = (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    si.is_dir = (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    si.is_file = !si.is_dir && !si.is_link;
    si.size = (static_cast<uint64_t>(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
    uint64_t ft = (static_cast<uint64_t>(d.ftLastWriteTime.dwHighDateTime) << 32) | d.ftLastWriteTime.dwLowDateTime;
    si.mtime_ns = (static_cast<int64_t>(ft) - 116444736000000000LL) * 100;
#else
    struct stat st;
    if (::lstat(p.c_str(), &st) != 0) return si;
    si.ok = true;
    si.is_link = S_ISLNK(st.st_mode);
    si.is_dir = S_ISDIR(st.st_mode);
    si.is_file = S_ISREG(st.st_mode);
    si.size = static_cast<uint64_t>(st.st_size);
#ifdef __APPLE__
    si.mtime_ns = static_cast<int64_t>(st.st_mtimespec.tv_sec) * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
    si.mtime_ns = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
#endif
#endif
    return si;
}

inline bool set_mtime_ns(const std::filesystem::path& p, int64_t mtime_ns) {
#ifdef _WIN32
    HANDLE h = CreateFileW(p.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint64_t ft = static_cast<uint64_t>(mtime_ns / 100 + 116444736000000000LL);
    FILETIME f;
    f.dwLowDateTime = static_cast<DWORD>(ft & 0xFFFFFFFFu);
    f.dwHighDateTime = static_cast<DWORD>(ft >> 32);
    bool ok = SetFileTime(h, nullptr, nullptr, &f) != 0;
    CloseHandle(h);
    return ok;
#else
    struct timespec ts[2];
    ts[0].tv_sec = 0;
    ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = static_cast<time_t>(mtime_ns / 1000000000LL);
    ts[1].tv_nsec = static_cast<long>(mtime_ns % 1000000000LL);
    if (ts[1].tv_nsec < 0) { ts[1].tv_nsec += 1000000000L; ts[1].tv_sec -= 1; }
    return ::utimensat(AT_FDCWD, p.c_str(), ts, 0) == 0;
#endif
}

// Flushes file data to stable storage. Best effort: returns false when it could not be done.
inline bool fsync_path(const std::filesystem::path& p) {
#ifdef _WIN32
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = FlushFileBuffers(h) != 0;
    CloseHandle(h);
    return ok;
#else
    int fd = ::open(p.c_str(), O_RDONLY);
    if (fd < 0) return false;
    bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
#endif
}

}  // namespace fsutil
}  // namespace mysync
