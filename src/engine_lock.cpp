// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/engine_lock.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace mysync {

struct FileLock::Impl {
#ifdef _WIN32
    HANDLE h = INVALID_HANDLE_VALUE;
#else
    int fd = -1;
#endif
    ~Impl() {
#ifdef _WIN32
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);  // closing the handle releases the lock
#else
        if (fd >= 0) ::close(fd);
#endif
    }
};

namespace {

#ifdef _WIN32
// The lock is taken on one byte far away from the text so the PID stays readable by the process that loses.
constexpr DWORD kLockOffsetLow = 0x40000000u;

std::string read_pid_text(const fs::path& p) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    char buf[64] = {};
    DWORD n = 0;
    ReadFile(h, buf, sizeof buf - 1, &n, nullptr);
    CloseHandle(h);
    return std::string(buf, n);
}
#else
std::string read_pid_text(const fs::path& p) {
    int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {};
    char buf[64] = {};
    ssize_t n = ::read(fd, buf, sizeof buf - 1);
    ::close(fd);
    return n > 0 ? std::string(buf, size_t(n)) : std::string();
}
#endif

std::string pid_label(const std::string& text) {
    std::string digits;
    for (char c : text) {
        if (c >= '0' && c <= '9') digits += c;
        else if (!digits.empty()) break;
    }
    return digits.empty() ? std::string() : "PID " + digits;
}

}  // namespace

std::string engine_lock_path_for_folder(const std::string& utf8_folder) {
    return (fs::u8path(utf8_folder) / "__sync" / "engine.lock").u8string();
}

std::string engine_lock_busy_message(const std::string& folder, const std::string& holder) {
    return "folder '" + folder + "' is already being synchronised by another process" +
           (holder.empty() ? std::string() : " (" + holder + ")");
}

FileLock::~FileLock() = default;

std::unique_ptr<FileLock> FileLock::try_acquire(const std::string& utf8_path, std::string* holder) {
    if (holder) holder->clear();
    fs::path p = fs::u8path(utf8_path);
    fs::path dirp = p.parent_path();
    const bool in_sync = dirp.filename() == "__sync";
    auto impl = std::make_unique<FileLock::Impl>();
    std::string pid = std::to_string(
#ifdef _WIN32
        static_cast<unsigned long>(GetCurrentProcessId())
#else
        static_cast<long>(::getpid())
#endif
    );
#ifdef _WIN32
    auto attrs = [](const fs::path& q) { return GetFileAttributesW(q.c_str()); };
    auto is_link_or_not_dir = [&](const fs::path& q) {
        DWORD a = attrs(q);
        return a != INVALID_FILE_ATTRIBUTES && ((a & FILE_ATTRIBUTE_REPARSE_POINT) || !(a & FILE_ATTRIBUTE_DIRECTORY));
    };
    std::error_code ec;
    if (in_sync) {
        if (is_link_or_not_dir(dirp))
            throw Error("'" + dirp.u8string() + "' is a link or not a folder: refusing to use it for the engine lock");
        if (attrs(dirp) == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(dirp.c_str(), nullptr)) {
                DWORD e = GetLastError();
                if (e == ERROR_ACCESS_DENIED || e == ERROR_WRITE_PROTECT)
                    throw LockNotPossible("the folder cannot be written (error " + std::to_string(e) + ")");
                if (e != ERROR_ALREADY_EXISTS)
                    throw Error("cannot create '" + dirp.u8string() + "' (error " + std::to_string(e) + ")");
            }
        }
    } else {
        fs::create_directories(dirp, ec);
        if (ec) throw Error("cannot create the folder of the lock file: " + ec.message());
    }
    DWORD pa = attrs(p);
    if (pa != INVALID_FILE_ATTRIBUTES && ((pa & FILE_ATTRIBUTE_DIRECTORY) || (pa & FILE_ATTRIBUTE_REPARSE_POINT)))
        throw Error("'" + p.u8string() + "' is a folder or a link, not a lock file");
    // No FILE_SHARE_DELETE: nobody can delete or rename the lock file from under the holder.
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION) {
            if (holder) *holder = pid_label(read_pid_text(p));
            return nullptr;
        }
        if ((e == ERROR_ACCESS_DENIED || e == ERROR_WRITE_PROTECT) && attrs(p) == INVALID_FILE_ATTRIBUTES)
            throw LockNotPossible("the lock file cannot be created (error " + std::to_string(e) + ")");
        throw Error("cannot open the lock file (error " + std::to_string(e) + ")");
    }
    impl->h = h;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        (in_sync && is_link_or_not_dir(dirp)))
        throw Error("the lock file or its folder changed into a link while opening it: refusing");
    OVERLAPPED ov{};
    ov.Offset = kLockOffsetLow;
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)) {
        DWORD e = GetLastError();
        if (e == ERROR_LOCK_VIOLATION || e == ERROR_IO_PENDING) {
            if (holder) *holder = pid_label(read_pid_text(p));
            return nullptr;
        }
        throw Error("cannot lock the lock file (error " + std::to_string(e) + ")");
    }
    SetFilePointer(h, 0, nullptr, FILE_BEGIN);
    DWORD wr = 0;
    WriteFile(h, pid.data(), DWORD(pid.size()), &wr, nullptr);
    SetEndOfFile(h);
#else
    // Every step is relative to the descriptor of the folder that holds `__sync`, so a `__sync` swapped for a symlink
    // cannot redirect us.
    fs::path top = in_sync ? dirp.parent_path() : dirp;
    std::error_code ec;
    if (!in_sync) {
        fs::create_directories(dirp, ec);
        if (ec) throw Error("cannot create the folder of the lock file: " + ec.message());
    }
    int tfd = ::open(top.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (tfd < 0) throw Error("cannot open the folder '" + top.string() + "': " + std::strerror(errno));
    struct FdGuard {
        int fd;
        ~FdGuard() {
            if (fd >= 0) ::close(fd);
        }
    } tg{tfd};
    auto read_only = [](int dfd) { return ::faccessat(dfd, ".", W_OK, AT_EACCESS) != 0; };
    int dfd = tfd;
    FdGuard sg{-1};
    if (in_sync) {
        if (::mkdirat(tfd, "__sync", 0700) != 0 && errno != EEXIST) {
            int e = errno;
            if ((e == EACCES || e == EROFS || e == EPERM) && read_only(tfd))
                throw LockNotPossible(std::string("the folder cannot be written: ") + std::strerror(e));
            throw Error(std::string("cannot create '__sync': ") + std::strerror(e));
        }
        dfd = ::openat(tfd, "__sync", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dfd < 0) throw Error("'" + dirp.string() + "' is a link or not a folder: refusing to use it for the engine lock");
        sg.fd = dfd;
    }
    std::string leaf = p.filename().string();
    int fd = ::openat(dfd, leaf.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        int e = errno;
        if ((e == EACCES || e == EROFS || e == EPERM) && read_only(dfd))
            throw LockNotPossible(std::string("the lock file cannot be created: ") + std::strerror(e));
        throw Error("cannot open the lock file '" + p.string() + "': " + std::strerror(e));
    }
    impl->fd = fd;
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) throw Error("'" + p.string() + "' is not a regular file");
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            if (holder) *holder = pid_label(read_pid_text(p));
            return nullptr;
        }
        throw Error(std::string("cannot lock the lock file: ") + std::strerror(errno));
    }
    if (::ftruncate(fd, 0) == 0) {
        ssize_t w = ::write(fd, pid.data(), pid.size());
        (void)w;
    }
#endif
    std::unique_ptr<FileLock> fl(new FileLock());
    fl->p_ = std::move(impl);
    fl->path_ = utf8_path;
    return fl;
}

}  // namespace mysync
