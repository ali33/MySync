// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/hash.h"

#include <cerrno>
#include <filesystem>

#include "blake3.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace mysync {

struct Hasher::Impl {
    blake3_hasher h;
};

Hasher::Hasher() : p_(new Impl) { blake3_hasher_init(&p_->h); }
Hasher::~Hasher() { delete p_; }

void Hasher::update(const void* data, size_t n) { blake3_hasher_update(&p_->h, data, n); }

Hash256 Hasher::finish() {
    Hash256 out;
    blake3_hasher_finalize(&p_->h, out.data(), out.size());
    return out;
}

Hash256 hash_bytes(const void* data, size_t n) {
    Hasher h;
    h.update(data, n);
    return h.finish();
}

std::array<uint8_t, 16> hash_block16(const void* data, size_t n) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, n);
    std::array<uint8_t, 16> out;
    blake3_hasher_finalize(&h, out.data(), out.size());
    return out;
}

Hash256 hash_file(const std::string& utf8_path, uint64_t* out_size) {
    constexpr size_t kBuf = 1u << 20;
    std::filesystem::path p = std::filesystem::u8path(utf8_path);
    std::vector<uint8_t> buf(kBuf);
    Hasher h;
    uint64_t total = 0;
#ifdef _WIN32
    // The last component is opened WITHOUT following a symbolic link: a file that was swapped for a link after the scan is
    // refused. Other reparse points (OneDrive placeholders ...) are ordinary files and are opened normally.
    HANDLE f = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (f == INVALID_HANDLE_VALUE) throw Error("cannot open file for hashing: " + utf8_path);
    {
        FILE_ATTRIBUTE_TAG_INFO ti{};
        if (GetFileInformationByHandleEx(f, FileAttributeTagInfo, &ti, sizeof ti) && (ti.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            CloseHandle(f);
            if (ti.ReparseTag == IO_REPARSE_TAG_SYMLINK || ti.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
                throw Error("refusing to read through a link: " + utf8_path);
            f = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (f == INVALID_HANDLE_VALUE) throw Error("cannot open file for hashing: " + utf8_path);
        }
    }
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(f, buf.data(), static_cast<DWORD>(kBuf), &got, nullptr)) {
            CloseHandle(f);
            throw Error("read error while hashing: " + utf8_path);
        }
        if (got == 0) break;
        h.update(buf.data(), got);
        total += got;
    }
    CloseHandle(f);
#else
    int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);   // never through a link on the last component
    if (fd < 0) throw Error((errno == ELOOP ? "refusing to read through a link: " : "cannot open file for hashing: ") + utf8_path);
    for (;;) {
        ssize_t got = ::read(fd, buf.data(), kBuf);
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw Error("read error while hashing: " + utf8_path);
        }
        if (got == 0) break;
        h.update(buf.data(), static_cast<size_t>(got));
        total += static_cast<uint64_t>(got);
    }
    ::close(fd);
#endif
    if (out_size) *out_size = total;
    return h.finish();
}

}  // namespace mysync
