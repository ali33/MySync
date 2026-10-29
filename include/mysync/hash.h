// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// hash.h - CONTRACT header: BLAKE3 content hashing.
#include <functional>
#include <string>

#include "mysync/util.h"

namespace mysync {

class Hasher {
public:
    Hasher();
    ~Hasher();
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;
    void update(const void* data, size_t n);
    Hash256 finish();
private:
    struct Impl;
    Impl* p_;
};

Hash256 hash_bytes(const void* data, size_t n);
// Streams the file with a large buffer (>= 1 MiB). Throws Error if unreadable. out_size receives bytes read.
Hash256 hash_file(const std::string& utf8_path, uint64_t* out_size = nullptr);
// Keyed 16-byte truncated BLAKE3 used for delta block signatures.
std::array<uint8_t, 16> hash_block16(const void* data, size_t n);

} // namespace mysync
