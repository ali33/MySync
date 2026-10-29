// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// compress.h - LZ4 block compression with a hard cap on decompressed size.
#include "mysync/util.h"

namespace mysync {

// Raw LZ4 block (no header). Throws Error if n is too large for LZ4 (> ~2 GiB) or on internal failure.
Bytes lz4_compress(const void* data, size_t n);

// Throws Error if the data is corrupt or would expand beyond max_out bytes.
Bytes lz4_decompress(const void* data, size_t n, size_t max_out);

struct MaybeCompressed {
    Bytes data;
    bool compressed = false;  // false => data is a verbatim copy of the input
};
// Compress, but fall back to the raw bytes when compression does not make the data smaller.
MaybeCompressed lz4_compress_if_smaller(const void* data, size_t n);

} // namespace mysync
