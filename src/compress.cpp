// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/compress.h"

#include <climits>
#include <cstring>

#include "lz4.h"

namespace mysync {

Bytes lz4_compress(const void* data, size_t n) {
    if (n > size_t(LZ4_MAX_INPUT_SIZE)) throw Error("lz4: input too large");
    if (n == 0) return {};
    int bound = LZ4_compressBound(int(n));
    if (bound <= 0) throw Error("lz4: input too large");
    Bytes out(static_cast<size_t>(bound) + 0);
    int r = LZ4_compress_default(static_cast<const char*>(data), reinterpret_cast<char*>(out.data()), int(n), bound);
    if (r <= 0) throw Error("lz4: compression failed");
    out.resize(size_t(r));
    return out;
}

Bytes lz4_decompress(const void* data, size_t n, size_t max_out) {
    if (n > size_t(INT_MAX) || max_out > size_t(INT_MAX)) throw Error("lz4: size out of range");
    if (n == 0) return {};
    Bytes out(max_out);
    // LZ4_decompress_safe never writes beyond dstCapacity and fails if the output would not fit.
    int r = LZ4_decompress_safe(static_cast<const char*>(data), reinterpret_cast<char*>(out.data()), int(n),
                                int(max_out));
    if (r < 0) throw Error("lz4: corrupt data or output exceeds limit");
    out.resize(size_t(r));
    return out;
}

MaybeCompressed lz4_compress_if_smaller(const void* data, size_t n) {
    MaybeCompressed r;
    if (n >= 16 && n <= size_t(LZ4_MAX_INPUT_SIZE)) {
        Bytes c = lz4_compress(data, n);
        if (c.size() < n) {
            r.data = std::move(c);
            r.compressed = true;
            return r;
        }
    }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    r.data.assign(p, p + n);
    return r;
}

}  // namespace mysync
