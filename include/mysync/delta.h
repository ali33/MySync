// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// delta.h - rsync-style block delta: signature of the OLD file, delta of the NEW file against it.
// Weak checksum = rsync rolling (a,b 16-bit sums); strong = hash_block16. All file access is streamed.
#include <array>
#include <functional>
#include <string>
#include <vector>

#include "mysync/util.h"

namespace mysync::delta {

constexpr uint32_t kMinBlockSize = 2048;       // choose_block_size() range
constexpr uint32_t kMaxBlockSize = 64 * 1024;
constexpr uint32_t kMinAcceptedBlock = 64;      // accepted from the wire / explicit callers
constexpr uint32_t kMaxAcceptedBlock = 1024 * 1024;
constexpr size_t kMaxLiteralOp = 64 * 1024;     // compute_delta never emits a literal larger than this

struct BlockSig {
    uint32_t weak = 0;
    std::array<uint8_t, 16> strong{};
};

// Signature of the old file. Blocks are consecutive block_size chunks; the last may be shorter.
struct Signature {
    uint32_t block_size = 0;
    uint64_t file_size = 0;
    std::vector<BlockSig> blocks;
};

struct DeltaOp {
    enum Kind : uint8_t { Copy = 0, Literal = 1 };
    Kind kind = Literal;
    uint32_t block_idx = 0;  // Copy: index into the old file's blocks
    Bytes data;              // Literal: raw bytes
};

// 2 KiB .. 64 KiB, about sqrt(size) rounded to a power of two.
uint32_t choose_block_size(uint64_t file_size);

uint32_t weak_checksum(const void* data, size_t n);

Signature make_signature(const std::string& utf8_path);                       // block size from choose_block_size
Signature make_signature(const std::string& utf8_path, uint32_t block_size);  // throws Error if out of range

// Streams the new file; calls sink for every op in order. Memory use is bounded (~1.3 MiB + block_size),
// independent of file size. Literal ops are at most kMaxLiteralOp bytes. Adjacent literals may be split.
void compute_delta(const Signature& sig, const std::string& new_path, const std::function<void(DeltaOp&&)>& sink);
std::vector<DeltaOp> compute_delta(const Signature& sig, const std::string& new_path);

// Rebuilds the new file from the old one. Can be fed op batches incrementally (server side).
// Throws Error on a Copy index outside the old file, or if the old file cannot be read.
class DeltaApplier {
public:
    using Sink = std::function<void(const void*, size_t)>;
    DeltaApplier(const std::string& old_utf8_path, uint32_t block_size);
    ~DeltaApplier();
    DeltaApplier(const DeltaApplier&) = delete;
    DeltaApplier& operator=(const DeltaApplier&) = delete;
    void apply(const DeltaOp& op, const Sink& out);
    void apply(const std::vector<DeltaOp>& ops, const Sink& out);
private:
    struct Impl;
    Impl* p_;
};

// One-shot helper: writes the reconstructed file through `out`.
void apply_delta(const std::string& old_path, uint32_t block_size, const std::vector<DeltaOp>& ops,
                 const DeltaApplier::Sink& out);
// One-shot helper: reconstructs into a file (created/truncated).
void apply_delta_to_file(const std::string& old_path, uint32_t block_size, const std::vector<DeltaOp>& ops,
                         const std::string& out_path);

} // namespace mysync::delta
