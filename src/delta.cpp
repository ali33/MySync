// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/delta.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

#include "mysync/hash.h"

namespace mysync::delta {

namespace fs = std::filesystem;

namespace {

fs::path to_path(const std::string& utf8) { return fs::u8path(utf8); }

void check_block_size(uint32_t bs) {
    if (bs < kMinAcceptedBlock || bs > kMaxAcceptedBlock) throw Error("delta: block size out of range");
}

std::ifstream open_in(const std::string& utf8) {
    std::ifstream in(to_path(utf8), std::ios::binary);
    if (!in) throw Error("delta: cannot open file for reading");
    return in;
}

struct Roll {
    uint32_t a = 0, b = 0;
    void init(const uint8_t* p, size_t n) {
        uint32_t x = 0, y = 0;
        for (size_t i = 0; i < n; i++) {
            x += p[i];
            y += uint32_t(n - i) * p[i];
        }
        a = x & 0xffff;
        b = y & 0xffff;
    }
    uint32_t value() const { return (b << 16) | a; }
    void roll(uint8_t out, uint8_t in, size_t n) {
        a = (a - out + in) & 0xffff;
        b = (b - uint32_t(n) * out + a) & 0xffff;
    }
};

}  // namespace

uint32_t choose_block_size(uint64_t file_size) {
    // ~sqrt(size), rounded to the nearest power of two (geometric midpoint), clamped.
    uint64_t target = 1;
    while (target * target < file_size) target <<= 1;  // smallest power of two with target^2 >= size
    // Step down one power of two when size <= 2*(target/2)^2, i.e. below the geometric midpoint.
    if (target > 1 && file_size <= (target / 2) * (target / 2) * 2) target >>= 1;
    if (target < kMinBlockSize) target = kMinBlockSize;
    if (target > kMaxBlockSize) target = kMaxBlockSize;
    return uint32_t(target);
}

uint32_t weak_checksum(const void* data, size_t n) {
    Roll r;
    r.init(static_cast<const uint8_t*>(data), n);
    return r.value();
}

Signature make_signature(const std::string& utf8_path) {
    std::error_code ec;
    uint64_t sz = fs::file_size(to_path(utf8_path), ec);
    if (ec) throw Error("delta: cannot stat file");
    return make_signature(utf8_path, choose_block_size(sz));
}

Signature make_signature(const std::string& utf8_path, uint32_t block_size) {
    check_block_size(block_size);
    std::ifstream in = open_in(utf8_path);
    Signature sig;
    sig.block_size = block_size;
    Bytes buf(block_size);
    for (;;) {
        in.read(reinterpret_cast<char*>(buf.data()), std::streamsize(block_size));
        size_t n = size_t(in.gcount());
        if (n == 0) break;
        BlockSig bs;
        bs.weak = weak_checksum(buf.data(), n);
        bs.strong = hash_block16(buf.data(), n);
        sig.blocks.push_back(bs);
        sig.file_size += n;
        if (n < block_size) break;
    }
    if (in.bad()) throw Error("delta: read error");
    return sig;
}

void compute_delta(const Signature& sig, const std::string& new_path, const std::function<void(DeltaOp&&)>& sink) {
    const uint32_t bs = sig.block_size;
    check_block_size(bs);
    const uint64_t expect_blocks = (sig.file_size + bs - 1) / bs;
    if (sig.blocks.size() != expect_blocks) throw Error("delta: signature inconsistent with file size");
    const size_t nfull = size_t(sig.file_size / bs);
    const size_t tail_len = size_t(sig.file_size % bs);

    // Lookup structures over the full blocks only; the short tail block is handled separately.
    std::vector<std::pair<uint32_t, uint32_t>> table;
    table.reserve(nfull);
    std::vector<uint64_t> bitmap(1u << 14, 0);  // 2^20 bits
    auto bit_of = [](uint32_t w) { return (w * 0x9E3779B1u) >> 12; };
    for (size_t i = 0; i < nfull; i++) {
        table.emplace_back(sig.blocks[i].weak, uint32_t(i));
        uint32_t bit = bit_of(sig.blocks[i].weak);
        bitmap[bit >> 6] |= uint64_t(1) << (bit & 63);
    }
    std::sort(table.begin(), table.end());

    std::ifstream in = open_in(new_path);
    const size_t cap = size_t(bs) + kMaxLiteralOp + 1 + 512 * 1024;
    Bytes buf(cap);
    size_t ws = 0, ls = 0, end = 0;
    bool eof = false;

    auto fill = [&](size_t need) {
        if (eof || end - ws >= need) return;
        if (ls > 0) {
            std::memmove(buf.data(), buf.data() + ls, end - ls);
            ws -= ls;
            end -= ls;
            ls = 0;
        }
        while (!eof && end - ws < need) {
            in.read(reinterpret_cast<char*>(buf.data() + end), std::streamsize(cap - end));
            size_t n = size_t(in.gcount());
            if (n == 0) {
                if (in.bad()) throw Error("delta: read error");
                eof = true;
                break;
            }
            end += n;
        }
    };
    auto flush = [&](size_t upto) {
        while (ls < upto) {
            size_t n = std::min(upto - ls, kMaxLiteralOp);
            DeltaOp op;
            op.kind = DeltaOp::Literal;
            op.data.assign(buf.begin() + ls, buf.begin() + ls + n);
            ls += n;
            sink(std::move(op));
        }
    };
    auto emit_copy = [&](uint32_t idx) {
        DeltaOp op;
        op.kind = DeltaOp::Copy;
        op.block_idx = idx;
        sink(std::move(op));
    };

    Roll roll;
    bool rolled = false;
    for (;;) {
        fill(size_t(bs) + 1);
        size_t avail = end - ws;
        if (avail == 0) break;
        if (avail >= bs) {
            if (!rolled) {
                roll.init(buf.data() + ws, bs);
                rolled = true;
            }
            bool matched = false;
            uint32_t w = roll.value();
            uint32_t bit = bit_of(w);
            if (nfull && (bitmap[bit >> 6] >> (bit & 63) & 1)) {
                auto it = std::lower_bound(table.begin(), table.end(), std::make_pair(w, uint32_t(0)));
                std::array<uint8_t, 16> strong{};
                bool have_strong = false;
                for (; it != table.end() && it->first == w; ++it) {
                    if (!have_strong) {
                        strong = hash_block16(buf.data() + ws, bs);
                        have_strong = true;
                    }
                    if (sig.blocks[it->second].strong == strong) {
                        flush(ws);
                        emit_copy(it->second);
                        ws += bs;
                        ls = ws;
                        rolled = false;
                        matched = true;
                        break;
                    }
                }
            }
            if (matched) continue;
            if (avail > bs) {
                roll.roll(buf[ws], buf[ws + bs], bs);
            } else {
                rolled = false;
            }
            ws++;
            if (ws - ls >= kMaxLiteralOp) flush(ws);
        } else {
            // Fewer than one block left and EOF: only the old file's short tail block can still match.
            if (tail_len == 0 || avail < tail_len) {
                ws = end;
                break;
            }
            if (avail == tail_len) {
                if (weak_checksum(buf.data() + ws, avail) == sig.blocks[nfull].weak &&
                    hash_block16(buf.data() + ws, avail) == sig.blocks[nfull].strong) {
                    flush(ws);
                    emit_copy(uint32_t(nfull));
                    ws = ls = end;
                }
                break;
            }
            ws++;
            if (ws - ls >= kMaxLiteralOp) flush(ws);
        }
    }
    flush(end);
}

std::vector<DeltaOp> compute_delta(const Signature& sig, const std::string& new_path) {
    std::vector<DeltaOp> ops;
    compute_delta(sig, new_path, [&](DeltaOp&& op) { ops.push_back(std::move(op)); });
    return ops;
}

struct DeltaApplier::Impl {
    std::string path;
    uint32_t bs;
    std::ifstream in;
    bool opened = false;
    uint64_t old_size = 0;
    Bytes buf;
};

DeltaApplier::DeltaApplier(const std::string& old_utf8_path, uint32_t block_size) : p_(new Impl) {
    try {
        check_block_size(block_size);
    } catch (...) {
        delete p_;
        throw;
    }
    p_->path = old_utf8_path;
    p_->bs = block_size;
}

DeltaApplier::~DeltaApplier() { delete p_; }

void DeltaApplier::apply(const DeltaOp& op, const Sink& out) {
    if (op.kind == DeltaOp::Literal) {
        if (!op.data.empty()) out(op.data.data(), op.data.size());
        return;
    }
    if (!p_->opened) {
        p_->in = open_in(p_->path);
        std::error_code ec;
        p_->old_size = fs::file_size(to_path(p_->path), ec);
        if (ec) throw Error("delta: cannot stat old file");
        p_->buf.resize(p_->bs);
        p_->opened = true;
    }
    uint64_t off = uint64_t(op.block_idx) * p_->bs;
    if (off >= p_->old_size) throw Error("delta: copy block outside old file");
    size_t n = size_t(std::min<uint64_t>(p_->bs, p_->old_size - off));
    p_->in.clear();
    p_->in.seekg(std::streamoff(off));
    p_->in.read(reinterpret_cast<char*>(p_->buf.data()), std::streamsize(n));
    if (size_t(p_->in.gcount()) != n) throw Error("delta: short read from old file");
    out(p_->buf.data(), n);
}

void DeltaApplier::apply(const std::vector<DeltaOp>& ops, const Sink& out) {
    for (const auto& op : ops) apply(op, out);
}

void apply_delta(const std::string& old_path, uint32_t block_size, const std::vector<DeltaOp>& ops,
                 const DeltaApplier::Sink& out) {
    DeltaApplier a(old_path, block_size);
    a.apply(ops, out);
}

void apply_delta_to_file(const std::string& old_path, uint32_t block_size, const std::vector<DeltaOp>& ops,
                         const std::string& out_path) {
    std::ofstream o(to_path(out_path), std::ios::binary | std::ios::trunc);
    if (!o) throw Error("delta: cannot open output file");
    apply_delta(old_path, block_size, ops, [&](const void* d, size_t n) {
        o.write(static_cast<const char*>(d), std::streamsize(n));
        if (!o) throw Error("delta: write error");
    });
    o.flush();
    if (!o) throw Error("delta: write error");
}

}  // namespace mysync::delta
