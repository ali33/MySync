// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/nettarget.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <optional>

#include "fileio.h"
#include "mysync/compress.h"
#include "mysync/delta.h"
#include "mysync/hash.h"
#include "mysync/net.h"
#include "mysync/protocol.h"
#include "mysync/secure_channel.h"

namespace mysync {

namespace fs = std::filesystem;
using namespace proto;

namespace {

constexpr size_t kWindow = 64;                 // OFFERs in flight
constexpr size_t kDeltaBatchBytes = 256 * 1024;
constexpr int kIdlePingSec = 10;
constexpr int64_t kMtimeTolNs = 1000;

// The server answered with an application-level refusal; the connection is still good.
struct RemoteError : Error {
    using Error::Error;
};

std::string lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = char(c + 32);
    return s;
}

std::string remote_msg(const FileErr& e) {
    return std::string(err_name(e.code)) + (e.message.empty() ? "" : ": " + e.message);
}

struct Slot {
    size_t idx = 0;
    enum Kind { Pending, Full, Delta } kind = Pending;
    uint32_t block_size = 0;
    std::vector<delta::BlockSig> sigs;
    std::string local_err;
    bool changed = false;
    uint64_t wire = 0;
};

class NetTarget : public ITarget {
public:
    NetTarget(const TargetConfig& t, const ClientConfig& c, const KeyPair& self, std::shared_ptr<RateLimiter> lim)
        : tc_(t), cc_(c), self_(self), lim_(std::move(lim)) {
        for (const auto& e : cc_.compress_skip_ext) skip_ext_.push_back(lower(e));
    }
    ~NetTarget() override {
        try {
            close();
        } catch (...) {
        }
    }

    void open() override {
        close();
        net::init();
        // Server key rotation: the pinned key first, then `server_key_next` (the order is swapped once the second one
        // has worked, so a finished rotation costs no refused handshake per connection). Only keys written in the
        // configuration are ever tried.
        std::vector<PubKey> keys{tc_.server_key};
        if (tc_.has_server_key_next) keys.push_back(tc_.server_key_next);
        if (next_first_ && keys.size() == 2) std::swap(keys[0], keys[1]);
        for (size_t i = 0; i < keys.size(); ++i) {
            net::Socket s = net::Socket::connect(tc_.host, tc_.port, 10000);
            try {
                ch_.emplace(SecureChannel::client(std::move(s), self_, keys[i]));
            } catch (const AuthError&) {
                if (i + 1 == keys.size()) throw;
                // the server does not answer to this key: try the other pinned one (never after a mere connection failure)
                log_warn("server " + tc_.host + ":" + std::to_string(tc_.port) + " refused " +
                         (next_first_ == (i == 0) ? "server_key_next" : "server_key") + ", trying the other pinned key");
                continue;
            }
            bool is_next = tc_.has_server_key_next && keys[i] == tc_.server_key_next;
            if (is_next != next_first_) {
                log_info("server " + tc_.host + ":" + std::to_string(tc_.port) + " accepted " +
                         (is_next ? "server_key_next" : "server_key"));
            }
            next_first_ = is_next;
            break;
        }
        try {
            ch_->socket().set_timeouts(120000, 120000);
            Hello h;
            h.client_name = "mysync";
            h.caps = kCapDelta | (cc_.compress == "lz4" ? kCapLz4 : 0u);
            send(h);
            Message m = recv();
            if (auto* e = std::get_if<FileErr>(&m)) throw Error("server refused: " + remote_msg(*e));
            auto* ok = std::get_if<HelloOk>(&m);
            if (!ok) throw Error("protocol error: HELLO_OK expected");
            caps_ = ok->server_caps & h.caps;
            max_chunk_ = std::clamp<uint32_t>(ok->max_chunk, 4096, kDefaultMaxChunk);
        } catch (...) {
            ch_.reset();
            throw;
        }
        touch();
    }

    void close() override {
        if (ch_) {
            try {
                send(Bye{});
            } catch (...) {
            }
            ch_.reset();
        }
    }

    PutResult put_file(const std::string& rel, const std::string& abs_src, const FileMeta& meta) override {
        PutItem it;
        it.rel = rel;
        it.abs_src = abs_src;
        it.meta = meta;
        return put_batch({it}).front();
    }

    std::vector<PutResult> put_batch(const std::vector<PutItem>& items) override {
        std::vector<PutResult> res(items.size());
        if (items.empty()) return res;
        op([&] {
            for (size_t i = 0; i < items.size();) {
                size_t j = std::min(items.size(), i + kWindow);
                window(items, i, j, res);
                i = j;
            }
        });
        return res;
    }

    void remove_path(const std::string& rel, bool /*is_dir*/) override {
        op([&] {
            send(Delete{remote_rel(rel)});
            expect_ok();
        });
    }
    void rename_path(const std::string& from, const std::string& to) override {
        op([&] {
            send(Rename{remote_rel(from), remote_rel(to)});
            expect_ok();
        });
    }
    void make_dir(const std::string& rel) override {
        op([&] {
            send(Mkdir{remote_rel(rel)});
            expect_ok();
        });
    }

    std::map<std::string, FileMeta> list_remote() override {
        std::map<std::string, FileMeta> out;
        op([&] {
            out.clear();
            std::string pre = tc_.remote_prefix;
            while (!pre.empty() && pre.back() == '/') pre.pop_back();
            send(ListReq{pre});
            uint64_t n = 0;
            for (;;) {
                Message m = recv();
                if (auto* e = std::get_if<ListEntry>(&m)) {
                    n++;
                    if (e->path.empty() || e->path[0] == '/' || e->path.find("..") != std::string::npos) continue;
                    FileMeta fm;
                    fm.rel = e->path;
                    fm.size = e->size;
                    fm.mtime_ns = e->mtime_ns;
                    fm.hash = e->hash;
                    fm.is_dir = e->is_dir;
                    out[fm.rel] = fm;
                } else if (auto* end = std::get_if<ListEnd>(&m)) {
                    if (end->count != n) throw Error("protocol error: list count mismatch");
                    break;
                } else if (auto* fe = std::get_if<FileErr>(&m)) {
                    throw RemoteError("server: " + remote_msg(*fe));
                } else {
                    throw Error("protocol error in listing");
                }
            }
        });
        return out;
    }

    std::string description() const override { return "net://" + tc_.host + ":" + std::to_string(tc_.port); }

private:
    TargetConfig tc_;
    ClientConfig cc_;
    KeyPair self_;
    std::shared_ptr<RateLimiter> lim_;
    std::vector<std::string> skip_ext_;
    std::optional<SecureChannel> ch_;
    bool next_first_ = false;  // server_key_next answered last time: try it first
    uint32_t caps_ = 0;
    uint32_t max_chunk_ = kDefaultMaxChunk;
    std::chrono::steady_clock::time_point last_use_{};

    void touch() { last_use_ = std::chrono::steady_clock::now(); }

    void send(const Message& m) { ch_->send_msg(encode(m)); }
    Message recv() { return decode(ch_->recv_msg()); }
    void expect_ok() {
        Message m = recv();
        if (std::get_if<FileOk>(&m)) return;
        if (auto* e = std::get_if<FileErr>(&m)) throw RemoteError("server: " + remote_msg(*e));
        throw Error("protocol error: FILE_OK expected");
    }

    // Reconnects when needed, runs f, and drops the connection if it died (so the next open() starts clean).
    template <class F>
    void op(F f) {
        if (!ch_) {
            open();
        } else if (std::chrono::steady_clock::now() - last_use_ > std::chrono::seconds(kIdlePingSec)) {
            try {
                uint64_t tok = uint64_t(now_unix_ns());
                send(Ping{tok});
                Message m = recv();
                auto* p = std::get_if<Pong>(&m);
                if (!p || p->token != tok) throw Error("bad pong");
            } catch (const Error&) {
                ch_.reset();
                open();
            }
        }
        try {
            f();
        } catch (const RemoteError&) {
            touch();
            throw;
        } catch (...) {
            ch_.reset();
            throw;
        }
        touch();
    }

    std::string remote_rel(const std::string& rel) const {
        std::string p = tc_.remote_prefix;
        while (!p.empty() && p.back() == '/') p.pop_back();
        while (!p.empty() && p.front() == '/') p.erase(p.begin());
        return p.empty() ? rel : p + "/" + rel;
    }

    bool lz4_for(const std::string& rel) const {
        if (!(caps_ & kCapLz4) || cc_.compress != "lz4") return false;
        std::string name = lower(rel);
        auto slash = name.rfind('/');
        if (slash != std::string::npos) name = name.substr(slash + 1);
        auto dot = name.rfind('.');
        if (dot == std::string::npos) return true;
        std::string ext = name.substr(dot);
        return std::find(skip_ext_.begin(), skip_ext_.end(), ext) == skip_ext_.end();
    }

    void window(const std::vector<PutItem>& items, size_t b, size_t e, std::vector<PutResult>& res) {
        std::vector<Slot> slots;
        // 1. validate the sources and send the OFFERs without waiting
        for (size_t k = b; k < e; k++) {
            const PutItem& it = items[k];
            PutResult& r = res[k];
            r = PutResult{};
            fio::StatInfo st = fio::stat_path(fs::u8path(it.abs_src));
            if (!st.exists || !st.is_regular) {
                r.error = "source file vanished or is not a regular file";
                continue;
            }
            if (st.size != it.meta.size || std::llabs(st.mtime_ns - it.meta.mtime_ns) > kMtimeTolNs) {
                r.error = "changed during transfer";
                continue;
            }
            Bytes msg;
            try {
                Offer o;
                o.path = remote_rel(it.rel);
                o.size = it.meta.size;
                o.mtime_ns = it.meta.mtime_ns;
                o.hash = it.meta.hash;
                msg = encode(o);
            } catch (const Error& ex) {
                r.error = std::string("cannot encode path: ") + ex.what();
                continue;
            }
            ch_->send_msg(msg);
            Slot s;
            s.idx = k;
            slots.push_back(std::move(s));
        }
        // 2. read the answers, in order
        std::vector<Slot*> need;
        for (Slot& s : slots) {
            PutResult& r = res[s.idx];
            Message m = recv();
            if (std::get_if<Skip>(&m)) {
                r.status = PutResult::Skipped;
            } else if (std::get_if<NeedFull>(&m)) {
                s.kind = Slot::Full;
                need.push_back(&s);
            } else if (auto* nd = std::get_if<NeedDelta>(&m)) {
                s.kind = Slot::Delta;
                s.block_size = nd->block_size;
                s.sigs = std::move(nd->sigs);
                need.push_back(&s);
            } else if (auto* fe = std::get_if<FileErr>(&m)) {
                r.error = "server: " + remote_msg(*fe);
            } else {
                throw Error("protocol error: unexpected reply to OFFER");
            }
        }
        // 3. stream the bodies, in the same order
        for (Slot* s : need) {
            const PutItem& it = items[s->idx];
            if (s->kind == Slot::Full) send_full(it, *s);
            else send_delta(it, *s);
        }
        // 4. collect the verdicts
        for (Slot* s : need) {
            PutResult& r = res[s->idx];
            Message m = recv();
            if (std::get_if<FileOk>(&m)) {
                r.status = PutResult::Sent;
                r.bytes_on_wire = s->wire;
                r.used_delta = s->kind == Slot::Delta;
                if (!s->local_err.empty()) {  // content verified but the source moved on: let the engine redo it
                    r.status = PutResult::Failed;
                    r.error = s->local_err;
                    r.bytes_on_wire = s->wire;
                }
            } else if (auto* fe = std::get_if<FileErr>(&m)) {
                r.status = PutResult::Failed;
                r.bytes_on_wire = s->wire;
                r.error = !s->local_err.empty() ? s->local_err : "server: " + remote_msg(*fe);
            } else {
                throw Error("protocol error: FILE_OK expected");
            }
        }
    }

    // True when the source differs from what the caller hashed.
    static bool source_changed(const PutItem& it) {
        fio::StatInfo st = fio::stat_path(fs::u8path(it.abs_src));
        return !st.exists || st.size != it.meta.size || std::llabs(st.mtime_ns - it.meta.mtime_ns) > kMtimeTolNs;
    }

    void send_full(const PutItem& it, Slot& s) {
        std::ifstream in(fs::u8path(it.abs_src), std::ios::binary);
        Hasher hasher;
        uint64_t left = it.meta.size;
        uint64_t seq = 0;
        bool try_lz4 = lz4_for(it.rel);
        int plain_streak = 0;
        Bytes buf(max_chunk_);
        if (!in) s.local_err = "cannot open source file";
        while (left > 0 && s.local_err.empty()) {
            size_t want = size_t(std::min<uint64_t>(left, buf.size()));
            in.read(reinterpret_cast<char*>(buf.data()), std::streamsize(want));
            size_t n = size_t(in.gcount());
            if (n == 0) {
                s.local_err = in.bad() ? "read error on source file" : "changed during transfer";
                break;
            }
            hasher.update(buf.data(), n);
            left -= n;
            Data d;
            d.seq = seq++;
            if (try_lz4 && n >= 64) {
                MaybeCompressed mc = lz4_compress_if_smaller(buf.data(), n);
                if (mc.compressed) {
                    d.flags = kDataLz4;
                    d.bytes = std::move(mc.data);
                    plain_streak = 0;
                } else if (++plain_streak >= 3) {
                    try_lz4 = false;  // incompressible: stop wasting CPU on this file
                }
            }
            if (d.bytes.empty()) d.bytes.assign(buf.begin(), buf.begin() + std::ptrdiff_t(n));
            if (lim_) lim_->acquire(d.bytes.size());
            s.wire += d.bytes.size();
            send(Message(std::move(d)));
        }
        EndFile ef;  // all-zero hash (never valid) when we could not deliver the real content
        if (s.local_err.empty()) {
            ef.hash = hasher.finish();
            bool grew = in.peek() != std::ifstream::traits_type::eof();
            if (grew || ef.hash != it.meta.hash || source_changed(it)) s.local_err = "changed during transfer";
        } else if (s.local_err == "changed during transfer") {
            s.changed = true;
        }
        send(ef);
    }

    void send_delta(const PutItem& it, Slot& s) {
        delta::Signature sig;
        sig.block_size = s.block_size;
        // The wire carries only the block count, not the old size: assume the tail block is full (a short tail
        // block is then simply never matched, which costs a literal, never correctness).
        sig.file_size = uint64_t(s.sigs.size()) * s.block_size;
        sig.blocks = std::move(s.sigs);
        std::vector<delta::DeltaOp> batch;
        size_t batch_bytes = 0;
        bool net_failed = false;
        auto flush = [&] {
            if (batch.empty()) return;
            DeltaOps m;
            m.ops = std::move(batch);
            batch.clear();
            batch_bytes = 0;
            Bytes enc = encode(Message(std::move(m)));
            if (lim_) lim_->acquire(enc.size());
            s.wire += enc.size();
            try {
                ch_->send_msg(enc);
            } catch (...) {
                net_failed = true;
                throw;
            }
        };
        try {
            delta::compute_delta(sig, it.abs_src, [&](delta::DeltaOp&& op) {
                size_t sz = (op.kind == delta::DeltaOp::Literal ? op.data.size() : 0) + 16;
                if (batch_bytes + sz > kDeltaBatchBytes) flush();
                batch.push_back(std::move(op));
                batch_bytes += sz;
            });
            flush();
        } catch (const Error& ex) {
            if (net_failed) throw;
            s.local_err = std::string("cannot read source: ") + ex.what();
        }
        EndFile ef;
        if (s.local_err.empty()) {
            ef.hash = it.meta.hash;
            if (source_changed(it)) s.local_err = "changed during transfer";
        }
        send(ef);
    }
};

}  // namespace

std::unique_ptr<ITarget> make_net_target(const TargetConfig& target, const ClientConfig& client, const KeyPair& self,
                                         std::shared_ptr<RateLimiter> limiter) {
    return std::make_unique<NetTarget>(target, client, self, std::move(limiter));
}

}  // namespace mysync
