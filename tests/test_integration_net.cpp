// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// End-to-end tests: real Server on a loopback port + NetTarget over a real SecureChannel.
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>

#include "../src/fileio.h"
#include "mysync/hash.h"
#include "mysync/net.h"
#include "mysync/nettarget.h"
#include "mysync/ratelimit.h"
#include "mysync/secure_channel.h"
#include "mysync/server.h"
#include "testing.h"

using namespace mysync;
namespace fs = std::filesystem;

namespace {

using Clock = std::chrono::steady_clock;
double secs_since(Clock::time_point t) { return std::chrono::duration<double>(Clock::now() - t).count(); }


fs::path unique_tmp() {
    uint8_t r[6];
    random_bytes(r, sizeof r);
    return fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
}

void write_file(const fs::path& p, const void* d, size_t n) {
    fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o.write(static_cast<const char*>(d), std::streamsize(n));
}
void write_text(const fs::path& p, const std::string& s) { write_file(p, s.data(), s.size()); }

Bytes pseudo_random(size_t n, uint64_t seed) {
    Bytes b(n);
    uint64_t x = seed * 0x9E3779B97F4A7C15ull + 1;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b[i] = uint8_t(x >> 24);
    }
    return b;
}

Hash256 hash_of(const fs::path& p) { return hash_file(p.u8string()); }

FileMeta meta_of(const fs::path& abs, const std::string& rel) {
    FileMeta m;
    m.rel = rel;
    fio::StatInfo st = fio::stat_path(abs);
    m.size = st.size;
    m.mtime_ns = st.mtime_ns;
    m.hash = hash_of(abs);
    return m;
}

bool any_tmp_left(const fs::path& root) {
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec))
        if (it->path().filename().u8string().rfind(".mysync-tmp-", 0) == 0) return true;
    return false;
}

struct Env {
    fs::path tmp, root, src;
    KeyPair server_kp = generate_keypair();
    KeyPair rw = generate_keypair();
    KeyPair ro = generate_keypair();
    KeyPair sub = generate_keypair();
    KeyPair stranger = generate_keypair();
    std::unique_ptr<Server> srv;
    std::atomic<bool> stop{false};
    std::thread th;
    double stop_seconds = 0;

    explicit Env(ServerConfig cfg = ServerConfig(), bool pre_orphans = false) {
        tmp = unique_tmp();
        root = tmp / "root";
        src = tmp / "src";
        fs::create_directories(root);
        fs::create_directories(src);
        if (pre_orphans) {
            write_text(root / "old" / ".mysync-tmp-aaaa", "stale");
            fio::set_mtime(root / "old" / ".mysync-tmp-aaaa", now_unix_ns() - 2 * 3600 * 1000000000LL);
            write_text(root / "old" / ".mysync-tmp-bbbb", "fresh");
        }
        cfg.bind = "127.0.0.1";
        cfg.port = 0;
        cfg.root = root.u8string();
        auto add = [&](const char* name, const KeyPair& k, bool ro_, const char* prefix) {
            ClientAcl a;
            a.name = name;
            a.public_key = k.pub;
            a.read_only = ro_;
            a.prefix = prefix;
            cfg.clients.push_back(a);
        };
        add("rw", rw, false, "");
        add("ro", ro, true, "");
        add("sub", sub, false, "sub/dir");
        srv = std::make_unique<Server>(cfg, server_kp);
        th = std::thread([this] { srv->run(stop); });
    }
    ~Env() {
        shutdown();
        std::error_code ec;
        fs::remove_all(tmp, ec);
    }
    void shutdown() {
        if (!th.joinable()) return;
        auto t = Clock::now();
        stop = true;
        th.join();
        stop_seconds = secs_since(t);
    }

    std::unique_ptr<ITarget> target(const KeyPair& kp, const PubKey* pinned = nullptr, ClientConfig cc = ClientConfig()) {
        TargetConfig tc;
        tc.host = "127.0.0.1";
        tc.port = srv->port();
        tc.server_key = pinned ? *pinned : server_kp.pub;
        return make_net_target(tc, cc, kp, nullptr);
    }
    // Writes `content` under src/ and returns its item.
    PutItem item(const std::string& rel, const Bytes& content) {
        fs::path p = src / fs::u8path(rel);
        write_file(p, content.data(), content.size());
        PutItem it;
        it.rel = rel;
        it.abs_src = p.u8string();
        it.meta = meta_of(p, rel);
        return it;
    }
    PutItem item_text(const std::string& rel, const std::string& s) {
        return item(rel, Bytes(s.begin(), s.end()));
    }
};

}  // namespace

TEST(net_small_empty_and_mtime) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    PutItem a = e.item_text("dir/hello.txt", "hello world\n");
    PutResult r = t->put_file(a.rel, a.abs_src, a.meta);
    CHECK(r.status == PutResult::Sent);
    CHECK(r.bytes_on_wire > 0);
    CHECK(hash_of(e.root / "dir" / "hello.txt") == a.meta.hash);
    fio::StatInfo st = fio::stat_path(e.root / "dir" / "hello.txt");
    CHECK(std::llabs(st.mtime_ns - a.meta.mtime_ns) <= 1000);

    PutItem z = e.item("empty.bin", Bytes());
    PutResult rz = t->put_file(z.rel, z.abs_src, z.meta);
    CHECK(rz.status == PutResult::Sent);
    CHECK(fs::exists(e.root / "empty.bin"));
    CHECK(fs::file_size(e.root / "empty.bin") == 0);
    PutResult rz2 = t->put_file(z.rel, z.abs_src, z.meta);
    CHECK(rz2.status == PutResult::Skipped);
    CHECK(!any_tmp_left(e.root));
    t->close();
}

TEST(net_large_skip_and_delta) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    Bytes big = pseudo_random(20u << 20, 7);
    PutItem a = e.item("big/data.bin", big);

    auto t0 = Clock::now();
    PutResult r = t->put_file(a.rel, a.abs_src, a.meta);
    double dt = secs_since(t0);
    CHECK(r.status == PutResult::Sent);
    CHECK(!r.used_delta);
    CHECK(hash_of(e.root / "big" / "data.bin") == a.meta.hash);
    std::cout << "    [perf] 20 MiB random file, loopback, full transfer: " << dt << " s = " << (20.0 / dt)
              << " MiB/s (wire " << r.bytes_on_wire << " B)\n";

    PutResult r2 = t->put_file(a.rel, a.abs_src, a.meta);
    CHECK(r2.status == PutResult::Skipped);
    CHECK(r2.bytes_on_wire == 0);

    big[10u << 20] ^= 0x5a;
    PutItem b = e.item("big/data.bin", big);
    t0 = Clock::now();
    PutResult r3 = t->put_file(b.rel, b.abs_src, b.meta);
    double dt3 = secs_since(t0);
    CHECK(r3.status == PutResult::Sent);
    CHECK(r3.used_delta);
    CHECK(r3.bytes_on_wire < big.size() / 20);
    CHECK(hash_of(e.root / "big" / "data.bin") == b.meta.hash);
    std::cout << "    [perf] 1-byte edit of 20 MiB: delta " << dt3 << " s, wire " << r3.bytes_on_wire << " B\n";
    CHECK(!any_tmp_left(e.root));
}

TEST(net_compressible_file_shrinks_on_wire) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    std::string text;
    for (int i = 0; i < 40000; i++) text += "line " + std::to_string(i % 100) + " of repetitive text\n";
    PutItem a = e.item_text("log.txt", text);
    PutResult r = t->put_file(a.rel, a.abs_src, a.meta);
    CHECK(r.status == PutResult::Sent);
    CHECK(r.bytes_on_wire < text.size() / 3);
    CHECK(hash_of(e.root / "log.txt") == a.meta.hash);
    // an already-compressed extension is sent verbatim
    PutItem z = e.item_text("a.zip", text);
    PutResult rz = t->put_file(z.rel, z.abs_src, z.meta);
    CHECK(rz.status == PutResult::Sent);
    CHECK(rz.bytes_on_wire == text.size());
}

TEST(net_delete_goes_to_trash_rename_and_mkdir) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    PutItem a = e.item_text("d/x.txt", "to be deleted");
    CHECK(t->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);
    t->remove_path("d/x.txt", false);
    CHECK(!fs::exists(e.root / "d" / "x.txt"));
    bool found = false;
    for (auto& ent : fs::directory_iterator(e.root / "__sync" / "__trash")) {
        if (fs::exists(ent.path() / "d" / "x.txt")) found = true;
    }
    CHECK(found);
    t->remove_path("d/x.txt", false);  // idempotent

    PutItem b = e.item_text("old.txt", "rename me");
    CHECK(t->put_file(b.rel, b.abs_src, b.meta).status == PutResult::Sent);
    t->rename_path("old.txt", "moved/new.txt");
    CHECK(!fs::exists(e.root / "old.txt"));
    CHECK(hash_of(e.root / "moved" / "new.txt") == b.meta.hash);

    t->make_dir("emptydir/inner");
    CHECK(fs::is_directory(e.root / "emptydir" / "inner"));
    t->remove_path("emptydir", true);
    CHECK(!fs::exists(e.root / "emptydir"));
    CHECK(fs::exists(e.root / "__sync" / "__trash"));
}

TEST(net_delete_without_trash) {
    ServerConfig cfg;
    cfg.trash = false;
    Env e(cfg);
    auto t = e.target(e.rw);
    t->open();
    PutItem a = e.item_text("gone.txt", "bye");
    CHECK(t->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);
    t->remove_path("gone.txt", false);
    CHECK(!fs::exists(e.root / "gone.txt"));
    CHECK(!fs::exists(e.root / "__sync" / "__trash"));
}

TEST(net_unknown_client_and_wrong_pinned_key_rejected) {
    Env e;
    auto bad = e.target(e.stranger);
    CHECK_THROWS(bad->open());
    PubKey wrong = generate_keypair().pub;
    auto pinned = e.target(e.rw, &wrong);
    CHECK_THROWS(pinned->open());
    // the server keeps serving legitimate clients
    auto ok = e.target(e.rw);
    ok->open();
    CHECK(ok->list_remote().empty());
}

TEST(net_read_only_client) {
    Env e;
    auto rw = e.target(e.rw);
    rw->open();
    PutItem a = e.item_text("shared.txt", "content");
    CHECK(rw->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);

    auto ro = e.target(e.ro);
    ro->open();
    auto list = ro->list_remote();
    CHECK(list.count("shared.txt") == 1);
    CHECK(list["shared.txt"].hash == a.meta.hash);
    PutItem b = e.item_text("new.txt", "nope");
    PutResult r = ro->put_file(b.rel, b.abs_src, b.meta);
    CHECK(r.status == PutResult::Failed);
    CHECK(!fs::exists(e.root / "new.txt"));
    CHECK_THROWS(ro->remove_path("shared.txt", false));
    CHECK_THROWS(ro->rename_path("shared.txt", "x.txt"));
    CHECK_THROWS(ro->make_dir("newdir"));
    CHECK(fs::exists(e.root / "shared.txt"));
    // the connection survived the refusals
    CHECK(ro->list_remote().count("shared.txt") == 1);
}

TEST(net_malicious_paths_rejected) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    PutItem base = e.item_text("payload.txt", "evil");
    const char* bad[] = {"../x",        "a/../../x", "/abs.txt", "..\\x",         "C:\\x.txt", "a/./../../y",
                         "__sync/p.txt", "__SYNC/p.txt", "d/.mysync-tmp-1", "con.txt", "x/\x01y"};
    for (const char* rel : bad) {
        PutResult r = t->put_file(rel, base.abs_src, base.meta);
        CHECK(r.status == PutResult::Failed);
    }
    // same through the batch path, mixed with a good file
    std::vector<PutItem> items;
    for (const char* rel : bad) {
        PutItem it = base;
        it.rel = rel;
        items.push_back(it);
    }
    PutItem good = base;
    good.rel = "ok/payload.txt";
    items.push_back(good);
    auto rs = t->put_batch(items);
    for (size_t i = 0; i + 1 < rs.size(); i++) CHECK(rs[i].status == PutResult::Failed);
    CHECK(rs.back().status == PutResult::Sent);

    CHECK_THROWS(t->remove_path("../root", true));
    CHECK_THROWS(t->rename_path("ok/payload.txt", "../stolen.txt"));
    CHECK_THROWS(t->make_dir("../newdir"));

    // nothing was created outside the root, nor in the internal directories
    CHECK(!fs::exists(e.tmp / "x"));
    CHECK(!fs::exists(e.tmp / "y"));
    CHECK(!fs::exists(e.tmp / "stolen.txt"));
    CHECK(!fs::exists(e.tmp / "newdir"));
    CHECK(!fs::exists(e.tmp / "abs.txt"));
    CHECK(!fs::exists(e.root / "x"));
    CHECK(!fs::exists(e.root / "__sync" / "p.txt"));
    CHECK(!fs::exists(e.root / "con.txt"));
    CHECK(fs::exists(e.root / "ok" / "payload.txt"));
    CHECK(!any_tmp_left(e.root));
}

TEST(net_hash_mismatch_and_changed_source_leave_nothing) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    // The caller hashed different content than what is on disk: server must refuse, no file, no temp.
    PutItem a = e.item_text("m.txt", "actual content");
    a.meta.hash[0] ^= 1;
    PutResult r = t->put_file(a.rel, a.abs_src, a.meta);
    CHECK(r.status == PutResult::Failed);
    CHECK(r.error.find("changed during transfer") != std::string::npos);
    CHECK(!fs::exists(e.root / "m.txt"));
    // size differs from the metadata
    PutItem b = e.item_text("n.txt", "12345");
    b.meta.size = 3;
    PutResult r2 = t->put_file(b.rel, b.abs_src, b.meta);
    CHECK(r2.status == PutResult::Failed);
    CHECK(r2.error.find("changed during transfer") != std::string::npos);
    // source vanished
    PutItem c = e.item_text("v.txt", "x");
    fs::remove(c.abs_src);
    CHECK(t->put_file(c.rel, c.abs_src, c.meta).status == PutResult::Failed);
    CHECK(!any_tmp_left(e.root));
    // the connection is still in sync after the failures
    PutItem ok = e.item_text("fine.txt", "fine");
    CHECK(t->put_file(ok.rel, ok.abs_src, ok.meta).status == PutResult::Sent);
}

TEST(net_hash_mismatch_big_file_with_failed_delta_leaves_old_file) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    Bytes v1 = pseudo_random(3u << 20, 1);
    PutItem a = e.item("w.bin", v1);
    CHECK(t->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);
    Bytes v2 = v1;
    v2[1000] ^= 1;
    PutItem b = e.item("w.bin", v2);
    b.meta.hash[5] ^= 0x10;  // lie about the content hash
    PutResult r = t->put_file(b.rel, b.abs_src, b.meta);
    CHECK(r.status == PutResult::Failed);
    CHECK(hash_of(e.root / "w.bin") == a.meta.hash);  // old version intact
    CHECK(!any_tmp_left(e.root));
}

TEST(net_batch_500_small_files) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    std::vector<PutItem> items;
    for (int i = 0; i < 500; i++) {
        std::string body;
        for (int k = 0; k < 20 + i % 40; k++) body += "file " + std::to_string(i) + " line " + std::to_string(k) + "\n";
        items.push_back(e.item_text("batch/d" + std::to_string(i % 10) + "/f" + std::to_string(i) + ".txt", body));
    }
    auto t0 = Clock::now();
    auto rs = t->put_batch(items);
    double dt = secs_since(t0);
    CHECK(rs.size() == items.size());
    for (size_t i = 0; i < rs.size(); i++) {
        CHECK(rs[i].status == PutResult::Sent);
        CHECK(hash_of(e.root / fs::u8path(items[i].rel)) == items[i].meta.hash);
    }
    std::cout << "    [perf] put_batch 500 small files: " << dt << " s (" << (500.0 / dt) << " files/s)\n";
    CHECK(!any_tmp_left(e.root));

    t0 = Clock::now();
    auto rs2 = t->put_batch(items);
    double dt2 = secs_since(t0);
    for (auto& r : rs2) {
        CHECK(r.status == PutResult::Skipped);
        CHECK(r.bytes_on_wire == 0);
    }
    std::cout << "    [perf] put_batch 500 identical files (all SKIP): " << dt2 << " s\n";

    auto listing = t->list_remote();
    size_t files = 0;
    for (auto& kv : listing)
        if (!kv.second.is_dir) files++;
    CHECK(files == 500);
    CHECK(listing.count("batch/d3/f3.txt") == 1);
    CHECK(listing["batch/d3/f3.txt"].hash == items[3].meta.hash);
    for (auto& kv : listing) CHECK(kv.first.rfind("__sync", 0) != 0);
}

TEST(net_prefix_client_is_confined) {
    Env e;
    auto t = e.target(e.sub);
    t->open();
    PutItem a = e.item_text("a.txt", "inside prefix");
    CHECK(t->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);
    CHECK(fs::exists(e.root / "sub" / "dir" / "a.txt"));
    CHECK(!fs::exists(e.root / "a.txt"));
    auto l = t->list_remote();
    CHECK(l.size() == 1 && l.count("a.txt") == 1);
    CHECK(t->put_file("../../../esc.txt", a.abs_src, a.meta).status == PutResult::Failed);
    CHECK(!fs::exists(e.root / "esc.txt"));
    // a file elsewhere in root is invisible to this client
    write_text(e.root / "secret.txt", "s");
    CHECK(t->list_remote().count("secret.txt") == 0);
}

TEST(net_remote_prefix_on_target) {
    Env e;
    TargetConfig tc;
    tc.host = "127.0.0.1";
    tc.port = e.srv->port();
    tc.server_key = e.server_kp.pub;
    tc.remote_prefix = "backup/pc1";
    auto t = make_net_target(tc, ClientConfig(), e.rw, nullptr);
    t->open();
    PutItem a = e.item_text("f/g.txt", "prefixed");
    CHECK(t->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);
    CHECK(fs::exists(e.root / "backup" / "pc1" / "f" / "g.txt"));
    auto l = t->list_remote();
    CHECK(l.count("f/g.txt") == 1);
    t->rename_path("f/g.txt", "f/h.txt");
    CHECK(fs::exists(e.root / "backup" / "pc1" / "f" / "h.txt"));
}

TEST(net_max_file_size_enforced) {
    ServerConfig cfg;
    cfg.max_file_size = 1u << 20;
    Env e(cfg);
    auto t = e.target(e.rw);
    t->open();
    PutItem big = e.item("big.bin", pseudo_random(2u << 20, 3));
    PutResult r = t->put_file(big.rel, big.abs_src, big.meta);
    CHECK(r.status == PutResult::Failed);
    CHECK(!fs::exists(e.root / "big.bin"));
    PutItem small = e.item("small.bin", pseudo_random(1000, 3));
    CHECK(t->put_file(small.rel, small.abs_src, small.meta).status == PutResult::Sent);
}

TEST(net_orphan_temp_files_cleaned_at_start) {
    Env e(ServerConfig(), true);
    CHECK(!fs::exists(e.root / "old" / ".mysync-tmp-aaaa"));  // older than 1 h: removed
    CHECK(fs::exists(e.root / "old" / ".mysync-tmp-bbbb"));   // recent: kept (could belong to a live transfer)
}

TEST(net_auth_failures_throttle_by_ip) {
    ServerConfig cfg;
    cfg.max_auth_failures_per_min = 3;
    Env e(cfg);
    for (int i = 0; i < 3; i++) {
        auto bad = e.target(e.stranger);
        CHECK_THROWS(bad->open());
    }
    // the source IP is now blocked temporarily, even for a valid client
    auto ok = e.target(e.rw);
    CHECK_THROWS(ok->open());
}

TEST(net_server_stops_promptly_with_open_session) {
    Env e;
    auto t = e.target(e.rw);
    t->open();
    PutItem a = e.item_text("s.txt", "x");
    CHECK(t->put_file(a.rel, a.abs_src, a.meta).status == PutResult::Sent);
    e.shutdown();
    std::cout << "stop_seconds=" << e.stop_seconds << std::endl; CHECK(e.stop_seconds < 5.0);
    // the client notices the connection is gone and reports it as an Error
    PutItem b = e.item_text("s2.txt", "y");
    CHECK_THROWS(t->put_file(b.rel, b.abs_src, b.meta));
}

TEST(net_many_parallel_clients) {
    Env e;
    std::vector<std::thread> ths;
    std::atomic<int> okc{0};
    for (int c = 0; c < 6; c++) {
        PutItem it = e.item("par/c" + std::to_string(c) + ".bin", pseudo_random(300000, 100 + uint64_t(c)));
        ths.emplace_back([&e, it, &okc] {
            try {
                auto t = e.target(e.rw);
                t->open();
                if (t->put_file(it.rel, it.abs_src, it.meta).status == PutResult::Sent) okc++;
            } catch (...) {
            }
        });
    }
    for (auto& th : ths) th.join();
    CHECK(okc == 6);
}

TEST(ip_filter_rules) {
    IpFilter f({"10.0.0.0/8", "192.168.1.5", "2001:db8::/32"}, {"10.1.0.0/16", "10.9.9.9"});
    CHECK(f.permits("10.2.3.4"));
    CHECK(!f.permits("10.1.2.3"));   // deny wins
    CHECK(!f.permits("10.9.9.9"));
    CHECK(f.permits("192.168.1.5"));
    CHECK(!f.permits("192.168.1.6"));
    CHECK(f.permits("::ffff:10.2.3.4"));   // IPv4-mapped IPv6
    CHECK(!f.permits("::ffff:10.1.2.3"));
    CHECK(f.permits("2001:db8::1"));
    CHECK(!f.permits("2001:db9::1"));
    CHECK(!f.permits("not-an-ip"));
    IpFilter all({"*"}, {"203.0.113.0/24"});
    CHECK(all.permits("8.8.8.8"));
    CHECK(!all.permits("203.0.113.77"));
    IpFilter none({}, {});
    CHECK(!none.permits("127.0.0.1"));
    CHECK_THROWS(IpFilter({"10.0.0.0/33"}, {}));
    CHECK_THROWS(IpFilter({"garbage"}, {}));
}

TEST(auth_throttle_sliding_window) {
    AuthThrottle t(3);
    CHECK(!t.blocked("1.2.3.4", 0));
    t.record_failure("1.2.3.4", 1000);
    t.record_failure("1.2.3.4", 2000);
    CHECK(!t.blocked("1.2.3.4", 3000));
    t.record_failure("1.2.3.4", 4000);
    CHECK(t.blocked("1.2.3.4", 5000));
    CHECK(!t.blocked("5.6.7.8", 5000));
    CHECK(!t.blocked("1.2.3.4", 61500));  // the 1 000 failure aged out: 2 left
}

TEST(rate_limiter_throttles) {
    RateLimiter unlimited(0);
    auto t0 = Clock::now();
    unlimited.acquire(100u << 20);
    CHECK(secs_since(t0) < 0.2);
    RateLimiter lim(800);  // 100 KB/s
    t0 = Clock::now();
    for (int i = 0; i < 6; i++) lim.acquire(20000);  // 120 KB at 100 KB/s, ~10 KB burst credit
    double dt = secs_since(t0);
    CHECK(dt > 0.9 && dt < 3.0);
}

// ---------------------------------------------------------------- security hardening

TEST(auth_throttle_ipv6_keyed_by_slash64) {
    AuthThrottle t(3);
    t.record_failure("2001:db8:0:1::1", 1000);
    t.record_failure("2001:db8:0:1:aaaa::2", 1001);
    t.record_failure("2001:db8:0:1:ffff:ffff:ffff:ffff", 1002);
    CHECK(t.tracked() == 1u);                                  // one /64 = one source
    CHECK(t.blocked("2001:db8:0:1::99", 2000));                // any address of it is blocked
    CHECK(!t.blocked("2001:db8:0:2::1", 2000));                // the neighbouring /64 is not
    CHECK(!t.blocked("1.2.3.4", 2000));
    t.record_failure("::ffff:9.9.9.9", 1000);                  // IPv4-mapped = the IPv4 host, not one shared v6 key
    t.record_failure("9.9.9.9", 1001);
    t.record_failure("9.9.9.9", 1002);
    CHECK(t.blocked("9.9.9.9", 2000));
    CHECK(!t.blocked("9.9.9.8", 2000));
}

TEST(auth_throttle_hard_cap_evicts_oldest) {
    AuthThrottle t(3);
    for (size_t i = 0; i < AuthThrottle::kMaxEntries + 500; i++)
        t.record_failure("10." + std::to_string(i / 65536) + "." + std::to_string((i / 256) % 256) + "." +
                             std::to_string(i % 256),
                         int64_t(i));  // all inside one 60 s window: the sweep cannot help, only the cap
    CHECK(t.tracked() <= AuthThrottle::kMaxEntries);
    // the oldest source was dropped, the newest is still tracked
    for (int k = 0; k < 3; k++) t.record_failure("10.0.0.0", 20000);
    CHECK(t.blocked("10.0.0.0", 20001));
    CHECK(t.tracked() <= AuthThrottle::kMaxEntries);
}

TEST(auth_throttle_periodic_sweep_drops_expired) {
    AuthThrottle t(3);
    for (int i = 0; i < 300; i++)
        t.record_failure("172.16." + std::to_string(i / 256) + "." + std::to_string(i % 256), 100);
    CHECK(t.tracked() == 300u);
    t.record_failure("8.8.8.8", 100 + 61000);  // past the window and the sweep period: the 300 are gone
    CHECK(t.tracked() == 1u);
}

namespace {

// Opens `n` raw TCP connections and keeps them silent (a handshake that never starts).
std::vector<net::Socket> silent_connections(uint16_t port, int n) {
    std::vector<net::Socket> v;
    for (int i = 0; i < n; i++) v.push_back(net::Socket::connect("127.0.0.1", port, 3000));
    return v;
}

ServerConfig quiet_cfg() {
    ServerConfig c;
    c.max_auth_failures_per_min = 0;  // do not let the abuse below lock the loopback address out
    return c;
}

// True when the server closed `s` (EOF or reset) within ms, false if it is still held open.
bool closed_by_server(net::Socket& s, int ms) {
    s.set_timeouts(ms, ms);
    uint8_t b;
    try {
        return s.recv_some(&b, 1) == 0;
    } catch (const Error& e) {
        return std::string(e.what()).find("timeout") == std::string::npos;
    }
}

}  // namespace

TEST(server_limits_unauthenticated_connections_per_ip) {
    Env e(quiet_cfg());
    auto held = silent_connections(e.srv->port(), 4);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    net::Socket fifth = net::Socket::connect("127.0.0.1", e.srv->port(), 3000);
    CHECK(closed_by_server(fifth, 2500));        // over the per-source budget of 4
    CHECK(!closed_by_server(held[0], 300));      // the first four are still waiting in the handshake
    held.clear();                                // they leave: the budget is free again
    bool ok = false;
    for (int i = 0; i < 20 && !ok; i++) {
        try {
            auto t = e.target(e.rw);
            t->open();
            t->close();
            ok = true;
        } catch (const std::exception&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
    }
    CHECK(ok);
}

TEST(server_unauthenticated_connections_do_not_use_session_slots) {
    ServerConfig cfg = quiet_cfg();
    cfg.max_connections = 2;
    Env e(cfg);
    auto held = silent_connections(e.srv->port(), 3);  // would have filled max_connections before
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    auto a = e.target(e.rw);
    a->open();                                         // still served
    a->close();
    held.clear();
}

TEST(server_caps_authenticated_sessions_at_max_connections) {
    ServerConfig cfg = quiet_cfg();
    cfg.max_connections = 1;
    Env e(cfg);
    auto a = e.target(e.rw);
    a->open();
    auto b = e.target(e.ro);
    CHECK_THROWS(b->open());                           // second authenticated session: refused
    a->close();
}

TEST(server_counts_first_record_garbage_as_auth_failure) {
    ServerConfig cfg;
    cfg.max_auth_failures_per_min = 1;
    Env e(cfg);
    {
        net::Socket s = net::Socket::connect("127.0.0.1", e.srv->port(), 3000);
        SecureChannel ch = SecureChannel::client(std::move(s), e.rw, e.server_kp.pub);
        Bytes junk(16, 0xee);
        ch.send_msg(junk);                             // authentic record, but not a HELLO
        ch.socket().set_timeouts(2000, 2000);
        CHECK_THROWS(ch.recv_msg());                   // server hangs up
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto t = e.target(e.rw);
    CHECK_THROWS(t->open());                           // the source is now throttled
}

TEST(server_counts_torn_handshake_as_auth_failure) {
    ServerConfig cfg;
    cfg.max_auth_failures_per_min = 1;
    Env e(cfg);
    {
        net::Socket s = net::Socket::connect("127.0.0.1", e.srv->port(), 3000);
        uint8_t half[20] = {1, 2, 3};
        s.send_all(half, sizeof half);
    }                                                  // closed mid-handshake
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    auto t = e.target(e.rw);
    CHECK_THROWS(t->open());
}

TEST(server_drops_silent_session_after_handshake_within_hello_deadline) {
    ServerConfig cfg;
    cfg.max_auth_failures_per_min = 1;
    Env e(cfg);
    auto t0 = Clock::now();
    {
        net::Socket s = net::Socket::connect("127.0.0.1", e.srv->port(), 3000);
        SecureChannel ch = SecureChannel::client(std::move(s), e.rw, e.server_kp.pub);  // e.g. a replayed msg1
        ch.socket().set_timeouts(12000, 12000);
        CHECK_THROWS(ch.recv_msg());                   // no HELLO from us: the server closes
    }
    double dt = secs_since(t0);
    CHECK(dt > 4.0 && dt < 8.5);                       // ~5 s hello deadline
    auto t = e.target(e.rw);
    CHECK_THROWS(t->open());                           // and the source was charged for it
}
