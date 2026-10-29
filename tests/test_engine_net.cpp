// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <thread>

#include "mysync/client_engine.h"
#include "mysync/keys.h"
#include "mysync/server.h"
#include "testing.h"

namespace fs = std::filesystem;
using namespace mysync;

namespace {

struct Tmp {
    fs::path root;
    Tmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        root = fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
        fs::create_directories(root);
        log_set_level(LogLevel::Warn);
    }
    ~Tmp() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    fs::path dir(const std::string& n) const {
        fs::create_directories(root / n);
        return root / n;
    }
};

void write_file(const fs::path& p, const std::string& data, bool old_mtime) {
    fs::create_directories(p.parent_path());
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f << data;
    }
    if (old_mtime) fs::last_write_time(p, fs::file_time_type::clock::now() - std::chrono::hours(3));
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool wait_for(const std::function<bool()>& cond, int ms = 20000) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return cond();
}

bool has_content(const fs::path& p, const std::string& s) {
    std::error_code ec;
    return fs::is_regular_file(p, ec) && read_file(p) == s;
}

}  // namespace

TEST(engine_net_end_to_end_over_loopback) {
    Tmp tmp;
    fs::path src = tmp.dir("src"), root = tmp.dir("srvroot"), state = tmp.dir("state"), srvstate = tmp.dir("srvstate");
    KeyPair server_key = generate_keypair();
    KeyPair client_key = generate_keypair();
    std::string client_key_file = (tmp.root / "client.key").u8string();
    save_keypair(client_key_file, client_key);

    ServerConfig sc;
    sc.bind = "127.0.0.1";
    sc.port = 0;
    sc.root = root.u8string();
    sc.state_dir = srvstate.u8string();
    ClientAcl acl;
    acl.name = "tester";
    acl.public_key = client_key.pub;
    sc.clients.push_back(acl);
    Server server(sc, server_key);
    std::atomic<bool> srv_stop{false};
    std::thread srv_thread([&] { server.run(srv_stop); });

    std::string big(2 * 1024 * 1024 + 123, 'q');
    for (size_t i = 0; i < big.size(); i += 97) big[i] = static_cast<char>('a' + (i / 97) % 26);
    write_file(src / "small.txt", "tiny", true);
    write_file(src / "big" / "large.dat", big, true);
    for (int i = 0; i < 40; ++i) write_file(src / "many" / ("m" + std::to_string(i) + ".txt"), "m" + std::to_string(i), true);

    ClientConfig cc;
    cc.key_file = client_key_file;
    cc.state_dir = state.u8string();
    cc.connections = 3;
    cc.retry_min_ms = 100;
    cc.retry_max_ms = 500;
    WatchConfig w;
    w.name = "net";
    w.path = src.u8string();
    w.quiet_ms = 100;
    w.sync_delay_ms = 0;
    w.periodic_scan_s = 0;
    TargetConfig t;
    t.host = "127.0.0.1";
    t.port = server.port();
    t.server_key = server.public_key();
    w.targets.push_back(t);
    cc.watches.push_back(w);

    bool ok = true;
    {
        SyncEngine eng(cc, "");
        std::atomic<bool> stop{false};
        std::thread th([&] { eng.run(stop); });
        ok = ok && wait_for([&] { return has_content(root / "big" / "large.dat", big) && has_content(root / "many" / "m39.txt", "m39"); });
        ok = ok && wait_for([&] { return eng.idle(); });
        CHECK(ok);
        CHECK(has_content(root / "small.txt", "tiny"));
        write_file(src / "live.txt", "live data", false);
        CHECK(wait_for([&] { return has_content(root / "live.txt", "live data"); }));
        write_file(src / "small.txt", "tiny but changed", false);
        CHECK(wait_for([&] { return has_content(root / "small.txt", "tiny but changed"); }));
        fs::rename(src / "live.txt", src / "live2.txt");
        CHECK(wait_for([&] { return has_content(root / "live2.txt", "live data") && !fs::exists(root / "live.txt"); }));
        fs::remove(src / "many" / "m0.txt");
        CHECK(wait_for([&] { return !fs::exists(root / "many" / "m0.txt"); }));
        CHECK(wait_for([&] { return eng.idle(); }));
        stop = true;
        th.join();
    }
    // a second pass finds nothing to do: nothing hashed (index), nothing sent
    {
        SyncEngine eng(cc, "");
        std::atomic<bool> stop{false};
        eng.sync_once(stop);
        EngineStats s = eng.stats();
        CHECK_EQ(s.sent, 0u);
        CHECK_EQ(s.gave_up, 0u);
    }
    srv_stop = true;
    srv_thread.join();
}
