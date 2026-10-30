// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// Shared helpers of the server-operation tests (test_server_ops*.cpp).
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <thread>

#include "mysync/cli_ops.h"
#include "mysync/keys.h"
#include "mysync/net.h"
#include "testing.h"

namespace fs = std::filesystem;

namespace sotest {
using namespace mysync;

struct Tmp {
    fs::path p;
    Tmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-so-" + to_hex(r, sizeof r));
        fs::create_directories(p);
        log_set_level(LogLevel::Error);
    }
    ~Tmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string s(const std::string& rel) const { return (p / fs::u8path(rel)).generic_u8string(); }
};

inline void spit(const fs::path& f, const std::string& text) {
    fs::create_directories(f.parent_path());
    std::ofstream o(f, std::ios::binary | std::ios::trunc);
    o << text;
}

inline std::string slurp(const fs::path& f) {
    std::ifstream i(f, std::ios::binary);
    std::ostringstream ss;
    ss << i.rdbuf();
    return ss.str();
}

inline bool wait_until(const std::function<bool()>& f, int ms = 15000) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        try {
            if (f()) return true;
        } catch (const std::exception&) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }
    return false;
}

inline std::string hex(const PubKey& k) { return key_to_hex(k); }

// Runs a command line, returns {exit code, stdout, stderr}.
struct Run {
    int rc = -1;
    std::string out, err;
};
inline Run cli(std::vector<std::string> args) {
    args.insert(args.begin(), "mysync");
    std::ostringstream o, e;
    auto* ob = std::cout.rdbuf(o.rdbuf());
    auto* eb = std::cerr.rdbuf(e.rdbuf());
    Run r;
    try {
        r.rc = cli_ops_main(args);
    } catch (...) {
        std::cout.rdbuf(ob);
        std::cerr.rdbuf(eb);
        throw;
    }
    std::cout.rdbuf(ob);
    std::cerr.rdbuf(eb);
    r.out = o.str();
    r.err = e.str();
    return r;
}

const std::string K1(64, 'a'), K2(64, 'b'), K3(64, 'c');

inline std::string server_toml_text(const std::string& extra, bool with_client = true) {
    return "[server]\nroot = \"r\"\nkey_file = \"k\"\n" + extra +
           (with_client ? "\n[[client]]\nname = \"main1\"\npublic_key = \"" + K1 + "\"\n" : "");
}

inline uint16_t free_port() {
    net::init();
    net::Socket s = net::Socket::listen("127.0.0.1", 0);
    uint16_t p = s.local_port();
    s.close();
    return p;
}

}  // namespace sotest
using namespace sotest;
