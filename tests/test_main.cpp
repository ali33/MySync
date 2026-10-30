// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

#include "testing.h"

int fake_engine_main(int argc, char** argv);  // tests/test_simple_engine.cpp: the engine the supervisor tests start

namespace {

// A test that never returns (a join that waits for ever, a socket nobody closes) must not hang the whole run: a
// watchdog names the test and ends the process with an error. The limit is generous (the slowest tests take a minute).
struct Watch {
    std::mutex m;
    std::string name;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    bool running = false;
};

Watch& watch() {
    static Watch w;
    return w;
}

void start_watchdog(int limit_s) {
    std::thread([limit_s] {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            Watch& w = watch();
            std::lock_guard<std::mutex> lk(w.m);
            if (w.running && std::chrono::steady_clock::now() - w.started > std::chrono::seconds(limit_s)) {
                std::cout << "[HANG] " << w.name << " : still running after " << limit_s << " s, aborting the test run" << std::endl;
                std::_Exit(4);
            }
        }
    }).detach();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--fake-engine") return fake_engine_main(argc, argv);
    std::string filter = argc > 1 ? argv[1] : "";
    int limit = 300;
    if (const char* e = std::getenv("MYSYNC_TEST_TIMEOUT_S")) limit = std::max(10, std::atoi(e));
    start_watchdog(limit);
    int pass = 0, fail = 0;
    for (auto& c : mytest::registry()) {
        if (!filter.empty() && std::string(c.name).find(filter) == std::string::npos) continue;
        {
            std::lock_guard<std::mutex> lk(watch().m);
            watch().name = c.name;
            watch().started = std::chrono::steady_clock::now();
            watch().running = true;
        }
        try {
            c.fn();
            ++pass;
            std::cout << "[ OK ] " << c.name << std::endl;
        } catch (const mytest::Failure& f) {
            ++fail;
            std::cout << "[FAIL] " << c.name << " : " << f.msg << std::endl;
        } catch (const std::exception& e) {
            ++fail;
            std::cout << "[FAIL] " << c.name << " : exception " << e.what() << std::endl;
        }
        std::lock_guard<std::mutex> lk(watch().m);
        watch().running = false;
    }
    std::cout << pass << " passed, " << fail << " failed\n";
    return fail == 0 ? 0 : 1;
}
