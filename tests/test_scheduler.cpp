// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <atomic>
#include <chrono>
#include <ctime>
#include <thread>

#include "mysync/scheduler.h"
#include "mysync/service.h"
#include "mysync/util.h"
#include "testing.h"

using namespace mysync;

namespace {
std::tm make_tm(int y, int mo, int d, int h, int mi, int s) {
    std::tm t{};
    t.tm_year = y - 1900;
    t.tm_mon = mo - 1;
    t.tm_mday = d;
    t.tm_hour = h;
    t.tm_min = mi;
    t.tm_sec = s;
    t.tm_isdst = -1;
    return t;
}
std::tm local_of(std::time_t t) {
    std::tm r{};
#ifdef _WIN32
    localtime_s(&r, &t);
#else
    localtime_r(&t, &r);
#endif
    return r;
}
}  // namespace

TEST(sched_parse_time_formats) {
    CHECK_EQ(parse_time_of_day("01:00"), 60);
    CHECK_EQ(parse_time_of_day("1:05"), 65);
    CHECK_EQ(parse_time_of_day("23:59"), 23 * 60 + 59);
    CHECK_EQ(parse_time_of_day("00:00"), 0);
    CHECK_EQ(parse_time_of_day("01:00 AM"), 60);
    CHECK_EQ(parse_time_of_day("12:10 PM"), 12 * 60 + 10);
    CHECK_EQ(parse_time_of_day("12:10 AM"), 10);
    CHECK_EQ(parse_time_of_day("11:30pm"), 23 * 60 + 30);
    CHECK_EQ(parse_time_of_day(" 07:15 am "), 7 * 60 + 15);
}

TEST(sched_parse_time_rejects_garbage) {
    CHECK_THROWS(parse_time_of_day(""));
    CHECK_THROWS(parse_time_of_day("24:00"));
    CHECK_THROWS(parse_time_of_day("12:60"));
    CHECK_THROWS(parse_time_of_day("0:00 PM"));
    CHECK_THROWS(parse_time_of_day("13:00 PM"));
    CHECK_THROWS(parse_time_of_day("12:5"));
    CHECK_THROWS(parse_time_of_day("12"));
    CHECK_THROWS(parse_time_of_day("12:00 XM"));
    CHECK_THROWS(parse_time_of_day("12:00 AM x"));
    CHECK_THROWS(parse_time_of_day("-1:00"));
    auto v = parse_times({"13:00", "01:00 PM", "02:00"});
    CHECK_EQ(v.size(), size_t(2));  // 13:00 and 01:00 PM collapse
    CHECK_EQ(v[0], 120);
}

TEST(sched_next_run_same_day_and_rollover) {
    std::vector<int> t = parse_times({"01:00", "13:30"});
    std::tm now = make_tm(2026, 3, 10, 0, 30, 0);
    std::tm nx = local_of(next_run(now, t));
    CHECK_EQ(nx.tm_mday, 10);
    CHECK_EQ(nx.tm_hour, 1);
    CHECK_EQ(nx.tm_min, 0);

    now = make_tm(2026, 3, 10, 1, 0, 0);  // exactly on a slot: strictly after, so the next one
    nx = local_of(next_run(now, t));
    CHECK_EQ(nx.tm_hour, 13);
    CHECK_EQ(nx.tm_min, 30);

    now = make_tm(2026, 3, 10, 14, 0, 0);  // past all slots: tomorrow
    nx = local_of(next_run(now, t));
    CHECK_EQ(nx.tm_mday, 11);
    CHECK_EQ(nx.tm_hour, 1);
}

TEST(sched_next_run_month_and_year_end) {
    std::vector<int> t = parse_times({"01:00"});
    std::tm nx = local_of(next_run(make_tm(2026, 1, 31, 23, 30, 0), t));
    CHECK_EQ(nx.tm_mon, 1);
    CHECK_EQ(nx.tm_mday, 1);
    nx = local_of(next_run(make_tm(2026, 12, 31, 23, 59, 59), t));
    CHECK_EQ(nx.tm_year, 2027 - 1900);
    CHECK_EQ(nx.tm_mon, 0);
    CHECK_EQ(nx.tm_mday, 1);
    CHECK_EQ(nx.tm_hour, 1);
    nx = local_of(next_run(make_tm(2028, 2, 28, 23, 0, 0), t));  // leap year
    CHECK_EQ(nx.tm_mon, 1);
    CHECK_EQ(nx.tm_mday, 29);
}

TEST(sched_next_run_always_in_future_and_empty) {
    std::vector<int> t = parse_times({"02:30", "03:00"});  // 02:30 may not exist on a DST-gap day
    std::time_t base = std::time(nullptr);
    for (int i = 0; i < 400; ++i) {
        std::time_t now_t = base + static_cast<std::time_t>(i) * 86400 + 3600 * (i % 24);
        std::tm now = local_of(now_t);
        std::time_t nr = next_run(now, t);
        CHECK(nr > now_t);
        CHECK(nr - now_t <= 3 * 86400);
    }
    CHECK_EQ(next_run(make_tm(2026, 1, 1, 0, 0, 0), {}), static_cast<std::time_t>(-1));
}

TEST(sched_interval_fires_and_stops_fast) {
    std::atomic<int> n{0};
    SchedulerOptions o;
    o.interval_s = 1;
    Scheduler s(o, [&] { ++n; });
    s.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(2600));
    s.stop();
    int got = n.load();
    CHECK(got >= 2 && got <= 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    CHECK_EQ(n.load(), got);  // really stopped
}

TEST(sched_stop_is_immediate) {
    SchedulerOptions o;
    o.interval_s = 3600;
    o.times = {"03:00"};
    Scheduler s(o, [] {});
    s.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto t0 = std::chrono::steady_clock::now();
    s.stop();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 500);
    s.stop();  // idempotent
}

TEST(sched_callback_exception_does_not_kill_thread) {
    std::atomic<int> n{0};
    SchedulerOptions o;
    o.interval_s = 1;
    Scheduler s(o, [&] { ++n; throw Error("boom"); });
    s.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));
    s.stop();
    CHECK(n.load() >= 2);
}

TEST(sched_bad_time_throws_in_ctor) {
    SchedulerOptions o;
    o.times = {"25:00"};
    CHECK_THROWS(Scheduler(o, [] {}));
}

// ---- service helpers that need no privileges ----
TEST(service_unit_text_hardened) {
    std::string u = systemd_unit_text("mysync-server", "/usr/local/bin/mysync", {"server", "-c", "/etc/mysync/server.toml"},
                                      "mysync", {"/srv/data", "/var/lib/mysync"}, "MySync server");
    auto has = [&](const char* s) { return u.find(s) != std::string::npos; };
    CHECK(has("ExecStart=\"/usr/local/bin/mysync\" \"server\" \"-c\" \"/etc/mysync/server.toml\"\n"));
    CHECK(has("User=mysync\n"));
    CHECK(has("NoNewPrivileges=true\n"));
    CHECK(has("ProtectSystem=strict\n"));
    CHECK(has("PrivateTmp=true\n"));
    CHECK(has("Restart=on-failure\n"));
    CHECK(has("ReadWritePaths=/srv/data /var/lib/mysync\n"));
    CHECK(has("WantedBy=multi-user.target"));
    CHECK(has("Description=MySync server\n"));
}

TEST(service_unit_text_rejects_injection) {
    CHECK_THROWS(systemd_unit_text("a b", "/bin/x", {}, ""));
    CHECK_THROWS(systemd_unit_text("a;rm", "/bin/x", {}, ""));
    CHECK_THROWS(systemd_unit_text("../x", "/bin/x", {}, ""));
    CHECK_THROWS(systemd_unit_text("-x", "/bin/x", {}, ""));
    CHECK_THROWS(systemd_unit_text("ok", "relative/x", {}, ""));
    CHECK_THROWS(systemd_unit_text("ok", "/bin/x\nExecStartPre=/bin/evil", {}, ""));
    CHECK_THROWS(systemd_unit_text("ok", "/bin/x", {"a\nb"}, ""));
    CHECK_THROWS(systemd_unit_text("ok", "/bin/x", {}, "root\nUser=0"));
    CHECK_THROWS(systemd_unit_text("ok", "/bin/x", {}, "", {"/a b"}));
    CHECK_THROWS(systemd_unit_text("ok", "/bin/x", {}, "", {"/a\nExecStart=/evil"}));
    CHECK_THROWS(systemd_unit_text("ok", "/bin/x", {}, "", {"rel"}));
    // quoting of metacharacters inside arguments
    std::string u = systemd_unit_text("ok", "/bin/x", {"a\"b", "50%", "$HOME", "back\\slash"}, "");
    CHECK(u.find("\"a\\\"b\" \"50%%\" \"$$HOME\" \"back\\\\slash\"") != std::string::npos);
    CHECK(u.find("User=") == std::string::npos);
}

TEST(service_install_validates_without_touching_system) {
    std::string err;
    CHECK(!service_install("bad name", "d", "/bin/x", {}, ServiceStartType::Manual, &err));
    CHECK(!err.empty());
    CHECK(!service_uninstall("a;b", &err));
    CHECK(!service_start("-x", &err));
    CHECK(!service_stop("", &err));
}

TEST(service_signal_handler_sets_flag) {
    static std::atomic<bool> stop{false};
    install_signal_handlers(stop);
    CHECK(!stop.load());
    // The handler itself is exercised by the platform; we only check installation is harmless.
}
