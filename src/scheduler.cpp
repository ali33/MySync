// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/scheduler.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include "mysync/util.h"

namespace mysync {

int parse_time_of_day(const std::string& s) {
    auto bad = [&]() { return Error("invalid time of day: \"" + s + "\" (expected HH:MM, or HH:MM AM/PM)"); };
    size_t i = 0, n = s.size();
    auto skip_ws = [&]() { while (i < n && std::isspace(static_cast<unsigned char>(s[i]))) ++i; };
    auto num = [&](int max_digits, int& out) {
        size_t start = i;
        int v = 0;
        while (i < n && std::isdigit(static_cast<unsigned char>(s[i])) && static_cast<int>(i - start) < max_digits)
            v = v * 10 + (s[i++] - '0');
        out = v;
        return i > start;
    };
    skip_ws();
    int h = 0, m = 0;
    if (!num(2, h)) throw bad();
    if (i >= n || s[i] != ':') throw bad();
    ++i;
    size_t mstart = i;
    if (!num(2, m) || i - mstart != 2) throw bad();
    skip_ws();
    int ampm = 0;  // 0 none, 1 AM, 2 PM
    if (i < n) {
        char a = static_cast<char>(std::toupper(static_cast<unsigned char>(s[i])));
        if ((a != 'A' && a != 'P') || i + 1 >= n || std::toupper(static_cast<unsigned char>(s[i + 1])) != 'M') throw bad();
        ampm = a == 'A' ? 1 : 2;
        i += 2;
        skip_ws();
    }
    if (i != n) throw bad();
    if (m > 59) throw bad();
    if (ampm == 0) {
        if (h > 23) throw bad();
    } else {
        if (h < 1 || h > 12) throw bad();
        h = h % 12 + (ampm == 2 ? 12 : 0);
    }
    return h * 60 + m;
}

std::vector<int> parse_times(const std::vector<std::string>& times) {
    std::vector<int> r;
    for (auto& t : times) r.push_back(parse_time_of_day(t));
    std::sort(r.begin(), r.end());
    r.erase(std::unique(r.begin(), r.end()), r.end());
    return r;
}

std::time_t next_run(const std::tm& now_local, const std::vector<int>& minutes_of_day) {
    if (minutes_of_day.empty()) return static_cast<std::time_t>(-1);
    std::tm n = now_local;
    const std::time_t now_t = std::mktime(&n);
    std::time_t best = static_cast<std::time_t>(-1);
    for (int day = 0; day < 3; ++day) {
        for (int m : minutes_of_day) {
            std::tm c = now_local;
            c.tm_mday += day;  // mktime normalises month/year overflow
            c.tm_hour = m / 60;
            c.tm_min = m % 60;
            c.tm_sec = 0;
            c.tm_isdst = -1;  // let the C library pick the DST state for that wall-clock time
            std::time_t t = std::mktime(&c);
            if (t == static_cast<std::time_t>(-1) || t <= now_t) continue;
            if (best == static_cast<std::time_t>(-1) || t < best) best = t;
        }
        if (best != static_cast<std::time_t>(-1)) break;  // days are searched in order: first hit is earliest
    }
    return best;
}

namespace {
std::tm local_tm(std::time_t t) {
    std::tm r{};
#ifdef _WIN32
    localtime_s(&r, &t);
#else
    localtime_r(&t, &r);
#endif
    return r;
}
}  // namespace

struct Scheduler::Impl {
    using SysClock = std::chrono::system_clock;
    using Steady = std::chrono::steady_clock;

    SchedulerOptions opt;
    std::vector<int> minutes;
    std::function<void()> cb;
    std::mutex mu;
    std::condition_variable cv;
    std::thread th;
    bool started = false;
    bool stopping = false;

    std::time_t compute_daily() const {
        if (minutes.empty()) return static_cast<std::time_t>(-1);
        std::tm now = local_tm(SysClock::to_time_t(SysClock::now()));
        return next_run(now, minutes);
    }

    void loop() {
        std::unique_lock<std::mutex> lk(mu);
        std::time_t daily = compute_daily();
        const bool use_interval = opt.interval_s > 0;
        auto next_interval = Steady::now() + std::chrono::seconds(opt.interval_s);
        constexpr auto kSlice = std::chrono::seconds(30);  // re-check wall clock regularly (suspend, DST, clock edits)
        while (!stopping) {
            std::time_t now_t = SysClock::to_time_t(SysClock::now());
            auto steady_now = Steady::now();
            bool due_daily = daily != static_cast<std::time_t>(-1) && now_t >= daily;
            bool due_interval = use_interval && steady_now >= next_interval;
            if (due_daily || due_interval) {
                lk.unlock();
                try {
                    cb();
                } catch (const std::exception& e) {
                    log_error(std::string("scheduler: callback threw: ") + e.what());
                } catch (...) {
                    log_error("scheduler: callback threw an unknown exception");
                }
                lk.lock();
                if (due_daily) daily = compute_daily();
                if (use_interval) next_interval = Steady::now() + std::chrono::seconds(opt.interval_s);
                continue;
            }
            Steady::duration wait = kSlice;
            if (daily != static_cast<std::time_t>(-1)) {
                auto secs = std::chrono::seconds(std::max<std::time_t>(daily - now_t, 0));
                // A target more than a day and a bit away means the clock moved; recompute it.
                if (secs > std::chrono::hours(26)) { daily = compute_daily(); continue; }
                wait = std::min<std::chrono::steady_clock::duration>(wait, secs);
            }
            if (use_interval) wait = std::min<std::chrono::steady_clock::duration>(wait, next_interval - steady_now);
            if (wait < std::chrono::milliseconds(1)) wait = std::chrono::milliseconds(1);
            cv.wait_for(lk, wait, [&] { return stopping; });
        }
    }
};

Scheduler::Scheduler(SchedulerOptions opt, std::function<void()> callback) : p_(std::make_unique<Impl>()) {
    p_->minutes = parse_times(opt.times);  // throws on bad input
    if (opt.interval_s < 0) throw Error("scheduler interval must not be negative");
    p_->opt = std::move(opt);
    p_->cb = std::move(callback);
}

Scheduler::~Scheduler() {
    try { stop(); } catch (...) {}
}

void Scheduler::start() {
    std::lock_guard<std::mutex> lk(p_->mu);
    if (p_->started) return;
    p_->started = true;
    p_->stopping = false;
    p_->th = std::thread([this] { p_->loop(); });
}

void Scheduler::stop() {
    {
        std::lock_guard<std::mutex> lk(p_->mu);
        if (!p_->started) return;
        p_->stopping = true;
        p_->started = false;
    }
    p_->cv.notify_all();
    if (p_->th.joinable()) {
        if (p_->th.get_id() == std::this_thread::get_id()) p_->th.detach();  // stop() from inside the callback
        else p_->th.join();
    }
}

}  // namespace mysync
