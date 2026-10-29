// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// scheduler.h - fixed daily times ("HH:MM") and/or a repeat interval, one callback thread.
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mysync {

// Parse "HH:MM" (24 h), "H:MM", "01:00 AM", "12:10 PM" (case-insensitive, space optional)
// into minutes since local midnight. Throws Error on bad input.
int parse_time_of_day(const std::string& s);
std::vector<int> parse_times(const std::vector<std::string>& times);  // sorted, de-duplicated

// Pure: the first local wall-clock instant strictly after `now_local` that matches one of
// `minutes_of_day` (looks up to 3 calendar days ahead; handles month/year roll-over through mktime).
// Local times that do not exist (DST gap) are normalised by mktime; the result is always > now.
// Returns (time_t)-1 if the list is empty.
std::time_t next_run(const std::tm& now_local, const std::vector<int>& minutes_of_day);

struct SchedulerOptions {
    std::vector<std::string> times;  // daily local times; may be empty
    int interval_s = 0;              // repeat every N seconds after the previous run ENDED; 0 = off
};

class Scheduler {
public:
    // Throws Error if a time string is invalid. The callback is serialised: runs never overlap, and a
    // run that overruns its slot skips the missed slot rather than queueing.
    Scheduler(SchedulerOptions opt, std::function<void()> callback);
    ~Scheduler();
    Scheduler(const Scheduler&) = delete;
    Scheduler& operator=(const Scheduler&) = delete;

    void start();
    void stop();  // wakes the thread immediately (condition_variable) and joins it; idempotent

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

}  // namespace mysync
