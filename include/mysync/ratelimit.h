// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// ratelimit.h - thread-safe token bucket shared by all connections of a client (bandwidth cap).
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

namespace mysync {

class RateLimiter {
public:
    // kbps = kilobits per second (1 kbps = 125 bytes/s); 0 = unlimited. Burst is ~100 ms worth (>= 4 KiB).
    explicit RateLimiter(uint32_t kbps);
    // Blocks until `bytes` may be sent. A request larger than the burst is allowed (the bucket goes into debt
    // and the caller sleeps it off), so the long-run rate is always honoured. The request is taken in pieces of
    // at most ~250 ms of rate (>= 4 KiB), so one caller never leaves the others queued behind a huge debt.
    // Sleeps in slices of <= 100 ms and returns early once *stop becomes true (stop may be null).
    void acquire(uint64_t bytes, const std::atomic<bool>* stop = nullptr);
    uint64_t bytes_per_sec() const { return rate_; }
    // Shutdown latch: after cancel(), acquire() throws Error at once, so a transfer stuck behind the bandwidth cap
    // (or just in the middle of a big file) ends promptly instead of running on unthrottled. One-way.
    void cancel() { cancelled_ = true; }
    // Bytes that passed through acquire() since construction (live transfer meter for the GUI).
    uint64_t total_bytes() const { return total_.load(); }

private:
    using Clock = std::chrono::steady_clock;
    const uint64_t rate_;      // bytes per second, 0 = unlimited
    const double capacity_;    // bytes
    std::atomic<bool> cancelled_{false};
    std::atomic<uint64_t> total_{0};
    std::mutex m_;
    double tokens_;
    Clock::time_point last_;
};

} // namespace mysync
