// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/ratelimit.h"

#include <algorithm>
#include <thread>

#include "mysync/util.h"

namespace mysync {

RateLimiter::RateLimiter(uint32_t kbps)
    : rate_(uint64_t(kbps) * 125), capacity_(std::max<double>(4096.0, double(rate_) / 10.0)),
      tokens_(capacity_), last_(Clock::now()) {}

void RateLimiter::acquire(uint64_t bytes, const std::atomic<bool>* stop) {
    total_ += bytes;
    if (cancelled_.load()) throw Error("transfer cancelled: the client is stopping");
    if (rate_ == 0 || bytes == 0) return;
    const uint64_t piece = std::max<uint64_t>(rate_ / 4, 4096);
    while (bytes > 0) {
        if (stop && stop->load()) return;
        const uint64_t n = std::min(bytes, piece);
        bytes -= n;
        double wait_s = 0;
        {
            std::lock_guard<std::mutex> lk(m_);
            auto now = Clock::now();
            double dt = std::chrono::duration<double>(now - last_).count();
            last_ = now;
            tokens_ = std::min(capacity_, tokens_ + dt * double(rate_));
            tokens_ -= double(n);
            if (tokens_ < 0) wait_s = -tokens_ / double(rate_);
        }
        auto until = Clock::now() + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(wait_s));
        for (;;) {
            if (stop && stop->load()) return;
            if (cancelled_.load()) throw Error("transfer cancelled: the client is stopping");
            auto left = until - Clock::now();
            if (left <= Clock::duration::zero()) break;
            std::this_thread::sleep_for(std::min<Clock::duration>(left, std::chrono::milliseconds(100)));
        }
    }
}

} // namespace mysync
