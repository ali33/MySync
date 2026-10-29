// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/ratelimit.h"

#include <algorithm>
#include <thread>

namespace mysync {

RateLimiter::RateLimiter(uint32_t kbps)
    : rate_(uint64_t(kbps) * 125), capacity_(std::max<double>(4096.0, double(rate_) / 10.0)),
      tokens_(capacity_), last_(Clock::now()) {}

void RateLimiter::acquire(uint64_t bytes) {
    if (rate_ == 0 || bytes == 0) return;
    double wait_s = 0;
    {
        std::lock_guard<std::mutex> lk(m_);
        auto now = Clock::now();
        double dt = std::chrono::duration<double>(now - last_).count();
        last_ = now;
        tokens_ = std::min(capacity_, tokens_ + dt * double(rate_));
        tokens_ -= double(bytes);
        if (tokens_ < 0) wait_s = -tokens_ / double(rate_);
    }
    if (wait_s > 0) std::this_thread::sleep_for(std::chrono::duration<double>(wait_s));
}

} // namespace mysync
