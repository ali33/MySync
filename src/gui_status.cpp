// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/status.h"

namespace mysync::gui {

const char* role_name(Role r) { return r == Role::Server ? "server" : "client"; }

const char* target_state_name(TargetState s) {
    switch (s) {
    case TargetState::Idle: return "idle";
    case TargetState::Syncing: return "syncing";
    case TargetState::Error: return "error";
    case TargetState::Disconnected: return "disconnected";
    }
    return "?";
}

uint64_t RateMeter::update(uint64_t counter) {
    while (lock_.test_and_set(std::memory_order_acquire)) {
    }
    auto now = std::chrono::steady_clock::now();
    if (!init_) {
        init_ = true;
        last_ = now;
        last_counter_ = counter;
    } else {
        double dt = std::chrono::duration<double>(now - last_).count();
        if (dt >= 0.5) {
            uint64_t delta = counter >= last_counter_ ? counter - last_counter_ : 0;
            uint64_t inst = static_cast<uint64_t>(double(delta) / dt);
            // light smoothing; a long gap (no poll for a while) forgets the past
            bps_ = dt > 5.0 || bps_ == 0 ? inst : (bps_ + inst) / 2;
            if (delta == 0) bps_ = 0;
            last_ = now;
            last_counter_ = counter;
        }
    }
    uint64_t r = bps_;
    lock_.clear(std::memory_order_release);
    return r;
}

}  // namespace mysync::gui
