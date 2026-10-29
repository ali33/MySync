// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "poller.h"

#include <wx/app.h>

#include <chrono>

namespace mysync::gui {

wxDEFINE_EVENT(EVT_POLL_RESULT, wxThreadEvent);

namespace {
int64_t now_unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
}  // namespace

void Poller::Start(const std::string& daemon_name, int interval_ms) {
    Stop();
    {
        std::lock_guard<std::mutex> lk(m_);
        name_ = daemon_name;
        interval_ms_ = interval_ms;
        stop_ = false;
        kick_ = true;  // hỏi ngay lần đầu
    }
    th_ = std::thread([this] { Loop(); });
}

void Poller::SetDaemon(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_);
    name_ = name;
    kick_ = true;
    cv_.notify_all();
}

void Poller::PollNow() {
    std::lock_guard<std::mutex> lk(m_);
    kick_ = true;
    cv_.notify_all();
}

void Poller::Stop() {
    {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = true;
        cv_.notify_all();
    }
    if (th_.joinable()) th_.join();
}

PollResult Poller::PollOnce(const std::string& name, uint64_t seq) {
    PollResult r;
    r.daemon = name;
    r.seq = seq;
    r.now_ms = now_unix_ms();
    try {
        ControlClient cc(name, 2000);
        r.snap = cc.get_status();
        r.connected = true;
        try {
            r.errors = cc.recent_errors(20);
        } catch (const std::exception&) {
            // Danh sách lỗi là phần phụ: không làm mất trạng thái chính.
        }
    } catch (const std::exception& e) {
        r.connected = false;
        r.error = e.what();
    } catch (...) {
        r.connected = false;
        r.error = "unknown exception while polling the daemon";
    }
    return r;
}

void Poller::Loop() {
    for (;;) {
        std::string name;
        uint64_t seq;
        {
            std::unique_lock<std::mutex> lk(m_);
            if (stop_) return;
            name = name_;
            seq = ++seq_;
            kick_ = false;
        }
        PollResult r;
        try {
            r = PollOnce(name, seq);
        } catch (...) {
            r.error = "unexpected error in poll thread";
            r.daemon = name;
            r.now_ms = now_unix_ms();
        }
        auto* ev = new wxThreadEvent(EVT_POLL_RESULT);
        ev->SetPayload(r);
        wxQueueEvent(sink_, ev);  // chuyển quyền sở hữu cho wx; xử lý ở luồng UI
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait_for(lk, std::chrono::milliseconds(interval_ms_), [&] { return stop_ || kick_; });
        if (stop_) return;
    }
}

}  // namespace mysync::gui
