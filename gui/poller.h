// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// poller.h - luồng nền hỏi daemon qua ControlClient mỗi ~1 s. Không đụng UI: kết quả trả về bằng wxQueueEvent.
#include <wx/event.h>

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "mysync/gui/ipc.h"
#include "mysync/gui/status.h"

namespace mysync::gui {

struct PollResult {
    bool connected = false;
    StatusSnapshot snap;
    std::vector<ErrorEntry> errors;  // lỗi gần đây của daemon (cũ -> mới)
    std::string error;               // nguyên văn khi không kết nối được / daemon trả lỗi
    int64_t now_ms = 0;
    std::string daemon;              // tên đã hỏi
    uint64_t seq = 0;
};

wxDECLARE_EVENT(EVT_POLL_RESULT, wxThreadEvent);  // payload: PollResult

class Poller {
public:
    explicit Poller(wxEvtHandler* sink) : sink_(sink) {}
    ~Poller() { Stop(); }
    void Start(const std::string& daemon_name, int interval_ms = 1000);
    void SetDaemon(const std::string& name);  // đổi daemon và hỏi lại ngay
    void PollNow();
    void Stop();                              // join; gọi trước khi huỷ sink

private:
    void Loop();
    PollResult PollOnce(const std::string& name, uint64_t seq);

    wxEvtHandler* sink_;
    std::thread th_;
    std::mutex m_;
    std::condition_variable cv_;
    std::string name_;
    int interval_ms_ = 1000;
    bool stop_ = false;
    bool kick_ = false;
    uint64_t seq_ = 0;
};

}  // namespace mysync::gui
