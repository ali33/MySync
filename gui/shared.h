// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// shared.h - trạng thái dùng chung giữa các tab (sống lâu hơn tab; khi đổi ngôn ngữ tab được dựng lại).
#include <functional>
#include <memory>
#include <string>

#include "mysync/gui/config_io.h"
#include "poller.h"
#include "status_model.h"

namespace mysync::gui {

struct Shared {
    std::unique_ptr<ConfigEditor> cfg;   // cấu hình đang mở (có thể null)
    std::string cfg_path;                // đường dẫn đang chọn (UTF-8), kể cả khi chưa mở được
    std::string daemon_name = "mysync-client";
    bool have_poll = false;
    PollResult last;                     // kết quả poll gần nhất

    // Gọi từ tab -> khung chính (luồng UI).
    std::function<void(BannerLevel, const std::string& source, const std::string& msg)> report;
    std::function<void(const std::string& source)> clear_report;
    std::function<void()> poll_now;
    std::function<void(const std::string& daemon)> set_daemon;
    std::function<void(const std::string& path)> open_config;   // chọn + mở tệp cấu hình
    std::function<bool()> save_config;                          // gom ô -> ghi nguyên tử -> RELOAD_CONFIG
    std::function<void()> config_changed;                       // cấu trúc cấu hình đổi (tab khác nạp lại)
    std::function<void(const std::string& svc, bool start)> service_toggle;  // từ khay
    // Cài đặt bền (wxConfig).
    std::function<std::string(const std::string& key, const std::string& def)> get_setting;
    std::function<void(const std::string& key, const std::string& value)> set_setting;
};

}  // namespace mysync::gui
