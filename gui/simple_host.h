// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// simple_host.h - phần không-wx của chế độ Đơn giản có tác dụng phụ: đường dẫn của người dùng, giám sát engine
// (tiến trình con), địa chỉ mạng của máy. Gọi được từ luồng nền, trừ khi ghi chú khác.
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mysync/keys.h"
#include "mysync/simple/user_engine.h"
#include "mysync/simple/user_paths.h"

namespace mysync::gui {

class SimpleHost {
public:
    // Xác định đường dẫn (không tạo gì). dir_override: thử nghiệm / chạy xách tay. Trả về false + lỗi nguyên văn.
    bool init(const std::string& dir_override, std::string* err);
    const simple::UserPaths& paths() const { return paths_; }
    bool has_config() const;            // tệp cấu hình người dùng đã có (đã chạy trình hướng dẫn)
    bool has_receiver_config() const;

    // Tạo giám sát (một lần): lấy khoá một-GUI-một-bộ-engine; chạy client nếu đã có cấu hình. Ném Error nguyên văn.
    void start_supervisor(bool run_client, bool run_receiver);
    bool supervisor_ready() const;
    simple::Supervisor* sup();
    // Sau khi cấu hình client được ghi/đổi (trình hướng dẫn): bật engine client (khởi động giám sát nếu chưa có) và
    // nạp cấu hình mới bằng cách khởi động lại engine. Chặn: gọi ở luồng nền.
    void apply_client_config();
    // Khoá client của máy này (tạo nếu chưa có, chỉ chủ sở hữu đọc được). Ném Error nguyên văn.
    static KeyPair load_or_create_client_key(const simple::UserPaths& p);
    simple::EngineInfo client_info() const;
    simple::EngineInfo receiver_info() const;
    void stop_all();                    // chặn tới khi engine dừng hẳn (gọi ở luồng nền)

    // Địa chỉ IP của máy (đã xếp: mạng nội bộ trước). Có thể chậm vài trăm ms: gọi ở luồng nền.
    static std::vector<std::string> local_addresses();
    static void set_demo_address(const std::string& ip);   // chỉ để chụp ảnh tài liệu: thay danh sách địa chỉ thật
    static std::string default_receive_folder();   // Documents\MySync-Nhan hay ~/MySync-Nhan

private:
    simple::UserPaths paths_;
    mutable std::mutex mu_;
    std::unique_ptr<simple::InstanceLock> lock_;
    std::unique_ptr<simple::Supervisor> sup_;
};

}  // namespace mysync::gui
