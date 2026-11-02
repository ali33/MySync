// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// server_wizard.h - hộp thoại "Dựng máy chủ" (wx mỏng; mọi logic ở server_wizard_model.*).
#include <string>

class wxWindow;

namespace mysync::gui {

// Móc chụp ảnh tài liệu (đặt từ dòng lệnh): tự điền thư mục mẫu, tự bấm Tạo, tự thêm một máy khách mẫu, chụp màn kết
// quả ra PNG rồi tự đóng. Chỉ dùng dữ liệu mẫu: thư mục này do người chạy lệnh chỉ định (thư mục tạm).
struct ServerWizardDemo {
    std::string folder;   // --server-wizard-demo=<thư mục>
    std::string png;      // --server-wizard-shot=<png>
};
ServerWizardDemo& server_wizard_demo();

// Mở hộp thoại (modal). Trả về khi người dùng đóng.
void show_server_wizard(wxWindow* parent);

}  // namespace mysync::gui
