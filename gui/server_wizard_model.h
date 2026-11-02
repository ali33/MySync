// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// server_wizard_model.h - phần thuần (KHÔNG wx) của hộp thoại "Dựng máy chủ": kiểm đầu vào, trạng thái các nút,
// dựng chữ hiện ra, thêm máy khách, cài dịch vụ. Hộp thoại wx (server_wizard.cpp) chỉ nối các hàm này với widget.
// Khoá bí mật KHÔNG BAO GIỜ đi qua đây: kết quả chỉ mang ĐƯỜNG DẪN tệp khoá và nửa công khai.
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/quick_setup.h"

namespace mysync::gui {

// Kết quả kiểm một ô nhập: ok, hoặc `error` là câu đã dịch (theo ngôn ngữ hiện tại) để hiện ngay cạnh ô.
struct InputCheck {
    bool ok = false;
    std::string error;
};

// Cổng: số nguyên 1..65535, chấp nhận khoảng trắng hai đầu. Rỗng = lỗi (ô luôn có giá trị mặc định 5656).
InputCheck check_server_port(const std::string& text, uint16_t& port);
// Thư mục cần chia sẻ: không rỗng, nếu đã tồn tại thì phải là thư mục. `normalized` = đã cắt khoảng trắng và dấu "".
InputCheck check_server_folder(const std::string& text, std::string& normalized);
// Khoá công khai của máy khách dán vào: bỏ khoảng trắng / xuống dòng / 0x / dấu ':' -> 64 hex thường.
InputCheck check_client_key(const std::string& pasted, std::string& hex);
// Tên máy khách: 1..128 ký tự, không có ký tự điều khiển. `normalized` = đã cắt khoảng trắng hai đầu.
InputCheck check_client_name(const std::string& text, std::string& normalized);

enum class ServerStage { Input, Creating, Result };

struct ServerButtons {
    bool create = false;          // "Tạo"
    bool browse = false;          // chọn thư mục
    bool copy = false;            // các nút Chép (có kết quả để chép)
    bool add_client = false;      // "Thêm máy khách"
    bool install_service = false; // "Cài thành dịch vụ"
    bool close = false;
};
// `busy` = đang thêm máy khách / cài dịch vụ (việc nền thứ hai): chặn thao tác chồng nhau.
// `inputs_ok` = thư mục và cổng đều hợp lệ (Input); `client_ok` = tên và khoá dán đều hợp lệ (Result).
ServerButtons server_buttons(ServerStage stage, bool inputs_ok, bool client_ok, bool busy);

// Chữ hiện ở màn kết quả. Không có chỗ nào chứa khoá bí mật.
struct ServerResultTexts {
    std::string headline;          // "Máy chủ đã sẵn sàng" / "... đã có sẵn từ trước"
    std::string folder_line;       // thư mục chia sẻ (+ "(vừa tạo)")
    std::string port_line;
    std::string config_line;       // đường dẫn cấu hình + "(đã có sẵn, giữ nguyên)" | "(vừa tạo)"
    std::string key_line;          // đường dẫn tệp khoá bí mật + trạng thái; kèm lời nhắc không chép đi
    std::string public_key;        // 64 hex
    std::string fingerprint;
    std::string pairing_line;      // "Ghép nối nhanh: tắt" ...
    std::vector<std::string> notes;
    std::string client_snippet;    // client.toml (chỉ-đọc, có nút Chép)
    std::string peer_add_command;  // dòng `mysync peer add ...` (chỉ-đọc, có nút Chép)
};
ServerResultTexts make_server_result_texts(const QuickResult&);

// Chạy quick_server (lõi, KHÔNG phải dòng lệnh). Gọi từ luồng nền. Ném mysync::Error khi bị từ chối.
QuickResult create_server(const std::string& folder, uint16_t port, bool fix_permissions = false);

// Như create_server nhưng không ném. Thư mục mà tài khoản khác ghi được (chỉ khi GUI chạy bằng quyền quản trị) trả về
// `untrusted_folder` + câu giải thích lời thường, để hộp thoại hiện nút "Khoá quyền thư mục" (gọi lại với fix_permissions).
struct CreateServerOutcome {
    bool ok = false;
    QuickResult result;
    std::string error;              // đã dịch, hiện nguyên văn dưới nút Dựng
    std::string untrusted_folder;   // khác rỗng: đề nghị khoá quyền thư mục này
};
CreateServerOutcome create_server_outcome(const std::string& folder, uint16_t port, bool fix_permissions);

// Thêm máy khách vào server.toml bằng peer_add (idempotent). Không ném: lỗi trả về trong `error` nguyên văn.
struct AddClientOutcome {
    bool ok = false;
    bool changed = false;
    std::string message;   // câu peer_add trả về (hoặc nguyên văn lỗi)
};
AddClientOutcome add_client(const std::string& config_file, const std::string& name, const std::string& key_text,
                            bool read_only);

// Cài thành dịch vụ rồi khởi động, như quick_service của dòng lệnh: bỏ qua cài nếu đã có. Gọi từ luồng nền; có thể
// bật UAC. Các kiểm tin cậy của đường dịch vụ có thể từ chối: `message` là nguyên văn, KHÔNG vòng qua.
struct ServiceOutcome {
    bool ok = false;
    bool cancelled = false;
    std::string message;
};
ServiceOutcome install_server_service(const QuickResult& r, const std::string& service_name = "mysync-server");

}  // namespace mysync::gui
