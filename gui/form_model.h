// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// form_model.h - kiểm hợp lệ từng ô của tab Cấu hình và chuyển đổi văn bản <-> giá trị. KHÔNG wx.
// Hàm check_* trả về "" nếu hợp lệ, ngược lại thông điệp đã dịch (tr) để hiện cạnh ô.
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/config.h"

namespace mysync::gui {

std::string trim(const std::string& s);
// Tách theo dòng, bỏ dòng trống, cắt khoảng trắng hai đầu mỗi dòng.
std::vector<std::string> split_lines(const std::string& text);
std::string join_lines(const std::vector<std::string>& v);

std::string check_port(const std::string& text, uint16_t* out = nullptr);
std::string check_host(const std::string& text);
// Số nguyên không âm trong [lo, hi].
std::string check_uint(const std::string& text, uint64_t lo, uint64_t hi, uint64_t* out = nullptr);
// "10MB", "1.5GB", số byte. allow_empty: ô trống hợp lệ (không giới hạn).
std::string check_size(const std::string& text, bool allow_empty, uint64_t* out = nullptr);
// "2026-01-01T00:00:00" (giờ địa phương) hoặc tương đối "7d", "12h". Trống = hợp lệ.
std::string check_mtime(const std::string& text);
std::string check_hhmm(const std::string& text);
std::string check_glob_or_ext(const std::string& text);   // ".docx" hoặc "*.xlsx"
std::string check_regex(const std::string& text);         // biên dịch thử std::regex
std::string check_ip_rule(const std::string& text);       // IPv4/IPv6, CIDR hoặc "*"
std::string check_octal_mode(const std::string& text, bool is_dir, uint32_t* out = nullptr);
std::string check_service_name(const std::string& text);
std::string check_prefix(const std::string& text);        // thư mục con, không '/' đầu/cuối, không ".."
std::string check_nonempty(const std::string& text);
std::string check_client_name(const std::string& text);

// Kiểm cả danh sách theo dòng; trả về thông điệp lỗi đầu tiên kèm số dòng.
std::string check_lines(const std::string& text, std::string (*fn)(const std::string&));
std::string check_ip_lines(const std::string& text);
std::string check_hhmm_lines(const std::string& text);
std::string check_glob_lines(const std::string& text);
std::string check_regex_lines(const std::string& text);

// Hiển thị số byte nguyên dạng ngắn nhất: 10737418240 -> "10GB"; không chia hết thì số byte. 0 -> "0".
std::string size_to_text(uint64_t bytes);
std::string mode_to_text(uint32_t mode);  // 0640 -> "0640"

// Kiểm cả cấu trúc (mọi watch, kể cả cái không đang hiện): danh sách thông điệp đã dịch, rỗng = hợp lệ.
// Đây là lớp chắn trước ConfigEditor::validate() (lỗi parser nguyên văn), cho thông điệp chỉ rõ ô nào sai.
std::vector<std::string> problems_client(const ClientConfig& c);
std::vector<std::string> problems_server(const ServerConfig& c);
bool key_is_unset(const PublicKey& k);

}  // namespace mysync::gui
