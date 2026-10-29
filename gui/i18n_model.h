// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// i18n_model.h - bảng chuỗi vi/en. KHÔNG phụ thuộc wx. Mọi chuỗi hiển thị đi qua tr("khoá"), UTF-8.
#include <string>
#include <vector>

namespace mysync::gui {

enum class Lang { Vi, En };

void set_lang(Lang l);
Lang lang();
const char* lang_code(Lang l);                    // "vi" / "en"
bool lang_from_code(const std::string& code, Lang& out);

// Trả về chuỗi theo ngôn ngữ hiện tại. Khoá không có trong bảng: trả về "?khoá?" (lỗi lộ ra màn, không im lặng).
const std::string& tr(const char* key);
// Như tr() nhưng thay {0} {1} ... bằng đối số.
std::string trf(const char* key, const std::vector<std::string>& args);

// Cho test: số mục, khoá thiếu bản dịch (vi hoặc en rỗng), khoá trùng.
size_t i18n_count();
std::vector<std::string> i18n_problems();
bool i18n_has(const char* key);

}  // namespace mysync::gui
