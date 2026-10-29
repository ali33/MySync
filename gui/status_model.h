// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// status_model.h - logic thuần (không wx) của tab Trạng thái và icon khay: định dạng số, giờ có thứ,
// ánh xạ trạng thái -> màu icon, gom băng báo lỗi.
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "mysync/gui/status.h"

namespace mysync::gui {

std::string fmt_bytes(uint64_t n);          // "1,5 MB" (dấu thập phân theo ngôn ngữ)
std::string fmt_rate(uint64_t bytes_per_s); // "1,2 MB/s"
std::string fmt_duration(uint64_t seconds); // "2 ngày 3 giờ" / "5 phút 07 giây"
std::string weekday_name(int tm_wday);      // "Thứ Năm"/"Thursday", "Chủ nhật"/"Sunday"
// Giờ địa phương có thứ: "Thứ Năm 29/10/2026 22:59:03". Với unix_ms <= 0 trả về "—".
std::string fmt_datetime(int64_t unix_ms);
std::string fmt_datetime_tm(const std::tm& t);  // đã là giờ địa phương (test được, không phụ thuộc múi giờ)
std::string fmt_time_ago(int64_t unix_ms, int64_t now_ms);  // "3 giây trước"

enum class TrayState { Offline, Idle, Syncing, Warning, Error };
const char* tray_state_name(TrayState);
// rgb 0xRRGGBB của màu icon: xám / xanh lá / xanh dương / vàng / đỏ.
uint32_t tray_state_color(TrayState);
// connected=false: không nói chuyện được với daemon. recent_error_ms: cửa sổ coi lỗi là "gần đây".
TrayState compute_tray_state(bool connected, const StatusSnapshot& s, int64_t now_ms,
                             int64_t recent_error_ms = 10 * 60 * 1000);
std::string tray_tooltip(bool connected, const StatusSnapshot& s, TrayState st);

std::string target_state_text(TargetState s);
std::string target_display(const std::string& raw);  // "net://h:p" -> "h:p (mạng)", "dir://p" -> "p (thư mục)"

// Một dòng bảng "Đích". Cột: tên watch, đích, trạng thái, hàng đợi, tốc độ gửi/nhận, đã gửi/bỏ qua/lỗi, tổng byte.
struct TargetRow {
    std::string watch, target, state, queued, speed, counts, bytes;
    TargetState raw_state = TargetState::Idle;
};
TargetRow make_target_row(const TargetStatus& t);
struct PeerRow {
    std::string name, sessions, speed, bytes;
};
PeerRow make_peer_row(const PeerStatus& p);

// Tóm tắt lỗi gần nhất trong mọi đích (nguyên văn + giờ). Rỗng nếu không có lỗi.
struct LastError {
    std::string where;    // "watch → đích"
    std::string message;  // nguyên văn
    int64_t unix_ms = 0;
};
bool latest_error(const StatusSnapshot& s, LastError& out);

// ---- băng báo lỗi (đỏ = chặn, hổ phách = cảnh báo): gộp trùng, tối đa kMaxBanner dòng ----
enum class BannerLevel { Warning, Error };
struct BannerItem {
    BannerLevel level = BannerLevel::Error;
    std::string source;   // khoá nguồn: cùng nguồn thì thay thế (ví dụ "poll")
    std::string message;  // nguyên văn
    int count = 1;
};
class BannerModel {
public:
    static constexpr size_t kMaxBanner = 5;
    // Cùng (level,message) -> tăng count. Vượt trần -> bỏ dòng cũ nhất. Trả về true nếu danh sách đổi.
    bool add(BannerLevel lv, const std::string& source, const std::string& msg);
    // Xoá mọi dòng của nguồn (khi nguồn đó hồi phục).
    bool clear_source(const std::string& source);
    bool remove(const std::string& source, const std::string& msg);  // đóng đúng một dòng
    void clear();
    const std::vector<BannerItem>& items() const { return items_; }
    bool has_error() const;
    std::string render(const BannerItem&) const;  // "message (×3)"
private:
    std::vector<BannerItem> items_;
};

}  // namespace mysync::gui
