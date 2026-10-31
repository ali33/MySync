// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// simple_model.h - logic thuần (KHÔNG wx) của chế độ Đơn giản: chọn câu trạng thái từ ảnh chụp, tiến độ, trạng thái
// trình hướng dẫn từng bước, kiểm hợp lệ, văn bản ghép máy. Mọi chuỗi hiển thị đi qua tr().
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/simple/pairing.h"
#include "mysync/simple/service_account.h"
#include "mysync/simple/service_upgrade.h"
#include "mysync/simple/user_engine.h"
#include "mysync/simple/wizard_model.h"
#include "status_model.h"

namespace mysync::gui {

// ---------------------------------------------------------------------------------------------- màn Trạng thái
enum class SimpleKind {
    NoFolder,    // chưa có thư mục nào
    Starting,    // bộ đồng bộ đang khởi động / chưa trả lời
    Restarting,  // vừa chết, đang tự khởi động lại (đếm lần)
    GaveUp,      // thử nhiều lần vẫn chết
    Stopped,     // đã dừng
    Syncing,
    UpToDate,
    Warning,
    Error,
};

struct SimpleInputs {
    bool has_config = false;                  // đã có ít nhất một thư mục
    bool engine_managed = true;               // true: bộ đồng bộ do giao diện giám sát; false: dịch vụ hệ thống
    simple::EngineState engine_state = simple::EngineState::Stopped;
    int restarts = 0;                         // số lần đã tự khởi động lại
    int next_retry_ms = 0;
    std::string engine_error;                 // nguyên văn những dòng cuối engine in ra
    bool connected = false;                   // đã hỏi được trạng thái
    StatusSnapshot snap;
    int64_t now_ms = 0;
};

struct SimpleStatus {
    SimpleKind kind = SimpleKind::NoFolder;
    std::string headline;     // một câu lớn, lời thường
    std::string detail;       // dòng phụ (có thể rỗng); lỗi thì là nguyên văn
    TrayState tray = TrayState::Offline;
    uint64_t pending = 0;     // số tệp đang chờ + đang gửi
    uint64_t sent = 0;        // tổng đã gửi (đếm từ lúc engine chạy)
    bool warn_banner = false; // hiện băng hổ phách "đang tự khởi động lại"
    bool error_banner = false;
};
SimpleStatus compute_simple_status(const SimpleInputs& in);

// Tiến độ của MỘT đợt đồng bộ: mốc đặt khi chuyển từ rảnh sang bận; đã gửi / (đã gửi + còn lại) kể từ mốc.
class SyncProgress {
public:
    // pending = số tệp chờ + đang gửi. Trả về true nếu giá trị hiển thị đổi.
    bool update(bool syncing, uint64_t total_sent, uint64_t pending);
    // -1 = không xác định (rảnh); 0..1 khi đang bận.
    double fraction() const { return frac_; }
    uint64_t done() const { return done_; }
    uint64_t total() const { return total_; }
    std::string text() const;  // "3 / 10 tệp"
    void reset();

private:
    bool active_ = false;
    uint64_t base_ = 0, done_ = 0, total_ = 0;
    double frac_ = -1;
};

// ---------------------------------------------------------------------------------------------- trình hướng dẫn
enum class WizardStep { Source = 0, Dest = 1, Finish = 2 };

// Văn bản dễ hiểu của một vấn đề từ validate_wizard (khoá đã dịch + chi tiết nguyên văn).
std::string wizard_issue_text(const simple::WizardIssue& i);
// Vấn đề thuộc bước nào (Source: chọn thư mục; Dest: nơi lưu).
WizardStep wizard_issue_step(const simple::WizardIssue& i);

class WizardModel {
public:
    WizardStep step() const { return step_; }
    const simple::WizardInput& input() const { return in_; }

    void set_source(const std::string& path);
    void set_kind(simple::DestKind k);
    void set_dest_path(const std::string& path);
    void set_paired(const simple::PairCode& c);   // sau khi máy kia đã đồng ý
    void clear_paired();
    // Kết quả kiểm (từ validate_wizard chạy ở luồng nền) cho đúng bản `input()` hiện tại.
    void apply_validation(const std::vector<simple::WizardIssue>& issues);
    bool validated() const { return validated_; }

    // Văn bản các vấn đề của một bước (rỗng nếu chưa kiểm). Với bước Dest: kiểu PairedMachine chưa ghép được -> nhắc.
    std::vector<std::string> issues_for(WizardStep s) const;
    bool step_ok(WizardStep s) const;
    bool can_next() const;
    bool next();   // false nếu chưa được
    bool back();
    void reset();

    // Tóm tắt lời thường cho bước cuối.
    std::string summary() const;

private:
    void invalidate() { validated_ = false; issues_.clear(); }
    WizardStep step_ = WizardStep::Source;
    simple::WizardInput in_;
    bool paired_ok_ = false;
    bool validated_ = false;
    std::vector<simple::WizardIssue> issues_;
};

// Tên cuối của đường dẫn để nói với người dùng ("D:\\Tài liệu\\Báo cáo" -> "Báo cáo"; "C:\\" -> "C:\\").
std::string folder_label(const std::string& path);
// Địa chỉ mạng dạng "\\\\máy\\chia-sẻ" hay "//máy/chia-sẻ"?
bool looks_like_unc(const std::string& p);

// ---------------------------------------------------------------------------------------------- ghép máy
// "9:41" (còn lại); âm -> "0:00".
std::string fmt_countdown(int seconds);
// Chuỗi xác nhận 4 nhóm: chuẩn hoá về hoa, nhóm bởi '-', cách nhau bằng khoảng trắng rộng cho dễ đọc: "ABCD  EFGH  JKMN  PQRS".
std::string sas_display(const std::string& sas);
// Xếp địa chỉ IP để chọn: IPv4 mạng nội bộ trước, rồi IPv4 khác, rồi IPv6; bỏ loopback / link-local; không trùng.
std::vector<std::string> rank_addresses(const std::vector<std::string>& ips);
bool is_private_ipv4(const std::string& ip);

// Kết quả ghép phía GỬI -> câu cho người dùng. Failed dùng nguyên văn `message`.
std::string pair_outcome_text(const simple::PairOutcome& o);
// Kiểm mã dán vào: "" nếu giải mã được, ngược lại câu lời thường (không lộ nội dung mã).
std::string check_pair_code_text(const std::string& text, simple::PairCode* out = nullptr);

// Lỗi của lõi dạng "<khoá>: <chi tiết>" (khoá wizard.* / receiver.*) -> lời thường + chi tiết nguyên văn.
// Lỗi khác trả về nguyên văn.
std::string friendly_error(const std::string& what);

// Hộp xác nhận TRƯỚC khi xin quyền quản trị để chuyển sang dịch vụ: thư mục nguồn, nơi lưu, danh tính khoá (vân tay
// ngắn), tài khoản chạy, các cảnh báo của lõi và lời nhắc quyền cao. Chuỗi động giữ nguyên văn.
std::string service_confirm_text(const simple::MigrationSummary& s, const std::string& account, bool windows);

// ---- nhập mật khẩu để dịch vụ chạy bằng chính tài khoản người dùng (Windows). Mô hình KHÔNG BAO GIỜ giữ mật khẩu:
// mật khẩu chỉ nằm trong hộp thoại và một SecretString đi thẳng tới bước cài đặt.
enum class PwdState { Idle, Asking, Working, NoPassword, Failed, Cancelled, Done };
enum class PwdErrorKind { None, WrongPassword, NoPassword, Other };
// Phân loại lỗi nguyên văn của bước cài đặt (dựa trên chính câu của explain_logon_error).
PwdErrorKind classify_password_error(const std::string& err);
std::string password_prompt_text(const std::string& account, bool update);

class PasswordFlow {
public:
    PwdState state() const { return state_; }
    const std::string& account() const { return account_; }
    const std::string& error() const { return error_; }   // nguyên văn / lời thường để hiện trong hộp nhập hoặc băng
    int attempts() const { return attempts_; }            // số lần nhập sai
    bool is_update() const { return update_; }
    void begin(const std::string& default_account, bool update);   // -> Asking
    // Người dùng bấm OK. Sai tên tài khoản / mật khẩu trống: ở lại Asking kèm lời nhắc, trả false.
    // `now_ms` (steady clock; -1 = the real one) is only there for tests. Sau 5 lần sai liên tiếp: khoá 30 giây, và việc mở lại
    // hộp KHÔNG xoá lần đếm (bộ giới hạn sống cùng đối tượng, không bị begin() đặt lại).
    bool submit(const std::string& account, bool has_password, int64_t now_ms = -1);
    void cancel();                                                 // đóng hộp / huỷ hộp xin quyền
    // Kết quả bước cài đặt. Sai mật khẩu -> Asking lần nữa (nhập lại); tài khoản không mật khẩu -> NoPassword.
    void finish(bool ok, bool cancelled, const std::string& error);

private:
    PwdState state_ = PwdState::Idle;
    std::string account_, error_;
    int attempts_ = 0;
    bool update_ = false;
    simple::PasswordAttemptLimiter limiter_;
    int64_t last_submit_ms_ = 0;
};

// Phía NHẬN: nhắc tường lửa lời thường (rỗng nếu không cần).
std::string firewall_hint(uint16_t port);

}  // namespace mysync::gui
