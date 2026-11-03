// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// invite_model.h - logic thuần (KHÔNG wx) của mã mời MSY2 ở giao diện: phía GỬI (dán mã, kiểm tra nền, tóm tắt bằng lời
// thường, bước "Bắt đầu đồng bộ") và phía NHẬN (hộp thoại "Cho máy khác gửi tệp tới đây": biểu mẫu, chọn thư mục / địa chỉ,
// các hàng danh sách). Mọi chuỗi hiển thị đi qua tr(); khoá công khai / toml / "peer add" KHÔNG xuất hiện ở đây, chỉ có
// dấu vân tay (trong phần Chi tiết gập sẵn). Khoá bí mật không bao giờ đi qua đây.
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "mysync/gui/invite_ops.h"
#include "mysync/simple/invite.h"
#include "mysync/simple/pair_code.h"

namespace mysync::gui {

// ---------------------------------------------------------------------------------------------- chữ dùng chung
std::string invite_perm_text(simple::InvitePerm p);          // "được gửi và sửa tệp" | "chỉ xem" (trong câu)
std::string invite_perm_choice_text(simple::InvitePerm p);   // "Gửi và sửa tệp" | "Chỉ xem" (nhãn nút chọn)
// "còn 23 giờ", "còn 12 phút", "còn dưới 1 phút", "còn 3 ngày"; <= 0 -> "đã hết hạn". Làm tròn xuống.
std::string time_left_text(int64_t seconds_left);
std::string uses_text(uint32_t uses);                        // "dùng được 1 lần"
// "Thứ Năm 02/11/2026 14:30" từ giờ ĐỊA PHƯƠNG đã tách sẵn (thuần, test được).
std::string fmt_weekday_time(const std::tm& local);
// Cùng dạng, từ unix (giờ địa phương của máy, không theo UTC).
std::string fmt_local_time(int64_t unix_seconds);
// "YYYY-MM-DD HH:MM" (UTC, do máy nhận ghi) -> giờ địa phương có thứ; không đọc được thì giữ NGUYÊN giá trị cũ.
std::string fmt_utc_stamp(const std::string& when_utc);

// ---------------------------------------------------------------------------------------------- phía GỬI
// Kết quả của probe_invite / redeem_invite -> lời thường theo Kind. Failed dùng nguyên văn `message`.
std::string invite_outcome_text(const simple::InviteOutcome& o);
// Đích máy-khác của trình hướng dẫn: địa chỉ + khoá máy nhận lấy từ lời máy nhận trả lời (token không dùng).
simple::PairCode pair_code_from_grant(const simple::InviteGrant& g);

enum class CodeStage { Empty, Invalid, Checking, Ready, Failed };

// Những gì hiện cho người gửi sau khi mã được kiểm xong. Dấu vân tay chỉ đi vào phần Chi tiết.
struct InviteSummary {
    std::string machine, folder, perm, left, uses;   // đã là lời thường
    std::string sentence;                            // một câu gom lại: Máy "X" cho phép máy này ... trong thư mục "Y".
    std::string line;                                // câu trên + (còn 23 giờ, dùng được 1 lần).
    std::string fingerprint;                         // aaaa-bbbb-cccc-dddd-eeee (Chi tiết)
    std::string dest_label;                          // "MAY-NHAN · thư mục \"Báo cáo\" · được gửi và sửa tệp" (tóm tắt bước 3)
};

class SenderInviteModel {
public:
    CodeStage stage() const { return stage_; }
    // Gọi mỗi khi ô mã đổi. Trả về true khi phải chạy kiểm nền (probe) cho lượt generation() hiện tại.
    // Đồng bộ làm trước: đúng dạng, đúng tổng kiểm, chưa hết hạn (giờ máy này). Lỗi nào cũng thành chữ đời thường, không lặp mã.
    bool set_text(const std::string& text, int64_t now_unix);
    uint64_t generation() const { return gen_; }
    const simple::InviteCode& code() const { return code_; }
    // Kết quả kiểm nền. Bỏ qua (false) nếu `gen` đã cũ (người dùng sửa ô trong lúc chờ).
    bool apply_probe(uint64_t gen, const simple::InviteOutcome& o);
    bool ready() const { return stage_ == CodeStage::Ready; }
    const std::string& error() const { return error_; }
    const simple::InviteGrant& grant() const { return grant_; }
    // Tóm tắt (cần stage Ready; trước đó chỉ có phần đọc được từ mã).
    InviteSummary summary(int64_t now_unix) const;
    void reset();

private:
    CodeStage stage_ = CodeStage::Empty;
    std::string text_, error_;
    simple::InviteCode code_;
    simple::InviteGrant grant_;
    uint64_t gen_ = 0;
};

// Bước "Bắt đầu đồng bộ" khi đích là máy khác: chữ chỉ báo.
std::string join_busy_text(bool waiting_for_confirm, int seconds_left);

// ---------------------------------------------------------------------------------------------- phía NHẬN
struct TtlChoice {
    int seconds = 0;
    std::string label;
};
std::vector<TtlChoice> invite_ttl_choices();      // 1 giờ, 24 giờ, 7 ngày
constexpr size_t kDefaultTtlIndex = 1;            // 24 giờ
struct UsesChoice {
    int uses = 1;
    std::string label;
};
std::vector<UsesChoice> invite_uses_choices();    // 1, 2, 5, 10 lần
constexpr size_t kDefaultUsesIndex = 0;           // 1 lần

struct ReceiverForm {
    std::string folder;
    simple::InvitePerm perm = simple::InvitePerm::ReadWrite;
    size_t ttl_index = kDefaultTtlIndex;
    size_t uses_index = kDefaultUsesIndex;
    bool ask = true;
};

struct FolderCheck {
    bool ok = false;
    std::string error;       // đã dịch
    std::string normalized;  // đã cắt khoảng trắng và dấu ""
};
// Không rỗng, là đường dẫn ĐẦY ĐỦ (mỗi mã trao đúng một thư mục tuyệt đối trên máy này); nếu đã có trên đĩa thì phải là thư mục.
FolderCheck check_receiver_folder(const std::string& text);

// Tạo (nếu chưa có, riêng tư) hoặc kiểm thư mục nhận. Ném UntrustedFolderError khi GUI chạy bằng quyền quản trị và tài khoản khác
// ghi được vào thư mục (hộp thoại giải thích + nút "Khoá quyền thư mục" = gọi lại với fix_permissions). Ném Error khác nguyên văn.
void prepare_receiver_folder(const std::string& dir, bool fix_permissions);

// Tối đa 3 địa chỉ cho mã: mạng nội bộ trước, trùng bị bỏ, địa chỉ không hợp lệ bị bỏ. Rỗng nếu không có.
std::vector<simple::InviteAddr> choose_invite_addrs(const std::vector<std::string>& ips, uint16_t port);

enum class ReceiverStage { Form, Working, Showing };
struct ReceiverButtons {
    bool create = false;      // "Tạo mã"
    bool browse = false;
    bool form = false;        // các ô của biểu mẫu
    bool copy = false;
    bool another = false;     // "Tạo mã khác"
    bool close = true;
};
ReceiverButtons receiver_buttons(ReceiverStage stage, bool folder_ok, bool busy);

// Số trong danh sách trả về của máy nhận -> hàng hiển thị (tên người, không phải khoá).
struct JoinedRow {
    std::string key_hex;   // chỉ để gọi "Gỡ"; không bao giờ hiện
    std::string title;     // tên máy (nguyên văn; rỗng -> "(không có tên)")
    std::string detail;    // "được gửi và sửa tệp · vào lúc Thứ Năm 02/11/2026 14:30"
};
std::vector<JoinedRow> joined_rows(const InviteListInfo& info);
struct LiveRow {
    std::string id_hex;
    std::string title;     // nhãn thư mục
    std::string detail;    // "được gửi và sửa tệp · còn 23 giờ · dùng được 1 lần"
};
std::vector<LiveRow> live_rows(const InviteListInfo& info, int64_t now_unix);

// Mã vừa tạo đang ở đâu: chờ / đã có máy vào / không còn dùng được.
struct CodeProgress {
    enum Kind { Waiting, Joined, Gone } kind = Waiting;
    std::string text;
};
CodeProgress code_progress(const InviteListInfo& info, const std::string& invite_id_hex, int64_t now_unix);
// id (16 hex) của mã đã tạo; "" nếu không đọc được.
std::string invite_code_id_hex(const std::string& code);

// CHỈ cho ảnh tài liệu / kiểm thử: một mã MSY2 hợp lệ ngẫu nhiên (khoá và bí mật dùng một lần, không tồn tại ở máy nhận nào).
std::string demo_invite_code(const std::string& machine, const std::string& label, const std::string& host, uint16_t port,
                             simple::InvitePerm perm, int ttl_seconds);

// Phía nhận: có yêu cầu `ask` đang chờ người dùng không (cái đầu tiên chưa bị bỏ qua).
const simple::PendingInvite* first_pending(const InviteListInfo& info, const std::vector<uint32_t>& dismissed);

}  // namespace mysync::gui
