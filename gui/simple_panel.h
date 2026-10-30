// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// simple_panel.h - giao diện chế độ Đơn giản: Bắt đầu nhanh, trình hướng dẫn 3 bước, màn Trạng thái gọn, ô nhận file.
// Mọi lời dùng tiếng đời thường (không daemon/TOML/Noise/allowlist/IPC/SID).
#include <wx/simplebook.h>
#include <wx/tglbtn.h>
#include <wx/wx.h>

#include <atomic>
#include <functional>
#include <memory>
#include <set>
#include <string>

#include "mysync/gui/ipc.h"
#include "shared.h"
#include "simple_host.h"
#include "simple_model.h"
#include "ui_common.h"

class wxGauge;

namespace mysync::gui {

// Nhãn tự xuống dòng theo bề rộng hiện có, giữ nguyên văn bản gốc (Wrap() của wx sửa nhãn nên không dùng trực tiếp).
inline void sp_font(wxWindow* w, double scale, bool bold = true) {
    wxFont f = w->GetFont();
    f.SetFractionalPointSize(f.GetFractionalPointSize() * scale);
    if (bold) f.MakeBold();
    w->SetFont(f);
}

class WrapText : public wxStaticText {
public:
    WrapText(wxWindow* parent, const wxString& text = "");
    void SetText(const wxString& t);           // dùng SetLabelText: '&' không thành phím tắt
    void SetTextColour(const wxColour& c) { SetForegroundColour(c); Refresh(); }
    const wxString& raw() const { return raw_; }

private:
    void Rewrap();
    wxString raw_;
    int last_w_ = 0;
};

// Những gì các trang cần từ khung chính (đặt bởi MainFrame).
struct SimpleCtx {
    Shared* sh = nullptr;
    SimpleHost* host = nullptr;
    AliveFlag alive;
    std::function<void()> go_advanced;                 // "Tôi đã có dịch vụ / cấu hình nâng cao"
    std::function<void(bool show)> show_advanced;      // nút "Chế độ nâng cao"
    std::function<void()> engines_changed;             // vừa thêm thư mục / đổi engine: poller đổi tên, làm mới
    std::function<void(bool service)> set_service_mode;  // chuyển sang/khỏi dịch vụ hệ thống
    std::function<bool()> service_mode;
    std::function<void()> attention;                   // đưa cửa sổ lên (có yêu cầu ghép cần duyệt)
    std::function<void()> quit_all;                    // "Thoát hẳn"
};

class QuickStartPage : public wxPanel {
public:
    QuickStartPage(wxWindow* parent, SimpleCtx& c, std::function<void()> go_wizard);
};

class WizardPage : public wxPanel {
public:
    WizardPage(wxWindow* parent, SimpleCtx& c, std::function<void()> done, std::function<void()> cancel);
    ~WizardPage() override;
    void Restart(bool can_cancel);           // về bước 1, xoá lựa chọn cũ
    void DropFolder(const std::string& path);  // kéo-thả vào cửa sổ
    bool IsBusy() const { return busy_flag_ || pair_running_; }
    void AutoDrive(const std::string& src, const std::string& dst);  // kiểm thử: đi hết ba bước bằng sự kiện thật

private:
    void BuildSource(wxWindow* parent);
    void BuildDest(wxWindow* parent);
    void BuildFinish(wxWindow* parent);
    void ShowStep();
    void CheckInput(bool advance);
    void ChooseSource();
    void ChooseDest();
    void SendPairRequest();
    void CancelPair();
    void PairTick();
    void Begin();
    void UpdateDestEnable();
    void SetBusy(bool on, const char* key);
    void AutoStep();

    SimpleCtx& c_;
    std::function<void()> done_, cancel_;
    WizardModel m_;
    wxBoxSizer* root_ = nullptr;
    wxStaticText *title_ = nullptr, *stepno_ = nullptr;
    wxSimplebook* book_ = nullptr;
    wxPanel* content_ = nullptr;
    BusyIndicator* busy_ = nullptr;
    WrapText *src_err_ = nullptr, *dst_err_ = nullptr, *summary_ = nullptr, *pair_msg_ = nullptr;
    wxTextCtrl *src_ = nullptr, *dst_ = nullptr, *code_ = nullptr;
    wxRadioButton *r_folder_ = nullptr, *r_machine_ = nullptr;
    wxButton *b_src_ = nullptr, *b_dst_ = nullptr, *b_send_ = nullptr, *b_pcancel_ = nullptr;
    wxStaticText *sas_ = nullptr, *sas_hint_ = nullptr;
    wxButton *b_back_ = nullptr, *b_next_ = nullptr, *b_start_ = nullptr, *b_quit_ = nullptr;
    BusyIndicator* pair_busy_ = nullptr;
    wxTimer pair_timer_, auto_timer_;
    std::string auto_src_, auto_dst_;
    bool auto_ = false;
    struct PairRun {
        std::atomic<bool> cancel{false};
        std::atomic<int> secs{-1};
    };
    std::shared_ptr<PairRun> pair_;
    bool pair_running_ = false;
    bool busy_flag_ = false;
    AliveFlag alive_ = make_alive();
};

// Một ô nhận file: công tắc, mã ghép, hộp thoại duyệt.
class ReceiveBox : public wxPanel {
public:
    ReceiveBox(wxWindow* parent, SimpleCtx& c);
    ~ReceiveBox() override;
    void RestoreAtStartup();   // đã bật lần trước thì chạy lại engine nhận (chưa mở cửa sổ ghép)
    bool IsOn() const { return on_; }
    void AutoEnable(const std::string& folder);   // kiểm thử: bật nhận với thư mục này, không hỏi

private:
    void OnToggle(bool want);
    void StartReceiving(bool open_window);
    void StopReceiving();
    void OpenWindow();
    void Tick();
    void ApplyInfo(const PairInfo& pi);
    void CancelCode();
    void MarkCodeUsed();
    void Rebuild();
    void RebuildCode();
    void ShowApprove(const PairPendingInfo& p);
    void Resize();

    SimpleCtx& c_;
    AliveFlag alive_ = make_alive();
    wxCheckBox* chk_ = nullptr;
    wxPanel* body_ = nullptr;
    BusyIndicator* busy_ = nullptr;
    wxTextCtrl* code_ = nullptr;
    wxChoice* ip_ = nullptr;
    wxStaticText *folder_ = nullptr, *count_ = nullptr, *portl_ = nullptr;
    WrapText *fw_ = nullptr, *result_ = nullptr;
    wxButton *copy_ = nullptr, *reopen_ = nullptr, *chg_ = nullptr, *cancel_code_ = nullptr;
    wxPanel* code_row_ = nullptr;
    wxTimer timer_;
    bool on_ = false;
    bool ticking_ = false;
    bool changing_ = false;
    bool window_open_ = false;
    int secs_left_ = 0;
    std::string pub_hex_;
    std::string token_hex_;   // mật mã dùng một lần của mã hiện tại; chỉ có ngay khi bật, không bao giờ đọc lại được
    bool code_used_ = false;
    uint16_t port_ = 0;
    std::vector<std::string> ips_;
    std::set<uint32_t> dismissed_;
    class ApproveDialog* dlg_ = nullptr;
    uint32_t dlg_id_ = 0;
    friend class ApproveDialog;
};

class StatusPage : public wxPanel {
public:
    StatusPage(wxWindow* parent, SimpleCtx& c, std::function<void()> add_folder);
    ~StatusPage() override;
    void OnPoll(const PollResult& r);   // luồng UI; cũng gọi khi engine đổi trạng thái
    void Refresh2();                    // dựng lại từ dữ liệu poll gần nhất
    SimpleStatus Current() const { return cur_; }
    bool IsSyncing() const { return cur_.kind == SimpleKind::Syncing; }
    void SetAdvancedShown(bool s);
    void RestoreReceiver() { if (recv_) recv_->RestoreAtStartup(); }
    void SetQuitting(bool on);
    void AutoReceive(const std::string& folder) { if (recv_) recv_->AutoEnable(folder); }
    void OnShown() { UpdateAutostart(); }   // đọc lại ô "Tự chạy khi tôi đăng nhập" từ hệ thống

private:
    void UpdateAutostart();
    void ToServiceClick();
    void RunUpgrade(bool to_service);
    void OnAutostart(bool on);

    SimpleCtx& c_;
    AliveFlag alive_ = make_alive();
    BusyIndicator *busy_ = nullptr, *starting_ = nullptr;
    wxPanel* content_ = nullptr;
    WrapText *headline_ = nullptr, *detail_ = nullptr, *warn_ = nullptr, *svc_result_ = nullptr;
    wxPanel* warn_panel_ = nullptr;
    wxGauge* gauge_ = nullptr;
    wxStaticText* prog_ = nullptr;
    wxListBox* folders_ = nullptr;
    wxStaticText* folders_lbl_ = nullptr;
    wxButton *b_add_ = nullptr, *b_svc_ = nullptr;
    wxToggleButton* b_adv_ = nullptr;
    wxCheckBox* chk_auto_ = nullptr;
    ReceiveBox* recv_ = nullptr;
    SyncProgress prog_model_;
    SimpleStatus cur_;
    PollResult last_;
    bool have_last_ = false;
    bool upgrading_ = false;
    bool updating_auto_ = false;
    bool busy_op_ = false;
    std::function<void()> add_folder_;
};

enum class SimplePage { Checking, QuickStart, Wizard, Status };

class SimplePanel : public wxPanel {
public:
    SimplePanel(wxWindow* parent, SimpleCtx& c);
    void ShowPage(SimplePage p);
    SimplePage Page() const { return page_; }
    void OnPoll(const PollResult& r);
    void DropFolder(const std::string& path);
    StatusPage* status() { return status_; }
    bool IsSyncing() const { return status_ && status_->IsSyncing(); }
    void StartAddFolder();
    void AutoDrive(const std::string& src, const std::string& dst);

private:
    SimpleCtx& c_;
    wxSimplebook* book_ = nullptr;
    QuickStartPage* quick_ = nullptr;
    WizardPage* wiz_ = nullptr;
    StatusPage* status_ = nullptr;
    SimplePage page_ = SimplePage::Checking;
    BusyIndicator* checking_ = nullptr;
};

}  // namespace mysync::gui
