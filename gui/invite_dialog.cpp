// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// Chế độ Đơn giản, phía NHẬN: hộp thoại "Cho máy khác gửi tệp tới đây" (tạo MỘT mã mời MSY2, danh sách máy đã vào, mã đang
// dùng được) và hộp xác nhận chuỗi SAS cho mã tạo với "Hỏi tôi trước khi cho vào". Logic thuần ở invite_model.*.
//
// THƯ MỤC: mỗi mã trao đúng MỘT thư mục tuyệt đối trên máy này (bất kỳ thư mục nào, không cần nằm trong "gốc" của bộ nhận);
// máy vào bằng mã bị nhốt trong thư mục đó. Bộ nhận có một cấu hình riêng của người dùng (tạo bằng simple::ensure_receiver_config
// ở lần dùng đầu, pairing = on-demand; gốc của cấu hình lấy thư mục đầu tiên được chọn, chỉ để cấu hình hợp lệ). Máy nhận kiểm
// chồng lấn giữa các thư mục đã trao và trả lý do nguyên văn, hiện nguyên văn ở đây.
//
// Mọi thao tác chờ máy chủ đều có chỉ báo động (BusyIndicator / BusyGate) và lỗi hiện nguyên văn; không động vào giao diện từ
// luồng nền (run_async đưa kết quả về luồng UI).
#include <wx/clipbrd.h>
#include <wx/dirdlg.h>
#include <wx/msgdlg.h>
#include <wx/scrolwin.h>

#include <chrono>
#include <ctime>
#include <thread>

#include "form_model.h"
#include "mysync/quick_setup.h"
#include "mysync/simple/wizard_model.h"
#include "simple_panel.h"

namespace mysync::gui {

namespace {
const wxColour kRed(0xA0, 0x10, 0x10), kGreen(0x1E, 0x7E, 0x34), kAmber(0x8A, 0x5A, 0x00), kGrey(0x55, 0x55, 0x55);
int64_t now_unix() { return static_cast<int64_t>(std::time(nullptr)); }
}  // namespace

// ---------------------------------------------------------------- hộp xác nhận (SAS)
class ApproveDialog : public wxDialog {
public:
    ApproveDialog(wxWindow* parent, const simple::PendingInvite& p, std::function<void(uint32_t, bool)> decide,
                  std::function<void()> closed)
        : wxDialog(parent, wxID_ANY, L("recv.dlg.title"), wxDefaultPosition, wxDefaultSize, wxDEFAULT_DIALOG_STYLE),
          id_(p.id), decide_(std::move(decide)), closed_(std::move(closed)) {
        auto* v = new wxBoxSizer(wxVERTICAL);
        busy_ = new BusyIndicator(this);
        v->Add(busy_, 0, wxEXPAND | wxALL, 8);
        auto* who = new WrapText(this, W(trf("recv.dlg.who", {p.name, p.ip})));
        who->SetMinSize(wxSize(440, -1));
        v->Add(who, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 14);
        v->Add(new wxStaticText(this, wxID_ANY, L("recv.dlg.sas")), 0, wxLEFT | wxRIGHT | wxTOP, 14);
        sas_ = new wxStaticText(this, wxID_ANY, W(sas_display(p.sas)));
        sp_font(sas_, 2.2);
        {
            wxFont f = sas_->GetFont();
            f.SetFamily(wxFONTFAMILY_TELETYPE);
            sas_->SetFont(f);
        }
        v->Add(sas_, 0, wxALIGN_CENTER | wxALL, 14);
        auto* hint = new WrapText(this, L("recv.dlg.check"));
        v->Add(hint, 0, wxEXPAND | wxLEFT | wxRIGHT, 14);
        left_ = new wxStaticText(this, wxID_ANY, "");
        left_->SetForegroundColour(kGrey);
        v->Add(left_, 0, wxLEFT | wxRIGHT | wxTOP, 14);
        auto* bh = new wxBoxSizer(wxHORIZONTAL);
        b_deny_ = new wxButton(this, wxID_ANY, L("recv.dlg.deny"));
        b_ok_ = new wxButton(this, wxID_ANY, L("recv.dlg.ok"));
        bh->AddStretchSpacer(1);
        bh->Add(b_deny_, 0, wxRIGHT, 8);
        bh->Add(b_ok_, 0);
        v->Add(bh, 0, wxEXPAND | wxALL, 14);
        SetSizerAndFit(v);
        SetLeft(p.seconds_left);
        b_ok_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Decide(true); });
        b_deny_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Decide(false); });
        Bind(wxEVT_CLOSE_WINDOW, [this](wxCloseEvent&) { Finish(); });  // đóng bằng X = để đó, không đồng ý
        CentreOnParent();
    }
    uint32_t id() const { return id_; }
    void SetLeft(int s) { left_->SetLabelText(W(trf("recv.dlg.left", {fmt_countdown(s)}))); }
    void SetBusy(bool on) {
        b_ok_->Enable(!on);
        b_deny_->Enable(!on);
        if (on) busy_->Start(L("recv.busy.decide"));
        else busy_->Stop();
        decided_ = on;
        Layout();
        Fit();
    }
    void Finish() {
        if (done_) return;
        done_ = true;
        auto cb = std::move(closed_);
        Destroy();
        if (cb) cb();
    }

private:
    void Decide(bool approve) {
        if (decided_) return;
        SetBusy(true);
        decide_(id_, approve);
    }
    uint32_t id_;
    std::function<void(uint32_t, bool)> decide_;
    std::function<void()> closed_;
    BusyIndicator* busy_ = nullptr;
    wxStaticText *sas_ = nullptr, *left_ = nullptr;
    wxButton *b_ok_ = nullptr, *b_deny_ = nullptr;
    bool decided_ = false;
    bool done_ = false;
};

// ---------------------------------------------------------------- hộp thoại "Cho máy khác gửi tệp tới đây"
class InviteDialog : public wxDialog {
public:
    InviteDialog(wxWindow* parent, ReceiveBox& box);
    ~InviteDialog() override { *alive_ = false; }
    void OnInfo(const InviteListInfo& info);
    void DemoStart();

private:
    void BuildForm(wxWindow* p, wxSizer* v);
    void BuildCode(wxWindow* p, wxSizer* v);
    void BuildLists(wxWindow* p, wxSizer* v);
    ReceiverForm ReadForm() const;
    void SetStage(ReceiverStage s);
    void UpdateButtons();
    void Create(bool fix_permissions);
    void RebuildRows();
    void ShowProgress();
    void Relayout();
    void OnCloseRequest(wxCloseEvent& e);
    void CopyCode();

    ReceiveBox& box_;
    AliveFlag alive_ = make_alive();
    BusyIndicator* busy_ = nullptr;
    BusyIndicator* wait_ = nullptr;   // "Đang chờ máy kia…" (vòng quay riêng của mã đang hiện)
    wxScrolledWindow* page_ = nullptr;
    BusyGate gate_{nullptr, nullptr};
    ReceiverStage stage_ = ReceiverStage::Form;

    wxTextCtrl* folder_ = nullptr;
    wxButton *b_browse_ = nullptr, *b_create_ = nullptr, *b_fixperm_ = nullptr, *b_another_ = nullptr, *b_copy_ = nullptr,
             *b_close_ = nullptr, *b_details_ = nullptr;
    wxRadioButton *r_rw_ = nullptr, *r_ro_ = nullptr;
    wxChoice *ttl_ = nullptr, *uses_ = nullptr;
    wxCheckBox* ask_ = nullptr;
    WrapText *folder_err_ = nullptr, *create_err_ = nullptr, *copy_msg_ = nullptr, *addr_ = nullptr, *progress_ = nullptr,
             *detail_ = nullptr;
    wxTextCtrl* code_ = nullptr;
    wxPanel *code_panel_ = nullptr, *form_panel_ = nullptr;
    wxPanel* rows_joined_ = nullptr;
    wxPanel* rows_live_ = nullptr;
    wxBoxSizer *joined_box_ = nullptr, *live_box_ = nullptr;
    std::vector<wxWindow*> form_widgets_;

    std::string untrusted_;       // thư mục đang đề nghị khoá quyền
    std::string code_id_;         // id của mã vừa tạo
    InviteListInfo info_;
    std::string rows_sig_;
    bool have_info_ = false;
    bool demo_shot_taken_ = false;
};

InviteDialog::InviteDialog(wxWindow* parent, ReceiveBox& box)
    : wxDialog(parent, wxID_ANY, L("inv.dlg.title"), wxDefaultPosition, wxSize(700, 820),
               wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER),
      box_(box) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxEXPAND | wxALL, 8);
    page_ = new wxScrolledWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL);
    page_->SetScrollRate(0, 12);
    auto* v = new wxBoxSizer(wxVERTICAL);
    auto* title = new wxStaticText(page_, wxID_ANY, L("inv.dlg.title"));
    sp_font(title, 1.5);
    v->Add(title, 0, wxBOTTOM, 8);
    v->Add(new WrapText(page_, L("inv.dlg.intro")), 0, wxEXPAND | wxBOTTOM, 12);
    form_panel_ = new wxPanel(page_, wxID_ANY);   // the form folds away while a code is shown (less to read)
    auto* fv = new wxBoxSizer(wxVERTICAL);
    BuildForm(form_panel_, fv);
    form_panel_->SetSizer(fv);
    v->Add(form_panel_, 0, wxEXPAND);
    BuildCode(page_, v);
    BuildLists(page_, v);
    page_->SetSizer(v);
    top->Add(page_, 1, wxEXPAND | wxLEFT | wxRIGHT, 14);
    auto* bh = new wxBoxSizer(wxHORIZONTAL);
    b_close_ = new wxButton(this, wxID_ANY, L("inv.close"));
    bh->AddStretchSpacer(1);
    bh->Add(b_close_, 0);
    top->Add(bh, 0, wxEXPAND | wxALL, 12);
    SetSizer(top);
    SetMinSize(wxSize(560, 480));
    SetInitialSize(wxSize(700, std::min(860, wxGetClientDisplayRect().height - 60)));
    Centre();
    gate_ = BusyGate(page_, busy_);

    b_close_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Close(); });
    Bind(wxEVT_CLOSE_WINDOW, &InviteDialog::OnCloseRequest, this);
    SetStage(ReceiverStage::Form);
    folder_->ChangeValue(W(box_.DefaultFolder()));
    UpdateButtons();
    have_info_ = false;
}

void InviteDialog::BuildForm(wxWindow* p, wxSizer* v) {
    v->Add(new wxStaticText(p, wxID_ANY, L("inv.folder")), 0, wxBOTTOM, 4);
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    folder_ = new wxTextCtrl(p, wxID_ANY, "");
    folder_->SetHint(L("inv.folder.hint"));
    b_browse_ = new wxButton(p, wxID_ANY, L("inv.browse"));
    h->Add(folder_, 1, wxEXPAND | wxRIGHT, 8);
    h->Add(b_browse_, 0);
    v->Add(h, 0, wxEXPAND);
    folder_err_ = new WrapText(p, "");
    folder_err_->SetTextColour(kRed);
    folder_err_->Hide();
    v->Add(folder_err_, 0, wxEXPAND | wxTOP, 4);

    v->Add(new wxStaticText(p, wxID_ANY, L("inv.perm.label")), 0, wxTOP | wxBOTTOM, 6);
    auto* ph = new wxBoxSizer(wxHORIZONTAL);
    r_rw_ = new wxRadioButton(p, wxID_ANY, W(invite_perm_choice_text(simple::InvitePerm::ReadWrite)), wxDefaultPosition,
                              wxDefaultSize, wxRB_GROUP);
    r_ro_ = new wxRadioButton(p, wxID_ANY, W(invite_perm_choice_text(simple::InvitePerm::ReadOnly)));
    r_rw_->SetValue(true);
    ph->Add(r_rw_, 0, wxRIGHT, 16);
    ph->Add(r_ro_, 0);
    v->Add(ph, 0, wxLEFT, 8);

    auto* row = new wxFlexGridSizer(2, 8, 12);
    row->AddGrowableCol(1, 1);
    row->Add(new wxStaticText(p, wxID_ANY, L("inv.ttl.label")), 0, wxALIGN_CENTER_VERTICAL);
    ttl_ = new wxChoice(p, wxID_ANY);
    for (const TtlChoice& t : invite_ttl_choices()) ttl_->Append(W(t.label));
    ttl_->SetSelection(static_cast<int>(kDefaultTtlIndex));
    row->Add(ttl_, 0);
    row->Add(new wxStaticText(p, wxID_ANY, L("inv.uses.label")), 0, wxALIGN_CENTER_VERTICAL);
    uses_ = new wxChoice(p, wxID_ANY);
    for (const UsesChoice& u : invite_uses_choices()) uses_->Append(W(u.label));
    uses_->SetSelection(static_cast<int>(kDefaultUsesIndex));
    row->Add(uses_, 0);
    v->Add(row, 0, wxTOP, 12);

    ask_ = new wxCheckBox(p, wxID_ANY, L("inv.ask"));
    ask_->SetValue(true);
    v->Add(ask_, 0, wxTOP, 12);
    auto* tip = new WrapText(p, L("inv.ask.tip"));
    tip->SetTextColour(kGrey);
    v->Add(tip, 0, wxEXPAND | wxLEFT, 22);

    create_err_ = new WrapText(p, "");
    create_err_->SetTextColour(kRed);
    create_err_->Hide();
    v->Add(create_err_, 0, wxEXPAND | wxTOP, 10);
    b_fixperm_ = new wxButton(p, wxID_ANY, L("inv.fixperm"));
    b_fixperm_->Hide();
    v->Add(b_fixperm_, 0, wxTOP, 6);
    b_create_ = new wxButton(p, wxID_ANY, L("inv.create"));
    sp_font(b_create_, 1.15);
    v->Add(b_create_, 0, wxTOP, 14);

    form_widgets_ = {folder_, b_browse_, r_rw_, r_ro_, ttl_, uses_, ask_};

    b_browse_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        wxDirDialog dlg(this, L("inv.folder.dlg"), W(trim(S(folder_->GetValue()))), wxDD_NEW_DIR_BUTTON);
        if (dlg.ShowModal() != wxID_OK) return;
        folder_->SetValue(dlg.GetPath());
    });
    folder_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) {
        folder_err_->Hide();
        UpdateButtons();
        Relayout();
    });
    b_create_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Create(false); });
    b_fixperm_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (untrusted_.empty()) return;
        if (wxMessageBox(W(trf("inv.fixperm.confirm", {untrusted_})), L("inv.dlg.title"), wxYES_NO | wxICON_QUESTION, this) != wxYES) return;
        Create(true);
    });
}

void InviteDialog::BuildCode(wxWindow* p, wxSizer* v) {
    code_panel_ = new wxPanel(p, wxID_ANY);
    auto* cv = new wxBoxSizer(wxVERTICAL);
    cv->Add(new wxStaticText(code_panel_, wxID_ANY, L("inv.code.title")), 0, wxBOTTOM, 4);
    auto* ch = new wxBoxSizer(wxHORIZONTAL);
    code_ = new wxTextCtrl(code_panel_, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 60), wxTE_READONLY | wxTE_MULTILINE | wxTE_BESTWRAP);
    {
        wxFont f = code_->GetFont();
        f.SetFamily(wxFONTFAMILY_TELETYPE);
        code_->SetFont(f);
    }
    b_copy_ = new wxButton(code_panel_, wxID_ANY, L("inv.copy"));
    ch->Add(code_, 1, wxEXPAND | wxRIGHT, 6);
    ch->Add(b_copy_, 0, wxALIGN_TOP);
    cv->Add(ch, 0, wxEXPAND);
    copy_msg_ = new WrapText(code_panel_, "");
    copy_msg_->Hide();
    cv->Add(copy_msg_, 0, wxEXPAND | wxTOP, 4);
    addr_ = new WrapText(code_panel_, "");
    addr_->SetTextColour(kGrey);
    cv->Add(addr_, 0, wxEXPAND | wxTOP, 4);
    wait_ = new BusyIndicator(code_panel_);
    cv->Add(wait_, 0, wxEXPAND | wxTOP, 6);
    progress_ = new WrapText(code_panel_, "");
    progress_->Hide();
    cv->Add(progress_, 0, wxEXPAND | wxTOP, 4);
    b_another_ = new wxButton(code_panel_, wxID_ANY, L("inv.another"));
    cv->Add(b_another_, 0, wxTOP, 8);
    code_panel_->SetSizer(cv);
    code_panel_->Hide();
    v->Add(code_panel_, 0, wxEXPAND | wxTOP, 14);

    b_copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { CopyCode(); });
    b_another_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        SetStage(ReceiverStage::Form);
        create_err_->Hide();
        UpdateButtons();
        Relayout();
    });
}

void InviteDialog::BuildLists(wxWindow* p, wxSizer* v) {
    auto* t1 = new wxStaticText(p, wxID_ANY, L("inv.joined.title"));
    sp_font(t1, 1.15);
    v->Add(t1, 0, wxTOP, 18);
    rows_joined_ = new wxPanel(p, wxID_ANY);
    joined_box_ = new wxBoxSizer(wxVERTICAL);
    rows_joined_->SetSizer(joined_box_);
    v->Add(rows_joined_, 0, wxEXPAND | wxTOP, 4);
    auto* t2 = new wxStaticText(p, wxID_ANY, L("inv.live.title"));
    sp_font(t2, 1.15);
    v->Add(t2, 0, wxTOP, 14);
    rows_live_ = new wxPanel(p, wxID_ANY);
    live_box_ = new wxBoxSizer(wxVERTICAL);
    rows_live_->SetSizer(live_box_);
    v->Add(rows_live_, 0, wxEXPAND | wxTOP, 4);

    // Chi tiết (đóng sẵn): chỉ dấu vân tay của máy này.
    b_details_ = new wxButton(p, wxID_ANY, L("simple.svc.details.show"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    v->Add(b_details_, 0, wxTOP, 16);
    detail_ = new WrapText(p, "");
    detail_->SetTextColour(kGrey);
    detail_->Hide();
    v->Add(detail_, 0, wxEXPAND | wxTOP, 4);
    b_details_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        bool show = !detail_->IsShown();
        detail_->Show(show);
        b_details_->SetLabel(L(show ? "simple.svc.details.hide" : "simple.svc.details.show"));
        Relayout();
    });
}

ReceiverForm InviteDialog::ReadForm() const {
    ReceiverForm f;
    f.folder = check_receiver_folder(S(folder_->GetValue())).normalized;
    f.perm = r_ro_->GetValue() ? simple::InvitePerm::ReadOnly : simple::InvitePerm::ReadWrite;
    f.ttl_index = static_cast<size_t>(std::max(0, ttl_->GetSelection()));
    f.uses_index = static_cast<size_t>(std::max(0, uses_->GetSelection()));
    f.ask = ask_->GetValue();
    return f;
}

void InviteDialog::SetStage(ReceiverStage s) {
    stage_ = s;
    code_panel_->Show(s == ReceiverStage::Showing);
    form_panel_->Show(s != ReceiverStage::Showing);
    if (s != ReceiverStage::Showing) wait_->Stop();
    UpdateButtons();
}

void InviteDialog::UpdateButtons() {
    bool folder_ok = check_receiver_folder(S(folder_->GetValue())).ok;
    ReceiverButtons b = receiver_buttons(stage_, folder_ok, gate_.busy());
    for (wxWindow* w : form_widgets_) w->Enable(b.form && stage_ == ReceiverStage::Form);
    b_create_->Show(stage_ != ReceiverStage::Showing);
    b_create_->Enable(b.create);
    b_browse_->Enable(b.browse);
    b_copy_->Enable(b.copy);
    b_another_->Enable(b.another);
}

void InviteDialog::Relayout() {
    page_->Layout();
    page_->FitInside();
    Layout();
}

void InviteDialog::Create(bool fix_permissions) {
    FolderCheck fc = check_receiver_folder(S(folder_->GetValue()));
    if (!fc.ok) {
        folder_err_->SetText(W(fc.error));
        folder_err_->Show();
        Relayout();
        return;
    }
    if (stage_ != ReceiverStage::Form || gate_.busy()) return;
    create_err_->Hide();
    b_fixperm_->Hide();
    folder_err_->Hide();
    ReceiverForm form = ReadForm();
    SetStage(ReceiverStage::Working);
    gate_.begin("inv.busy.start");
    auto al = alive_;
    box_.CreateCode(form, fix_permissions, [this, al](bool ok, ReceiveBox::CreateResult& r, const std::string& err) {
        if (!*al) return;
        gate_.end();
        if (!ok || !r.ok) {
            SetStage(ReceiverStage::Form);
            std::string msg = ok ? r.error : err;
            if (ok && !r.untrusted_folder.empty()) {
                untrusted_ = r.untrusted_folder;
                create_err_->SetText(W(trf("inv.err.untrusted", {untrusted_})));
                b_fixperm_->Show();
            } else {
                create_err_->SetText(W(trf("inv.err.create", {friendly_error(msg)})));
                b_fixperm_->Hide();
            }
            create_err_->Show();
            Relayout();
            return;
        }
        code_id_ = invite_code_id_hex(r.code);
        code_->SetValue(W(r.code));
        copy_msg_->Hide();
        SetStage(ReceiverStage::Showing);
        OnInfo(r.info);
        Relayout();
        page_->Scroll(0, 0);
        if (!simple_test_hooks().invite_demo_png.empty() && !demo_shot_taken_) {
            demo_shot_taken_ = true;
            auto* t = new wxTimer;
            t->Bind(wxEVT_TIMER, [this, al, t](wxTimerEvent&) {
                t->Stop();
                if (!*al) return;
                std::string e = save_window_png(this, simple_test_hooks().invite_demo_png);
                if (!e.empty()) wxLogError("%s", W(e));
                if (wxTheApp && wxTheApp->GetTopWindow()) wxTheApp->GetTopWindow()->Close(true);
            });
            t->StartOnce(1800);
        }
    });
}

void InviteDialog::DemoStart() {
    folder_->ChangeValue(W(simple_test_hooks().invite_demo_folder));
    UpdateButtons();
    Create(false);
}

void InviteDialog::CopyCode() {
    if (code_->GetValue().empty()) return;
    if (wxTheClipboard->Open()) {
        wxTheClipboard->SetData(new wxTextDataObject(code_->GetValue()));
        wxTheClipboard->Close();
        copy_msg_->SetText(L("inv.copied"));
        copy_msg_->SetTextColour(kGreen);
        copy_msg_->Show();
        Relayout();
    } else {
        box_.ctx().sh->report(BannerLevel::Warning, "simple.recv.copy", tr("inv.copyfail"));
    }
}

void InviteDialog::OnCloseRequest(wxCloseEvent&) {
    box_.DialogClosed();
    Destroy();
}

void InviteDialog::OnInfo(const InviteListInfo& in) {
    info_ = in;
    have_info_ = true;
    const std::string& demo = simple_test_hooks().invite_demo_joined;
    if (!demo.empty()) {   // chỉ ảnh tài liệu: một máy mẫu đã vào (hiển thị, không có thật)
        JoinedMachineView j;
        j.name = demo;
        j.key_hex = std::string(64, 'a');
        j.when_utc = "2026-11-02 07:30";
        info_.joined.push_back(j);
    }
    if (!info_.fingerprint.empty()) detail_->SetText(W(trf("inv.fp.self", {info_.fingerprint})));
    RebuildRows();
    ShowProgress();
}

void InviteDialog::ShowProgress() {
    if (stage_ != ReceiverStage::Showing) return;
    if (!info_.fingerprint.empty() || info_.port) {
        addr_->SetText(W(firewall_hint(info_.port)));
    }
    CodeProgress p = code_progress(info_, code_id_, now_unix());
    if (p.kind == CodeProgress::Waiting) {
        wait_->Start(W(p.text));
        progress_->Hide();
    } else {
        wait_->Stop();
        progress_->SetText(W(p.text));
        progress_->SetTextColour(p.kind == CodeProgress::Joined ? kGreen : kGrey);
        progress_->Show();
    }
    Relayout();
}

void InviteDialog::RebuildRows() {
    std::vector<JoinedRow> jr = joined_rows(info_);
    std::vector<LiveRow> lr = live_rows(info_, now_unix());
    std::string sig;
    for (const auto& r : jr) sig += "J|" + r.key_hex + "|" + r.title + "|" + r.detail + "\n";
    for (const auto& r : lr) sig += "L|" + r.id_hex + "|" + r.title + "|" + r.detail + "\n";
    if (sig == rows_sig_) return;   // không dựng lại khi không đổi: nút đang được rê chuột không bị giật
    rows_sig_ = sig;
    joined_box_->Clear(true);
    live_box_->Clear(true);
    auto add_row = [&](wxWindow* parent, wxBoxSizer* box, const std::string& title, const std::string& detail, const char* btn_key,
                       std::function<void()> on_click) {
        auto* row = new wxBoxSizer(wxHORIZONTAL);
        auto* col = new wxBoxSizer(wxVERTICAL);
        auto* t = new wxStaticText(parent, wxID_ANY, W(title));
        sp_font(t, 1.0);
        auto* d = new wxStaticText(parent, wxID_ANY, W(detail));
        d->SetForegroundColour(kGrey);
        col->Add(t, 0);
        col->Add(d, 0);
        row->Add(col, 1, wxALIGN_CENTER_VERTICAL);
        auto* b = new wxButton(parent, wxID_ANY, L(btn_key), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
        b->Bind(wxEVT_BUTTON, [on_click](wxCommandEvent&) { on_click(); });
        row->Add(b, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 8);
        box->Add(row, 0, wxEXPAND | wxTOP | wxBOTTOM, 4);
    };
    auto al = alive_;
    if (jr.empty()) {
        auto* n = new wxStaticText(rows_joined_, wxID_ANY, L("inv.joined.none"));
        n->SetForegroundColour(kGrey);
        joined_box_->Add(n, 0);
    }
    for (const JoinedRow& r : jr) {
        add_row(rows_joined_, joined_box_, r.title, r.detail, "inv.remove", [this, al, r] {
            if (!*al || gate_.busy()) return;
            if (wxMessageBox(W(trf("inv.remove.confirm", {r.title})), L("inv.dlg.title"), wxYES_NO | wxICON_QUESTION, this) != wxYES)
                return;
            gate_.begin("inv.busy.remove");
            box_.RemoveMachine(r.key_hex, [this, al](bool ok, InviteListInfo& info, const std::string& err) {
                if (!*al) return;
                gate_.end();
                UpdateButtons();
                if (!ok) {
                    box_.ctx().sh->report(BannerLevel::Error, "simple.recv", err);
                    return;
                }
                box_.ctx().sh->clear_report("simple.recv");
                OnInfo(info);
            });
        });
    }
    if (lr.empty()) {
        auto* n = new wxStaticText(rows_live_, wxID_ANY, L("inv.live.none"));
        n->SetForegroundColour(kGrey);
        live_box_->Add(n, 0);
    }
    for (const LiveRow& r : lr) {
        add_row(rows_live_, live_box_, r.title, r.detail, "inv.revoke", [this, al, r] {
            if (!*al || gate_.busy()) return;
            if (wxMessageBox(L("inv.revoke.confirm"), L("inv.dlg.title"), wxYES_NO | wxICON_QUESTION, this) != wxYES) return;
            gate_.begin("inv.busy.revoke");
            box_.RevokeInvite(r.id_hex, [this, al](bool ok, InviteListInfo& info, const std::string& err) {
                if (!*al) return;
                gate_.end();
                UpdateButtons();
                if (!ok) {
                    box_.ctx().sh->report(BannerLevel::Error, "simple.recv", err);
                    return;
                }
                box_.ctx().sh->clear_report("simple.recv");
                OnInfo(info);
            });
        });
    }
    rows_joined_->Layout();
    rows_live_->Layout();
    Relayout();
}

// ---------------------------------------------------------------- ô trên màn Trạng thái + bộ canh
ReceiveBox::ReceiveBox(wxWindow* parent, SimpleCtx& c) : wxPanel(parent, wxID_ANY), c_(c), timer_(this) {
    auto* v = new wxStaticBoxSizer(wxVERTICAL, this, L("inv.title"));
    auto* sb = v->GetStaticBox();
    auto* hint = new WrapText(sb, L("inv.btn.hint"));
    v->Add(hint, 0, wxEXPAND | wxALL, 8);
    auto* b = new wxButton(sb, wxID_ANY, L("inv.btn"));
    v->Add(b, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);
    SetSizer(v);
    b->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { OpenDialog(); });
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { Tick(); });
}

ReceiveBox::~ReceiveBox() {
    *alive_ = false;
    timer_.Stop();
}

std::string ReceiveBox::DefaultFolder() const {
    return SimpleHost::default_receive_folder();
}

void ReceiveBox::Watch(bool on) {
    watching_ = on;
    if (on) timer_.Start(2000);
    else timer_.Stop();
}

void ReceiveBox::RestoreAtStartup() {
    // Đã tạo mã lần trước: MainFrame đã bật bộ nhận; ở đây chỉ canh các yêu cầu cần người dùng đồng ý.
    if (c_.sh->get_setting("recv.on", "0") == "1" && c_.host->has_receiver_config()) Watch(true);
}

void ReceiveBox::OpenDialog() {
    if (dlg_) {
        dlg_->Raise();
        return;
    }
    dlg_ = new InviteDialog(wxGetTopLevelParent(this), *this);
    dlg_->Show();
    dlg_->Raise();
    if (watching_) Tick();
}

void ReceiveBox::AutoDemo() {
    OpenDialog();
    if (dlg_) dlg_->DemoStart();
}

void ReceiveBox::Tick() {
    if (!watching_ || ticking_ || working_) return;
    ticking_ = true;
    std::string name = c_.host->paths().receiver_control_name;
    run_async<InviteListInfo>(
        alive_,
        [name]() {
            ControlClient cc(name, 1500);
            return cc.invite_list();
        },
        [this](bool ok, InviteListInfo& info, const std::string& err) {
            ticking_ = false;
            if (!ok) {
                c_.sh->report(BannerLevel::Warning, "simple.recv", trf("inv.err.poll", {err}));
                return;
            }
            c_.sh->clear_report("simple.recv");
            OnInfo(info);
        });
}

void ReceiveBox::OnInfo(const InviteListInfo& info) {
    if (dlg_) dlg_->OnInfo(info);
    // Yêu cầu đang chờ người dùng đồng ý.
    if (approve_) {
        bool still = false;
        for (const auto& p : info.pending)
            if (p.id == approve_id_) {
                still = true;
                approve_->SetLeft(p.seconds_left);
            }
        if (!still) approve_->Finish();   // hết hạn hoặc đã xử lý ở nơi khác
    }
    if (!approve_)
        if (const simple::PendingInvite* p = first_pending(info, dismissed_)) ShowApprove(*p);
}

void ReceiveBox::ShowApprove(const simple::PendingInvite& p) {
    approve_id_ = p.id;
    if (c_.attention) c_.attention();
    wxWindow* top = wxGetTopLevelParent(this);
    approve_ = new ApproveDialog(
        top, p,
        [this](uint32_t id, bool approve) {
            std::string name = c_.host->paths().receiver_control_name;
            run_async<InviteListInfo>(
                alive_,
                [name, id, approve]() {
                    ControlClient cc(name, 8000);
                    return approve ? cc.invite_approve(id) : cc.invite_deny(id);
                },
                [this, id, approve](bool ok, InviteListInfo& info, const std::string& err) {
                    dismissed_.push_back(id);
                    if (approve_ && approve_id_ == id) approve_->Finish();
                    if (!ok) {
                        c_.sh->report(BannerLevel::Error, "simple.recv", err);
                        return;
                    }
                    c_.sh->clear_report("simple.recv");
                    OnInfo(info);
                });
        },
        [this] {
            dismissed_.push_back(approve_id_);   // đã đóng: không bật lại cùng yêu cầu
            approve_ = nullptr;
        });
    approve_->Show();
    approve_->Raise();
}

void ReceiveBox::CreateCode(const ReceiverForm& form, bool fix_permissions,
                            std::function<void(bool, CreateResult&, const std::string&)> done) {
    working_ = true;
    SimpleHost* host = c_.host;
    run_async<CreateResult>(
        alive_,
        [host, form, fix_permissions]() {
            CreateResult r;
            const simple::UserPaths& paths = host->paths();
            std::vector<std::string> ips = SimpleHost::local_addresses();
            simple::ReceiverSettings rs;
            bool has_cfg = simple::read_receiver_settings(paths, &rs);
            try {
                prepare_receiver_folder(form.folder, fix_permissions);   // tạo riêng tư nếu chưa có; kiểm thư mục tài khoản khác ghi được
            } catch (const UntrustedFolderError& e) {
                r.untrusted_folder = e.path;
                r.error = e.what();
                return r;
            }
            // Lần đầu: cấu hình nhận lấy chính thư mục này làm gốc. Những lần sau cấu hình giữ nguyên (mỗi mã mang thư mục riêng).
            if (!has_cfg) simple::ensure_receiver_config(form.folder, paths, 5656);
            if (!host->supervisor_ready()) host->start_supervisor(host->has_config(), true);
            host->sup()->set_receiver_enabled(true);   // idempotent
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(25);
            std::string last;
            InviteListInfo info;
            for (;;) {
                simple::EngineInfo ei = host->receiver_info();
                if (ei.state == simple::EngineState::GaveUp) throw Error(ei.last_error.empty() ? tr("inv.err.gaveup") : ei.last_error);
                try {
                    ControlClient cc(paths.receiver_control_name, 2000);
                    info = cc.invite_list();
                    if (info.allowed) break;
                    last = tr("inv.err.gaveup");
                } catch (const std::exception& e) {
                    last = e.what();
                }
                if (std::chrono::steady_clock::now() > deadline) throw Error(trf("inv.err.nostart", {last}));
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
            std::vector<simple::InviteAddr> addrs = choose_invite_addrs(ips, info.port);
            if (addrs.empty()) throw Error(tr("inv.noip"));
            InviteCreateReq req;
            req.folder = form.folder;   // the ABSOLUTE folder the code hands out
            req.label = folder_label(form.folder);
            req.perm = form.perm;
            std::vector<TtlChoice> ttl = invite_ttl_choices();
            std::vector<UsesChoice> uses = invite_uses_choices();
            req.ttl_seconds = static_cast<uint32_t>(ttl[std::min(form.ttl_index, ttl.size() - 1)].seconds);
            req.uses = static_cast<uint32_t>(uses[std::min(form.uses_index, uses.size() - 1)].uses);
            req.ask = form.ask;
            req.addrs = addrs;
            ControlClient cc(paths.receiver_control_name, 10000);
            r.info = cc.invite_create(req);
            r.code = r.info.created_code;
            r.info.created_code.clear();   // đã chuyển vào r.code; danh sách không giữ mã
            r.ok = true;
            return r;
        },
        [this, done](bool ok, CreateResult& r, const std::string& err) {
            working_ = false;
            if (ok && r.ok) {
                c_.sh->clear_report("simple.recv");
                c_.sh->set_setting("recv.on", "1");
                if (!watching_) Watch(true);
            }
            done(ok, r, err);
        });
}

void ReceiveBox::RemoveMachine(const std::string& key_hex, std::function<void(bool, InviteListInfo&, const std::string&)> done) {
    std::string name = c_.host->paths().receiver_control_name;
    run_async<InviteListInfo>(
        alive_,
        [name, key_hex]() {
            ControlClient cc(name, 10000);
            return cc.invite_remove_machine(key_hex);
        },
        [done](bool ok, InviteListInfo& info, const std::string& err) { done(ok, info, err); });
}

void ReceiveBox::RevokeInvite(const std::string& id_hex, std::function<void(bool, InviteListInfo&, const std::string&)> done) {
    std::string name = c_.host->paths().receiver_control_name;
    run_async<InviteListInfo>(
        alive_,
        [name, id_hex]() {
            ControlClient cc(name, 10000);
            return cc.invite_revoke(id_hex);
        },
        [done](bool ok, InviteListInfo& info, const std::string& err) { done(ok, info, err); });
}

}  // namespace mysync::gui
