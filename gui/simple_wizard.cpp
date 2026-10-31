// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// Trình hướng dẫn 3 bước của chế độ Đơn giản: (1) thư mục cần đồng bộ, (2) nơi lưu, (3) bắt đầu.
#include <wx/dirdlg.h>

#include "form_model.h"
#include "mysync/keys.h"
#include "mysync/simple/autostart.h"
#include "simple_panel.h"

namespace mysync::gui {

namespace {
const wxColour kRed(0xA0, 0x10, 0x10), kGreen(0x1E, 0x7E, 0x34), kAmber(0x8A, 0x5A, 0x00), kGrey(0x55, 0x55, 0x55);

std::string join_nl(const std::vector<std::string>& v) {
    std::string o;
    for (const auto& s : v) o += (o.empty() ? "" : "\n") + s;
    return o;
}
}  // namespace

WizardPage::WizardPage(wxWindow* parent, SimpleCtx& c, std::function<void()> done, std::function<void()> cancel)
    : wxPanel(parent, wxID_ANY), c_(c), done_(std::move(done)), cancel_(std::move(cancel)), pair_timer_(this),
      auto_timer_(this, wxID_HIGHEST + 77) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxEXPAND | wxALL, 8);
    content_ = new wxPanel(this, wxID_ANY);
    root_ = new wxBoxSizer(wxVERTICAL);

    stepno_ = new wxStaticText(content_, wxID_ANY, "");
    stepno_->SetForegroundColour(kGrey);
    title_ = new wxStaticText(content_, wxID_ANY, "");
    sp_font(title_, 1.5);
    root_->Add(stepno_, 0, wxLEFT | wxRIGHT | wxTOP, 16);
    root_->Add(title_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 16);

    book_ = new wxSimplebook(content_, wxID_ANY);
    auto* p1 = new wxPanel(book_);
    auto* p2 = new wxPanel(book_);
    auto* p3 = new wxPanel(book_);
    BuildSource(p1);
    BuildDest(p2);
    BuildFinish(p3);
    book_->AddPage(p1, "1");
    book_->AddPage(p2, "2");
    book_->AddPage(p3, "3");
    root_->Add(book_, 1, wxEXPAND | wxLEFT | wxRIGHT, 16);

    auto* nav = new wxBoxSizer(wxHORIZONTAL);
    b_quit_ = new wxButton(content_, wxID_ANY, L("btn.cancel"));
    b_back_ = new wxButton(content_, wxID_ANY, L("wizard.back"));
    b_next_ = new wxButton(content_, wxID_ANY, L("wizard.next"));
    b_start_ = new wxButton(content_, wxID_ANY, L("wizard.start"));
    sp_font(b_start_, 1.2);
    nav->Add(b_quit_, 0, wxRIGHT, 8);
    nav->AddStretchSpacer(1);
    nav->Add(b_back_, 0, wxRIGHT, 8);
    nav->Add(b_next_, 0);
    nav->Add(b_start_, 0);
    root_->Add(nav, 0, wxEXPAND | wxALL, 16);
    content_->SetSizer(root_);
    top->Add(content_, 1, wxEXPAND);
    SetSizer(top);

    b_quit_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!IsBusy() && cancel_) cancel_();
    });
    b_back_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!IsBusy() && m_.back()) ShowStep();
    });
    b_next_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { CheckInput(true); });
    b_start_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Begin(); });
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { PairTick(); }, pair_timer_.GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { AutoStep(); }, auto_timer_.GetId());
    Restart(false);
}

WizardPage::~WizardPage() {
    *alive_ = false;
    pair_timer_.Stop();
    auto_timer_.Stop();
    if (pair_) pair_->cancel = true;
}

void WizardPage::SetBusy(bool on, const char* key) {
    busy_flag_ = on;
    if (on) {
        content_->Enable(false);
        busy_->Start(L(key));
    } else {
        content_->Enable(true);
        busy_->Stop();
    }
}

void WizardPage::BuildSource(wxWindow* p) {
    auto* v = new wxBoxSizer(wxVERTICAL);
    v->Add(new wxStaticText(p, wxID_ANY, L("wizard.s1.intro")), 0, wxBOTTOM, 10);
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    src_ = new wxTextCtrl(p, wxID_ANY, "");
    src_->SetHint(L("wizard.s1.hint"));
    b_src_ = new wxButton(p, wxID_ANY, L("wizard.pick"));
    h->Add(src_, 1, wxEXPAND | wxRIGHT, 8);
    h->Add(b_src_, 0);
    v->Add(h, 0, wxEXPAND);
    auto* tip = new wxStaticText(p, wxID_ANY, L("wizard.s1.drop"));
    tip->SetForegroundColour(kGrey);
    v->Add(tip, 0, wxTOP, 8);
    src_err_ = new WrapText(p, "");
    src_err_->SetTextColour(kRed);
    src_err_->Hide();
    v->Add(src_err_, 0, wxEXPAND | wxTOP, 10);
    p->SetSizer(v);
    b_src_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ChooseSource(); });
    src_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent&) { CheckInput(true); });
}

void WizardPage::BuildDest(wxWindow* p) {
    auto* v = new wxBoxSizer(wxVERTICAL);
    v->Add(new wxStaticText(p, wxID_ANY, L("wizard.s2.intro")), 0, wxBOTTOM, 10);

    r_folder_ = new wxRadioButton(p, wxID_ANY, L("wizard.s2.folder"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
    r_machine_ = new wxRadioButton(p, wxID_ANY, L("wizard.s2.machine"));
    r_folder_->SetValue(true);

    v->Add(r_folder_, 0, wxBOTTOM, 4);
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    dst_ = new wxTextCtrl(p, wxID_ANY, "");
    dst_->SetHint(L("wizard.s2.folder.hint"));
    b_dst_ = new wxButton(p, wxID_ANY, L("wizard.pick"));
    h->Add(dst_, 1, wxEXPAND | wxRIGHT, 8);
    h->Add(b_dst_, 0);
    v->Add(h, 0, wxEXPAND | wxLEFT, 24);
    auto* tip = new wxStaticText(p, wxID_ANY, L("wizard.s2.folder.tip"));
    tip->SetForegroundColour(kGrey);
    v->Add(tip, 0, wxLEFT | wxTOP, 24);
    dst_err_ = new WrapText(p, "");
    dst_err_->SetTextColour(kRed);
    dst_err_->Hide();
    v->Add(dst_err_, 0, wxEXPAND | wxLEFT | wxTOP, 24);

    v->AddSpacer(14);
    v->Add(r_machine_, 0, wxBOTTOM, 4);
    auto* mv = new wxBoxSizer(wxVERTICAL);
    mv->Add(new wxStaticText(p, wxID_ANY, L("wizard.s2.machine.how")), 0, wxBOTTOM, 4);
    code_ = new wxTextCtrl(p, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 54), wxTE_MULTILINE | wxTE_BESTWRAP);
    code_->SetHint(L("wizard.s2.code.hint"));
    mv->Add(code_, 0, wxEXPAND);
    auto* bh = new wxBoxSizer(wxHORIZONTAL);
    b_send_ = new wxButton(p, wxID_ANY, L("wizard.s2.send"));
    b_pcancel_ = new wxButton(p, wxID_ANY, L("btn.cancel"));
    b_pcancel_->Hide();
    bh->Add(b_send_, 0, wxRIGHT, 8);
    bh->Add(b_pcancel_, 0);
    mv->Add(bh, 0, wxTOP, 6);
    sas_hint_ = new wxStaticText(p, wxID_ANY, L("wizard.s2.sas.hint"));
    sas_hint_->Hide();
    sas_ = new wxStaticText(p, wxID_ANY, "");
    sp_font(sas_, 2.0);
    {
        wxFont f = sas_->GetFont();
        f.SetFamily(wxFONTFAMILY_TELETYPE);
        sas_->SetFont(f);
    }
    sas_->Hide();
    mv->Add(sas_hint_, 0, wxTOP, 8);
    mv->Add(sas_, 0, wxTOP | wxBOTTOM, 4);
    pair_busy_ = new BusyIndicator(p);
    mv->Add(pair_busy_, 0, wxEXPAND);
    pair_msg_ = new WrapText(p, "");
    pair_msg_->Hide();
    mv->Add(pair_msg_, 0, wxEXPAND | wxTOP, 4);
    v->Add(mv, 0, wxEXPAND | wxLEFT, 24);
    p->SetSizer(v);

    b_dst_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ChooseDest(); });
    r_folder_->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) { UpdateDestEnable(); });
    r_machine_->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) { UpdateDestEnable(); });
    b_send_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { SendPairRequest(); });
    b_pcancel_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { CancelPair(); });
    code_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) {
        if (pair_running_) return;
        // Sửa mã sau khi đã ghép: bỏ kết quả ghép cũ, phải gửi lại.
        m_.clear_paired();
        sas_->Hide();
        sas_hint_->Hide();
        pair_msg_->Hide();
        Layout();
    });
}

void WizardPage::BuildFinish(wxWindow* p) {
    auto* v = new wxBoxSizer(wxVERTICAL);
    v->Add(new wxStaticText(p, wxID_ANY, L("wizard.s3.intro")), 0, wxBOTTOM, 10);
    summary_ = new WrapText(p, "");
    sp_font(summary_, 1.1, false);
    v->Add(summary_, 0, wxEXPAND | wxBOTTOM, 14);
    auto* note = new WrapText(p, L("wizard.s3.note"));
    note->SetTextColour(kGrey);
    v->Add(note, 0, wxEXPAND);
    p->SetSizer(v);
}

void WizardPage::UpdateDestEnable() {
    bool folder = r_folder_->GetValue();
    dst_->Enable(folder);
    b_dst_->Enable(folder);
    code_->Enable(!folder && !pair_running_);
    b_send_->Enable(!folder && !pair_running_);
    m_.set_kind(folder ? simple::DestKind::Folder : simple::DestKind::PairedMachine);
}

void WizardPage::Restart(bool can_cancel) {
    if (pair_) pair_->cancel = true;
    pair_running_ = false;
    pair_timer_.Stop();
    m_.reset();
    src_->SetValue("");
    dst_->SetValue("");
    code_->SetValue("");
    r_folder_->SetValue(true);
    src_err_->Hide();
    dst_err_->Hide();
    sas_->Hide();
    sas_hint_->Hide();
    pair_msg_->Hide();
    pair_busy_->Stop();
    b_pcancel_->Hide();
    b_quit_->Show(can_cancel);
    UpdateDestEnable();
    ShowStep();
}

void WizardPage::ShowStep() {
    int s = static_cast<int>(m_.step());
    book_->ChangeSelection(static_cast<size_t>(s));
    stepno_->SetLabelText(W(trf("wizard.stepno", {std::to_string(s + 1)})));
    static const char* kTitles[] = {"wizard.s1.title", "wizard.s2.title", "wizard.s3.title"};
    title_->SetLabelText(L(kTitles[s]));
    b_back_->Show(s > 0);
    b_next_->Show(s < 2);
    b_start_->Show(s == 2);
    if (s == 2) summary_->SetText(W(m_.summary()));
    content_->Layout();
    Layout();
}

void WizardPage::ChooseSource() {
    wxDirDialog dlg(this, L("wizard.s1.dlg"), W(trim(S(src_->GetValue()))), wxDD_DIR_MUST_EXIST | wxDD_NEW_DIR_BUTTON);
    if (dlg.ShowModal() != wxID_OK) return;
    src_->SetValue(dlg.GetPath());
    CheckInput(false);
}

void WizardPage::ChooseDest() {
    wxDirDialog dlg(this, L("wizard.s2.dlg"), W(trim(S(dst_->GetValue()))), wxDD_NEW_DIR_BUTTON);
    if (dlg.ShowModal() != wxID_OK) return;
    dst_->SetValue(dlg.GetPath());
    CheckInput(false);
}

void WizardPage::DropFolder(const std::string& path) {
    if (IsBusy()) return;
    if (m_.step() == WizardStep::Dest && r_folder_->GetValue()) {
        dst_->SetValue(W(path));
    } else if (m_.step() == WizardStep::Source) {
        src_->SetValue(W(path));
    } else {
        return;
    }
    CheckInput(false);
}

void WizardPage::CheckInput(bool advance) {
    if (busy_flag_ || pair_running_) return;
    m_.set_source(trim(S(src_->GetValue())));
    bool folder = r_folder_->GetValue();
    m_.set_kind(folder ? simple::DestKind::Folder : simple::DestKind::PairedMachine);
    if (folder) m_.set_dest_path(trim(S(dst_->GetValue())));
    simple::WizardInput in = m_.input();
    SetBusy(true, "wizard.busy.check");
    run_async<std::vector<simple::WizardIssue>>(
        alive_, [in]() { return simple::validate_wizard(in); },
        [this, advance](bool ok, std::vector<simple::WizardIssue>& issues, const std::string& err) {
            SetBusy(false, "");
            if (!ok) {
                c_.sh->report(BannerLevel::Error, "simple.wizard", err);
                return;
            }
            c_.sh->clear_report("simple.wizard");
            m_.apply_validation(issues);
            auto a = m_.issues_for(WizardStep::Source);
            src_err_->SetText(W(join_nl(a)));
            src_err_->Show(!a.empty());
            if (m_.step() == WizardStep::Dest) {
                auto b = m_.issues_for(WizardStep::Dest);
                dst_err_->SetText(W(join_nl(b)));
                dst_err_->Show(!b.empty());
            } else {
                dst_err_->Hide();
            }
            if (advance && m_.next()) ShowStep();
            content_->Layout();
            Layout();
        });
}

void WizardPage::CancelPair() {
    if (pair_) pair_->cancel = true;
}

void WizardPage::SendPairRequest() {
    if (pair_running_ || busy_flag_) return;
    simple::PairCode code;
    std::string e = check_pair_code_text(S(code_->GetValue()), &code);
    if (!e.empty()) {
        pair_msg_->SetText(W(e));
        pair_msg_->SetTextColour(kRed);
        pair_msg_->Show();
        sas_->Hide();
        sas_hint_->Hide();
        Layout();
        return;
    }
    KeyPair self;
    try {
        self = SimpleHost::load_or_create_client_key(c_.host->paths());
    } catch (const std::exception& ex) {
        pair_msg_->SetText(W(ex.what()));
        pair_msg_->SetTextColour(kRed);
        pair_msg_->Show();
        Layout();
        return;
    }
    // Chuỗi xác nhận tính được ngay từ hai khoá công khai: hiện trước khi chờ để hai bên so cùng lúc.
    sas_->SetLabelText(W(sas_display(simple::pair_sas(self.pub, code.server_key))));
    sas_->Show();
    sas_hint_->Show();
    pair_msg_->Hide();
    pair_ = std::make_shared<PairRun>();
    pair_running_ = true;
    b_send_->Disable();
    code_->Disable();
    r_folder_->Disable();
    r_machine_->Disable();
    b_dst_->Disable();
    b_next_->Disable();
    b_back_->Disable();
    b_pcancel_->Show();
    pair_busy_->Start(L("pair.waiting"));
    pair_timer_.Start(prefers_reduced_motion() ? 1000 : 500);
    auto run = pair_;
    run_async<simple::PairOutcome>(
        alive_,
        [code, self, run]() {
            simple::PairingClient pc(code, self, simple::default_device_name());
            return pc.run(run->cancel, [run](int s) { run->secs = s; });
        },
        [this, run, code](bool ok, simple::PairOutcome& o, const std::string& err) {
            if (pair_ != run) return;  // lượt cũ đã bị thay
            pair_running_ = false;
            pair_timer_.Stop();
            pair_busy_->Stop();
            b_pcancel_->Hide();
            r_folder_->Enable();
            r_machine_->Enable();
            b_next_->Enable();
            b_back_->Enable();
            code_->Enable();
            b_send_->Enable();
            UpdateDestEnable();
            if (!ok) {
                pair_msg_->SetText(W(err));
                pair_msg_->SetTextColour(kRed);
                sas_->Hide();
                sas_hint_->Hide();
            } else if (o.kind == simple::PairOutcome::Approved) {
                m_.set_paired(code);
                pair_msg_->SetText(W(pair_outcome_text(o)));
                pair_msg_->SetTextColour(kGreen);
            } else {
                pair_msg_->SetText(W(pair_outcome_text(o)));
                pair_msg_->SetTextColour(o.kind == simple::PairOutcome::Failed ? kRed : kAmber);
                sas_->Hide();
                sas_hint_->Hide();
            }
            pair_msg_->Show();
            content_->Layout();
            Layout();
        });
    Layout();
}

void WizardPage::PairTick() {
    if (!pair_running_ || !pair_) return;
    int s = pair_->secs.load();
    pair_busy_->Start(s >= 0 ? W(trf("pair.waiting_left", {fmt_countdown(s)})) : L("pair.waiting"));
}

void WizardPage::AutoDrive(const std::string& src, const std::string& dst) {
    auto_src_ = src;
    auto_dst_ = dst;
    auto_ = true;
    auto_timer_.Start(500);
}

void WizardPage::AutoStep() {
    if (!auto_ || IsBusy()) return;
    switch (m_.step()) {
        case WizardStep::Source:
            if (src_->GetValue().empty()) src_->SetValue(W(auto_src_));
            if (simple_test_hooks().auto_stop == 0) {  // chụp ảnh tài liệu: dừng ở bước 1 với thư mục đã chọn
                auto_ = false;
                auto_timer_.Stop();
                CheckInput(false);
                break;
            }
            CheckInput(true);
            break;
        case WizardStep::Dest:
            if (dst_->GetValue().empty()) dst_->SetValue(W(auto_dst_));
            if (simple_test_hooks().auto_stop == 1) {
                auto_ = false;
                auto_timer_.Stop();
                CheckInput(false);
                break;
            }
            CheckInput(true);
            break;
        case WizardStep::Finish:
            if (simple_test_hooks().auto_stop == 2) {
                auto_ = false;
                auto_timer_.Stop();
                break;
            }
            auto_ = false;
            auto_timer_.Stop();
            Begin();
            break;
    }
}

void WizardPage::Begin() {
    if (busy_flag_) return;
    simple::WizardInput in = m_.input();
    SimpleHost* host = c_.host;
    SetBusy(true, "wizard.busy.start");
    run_async<int>(
        alive_,
        [in, host]() {
            simple::save_wizard(in, host->paths());
            host->apply_client_config();
            return 0;
        },
        [this](bool ok, int&, const std::string& err) {
            SetBusy(false, "");
            if (!ok) {
                c_.sh->report(BannerLevel::Error, "simple.wizard", friendly_error(err));
                return;
            }
            c_.sh->clear_report("simple.wizard");
            // Lần đầu hoàn tất: bật "Tự chạy khi tôi đăng nhập" (có thể tắt ở màn Trạng thái).
            if (c_.sh->get_setting("simple.autostart_init", "") != "1") {
                try {
                    simple::set_autostart(true);
                } catch (const std::exception& e) {
                    c_.sh->report(BannerLevel::Warning, "simple.autostart", std::string(S(L("simple.autostart.fail"))) + " " + e.what());
                }
                c_.sh->set_setting("simple.autostart_init", "1");
            }
            if (done_) done_();
        });
}

}  // namespace mysync::gui
