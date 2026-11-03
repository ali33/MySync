// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// Trình hướng dẫn 3 bước của chế độ Đơn giản: (1) thư mục cần đồng bộ, (2) nơi lưu, (3) bắt đầu.
// Bước 2 có hai cách: thư mục / USB / thư mục chia sẻ, hoặc "máy khác có cài MySync" = dán MỘT mã mời (MSY2). Mã được kiểm
// ngay khi dán (nền, có chỉ báo động): dạng, tổng kiểm, hạn, rồi hỏi máy kia (probe_invite, chạy thử, chưa dùng mã). Việc
// dùng mã thật (redeem_invite) xảy ra ở "Bắt đầu đồng bộ"; xong mới ghi cấu hình như mọi đích khác.
#include <wx/dirdlg.h>

#include <ctime>

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

int64_t now_unix() { return static_cast<int64_t>(std::time(nullptr)); }
}  // namespace

WizardPage::WizardPage(wxWindow* parent, SimpleCtx& c, std::function<void()> done, std::function<void()> cancel)
    : wxPanel(parent, wxID_ANY), c_(c), done_(std::move(done)), cancel_(std::move(cancel)), join_timer_(this),
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
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { JoinTick(); }, join_timer_.GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { AutoStep(); }, auto_timer_.GetId());
    Restart(false);
}

WizardPage::~WizardPage() {
    *alive_ = false;
    join_timer_.Stop();
    auto_timer_.Stop();
    if (join_) join_->cancel = true;
    if (probe_cancel_) *probe_cancel_ = true;
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
    auto* how = new WrapText(p, L("wizard.s2.machine.how"));
    mv->Add(how, 0, wxEXPAND | wxBOTTOM, 4);
    code_ = new wxTextCtrl(p, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 54), wxTE_MULTILINE | wxTE_BESTWRAP);
    code_->SetHint(L("wizard.s2.code.hint"));
    mv->Add(code_, 0, wxEXPAND);
    probe_busy_ = new BusyIndicator(p);
    mv->Add(probe_busy_, 0, wxEXPAND | wxTOP, 4);
    code_msg_ = new WrapText(p, "");
    code_msg_->Hide();
    mv->Add(code_msg_, 0, wxEXPAND | wxTOP, 4);

    // Phần tóm tắt bằng lời thường; dấu vân tay chỉ nằm trong "Chi tiết" (đóng sẵn).
    inv_panel_ = new wxPanel(p, wxID_ANY);
    auto* iv = new wxBoxSizer(wxVERTICAL);
    inv_sentence_ = new WrapText(inv_panel_, "");
    sp_font(inv_sentence_, 1.05, false);
    iv->Add(inv_sentence_, 0, wxEXPAND | wxTOP, 6);
    b_details_ = new wxButton(inv_panel_, wxID_ANY, L("simple.svc.details.show"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    iv->Add(b_details_, 0, wxTOP, 6);
    inv_detail_ = new WrapText(inv_panel_, "");
    inv_detail_->SetTextColour(kGrey);
    inv_detail_->Hide();
    iv->Add(inv_detail_, 0, wxEXPAND | wxTOP, 4);
    inv_panel_->SetSizer(iv);
    inv_panel_->Hide();
    mv->Add(inv_panel_, 0, wxEXPAND);
    v->Add(mv, 0, wxEXPAND | wxLEFT, 24);
    p->SetSizer(v);

    b_dst_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ChooseDest(); });
    r_folder_->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) { UpdateDestEnable(); });
    r_machine_->Bind(wxEVT_RADIOBUTTON, [this](wxCommandEvent&) { UpdateDestEnable(); });
    b_details_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        bool show = !inv_detail_->IsShown();
        inv_detail_->Show(show);
        b_details_->SetLabel(L(show ? "simple.svc.details.hide" : "simple.svc.details.show"));
        content_->Layout();
        Layout();
    });
    code_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { OnCodeText(); });
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

    // Chỉ dùng khi đích là máy khác và máy kia hỏi người dùng trước khi cho vào.
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
    v->Add(sas_hint_, 0, wxTOP, 14);
    v->Add(sas_, 0, wxTOP | wxBOTTOM, 4);
    join_busy_ = new BusyIndicator(p);
    v->Add(join_busy_, 0, wxEXPAND | wxTOP, 8);
    b_jcancel_ = new wxButton(p, wxID_ANY, L("inv.join.cancel"));
    b_jcancel_->Hide();
    v->Add(b_jcancel_, 0, wxTOP, 6);
    join_msg_ = new WrapText(p, "");
    join_msg_->SetTextColour(kRed);
    join_msg_->Hide();
    v->Add(join_msg_, 0, wxEXPAND | wxTOP, 8);
    p->SetSizer(v);
    b_jcancel_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { CancelJoin(); });
}

void WizardPage::UpdateDestEnable() {
    bool folder = r_folder_->GetValue();
    dst_->Enable(folder);
    b_dst_->Enable(folder);
    code_->Enable(!folder && !join_running_);
    m_.set_kind(folder ? simple::DestKind::Folder : simple::DestKind::PairedMachine);
}

void WizardPage::Restart(bool can_cancel) {
    if (join_) join_->cancel = true;
    if (probe_cancel_) *probe_cancel_ = true;
    join_running_ = false;
    join_timer_.Stop();
    m_.reset();
    inv_.reset();
    src_->SetValue("");
    dst_->SetValue("");
    code_->ChangeValue("");
    r_folder_->SetValue(true);
    src_err_->Hide();
    dst_err_->Hide();
    code_msg_->Hide();
    inv_panel_->Hide();
    probe_busy_->Stop();
    join_busy_->Stop();
    join_msg_->Hide();
    sas_->Hide();
    sas_hint_->Hide();
    b_jcancel_->Hide();
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
    if (busy_flag_ || join_running_) return;
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
                // Mã đang được kiểm / đã có lỗi riêng: không chồng thêm câu "hãy dán mã".
                if (!r_folder_->GetValue() && inv_.stage() != CodeStage::Empty && inv_.stage() != CodeStage::Ready) b.clear();
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

// ---------------------------------------------------------------------------------------------- mã mời (phía gửi)
void WizardPage::OnCodeText() {
    if (join_running_) return;
    std::string text = S(code_->GetValue());
    if (!trim(text).empty() && !r_machine_->GetValue()) {   // dán mã = chọn cách "máy khác"
        r_machine_->SetValue(true);
        UpdateDestEnable();
    }
    if (probe_cancel_) *probe_cancel_ = true;
    bool probe = inv_.set_text(text, now_unix());
    m_.clear_paired();   // mã đổi: kết quả kiểm cũ không còn đúng
    ShowCodeState();
    if (probe) StartProbe();
}

void WizardPage::StartProbe() {
    simple::InviteCode code = inv_.code();
    uint64_t gen = inv_.generation();
    probe_cancel_ = std::make_shared<std::atomic<bool>>(false);
    auto cancel = probe_cancel_;
    SimpleHost* host = c_.host;
    const bool demo = !simple_test_hooks().demo_invite_code.empty();
    probe_busy_->Start(L("inv.checking"));
    run_async<simple::InviteOutcome>(
        alive_,
        [code, cancel, host, demo]() {
            if (demo) {   // chỉ ảnh tài liệu: không hỏi mạng, coi như máy kia đã trả lời
                simple::InviteOutcome o;
                o.kind = simple::InviteOutcome::Ok;
                o.grant.machine = code.machine;
                o.grant.label = code.label;
                o.grant.perm = code.perm;
                o.grant.expires_unix = code.expires_unix;
                o.grant.uses_left = 1;
                o.grant.fingerprint = simple::invite_fingerprint(code.server_key);
                if (!code.addrs.empty()) o.grant.address = code.addrs[0];
                o.grant.server_key = code.server_key;
                return o;
            }
            KeyPair self = SimpleHost::load_or_create_client_key(host->paths());
            return simple::probe_invite(code, self, *cancel);
        },
        [this, gen](bool ok, simple::InviteOutcome& o, const std::string& err) {
            if (gen != inv_.generation()) return;   // người dùng đã sửa ô trong lúc chờ
            probe_busy_->Stop();
            if (!ok) {
                o = simple::InviteOutcome{};
                o.kind = simple::InviteOutcome::Failed;
                o.message = err;
            }
            if (!inv_.apply_probe(gen, o)) return;
            if (inv_.ready()) {
                m_.set_paired(pair_code_from_grant(inv_.grant()));
                m_.set_machine_label(inv_.summary(now_unix()).dest_label);
            }
            ShowCodeState();
        });
}

void WizardPage::ShowCodeState() {
    CodeStage st = inv_.stage();
    if (st != CodeStage::Checking) probe_busy_->Stop();
    bool err = st == CodeStage::Invalid || st == CodeStage::Failed;
    code_msg_->SetText(W(inv_.error()));
    code_msg_->SetTextColour(kRed);
    code_msg_->Show(err);
    if (st == CodeStage::Ready) {
        InviteSummary s = inv_.summary(now_unix());
        inv_sentence_->SetText(W(s.line));
        std::string d = trf("inv.fp", {s.fingerprint});
        inv_detail_->SetText(W(d));
        inv_panel_->Show();
        dst_err_->Hide();
    } else {
        inv_panel_->Hide();
    }
    content_->Layout();
    Layout();
}

// ---------------------------------------------------------------------------------------------- Bắt đầu
void WizardPage::CancelJoin() {
    if (join_) join_->cancel = true;
}

void WizardPage::JoinTick() {
    if (!join_running_ || !join_) return;
    int s = join_->secs.load();
    if (s >= 0) {
        sas_hint_->Show();
        sas_->Show();
        content_->Layout();
    }
    join_busy_->Start(W(join_busy_text(s >= 0, s)));
}

void WizardPage::Begin() {
    if (busy_flag_ || join_running_) return;
    if (m_.input().kind == simple::DestKind::PairedMachine && inv_.ready()) {
        StartJoin();
        return;
    }
    SaveAndFinish();
}

void WizardPage::StartJoin() {
    simple::InviteCode code = inv_.code();
    KeyPair self;
    try {
        self = SimpleHost::load_or_create_client_key(c_.host->paths());
    } catch (const std::exception& ex) {
        join_msg_->SetText(W(ex.what()));
        join_msg_->Show();
        content_->Layout();
        return;
    }
    // Chuỗi xác nhận tính được ngay từ mã + khoá của máy này; chỉ hiện khi máy kia thật sự đang chờ người đồng ý.
    sas_->SetLabelText(W(sas_display(simple::invite_sas(code, self))));
    join_msg_->Hide();
    join_ = std::make_shared<JoinRun>();
    join_running_ = true;
    b_start_->Disable();
    b_back_->Disable();
    b_quit_->Disable();
    b_jcancel_->Show();
    join_busy_->Start(W(join_busy_text(false, 0)));
    join_timer_.Start(prefers_reduced_motion() ? 1000 : 500);
    const bool demo = !simple_test_hooks().demo_invite_code.empty();
    auto run = join_;
    run_async<simple::InviteOutcome>(
        alive_,
        [code, self, run, demo]() {
            if (demo) {
                simple::InviteOutcome o;
                o.kind = simple::InviteOutcome::Failed;
                o.message = "demo";
                return o;
            }
            return simple::redeem_invite(code, self, simple::default_device_name(), run->cancel,
                                         [run](int s) { run->secs = s; });
        },
        [this, run](bool ok, simple::InviteOutcome& o, const std::string& err) {
            if (join_ != run) return;   // lượt cũ đã bị thay
            join_running_ = false;
            join_timer_.Stop();
            join_busy_->Stop();
            b_jcancel_->Hide();
            b_start_->Enable();
            b_back_->Enable();
            b_quit_->Enable();
            sas_->Hide();
            sas_hint_->Hide();
            if (!ok) {
                join_msg_->SetText(W(err));
                join_msg_->Show();
            } else if (o.kind != simple::InviteOutcome::Ok) {
                join_msg_->SetText(W(invite_outcome_text(o)));
                join_msg_->Show();
            } else {
                // Máy kia đã cho vào: đích là địa chỉ đã trả lời + khoá máy kia (ghim); máy kia tự áp thư mục con / quyền.
                m_.set_paired(pair_code_from_grant(o.grant));
                m_.set_machine_label(inv_.summary(now_unix()).dest_label);
                content_->Layout();
                Layout();
                SaveAndFinish();
                return;
            }
            content_->Layout();
            Layout();
        });
    content_->Layout();
    Layout();
}

void WizardPage::SaveAndFinish() {
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
            if (!simple_test_hooks().demo_invite_code.empty()) {   // ảnh tài liệu: dán mã mẫu, đợi kiểm xong
                if (!auto_code_done_) {
                    auto_code_done_ = true;
                    code_->SetValue(W(simple_test_hooks().demo_invite_code));
                    break;
                }
                if (!inv_.ready()) break;
            } else if (dst_->GetValue().empty()) {
                dst_->SetValue(W(auto_dst_));
            }
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

}  // namespace mysync::gui
