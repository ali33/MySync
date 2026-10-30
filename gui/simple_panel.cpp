// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// Chế độ Đơn giản: nhãn tự xuống dòng, Bắt đầu nhanh, màn Trạng thái gọn, khung chứa các trang.
#include "simple_panel.h"

#include <wx/commandlinkbutton.h>
#include <wx/gauge.h>

#include "mysync/gui/service_ctl.h"
#include "mysync/simple/autostart.h"
#include "mysync/simple/service_upgrade.h"

namespace mysync::gui {

namespace {
const wxColour kRed(0xA0, 0x10, 0x10), kGreen(0x1E, 0x7E, 0x34), kAmber(0x8A, 0x5A, 0x00), kBlue(0x1F, 0x5F, 0xBF),
    kGrey(0x55, 0x55, 0x55);

wxColour kind_colour(SimpleKind k) {
    switch (k) {
        case SimpleKind::UpToDate: return kGreen;
        case SimpleKind::Syncing: return kBlue;
        case SimpleKind::Warning:
        case SimpleKind::Restarting: return kAmber;
        case SimpleKind::Error:
        case SimpleKind::GaveUp: return kRed;
        default: return kGrey;
    }
}

const char* step_key(simple::UpgradeStep s) {
    switch (s) {
        case simple::UpgradeStep::Preconditions: return "simple.svc.step.pre";
        case simple::UpgradeStep::StopUserEngine: return "simple.svc.step.stopuser";
        case simple::UpgradeStep::MigrateConfig: return "simple.svc.step.migrate";
        case simple::UpgradeStep::InstallService: return "simple.svc.step.install";
        case simple::UpgradeStep::StartTheService: return "simple.svc.step.start";
        case simple::UpgradeStep::StopService: return "simple.svc.step.stopsvc";
        case simple::UpgradeStep::UninstallService: return "simple.svc.step.uninstall";
        case simple::UpgradeStep::RestoreConfig: return "simple.svc.step.restore";
        case simple::UpgradeStep::StartUserEngine: return "simple.svc.step.startuser";
        case simple::UpgradeStep::Done: break;
    }
    return "simple.svc.step.done";
}
}  // namespace

// ---------------------------------------------------------------- WrapText
WrapText::WrapText(wxWindow* parent, const wxString& text)
    : wxStaticText(parent, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxST_NO_AUTORESIZE) {
    raw_ = text;
    SetLabelText(raw_);
    // Bề rộng tối thiểu nhỏ: nếu không, bề rộng "tốt nhất" của cả dòng chưa xuống dòng sẽ ép cửa sổ rộng ra.
    SetMinSize(wxSize(1, GetBestSize().y));
    Bind(wxEVT_SIZE, [this](wxSizeEvent& e) {
        e.Skip();
        int w = e.GetSize().x;
        if (w > 20 && w != last_w_) {
            last_w_ = w;
            CallAfter([this] { Rewrap(); });
        }
    });
}

void WrapText::SetText(const wxString& t) {
    raw_ = t;
    last_w_ = 0;
    SetLabelText(raw_);
    CallAfter([this] {
        last_w_ = GetSize().x;
        Rewrap();
    });
}

void WrapText::Rewrap() {
    int w = GetSize().x;
    if (w <= 20) return;
    SetLabelText(raw_);
    Wrap(w);
    int old_h = GetMinSize().y;
    wxSize best = GetBestSize();
    SetMinSize(wxSize(1, best.y));
    if (best.y != old_h && GetParent()) {
        GetParent()->Layout();
        if (GetParent()->GetParent()) GetParent()->GetParent()->Layout();
    }
}

// ---------------------------------------------------------------- Bắt đầu nhanh
QuickStartPage::QuickStartPage(wxWindow* parent, SimpleCtx& c, std::function<void()> go_wizard)
    : wxPanel(parent, wxID_ANY) {
    auto* v = new wxBoxSizer(wxVERTICAL);
    auto* t = new wxStaticText(this, wxID_ANY, L("quick.title"));
    sp_font(t, 1.9);
    v->Add(t, 0, wxLEFT | wxRIGHT | wxTOP, 24);
    auto* intro = new WrapText(this, L("quick.intro"));
    v->Add(intro, 0, wxEXPAND | wxALL, 24);

    auto* b1 = new wxCommandLinkButton(this, wxID_ANY, L("quick.simple"), L("quick.simple.note"));
    auto* b2 = new wxCommandLinkButton(this, wxID_ANY, L("quick.advanced"), L("quick.advanced.note"));
    v->Add(b1, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 24);
    v->Add(b2, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 24);
    SetSizer(v);
    b1->SetDefault();
    b1->Bind(wxEVT_BUTTON, [go_wizard](wxCommandEvent&) { go_wizard(); });
    b2->Bind(wxEVT_BUTTON, [&c](wxCommandEvent&) {
        if (c.go_advanced) c.go_advanced();
    });
}

// ---------------------------------------------------------------- Trạng thái
StatusPage::StatusPage(wxWindow* parent, SimpleCtx& c, std::function<void()> add_folder)
    : wxPanel(parent, wxID_ANY), c_(c), add_folder_(std::move(add_folder)) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxEXPAND | wxALL, 8);
    content_ = new wxScrolledWindow(this, wxID_ANY);
    static_cast<wxScrolledWindow*>(content_)->SetScrollRate(0, 12);
    auto* v = new wxBoxSizer(wxVERTICAL);

    headline_ = new WrapText(content_, "");
    sp_font(headline_, 1.7);
    detail_ = new WrapText(content_, "");
    detail_->SetTextColour(kGrey);
    v->Add(headline_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);
    v->Add(detail_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);

    starting_ = new BusyIndicator(content_);
    v->Add(starting_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);

    gauge_ = new wxGauge(content_, wxID_ANY, 1000, wxDefaultPosition, wxSize(-1, 18));
    gauge_->Hide();
    prog_ = new wxStaticText(content_, wxID_ANY, "");
    prog_->Hide();
    v->Add(gauge_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);
    v->Add(prog_, 0, wxLEFT | wxRIGHT | wxTOP, 20);

    warn_panel_ = new wxPanel(content_, wxID_ANY);
    warn_panel_->SetBackgroundColour(wxColour(0xFF, 0xF1, 0xC4));
    auto* wh = new wxBoxSizer(wxHORIZONTAL);
    warn_ = new WrapText(warn_panel_, "");
    warn_->SetTextColour(wxColour(0x5C, 0x45, 0x00));
    wh->Add(warn_, 1, wxALL | wxEXPAND, 8);
    warn_panel_->SetSizer(wh);
    warn_panel_->Hide();
    v->Add(warn_panel_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);

    folders_lbl_ = new wxStaticText(content_, wxID_ANY, L("simple.folders"));
    v->Add(folders_lbl_, 0, wxLEFT | wxRIGHT | wxTOP, 20);
    folders_ = new wxListBox(content_, wxID_ANY, wxDefaultPosition, wxSize(-1, 64));
    v->Add(folders_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);

    auto* bh = new wxBoxSizer(wxHORIZONTAL);
    b_add_ = new wxButton(content_, wxID_ANY, L("simple.add"));
    b_adv_ = new wxToggleButton(content_, wxID_ANY, L("simple.advanced"));
    bh->Add(b_add_, 0, wxRIGHT, 8);
    bh->Add(b_adv_, 0);
    v->Add(bh, 0, wxLEFT | wxRIGHT | wxTOP, 20);

    chk_auto_ = new wxCheckBox(content_, wxID_ANY, L("simple.autostart"));
    v->Add(chk_auto_, 0, wxLEFT | wxRIGHT | wxTOP, 20);

    b_svc_ = new wxButton(content_, wxID_ANY, L("simple.svc.to"));
    v->Add(b_svc_, 0, wxLEFT | wxRIGHT | wxTOP, 20);
    svc_result_ = new WrapText(content_, "");
    svc_result_->Hide();
    v->Add(svc_result_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 20);

    recv_ = new ReceiveBox(content_, c_);
    v->Add(recv_, 0, wxEXPAND | wxALL, 20);
    content_->SetSizer(v);
    top->Add(content_, 1, wxEXPAND);
    SetSizer(top);

    b_add_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!busy_op_ && add_folder_) add_folder_();
    });
    b_adv_->Bind(wxEVT_TOGGLEBUTTON, [this](wxCommandEvent&) {
        if (c_.show_advanced) c_.show_advanced(b_adv_->GetValue());
    });
    chk_auto_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent&) { OnAutostart(chk_auto_->GetValue()); });
    b_svc_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ToServiceClick(); });
    UpdateAutostart();
}

StatusPage::~StatusPage() { *alive_ = false; }

void StatusPage::UpdateAutostart() {
    updating_auto_ = true;
    chk_auto_->SetValue(simple::autostart_enabled());
    updating_auto_ = false;
}

void StatusPage::OnAutostart(bool on) {
    if (updating_auto_) return;
    try {
        simple::set_autostart(on);
        c_.sh->clear_report("simple.autostart");
    } catch (const std::exception& e) {
        c_.sh->report(BannerLevel::Warning, "simple.autostart", std::string(S(L("simple.autostart.fail"))) + " " + e.what());
        UpdateAutostart();
    }
}

void StatusPage::SetAdvancedShown(bool s) { b_adv_->SetValue(s); }

void StatusPage::SetQuitting(bool on) {
    busy_op_ = on;
    content_->Enable(!on);
    if (on) busy_->Start(L("simple.quitting"));
    else busy_->Stop();
}

void StatusPage::OnPoll(const PollResult& r) {
    last_ = r;
    have_last_ = true;
    Refresh2();
}

void StatusPage::Refresh2() {
    SimpleInputs in;
    in.has_config = c_.host->has_config();
    in.engine_managed = !c_.service_mode();
    if (in.engine_managed) {
        simple::EngineInfo ci = c_.host->client_info();
        in.engine_state = ci.state;
        in.restarts = ci.restarts;
        in.next_retry_ms = ci.next_retry_ms;
        in.engine_error = ci.last_error;
    }
    if (have_last_) {
        in.connected = last_.connected;
        in.snap = last_.snap;
        in.now_ms = last_.now_ms;
    }
    cur_ = compute_simple_status(in);

    headline_->SetText(W(cur_.headline));
    headline_->SetTextColour(kind_colour(cur_.kind));
    detail_->SetText(W(cur_.detail));
    detail_->Show(!cur_.detail.empty() && !cur_.warn_banner);

    bool starting = cur_.kind == SimpleKind::Starting || cur_.kind == SimpleKind::Restarting;
    if (starting && !starting_->IsRunning()) starting_->Start(L(cur_.kind == SimpleKind::Starting ? "simple.st.starting.b" : "simple.st.restarting.b"));
    if (!starting && starting_->IsRunning()) starting_->Stop();

    bool syncing = cur_.kind == SimpleKind::Syncing;
    prog_model_.update(syncing, cur_.sent, cur_.pending);
    if (prog_model_.fraction() >= 0) {
        gauge_->SetValue(static_cast<int>(prog_model_.fraction() * 1000));
        prog_->SetLabelText(W(prog_model_.text()));
    }
    gauge_->Show(prog_model_.fraction() >= 0);
    prog_->Show(prog_model_.fraction() >= 0);

    warn_panel_->Show(cur_.warn_banner);
    if (cur_.warn_banner)
        warn_->SetText(W(cur_.detail.empty() ? tr("simple.st.restarting.nodetail") : trf("simple.st.restarting.last", {cur_.detail})));

    if (have_last_ && last_.connected) {
        std::vector<wxString> rows;
        for (const auto& t : last_.snap.targets) rows.push_back(W(trf("simple.folder.row", {t.watch, target_display(t.target)})));
        wxArrayString arr;
        for (auto& r : rows) arr.Add(r);
        if (arr != folders_->GetStrings()) folders_->Set(arr);
    }
    bool any_folder = folders_->GetCount() > 0;
    folders_lbl_->Show(any_folder);
    folders_->Show(any_folder);

    bool svc = c_.service_mode();
    b_svc_->SetLabel(L(svc ? "simple.svc.back" : "simple.svc.to"));
    b_svc_->Enable(!busy_op_);
    b_add_->Enable(!svc && !busy_op_);
    b_add_->SetToolTip(svc ? L("simple.add.svc") : wxString());
    content_->Layout();
    Layout();
}

void StatusPage::ToServiceClick() {
    if (busy_op_) return;
    bool to_service = !c_.service_mode();
    if (!to_service) {
        wxMessageDialog q(this, L("simple.svc.confirm.back"), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        q.SetYesNoLabels(L("simple.svc.yes"), L("btn.cancel"));
        if (q.ShowModal() != wxID_YES) return;
        RunUpgrade(false);
        return;
    }
    // Trước khi xin quyền quản trị: cho người dùng thấy dịch vụ sẽ đụng tới thư mục nào, dùng khoá nào.
    busy_op_ = true;
    content_->Enable(false);
    busy_->Start(L("simple.svc.summarizing"));
    svc_result_->Hide();
    SimpleHost* host = c_.host;
    run_async<simple::MigrationSummary>(
        alive_, [host]() { return simple::summarize_user_config(host->paths()); },
        [this](bool ok, simple::MigrationSummary& s, const std::string& err) {
            busy_op_ = false;
            content_->Enable(true);
            busy_->Stop();
            std::string problem = !ok ? err : s.problems.empty() ? std::string() : s.problems.front();
            if (!problem.empty()) {
                svc_result_->SetText(W(problem));
                svc_result_->SetTextColour(kRed);
                svc_result_->Show();
                c_.sh->report(BannerLevel::Error, "simple.svc", problem);
                Refresh2();
                return;
            }
            wxMessageDialog q(this, W(service_confirm_text(s)), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_WARNING);
            q.SetYesNoLabels(L("simple.svc.yes"), L("btn.cancel"));
            if (q.ShowModal() != wxID_YES) {
                Refresh2();
                return;
            }
            RunUpgrade(true);
        });
}

void StatusPage::RunUpgrade(bool to_service) {
    busy_op_ = true;
    content_->Enable(false);
    busy_->Start(L("simple.svc.busy"));
    svc_result_->Hide();
    SimpleHost* host = c_.host;
    AliveFlag alive = alive_;
    run_async<simple::UpgradeResult>(
        alive_,
        [this, host, to_service, alive]() {
            simple::Supervisor* sup = host->sup();
            if (!sup) throw Error(tr("simple.svc.nosup"));
            ServiceController ctl;
            auto steps = simple::make_real_upgrade_steps(*sup, ctl, host->paths());
            // Gọi từ luồng nền: chỉ đẩy việc về luồng UI (CallAfter), không chạm cửa sổ ở đây.
            std::function<void(simple::UpgradeStep)> cb = [this, alive](simple::UpgradeStep s) {
                if (!wxTheApp) return;
                wxTheApp->CallAfter([this, alive, s] {
                    if (*alive && busy_op_) busy_->Start(L(step_key(s)));
                });
            };
            return to_service ? simple::upgrade_to_service(*steps, cb) : simple::downgrade_to_user(*steps, cb);
        },
        [this, to_service](bool ok, simple::UpgradeResult& r, const std::string& err) {
            busy_op_ = false;
            content_->Enable(true);
            busy_->Stop();
            std::string txt;
            wxColour col = kRed;
            if (!ok) {
                txt = err;
            } else if (r.ok) {
                txt = tr(to_service ? "simple.svc.done.to" : "simple.svc.done.back");
                col = kGreen;
                if (c_.set_service_mode) c_.set_service_mode(to_service);
            } else if (r.cancelled) {
                txt = tr("simple.svc.cancelled");
                col = kAmber;
            } else {
                txt = trf("simple.svc.fail", {tr(step_key(r.failed_step)), r.error});
                if (r.rolled_back) txt += "\n" + tr("simple.svc.rolledback");
                else if (!r.rollback_error.empty()) txt += "\n" + trf("simple.svc.rollbackfail", {r.rollback_error});
            }
            svc_result_->SetText(W(txt));
            svc_result_->SetTextColour(col);
            svc_result_->Show();
            if (!ok || (!r.ok && !r.cancelled)) c_.sh->report(BannerLevel::Error, "simple.svc", txt);
            else c_.sh->clear_report("simple.svc");
            Refresh2();
            if (c_.sh->poll_now) c_.sh->poll_now();
        });
}

// ---------------------------------------------------------------- khung chứa
SimplePanel::SimplePanel(wxWindow* parent, SimpleCtx& c) : wxPanel(parent, wxID_ANY), c_(c) {
    auto* v = new wxBoxSizer(wxVERTICAL);
    book_ = new wxSimplebook(this, wxID_ANY);

    auto* chk = new wxPanel(book_);
    auto* cs = new wxBoxSizer(wxVERTICAL);
    checking_ = new BusyIndicator(chk);
    cs->Add(checking_, 0, wxEXPAND | wxALL, 24);
    chk->SetSizer(cs);
    book_->AddPage(chk, "checking");

    quick_ = new QuickStartPage(book_, c_, [this] { StartAddFolder(); });
    book_->AddPage(quick_, "quick");
    wiz_ = new WizardPage(
        book_, c_,
        [this] {
            if (c_.engines_changed) c_.engines_changed();
            ShowPage(SimplePage::Status);
        },
        [this] { ShowPage(c_.host->has_config() ? SimplePage::Status : SimplePage::QuickStart); });
    book_->AddPage(wiz_, "wizard");
    status_ = new StatusPage(book_, c_, [this] { StartAddFolder(); });
    book_->AddPage(status_, "status");
    v->Add(book_, 1, wxEXPAND);
    SetSizer(v);
    ShowPage(SimplePage::Checking);
}

void SimplePanel::ShowPage(SimplePage p) {
    page_ = p;
    book_->ChangeSelection(static_cast<size_t>(p));
    if (p == SimplePage::Checking) checking_->Start(L("simple.checking"));
    else checking_->Stop();
    if (p == SimplePage::Status) {
        status_->OnShown();
        status_->Refresh2();
    }
    Layout();
}

void SimplePanel::StartAddFolder() {
    wiz_->Restart(true);
    ShowPage(SimplePage::Wizard);
}

void SimplePanel::AutoDrive(const std::string& src, const std::string& dst) {
    wiz_->Restart(true);
    ShowPage(SimplePage::Wizard);
    wiz_->AutoDrive(src, dst);
}

void SimplePanel::OnPoll(const PollResult& r) { status_->OnPoll(r); }

void SimplePanel::DropFolder(const std::string& path) {
    if (page_ == SimplePage::Wizard) {
        wiz_->DropFolder(path);
    } else if (page_ == SimplePage::QuickStart || page_ == SimplePage::Status) {
        // Thả thư mục khi chưa ở trong trình hướng dẫn: mở trình hướng dẫn với thư mục đó.
        if (page_ == SimplePage::Status && c_.service_mode()) return;
        wiz_->Restart(true);
        ShowPage(SimplePage::Wizard);
        wiz_->DropFolder(path);
    }
}

}  // namespace mysync::gui
