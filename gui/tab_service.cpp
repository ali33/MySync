// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "tab_service.h"

#include <wx/filedlg.h>

#include "form_model.h"

namespace mysync::gui {

void service_run_async(const AliveFlag& alive, ServiceAction act, const ServiceRequest& req,
                       std::function<void(bool, ServiceResult&, const std::string&)> done) {
    run_async<ServiceResult>(
        alive,
        [act, req]() {
            ServiceController ctl;  // ném Error nếu không tìm thấy mysync hợp lệ -> hiện nguyên văn
            return ctl.run(act, req);
        },
        std::move(done));
}

std::string service_result_text(ServiceAction act, const ServiceResult& r) {
    std::string t = trf("svc.res.head", {service_action_name(act), r.ok ? tr("svc.res.ok") : (r.cancelled ? tr("svc.res.cancelled") : tr("svc.res.fail")),
                                         std::to_string(r.exit_code)});
    if (r.elevated) t += "\n" + tr("svc.res.elevated");
    if (!r.message.empty()) t += "\n" + r.message;
    if (!r.state_after.error.empty()) t += "\n" + tr("svc.res.stateerr") + " " + r.state_after.error;
    return t;
}

ServiceTab::ServiceTab(wxWindow* parent, Shared& sh) : wxPanel(parent, wxID_ANY), sh_(sh), timer_(this) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    content_ = new wxPanel(this, wxID_ANY);
    auto* v = new wxBoxSizer(wxVERTICAL);

    auto* g = new wxFlexGridSizer(3, 6, 8);
    g->AddGrowableCol(1, 1);
    auto lab = [&](const char* k) { g->Add(new wxStaticText(content_, wxID_ANY, L(k)), 0, wxALIGN_CENTER_VERTICAL); };

    lab("svc.name");
    name_ = new wxTextCtrl(content_, wxID_ANY, W(sh_.daemon_name));
    g->Add(name_, 1, wxEXPAND);
    g->AddSpacer(1);

    lab("svc.role");
    role_ = new wxChoice(content_, wxID_ANY);
    role_->Append(L("svc.role.auto"));
    role_->Append(L("role.server"));
    role_->Append(L("role.client"));
    role_->SetSelection(0);
    g->Add(role_, 0);
    g->AddSpacer(1);

    lab("svc.cfg");
    cfg_ = new wxTextCtrl(content_, wxID_ANY, W(sh_.cfg_path));
    g->Add(cfg_, 1, wxEXPAND);
    auto* br = new wxButton(content_, wxID_ANY, L("btn.browse"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    g->Add(br, 0);
    br->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        wxFileDialog dlg(this, L("svc.cfg"), "", "", "TOML (*.toml)|*.toml|*.*|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (dlg.ShowModal() == wxID_OK) cfg_->SetValue(dlg.GetPath());
    });

    lab("svc.runas");
    runas_ = new wxTextCtrl(content_, wxID_ANY, "");
    runas_->SetHint(L("svc.runas.hint"));
    g->Add(runas_, 1, wxEXPAND);
    g->AddSpacer(1);

    lab("svc.allow");
    allow_ = new wxTextCtrl(content_, wxID_ANY, "");
    allow_->SetHint(L("svc.allow.hint"));
    g->Add(allow_, 1, wxEXPAND);
    g->AddSpacer(1);
    v->Add(g, 0, wxEXPAND | wxALL, 8);

    auto* btns = new wxBoxSizer(wxHORIZONTAL);
    b_install_ = new wxButton(content_, wxID_ANY, L("svc.install"));
    b_uninstall_ = new wxButton(content_, wxID_ANY, L("svc.uninstall"));
    b_start_ = new wxButton(content_, wxID_ANY, L("svc.start"));
    b_stop_ = new wxButton(content_, wxID_ANY, L("svc.stop"));
    b_refresh_ = new wxButton(content_, wxID_ANY, L("svc.refresh"));
    for (auto* b : {b_install_, b_uninstall_, b_start_, b_stop_, b_refresh_}) btns->Add(b, 0, wxRIGHT, 6);
    v->Add(btns, 0, wxLEFT | wxRIGHT, 8);

    state_ = new wxStaticText(content_, wxID_ANY, "—");
    v->Add(state_, 0, wxALL, 8);
    elev_ = new wxStaticText(content_, wxID_ANY, W(ServiceController::is_elevated() ? tr("svc.elev.yes") : tr("svc.elev.no")));
    v->Add(elev_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);

    v->Add(new wxStaticText(content_, wxID_ANY, L("svc.result")), 0, wxLEFT | wxRIGHT, 8);
    result_ = new wxTextCtrl(content_, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 160),
                             wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH2 | wxTE_BESTWRAP);
    v->Add(result_, 1, wxEXPAND | wxALL, 8);
    content_->SetSizer(v);

    top->Add(busy_, 0, wxEXPAND | wxALL, 8);
    top->Add(content_, 1, wxEXPAND);
    SetSizer(top);
    gate_ = BusyGate(content_, busy_);

    b_install_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Do(ServiceAction::Install); });
    b_uninstall_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Do(ServiceAction::Uninstall); });
    b_start_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Do(ServiceAction::Start); });
    b_stop_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Do(ServiceAction::Stop); });
    b_refresh_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { RefreshState(true); });
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) {
        if (IsShownOnScreen() && !gate_.busy()) RefreshState();
    });
    timer_.Start(4000);
    OnConfigChanged();
    RefreshState();
}

ServiceTab::~ServiceTab() {
    timer_.Stop();
    *alive_ = false;
}

void ServiceTab::OnConfigChanged() {
    if (sh_.cfg) {
        cfg_->SetValue(W(sh_.cfg->path()));
        bool srv = sh_.cfg->role() == ConfigRole::Server;
        role_->SetSelection(srv ? 1 : 2);
        const std::string cn = srv ? sh_.cfg->server().control_name : sh_.cfg->client().control_name;
        name_->SetValue(W(cn.empty() ? (srv ? "mysync-server" : "mysync-client") : cn));
    } else if (!sh_.cfg_path.empty()) {
        cfg_->SetValue(W(sh_.cfg_path));
    }
}

ServiceRequest ServiceTab::BuildRequest(std::string* err) const {
    ServiceRequest r;
    r.name = trim(S(name_->GetValue()));
    r.config_path = trim(S(cfg_->GetValue()));
    int sel = role_->GetSelection();
    r.role = sel == 1 ? "server" : sel == 2 ? "client" : "";
    r.run_as = trim(S(runas_->GetValue()));
    std::string a = S(allow_->GetValue());
    size_t i = 0;
    while (i <= a.size()) {
        size_t j = a.find(';', i);
        if (j == std::string::npos) j = a.size();
        std::string p = trim(a.substr(i, j - i));
        if (!p.empty()) r.control_allow.push_back(p);
        i = j + 1;
    }
    auto e = check_service_name(r.name);
    if (!e.empty() && err) *err = S(L("svc.name")) + ": " + e;
    return r;
}

void ServiceTab::ShowState(const ServiceState& st) {
    std::string t;
    if (!st.error.empty()) t = tr("svc.state.err") + " " + st.error;
    else if (!st.installed) t = tr("svc.state.notinstalled");
    else
        t = (st.running ? tr("svc.state.running") : tr("svc.state.stopped")) + " · " +
            (st.auto_start ? tr("svc.state.auto") : tr("svc.state.manual")) + (st.detail.empty() ? "" : " (" + st.detail + ")");
    state_->SetLabelText(W(tr("svc.state") + " " + t));
    state_->SetForegroundColour(!st.error.empty() ? wxColour(0xA0, 0x10, 0x10)
                                : st.running ? wxColour(0x1E, 0x7E, 0x34) : wxColour(0x50, 0x50, 0x50));
    b_install_->Enable(!st.installed);
    b_uninstall_->Enable(st.installed);
    b_start_->Enable(st.installed && !st.running);
    b_stop_->Enable(st.installed && st.running);
    Layout();
}

void ServiceTab::RefreshState(bool user) {
    if (querying_ || gate_.busy()) return;
    std::string name = trim(S(name_->GetValue()));
    if (!check_service_name(name).empty()) {
        if (user) sh_.report(BannerLevel::Error, "svc.input", S(L("svc.name")) + ": " + check_service_name(name));
        return;
    }
    querying_ = true;
    // Bấm tay thì có chỉ báo động; làm mới tự động mỗi 4 s chạy ngầm.
    if (user) gate_.begin("busy.svcquery");
    run_async<ServiceState>(
        alive_, [name]() { ServiceController ctl; return ctl.query(name); },
        [this, user](bool ok, ServiceState& st, const std::string& err) {
            querying_ = false;
            if (user) gate_.end();
            if (!ok) {
                st.error = err;
                sh_.report(BannerLevel::Warning, "svc.query", err);
            } else {
                sh_.clear_report("svc.query");
            }
            ShowState(st);
        });
}

void ServiceTab::Do(ServiceAction act) {
    std::string err;
    ServiceRequest req = BuildRequest(&err);
    if (err.empty() && act == ServiceAction::Install) {
        if (req.config_path.empty()) err = S(L("svc.cfg")) + ": " + S(L("err.required"));
    }
    if (!err.empty()) {
        sh_.report(BannerLevel::Error, "svc.input", err);
        return;
    }
    sh_.clear_report("svc.input");
    if (act == ServiceAction::Uninstall || act == ServiceAction::Stop) {
        wxMessageDialog q(this, W(trf("svc.confirm", {service_action_name(act), req.name})), L("app.title"),
                          wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        if (q.ShowModal() != wxID_YES) return;
    }
    if (!gate_.begin("busy.service")) return;
    result_->SetValue("");
    service_run_async(alive_, act, req, [this, act](bool ok, ServiceResult& r, const std::string& err) {
        gate_.end();
        if (!ok) {
            result_->SetValue(W(err));
            result_->SetStyle(0, result_->GetLastPosition(), wxTextAttr(wxColour(0xA0, 0x10, 0x10)));
            sh_.report(BannerLevel::Error, "svc.run", err);
            return;
        }
        std::string txt = service_result_text(act, r);
        result_->SetValue(W(txt));
        result_->SetStyle(0, result_->GetLastPosition(),
                          wxTextAttr(r.ok ? wxColour(0x1E, 0x7E, 0x34) : wxColour(0xA0, 0x10, 0x10)));
        if (r.ok) sh_.clear_report("svc.run");
        else if (r.cancelled) sh_.report(BannerLevel::Warning, "svc.run", txt);
        else sh_.report(BannerLevel::Error, "svc.run", txt);
        ShowState(r.state_after);
        sh_.poll_now();
    });
}

}  // namespace mysync::gui
