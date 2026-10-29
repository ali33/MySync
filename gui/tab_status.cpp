// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "tab_status.h"

namespace mysync::gui {

StatusTab::StatusTab(wxWindow* parent, Shared& sh) : wxPanel(parent, wxID_ANY), sh_(sh) {
    auto* top = new wxBoxSizer(wxVERTICAL);

    // --- chọn daemon
    auto* r1 = new wxBoxSizer(wxHORIZONTAL);
    r1->Add(new wxStaticText(this, wxID_ANY, L("status.daemon")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    daemon_ = new wxComboBox(this, wxID_ANY, W(sh_.daemon_name), wxDefaultPosition, wxSize(220, -1));
    daemon_->Append("mysync-client");
    daemon_->Append("mysync-server");
    r1->Add(daemon_, 0, wxRIGHT, 6);
    auto* apply = new wxButton(this, wxID_ANY, L("status.connect"));
    r1->Add(apply, 0, wxRIGHT, 12);
    conn_ = new wxStaticText(this, wxID_ANY, "");
    r1->Add(conn_, 1, wxALIGN_CENTER_VERTICAL);
    top->Add(r1, 0, wxEXPAND | wxALL, 8);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxLEFT | wxRIGHT | wxBOTTOM, 8);

    auto submit = [this](wxCommandEvent&) {
        std::string n = S(daemon_->GetValue());
        n.erase(0, n.find_first_not_of(" \t"));
        while (!n.empty() && (n.back() == ' ' || n.back() == '\t')) n.pop_back();
        if (!valid_control_name(n)) {
            sh_.report(BannerLevel::Error, "status.name", S(L("err.svcname")));
            return;
        }
        sh_.clear_report("status.name");
        sh_.daemon_name = n;
        sh_.set_setting("daemon", n);
        first_ = true;
        busy_->Start(L("status.connecting"));
        sh_.set_daemon(n);
    };
    apply->Bind(wxEVT_BUTTON, submit);
    daemon_->Bind(wxEVT_TEXT_ENTER, submit);

    // --- tóm tắt
    auto* g = new wxFlexGridSizer(4, 6, 16);
    g->AddGrowableCol(1, 1);
    g->AddGrowableCol(3, 1);
    auto row = [&](const char* key, wxStaticText*& out) {
        g->Add(new wxStaticText(this, wxID_ANY, L(key)), 0, wxALIGN_TOP);
        out = new wxStaticText(this, wxID_ANY, "—");
        g->Add(out, 1, wxEXPAND);
    };
    row("status.role", role_);
    row("status.version", ver_);
    row("status.uptime", up_);
    row("status.listen", listen_);
    row("status.rate", rate_);
    row("status.totals", totals_);
    row("status.cfgloaded", loaded_);
    g->Add(new wxStaticText(this, wxID_ANY, L("status.cfgfile")), 0, wxALIGN_CENTER_VERTICAL);
    auto* cf = new wxBoxSizer(wxHORIZONTAL);
    cfgp_ = new wxStaticText(this, wxID_ANY, "—", wxDefaultPosition, wxDefaultSize, wxST_ELLIPSIZE_MIDDLE);
    open_cfg_ = new wxButton(this, wxID_ANY, L("status.open_cfg"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    open_cfg_->Disable();
    cf->Add(cfgp_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    cf->Add(open_cfg_, 0);
    g->Add(cf, 1, wxEXPAND);
    top->Add(g, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 10);
    open_cfg_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!last_cfg_path_.empty()) sh_.open_config(last_cfg_path_);
    });

    // --- bảng đích / máy khách
    list_title_ = new wxStaticText(this, wxID_ANY, L("status.targets"));
    top->Add(list_title_, 0, wxLEFT | wxRIGHT, 10);
    list_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, 150), wxLC_REPORT | wxLC_SINGLE_SEL);
    top->Add(list_, 2, wxEXPAND | wxALL, 8);
    list_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent& e) {
        long i = e.GetIndex();
        if (!list_is_peers_ && i >= 0 && static_cast<size_t>(i) < targets_.size())
            sel_key_ = targets_[i].watch + "\n" + targets_[i].target;
        FillActive();
    });

    auto* mid = new wxBoxSizer(wxHORIZONTAL);
    auto* ca = new wxBoxSizer(wxVERTICAL);
    ca->Add(new wxStaticText(this, wxID_ANY, L("status.active")), 0, wxBOTTOM, 2);
    active_ = new wxListBox(this, wxID_ANY, wxDefaultPosition, wxSize(-1, 90));
    ca->Add(active_, 1, wxEXPAND);
    mid->Add(ca, 1, wxEXPAND | wxRIGHT, 8);
    auto* ce = new wxBoxSizer(wxVERTICAL);
    ce->Add(new wxStaticText(this, wxID_ANY, L("status.lasterr")), 0, wxBOTTOM, 2);
    last_err_ = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxSize(-1, 90),
                               wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH2 | wxTE_BESTWRAP);
    ce->Add(last_err_, 1, wxEXPAND);
    mid->Add(ce, 2, wxEXPAND);
    top->Add(mid, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    top->Add(new wxStaticText(this, wxID_ANY, L("status.recent")), 0, wxLEFT | wxRIGHT, 10);
    errs_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxSize(-1, 110), wxLC_REPORT | wxLC_SINGLE_SEL);
    errs_->AppendColumn(L("col.time"), wxLIST_FORMAT_LEFT, 200);
    errs_->AppendColumn(L("col.level"), wxLIST_FORMAT_LEFT, 60);
    errs_->AppendColumn(L("col.message"), wxLIST_FORMAT_LEFT, 600);
    top->Add(errs_, 1, wxEXPAND | wxALL, 8);

    SetSizer(top);
    busy_->Start(L("status.connecting"));
    if (sh_.have_poll) Apply(sh_.last);
}

void StatusTab::SetCell(wxListCtrl* l, long row, int col, const std::string& v) {
    if (l->GetItemText(row, col) != W(v)) l->SetItem(row, col, W(v));
}

void StatusTab::OnPoll(const PollResult& r) { Apply(r); }

void StatusTab::Apply(const PollResult& r) {
    if (first_) {
        first_ = false;
        busy_->Stop();
    }
    if (!r.connected) {
        conn_->SetLabelText(W("● " + trf("status.offline_short", {r.daemon})));
        conn_->SetToolTip(W(r.error));
        conn_->SetForegroundColour(wxColour(0x80, 0x80, 0x80));
        open_cfg_->Disable();
        return;  // giữ nguyên số liệu cũ (mờ đi) thay vì xoá trắng
    }
    const auto& s = r.snap;
    conn_->SetLabelText(W("● " + trf("status.online", {r.daemon})));
    conn_->SetForegroundColour(wxColour(0x1E, 0x7E, 0x34));
    role_->SetLabelText(W(s.role == Role::Server ? tr("role.server") : tr("role.client")));
    ver_->SetLabelText(W(s.version));
    up_->SetLabelText(W(fmt_duration(s.uptime_s)));
    listen_->SetLabelText(W(s.role == Role::Server
                            ? s.listen + " · " + trf("status.sessions", {std::to_string(s.sessions), std::to_string(s.max_connections)})
                            : "—"));
    rate_->SetLabelText(W("↑ " + fmt_rate(s.total_tx_bps) + "   ↓ " + fmt_rate(s.total_rx_bps)));
    totals_->SetLabelText(W(s.role == Role::Client
                            ? trf("status.totals_fmt", {std::to_string(s.total_sent), std::to_string(s.total_skipped), std::to_string(s.total_failed)})
                            : "—"));
    loaded_->SetLabelText(W(fmt_datetime(s.config_loaded_unix_ms)));
    last_cfg_path_ = s.config_path;
    cfgp_->SetLabelText(W(s.config_path.empty() ? std::string("—") : s.config_path));
    open_cfg_->Enable(!s.config_path.empty());
    GetSizer()->Layout();

    if (s.role == Role::Server) FillPeers(s); else FillTargets(s);
    FillErrors(r);

    // Lỗi gần nhất, nguyên văn kèm giờ (có thứ).
    std::string txt;
    LastError le;
    if (latest_error(s, le))
        txt = fmt_datetime(le.unix_ms) + " · " + fmt_time_ago(le.unix_ms, r.now_ms) + "\n" + le.where + "\n" + le.message;
    if (!s.config_error.empty()) {
        if (!txt.empty()) txt += "\n\n";
        txt += tr("status.cfgerr") + "\n" + s.config_error;
    }
    if (txt.empty()) txt = tr("status.noerr");
    if (last_err_->GetValue() != W(txt)) {
        last_err_->SetValue(W(txt));
        last_err_->SetStyle(0, last_err_->GetLastPosition(),
                            wxTextAttr(txt == tr("status.noerr") ? wxColour(0x60, 0x60, 0x60) : wxColour(0xA0, 0x10, 0x10)));
    }
}

void StatusTab::FillTargets(const StatusSnapshot& s) {
    if (list_is_peers_ || list_->GetColumnCount() == 0) {
        list_->DeleteAllColumns();
        list_->DeleteAllItems();
        cache_.clear();
        const char* keys[] = {"col.watch", "col.target", "col.state", "col.queue", "col.speed", "col.counts", "col.bytes"};
        int widths[] = {120, 220, 130, 80, 220, 130, 90};
        for (int i = 0; i < 7; ++i) list_->AppendColumn(L(keys[i]), wxLIST_FORMAT_LEFT, widths[i]);
        list_is_peers_ = false;
        list_title_->SetLabel(L("status.targets"));
    }
    targets_ = s.targets;
    while (list_->GetItemCount() > static_cast<long>(s.targets.size())) list_->DeleteItem(list_->GetItemCount() - 1);
    long sel = -1;
    for (size_t i = 0; i < s.targets.size(); ++i) {
        auto r = make_target_row(s.targets[i]);
        long row = static_cast<long>(i);
        if (row >= list_->GetItemCount()) list_->InsertItem(row, W(r.watch));
        const std::string cells[] = {r.watch, r.target, r.state, r.queued, r.speed, r.counts, r.bytes};
        for (int c = 0; c < 7; ++c) SetCell(list_, row, c, cells[c]);
        wxColour col = *wxBLACK;
        if (r.raw_state == TargetState::Error) col = wxColour(0xB0, 0x20, 0x20);
        else if (r.raw_state == TargetState::Disconnected) col = wxColour(0x90, 0x6A, 0x00);
        else if (r.raw_state == TargetState::Syncing) col = wxColour(0x1F, 0x5F, 0xBF);
        list_->SetItemTextColour(row, col);
        if (!sel_key_.empty() && sel_key_ == s.targets[i].watch + "\n" + s.targets[i].target) sel = row;
    }
    if (sel >= 0 && first_selected(list_) != sel) list_->SetItemState(sel, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    FillActive();
}

void StatusTab::FillPeers(const StatusSnapshot& s) {
    if (!list_is_peers_ || list_->GetColumnCount() == 0) {
        list_->DeleteAllColumns();
        list_->DeleteAllItems();
        const char* keys[] = {"col.client", "col.sessions", "col.speed", "col.bytes"};
        int widths[] = {200, 80, 240, 260};
        for (int i = 0; i < 4; ++i) list_->AppendColumn(L(keys[i]), wxLIST_FORMAT_LEFT, widths[i]);
        list_is_peers_ = true;
        list_title_->SetLabel(L("status.peers"));
    }
    targets_.clear();
    while (list_->GetItemCount() > static_cast<long>(s.peers.size())) list_->DeleteItem(list_->GetItemCount() - 1);
    for (size_t i = 0; i < s.peers.size(); ++i) {
        auto r = make_peer_row(s.peers[i]);
        long row = static_cast<long>(i);
        if (row >= list_->GetItemCount()) list_->InsertItem(row, W(r.name));
        const std::string cells[] = {r.name, r.sessions, r.speed, r.bytes};
        for (int c = 0; c < 4; ++c) SetCell(list_, row, c, cells[c]);
    }
    active_->Clear();
}

void StatusTab::FillActive() {
    long sel = first_selected(list_);
    wxArrayString items;
    if (!list_is_peers_ && sel >= 0 && static_cast<size_t>(sel) < targets_.size())
        for (const auto& f : targets_[sel].active_files) items.Add(W(f));
    bool same = active_->GetCount() == items.size();
    for (size_t i = 0; same && i < items.size(); ++i) same = active_->GetString(i) == items[i];
    if (!same) {
        active_->Clear();
        active_->Append(items);
    }
}

void StatusTab::FillErrors(const PollResult& r) {
    // mới nhất lên đầu
    long n = static_cast<long>(r.errors.size());
    while (errs_->GetItemCount() > n) errs_->DeleteItem(errs_->GetItemCount() - 1);
    for (long i = 0; i < n; ++i) {
        const auto& e = r.errors[static_cast<size_t>(n - 1 - i)];
        if (i >= errs_->GetItemCount()) errs_->InsertItem(i, "");
        SetCell(errs_, i, 0, fmt_datetime(e.unix_ms));
        SetCell(errs_, i, 1, e.level);
        SetCell(errs_, i, 2, e.message);
        errs_->SetItemTextColour(i, e.level == "ERROR" ? wxColour(0xB0, 0x20, 0x20) : wxColour(0x90, 0x6A, 0x00));
    }
}

}  // namespace mysync::gui
