// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "tab_config.h"

#include <wx/filedlg.h>
#include <wx/notebook.h>

#include "mysync/gui/ipc.h"
#include "mysync/gui/key_mgr.h"
#include "mysync/keys.h"

#define R(T, expr) [](T& x) -> auto& { return x.expr; }

namespace mysync::gui {

struct SaveOutcome {
    ConfigEditor ed;
    bool reload_attempted = false;
    ReloadResult rr;
    std::string reload_err;
};

namespace {
constexpr int ID_NEW_CLIENT = 2001, ID_NEW_SERVER = 2002;
const std::vector<std::string> kLogLevels{"debug", "info", "warn", "error"};

void apply_kind(Form<TargetConfig>& f, bool local, bool have) {
    for (const char* k : {"cfg.t.host", "cfg.t.port", "cfg.t.server_key", "cfg.t.key_file", "cfg.t.remote_prefix"})
        if (auto* c = f.ctrl(k)) c->Enable(have && !local);
    for (const char* k : {"cfg.t.path", "cfg.t.file_mode", "cfg.t.dir_mode"})
        if (auto* c = f.ctrl(k)) c->Enable(have && local);
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string r;
    for (size_t i = 0; i < v.size(); ++i) r += (i ? sep : "") + v[i];
    return r;
}
}  // namespace

ClientConfig* ConfigTab::cur_client() {
    return sh_.cfg && sh_.cfg->role() == ConfigRole::Client ? &sh_.cfg->client() : nullptr;
}
ServerConfig* ConfigTab::cur_server() {
    return sh_.cfg && sh_.cfg->role() == ConfigRole::Server ? &sh_.cfg->server() : nullptr;
}
WatchConfig* ConfigTab::cur_watch() {
    auto* c = cur_client();
    return c && cur_w_ >= 0 && static_cast<size_t>(cur_w_) < c->watches.size() ? &c->watches[cur_w_] : nullptr;
}
TargetConfig* ConfigTab::cur_target() {
    auto* w = cur_watch();
    return w && cur_t_ >= 0 && static_cast<size_t>(cur_t_) < w->targets.size() ? &w->targets[cur_t_] : nullptr;
}

ConfigTab::ConfigTab(wxWindow* parent, Shared& sh) : wxPanel(parent, wxID_ANY), sh_(sh), timer_(this) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxEXPAND | wxALL, 6);
    body_ = new wxPanel(this, wxID_ANY);
    auto* v = new wxBoxSizer(wxVERTICAL);

    auto* r1 = new wxBoxSizer(wxHORIZONTAL);
    r1->Add(new wxStaticText(body_, wxID_ANY, L("cfg.file")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    path_ = new wxTextCtrl(body_, wxID_ANY, W(sh_.cfg_path), wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    r1->Add(path_, 1, wxRIGHT, 6);
    auto* bb = new wxButton(body_, wxID_ANY, L("btn.browse"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    auto* bo = new wxButton(body_, wxID_ANY, L("cfg.open"));
    auto* bn = new wxButton(body_, wxID_ANY, L("cfg.new"));
    r1->Add(bb, 0, wxRIGHT, 6);
    r1->Add(bo, 0, wxRIGHT, 6);
    r1->Add(bn, 0);
    v->Add(r1, 0, wxEXPAND | wxALL, 6);
    role_lbl_ = new wxStaticText(body_, wxID_ANY, "");
    v->Add(role_lbl_, 0, wxLEFT | wxRIGHT, 8);

    book_ = new wxSimplebook(body_, wxID_ANY);
    auto* empty = new wxPanel(book_);
    auto* ev = new wxBoxSizer(wxVERTICAL);
    ev->Add(new wxStaticText(empty, wxID_ANY, L("cfg.empty")), 0, wxALL, 20);
    empty->SetSizer(ev);
    book_->AddPage(empty, "");
    auto* cl = new wxNotebook(book_, wxID_ANY);
    nb_client_ = cl;
    BuildClient(cl);
    book_->AddPage(cl, "");
    auto* srv = new wxPanel(book_);
    BuildServer(srv);
    book_->AddPage(srv, "");
    v->Add(book_, 1, wxEXPAND | wxALL, 4);

    auto* bot = new wxBoxSizer(wxHORIZONTAL);
    save_ = new wxButton(body_, wxID_ANY, L("cfg.save"));
    revert_ = new wxButton(body_, wxID_ANY, L("cfg.revert"));
    auto* toml = new wxButton(body_, wxID_ANY, L("cfg.showtoml"));
    status_ = new wxStaticText(body_, wxID_ANY, "");
    bot->Add(save_, 0, wxRIGHT, 6);
    bot->Add(revert_, 0, wxRIGHT, 6);
    bot->Add(toml, 0, wxRIGHT, 12);
    bot->Add(status_, 1, wxALIGN_CENTER_VERTICAL);
    v->Add(bot, 0, wxEXPAND | wxALL, 6);
    body_->SetSizer(v);
    top->Add(body_, 1, wxEXPAND);
    SetSizer(top);
    gate_ = BusyGate(body_, busy_);

    bb->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { BrowseOpen(); });
    bo->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { OpenPath(S(path_->GetValue())); });
    path_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent&) { OpenPath(S(path_->GetValue())); });
    bn->Bind(wxEVT_BUTTON, [this, bn](wxCommandEvent&) {
        wxMenu m;
        m.Append(ID_NEW_CLIENT, L("cfg.new.client"));
        m.Append(ID_NEW_SERVER, L("cfg.new.server"));
        m.Bind(wxEVT_MENU, [this](wxCommandEvent&) { NewConfig(ConfigRole::Client); }, ID_NEW_CLIENT);
        m.Bind(wxEVT_MENU, [this](wxCommandEvent&) { NewConfig(ConfigRole::Server); }, ID_NEW_SERVER);
        bn->PopupMenu(&m, 0, bn->GetSize().GetHeight());
    });
    save_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Save(); });
    revert_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!sh_.cfg) return;
        if (HasUnsaved()) {
            wxMessageDialog q(this, L("cfg.revert.confirm"), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
            if (q.ShowModal() != wxID_YES) return;
        }
        OpenPath(sh_.cfg->path());
    });
    toml->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ShowToml(); });
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { CheckDisk(); });
    timer_.Start(4000);
    OnConfigChanged();
}

ConfigTab::~ConfigTab() {
    timer_.Stop();
    *alive_ = false;
}

// ---------------------------------------------------------------- dựng biểu mẫu
void ConfigTab::BuildClient(wxWindow* nb_) {
    auto* nb = static_cast<wxNotebook*>(nb_);
    auto edit = [this] { MarkEdited(); };

    f_client_ = std::make_unique<Form<ClientConfig>>(nb, [this] { return cur_client(); }, edit);
    auto& f = *f_client_;
    f.text("cfg.key_file", R(ClientConfig, key_file), {}, Browse::FileOpen);
    f.text("cfg.state_dir", R(ClientConfig, state_dir), {}, Browse::Dir);
    f.text("cfg.log_file", R(ClientConfig, log_file), {}, Browse::FileSave);
    f.choice("cfg.log_level", R(ClientConfig, log_level), kLogLevels);
    f.num<uint32_t>("cfg.connections", R(ClientConfig, connections), 1, 64);
    f.choice("cfg.compress", R(ClientConfig, compress), {"lz4", "none"});
    f.num<uint32_t>("cfg.max_bandwidth_kbps", R(ClientConfig, max_bandwidth_kbps), 0, 100000000, "cfg.hint.zero_unlimited");
    f.num<uint32_t>("cfg.retry_min", R(ClientConfig, retry_min_ms), 1, 3600000);
    f.num<uint32_t>("cfg.retry_max", R(ClientConfig, retry_max_ms), 1, 3600000);
    nb->AddPage(f.window(), L("cfg.page.general"));

    // --- trang các thư mục theo dõi
    auto* wp = new wxPanel(nb);
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    auto* left = new wxBoxSizer(wxVERTICAL);
    watches_ = new wxListBox(wp, wxID_ANY, wxDefaultPosition, wxSize(190, -1));
    left->Add(watches_, 1, wxEXPAND);
    auto* lb = new wxBoxSizer(wxHORIZONTAL);
    auto* ba = new wxButton(wp, wxID_ANY, "+", wxDefaultPosition, wxSize(34, -1));
    auto* bd = new wxButton(wp, wxID_ANY, L("cfg.dup"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    auto* br = new wxButton(wp, wxID_ANY, "−", wxDefaultPosition, wxSize(34, -1));
    ba->SetToolTip(L("cfg.watch.add"));
    br->SetToolTip(L("cfg.watch.remove"));
    lb->Add(ba, 0, wxRIGHT, 4);
    lb->Add(bd, 0, wxRIGHT, 4);
    lb->Add(br, 0);
    left->Add(lb, 0, wxTOP, 4);
    h->Add(left, 0, wxEXPAND | wxALL, 6);

    auto* inner = new wxNotebook(wp, wxID_ANY);
    nb_watch_ = inner;
    f_watch_ = std::make_unique<Form<WatchConfig>>(inner, [this] { return cur_watch(); }, edit);
    auto& w = *f_watch_;
    w.text("cfg.w.name", R(WatchConfig, name), check_nonempty);
    w.text("cfg.w.path", R(WatchConfig, path), check_nonempty, Browse::Dir);
    w.boolean("cfg.w.enabled", R(WatchConfig, enabled));
    w.boolean("cfg.w.recursive", R(WatchConfig, recursive));
    w.num<uint32_t>("cfg.w.quiet_ms", R(WatchConfig, quiet_ms), 0, 3600000);
    w.num<uint32_t>("cfg.w.sync_delay_ms", R(WatchConfig, sync_delay_ms), 0, 3600000);
    w.boolean("cfg.w.start_sync", R(WatchConfig, start_sync));
    w.boolean("cfg.w.propagate_delete", R(WatchConfig, propagate_delete));
    w.lines("cfg.w.schedule_at", R(WatchConfig, schedule_at), check_hhmm_lines, 3, "cfg.hint.hhmm");
    w.num<uint32_t>("cfg.w.schedule_interval_s", R(WatchConfig, schedule_interval_s), 0, 31536000, "cfg.hint.zero_off");
    w.num<uint32_t>("cfg.w.periodic_scan_s", R(WatchConfig, periodic_scan_s), 0, 31536000, "cfg.hint.zero_off");
    inner->AddPage(w.window(), L("cfg.page.watch"));

    f_filter_ = std::make_unique<Form<WatchConfig>>(inner, [this] { return cur_watch(); }, edit);
    auto& fl = *f_filter_;
    fl.lines("cfg.f.include", R(WatchConfig, filter.include), check_glob_lines, 3, "cfg.hint.include");
    fl.lines("cfg.f.include_regex", R(WatchConfig, filter.include_regex), check_regex_lines, 2);
    fl.lines("cfg.f.exclude", R(WatchConfig, filter.exclude), {}, 3, "cfg.hint.exclude");
    fl.lines("cfg.f.exclude_regex", R(WatchConfig, filter.exclude_regex), check_regex_lines, 2);
    fl.text("cfg.f.size_min", R(WatchConfig, filter.size_min), [](const std::string& s) { return check_size(s, true); }, Browse::None, "cfg.hint.size");
    fl.text("cfg.f.size_max", R(WatchConfig, filter.size_max), [](const std::string& s) { return check_size(s, true); }, Browse::None, "cfg.hint.size");
    fl.text("cfg.f.mtime_after", R(WatchConfig, filter.mtime_after), check_mtime, Browse::None, "cfg.hint.mtime");
    fl.text("cfg.f.mtime_before", R(WatchConfig, filter.mtime_before), check_mtime, Browse::None, "cfg.hint.mtime");
    inner->AddPage(fl.window(), L("cfg.page.filter"));

    auto* tp = new wxPanel(inner);
    BuildTargetPage(tp);
    inner->AddPage(tp, L("cfg.page.targets"));
    h->Add(inner, 1, wxEXPAND | wxALL, 6);
    wp->SetSizer(h);
    nb->AddPage(wp, L("cfg.page.watches"));

    ba->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { AddWatch(); });
    bd->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { DupWatch(); });
    br->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { RemoveWatch(); });
    watches_->Bind(wxEVT_LISTBOX, [this](wxCommandEvent& e) { SelectWatch(e.GetSelection()); });
}

void ConfigTab::BuildTargetPage(wxWindow* tp) {
    auto edit = [this] { MarkEdited(); };
    auto* v = new wxBoxSizer(wxVERTICAL);
    auto* r = new wxBoxSizer(wxHORIZONTAL);
    targets_ = new wxListBox(tp, wxID_ANY, wxDefaultPosition, wxSize(-1, 80));
    r->Add(targets_, 1, wxEXPAND | wxRIGHT, 6);
    auto* bs = new wxBoxSizer(wxVERTICAL);
    auto* ba = new wxButton(tp, wxID_ANY, "+", wxDefaultPosition, wxSize(34, -1));
    auto* br = new wxButton(tp, wxID_ANY, "−", wxDefaultPosition, wxSize(34, -1));
    ba->SetToolTip(L("cfg.target.add"));
    br->SetToolTip(L("cfg.target.remove"));
    bs->Add(ba, 0, wxBOTTOM, 4);
    bs->Add(br, 0);
    r->Add(bs, 0);
    v->Add(r, 0, wxEXPAND | wxALL, 6);

    auto* kr = new wxBoxSizer(wxHORIZONTAL);
    kr->Add(new wxStaticText(tp, wxID_ANY, L("cfg.t.kind")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    kind_ = new wxChoice(tp, wxID_ANY);
    kind_->Append(L("cfg.t.kind.net"));
    kind_->Append(L("cfg.t.kind.local"));
    kind_->SetSelection(0);
    kr->Add(kind_, 0);
    v->Add(kr, 0, wxLEFT | wxRIGHT, 6);

    f_target_ = std::make_unique<Form<TargetConfig>>(tp, [this] { return cur_target(); }, edit);
    auto& f = *f_target_;
    f.text("cfg.t.host", R(TargetConfig, host), [this](const std::string& s) { return target_local_ ? std::string() : check_host(s); });
    f.num<uint16_t>("cfg.t.port", R(TargetConfig, port), 1, 65535);
    f.custom(
        "cfg.t.server_key", new wxTextCtrl(f.parent(), wxID_ANY, ""),
        [this](const std::string& s) -> std::string {
            if (target_local_) return "";
            try {
                KeyManager::normalize_public_hex(s);
                return "";
            } catch (const std::exception& e) {
                return e.what();
            }
        },
        [](TargetConfig& t, wxTextCtrl* c) { c->ChangeValue(key_is_unset(t.server_key) ? wxString() : W(key_to_hex(t.server_key))); },
        [this](TargetConfig& t, const std::string& s) {
            if (target_local_ || trim(s).empty()) return;
            auto raw = from_hex(KeyManager::normalize_public_hex(s));
            std::copy(raw.begin(), raw.begin() + 32, t.server_key.begin());
        });
    f.text("cfg.t.key_file", R(TargetConfig, key_file), {}, Browse::FileOpen, "cfg.hint.keyfile_default");
    f.text("cfg.t.remote_prefix", R(TargetConfig, remote_prefix), check_prefix);
    f.text("cfg.t.path", R(TargetConfig, path), [this](const std::string& s) { return target_local_ ? check_nonempty(s) : std::string(); }, Browse::Dir);
    f.mode("cfg.t.file_mode", R(TargetConfig, file_mode), false);
    f.mode("cfg.t.dir_mode", R(TargetConfig, dir_mode), true);
    f.boolean("cfg.t.enabled", R(TargetConfig, enabled));
    v->Add(f.window(), 1, wxEXPAND);
    tp->SetSizer(v);

    kind_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) {
        target_local_ = kind_->GetSelection() == 1;
        if (f_target_) {
            f_target_->Revalidate();
            apply_kind(*f_target_, target_local_, cur_target() != nullptr);
        }
        MarkEdited();
    });
    ba->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { AddTarget(); });
    br->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { RemoveTarget(); });
    targets_->Bind(wxEVT_LISTBOX, [this](wxCommandEvent& e) { SelectTarget(e.GetSelection()); });
}

void ConfigTab::BuildServer(wxWindow* parent) {
    auto edit = [this] { MarkEdited(); };
    f_server_ = std::make_unique<Form<ServerConfig>>(parent, [this] { return cur_server(); }, edit);
    auto& f = *f_server_;
    f.text("cfg.s.bind", R(ServerConfig, bind), check_nonempty);
    f.num<uint16_t>("cfg.s.port", R(ServerConfig, port), 1, 65535);
    f.text("cfg.s.root", R(ServerConfig, root), check_nonempty, Browse::Dir);
    f.text("cfg.key_file", R(ServerConfig, key_file), check_nonempty, Browse::FileOpen);
    f.num<uint32_t>("cfg.s.max_connections", R(ServerConfig, max_connections), 1, 100000);
    f.num<uint32_t>("cfg.s.max_auth_failures", R(ServerConfig, max_auth_failures_per_min), 1, 100000);
    f.num<uint32_t>("cfg.max_bandwidth_kbps", R(ServerConfig, max_bandwidth_kbps), 0, 100000000, "cfg.hint.zero_unlimited");
    f.boolean("cfg.s.trash", R(ServerConfig, trash));
    f.size("cfg.s.max_trash", R(ServerConfig, max_trash_bytes), true, "cfg.hint.size0");
    f.size("cfg.s.max_file_size", R(ServerConfig, max_file_size), true, "cfg.hint.size0");
    f.mode("cfg.s.file_mode", R(ServerConfig, file_mode), false);
    f.mode("cfg.s.dir_mode", R(ServerConfig, dir_mode), true);
    f.num<uint32_t>("cfg.s.io_timeout", R(ServerConfig, io_timeout_s), 1, 86400);
    f.lines("cfg.s.allow", R(ServerConfig, allow), check_ip_lines, 3, "cfg.hint.ip");
    f.lines("cfg.s.deny", R(ServerConfig, deny), check_ip_lines, 3, "cfg.hint.ip");
    f.text("cfg.state_dir", R(ServerConfig, state_dir), {}, Browse::Dir);
    f.text("cfg.log_file", R(ServerConfig, log_file), {}, Browse::FileSave);
    f.choice("cfg.log_level", R(ServerConfig, log_level), kLogLevels);
    auto* v = new wxBoxSizer(wxVERTICAL);
    v->Add(f.window(), 1, wxEXPAND);
    parent->SetSizer(v);
}

// ---------------------------------------------------------------- đồng bộ ô <-> struct
void ConfigTab::PushAll() {
    auto* c = cur_client();
    auto* s = cur_server();
    book_->SetSelection(c ? 1 : s ? 2 : 0);
    role_lbl_->SetLabelText(sh_.cfg ? W(tr(c ? "cfg.role.client" : "cfg.role.server") + "  ·  " + sh_.cfg->path()) : wxString());
    if (c) {
        if (cur_w_ >= static_cast<int>(c->watches.size())) cur_w_ = static_cast<int>(c->watches.size()) - 1;
        if (cur_w_ < 0 && !c->watches.empty()) cur_w_ = 0;
        RefreshWatchList();
        f_client_->Push();
        f_watch_->Push();
        f_filter_->Push();
        RefreshTargetList();
    }
    if (s) f_server_->Push();
    edited_ = false;
    UpdateStatusLine();
    Layout();
}

void ConfigTab::RefreshWatchList() {
    auto* c = cur_client();
    watches_->Clear();
    if (!c) return;
    for (auto& w : c->watches) watches_->Append(W((w.enabled ? "" : "⏸ ") + (w.name.empty() ? tr("cfg.unnamed") : w.name)));
    if (cur_w_ >= 0) watches_->SetSelection(cur_w_);
}

void ConfigTab::RefreshTargetList() {
    targets_->Clear();
    auto* w = cur_watch();
    if (!w) {
        cur_t_ = -1;
        f_target_->Push();
        return;
    }
    if (cur_t_ >= static_cast<int>(w->targets.size())) cur_t_ = static_cast<int>(w->targets.size()) - 1;
    if (cur_t_ < 0 && !w->targets.empty()) cur_t_ = 0;
    for (auto& t : w->targets) {
        std::string label = t.is_local() ? t.path : t.host + ":" + std::to_string(t.port);
        targets_->Append(W((t.enabled ? "" : "⏸ ") + (t.is_local() ? std::string("\U0001F4C1 ") : std::string("\U0001F310 ")) + label));
    }
    if (cur_t_ >= 0) targets_->SetSelection(cur_t_);
    auto* t = cur_target();
    target_local_ = t && t->is_local();
    kind_->SetSelection(target_local_ ? 1 : 0);
    kind_->Enable(t != nullptr);
    f_target_->Push();
    apply_kind(*f_target_, target_local_, t != nullptr);
}

bool ConfigTab::CommitStrict(bool report) {
    std::vector<std::string> errs;
    auto add = [&](std::vector<std::string> e) { errs.insert(errs.end(), e.begin(), e.end()); };
    if (cur_client()) {
        add(f_client_->Pull());
        if (cur_watch()) {
            add(f_watch_->Pull());
            add(f_filter_->Pull());
            if (cur_target()) {
                auto te = f_target_->Pull();
                add(te);
                if (te.empty()) {
                    auto* t = cur_target();
                    if (target_local_) {
                        t->host.clear();
                        t->server_key = PublicKey{};
                    } else {
                        t->path.clear();
                    }
                }
            }
        }
    } else if (cur_server()) {
        add(f_server_->Pull());
    }
    if (!errs.empty() && report) sh_.report(BannerLevel::Error, "cfg.fields", join(errs, "\n"));
    if (errs.empty()) sh_.clear_report("cfg.fields");
    return errs.empty();
}

void ConfigTab::CommitQuiet() {
    if (!sh_.cfg) return;
    if (cur_client() && f_client_->AnyBad()) return;
    CommitStrict(false);
}

void ConfigTab::MarkEdited() {
    edited_ = true;
    UpdateStatusLine();
}

bool ConfigTab::HasUnsaved() const { return edited_ || (sh_.cfg && sh_.cfg->dirty()); }

void ConfigTab::UpdateStatusLine() {
    status_->SetLabelText(HasUnsaved() ? L("cfg.unsaved") : (sh_.cfg ? L("cfg.saved") : wxString()));
    status_->SetForegroundColour(HasUnsaved() ? wxColour(0x90, 0x6A, 0x00) : wxColour(0x50, 0x50, 0x50));
    save_->Enable(sh_.cfg != nullptr);
    revert_->Enable(sh_.cfg != nullptr);
}

void ConfigTab::OnConfigChanged() {
    // Struct có thể vừa bị tab khác sửa (thêm máy khách, ghim khoá...). Giữ ô đang sửa dở nếu có ô sai.
    if (sh_.cfg && edited_ && !CommitStrict(false)) {
        UpdateStatusLine();
        return;
    }
    if (!sh_.cfg_path.empty() && S(path_->GetValue()).empty()) path_->SetValue(W(sh_.cfg_path));
    if (sh_.cfg) path_->ChangeValue(W(sh_.cfg->path()));
    bool was = sh_.cfg && sh_.cfg->dirty();
    PushAll();
    if (was) UpdateStatusLine();
}

// ---------------------------------------------------------------- danh sách watch / đích
void ConfigTab::SelectWatch(int idx) {
    if (!cur_client() || idx == cur_w_) return;
    if (!CommitStrict(true)) {
        watches_->SetSelection(cur_w_);  // không cho chuyển khi còn ô sai
        return;
    }
    cur_w_ = idx;
    cur_t_ = -1;
    f_watch_->Push();
    f_filter_->Push();
    RefreshTargetList();
    RefreshWatchList();
}

void ConfigTab::SelectTarget(int idx) {
    if (!cur_watch() || idx == cur_t_) return;
    if (!CommitStrict(true)) {
        targets_->SetSelection(cur_t_);
        return;
    }
    cur_t_ = idx;
    RefreshTargetList();
}

void ConfigTab::AddWatch() {
    auto* c = cur_client();
    if (!c || !CommitStrict(true)) return;
    WatchConfig w;
    w.name = "watch-" + std::to_string(c->watches.size() + 1);
    TargetConfig t;
    w.targets.push_back(t);
    c->watches.push_back(w);
    cur_w_ = static_cast<int>(c->watches.size()) - 1;
    cur_t_ = 0;
    RefreshWatchList();
    f_watch_->Push();
    f_filter_->Push();
    RefreshTargetList();
    MarkEdited();
}

void ConfigTab::DupWatch() {
    auto* c = cur_client();
    if (!c || !cur_watch() || !CommitStrict(true)) return;
    WatchConfig w = *cur_watch();
    w.name += "-copy";
    c->watches.push_back(w);
    cur_w_ = static_cast<int>(c->watches.size()) - 1;
    cur_t_ = 0;
    RefreshWatchList();
    f_watch_->Push();
    f_filter_->Push();
    RefreshTargetList();
    MarkEdited();
}

void ConfigTab::RemoveWatch() {
    auto* c = cur_client();
    auto* w = cur_watch();
    if (!c || !w) return;
    wxMessageDialog q(this, W(trf("cfg.watch.confirm_remove", {w->name})), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
    if (q.ShowModal() != wxID_YES) return;
    c->watches.erase(c->watches.begin() + cur_w_);
    if (cur_w_ >= static_cast<int>(c->watches.size())) cur_w_ = static_cast<int>(c->watches.size()) - 1;
    cur_t_ = -1;
    RefreshWatchList();
    f_watch_->Push();
    f_filter_->Push();
    RefreshTargetList();
    MarkEdited();
}

void ConfigTab::AddTarget() {
    auto* w = cur_watch();
    if (!w || !CommitStrict(true)) return;
    w->targets.push_back(TargetConfig{});
    cur_t_ = static_cast<int>(w->targets.size()) - 1;
    RefreshTargetList();
    MarkEdited();
}

void ConfigTab::RemoveTarget() {
    auto* w = cur_watch();
    if (!w || !cur_target()) return;
    w->targets.erase(w->targets.begin() + cur_t_);
    cur_t_ = -1;
    RefreshTargetList();
    MarkEdited();
}

// ---------------------------------------------------------------- mở / tạo / lưu
void ConfigTab::BrowseOpen() {
    wxFileDialog dlg(this, L("cfg.file"), "", "", "TOML (*.toml)|*.toml|*.*|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (dlg.ShowModal() == wxID_OK) {
        path_->SetValue(dlg.GetPath());
        OpenPath(S(dlg.GetPath()));
    }
}

void ConfigTab::OpenPath(const std::string& path0) {
    std::string path = trim(path0);
    if (path.empty()) {
        sh_.report(BannerLevel::Error, "cfg.open", S(L("cfg.file")) + ": " + S(L("err.required")));
        return;
    }
    if (HasUnsaved() && sh_.cfg && sh_.cfg->path() != path) {
        wxMessageDialog q(this, L("cfg.discard.confirm"), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        if (q.ShowModal() != wxID_YES) return;
    }
    if (!gate_.begin("busy.loadcfg")) return;
    path_->ChangeValue(W(path));
    run_async<ConfigEditor>(
        alive_, [path]() { return ConfigEditor::open(path); },
        [this, path](bool ok, ConfigEditor& ed, const std::string& err) {
            gate_.end();
            if (!ok) {
                sh_.report(BannerLevel::Error, "cfg.open", err);  // nguyên văn, có số dòng
                return;
            }
            sh_.clear_report("cfg.open");
            sh_.clear_report("cfg.fields");
            sh_.cfg = std::make_unique<ConfigEditor>(std::move(ed));
            sh_.cfg_path = path;
            sh_.set_setting("cfgpath", path);
            cur_w_ = cur_t_ = -1;
            edited_ = false;
            prompted_hash_ = sh_.cfg->disk_hash();
            sh_.config_changed();
        });
}

void ConfigTab::NewConfig(ConfigRole role) {
    wxFileDialog dlg(this, L("cfg.new"), "", role == ConfigRole::Server ? "server.toml" : "client.toml", "TOML (*.toml)|*.toml",
                     wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dlg.ShowModal() != wxID_OK) return;
    std::string path = S(dlg.GetPath());
    try {
        auto ed = ConfigEditor::create(path, role);
        if (role == ConfigRole::Client) {
            WatchConfig w;
            w.name = "watch-1";
            w.targets.push_back(TargetConfig{});
            ed.client().watches.push_back(w);
        }
        sh_.cfg = std::make_unique<ConfigEditor>(std::move(ed));
        sh_.cfg_path = path;
        sh_.set_setting("cfgpath", path);
        sh_.clear_report("cfg.open");
        cur_w_ = 0;
        cur_t_ = 0;
        sh_.config_changed();
        MarkEdited();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "cfg.open", e.what());
    }
}

void ConfigTab::ShowToml() {
    if (!sh_.cfg) return;
    if (!CommitStrict(true)) return;
    try {
        std::string t = sh_.cfg->to_toml();
        wxDialog d(this, wxID_ANY, L("cfg.showtoml"), wxDefaultPosition, wxSize(720, 520), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
        auto* v = new wxBoxSizer(wxVERTICAL);
        auto* tc = new wxTextCtrl(&d, wxID_ANY, W(t), wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY | wxHSCROLL);
        tc->SetFont(wxFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL));
        v->Add(tc, 1, wxEXPAND | wxALL, 8);
        v->Add(d.CreateStdDialogButtonSizer(wxOK), 0, wxEXPAND | wxALL, 8);
        d.SetSizer(v);
        d.ShowModal();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "cfg.fields", e.what());
    }
}

bool ConfigTab::Save() {
    if (!sh_.cfg) return false;
    if (!CommitStrict(true)) return false;

    // Lớp chắn 1: thông điệp chỉ rõ ô nào sai (mọi watch, kể cả cái không đang hiện).
    auto probs = cur_client() ? problems_client(*cur_client()) : problems_server(*cur_server());
    if (!probs.empty()) {
        sh_.report(BannerLevel::Error, "cfg.fields", join(probs, "\n"));
        return false;
    }
    // Lớp chắn 2: đúng bộ phân tích của daemon (lỗi nguyên văn).
    try {
        sh_.cfg->validate();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "cfg.fields", e.what());
        return false;
    }
    sh_.clear_report("cfg.fields");

    // Lần đầu: cảnh báo .bak và mất chú thích tay.
    if (sh_.get_setting("bak_warned", "") != "1") {
        wxMessageDialog q(this, L("cfg.firstsave.msg"), L("cfg.firstsave.title"), wxOK | wxCANCEL | wxICON_WARNING);
        q.SetOKCancelLabels(L("cfg.firstsave.ok"), L("btn.cancel"));
        if (q.ShowModal() != wxID_OK) return false;
        sh_.set_setting("bak_warned", "1");
    }

    SaveOptions opts;
    opts.make_backup = true;
    try {
        if (sh_.cfg->changed_on_disk()) {
            wxMessageDialog q(this, L("cfg.ext.msg"), L("cfg.ext.title"), wxYES_NO | wxCANCEL | wxICON_QUESTION);
            q.SetYesNoCancelLabels(L("cfg.ext.overwrite"), L("cfg.ext.reload"), L("btn.cancel"));
            int r = q.ShowModal();
            if (r == wxID_CANCEL) return false;
            if (r == wxID_NO) {
                OpenPath(sh_.cfg->path());
                return false;
            }
            opts.force = true;
        }
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "cfg.save", e.what());
        return false;
    }

    if (!gate_.begin("busy.save")) return false;
    ConfigEditor copy = *sh_.cfg;
    bool connected = sh_.have_poll && sh_.last.connected;
    std::string daemon = sh_.daemon_name;
    run_async<SaveOutcome>(
        alive_,
        [copy, opts, connected, daemon]() mutable {
            SaveOutcome o;
            copy.save(opts);
            o.ed = copy;
            if (connected) {
                o.reload_attempted = true;
                try {
                    ControlClient cc(daemon, 20000);
                    o.rr = cc.reload_config();
                } catch (const std::exception& e) {
                    o.reload_err = e.what();
                }
            }
            return o;
        },
        [this](bool ok, SaveOutcome& o, const std::string& err) {
            gate_.end();
            if (!ok) {
                sh_.report(BannerLevel::Error, "cfg.save", err);  // nguyên văn (kể cả "tệp đã bị sửa ngoài")
                return;
            }
            FinishSave(o);
        });
    return true;
}

void ConfigTab::FinishSave(SaveOutcome& o) {
    sh_.clear_report("cfg.save");
    *sh_.cfg = o.ed;
    prompted_hash_ = sh_.cfg->disk_hash();
    edited_ = false;
    std::string msg = tr("cfg.saved_to") + " " + sh_.cfg->path();
    if (!o.reload_attempted) {
        msg += "  ·  " + tr("cfg.nodaemon");
    } else if (!o.reload_err.empty()) {
        sh_.report(BannerLevel::Warning, "cfg.reload", trf("cfg.reload.transport", {o.reload_err}));
    } else if (!o.rr.ok) {
        sh_.report(BannerLevel::Error, "cfg.reload", trf("cfg.reload.refused", {o.rr.message}));
    } else {
        sh_.clear_report("cfg.reload");
        msg += "  ·  " + tr("cfg.reloaded");
        if (!o.rr.needs_restart.empty())
            sh_.report(BannerLevel::Warning, "cfg.restart", trf("cfg.needs_restart", {join(o.rr.needs_restart, ", ")}));
        else
            sh_.clear_report("cfg.restart");
    }
    status_->SetLabelText(W(msg));
    status_->SetForegroundColour(wxColour(0x1E, 0x7E, 0x34));
    sh_.poll_now();
    sh_.config_changed();
    status_->SetLabelText(W(msg));  // config_changed làm mới dòng trạng thái; đặt lại thông điệp kết quả
}

// ---------------------------------------------------------------- phát hiện tệp bị sửa ngoài
void ConfigTab::CheckDisk() {
    if (!sh_.cfg || checking_ || gate_.busy() || !IsShownOnScreen()) return;
    std::string path = sh_.cfg->path();
    std::string known = sh_.cfg->disk_hash();
    checking_ = true;
    run_async<std::string>(
        alive_, [path]() { return file_content_hash(path); },
        [this, known, path](bool ok, std::string& now, const std::string& err) {
            checking_ = false;
            if (!ok) {
                sh_.report(BannerLevel::Warning, "cfg.disk", err);
                return;
            }
            sh_.clear_report("cfg.disk");
            if (!sh_.cfg || sh_.cfg->path() != path || now == known || now == prompted_hash_) return;
            prompted_hash_ = now;  // hỏi một lần cho mỗi phiên bản của tệp
            wxMessageDialog q(this, W(trf("cfg.ext.detected", {path})), L("cfg.ext.title"), wxYES_NO | wxICON_QUESTION);
            q.SetYesNoLabels(L("cfg.ext.reload"), L("cfg.ext.keep"));
            if (q.ShowModal() == wxID_YES) {
                edited_ = false;
                try {
                    sh_.cfg->reload();
                    sh_.config_changed();
                } catch (const std::exception& e) {
                    sh_.report(BannerLevel::Error, "cfg.open", e.what());
                }
            }
        });
}

}  // namespace mysync::gui

namespace mysync::gui {
void ConfigTab::SelectPage(int outer, int inner) {
    if (nb_client_ && outer >= 0 && outer < static_cast<int>(nb_client_->GetPageCount())) nb_client_->SetSelection(outer);
    if (nb_watch_ && inner >= 0 && inner < static_cast<int>(nb_watch_->GetPageCount())) nb_watch_->SetSelection(inner);
}
}  // namespace mysync::gui
