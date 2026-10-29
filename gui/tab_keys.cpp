// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "tab_keys.h"

#include <wx/clipbrd.h>
#include <wx/filedlg.h>
#include <wx/filename.h>

#include "form_model.h"

namespace mysync::gui {

namespace {

// Hộp thoại thêm / sửa một máy khách được phép (server). Khoá bí mật không bao giờ xuất hiện ở đây.
class ClientDialog : public wxDialog {
public:
    ClientDialog(wxWindow* parent, const AllowedClient& init, bool editing)
        : wxDialog(parent, wxID_ANY, L(editing ? "keys.dlg.edit" : "keys.dlg.add"), wxDefaultPosition, wxDefaultSize,
                   wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER) {
        auto* v = new wxBoxSizer(wxVERTICAL);
        auto* g = new wxFlexGridSizer(2, 6, 8);
        g->AddGrowableCol(1, 1);
        auto lab = [&](const char* k) { g->Add(new wxStaticText(this, wxID_ANY, L(k)), 0, wxALIGN_CENTER_VERTICAL); };
        lab("keys.cl.name");
        name_ = new wxTextCtrl(this, wxID_ANY, W(init.name));
        g->Add(name_, 1, wxEXPAND);
        lab("keys.cl.key");
        key_ = new wxTextCtrl(this, wxID_ANY, W(init.public_hex), wxDefaultPosition, wxSize(460, -1));
        g->Add(key_, 1, wxEXPAND);
        lab("keys.cl.fp");
        fp_ = new wxStaticText(this, wxID_ANY, "");
        g->Add(fp_, 1, wxEXPAND);
        lab("keys.cl.access");
        access_ = new wxChoice(this, wxID_ANY);
        access_->Append(L("keys.access.rw"));
        access_->Append(L("keys.access.ro"));
        access_->SetSelection(init.read_only ? 1 : 0);
        g->Add(access_, 0);
        lab("keys.cl.prefix");
        prefix_ = new wxTextCtrl(this, wxID_ANY, W(init.prefix));
        g->Add(prefix_, 1, wxEXPAND);
        lab("keys.cl.sessions");
        sessions_ = new wxTextCtrl(this, wxID_ANY, W(std::to_string(init.max_sessions)));
        g->Add(sessions_, 0);
        lab("keys.cl.quota");
        quota_ = new wxTextCtrl(this, wxID_ANY, W(size_to_text(init.max_write_bytes_per_hour)));
        g->Add(quota_, 0);
        lab("keys.cl.bw");
        bw_ = new wxTextCtrl(this, wxID_ANY, W(std::to_string(init.max_bandwidth_kbps)));
        g->Add(bw_, 0);
        v->Add(g, 0, wxEXPAND | wxALL, 10);
        err_ = new wxStaticText(this, wxID_ANY, "");
        err_->SetForegroundColour(wxColour(0xA0, 0x10, 0x10));
        v->Add(err_, 0, wxLEFT | wxRIGHT, 10);
        v->Add(CreateStdDialogButtonSizer(wxOK | wxCANCEL), 0, wxEXPAND | wxALL, 10);
        SetSizerAndFit(v);
        key_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { UpdateFp(); });
        UpdateFp();
        Bind(wxEVT_BUTTON, [this](wxCommandEvent& e) {
            if (!Validate()) return;
            e.Skip();
        }, wxID_OK);
    }

    AllowedClient result;

private:
    void UpdateFp() {
        try {
            fp_->SetLabelText(W(KeyManager::fingerprint(KeyManager::normalize_public_hex(S(key_->GetValue())))));
        } catch (const std::exception&) {
            fp_->SetLabelText("—");
        }
    }
    bool Validate() {
        std::string e = check_client_name(S(name_->GetValue()));
        if (e.empty()) e = check_prefix(S(prefix_->GetValue()));
        uint64_t sess = 0, bw = 0, quota = 0;
        if (e.empty()) e = check_uint(S(sessions_->GetValue()), 0, 1000, &sess);
        if (e.empty()) e = check_size(S(quota_->GetValue()), true, &quota);
        if (e.empty()) e = check_uint(S(bw_->GetValue()), 0, 100000000, &bw);
        std::string hex;
        if (e.empty()) {
            try {
                hex = KeyManager::normalize_public_hex(S(key_->GetValue()));
            } catch (const std::exception& ex) {
                e = ex.what();
            }
        }
        if (!e.empty()) {
            err_->SetLabelText(W(e));
            Layout();
            return false;
        }
        result.name = trim(S(name_->GetValue()));
        result.public_hex = hex;
        result.read_only = access_->GetSelection() == 1;
        result.prefix = trim(S(prefix_->GetValue()));
        result.max_sessions = static_cast<uint32_t>(sess);
        result.max_write_bytes_per_hour = quota;
        result.max_bandwidth_kbps = static_cast<uint32_t>(bw);
        return true;
    }
    wxTextCtrl *name_, *key_, *prefix_, *sessions_, *quota_, *bw_;
    wxStaticText *fp_, *err_;
    wxChoice* access_;
};

}  // namespace

KeysTab::KeysTab(wxWindow* parent, Shared& sh) : wxPanel(parent, wxID_ANY), sh_(sh) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxEXPAND | wxALL, 8);
    content_ = new wxPanel(this, wxID_ANY);
    auto* v = new wxBoxSizer(wxVERTICAL);

    // --- A. khoá của máy này
    auto* boxA = new wxStaticBoxSizer(wxVERTICAL, content_, L("keys.mine"));
    auto* ra = new wxBoxSizer(wxHORIZONTAL);
    ra->Add(new wxStaticText(boxA->GetStaticBox(), wxID_ANY, L("keys.file")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    keyfile_ = new wxTextCtrl(boxA->GetStaticBox(), wxID_ANY, "");
    ra->Add(keyfile_, 1, wxRIGHT, 6);
    auto* br = new wxButton(boxA->GetStaticBox(), wxID_ANY, L("btn.browse"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    ra->Add(br, 0, wxRIGHT, 6);
    auto* gen = new wxButton(boxA->GetStaticBox(), wxID_ANY, L("keys.generate"));
    ra->Add(gen, 0, wxRIGHT, 6);
    auto* show = new wxButton(boxA->GetStaticBox(), wxID_ANY, L("keys.showexisting"));
    ra->Add(show, 0);
    boxA->Add(ra, 0, wxEXPAND | wxALL, 6);
    auto* rb = new wxBoxSizer(wxHORIZONTAL);
    rb->Add(new wxStaticText(boxA->GetStaticBox(), wxID_ANY, L("keys.pub")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    pub_ = new wxTextCtrl(boxA->GetStaticBox(), wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
    rb->Add(pub_, 1, wxRIGHT, 6);
    auto* cp = new wxButton(boxA->GetStaticBox(), wxID_ANY, L("keys.copy"));
    rb->Add(cp, 0);
    boxA->Add(rb, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 6);
    auto* rc = new wxBoxSizer(wxHORIZONTAL);
    rc->Add(new wxStaticText(boxA->GetStaticBox(), wxID_ANY, L("keys.fp")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    fp_ = new wxTextCtrl(boxA->GetStaticBox(), wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
    rc->Add(fp_, 1);
    boxA->Add(rc, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 6);
    boxA->Add(new wxStaticText(boxA->GetStaticBox(), wxID_ANY, L("keys.secretnote")), 0, wxLEFT | wxRIGHT | wxBOTTOM, 6);
    v->Add(boxA, 0, wxEXPAND | wxALL, 6);

    // --- B. dán khoá của bên kia
    auto* boxB = new wxStaticBoxSizer(wxVERTICAL, content_, L("keys.theirs"));
    role_note_ = new wxStaticText(boxB->GetStaticBox(), wxID_ANY, "");
    boxB->Add(role_note_, 0, wxALL, 6);
    paste_ = new wxTextCtrl(boxB->GetStaticBox(), wxID_ANY, "");
    paste_->SetHint(L("keys.paste.hint"));
    boxB->Add(paste_, 0, wxEXPAND | wxLEFT | wxRIGHT, 6);
    paste_info_ = new wxStaticText(boxB->GetStaticBox(), wxID_ANY, "");
    boxB->Add(paste_info_, 0, wxALL, 6);
    auto* rbtn = new wxBoxSizer(wxHORIZONTAL);
    target_ = new wxChoice(boxB->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxSize(320, -1));
    pin_ = new wxButton(boxB->GetStaticBox(), wxID_ANY, L("keys.pin"));
    add_from_paste_ = new wxButton(boxB->GetStaticBox(), wxID_ANY, L("keys.addclient_from_paste"));
    rbtn->Add(target_, 0, wxRIGHT, 6);
    rbtn->Add(pin_, 0, wxRIGHT, 6);
    rbtn->Add(add_from_paste_, 0);
    boxB->Add(rbtn, 0, wxLEFT | wxRIGHT | wxBOTTOM, 6);
    v->Add(boxB, 0, wxEXPAND | wxALL, 6);

    // --- C. allowlist (server)
    auto* boxC = new wxStaticBoxSizer(wxVERTICAL, content_, L("keys.allowlist"));
    clients_ = new wxListCtrl(boxC->GetStaticBox(), wxID_ANY, wxDefaultPosition, wxSize(-1, 150), wxLC_REPORT | wxLC_SINGLE_SEL);
    const char* ck[] = {"keys.cl.name", "keys.cl.fp", "keys.cl.access", "keys.cl.prefix", "keys.cl.sessions", "keys.cl.quota"};
    int cw[] = {160, 190, 70, 120, 80, 90};
    for (int i = 0; i < 6; ++i) clients_->AppendColumn(L(ck[i]), wxLIST_FORMAT_LEFT, cw[i]);
    boxC->Add(clients_, 1, wxEXPAND | wxALL, 6);
    auto* cb = new wxBoxSizer(wxHORIZONTAL);
    auto* badd = new wxButton(boxC->GetStaticBox(), wxID_ANY, L("keys.cl.add"));
    auto* bedit = new wxButton(boxC->GetStaticBox(), wxID_ANY, L("keys.cl.edit"));
    auto* brem = new wxButton(boxC->GetStaticBox(), wxID_ANY, L("keys.cl.remove"));
    auto* bsave = new wxButton(boxC->GetStaticBox(), wxID_ANY, L("cfg.save"));
    for (auto* b : {badd, bedit, brem}) cb->Add(b, 0, wxRIGHT, 6);
    cb->AddStretchSpacer(1);
    cb->Add(bsave, 0);
    boxC->Add(cb, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 6);
    v->Add(boxC, 1, wxEXPAND | wxALL, 6);
    content_->SetSizer(v);
    top->Add(content_, 1, wxEXPAND);
    SetSizer(top);
    gate_ = BusyGate(content_, busy_);

    br->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        wxFileDialog dlg(this, L("keys.file"), "", "", "*.key|*.key|*.*|*.*", wxFD_SAVE);
        if (dlg.ShowModal() == wxID_OK) keyfile_->SetValue(dlg.GetPath());
    });
    gen->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Generate(); });
    show->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { ShowExisting(); });
    cp->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { CopyPublic(); });
    paste_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { OnPasteChanged(); });
    pin_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { PinServerKey(); });
    add_from_paste_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        try {
            AddClient(KeyManager::normalize_public_hex(S(paste_->GetValue())));
        } catch (const std::exception& e) {
            sh_.report(BannerLevel::Error, "keys.paste", e.what());
        }
    });
    badd->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { AddClient(""); });
    bedit->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { EditClient(); });
    brem->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { RemoveClient(); });
    bsave->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { sh_.save_config(); });
    clients_->Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent&) { EditClient(); });

    boxC_ = boxC;
    OnConfigChanged();
}

std::string KeysTab::Resolve(const std::string& p) const {
    // Đường dẫn tương đối trong cấu hình được hiểu so với thư mục chứa tệp cấu hình (như daemon).
    wxFileName fn(W(p));
    if (!p.empty() && !fn.IsAbsolute() && sh_.cfg) fn.MakeAbsolute(wxFileName(W(sh_.cfg->path())).GetPath());
    return S(fn.GetFullPath());
}

std::string KeysTab::DefaultKeyPath() const {
    wxFileName dir = sh_.cfg ? wxFileName(W(sh_.cfg->path())) : wxFileName();
    wxString d = dir.IsOk() ? dir.GetPath() : wxString();
    wxString name = IsServer() ? "server.key" : "client.key";
    return S(d.empty() ? name : (d + wxFileName::GetPathSeparator() + name));
}

void KeysTab::OnConfigChanged() {
    bool server = IsServer();
    role_note_->SetLabelText(L(!sh_.cfg ? "keys.note.nocfg" : server ? "keys.note.server" : "keys.note.client"));
    {
        // Ô tệp khoá theo cấu hình đang mở, trừ khi người dùng đã gõ đường dẫn khác.
        std::string kf = sh_.cfg ? (server ? sh_.cfg->server().key_file : sh_.cfg->client().key_file) : "";
        std::string want = kf.empty() ? DefaultKeyPath() : kf;
        std::string have = S(keyfile_->GetValue());
        if (have.empty() || have == auto_keyfile_) {
            keyfile_->ChangeValue(W(want));
            auto_keyfile_ = want;
        }
        // Tệp khoá đã có: đọc sẵn khoá công khai + vân tay để người dùng thấy ngay.
        if (sh_.cfg && !kf.empty()) {
            wxFileName fn(W(kf));
            if (!fn.IsAbsolute()) fn.MakeAbsolute(wxFileName(W(sh_.cfg->path())).GetPath());
            std::string abs = S(fn.GetFullPath());
            if (wxFileExists(W(abs)) && abs != last_read_key_ && !gate_.busy()) {
                last_read_key_ = abs;
                run_async<std::string>(
                    alive_, [abs]() { return KeyManager::public_key_of_file(abs); },
                    [this, abs](bool ok, std::string& hex, const std::string& err) {
                        if (ok) {
                            sh_.clear_report("keys.autoread");
                            ShowKey(hex);
                        } else {
                            sh_.report(BannerLevel::Warning, "keys.autoread", err);
                        }
                    });
            }
        }
    }
    // Chọn đích mạng để ghim khoá máy chủ.
    target_->Clear();
    target_idx_.clear();
    if (sh_.cfg && !server) {
        const auto& w = sh_.cfg->client().watches;
        for (size_t i = 0; i < w.size(); ++i)
            for (size_t j = 0; j < w[i].targets.size(); ++j)
                if (!w[i].targets[j].is_local()) {
                    target_->Append(W(w[i].name + " → " + w[i].targets[j].host + ":" + std::to_string(w[i].targets[j].port)));
                    target_idx_.emplace_back(i, j);
                }
        if (target_->GetCount()) target_->SetSelection(0);
    }
    pin_->Show(!server);
    target_->Show(!server);
    add_from_paste_->Show(server);
    content_->GetSizer()->Show(boxC_, server, true);
    pin_->Enable(sh_.cfg && !server && !target_idx_.empty());
    add_from_paste_->Enable(server);
    RefreshClients();
    OnPasteChanged();
    Layout();
}

void KeysTab::ShowKey(const std::string& pub_hex) {
    current_pub_ = pub_hex;
    pub_->SetValue(W(pub_hex));
    fp_->SetValue(W(pub_hex.empty() ? "" : KeyManager::fingerprint(pub_hex)));
}

void KeysTab::Generate() {
    std::string path = trim(S(keyfile_->GetValue()));
    if (path.empty()) {
        sh_.report(BannerLevel::Error, "keys.gen", S(L("keys.file")) + ": " + S(L("err.required")));
        return;
    }
    path = Resolve(path);
    sh_.clear_report("keys.gen");
    if (!gate_.begin("busy.keygen")) return;
    run_async<GeneratedKey>(
        alive_, [path]() { return KeyManager::generate_key_file(path); },
        [this](bool ok, GeneratedKey& k, const std::string& err) {
            gate_.end();
            if (!ok) {
                sh_.report(BannerLevel::Error, "keys.gen", S(L("keys.generate")) + ": " + err);
                return;
            }
            ShowKey(k.public_hex);
            keyfile_->SetValue(W(k.key_file));
            auto exp = KeyManager::key_file_exposure(k.key_file);
            if (!exp.empty()) {
                std::string who;
                for (auto& e : exp) who += (who.empty() ? "" : ", ") + e;
                sh_.report(BannerLevel::Warning, "keys.exposure", trf("keys.exposure", {k.key_file, who}));
            }
            if (sh_.cfg) {
                wxMessageDialog q(this, W(trf("keys.setcfg", {k.key_file})), L("app.title"), wxYES_NO | wxICON_QUESTION);
                if (q.ShowModal() == wxID_YES) {
                    try {
                        if (IsServer()) sh_.cfg->server().key_file = k.key_file;
                        else sh_.cfg->client().key_file = k.key_file;
                        sh_.config_changed();
                    } catch (const std::exception& e) {
                        sh_.report(BannerLevel::Error, "keys.gen", e.what());
                    }
                }
            }
        });
}

void KeysTab::ShowExisting() {
    std::string path = trim(S(keyfile_->GetValue()));
    if (path.empty()) return;
    path = Resolve(path);
    if (!gate_.begin("busy.keyread")) return;
    run_async<std::string>(
        alive_, [path]() { return KeyManager::public_key_of_file(path); },
        [this, path](bool ok, std::string& hex, const std::string& err) {
            gate_.end();
            if (!ok) {
                sh_.report(BannerLevel::Error, "keys.gen", S(L("keys.showexisting")) + ": " + err);
                return;
            }
            sh_.clear_report("keys.gen");
            ShowKey(hex);
            auto exp = KeyManager::key_file_exposure(path);
            if (!exp.empty()) {
                std::string who;
                for (auto& e : exp) who += (who.empty() ? "" : ", ") + e;
                sh_.report(BannerLevel::Warning, "keys.exposure", trf("keys.exposure", {path, who}));
            }
        });
}

void KeysTab::CopyPublic() {
    if (current_pub_.empty()) return;
    // Chỉ khoá CÔNG KHAI được đưa vào clipboard.
    if (wxTheClipboard->Open()) {
        wxTheClipboard->SetData(new wxTextDataObject(W(current_pub_)));
        wxTheClipboard->Close();
        sh_.clear_report("keys.copy");
        paste_info_->SetLabelText(L("keys.copied"));
    } else {
        sh_.report(BannerLevel::Error, "keys.copy", S(L("keys.copyfail")));
    }
}

void KeysTab::OnPasteChanged() {
    std::string t = S(paste_->GetValue());
    if (trim(t).empty()) {
        paste_info_->SetLabelText("");
        pin_->Enable(false);
        add_from_paste_->Enable(false);
        return;
    }
    try {
        std::string hex = KeyManager::normalize_public_hex(t);
        paste_info_->SetLabelText(W(tr("keys.paste.ok") + " " + KeyManager::fingerprint(hex)));
        paste_info_->SetForegroundColour(wxColour(0x1E, 0x7E, 0x34));
        pin_->Enable(sh_.cfg && !IsServer() && !target_idx_.empty());
        add_from_paste_->Enable(IsServer());
    } catch (const std::exception& e) {
        paste_info_->SetLabelText(W(e.what()));
        paste_info_->SetForegroundColour(wxColour(0xA0, 0x10, 0x10));
        pin_->Enable(false);
        add_from_paste_->Enable(false);
    }
    Layout();
}

void KeysTab::PinServerKey() {
    int sel = target_->GetSelection();
    if (!sh_.cfg || sel < 0 || static_cast<size_t>(sel) >= target_idx_.size()) return;
    try {
        KeyManager::set_target_server_key(*sh_.cfg, target_idx_[sel].first, target_idx_[sel].second, S(paste_->GetValue()));
        sh_.clear_report("keys.paste");
        paste_info_->SetLabelText(L("keys.pinned"));
        sh_.config_changed();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "keys.paste", e.what());
    }
}

void KeysTab::RefreshClients() {
    clients_->DeleteAllItems();
    if (!IsServer()) return;
    try {
        auto v = KeyManager::list_clients(*sh_.cfg);
        for (size_t i = 0; i < v.size(); ++i) {
            long r = clients_->InsertItem(static_cast<long>(i), W(v[i].name));
            clients_->SetItem(r, 1, W(v[i].fingerprint));
            clients_->SetItem(r, 2, L(v[i].read_only ? "keys.access.ro" : "keys.access.rw"));
            clients_->SetItem(r, 3, W(v[i].prefix.empty() ? "/" : v[i].prefix));
            clients_->SetItem(r, 4, W(std::to_string(v[i].max_sessions)));
            clients_->SetItem(r, 5, W(v[i].max_write_bytes_per_hour ? fmt_bytes(v[i].max_write_bytes_per_hour) + "/h" : tr("keys.unlimited")));
        }
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "keys.list", e.what());
    }
}

void KeysTab::AddClient(const std::string& prefill_key) {
    if (!IsServer()) return;
    AllowedClient init;
    init.public_hex = prefill_key;
    init.max_write_bytes_per_hour = 50ull << 30;
    ClientDialog dlg(this, init, false);
    if (dlg.ShowModal() != wxID_OK) return;
    try {
        KeyManager::add_client(*sh_.cfg, dlg.result);
        sh_.clear_report("keys.list");
        RefreshClients();
        sh_.config_changed();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "keys.list", e.what());
    }
}

void KeysTab::EditClient() {
    long sel = first_selected(clients_);
    if (!IsServer() || sel < 0) return;
    try {
        auto v = KeyManager::list_clients(*sh_.cfg);
        if (static_cast<size_t>(sel) >= v.size()) return;
        ClientDialog dlg(this, v[sel], true);
        if (dlg.ShowModal() != wxID_OK) return;
        KeyManager::update_client(*sh_.cfg, v[sel].name, dlg.result);
        sh_.clear_report("keys.list");
        RefreshClients();
        sh_.config_changed();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "keys.list", e.what());
    }
}

void KeysTab::RemoveClient() {
    long sel = first_selected(clients_);
    if (!IsServer() || sel < 0) return;
    try {
        auto v = KeyManager::list_clients(*sh_.cfg);
        if (static_cast<size_t>(sel) >= v.size()) return;
        wxMessageDialog q(this, W(trf("keys.cl.confirm_remove", {v[sel].name, v[sel].fingerprint})), L("app.title"),
                          wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        if (q.ShowModal() != wxID_YES) return;
        KeyManager::remove_client(*sh_.cfg, v[sel].name);
        sh_.clear_report("keys.list");
        RefreshClients();
        sh_.config_changed();
    } catch (const std::exception& e) {
        sh_.report(BannerLevel::Error, "keys.list", e.what());
    }
}

}  // namespace mysync::gui
