// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
#include <wx/listctrl.h>
#include <wx/wx.h>

#include "mysync/gui/key_mgr.h"
#include "shared.h"
#include "ui_common.h"

namespace mysync::gui {

class KeysTab : public wxPanel {
public:
    KeysTab(wxWindow* parent, Shared& sh);
    ~KeysTab() override { *alive_ = false; }
    void OnConfigChanged();

private:
    void Generate();
    void ShowExisting();
    void ShowKey(const std::string& pub_hex);
    void CopyPublic();
    void OnPasteChanged();
    void PinServerKey();
    void RefreshClients();
    void AddClient(const std::string& prefill_key);
    void EditClient();
    void RemoveClient();
    std::string DefaultKeyPath() const;
    std::string Resolve(const std::string& p) const;
    bool IsServer() const { return sh_.cfg && sh_.cfg->role() == ConfigRole::Server; }

    Shared& sh_;
    AliveFlag alive_ = make_alive();
    wxPanel* content_;
    BusyIndicator* busy_;
    BusyGate gate_{nullptr, nullptr};
    wxTextCtrl *keyfile_, *pub_, *fp_, *paste_;
    wxStaticText *paste_info_, *role_note_;
    wxChoice* target_;
    wxButton *pin_, *add_from_paste_;
    wxListCtrl* clients_;
    wxStaticBoxSizer* boxC_ = nullptr;
    std::string current_pub_, auto_keyfile_, last_read_key_;
    std::vector<std::pair<size_t, size_t>> target_idx_;
};

}  // namespace mysync::gui
