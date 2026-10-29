// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
#include <wx/listctrl.h>
#include <wx/wx.h>

#include <vector>

#include "shared.h"
#include "ui_common.h"

namespace mysync::gui {

class StatusTab : public wxPanel {
public:
    StatusTab(wxWindow* parent, Shared& sh);
    void OnPoll(const PollResult& r);  // luồng UI

private:
    void Apply(const PollResult& r);
    void FillTargets(const StatusSnapshot& s);
    void FillPeers(const StatusSnapshot& s);
    void FillActive();
    void FillErrors(const PollResult& r);
    void SetCell(wxListCtrl* l, long row, int col, const std::string& v);

    Shared& sh_;
    wxComboBox* daemon_ = nullptr;
    wxStaticText *conn_ = nullptr, *role_ = nullptr, *ver_ = nullptr, *up_ = nullptr, *cfgp_ = nullptr, *loaded_ = nullptr,
                 *rate_ = nullptr, *totals_ = nullptr, *listen_ = nullptr;
    wxButton* open_cfg_ = nullptr;
    BusyIndicator* busy_ = nullptr;
    wxListCtrl* list_ = nullptr;
    wxListBox* active_ = nullptr;
    wxTextCtrl* last_err_ = nullptr;
    wxListCtrl* errs_ = nullptr;
    wxStaticText* list_title_ = nullptr;
    bool first_ = true;
    bool list_is_peers_ = false;
    std::vector<std::vector<std::string>> cache_;
    std::vector<TargetStatus> targets_;
    std::string sel_key_;
    std::string last_cfg_path_;
};

}  // namespace mysync::gui
