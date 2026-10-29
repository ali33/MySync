// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
#include <wx/wx.h>

#include <functional>

#include "mysync/gui/service_ctl.h"
#include "shared.h"
#include "ui_common.h"

namespace mysync::gui {

// Chạy một thao tác dịch vụ (có thể nâng quyền, chặn lâu) trong luồng nền; done chạy ở luồng UI.
void service_run_async(const AliveFlag& alive, ServiceAction act, const ServiceRequest& req,
                       std::function<void(bool ok, ServiceResult& r, const std::string& err)> done);
// Văn bản kết quả để hiện nguyên văn.
std::string service_result_text(ServiceAction act, const ServiceResult& r);

class ServiceTab : public wxPanel {
public:
    ServiceTab(wxWindow* parent, Shared& sh);
    ~ServiceTab() override;
    void RefreshState(bool user = false);
    void OnConfigChanged();  // đường dẫn/vai trò cấu hình đổi

private:
    void Do(ServiceAction act);
    ServiceRequest BuildRequest(std::string* err) const;
    void ShowState(const ServiceState& st);

    Shared& sh_;
    AliveFlag alive_ = make_alive();
    wxTextCtrl *name_, *cfg_, *runas_, *allow_, *result_;
    wxChoice* role_;
    wxStaticText *state_, *elev_;
    wxButton *b_install_, *b_uninstall_, *b_start_, *b_stop_, *b_refresh_;
    wxPanel* content_;
    BusyIndicator* busy_;
    BusyGate gate_{nullptr, nullptr};
    wxTimer timer_;
    bool querying_ = false;
};

}  // namespace mysync::gui
