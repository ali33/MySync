// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
#include <wx/config.h>
#include <wx/notebook.h>
#include <wx/taskbar.h>
#include <wx/wx.h>

#include <memory>

#include "poller.h"
#include "shared.h"
#include "tab_config.h"
#include "tab_keys.h"
#include "tab_service.h"
#include "tab_status.h"
#include "ui_common.h"

namespace mysync::gui {

class MainFrame;

class TrayIcon : public wxTaskBarIcon {
public:
    explicit TrayIcon(MainFrame* f) : frame_(f) {}
    wxMenu* CreatePopupMenu() override;
    void SetState(TrayState st, const std::string& tip, int frame);

private:
    MainFrame* frame_;
};

class MainFrame : public wxFrame {
public:
    // daemon/lang_code: ghi đè cài đặt đã lưu (từ dòng lệnh); rỗng = dùng cài đặt đã lưu.
    MainFrame(const std::string& daemon = "", const std::string& lang_code = "");
    ~MainFrame() override;
    // An toàn gọi từ luồng UI (kể cả từ bộ xử lý ngoại lệ của ứng dụng).
    void ReportError(BannerLevel lv, const std::string& source, const std::string& msg);
    void ShowAndRaise();
    void AutoOpenLast();
    void OpenConfigFile(const std::string& p) { if (sh_.open_config) sh_.open_config(p); }
    void SelectCfgPage(int o, int i) { if (t_cfg_) t_cfg_->SelectPage(o, i); }
    void SelectTab(int i) { if (nb_ && i >= 0 && i < static_cast<int>(nb_->GetPageCount())) nb_->SetSelection(i); }
    void Quit();                         // thoát thật (khác với đóng cửa sổ = thu xuống khay)
    void ToggleService();                // từ menu khay
    bool IsConnected() const { return sh_.have_poll && sh_.last.connected; }

private:
    void BuildMenu();
    void BuildUi();
    void OnPoll(wxThreadEvent& e);
    void OnClose(wxCloseEvent& e);
    void SetLanguage(Lang l);
    void UpdateTray();
    void OnAnim(wxTimerEvent&);
    void ShowAbout();

    Shared sh_;
    std::unique_ptr<wxConfig> cfg_;
    std::unique_ptr<Poller> poller_;
    std::unique_ptr<TrayIcon> tray_;
    wxBoxSizer* root_ = nullptr;
    ErrorBanner* banner_ = nullptr;
    wxNotebook* nb_ = nullptr;
    StatusTab* t_status_ = nullptr;
    ConfigTab* t_cfg_ = nullptr;
    ServiceTab* t_svc_ = nullptr;
    KeysTab* t_keys_ = nullptr;
    AliveFlag alive_ = make_alive();
    wxTimer anim_;
    int anim_frame_ = 0;
    TrayState tray_state_ = TrayState::Offline;
    std::string tray_tip_;
    bool quitting_ = false;
    bool svc_busy_ = false;
};

}  // namespace mysync::gui
