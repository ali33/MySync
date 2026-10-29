// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
#include <wx/notebook.h>
#include <wx/simplebook.h>
#include <wx/wx.h>

#include <memory>

#include "form_widgets.h"
#include "shared.h"
#include "ui_common.h"

namespace mysync::gui {

struct SaveOutcome;

class ConfigTab : public wxPanel {
public:
    ConfigTab(wxWindow* parent, Shared& sh);
    ~ConfigTab() override;

    // Gom ô -> struct (nghiêm ngặt), kiểm, ghi nguyên tử, RELOAD_CONFIG. Trả về false nếu không bắt đầu được.
    bool Save();
    // Gom ô -> struct nếu hợp lệ (không báo lỗi); dùng trước khi đổi ngôn ngữ / khi tab khác sửa struct.
    void CommitQuiet();
    void OnConfigChanged();        // struct đổi từ bên ngoài (tab khác / mở tệp) -> nạp lại ô
    void OpenPath(const std::string& path);
    bool HasUnsaved() const;
    void SelectPage(int outer, int inner);  // chọn trang con (dùng cho --page khi chụp ảnh/kiểm thử)

private:
    void BuildClient(wxWindow* parent);
    void BuildServer(wxWindow* parent);
    void BuildTargetPage(wxWindow* parent);
    void PushAll();
    bool CommitStrict(bool report);   // false = có ô sai (đã báo)
    void MarkEdited();
    void UpdateStatusLine();
    void SelectWatch(int idx);
    void SelectTarget(int idx);
    void RefreshWatchList();
    void RefreshTargetList();
    void AddWatch();
    void DupWatch();
    void RemoveWatch();
    void AddTarget();
    void RemoveTarget();
    void NewConfig(ConfigRole role);
    void BrowseOpen();
    void ShowToml();
    void CheckDisk();
    void FinishSave(SaveOutcome& o);

    ClientConfig* cur_client();
    ServerConfig* cur_server();
    WatchConfig* cur_watch();
    TargetConfig* cur_target();

    Shared& sh_;
    AliveFlag alive_ = make_alive();
    wxTextCtrl* path_;
    wxStaticText *role_lbl_, *status_;
    BusyIndicator* busy_;
    BusyGate gate_{nullptr, nullptr};
    wxPanel* body_;
    wxSimplebook* book_;
    wxNotebook *nb_client_ = nullptr, *nb_watch_ = nullptr;
    wxButton *save_, *revert_;
    wxListBox *watches_ = nullptr, *targets_ = nullptr;
    wxChoice* kind_ = nullptr;
    std::unique_ptr<Form<ClientConfig>> f_client_;
    std::unique_ptr<Form<WatchConfig>> f_watch_, f_filter_;
    std::unique_ptr<Form<TargetConfig>> f_target_;
    std::unique_ptr<Form<ServerConfig>> f_server_;
    int cur_w_ = -1, cur_t_ = -1;
    bool target_local_ = false;
    bool edited_ = false;
    wxTimer timer_;
    std::string prompted_hash_;
    bool checking_ = false;
};

}  // namespace mysync::gui
