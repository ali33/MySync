// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#pragma once
// ui_common.h - tiện ích dùng chung của giao diện wx: đổi chuỗi UTF-8, chạy việc nền rồi trả kết quả về luồng UI,
// chỉ báo động (spinner / nhấp nháy khi giảm chuyển động), băng báo lỗi, vẽ icon khay.
#include <wx/listctrl.h>
#include <wx/wx.h>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "i18n_model.h"
#include "status_model.h"

class wxActivityIndicator;

namespace mysync::gui {

inline wxString W(const std::string& s) { return wxString::FromUTF8(s.c_str()); }
inline std::string S(const wxString& s) { return std::string(s.ToUTF8().data()); }
inline long first_selected(wxListCtrl* l) { return l->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); }
inline wxString L(const char* key) { return W(tr(key)); }

// Hệ điều hành yêu cầu giảm chuyển động? (Windows: animation client area tắt; GTK: gtk-enable-animations=false)
bool prefers_reduced_motion();

// ---- việc nền ----------------------------------------------------------------------------------------------
// Mọi ngoại lệ trong luồng nền được bắt và đổi thành `err` rồi trả về luồng UI bằng CallAfter (an toàn đa luồng).
// `alive` là cờ chủ sở hữu (đặt false trong hàm huỷ, đọc ở luồng UI) để không gọi vào cửa sổ đã đóng.
using AliveFlag = std::shared_ptr<bool>;
inline AliveFlag make_alive() { return std::make_shared<bool>(true); }
void async_begin();
void async_end();
int async_inflight();
void async_wait_idle(int timeout_ms);

template <class R>
void run_async(const AliveFlag& alive, std::function<R()> work, std::function<void(bool ok, R& r, const std::string& err)> done) {
    async_begin();
    std::thread([alive, work = std::move(work), done = std::move(done)]() mutable {
        auto res = std::make_shared<R>();
        auto err = std::make_shared<std::string>();
        bool ok = false;
        try {
            *res = work();
            ok = true;
        } catch (const std::exception& e) {
            *err = e.what();
            if (err->empty()) err = std::make_shared<std::string>("unknown error");
        } catch (...) {
            *err = "unknown exception in background thread";
        }
        if (wxTheApp) {
            wxTheApp->CallAfter([alive, done = std::move(done), res, err, ok]() mutable {
                if (*alive) {
                    try {
                        done(ok, *res, *err);
                    } catch (const std::exception& e) {
                        wxLogError("%s", wxString::FromUTF8(e.what()));
                    }
                }
                async_end();
            });
        } else {
            async_end();
        }
    }).detach();
}

// ---- chỉ báo động ------------------------------------------------------------------------------------------
class BusyIndicator : public wxPanel {
public:
    BusyIndicator(wxWindow* parent);
    ~BusyIndicator() override;
    void Start(const wxString& label);
    void Stop();
    bool IsRunning() const { return running_; }

private:
    void OnTimer(wxTimerEvent&);
    wxActivityIndicator* spin_ = nullptr;
    wxStaticText* text_ = nullptr;
    wxTimer timer_;
    bool running_ = false;
    bool reduced_ = false;
    bool phase_ = false;
    wxString label_;
};

// Chặn thao tác chồng: begin() trả false nếu đang bận. Khi bận: vô hiệu hoá `content` (mờ đi) + chỉ báo chạy.
class BusyGate {
public:
    BusyGate(wxWindow* content, BusyIndicator* ind) : content_(content), ind_(ind) {}
    bool begin(const char* label_key);
    void end();
    bool busy() const { return busy_; }

private:
    wxWindow* content_;
    BusyIndicator* ind_;
    bool busy_ = false;
};

// ---- băng báo lỗi ------------------------------------------------------------------------------------------
// Đỏ = lỗi chặn, hổ phách = cảnh báo. Tối đa BannerModel::kMaxBanner dòng, gộp trùng.
class ErrorBanner : public wxPanel {
public:
    ErrorBanner(wxWindow* parent);
    void Report(BannerLevel lv, const std::string& source, const std::string& msg);
    void ClearSource(const std::string& source);
    void ClearAll();
    bool HasError() const { return model_.has_error(); }
    void Relayout();

private:
    void Rebuild();
    BannerModel model_;
    std::map<std::string, std::string> dismissed_;  // nguồn -> thông điệp đã đóng (không hiện lại tới khi đổi)
    wxBoxSizer* box_;
};

// ---- icon --------------------------------------------------------------------------------------------------
// frame: 0..7 cho hoạt ảnh xoay của Syncing (các trạng thái khác bỏ qua).
wxIcon make_state_icon(TrayState st, int frame, int size = 32);

// Hộp thoại lỗi nguyên văn (không chỉ log).
void show_error_dialog(wxWindow* parent, const std::string& title, const std::string& message);

}  // namespace mysync::gui
