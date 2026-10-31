// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// mysync-gui: ứng dụng wxWidgets (Windows + Linux GTK3) điều khiển daemon MySync qua kênh điều khiển cục bộ.
#include <wx/wx.h>
#include <wx/cmdline.h>
#include <wx/snglinst.h>

#include "main_frame.h"

using namespace mysync::gui;

namespace {
MainFrame* g_frame = nullptr;

// Mọi wxLogError / wxLogWarning (kể cả từ luồng nền) đi lên băng báo lỗi chứ không chỉ nằm trong log.
class BannerLog : public wxLog {
protected:
    void DoLogRecord(wxLogLevel level, const wxString& msg, const wxLogRecordInfo& info) override {
        if (level > wxLOG_Warning) return;
        std::string m = S(msg);
        BannerLevel lv = level <= wxLOG_Error ? BannerLevel::Error : BannerLevel::Warning;
        if (wxTheApp)
            wxTheApp->CallAfter([m, lv] {
                if (g_frame) g_frame->ReportError(lv, "wxlog", m);
            });
    }
};
}  // namespace

class MySyncApp : public wxApp {
public:
    bool OnInit() override {
        SetAppName("MySync-GUI");
        SetVendorName("META.vn");
        if (!wxApp::OnInit()) return false;
        wxInitAllImageHandlers();
        wxLog::SetActiveTarget(new BannerLog);
        single_ = std::make_unique<wxSingleInstanceChecker>(wxString("MySync-GUI-") + wxGetUserId());
        if (single_->IsAnotherRunning()) {
            wxMessageBox(L("app.already_running"), L("app.title"), wxOK | wxICON_INFORMATION);
            return false;
        }
        if (!dump_icons_.empty()) return DumpIcons(dump_icons_), false;  // tiện ích chẩn đoán: vẽ 5 trạng thái ra một ảnh PNG rồi thoát
        bool force_adv = !daemon_.empty() || !config_.empty() || tab_ >= 0 || page_ >= 0;
        auto* f = new MainFrame(daemon_, lang_, force_adv, user_dir_);
        g_frame = f;
        bool hidden = false;
        hidden = tray_only_;
        if (!config_.empty()) f->OpenConfigFile(config_);
        else f->AutoOpenLast();
        if (tab_ >= 0) f->SelectTab(tab_);
        if (page_ >= 0) f->SelectCfgPage(page_ / 10, page_ % 10);
        if (!hidden) f->Show();
        SetTopWindow(f);
        // Tham số kiểm thử: lái trình hướng dẫn thật bằng sự kiện giao diện, chụp cửa sổ, thoát.
        if (!auto_src_.empty()) f->SimpleAutoDrive(auto_src_, auto_dst_);
        if (!demo_ip_.empty()) SimpleHost::set_demo_address(demo_ip_);
        simple_test_hooks().auto_stop = wizard_stop_;
        simple_test_hooks().dialog_shot = dialog_shot_;
        simple_test_hooks().redact_account = redact_;
        if (show_adv_) f->CallAfter([f] { f->SimpleShowAdvanced(true); });
        if (auto_svc_dialog_) f->CallAfter([f, this] {
            wxTimer* t = new wxTimer;
            t->Bind(wxEVT_TIMER, [f, t](wxTimerEvent&) {
                f->SimpleAutoServiceDialog();
                t->Stop();
            });
            t->StartOnce(3000);
        });
        if (!auto_recv_.empty()) f->CallAfter([f, this] { f->SimpleAutoReceive(auto_recv_, !no_code_); });
        if (!shot_.empty()) {
            std::string png = shot_;
            bool ex = shot_exit_;
            f->CallAfter([f, png, ex, this] {
                wxTimer* t = new wxTimer;
                t->Bind(wxEVT_TIMER, [f, png, ex, t](wxTimerEvent&) {
                    f->Screenshot(png);
                    t->Stop();
                    if (ex) f->Close(true);
                });
                t->StartOnce(shot_delay_);
            });
        }
        return true;
    }

    void OnInitCmdLine(wxCmdLineParser& p) override {
        wxApp::OnInitCmdLine(p);
        p.AddSwitch("", "tray", "start hidden in the system tray");
        p.AddOption("", "tab", "open on tab 0..3", wxCMD_LINE_VAL_NUMBER);
        p.AddOption("", "page", "config sub-page outer*10+inner", wxCMD_LINE_VAL_NUMBER);
        p.AddOption("", "daemon", "daemon (control/service) name to poll", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "lang", "vi or en", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "dump-icons", "write the tray icon states to a PNG and exit", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "config", "open this configuration file", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "user-dir", "folder for Simple mode data (default: the per-user location)", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "screenshot", "write a PNG of the window after --shot-delay ms", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "shot-delay", "milliseconds before --screenshot (default 2500)", wxCMD_LINE_VAL_NUMBER);
        p.AddSwitch("", "shot-exit", "exit after the screenshot");
        p.AddOption("", "auto-src", "test: run the wizard with this source folder", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "wizard-stop", "test: stop the self-driven wizard at step 0..2", wxCMD_LINE_VAL_NUMBER);
        p.AddOption("", "demo-ip", "documentation screenshots: show this address instead of the real ones", wxCMD_LINE_VAL_STRING);
        p.AddSwitch("", "show-advanced", "test: show the advanced tabs under the Simple screen");
        p.AddSwitch("", "auto-svc-dialog", "test: open the service-install confirmation (cancelled after the screenshot)");
        p.AddSwitch("", "redact-account", "documentation screenshots: show a sample account name instead of the real one");
        p.AddOption("", "dialog-shot", "test: PNG of that confirmation dialog", wxCMD_LINE_VAL_STRING);
        p.AddSwitch("", "no-code", "test: with --auto-recv, receive without opening a pairing code");
        p.AddOption("", "auto-recv", "test: turn on receiving into this folder", wxCMD_LINE_VAL_STRING);
        p.AddOption("", "auto-dst", "test: run the wizard with this destination folder", wxCMD_LINE_VAL_STRING);
    }
    bool OnCmdLineParsed(wxCmdLineParser& p) override {
        tray_only_ = p.Found("tray");
        long n = -1;
        if (p.Found("tab", &n)) tab_ = static_cast<int>(n);
        if (p.Found("page", &n)) page_ = static_cast<int>(n);
        wxString c;
        if (p.Found("config", &c)) config_ = S(c);
        if (p.Found("daemon", &c)) daemon_ = S(c);
        if (p.Found("dump-icons", &c)) dump_icons_ = S(c);
        if (p.Found("lang", &c)) lang_ = S(c);
        if (p.Found("user-dir", &c)) user_dir_ = S(c);
        if (p.Found("screenshot", &c)) shot_ = S(c);
        if (p.Found("shot-delay", &n)) shot_delay_ = static_cast<int>(n);
        shot_exit_ = p.Found("shot-exit");
        if (p.Found("auto-src", &c)) auto_src_ = S(c);
        if (p.Found("auto-dst", &c)) auto_dst_ = S(c);
        if (p.Found("auto-recv", &c)) auto_recv_ = S(c);
        if (p.Found("wizard-stop", &n)) wizard_stop_ = static_cast<int>(n);
        if (p.Found("demo-ip", &c)) demo_ip_ = S(c);
        show_adv_ = p.Found("show-advanced");
        redact_ = p.Found("redact-account");
        no_code_ = p.Found("no-code");
        auto_svc_dialog_ = p.Found("auto-svc-dialog");
        if (p.Found("dialog-shot", &c)) dialog_shot_ = S(c);
        return wxApp::OnCmdLineParsed(p);
    }

    int OnExit() override {
        g_frame = nullptr;
        async_wait_idle(1500);
        return wxApp::OnExit();
    }

    // Ngoại lệ ném ra từ bộ xử lý sự kiện: hiện lên màn hình, ứng dụng tiếp tục chạy.
    bool OnExceptionInMainLoop() override {
        std::string m;
        try {
            throw;
        } catch (const std::exception& e) {
            m = e.what();
        } catch (...) {
            m = "unknown exception";
        }
        if (g_frame) g_frame->ReportError(BannerLevel::Error, "exception", m);
        else wxMessageBox(W(m), L("app.title"), wxOK | wxICON_ERROR);
        return true;
    }

    void OnUnhandledException() override {
        std::string m;
        try {
            throw;
        } catch (const std::exception& e) {
            m = e.what();
        } catch (...) {
            m = "unknown exception";
        }
        wxMessageBox(W(m), L("app.title"), wxOK | wxICON_ERROR);
    }

private:
    std::unique_ptr<wxSingleInstanceChecker> single_;
    bool tray_only_ = false;
    int tab_ = -1;
    int page_ = -1;
    std::string config_, daemon_, lang_, dump_icons_, user_dir_, shot_, auto_src_, auto_dst_, auto_recv_;
    int shot_delay_ = 2500;
    int wizard_stop_ = -1;
    bool show_adv_ = false, auto_svc_dialog_ = false, redact_ = false, no_code_ = false;
    std::string demo_ip_, dialog_shot_;
    bool shot_exit_ = false;

    static void DumpIcons(const std::string& path) {
        const TrayState sts[] = {TrayState::Offline, TrayState::Idle, TrayState::Syncing, TrayState::Warning, TrayState::Error};
        wxBitmap sheet(32 * 8 * 6, 32 * 8);
        wxMemoryDC dc(sheet);
        dc.SetBackground(*wxWHITE_BRUSH);
        dc.Clear();
        int x = 0;
        for (auto st : sts) {
            for (int fr = 0; fr < (st == TrayState::Syncing ? 2 : 1); ++fr) {
                wxBitmap b;
                b.CopyFromIcon(make_state_icon(st, fr * 3, 32));
                wxImage im = b.ConvertToImage().Rescale(32 * 8, 32 * 8, wxIMAGE_QUALITY_NEAREST);
                dc.DrawBitmap(wxBitmap(im), x, 0, true);
                x += 32 * 8;
            }
        }
        dc.SelectObject(wxNullBitmap);
        sheet.SaveFile(W(path), wxBITMAP_TYPE_PNG);
    }
};

wxIMPLEMENT_APP(MySyncApp);
