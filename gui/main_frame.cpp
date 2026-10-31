// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "main_frame.h"

#include <wx/aboutdlg.h>
#include <wx/dnd.h>
#include <wx/dcclient.h>
#include <wx/dcmemory.h>
#include <wx/dcscreen.h>

#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace mysync::gui {

namespace {
enum { ID_LANG_VI = 3001, ID_LANG_EN, ID_TRAY_OPEN, ID_TRAY_TOGGLE, ID_TRAY_EXIT, ID_SAVE, ID_MODE };
}

// ---------------------------------------------------------------- khay
wxMenu* TrayIcon::CreatePopupMenu() {
    auto* m = new wxMenu;
    m->Append(ID_TRAY_OPEN, L("tray.menu.open"));
    bool conn = frame_->IsConnected();
    if (!frame_->SimpleActive()) m->Append(ID_TRAY_TOGGLE, L(conn ? "tray.menu.pause" : "tray.menu.start"));
    m->AppendSeparator();
    m->Append(ID_TRAY_EXIT, L(frame_->SimpleActive() ? "simple.tray.quit" : "tray.menu.exit"));
    m->Bind(wxEVT_MENU, [this](wxCommandEvent&) { frame_->ShowAndRaise(); }, ID_TRAY_OPEN);
    m->Bind(wxEVT_MENU, [this](wxCommandEvent&) { frame_->ToggleService(); }, ID_TRAY_TOGGLE);
    m->Bind(wxEVT_MENU, [this](wxCommandEvent&) { frame_->Quit(); }, ID_TRAY_EXIT);
    return m;
}

void TrayIcon::SetState(TrayState st, const std::string& tip, int frame) {
    SetIcon(make_state_icon(st, frame, 32), W(tip));
}

namespace {
class FolderDrop : public wxFileDropTarget {
public:
    explicit FolderDrop(MainFrame* f) : f_(f) {}
    bool OnDropFiles(wxCoord, wxCoord, const wxArrayString& files) override {
        f_->DropFolders(files);
        return true;
    }

private:
    MainFrame* f_;
};
}  // namespace

// ---------------------------------------------------------------- khung chính
MainFrame::MainFrame(const std::string& daemon_arg, const std::string& lang_arg, bool force_advanced,
                     const std::string& user_dir)
    : wxFrame(nullptr, wxID_ANY, "MySync", wxDefaultPosition, wxSize(1020, 760)), anim_(this) {
    cfg_ = std::make_unique<wxConfig>("MySync-GUI");
    {
        wxString l;
        Lang lang_v;
        if (cfg_->Read("lang", &l) && lang_from_code(S(l), lang_v)) set_lang(lang_v);
    }
    sh_.get_setting = [this](const std::string& k, const std::string& d) {
        wxString v;
        return cfg_->Read(W(k), &v) ? S(v) : d;
    };
    sh_.set_setting = [this](const std::string& k, const std::string& v) {
        cfg_->Write(W(k), W(v));
        cfg_->Flush();
    };
    {
        Lang la;
        if (!lang_arg.empty() && lang_from_code(lang_arg, la)) set_lang(la);
    }
    sh_.daemon_name = daemon_arg.empty() ? sh_.get_setting("daemon", "mysync-client") : daemon_arg;
    sh_.cfg_path = sh_.get_setting("cfgpath", "");
    sh_.report = [this](BannerLevel lv, const std::string& src, const std::string& msg) { ReportError(lv, src, msg); };
    sh_.clear_report = [this](const std::string& src) {
        if (banner_) banner_->ClearSource(src);
    };
    sh_.poll_now = [this] {
        if (poller_) poller_->PollNow();
    };
    sh_.set_daemon = [this](const std::string& d) {
        if (poller_) poller_->SetDaemon(d);
        if (t_svc_) t_svc_->OnConfigChanged();
    };
    sh_.open_config = [this](const std::string& p) {
        if (t_cfg_) {
            nb_->SetSelection(1);
            t_cfg_->OpenPath(p);
        }
    };
    sh_.save_config = [this] { return t_cfg_ ? t_cfg_->Save() : false; };
    sh_.config_changed = [this] {
        if (t_cfg_) t_cfg_->OnConfigChanged();
        if (t_svc_) t_svc_->OnConfigChanged();
        if (t_keys_) t_keys_->OnConfigChanged();
    };

    {
        std::string herr;
        host_ok_ = host_.init(user_dir, &herr);
        if (!host_ok_) CallAfter([this, herr] { ReportError(BannerLevel::Warning, "simple.init", herr); });
        svc_mode_ = sh_.get_setting("svc.mode", "0") == "1";
        sctx_.sh = &sh_;
        sctx_.host = &host_;
        sctx_.alive = alive_;
        sctx_.go_advanced = [this] { EnterAdvanced(true); };
        sctx_.show_advanced = [this](bool show) {
            adv_shown_ = show;
            LayoutModes();
        };
        sctx_.engines_changed = [this] { EnginesChanged(); };
        sctx_.set_service_mode = [this](bool on) { SetServiceMode(on); };
        sctx_.service_mode = [this] { return svc_mode_; };
        sctx_.attention = [this] { ShowAndRaise(); };
        sctx_.quit_all = [this] { QuitAll(); };
        if (force_advanced || !host_ok_ || sh_.get_setting("mode", "") == "advanced") mode_ = Mode::Advanced;
        else if (host_.has_config()) mode_ = Mode::Simple;
        else mode_ = Mode::Pending;
        if (mode_ == Mode::Simple) {
            sh_.daemon_name = svc_mode_ ? sh_.get_setting("svc.name", "mysync-client") : host_.paths().client_control_name;
            sh_.cfg_path = host_.paths().client_config;
        }
    }

    SetIcon(make_state_icon(TrayState::Idle, 0, 32));
    BuildMenu();
    root_ = new wxBoxSizer(wxVERTICAL);
    SetSizer(root_);
    banner_ = new ErrorBanner(this);
    root_->Add(banner_, 0, wxEXPAND);
    BuildUi();

    tray_ = std::make_unique<TrayIcon>(this);
    UpdateTray();
    tray_->Bind(wxEVT_TASKBAR_LEFT_DCLICK, [this](wxTaskBarIconEvent&) { ShowAndRaise(); });
    tray_->Bind(wxEVT_TASKBAR_LEFT_UP, [this](wxTaskBarIconEvent&) { ShowAndRaise(); });
    if (!wxTaskBarIcon::IsAvailable())
        ReportError(BannerLevel::Warning, "tray", S(L("tray.unavailable")));

    Bind(wxEVT_CLOSE_WINDOW, &MainFrame::OnClose, this);
    Bind(EVT_POLL_RESULT, &MainFrame::OnPoll, this);
    Bind(wxEVT_TIMER, &MainFrame::OnAnim, this);
    Bind(wxEVT_MENU, [this](wxCommandEvent&) { sh_.save_config(); }, ID_SAVE);
    wxAcceleratorEntry acc[1];
    acc[0].Set(wxACCEL_CTRL, 'S', ID_SAVE);
    SetAcceleratorTable(wxAcceleratorTable(1, acc));

    poller_ = std::make_unique<Poller>(this);
    poller_->Start(sh_.daemon_name, 1000);
    SetDropTarget(new FolderDrop(this));
    if (mode_ == Mode::Simple) StartEngines();
}

void MainFrame::AutoOpenLast() {
    // Tự mở lại tệp cấu hình lần trước (nếu còn).
    if (!sh_.cfg_path.empty() && wxFileExists(W(sh_.cfg_path)))
        CallAfter([this, p = sh_.cfg_path] { if (t_cfg_) t_cfg_->OpenPath(p); });
}

MainFrame::~MainFrame() {
    *alive_ = false;
    anim_.Stop();
    if (poller_) poller_->Stop();
    if (tray_) tray_->RemoveIcon();
}

void MainFrame::BuildMenu() {
    auto* mb = new wxMenuBar;
    auto* file = new wxMenu;
    file->Append(ID_SAVE, L("menu.save") + "\tCtrl+S");
    file->AppendSeparator();
    file->Append(ID_TRAY_EXIT, L("tray.menu.exit"));
    auto* set = new wxMenu;
    auto* lang = new wxMenu;
    lang->AppendRadioItem(ID_LANG_VI, "Tiếng Việt");
    lang->AppendRadioItem(ID_LANG_EN, "English");
    (mysync::gui::lang() == Lang::Vi ? lang->FindItem(ID_LANG_VI) : lang->FindItem(ID_LANG_EN))->Check();
    set->AppendSubMenu(lang, L("menu.language"));
    mode_item_ = set->Append(ID_MODE, L(mode_ == Mode::Advanced ? "simple.menu.tosimple" : "simple.menu.advanced"));
    auto* help = new wxMenu;
    help->Append(wxID_ABOUT, L("menu.about"));
    mb->Append(file, L("menu.file"));
    mb->Append(set, L("menu.settings"));
    mb->Append(help, L("menu.help"));
    SetMenuBar(mb);
    Bind(wxEVT_MENU, [this](wxCommandEvent&) { SetLanguage(Lang::Vi); }, ID_LANG_VI);
    Bind(wxEVT_MENU, [this](wxCommandEvent&) { SetLanguage(Lang::En); }, ID_LANG_EN);
    Bind(wxEVT_MENU, [this](wxCommandEvent&) { Quit(); }, ID_TRAY_EXIT);
    Bind(wxEVT_MENU, [this](wxCommandEvent&) { OnModeMenu(); }, ID_MODE);
    Bind(wxEVT_MENU, [this](wxCommandEvent&) { ShowAbout(); }, wxID_ABOUT);
}

void MainFrame::BuildUi() {
    int sel = nb_ ? nb_->GetSelection() : 0;
    if (nb_) {
        root_->Detach(nb_);
        nb_->Destroy();
        nb_ = nullptr;
        t_status_ = nullptr;
        t_cfg_ = nullptr;
        t_svc_ = nullptr;
        t_keys_ = nullptr;
    }
    SetTitle(W("MySync - " + tr("app.title")));
    nb_ = new wxNotebook(this, wxID_ANY);
    t_status_ = new StatusTab(nb_, sh_);
    t_cfg_ = new ConfigTab(nb_, sh_);
    t_svc_ = new ServiceTab(nb_, sh_);
    t_keys_ = new KeysTab(nb_, sh_);
    nb_->AddPage(t_status_, L("tab.status"));
    nb_->AddPage(t_cfg_, L("tab.config"));
    nb_->AddPage(t_svc_, L("tab.service"));
    nb_->AddPage(t_keys_, L("tab.keys"));
    // Mỗi tab một màu nhấn nhẹ ở tiêu đề tab không có trong wxNotebook; giữ nguyên giao diện hệ thống.
    nb_->SetSelection(sel);
    BuildSimple();
    root_->Add(nb_, 1, wxEXPAND);
    LayoutModes();
}

void MainFrame::BuildSimple() {
    SimplePage keep = SimplePage::Checking;
    bool had = simple_ != nullptr;
    if (simple_) {
        keep = simple_->Page();
        root_->Detach(simple_);
        simple_->Destroy();
        simple_ = nullptr;
    }
    simple_ = new SimplePanel(this, sctx_);
    root_->Insert(1, simple_, 1, wxEXPAND);
    if (had) {
        simple_->ShowPage(keep == SimplePage::Wizard ? SimplePage::Status : keep);
    } else if (mode_ == Mode::Simple) {
        simple_->ShowPage(host_.has_config() ? SimplePage::Status : SimplePage::QuickStart);
    }
}

void MainFrame::LayoutModes() {
    bool simple = mode_ != Mode::Advanced && simple_;
    if (simple_) simple_->Show(simple);
    if (nb_) nb_->Show(!simple || adv_shown_);
    if (simple_ && simple_->status()) simple_->status()->SetAdvancedShown(adv_shown_);
    Layout();
}

void MainFrame::EnterSimple() {
    mode_ = Mode::Simple;
    sh_.set_setting("mode", "simple");
    sh_.daemon_name = svc_mode_ ? sh_.get_setting("svc.name", "mysync-client") : host_.paths().client_control_name;
    if (host_.has_config()) sh_.cfg_path = host_.paths().client_config;
    if (poller_) poller_->SetDaemon(sh_.daemon_name);
    if (t_svc_) t_svc_->OnConfigChanged();
    if (simple_) simple_->ShowPage(host_.has_config() ? SimplePage::Status : SimplePage::QuickStart);
    if (mode_item_) mode_item_->SetItemLabel(L("simple.menu.advanced"));
    if (host_.has_config() && !svc_mode_) StartEngines();
    LayoutModes();
    UpdateTray();
    RunAutoDrive();
}

void MainFrame::EnterAdvanced(bool remember) {
    mode_ = Mode::Advanced;
    if (remember) sh_.set_setting("mode", "advanced");
    sh_.daemon_name = sh_.get_setting("daemon", "mysync-client");
    if (poller_) poller_->SetDaemon(sh_.daemon_name);
    if (mode_item_) mode_item_->SetItemLabel(L("simple.menu.tosimple"));
    LayoutModes();
    UpdateTray();
}

void MainFrame::OnModeMenu() {
    if (mode_ == Mode::Advanced) {
        EnterSimple();
    } else {
        adv_shown_ = !adv_shown_;
        LayoutModes();
    }
}

void MainFrame::StartEngines() {
    if (!host_ok_ || svc_mode_ || host_.supervisor_ready()) return;
    bool recv = sh_.get_setting("recv.on", "0") == "1";
    SimpleHost* h = &host_;
    run_async<int>(
        alive_,
        [h, recv]() {
            h->start_supervisor(true, recv);
            return 0;
        },
        [this](bool ok, int&, const std::string& err) {
            if (!ok) ReportError(BannerLevel::Error, "simple.engine.start", err);
            else banner_->ClearSource("simple.engine.start");
            if (poller_) poller_->PollNow();
            if (simple_ && simple_->status()) simple_->status()->RestoreReceiver();
        });
}

void MainFrame::EnginesChanged() {
    // Sau trình hướng dẫn: cấu hình người dùng đã có, engine client chạy; hướng bộ hỏi trạng thái vào nó.
    mode_ = Mode::Simple;
    sh_.set_setting("mode", "simple");
    svc_mode_ = false;
    sh_.set_setting("svc.mode", "0");
    sh_.daemon_name = host_.paths().client_control_name;
    sh_.cfg_path = host_.paths().client_config;
    if (poller_) poller_->SetDaemon(sh_.daemon_name);
    if (sh_.config_changed) sh_.config_changed();
    if (t_svc_) t_svc_->OnConfigChanged();
    if (mode_item_) mode_item_->SetItemLabel(L("simple.menu.advanced"));
    LayoutModes();
    UpdateTray();
}

void MainFrame::SetServiceMode(bool on) {
    svc_mode_ = on;
    sh_.set_setting("svc.mode", on ? "1" : "0");
    sh_.daemon_name = on ? sh_.get_setting("svc.name", "mysync-client") : host_.paths().client_control_name;
    if (poller_) poller_->SetDaemon(sh_.daemon_name);
    if (t_svc_) t_svc_->OnConfigChanged();
    UpdateTray();
}

void MainFrame::DropFolders(const wxArrayString& files) {
    if (mode_ != Mode::Simple || !simple_) return;
    for (const auto& f : files) {
        if (wxDirExists(f)) {
            ShowAndRaise();
            simple_->DropFolder(S(f));
            return;
        }
    }
    ReportError(BannerLevel::Warning, "simple.drop", tr("simple.drop.notfolder"));
}

void MainFrame::Screenshot(const std::string& png) {
    std::string e = save_window_png(this, png);
    if (!e.empty()) ReportError(BannerLevel::Warning, "shot", e);
}

void MainFrame::SimpleShowAdvanced(bool on) {
    adv_shown_ = on;
    LayoutModes();
}

void MainFrame::SetLanguage(Lang l) {
    if (l == mysync::gui::lang()) return;
    if (t_cfg_) t_cfg_->CommitQuiet();  // giữ ô đang sửa dở trong struct trước khi dựng lại
    set_lang(l);
    sh_.set_setting("lang", lang_code(l));
    banner_->ClearAll();
    SetMenuBar(nullptr);
    BuildMenu();
    BuildUi();
    if (t_cfg_) t_cfg_->OnConfigChanged();
    if (sh_.have_poll && t_status_) t_status_->OnPoll(sh_.last);
    UpdateTray();
}

void MainFrame::ShowAbout() {
    wxAboutDialogInfo info;
    info.SetName("MySync");
    info.SetVersion("1.0.0");
    info.SetCopyright(W("© 2026 META.vn — Nguyễn Đức Sơn"));
    info.SetLicence(W("GPL-2.0-or-later\nwxWidgets 3.2: wxWindows Library Licence"));
    info.SetDescription(L("about.desc"));
    wxAboutBox(info, this);
}

void MainFrame::ReportError(BannerLevel lv, const std::string& source, const std::string& msg) {
    if (banner_) banner_->Report(lv, source, msg);
    // Lỗi đỏ khi cửa sổ đang ẩn: hiện ngay để không ai bỏ sót.
    if (lv == BannerLevel::Error && !IsShown() && !quitting_) ShowAndRaise();
}

void MainFrame::ShowAndRaise() {
    if (IsIconized()) Iconize(false);
    Show(true);
    Raise();
}

void MainFrame::OnClose(wxCloseEvent& e) {
    if (e.CanVeto() && !quitting_ && wxTaskBarIcon::IsAvailable()) {
        e.Veto();
        Hide();  // đóng cửa sổ = thu xuống khay
        return;
    }
    Destroy();
}

void MainFrame::QuitAll() {
    if (quitting_) return;
    if (simple_ && simple_->IsSyncing()) {
        ShowAndRaise();
        wxMessageDialog q(this, L("simple.quit.confirm"), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        q.SetYesNoLabels(L("simple.quit.yes"), L("simple.quit.no"));
        if (q.ShowModal() != wxID_YES) return;
    }
    if (t_cfg_ && t_cfg_->HasUnsaved()) {
        ShowAndRaise();
        wxMessageDialog q(this, L("cfg.quit.confirm"), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        if (q.ShowModal() != wxID_YES) return;
    }
    if (!host_.supervisor_ready()) {
        quitting_ = true;
        Close(true);
        return;
    }
    ShowAndRaise();
    quitting_ = true;
    if (simple_ && simple_->status()) simple_->status()->SetQuitting(true);
    SimpleHost* h = &host_;
    run_async<int>(
        alive_,
        [h]() {
            h->stop_all();
            return 0;
        },
        [this](bool ok, int&, const std::string& err) {
            if (!ok) ReportError(BannerLevel::Warning, "simple.quit", err);
            Close(true);
        });
}

void MainFrame::Quit() {
    if (mode_ == Mode::Simple) {
        QuitAll();
        return;
    }
    if (t_cfg_ && t_cfg_->HasUnsaved()) {
        ShowAndRaise();
        wxMessageDialog q(this, L("cfg.quit.confirm"), L("app.title"), wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        if (q.ShowModal() != wxID_YES) return;
    }
    quitting_ = true;
    Close(true);
}

void MainFrame::ToggleService() {
    if (svc_busy_) return;
    bool stop = IsConnected();
    ServiceRequest req;
    req.name = sh_.daemon_name;
    svc_busy_ = true;
    UpdateTray();
    service_run_async(alive_, stop ? ServiceAction::Stop : ServiceAction::Start, req,
                      [this, stop](bool ok, ServiceResult& r, const std::string& err) {
                          svc_busy_ = false;
                          UpdateTray();
                          auto act = stop ? ServiceAction::Stop : ServiceAction::Start;
                          if (!ok) {
                              ReportError(BannerLevel::Error, "svc.tray", err);
                          } else if (!r.ok) {
                              ReportError(r.cancelled ? BannerLevel::Warning : BannerLevel::Error, "svc.tray",
                                          service_result_text(act, r));
                          } else {
                              banner_->ClearSource("svc.tray");
                          }
                          if (poller_) poller_->PollNow();
                      });
}

// ---------------------------------------------------------------- poll -> UI
void MainFrame::OnPoll(wxThreadEvent& e) {
    PollResult r = e.GetPayload<PollResult>();
    if (r.daemon != sh_.daemon_name) return;  // kết quả của daemon cũ (vừa đổi): bỏ
    sh_.last = r;
    sh_.have_poll = true;
    if (mode_ == Mode::Pending) {
        // Lần mở đầu tiên chưa có cấu hình riêng: nếu đã có dịch vụ nối được thì vào thẳng nâng cao, không thì Bắt đầu nhanh.
        if (r.connected) EnterAdvanced(false);
        else EnterSimple();
        if (mode_ == Mode::Simple) return;  // đổi daemon hỏi: đợi kết quả của daemon mới
    }
    if (mode_ == Mode::Simple && simple_) {
        simple_->OnPoll(r);
        SimpleStatus cur = simple_->status()->Current();
        if (cur.error_banner) ReportError(BannerLevel::Error, "simple.engine", cur.headline + (cur.detail.empty() ? "" : "\n" + cur.detail));
        else banner_->ClearSource("simple.engine");
        if (r.connected && !r.snap.config_error.empty())
            banner_->Report(BannerLevel::Warning, "daemon.cfgerr", S(L("status.cfgerr")) + " " + r.snap.config_error);
        else
            banner_->ClearSource("daemon.cfgerr");
        banner_->ClearSource("poll");
        if (t_status_) t_status_->OnPoll(r);
        UpdateTray();
        return;
    }
    if (r.connected) {
        banner_->ClearSource("poll");
        if (!r.snap.config_error.empty())
            banner_->Report(BannerLevel::Warning, "daemon.cfgerr", S(L("status.cfgerr")) + " " + r.snap.config_error);
        else
            banner_->ClearSource("daemon.cfgerr");
    } else {
        banner_->Report(BannerLevel::Warning, "poll", trf("status.offline", {r.daemon, r.error}));
    }
    if (t_status_) t_status_->OnPoll(r);
    UpdateTray();
}

void MainFrame::UpdateTray() {
    TrayState st = compute_tray_state(sh_.have_poll && sh_.last.connected, sh_.last.snap,
                                      sh_.have_poll ? sh_.last.now_ms : 0);
    std::string simple_tip;
    if (mode_ == Mode::Simple && simple_ && simple_->Page() == SimplePage::Status && simple_->status()) {
        SimpleStatus cur = simple_->status()->Current();
        st = cur.tray;
        simple_tip = "MySync - " + cur.headline;
    }
    if (svc_busy_) st = TrayState::Syncing;  // đang chờ thao tác dịch vụ (có thể là hộp thoại xin quyền): icon xoay
    bool changed = st != tray_state_;
    tray_state_ = st;
    // Hoạt ảnh xoay khi đang đồng bộ; giảm chuyển động thì đổi nhịp chậm (800 ms) chứ không bỏ.
    if (st == TrayState::Syncing) {
        if (!anim_.IsRunning()) anim_.Start(prefers_reduced_motion() ? 800 : 150);
    } else {
        anim_.Stop();
        anim_frame_ = 0;
    }
    std::string tip = svc_busy_ ? "MySync - " + tr("busy.service")
                                : !simple_tip.empty() ? simple_tip
                                : tray_tooltip(sh_.have_poll && sh_.last.connected, sh_.last.snap, st);
    if (tray_ && (changed || tip != tray_tip_)) {
        tray_tip_ = tip;
        tray_->SetState(st, tip, anim_frame_);
    }
    if (changed) SetIcon(make_state_icon(st, 0, 32));
}

void MainFrame::OnAnim(wxTimerEvent&) {
    anim_frame_ = (anim_frame_ + 1) % 8;
    if (tray_ && tray_state_ == TrayState::Syncing)
        tray_->SetState(tray_state_, tray_tooltip(true, sh_.last.snap, tray_state_), anim_frame_);
}

}  // namespace mysync::gui
