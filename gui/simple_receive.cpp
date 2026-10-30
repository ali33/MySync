// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// Chế độ Đơn giản, phía NHẬN: công tắc "Cho phép máy khác gửi file vào đây", mã ghép, hộp thoại duyệt yêu cầu.
#include <wx/clipbrd.h>
#include <wx/dirdlg.h>

#include <chrono>
#include <thread>

#include "mysync/simple/pairing.h"
#include "mysync/simple/wizard_model.h"
#include "simple_panel.h"

namespace mysync::gui {

namespace {
const wxColour kRed(0xA0, 0x10, 0x10), kGreen(0x1E, 0x7E, 0x34), kAmber(0x8A, 0x5A, 0x00), kGrey(0x55, 0x55, 0x55);

struct StartResult {
    PairInfo pi;
    std::string token;
    std::vector<std::string> ips;
};
}  // namespace

// ---------------------------------------------------------------- hộp thoại duyệt
class ApproveDialog : public wxDialog {
public:
    ApproveDialog(wxWindow* parent, const PairPendingInfo& p, std::function<void(uint32_t, bool)> decide,
                  std::function<void()> closed)
        : wxDialog(parent, wxID_ANY, L("recv.dlg.title"), wxDefaultPosition, wxDefaultSize, wxDEFAULT_DIALOG_STYLE),
          id_(p.id), decide_(std::move(decide)), closed_(std::move(closed)) {
        auto* v = new wxBoxSizer(wxVERTICAL);
        busy_ = new BusyIndicator(this);
        v->Add(busy_, 0, wxEXPAND | wxALL, 8);
        auto* who = new WrapText(this, W(trf("recv.dlg.who", {p.name, p.ip})));
        who->SetMinSize(wxSize(440, -1));
        v->Add(who, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, 14);
        v->Add(new wxStaticText(this, wxID_ANY, L("recv.dlg.sas")), 0, wxLEFT | wxRIGHT | wxTOP, 14);
        sas_ = new wxStaticText(this, wxID_ANY, W(sas_display(p.sas)));
        sp_font(sas_, 2.2);
        {
            wxFont f = sas_->GetFont();
            f.SetFamily(wxFONTFAMILY_TELETYPE);
            sas_->SetFont(f);
        }
        v->Add(sas_, 0, wxALIGN_CENTER | wxALL, 14);
        auto* hint = new WrapText(this, L("recv.dlg.check"));
        v->Add(hint, 0, wxEXPAND | wxLEFT | wxRIGHT, 14);
        left_ = new wxStaticText(this, wxID_ANY, "");
        left_->SetForegroundColour(kGrey);
        v->Add(left_, 0, wxLEFT | wxRIGHT | wxTOP, 14);
        auto* bh = new wxBoxSizer(wxHORIZONTAL);
        b_deny_ = new wxButton(this, wxID_ANY, L("recv.dlg.deny"));
        b_ok_ = new wxButton(this, wxID_ANY, L("recv.dlg.ok"));
        bh->AddStretchSpacer(1);
        bh->Add(b_deny_, 0, wxRIGHT, 8);
        bh->Add(b_ok_, 0);
        v->Add(bh, 0, wxEXPAND | wxALL, 14);
        SetSizerAndFit(v);
        SetLeft(static_cast<int>(p.seconds_left));
        b_ok_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Decide(true); });
        b_deny_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Decide(false); });
        Bind(wxEVT_CLOSE_WINDOW, [this](wxCloseEvent&) { Finish(); });  // đóng bằng X = để đó, không đồng ý
        CentreOnParent();
    }
    uint32_t id() const { return id_; }
    void SetLeft(int s) { left_->SetLabelText(W(trf("recv.dlg.left", {fmt_countdown(s)}))); }
    void SetBusy(bool on) {
        b_ok_->Enable(!on);
        b_deny_->Enable(!on);
        if (on) busy_->Start(L("recv.busy.decide"));
        else busy_->Stop();
        decided_ = on;
        Layout();
        Fit();
    }
    void Finish() {
        if (done_) return;
        done_ = true;
        auto cb = std::move(closed_);
        Destroy();
        if (cb) cb();
    }

private:
    void Decide(bool approve) {
        if (decided_) return;
        SetBusy(true);
        decide_(id_, approve);
    }
    uint32_t id_;
    std::function<void(uint32_t, bool)> decide_;
    std::function<void()> closed_;
    BusyIndicator* busy_ = nullptr;
    wxStaticText *sas_ = nullptr, *left_ = nullptr;
    wxButton *b_ok_ = nullptr, *b_deny_ = nullptr;
    bool decided_ = false;
    bool done_ = false;
};

// ---------------------------------------------------------------- ô nhận
ReceiveBox::ReceiveBox(wxWindow* parent, SimpleCtx& c) : wxPanel(parent, wxID_ANY), c_(c), timer_(this) {
    auto* v = new wxStaticBoxSizer(wxVERTICAL, this, L("recv.title"));
    auto* sb = v->GetStaticBox();
    chk_ = new wxCheckBox(sb, wxID_ANY, L("recv.toggle"));
    v->Add(chk_, 0, wxALL, 8);
    busy_ = new BusyIndicator(sb);
    v->Add(busy_, 0, wxEXPAND | wxLEFT | wxRIGHT, 8);

    body_ = new wxPanel(sb, wxID_ANY);
    auto* b = new wxBoxSizer(wxVERTICAL);
    auto* fr = new wxBoxSizer(wxHORIZONTAL);
    fr->Add(new wxStaticText(body_, wxID_ANY, L("recv.folder")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    folder_ = new wxStaticText(body_, wxID_ANY, "");
    fr->Add(folder_, 1, wxALIGN_CENTER_VERTICAL);
    chg_ = new wxButton(body_, wxID_ANY, L("recv.change"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
    fr->Add(chg_, 0, wxLEFT, 6);
    b->Add(fr, 0, wxEXPAND | wxBOTTOM, 8);

    code_row_ = new wxPanel(body_, wxID_ANY);
    auto* cr = new wxBoxSizer(wxVERTICAL);
    cr->Add(new wxStaticText(code_row_, wxID_ANY, L("recv.code")), 0, wxBOTTOM, 4);
    auto* ch = new wxBoxSizer(wxHORIZONTAL);
    code_ = new wxTextCtrl(code_row_, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
    {
        wxFont f = code_->GetFont();
        f.SetFamily(wxFONTFAMILY_TELETYPE);
        code_->SetFont(f);
    }
    copy_ = new wxButton(code_row_, wxID_ANY, L("recv.copy"));
    ch->Add(code_, 1, wxEXPAND | wxRIGHT, 6);
    ch->Add(copy_, 0);
    cr->Add(ch, 0, wxEXPAND);
    auto* ih = new wxBoxSizer(wxHORIZONTAL);
    ih->Add(new wxStaticText(code_row_, wxID_ANY, L("recv.address")), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    ip_ = new wxChoice(code_row_, wxID_ANY);
    ih->Add(ip_, 0);
    portl_ = new wxStaticText(code_row_, wxID_ANY, "");
    ih->Add(portl_, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, 10);
    cr->Add(ih, 0, wxTOP, 6);
    fw_ = new WrapText(code_row_, "");
    fw_->SetTextColour(kGrey);
    cr->Add(fw_, 0, wxEXPAND | wxTOP, 6);
    code_row_->SetSizer(cr);
    b->Add(code_row_, 0, wxEXPAND);

    auto* wr = new wxBoxSizer(wxHORIZONTAL);
    count_ = new wxStaticText(body_, wxID_ANY, "");
    reopen_ = new wxButton(body_, wxID_ANY, L("recv.reopen"));
    cancel_code_ = new wxButton(body_, wxID_ANY, L("recv.cancelcode"));
    wr->Add(count_, 1, wxALIGN_CENTER_VERTICAL);
    wr->Add(cancel_code_, 0, wxRIGHT, 6);
    wr->Add(reopen_, 0);
    b->Add(wr, 0, wxEXPAND | wxTOP, 8);
    result_ = new WrapText(body_, "");
    result_->Hide();
    b->Add(result_, 0, wxEXPAND | wxTOP, 6);
    body_->SetSizer(b);
    v->Add(body_, 0, wxEXPAND | wxALL, 8);
    SetSizer(v);
    body_->Hide();

    chk_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent&) { OnToggle(chk_->GetValue()); });
    copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (code_->GetValue().empty()) return;
        if (wxTheClipboard->Open()) {
            wxTheClipboard->SetData(new wxTextDataObject(code_->GetValue()));
            wxTheClipboard->Close();
            result_->SetText(L("recv.copied"));
            result_->SetTextColour(kGreen);
            result_->Show();
            Resize();
        } else {
            c_.sh->report(BannerLevel::Warning, "simple.recv.copy", tr("recv.copyfail"));
        }
    });
    ip_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) { RebuildCode(); });
    reopen_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { OpenWindow(); });
    cancel_code_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { CancelCode(); });
    chg_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (changing_ || !on_) return;
        wxDirDialog dlg(this, L("recv.dlg.folder"), W(c_.sh->get_setting("recv.root", SimpleHost::default_receive_folder())),
                        wxDD_NEW_DIR_BUTTON);
        if (dlg.ShowModal() != wxID_OK) return;
        c_.sh->set_setting("recv.root", S(dlg.GetPath()));
        // Đổi thư mục nhận: tắt rồi bật lại để áp dụng.
        StopReceiving();
        CallAfter([this] { StartReceiving(true); });
    });
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { Tick(); });
}

ReceiveBox::~ReceiveBox() {
    *alive_ = false;
    timer_.Stop();
}

void ReceiveBox::Resize() {
    body_->Layout();
    Layout();
    if (GetParent()) GetParent()->Layout();
    if (auto* sw = wxDynamicCast(GetParent(), wxScrolledWindow)) sw->FitInside();
}

void ReceiveBox::RestoreAtStartup() {
    if (c_.sh->get_setting("recv.on", "0") != "1" || !c_.host->has_receiver_config()) return;
    chk_->SetValue(true);
    // Chỉ chạy lại engine nhận (chưa mở cửa sổ ghép: phải do người dùng bật chủ động).
    OnToggle(true);
}

void ReceiveBox::AutoEnable(const std::string& folder) {
    c_.sh->set_setting("recv.root", folder);
    chk_->SetValue(true);
    StartReceiving(true);
}

void ReceiveBox::OnToggle(bool want) {
    if (changing_) {
        chk_->SetValue(on_);
        return;
    }
    if (want) {
        if (c_.sh->get_setting("recv.on", "0") != "1" || !c_.host->has_receiver_config()) {
            // Lần đầu: hỏi thư mục nhận.
            wxDirDialog dlg(this, L("recv.dlg.folder"), W(c_.sh->get_setting("recv.root", SimpleHost::default_receive_folder())),
                            wxDD_NEW_DIR_BUTTON);
            if (dlg.ShowModal() != wxID_OK) {
                chk_->SetValue(false);
                return;
            }
            c_.sh->set_setting("recv.root", S(dlg.GetPath()));
            StartReceiving(true);
        } else {
            StartReceiving(false);
        }
    } else {
        StopReceiving();
    }
}

void ReceiveBox::StartReceiving(bool open_window) {
    if (changing_) return;
    changing_ = true;
    chk_->Disable();
    busy_->Start(L("recv.busy.start"));
    SimpleHost* host = c_.host;
    std::string root = c_.sh->get_setting("recv.root", SimpleHost::default_receive_folder());
    run_async<StartResult>(
        alive_,
        [host, root, open_window]() {
            StartResult r;
            r.ips = SimpleHost::local_addresses();
            simple::ensure_receiver_config(root, host->paths());
            if (!host->supervisor_ready()) host->start_supervisor(host->has_config(), true);
            host->sup()->set_receiver_enabled(true);  // idempotent; cần khi bộ giám sát do luồng khác vừa tạo không kèm bộ nhận
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(25);
            std::string last;
            for (;;) {
                simple::EngineInfo ei = host->receiver_info();
                if (ei.state == simple::EngineState::GaveUp)
                    throw Error(ei.last_error.empty() ? tr("recv.err.gaveup") : ei.last_error);
                try {
                    ControlClient cc(host->paths().receiver_control_name, 2000);
                    r.pi = cc.pair_info();
                    if (r.pi.available) {
                        if (open_window) {
                            r.pi = cc.pair_mode(true);
                            r.token = r.pi.token_hex;
                        }
                        return r;
                    }
                    last = tr("recv.err.unavailable");
                } catch (const std::exception& e) {
                    last = e.what();
                }
                if (std::chrono::steady_clock::now() > deadline) throw Error(trf("recv.err.nostart", {last}));
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
        },
        [this](bool ok, StartResult& r, const std::string& err) {
            changing_ = false;
            chk_->Enable();
            busy_->Stop();
            if (!ok) {
                on_ = false;
                chk_->SetValue(false);
                body_->Hide();
                c_.sh->set_setting("recv.on", "0");
                c_.sh->report(BannerLevel::Error, "simple.recv", friendly_error(err));
                Resize();
                return;
            }
            c_.sh->clear_report("simple.recv");
            on_ = true;
            chk_->SetValue(true);
            c_.sh->set_setting("recv.on", "1");
            ips_ = r.ips;
            ip_->Clear();
            for (const auto& ip : ips_) ip_->Append(W(ip));
            if (ip_->GetCount()) ip_->SetSelection(0);
            folder_->SetLabelText(W(folder_label(c_.sh->get_setting("recv.root", SimpleHost::default_receive_folder()))));
            folder_->SetToolTip(W(c_.sh->get_setting("recv.root", SimpleHost::default_receive_folder())));
            body_->Show();
            token_hex_ = r.token;
            code_used_ = false;
            ApplyInfo(r.pi);
            timer_.Start(prefers_reduced_motion() ? 1000 : 1000);
        });
}

void ReceiveBox::StopReceiving() {
    if (changing_) {
        chk_->SetValue(on_);
        return;
    }
    changing_ = true;
    chk_->Disable();
    timer_.Stop();
    busy_->Start(L("recv.busy.stop"));
    SimpleHost* host = c_.host;
    run_async<int>(
        alive_,
        [host]() {
            try {
                ControlClient cc(host->paths().receiver_control_name, 2000);
                cc.pair_mode(false);
            } catch (const std::exception&) {
                // Engine nhận có thể đã dừng: tiếp tục tắt.
            }
            if (host->supervisor_ready()) host->sup()->set_receiver_enabled(false);
            return 0;
        },
        [this](bool ok, int&, const std::string& err) {
            changing_ = false;
            chk_->Enable();
            busy_->Stop();
            if (!ok) c_.sh->report(BannerLevel::Error, "simple.recv", err);
            on_ = !ok;
            chk_->SetValue(on_);
            c_.sh->set_setting("recv.on", on_ ? "1" : "0");
            window_open_ = false;
            if (dlg_) dlg_->Finish();
            body_->Show(on_);
            if (on_) timer_.Start(1000);
            Resize();
        });
}

void ReceiveBox::OpenWindow() {
    if (changing_ || !on_) return;
    changing_ = true;
    reopen_->Disable();
    busy_->Start(L("recv.busy.window"));
    SimpleHost* host = c_.host;
    run_async<PairInfo>(
        alive_,
        [host]() {
            ControlClient cc(host->paths().receiver_control_name, 3000);
            return cc.pair_mode(true);
        },
        [this](bool ok, PairInfo& pi, const std::string& err) {
            changing_ = false;
            reopen_->Enable();
            busy_->Stop();
            if (!ok) {
                c_.sh->report(BannerLevel::Error, "simple.recv", err);
                return;
            }
            c_.sh->clear_report("simple.recv");
            token_hex_ = pi.token_hex;  // chỉ có trong câu trả lời này
            code_used_ = false;
            ApplyInfo(pi);
        });
}

void ReceiveBox::CancelCode() {
    if (changing_ || !on_) return;
    changing_ = true;
    busy_->Start(L("recv.busy.window"));
    SimpleHost* host = c_.host;
    run_async<PairInfo>(
        alive_,
        [host]() {
            ControlClient cc(host->paths().receiver_control_name, 3000);
            return cc.pair_mode(false);
        },
        [this](bool ok, PairInfo& pi, const std::string& err) {
            changing_ = false;
            busy_->Stop();
            if (!ok) {
                c_.sh->report(BannerLevel::Error, "simple.recv", err);
                return;
            }
            token_hex_.clear();
            ApplyInfo(pi);
        });
}

void ReceiveBox::MarkCodeUsed() {
    // Mã chỉ dùng được MỘT lần: đã có máy xin ghép (đồng ý hay không) thì mã cũ hết hiệu lực.
    if (code_used_) return;
    code_used_ = true;
    token_hex_.clear();
    RebuildCode();
    count_->SetLabelText(L("recv.code_used"));
    count_->SetForegroundColour(kAmber);
}

void ReceiveBox::Tick() {
    if (!on_ || ticking_ || changing_) return;
    ticking_ = true;
    std::string name = c_.host->paths().receiver_control_name;
    run_async<PairInfo>(
        alive_,
        [name]() {
            ControlClient cc(name, 1500);
            return cc.pair_info();
        },
        [this](bool ok, PairInfo& pi, const std::string& err) {
            ticking_ = false;
            if (!ok) {
                c_.sh->report(BannerLevel::Warning, "simple.recv", trf("recv.err.poll", {err}));
                return;
            }
            c_.sh->clear_report("simple.recv");
            ApplyInfo(pi);
        });
}

void ReceiveBox::ApplyInfo(const PairInfo& pi) {
    bool was_open = window_open_;
    if (!pi.public_hex.empty()) pub_hex_ = pi.public_hex;
    if (pi.port) port_ = pi.port;
    window_open_ = pi.mode_on;
    secs_left_ = static_cast<int>(pi.seconds_left);
    if (!window_open_) token_hex_.clear();
    if (window_open_ && !pi.pending.empty()) code_used_ = true;
    if (code_used_) token_hex_.clear();
    if (code_used_ && window_open_) {
        count_->SetLabelText(L("recv.code_used"));
        count_->SetForegroundColour(kAmber);
    } else if (window_open_) {
        count_->SetLabelText(W(trf("recv.window_left", {fmt_countdown(secs_left_)})));
        count_->SetForegroundColour(kGreen);
    } else {
        count_->SetLabelText(L("recv.window_closed"));
        count_->SetForegroundColour(kGrey);
    }
    reopen_->SetLabel(L("recv.reopen"));
    cancel_code_->Show(window_open_);
    if (was_open != window_open_ || code_->GetValue().empty() == (window_open_ && !code_used_)) RebuildCode();
    code_row_->Show(window_open_ && !code_used_);

    // Yêu cầu đang chờ duyệt.
    if (dlg_) {
        bool still = false;
        for (const auto& p : pi.pending)
            if (p.id == dlg_id_) {
                still = true;
                dlg_->SetLeft(static_cast<int>(p.seconds_left));
            }
        if (!still) dlg_->Finish();  // hết hạn hoặc đã xử lý ở nơi khác
    }
    if (!dlg_) {
        for (const auto& p : pi.pending) {
            if (dismissed_.count(p.id)) continue;
            ShowApprove(p);
            break;
        }
    }
    Resize();
}

void ReceiveBox::RebuildCode() {
    if (!window_open_ || pub_hex_.empty() || ips_.empty() || token_hex_.empty()) {
        code_->SetValue("");
        portl_->SetLabelText("");
        fw_->SetText(ips_.empty() && window_open_ ? L("recv.noip") : wxString());
        return;
    }
    try {
        simple::PairCode pc;
        pc.server_key = key_from_hex(pub_hex_);
        pc.port = port_;
        {
            Bytes tk = from_hex(token_hex_);
            if (tk.size() != pc.token.size()) throw Error("bad pairing token length");
            std::copy(tk.begin(), tk.end(), pc.token.begin());
        }
        pc.host = S(ip_->GetStringSelection());
        code_->SetValue(W(simple::encode_pair_code(pc)));
        portl_->SetLabelText(W(trf("recv.port", {std::to_string(port_)})));
        fw_->SetText(W(firewall_hint(port_)));
    } catch (const std::exception& e) {
        code_->SetValue("");
        c_.sh->report(BannerLevel::Error, "simple.recv.code", e.what());
    }
}

void ReceiveBox::ShowApprove(const PairPendingInfo& p) {
    dlg_id_ = p.id;
    if (c_.attention) c_.attention();
    wxWindow* top = wxGetTopLevelParent(this);
    dlg_ = new ApproveDialog(
        top, p,
        [this](uint32_t id, bool approve) {
            std::string name = c_.host->paths().receiver_control_name;
            run_async<std::string>(
                alive_,
                [name, id, approve]() {
                    ControlClient cc(name, 8000);
                    if (approve) return cc.pair_approve(id);
                    cc.pair_deny(id);
                    return std::string();
                },
                [this, id, approve](bool ok, std::string& prefix, const std::string& err) {
                    dismissed_.insert(id);
                    MarkCodeUsed();
                    if (dlg_ && dlg_id_ == id) dlg_->Finish();
                    if (!ok) {
                        c_.sh->report(BannerLevel::Error, "simple.recv", err);
                        return;
                    }
                    c_.sh->clear_report("simple.recv");
                    result_->SetText(W(approve ? trf("recv.approved", {prefix}) : tr("recv.denied")));
                    result_->SetTextColour(approve ? kGreen : kGrey);
                    result_->Show();
                    Resize();
                });
        },
        [this] {
            dismissed_.insert(dlg_id_);  // đã đóng: không bật lại cùng yêu cầu
            dlg_ = nullptr;
        });
    dlg_->Show();
    dlg_->Raise();
}

}  // namespace mysync::gui
