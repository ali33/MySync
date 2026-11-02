// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
// Hộp thoại "Dựng máy chủ": (1) chọn thư mục + cổng, (2) Tạo (lõi quick_server ở luồng nền, có chỉ báo động),
// (3) màn kết quả có nút Chép, thêm máy khách, cài thành dịch vụ. Logic thuần ở server_wizard_model.*.
#include "server_wizard.h"

#include <wx/clipbrd.h>
#include <algorithm>
#include <wx/dirdlg.h>
#include <wx/msgdlg.h>
#include <wx/scrolwin.h>
#include <wx/simplebook.h>
#include <wx/statline.h>

#include "server_wizard_model.h"
#include "simple_panel.h"   // WrapText, sp_font, save_window_png
#include "ui_common.h"

namespace mysync::gui {

namespace {
const wxColour kRed(0xA0, 0x10, 0x10), kGreen(0x1E, 0x7E, 0x34), kGrey(0x55, 0x55, 0x55);

class ServerWizardDialog : public wxDialog {
public:
    explicit ServerWizardDialog(wxWindow* parent);
    ~ServerWizardDialog() override { *alive_ = false; }

private:
    void BuildInput(wxWindow* p);
    void BuildResult(wxWindow* p);
    wxTextCtrl* ReadOnlyBox(wxWindow* p, const wxString& text, bool multiline, int height);
    void AddCopyRow(wxWindow* p, wxSizer* v, const char* label_key, const std::string& text, bool multiline, int height = 0);
    void CopyText(const std::string& text);
    void UpdateInput();
    void UpdateResultButtons();
    void SetStage(ServerStage s);
    void Create(bool fix_permissions = false);
    void ShowResult();
    void AddClient();
    void InstallService();
    void BeginBusy(const char* key);
    void EndBusy();
    void OnCloseRequest(wxCloseEvent& e);
    void DemoStep();

    AliveFlag alive_ = make_alive();
    BusyIndicator* busy_ = nullptr;
    wxPanel* content_ = nullptr;
    wxSimplebook* book_ = nullptr;
    ServerStage stage_ = ServerStage::Input;
    bool bg_busy_ = false;

    // trang nhập
    wxTextCtrl *folder_ = nullptr, *port_ = nullptr;
    wxButton *b_browse_ = nullptr, *b_create_ = nullptr, *b_close1_ = nullptr;
    WrapText *folder_err_ = nullptr, *port_err_ = nullptr, *create_err_ = nullptr;
    wxButton* b_fixperm_ = nullptr;   // hiện khi lõi từ chối thư mục người khác ghi được (GUI chạy quyền quản trị)
    std::string untrusted_;           // thư mục đang đề nghị khoá quyền
    std::string folder_norm_;
    uint16_t port_val_ = kQuickDefaultPort;

    // trang kết quả
    QuickResult res_;
    wxScrolledWindow* result_page_ = nullptr;
    wxBoxSizer* result_box_ = nullptr;
    std::vector<wxButton*> copy_btns_;
    WrapText* copy_status_ = nullptr;
    wxTextCtrl *c_key_ = nullptr, *c_name_ = nullptr;
    wxRadioButton *c_rw_ = nullptr, *c_ro_ = nullptr;
    wxButton *b_add_ = nullptr, *b_svc_ = nullptr, *b_close2_ = nullptr;
    WrapText *client_msg_ = nullptr, *svc_msg_ = nullptr, *key_err_ = nullptr, *name_err_ = nullptr;
};

ServerWizardDialog::ServerWizardDialog(wxWindow* parent)
    : wxDialog(parent, wxID_ANY, L("srv.title"), wxDefaultPosition, wxSize(780, 780),
               wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER) {
    auto* top = new wxBoxSizer(wxVERTICAL);
    busy_ = new BusyIndicator(this);
    top->Add(busy_, 0, wxEXPAND | wxALL, 8);
    content_ = new wxPanel(this, wxID_ANY);
    auto* cs = new wxBoxSizer(wxVERTICAL);
    book_ = new wxSimplebook(content_, wxID_ANY);
    auto* p1 = new wxPanel(book_);
    BuildInput(p1);
    book_->AddPage(p1, "input");
    result_page_ = new wxScrolledWindow(book_, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxVSCROLL);
    result_page_->SetScrollRate(0, 12);
    BuildResult(result_page_);
    book_->AddPage(result_page_, "result");
    cs->Add(book_, 1, wxEXPAND | wxALL, 12);
    content_->SetSizer(cs);
    top->Add(content_, 1, wxEXPAND);
    SetSizer(top);
    SetMinSize(wxSize(620, 520));
    SetInitialSize(wxSize(780, std::min(900, wxGetClientDisplayRect().height - 60)));
    Centre();
    Bind(wxEVT_CLOSE_WINDOW, &ServerWizardDialog::OnCloseRequest, this);
    UpdateInput();
    CallAfter([this] { DemoStep(); });
}

void ServerWizardDialog::BuildInput(wxWindow* p) {
    auto* v = new wxBoxSizer(wxVERTICAL);
    auto* title = new wxStaticText(p, wxID_ANY, L("srv.title"));
    sp_font(title, 1.5);
    v->Add(title, 0, wxBOTTOM, 8);
    v->Add(new WrapText(p, L("srv.intro")), 0, wxEXPAND | wxBOTTOM, 14);

    v->Add(new wxStaticText(p, wxID_ANY, L("srv.folder")), 0, wxBOTTOM, 4);
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    folder_ = new wxTextCtrl(p, wxID_ANY, "");
    folder_->SetHint(L("srv.folder.hint"));
    b_browse_ = new wxButton(p, wxID_ANY, L("srv.browse"));
    h->Add(folder_, 1, wxEXPAND | wxRIGHT, 8);
    h->Add(b_browse_, 0);
    v->Add(h, 0, wxEXPAND);
    folder_err_ = new WrapText(p, "");
    folder_err_->SetTextColour(kRed);
    folder_err_->Hide();
    v->Add(folder_err_, 0, wxEXPAND | wxTOP, 4);

    v->Add(new wxStaticText(p, wxID_ANY, L("srv.port")), 0, wxTOP | wxBOTTOM, 4);
    port_ = new wxTextCtrl(p, wxID_ANY, std::to_string(kQuickDefaultPort), wxDefaultPosition, wxSize(110, -1));
    v->Add(port_, 0);
    port_err_ = new WrapText(p, "");
    port_err_->SetTextColour(kRed);
    port_err_->Hide();
    v->Add(port_err_, 0, wxEXPAND | wxTOP, 4);
    auto* note = new WrapText(p, L("srv.port.note"));
    note->SetTextColour(kGrey);
    v->Add(note, 0, wxEXPAND | wxTOP, 4);

    create_err_ = new WrapText(p, "");
    create_err_->SetTextColour(kRed);
    create_err_->Hide();
    v->Add(create_err_, 0, wxEXPAND | wxTOP, 12);
    b_fixperm_ = new wxButton(p, wxID_ANY, L("srv.fixperm"));
    b_fixperm_->Hide();
    v->Add(b_fixperm_, 0, wxTOP, 6);

    v->AddStretchSpacer(1);
    auto* nav = new wxBoxSizer(wxHORIZONTAL);
    b_close1_ = new wxButton(p, wxID_ANY, L("srv.close"));
    b_create_ = new wxButton(p, wxID_ANY, L("srv.create"));
    sp_font(b_create_, 1.2);
    nav->Add(b_close1_, 0, wxRIGHT, 8);
    nav->AddStretchSpacer(1);
    nav->Add(b_create_, 0);
    v->Add(nav, 0, wxEXPAND | wxTOP, 14);
    p->SetSizer(v);

    b_fixperm_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (untrusted_.empty() || bg_busy_) return;
        wxMessageDialog q(this, W(trf("srv.fixperm.confirm", {untrusted_})), L("srv.fixperm"),
                          wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION);
        if (q.ShowModal() == wxID_YES) Create(true);
    });
    b_browse_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        wxDirDialog dlg(this, L("srv.browse.dlg"), folder_->GetValue(), wxDD_DEFAULT_STYLE | wxDD_NEW_DIR_BUTTON);
        if (dlg.ShowModal() == wxID_OK) folder_->SetValue(dlg.GetPath());
    });
    folder_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { UpdateInput(); });
    port_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { UpdateInput(); });
    b_create_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Create(); });
    b_close1_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Close(); });
}

wxTextCtrl* ServerWizardDialog::ReadOnlyBox(wxWindow* p, const wxString& text, bool multiline, int height) {
    long style = wxTE_READONLY | (multiline ? (wxTE_MULTILINE | wxTE_DONTWRAP | wxHSCROLL) : 0L);
    auto* t = new wxTextCtrl(p, wxID_ANY, text, wxDefaultPosition, multiline ? wxSize(-1, height) : wxDefaultSize, style);
    wxFont f(wxFontInfo(t->GetFont().GetPointSize()).Family(wxFONTFAMILY_TELETYPE));
    if (f.IsOk()) t->SetFont(f);
    return t;
}

void ServerWizardDialog::AddCopyRow(wxWindow* p, wxSizer* v, const char* label_key, const std::string& text, bool multiline, int height) {
    v->Add(new wxStaticText(p, wxID_ANY, L(label_key)), 0, wxTOP | wxBOTTOM, 4);
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    auto* box = ReadOnlyBox(p, W(text), multiline, height);
    auto* btn = new wxButton(p, wxID_ANY, L("srv.copy"));
    h->Add(box, 1, wxEXPAND | wxRIGHT, 8);
    h->Add(btn, 0, multiline ? wxALIGN_TOP : wxALIGN_CENTER_VERTICAL);
    v->Add(h, 0, wxEXPAND);
    copy_btns_.push_back(btn);
    btn->Bind(wxEVT_BUTTON, [this, text](wxCommandEvent&) { CopyText(text); });
}

void ServerWizardDialog::BuildResult(wxWindow* p) {
    // Phần động (chữ lấy từ kết quả) được dựng lại trong ShowResult(); ở đây chỉ dựng khung.
    result_box_ = new wxBoxSizer(wxVERTICAL);
    p->SetSizer(result_box_);
}

void ServerWizardDialog::ShowResult() {
    wxWindow* p = result_page_;
    result_box_->Clear(true);
    copy_btns_.clear();
    ServerResultTexts t = make_server_result_texts(res_);

    auto* head = new wxStaticText(p, wxID_ANY, W(t.headline));
    sp_font(head, 1.4);
    head->SetForegroundColour(kGreen);
    result_box_->Add(head, 0, wxBOTTOM, 8);
    for (const std::string* line : {&t.folder_line, &t.port_line, &t.config_line, &t.key_line, &t.pairing_line})
        result_box_->Add(new WrapText(p, W(*line)), 0, wxEXPAND | wxBOTTOM, 3);
    for (const auto& n : t.notes) {
        auto* w = new WrapText(p, W(n));
        w->SetTextColour(wxColour(0x8A, 0x5A, 0x00));
        result_box_->Add(w, 0, wxEXPAND | wxBOTTOM, 3);
    }
    AddCopyRow(p, result_box_, "srv.res.pubkey", t.public_key, false);
    AddCopyRow(p, result_box_, "srv.res.fp", t.fingerprint, false);
    AddCopyRow(p, result_box_, "srv.res.snippet", t.client_snippet, true, 150);
    AddCopyRow(p, result_box_, "srv.res.peeradd", t.peer_add_command, true, 60);
    copy_status_ = new WrapText(p, "");
    result_box_->Add(copy_status_, 0, wxEXPAND | wxTOP, 4);

    // Thêm máy khách
    result_box_->Add(new wxStaticLine(p), 0, wxEXPAND | wxTOP | wxBOTTOM, 10);
    auto* ct = new wxStaticText(p, wxID_ANY, L("srv.client.title"));
    sp_font(ct, 1.15);
    result_box_->Add(ct, 0, wxBOTTOM, 6);
    result_box_->Add(new wxStaticText(p, wxID_ANY, L("srv.client.key")), 0, wxBOTTOM, 3);
    c_key_ = new wxTextCtrl(p, wxID_ANY, "");
    c_key_->SetHint(L("srv.client.key.hint"));
    result_box_->Add(c_key_, 0, wxEXPAND);
    key_err_ = new WrapText(p, "");
    key_err_->SetTextColour(kRed);
    key_err_->Hide();
    result_box_->Add(key_err_, 0, wxEXPAND | wxTOP, 3);
    result_box_->Add(new wxStaticText(p, wxID_ANY, L("srv.client.name")), 0, wxTOP | wxBOTTOM, 3);
    c_name_ = new wxTextCtrl(p, wxID_ANY, "");
    result_box_->Add(c_name_, 0, wxEXPAND);
    name_err_ = new WrapText(p, "");
    name_err_->SetTextColour(kRed);
    name_err_->Hide();
    result_box_->Add(name_err_, 0, wxEXPAND | wxTOP, 3);
    auto* mode = new wxBoxSizer(wxHORIZONTAL);
    c_rw_ = new wxRadioButton(p, wxID_ANY, L("srv.client.rw"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
    c_ro_ = new wxRadioButton(p, wxID_ANY, L("srv.client.ro"));
    c_rw_->SetValue(true);
    mode->Add(c_rw_, 0, wxRIGHT, 16);
    mode->Add(c_ro_, 0);
    result_box_->Add(mode, 0, wxTOP, 8);
    b_add_ = new wxButton(p, wxID_ANY, L("srv.client.add"));
    result_box_->Add(b_add_, 0, wxTOP, 8);
    client_msg_ = new WrapText(p, "");
    client_msg_->Hide();
    result_box_->Add(client_msg_, 0, wxEXPAND | wxTOP, 4);

    // Dịch vụ
    result_box_->Add(new wxStaticLine(p), 0, wxEXPAND | wxTOP | wxBOTTOM, 10);
    auto* st = new wxStaticText(p, wxID_ANY, L("srv.svc.title"));
    sp_font(st, 1.15);
    result_box_->Add(st, 0, wxBOTTOM, 6);
    b_svc_ = new wxButton(p, wxID_ANY, L("srv.svc.install"));
    result_box_->Add(b_svc_, 0);
    svc_msg_ = new WrapText(p, "");
    svc_msg_->Hide();
    result_box_->Add(svc_msg_, 0, wxEXPAND | wxTOP, 4);

    result_box_->Add(new wxStaticLine(p), 0, wxEXPAND | wxTOP | wxBOTTOM, 10);
    b_close2_ = new wxButton(p, wxID_ANY, L("srv.close"));
    result_box_->Add(b_close2_, 0, wxALIGN_RIGHT);

    c_key_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { UpdateResultButtons(); });
    c_name_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { UpdateResultButtons(); });
    b_add_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { AddClient(); });
    b_svc_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { InstallService(); });
    b_close2_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { Close(); });

    result_page_->FitInside();
    book_->SetSelection(1);
    SetStage(ServerStage::Result);
    UpdateResultButtons();
    Layout();
    result_page_->Layout();
    result_page_->FitInside();
}

void ServerWizardDialog::CopyText(const std::string& text) {
    if (wxTheClipboard->Open()) {
        wxTheClipboard->SetData(new wxTextDataObject(W(text)));
        wxTheClipboard->Close();
        copy_status_->SetText(L("srv.copied"));
        copy_status_->SetTextColour(kGreen);
    } else {
        copy_status_->SetText(L("srv.copyfail"));
        copy_status_->SetTextColour(kRed);
    }
    result_page_->Layout();
}

void ServerWizardDialog::UpdateInput() {
    std::string fn;
    uint16_t pv = 0;
    const std::string ftxt = S(folder_->GetValue()), ptxt = S(port_->GetValue());
    InputCheck f = check_server_folder(ftxt, fn);
    InputCheck p = check_server_port(ptxt, pv);
    // Ô trống chưa gõ gì thì chưa báo lỗi đỏ (nút Tạo vẫn tắt); gõ sai thì báo ngay cạnh ô.
    bool fshow = !f.ok && !ftxt.empty(), pshow = !p.ok;
    folder_err_->SetText(W(f.error));
    port_err_->SetText(W(p.error));
    folder_err_->Show(fshow);
    port_err_->Show(pshow);
    if (f.ok) folder_norm_ = fn;
    if (p.ok) port_val_ = pv;
    ServerButtons b = server_buttons(stage_, f.ok && p.ok, false, false);
    b_create_->Enable(b.create);
    b_browse_->Enable(b.browse);
    b_close1_->Enable(b.close);
    if (auto* pg = folder_->GetParent()) pg->Layout();
}

void ServerWizardDialog::UpdateResultButtons() {
    if (!b_add_) return;
    std::string hex, nm;
    const std::string ktxt = S(c_key_->GetValue()), ntxt = S(c_name_->GetValue());
    InputCheck k = check_client_key(ktxt, hex);
    InputCheck n = check_client_name(ntxt, nm);
    key_err_->SetText(W(k.error));
    name_err_->SetText(W(n.error));
    key_err_->Show(!k.ok && !ktxt.empty());
    name_err_->Show(!n.ok && !ntxt.empty());
    ServerButtons b = server_buttons(stage_, true, k.ok && n.ok, bg_busy_);
    b_add_->Enable(b.add_client);
    b_svc_->Enable(b.install_service);
    b_close2_->Enable(b.close);
    for (auto* c : copy_btns_) c->Enable(b.copy);
    result_page_->Layout();
    result_page_->FitInside();
}

void ServerWizardDialog::SetStage(ServerStage s) {
    stage_ = s;
    if (s == ServerStage::Input) UpdateInput();
}

void ServerWizardDialog::BeginBusy(const char* key) {
    bg_busy_ = true;
    content_->Enable(false);
    busy_->Start(L(key));
    Layout();
}

void ServerWizardDialog::EndBusy() {
    bg_busy_ = false;
    content_->Enable(true);
    busy_->Stop();
    Layout();
}

void ServerWizardDialog::OnCloseRequest(wxCloseEvent& e) {
    // Không đóng khi lõi đang chạy (cài dịch vụ có thể đang chờ UAC): tránh bỏ dở giữa chừng.
    if (bg_busy_ && e.CanVeto()) {
        e.Veto();
        return;
    }
    e.Skip();
}

void ServerWizardDialog::Create(bool fix_permissions) {
    std::string fn;
    uint16_t pv = 0;
    if (!check_server_folder(S(folder_->GetValue()), fn).ok || !check_server_port(S(port_->GetValue()), pv).ok) {
        UpdateInput();
        return;
    }
    if (bg_busy_) return;
    create_err_->Hide();
    b_fixperm_->Hide();
    untrusted_.clear();
    stage_ = ServerStage::Creating;
    b_create_->Enable(false);
    BeginBusy("srv.busy.create");
    run_async<CreateServerOutcome>(
        alive_, [fn, pv, fix_permissions]() { return create_server_outcome(fn, pv, fix_permissions); },
        [this](bool ok, CreateServerOutcome& o, const std::string& err) {
            EndBusy();
            if (!ok || !o.ok) {
                stage_ = ServerStage::Input;
                create_err_->SetText(W(ok ? o.error : trf("srv.err.create", {err})));   // nguyên văn lỗi của lõi
                create_err_->Show();
                untrusted_ = ok ? o.untrusted_folder : std::string();
                b_fixperm_->Show(!untrusted_.empty());
                UpdateInput();
                book_->GetPage(0)->Layout();
                return;
            }
            res_ = o.result;
            ShowResult();
            CallAfter([this] { DemoStep(); });
        });
}

void ServerWizardDialog::AddClient() {
    if (bg_busy_ || stage_ != ServerStage::Result) return;
    const std::string cfg = res_.config_file, name = S(c_name_->GetValue()), key = S(c_key_->GetValue());
    const bool ro = c_ro_->GetValue();
    BeginBusy("srv.busy.client");
    run_async<AddClientOutcome>(
        alive_, [cfg, name, key, ro]() { return add_client(cfg, name, key, ro); },
        [this](bool ok, AddClientOutcome& o, const std::string& err) {
            EndBusy();
            if (!ok) {
                o.ok = false;
                o.message = err;
            }
            client_msg_->SetText(W(trf(o.ok ? "srv.client.done" : "srv.client.fail", {o.message})));
            client_msg_->SetTextColour(o.ok ? kGreen : kRed);
            client_msg_->Show();
            UpdateResultButtons();
            CallAfter([this] { DemoStep(); });
        });
}

void ServerWizardDialog::InstallService() {
    if (bg_busy_ || stage_ != ServerStage::Result) return;
    const QuickResult r = res_;
    BeginBusy("srv.busy.service");
    run_async<ServiceOutcome>(
        alive_, [r]() { return install_server_service(r); },
        [this](bool ok, ServiceOutcome& o, const std::string& err) {
            EndBusy();
            if (!ok) {
                o.ok = false;
                o.message = err;
            }
            svc_msg_->SetText(W(o.cancelled ? tr("srv.svc.cancelled") : o.message));
            svc_msg_->SetTextColour(o.ok ? kGreen : kRed);
            svc_msg_->Show();
            UpdateResultButtons();
        });
}

// Chỉ chạy khi có --server-wizard-demo: lái hộp thoại bằng đường sự kiện thật rồi chụp màn kết quả.
void ServerWizardDialog::DemoStep() {
    const ServerWizardDemo& d = server_wizard_demo();
    if (d.folder.empty()) return;
    if (stage_ == ServerStage::Input && !bg_busy_) {
        folder_->SetValue(W(d.folder));
        Create();
    } else if (stage_ == ServerStage::Result && client_msg_ && !client_msg_->IsShown()) {
        c_key_->SetValue("0x07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab07ab");   // khoá mẫu, không phải của ai
        c_name_->SetValue("may-ke-toan");
        AddClient();
    } else if (stage_ == ServerStage::Result && client_msg_ && client_msg_->IsShown() && !d.png.empty()) {
        auto* t = new wxTimer;
        t->Bind(wxEVT_TIMER, [this, t, d](wxTimerEvent&) {
            result_page_->Scroll(0, 0);
            std::string e = save_window_png(this, d.png);
            if (!e.empty()) wxLogError("%s", W(e));
            t->Stop();
            Close(true);
        });
        t->StartOnce(600);
    }
}

}  // namespace

ServerWizardDemo& server_wizard_demo() {
    static ServerWizardDemo d;
    return d;
}

void show_server_wizard(wxWindow* parent) {
    ServerWizardDialog dlg(parent);
    dlg.ShowModal();
    if (!server_wizard_demo().png.empty() && parent) parent->Close(true);   // chỉ khi chụp ảnh tài liệu
}

}  // namespace mysync::gui
