// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "ui_common.h"

#include <wx/activityindicator.h>
#include <wx/dcmemory.h>
#include <wx/image.h>

#include <algorithm>
#include <chrono>
#include <cmath>

#ifdef _WIN32
#include <windows.h>
#endif
#ifdef __WXGTK__
#include <gtk/gtk.h>
#endif

namespace mysync::gui {

bool prefers_reduced_motion() {
#ifdef _WIN32
    BOOL on = TRUE;
    if (SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &on, 0)) return on == FALSE;
    return false;
#elif defined(__WXGTK__)
    gboolean anim = TRUE;
    GtkSettings* st = gtk_settings_get_default();
    if (st) g_object_get(st, "gtk-enable-animations", &anim, nullptr);
    return anim == FALSE;
#else
    return false;
#endif
}

// ---------------------------------------------------------------- async bookkeeping
namespace {
std::atomic<int> g_inflight{0};
}
void async_begin() { ++g_inflight; }
void async_end() { --g_inflight; }
int async_inflight() { return g_inflight.load(); }
void async_wait_idle(int timeout_ms) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (g_inflight.load() > 0 && std::chrono::steady_clock::now() < end) {
        wxMilliSleep(20);
        if (wxTheApp) wxTheApp->ProcessPendingEvents();
    }
}

// ---------------------------------------------------------------- BusyIndicator
BusyIndicator::BusyIndicator(wxWindow* parent) : wxPanel(parent, wxID_ANY), timer_(this) {
    auto* h = new wxBoxSizer(wxHORIZONTAL);
    spin_ = new wxActivityIndicator(this, wxID_ANY, wxDefaultPosition, wxSize(22, 22));
    text_ = new wxStaticText(this, wxID_ANY, "");
    h->Add(spin_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
    h->Add(text_, 1, wxALIGN_CENTER_VERTICAL);
    SetSizer(h);
    Bind(wxEVT_TIMER, &BusyIndicator::OnTimer, this);
    Hide();
}

BusyIndicator::~BusyIndicator() { timer_.Stop(); }

void BusyIndicator::Start(const wxString& label) {
    label_ = label;
    reduced_ = prefers_reduced_motion();
    running_ = true;
    phase_ = false;
    // Giảm chuyển động: không quay, chỉ nhấp nháy chậm (vẫn là tín hiệu "đang làm việc", không bỏ).
    if (reduced_) {
        spin_->Hide();
        text_->SetLabelText(label_ + " ●");
        timer_.Start(800);
    } else {
        spin_->Show();
        spin_->Start();
        text_->SetLabelText(label_);
    }
    Show();
    GetParent()->Layout();
}

void BusyIndicator::Stop() {
    running_ = false;
    timer_.Stop();
    spin_->Stop();
    Hide();
    if (GetParent()) GetParent()->Layout();
}

void BusyIndicator::OnTimer(wxTimerEvent&) {
    phase_ = !phase_;
    text_->SetLabelText(label_ + (phase_ ? " ○" : " ●"));
}

// ---------------------------------------------------------------- BusyGate
bool BusyGate::begin(const char* label_key) {
    if (busy_) return false;
    busy_ = true;
    if (content_) content_->Enable(false);
    if (ind_) ind_->Start(L(label_key));
    return true;
}
void BusyGate::end() {
    busy_ = false;
    if (content_) content_->Enable(true);
    if (ind_) ind_->Stop();
}

// ---------------------------------------------------------------- ErrorBanner
ErrorBanner::ErrorBanner(wxWindow* parent) : wxPanel(parent, wxID_ANY) {
    box_ = new wxBoxSizer(wxVERTICAL);
    SetSizer(box_);
    Hide();
}

void ErrorBanner::Report(BannerLevel lv, const std::string& source, const std::string& msg) {
    wxLogDebug("banner[%s]: %s", wxString::FromUTF8(source), wxString::FromUTF8(msg));
    if (!source.empty()) {
        auto d = dismissed_.find(source);
        if (d != dismissed_.end() && d->second == msg) return;
    }
    if (model_.add(lv, source, msg)) Rebuild();
}
void ErrorBanner::ClearSource(const std::string& source) {
    dismissed_.erase(source);
    if (model_.clear_source(source)) Rebuild();
}
void ErrorBanner::ClearAll() {
    model_.clear();
    Rebuild();
}

void ErrorBanner::Rebuild() {
    Freeze();
    box_->Clear(true);
    for (const auto& it : model_.items()) {
        bool err = it.level == BannerLevel::Error;
        auto* row = new wxPanel(this, wxID_ANY);
        row->SetBackgroundColour(err ? wxColour(0xFD, 0xE2, 0xE0) : wxColour(0xFF, 0xF1, 0xC4));
        auto* h = new wxBoxSizer(wxHORIZONTAL);
        auto* t = new wxStaticText(row, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxST_NO_AUTORESIZE);
        t->SetLabelText(W((err ? "⛔ " : "⚠ ") + model_.render(it)));  // nguyên văn: '&' không thành phím tắt
        t->SetForegroundColour(err ? wxColour(0x8B, 0x10, 0x10) : wxColour(0x5C, 0x45, 0x00));
        h->Add(t, 1, wxALL | wxEXPAND, 6);
        auto* x = new wxButton(row, wxID_ANY, L("banner.dismiss"), wxDefaultPosition, wxDefaultSize, wxBU_EXACTFIT);
        std::string src = it.source;
        std::string msg = it.message;
        x->Bind(wxEVT_BUTTON, [this, src, msg](wxCommandEvent&) {
            if (!src.empty()) dismissed_[src] = msg;
            model_.remove(src, msg);
            CallAfter([this] { Rebuild(); Relayout(); });
        });
        h->Add(x, 0, wxALL | wxALIGN_CENTER_VERTICAL, 3);
        row->SetSizer(h);
        box_->Add(row, 0, wxEXPAND | wxBOTTOM, 1);
        t->Wrap(std::max(300, GetParent() ? GetParent()->GetClientSize().GetWidth() - 120 : 600));
    }
    Show(!model_.items().empty());
    Thaw();
    Relayout();
}

void ErrorBanner::Relayout() {
    Layout();
    if (GetParent()) GetParent()->Layout();
}

// ---------------------------------------------------------------- icon
wxIcon make_state_icon(TrayState st, int frame, int size) {
    uint32_t rgb = tray_state_color(st);
    int R = (rgb >> 16) & 0xFF, G = (rgb >> 8) & 0xFF, B = rgb & 0xFF;
    wxImage img(size, size);
    img.InitAlpha();
    double c = (size - 1) / 2.0, r = size / 2.0 - 1.0;
    const double pi = 3.14159265358979;
    double spin_a = (frame % 8) * (pi / 4.0);
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            double dx = x - c, dy = y - c, d = std::sqrt(dx * dx + dy * dy);
            double a = std::clamp(r + 0.5 - d, 0.0, 1.0);  // chống răng cưa mép
            int pr = R, pg = G, pb = B;
            if (a > 0) {
                if (st == TrayState::Syncing) {
                    // cung trắng xoay quanh tâm
                    double ang = std::atan2(dy, dx) - spin_a;
                    while (ang < 0) ang += 2 * pi;
                    while (ang >= 2 * pi) ang -= 2 * pi;
                    if (d > r * 0.35 && d < r * 0.78 && ang < pi * 0.75) pr = pg = pb = 255;
                } else if (st == TrayState::Error) {
                    // dấu chấm than
                    if (std::abs(dx) < size * 0.07 && dy > -r * 0.6 && dy < r * 0.15) pr = pg = pb = 255;
                    if (dx * dx + (dy - r * 0.5) * (dy - r * 0.5) < (size * 0.08) * (size * 0.08)) pr = pg = pb = 255;
                } else if (st == TrayState::Warning) {
                    if (std::abs(dx) < size * 0.07 && dy > -r * 0.6 && dy < r * 0.15) pr = pg = pb = 0x44;
                    if (dx * dx + (dy - r * 0.5) * (dy - r * 0.5) < (size * 0.08) * (size * 0.08)) pr = pg = pb = 0x44;
                } else if (st == TrayState::Idle) {
                    // dấu tích
                    double u = dx / r, v = dy / r;
                    auto seg = [&](double x1, double y1, double x2, double y2) {
                        double px = u - x1, py = v - y1, ex = x2 - x1, ey = y2 - y1;
                        double t = std::clamp((px * ex + py * ey) / (ex * ex + ey * ey), 0.0, 1.0);
                        double qx = px - t * ex, qy = py - t * ey;
                        return std::sqrt(qx * qx + qy * qy) < 0.14;
                    };
                    if (seg(-0.5, 0.05, -0.12, 0.42) || seg(-0.12, 0.42, 0.52, -0.38)) pr = pg = pb = 255;
                } else {
                    // Offline: dấu gạch ngang
                    if (std::abs(dy) < size * 0.07 && std::abs(dx) < r * 0.5) pr = pg = pb = 255;
                }
            }
            img.SetRGB(x, y, static_cast<unsigned char>(pr), static_cast<unsigned char>(pg), static_cast<unsigned char>(pb));
            img.SetAlpha(x, y, static_cast<unsigned char>(a * 255));
        }
    }
    wxBitmap bmp(img);
    wxIcon ic;
    ic.CopyFromBitmap(bmp);
    return ic;
}

void show_error_dialog(wxWindow* parent, const std::string& title, const std::string& message) {
    wxMessageDialog dlg(parent, W(message), W(title), wxOK | wxICON_ERROR);
    dlg.ShowModal();
}

}  // namespace mysync::gui
