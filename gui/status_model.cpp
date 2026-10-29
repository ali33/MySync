// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "status_model.h"

#include <algorithm>
#include <chrono>
#include <cstdio>

#include "i18n_model.h"

namespace mysync::gui {

namespace {
std::string num1(double v) {
    char b[48];
    std::snprintf(b, sizeof b, "%.1f", v);
    std::string s = b;
    if (lang() == Lang::Vi) std::replace(s.begin(), s.end(), '.', ',');
    return s;
}
std::string itoa(uint64_t v) { return std::to_string(v); }
}  // namespace

std::string fmt_bytes(uint64_t n) {
    static const char* unit[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    if (n < 1024) return itoa(n) + " B";
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024.0 && u < 5) { v /= 1024.0; ++u; }
    return num1(v) + " " + unit[u];
}

std::string fmt_rate(uint64_t bps) { return fmt_bytes(bps) + "/s"; }

std::string fmt_duration(uint64_t s) {
    char b[96];
    uint64_t d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60, sec = s % 60;
    if (d > 0) return trf("dur.dh", {itoa(d), itoa(h)});
    if (h > 0) return trf("dur.hm", {itoa(h), itoa(m)});
    if (m > 0) {
        std::snprintf(b, sizeof b, "%02llu", static_cast<unsigned long long>(sec));
        return trf("dur.ms", {itoa(m), b});
    }
    return trf("dur.s", {itoa(sec)});
}

std::string weekday_name(int w) {
    if (w < 0 || w > 6) return "?";
    static const char* keys[] = {"wd.0", "wd.1", "wd.2", "wd.3", "wd.4", "wd.5", "wd.6"};
    return tr(keys[w]);
}

std::string fmt_datetime_tm(const std::tm& t) {
    char b[64];
    std::snprintf(b, sizeof b, "%02d/%02d/%04d %02d:%02d:%02d", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900,
                  t.tm_hour, t.tm_min, t.tm_sec);
    return weekday_name(t.tm_wday) + " " + b;
}

std::string fmt_datetime(int64_t unix_ms) {
    if (unix_ms <= 0) return "—";
    std::time_t tt = static_cast<std::time_t>(unix_ms / 1000);
    std::tm t{};
#ifdef _WIN32
    localtime_s(&t, &tt);  // giờ địa phương, không phải UTC
#else
    localtime_r(&tt, &t);
#endif
    return fmt_datetime_tm(t);
}

std::string fmt_time_ago(int64_t unix_ms, int64_t now_ms) {
    if (unix_ms <= 0) return "—";
    int64_t s = std::max<int64_t>(0, (now_ms - unix_ms) / 1000);
    if (s < 60) return trf("ago.s", {std::to_string(s)});
    if (s < 3600) return trf("ago.m", {std::to_string(s / 60)});
    if (s < 86400) return trf("ago.h", {std::to_string(s / 3600)});
    return trf("ago.d", {std::to_string(s / 86400)});
}

const char* tray_state_name(TrayState s) {
    switch (s) {
        case TrayState::Offline: return "offline";
        case TrayState::Idle: return "idle";
        case TrayState::Syncing: return "syncing";
        case TrayState::Warning: return "warning";
        case TrayState::Error: return "error";
    }
    return "?";
}

uint32_t tray_state_color(TrayState s) {
    switch (s) {
        case TrayState::Offline: return 0x8A8A8A;
        case TrayState::Idle: return 0x2E9E4F;
        case TrayState::Syncing: return 0x2B7BE4;
        case TrayState::Warning: return 0xE0A800;
        case TrayState::Error: return 0xD0312D;
    }
    return 0x8A8A8A;
}

TrayState compute_tray_state(bool connected, const StatusSnapshot& s, int64_t now_ms, int64_t recent_ms) {
    if (!connected) return TrayState::Offline;
    bool syncing = false, warn = !s.config_error.empty();
    for (const auto& t : s.targets) {
        if (t.state == TargetState::Error) return TrayState::Error;
        if (t.state == TargetState::Syncing) syncing = true;
        if (t.state == TargetState::Disconnected) warn = true;
        if (t.last_error_unix_ms > 0 && now_ms - t.last_error_unix_ms <= recent_ms) warn = true;
    }
    if (warn) return TrayState::Warning;
    if (syncing) return TrayState::Syncing;
    return TrayState::Idle;
}

std::string tray_tooltip(bool connected, const StatusSnapshot& s, TrayState st) {
    std::string head = "MySync";
    if (!connected) return head + " - " + tr("tray.offline");
    std::string txt;
    switch (st) {
        case TrayState::Syncing: txt = tr("tray.syncing"); break;
        case TrayState::Warning: txt = tr("tray.warning"); break;
        case TrayState::Error: txt = tr("tray.error"); break;
        default: txt = tr("tray.idle"); break;
    }
    std::string r = head + " - " + txt;
    if (s.total_tx_bps || s.total_rx_bps)
        r += "\n" + tr("tray.rate") + " " + fmt_rate(s.total_tx_bps) + " / " + fmt_rate(s.total_rx_bps);
    return r;
}

std::string target_state_text(TargetState s) {
    switch (s) {
        case TargetState::Idle: return tr("state.idle");
        case TargetState::Syncing: return tr("state.syncing");
        case TargetState::Error: return tr("state.error");
        case TargetState::Disconnected: return tr("state.disconnected");
    }
    return "?";
}

std::string target_display(const std::string& raw) {
    if (raw.rfind("net://", 0) == 0) return raw.substr(6) + " " + tr("target.net");
    if (raw.rfind("dir://", 0) == 0) return raw.substr(6) + " " + tr("target.dir");
    return raw;
}

TargetRow make_target_row(const TargetStatus& t) {
    TargetRow r;
    r.watch = t.watch;
    r.target = target_display(t.target);
    r.raw_state = t.state;
    r.state = target_state_text(t.state);
    r.queued = itoa(t.queued) + (t.active_files.empty() ? "" : " (+" + itoa(t.active_files.size()) + ")");
    r.speed = "↑ " + fmt_rate(t.tx_bps) + "  ↓ " + fmt_rate(t.rx_bps);
    r.counts = itoa(t.sent) + " / " + itoa(t.skipped) + " / " + itoa(t.failed);
    r.bytes = fmt_bytes(t.bytes);
    return r;
}

PeerRow make_peer_row(const PeerStatus& p) {
    PeerRow r;
    r.name = p.name;
    r.sessions = itoa(p.sessions);
    r.speed = "↓ " + fmt_rate(p.rx_bps) + "  ↑ " + fmt_rate(p.tx_bps);
    r.bytes = "↓ " + fmt_bytes(p.bytes_rx) + "  ↑ " + fmt_bytes(p.bytes_tx);
    return r;
}

bool latest_error(const StatusSnapshot& s, LastError& out) {
    bool found = false;
    for (const auto& t : s.targets) {
        if (t.last_error.empty() || t.last_error_unix_ms <= 0) continue;
        if (!found || t.last_error_unix_ms > out.unix_ms) {
            out.unix_ms = t.last_error_unix_ms;
            out.message = t.last_error;
            out.where = t.watch + " → " + target_display(t.target);
            found = true;
        }
    }
    return found;
}

// ---------------------------------------------------------------- BannerModel
bool BannerModel::add(BannerLevel lv, const std::string& source, const std::string& msg) {
    for (auto& it : items_) {
        if (it.level == lv && it.message == msg && it.source == source) {
            // Nguồn có tên (như "poll") lặp lại mỗi giây: không đếm, chỉ giữ nguyên một dòng.
            if (source.empty()) {
                ++it.count;
                return true;
            }
            return false;
        }
    }
    // Cùng nguồn + cùng mức mà nội dung khác: thay thế (nguồn như "poll" chỉ có một lỗi hiện hành).
    if (!source.empty()) {
        for (auto& it : items_) {
            if (it.source == source && it.level == lv) {
                it.message = msg;
                it.count = 1;
                return true;
            }
        }
    }
    items_.push_back({lv, source, msg, 1});
    while (items_.size() > kMaxBanner) items_.erase(items_.begin());
    return true;
}

bool BannerModel::clear_source(const std::string& source) {
    auto n = items_.size();
    items_.erase(std::remove_if(items_.begin(), items_.end(), [&](const BannerItem& i) { return i.source == source; }),
                 items_.end());
    return items_.size() != n;
}

void BannerModel::clear() { items_.clear(); }

bool BannerModel::has_error() const {
    for (const auto& i : items_)
        if (i.level == BannerLevel::Error) return true;
    return false;
}

std::string BannerModel::render(const BannerItem& i) const {
    return i.count > 1 ? i.message + " (×" + std::to_string(i.count) + ")" : i.message;
}

}  // namespace mysync::gui

namespace mysync::gui {
bool BannerModel::remove(const std::string& source, const std::string& msg) {
    auto n = items_.size();
    items_.erase(std::remove_if(items_.begin(), items_.end(),
                                [&](const BannerItem& i) { return i.source == source && i.message == msg; }),
                 items_.end());
    return items_.size() != n;
}
}  // namespace mysync::gui
