// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "simple_model.h"

#include <algorithm>
#include <cctype>
#include <set>

#include "form_model.h"
#include "i18n_model.h"

namespace mysync::gui {

// ---------------------------------------------------------------------------------------------- Trạng thái
SimpleStatus compute_simple_status(const SimpleInputs& in) {
    SimpleStatus r;
    if (!in.has_config) {
        r.kind = SimpleKind::NoFolder;
        r.headline = tr("simple.st.nofolder");
        r.detail = tr("simple.st.nofolder.d");
        r.tray = TrayState::Offline;
        return r;
    }
    if (in.engine_managed) {
        switch (in.engine_state) {
            case simple::EngineState::GaveUp:
                r.kind = SimpleKind::GaveUp;
                r.headline = tr("simple.st.gaveup");
                r.detail = in.engine_error.empty() ? tr("simple.st.gaveup.d") : in.engine_error;
                r.tray = TrayState::Error;
                r.error_banner = true;
                return r;
            case simple::EngineState::Backoff:
                r.kind = SimpleKind::Restarting;
                r.headline = trf("simple.st.restarting", {std::to_string(std::max(1, in.restarts))});
                r.detail = in.engine_error;
                r.tray = TrayState::Warning;
                r.warn_banner = true;
                return r;
            case simple::EngineState::Stopped:
                r.kind = SimpleKind::Stopped;
                r.headline = tr("simple.st.stopped");
                r.tray = TrayState::Offline;
                return r;
            case simple::EngineState::Starting:
                r.kind = SimpleKind::Starting;
                r.headline = tr("simple.st.starting");
                r.tray = TrayState::Offline;
                return r;
            case simple::EngineState::Running:
                break;
        }
    }
    if (!in.connected) {
        r.kind = SimpleKind::Starting;
        r.headline = tr(in.engine_managed ? "simple.st.starting" : "simple.st.svc_silent");
        r.tray = TrayState::Offline;
        return r;
    }
    const StatusSnapshot& s = in.snap;
    r.sent = s.total_sent;
    for (const auto& t : s.targets) r.pending += t.queued + t.active_files.size();
    r.tray = compute_tray_state(true, s, in.now_ms);

    LastError le;
    bool has_err = latest_error(s, le);
    switch (r.tray) {
        case TrayState::Error: {
            r.kind = SimpleKind::Error;
            r.headline = trf("simple.st.error", {has_err ? le.message : tr("simple.st.error.unknown")});
            if (has_err && !le.where.empty()) r.detail = le.where;
            r.error_banner = false;  // câu lớn đã là lỗi nguyên văn
            return r;
        }
        case TrayState::Warning: {
            r.kind = SimpleKind::Warning;
            const TargetStatus* disc = nullptr;
            for (const auto& t : s.targets)
                if (t.state == TargetState::Disconnected) { disc = &t; break; }
            if (!s.config_error.empty()) {
                r.headline = trf("simple.st.cfgerr", {s.config_error});
            } else if (disc) {
                r.headline = trf("simple.st.disconnected", {target_display(disc->target)});
                if (!disc->last_error.empty()) r.detail = disc->last_error;
            } else if (has_err) {
                r.headline = trf("simple.st.warn", {le.message});
                if (!le.where.empty()) r.detail = le.where;
            } else {
                r.headline = tr("simple.st.warn.unknown");
            }
            return r;
        }
        case TrayState::Syncing: {
            r.kind = SimpleKind::Syncing;
            r.headline = trf("simple.st.syncing", {std::to_string(r.pending)});
            for (const auto& t : s.targets)
                if (!t.active_files.empty()) {
                    r.detail = trf("simple.st.sending", {t.active_files.front()});
                    break;
                }
            return r;
        }
        default:
            break;
    }
    r.kind = SimpleKind::UpToDate;
    r.tray = TrayState::Idle;
    r.headline = tr("simple.st.uptodate");
    r.detail = s.total_sent ? trf("simple.st.uptodate.n", {std::to_string(s.total_sent)}) : tr("simple.st.uptodate.watching");
    return r;
}

bool SyncProgress::update(bool syncing, uint64_t total_sent, uint64_t pending) {
    double old_f = frac_;
    uint64_t old_d = done_, old_t = total_;
    if (!syncing) {
        reset();
    } else {
        if (!active_) {
            active_ = true;
            base_ = total_sent;
            total_ = 0;
        }
        if (total_sent < base_) base_ = total_sent;  // bộ đếm đặt lại (engine khởi động lại)
        done_ = total_sent - base_;
        total_ = std::max<uint64_t>(total_, done_ + pending);
        frac_ = total_ ? static_cast<double>(done_) / static_cast<double>(total_) : 0.0;
        if (frac_ > 1.0) frac_ = 1.0;
    }
    return old_f != frac_ || old_d != done_ || old_t != total_;
}

void SyncProgress::reset() {
    active_ = false;
    base_ = done_ = total_ = 0;
    frac_ = -1;
}

std::string SyncProgress::text() const {
    if (frac_ < 0) return "";
    return trf("simple.st.progress", {std::to_string(done_), std::to_string(total_)});
}

// ---------------------------------------------------------------------------------------------- Trình hướng dẫn
std::string wizard_issue_text(const simple::WizardIssue& i) {
    std::string t = tr(i.key.c_str());
    if (!i.detail.empty()) t += "\n" + i.detail;
    return t;
}

WizardStep wizard_issue_step(const simple::WizardIssue& i) {
    static const std::set<std::string> src = {"wizard.source_empty", "wizard.source_missing", "wizard.source_not_dir",
                                              "wizard.source_is_root", "wizard.source_internal", "wizard.bad_name"};
    return src.count(i.key) ? WizardStep::Source : WizardStep::Dest;
}

void WizardModel::set_source(const std::string& path) {
    if (in_.source == path) return;
    in_.source = path;
    in_.watch_name.clear();
    invalidate();
}
void WizardModel::set_kind(simple::DestKind k) {
    if (in_.kind == k) return;
    in_.kind = k;
    invalidate();
}
void WizardModel::set_dest_path(const std::string& path) {
    if (in_.dest_path == path) return;
    in_.dest_path = path;
    invalidate();
}
void WizardModel::set_paired(const simple::PairCode& c) {
    in_.paired = c;
    paired_ok_ = true;
    invalidate();
}
void WizardModel::clear_paired() {
    if (!paired_ok_) return;
    in_.paired = simple::PairCode{};
    paired_ok_ = false;
    invalidate();
}
void WizardModel::apply_validation(const std::vector<simple::WizardIssue>& issues) {
    issues_ = issues;
    validated_ = true;
}

std::vector<std::string> WizardModel::issues_for(WizardStep s) const {
    std::vector<std::string> out;
    for (const auto& i : issues_) {
        // Bước 2 dùng "kiểu máy khác": các khoá về thư mục đích không áp dụng; chỉ giữ pair_missing và các xung đột nguồn.
        if (wizard_issue_step(i) != s) continue;
        out.push_back(wizard_issue_text(i));
    }
    if (s == WizardStep::Dest && in_.kind == simple::DestKind::PairedMachine && !paired_ok_)
        out.push_back(tr("wizard.pair_wait"));
    return out;
}

bool WizardModel::step_ok(WizardStep s) const {
    if (!validated_) return false;
    for (const auto& i : issues_)
        if (wizard_issue_step(i) == s) return false;
    if (s == WizardStep::Source) return !trim(in_.source).empty();
    if (s == WizardStep::Dest && in_.kind == simple::DestKind::PairedMachine) return paired_ok_;
    if (s == WizardStep::Dest) return !trim(in_.dest_path).empty();
    return true;
}

bool WizardModel::can_next() const {
    switch (step_) {
        case WizardStep::Source: return step_ok(WizardStep::Source);
        case WizardStep::Dest: return step_ok(WizardStep::Source) && step_ok(WizardStep::Dest);
        case WizardStep::Finish: return false;
    }
    return false;
}

bool WizardModel::next() {
    if (!can_next()) return false;
    step_ = step_ == WizardStep::Source ? WizardStep::Dest : WizardStep::Finish;
    return true;
}
bool WizardModel::back() {
    if (step_ == WizardStep::Source) return false;
    step_ = step_ == WizardStep::Finish ? WizardStep::Dest : WizardStep::Source;
    return true;
}
void WizardModel::reset() { *this = WizardModel{}; }

std::string WizardModel::summary() const {
    std::string dest = in_.kind == simple::DestKind::PairedMachine
                           ? trf("wizard.sum.machine", {in_.paired.host})
                           : trf("wizard.sum.folder", {in_.dest_path});
    return trf("wizard.summary", {in_.source, dest});
}

std::string folder_label(const std::string& path) {
    std::string p = path;
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\')) {
        if (p.size() == 3 && p[1] == ':') return p;  // "C:\"
        p.pop_back();
    }
    size_t k = p.find_last_of("/\\");
    if (k == std::string::npos || k + 1 >= p.size()) return p;
    return p.substr(k + 1);
}

bool looks_like_unc(const std::string& p) {
    return p.size() > 2 && ((p[0] == '\\' && p[1] == '\\') || (p[0] == '/' && p[1] == '/'));
}

// ---------------------------------------------------------------------------------------------- Ghép máy
std::string fmt_countdown(int s) {
    if (s < 0) s = 0;
    char b[24];
    snprintf(b, sizeof b, "%d:%02d", s / 60, s % 60);
    return b;
}

std::string sas_display(const std::string& sas) {
    std::string out;
    for (char c : sas) {
        if (c == '-') out += "   ";
        else if (c != ' ') out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return out;
}

bool is_private_ipv4(const std::string& ip) {
    int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return false;
    return a == 10 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31);
}

std::vector<std::string> rank_addresses(const std::vector<std::string>& ips) {
    std::vector<std::string> priv, pub, v6;
    std::set<std::string> seen;
    for (const auto& ip : ips) {
        std::string x = trim(ip);
        if (x.empty() || !seen.insert(x).second) continue;
        if (x.find(':') != std::string::npos) {
            std::string l = x;
            std::transform(l.begin(), l.end(), l.begin(), [](unsigned char c) { return std::tolower(c); });
            if (l == "::1" || l.rfind("fe80", 0) == 0 || l == "::") continue;
            v6.push_back(x);
            continue;
        }
        if (x.rfind("127.", 0) == 0 || x.rfind("169.254.", 0) == 0 || x == "0.0.0.0") continue;
        (is_private_ipv4(x) ? priv : pub).push_back(x);
    }
    std::vector<std::string> out = priv;
    out.insert(out.end(), pub.begin(), pub.end());
    out.insert(out.end(), v6.begin(), v6.end());
    return out;
}

std::string pair_outcome_text(const simple::PairOutcome& o) {
    switch (o.kind) {
        case simple::PairOutcome::Approved: return tr("pair.out.approved");
        case simple::PairOutcome::Denied: return tr("pair.out.denied");
        case simple::PairOutcome::Busy: return tr("pair.out.busy");
        case simple::PairOutcome::Expired: return tr("pair.out.expired");
        case simple::PairOutcome::Cancelled: return tr("pair.out.cancelled");
        case simple::PairOutcome::Failed: break;
    }
    return o.message.empty() ? tr("pair.out.failed") : trf("pair.out.failed_msg", {o.message});
}

std::string check_pair_code_text(const std::string& text, simple::PairCode* out) {
    std::string t = trim(text);
    if (t.empty()) return tr("pair.code.empty");
    if (!simple::looks_like_pair_code(t)) return tr("pair.code.notcode");
    try {
        simple::PairCode c = simple::decode_pair_code(t);
        if (out) *out = c;
        return "";
    } catch (const std::exception&) {
        return tr("pair.code.broken");  // không lặp lại nội dung đã dán
    }
}

std::string friendly_error(const std::string& what) {
    size_t colon = what.find(':');
    std::string key = colon == std::string::npos ? what : what.substr(0, colon);
    bool known = key.rfind("wizard.", 0) == 0 || key.rfind("receiver.", 0) == 0;
    for (char c : key)
        if (!(std::islower(static_cast<unsigned char>(c)) || c == '_' || c == '.')) known = false;
    if (!known || !i18n_has(key.c_str())) return what;
    std::string detail = colon == std::string::npos ? "" : trim(what.substr(colon + 1));
    return tr(key.c_str()) + (detail.empty() ? "" : "\n" + detail);
}

std::string service_confirm_text(const simple::MigrationSummary& s) {
    auto list = [](const std::vector<std::string>& v) {
        std::string o;
        for (const auto& x : v) o += "\n  - " + x;
        return o;
    };
    std::string t = tr("simple.svc.confirm.to") + "\n\n" + tr("simple.svc.sum.sources") + list(s.sources) + "\n\n" +
                    tr("simple.svc.sum.dests") + list(s.destinations) + "\n\n" +
                    trf("simple.svc.sum.key", {s.key_identity.empty() ? "?" : s.key_identity}) + "\n" +
                    trf("simple.svc.sum.account", {s.service_account.empty() ? "?" : s.service_account});
    for (const auto& w : s.warnings) t += "\n! " + w;
    t += "\n\n" + tr("simple.svc.sum.warn");
    return t;
}

std::string firewall_hint(uint16_t port) {
    return trf("pair.firewall", {std::to_string(port)});
}

}  // namespace mysync::gui
