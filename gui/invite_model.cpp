// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "invite_model.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <set>

#include "form_model.h"
#include "i18n_model.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/gui/trust.h"
#include "mysync/quick_setup.h"
#include "simple_model.h"

namespace mysync::gui {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------------------------- chữ dùng chung
std::string invite_perm_text(simple::InvitePerm p) {
    return tr(p == simple::InvitePerm::ReadOnly ? "inv.perm.ro" : "inv.perm.rw");
}
std::string invite_perm_choice_text(simple::InvitePerm p) {
    return tr(p == simple::InvitePerm::ReadOnly ? "inv.perm.ro.choice" : "inv.perm.rw.choice");
}

std::string time_left_text(int64_t s) {
    if (s <= 0) return tr("inv.left.expired");
    if (s < 60) return tr("inv.left.lt1min");
    if (s < 3600) return trf("inv.left.min", {std::to_string(s / 60)});
    if (s < 2 * 86400) return trf("inv.left.hour", {std::to_string(s / 3600)});
    return trf("inv.left.day", {std::to_string(s / 86400)});
}

std::string uses_text(uint32_t uses) { return trf("inv.uses.n", {std::to_string(uses)}); }

std::string fmt_weekday_time(const std::tm& t) {
    char b[48];
    std::snprintf(b, sizeof b, " %02d/%02d/%04d %02d:%02d", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min);
    int wd = ((t.tm_wday % 7) + 7) % 7;
    return tr(("wd." + std::to_string(wd)).c_str()) + b;
}

namespace {
bool local_tm(int64_t unix_s, std::tm* out) {
    std::time_t tt = static_cast<std::time_t>(unix_s);
#ifdef _WIN32
    return localtime_s(out, &tt) == 0;
#else
    return localtime_r(&tt, out) != nullptr;
#endif
}
}  // namespace

std::string fmt_local_time(int64_t unix_s) {
    std::tm t{};
    if (!local_tm(unix_s, &t)) return std::to_string(unix_s);
    return fmt_weekday_time(t);
}

std::string fmt_utc_stamp(const std::string& when_utc) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0;
    char tail = 0;
    if (std::sscanf(when_utc.c_str(), "%4d-%2d-%2d %2d:%2d%c", &y, &mo, &d, &h, &mi, &tail) != 5) return when_utc;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || y < 1970) return when_utc;
    std::tm u{};
    u.tm_year = y - 1900;
    u.tm_mon = mo - 1;
    u.tm_mday = d;
    u.tm_hour = h;
    u.tm_min = mi;
#ifdef _WIN32
    std::time_t tt = _mkgmtime(&u);
#else
    std::time_t tt = timegm(&u);
#endif
    if (tt == static_cast<std::time_t>(-1)) return when_utc;
    return fmt_local_time(static_cast<int64_t>(tt));
}

// ---------------------------------------------------------------------------------------------- phía GỬI
std::string invite_outcome_text(const simple::InviteOutcome& o) {
    using K = simple::InviteOutcome;
    switch (o.kind) {
        case K::Ok: return tr("inv.out.ok");
        case K::BadCode: return tr("inv.out.badcode");
        case K::Expired: return tr("inv.out.expired");
        case K::Unreachable: return tr("inv.out.unreachable");
        case K::Refused: return tr("inv.out.refused");
        case K::Busy: return tr("inv.out.busy");
        case K::Cancelled: return tr("inv.out.cancelled");
        case K::Failed: break;
    }
    return o.message.empty() ? tr("inv.out.failed_nomsg") : trf("inv.out.failed", {o.message});
}

simple::PairCode pair_code_from_grant(const simple::InviteGrant& g) {
    simple::PairCode c;
    c.server_key = g.server_key;
    c.host = g.address.host;
    c.port = g.address.port;
    return c;
}

bool SenderInviteModel::set_text(const std::string& text, int64_t now_unix) {
    std::string t = trim(text);
    if (t == text_ && stage_ != CodeStage::Empty) return false;
    if (t.empty() && stage_ == CodeStage::Empty) return false;
    text_ = t;
    ++gen_;
    code_ = simple::InviteCode{};
    grant_ = simple::InviteGrant{};
    error_.clear();
    if (t.empty()) {
        stage_ = CodeStage::Empty;
        return false;
    }
    if (!simple::looks_like_invite_code(t)) {
        stage_ = CodeStage::Invalid;
        error_ = tr("inv.code.notcode");
        return false;
    }
    try {
        code_ = simple::decode_invite_code(t);
    } catch (const std::exception&) {
        stage_ = CodeStage::Invalid;
        error_ = tr("inv.out.badcode");   // không lặp lại nội dung đã dán
        return false;
    }
    if (code_.perm == simple::InvitePerm::ReadOnly) {   // this program sends files: a view-only code is useless, say so at once
        stage_ = CodeStage::Failed;
        error_ = tr("inv.code.readonly");
        return false;
    }
    if (code_.expires_unix <= now_unix) {
        stage_ = CodeStage::Failed;
        error_ = tr("inv.out.expired");
        return false;
    }
    stage_ = CodeStage::Checking;
    return true;
}

bool SenderInviteModel::apply_probe(uint64_t gen, const simple::InviteOutcome& o) {
    if (gen != gen_ || stage_ != CodeStage::Checking) return false;
    if (o.kind == simple::InviteOutcome::Ok && o.grant.perm == simple::InvitePerm::ReadOnly) {
        stage_ = CodeStage::Failed;   // the receiver says view-only whatever the code claimed
        error_ = tr("inv.code.readonly");
    } else if (o.kind == simple::InviteOutcome::Ok) {
        stage_ = CodeStage::Ready;
        grant_ = o.grant;
        error_.clear();
    } else {
        stage_ = CodeStage::Failed;
        error_ = invite_outcome_text(o);
    }
    return true;
}

void SenderInviteModel::reset() { *this = SenderInviteModel{}; }

InviteSummary SenderInviteModel::summary(int64_t now_unix) const {
    InviteSummary s;
    if (stage_ != CodeStage::Ready && stage_ != CodeStage::Checking) return s;
    bool known = stage_ == CodeStage::Ready;
    s.machine = known && !grant_.machine.empty() ? grant_.machine : code_.machine;
    if (s.machine.empty()) s.machine = tr("inv.noname");
    s.folder = known && !grant_.label.empty() ? grant_.label : code_.label;
    if (s.folder.empty()) s.folder = tr("inv.noname");
    simple::InvitePerm perm = known ? grant_.perm : code_.perm;
    s.perm = invite_perm_text(perm);
    int64_t exp = known && grant_.expires_unix > 0 ? grant_.expires_unix : code_.expires_unix;
    s.left = time_left_text(exp - now_unix);
    if (known && grant_.uses_left > 0) s.uses = uses_text(grant_.uses_left);
    s.fingerprint = simple::invite_fingerprint(code_.server_key);
    s.sentence = trf("inv.sum.sentence", {s.machine, s.perm, s.folder}) + ".";
    s.line = trf("inv.sum.sentence", {s.machine, s.perm, s.folder}) + " (" + s.left + (s.uses.empty() ? "" : ", " + s.uses) + ").";
    s.dest_label = trf("inv.dest.label", {s.machine, s.folder, s.perm});
    return s;
}

std::string join_busy_text(bool waiting, int seconds_left) {
    if (!waiting) return tr("inv.join.busy");
    return trf("inv.join.waiting", {fmt_countdown(seconds_left)});
}

// ---------------------------------------------------------------------------------------------- phía NHẬN
std::vector<TtlChoice> invite_ttl_choices() {
    return {{3600, tr("inv.ttl.1h")}, {24 * 3600, tr("inv.ttl.24h")}, {7 * 24 * 3600, tr("inv.ttl.7d")}};
}

std::vector<UsesChoice> invite_uses_choices() {
    std::vector<UsesChoice> v;
    for (int n : {1, 2, 5, 10}) v.push_back({n, trf("inv.uses.choice", {std::to_string(n)})});
    return v;
}

FolderCheck check_receiver_folder(const std::string& text) {
    FolderCheck r;
    std::string t = trim(text);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') t = trim(t.substr(1, t.size() - 2));
    if (t.empty()) {
        r.error = tr("inv.folder.empty");
        return r;
    }
    for (char c : t)
        if (static_cast<unsigned char>(c) < 0x20) {
            r.error = tr("inv.folder.bad");
            return r;
        }
    std::error_code ec;
    fs::path p = fs::u8path(t);
    if (!p.is_absolute()) {
        r.error = tr("inv.folder.relative");
        return r;
    }
    if (fs::exists(p, ec) && !fs::is_directory(p, ec)) {
        r.error = tr("inv.folder.file");
        return r;
    }
    r.ok = true;
    r.normalized = t;
    return r;
}

void prepare_receiver_folder(const std::string& dir, bool fix_permissions) {
    std::error_code ec;
    fs::path p = fs::u8path(dir);
    bool existed = fs::exists(p, ec);
    if (existed && !fs::is_directory(p, ec)) throw Error(tr("inv.folder.file"));
    if (!existed) {
        fs::create_directories(p, ec);
        if (ec) throw Error(dir + ": " + ec.message());
        make_folder_private(dir);   // folder vừa tạo: riêng tư ngay
    } else if (fix_permissions) {
        make_folder_private(dir);
    }
    if (!need_strict_trust(ServiceController::is_elevated(), false)) return;
    try {
        require_trusted_dir(dir, "folder", {});
    } catch (const Error& e) {
        throw UntrustedFolderError(dir, e.what());
    }
}

std::vector<simple::InviteAddr> choose_invite_addrs(const std::vector<std::string>& ips, uint16_t port) {
    std::vector<simple::InviteAddr> out;
    if (port == 0) return out;
    for (const std::string& ip : rank_addresses(ips)) {
        if (!simple::valid_pair_host(ip)) continue;
        out.push_back({ip, port});
        if (out.size() >= simple::kInviteMaxAddrs) break;
    }
    return out;
}

ReceiverButtons receiver_buttons(ReceiverStage stage, bool folder_ok, bool busy) {
    ReceiverButtons b;
    switch (stage) {
        case ReceiverStage::Form:
            b.form = !busy;
            b.browse = !busy;
            b.create = !busy && folder_ok;
            break;
        case ReceiverStage::Working:
            break;
        case ReceiverStage::Showing:
            b.copy = true;
            b.another = !busy;
            break;
    }
    return b;
}

std::vector<JoinedRow> joined_rows(const InviteListInfo& info) {
    std::vector<JoinedRow> rows;
    for (const JoinedMachineView& j : info.joined) {
        JoinedRow r;
        r.key_hex = j.key_hex;
        r.title = j.name.empty() ? tr("inv.noname") : j.name;
        r.detail = trf("inv.joined.detail", {invite_perm_text(j.perm), fmt_utc_stamp(j.when_utc)});
        rows.push_back(std::move(r));
    }
    return rows;
}

std::vector<LiveRow> live_rows(const InviteListInfo& info, int64_t now) {
    std::vector<LiveRow> rows;
    for (const InviteView& v : info.invites) {
        if (v.state != "live") continue;
        LiveRow r;
        r.id_hex = v.id_hex;
        r.title = v.label.empty() ? tr("inv.noname") : v.label;
        r.detail = trf("inv.live.detail", {invite_perm_text(v.perm), time_left_text(v.expires_unix - now), uses_text(v.uses_left)});
        rows.push_back(std::move(r));
    }
    return rows;
}

std::string invite_code_id_hex(const std::string& code) {
    try {
        return simple::invite_id_hex(simple::decode_invite_code(trim(code)).id);
    } catch (const std::exception&) {
        return "";
    }
}

CodeProgress code_progress(const InviteListInfo& info, const std::string& id, int64_t now) {
    CodeProgress p;
    const JoinedMachineView* last = nullptr;
    for (const JoinedMachineView& j : info.joined)
        if (j.invite_id_hex == id) last = &j;
    if (last) {
        p.kind = CodeProgress::Joined;
        p.text = trf("inv.joined.now", {last->name.empty() ? tr("inv.noname") : last->name});
        return p;
    }
    for (const InviteView& v : info.invites)
        if (v.id_hex == id && v.state == "live" && v.expires_unix > now) {
            p.kind = CodeProgress::Waiting;
            p.text = tr("inv.wait");
            return p;
        }
    p.kind = CodeProgress::Gone;
    p.text = tr("inv.gone");
    return p;
}

std::string demo_invite_code(const std::string& machine, const std::string& label, const std::string& host, uint16_t port,
                             simple::InvitePerm perm, int ttl_seconds) {
    simple::InviteCode c;
    c.server_key = generate_keypair().pub;
    random_bytes(c.id.data(), c.id.size());
    random_bytes(c.secret.data(), c.secret.size());
    c.expires_unix = static_cast<int64_t>(std::time(nullptr)) + ttl_seconds;
    c.perm = perm;
    c.addrs.push_back({host, port});
    c.machine = machine;
    c.label = label;
    return simple::encode_invite_code(c);
}

const simple::PendingInvite* first_pending(const InviteListInfo& info, const std::vector<uint32_t>& dismissed) {
    for (const simple::PendingInvite& q : info.pending)
        if (std::find(dismissed.begin(), dismissed.end(), q.id) == dismissed.end()) return &q;
    return nullptr;
}

}  // namespace mysync::gui
