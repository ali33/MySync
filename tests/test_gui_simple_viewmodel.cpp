// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Headless tests of the Simple-mode view-model (gui/simple_model.*): status sentence, progress, wizard steps,
// pairing texts. Deliberately does NOT include any wx header.
#include <algorithm>
#include <cctype>

#include "i18n_model.h"
#include "simple_model.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;

namespace {
struct LangGuard {
    explicit LangGuard(Lang l) { set_lang(l); }
    ~LangGuard() { set_lang(Lang::Vi); }
};

SimpleInputs running(bool connected = true) {
    SimpleInputs in;
    in.has_config = true;
    in.engine_state = simple::EngineState::Running;
    in.connected = connected;
    in.now_ms = 1'000'000'000;
    return in;
}
TargetStatus tgt(TargetState s, uint64_t queued = 0) {
    TargetStatus t;
    t.watch = "Tài liệu";
    t.target = "dir://E:/Sao-luu";
    t.state = s;
    t.queued = queued;
    return t;
}
simple::WizardIssue issue(const char* k, const char* d = "") { return {k, d}; }
bool has(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }
}  // namespace

// ---- status sentence
TEST(simple_status_no_folder_and_engine_states) {
    LangGuard g(Lang::Vi);
    SimpleInputs in;
    auto s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::NoFolder);
    CHECK(s.tray == TrayState::Offline);

    in = running(false);
    in.engine_state = simple::EngineState::Starting;
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Starting);

    in.engine_state = simple::EngineState::Backoff;
    in.restarts = 2;
    in.engine_error = "boom";
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Restarting);
    CHECK(has(s.headline, "lần 2"));
    CHECK(s.warn_banner);
    CHECK(!s.error_banner);
    CHECK(s.tray == TrayState::Warning);
    CHECK_EQ(s.detail, std::string("boom"));  // nguyên văn

    in.engine_state = simple::EngineState::GaveUp;
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::GaveUp);
    CHECK(s.error_banner);
    CHECK(s.tray == TrayState::Error);
    CHECK_EQ(s.detail, std::string("boom"));
    in.engine_error.clear();
    CHECK(!compute_simple_status(in).detail.empty());  // vẫn có lời khuyên

    in.engine_state = simple::EngineState::Stopped;
    CHECK(compute_simple_status(in).kind == SimpleKind::Stopped);
}

TEST(simple_status_connected_variants) {
    LangGuard g(Lang::Vi);
    // rảnh
    auto in = running();
    in.snap.targets.push_back(tgt(TargetState::Idle));
    auto s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::UpToDate);
    CHECK_EQ(s.headline, std::string("Mọi thứ đã được đồng bộ"));
    CHECK(s.tray == TrayState::Idle);
    in.snap.total_sent = 7;
    CHECK(has(compute_simple_status(in).detail, "7"));

    // đang đồng bộ: đếm chờ + đang gửi, kèm tên tệp đầu tiên
    in = running();
    auto t = tgt(TargetState::Syncing, 2);
    t.active_files = {"a/b.docx", "c.txt"};
    in.snap.targets.push_back(t);
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Syncing);
    CHECK_EQ(s.pending, uint64_t(4));
    CHECK(has(s.headline, "4 tệp"));
    CHECK(has(s.detail, "a/b.docx"));
    CHECK(s.tray == TrayState::Syncing);

    // lỗi: lời nguyên văn
    in = running();
    t = tgt(TargetState::Error);
    t.last_error = "access denied: E:/Sao-luu/x.doc";
    t.last_error_unix_ms = in.now_ms - 1000;
    in.snap.targets.push_back(t);
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Error);
    CHECK(has(s.headline, "Có lỗi: access denied: E:/Sao-luu/x.doc"));
    CHECK(s.tray == TrayState::Error);

    // mất kết nối tới nơi lưu: cảnh báo, nói tên nơi lưu dễ đọc
    in = running();
    in.snap.targets.push_back(tgt(TargetState::Disconnected));
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Warning);
    CHECK(has(s.headline, "E:/Sao-luu"));
    CHECK(!has(s.headline, "dir://"));

    // cấu hình mới bị từ chối
    in = running();
    in.snap.targets.push_back(tgt(TargetState::Idle));
    in.snap.config_error = "line 3: bad";
    s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Warning);
    CHECK(has(s.headline, "line 3: bad"));
}

TEST(simple_status_service_mode_waits_for_the_service) {
    LangGuard g(Lang::Vi);
    auto in = running(false);
    in.engine_managed = false;
    in.engine_state = simple::EngineState::GaveUp;  // bị bỏ qua khi dịch vụ lo
    auto s = compute_simple_status(in);
    CHECK(s.kind == SimpleKind::Starting);
    CHECK(has(s.headline, "Dịch vụ"));
    in.connected = true;
    in.snap.targets.push_back(tgt(TargetState::Idle));
    CHECK(compute_simple_status(in).kind == SimpleKind::UpToDate);
}

TEST(simple_status_english) {
    LangGuard g(Lang::En);
    auto in = running();
    in.snap.targets.push_back(tgt(TargetState::Idle));
    CHECK_EQ(compute_simple_status(in).headline, std::string("Everything is up to date"));
}

// ---- progress
TEST(simple_progress_burst) {
    LangGuard g(Lang::Vi);
    SyncProgress p;
    CHECK(p.fraction() < 0);
    p.update(true, 100, 10);  // mốc: đã gửi 100 trước đợt này
    CHECK_EQ(p.total(), uint64_t(10));
    CHECK_EQ(p.done(), uint64_t(0));
    CHECK(p.fraction() == 0.0);
    p.update(true, 105, 5);
    CHECK_EQ(p.done(), uint64_t(5));
    CHECK_EQ(p.total(), uint64_t(10));
    CHECK(p.fraction() == 0.5);
    p.update(true, 110, 0);
    CHECK(p.fraction() == 1.0);
    CHECK_EQ(p.text(), std::string("Đã xong 10 / 10 tệp"));
    // thêm tệp giữa chừng: tổng tăng, không lùi về âm
    p.update(true, 110, 3);
    CHECK_EQ(p.total(), uint64_t(13));
    p.update(false, 113, 0);
    CHECK(p.fraction() < 0);
    CHECK_EQ(p.text(), std::string(""));
    // bộ đếm đặt lại (engine khởi động lại) không tràn số
    p.update(true, 50, 4);
    p.update(true, 2, 4);
    CHECK(p.fraction() >= 0 && p.fraction() <= 1.0);
}

// ---- wizard
TEST(simple_wizard_steps_and_gating) {
    LangGuard g(Lang::Vi);
    WizardModel m;
    CHECK(m.step() == WizardStep::Source);
    CHECK(!m.can_next());  // chưa kiểm
    CHECK(!m.next());

    m.set_source("D:/Tài liệu");
    CHECK(!m.can_next());  // đổi nguồn: phải kiểm lại
    m.apply_validation({issue("wizard.dest_empty")});  // lỗi của bước 2 không chặn bước 1
    CHECK(m.can_next());
    CHECK(m.issues_for(WizardStep::Source).empty());
    CHECK(m.next());
    CHECK(m.step() == WizardStep::Dest);
    CHECK(!m.can_next());  // chưa nhập nơi lưu
    CHECK(m.back());
    CHECK(m.step() == WizardStep::Source);
    CHECK(!m.back());

    m.apply_validation({issue("wizard.source_missing", "D:/Tài liệu")});
    CHECK(!m.can_next());
    auto txt = m.issues_for(WizardStep::Source);
    CHECK_EQ(txt.size(), size_t(1));
    CHECK(has(txt[0], "Không tìm thấy thư mục này"));
    CHECK(has(txt[0], "D:/Tài liệu"));  // chi tiết nguyên văn kèm theo

    m.apply_validation({});
    CHECK(m.next());
    m.set_dest_path("E:/Sao-luu");
    CHECK(!m.can_next());
    m.apply_validation({issue("wizard.dest_not_writable", "denied")});
    CHECK(!m.can_next());
    CHECK(has(m.issues_for(WizardStep::Dest)[0], "Không ghi được"));
    m.apply_validation({});
    CHECK(m.can_next());
    CHECK(m.next());
    CHECK(m.step() == WizardStep::Finish);
    CHECK(!m.can_next());
    CHECK(has(m.summary(), "D:/Tài liệu"));
    CHECK(has(m.summary(), "E:/Sao-luu"));
    CHECK(!has(m.summary(), "{0}"));
}

TEST(simple_wizard_paired_machine_needs_approval) {
    LangGuard g(Lang::Vi);
    WizardModel m;
    m.set_source("D:/A");
    m.apply_validation({});
    CHECK(m.next());
    m.set_kind(simple::DestKind::PairedMachine);
    m.apply_validation({issue("wizard.pair_missing")});
    CHECK(!m.can_next());
    CHECK(m.issues_for(WizardStep::Dest).size() >= 1);
    simple::PairCode c;
    c.host = "192.168.1.20";
    c.port = 5656;
    m.set_paired(c);
    CHECK(!m.can_next());  // đổi đầu vào: kiểm lại
    m.apply_validation({});
    CHECK(m.can_next());
    // tạo tay: kind máy khác nhưng chưa ghép dù không có issue -> vẫn chặn
    WizardModel m2;
    m2.set_source("D:/A");
    m2.apply_validation({});
    m2.next();
    m2.set_kind(simple::DestKind::PairedMachine);
    m2.apply_validation({});
    CHECK(!m2.can_next());
    // sửa mã sau khi ghép: bỏ kết quả ghép
    m.clear_paired();
    m.apply_validation({});
    CHECK(!m.can_next());
    CHECK(has(m.summary(), "192") == false);
}

TEST(simple_wizard_issue_keys_all_translated) {
    // Mọi khoá lỗi của wizard_model có bản dịch (vi + en), và thuộc đúng một bước.
    const char* keys[] = {"wizard.source_empty", "wizard.source_missing", "wizard.source_not_dir", "wizard.dest_empty",
                          "wizard.dest_missing", "wizard.dest_not_writable", "wizard.dest_inside_source",
                          "wizard.source_inside_dest", "wizard.same_folder", "wizard.source_is_root",
                          "wizard.source_internal", "wizard.pair_missing", "wizard.bad_name"};
    for (const char* k : keys) {
        CHECK(i18n_has(k));
        LangGuard g(Lang::En);
        CHECK(tr(k).find("?wizard") == std::string::npos);
    }
    CHECK(wizard_issue_step(issue("wizard.source_missing")) == WizardStep::Source);
    CHECK(wizard_issue_step(issue("wizard.dest_not_writable")) == WizardStep::Dest);
    CHECK(wizard_issue_step(issue("wizard.same_folder")) == WizardStep::Dest);
}

TEST(simple_folder_label_and_unc) {
    CHECK_EQ(folder_label("D:\\Tài liệu\\Báo cáo"), std::string("Báo cáo"));
    CHECK_EQ(folder_label("D:\\Tài liệu\\Báo cáo\\"), std::string("Báo cáo"));
    CHECK_EQ(folder_label("/home/a/b/"), std::string("b"));
    CHECK_EQ(folder_label("C:\\"), std::string("C:\\"));
    CHECK(looks_like_unc("\\\\may\\chia-se"));
    CHECK(looks_like_unc("//may/chia-se"));
    CHECK(!looks_like_unc("D:\\x"));
}

// ---- pairing texts
TEST(simple_pair_helpers) {
    LangGuard g(Lang::Vi);
    CHECK_EQ(fmt_countdown(601), std::string("10:01"));
    CHECK_EQ(fmt_countdown(59), std::string("0:59"));
    CHECK_EQ(fmt_countdown(-3), std::string("0:00"));
    CHECK_EQ(sas_display("abcd-efgh-jkmn-pqrs"), std::string("ABCD   EFGH   JKMN   PQRS"));

    auto r = rank_addresses({"127.0.0.1", "169.254.3.4", "8.8.4.4", "192.168.1.20", "fe80::1", "::1", "10.0.0.5",
                             "2001:db8::2", "192.168.1.20", "172.16.0.9", "172.32.0.1", "0.0.0.0"});
    std::vector<std::string> want = {"192.168.1.20", "10.0.0.5", "172.16.0.9", "8.8.4.4", "172.32.0.1", "2001:db8::2"};
    CHECK(r == want);
    CHECK(is_private_ipv4("172.31.255.1"));
    CHECK(!is_private_ipv4("172.15.0.1"));
    CHECK(!is_private_ipv4("example.com"));

    CHECK(has(firewall_hint(5656), "5656"));
}

TEST(simple_pair_code_check_is_plain_and_never_echoes_the_code) {
    LangGuard g(Lang::Vi);
    CHECK(!check_pair_code_text("").empty());
    CHECK(has(check_pair_code_text("hello world"), "MSY1-"));

    simple::PairCode c;
    c.server_key = key_from_hex(std::string(64, 'a'));
    c.port = 5656;
    c.host = "192.168.1.20";
    std::string code = simple::encode_pair_code(c);
    simple::PairCode back;
    CHECK_EQ(check_pair_code_text(code, &back), std::string(""));
    CHECK_EQ(back.host, c.host);
    CHECK_EQ(back.port, uint16_t(5656));
    // dán thừa khoảng trắng / xuống dòng (chép từ email) vẫn đọc được
    CHECK_EQ(check_pair_code_text("  " + code + "\r\n"), std::string(""));
    // hỏng một ký tự giữa mã: báo bằng lời thường, không lộ mã
    std::string bad = code;
    size_t i = bad.size() / 2;
    bad[i] = bad[i] == '2' ? '3' : '2';
    std::string e = check_pair_code_text(bad);
    CHECK(!e.empty());
    CHECK(!has(e, bad));
    CHECK(!has(e, "checksum"));
}

TEST(simple_pair_outcome_text_covers_every_kind) {
    LangGuard g(Lang::Vi);
    using K = simple::PairOutcome;
    for (auto k : {K::Approved, K::Denied, K::Busy, K::Expired, K::Cancelled, K::Failed}) {
        K o;
        o.kind = k;
        auto t = pair_outcome_text(o);
        CHECK(!t.empty());
        CHECK(t.find("?pair") == std::string::npos);
    }
    K f;
    f.kind = K::Failed;
    f.message = "connection refused";
    CHECK(has(pair_outcome_text(f), "connection refused"));  // nguyên văn
}

TEST(simple_friendly_error_translates_core_issue_keys) {
    LangGuard g(Lang::Vi);
    auto e = friendly_error("receiver.root_not_writable: D:/Nhan");
    CHECK(has(e, "Không ghi được"));
    CHECK(has(e, "D:/Nhan"));  // chi tiết nguyên văn còn nguyên
    CHECK(has(friendly_error("wizard.dest_missing"), "Không tìm thấy nơi lưu"));
    CHECK_EQ(friendly_error("connection refused"), std::string("connection refused"));
    CHECK_EQ(friendly_error("wizard.no_such_key: x"), std::string("wizard.no_such_key: x"));  // khoá lạ: không bịa
    set_lang(Lang::En);
    CHECK(has(friendly_error("receiver.root_is_root"), "whole drive"));
}

TEST(simple_service_confirm_text_lists_folders_key_and_warning) {
    LangGuard g(Lang::Vi);
    simple::MigrationSummary m;
    m.sources = {"D:/Tài liệu"};
    m.destinations = {"E:/Sao-luu"};
    m.key_identity = "ab12 cd34";
    m.service_account = "LocalSystem";
    m.warnings = {"canh bao rieng"};
    auto t = service_confirm_text(m);
    for (const char* x : {"D:/Tài liệu", "E:/Sao-luu", "ab12 cd34", "LocalSystem", "canh bao rieng", "quyền cao", "Tiếp tục?"})
        CHECK(has(t, x));
    CHECK(!has(t, "{0}"));
}

// ---- không có thuật ngữ kỹ thuật trong lời của chế độ Đơn giản
TEST(simple_strings_have_no_jargon) {
    const char* banned[] = {"daemon", "toml", "noise", "allowlist", "ipc", "sid ", "named pipe", "pubkey", "public key"};
    const char* prefixes[] = {"simple.", "wizard.", "pair.", "recv.", "quick."};
    size_t checked = 0;
    for (Lang l : {Lang::Vi, Lang::En}) {
        LangGuard g(l);
        for (const auto& k : i18n_keys()) {
            bool mine = false;
            for (const char* p : prefixes)
                if (k.rfind(p, 0) == 0) mine = true;
            if (!mine) continue;
            std::string t = tr(k.c_str());
            std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return std::tolower(c); });
            for (const char* b : banned)
                if (has(t, b)) throw mytest::Failure{"jargon '" + std::string(b) + "' in " + k};
            ++checked;
        }
    }
    CHECK(checked > 200);
}
