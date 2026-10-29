// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Headless tests of the pure GUI view-model layer (gui/*_model.*). Deliberately does NOT include any wx header.
#include "form_model.h"
#include "i18n_model.h"
#include "status_model.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;

namespace {
struct LangGuard {
    explicit LangGuard(Lang l) { set_lang(l); }
    ~LangGuard() { set_lang(Lang::Vi); }
};
StatusSnapshot snap_with(TargetState s) {
    StatusSnapshot sn;
    TargetStatus t;
    t.watch = "docs";
    t.target = "net://srv:5656";
    t.state = s;
    sn.targets.push_back(t);
    return sn;
}
}  // namespace

// ---- i18n
TEST(gui_i18n_table_is_complete_and_unique) {
    CHECK(i18n_count() > 100);
    auto p = i18n_problems();
    if (!p.empty()) throw mytest::Failure{"i18n: " + p.front() + " (+" + std::to_string(p.size() - 1) + " more)"};
}

TEST(gui_i18n_switch_and_placeholders) {
    LangGuard g(Lang::Vi);
    CHECK_EQ(tr("tab.status"), std::string("Trạng thái"));
    set_lang(Lang::En);
    CHECK_EQ(tr("tab.status"), std::string("Status"));
    CHECK_EQ(trf("err.uint", {"1", "64"}), std::string("Need an integer from 1 to 64."));
    set_lang(Lang::Vi);
    CHECK_EQ(trf("dur.dh", {"2", "3"}), std::string("2 ngày 3 giờ"));
    // khoá thiếu lộ ra màn hình chứ không im lặng
    CHECK_EQ(tr("no.such.key"), std::string("?no.such.key?"));
    CHECK(!i18n_has("no.such.key"));
    Lang l;
    CHECK(lang_from_code("en", l) && l == Lang::En);
    CHECK(!lang_from_code("fr", l));
}

// ---- định dạng
TEST(gui_format_bytes_rate_duration) {
    LangGuard g(Lang::Vi);
    CHECK_EQ(fmt_bytes(0), std::string("0 B"));
    CHECK_EQ(fmt_bytes(1023), std::string("1023 B"));
    CHECK_EQ(fmt_bytes(1536), std::string("1,5 KB"));  // dấu phẩy thập phân tiếng Việt
    set_lang(Lang::En);
    CHECK_EQ(fmt_rate(5ull << 20), std::string("5.0 MB/s"));
    set_lang(Lang::Vi);
    CHECK_EQ(fmt_duration(59), std::string("59 giây"));
    CHECK_EQ(fmt_duration(3 * 60 + 7), std::string("3 phút 07 giây"));
    CHECK_EQ(fmt_duration(2 * 3600 + 5 * 60), std::string("2 giờ 5 phút"));
    CHECK_EQ(fmt_duration(2 * 86400 + 3 * 3600), std::string("2 ngày 3 giờ"));
}

TEST(gui_datetime_always_has_weekday) {
    LangGuard g(Lang::Vi);
    std::tm t{};
    t.tm_year = 2026 - 1900;
    t.tm_mon = 9;  // tháng 10
    t.tm_mday = 29;
    t.tm_hour = 22;
    t.tm_min = 59;
    t.tm_sec = 3;
    t.tm_wday = 4;  // 29/10/2026 là Thứ Năm
    CHECK_EQ(fmt_datetime_tm(t), std::string("Thứ Năm 29/10/2026 22:59:03"));
    t.tm_wday = 0;
    CHECK(fmt_datetime_tm(t).rfind("Chủ nhật ", 0) == 0);
    set_lang(Lang::En);
    t.tm_wday = 6;
    CHECK_EQ(fmt_datetime_tm(t), std::string("Saturday 29/10/2026 22:59:03"));
    CHECK_EQ(fmt_datetime(0), std::string("—"));
    // một mốc thật: chuỗi phải bắt đầu bằng tên thứ
    std::string s = fmt_datetime(1780000000000LL);
    bool ok = false;
    for (int w = 0; w < 7; ++w)
        if (s.rfind(weekday_name(w), 0) == 0) ok = true;
    CHECK(ok);
}

TEST(gui_time_ago) {
    LangGuard g(Lang::En);
    CHECK_EQ(fmt_time_ago(1000, 4000), std::string("3s ago"));
    CHECK_EQ(fmt_time_ago(0, 4000), std::string("—"));
    CHECK_EQ(fmt_time_ago(0 + 1, 3600 * 1000 * 5 + 1), std::string("5 h ago"));
}

// ---- trạng thái -> màu icon khay
TEST(gui_tray_state_mapping) {
    LangGuard g(Lang::Vi);
    const int64_t now = 1'000'000'000'000LL;
    StatusSnapshot none;
    CHECK(compute_tray_state(false, none, now) == TrayState::Offline);
    CHECK(compute_tray_state(true, none, now) == TrayState::Idle);
    CHECK(compute_tray_state(true, snap_with(TargetState::Idle), now) == TrayState::Idle);
    CHECK(compute_tray_state(true, snap_with(TargetState::Syncing), now) == TrayState::Syncing);
    CHECK(compute_tray_state(true, snap_with(TargetState::Error), now) == TrayState::Error);
    CHECK(compute_tray_state(true, snap_with(TargetState::Disconnected), now) == TrayState::Warning);
    // lỗi cũ (ngoài cửa sổ) không làm vàng; lỗi mới thì có
    auto s = snap_with(TargetState::Idle);
    s.targets[0].last_error = "boom";
    s.targets[0].last_error_unix_ms = now - 20 * 60 * 1000;
    CHECK(compute_tray_state(true, s, now) == TrayState::Idle);
    s.targets[0].last_error_unix_ms = now - 60 * 1000;
    CHECK(compute_tray_state(true, s, now) == TrayState::Warning);
    // daemon từ chối cấu hình -> cảnh báo
    StatusSnapshot ce;
    ce.config_error = "line 3: bad";
    CHECK(compute_tray_state(true, ce, now) == TrayState::Warning);
    // lỗi thắng đang đồng bộ
    auto mix = snap_with(TargetState::Syncing);
    TargetStatus e2;
    e2.state = TargetState::Error;
    mix.targets.push_back(e2);
    CHECK(compute_tray_state(true, mix, now) == TrayState::Error);
}

TEST(gui_tray_colors_are_distinct) {
    uint32_t c[] = {tray_state_color(TrayState::Offline), tray_state_color(TrayState::Idle),
                    tray_state_color(TrayState::Syncing), tray_state_color(TrayState::Warning),
                    tray_state_color(TrayState::Error)};
    for (int i = 0; i < 5; ++i)
        for (int j = i + 1; j < 5; ++j) CHECK(c[i] != c[j]);
    // đỏ phải đỏ, xanh dương phải xanh dương, lá phải lá
    CHECK(((c[4] >> 16) & 0xFF) > 0xB0);
    CHECK((c[2] & 0xFF) > 0xB0);
    CHECK(((c[1] >> 8) & 0xFF) > 0x80);
}

TEST(gui_target_row_and_latest_error) {
    LangGuard g(Lang::Vi);
    TargetStatus t;
    t.watch = "docs";
    t.target = "net://srv:5656";
    t.state = TargetState::Syncing;
    t.queued = 7;
    t.active_files = {"a.txt", "b.txt"};
    t.sent = 5;
    t.skipped = 2;
    t.failed = 1;
    t.bytes = 2048;
    auto r = make_target_row(t);
    CHECK_EQ(r.target, std::string("srv:5656 (mạng)"));
    CHECK_EQ(r.queued, std::string("7 (+2)"));
    CHECK_EQ(r.counts, std::string("5 / 2 / 1"));
    CHECK_EQ(r.bytes, std::string("2,0 KB"));
    CHECK_EQ(target_display("dir:///mnt/nas"), std::string("/mnt/nas (thư mục)"));

    StatusSnapshot s;
    TargetStatus a = t, b = t;
    a.last_error = "old";
    a.last_error_unix_ms = 100;
    b.watch = "pics";
    b.last_error = "connection refused";  // nguyên văn, không sửa
    b.last_error_unix_ms = 200;
    s.targets = {a, b};
    LastError le;
    CHECK(latest_error(s, le));
    CHECK_EQ(le.message, std::string("connection refused"));
    CHECK_EQ(le.unix_ms, int64_t(200));
    CHECK(le.where.find("pics") != std::string::npos);
    StatusSnapshot empty;
    CHECK(!latest_error(empty, le));
}

// ---- băng báo lỗi
TEST(gui_banner_merges_duplicates_and_caps) {
    BannerModel m;
    m.add(BannerLevel::Error, "", "x failed");
    m.add(BannerLevel::Error, "", "x failed");
    m.add(BannerLevel::Error, "", "x failed");
    CHECK_EQ(m.items().size(), size_t(1));
    CHECK_EQ(m.items()[0].count, 3);
    CHECK_EQ(m.render(m.items()[0]), std::string("x failed (×3)"));
    for (int i = 0; i < 10; ++i) m.add(BannerLevel::Warning, "", "w" + std::to_string(i));
    CHECK_EQ(m.items().size(), BannerModel::kMaxBanner);  // trần, dòng cũ nhất bị bỏ
    CHECK_EQ(m.items().back().message, std::string("w9"));
}

TEST(gui_banner_named_source_does_not_count_repeats) {
    BannerModel m;
    CHECK(m.add(BannerLevel::Warning, "poll", "cannot reach A"));
    CHECK(!m.add(BannerLevel::Warning, "poll", "cannot reach A"));  // poll mỗi giây: không đổi gì
    CHECK_EQ(m.items()[0].count, 1);
}

TEST(gui_banner_source_replaces_and_clears) {
    BannerModel m;
    m.add(BannerLevel::Warning, "poll", "cannot reach A");
    m.add(BannerLevel::Warning, "poll", "cannot reach B");  // cùng nguồn: thay, không chồng
    CHECK_EQ(m.items().size(), size_t(1));
    CHECK_EQ(m.items()[0].message, std::string("cannot reach B"));
    m.add(BannerLevel::Error, "cfg", "bad line 3");
    CHECK(m.has_error());
    CHECK(m.clear_source("poll"));
    CHECK_EQ(m.items().size(), size_t(1));
    CHECK(m.remove("cfg", "bad line 3"));
    CHECK(!m.has_error());
    CHECK(!m.clear_source("nothing"));
}

// ---- kiểm hợp lệ
TEST(gui_check_port_and_uint) {
    uint16_t p = 0;
    CHECK(check_port("5656", &p).empty());
    CHECK_EQ(p, uint16_t(5656));
    CHECK(!check_port("0").empty());
    CHECK(!check_port("65536").empty());
    CHECK(!check_port("abc").empty());
    CHECK(!check_port("").empty());
    CHECK(!check_port("-1").empty());
    uint64_t v = 0;
    CHECK(check_uint(" 12 ", 1, 64, &v).empty());
    CHECK_EQ(v, uint64_t(12));
    CHECK(!check_uint("65", 1, 64).empty());
}

TEST(gui_check_host_ip_and_cidr) {
    CHECK(check_host("may-chu.example.com").empty());
    CHECK(check_host("192.168.1.5").empty());
    CHECK(check_host("[fd00::1]").empty());
    CHECK(!check_host("").empty());
    CHECK(!check_host("bad host").empty());
    CHECK(!check_host("a/b").empty());
    CHECK(check_ip_rule("*").empty());
    CHECK(check_ip_rule("10.0.0.0/8").empty());
    CHECK(check_ip_rule("192.168.1.10").empty());
    CHECK(check_ip_rule("fd00::/8").empty());
    CHECK(check_ip_rule("2001:db8::1").empty());
    CHECK(!check_ip_rule("10.0.0.0/33").empty());
    CHECK(!check_ip_rule("300.1.1.1").empty());
    CHECK(!check_ip_rule("10.0.0").empty());
    CHECK(!check_ip_rule("hello").empty());
    CHECK(!check_ip_rule("1.2.3.4/").empty());
    CHECK(!check_ip_lines("10.0.0.0/8\nnope").empty());
    CHECK(check_ip_lines("10.0.0.0/8\n\n 192.168.0.1 ").empty());
}

TEST(gui_check_size_time_hhmm) {
    uint64_t v = 0;
    CHECK(check_size("10MB", false, &v).empty());
    CHECK_EQ(v, uint64_t(10) << 20);
    CHECK(check_size("", true).empty());
    CHECK(!check_size("", false).empty());
    CHECK(!check_size("ten", true).empty());
    CHECK(check_mtime("").empty());
    CHECK(check_mtime("7d").empty());
    CHECK(check_mtime("12h").empty());
    CHECK(check_mtime("2026-01-01T00:00:00").empty());
    CHECK(check_mtime("2026-01-01").empty());
    CHECK(!check_mtime("2026-13-01T00:00:00").empty());
    CHECK(!check_mtime("yesterday").empty());
    CHECK(check_hhmm("01:00").empty());
    CHECK(check_hhmm("23:59").empty());
    CHECK(!check_hhmm("24:00").empty());
    CHECK(!check_hhmm("1:00").empty());
    CHECK(!check_hhmm("12:60").empty());
    CHECK(!check_hhmm_lines("01:00\n99:99").empty());
}

TEST(gui_check_regex_mode_prefix_names) {
    CHECK(check_regex("^docs/.*\\.txt$").empty());
    CHECK(!check_regex("([unclosed").empty());
    CHECK(!check_regex("").empty());
    uint32_t m = 0;
    CHECK(check_octal_mode("0640", false, &m).empty());
    CHECK_EQ(m, uint32_t(0640));
    CHECK(!check_octal_mode("0755", false).empty());  // tệp không được có bit thực thi
    CHECK(!check_octal_mode("0444", false).empty());  // chủ phải giữ rw
    CHECK(check_octal_mode("0750", true).empty());
    CHECK(!check_octal_mode("0640", true).empty());   // thư mục phải giữ rwx cho chủ
    CHECK(!check_octal_mode("0689", true).empty());
    CHECK(check_service_name("mysync-client").empty());
    CHECK(!check_service_name("-bad").empty());
    CHECK(!check_service_name("a b").empty());
    CHECK(!check_service_name("").empty());
    CHECK(!check_service_name(std::string(65, 'a')).empty());
    CHECK(check_prefix("").empty());
    CHECK(check_prefix("hanoi/van-phong").empty());
    CHECK(!check_prefix("/abs").empty());
    CHECK(!check_prefix("a/").empty());
    CHECK(!check_prefix("a/../b").empty());
    CHECK(check_client_name("Văn phòng Hà Nội").empty());
    CHECK(!check_client_name("  ").empty());
}

TEST(gui_lines_and_size_text) {
    auto v = split_lines("  a \r\n\n b\n  \n");
    CHECK_EQ(v.size(), size_t(2));
    CHECK_EQ(v[0], std::string("a"));
    CHECK_EQ(v[1], std::string("b"));
    CHECK_EQ(join_lines(v), std::string("a\nb"));
    CHECK_EQ(size_to_text(10ull << 30), std::string("10GB"));
    CHECK_EQ(size_to_text(1536), std::string("1536"));
    CHECK_EQ(size_to_text(0), std::string("0"));
    CHECK_EQ(size_to_text(512ull << 20), std::string("512MB"));
    CHECK_EQ(mode_to_text(0640), std::string("0640"));
    // vòng tròn: văn bản -> số -> văn bản
    uint64_t b = 0;
    CHECK(check_size(size_to_text(7ull << 30), false, &b).empty());
    CHECK_EQ(b, uint64_t(7) << 30);
}

// ---- kiểm cả cấu trúc
TEST(gui_problems_client_catches_every_hidden_watch) {
    LangGuard g(Lang::En);
    ClientConfig c;
    CHECK(!problems_client(c).empty());  // chưa có watch
    WatchConfig ok;
    ok.name = "docs";
    ok.path = "/data";
    TargetConfig net;
    net.host = "srv";
    net.port = 5656;
    net.server_key.fill(7);
    ok.targets.push_back(net);
    c.key_file = "client.key";
    c.watches.push_back(ok);
    CHECK(problems_client(c).empty());

    // watch thứ hai (không hiển thị) hỏng: vẫn bị bắt
    WatchConfig bad = ok;
    bad.name = "pics";
    bad.schedule_at = {"25:00"};
    bad.filter.exclude_regex = {"([x"};
    bad.filter.size_max = "lots";
    bad.targets[0].server_key = PublicKey{};  // chưa ghim khoá
    c.watches.push_back(bad);
    auto p = problems_client(c);
    CHECK(p.size() >= 4);
    bool names_it = false;
    for (auto& s : p)
        if (s.find("pics") != std::string::npos) names_it = true;
    CHECK(names_it);

    // đích copy cục bộ không cần khoá/host
    ClientConfig c2;
    c2.watches.push_back(ok);
    c2.watches[0].targets[0] = TargetConfig{};
    c2.watches[0].targets[0].path = "/mnt/nas";
    CHECK(problems_client(c2).empty());
    // retry đảo ngược
    c2.retry_min_ms = 5000;
    c2.retry_max_ms = 1000;
    CHECK(!problems_client(c2).empty());
}

TEST(gui_problems_server) {
    LangGuard g(Lang::En);
    ServerConfig s;
    CHECK(!problems_server(s).empty());  // thiếu root, key_file, client
    s.root = "/srv/mysync";
    s.key_file = "server.key";
    ClientAcl a;
    a.name = "hn";
    s.clients.push_back(a);
    CHECK(problems_server(s).empty());
    s.allow = {"10.0.0.0/99"};
    CHECK(!problems_server(s).empty());
    CHECK(key_is_unset(PublicKey{}));
    PublicKey k{};
    k[31] = 1;
    CHECK(!key_is_unset(k));
}
