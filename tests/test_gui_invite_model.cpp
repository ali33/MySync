// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Headless tests of the invitation-code view-model (gui/invite_model.*): the sender's paste-and-check state machine, the
// plain-words summary, outcome texts, the receiver's form helpers (folder plan, addresses, rows). No wx header.
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>

#include "i18n_model.h"
#include "invite_model.h"
#include "simple_model.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {
struct LangGuard {
    explicit LangGuard(Lang l) { set_lang(l); }
    ~LangGuard() { set_lang(Lang::Vi); }
};
bool has(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }

simple::InviteOutcome outcome(simple::InviteOutcome::Kind k, const std::string& msg = "") {
    simple::InviteOutcome o;
    o.kind = k;
    o.message = msg;
    return o;
}

// A code for a receiver "MAY-NHAN", folder "Báo cáo", valid for `ttl` seconds from `now`.
std::string make_code(int64_t now, int ttl, simple::InvitePerm perm = simple::InvitePerm::ReadWrite) {
    simple::InviteCode c;
    c.server_key = generate_keypair().pub;
    random_bytes(c.id.data(), c.id.size());
    random_bytes(c.secret.data(), c.secret.size());
    c.expires_unix = now + ttl;
    c.perm = perm;
    c.addrs.push_back({"192.168.1.20", 5656});
    c.machine = "MAY-NHAN";
    c.label = "B\xC3\xA1o c\xC3\xA1o";
    return simple::encode_invite_code(c);
}

simple::InviteOutcome ok_outcome(const simple::InviteCode& c) {
    simple::InviteOutcome o;
    o.kind = simple::InviteOutcome::Ok;
    o.grant.machine = c.machine;
    o.grant.label = c.label;
    o.grant.perm = c.perm;
    o.grant.expires_unix = c.expires_unix;
    o.grant.uses_left = 1;
    o.grant.fingerprint = simple::invite_fingerprint(c.server_key);
    o.grant.address = c.addrs[0];
    o.grant.server_key = c.server_key;
    return o;
}
}  // namespace

// ------------------------------------------------------------------------------------------------ plain words
TEST(invite_model_time_left_is_plain_and_rounds_down) {
    LangGuard g(Lang::Vi);
    CHECK_EQ(time_left_text(0), std::string("đã hết hạn"));
    CHECK_EQ(time_left_text(-5), std::string("đã hết hạn"));
    CHECK_EQ(time_left_text(30), std::string("còn dưới 1 phút"));
    CHECK_EQ(time_left_text(120), std::string("còn 2 phút"));
    CHECK_EQ(time_left_text(3599), std::string("còn 59 phút"));
    CHECK_EQ(time_left_text(3600), std::string("còn 1 giờ"));
    CHECK_EQ(time_left_text(23 * 3600 + 1800), std::string("còn 23 giờ"));
    CHECK_EQ(time_left_text(47 * 3600), std::string("còn 47 giờ"));
    CHECK_EQ(time_left_text(3 * 86400 + 5), std::string("còn 3 ngày"));
    LangGuard e(Lang::En);
    CHECK_EQ(time_left_text(7200), std::string("2 hours left"));
}

TEST(invite_model_permission_and_uses_texts) {
    LangGuard g(Lang::Vi);
    CHECK_EQ(invite_perm_text(simple::InvitePerm::ReadWrite), std::string("được gửi và sửa tệp"));
    CHECK_EQ(invite_perm_text(simple::InvitePerm::ReadOnly), std::string("chỉ xem"));
    CHECK_EQ(invite_perm_choice_text(simple::InvitePerm::ReadWrite), std::string("Gửi và sửa tệp"));
    CHECK_EQ(invite_perm_choice_text(simple::InvitePerm::ReadOnly), std::string("Chỉ xem"));
    CHECK_EQ(uses_text(1), std::string("dùng được 1 lần"));
}

TEST(invite_model_times_carry_the_weekday_and_keep_unreadable_values) {
    LangGuard g(Lang::Vi);
    std::tm t{};
    t.tm_year = 2026 - 1900;
    t.tm_mon = 10;
    t.tm_mday = 2;
    t.tm_hour = 14;
    t.tm_min = 5;
    t.tm_wday = 1;   // 2 November 2026 is a Monday
    CHECK_EQ(fmt_weekday_time(t), std::string("Thứ Hai 02/11/2026 14:05"));
    t.tm_wday = 0;
    CHECK(has(fmt_weekday_time(t), "Chủ nhật"));
    std::string loc = fmt_utc_stamp("2026-11-02 07:30");
    CHECK(has(loc, "2026"));
    CHECK(has(loc, "Thứ") || has(loc, "Chủ nhật"));
    // the UTC stamp is shown in LOCAL time: same instant as fmt_local_time of the equivalent unix time
    std::tm u{};
    u.tm_year = 126;
    u.tm_mon = 10;
    u.tm_mday = 2;
    u.tm_hour = 7;
    u.tm_min = 30;
#ifdef _WIN32
    std::time_t tt = _mkgmtime(&u);
#else
    std::time_t tt = timegm(&u);
#endif
    CHECK_EQ(loc, fmt_local_time(static_cast<int64_t>(tt)));
    // not a stamp: kept as it was (a missing value must stay visible)
    CHECK_EQ(fmt_utc_stamp("hôm qua"), std::string("hôm qua"));
    CHECK_EQ(fmt_utc_stamp(""), std::string(""));
    CHECK_EQ(fmt_utc_stamp("2026-13-45 99:99"), std::string("2026-13-45 99:99"));
}

// ------------------------------------------------------------------------------------------------ sender
TEST(invite_model_sender_paste_check_and_summary) {
    LangGuard g(Lang::Vi);
    const int64_t now = 1'900'000'000;
    std::string text = make_code(now, 23 * 3600 + 1800);
    SenderInviteModel m;
    CHECK(m.stage() == CodeStage::Empty);
    CHECK(!m.set_text("", now));
    CHECK(m.set_text("  " + text + "\r\n", now));          // pasted with stray blanks: read; a probe must start
    CHECK(m.stage() == CodeStage::Checking);
    CHECK(!m.ready());
    uint64_t gen = m.generation();
    CHECK(!m.set_text(text, now));                          // same code again: nothing new to check
    CHECK_EQ(m.generation(), gen);
    InviteSummary early = m.summary(now);                   // readable from the code even before the receiver answered
    CHECK_EQ(early.machine, std::string("MAY-NHAN"));

    CHECK(m.apply_probe(gen, ok_outcome(m.code())));
    CHECK(m.ready());
    InviteSummary s = m.summary(now);
    CHECK_EQ(s.machine, std::string("MAY-NHAN"));
    CHECK_EQ(s.folder, std::string("B\xC3\xA1o c\xC3\xA1o"));
    CHECK_EQ(s.perm, std::string("được gửi và sửa tệp"));
    CHECK_EQ(s.left, std::string("còn 23 giờ"));
    CHECK_EQ(s.uses, std::string("dùng được 1 lần"));
    CHECK(has(s.sentence, "MAY-NHAN"));
    CHECK(has(s.sentence, "được gửi và sửa tệp"));
    CHECK(has(s.line, "(còn 23 giờ, dùng được 1 lần)."));
    CHECK(has(s.sentence, "B\xC3\xA1o c\xC3\xA1o"));
    CHECK(has(s.dest_label, "MAY-NHAN"));
    // the fingerprint exists, but only as its own field (the UI puts it under the collapsed details)
    CHECK(!s.fingerprint.empty());
    CHECK(!has(s.sentence, s.fingerprint));
    CHECK(!has(s.dest_label, s.fingerprint));
    // no jargon in what the sender reads
    for (const std::string& t : {s.sentence, s.dest_label, s.perm, s.left, s.uses})
        for (const char* bad : {"toml", "peer", "public key", "hex", "MSY2", "client", "server"}) CHECK(!has(t, bad));
    // editing the box clears everything
    CHECK(!m.set_text("", now));
    CHECK(m.stage() == CodeStage::Empty);
    CHECK(!m.ready());
}

TEST(invite_model_sender_blocks_a_read_only_code_at_paste) {
    LangGuard g(Lang::Vi);
    const int64_t now = 1'900'000'000;
    SenderInviteModel m;
    CHECK(!m.set_text(make_code(now, 3600, simple::InvitePerm::ReadOnly), now));   // no probe is even started
    CHECK(m.stage() == CodeStage::Failed);
    CHECK(!m.ready());
    CHECK(has(m.error(), "Mã này chỉ cho xem, không dùng để gửi tệp lên máy kia được."));
    CHECK(has(m.error(), "Gửi và sửa tệp"));
    // a code that claims read-write but the receiver answers view-only is blocked as well
    SenderInviteModel x;
    CHECK(x.set_text(make_code(now, 3600), now));
    simple::InviteOutcome o = ok_outcome(x.code());
    o.grant.perm = simple::InvitePerm::ReadOnly;
    CHECK(x.apply_probe(x.generation(), o));
    CHECK(!x.ready());
    CHECK(has(x.error(), "chỉ cho xem"));
    // the wizard never gets a destination from it
    WizardModel w;
    w.set_source("D:/A");
    w.apply_validation({});
    CHECK(w.next());
    w.set_kind(simple::DestKind::PairedMachine);
    w.apply_validation({});
    CHECK(!w.can_next());   // Next stays disabled: no destination was ever set
}

TEST(invite_model_sender_errors_are_plain_and_never_echo_the_code) {
    LangGuard g(Lang::Vi);
    const int64_t now = 1'900'000'000;
    std::string text = make_code(now, 3600);
    SenderInviteModel m;
    // not a code at all
    CHECK(!m.set_text("hello world", now));
    CHECK(m.stage() == CodeStage::Invalid);
    CHECK(has(m.error(), "MSY2-"));
    // right prefix, one character wrong in the middle: checksum fails
    std::string bad = text;
    size_t i = bad.size() / 2;
    bad[i] = bad[i] == '2' ? '3' : '2';
    CHECK(!m.set_text(bad, now));
    CHECK(m.stage() == CodeStage::Invalid);
    CHECK(has(m.error(), "Mã này chưa đúng"));
    CHECK(!has(m.error(), bad));
    CHECK(!has(m.error(), "checksum"));
    // an old pairing code is not an invitation
    CHECK(!m.set_text("MSY1-ABCDE-FGHJK", now));
    CHECK(m.stage() == CodeStage::Invalid);
    // expired locally: no probe at all
    CHECK(!m.set_text(make_code(now - 7200, 3600), now));
    CHECK(m.stage() == CodeStage::Failed);
    CHECK(has(m.error(), "hết hạn"));
    // a probe result for a code the user has since replaced is ignored
    CHECK(m.set_text(text, now));
    uint64_t old_gen = m.generation();
    CHECK(m.set_text(make_code(now, 3600), now));
    CHECK(!m.apply_probe(old_gen, ok_outcome(m.code())));
    CHECK(m.stage() == CodeStage::Checking);
    // each failure kind has its own plain sentence
    struct Case {
        simple::InviteOutcome::Kind k;
        const char* expect;
    } cases[] = {
        {simple::InviteOutcome::BadCode, "Mã này chưa đúng"},
        {simple::InviteOutcome::Expired, "hết hạn"},
        {simple::InviteOutcome::Unreachable, "cùng một mạng"},
        {simple::InviteOutcome::Refused, "không nhận mã này"},
        {simple::InviteOutcome::Busy, "đang bận"},
    };
    for (const Case& c : cases) {
        SenderInviteModel x;
        CHECK(x.set_text(make_code(now, 3600), now));
        CHECK(x.apply_probe(x.generation(), outcome(c.k)));
        CHECK(x.stage() == CodeStage::Failed);
        CHECK(has(x.error(), c.expect));
        CHECK(!x.ready());
        CHECK(!has(x.error(), "?inv."));
    }
    // "unreachable" explains the condition for BOTH machines
    CHECK(has(invite_outcome_text(outcome(simple::InviteOutcome::Unreachable)), "địa chỉ công khai"));
    CHECK(has(invite_outcome_text(outcome(simple::InviteOutcome::Unreachable)), "mở cổng"));
    // Failed keeps the verbatim detail; Cancelled / Ok have text too
    CHECK(has(invite_outcome_text(outcome(simple::InviteOutcome::Failed, "boom: 0x80070005")), "boom: 0x80070005"));
    CHECK(!invite_outcome_text(outcome(simple::InviteOutcome::Failed)).empty());
    CHECK(!invite_outcome_text(outcome(simple::InviteOutcome::Cancelled)).empty());
    CHECK(!invite_outcome_text(outcome(simple::InviteOutcome::Ok)).empty());
}

TEST(invite_model_destination_comes_from_the_receivers_answer) {
    simple::InviteGrant g;
    g.server_key = generate_keypair().pub;
    g.address = {"10.0.0.7", 6001};
    simple::PairCode pc = pair_code_from_grant(g);
    CHECK_EQ(pc.host, std::string("10.0.0.7"));
    CHECK_EQ(pc.port, uint16_t(6001));
    CHECK(pc.server_key == g.server_key);
    // the wizard model accepts it as the destination and shows the machine name, not the address
    LangGuard lg(Lang::Vi);
    WizardModel w;
    w.set_source("D:/A");
    w.set_kind(simple::DestKind::PairedMachine);
    w.set_paired(pc);
    w.set_machine_label("MAY-NHAN · thư mục \"Báo cáo\" · chỉ xem");
    CHECK(has(w.summary(), "MAY-NHAN"));
    CHECK(has(w.summary(), "chỉ xem"));
    CHECK(!has(w.summary(), "10.0.0.7"));
    w.clear_paired();
    CHECK(!has(w.summary(), "MAY-NHAN"));
}

TEST(invite_model_join_texts_and_demo_code) {
    LangGuard g(Lang::Vi);
    CHECK(has(join_busy_text(false, 0), "Đang nối"));
    CHECK(has(join_busy_text(true, 95), "Đang chờ máy kia đồng ý"));
    CHECK(has(join_busy_text(true, 95), "1:35"));
    std::string demo = demo_invite_code("MAY-NHAN", "Bao cao", "192.168.1.20", 5656, simple::InvitePerm::ReadWrite, 3600);
    simple::InviteCode c = simple::decode_invite_code(demo);
    CHECK_EQ(c.machine, std::string("MAY-NHAN"));
    CHECK_EQ(c.addrs[0].host, std::string("192.168.1.20"));
    CHECK(demo != demo_invite_code("MAY-NHAN", "Bao cao", "192.168.1.20", 5656, simple::InvitePerm::ReadWrite, 3600));   // random each time
}

// ------------------------------------------------------------------------------------------------ receiver form
TEST(invite_model_receiver_choices_and_defaults) {
    LangGuard g(Lang::Vi);
    auto ttl = invite_ttl_choices();
    CHECK_EQ(ttl.size(), size_t(3));
    CHECK_EQ(ttl[0].seconds, 3600);
    CHECK_EQ(ttl[1].seconds, 86400);
    CHECK_EQ(ttl[2].seconds, 7 * 86400);
    CHECK_EQ(ttl[kDefaultTtlIndex].label, std::string("24 giờ"));
    CHECK_EQ(ttl[2].label, std::string("7 ngày"));
    auto uses = invite_uses_choices();
    CHECK_EQ(uses[kDefaultUsesIndex].uses, 1);
    for (const auto& u : uses) CHECK(u.uses >= 1 && u.uses <= simple::kInviteMaxUses);
    for (const auto& t : ttl) CHECK(t.seconds <= simple::kInviteMaxTtlSeconds);
    ReceiverForm f;
    CHECK(f.perm == simple::InvitePerm::ReadWrite);   // "Gửi và sửa tệp" by default
    CHECK(f.ask);                                     // "Hỏi tôi trước khi cho vào" ticked by default
}

TEST(invite_model_receiver_folder_check) {
    LangGuard g(Lang::Vi);
    CHECK(!check_receiver_folder("").ok);
    CHECK(has(check_receiver_folder("   ").error, "chọn thư mục"));
    // each code hands out ONE absolute folder: a relative path is refused in plain words
    std::string abs = fs::temp_directory_path().generic_u8string() + "/Nhan";
    FolderCheck q = check_receiver_folder("  \"" + abs + "\"  ");
    CHECK(q.ok);
    CHECK_EQ(q.normalized, abs);
    FolderCheck rel = check_receiver_folder("Nhan/Tep");
    CHECK(!rel.ok);
    CHECK(has(rel.error, "đường dẫn đầy đủ"));
    CHECK(!check_receiver_folder("..").ok);
    fs::path f = fs::temp_directory_path() / "mysync-invm-file.txt";
    {
        FILE* fp = std::fopen(f.string().c_str(), "wb");
        if (fp) std::fclose(fp);
    }
    FolderCheck file = check_receiver_folder(f.u8string());
    CHECK(!file.ok);
    CHECK(has(file.error, "tệp"));
    std::error_code ec;
    fs::remove(f, ec);
    CHECK(!check_receiver_folder(abs + char(7) + "b").ok);
}

TEST(invite_model_prepare_folder_creates_a_missing_one_and_refuses_a_file) {
    fs::path base = fs::temp_directory_path() / ("mysync-invm-" + std::to_string(std::time(nullptr)) + "-" + std::to_string(std::rand()));
    std::error_code ec;
    fs::create_directories(base, ec);
    std::string made = (base / "nhan" / "con").generic_u8string();
    prepare_receiver_folder(made, false);
    CHECK(fs::is_directory(fs::u8path(made)));
    prepare_receiver_folder(made, false);   // again: nothing to do
    fs::path file = base / "tep.txt";
    {
        FILE* fp = std::fopen(file.string().c_str(), "wb");
        if (fp) std::fclose(fp);
    }
    CHECK_THROWS(prepare_receiver_folder(file.generic_u8string(), false));
    fs::remove_all(base, ec);
}

TEST(invite_model_addresses_local_first_at_most_three) {
    auto a = choose_invite_addrs({"8.8.4.4", "192.168.1.20", "fe80::1", "127.0.0.1", "10.0.0.5", "192.168.1.20", "2001:db8::2", "172.16.0.9", "169.254.1.1"}, 5656);
    CHECK_EQ(a.size(), size_t(3));
    CHECK_EQ(a[0].host, std::string("192.168.1.20"));    // local network first, duplicates dropped
    CHECK_EQ(a[1].host, std::string("10.0.0.5"));
    CHECK_EQ(a[2].host, std::string("172.16.0.9"));
    for (const auto& x : a) CHECK_EQ(x.port, uint16_t(5656));
    auto b = choose_invite_addrs({"8.8.4.4", "2001:db8::2"}, 6000);
    CHECK_EQ(b.size(), size_t(2));
    CHECK_EQ(b[0].host, std::string("8.8.4.4"));         // public IPv4 before IPv6
    CHECK_EQ(b[1].host, std::string("2001:db8::2"));
    CHECK(choose_invite_addrs({}, 5656).empty());
    CHECK(choose_invite_addrs({"127.0.0.1", "fe80::1"}, 5656).empty());
    CHECK(choose_invite_addrs({"192.168.1.20"}, 0).empty());
}

TEST(invite_model_buttons_follow_the_stage) {
    ReceiverButtons form_ok = receiver_buttons(ReceiverStage::Form, true, false);
    CHECK(form_ok.create && form_ok.browse && form_ok.form && !form_ok.copy && !form_ok.another);
    ReceiverButtons form_bad = receiver_buttons(ReceiverStage::Form, false, false);
    CHECK(!form_bad.create && form_bad.browse);
    ReceiverButtons busy = receiver_buttons(ReceiverStage::Form, true, true);
    CHECK(!busy.create && !busy.browse && !busy.form);
    ReceiverButtons work = receiver_buttons(ReceiverStage::Working, true, false);
    CHECK(!work.create && !work.browse && !work.form && !work.copy && !work.another);
    ReceiverButtons show = receiver_buttons(ReceiverStage::Showing, true, false);
    CHECK(show.copy && show.another && !show.create);
    ReceiverButtons show_busy = receiver_buttons(ReceiverStage::Showing, true, true);
    CHECK(show_busy.copy && !show_busy.another);   // no second action while one is under way
}

// ------------------------------------------------------------------------------------------------ rows
TEST(invite_model_rows_show_names_never_keys) {
    LangGuard g(Lang::Vi);
    InviteListInfo info;
    JoinedMachineView a;
    a.name = "MAY-GUI";
    a.key_hex = std::string(64, 'c');
    a.when_utc = "2026-11-02 07:30";
    a.invite_id_hex = "0123456789abcdef";
    a.perm = simple::InvitePerm::ReadOnly;
    JoinedMachineView b = a;
    b.name = "";
    b.key_hex = std::string(64, 'd');
    b.when_utc = "không rõ";
    info.joined = {a, b};
    auto rows = joined_rows(info);
    CHECK_EQ(rows.size(), size_t(2));
    CHECK_EQ(rows[0].title, std::string("MAY-GUI"));
    CHECK_EQ(rows[0].key_hex, std::string(64, 'c'));          // kept only to call "Gỡ"
    CHECK(has(rows[0].detail, "chỉ xem"));
    CHECK(has(rows[0].detail, "vào lúc"));
    CHECK(!has(rows[0].title + rows[0].detail, std::string(64, 'c')));
    CHECK_EQ(rows[1].title, std::string("(không có tên)"));
    CHECK(has(rows[1].detail, "không rõ"));                  // unreadable time stays as it was
    CHECK(!has(rows[1].title + rows[1].detail, std::string(64, 'd')));

    InviteView live;
    live.id_hex = "aaaaaaaaaaaaaaaa";
    live.label = "Báo cáo";
    live.state = "live";
    live.expires_unix = 1'900'000'000 + 3 * 3600;
    live.uses_left = 2;
    live.perm = simple::InvitePerm::ReadWrite;
    InviteView dead = live;
    dead.state = "revoked";
    dead.id_hex = "bbbbbbbbbbbbbbbb";
    info.invites = {live, dead};
    auto lr = live_rows(info, 1'900'000'000);
    CHECK_EQ(lr.size(), size_t(1));
    CHECK_EQ(lr[0].id_hex, std::string("aaaaaaaaaaaaaaaa"));
    CHECK_EQ(lr[0].title, std::string("Báo cáo"));
    CHECK(has(lr[0].detail, "được gửi và sửa tệp"));
    CHECK(has(lr[0].detail, "còn 3 giờ"));
    CHECK(has(lr[0].detail, "dùng được 2 lần"));
}

TEST(invite_model_code_progress_waiting_joined_gone) {
    LangGuard g(Lang::Vi);
    const int64_t now = 1'900'000'000;
    std::string text = make_code(now, 3600);
    std::string id = invite_code_id_hex(text);
    CHECK_EQ(id.size(), size_t(16));
    CHECK_EQ(invite_code_id_hex("rubbish"), std::string(""));
    InviteListInfo info;
    CodeProgress gone = code_progress(info, id, now);
    CHECK(gone.kind == CodeProgress::Gone);
    CHECK(has(gone.text, "không còn dùng được"));
    InviteView v;
    v.id_hex = id;
    v.state = "live";
    v.expires_unix = now + 100;
    info.invites.push_back(v);
    CodeProgress wait = code_progress(info, id, now);
    CHECK(wait.kind == CodeProgress::Waiting);
    CHECK(has(wait.text, "Đang chờ máy kia"));
    CHECK(code_progress(info, id, now + 200).kind == CodeProgress::Gone);   // past its expiry
    JoinedMachineView j;
    j.name = "MAY-GUI";
    j.invite_id_hex = id;
    info.joined.push_back(j);
    CodeProgress joined = code_progress(info, id, now);
    CHECK(joined.kind == CodeProgress::Joined);
    CHECK(has(joined.text, "MAY-GUI"));
    info.invites.clear();   // used up and joined: still "joined", not "gone"
    CHECK(code_progress(info, id, now).kind == CodeProgress::Joined);
}

TEST(invite_model_first_pending_skips_the_dismissed) {
    InviteListInfo info;
    CHECK(first_pending(info, {}) == nullptr);
    simple::PendingInvite a, b;
    a.id = 4;
    b.id = 9;
    info.pending = {a, b};
    CHECK_EQ(first_pending(info, {})->id, uint32_t(4));
    CHECK_EQ(first_pending(info, {4})->id, uint32_t(9));
    CHECK(first_pending(info, {4, 9}) == nullptr);
}

// ------------------------------------------------------------------------------------------------ strings
TEST(invite_model_strings_exist_in_both_languages_and_have_no_jargon) {
    CHECK(i18n_problems().empty());
    const char* banned[] = {"toml", "peer add", "public key", "khoá công khai", "máy chủ", "máy khách", "client", "server", "daemon",
                            "allowlist", "noise", "named pipe", "ipc"};
    size_t checked = 0;
    for (Lang l : {Lang::Vi, Lang::En}) {
        LangGuard g(l);
        for (const auto& k : i18n_keys()) {
            if (k.rfind("inv.", 0) != 0) continue;
            std::string t = tr(k.c_str());
            CHECK(!t.empty());
            std::string low = t;
            std::transform(low.begin(), low.end(), low.begin(), [](unsigned char c) { return std::tolower(c); });
            for (const char* b : banned)
                if (has(low, b)) throw mytest::Failure{"jargon '" + std::string(b) + "' in " + k};
            ++checked;
        }
    }
    CHECK(checked > 100);
}
