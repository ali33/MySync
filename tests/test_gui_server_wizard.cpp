// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Headless tests of the "Dựng máy chủ" wizard model (gui/server_wizard_model.*). No wx header.
#include <filesystem>
#include <fstream>
#include <sstream>

#include "i18n_model.h"
#include "mysync/config.h"
#include "mysync/gui/key_mgr.h"
#include "mysync/peers.h"
#include "server_wizard_model.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {
struct SwTmp {
    fs::path p;
    SwTmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-guisw-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~SwTmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string sub(const std::string& n) const { return (p / n).u8string(); }
};

std::string slurp(const std::string& path) {
    std::ifstream f(fs::u8path(path), std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
bool has(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }
std::string any_pub_hex() {
    std::string h;
    for (int i = 0; i < 32; ++i) h += (i % 2 ? "ab" : "07");
    return h;
}
}  // namespace

TEST(sw_port_validation) {
    set_lang(Lang::Vi);
    uint16_t p = 0;
    CHECK(check_server_port("5656", p).ok && p == 5656);
    CHECK(check_server_port("  80 \n", p).ok && p == 80);
    CHECK(check_server_port("1", p).ok && p == 1);
    CHECK(check_server_port("65535", p).ok && p == 65535);
    for (const char* bad : {"", " ", "0", "65536", "99999", "123456", "-1", "12a", "5 6", "0x10", "5656.0", "+80"}) {
        InputCheck c = check_server_port(bad, p);
        CHECK(!c.ok);
        CHECK(!c.error.empty());
    }
}

TEST(sw_folder_validation) {
    set_lang(Lang::Vi);
    SwTmp t;
    std::string n;
    CHECK(!check_server_folder("", n).ok);
    CHECK(!check_server_folder("   ", n).ok);
    CHECK(check_server_folder(t.p.u8string(), n).ok && n == t.p.u8string());
    CHECK(check_server_folder("\"" + t.p.u8string() + "\"", n).ok && n == t.p.u8string());   // pasted with quotes
    CHECK(check_server_folder(t.sub("chua-co-thu-muc"), n).ok);                                // will be created
    std::ofstream(fs::u8path(t.sub("tep.txt"))) << "x";
    InputCheck c = check_server_folder(t.sub("tep.txt"), n);
    CHECK(!c.ok && !c.error.empty());
    CHECK(!check_server_folder(std::string("a\x01" "b"), n).ok);
}

TEST(sw_client_key_normalisation) {
    set_lang(Lang::Vi);
    const std::string hex = any_pub_hex();
    std::string out;
    CHECK(check_client_key(hex, out).ok && out == hex);
    CHECK(check_client_key("  \n" + hex + "\r\n ", out).ok && out == hex);
    CHECK(check_client_key("0x" + hex, out).ok && out == hex);
    std::string upper = hex;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    CHECK(check_client_key(upper, out).ok && out == hex);
    std::string spaced;
    for (size_t i = 0; i < hex.size(); i += 4) spaced += hex.substr(i, 4) + (i + 4 < hex.size() ? " " : "");
    CHECK(check_client_key(spaced, out).ok && out == hex);
    CHECK(!check_client_key("", out).ok);
    CHECK(!check_client_key("   \n", out).ok);
    CHECK(!check_client_key(hex.substr(2), out).ok);       // too short
    CHECK(!check_client_key(hex + "00", out).ok);          // too long
    CHECK(!check_client_key("zz" + hex.substr(2), out).ok);
}

TEST(sw_client_name_validation) {
    set_lang(Lang::Vi);
    std::string n;
    CHECK(check_client_name("  may-ke-toan ", n).ok && n == "may-ke-toan");
    CHECK(check_client_name("Máy kế toán", n).ok);
    CHECK(!check_client_name("", n).ok);
    CHECK(!check_client_name("   ", n).ok);
    CHECK(!check_client_name(std::string(129, 'a'), n).ok);
    CHECK(check_client_name(std::string(128, 'a'), n).ok);
    CHECK(!check_client_name(std::string("a\nb"), n).ok);
}

TEST(sw_buttons_per_stage) {
    ServerButtons in_bad = server_buttons(ServerStage::Input, false, false, false);
    CHECK(!in_bad.create && in_bad.browse && in_bad.close && !in_bad.add_client && !in_bad.install_service);
    ServerButtons in_ok = server_buttons(ServerStage::Input, true, false, false);
    CHECK(in_ok.create);
    ServerButtons busy = server_buttons(ServerStage::Creating, true, true, false);
    CHECK(!busy.create && !busy.browse && !busy.close && !busy.add_client && !busy.install_service && !busy.copy);
    ServerButtons res = server_buttons(ServerStage::Result, true, false, false);
    CHECK(!res.create && res.copy && !res.add_client && res.install_service && res.close);
    CHECK(server_buttons(ServerStage::Result, true, true, false).add_client);
    ServerButtons res_busy = server_buttons(ServerStage::Result, true, true, true);   // second background job running
    CHECK(!res_busy.add_client && !res_busy.install_service && !res_busy.close);
}

TEST(sw_create_texts_and_idempotence) {
    set_lang(Lang::Vi);
    SwTmp t;
    QuickResult a = create_server(t.sub("nhan"), 5757);
    CHECK(a.role == "server" && a.port == 5757);
    CHECK(a.key_created && a.config_created);
    ServerResultTexts ta = make_server_result_texts(a);
    CHECK(has(ta.headline, "sẵn sàng"));
    CHECK(has(ta.key_line, "vừa tạo"));
    CHECK(has(ta.config_line, "vừa tạo"));
    CHECK(ta.public_key.size() == 64);
    CHECK(!ta.fingerprint.empty());
    CHECK(has(ta.client_snippet, ta.public_key));
    CHECK(has(ta.peer_add_command, "peer"));
    CHECK(has(ta.port_line, "5757"));

    QuickResult b = create_server(t.sub("nhan"), 5757);   // again: nothing changes
    CHECK(!b.changed() && b.key_existed && b.config_existed);
    CHECK(b.public_key == a.public_key);
    ServerResultTexts tb = make_server_result_texts(b);
    CHECK(has(tb.headline, "đã dựng từ trước"));
    CHECK(has(tb.key_line, "đã có sẵn, giữ nguyên"));
    CHECK(has(tb.config_line, "đã có sẵn, giữ nguyên"));

    set_lang(Lang::En);
    ServerResultTexts te = make_server_result_texts(b);
    CHECK(has(te.key_line, "already there, kept"));
    set_lang(Lang::Vi);
}

TEST(sw_result_texts_never_carry_the_secret_key) {
    set_lang(Lang::Vi);
    SwTmp t;
    QuickResult r = create_server(t.sub("nhan"), 5656);
    std::string secret = slurp(r.key_file);
    while (!secret.empty() && std::isspace(static_cast<unsigned char>(secret.back()))) secret.pop_back();
    CHECK(secret.size() >= 32);
    for (Lang l : {Lang::Vi, Lang::En}) {
        set_lang(l);
        ServerResultTexts x = make_server_result_texts(r);
        std::string all = x.headline + "\n" + x.folder_line + "\n" + x.port_line + "\n" + x.config_line + "\n" + x.key_line + "\n" +
                          x.public_key + "\n" + x.fingerprint + "\n" + x.pairing_line + "\n" + x.client_snippet + "\n" + x.peer_add_command;
        for (const auto& n : x.notes) all += "\n" + n;
        CHECK(!has(all, secret));
        // The key file's path is shown, its content is not; the public half is not the secret either.
        CHECK(has(x.key_line, r.key_file));
        CHECK(secret != x.public_key);
    }
    set_lang(Lang::Vi);
}

TEST(sw_add_client_is_idempotent_and_reports) {
    set_lang(Lang::Vi);
    SwTmp t;
    QuickResult r = create_server(t.sub("nhan"), 5656);
    const std::string hex = any_pub_hex();

    AddClientOutcome a = add_client(r.config_file, "may-ke-toan", "  0x" + hex + "\n", false);
    CHECK(a.ok && a.changed);
    CHECK(!a.message.empty());
    bool found = false;
    for (const auto& c : peer_list(r.config_file))
        if (c.name == "may-ke-toan" && c.public_key == parse_public_key_hex(hex) && !c.read_only) found = true;
    CHECK(found);

    AddClientOutcome again = add_client(r.config_file, "may-ke-toan", hex, false);   // same thing: unchanged
    CHECK(again.ok && !again.changed);

    AddClientOutcome ro = add_client(r.config_file, "may-ke-toan", hex, true);       // same key, other mode: updated
    CHECK(ro.ok && ro.changed);
    bool is_ro = false;
    for (const auto& c : peer_list(r.config_file))
        if (c.name == "may-ke-toan") is_ro = c.read_only;
    CHECK(is_ro);

    // Same name, other key: refused with peer_add's own text (verbatim), nothing thrown.
    std::string other = hex;
    other[0] = '9';
    AddClientOutcome clash = add_client(r.config_file, "may-ke-toan", other, false);
    CHECK(!clash.ok && !clash.message.empty());

    // Bad input is reported, not thrown, and nothing is written.
    CHECK(!add_client(r.config_file, "x", "not a key", false).ok);
    CHECK(!add_client(r.config_file, "  ", hex, false).ok);
    CHECK(!add_client(t.sub("khong-co/server.toml"), "x", hex, false).ok);
}

TEST(sw_i18n_has_every_key_in_both_languages) {
    CHECK(i18n_problems().empty());
    for (const auto& k : i18n_keys())
        if (k.rfind("srv.", 0) == 0) {
            set_lang(Lang::Vi);
            CHECK(tr(k.c_str()).size() > 0 && tr(k.c_str())[0] != '?');
            set_lang(Lang::En);
            CHECK(tr(k.c_str()).size() > 0 && tr(k.c_str())[0] != '?');
        }
    set_lang(Lang::Vi);
    CHECK(i18n_has("srv.menu") && i18n_has("srv.title"));
}
