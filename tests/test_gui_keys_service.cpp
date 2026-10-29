// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// KeyManager (pairing machines) and ServiceController (argument checks only: nothing is ever installed here).
#include <filesystem>
#include <fstream>
#include <sstream>

#include "mysync/gui/key_mgr.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/keys.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {

struct KsTmp {
    fs::path p;
    KsTmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-guiks-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~KsTmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    std::string file(const std::string& n) const { return (p / n).u8string(); }
};

std::string slurp(const std::string& path) {
    std::ifstream f(fs::u8path(path), std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string server_toml_text(const std::string& pub_hex) {
    return "[server]\nroot = \"/srv/x\"\nkey_file = \"/etc/k\"\n\n[[client]]\nname = \"first\"\npublic_key = \"" + pub_hex + "\"\n";
}

std::string a_pub() { return key_to_hex(generate_keypair().pub); }

// An executable stand-in called mysync(.exe): ServiceController only validates it, tests never run it.
std::string fake_exe(const KsTmp& t) {
#ifdef _WIN32
    std::string n = t.file("mysync.exe");
#else
    std::string n = t.file("mysync");
#endif
    std::ofstream(fs::u8path(n), std::ios::binary) << "stub";
#ifndef _WIN32
    fs::permissions(fs::u8path(n), fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read |
                                       fs::perms::others_exec);
#endif
    return n;
}

}  // namespace

TEST(gui_keys_generate_never_exposes_the_secret) {
    KsTmp t;
    std::string kf = t.file("client.key");
    GeneratedKey g = KeyManager::generate_key_file(kf);
    CHECK_EQ(g.public_hex.size(), size_t(64));
    CHECK(KeyManager::is_valid_public_hex(g.public_hex));
    CHECK_EQ(g.fingerprint.size(), size_t(24));  // 5 groups of 4 hex + 4 dashes
    CHECK(g.fingerprint[4] == '-');
    CHECK(fs::exists(fs::u8path(kf)));
    CHECK(!g.pub_file.empty());
    CHECK_EQ(KeyManager::normalize_public_hex(slurp(g.pub_file)), g.public_hex);
    // the secret (read straight from the file) appears in none of the strings handed back
    std::string secret = read_secret_file(kf);
    while (!secret.empty() && (secret.back() == '\n' || secret.back() == '\r')) secret.pop_back();
    CHECK_EQ(secret.size(), size_t(64));
    CHECK(secret != g.public_hex);
    for (const std::string& s : {g.key_file, g.public_hex, g.fingerprint, g.pub_file})
        CHECK(s.find(secret) == std::string::npos);
    CHECK_EQ(KeyManager::public_key_of_file(kf), g.public_hex);
    secure_wipe(&secret[0], secret.size());
    // never overwrites
    CHECK_THROWS(KeyManager::generate_key_file(kf));
    CHECK_EQ(KeyManager::public_key_of_file(kf), g.public_hex);
    // a second key differs
    GeneratedKey g2 = KeyManager::generate_key_file(t.file("other.key"), false);
    CHECK(g2.public_hex != g.public_hex);
    CHECK(g2.fingerprint != g.fingerprint);
    CHECK(g2.pub_file.empty());
}

TEST(gui_keys_error_messages_do_not_echo_key_text) {
    KsTmp t;
    std::string kf = t.file("k.key");
    std::ofstream(fs::u8path(kf), std::ios::binary) << "SECRET-TEXT-NOT-A-KEY";
    bool threw = false;
    try {
        KeyManager::public_key_of_file(kf);
    } catch (const Error& e) {
        threw = true;
        CHECK(std::string(e.what()).find("SECRET-TEXT") == std::string::npos);
    }
    CHECK(threw);
    try {
        KeyManager::normalize_public_hex("zzzz-secret-looking-input");
    } catch (const Error& e) {
        CHECK(std::string(e.what()).find("secret-looking") == std::string::npos);
    }
}

TEST(gui_keys_public_text_normalisation) {
    std::string k = a_pub();
    std::string upper = k;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    CHECK_EQ(KeyManager::normalize_public_hex("  " + upper + "\r\n"), k);
    CHECK_EQ(KeyManager::normalize_public_hex("0x" + k), k);
    std::string spaced;
    for (size_t i = 0; i < k.size(); i += 2) spaced += k.substr(i, 2) + (i % 8 == 6 ? ":" : " ");
    CHECK_EQ(KeyManager::normalize_public_hex(spaced), k);
    CHECK(!KeyManager::is_valid_public_hex(""));
    CHECK(!KeyManager::is_valid_public_hex(k.substr(1)));
    CHECK(!KeyManager::is_valid_public_hex(k + "0"));
    CHECK(!KeyManager::is_valid_public_hex(std::string(63, 'a') + "g"));
    CHECK_EQ(KeyManager::fingerprint(k), KeyManager::fingerprint(upper));
    CHECK_EQ(KeyManager::fingerprint(k).size(), size_t(24));
}

TEST(gui_keys_allowlist_editing) {
    KsTmp t;
    std::string path = t.file("server.toml");
    std::string k1 = a_pub();
    std::ofstream(fs::u8path(path), std::ios::binary) << server_toml_text(k1);
    ConfigEditor ed = ConfigEditor::open(path);
    auto list = KeyManager::list_clients(ed);
    CHECK_EQ(list.size(), size_t(1));
    CHECK_EQ(list[0].name, std::string("first"));
    CHECK_EQ(list[0].public_hex, k1);
    CHECK_EQ(list[0].fingerprint, KeyManager::fingerprint(k1));

    AllowedClient c;
    c.name = "second";
    c.public_hex = a_pub();
    c.read_only = true;
    c.prefix = "hanoi\\2026/";
    KeyManager::add_client(ed, c);
    CHECK_EQ(ed.server().clients.size(), size_t(2));
    CHECK_EQ(ed.server().clients[1].prefix, std::string("hanoi/2026"));
    CHECK(ed.server().clients[1].read_only);
    // duplicates and bad input
    CHECK_THROWS(KeyManager::add_client(ed, c));                  // same name
    AllowedClient dupkey = c;
    dupkey.name = "third";
    dupkey.public_hex = k1;
    CHECK_THROWS(KeyManager::add_client(ed, dupkey));             // same key
    AllowedClient bad = c;
    bad.name = "x";
    bad.public_hex = a_pub();
    bad.prefix = "../up";
    CHECK_THROWS(KeyManager::add_client(ed, bad));
    bad.prefix = "";
    bad.public_hex = "not a key";
    CHECK_THROWS(KeyManager::add_client(ed, bad));
    bad.public_hex = a_pub();
    bad.name = "";
    CHECK_THROWS(KeyManager::add_client(ed, bad));
    CHECK_EQ(ed.server().clients.size(), size_t(2));
    // update (rename + rotate key)
    AllowedClient upd = c;
    upd.name = "second-renamed";
    upd.public_hex = a_pub();
    upd.read_only = false;
    KeyManager::update_client(ed, "second", upd);
    CHECK_EQ(ed.server().clients[1].name, std::string("second-renamed"));
    CHECK(!ed.server().clients[1].read_only);
    CHECK_THROWS(KeyManager::update_client(ed, "nobody", upd));
    // the result is a loadable file
    ed.save();
    ConfigEditor back = ConfigEditor::open(path);
    CHECK_EQ(KeyManager::list_clients(back).size(), size_t(2));
    // remove; the last client cannot go
    KeyManager::remove_client(ed, "second-renamed");
    CHECK_THROWS(KeyManager::remove_client(ed, "second-renamed"));
    CHECK_THROWS(KeyManager::remove_client(ed, "first"));
    CHECK_EQ(ed.server().clients.size(), size_t(1));
    CHECK_THROWS(KeyManager::list_clients(ConfigEditor::create(t.file("c.toml"), ConfigRole::Client)));
}

TEST(gui_keys_pin_server_key_on_a_target) {
    KsTmp t;
    std::string path = t.file("client.toml");
    std::ofstream(fs::u8path(path), std::ios::binary)
        << "[client]\nkey_file = \"k\"\n[[watch]]\nname = \"w\"\npath = \"/a\"\n[[watch.target]]\nhost = \"h\"\nserver_key = \""
        << std::string(64, '0') << "\"\n[[watch.target]]\npath = \"/b\"\n";
    ConfigEditor ed = ConfigEditor::open(path);
    std::string pub = a_pub();
    KeyManager::set_target_server_key(ed, 0, 0, " " + pub + "\n");
    CHECK_EQ(to_hex(ed.client().watches[0].targets[0].server_key.data(), 32), pub);
    CHECK_THROWS(KeyManager::set_target_server_key(ed, 0, 1, pub));   // local target
    CHECK_THROWS(KeyManager::set_target_server_key(ed, 5, 0, pub));
    CHECK_THROWS(KeyManager::set_target_server_key(ed, 0, 0, "nope"));
    ed.save();
    CHECK_EQ(to_hex(ConfigEditor::open(path).client().watches[0].targets[0].server_key.data(), 32), pub);
}

TEST(gui_service_name_and_argument_validation) {
    for (const char* ok : {"mysync-server", "a", "My_Svc.1", "x-y"}) CHECK(ServiceController::valid_name(ok));
    for (const char* bad : {"", "-rf", ".hidden", "a b", "a;b", "a&b", "a|b", "a$(id)", "a`id`", "../x", "a/b", "a\\b", "a\"b", "a\nb"})
        CHECK(!ServiceController::valid_name(bad));
    CHECK(!ServiceController::valid_name(std::string(65, 'a')));
    CHECK(ServiceController::valid_name(std::string(64, 'a')));

    KsTmp t;
    ServiceController sc(fake_exe(t));
    std::string cfg = t.file("server.toml");
    std::ofstream(fs::u8path(cfg), std::ios::binary) << server_toml_text(a_pub());

    ServiceRequest r;
    r.name = "mysync-server";
    r.config_path = cfg;
    r.role = "server";
    r.run_as = "mysync";
    r.control_allow = {"S-1-5-21-1-2-3-1001", "CORP\\alice"};
    auto a = sc.build_args(ServiceAction::Install, r);
    std::vector<std::string> want = {"service", "install", "-c", cfg, "--role", "server", "--user", "mysync",
                                     "--control-allow", "S-1-5-21-1-2-3-1001", "--control-allow", "CORP\\alice",
                                     "--name", "mysync-server"};
    CHECK(a == want);

    ServiceRequest s;
    s.name = "mysync-server";
    CHECK((sc.build_args(ServiceAction::Start, s) == std::vector<std::string>{"service", "start", "--name", "mysync-server"}));
    CHECK((sc.build_args(ServiceAction::Stop, s) == std::vector<std::string>{"service", "stop", "--name", "mysync-server"}));
    CHECK((sc.build_args(ServiceAction::Uninstall, s) == std::vector<std::string>{"service", "uninstall", "--name", "mysync-server"}));

    // anything that could be taken for an option, a second command or a path trick is rejected
    ServiceRequest bad = s;
    for (const char* n : {"", "-x", "a b", "a;b", "a&&b", "$(id)", "x\ny"}) {
        bad.name = n;
        CHECK_THROWS(sc.build_args(ServiceAction::Start, bad));
    }
    bad = r;
    bad.config_path = "relative.toml";
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    bad.config_path = t.file("does-not-exist.toml");
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    bad = r;
    bad.role = "admin";
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    bad = r;
    bad.run_as = "root; rm -rf /";
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    bad.run_as = "-oProxyCommand=x";
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    bad = r;
    bad.control_allow = {"--exec=evil"};
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    bad.control_allow = {"a\"b"};
    CHECK_THROWS(sc.build_args(ServiceAction::Install, bad));
    // options that only make sense for install are refused on the other actions
    bad = s;
    bad.config_path = cfg;
    CHECK_THROWS(sc.build_args(ServiceAction::Stop, bad));
}

TEST(gui_service_executable_checks) {
    KsTmp t;
    CHECK_THROWS(ServiceController(t.file("missing/mysync")));
    CHECK_THROWS(ServiceController("mysync"));  // not absolute
    std::string other = t.file("notmysync");
    std::ofstream(fs::u8path(other), std::ios::binary) << "x";
    CHECK_THROWS(ServiceController(other));     // wrong name: never elevate arbitrary programs
    std::string ok = fake_exe(t);
    ServiceController sc(ok);
    CHECK_EQ(sc.exe(), ok);
#ifndef _WIN32
    fs::permissions(fs::u8path(ok), fs::perms::group_write, fs::perm_options::add);
    CHECK_THROWS(ServiceController(ok));        // writable by the group: refused for elevation
#endif
}

TEST(gui_service_query_of_an_unknown_service) {
    KsTmp t;
    ServiceController sc(fake_exe(t));
    ServiceState st = sc.query("mysync-test-never-installed-xyz");
    CHECK(!st.installed);
    CHECK(!st.running);
    ServiceState bad = sc.query("bad name;");
    CHECK(!bad.installed);
    CHECK(!bad.error.empty());
}

TEST(gui_service_exit_code_classification) {
    CHECK_EQ(service_exit_code_for_error("OpenSCManager failed: error 5 (Access is denied.)"), int(kServiceAccessDenied));
    CHECK_EQ(service_exit_code_for_error("cannot write /etc/systemd/system/x.service.tmp: Permission denied (root required)"),
             int(kServiceAccessDenied));
    CHECK_EQ(service_exit_code_for_error("OpenService failed: error 1060 (The specified service does not exist as an installed service.)"),
             int(kServiceNotInstalled));
    CHECK_EQ(service_exit_code_for_error("CreateService failed: error 1073 (The specified service already exists.)"),
             int(kServiceAlreadyInstalled));
    CHECK_EQ(service_exit_code_for_error("stop timed out"), int(kServiceTimeout));
    CHECK_EQ(service_exit_code_for_error("invalid service name"), int(kServiceBadArguments));
    CHECK_EQ(service_exit_code_for_error("something else entirely"), int(kServiceGenericFailure));
    for (int c : {0, 1, 20, 21, 22, 23, 24, 25, 126, 77}) CHECK(!service_exit_message(c).empty());
    CHECK_EQ(std::string(service_action_name(ServiceAction::Uninstall)), std::string("uninstall"));
}
