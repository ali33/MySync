// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// quick-server / quick-client: idempotency, never overwriting, safe defaults, the snippet loads, JSON output.
#include "so_util.h"
#include "mysync/config.h"
#include "mysync/peers.h"
#include "mysync/quick_setup.h"
#include "mysync/gui/trust.h"
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace mysync;
using sotest::Tmp;
using sotest::slurp;
using sotest::spit;

namespace {
std::string trim_nl(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    return s;
}
}  // namespace

TEST(qs_server_creates_key_and_safe_config) {
    Tmp t;
    QuickServerOptions o;
    o.dir = t.s("share");
    o.port = 6123;
    QuickResult r = quick_server(o);
    CHECK(r.key_created);
    CHECK(r.config_created);
    CHECK(r.dir_created);
    CHECK(r.changed());
    CHECK_EQ(r.public_key.size(), size_t(64));
    CHECK_EQ(r.pairing, std::string("off"));
    // the configuration lives BESIDE the shared folder, never inside it
    CHECK(fs::exists(fs::u8path(r.config_file)));
    CHECK(fs::u8path(r.config_file).parent_path() != fs::u8path(r.dir));
    ServerConfig c = load_server_config(r.config_file);
    CHECK(c.pairing == PairingMode::Off);
    CHECK_EQ(c.port, uint16_t(6123));
    CHECK_EQ(c.max_file_size, uint64_t(10) << 30);
    CHECK_EQ(c.max_trash_bytes, uint64_t(10) << 30);
    CHECK_EQ(c.file_mode, 0640u);
    CHECK_EQ(c.dir_mode, 0750u);
    CHECK(c.trash);
    CHECK_EQ(c.max_connections, 20u);
    CHECK(!c.peers_dir.empty());
    CHECK(fs::exists(fs::u8path(c.peers_dir)));
    // the public key reported is the one of the key file
    CHECK_EQ(r.public_key, key_to_hex(load_keypair(r.key_file).pub));
}

TEST(qs_server_idempotent_and_never_overwrites) {
    Tmp t;
    QuickServerOptions o;
    o.dir = t.s("share");
    QuickResult a = quick_server(o);
    std::string key_before = slurp(fs::u8path(a.key_file));
    spit(fs::u8path(a.config_file), slurp(fs::u8path(a.config_file)) + "\n# my own note\n");
    std::string cfg_before = slurp(fs::u8path(a.config_file));
    o.port = 7777;   // a different request must not rewrite the file either
    QuickResult b = quick_server(o);
    CHECK(!b.changed());
    CHECK(b.config_existed && !b.config_created && !b.config_replaced);
    CHECK(b.key_existed && !b.key_created);
    CHECK_EQ(b.public_key, a.public_key);
    CHECK_EQ(b.port, a.port);                     // reports what is really in the file
    CHECK(!b.notes.empty());                      // and says that the asked-for port was ignored
    CHECK_EQ(slurp(fs::u8path(a.config_file)), cfg_before);
    CHECK_EQ(slurp(fs::u8path(a.key_file)), key_before);
}

TEST(qs_server_force_rewrites_config_keeps_key) {
    Tmp t;
    QuickServerOptions o;
    o.dir = t.s("share");
    QuickResult a = quick_server(o);
    std::string key_before = slurp(fs::u8path(a.key_file));
    o.force = true;
    o.port = 6200;
    QuickResult b = quick_server(o);
    CHECK(b.config_replaced);
    CHECK(!b.key_created);                         // --force never replaces a key
    CHECK_EQ(slurp(fs::u8path(a.key_file)), key_before);
    CHECK_EQ(b.public_key, a.public_key);
    CHECK_EQ(load_server_config(b.config_file).port, uint16_t(6200));
    CHECK(fs::exists(fs::u8path(b.config_file + ".bak")));
}

TEST(qs_server_existing_key_without_config_is_kept) {
    Tmp t;
    std::string cdir = t.s("cfg");
    fs::create_directories(fs::u8path(cdir));
    KeyPair kp = generate_keypair();
    save_keypair(cdir + "/server.key", kp);
    QuickServerOptions o;
    o.dir = t.s("share");
    o.config_dir = cdir;
    QuickResult r = quick_server(o);
    CHECK(!r.key_created && r.key_existed);
    CHECK(r.config_created);
    CHECK_EQ(r.public_key, key_to_hex(kp.pub));
}

TEST(qs_server_refuses_bad_input) {
    Tmp t;
    QuickServerOptions o;
    CHECK_THROWS(quick_server(o));                                  // no --dir
    o.dir = t.s("share");
    o.config_dir = t.s("share/cfg");                                // inside the shared folder: key would be served
    CHECK_THROWS(quick_server(o));
    CHECK(!fs::exists(fs::u8path(t.s("share/cfg/server.key"))));
    spit(fs::u8path(t.s("file")), "x");
    o.config_dir = "";
    o.dir = t.s("file");                                            // a file, not a folder
    CHECK_THROWS(quick_server(o));
    // an invalid existing configuration is reported, never replaced silently
    QuickServerOptions p;
    p.dir = t.s("s2");
    QuickResult r = quick_server(p);
    spit(fs::u8path(r.config_file), "[server]\nport = 99999\n");
    CHECK_THROWS(quick_server(p));
    CHECK_EQ(slurp(fs::u8path(r.config_file)), std::string("[server]\nport = 99999\n"));
}

TEST(qs_snippet_loads_and_is_usable) {
    Tmp t;
    QuickServerOptions o;
    o.dir = t.s("share");
    o.name = "van phong HN";
    QuickResult r = quick_server(o);
    ClientConfig c = parse_client_config_text(r.client_snippet);   // loads exactly as printed
    CHECK_EQ(c.watches.size(), size_t(1));
    CHECK_EQ(c.watches[0].targets.size(), size_t(1));
    CHECK_EQ(key_to_hex(c.watches[0].targets[0].server_key), r.public_key);
    CHECK_EQ(c.watches[0].targets[0].port, uint16_t(5656));
    // with the placeholders filled in it still loads
    std::string s = r.client_snippet;
    s.replace(s.find("TEN-HOAC-IP-MAY-CHU"), 19, "192.168.1.10");
    s.replace(s.find("THU-MUC-CAN-DONG-BO"), 19, "/data/x");
    CHECK_EQ(parse_client_config_text(s).watches[0].targets[0].host, std::string("192.168.1.10"));
    CHECK(r.peer_add_command.find("--name van-phong-HN") != std::string::npos);
    CHECK(r.peer_add_command.find("<KHOA-CONG-KHAI-CUA-MAY-KHACH>") != std::string::npos);
}

TEST(qs_client_writes_config_and_peer_add_line_works) {
    Tmp t;
    QuickServerOptions so;
    so.dir = t.s("share");
    QuickResult s = quick_server(so);
    fs::create_directories(fs::u8path(t.s("data")));
    QuickClientOptions co;
    co.server = "10.1.2.3:6001";
    co.server_key = "  " + s.public_key + "\n";                // pasted text
    co.dir = t.s("data");
    co.name = "hn";
    QuickResult c = quick_client(co);
    CHECK(c.key_created && c.config_created);
    ClientConfig cc = load_client_config(c.config_file);
    CHECK_EQ(cc.watches[0].targets[0].host, std::string("10.1.2.3"));
    CHECK_EQ(cc.watches[0].targets[0].port, uint16_t(6001));
    CHECK_EQ(key_to_hex(cc.watches[0].targets[0].server_key), s.public_key);
    CHECK(c.peer_add_command.find(c.public_key) != std::string::npos);
    // idempotent
    QuickResult c2 = quick_client(co);
    CHECK(!c2.changed());
    CHECK_EQ(c2.public_key, c.public_key);
    // the printed peer-add arguments really work against the server
    auto r = sotest::cli({"peer", "add", c.public_key, "--name", "hn", "--perm", "rw", "-c", s.config_file});
    CHECK_EQ(r.rc, 0);
    auto l = sotest::cli({"peer", "list", "--json", "-c", s.config_file});
    CHECK(l.out.find(c.public_key) != std::string::npos);
}

TEST(qs_client_rejects_bad_input_and_writes_nothing) {
    Tmp t;
    fs::create_directories(fs::u8path(t.s("data")));
    QuickClientOptions co;
    co.server = "host:5656";
    co.server_key = "not-a-key";
    co.dir = t.s("data");
    CHECK_THROWS(quick_client(co));
    CHECK(!fs::exists(fs::u8path(default_quick_config_dir(co.dir))));
    co.server_key = std::string(64, 'a');
    co.server = "host:70000";
    CHECK_THROWS(quick_client(co));
    co.server = "host:5656";
    co.dir = t.s("nope");                                         // the folder must exist
    CHECK_THROWS(quick_client(co));
}

TEST(qs_parse_host_port) {
    std::string h;
    uint16_t p = 0;
    parse_host_port("a.example.com:6000", h, p);
    CHECK_EQ(h, std::string("a.example.com"));
    CHECK_EQ(p, uint16_t(6000));
    parse_host_port("a.example.com", h, p);
    CHECK_EQ(p, uint16_t(5656));
    parse_host_port("[::1]:7000", h, p);
    CHECK_EQ(h, std::string("::1"));
    CHECK_EQ(p, uint16_t(7000));
    CHECK_THROWS(parse_host_port("", h, p));
    CHECK_THROWS(parse_host_port(":5656", h, p));
    CHECK_THROWS(parse_host_port("h:0", h, p));
    CHECK_THROWS(parse_host_port("h:abc", h, p));
    CHECK_THROWS(parse_host_port("h\"x:1", h, p));
}

TEST(qs_cli_json_and_exit_codes_and_no_secret_in_output) {
    Tmp t;
    auto a = sotest::cli({"quick-server", "--dir", t.s("share"), "--port", "6055", "--json", "--changed-exit"});
    CHECK_EQ(a.rc, 10);                                           // something changed
    CHECK(a.out.find("\"role\":\"server\"") != std::string::npos);
    CHECK(a.out.find("\"pairing\":\"off\"") != std::string::npos);
    CHECK(a.out.find("\"port\":6055") != std::string::npos);
    CHECK(a.out.find("\"changed\":true") != std::string::npos);
    CHECK(a.out.find("\"client_snippet\":") != std::string::npos);
    CHECK(a.out.find("\"peer_add_command\":") != std::string::npos);
    CHECK_EQ(a.out.back(), '\n');
    std::string key_file = default_quick_config_dir(t.s("share")) + "/server.key";
    std::string secret = trim_nl(slurp(fs::u8path(key_file)));
    CHECK_EQ(secret.size(), size_t(64));
    CHECK(a.out.find(secret) == std::string::npos);               // the private key is never printed
    CHECK(a.err.find(secret) == std::string::npos);
    auto b = sotest::cli({"quick-server", "--dir", t.s("share"), "--json", "--changed-exit"});
    CHECK_EQ(b.rc, 0);                                            // nothing to change
    CHECK(b.out.find("\"changed\":false") != std::string::npos);
    CHECK(b.out.find("\"key_existed\":true") != std::string::npos);
    // human text: same guarantees
    auto h = sotest::cli({"quick-server", "--dir", t.s("share")});
    CHECK_EQ(h.rc, 0);
    CHECK(h.out.find("already there, kept") != std::string::npos);
    CHECK(h.out.find(secret) == std::string::npos);
    CHECK(h.out.find("pairing: off") != std::string::npos);
    // wrong arguments
    CHECK_EQ(sotest::cli({"quick-server"}).rc, 2);
    CHECK_EQ(sotest::cli({"quick-server", "--dir", t.s("x"), "--port", "0"}).rc, 2);
    CHECK_EQ(sotest::cli({"quick-client", "--dir", t.s("x")}).rc, 2);
}

TEST(qs_cli_client_json) {
    Tmp t;
    auto s = sotest::cli({"quick-server", "--dir", t.s("share"), "--json"});
    CHECK_EQ(s.rc, 0);
    QuickResult sr = quick_server(QuickServerOptions{t.s("share"), "", 5656, "", false});
    fs::create_directories(fs::u8path(t.s("data")));
    auto c = sotest::cli({"quick-client", "--server", "srv:5656", "--server-key", sr.public_key, "--dir", t.s("data"), "--json"});
    CHECK_EQ(c.rc, 0);
    CHECK(c.out.find("\"role\":\"client\"") != std::string::npos);
    CHECK(c.out.find("\"server\":\"srv:5656\"") != std::string::npos);
    std::string secret = trim_nl(slurp(fs::u8path(default_quick_config_dir(t.s("data")) + "/client.key")));
    CHECK(c.out.find(secret) == std::string::npos);
    auto bad = sotest::cli({"quick-client", "--server", "srv:5656", "--server-key", "zz", "--dir", t.s("data")});
    CHECK_EQ(bad.rc, 2);
}

TEST(qs_config_inside_root_refused_case_insensitively_and_force_keeps_key_path) {
    Tmp t;
    QuickServerOptions o;
    o.dir = t.s("Share");
    o.config_dir = t.s("Share") + "/cfg";
    CHECK_THROWS(quick_server(o));
#ifdef _WIN32
    o.config_dir = t.s("share") + "/cfg";   // other case, same folder on Windows
    CHECK_THROWS(quick_server(o));
#endif
    // --force reuses the key location of the old configuration (same server identity)
    QuickServerOptions p;
    p.dir = t.s("s3");
    QuickResult a = quick_server(p);
    p.force = true;
    QuickResult b = quick_server(p);
    CHECK_EQ(a.public_key, b.public_key);
    CHECK_EQ(a.key_file, b.key_file);
}

TEST(qs_json_escapes_non_ascii_and_invalid_utf8) {
    QuickResult r;
    r.role = "server";
    r.dir = "/d/T\xC3\xA0i-li\xE1\xBB\x87u/\xF0\x9F\x98\x80/bad\xFF" "x/trunc\xE1\xBB";
    std::string j = quick_result_json(r);
    for (unsigned char c : j) CHECK(c < 0x80);                       // pure ASCII
    CHECK(j.find("T\\u00e0i-li\\u1ec7u") != std::string::npos);
    CHECK(j.find("\\ud83d\\ude00") != std::string::npos);            // surrogate pair
    CHECK(j.find("bad\\ufffdx") != std::string::npos);               // invalid byte
    CHECK(j.find("trunc\\ufffd\\ufffd") != std::string::npos);       // truncated sequence
}

TEST(qs_refuses_link_or_junction_on_the_way) {
    Tmp t;
    fs::create_directories(fs::u8path(t.s("real")));
    std::string link = t.s("lnk");
#ifdef _WIN32
    std::string cmd = "mklink /J \"" + fs::u8path(link).make_preferred().string() + "\" \"" + fs::u8path(t.s("real")).make_preferred().string() + "\" >nul 2>&1";
    if (std::system(cmd.c_str()) != 0) return;                        // cannot make a junction here: nothing to test
#else
    // As root the link is root-owned, and a root-owned link in an ANCESTOR is trusted by design (linkcheck: /home ->
    // /var/home); the refusal of such a link only shows for an ordinary user.
    if (::geteuid() == 0) return;
    std::error_code ec;
    fs::create_directory_symlink(fs::u8path(t.s("real")), fs::u8path(link), ec);
    if (ec) return;
#endif
    QuickServerOptions o;
    o.dir = t.s("share");
    o.config_dir = link + "/cfg";
    CHECK_THROWS(quick_server(o));
    CHECK(!fs::exists(fs::u8path(t.s("real/cfg"))));
    QuickServerOptions p;
    p.dir = link + "/share";                                          // the shared folder behind a link
    CHECK_THROWS(quick_server(p));
}

// GUI "add client" runs the same trust guard as `mysync peer add`: a server.toml reached through a link is refused,
// and nothing is written.
#include "i18n_model.h"
#include "server_wizard_model.h"
TEST(qs_gui_add_client_runs_the_trust_guard) {
    Tmp t;
    QuickResult r = quick_server(QuickServerOptions{t.s("share"), "", 5656, "", false});
    std::string lnk = t.s("link.toml");
    std::error_code ec;
    fs::create_symlink(fs::u8path(r.config_file), fs::u8path(lnk), ec);
    if (ec) return;   // no right to create symbolic links here
    std::string hex = key_to_hex(generate_keypair().pub);
    gui::AddClientOutcome o = gui::add_client(lnk, "may-a", hex, false);
    CHECK(!o.ok);
    CHECK(o.message.find("link") != std::string::npos);
    auto cli = sotest::cli({"peer", "add", hex, "--name", "may-a", "--perm", "rw", "-c", lnk});
    CHECK(cli.rc != 0);                                       // the CLI refuses the same file
    CHECK(peer_list(r.config_file).empty());
    gui::AddClientOutcome good = gui::add_client(r.config_file, "may-a", hex, false);   // the real file still works
    CHECK(good.ok);
}

TEST(qs_vietnamese_snippet_loads_and_gui_messages_follow_language) {
    // core: Vietnamese comments are still valid TOML
    std::string vi = make_client_snippet("host.example", 5656, std::string(64, 'a'), "may-a", true);
    CHECK(vi.find("thay b\xE1\xBA\xB1ng") != std::string::npos);
    CHECK_EQ(parse_client_config_text(vi).watches[0].targets[0].host, std::string("host.example"));
    std::string en = make_client_snippet("host.example", 5656, std::string(64, 'a'), "may-a", false);
    CHECK(en.find("replace with the folder") != std::string::npos);
    // CLI result stays English
    Tmp t;
    CHECK(quick_server(QuickServerOptions{t.s("a"), "", 5656, "", false}).client_snippet.find("replace with the folder") != std::string::npos);
    // GUI in Vietnamese: snippet comments and the add-client sentence are Vietnamese, the snippet loads
    gui::set_lang(gui::Lang::Vi);
    QuickResult r = gui::create_server(t.s("b"), 5700);
    CHECK(r.client_snippet.find("thay b\xE1\xBA\xB1ng") != std::string::npos);
    CHECK_EQ(parse_client_config_text(r.client_snippet).watches[0].targets[0].port, uint16_t(5700));
    std::string hex = key_to_hex(generate_keypair().pub);
    gui::AddClientOutcome o = gui::add_client(r.config_file, "may-a", hex, false);
    CHECK(o.ok);
    CHECK(o.message.find("peer '") == std::string::npos);
    CHECK(o.message.find("\xC4\x91\xC3\xA3 th\xC3\xAA" "m") != std::string::npos);   // "đã thêm"
    gui::set_lang(gui::Lang::En);
    gui::AddClientOutcome o2 = gui::add_client(r.config_file, "may-a", hex, false);
    CHECK(o2.message.find("unchanged") != std::string::npos);
}

TEST(qs_make_folder_private_removes_other_writers_and_new_folders_start_private) {
    Tmp t;
    std::string d = t.s("open");
    fs::create_directories(fs::u8path(d));
#ifdef _WIN32
    // what a folder on D:\ typically inherits: BUILTIN\Users may write
    std::string cmd = "icacls \"" + fs::u8path(d).make_preferred().string() + "\" /grant *S-1-5-32-545:(OI)(CI)M >nul 2>&1";
    if (std::system(cmd.c_str()) != 0) return;   // cannot set up the case here: nothing to test
#else
    ::chmod(fs::u8path(d).c_str(), 0777);
#endif
    CHECK(!gui::untrusted_writer_reason(d, {}).empty());
    make_folder_private(d);
    CHECK_EQ(gui::untrusted_writer_reason(d, {}), std::string());
    // a shared / configuration folder that quick_server creates is private from the start
    QuickResult r = quick_server(QuickServerOptions{t.s("open/nhan"), "", 5656, "", false});
    CHECK(r.dir_created);
    CHECK_EQ(gui::untrusted_writer_reason(r.dir, {}), std::string());
    CHECK_EQ(gui::untrusted_writer_reason(r.config_dir, {}), std::string());
    // --fix-permissions on an existing open folder makes it private, and running again changes nothing
    std::string e = t.s("existing");
    fs::create_directories(fs::u8path(e));
#ifdef _WIN32
    std::string cmd2 = "icacls \"" + fs::u8path(e).make_preferred().string() + "\" /grant *S-1-5-32-545:(OI)(CI)M >nul 2>&1";
    CHECK(std::system(cmd2.c_str()) == 0);
#else
    ::chmod(fs::u8path(e).c_str(), 0777);
#endif
    QuickServerOptions o{e, "", 5656, "", false};
    o.fix_permissions = true;
    quick_server(o);
    CHECK_EQ(gui::untrusted_writer_reason(e, {}), std::string());
}
