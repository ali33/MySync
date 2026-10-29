// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// ConfigEditor: canonical serialisation, round trips, atomic writes, hand-edit detection, backups.
#include <filesystem>
#include <fstream>
#include <sstream>

#include "mysync/gui/config_io.h"
#include "mysync/keys.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {

struct GuiTmp {
    fs::path p;
    GuiTmp() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-guicfg-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~GuiTmp() {
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

void spit(const std::string& path, const std::string& text) {
    std::ofstream f(fs::u8path(path), std::ios::binary | std::ios::trunc);
    f << text;
}

std::string example(const char* name) { return slurp(std::string(MYSYNC_SOURCE_DIR) + "/examples/" + name); }

bool same_server(const ServerConfig& a, const ServerConfig& b) { return serialize_server_config(a) == serialize_server_config(b); }
bool same_client(const ClientConfig& a, const ClientConfig& b) { return serialize_client_config(a) == serialize_client_config(b); }

bool any_tmp_left(const fs::path& dir) {
    for (const auto& e : fs::directory_iterator(dir))
        if (e.path().filename().u8string().find(".tmp-") != std::string::npos) return true;
    return false;
}

}  // namespace

TEST(gui_config_server_example_round_trips) {
    std::string text = example("server.toml");
    CHECK(!text.empty());
    ServerConfig a = parse_server_config_text(text);
    std::string out = serialize_server_config(a);
    ServerConfig b = parse_server_config_text(out);
    CHECK(same_server(a, b));
    CHECK_EQ(out, serialize_server_config(b));  // canonical: a fixed point
    CHECK_EQ(b.port, a.port);
    CHECK_EQ(b.max_file_size, a.max_file_size);
    CHECK_EQ(b.max_trash_bytes, a.max_trash_bytes);
    CHECK_EQ(b.file_mode, a.file_mode);
    CHECK_EQ(b.dir_mode, a.dir_mode);
    CHECK_EQ(b.clients.size(), a.clients.size());
    CHECK_EQ(b.clients[0].prefix, a.clients[0].prefix);
    CHECK_EQ(b.clients[0].max_write_bytes_per_hour, a.clients[0].max_write_bytes_per_hour);
    CHECK(b.clients[0].public_key == a.clients[0].public_key);
    CHECK(b.allow == a.allow);
    CHECK(out.find("[control]") != std::string::npos);
}

TEST(gui_config_client_example_round_trips) {
    std::string text = example("client.toml");
    CHECK(!text.empty());
    ClientConfig a = parse_client_config_text(text);
    std::string out = serialize_client_config(a);
    ClientConfig b = parse_client_config_text(out);
    CHECK(same_client(a, b));
    CHECK_EQ(out, serialize_client_config(b));
    CHECK_EQ(b.watches.size(), a.watches.size());
    CHECK_EQ(b.watches[0].targets.size(), size_t(2));
    CHECK(b.watches[0].targets[0].server_key == a.watches[0].targets[0].server_key);
    CHECK(b.watches[0].targets[1].is_local());
    CHECK(b.watches[0].filter.include == a.watches[0].filter.include);
    CHECK_EQ(b.watches[0].filter.size_max, a.watches[0].filter.size_max);
    CHECK(b.compress_skip_ext == a.compress_skip_ext);
    CHECK(b.watches[0].schedule_at == a.watches[0].schedule_at);
}

TEST(gui_config_awkward_strings_survive) {
    ServerConfig a = parse_server_config_text(example("server.toml"));
    a.root = "D:\\dữ liệu\\\"quote\" 'single' \t tab";
    a.clients[0].name = "máy \"1\" \\ \u00e9";
    ServerConfig b = parse_server_config_text(serialize_server_config(a));
    CHECK_EQ(b.root, a.root);
    CHECK_EQ(b.clients[0].name, a.clients[0].name);
}

TEST(gui_config_control_table_round_trips) {
    ServerConfig a = parse_server_config_text(example("server.toml"));
    CHECK(a.control_enabled);
    a.control_enabled = false;
    a.control_allow = {"S-1-5-21-1-2-3-1001", "CORP\\an"};
    a.control_group = "mysync";
    a.control_name = "my-svc";
    ServerConfig b = parse_server_config_text(serialize_server_config(a));
    CHECK(!b.control_enabled);
    CHECK(b.control_allow == a.control_allow);
    CHECK_EQ(b.control_group, std::string("mysync"));
    CHECK_EQ(b.control_name, std::string("my-svc"));
    ClientConfig c = parse_client_config_text(example("client.toml") + "\n[control]\nenabled = true\nallow = [\"S-1-5-21-9-9-9-9\"]\nname = \"x\"\n");
    CHECK(c.control_enabled);
    CHECK_EQ(c.control_allow.size(), size_t(1));
    CHECK_EQ(c.control_name, std::string("x"));
    CHECK_THROWS(parse_client_config_text(example("client.toml") + "\n[control]\nbogus = 1\n"));
    CHECK_THROWS(parse_client_config_text(example("client.toml") + "\n[control]\nname = \"../x\"\n"));
    CHECK_THROWS(parse_server_config_text(example("server.toml") + "\n[control]\nallow = [\"a\\\"b\"]\n"));
}

TEST(gui_config_editor_edit_save_reload) {
    GuiTmp t;
    std::string path = t.file("server.toml");
    spit(path, example("server.toml"));
    ConfigEditor ed = ConfigEditor::open(path);
    CHECK(ed.role() == ConfigRole::Server);
    CHECK(!ed.dirty());
    CHECK(!ed.changed_on_disk());
    ed.server().max_connections = 77;
    ed.server().trash = false;
    CHECK(ed.dirty());
    ed.save();
    CHECK(!ed.dirty());
    CHECK(!any_tmp_left(t.p));
    ConfigEditor again = ConfigEditor::open(path);
    CHECK_EQ(again.server().max_connections, 77u);
    CHECK(!again.server().trash);
    CHECK_THROWS(again.client());
    // the previous version is kept, comments and all
    CHECK(fs::exists(fs::u8path(path + ".bak")));
    CHECK_EQ(slurp(path + ".bak"), example("server.toml"));
    CHECK(slurp(path).find("max_connections = 77") != std::string::npos);
    // a second save keeps the file the editor wrote as the new backup
    ed.server().max_connections = 78;
    ed.save();
    CHECK(slurp(path + ".bak").find("max_connections = 77") != std::string::npos);
    ed.reload();
    CHECK_EQ(ed.server().max_connections, 78u);
}

TEST(gui_config_hand_edit_is_never_overwritten) {
    GuiTmp t;
    std::string path = t.file("client.toml");
    spit(path, example("client.toml"));
    ConfigEditor ed = ConfigEditor::open(path);
    ed.client().connections = 9;
    // someone edits the file by hand after the editor read it
    spit(path, example("client.toml") + "\n# hand edit\n");
    CHECK(ed.changed_on_disk());
    std::string before = slurp(path);
    bool threw = false;
    try {
        ed.save();
    } catch (const Error& e) {
        threw = true;
        CHECK(std::string(e.what()).find("changed on disk") != std::string::npos);
    }
    CHECK(threw);
    CHECK_EQ(slurp(path), before);
    CHECK(!fs::exists(fs::u8path(path + ".bak")));
    // explicit force writes anyway (and still backs up the hand-edited file)
    SaveOptions force;
    force.force = true;
    ed.save(force);
    CHECK(slurp(path + ".bak").find("# hand edit") != std::string::npos);
    CHECK(slurp(path).find("connections = 9") != std::string::npos);
    // a deleted file counts as a change too
    fs::remove(fs::u8path(path));
    CHECK(ed.changed_on_disk());
    CHECK_THROWS(ed.save());
}

TEST(gui_config_invalid_edit_is_not_written) {
    GuiTmp t;
    std::string path = t.file("server.toml");
    spit(path, example("server.toml"));
    ConfigEditor ed = ConfigEditor::open(path);
    ed.server().port = 0;           // out of range for the parser
    std::string before = slurp(path);
    bool threw = false;
    try {
        ed.save();
    } catch (const Error& e) {
        threw = true;
        CHECK(std::string(e.what()).find("not valid") != std::string::npos);
    }
    CHECK(threw);
    CHECK_EQ(slurp(path), before);
    CHECK(!any_tmp_left(t.p));
    ed.server().port = 5656;
    ed.server().clients.clear();    // a server needs at least one client
    CHECK_THROWS(ed.validate());
    ed.reload();
    CHECK_EQ(ed.server().port, uint16_t(5656));
}

TEST(gui_config_parse_errors_carry_the_line) {
    GuiTmp t;
    std::string path = t.file("bad.toml");
    spit(path, "[server]\nroot = \"/x\"\nkey_file = \"k\"\nbogus_key = 1\n");
    bool threw = false;
    try {
        ConfigEditor::open(path);
    } catch (const Error& e) {
        threw = true;
        std::string m = e.what();
        CHECK(m.find("bogus_key") != std::string::npos);
        CHECK(m.find("line 4") != std::string::npos);
        CHECK(m.find("bad.toml") != std::string::npos);
    }
    CHECK(threw);
    CHECK_THROWS(ConfigEditor::open(t.file("missing.toml")));
    spit(path, "[server]\nroot=\"/x\"\n[client]\nkey_file=\"k\"\n");
    CHECK_THROWS(ConfigEditor::detect_role("[server]\n[[watch]]\n"));
    CHECK_THROWS(ConfigEditor::detect_role("a = 1\n"));
    CHECK(ConfigEditor::detect_role("[client]\n") == ConfigRole::Client);
    CHECK(ConfigEditor::detect_role("[[client]]\n") == ConfigRole::Server);
}

TEST(gui_config_create_new_file) {
    GuiTmp t;
    std::string path = t.file("sub/new.toml");
    ConfigEditor ed = ConfigEditor::create(path, ConfigRole::Server);
    CHECK(ed.dirty());
    CHECK_THROWS(ed.save());  // no root / key / client yet
    ed.server().root = "/srv/x";
    ed.server().key_file = "/etc/mysync/server.key";
    ClientAcl a;
    a.name = "c1";
    a.public_key = generate_keypair().pub;
    ed.server().clients.push_back(a);
    ed.save();
    CHECK(fs::exists(fs::u8path(path)));
    CHECK(!fs::exists(fs::u8path(path + ".bak")));
    ConfigEditor back = ConfigEditor::open(path);
    CHECK_EQ(back.server().clients[0].name, std::string("c1"));
    // creating over an existing file that this editor did not read is refused
    ConfigEditor other = ConfigEditor::create(path, ConfigRole::Server);
    other.server() = back.server();
    CHECK_THROWS(other.save());
}

TEST(gui_config_atomic_write_helper) {
    GuiTmp t;
    std::string p = t.file("f.txt");
    write_file_atomic(p, "one");
    CHECK_EQ(slurp(p), std::string("one"));
    write_file_atomic(p, std::string(200000, 'x'));
    CHECK_EQ(slurp(p).size(), size_t(200000));
    CHECK(!any_tmp_left(t.p));
    CHECK_EQ(file_content_hash(t.file("nope")), std::string());
    CHECK_EQ(file_content_hash(p).size(), size_t(64));
}

#ifndef _WIN32
TEST(gui_config_save_keeps_posix_permissions) {
    GuiTmp t;
    std::string path = t.file("server.toml");
    spit(path, example("server.toml"));
    fs::permissions(fs::u8path(path), fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read);
    ConfigEditor ed = ConfigEditor::open(path);
    ed.server().max_connections = 5;
    ed.save();
    auto perm = fs::status(fs::u8path(path)).permissions();
    CHECK((perm & fs::perms::others_read) == fs::perms::none);
    CHECK((perm & fs::perms::group_read) != fs::perms::none);
    auto bperm = fs::status(fs::u8path(path + ".bak")).permissions();
    CHECK((bperm & fs::perms::others_read) == fs::perms::none);
}
#endif
