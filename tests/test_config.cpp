// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include <filesystem>
#include <fstream>

#include "mysync/config.h"
#include "mysync/util.h"
#include "testing.h"

namespace fs = std::filesystem;
using namespace mysync;

namespace {

struct TmpDir {
    fs::path p;
    TmpDir() {
        uint8_t r[6];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-test-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~TmpDir() { std::error_code ec; fs::remove_all(p, ec); }
};

const std::string K1(64, '1');
const std::string K2(64, '2');
const std::string K3(64, '3');

std::string err_of(const std::string& text, bool server) {
    try {
        if (server) parse_server_config_text(text);
        else parse_client_config_text(text);
    } catch (const Error& e) {
        return e.what();
    }
    return "";
}

// minimal valid server file head
std::string srv(const std::string& extra = "") {
    return "root='r'\nkey_file='k'\n" + extra + "[[client]]\nname='c1'\npublic_key='" + K1 + "'\n";
}

} // namespace

TEST(config_server_defaults_and_values) {
    ServerConfig c = parse_server_config_text(
        "# comment\n"
        "root = '/srv/data'   # trailing\n"
        "key_file = \"/etc/mysync/server.key\"\n"
        "port = 6_000\n"
        "allow = [\"10.0.0.0/8\",\n   \"192.168.1.5\", # inline\n]\n"
        "max_file_size = \"1.5GB\"\n"
        "[[client]]\nname = 'ketoan'\npublic_key = '" + K1 + "'\naccess = 'ro'\nprefix = 'kt\\2026/'\n"
        "[[client]]\npublic_key = '" + K2 + "'\n");
    CHECK_EQ(c.root, std::string("/srv/data"));
    CHECK_EQ(c.port, 6000);
    CHECK_EQ(c.bind, std::string("*"));
    CHECK_EQ(c.max_connections, 20u);
    CHECK_EQ(c.max_auth_failures_per_min, 10u);
    CHECK(c.trash);
    CHECK_EQ(c.allow.size(), size_t(2));
    CHECK_EQ(c.max_file_size, uint64_t(1610612736));
    CHECK_EQ(c.io_timeout_s, 60u);
    CHECK_EQ(c.clients.size(), size_t(2));
    CHECK_EQ(c.clients[0].name, std::string("ketoan"));
    CHECK(c.clients[0].read_only);
    CHECK_EQ(c.clients[0].prefix, std::string("kt/2026"));
    CHECK_EQ(c.clients[0].public_key[0], 0x11);
    CHECK(!c.clients[1].read_only);
    CHECK_EQ(c.clients[1].prefix, std::string(""));
    CHECK_EQ(c.clients[1].name, std::string("client2"));

    ServerConfig d = parse_server_config_text("[server]\nroot='r'\nkey_file='k'\n[[client]]\npublic_key='" + K1 + "'\n");
    CHECK_EQ(d.allow.size(), size_t(1));
    CHECK_EQ(d.allow[0], std::string("*"));
}

TEST(config_server_errors) {
    CHECK(err_of("root='r'\n[[client]]\npublic_key='" + K1 + "'\n", true).find("key_file") != std::string::npos);
    CHECK(err_of("root='r'\nkey_file='k'\n", true).find("[[client]]") != std::string::npos);
    CHECK_EQ(err_of(srv("bogus = 1\n"), true), std::string("unknown key 'bogus' at line 3"));
    CHECK(err_of(srv("port = 70000\n"), true).find("line 3") != std::string::npos);
    CHECK(err_of(srv("port = 0\n"), true).find("out of range") != std::string::npos);
    CHECK(err_of(srv("port = 1\nport = 2\n"), true).find("duplicate key 'port' at line 4") != std::string::npos);
    CHECK(err_of(srv("log_level='loud'\n"), true).find("log_level") != std::string::npos);
    CHECK(err_of(srv("root = oops\n"), true).find("line 3") != std::string::npos);
    CHECK(err_of(srv() + "[nope]\n", true).find("unknown table") != std::string::npos);
    CHECK(err_of("root=\"C:\\data\"\nkey_file='k'\n", true).find("invalid escape") != std::string::npos);
    CHECK(err_of(srv("allow=['not an ip']\n"), true).find("allow") != std::string::npos);
    // client ACL
    CHECK(err_of("root='r'\nkey_file='k'\n[[client]]\nname='x'\n", true).find("public_key") != std::string::npos);
    CHECK(err_of("root='r'\nkey_file='k'\n[[client]]\npublic_key='abc'\n", true).find("line 4") != std::string::npos);
    CHECK(err_of(srv() + "[[client]]\npublic_key='" + K1 + "'\nname='c2'\n", true).find("repeats") != std::string::npos);
    CHECK(err_of(srv() + "[[client]]\nname='c1'\npublic_key='" + K2 + "'\n", true).find("duplicate client name") != std::string::npos);
    CHECK(err_of(srv() + "[[client]]\nname='c2'\npublic_key='" + K2 + "'\naccess='rwx'\n", true).find("access") != std::string::npos);
    CHECK(err_of(srv() + "[[client]]\nname='c2'\npublic_key='" + K2 + "'\nprefix='../x'\n", true).find("prefix") != std::string::npos);
    CHECK(err_of(srv() + "[[client]]\nname='c2'\npublic_key='" + K2 + "'\nprefix='/abs'\n", true).find("prefix") != std::string::npos);
    CHECK(err_of(srv() + "[[client]]\nname='c2'\npublic_key='" + K2 + "'\nsecret='x'\n", true).find("unknown key 'secret'") != std::string::npos);
}

TEST(config_string_escapes) {
    ServerConfig c = parse_server_config_text(
        "root = \"a\\\\b\\\"c\\n\\t\\u00e1\\u1EA1\"\nkey_file = 'k\\n'\n[[client]]\npublic_key='" + K1 + "'\n");
    CHECK_EQ(c.root, std::string("a\\b\"c\n\t\xC3\xA1\xE1\xBA\xA1"));
    CHECK_EQ(c.key_file, std::string("k\\n"));
}

TEST(config_client_full) {
    ClientConfig c = parse_client_config_text(
        "connections = 8\ncompress = \"none\"\nlog_level = \"debug\"\nkey_file = 'client.key'\n"
        "[[watch]]\n"
        "name = \"docs\"\npath = 'D:\\Docs'\nquiet_ms = 250\nschedule_at = [\"01:00\", \"13:30\"]\n"
        "[watch.filter]\n"
        "include = [\".txt\", \"*.docx\"]\nexclude = [\"backup\"]\nsize_max = \"10MB\"\nmtime_after = \"7d\"\n"
        "[[watch.target]]\nhost = \"10.0.0.2\"\nserver_key = '" + K2 + "'\nremote_prefix = \"docs\"\n"
        "[[watch.target]]\nhost = \"10.0.0.3\"\nport = 7000\nserver_key = '" + K3 + "'\nkey_file = 'other.key'\n"
        "[[watch.target]]\npath = 'E:\\Backup\\docs'\n"
        "[[watch]]\npath = \"/data\"\n[[watch.target]]\npath = '\\\\nas\\share\\x'\n");
    CHECK_EQ(c.connections, 8u);
    CHECK_EQ(c.compress, std::string("none"));
    CHECK_EQ(c.key_file, std::string("client.key"));
    CHECK_EQ(c.watches.size(), size_t(2));
    const WatchConfig& w = c.watches[0];
    CHECK_EQ(w.name, std::string("docs"));
    CHECK_EQ(w.path, std::string("D:\\Docs"));
    CHECK_EQ(w.quiet_ms, 250u);
    CHECK_EQ(w.schedule_at.size(), size_t(2));
    CHECK_EQ(w.filter.include.size(), size_t(2));
    CHECK_EQ(w.filter.size_max, std::string("10MB"));
    CHECK_EQ(w.targets.size(), size_t(3));
    CHECK(!w.targets[0].is_local());
    CHECK_EQ(w.targets[0].remote_prefix, std::string("docs"));
    CHECK_EQ(w.targets[0].port, 5656);
    CHECK_EQ(w.targets[0].server_key[0], 0x22);
    CHECK_EQ(w.targets[1].port, 7000);
    CHECK_EQ(w.targets[1].key_file, std::string("other.key"));
    CHECK(w.targets[2].is_local());
    CHECK_EQ(w.targets[2].path, std::string("E:\\Backup\\docs"));
    CHECK(w.recursive);
    CHECK_EQ(w.periodic_scan_s, 300u);
    CHECK_EQ(c.watches[1].name, std::string("/data"));
    CHECK_EQ(c.watches[1].quiet_ms, 300u);
    CHECK(c.watches[1].targets[0].is_local());
    CHECK_EQ(c.watches[1].targets[0].path, std::string("\\\\nas\\share\\x"));
}

TEST(config_client_defaults_and_skip_ext) {
    ClientConfig c = parse_client_config_text("");
    CHECK_EQ(c.watches.size(), size_t(0));
    bool zip = false, pdf = false;
    for (const auto& e : c.compress_skip_ext) {
        zip = zip || e == ".zip";
        pdf = pdf || e == ".pdf";
    }
    CHECK(zip && pdf);
    CHECK_EQ(c.compress_skip_ext.size(), size_t(21));
    ClientConfig d = parse_client_config_text("compress_skip_ext = ['.abc']\n");
    CHECK_EQ(d.compress_skip_ext.size(), size_t(1));
}

TEST(config_client_errors) {
    const std::string tgt = "[[watch.target]]\nhost='h'\nserver_key='" + K1 + "'\n";
    CHECK(err_of("connections = 65\n", false).find("out of range") != std::string::npos);
    CHECK(err_of("connections = 0\n", false).find("out of range") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n", false).find("no [[watch.target]]") != std::string::npos);
    // network target needs server_key and a secret key somewhere
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.target]]\nhost='h'\n", false).find("server_key") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n" + tgt, false).find("no key_file") != std::string::npos);
    CHECK(err_of("key_file='k'\n[[watch]]\npath='p'\n" + tgt, false).empty());
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.target]]\nhost='h'\nserver_key='zz'\nkey_file='k'\n", false).find("line 5") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.target]]\n", false).find("either 'path'") != std::string::npos);
    // local target: no key requirement, but no network keys allowed
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.target]]\npath='/mnt/x'\n", false).empty());
    CHECK_EQ(err_of("[[watch]]\npath='p'\n[[watch.target]]\npath='/mnt/x'\nhost='h'\n", false),
             std::string("target has both 'path' and 'host' (a target is either local or network) at line 5"));
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.target]]\npath='/mnt/x'\nkey_file='k'\n", false).find("line 5") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.target]]\npath='/mnt/x'\nserver_key='" + K1 + "'\n", false).find("both") != std::string::npos);
    CHECK(err_of("[[watch.target]]\nhost='h'\n", false).find("line 1") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\ncolour='x'\n", false) == "unknown key 'colour' at line 3");
    CHECK(err_of("[[watch]]\npath='p'\nschedule_at=['25:00']\n", false).find("HH:MM") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n[watch.filter]\nexclude_regex=['(']\n[[watch.target]]\npath='x'\n", false)
              .find("regular expression") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n[watch.filter]\nsize_max='10XB'\n", false).find("line 4") != std::string::npos);
    CHECK(err_of("compress='zip'\n", false).find("compress") != std::string::npos);
    CHECK(err_of("[[watch]]\npath='p'\n[[watch.ftp]]\n", false).find("unknown table") != std::string::npos);
}

TEST(config_public_key_hex) {
    PublicKey k = parse_public_key_hex(std::string(62, 'a') + "0F");
    CHECK_EQ(k[0], 0xaa);
    CHECK_EQ(k[31], 0x0F);
    CHECK_THROWS(parse_public_key_hex(std::string(63, 'a')));
    CHECK_THROWS(parse_public_key_hex(std::string(65, 'a')));
    CHECK_THROWS(parse_public_key_hex(std::string(63, 'a') + "g"));
    CHECK_THROWS(parse_public_key_hex(""));
}

TEST(config_secret_key_file) {
    TmpDir d;
    std::string hex(64, 'a');
    hex[3] = 'F';
    auto write = [&](const std::string& name, const std::string& content) {
        fs::path f = d.p / name;
        std::ofstream o(f, std::ios::binary);
        o << content;
        o.close();
#ifndef _WIN32
        fs::permissions(f, fs::perms::owner_read | fs::perms::owner_write);
#endif
        return f.u8string();
    };
    Bytes k = load_secret_key_file(write("ok.key", hex + "\n"));
    CHECK_EQ(k.size(), size_t(32));
    CHECK_EQ(k[0], 0xaa);
    CHECK_EQ(k[1], 0xaF);

    CHECK_THROWS(load_secret_key_file(write("short.key", std::string(62, 'a'))));
    CHECK_THROWS(load_secret_key_file(write("long.key", std::string(66, 'a'))));
    CHECK_THROWS(load_secret_key_file(write("bad.key", std::string(63, 'a') + "z")));
    CHECK_THROWS(load_secret_key_file((d.p / "missing.key").u8string()));
    std::string secret(64, '7');
    std::string msg;
    try { load_secret_key_file(write("bad2.key", secret + "00")); } catch (const Error& e) { msg = e.what(); }
    CHECK(!msg.empty());
    CHECK(msg.find(secret) == std::string::npos);
#ifndef _WIN32
    std::string open_key = write("open.key", std::string(64, 'a'));
    fs::permissions(open_key, fs::perms::owner_read | fs::perms::group_read);
    CHECK_THROWS(load_secret_key_file(open_key));
#endif
}

TEST(config_load_from_file_mentions_path) {
    TmpDir d;
    fs::path f = d.p / "server.toml";
    { std::ofstream o(f); o << srv("zzz=1\n"); }
    std::string msg;
    try { load_server_config(f.u8string()); } catch (const Error& e) { msg = e.what(); }
    CHECK(msg.find("server.toml") != std::string::npos);
    CHECK(msg.find("unknown key 'zzz' at line 3") != std::string::npos);
    CHECK_THROWS(load_client_config((d.p / "nope.toml").u8string()));
}


TEST(config_server_limits_modes_and_defaults) {
    ServerConfig d = parse_server_config_text(srv());
    CHECK_EQ(d.max_file_size, uint64_t(10) << 30);
    CHECK_EQ(d.max_trash_bytes, uint64_t(10) << 30);
    CHECK_EQ(d.file_mode, 0640u);
    CHECK_EQ(d.dir_mode, 0750u);
    CHECK_EQ(d.clients[0].max_sessions, 4u);
    CHECK_EQ(d.clients[0].max_write_bytes_per_hour, uint64_t(50) << 30);

    ServerConfig c = parse_server_config_text(
        "[server]\nroot='r'\nkey_file='k'\nmax_trash_bytes = \"2GB\"\nmax_file_size = 0\n"
        "file_mode = \"0600\"\ndir_mode = '0700'\n"
        "[[client]]\nname='a'\npublic_key='" + K1 + "'\nmax_sessions = 9\nmax_write_bytes_per_hour = \"1.5GB\"\n"
        "[[client]]\nname='b'\npublic_key='" + K2 + "'\nmax_write_bytes_per_hour = 12345\n"
        "[[client]]\nname='c'\npublic_key='" + K3 + "'\nmax_write_bytes_per_hour = 0\n");
    CHECK_EQ(c.max_trash_bytes, uint64_t(2) << 30);
    CHECK_EQ(c.max_file_size, uint64_t(0));  // explicit 0 = unlimited
    CHECK_EQ(c.file_mode, 0600u);
    CHECK_EQ(c.dir_mode, 0700u);
    CHECK_EQ(c.clients[0].max_sessions, 9u);
    CHECK_EQ(c.clients[0].max_write_bytes_per_hour, uint64_t(1610612736));
    CHECK_EQ(c.clients[1].max_sessions, 4u);
    CHECK_EQ(c.clients[1].max_write_bytes_per_hour, uint64_t(12345));
    CHECK_EQ(c.clients[2].max_write_bytes_per_hour, uint64_t(0));
}

TEST(config_server_limits_and_modes_errors) {
    CHECK(err_of(srv("file_mode = \"0755\"\n"), true).find("execute") != std::string::npos);
    CHECK(err_of(srv("file_mode = \"0400\"\n"), true).find("owner") != std::string::npos);
    CHECK(err_of(srv("file_mode = \"0689\"\n"), true).find("octal") != std::string::npos);
    CHECK(err_of(srv("file_mode = \"abc\"\n"), true).find("line 3") != std::string::npos);
    CHECK(err_of(srv("file_mode = 640\n"), true).find("octal string") != std::string::npos);
    CHECK(err_of(srv("dir_mode = \"0600\"\n"), true).find("rwx") != std::string::npos);
    CHECK(err_of(srv("max_trash_bytes = \"lots\"\n"), true).find("line 3") != std::string::npos);
    CHECK(err_of(srv("max_trash_bytes = -1\n"), true).find("negative") != std::string::npos);
    CHECK(err_of(srv() + "max_sessions = 0\n", true).find("out of range") != std::string::npos);
    CHECK(err_of(srv() + "max_sessions = \"4\"\n", true).find("integer") != std::string::npos);
    CHECK(err_of(srv() + "max_write_bytes_per_hour = \"x\"\n", true).find("line 6") != std::string::npos);
    CHECK(err_of(srv() + "max_sessionz = 4\n", true).find("unknown key 'max_sessionz'") != std::string::npos);
    CHECK_EQ(parse_file_mode("640"), 0640u);
    CHECK_EQ(parse_dir_mode("0755"), 0755u);
    CHECK_THROWS(parse_file_mode(""));
    CHECK_THROWS(parse_file_mode("06400"));
    CHECK_THROWS(parse_dir_mode("0o755"));
}

TEST(config_local_target_modes) {
    ClientConfig c = parse_client_config_text(
        "key_file='k'\n[[watch]]\npath='/w'\n[[watch.target]]\npath='/d'\nfile_mode='0644'\ndir_mode='0755'\n"
        "[[watch.target]]\npath='/e'\n");
    CHECK_EQ(c.watches[0].targets[0].file_mode, 0644u);
    CHECK_EQ(c.watches[0].targets[0].dir_mode, 0755u);
    CHECK_EQ(c.watches[0].targets[1].file_mode, 0640u);
    CHECK_EQ(c.watches[0].targets[1].dir_mode, 0750u);
    CHECK(err_of("key_file='k'\n[[watch]]\npath='/w'\n[[watch.target]]\nhost='h'\nserver_key='" + K1 +
                 "'\nfile_mode='0640'\n", false).find("local targets") != std::string::npos);
    CHECK(err_of("key_file='k'\n[[watch]]\npath='/w'\n[[watch.target]]\npath='/d'\nfile_mode='0750'\n", false)
              .find("execute") != std::string::npos);
}

TEST(config_server_bandwidth_caps) {
    ServerConfig d = parse_server_config_text(srv());
    CHECK_EQ(d.max_bandwidth_kbps, 0u);
    CHECK_EQ(d.clients[0].max_bandwidth_kbps, 0u);
    ServerConfig c = parse_server_config_text(
        "[server]\nroot='r'\nkey_file='k'\nmax_bandwidth_kbps = 8000\n[[client]]\nname='a'\npublic_key='" + K1 +
        "'\nmax_bandwidth_kbps = 1_000\n");
    CHECK_EQ(c.max_bandwidth_kbps, 8000u);
    CHECK_EQ(c.clients[0].max_bandwidth_kbps, 1000u);
    CHECK(err_of(srv("max_bandwidth_kbps = -1\n"), true).find("out of range") != std::string::npos);
    CHECK(err_of(srv() + "max_bandwidth_kbps = \"5\"\n", true).find("integer") != std::string::npos);
}

TEST(config_bandwidth_floor_raises_tiny_caps) {
    ServerConfig c = parse_server_config_text(
        "[server]\nroot='r'\nkey_file='k'\nmax_bandwidth_kbps = 10\n[[client]]\nname='a'\npublic_key='" + K1 +
        "'\nmax_bandwidth_kbps = 1\n[[client]]\nname='b'\npublic_key='" + K2 + "'\nmax_bandwidth_kbps = 0\n");
    CHECK_EQ(c.max_bandwidth_kbps, 64u);
    CHECK_EQ(c.clients[0].max_bandwidth_kbps, 64u);
    CHECK_EQ(c.clients[1].max_bandwidth_kbps, 0u);  // 0 stays "no limit"
    CHECK_EQ(parse_client_config_text("max_bandwidth_kbps = 63\n").max_bandwidth_kbps, 64u);
    CHECK_EQ(parse_client_config_text("max_bandwidth_kbps = 64\n").max_bandwidth_kbps, 64u);
    CHECK_EQ(parse_client_config_text("max_bandwidth_kbps = 0\n").max_bandwidth_kbps, 0u);
}
