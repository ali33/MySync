// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Server-to-server operation: peers.d, the `mysync peer / key / keygen / status / health` commands, two-key server
// handshakes (rotation), revocation that cuts live sessions, reconnection of unattended clients.
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <thread>

#include "so_util.h"
#include "mysync/cli_ops.h"
#include "mysync/client_engine.h"
#include "mysync/config.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/daemon.h"
#include "mysync/keys.h"
#include "mysync/net.h"
#include "mysync/nettarget.h"
#include "mysync/peers.h"
#include "mysync/protocol.h"
#include "mysync/secure_channel.h"
#include "mysync/server.h"
#include "testing.h"

using namespace mysync;
namespace fs = std::filesystem;


// ------------------------------------------------------------------------------------------------ configuration

TEST(so_config_new_server_fields_roundtrip) {
    ServerConfig c = parse_server_config_text(server_toml_text("key_file_next = \"k2\"\npeers_dir = \"peers.d\"\npairing = \"on-demand\"\n"));
    CHECK_EQ(c.key_file_next, std::string("k2"));
    CHECK_EQ(c.peers_dir, std::string("peers.d"));
    CHECK(c.pairing == PairingMode::OnDemand);
    ServerConfig d = parse_server_config_text(gui::serialize_server_config(c));
    CHECK_EQ(d.key_file_next, std::string("k2"));
    CHECK_EQ(d.peers_dir, std::string("peers.d"));
    CHECK(d.pairing == PairingMode::OnDemand);
    // default is off
    CHECK(parse_server_config_text(server_toml_text("")).pairing == PairingMode::Off);
    CHECK_THROWS(parse_server_config_text(server_toml_text("pairing = \"always\"\n")));
    CHECK_THROWS(parse_server_config_text(server_toml_text("key_file_next = \"k\"\n")));  // same file as key_file
}

TEST(so_config_peers_dir_allows_no_client_in_main_file) {
    CHECK_THROWS(parse_server_config_text(server_toml_text("", false)));
    ServerConfig c = parse_server_config_text(server_toml_text("peers_dir = \"peers.d\"\n", false));
    CHECK(c.clients.empty());
}

TEST(so_config_client_extra_public_keys) {
    ServerConfig c = parse_server_config_text(server_toml_text("") + "public_keys = [\"" + K2 + "\", \"" + K3 + "\"]\n");
    CHECK_EQ(c.clients[0].extra_keys.size(), size_t(2));
    CHECK(acl_has_key(c.clients[0], parse_public_key_hex(K3)));
    ServerConfig d = parse_server_config_text(gui::serialize_server_config(c));
    CHECK(d.clients[0].extra_keys == c.clients[0].extra_keys);
    // repeats are refused: inside one peer, and across peers
    CHECK_THROWS(parse_server_config_text(server_toml_text("") + "public_keys = [\"" + K1 + "\"]\n"));
    CHECK_THROWS(parse_server_config_text(server_toml_text("") + "public_keys = [\"" + K2 + "\"]\n[[client]]\nname='o'\npublic_key='" + K2 + "'\n"));
    CHECK_THROWS(parse_server_config_text(server_toml_text("") + "public_keys = [\"zz\"]\n"));
}

TEST(so_config_target_server_key_next) {
    std::string base = "key_file='k'\n[[watch]]\npath='/w'\n[[watch.target]]\nhost='h'\nserver_key='" + K1 + "'\n";
    ClientConfig c = parse_client_config_text(base + "server_key_next='" + K2 + "'\n");
    const TargetConfig& t = c.watches[0].targets[0];
    CHECK(t.has_server_key_next);
    CHECK_EQ(t.server_key_next[0], uint8_t(0xbb));
    ClientConfig d = parse_client_config_text(gui::serialize_client_config(c));
    CHECK(d.watches[0].targets[0].has_server_key_next);
    CHECK(!parse_client_config_text(base).watches[0].targets[0].has_server_key_next);
    CHECK_THROWS(parse_client_config_text(base + "server_key_next='" + K1 + "'\n"));
    CHECK_THROWS(parse_client_config_text("key_file='k'\n[[watch]]\npath='/w'\n[[watch.target]]\npath='/x'\nserver_key_next='" + K2 + "'\n"));
}

TEST(so_peer_file_parse) {
    ClientAcl a = parse_peer_file_text("name='web'\npublic_key='" + K1 + "'\naccess='ro'\nprefix='a/b'\n", "stem");
    CHECK_EQ(a.name, std::string("web"));
    CHECK(a.read_only);
    CHECK_EQ(a.prefix, std::string("a/b"));
    CHECK_EQ(parse_peer_file_text("public_key='" + K1 + "'\n", "stem").name, std::string("stem"));
    CHECK_THROWS(parse_peer_file_text("name='x'\n", "s"));
    CHECK_THROWS(parse_peer_file_text("[server]\nname='x'\npublic_key='" + K1 + "'\n", "s"));
    CHECK_THROWS(parse_peer_file_text("public_key='" + K1 + "'\nprefix='../x'\n", "s"));
    CHECK_THROWS(parse_peer_file_text("public_key='" + K1 + "'\nbogus=1\n", "s"));
}

// ------------------------------------------------------------------------------------------------ peers.d

TEST(so_peers_dir_merge_rules_and_bad_files) {
    Tmp t;
    spit(t.p / "peers.d" / "a.toml", "name='alpha'\npublic_key='" + K2 + "'\n");
    spit(t.p / "peers.d" / "b-broken.toml", "name='broken'\npublic_key='nothex'\n");
    spit(t.p / "peers.d" / "c-dupkey.toml", "name='gamma'\npublic_key='" + K1 + "'\n");   // main file's key
    spit(t.p / "peers.d" / "d-dupname.toml", "name='main1'\npublic_key='" + K3 + "'\n");  // main file's name
    spit(t.p / "peers.d" / "e.toml", "name='epsilon'\npublic_key='" + std::string(64, 'e') + "'\naccess='ro'\n");
    spit(t.p / "peers.d" / "notes.txt", "ignored");
    spit(t.p / "peers.d" / ".hidden.toml", "name='h'\npublic_key='" + std::string(64, 'f') + "'\n");
    ServerConfig c = parse_server_config_text(server_toml_text("peers_dir = \"peers.d\"\n"));
    PeerLoad rep = load_peers(c, t.p.u8string(), {}, false);
    CHECK_EQ(rep.files, size_t(5));
    CHECK_EQ(rep.loaded, size_t(2));
    CHECK_EQ(rep.bad, size_t(3));
    CHECK_EQ(rep.warnings.size(), size_t(3));
    CHECK_EQ(c.clients.size(), size_t(3));
    CHECK_EQ(c.clients[0].name, std::string("main1"));   // main file first
    CHECK_EQ(c.clients[1].name, std::string("alpha"));   // then peers.d in file-name order
    CHECK_EQ(c.clients[2].name, std::string("epsilon"));
    CHECK_EQ(c.clients[1].source, std::string("a.toml"));
    CHECK(c.clients[2].read_only);
    bool broken_named = false, dupkey_named = false;
    for (const auto& w : rep.warnings) {
        if (w.find("b-broken.toml") != std::string::npos && w.find("64 hexadecimal") != std::string::npos) broken_named = true;
        if (w.find("c-dupkey.toml") != std::string::npos && w.find("main1") != std::string::npos) dupkey_named = true;
    }
    CHECK(broken_named);   // the verbatim reason, file name included
    CHECK(dupkey_named);
}

TEST(so_peers_dir_default_location_and_missing_dir) {
    Tmp t;
    ServerConfig c = parse_server_config_text(server_toml_text(""));
    CHECK(peers_dir_path(c, t.p.u8string()).empty());  // no peers.d, none configured: nothing read
    spit(t.p / "peers.d" / "a.toml", "name='alpha'\npublic_key='" + K2 + "'\n");
    CHECK(!peers_dir_path(c, t.p.u8string()).empty());  // the default directory is picked up
    PeerLoad rep = load_peers(c, t.p.u8string(), {}, false);
    CHECK_EQ(rep.loaded, size_t(1));
    ServerConfig d = parse_server_config_text(server_toml_text("peers_dir = \"nowhere\"\n"));
    PeerLoad r2 = load_peers(d, t.p.u8string(), {}, false);
    CHECK_EQ(r2.warnings.size(), size_t(1));  // a typo in peers_dir is not silent
}

TEST(so_peers_dir_trust_callback_refuses_one_file) {
    Tmp t;
    spit(t.p / "peers.d" / "good.toml", "name='good'\npublic_key='" + K2 + "'\n");
    spit(t.p / "peers.d" / "evil.toml", "name='evil'\npublic_key='" + K3 + "'\n");
    ServerConfig c = parse_server_config_text(server_toml_text("peers_dir = \"peers.d\"\n"));
    PeerLoad rep = load_peers(
        c, t.p.u8string(),
        [](const std::string& f) { return f.find("evil") != std::string::npos ? std::string("writable by Everyone") : std::string(); }, false);
    CHECK_EQ(c.clients.size(), size_t(2));
    CHECK_EQ(rep.bad, size_t(1));
    CHECK(rep.warnings[0].find("writable by Everyone") != std::string::npos);
}

TEST(so_revocation_list_drops_keys_everywhere) {
    Tmp t;
    spit(t.p / "peers.d" / "a.toml", "name='alpha'\npublic_key='" + K2 + "'\npublic_keys=['" + K3 + "']\n");
    spit(t.p / "revoked-keys.txt", K1 + " 2026-01-01 main1\n" + K2 + " 2026-01-01 alpha\n");
    ServerConfig c = parse_server_config_text(server_toml_text("peers_dir = \"peers.d\"\n"));
    PeerLoad rep = load_peers(c, t.p.u8string(), {}, false);
    CHECK_EQ(c.clients.size(), size_t(1));  // main1 gone (its only key is revoked); alpha keeps its other key
    CHECK_EQ(c.clients[0].name, std::string("alpha"));
    CHECK(c.clients[0].public_key == parse_public_key_hex(K3));
    CHECK(c.clients[0].extra_keys.empty());
    CHECK_EQ(rep.warnings.size(), size_t(2));
}

TEST(so_peers_fingerprint_changes_with_the_folder) {
    Tmp t;
    ServerConfig c = parse_server_config_text(server_toml_text("peers_dir = \"peers.d\"\n"));
    std::string f0 = peers_fingerprint(c, t.p.u8string());
    spit(t.p / "peers.d" / "a.toml", "name='alpha'\npublic_key='" + K2 + "'\n");
    std::string f1 = peers_fingerprint(c, t.p.u8string());
    CHECK(f0 != f1);
    CHECK_EQ(f1, peers_fingerprint(c, t.p.u8string()));
    spit(t.p / "peers.d" / "a.toml", "name='alpha'\npublic_key='" + K2 + "'\naccess='ro'\n");
    CHECK(f1 != peers_fingerprint(c, t.p.u8string()));
    fs::remove(t.p / "peers.d" / "a.toml");
    CHECK_EQ(f0, peers_fingerprint(c, t.p.u8string()));
}

// ------------------------------------------------------------------------------------------------ command line

namespace {
struct Cfg {
    Tmp t;
    std::string path;
    explicit Cfg(const std::string& extra = "peers_dir = \"peers.d\"\n", bool with_client = false) {
        path = t.s("server.toml");
        spit(path, server_toml_text(extra, with_client));
    }
};
}  // namespace

TEST(so_cli_peer_add_is_idempotent_and_reports_changes) {
    Cfg c;
    Run r = cli({"peer", "add", K1, "--name", "web1", "--perm", "rw", "--subdir", "web1", "-c", c.path, "--changed-exit", "--no-reload"});
    CHECK_EQ(r.rc, 10);
    CHECK(fs::exists(c.t.p / "peers.d" / "web1.toml"));
    // the same again: no change, exit 0 even with --changed-exit
    CHECK_EQ(cli({"peer", "add", K1, "--name", "web1", "--perm", "rw", "--subdir", "web1", "-c", c.path, "--changed-exit", "--no-reload"}).rc, 0);
    // without --changed-exit a change is still exit 0
    CHECK_EQ(cli({"peer", "add", K1, "--name", "web1", "--perm", "ro", "--subdir", "web1", "-c", c.path, "--no-reload"}).rc, 0);
    ServerConfig m = gui::load_server_config_resolved(c.path);
    CHECK_EQ(m.clients.size(), size_t(1));
    CHECK(m.clients[0].read_only);  // same key, other parameters = updated
    CHECK_EQ(m.clients[0].prefix, std::string("web1"));
    // same name, other key = a clear error (exit 2) and nothing written
    Run bad = cli({"peer", "add", K2, "--name", "web1", "--perm", "rw", "-c", c.path, "--no-reload"});
    CHECK_EQ(bad.rc, 2);
    CHECK(bad.err.find("already belongs") != std::string::npos);
    CHECK_EQ(gui::load_server_config_resolved(c.path).clients[0].public_key, parse_public_key_hex(K1));
    // same key under another name while that name is free = rename; name taken by another peer = error
    CHECK_EQ(cli({"peer", "add", K2, "--name", "web2", "--perm", "rw", "-c", c.path, "--no-reload"}).rc, 0);
    CHECK_EQ(cli({"peer", "add", K2, "--name", "web1", "--perm", "rw", "-c", c.path, "--no-reload"}).rc, 2);
    // arguments
    CHECK_EQ(cli({"peer", "add", "nothex", "--name", "x", "--perm", "rw", "-c", c.path}).rc, 2);
    CHECK_EQ(cli({"peer", "add", K3, "--name", "x", "--perm", "wx", "-c", c.path}).rc, 2);
    CHECK_EQ(cli({"peer", "add", K3, "--perm", "rw", "-c", c.path}).rc, 2);
    CHECK_EQ(cli({"peer", "add", K3, "--name", "x", "--perm", "rw", "--subdir", "../etc", "-c", c.path}).rc, 2);
    CHECK_EQ(cli({"peer", "add", K3, "--name", "x", "--perm", "rw", "--bogus", "-c", c.path}).rc, 2);
}

TEST(so_cli_peer_remove_revoke_list_and_missing) {
    Cfg c;
    CHECK_EQ(cli({"peer", "add", K1, "--name", "a", "--perm", "rw", "-c", c.path, "--no-reload"}).rc, 0);
    CHECK_EQ(cli({"peer", "add", K2, "--name", "b", "--perm", "ro", "-c", c.path, "--no-reload"}).rc, 0);
    Run l = cli({"peer", "list", "--json", "-c", c.path});
    CHECK_EQ(l.rc, 0);
    CHECK(l.out.find("\"name\":\"a\"") != std::string::npos && l.out.find("\"name\":\"b\"") != std::string::npos);
    CHECK_EQ(cli({"peer", "remove", "a", "-c", c.path, "--changed-exit", "--no-reload"}).rc, 10);
    CHECK_EQ(cli({"peer", "remove", "a", "-c", c.path, "--changed-exit", "--no-reload"}).rc, 0);  // gone: nothing to do
    CHECK(!fs::exists(c.t.p / "peers.d" / "a.toml"));
    // revoke by key: removed and the key cannot come back by accident
    CHECK_EQ(cli({"peer", "revoke", K2, "-c", c.path, "--changed-exit", "--no-reload"}).rc, 10);
    CHECK(slurp(c.t.p / "revoked-keys.txt").find(K2) != std::string::npos);
    Run again = cli({"peer", "add", K2, "--name", "b2", "--perm", "rw", "-c", c.path, "--no-reload"});
    CHECK_EQ(again.rc, 2);
    CHECK(again.err.find("revoked") != std::string::npos);
    CHECK_EQ(cli({"peer", "add", K2, "--name", "b2", "--perm", "rw", "--allow-revoked", "-c", c.path, "--no-reload"}).rc, 0);
    CHECK(slurp(c.t.p / "revoked-keys.txt").find(K2) == std::string::npos);
}

TEST(so_cli_peer_rotate_keeps_old_key_until_retired) {
    Cfg c;
    CHECK_EQ(cli({"peer", "add", K1, "--name", "a", "--perm", "rw", "-c", c.path, "--no-reload"}).rc, 0);
    CHECK_EQ(cli({"peer", "add", K2, "--name", "a", "--perm", "rw", "--rotate", "-c", c.path, "--no-reload", "--changed-exit"}).rc, 10);
    ServerConfig m = gui::load_server_config_resolved(c.path);
    CHECK_EQ(m.clients.size(), size_t(1));
    CHECK(acl_has_key(m.clients[0], parse_public_key_hex(K1)) && acl_has_key(m.clients[0], parse_public_key_hex(K2)));
    CHECK(m.clients[0].public_key == parse_public_key_hex(K2));
    CHECK_EQ(cli({"peer", "retire-key", "a", K2, "-c", c.path}).rc, 2);  // the primary key cannot be retired
    CHECK_EQ(cli({"peer", "retire-key", "a", K1, "-c", c.path, "--no-reload", "--changed-exit"}).rc, 10);
    CHECK_EQ(cli({"peer", "retire-key", "a", K1, "-c", c.path, "--no-reload", "--changed-exit"}).rc, 0);
    m = gui::load_server_config_resolved(c.path);
    CHECK(!acl_has_key(m.clients[0], parse_public_key_hex(K1)));
}

TEST(so_cli_peer_add_into_main_file_without_peers_dir) {
    Cfg c("", true);
    CHECK_EQ(cli({"peer", "add", K2, "--name", "viaedit", "--perm", "rw", "-c", c.path, "--no-reload", "--changed-exit"}).rc, 10);
    CHECK(!fs::exists(c.t.p / "peers.d"));
    ServerConfig m = parse_server_config_text(slurp(c.path));
    CHECK_EQ(m.clients.size(), size_t(2));
    CHECK(fs::exists(c.path + ".bak"));
    CHECK_EQ(cli({"peer", "add", K2, "--name", "viaedit", "--perm", "rw", "-c", c.path, "--no-reload", "--changed-exit"}).rc, 0);
    CHECK_EQ(cli({"peer", "remove", "viaedit", "-c", c.path, "--no-reload"}).rc, 0);
    CHECK_EQ(parse_server_config_text(slurp(c.path)).clients.size(), size_t(1));
    // removing the last [[client]] with no peers_dir would leave an unloadable file: refused
    CHECK_EQ(cli({"peer", "remove", "main1", "-c", c.path, "--no-reload"}).rc, 2);
}

TEST(so_cli_keygen_never_overwrites_without_force) {
    Tmp t;
    std::string k = t.s("keys/a.key");
    Run r = cli({"keygen", "--out", k, "--changed-exit"});
    CHECK_EQ(r.rc, 10);
    std::string pub1 = r.out;
    CHECK_EQ(pub1.size(), size_t(65));
    CHECK(!r.err.empty() && r.out.find("secret") == std::string::npos);
    std::string secret = slurp(k);
    Run again = cli({"keygen", "--out", k});
    CHECK_EQ(again.rc, 2);
    CHECK_EQ(slurp(k), secret);  // untouched
    Run keep = cli({"keygen", "--out", k, "--if-missing", "--changed-exit"});
    CHECK_EQ(keep.rc, 0);
    CHECK_EQ(keep.out, pub1);  // same public key again
    Run force = cli({"keygen", "--out", k, "--force", "--changed-exit"});
    CHECK_EQ(force.rc, 10);
    CHECK(force.out != pub1);
    CHECK(slurp(k) != secret);
    // stdout never carries the secret
    CHECK(force.out.find(slurp(k).substr(0, 64)) == std::string::npos);
    // key show --public prints the public half only
    Run show = cli({"key", "show", "--public", "-k", k});
    CHECK_EQ(show.rc, 0);
    CHECK_EQ(show.out, force.out);
    CHECK_EQ(cli({"key", "show", "-k", k}).rc, 2);  // --public is mandatory
    Run js = cli({"key", "show", "--public", "-k", k, "--json"});
    CHECK(js.out.find("\"public_key\":\"" + force.out.substr(0, 64) + "\"") != std::string::npos);
}

TEST(so_cli_key_rotate_prepare_status_promote) {
    Tmp t;
    std::string key = t.s("server.key");
    CHECK_EQ(cli({"keygen", "--out", key}).rc, 0);
    std::string cfg = t.s("server.toml");
    spit(cfg, "[server]\nroot = \"r\"\nkey_file = \"server.key\"\npeers_dir = \"peers.d\"\n");
    std::string old_pub = cli({"key", "show", "--public", "-k", key}).out.substr(0, 64);
    Run p = cli({"key", "rotate", "--server-config", cfg, "--prepare", "--changed-exit", "--no-reload"});
    CHECK_EQ(p.rc, 10);
    CHECK(fs::exists(t.p / "server.key.next"));
    ServerConfig c = parse_server_config_text(slurp(cfg));
    CHECK_EQ(c.key_file_next, std::string("server.key.next"));
    std::string new_pub = cli({"key", "show", "--public", "-k", t.s("server.key.next")}).out.substr(0, 64);
    CHECK(new_pub != old_pub);
    CHECK(p.out.find(new_pub) != std::string::npos);
    // idempotent
    CHECK_EQ(cli({"key", "rotate", "--server-config", cfg, "--prepare", "--changed-exit", "--no-reload"}).rc, 0);
    Run st = cli({"key", "rotate", "--server-config", cfg, "--status", "--json"});
    CHECK(st.out.find("\"rotation\":true") != std::string::npos && st.out.find(old_pub) != std::string::npos &&
          st.out.find(new_pub) != std::string::npos);
    Run pr = cli({"key", "rotate", "--server-config", cfg, "--promote", "--changed-exit", "--no-reload"});
    CHECK_EQ(pr.rc, 10);
    c = parse_server_config_text(slurp(cfg));
    CHECK_EQ(c.key_file, std::string("server.key.next"));
    CHECK(c.key_file_next.empty());
    CHECK_EQ(cli({"key", "show", "--public", "-c", cfg}).out.substr(0, 64), new_pub);
    CHECK_EQ(cli({"key", "rotate", "--server-config", cfg, "--promote", "--changed-exit", "--no-reload"}).rc, 0);  // nothing left
    CHECK_EQ(cli({"key", "rotate", "--server-config", cfg, "--no-reload"}).rc, 2);  // needs a mode
    CHECK_EQ(cli({"key", "rotate", "--server-config", cfg, "--prepare", "--promote"}).rc, 2);
}

TEST(so_cli_health_without_daemon_is_critical_and_bad_config_too) {
    Cfg c("peers_dir = \"peers.d\"\n[control]\nname = \"so-nobody-home\"\n", false);
    Run h = cli({"health", "-c", c.path});
    CHECK_EQ(h.rc, 2);
    CHECK(h.out.find("CRITICAL") != std::string::npos && h.out.find("not running") != std::string::npos);
    Run hj = cli({"health", "-c", c.path, "--json"});
    CHECK(hj.out.find("\"code\":2") != std::string::npos);
    Run missing = cli({"health", "-c", c.t.s("does-not-exist.toml")});
    CHECK_EQ(missing.rc, 2);
    CHECK(missing.out.find("CRITICAL") != std::string::npos);
    CHECK_EQ(cli({"health", "-c", c.path, "--max-lag-seconds", "x"}).rc, 64);  // wrong arguments: not CRITICAL (2)
}
