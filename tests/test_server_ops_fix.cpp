// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// Review fixes of the server-operation commands: cross-process lock, fail-closed revocation list, no silent change of
// a peer's folder, key rotation that does not adopt a file it did not create, authentication-only key fallback.
#include "so_util.h"

#include <atomic>
#include <set>

#include "mysync/config.h"
#include "mysync/gui/daemon.h"
#include "mysync/peers.h"
#include "mysync/secure_channel.h"

namespace {

std::string key_n(int i) {  // a distinct, valid public key per number
    char b[8];
    std::snprintf(b, sizeof b, "%02x", 0x10 + i);
    std::string s;
    for (int k = 0; k < 32; ++k) s += b;
    return s;
}

struct Cfg2 {
    Tmp t;
    std::string path;
    explicit Cfg2(bool peers_dir) {
        path = t.s("server.toml");
        spit(path, server_toml_text(peers_dir ? "peers_dir = \"peers.d\"\n" : "", !peers_dir));
    }
};

}  // namespace

// ---- M1: concurrent edits do not lose each other

TEST(so_fix_parallel_peer_adds_into_peers_dir_lose_nothing) {
    Cfg2 c(true);
    std::vector<std::thread> th;
    std::atomic<int> failed{0};
    for (int i = 0; i < 12; ++i)
        th.emplace_back([&, i] {
            try {
                PeerSpec s;
                s.name = "p" + std::to_string(i);
                s.key = parse_public_key_hex(key_n(i));
                (void)peer_add(c.path, s);
            } catch (const std::exception&) {
                ++failed;
            }
        });
    for (auto& t : th) t.join();
    CHECK_EQ(failed.load(), 0);
    CHECK_EQ(peer_list(c.path).size(), size_t(12));
}

TEST(so_fix_parallel_peer_adds_into_the_main_file_lose_nothing) {
    Cfg2 c(false);  // read-modify-write of the whole configuration file
    std::vector<std::thread> th;
    std::atomic<int> failed{0};
    for (int i = 0; i < 8; ++i)
        th.emplace_back([&, i] {
            try {
                PeerSpec s;
                s.name = "m" + std::to_string(i);
                s.key = parse_public_key_hex(key_n(i));
                (void)peer_add(c.path, s);
            } catch (const std::exception&) {
                ++failed;
            }
        });
    for (auto& t : th) t.join();
    CHECK_EQ(failed.load(), 0);
    CHECK_EQ(peer_list(c.path).size(), size_t(9));  // 8 + the one that was there
}

TEST(so_fix_parallel_same_name_different_keys_one_winner) {
    Cfg2 c(true);
    std::vector<std::thread> th;
    std::atomic<int> ok{0}, refused{0};
    for (int i = 0; i < 6; ++i)
        th.emplace_back([&, i] {
            try {
                PeerSpec s;
                s.name = "same";
                s.key = parse_public_key_hex(key_n(i));
                (void)peer_add(c.path, s);
                ++ok;
            } catch (const std::exception&) {
                ++refused;
            }
        });
    for (auto& t : th) t.join();
    CHECK_EQ(ok.load(), 1);
    CHECK_EQ(refused.load(), 5);
    CHECK_EQ(peer_list(c.path).size(), size_t(1));
}

TEST(so_fix_parallel_revokes_keep_every_key_on_the_list) {
    Cfg2 c(true);
    for (int i = 0; i < 8; ++i) {
        PeerSpec s;
        s.name = "r" + std::to_string(i);
        s.key = parse_public_key_hex(key_n(i));
        (void)peer_add(c.path, s);
    }
    std::vector<std::thread> th;
    for (int i = 0; i < 8; ++i)
        th.emplace_back([&, i] { (void)peer_remove(c.path, "r" + std::to_string(i), true); });
    for (auto& t : th) t.join();
    CHECK_EQ(peer_list(c.path).size(), size_t(0));
    CHECK_EQ(load_revoked(c.t.p.u8string()).size(), size_t(8));
}

TEST(so_fix_new_peer_file_is_never_overwritten_by_add) {
    Cfg2 c(true);
    // a file already sitting under the name the new peer would get, but not loadable as that peer: add must refuse it
    spit(c.t.p / "peers.d" / "web.toml", "this is not a peer file");
    PeerSpec s;
    s.name = "web";
    s.key = parse_public_key_hex(key_n(1));
    CHECK_THROWS(peer_add(c.path, s));
    CHECK_EQ(slurp(c.t.p / "peers.d" / "web.toml"), std::string("this is not a peer file"));
}

// ---- M2: the revocation list never fails open

TEST(so_fix_revocation_list_fails_closed) {
    Cfg2 c(true);
    ServerConfig cfg = parse_server_config_text(server_toml_text("peers_dir = \"peers.d\"\n", false));
    CHECK(load_revoked(c.t.p.u8string()).empty());  // absent = nothing revoked
    // a malformed line: the whole configuration is refused rather than ignoring the list
    spit(c.t.p / "revoked-keys.txt", key_n(1) + " 2026-01-01 a\nthis line is rubbish\n");
    CHECK_THROWS(load_revoked(c.t.p.u8string()));
    CHECK_THROWS(load_peers(cfg, c.t.p.u8string(), {}, false));
    CHECK_THROWS(gui::load_server_config_resolved(c.path));
    CHECK_EQ(cli({"peer", "add", key_n(2), "--name", "x", "--perm", "rw", "-c", c.path, "--no-reload"}).rc, 2);
    // a UTF-8 BOM (Notepad) in front of a good list is fine
    spit(c.t.p / "revoked-keys.txt", std::string("\xEF\xBB\xBF") + key_n(1) + " 2026-01-01 a\n# comment\n\n" + key_n(2) + "\n");
    std::vector<RevokedKey> rv = load_revoked(c.t.p.u8string());
    CHECK_EQ(rv.size(), size_t(2));
    // CRLF line ends too
    spit(c.t.p / "revoked-keys.txt", key_n(3) + " 2026-01-01 a\r\n" + key_n(4) + " 2026-01-01 b\r\n");
    CHECK_EQ(load_revoked(c.t.p.u8string()).size(), size_t(2));
}

// ---- M3 order / L4 / L2

TEST(so_fix_revoke_records_the_keys_and_unrevoke_is_last) {
    Cfg2 c(true);
    PeerSpec s;
    s.name = "a";
    s.key = parse_public_key_hex(key_n(1));
    s.prefix = std::string("sub");
    (void)peer_add(c.path, s);
    PeerEdit e = peer_remove(c.path, "a", true);
    CHECK(e.changed);
    CHECK_EQ(load_revoked(c.t.p.u8string()).size(), size_t(1));
    // allow_revoked + a write that cannot happen (the name clashes): the key stays revoked
    PeerSpec other;
    other.name = "a";
    other.key = parse_public_key_hex(key_n(2));
    (void)peer_add(c.path, other);
    PeerSpec again;
    again.name = "a";  // same name as the live peer, different key, no rotate: refused
    again.key = parse_public_key_hex(key_n(1));
    again.allow_revoked = true;
    CHECK_THROWS(peer_add(c.path, again));
    CHECK_EQ(load_revoked(c.t.p.u8string()).size(), size_t(1));  // still revoked
}

TEST(so_fix_peer_add_without_subdir_keeps_the_folder) {
    Cfg2 c(true);
    CHECK_EQ(cli({"peer", "add", key_n(1), "--name", "a", "--perm", "rw", "--subdir", "keepme", "-c", c.path, "--no-reload"}).rc, 0);
    // run again with fewer options: nothing changes, the folder is not silently widened to the whole root
    CHECK_EQ(cli({"peer", "add", key_n(1), "--name", "a", "--perm", "rw", "-c", c.path, "--no-reload", "--changed-exit"}).rc, 0);
    CHECK_EQ(peer_list(c.path)[0].prefix, std::string("keepme"));
    // an explicit empty --subdir is a deliberate widening
    CHECK_EQ(cli({"peer", "add", key_n(1), "--name", "a", "--perm", "rw", "--subdir", "", "-c", c.path, "--no-reload", "--changed-exit"}).rc, 10);
    CHECK_EQ(peer_list(c.path)[0].prefix, std::string(""));
}

// ---- M4

TEST(so_fix_key_rotate_prepare_does_not_adopt_an_existing_file) {
    Tmp t;
    std::string cfg = t.s("server.toml");
    CHECK_EQ(cli({"keygen", "--out", t.s("server.key")}).rc, 0);
    spit(cfg, "[server]\nroot = \"r\"\nkey_file = \"server.key\"\npeers_dir = \"peers.d\"\n");
    CHECK_EQ(cli({"keygen", "--out", t.s("planted.key")}).rc, 0);
    fs::copy_file(t.p / "planted.key", t.p / "server.key.next");
    Run r = cli({"key", "rotate", "--server-config", cfg, "--prepare", "--no-reload"});
    CHECK_EQ(r.rc, 2);
    CHECK(r.err.find("already exists") != std::string::npos);
    CHECK(parse_server_config_text(slurp(cfg)).key_file_next.empty());
    // explicit consent adopts it
    Run adopt = cli({"key", "rotate", "--server-config", cfg, "--prepare", "--adopt", "--no-reload", "--changed-exit"});
    CHECK_EQ(adopt.rc, 10);
    CHECK_EQ(parse_server_config_text(slurp(cfg)).key_file_next, std::string("server.key.next"));
}

#ifndef _WIN32
TEST(so_fix_commands_refuse_to_write_through_symlinks) {
    Tmp t;
    CHECK_EQ(cli({"keygen", "--out", t.s("real.key")}).rc, 0);
    fs::create_symlink(t.p / "real.key", t.p / "link.key");
    CHECK_EQ(cli({"keygen", "--out", t.s("link.key"), "--force"}).rc, 2);
    Cfg2 c(true);
    fs::create_directories(t.p / "elsewhere");
    fs::remove_all(c.t.p / "peers.d");
    fs::create_directory_symlink(t.p / "elsewhere", c.t.p / "peers.d");
    CHECK_EQ(cli({"peer", "add", key_n(1), "--name", "a", "--perm", "rw", "-c", c.path, "--no-reload"}).rc, 2);
    CHECK(fs::is_empty(t.p / "elsewhere"));
}
#endif

// ---- M5: only an authentication refusal makes the client try its second pinned key

TEST(so_fix_auth_error_is_distinguished_from_connection_errors) {
    net::init();
    KeyPair server = generate_keypair(), client = generate_keypair(), other = generate_keypair();
    // (a) the server refuses the pinned key by closing at once: an authentication error
    {
        net::Socket l = net::Socket::listen("127.0.0.1", 0);
        std::thread th([&] {
            net::Socket s = l.accept(3000);
            uint8_t m1[96];
            try {
                s.recv_all(m1, sizeof m1);  // a real server reads the first message, finds no key it knows, closes
            } catch (const std::exception&) {
            }
            s.close();
        });
        net::Socket c = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
        bool auth = false;
        try {
            SecureChannel::client(std::move(c), client, other.pub, 3000);
        } catch (const AuthError&) {
            auth = true;
        } catch (const std::exception&) {
        }
        th.join();
        CHECK(auth);
    }
    // (b) the server never answers: a timeout is not evidence about the key
    {
        net::Socket l = net::Socket::listen("127.0.0.1", 0);
        std::atomic<bool> release{false};
        std::thread th([&] {
            net::Socket s = l.accept(3000);
            while (!release) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        });
        net::Socket c = net::Socket::connect("127.0.0.1", l.local_port(), 3000);
        bool auth = false, other_err = false;
        try {
            SecureChannel::client(std::move(c), client, other.pub, 300);
        } catch (const AuthError&) {
            auth = true;
        } catch (const std::exception& e) {
            other_err = std::string(e.what()) == "authentication failed";
        }
        release = true;
        th.join();
        CHECK(!auth);
        CHECK(other_err);
    }
}
