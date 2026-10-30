// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/cli_ops.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

#include "mysync/config.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/daemon.h"
#include "mysync/gui/ipc.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/gui/trust.h"
#include "mysync/keys.h"
#include "mysync/peers.h"

namespace fs = std::filesystem;

namespace mysync {
namespace {

constexpr int kChanged = 10;
constexpr int kNotApplied = 3;  // written, but the running daemon refused to apply it
constexpr int kHealthUsage = 64;  // health: wrong arguments (2 is CRITICAL there)

struct UsageErr : Error {
    using Error::Error;
};

[[noreturn]] void usage(const std::string& m) { throw UsageErr(m); }

// ---------------------------------------------------------------------------------------------- arguments
class Args {
public:
    Args(const std::vector<std::string>& a, size_t from) : v_(a.begin() + static_cast<std::ptrdiff_t>(std::min(from, a.size())), a.end()) {}

    bool flag(std::initializer_list<const char*> names) {
        bool hit = false;
        for (size_t i = 0; i < v_.size();) {
            if (is_one_of(v_[i], names)) {
                hit = true;
                v_.erase(v_.begin() + static_cast<std::ptrdiff_t>(i));
            } else {
                ++i;
            }
        }
        return hit;
    }
    // Last occurrence wins. Throws UsageErr when the value is missing.
    bool value(std::initializer_list<const char*> names, std::string& out) {
        bool hit = false;
        for (size_t i = 0; i < v_.size();) {
            if (is_one_of(v_[i], names)) {
                if (i + 1 >= v_.size()) usage("option " + v_[i] + " needs a value");
                out = v_[i + 1];
                hit = true;
                v_.erase(v_.begin() + static_cast<std::ptrdiff_t>(i), v_.begin() + static_cast<std::ptrdiff_t>(i) + 2);
            } else {
                ++i;
            }
        }
        return hit;
    }
    // What is left: positional words. Anything that still looks like an option is an error.
    std::vector<std::string> positional() const {
        for (const auto& s : v_)
            if (s.size() > 1 && s[0] == '-') usage("unknown option " + s);
        return v_;
    }

private:
    static bool is_one_of(const std::string& s, std::initializer_list<const char*> names) {
        for (const char* n : names)
            if (s == n) return true;
        return false;
    }
    std::vector<std::string> v_;
};

uint32_t parse_u32(const std::string& s, const char* what) {
    if (s.empty() || s.size() > 10 || s.find_first_not_of("0123456789") != std::string::npos)
        usage(std::string(what) + " must be a number");
    unsigned long long v = std::stoull(s);
    if (v > 0xFFFFFFFFull) usage(std::string(what) + " is too large");
    return static_cast<uint32_t>(v);
}

std::string abs_path(const std::string& p) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(p), ec);
    return ec ? p : a.lexically_normal().u8string();
}

std::string dir_of(const std::string& p) { return fs::u8path(p).parent_path().u8string(); }

std::string resolve_in(const std::string& dir, const std::string& p) {
    if (p.empty()) return p;
    fs::path q = fs::u8path(p);
    if (q.is_absolute() || q.has_root_name() || q.has_root_directory()) return p;
    return (fs::u8path(dir) / q).lexically_normal().u8string();
}

std::string read_text(const std::string& path) {
    std::ifstream f(fs::u8path(path), std::ios::binary);
    if (!f) throw Error("cannot read " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// ---------------------------------------------------------------------------------------------- JSON output
std::string jq(const std::string& s) {
    std::string r = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"': r += "\\\""; break;
        case '\\': r += "\\\\"; break;
        case '\n': r += "\\n"; break;
        case '\r': r += "\\r"; break;
        case '\t': r += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04x", c);
                r += b;
            } else {
                r += static_cast<char>(c);
            }
        }
    }
    return r + "\"";
}
std::string jb(bool b) { return b ? "true" : "false"; }
std::string jn(uint64_t v) { return std::to_string(v); }
std::string jarr(const std::vector<std::string>& items) {
    std::string r = "[";
    for (size_t i = 0; i < items.size(); ++i) r += (i ? "," : "") + items[i];
    return r + "]";
}
std::string jstrs(const std::vector<std::string>& v) {
    std::vector<std::string> q;
    for (const auto& s : v) q.push_back(jq(s));
    return jarr(q);
}

int64_t now_ms() { return now_unix_ns() / 1000000; }

int done(bool changed, bool changed_exit) { return changed && changed_exit ? kChanged : 0; }

// ---------------------------------------------------------------------------------------------- daemon reload
// After an edit: ask the running daemon to read the configuration again. Best effort when it cannot be reached (not
// running, no permission): it picks the change up by itself (peers.d is watched, the rest at restart). A daemon that IS
// reached and REFUSES the new configuration (invalid, untrusted, ...) is different: the file is written but not in
// force, which the caller reports with exit code 3. "Reload requested too quickly" is retried a few times.
struct Poke {
    enum State { Unreachable, Applied, Refused } state = Unreachable;
    std::string note;
};

Poke poke_daemon(const std::string& config_path, const std::string& service_name) {
    Poke out;
    try {
        ServerConfig c = gui::load_server_config_resolved(config_path);
        std::string name = gui::effective_control_name(c.control_name, service_name, true);
        gui::ControlClient cc(name, 4000);
        for (int attempt = 0; attempt < 4; ++attempt) {
            gui::ReloadResult r = cc.reload_config();
            if (r.ok) {
                out.state = Poke::Applied;
                out.note = "daemon reloaded (" + r.message + ")";
                return out;
            }
            out.state = Poke::Refused;
            out.note = "the daemon refused the new configuration (it keeps the old one): " + r.message;
            if (r.message.find("too quickly") == std::string::npos) return out;
            std::this_thread::sleep_for(std::chrono::milliseconds(2200));  // reload_min_interval_ms is 2 s
        }
    } catch (const std::exception& e) {
        out.state = Poke::Unreachable;
        out.note = std::string("daemon not reloaded (") + e.what() +
                   "); it notices peers.d changes within seconds, other changes at restart";
    }
    return out;
}

const char* applied_json(const Poke& p, bool attempted) {
    if (!attempted || p.state == Poke::Unreachable) return "null";
    return p.state == Poke::Applied ? "true" : "false";
}

// ---------------------------------------------------------------------------------------------- safety of the writes
// An administrator (root / elevated) must not be tricked into writing through a symbolic link or into a folder others
// can change: the same trust rules as the daemon's apply to the files these commands touch.
void refuse_symlink(const std::string& p) {
    if (p.empty()) return;
    std::error_code ec;
    if (fs::is_symlink(fs::u8path(p), ec)) throw Error("refusing to write through a symbolic link: " + p);
}

bool strict_trust() { return gui::need_strict_trust(gui::ServiceController::is_elevated(), false); }

void guard_dir(const std::string& dir, const std::string& what) {
    if (dir.empty()) return;
    refuse_symlink(dir);
    if (strict_trust()) gui::require_trusted_dir(dir, what, {});
}

// config_path: the configuration file; extra: other files / folders that will be written.
void guard_admin(const std::string& config_path, const std::vector<std::string>& dirs, const std::vector<std::string>& files) {
    refuse_symlink(config_path);
    if (strict_trust()) gui::require_trusted_config(config_path, {});
    for (const auto& d : dirs) guard_dir(d, "a folder these commands write into");
    for (const auto& f : files) {
        refuse_symlink(f);
        if (!f.empty() && strict_trust()) {
            std::error_code ec;
            if (fs::exists(fs::u8path(f), ec)) {
                std::string why = gui::untrusted_writer_reason(f, {});
                if (!why.empty()) throw Error("refusing " + f + ": " + why);
            }
        }
    }
}

void guard_server_config(const std::string& config_path) {
    ServerConfig c = load_server_config(config_path);
    std::string dir = dir_of(config_path);
    std::vector<std::string> dirs{dir};
    std::string pd = peers_dir_path(c, dir);
    if (!pd.empty()) dirs.push_back(pd);
    std::vector<std::string> files{revoked_list_path(dir)};
    guard_admin(config_path, dirs, files);
}

// ---------------------------------------------------------------------------------------------- keygen / key
int cmd_keygen(Args a) {
    std::string out = "mysync.key";
    a.value({"-o", "--out"}, out);
    bool force = a.flag({"--force"}), if_missing = a.flag({"--if-missing"}), changed_exit = a.flag({"--changed-exit"});
    bool json = a.flag({"--json"});
    if (!a.positional().empty()) usage("keygen takes no positional argument (use --out <file>)");
    if (force && if_missing) usage("--force and --if-missing exclude each other");
    fs::path outp = fs::u8path(out);
    std::error_code ec;
    refuse_symlink(out);
    refuse_symlink(out + ".pub");
    if (!outp.parent_path().empty()) guard_dir(outp.parent_path().u8string(), "the key folder");
    bool exists = fs::exists(outp, ec) || fs::is_symlink(outp, ec);
    KeyPair kp;
    bool created = false;
    if (exists && !force) {
        if (!if_missing) throw Error("key file " + out + " already exists: not overwritten (use --force to replace it, --if-missing to keep it)");
        kp = load_keypair(out);  // also checks owner and permissions
    } else {
        if (!outp.parent_path().empty()) fs::create_directories(outp.parent_path(), ec);
        kp = generate_keypair();
        try {
            if (exists) {
                // never leave a window with no key file: write the new one beside it and rename over
                uint8_t r[6];
                random_bytes(r, sizeof r);
                std::string tmp = out + ".new-" + to_hex(r, sizeof r);
                save_keypair(tmp, kp);
                std::error_code e2;
                fs::rename(fs::u8path(tmp), outp, e2);
                if (e2) {
                    fs::remove(fs::u8path(tmp), e2);
                    throw RuntimeFailure("cannot replace " + out + ": " + e2.message());
                }
            } else {
                save_keypair(out, kp);
            }
        } catch (const RuntimeFailure&) {
            throw;
        } catch (const Error& e) {
            throw RuntimeFailure(std::string("cannot write the key file: ") + e.what());
        }
        created = true;
        try {
            gui::write_file_atomic(out + ".pub", key_to_hex(kp.pub) + "\n", false);
        } catch (const Error&) {
        }
    }
    std::string pub = key_to_hex(kp.pub);
    if (json) {
        std::cout << "{\"public_key\":" << jq(pub) << ",\"key_file\":" << jq(out) << ",\"created\":" << jb(created) << "}\n";
    } else {
        std::cerr << (created ? "secret key written to " + out + " (keep it private, never copy it to the other machine)\n"
                              : "key file " + out + " already present: kept\n");
        std::cerr << "give the public key below to the other side:\n";
        std::cout << pub << "\n";
    }
    return done(created, changed_exit);
}

struct ConfigRef {
    std::string path, dir;
    gui::ConfigRole role = gui::ConfigRole::Client;
};

ConfigRef open_ref(const std::string& config, const std::string& role_opt) {
    if (config.empty()) usage("-c <config> is required");
    ConfigRef r;
    r.path = abs_path(config);
    r.dir = dir_of(r.path);
    if (role_opt == "server") r.role = gui::ConfigRole::Server;
    else if (role_opt == "client") r.role = gui::ConfigRole::Client;
    else if (!role_opt.empty()) usage("--role must be 'server' or 'client'");
    else r.role = gui::ConfigEditor::detect_role(read_text(r.path));
    return r;
}

int cmd_key_show(Args a) {
    std::string keyfile, config, role;
    a.value({"-k", "--key"}, keyfile);
    a.value({"-c", "--config"}, config);
    a.value({"--role"}, role);
    bool pub = a.flag({"--public"}), json = a.flag({"--json"});
    if (!a.positional().empty()) usage("usage: mysync key show --public [-k <keyfile> | -c <config>] [--json]");
    if (!pub) usage("key show needs --public (a secret key is never printed)");
    std::string next_file;
    if (keyfile.empty()) {
        if (config.empty()) usage("give -k <keyfile> or -c <config>");
        ConfigRef r = open_ref(config, role);
        if (r.role == gui::ConfigRole::Server) {
            ServerConfig c = load_server_config(r.path);
            keyfile = resolve_in(r.dir, c.key_file);
            next_file = resolve_in(r.dir, c.key_file_next);
        } else {
            keyfile = resolve_in(r.dir, load_client_config(r.path).key_file);
            if (keyfile.empty()) throw Error("the client configuration has no key_file at client level; use -k");
        }
    }
    std::string p = key_to_hex(load_keypair(keyfile).pub), n;
    if (!next_file.empty()) n = key_to_hex(load_keypair(next_file).pub);
    if (json) {
        std::cout << "{\"public_key\":" << jq(p) << ",\"next_public_key\":" << (n.empty() ? "null" : jq(n))
                  << ",\"key_file\":" << jq(keyfile) << "}\n";
    } else {
        std::cout << p << "\n";
        if (!n.empty()) std::cerr << "next public key (rotation under way): " << n << "\n";
    }
    return 0;
}

int cmd_key_rotate(Args a) {
    std::string config, out, svc;
    a.value({"--server-config", "-c", "--config"}, config);
    a.value({"--out"}, out);
    a.value({"--service-name"}, svc);
    bool prepare = a.flag({"--prepare"}), promote = a.flag({"--promote"}), status = a.flag({"--status"});
    bool changed_exit = a.flag({"--changed-exit"}), no_reload = a.flag({"--no-reload"}), json = a.flag({"--json"});
    bool adopt = a.flag({"--adopt"});
    if (!a.positional().empty()) usage("usage: mysync key rotate --server-config <server.toml> --prepare|--promote|--status");
    if (int(prepare) + int(promote) + int(status) != 1) usage("give exactly one of --prepare, --promote, --status");
    if (config.empty()) usage("--server-config <server.toml> is required");
    std::string path = abs_path(config), dir = dir_of(path);
    gui::ConfigEditor ed = gui::ConfigEditor::open(path, gui::ConfigRole::Server);
    ServerConfig& sc = ed.server();
    if (!status) {
        std::vector<std::string> kd{dir};
        std::string kf = resolve_in(dir, sc.key_file);
        if (!kf.empty()) kd.push_back(dir_of(kf));
        guard_admin(path, kd, {kf, resolve_in(dir, sc.key_file_next), resolve_in(dir, out)});
    }
    auto pub_of = [&](const std::string& f) { return key_to_hex(load_keypair(resolve_in(dir, f)).pub); };
    bool changed = false;
    std::string msg;
    if (status) {
        std::string p = pub_of(sc.key_file);
        std::string n = sc.key_file_next.empty() ? "" : pub_of(sc.key_file_next);
        if (json)
            std::cout << "{\"rotation\":" << jb(!n.empty()) << ",\"public_key\":" << jq(p) << ",\"next_public_key\":"
                      << (n.empty() ? "null" : jq(n)) << "}\n";
        else {
            std::cout << "key_file       : " << sc.key_file << "\n  public key   : " << p << "\n";
            if (n.empty()) std::cout << "no rotation under way (key_file_next is not set)\n";
            else std::cout << "key_file_next  : " << sc.key_file_next << "\n  public key   : " << n
                           << "\nrotation under way: clients may pin either public key; finish with --promote\n";
        }
        return 0;
    }
    if (prepare) {
        if (!sc.key_file_next.empty()) {
            std::string nf = resolve_in(dir, sc.key_file_next);
            std::error_code ec;
            if (!fs::exists(fs::u8path(nf), ec)) throw Error("key_file_next = " + sc.key_file_next + " is set but the file does not exist");
            msg = "rotation already prepared; new public key " + pub_of(sc.key_file_next);
        } else {
            std::string rel = out.empty() ? sc.key_file + ".next" : out;
            std::string full = resolve_in(dir, rel);
            std::error_code ec;
            KeyPair kp;
            if (fs::exists(fs::u8path(full), ec) || fs::is_symlink(fs::u8path(full), ec)) {
                // A file that is already there is never taken over silently: it could be anyone's key (or a plant).
                if (!adopt)
                    throw Error(rel + " already exists: not used as the new server key. Remove it, choose --out <file>, or "
                                      "pass --adopt to use the key it holds (after an interrupted --prepare)");
                refuse_symlink(full);
                kp = load_keypair(full);
            } else {
                kp = generate_keypair();
                try {
                    save_keypair(full, kp);
                } catch (const Error& e) {
                    throw RuntimeFailure(std::string("cannot write the new key file: ") + e.what());
                }
            }
            if (kp.pub == load_keypair(resolve_in(dir, sc.key_file)).pub) throw Error("the new key file holds the same key as key_file");
            sc.key_file_next = rel;
            try {
                ed.save();
            } catch (const Error& e) {
                throw RuntimeFailure(e.what());
            }
            changed = true;
            msg = "new server key written to " + rel + "; the server now answers to both keys. New public key: " + key_to_hex(kp.pub);
        }
    } else {  // promote
        if (sc.key_file_next.empty()) {
            msg = "no rotation under way (key_file_next is not set): nothing to promote";
        } else {
            std::string old = sc.key_file;
            (void)pub_of(sc.key_file_next);  // must be readable before the swap
            sc.key_file = sc.key_file_next;
            sc.key_file_next.clear();
            try {
                ed.save();
            } catch (const Error& e) {
                throw RuntimeFailure(e.what());
            }
            changed = true;
            msg = "promoted: key_file is now " + sc.key_file + "; the old key (" + old +
                  ") is no longer accepted - delete that file when you are sure no client still pins it";
        }
    }
    Poke pk;
    bool attempted = changed && !no_reload;
    if (attempted) pk = poke_daemon(path, svc);
    if (json)
        std::cout << "{\"changed\":" << jb(changed) << ",\"message\":" << jq(msg) << ",\"daemon\":" << jq(pk.note)
                  << ",\"daemon_applied\":" << applied_json(pk, attempted) << "}\n";
    else {
        std::cout << msg << "\n";
        if (!pk.note.empty()) std::cerr << pk.note << "\n";
    }
    if (attempted && pk.state == Poke::Refused) return kNotApplied;
    return done(changed, changed_exit);
}

int cmd_key(const std::vector<std::string>& v) {
    if (v.size() < 3) usage("usage: mysync key show|rotate ...");
    if (v[2] == "show") return cmd_key_show(Args(v, 3));
    if (v[2] == "rotate") return cmd_key_rotate(Args(v, 3));
    usage("unknown key command '" + v[2] + "' (show, rotate)");
}

// ---------------------------------------------------------------------------------------------- peer
int cmd_peer(const std::vector<std::string>& v) {
    if (v.size() < 3) usage("usage: mysync peer add|remove|revoke|retire-key|list ...");
    const std::string sub = v[2];
    Args a(v, 3);
    std::string config, name, perm, subdir, svc, ms, mb;
    a.value({"-c", "--config", "--server-config"}, config);
    a.value({"--service-name"}, svc);
    bool changed_exit = a.flag({"--changed-exit"}), no_reload = a.flag({"--no-reload"}), json = a.flag({"--json"});
    if (config.empty()) usage("-c <server.toml> is required");
    std::string path = abs_path(config);

    if (sub == "add" || sub == "remove" || sub == "revoke" || sub == "retire-key") guard_server_config(path);

    auto finish = [&](const PeerEdit& e) {
        Poke pk;
        bool attempted = e.changed && !no_reload;
        if (attempted) pk = poke_daemon(path, svc);
        if (json) {
            std::vector<std::string> rk;
            for (const auto& k : e.revoked_keys) rk.push_back(jq(k));
            std::cout << "{\"changed\":" << jb(e.changed) << ",\"where\":" << jq(e.where) << ",\"message\":" << jq(e.message)
                      << ",\"revoked_keys\":" << jarr(rk) << ",\"daemon\":" << jq(pk.note)
                      << ",\"daemon_applied\":" << applied_json(pk, attempted) << "}\n";
        } else {
            std::cout << e.message << "\n";
            if (!pk.note.empty()) std::cerr << pk.note << "\n";
        }
        if (attempted && pk.state == Poke::Refused) return kNotApplied;  // written, but not in force
        return done(e.changed, changed_exit);
    };

    if (sub == "add") {
        a.value({"--name"}, name);
        a.value({"--perm"}, perm);
        bool have_subdir = a.value({"--subdir", "--prefix"}, subdir);
        a.value({"--max-sessions"}, ms);
        a.value({"--max-bandwidth-kbps"}, mb);
        PeerSpec s;
        s.rotate = a.flag({"--rotate"});
        s.allow_revoked = a.flag({"--allow-revoked"});
        std::vector<std::string> pos = a.positional();
        if (pos.size() != 1) usage("usage: mysync peer add <public key, 64 hex> --name <name> --perm ro|rw [--subdir <dir>] -c <server.toml>");
        if (name.empty()) usage("--name is required");
        if (perm != "ro" && perm != "rw") usage("--perm must be ro or rw");
        try {
            s.key = parse_public_key_hex(pos[0]);
        } catch (const Error& e) {
            usage(std::string("the public key: ") + e.what());
        }
        s.name = name;
        s.read_only = perm == "ro";
        if (have_subdir) s.prefix = subdir;  // not given: an existing peer keeps its folder, a new one gets the whole root
        if (!ms.empty()) s.max_sessions = parse_u32(ms, "--max-sessions");
        if (!mb.empty()) s.max_bandwidth_kbps = parse_u32(mb, "--max-bandwidth-kbps");
        return finish(peer_add(path, s));
    }
    if (sub == "remove" || sub == "revoke") {
        std::vector<std::string> pos = a.positional();
        if (pos.size() != 1) usage("usage: mysync peer " + sub + " <name|public key> -c <server.toml>");
        return finish(peer_remove(path, pos[0], sub == "revoke"));
    }
    if (sub == "retire-key") {
        std::vector<std::string> pos = a.positional();
        if (pos.size() != 2) usage("usage: mysync peer retire-key <name> <old public key> -c <server.toml>");
        PublicKey k;
        try {
            k = parse_public_key_hex(pos[1]);
        } catch (const Error& e) {
            usage(std::string("the public key: ") + e.what());
        }
        return finish(peer_retire_key(path, pos[0], k));
    }
    if (sub == "list") {
        if (!a.positional().empty()) usage("usage: mysync peer list [--json] -c <server.toml>");
        PeerLoad rep;
        std::vector<ClientAcl> v2 = peer_list(path, &rep);
        if (json) {
            std::vector<std::string> items;
            for (const auto& c : v2) {
                std::vector<std::string> ks;
                ks.push_back(jq(key_to_hex(c.public_key)));
                for (const auto& k : c.extra_keys) ks.push_back(jq(key_to_hex(k)));
                items.push_back("{\"name\":" + jq(c.name) + ",\"access\":" + jq(c.read_only ? "ro" : "rw") + ",\"subdir\":" +
                                jq(c.prefix) + ",\"public_key\":" + jq(key_to_hex(c.public_key)) + ",\"keys\":" + jarr(ks) +
                                ",\"max_sessions\":" + jn(c.max_sessions) + ",\"source\":" + jq(c.source.empty() ? "main" : "peers.d/" + c.source) + "}");
            }
            std::cout << "{\"peers\":" << jarr(items) << ",\"peer_file_errors\":" << jn(rep.bad) << ",\"warnings\":" << jstrs(rep.warnings) << "}\n";
        } else {
            for (const auto& c : v2) {
                std::cout << c.name << "\t" << (c.read_only ? "ro" : "rw") << "\t" << (c.prefix.empty() ? "-" : c.prefix) << "\t"
                          << key_short(c.public_key) << (c.extra_keys.empty() ? "" : " (+" + std::to_string(c.extra_keys.size()) + " old key)")
                          << "\t" << (c.source.empty() ? "main" : "peers.d/" + c.source) << "\n";
            }
            for (const auto& w : rep.warnings) std::cerr << "warning: " << w << "\n";
        }
        return 0;
    }
    usage("unknown peer command '" + sub + "' (add, remove, revoke, retire-key, list)");
}

// ---------------------------------------------------------------------------------------------- status / health
struct View {
    std::string role;  // "server" | "client"
    std::string config;
    std::string version;
    bool running = false;
    std::string control_error;
    bool control_enabled = true;
    gui::StatusSnapshot snap;
    std::vector<std::string> warnings;     // from the CLI's own reading of the configuration
    uint32_t peer_file_errors = 0;
    std::string pairing;                   // server
    std::string public_key, next_public_key;
    // from the configuration (used when the daemon cannot be asked)
    std::vector<ClientAcl> peers;
    std::vector<std::pair<std::string, std::string>> targets;  // watch, label
};

View gather(const std::string& config, const std::string& role_opt, const std::string& svc) {
    ConfigRef r = open_ref(config, role_opt);
    View v;
    v.config = r.path;
    v.version = "1.0.0";
    std::string control_name;
    bool is_server = r.role == gui::ConfigRole::Server;
    v.role = is_server ? "server" : "client";
    if (is_server) {
        PeerLoad pl;
        ServerConfig c = gui::load_server_config_resolved(r.path, &pl);
        v.peers = c.clients;
        v.peer_file_errors = static_cast<uint32_t>(pl.bad);
        v.warnings = pl.warnings;
        v.pairing = pairing_name(c.pairing);
        v.control_enabled = c.control_enabled;
        control_name = gui::effective_control_name(c.control_name, svc, true);
        try {
            v.public_key = key_to_hex(load_keypair(c.key_file).pub);
            if (!c.key_file_next.empty()) v.next_public_key = key_to_hex(load_keypair(c.key_file_next).pub);
        } catch (const std::exception& e) {
            v.warnings.push_back(std::string("cannot read the server key: ") + e.what());
        }
        if (!c.key_file_next.empty()) v.warnings.push_back("server key rotation under way: key_file_next is set");
    } else {
        ClientConfig c = gui::load_client_config_resolved(r.path);
        v.control_enabled = c.control_enabled;
        control_name = gui::effective_control_name(c.control_name, svc, false);
        for (const auto& w : c.watches) {
            if (!w.enabled) continue;
            for (const auto& t : w.targets)
                if (t.enabled)
                    v.targets.emplace_back(w.name, t.is_local() ? "dir://" + t.path : "net://" + t.host + ":" + std::to_string(t.port));
        }
        try {
            if (!c.key_file.empty()) v.public_key = key_to_hex(load_keypair(resolve_in(r.dir, c.key_file)).pub);
        } catch (const std::exception&) {
        }
    }
    if (!v.control_enabled) {
        v.control_error = "[control] enabled = false: the daemon cannot be asked";
    } else {
        try {
            gui::ControlClient cc(control_name, 4000);
            v.snap = cc.get_status();
            v.running = true;
            v.version = v.snap.version.empty() ? v.version : v.snap.version;
        } catch (const std::exception& e) {
            v.control_error = e.what();
        }
    }
    return v;
}

const char* state_name(gui::TargetState s) { return gui::target_state_name(s); }

// Seconds since the target last worked, -1 = never (since the daemon started).
int64_t lag_s(const gui::TargetStatus& t, int64_t now) {
    if (t.state == gui::TargetState::Idle) return 0;
    if (t.last_ok_unix_ms <= 0) return -1;
    return std::max<int64_t>(0, (now - t.last_ok_unix_ms) / 1000);
}

int cmd_status_json(Args a) {
    std::string config, role, svc;
    a.value({"-c", "--config"}, config);
    a.value({"--role"}, role);
    a.value({"--service-name", "--name"}, svc);
    a.flag({"--json"});
    if (!a.positional().empty()) usage("usage: mysync status -c <config> --json");
    View v = gather(config, role, svc);
    int64_t now = now_ms();
    const gui::StatusSnapshot& s = v.snap;
    std::vector<std::string> warns = v.warnings;
    if (v.running) {
        for (const auto& w : s.warnings)
            if (std::find(warns.begin(), warns.end(), w) == warns.end()) warns.push_back(w);
    }
    std::string o = "{\"version\":" + jq(v.version) + ",\"role\":" + jq(v.role) + ",\"config\":" + jq(v.config) +
                    ",\"running\":" + jb(v.running) + ",\"source\":" + jq(v.running ? "daemon" : "config") +
                    ",\"control_error\":" + (v.control_error.empty() ? "null" : jq(v.control_error)) +
                    ",\"uptime_s\":" + jn(v.running ? s.uptime_s : 0) + ",\"taken_unix_ms\":" + jn(static_cast<uint64_t>(now)) +
                    ",\"public_key\":" + (v.public_key.empty() ? "null" : jq(v.public_key)) +
                    ",\"next_public_key\":" + (v.next_public_key.empty() ? "null" : jq(v.next_public_key));
    if (v.role == "server") {
        o += ",\"pairing\":" + jq(v.running && !s.pairing.empty() ? s.pairing : v.pairing);
        o += ",\"listen\":" + jq(v.running ? s.listen : "") + ",\"sessions\":" + jn(v.running ? s.sessions : 0);
        std::vector<std::string> ps;
        for (const auto& c : v.peers) {
            uint32_t sess = 0;
            uint64_t rx = 0, tx = 0;
            for (const auto& p : s.peers)
                if (v.running && p.name == c.name) {
                    sess = p.sessions;
                    rx = p.bytes_rx;
                    tx = p.bytes_tx;
                }
            ps.push_back("{\"name\":" + jq(c.name) + ",\"access\":" + jq(c.read_only ? "ro" : "rw") + ",\"subdir\":" + jq(c.prefix) +
                         ",\"keys\":" + jn(1 + c.extra_keys.size()) + ",\"source\":" + jq(c.source.empty() ? "main" : "peers.d/" + c.source) +
                         ",\"sessions\":" + jn(sess) + ",\"bytes_received\":" + jn(rx) + ",\"bytes_sent\":" + jn(tx) + "}");
        }
        o += ",\"peers\":" + jarr(ps) + ",\"targets\":[]";
        o += ",\"errors\":" + jn(v.peer_file_errors);
        o += ",\"peer_file_errors\":" + jn(v.running ? std::max<uint32_t>(s.peer_file_errors, v.peer_file_errors) : v.peer_file_errors);
        o += ",\"last_ok_unix_ms\":null";
    } else {
        std::vector<std::string> ts;
        int64_t last_ok = 0;
        if (v.running) {
            for (const auto& t : s.targets) {
                int64_t lag = lag_s(t, now);
                last_ok = std::max(last_ok, t.last_ok_unix_ms);
                ts.push_back("{\"watch\":" + jq(t.watch) + ",\"target\":" + jq(t.target) + ",\"state\":" + jq(state_name(t.state)) +
                             ",\"queued\":" + jn(t.queued) + ",\"sent\":" + jn(t.sent) + ",\"skipped\":" + jn(t.skipped) +
                             ",\"failed\":" + jn(t.failed) + ",\"bytes\":" + jn(t.bytes) + ",\"tx_bps\":" + jn(t.tx_bps) +
                             ",\"lag_seconds\":" + (lag < 0 ? "null" : jn(static_cast<uint64_t>(lag))) +
                             ",\"last_ok_unix_ms\":" + (t.last_ok_unix_ms ? jn(static_cast<uint64_t>(t.last_ok_unix_ms)) : "null") +
                             ",\"last_error\":" + (t.last_error.empty() ? "null" : jq(t.last_error)) +
                             ",\"last_error_unix_ms\":" + (t.last_error_unix_ms ? jn(static_cast<uint64_t>(t.last_error_unix_ms)) : "null") + "}");
            }
        } else {
            for (const auto& t : v.targets)
                ts.push_back("{\"watch\":" + jq(t.first) + ",\"target\":" + jq(t.second) + ",\"state\":\"unknown\"}");
        }
        o += ",\"peers\":[],\"targets\":" + jarr(ts);
        o += ",\"errors\":" + jn(v.running ? s.total_failed : 0) + ",\"total_sent\":" + jn(v.running ? s.total_sent : 0) +
             ",\"last_ok_unix_ms\":" + (last_ok ? jn(static_cast<uint64_t>(last_ok)) : "null");
    }
    o += ",\"config_error\":" + (v.running && !s.config_error.empty() ? jq(s.config_error) : "null");
    o += ",\"warnings\":" + jstrs(warns) + "}";
    std::cout << o << "\n";
    return 0;
}

int cmd_health(Args a) {
    std::string config, role, svc, maxlag = "900";
    a.value({"-c", "--config"}, config);
    a.value({"--role"}, role);
    a.value({"--service-name", "--name"}, svc);
    a.value({"--max-lag-seconds"}, maxlag);
    bool json = a.flag({"--json"});
    if (!a.positional().empty()) usage("usage: mysync health -c <config> [--max-lag-seconds N] [--json]");
    uint32_t max_lag = parse_u32(maxlag, "--max-lag-seconds");

    int code = 0;
    std::vector<std::string> msgs;
    auto raise = [&](int c, const std::string& m) {
        code = std::max(code, c);
        msgs.push_back(m);
    };
    std::string summary_ok;
    try {
        View v = gather(config, role, svc);
        int64_t now = now_ms();
        if (!v.running) {
            raise(2, "daemon not running or not reachable (" + v.control_error + ")");
        } else {
            const gui::StatusSnapshot& s = v.snap;
            if (!s.config_error.empty()) raise(1, "last configuration reload refused: " + s.config_error);
            uint32_t pfe = std::max<uint32_t>(s.peer_file_errors, v.peer_file_errors);
            if (pfe) raise(1, std::to_string(pfe) + " peer file(s) could not be used");
            if (v.role == "server") {
                summary_ok = "server " + s.listen + ", " + std::to_string(s.sessions) + " session(s), " + std::to_string(v.peers.size()) + " peer(s)";
            } else {
                size_t idle = 0;
                for (const auto& t : s.targets) {
                    int64_t lag = lag_s(t, now);
                    std::string who = t.watch + " -> " + t.target;
                    // "never worked since the daemon started" counts from the daemon's start
                    int64_t eff = lag >= 0 ? lag : static_cast<int64_t>(s.uptime_s);
                    switch (t.state) {
                    case gui::TargetState::Idle: ++idle; break;
                    case gui::TargetState::Syncing:
                        if (eff > static_cast<int64_t>(max_lag)) raise(2, who + " has made no progress for " + std::to_string(eff) + " s");
                        break;
                    case gui::TargetState::Error:
                    case gui::TargetState::Disconnected: {
                        std::string why = t.last_error.empty() ? "" : " (" + t.last_error.substr(0, 120) + ")";
                        std::string what = std::string(state_name(t.state)) + " for " + std::to_string(eff) + " s";
                        if (eff > static_cast<int64_t>(max_lag)) raise(2, who + " " + what + why + ", over --max-lag-seconds");
                        else raise(1, who + " " + what + why);
                        break;
                    }
                    }
                }
                summary_ok = std::to_string(idle) + "/" + std::to_string(s.targets.size()) + " target(s) idle";
                if (s.targets.empty()) raise(1, "the daemon reports no target");
            }
        }
    } catch (const UsageErr&) {
        throw;
    } catch (const std::exception& e) {
        raise(2, std::string("configuration unusable: ") + e.what());
    }
    const char* word = code == 0 ? "OK" : code == 1 ? "WARNING" : "CRITICAL";
    std::string line = std::string("MYSYNC ") + word + " - ";
    if (msgs.empty()) line += summary_ok;
    for (size_t i = 0; i < msgs.size(); ++i) line += (i ? "; " : "") + msgs[i];
    if (json) {
        std::cout << "{\"status\":" << jq(code == 0 ? "ok" : code == 1 ? "warning" : "critical") << ",\"code\":" << code
                  << ",\"summary\":" << jq(summary_ok) << ",\"messages\":" << jstrs(msgs) << "}\n";
    } else {
        std::cout << line << "\n";
    }
    return code;
}

}  // namespace

int cli_ops_main(const std::vector<std::string>& args) {
    try {
        if (args.size() < 2) usage("no command");
        const std::string& cmd = args[1];
        if (cmd == "keygen") return cmd_keygen(Args(args, 2));
        if (cmd == "key") return cmd_key(args);
        if (cmd == "peer") return cmd_peer(args);
        if (cmd == "status") return cmd_status_json(Args(args, 2));
        if (cmd == "health") {
            try {
                return cmd_health(Args(args, 2));
            } catch (const UsageErr& e) {  // 2 means CRITICAL for health: wrong arguments get their own code
                std::cerr << "mysync: " << e.what() << "\n(run 'mysync help' for usage)\n";
                return kHealthUsage;
            }
        }
        usage("unknown command '" + cmd + "'");
    } catch (const UsageErr& e) {
        std::cerr << "mysync: " << e.what() << "\n(run 'mysync help' for usage)\n";
        return 2;
    } catch (const RuntimeFailure& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return 1;
    } catch (const Error& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return 1;
    }
}

}  // namespace mysync
