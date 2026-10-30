// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// main.cpp - the `mysync` command line: keygen, run, status, service, hash, version, help.
//
// Roles: one configuration file = one role. A file with [server] / [[client]] is a server file, one with
// [client] / [[watch]] is a client file (the two parsers are strict and reject each other's tables). Role is detected
// from those markers; --role server|client overrides the detection. A machine that is both server and client runs two
// processes / two services from two files.
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

#include "mysync/cli_ops.h"
#include "mysync/client_engine.h"
#include "mysync/config.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/daemon.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/gui/trust.h"
#include "mysync/hash.h"
#include "mysync/keys.h"
#include "mysync/server.h"
#include "mysync/service.h"
#include "mysync/simple/service_account.h"
#include "mysync/simple/service_upgrade.h"
#include "mysync/util.h"

namespace fs = std::filesystem;
using namespace mysync;

namespace {

const char* kVersion = "1.0.0";

std::atomic<bool> g_stop{false};

struct UsageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

const char* kHelp =
    "MySync " "1.0.0" " - file synchronisation (GPL-2.0-or-later, META.vn)\n"
    "\n"
    "Usage:\n"
    "  mysync keygen [--out|-o <keyfile>] [--force|--if-missing] [--changed-exit]\n"
    "                                          create an identity key (default ./mysync.key); prints the PUBLIC key. Never\n"
    "                                          overwrites a key unless --force; --if-missing keeps an existing key (idempotent)\n"
    "  mysync run -c <config> [--role server|client] [--once]\n"
    "                                          run in the foreground (Ctrl+C stops). --once = one sync pass, then exit\n"
    "                  [--exit-on-stdin-eof]   stop cleanly when standard input closes (used by the GUI that starts the engine)\n"
    "                  [--user-mode]           control channel for the current user only (engine started by the GUI)\n"
    "                  [--allow-pairing]       (server) allow the pairing-by-code mode, switched on from the GUI\n"
    "  mysync status -c <config> [--role ...]  show the loaded configuration (no secrets)\n"
    "  mysync service install|uninstall|start|stop [-c <config>] [--role server|client] [--name N] [--user U]\n"
    "                  [--trust-writer <account>]...   (install: also allowed to edit the configuration; kept in the service arguments)\n"
    "                  [--control-allow <SID|DOMAIN\\user>]...   (install: admit that account to the GUI control channel)\n"
    "                                          install/remove/start/stop the Windows service or systemd unit (admin/root)\n"
    "  mysync status -c <config> --json        the same as a stable JSON document (daemon state when it runs)\n"
    "  mysync health -c <config> [--max-lag-seconds N] [--json]   one line; exit 0 healthy, 1 warning, 2 critical\n"
    "  mysync peer add <public key hex> --name N --perm ro|rw [--subdir D] [--rotate] -c <server.toml>\n"
    "  mysync peer remove|revoke <name|key> | peer retire-key <name> <key> | peer list [--json]   (server peers, idempotent)\n"
    "  mysync key show --public [-k keyfile|-c config] [--json]\n"
    "  mysync key rotate --server-config <server.toml> --prepare|--promote|--status   (server key rotation, no downtime)\n"
    "                                          --changed-exit on the commands above: exit 10 when something changed\n"
    "                                          (docs/SERVER-TO-SERVER.md)\n"
    "  mysync hash <file>                      BLAKE3 of a file\n"
    "  mysync version | help\n"
    "\n"
    "The role of a config file is detected from its tables ([server]/[[client]] = server, [[watch]] = client).\n"
    "Exit code: 0 ok, 1 runtime error, 2 usage or configuration error (10 = changed, only with --changed-exit; 3 = a peer/key command wrote the file but the running daemon refused it; health: 0/1/2 = ok/warning/critical, 64 = bad arguments).\n";

[[noreturn]] void usage(const std::string& m) { throw UsageError(m); }

// ---------------------------------------------------------------------------------------------- helpers
std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string read_text(const std::string& path) {
    std::ifstream f(fs::u8path(path), std::ios::binary);
    if (!f) throw Error("cannot read " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string abs_path(const std::string& p) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(p), ec);
    return ec ? p : a.lexically_normal().u8string();
}

std::string resolve(const std::string& dir, const std::string& p) {
    if (p.empty()) return p;
    fs::path q = fs::u8path(p);
    if (q.is_absolute() || q.has_root_name() || q.has_root_directory()) return p;
    return (fs::u8path(dir) / q).lexically_normal().u8string();
}

std::string dir_of(const std::string& path) {
    return fs::u8path(path).parent_path().u8string();
}

std::string self_exe() {
#ifdef _WIN32
    std::wstring buf(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, &buf[0], static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return fs::path(buf).u8string();
#else
    std::error_code ec;
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    return ec ? std::string() : p.u8string();
#endif
}

enum class Role { None, Server, Client };

Role detect_role(const std::string& text) {
    bool server = false, client = false;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] != '[') continue;
        size_t e = t.find(']');
        std::string head = lower(trim(t.substr(0, e == std::string::npos ? t.size() : e + 1)));
        if (head == "[server]" || head == "[[client]]") server = true;
        else if (head == "[client]" || head.rfind("[[watch", 0) == 0 || head.rfind("[watch", 0) == 0) client = true;
    }
    if (server && client)
        throw Error("the file mixes server tables ([server]/[[client]]) and client tables ([client]/[[watch]]): "
                    "use one file per role");
    return server ? Role::Server : client ? Role::Client : Role::None;
}

Role parse_role(const std::string& s) {
    if (s == "server") return Role::Server;
    if (s == "client") return Role::Client;
    usage("--role must be 'server' or 'client'");
}

struct Opts {
    std::string config;
    std::string role;
    std::string name;
    std::string user;
    std::string out;
    bool once = false;
    bool service = false;
    bool exit_on_stdin_eof = false;  // parent (GUI supervisor) closes our stdin => stop cleanly
    std::string expect_hash, expect_key_hash;
    std::string password_pipe, password_nonce, account;
    std::vector<std::string> state_writers;   // run: SIDs trusted for state/ and log/ only (Windows Simple-mode service)
    bool enforce_paths = false;   // run: apply the Simple-mode path allowlist to every configuration load
    bool user_service = false;   // service install: the Simple-mode flavour (runs as the user, own runtime folder)
    std::vector<std::string> allow_roots;
    bool remove_copy = false;        // service migrate-from-user --remove
    bool user_mode = false;          // engine of a plain user started by the GUI: control channel for that user only
    bool allow_pairing = false;      // receiver: enable the code-pairing mode (simple/pairing.h)
    std::string user_config;
    std::vector<std::string> control_allow;
    std::vector<std::string> trust_writers;
    std::vector<std::string> pos;
};

Opts parse_opts(const std::vector<std::string>& a, size_t from) {
    Opts o;
    for (size_t i = from; i < a.size(); ++i) {
        const std::string& s = a[i];
        auto val = [&]() -> const std::string& {
            if (i + 1 >= a.size()) usage("option " + s + " needs a value");
            return a[++i];
        };
        if (s == "-c" || s == "--config") o.config = val();
        else if (s == "--role") o.role = val();
        else if (s == "--name") o.name = val();
        else if (s == "--user") o.user = val();
        else if (s == "-o" || s == "--out") o.out = val();
        else if (s == "--control-allow") o.control_allow.push_back(val());
        else if (s == "--trust-writer") o.trust_writers.push_back(val());
        else if (s == "--once") o.once = true;
        else if (s == "--service") o.service = true;
        else if (s == "--exit-on-stdin-eof") o.exit_on_stdin_eof = true;
        else if (s == "--allow-pairing") o.allow_pairing = true;
        else if (s == "--user-mode") o.user_mode = true;
        else if (s == "--remove") o.remove_copy = true;
        else if (s == "--expect-hash") o.expect_hash = val();
        else if (s == "--password-pipe") o.password_pipe = val();
        else if (s == "--password-nonce") o.password_nonce = val();
        else if (s == "--account") o.account = val();
        else if (s == "--user-service") o.user_service = true;
        else if (s == "--enforce-paths") o.enforce_paths = true;
        else if (s == "--state-writer") o.state_writers.push_back(val());
        else if (s == "--expect-key-hash") o.expect_key_hash = val();
        else if (s == "--allow-root") o.allow_roots.push_back(val());
        else if (s == "--user-config") o.user_config = val();
        else if (s == "--foreground") {}
        else if (!s.empty() && s[0] == '-') usage("unknown option " + s);
        else o.pos.push_back(s);
    }
    return o;
}

void setup_log(const std::string& level, const std::string& file) {
    std::string l = lower(level);
    log_set_level(l == "debug" ? LogLevel::Debug : l == "warn" || l == "warning" ? LogLevel::Warn
                  : l == "error" ? LogLevel::Error : LogLevel::Info);
    if (!file.empty()) {
        std::error_code ec;
        fs::create_directories(fs::u8path(file).parent_path(), ec);
        log_set_file(file);
    }
}

struct Loaded {
    Role role = Role::None;
    std::string path;      // absolute config path
    std::string dir;       // its directory
    ServerConfig server;
    ClientConfig client;
};

// Loads the configuration; relative paths inside it are made absolute against the config directory.
Loaded load_config(const Opts& o) {
    if (o.config.empty()) usage("-c <config> is required");
    Loaded l;
    l.path = abs_path(o.config);
    l.dir = dir_of(l.path);
    std::string text = read_text(l.path);
    l.role = o.role.empty() ? detect_role(text) : parse_role(o.role);
    if (l.role == Role::None)
        throw Error("cannot tell the role of " + o.config + ": no [server]/[[client]]/[[watch]] table (use --role)");
    if (l.role == Role::Server) {
        l.server = gui::load_server_config_resolved(l.path);  // paths made absolute, peers.d merged
    } else {
        l.client = load_client_config(l.path);
        l.client.key_file = resolve(l.dir, l.client.key_file);
        l.client.state_dir = resolve(l.dir, l.client.state_dir);
        l.client.log_file = resolve(l.dir, l.client.log_file);
        // watch/target paths are resolved by the engine against the config directory
    }
    return l;
}

// ---------------------------------------------------------------------------------------------- commands
int cmd_hash(const Opts& o) {
    if (o.pos.size() != 1) usage("usage: mysync hash <file>");
    uint64_t size = 0;
    Hash256 h = hash_file(o.pos[0], &size);
    std::cout << hash_hex(h) << "  " << o.pos[0] << "\n";
    return 0;
}

std::string pubkey_of(const std::string& key_file) {
    try {
        return key_to_hex(load_keypair(key_file).pub);
    } catch (const std::exception& e) {
        return std::string("(cannot read key: ") + e.what() + ")";
    }
}

int cmd_status(const Opts& o) {
    Loaded l = load_config(o);
    std::cout << "config: " << l.path << "\n";
    if (l.role == Role::Server) {
        const ServerConfig& s = l.server;
        std::cout << "role: server\nlisten: " << s.bind << ":" << s.port << "\nroot: " << s.root
                  << "\nkey_file: " << s.key_file << "\npublic key: " << pubkey_of(s.key_file)
                  << "\ntrash: " << (s.trash ? "yes" : "no") << "\nmax_connections: " << s.max_connections
                  << "\nclients (" << s.clients.size() << "):\n";
        for (const auto& c : s.clients)
            std::cout << "  - " << c.name << "  " << (c.read_only ? "ro" : "rw") << "  prefix='" << c.prefix << "'  key "
                      << key_to_hex(c.public_key).substr(0, 8) << "...\n";
        std::cout << "state_dir: " << (s.state_dir.empty() ? "(default)" : s.state_dir)
                  << "\nlog: " << (s.log_file.empty() ? "stderr" : s.log_file) << " (" << s.log_level << ")\n";
    } else {
        const ClientConfig& c = l.client;
        std::cout << "role: client\nkey_file: " << c.key_file << "\npublic key: " << pubkey_of(c.key_file)
                  << "\nconnections: " << c.connections << "\ncompress: " << c.compress
                  << "\nmax_bandwidth_kbps: " << c.max_bandwidth_kbps << "\nretry: " << c.retry_min_ms << ".."
                  << c.retry_max_ms << " ms\nstate_dir: " << (c.state_dir.empty() ? "(default: <config dir>/state)" : c.state_dir)
                  << "\nlog: " << (c.log_file.empty() ? "stderr" : c.log_file) << " (" << c.log_level << ")\nwatches ("
                  << c.watches.size() << "):\n";
        for (const auto& w : c.watches) {
            std::cout << "  - " << w.name << (w.enabled ? "" : " [disabled]") << "  " << w.path
                      << (w.recursive ? "  recursive" : "") << (w.propagate_delete ? "  propagate_delete" : "") << "\n";
            for (const auto& t : w.targets)
                std::cout << "      -> " << (t.is_local() ? "dir://" + t.path : "net://" + t.host + ":" + std::to_string(t.port))
                          << (t.enabled ? "" : " [disabled]") << "\n";
        }
    }
    std::cout << "service state: not queried (use systemctl status / sc query with the service name)\n";
    return 0;
}

std::string default_service_name(Role r) { return r == Role::Server ? "mysync-server" : "mysync-client"; }

#ifdef _WIN32
constexpr bool kWindowsHost = true;
#else
constexpr bool kWindowsHost = false;
#endif

int cmd_run(const Opts& o) {
    if (o.service && o.enforce_paths && kWindowsHost) {
        // The Simple-mode service checks again at EVERY start: the account may have been made an administrator after the install.
        std::string why = simple::service_start_refusal(simple::account_admin_state(simple::current_user_sid()));
        if (!why.empty()) {
            log_error(why);
            std::cerr << "mysync: " << why << "\n";
            return 1;
        }
    }
    Loaded l = load_config(o);
    // Trust comes FIRST: before the log file is opened or anything is created from this configuration. With high
    // rights (elevated / SYSTEM / root / --service) the file, its folder, the state folder (the default one when
    // state_dir is empty) and the log folder must not be changeable by others. A plain account running its own files
    // is not blocked. The daemon repeats the check at start and on every reload.
    for (const auto& w : o.trust_writers) {
        if (!gui::valid_trust_writer_entry(w)) usage("invalid --trust-writer entry");
        std::string why = gui::broad_principal_reason(w);
        if (!why.empty()) usage("refusing --trust-writer: " + why);
    }
    if (gui::need_strict_trust(gui::ServiceController::is_elevated(), o.service)) {
        try {
            if (l.role == Role::Server)
                gui::require_trusted_run(l.path, gui::effective_server_state_dir(l.server.state_dir, l.server.root),
                                         l.server.log_file, o.trust_writers);
            else if (o.enforce_paths && kWindowsHost)   // the Simple-mode service: the user's own account is NOT trusted for the configuration
                gui::require_trusted_run(l.path, gui::effective_client_state_dir(l.client.state_dir, l.path), l.client.log_file,
                                         o.trust_writers, o.state_writers, /*include_self=*/false);
            else
                gui::require_trusted_run(l.path, gui::effective_client_state_dir(l.client.state_dir, l.path),
                                         l.client.log_file, o.trust_writers);
        } catch (const Error& e) {
            std::cerr << "mysync: " << e.what() << "\n";
            return 1;
        }
    }
    std::function<void(std::atomic<bool>&)> body;
    int rc = 0;
    if (l.role == Role::Server) {
        if (o.once) usage("--once only applies to a client");
        setup_log(l.server.log_level, l.server.log_file);
        ServerConfig sc = l.server;
        gui::DaemonOptions dopt;
        dopt.service_name = o.name.empty() ? default_service_name(l.role) : o.name;
        dopt.config_path = l.path;
        dopt.version = kVersion;
        dopt.enforce_config_trust = gui::need_strict_trust(gui::ServiceController::is_elevated(), o.service);
        dopt.trusted_writers = o.trust_writers;
        dopt.control_user_only = o.user_mode;
        dopt.allow_pairing = o.allow_pairing;
        std::string dir = l.dir;
        body = [sc, dir, dopt](std::atomic<bool>& stop) {
            gui::ServerDaemon d(sc, dir, dopt);
            d.run(stop);  // the Server, plus the GUI control channel and hot reload
            log_info("server stopped");
        };
    } else {
        setup_log(l.client.log_level, l.client.log_file);
        ClientConfig cc = l.client;
        std::string dir = l.dir;
        bool once = o.once;
        int* prc = &rc;
        gui::DaemonOptions dopt;
        dopt.service_name = o.name.empty() ? default_service_name(l.role) : o.name;
        dopt.config_path = l.path;
        dopt.version = kVersion;
        dopt.enforce_config_trust = gui::need_strict_trust(gui::ServiceController::is_elevated(), o.service);
        dopt.trusted_writers = o.trust_writers;
        dopt.control_user_only = o.user_mode;
        if (o.enforce_paths) {
            std::vector<std::string> roots = o.allow_roots;
            std::string cdir = dir;
            dopt.config_check = [roots, cdir](const ClientConfig& c) { return simple::service_config_path_problem(c, cdir, roots); };
            if (kWindowsHost) {
                dopt.exclude_self_from_trust = true;
                dopt.state_writers = o.state_writers;
            }
            std::string why = dopt.config_check(cc);
            if (!why.empty()) {
                std::cerr << "mysync: refusing the configuration: " << why << "\n";
                return 1;
            }
        }
        body = [cc, dir, once, prc, dopt](std::atomic<bool>& stop) {
            log_info("MySync client " + std::string(kVersion) + (once ? ": one sync pass" : ": watching"));
            if (once) {
                SyncEngine eng(cc, dir);
                eng.sync_once(stop);
                EngineStats s = eng.stats();
                if (s.gave_up > 0) *prc = 1;
            } else {
                gui::ClientDaemon d(cc, dir, dopt);
                d.run(stop);  // the engine, plus the GUI control channel and hot reload
            }
        };
    }
    if (o.service) {
        std::string name = o.name.empty() ? default_service_name(l.role) : o.name;
        return run_as_service(name, body);
    }
    install_signal_handlers(g_stop);
    if (o.exit_on_stdin_eof) {
        // The supervising GUI holds the write end of our stdin; when it closes it (or dies) we stop like on Ctrl+C.
        std::thread([] {
            char c;
#ifdef _WIN32
            HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
            DWORD n = 0;
            while (h && h != INVALID_HANDLE_VALUE && ReadFile(h, &c, 1, &n, nullptr) && n > 0) {}
#else
            while (true) {
                ssize_t n = ::read(0, &c, 1);
                if (n > 0 || (n < 0 && errno == EINTR)) continue;
                break;
            }
#endif
            g_stop = true;
        }).detach();
    }
    try {
        body(g_stop);
    } catch (const std::exception& e) {
        log_error(std::string("fatal: ") + e.what());
        std::cerr << "mysync: " << e.what() << "\n";
        return 1;
    }
    return rc;
}

int cmd_service_impl(const Opts& o);

// Exit codes of this command are the stable gui::ServiceExit values: the GUI (which may run this elevated and can
// only read the exit code) maps them to messages.
int cmd_service(const Opts& o) {
    try {
        return cmd_service_impl(o);
    } catch (const UsageError& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return gui::kServiceBadArguments;
    } catch (const Error& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return gui::kServiceConfigError;
    }
}

int cmd_service_impl(const Opts& o) {
    if (o.pos.size() == 1 && (o.pos[0] == "migrate-from-user" || o.pos[0] == "apply-config")) {  // elevated helper of the GUI (simple mode)
        if (o.user_config.empty() && !o.remove_copy) usage("service migrate-from-user needs --user-config <file>");
        std::vector<std::string> a;
        if (!o.user_config.empty()) { a.push_back("--user-config"); a.push_back(o.user_config); }
        if (o.remove_copy) a.push_back("--remove");
        if (o.pos[0] == "apply-config") a.push_back("--config-only");   // a new configuration for the service, same key
        if (!o.account.empty()) { a.push_back("--account"); a.push_back(o.account); }
        if (!o.expect_hash.empty()) { a.push_back("--expect-hash"); a.push_back(o.expect_hash); }
        if (!o.expect_key_hash.empty()) { a.push_back("--expect-key-hash"); a.push_back(o.expect_key_hash); }
        for (const auto& r : o.allow_roots) { a.push_back("--allow-root"); a.push_back(r); }
        if (!o.name.empty()) { a.push_back("--name"); a.push_back(o.name); }
        return simple::run_migrate_from_user(a);
    }
    if (o.pos.size() != 1) usage("usage: mysync service install|uninstall|start|stop [options]");
    const std::string& act = o.pos[0];
    if (act != "install" && act != "uninstall" && act != "start" && act != "stop" && act != "set-password")
        usage("unknown service action " + act);
    Role role = Role::None;
    Loaded l;
    if (!o.config.empty()) {
        l = load_config(o);
        role = l.role;
    } else if (!o.role.empty()) {
        role = parse_role(o.role);
    }
    std::string name = o.name.empty() ? (role == Role::None ? "" : default_service_name(role)) : o.name;
    if (name.empty()) usage("give -c <config> or --name <service name>");
    if (act == "set-password") {
        // Windows: the user changed the password of the account the service runs as. The new password arrives through the
        // private channel (never on a command line); it is checked with a logon first.
        if (o.user.empty() || o.password_pipe.empty()) usage("service set-password needs --user <account> and --password-pipe/--password-nonce");
#ifdef _WIN32
        {   // only for the account of the user who asks, and only on a MySync service of this installation
            if (simple::account_sid(o.user) != simple::current_user_sid()) {
                std::cerr << "mysync: the password can only be changed for your own account\n";
                return gui::kServiceAccessDenied;
            }
            // the service must carry THIS user's owner label (and name), not just be a MySync service
            if (!simple::user_service_name_matches_owner(name, simple::current_owner_id()) ||
                service_description(name).find(simple::owner_label(simple::current_owner_id())) == std::string::npos) {
                std::cerr << "mysync: the service '" << name << "' was not installed for you\n";
                return gui::kServiceAccessDenied;
            }
            std::string serr;
            if (!service_runs_program(name, self_exe(), &serr)) {
                std::cerr << "mysync: " << serr << "\n";
                return gui::kServiceConfigError;
            }
        }
#endif
        simple::SecretString pw;
        std::string perr;
        if (!simple::receive_password(o.password_pipe, o.password_nonce, &pw, &perr)) {
            std::cerr << "mysync: " << perr << "\n";
            return gui::kServiceGenericFailure;
        }
        simple::AccountCheck chk = simple::check_service_account(o.user, pw);
        if (!chk.ok) {
            std::cerr << "mysync: " << chk.error << "\n";
            return gui::kServiceConfigError;
        }
        {   // a password is not changed on a service whose account is (or may be) an administrator
            std::string why = simple::service_account_refusal(chk.admin, simple::account_admin_state(chk.sid));
            if (!why.empty()) {
                std::cerr << "mysync: " << why << "\n";
                return gui::kServiceAccessDenied;
            }
        }
        std::string pws = pw.reveal();
        pw.clear();
        std::string err;
        std::string canon = simple::account_name_from_sid(chk.sid);   // the canonical DOMAIN\name, not what was typed
        bool ok = service_set_password(name, canon.empty() ? o.user : canon, pws, &err);   // wipes pws
        if (!pws.empty()) secure_wipe(&pws[0], pws.size());       // whatever is left (a failure path)
        pws.clear();
        if (!ok) {
            std::cerr << "mysync: service set-password failed: " << err << "\n";
            return gui::service_exit_code_for_error(err);
        }
        std::cout << "service " << name << ": password updated\n";
        return 0;
    }
    std::string err;
    bool ok = false;
    if (act == "install") {
        if (o.config.empty()) usage("service install needs -c <config>");
        if (!o.user_service && simple::looks_like_user_service_name(name))
            usage("the name '" + name + "' is reserved for Simple-mode services: use --user-service");
        for (const auto& a : o.control_allow)
            if (!gui::valid_control_allow_entry(a)) usage("invalid --control-allow entry (use a SID like S-1-5-21-... or DOMAIN\\user)");
        for (const auto& a : o.trust_writers)
            if (!gui::valid_trust_writer_entry(a)) usage("invalid --trust-writer entry");
        // The accounts the administrator names now are the only additions to "who may edit the configuration": they
        // go into the service arguments, never into (or from) the file itself.
        std::vector<std::string> trusted = o.trust_writers;
        trusted.insert(trusted.end(), o.control_allow.begin(), o.control_allow.end());
        std::string exe = self_exe();
        // One shared vetting (also used by the GUI): the program, broad groups, and a configuration that nobody but the
        // service's trusted set can edit.
        std::string bad = gui::validate_install_inputs(exe, l.path, o.trust_writers, o.control_allow, o.user);
        if (!bad.empty()) throw Error(bad);
        ServiceSpec sp;
        sp.name = name;
        sp.display = role == Role::Server ? "MySync server" : "MySync client";
        sp.description = "MySync file synchronisation (" + std::string(role == Role::Server ? "server" : "client") + ")";
        sp.exe_path = exe;
        sp.args = {"run", "-c", l.path, "--role", role == Role::Server ? "server" : "client", "--service", "--name", name};
        sp.run_as = o.user;
        if (o.user_service) {   // the service re-applies the path allowlist whenever it loads its configuration
            sp.args.push_back("--enforce-paths");
            for (const auto& r : o.allow_roots) {
                sp.args.push_back("--allow-root");
                sp.args.push_back(r);
            }
        }
        std::string owner_id;
        bool right_added = false;
        std::string right_sid;
        // The right to log on as a service, once granted by us, is taken away again on EVERY way out that does not end with a
        // working service and its marker (an early return, an exception from the install, a failed --control-allow ...).
        simple::LogonRightGuard right_guard;
        if (o.user_service) {   // the Simple-mode flavour: never root / SYSTEM, and labelled with its owner
#ifndef _WIN32
            struct passwd pw{}, *pres = nullptr;
            char pbuf[4096];
            if (o.user.empty() || ::getpwnam_r(o.user.c_str(), &pw, pbuf, sizeof pbuf, &pres) != 0 || !pres)
                throw Error("--user-service needs --user <an existing account>");
            if (pw.pw_uid == 0 || pw.pw_uid < simple::min_login_uid() || pw.pw_uid == 65534)
                throw Error("a user service must not run as root, as a system account or as 'nobody'");
            // The account must be the one who asked (pkexec / sudo name them), never an arbitrary other user.
            {
                const char* inv = std::getenv("PKEXEC_UID");
                if (!inv || !*inv) inv = std::getenv("SUDO_UID");
                if (!inv || std::to_string(static_cast<unsigned long>(pw.pw_uid)) != inv)
                    throw Error("a user service can only be installed for the account that asks for it");
            }
            owner_id = std::to_string(static_cast<unsigned long>(pw.pw_uid));
            sp.display += " " + simple::owner_label(owner_id);   // the unit's Description=
#else
            owner_id = simple::current_user_sid();
            // The account's password must come through the private channel, and the account must be the requester's own,
            // whatever else the arguments say.
            if (o.password_pipe.empty()) throw Error("--user-service needs the private password channel (--password-pipe)");
            if (simple::account_sid(o.user) != owner_id) throw Error("the service must run as the account of the user who asks (" + o.user + " is not you)");
#endif
            if (!simple::user_service_name_matches_owner(name, owner_id))
                throw Error("a user service must be named mysync-<account>-<owner code>; '" + name + "' is not");
            sp.description += " " + simple::owner_label(owner_id);
        }
        if (!o.password_pipe.empty()) {
            // The account's password, from the private channel. Checked BEFORE anything is installed, so a wrong password is
            // reported at once; the right to log on as a service is granted to exactly this account, only if it lacks it.
            simple::SecretString pw;
            std::string perr;
            if (!simple::receive_password(o.password_pipe, o.password_nonce, &pw, &perr)) {
                std::cerr << "mysync: " << perr << "\n";
                return gui::kServiceGenericFailure;
            }
            simple::AccountCheck chk = simple::check_service_account(o.user, pw);
            if (!chk.ok) {
                std::cerr << "mysync: " << chk.error << "\n";
                return gui::kServiceConfigError;
            }
            if (o.user_service && chk.sid != simple::current_user_sid()) {
                std::cerr << "mysync: the service must run as the account of the user who asks (" << o.user << " is not you)\n";
                return gui::kServiceAccessDenied;
            }
            if (o.user_service) {   // the account's NEW logon token AND this process must both say 'ordinary'
                std::string why = simple::service_account_refusal(chk.admin, simple::account_admin_state(chk.sid));
                if (!why.empty()) {
                    std::cerr << "mysync: " << why << "\n";
                    return gui::kServiceAccessDenied;
                }
            }
            std::string gerr = simple::grant_service_logon_right(chk.sid, &right_added);
            right_sid = chk.sid;
            if (right_added) right_guard.granted(chk.sid);
            if (o.user_service && !simple::account_is_administrator(chk.sid))
                sp.args.insert(sp.args.end(), {"--state-writer", chk.sid});   // ordinary account: its state/ and log/ are its own
            if (!gerr.empty()) {
                std::cerr << "mysync: " << gerr << "\n";
                return gui::kServiceAccessDenied;
            }
            {
                std::string canon = simple::account_name_from_sid(chk.sid);   // DOMAIN\name from the SID, not the typed string
                if (!canon.empty()) sp.run_as = canon;
            }
            sp.run_as_password = pw.reveal();
            pw.clear();
        }
        if (o.user_service && !o.user.empty()) {
#ifndef _WIN32
            sp.run_group = simple::primary_group_of_user(o.user);
            sp.runtime_dir = name;          // /run/<service>/ owned by the user, mode 0700: the control socket is theirs alone
            sp.runtime_dir_mode = "0700";
            sp.strict_user = true;
#endif
        }
        for (const auto& t : trusted) {
            sp.args.push_back("--trust-writer");
            sp.args.push_back(t);
        }
        auto add = [&](const std::string& p) {
            if (!p.empty()) sp.read_write_paths.push_back(p);
        };
        if (role == Role::Server) {
            add(l.server.root);
            add(l.server.state_dir);
            if (!l.server.log_file.empty()) add(dir_of(l.server.log_file));
        } else {
            add(l.client.state_dir.empty() ? resolve(l.dir, "state") : l.client.state_dir);
            if (!l.client.log_file.empty()) add(dir_of(l.client.log_file));
            for (const auto& w : l.client.watches) {
                if (o.user_service) add(resolve(l.dir, w.path));   // the engine keeps its lock file in <folder>/__sync
                for (const auto& t : w.targets)
                    if (t.is_local()) add(resolve(l.dir, t.path));
            }
        }
        ok = service_install(sp, &err);
        if (!sp.run_as_password.empty()) {
            secure_wipe(&sp.run_as_password[0], sp.run_as_password.size());
            sp.run_as_password.clear();
        }
        if (right_added && ok) {   // remembered, so that removing the service takes it away again
            std::string marker = simple::user_service_locations(name).dir + "/.logon-right-added";
            bool written = false;
            {
                std::ofstream mo(marker, std::ios::binary | std::ios::trunc);
                mo << right_sid;
                mo.flush();
                written = static_cast<bool>(mo);
            }
            if (!written) {   // without the marker the right could never be taken away: undo the installation instead
                std::string ignore;
                service_uninstall(name, &ignore);
                err = "the service could not be recorded (" + marker + "); the installation was rolled back";
                ok = false;
            }
        }
        if (ok && !o.control_allow.empty()) {
            // Written only now that the service exists; if that fails the installation is undone.
            try {
                gui::ConfigEditor ed = gui::ConfigEditor::open(l.path, l.role == Role::Server ? gui::ConfigRole::Server : gui::ConfigRole::Client);
                auto& allow = l.role == Role::Server ? ed.server().control_allow : ed.client().control_allow;
                for (const auto& a : o.control_allow)
                    if (std::find(allow.begin(), allow.end(), a) == allow.end()) allow.push_back(a);
                ed.save();
            } catch (const std::exception& e) {
                std::string ignore;
                service_uninstall(name, &ignore);
                err = std::string("the configuration could not be updated with --control-allow (") + e.what() +
                      "); the service installation was rolled back";
                ok = false;
            }
        }
        if (ok) right_guard.release();   // a working service owns the right now (its marker is on disk)
    } else if (act == "uninstall") {
        ok = service_uninstall(name, &err);
        if (ok) {   // the right we added when the service was installed is taken away with it (never one we did not add)
            std::string marker = simple::user_service_locations(name).dir + "/.logon-right-added";
            std::ifstream mf(marker);
            std::string sid;
            if (mf >> sid) {
                std::string rerr = simple::revoke_service_logon_right(sid);
                if (!rerr.empty()) std::cerr << "mysync: warning: " << rerr << "\n";
                mf.close();
                std::error_code mec;
                fs::remove(fs::u8path(marker), mec);
            }
        }
    } else if (act == "start") {
        ok = service_start(name, &err);
    } else {
        ok = service_stop(name, &err);
    }
    if (!ok) {
        std::cerr << "mysync: service " << act << " failed: " << err << "\n";
        return gui::service_exit_code_for_error(err);
    }
    std::cout << "service " << name << ": " << act << " ok\n";
    return 0;
}

int dispatch(const std::vector<std::string>& a) {
    if (a.size() < 2) {
        std::cout << kHelp;
        return 2;
    }
    const std::string cmd = a[1];
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        std::cout << kHelp;
        return 0;
    }
    if (cmd == "version" || cmd == "--version") {
        std::cout << "mysync " << kVersion << "\n";
        return 0;
    }
    if (cmd == "keygen" || cmd == "peer" || cmd == "key" || cmd == "health" ||
        (cmd == "status" && std::find(a.begin(), a.end(), "--json") != a.end()))
        return cli_ops_main(a);  // server operations: non-interactive, scriptable (see cli_ops.h)
    Opts o = parse_opts(a, 2);
    if (cmd == "hash") return cmd_hash(o);
    if (cmd == "status") return cmd_status(o);
    if (cmd == "run") return cmd_run(o);
    if (cmd == "service") return cmd_service(o);
    usage("unknown command '" + cmd + "'");
}

std::vector<std::string> get_args(int argc, char** argv) {
    std::vector<std::string> out;
#ifdef _WIN32
    // UTF-8 arguments (the ANSI argv would mangle non-ASCII paths). Loaded dynamically: no extra link library.
    typedef LPWSTR* (WINAPI * Fn)(LPCWSTR, int*);
    HMODULE sh = LoadLibraryW(L"shell32.dll");
    Fn fn = sh ? reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(sh, "CommandLineToArgvW"))) : nullptr;
    int n = 0;
    LPWSTR* w = fn ? fn(GetCommandLineW(), &n) : nullptr;
    if (w) {
        for (int i = 0; i < n; ++i) {
            int len = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, nullptr, 0, nullptr, nullptr);
            std::string s(len > 0 ? static_cast<size_t>(len - 1) : 0, '\0');
            if (len > 1) WideCharToMultiByte(CP_UTF8, 0, w[i], -1, &s[0], len, nullptr, nullptr);
            out.push_back(s);
        }
        LocalFree(w);
        return out;
    }
#endif
    for (int i = 0; i < argc; ++i) out.push_back(argv[i]);
    return out;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    try {
        return dispatch(get_args(argc, argv));
    } catch (const UsageError& e) {
        std::cerr << "mysync: " << e.what() << "\n(run 'mysync help' for usage)\n";
        return 2;
    } catch (const Error& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "mysync: " << e.what() << "\n";
        return 1;
    }
}
