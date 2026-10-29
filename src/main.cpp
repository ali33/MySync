// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// main.cpp - the `mysync` command line: keygen, run, status, service, hash, version, help.
//
// Roles: one configuration file = one role. A file with [server] / [[client]] is a server file, one with
// [client] / [[watch]] is a client file (the two parsers are strict and reject each other's tables). Role is detected
// from those markers; --role server|client overrides the detection. A machine that is both server and client runs two
// processes / two services from two files.
#include <atomic>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "mysync/client_engine.h"
#include "mysync/config.h"
#include "mysync/hash.h"
#include "mysync/keys.h"
#include "mysync/server.h"
#include "mysync/service.h"
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
    "  mysync keygen [-o <keyfile>]            create an identity key (default ./mysync.key); prints the PUBLIC key\n"
    "  mysync run -c <config> [--role server|client] [--once]\n"
    "                                          run in the foreground (Ctrl+C stops). --once = one sync pass, then exit\n"
    "  mysync status -c <config> [--role ...]  show the loaded configuration (no secrets)\n"
    "  mysync service install|uninstall|start|stop [-c <config>] [--role server|client] [--name N] [--user U]\n"
    "                                          install/remove/start/stop the Windows service or systemd unit (admin/root)\n"
    "  mysync hash <file>                      BLAKE3 of a file\n"
    "  mysync version | help\n"
    "\n"
    "The role of a config file is detected from its tables ([server]/[[client]] = server, [[watch]] = client).\n"
    "Exit code: 0 ok, 1 runtime error, 2 usage or configuration error.\n";

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
        else if (s == "--once") o.once = true;
        else if (s == "--service") o.service = true;
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
        l.server = load_server_config(l.path);
        l.server.root = resolve(l.dir, l.server.root);
        l.server.key_file = resolve(l.dir, l.server.key_file);
        l.server.state_dir = resolve(l.dir, l.server.state_dir);
        l.server.log_file = resolve(l.dir, l.server.log_file);
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
int cmd_keygen(const Opts& o) {
    std::string out = o.out.empty() ? "mysync.key" : o.out;
    KeyPair kp = generate_keypair();
    save_keypair(out, kp);  // refuses to overwrite; 0600 on POSIX
    std::string pub = key_to_hex(kp.pub);
    std::string pubfile = out + ".pub";
    try {
        if (!fs::exists(fs::u8path(pubfile))) save_public_file(pubfile, kp.pub);
        else pubfile.clear();
    } catch (const std::exception&) {
        pubfile.clear();
    }
    std::cerr << "secret key written to " << out << " (keep it private, never copy it to the other machine)\n";
    if (!pubfile.empty()) std::cerr << "public key also in " << pubfile << "\n";
    std::cerr << "give the public key below to the other side:\n";
    std::cout << pub << "\n";
    return 0;
}

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

int cmd_run(const Opts& o) {
    Loaded l = load_config(o);
    std::function<void(std::atomic<bool>&)> body;
    int rc = 0;
    if (l.role == Role::Server) {
        if (o.once) usage("--once only applies to a client");
        setup_log(l.server.log_level, l.server.log_file);
        ServerConfig sc = l.server;
        body = [sc](std::atomic<bool>& stop) {
            Server srv(sc);
            log_info("MySync server " + std::string(kVersion) + " listening on " + sc.bind + ":" + std::to_string(srv.port()) +
                     ", root " + sc.root + ", public key " + key_to_hex(srv.public_key()));
            srv.run(stop);
            log_info("server stopped");
        };
    } else {
        setup_log(l.client.log_level, l.client.log_file);
        ClientConfig cc = l.client;
        std::string dir = l.dir;
        bool once = o.once;
        int* prc = &rc;
        body = [cc, dir, once, prc](std::atomic<bool>& stop) {
            SyncEngine eng(cc, dir);
            log_info("MySync client " + std::string(kVersion) + (once ? ": one sync pass" : ": watching"));
            if (once) {
                eng.sync_once(stop);
                EngineStats s = eng.stats();
                if (s.gave_up > 0) *prc = 1;
            } else {
                eng.run(stop);
            }
        };
    }
    if (o.service) {
        std::string name = o.name.empty() ? default_service_name(l.role) : o.name;
        return run_as_service(name, body);
    }
    install_signal_handlers(g_stop);
    try {
        body(g_stop);
    } catch (const std::exception& e) {
        log_error(std::string("fatal: ") + e.what());
        std::cerr << "mysync: " << e.what() << "\n";
        return 1;
    }
    return rc;
}

int cmd_service(const Opts& o) {
    if (o.pos.size() != 1) usage("usage: mysync service install|uninstall|start|stop [options]");
    const std::string& act = o.pos[0];
    if (act != "install" && act != "uninstall" && act != "start" && act != "stop") usage("unknown service action " + act);
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
    std::string err;
    bool ok = false;
    if (act == "install") {
        if (o.config.empty()) usage("service install needs -c <config>");
        std::string exe = self_exe();
        if (exe.empty()) throw Error("cannot determine the path of the mysync executable");
        ServiceSpec sp;
        sp.name = name;
        sp.display = role == Role::Server ? "MySync server" : "MySync client";
        sp.description = "MySync file synchronisation (" + std::string(role == Role::Server ? "server" : "client") + ")";
        sp.exe_path = exe;
        sp.args = {"run", "-c", l.path, "--role", role == Role::Server ? "server" : "client", "--service", "--name", name};
        sp.run_as = o.user;
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
            for (const auto& w : l.client.watches)
                for (const auto& t : w.targets)
                    if (t.is_local()) add(resolve(l.dir, t.path));
        }
        ok = service_install(sp, &err);
    } else if (act == "uninstall") {
        ok = service_uninstall(name, &err);
    } else if (act == "start") {
        ok = service_start(name, &err);
    } else {
        ok = service_stop(name, &err);
    }
    if (!ok) {
        std::cerr << "mysync: service " << act << " failed: " << err << "\n";
        return 1;
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
    Opts o = parse_opts(a, 2);
    if (cmd == "keygen") return cmd_keygen(o);
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
