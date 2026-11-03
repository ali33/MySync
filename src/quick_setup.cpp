// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/quick_setup.h"

#include <cctype>
#include <cstdio>
#include <filesystem>

#include "mysync/config.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/key_mgr.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/gui/trust.h"
#include "mysync/keys.h"
#include "mysync/linkcheck.h"
#include "mysync/simple/user_paths.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace mysync {
namespace {

std::string abs_norm(const std::string& p) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(p), ec);
    return ec ? p : a.lexically_normal().u8string();
}

std::string strip_trailing_sep(std::string s) {
    while (s.size() > 1 && (s.back() == '/' || s.back() == '\\') && !(s.size() == 3 && s[1] == ':')) s.pop_back();
    return s;
}

std::string path_join(const std::string& dir, const std::string& leaf) {
    return (fs::u8path(dir) / fs::u8path(leaf)).lexically_normal().u8string();
}

bool is_symlink_or_exists(const std::string& p) {
    std::error_code ec;
    return fs::exists(fs::u8path(p), ec) || fs::is_symlink(fs::u8path(p), ec);
}

// Same check as the roots of the engine (linkcheck.h): a symbolic link OR a junction / mount point in any existing
// component of the path is refused (std::filesystem::is_symlink does not see junctions).
void refuse_symlink(const std::string& p) {
    std::string bad = link_refusal_text(p);
    if (!bad.empty()) throw Error("refusing to write through a link: " + bad);
    std::error_code ec;
    if (fs::is_symlink(fs::u8path(p), ec)) throw Error("refusing to write through a symbolic link: " + p);
}

// Same invariant as the other commands that write beside a privileged daemon: an administrator / root run must not
// write into a folder other people can change.
void guard_dir(const std::string& dir, const std::string& what) {
    refuse_symlink(dir);
    if (!gui::need_strict_trust(gui::ServiceController::is_elevated(), false)) return;
    try {
        gui::require_trusted_dir(dir, what, {});
    } catch (const Error& e) {
        throw UntrustedFolderError(dir, std::string(e.what()) + "; --fix-permissions makes it private (you, SYSTEM and Administrators only)");   // typed, so the GUI can explain it and offer make_folder_private
    }
}

// Creates `dir` (and parents) when missing. Returns true when it did.
bool ensure_dir(const std::string& dir, const std::string& what) {
    std::error_code ec;
    fs::path p = fs::u8path(dir);
    if (fs::exists(p, ec)) {
        if (!fs::is_directory(p, ec)) throw Error(what + " exists but is not a folder: " + dir);
        return false;
    }
    refuse_symlink(dir);
    fs::create_directories(p, ec);
    if (ec) throw Error("cannot create " + what + " " + dir + ": " + ec.message());
    make_folder_private(dir);   // a folder we create starts private, whatever the parent lets other accounts do
    return true;
}

std::string toml_str(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if (static_cast<unsigned char>(c) < 0x20) throw Error("a control character cannot be written to the configuration");
        if (c == '\\' || c == '"') o += '\\';
        o += c;
    }
    return o + "\"";
}

std::string sanitize_label(const std::string& in, const std::string& fallback) {
    std::string o;
    for (char c : in) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        o += ok ? c : '-';
    }
    while (!o.empty() && o.front() == '-') o.erase(o.begin());
    while (!o.empty() && o.back() == '-') o.pop_back();
    if (o.size() > 48) o.resize(48);
    return o.empty() ? fallback : o;
}

std::string shell_quote_if_needed(const std::string& s) {
    bool plain = !s.empty();
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7f) throw Error("a control character in a path cannot be printed in a command");
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || std::string("_@%+=:,./-").find(static_cast<char>(c)) != std::string::npos || c >= 0x80;
#ifdef _WIN32
        if (c == '\\') ok = true;
#endif
        if (!ok) plain = false;
    }
    if (plain) return s;
#ifdef _WIN32
    if (s.find('"') != std::string::npos || s.find('%') != std::string::npos) throw Error("a quote in a path cannot be printed in a command");
    return "\"" + s + "\"";
#else
    std::string o = "'";   // POSIX: single quotes expand nothing
    for (char c : s) {
        if (c == '\'') o += "'\\''";
        else o += c;
    }
    return o + "'";
#endif
}

// Key: keep the one that exists (also checks owner / permissions via the real loader), else create it.
void ensure_key(const std::string& key_file, QuickResult& r) {
    if (is_symlink_or_exists(key_file)) {
        r.public_key = gui::KeyManager::public_key_of_file(key_file);   // fails on a broken / unsafe key; the message never echoes key bytes
        r.key_existed = true;
    } else {
        gui::GeneratedKey g = gui::KeyManager::generate_key_file(key_file, true);
        r.public_key = g.public_hex;
        r.key_created = true;
    }
    r.key_file = key_file;
    r.fingerprint = gui::KeyManager::fingerprint(r.public_key);
}

void check_inside(const std::string& config_dir, const std::string& dir, const char* what) {
    std::error_code ec;
    fs::path a = fs::weakly_canonical(fs::u8path(config_dir), ec);   // resolves links / junctions / short names of what exists
    if (ec) a = fs::u8path(config_dir);
    fs::path b = fs::weakly_canonical(fs::u8path(dir), ec);
    if (ec) b = fs::u8path(dir);
    auto fold = [](std::string s) {
#ifdef _WIN32
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
#endif
        return s;
    };
    auto ai = a.begin();
    auto bi = b.begin();
    bool inside = true;   // every element of the shared folder is a prefix of the config folder
    for (; bi != b.end(); ++bi, ++ai) {
        if (bi->empty()) continue;
        if (ai == a.end() || fold(ai->u8string()) != fold(bi->u8string())) { inside = false; break; }
    }
    if (inside) throw Error(std::string("the configuration folder must be outside the ") + what + " (" + dir + ")");
}

}  // namespace

void parse_host_port(const std::string& text, std::string& host, uint16_t& port) {
    std::string t = text;
    while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.erase(t.begin());
    while (!t.empty() && (t.back() == ' ' || t.back() == '\t' || t.back() == '\r' || t.back() == '\n')) t.pop_back();
    if (t.empty()) throw Error("the server address is empty (use host:port)");
    std::string h, p;
    if (t[0] == '[') {   // [v6]:port
        size_t e = t.find(']');
        if (e == std::string::npos) throw Error("the server address has an unclosed '['");
        h = t.substr(1, e - 1);
        if (e + 1 < t.size()) {
            if (t[e + 1] != ':') throw Error("the server address: expected ':port' after ']'");
            p = t.substr(e + 2);
        }
    } else {
        size_t c = t.rfind(':');
        if (c != std::string::npos && t.find(':') == c) {   // exactly one ':' = host:port
            h = t.substr(0, c);
            p = t.substr(c + 1);
        } else {
            h = t;   // bare name, or a bare IPv6 address with no port
        }
    }
    if (h.empty()) throw Error("the server address has no host");
    for (char c : h)
        if (static_cast<unsigned char>(c) <= 0x20 || c == '"' || c == '\\' || c == '/' || c == '\'')
            throw Error("the server address has a character that is not allowed in a host name");
    uint32_t pn = kQuickDefaultPort;
    if (!p.empty()) {
        if (p.size() > 5 || p.find_first_not_of("0123456789") != std::string::npos) throw Error("the server port must be a number 1-65535");
        pn = static_cast<uint32_t>(std::stoul(p));
        if (pn < 1 || pn > 65535) throw Error("the server port must be 1-65535");
    }
    host = h;
    port = static_cast<uint16_t>(pn);
}

std::string default_quick_config_dir(const std::string& dir) {
    std::string d = strip_trailing_sep(abs_norm(dir));
    fs::path p = fs::u8path(d);
    if (!p.has_filename() || p.parent_path() == p) throw Error("cannot place the configuration beside " + dir + ": give --config-dir");
    return d + ".mysync";
}

std::string make_client_snippet(const std::string& host, uint16_t port, const std::string& server_public_hex,
                                const std::string& watch_name, bool vi) {
    std::string s;
    s += "[client]\n";
    s += std::string("key_file = \"client.key\"   # ") + (vi ? "tạo khoá trên máy khách: mysync keygen --out client.key" : "create it on the client machine: mysync keygen --out client.key") + "\n\n";
    s += "[[watch]]\n";
    s += "name = " + toml_str(sanitize_label(watch_name, "du-lieu")) + "\n";
    s += std::string("path = \"THU-MUC-CAN-DONG-BO\"   # ") + (vi ? "thay bằng thư mục cần đồng bộ" : "replace with the folder to synchronise") + "\n\n";
    s += "[[watch.target]]\n";
    s += "host = " + toml_str(host) + "\n";
    s += "port = " + std::to_string(port) + "\n";
    s += "server_key = " + toml_str(server_public_hex) + "\n";
    try {
        (void)parse_client_config_text(s);
    } catch (const Error& e) {
        throw Error(std::string("internal error: the client snippet does not load: ") + e.what());
    }
    return s;
}

std::string make_peer_add_command(const std::string& client_public, const std::string& name, const std::string& server_config_path) {
    return "mysync peer add " + client_public + " --name " + sanitize_label(name, "may-khach") + " --perm rw -c " +
           shell_quote_if_needed(server_config_path);
}

bool prepare_shared_folder(const std::string& dir, bool fix_permissions) {
    std::error_code ec;
    if (fix_permissions && fs::is_directory(fs::u8path(dir), ec)) make_folder_private(dir);
    guard_dir(dir, "the shared folder");
    bool created = ensure_dir(dir, "the shared folder");
    guard_dir(dir, "the shared folder");   // judged again now that it exists
    return created;
}

void make_folder_private(const std::string& dir) {
    refuse_symlink(dir);
    fs::path p = fs::u8path(dir);
#ifdef _WIN32
    std::string me = simple::current_user_sid();
    if (me.empty()) throw Error("cannot read the account of this process to set the permissions of '" + dir + "'");
    std::wstring sddl = L"D:P(A;OICI;FA;;;" + fs::u8path(me).wstring() + L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr))
        throw Error("cannot build the private permissions for '" + dir + "'");
    BOOL present = FALSE, dflt = FALSE;
    PACL dacl = nullptr;
    DWORD rc = ERROR_INVALID_PARAMETER;
    if (GetSecurityDescriptorDacl(psd, &present, &dacl, &dflt) && present)
        rc = SetNamedSecurityInfoW(const_cast<LPWSTR>(p.c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    LocalFree(psd);
    if (rc != ERROR_SUCCESS) throw Error("cannot change the permissions of '" + dir + "' (error " + std::to_string(rc) + ")");
#else
    struct stat st{};
    if (::lstat(p.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) throw Error("not a folder: " + dir);
    if (::chmod(p.c_str(), st.st_mode & 07755 & ~static_cast<mode_t>(S_IWGRP | S_IWOTH)) != 0)
        throw Error("cannot change the permissions of '" + dir + "'");
#endif
}

QuickResult quick_server(const QuickServerOptions& o) {
    if (o.dir.empty()) throw Error("--dir <folder> is required");
    if (o.port == 0) throw Error("the port must be 1-65535");
    QuickResult r;
    r.role = "server";
    r.dir = strip_trailing_sep(abs_norm(o.dir));
    r.config_dir = strip_trailing_sep(abs_norm(o.config_dir.empty() ? default_quick_config_dir(o.dir) : o.config_dir));
    // the key and the allowlist must not sit inside the shared root: they would be served to the clients
    check_inside(r.config_dir, r.dir, "shared folder");
    r.config_file = path_join(r.config_dir, "server.toml");
    std::string key_file = path_join(r.config_dir, "server.key");
    std::string peers_dir = path_join(r.config_dir, "peers.d");
    std::string label = sanitize_label(o.name, "may-khach");

    if (o.fix_permissions) {
        std::error_code ec;
        if (fs::is_directory(fs::u8path(r.dir), ec)) make_folder_private(r.dir);
        if (fs::is_directory(fs::u8path(r.config_dir), ec)) make_folder_private(r.config_dir);
    }
    guard_dir(r.dir, "the shared folder");
    guard_dir(r.config_dir, "the configuration folder");
    refuse_symlink(r.config_file);
    r.dir_created = ensure_dir(r.dir, "the shared folder");
    ensure_dir(r.config_dir, "the configuration folder");
    guard_dir(r.dir, "the shared folder");                 // judged again now that they exist
    guard_dir(r.config_dir, "the configuration folder");
    check_inside(r.config_dir, r.dir, "shared folder");    // and the containment check again on the real paths

    r.config_existed = is_symlink_or_exists(r.config_file);
    bool keep = r.config_existed && !o.force;
    if (r.config_existed && o.force) {   // forcing the file must not change the server's identity: reuse the old key / peers locations
        try {
            ServerConfig old = load_server_config(r.config_file);
            if (!old.key_file.empty()) key_file = fs::u8path(old.key_file).is_relative() ? path_join(r.config_dir, old.key_file) : old.key_file;
            if (!old.peers_dir.empty()) peers_dir = fs::u8path(old.peers_dir).is_relative() ? path_join(r.config_dir, old.peers_dir) : old.peers_dir;
        } catch (const Error&) {
            r.notes.push_back("the old configuration could not be read: a key at the default place is used");
        }
    }
    if (keep) {
        ServerConfig existing = load_server_config(r.config_file);   // an unreadable / invalid file is an error, never silently replaced
        key_file = existing.key_file;
        if (key_file.empty()) throw Error("the existing configuration has no key_file: " + r.config_file);
        if (fs::u8path(key_file).is_relative()) key_file = path_join(r.config_dir, key_file);
        r.pairing = pairing_name(existing.pairing);
        r.port = existing.port;
        if (existing.port != o.port && o.port != kQuickDefaultPort)
            r.notes.push_back("the existing configuration listens on port " + std::to_string(existing.port) + " (asked for " +
                              std::to_string(o.port) + "): kept; use --force to rewrite it");
        if (existing.pairing != PairingMode::Off)
            r.notes.push_back("the existing configuration has pairing = \"" + r.pairing + "\" (this command only writes \"off\")");
    }
    ensure_key(key_file, r);

    if (!keep) {
        ensure_dir(peers_dir, "the peers folder");
        guard_dir(peers_dir, "the peers folder");
        gui::ConfigEditor ed = gui::ConfigEditor::create(r.config_file, gui::ConfigRole::Server);
        ServerConfig& c = ed.server();
        c.bind = "*";
        c.port = o.port;
        c.root = r.dir;
        c.key_file = key_file;
        c.peers_dir = peers_dir;
        c.pairing = PairingMode::Off;
        // quotas, max_file_size, trash, file/dir modes: the defaults of ServerConfig (the same as examples/server.toml)
        gui::SaveOptions so;
        so.force = o.force;
        ed.save(so);
        if (r.config_existed) r.config_replaced = true;
        else r.config_created = true;
        r.port = o.port;
        r.pairing = pairing_name(PairingMode::Off);
        (void)load_server_config(r.config_file);   // what is on disk loads with the same parser as the daemon
    }

    r.client_snippet = make_client_snippet("TEN-HOAC-IP-MAY-CHU", r.port, r.public_key, label, o.vietnamese_comments);
    r.peer_add_command = make_peer_add_command("<KHOA-CONG-KHAI-CUA-MAY-KHACH>", label, r.config_file);
    return r;
}

QuickResult quick_client(const QuickClientOptions& o) {
    if (o.dir.empty()) throw Error("--dir <folder> is required");
    if (o.server.empty()) throw Error("--server host:port is required");
    if (o.server_key.empty()) throw Error("--server-key <public key, 64 hex> is required");
    std::string host;
    uint16_t port = 0;
    parse_host_port(o.server, host, port);
    std::string key_hex = gui::KeyManager::normalize_public_hex(o.server_key);   // the message never echoes the input

    QuickResult r;
    r.role = "client";
    r.dir = strip_trailing_sep(abs_norm(o.dir));
    r.config_dir = strip_trailing_sep(abs_norm(o.config_dir.empty() ? default_quick_config_dir(o.dir) : o.config_dir));
    check_inside(r.config_dir, r.dir, "synchronised folder");
    r.config_file = path_join(r.config_dir, "client.toml");
    std::string key_file = path_join(r.config_dir, "client.key");
    std::string label = sanitize_label(o.name, "may-khach");

    {
        std::error_code ec;
        if (!fs::is_directory(fs::u8path(r.dir), ec)) throw Error("the folder to synchronise does not exist: " + r.dir);
    }
    if (o.fix_permissions) {
        std::error_code ec;
        if (fs::is_directory(fs::u8path(r.config_dir), ec)) make_folder_private(r.config_dir);
    }
    guard_dir(r.config_dir, "the configuration folder");
    refuse_symlink(r.config_file);
    ensure_dir(r.config_dir, "the configuration folder");
    guard_dir(r.config_dir, "the configuration folder");

    r.config_existed = is_symlink_or_exists(r.config_file);
    bool keep = r.config_existed && !o.force;
    r.server_address = (host.find(':') != std::string::npos ? "[" + host + "]" : host) + ":" + std::to_string(port);
    if (keep) {
        ClientConfig ex = load_client_config(r.config_file);
        if (ex.key_file.empty()) throw Error("the existing configuration has no key_file: " + r.config_file);
        key_file = ex.key_file;
        if (fs::u8path(key_file).is_relative()) key_file = path_join(r.config_dir, key_file);
        bool same = false;
        for (const auto& w : ex.watches)
            for (const auto& t : w.targets)
                if (!t.is_local() && t.host == host && t.port == port && key_to_hex(t.server_key) == key_hex) same = true;
        if (!same) r.notes.push_back("the existing configuration does not point at this server and key: kept; use --force to rewrite it");
    }
    ensure_key(key_file, r);

    if (!keep) {
        gui::ConfigEditor ed = gui::ConfigEditor::create(r.config_file, gui::ConfigRole::Client);
        ClientConfig& c = ed.client();
        c.key_file = key_file;
        WatchConfig w;
        w.name = sanitize_label(fs::u8path(r.dir).filename().u8string(), "du-lieu");
        w.path = r.dir;
        TargetConfig t;
        t.host = host;
        t.port = port;
        t.server_key = parse_public_key_hex(key_hex);
        w.targets.push_back(t);
        c.watches.push_back(w);
        gui::SaveOptions so;
        so.force = o.force;
        ed.save(so);
        if (r.config_existed) r.config_replaced = true;
        else r.config_created = true;
        (void)load_client_config(r.config_file);
    }
    r.peer_add_command = make_peer_add_command(r.public_key, label, "server.toml");
    return r;
}

std::string quick_result_json(const QuickResult& r) {
    auto q = [](const std::string& s) {
        std::string o = "\"";
        auto u = [&](unsigned v) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", v); o += b; };
        for (size_t i = 0; i < s.size();) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == '"' || c == '\\') { o += '\\'; o += static_cast<char>(c); ++i; }
            else if (c == '\n') { o += "\\n"; ++i; }
            else if (c == '\r') { o += "\\r"; ++i; }
            else if (c == '\t') { o += "\\t"; ++i; }
            else if (c < 0x20 || c == 0x7f) { u(c); ++i; }
            else if (c < 0x80) { o += static_cast<char>(c); ++i; }
            else {   // above 0x7F: decode UTF-8 and write \uXXXX (invalid bytes become U+FFFD), so the output is always ASCII + valid JSON
                int n = c >= 0xF0 && c < 0xF8 ? 3 : c >= 0xE0 ? 2 : c >= 0xC2 && c < 0xE0 ? 1 : -1;
                if (c >= 0xF8) n = -1;
                unsigned cp = n == 3 ? c & 0x07 : n == 2 ? c & 0x0F : c & 0x1F;
                bool ok = n > 0 && i + static_cast<size_t>(n) < s.size();
                for (int k = 1; ok && k <= n; ++k) {
                    unsigned char d = static_cast<unsigned char>(s[i + static_cast<size_t>(k)]);
                    if ((d & 0xC0) != 0x80) ok = false;
                    else cp = (cp << 6) | (d & 0x3F);
                }
                if (ok && ((n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp <= 0xDFFF))) ok = false;
                if (!ok) { u(0xFFFD); ++i; continue; }
                if (cp >= 0x10000) { cp -= 0x10000; u(0xD800 + (cp >> 10)); u(0xDC00 + (cp & 0x3FF)); }
                else u(cp);
                i += static_cast<size_t>(n) + 1;
            }
        }
        return o + "\"";
    };
    auto b = [](bool v) { return v ? "true" : "false"; };
    std::string s = "{\"role\":" + q(r.role) + ",\"changed\":" + b(r.changed()) + ",\"dir\":" + q(r.dir) +
                    ",\"config_dir\":" + q(r.config_dir) + ",\"config_file\":" + q(r.config_file) + ",\"key_file\":" + q(r.key_file) +
                    ",\"public_key\":" + q(r.public_key) + ",\"fingerprint\":" + q(r.fingerprint) +
                    ",\"dir_created\":" + b(r.dir_created) + ",\"key_created\":" + b(r.key_created) + ",\"key_existed\":" + b(r.key_existed) +
                    ",\"config_created\":" + b(r.config_created) + ",\"config_existed\":" + b(r.config_existed) +
                    ",\"config_replaced\":" + b(r.config_replaced);
    if (r.role == "server") s += ",\"port\":" + std::to_string(r.port) + ",\"pairing\":" + q(r.pairing) + ",\"client_snippet\":" + q(r.client_snippet);
    else s += ",\"server\":" + q(r.server_address);
    s += ",\"peer_add_command\":" + q(r.peer_add_command) + ",\"notes\":[";
    for (size_t i = 0; i < r.notes.size(); ++i) s += (i ? "," : "") + q(r.notes[i]);
    return s + "]}\n";
}

}  // namespace mysync
