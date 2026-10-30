// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/wizard_model.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>

#include "mysync/gui/config_io.h"
#include "mysync/gui/key_mgr.h"

namespace fs = std::filesystem;

namespace mysync::simple {
namespace {

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Absolute, normalised, symlinks resolved as far as the path exists.
fs::path normal(const std::string& utf8) {
    std::error_code ec;
    fs::path p = fs::absolute(fs::u8path(utf8), ec);
    fs::path w = fs::weakly_canonical(p, ec);
    return ec ? p.lexically_normal() : w;
}

std::string cmp_key(const fs::path& p) {
    std::string s = p.generic_u8string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
#ifdef _WIN32
    s = lower(s);
#endif
    return s;
}

bool same_path(const fs::path& a, const fs::path& b) { return cmp_key(a) == cmp_key(b); }

// `a` is strictly inside `b`.
bool is_inside(const fs::path& a, const fs::path& b) {
    std::string ka = cmp_key(a), kb = cmp_key(b);
    if (ka.size() <= kb.size()) return false;
    if (ka.compare(0, kb.size(), kb) != 0) return false;
    return kb.back() == '/' || ka[kb.size()] == '/';
}

bool writable_dir(const fs::path& dir, std::string* why) {
    std::error_code ec;
    fs::path probe = dir / (".mysync-probe-" + std::to_string(now_unix_ns() % 1000000007LL));
    {
        std::ofstream f(probe, std::ios::binary);
        if (!f) {
            if (why) *why = dir.u8string();
            return false;
        }
        f << "x";
    }
    fs::remove(probe, ec);
    return true;
}

bool name_ok(const std::string& n) {
    if (n.empty() || n.size() > 64) return false;
    for (unsigned char c : n)
        if (c < 0x20 || c == 0x7F || c == '"' || c == '\\') return false;
    return true;
}

bool has_internal_component(const fs::path& p) {
    for (const auto& c : p)
        if (lower(c.u8string()) == "__sync") return true;
    return false;
}

}  // namespace

std::string default_watch_name(const std::string& source_folder) {
    fs::path p = fs::u8path(source_folder);
    std::string n = p.filename().u8string();
    if (n.empty() || n == "." || n == "..") n = p.parent_path().filename().u8string();
    std::string out;
    for (unsigned char c : n) {
        if (c < 0x20 || c == 0x7F || c == '"' || c == '\\' || c == '/') continue;
        out += static_cast<char>(c);
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    if (out.size() > 64) {
        out.resize(64);
        while (!out.empty() && (static_cast<unsigned char>(out.back()) & 0xC0) == 0x80) out.pop_back();  // keep UTF-8 whole
        if (!out.empty() && static_cast<unsigned char>(out.back()) >= 0xC0) out.pop_back();
    }
    return out.empty() ? "folder" : out;
}

std::vector<WizardIssue> validate_wizard(const WizardInput& in) {
    std::vector<WizardIssue> v;
    auto add = [&](const char* k, const std::string& d = {}) { v.push_back({k, d}); };
    if (!in.watch_name.empty() && !name_ok(in.watch_name)) add("wizard.bad_name", in.watch_name);

    fs::path src;
    bool src_ok = false;
    if (in.source.empty()) {
        add("wizard.source_empty");
    } else {
        std::error_code ec;
        src = normal(in.source);
        if (!fs::exists(src, ec)) add("wizard.source_missing", in.source);
        else if (!fs::is_directory(src, ec)) add("wizard.source_not_dir", in.source);
        else if (src == src.root_path() || src.filename().empty()) add("wizard.source_is_root", in.source);
        else if (has_internal_component(src)) add("wizard.source_internal", in.source);
        else src_ok = true;
    }

    if (in.kind == DestKind::Folder) {
        if (in.dest_path.empty()) {
            add("wizard.dest_empty");
        } else {
            std::error_code ec;
            fs::path dst = normal(in.dest_path);
            bool dst_ok = false;
            if (fs::exists(dst, ec)) {
                if (!fs::is_directory(dst, ec)) add("wizard.dest_missing", in.dest_path);
                else {
                    std::string why;
                    if (!writable_dir(dst, &why)) add("wizard.dest_not_writable", in.dest_path);
                    else dst_ok = true;
                }
            } else {
                // A destination that does not exist yet is created when its parent exists and can be written.
                fs::path parent = dst.parent_path();
                std::string why;
                if (parent.empty() || !fs::is_directory(parent, ec)) add("wizard.dest_missing", in.dest_path);
                else if (!writable_dir(parent, &why)) add("wizard.dest_not_writable", parent.u8string());
                else dst_ok = true;
            }
            if (dst_ok && has_internal_component(dst)) {
                add("wizard.dest_missing", in.dest_path);
                dst_ok = false;
            }
            if (src_ok && dst_ok) {
                if (same_path(src, dst)) add("wizard.same_folder", in.source);
                else if (is_inside(dst, src)) add("wizard.dest_inside_source", in.dest_path);
                else if (is_inside(src, dst)) add("wizard.source_inside_dest", in.source);
            }
        }
    } else {
        if (in.paired.port == 0 || in.paired.host.empty()) add("wizard.pair_missing");
    }
    return v;
}

ClientConfig build_client_config(const WizardInput& in, const UserPaths& paths) {
    if (in.source.empty()) throw Error("wizard.source_empty");
    ClientConfig c;
    c.key_file = paths.client_key;
    c.state_dir = paths.client_state;
    c.log_file = paths.client_log;
    c.log_level = "info";
    c.control_enabled = true;
    c.control_name = paths.client_control_name;
    // c.max_bandwidth_kbps stays 0 (no cap); connections / compression keep the defaults.

    WatchConfig w;
    w.name = in.watch_name.empty() ? default_watch_name(in.source) : in.watch_name;
    w.path = normal(in.source).u8string();
    w.enabled = true;
    w.recursive = true;
    w.start_sync = true;          // reconcile once at start, then watch in real time
    w.propagate_delete = true;    // removals / overwrites go to the target's trash (see localtarget / server)
    // Temporary and system files nobody wants copied. Substrings are case-insensitive; the two regexes cover
    // "~$*" (Office lock files) and "*.tmp" in a case-insensitive way.
    w.filter.exclude = {"thumbs.db", "desktop.ini", "$recycle.bin", ".ds_store", "$recycle.bin/"};
    w.filter.exclude_regex = {"(^|/)~\\$[^/]*$", "\\.[Tt][Mm][Pp]$"};

    TargetConfig t;
    if (in.kind == DestKind::Folder) {
        if (in.dest_path.empty()) throw Error("wizard.dest_empty");
        t.path = normal(in.dest_path).u8string();
    } else {
        if (in.paired.port == 0 || in.paired.host.empty()) throw Error("wizard.pair_missing");
        t.host = in.paired.host;
        t.port = in.paired.port;
        t.server_key = in.paired.server_key;
    }
    t.enabled = true;
    w.targets.push_back(t);
    c.watches.push_back(w);
    return c;
}

std::string ensure_user_key(const std::string& key_file) {
    std::error_code ec;
    if (!fs::exists(fs::u8path(key_file), ec)) {
        gui::KeyManager::generate_key_file(key_file, /*write_pub_file=*/false);
        restrict_to_current_user(key_file, false);
    }
    return gui::KeyManager::public_key_of_file(key_file);
}

KeyPair ensure_client_key(const UserPaths& paths) {
    paths.ensure_dirs();
    ensure_user_key(paths.client_key);
    return load_keypair(paths.client_key);
}

bool read_receiver_settings(const UserPaths& paths, ReceiverSettings* out) {
    std::error_code ec;
    if (!fs::exists(fs::u8path(paths.receiver_config), ec)) return false;
    try {
        ServerConfig c = load_server_config(paths.receiver_config);
        if (out) {
            out->root = c.root;
            out->port = c.port;
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

void save_wizard(const WizardInput& in, const UserPaths& paths) {
    std::vector<WizardIssue> issues = validate_wizard(in);
    if (issues.empty()) {
        // The program's own files must never end up inside what it synchronises (or the other way round).
        fs::path src = normal(in.source), cfg = normal(paths.dir);
        if (is_inside(cfg, src) || same_path(cfg, src) || is_inside(src, cfg))
            issues.push_back({"wizard.source_internal", in.source});
        if (in.kind == DestKind::Folder) {
            fs::path dst = normal(in.dest_path);
            if (is_inside(cfg, dst) || same_path(cfg, dst) || is_inside(dst, cfg))
                issues.push_back({"wizard.dest_inside_source", in.dest_path});
        }
    }
    if (!issues.empty()) throw Error(issues[0].key + (issues[0].detail.empty() ? "" : ": " + issues[0].detail));

    paths.ensure_dirs();
    ensure_user_key(paths.client_key);
    if (in.kind == DestKind::Folder) {
        std::error_code ec;
        fs::create_directories(fs::u8path(in.dest_path), ec);
        if (ec) throw Error("wizard.dest_not_writable: " + in.dest_path);
    }
    ClientConfig fresh = build_client_config(in, paths);

    std::error_code ec;
    if (fs::exists(fs::u8path(paths.client_config), ec)) {
        gui::ConfigEditor ed = gui::ConfigEditor::open(paths.client_config, gui::ConfigRole::Client);
        ClientConfig& c = ed.client();
        std::set<std::string> names;
        for (const auto& w : c.watches) names.insert(w.name);
        WatchConfig w = fresh.watches[0];
        std::string base = w.name;
        for (int n = 2; names.count(w.name); ++n) w.name = base + " (" + std::to_string(n) + ")";
        c.watches.push_back(w);
        // Make sure the control channel and key paths are the per-user ones.
        if (c.control_name.empty()) c.control_name = paths.client_control_name;
        ed.save();
    } else {
        gui::ConfigEditor ed = gui::ConfigEditor::create(paths.client_config, gui::ConfigRole::Client);
        ed.client() = fresh;
        ed.save();
        restrict_to_current_user(paths.client_config, false);
    }
}

std::vector<WizardIssue> validate_receiver_root(const std::string& receive_root, const UserPaths& paths) {
    std::vector<WizardIssue> v;
    auto add = [&](const char* k, const std::string& d = {}) { v.push_back({k, d}); };
    if (receive_root.empty()) { add("receiver.root_empty"); return v; }
    std::error_code ec;
    fs::path root = normal(receive_root);
    if (root == root.root_path() || root.filename().empty()) { add("receiver.root_is_root", receive_root); return v; }
    if (fs::exists(root, ec)) {
        std::string why;
        if (!fs::is_directory(root, ec)) { add("receiver.root_missing", receive_root); return v; }
        if (!writable_dir(root, &why)) { add("receiver.root_not_writable", receive_root); return v; }
    } else {
        fs::path parent = root.parent_path();
        std::string why;
        if (parent.empty() || !fs::is_directory(parent, ec)) { add("receiver.root_missing", receive_root); return v; }
        if (!writable_dir(parent, &why)) { add("receiver.root_not_writable", parent.u8string()); return v; }
    }
    fs::path own = normal(paths.dir);
    if (same_path(root, own) || is_inside(root, own) || is_inside(own, root)) add("receiver.root_internal", receive_root);
    // A folder this computer already sends from (or sits inside / around) would feed itself.
    if (fs::exists(fs::u8path(paths.client_config), ec)) {
        try {
            ClientConfig c = load_client_config(paths.client_config);
            for (const auto& w : c.watches) {
                fs::path src = normal(w.path);
                if (same_path(root, src) || is_inside(root, src) || is_inside(src, root)) {
                    add("receiver.root_is_source", w.path);
                    break;
                }
            }
        } catch (const std::exception&) {  // an unreadable client configuration is reported elsewhere
        }
    }
    return v;
}

std::string ensure_receiver_config(const std::string& receive_root, const UserPaths& paths, uint16_t port) {
    std::vector<WizardIssue> issues = validate_receiver_root(receive_root, paths);
    if (!issues.empty()) throw Error(issues[0].key + (issues[0].detail.empty() ? "" : ": " + issues[0].detail));
    paths.ensure_dirs();
    std::string pub = ensure_user_key(paths.receiver_key);
    std::error_code ec;
    fs::create_directories(fs::u8path(receive_root), ec);
    if (ec) throw Error("receiver.root_not_writable: " + receive_root);
    std::string peers = (fs::u8path(paths.dir) / "peers.d").u8string();
    fs::create_directories(fs::u8path(peers), ec);
    restrict_to_current_user(peers, true);

    bool exists = fs::exists(fs::u8path(paths.receiver_config), ec);
    gui::ConfigEditor ed = exists ? gui::ConfigEditor::open(paths.receiver_config, gui::ConfigRole::Server)
                                  : gui::ConfigEditor::create(paths.receiver_config, gui::ConfigRole::Server);
    ServerConfig& s = ed.server();
    s.bind = "*";
    s.port = port;
    s.root = normal(receive_root).u8string();
    s.key_file = paths.receiver_key;
    s.state_dir = paths.receiver_state;
    s.log_file = paths.receiver_log;
    s.log_level = "info";
    s.control_enabled = true;
    s.control_name = paths.receiver_control_name;
    s.pairing = PairingMode::OnDemand;
    s.peers_dir = peers;
    s.trash = true;
    ed.save();
    if (!exists) restrict_to_current_user(paths.receiver_config, false);
    return pub;
}

}  // namespace mysync::simple
