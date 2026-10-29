// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/key_mgr.h"

#include <algorithm>
#include <cctype>
#include <filesystem>

#include "mysync/hash.h"

namespace fs = std::filesystem;

namespace mysync::gui {
namespace {

std::string abs_utf8(const std::string& p) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(p), ec);
    return ec ? p : a.lexically_normal().u8string();
}

bool is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

void check_name(const std::string& n) {
    if (n.empty() || n.size() > 64) throw Error("the client name must be 1..64 characters");
    for (unsigned char c : n)
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\') throw Error("the client name has characters that are not allowed");
}

std::string clean_prefix(std::string p) {
    for (auto& c : p)
        if (c == '\\') c = '/';
    while (!p.empty() && p.back() == '/') p.pop_back();
    if (p.empty()) return p;
    bool bad = p[0] == '/' || (p.size() > 1 && p[1] == ':');
    size_t start = 0;
    while (!bad) {
        size_t e = p.find('/', start);
        std::string comp = p.substr(start, e == std::string::npos ? std::string::npos : e - start);
        if (comp.empty() || comp == "." || comp == ".." || comp == "__sync") bad = true;
        if (e == std::string::npos) break;
        start = e + 1;
    }
    if (bad) throw Error("invalid prefix (must be a relative sub-directory of the server root)");
    return p;
}

AllowedClient to_allowed(const ClientAcl& a) {
    AllowedClient r;
    r.name = a.name;
    r.public_hex = to_hex(a.public_key.data(), a.public_key.size());
    r.fingerprint = KeyManager::fingerprint(r.public_hex);
    r.read_only = a.read_only;
    r.prefix = a.prefix;
    r.max_sessions = a.max_sessions;
    r.max_write_bytes_per_hour = a.max_write_bytes_per_hour;
    r.max_bandwidth_kbps = a.max_bandwidth_kbps;
    return r;
}

ClientAcl to_acl(const AllowedClient& c) {
    check_name(c.name);
    ClientAcl a;
    a.name = c.name;
    a.public_key = parse_public_key_hex(KeyManager::normalize_public_hex(c.public_hex));
    a.read_only = c.read_only;
    a.prefix = clean_prefix(c.prefix);
    if (c.max_sessions < 1 || c.max_sessions > 10000) throw Error("max_sessions must be 1..10000");
    a.max_sessions = c.max_sessions;
    a.max_write_bytes_per_hour = c.max_write_bytes_per_hour;
    a.max_bandwidth_kbps = c.max_bandwidth_kbps;
    return a;
}

void check_unique(const std::vector<ClientAcl>& v, const ClientAcl& a, size_t skip) {
    for (size_t i = 0; i < v.size(); ++i) {
        if (i == skip) continue;
        if (v[i].name == a.name) throw Error("there is already a client called '" + a.name + "'");
        if (v[i].public_key == a.public_key)
            throw Error("this public key is already allowed as client '" + v[i].name + "'");
    }
}

}  // namespace

std::string KeyManager::fingerprint(const PubKey& key) {
    Hash256 h = hash_bytes(key.data(), key.size());
    std::string hex = to_hex(h.data(), 10);
    std::string out;
    for (size_t i = 0; i < hex.size(); i += 4) out += (i ? "-" : "") + hex.substr(i, 4);
    return out;
}

std::string KeyManager::fingerprint(const std::string& public_hex) {
    return fingerprint(key_from_hex(normalize_public_hex(public_hex)));
}

bool KeyManager::is_valid_public_hex(const std::string& text) {
    try {
        (void)normalize_public_hex(text);
        return true;
    } catch (const Error&) {
        return false;
    }
}

std::string KeyManager::normalize_public_hex(const std::string& pasted) {
    std::string s;
    for (char c : pasted) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == ':') continue;
        s += c;
    }
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.erase(0, 2);
    if (s.size() != 64 || !std::all_of(s.begin(), s.end(), is_hex))
        throw Error("not a valid public key: it must be exactly 64 hexadecimal characters");
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

GeneratedKey KeyManager::generate_key_file(const std::string& utf8_path, bool write_pub_file) {
    GeneratedKey g;
    g.key_file = abs_utf8(utf8_path);
    KeyPair kp = generate_keypair();
    save_keypair(g.key_file, kp);  // refuses to overwrite, never follows a symlink, owner-only permissions
    g.public_hex = key_to_hex(kp.pub);
    g.fingerprint = fingerprint(kp.pub);
    if (write_pub_file) {
        std::string pf = g.key_file + ".pub";
        try {
            if (!fs::exists(fs::u8path(pf))) {
                save_public_file(pf, kp.pub);
                g.pub_file = pf;
            }
        } catch (const std::exception&) {
        }
    }
    return g;
}

std::string KeyManager::public_key_of_file(const std::string& utf8_key_file) {
    KeyPair kp = load_keypair(utf8_key_file);
    return key_to_hex(kp.pub);
}

std::vector<std::string> KeyManager::key_file_exposure(const std::string& utf8_key_file) {
    return key_file_broad_acl(utf8_key_file);
}

std::vector<AllowedClient> KeyManager::list_clients(const ConfigEditor& ed) {
    std::vector<AllowedClient> out;
    for (const ClientAcl& a : ed.server().clients) out.push_back(to_allowed(a));
    return out;
}

void KeyManager::add_client(ConfigEditor& ed, const AllowedClient& c) {
    ClientAcl a = to_acl(c);
    auto& v = ed.server().clients;
    check_unique(v, a, v.size());
    v.push_back(std::move(a));
}

void KeyManager::update_client(ConfigEditor& ed, const std::string& name, const AllowedClient& c) {
    ClientAcl a = to_acl(c);
    auto& v = ed.server().clients;
    size_t idx = v.size();
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].name == name) idx = i;
    if (idx == v.size()) throw Error("there is no client called '" + name + "'");
    check_unique(v, a, idx);
    v[idx] = std::move(a);
}

void KeyManager::remove_client(ConfigEditor& ed, const std::string& name) {
    auto& v = ed.server().clients;
    auto it = std::find_if(v.begin(), v.end(), [&](const ClientAcl& a) { return a.name == name; });
    if (it == v.end()) throw Error("there is no client called '" + name + "'");
    if (v.size() == 1) throw Error("the last allowed client cannot be removed: a server needs at least one");
    v.erase(it);
}

void KeyManager::set_target_server_key(ConfigEditor& ed, size_t wi, size_t ti, const std::string& pasted) {
    auto& watches = ed.client().watches;
    if (wi >= watches.size() || ti >= watches[wi].targets.size()) throw Error("no such watch / target");
    TargetConfig& t = watches[wi].targets[ti];
    if (t.is_local()) throw Error("a local target has no server key");
    t.server_key = parse_public_key_hex(normalize_public_hex(pasted));
}

}  // namespace mysync::gui
