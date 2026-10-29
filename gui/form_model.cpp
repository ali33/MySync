// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "form_model.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <regex>

#include "i18n_model.h"
#include "mysync/filter.h"
#include "mysync/util.h"

namespace mysync::gui {

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : text) {
        if (c == '\n' || c == '\r') {
            auto t = trim(cur);
            if (!t.empty()) out.push_back(t);
            cur.clear();
        } else {
            cur += c;
        }
    }
    auto t = trim(cur);
    if (!t.empty()) out.push_back(t);
    return out;
}

std::string join_lines(const std::vector<std::string>& v) {
    std::string r;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) r += "\n";
        r += v[i];
    }
    return r;
}

namespace {
bool all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (c < '0' || c > '9') return false;
    return true;
}
bool valid_ipv4(const std::string& s) {
    int parts = 0;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = s.find('.', i);
        if (j == std::string::npos) j = s.size();
        std::string p = s.substr(i, j - i);
        if (!all_digits(p) || p.size() > 3 || std::stoi(p) > 255) return false;
        ++parts;
        i = j + 1;
        if (j == s.size()) break;
    }
    return parts == 4;
}
bool valid_ipv6(const std::string& s) {
    if (s.find(':') == std::string::npos || s.size() > 45) return false;
    int groups = 0, dbl = 0;
    size_t i = 0;
    for (size_t k = 0; k + 1 < s.size(); ++k)
        if (s[k] == ':' && s[k + 1] == ':') ++dbl;
    if (dbl > 1) return false;
    while (i < s.size()) {
        size_t j = s.find(':', i);
        if (j == std::string::npos) j = s.size();
        std::string p = s.substr(i, j - i);
        if (!p.empty()) {
            if (p.find('.') != std::string::npos) {
                if (!valid_ipv4(p)) return false;
                groups += 2;
            } else {
                if (p.size() > 4) return false;
                for (char c : p)
                    if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
                ++groups;
            }
        }
        i = j + 1;
    }
    return dbl ? groups < 8 : groups == 8;
}
}  // namespace

std::string check_port(const std::string& text, uint16_t* out) {
    uint64_t v = 0;
    auto e = check_uint(text, 1, 65535, &v);
    if (!e.empty()) return tr("err.port");
    if (out) *out = static_cast<uint16_t>(v);
    return "";
}

std::string check_host(const std::string& text) {
    std::string t = trim(text);
    if (t.empty()) return tr("err.required");
    if (t.size() > 253) return tr("err.host");
    for (char c : t) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']')) return tr("err.host");
    }
    return "";
}

std::string check_uint(const std::string& text, uint64_t lo, uint64_t hi, uint64_t* out) {
    std::string t = trim(text);
    if (!all_digits(t) || t.size() > 18) return trf("err.uint", {std::to_string(lo), std::to_string(hi)});
    uint64_t v = std::strtoull(t.c_str(), nullptr, 10);
    if (v < lo || v > hi) return trf("err.uint", {std::to_string(lo), std::to_string(hi)});
    if (out) *out = v;
    return "";
}

std::string check_size(const std::string& text, bool allow_empty, uint64_t* out) {
    std::string t = trim(text);
    if (t.empty()) {
        if (out) *out = 0;
        return allow_empty ? "" : tr("err.required");
    }
    try {
        uint64_t v = parse_size(t);
        if (out) *out = v;
        return "";
    } catch (const std::exception&) {
        return tr("err.size");
    }
}

std::string check_mtime(const std::string& text) {
    std::string t = trim(text);
    if (t.empty()) return "";
    // Tương đối: số + d/h/m/s/w (7d, 12h).
    if (t.size() >= 2 && all_digits(t.substr(0, t.size() - 1)) && std::string("dhmsw").find(t.back()) != std::string::npos)
        return "";
    // Tuyệt đối: YYYY-MM-DD[THH:MM[:SS]]
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    char tail = 0;
    int n = std::sscanf(t.c_str(), "%4d-%2d-%2d%c%2d:%2d:%2d", &y, &mo, &d, &tail, &h, &mi, &s);
    if (n == 3 || (n >= 6 && (tail == 'T' || tail == ' '))) {
        if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h < 24 && mi < 60 && s < 61 && y >= 1970) return "";
    }
    return tr("err.mtime");
}

std::string check_hhmm(const std::string& text) {
    std::string t = trim(text);
    int h = 0, m = 0;
    char x = 0;
    if (t.size() == 5 && t[2] == ':' && std::sscanf(t.c_str(), "%2d:%2d%c", &h, &m, &x) == 2 && h >= 0 && h < 24 &&
        m >= 0 && m < 60)
        return "";
    return tr("err.hhmm");
}

std::string check_glob_or_ext(const std::string& text) {
    std::string t = trim(text);
    if (t.empty()) return tr("err.required");
    if (t.find('"') != std::string::npos) return tr("err.glob");
    return "";
}

std::string check_regex(const std::string& text) {
    std::string t = trim(text);
    if (t.empty()) return tr("err.required");
    try {
        std::regex re(t, std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
        return trf("err.regex", {e.what()});
    }
    return "";
}

std::string check_ip_rule(const std::string& text) {
    std::string t = trim(text);
    if (t == "*") return "";
    auto slash = t.find('/');
    if (slash == std::string::npos) return valid_ipv4(t) || valid_ipv6(t) ? "" : tr("err.ip");
    std::string addr = t.substr(0, slash), bits = t.substr(slash + 1);
    if (!all_digits(bits) || bits.size() > 3) return tr("err.ip");
    int b = std::stoi(bits);
    if (valid_ipv4(addr)) return b <= 32 ? "" : tr("err.ip");
    if (valid_ipv6(addr)) return b <= 128 ? "" : tr("err.ip");
    return tr("err.ip");
}

std::string check_octal_mode(const std::string& text, bool is_dir, uint32_t* out) {
    std::string t = trim(text);
    if (t.empty() || t.size() > 4) return tr("err.mode");
    uint32_t v = 0;
    for (char c : t) {
        if (c < '0' || c > '7') return tr("err.mode");
        v = v * 8 + static_cast<uint32_t>(c - '0');
    }
    if (!is_dir && ((v & 0111) || (v & 0600) != 0600)) return tr("err.mode_file");
    if (is_dir && (v & 0700) != 0700) return tr("err.mode_dir");
    if (out) *out = v;
    return "";
}

std::string check_service_name(const std::string& text) {
    if (text.empty() || text.size() > 64 || text[0] == '-' || text[0] == '.') return tr("err.svcname");
    for (char c : text) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '_' || c == '.' || c == '-')) return tr("err.svcname");
    }
    return "";
}

std::string check_prefix(const std::string& text) {
    std::string t = trim(text);
    if (t.empty()) return "";
    if (t.front() == '/' || t.back() == '/' || t.find('\\') != std::string::npos || t.find("..") != std::string::npos ||
        t.find("//") != std::string::npos)
        return tr("err.prefix");
    return "";
}

std::string check_nonempty(const std::string& text) { return trim(text).empty() ? tr("err.required") : ""; }

std::string check_client_name(const std::string& text) {
    std::string t = trim(text);
    if (t.empty()) return tr("err.required");
    if (t.size() > 64) return tr("err.clientname");
    for (char c : t)
        if (static_cast<unsigned char>(c) < 0x20) return tr("err.clientname");
    return "";
}

std::string check_lines(const std::string& text, std::string (*fn)(const std::string&)) {
    auto v = split_lines(text);
    for (size_t i = 0; i < v.size(); ++i) {
        auto e = fn(v[i]);
        if (!e.empty()) return trf("err.line", {std::to_string(i + 1), e});
    }
    return "";
}
std::string check_ip_lines(const std::string& t) { return check_lines(t, check_ip_rule); }
std::string check_hhmm_lines(const std::string& t) { return check_lines(t, check_hhmm); }
std::string check_glob_lines(const std::string& t) { return check_lines(t, check_glob_or_ext); }
std::string check_regex_lines(const std::string& t) { return check_lines(t, check_regex); }

std::string size_to_text(uint64_t b) {
    if (b == 0) return "0";
    static const struct {
        uint64_t m;
        const char* u;
    } units[] = {{1ull << 40, "TB"}, {1ull << 30, "GB"}, {1ull << 20, "MB"}, {1ull << 10, "KB"}};
    for (auto& u : units)
        if (b % u.m == 0) return std::to_string(b / u.m) + u.u;
    return std::to_string(b);
}

std::string mode_to_text(uint32_t m) {
    char b[16];
    std::snprintf(b, sizeof b, "%04o", m & 07777);
    return b;
}

}  // namespace mysync::gui

namespace mysync::gui {

bool key_is_unset(const PublicKey& k) {
    for (auto b : k)
        if (b) return false;
    return true;
}

namespace {
void add_if(std::vector<std::string>& out, const std::string& where, const std::string& err) {
    if (!err.empty()) out.push_back(where + ": " + err);
}
std::string u(const char* key) { return tr(key); }
}  // namespace

std::vector<std::string> problems_client(const ClientConfig& c) {
    std::vector<std::string> p;
    bool need_key = false;
    add_if(p, u("cfg.connections"), check_uint(std::to_string(c.connections), 1, 64));
    if (c.compress != "none" && c.compress != "lz4") p.push_back(u("cfg.compress") + ": none | lz4");
    if (c.retry_min_ms > c.retry_max_ms) p.push_back(u("cfg.retry_min") + ": " + u("err.retry"));
    if (c.watches.empty()) p.push_back(u("err.nowatch"));
    for (size_t i = 0; i < c.watches.size(); ++i) {
        const auto& w = c.watches[i];
        std::string at = u("cfg.watch") + " " + (w.name.empty() ? "#" + std::to_string(i + 1) : "'" + w.name + "'");
        add_if(p, at + " / " + u("cfg.w.name"), check_nonempty(w.name));
        add_if(p, at + " / " + u("cfg.w.path"), check_nonempty(w.path));
        for (size_t j = 0; j < w.schedule_at.size(); ++j) add_if(p, at + " / " + u("cfg.w.schedule_at"), check_hhmm(w.schedule_at[j]));
        for (const auto& s : w.filter.include) add_if(p, at + " / " + u("cfg.f.include"), check_glob_or_ext(s));
        for (const auto& s : w.filter.include_regex) add_if(p, at + " / " + u("cfg.f.include_regex"), check_regex(s));
        for (const auto& s : w.filter.exclude_regex) add_if(p, at + " / " + u("cfg.f.exclude_regex"), check_regex(s));
        add_if(p, at + " / " + u("cfg.f.size_min"), check_size(w.filter.size_min, true));
        add_if(p, at + " / " + u("cfg.f.size_max"), check_size(w.filter.size_max, true));
        add_if(p, at + " / " + u("cfg.f.mtime_after"), check_mtime(w.filter.mtime_after));
        add_if(p, at + " / " + u("cfg.f.mtime_before"), check_mtime(w.filter.mtime_before));
        if (w.targets.empty()) p.push_back(at + ": " + u("err.notarget"));
        for (size_t j = 0; j < w.targets.size(); ++j) {
            const auto& t = w.targets[j];
            std::string tt = at + " / " + u("cfg.target") + " #" + std::to_string(j + 1);
            if (t.is_local()) {
                add_if(p, tt, check_prefix(t.remote_prefix));
            } else {
                need_key = need_key || t.key_file.empty();
                add_if(p, tt + " / " + u("cfg.t.host"), check_host(t.host));
                if (t.port == 0) p.push_back(tt + " / " + u("cfg.t.port") + ": " + u("err.port"));
                if (key_is_unset(t.server_key)) p.push_back(tt + " / " + u("cfg.t.server_key") + ": " + u("err.nokey"));
                add_if(p, tt + " / " + u("cfg.t.remote_prefix"), check_prefix(t.remote_prefix));
            }
        }
    }
    if (need_key) add_if(p, u("cfg.key_file"), check_nonempty(c.key_file));
    return p;
}

std::vector<std::string> problems_server(const ServerConfig& c) {
    std::vector<std::string> p;
    add_if(p, u("cfg.s.root"), check_nonempty(c.root));
    add_if(p, u("cfg.key_file"), check_nonempty(c.key_file));
    if (c.port == 0) p.push_back(u("cfg.s.port") + ": " + u("err.port"));
    add_if(p, u("cfg.s.bind"), check_nonempty(c.bind));
    add_if(p, u("cfg.s.max_connections"), check_uint(std::to_string(c.max_connections), 1, 100000));
    for (const auto& s : c.allow) add_if(p, u("cfg.s.allow"), check_ip_rule(s));
    for (const auto& s : c.deny) add_if(p, u("cfg.s.deny"), check_ip_rule(s));
    if (c.clients.empty()) p.push_back(u("err.noclient"));
    return p;
}

}  // namespace mysync::gui
