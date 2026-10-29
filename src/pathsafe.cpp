// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/pathsafe.h"

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace mysync {

namespace {

// Strict UTF-8 validation: no overlongs, no surrogates, max U+10FFFF.
bool valid_utf8(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            ++i;
            continue;
        }
        int len;
        uint32_t cp;
        if (c >= 0xC2 && c <= 0xDF) {
            len = 2;
            cp = c & 0x1F;
        } else if (c >= 0xE0 && c <= 0xEF) {
            len = 3;
            cp = c & 0x0F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            len = 4;
            cp = c & 0x07;
        } else {
            return false;
        }
        if (i + static_cast<size_t>(len) > n) return false;
        for (int k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + static_cast<size_t>(k)]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return false;
        if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) return false;
        i += static_cast<size_t>(len);
    }
    return true;
}

std::vector<std::string> split_components(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '/' || c == '\\') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// ASCII-only upper case (std::toupper would depend on the C locale for bytes >= 0x80).
std::string upper_ascii(std::string s) {
    for (auto& c : s)
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return s;
}

// Simple case folding for comparing internal names: ASCII lower case, plus the two non-ASCII code points whose
// simple folding is an ASCII letter and which Windows/macOS file systems may therefore treat as that letter:
// U+017F LATIN SMALL LETTER LONG S -> 's' and U+212A KELVIN SIGN -> 'k'. Other bytes are copied unchanged.
std::string fold_simple(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : static_cast<char>(c);
        } else if (c == 0xC5 && i + 1 < s.size() && static_cast<unsigned char>(s[i + 1]) == 0xBF) {
            out += 's';
            ++i;
        } else if (c == 0xE2 && i + 2 < s.size() && static_cast<unsigned char>(s[i + 1]) == 0x84 &&
                   static_cast<unsigned char>(s[i + 2]) == 0xAA) {
            out += 'k';
            i += 2;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

bool is_reserved_device(const std::string& comp) {
    std::string stem = comp.substr(0, comp.find('.'));
    while (!stem.empty() && stem.back() == ' ') stem.pop_back();
    stem = upper_ascii(stem);
    if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$")
        return true;
    if (stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) && stem[3] >= '1' &&
        stem[3] <= '9')
        return true;
    // Windows also reserves COM/LPT followed by superscript 1, 2, 3 (U+00B9, U+00B2, U+00B3; UTF-8 C2 B9/B2/B3).
    // Blocked on every platform so that a Windows destination stays safe.
    if (stem.size() == 5 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) &&
        static_cast<unsigned char>(stem[3]) == 0xC2) {
        unsigned char t = static_cast<unsigned char>(stem[4]);
        if (t == 0xB9 || t == 0xB2 || t == 0xB3) return true;
    }
    return false;
}

bool path_comp_equal(const fs::path& a, const fs::path& b) {
#ifdef _WIN32
    const auto& x = a.native();
    const auto& y = b.native();
    if (x.size() != y.size()) return false;
    for (size_t i = 0; i < x.size(); ++i)
        if (std::towlower(x[i]) != std::towlower(y[i])) return false;
    return true;
#else
    return a == b;
#endif
}

// True when p lies at or below root (both already canonical/absolute).
bool is_inside(const fs::path& root, const fs::path& p) {
    auto ri = root.begin(), re = root.end();
    auto pi = p.begin(), pe = p.end();
    for (; ri != re; ++ri, ++pi) {
        if (pi == pe) return false;
        if (ri->empty()) continue;  // trailing separator yields an empty last element
        if (!path_comp_equal(*ri, *pi)) return false;
    }
    return true;
}

}  // namespace

bool has_tmp_component(const std::string& rel_utf8) {
    static const std::string pre = ".mysync-tmp-";
    for (const auto& c : split_components(rel_utf8))
        if (fold_simple(c).compare(0, pre.size(), pre) == 0) return true;
    return false;
}

std::string normalize_rel(const std::string& rel_utf8) {
    bool lead = !rel_utf8.empty() && (rel_utf8[0] == '/' || rel_utf8[0] == '\\');
    std::string out = lead ? "/" : "";
    bool first = true;
    for (const auto& c : split_components(rel_utf8)) {
        if (c == ".") continue;
        if (!first) out += '/';
        out += c;
        first = false;
    }
    return out;
}

bool is_internal_dir(const std::string& rel_utf8) {
    auto comps = split_components(rel_utf8);
    for (const auto& c : comps) {
        if (c == ".") continue;
        return fold_simple(c) == "__sync";
    }
    return false;
}

fs::path safe_join(const std::string& root_utf8, const std::string& rel_utf8) {
    if (root_utf8.empty()) throw Error("path denied: empty root");
    if (rel_utf8.empty()) throw Error("path denied: empty path");
    if (!valid_utf8(rel_utf8)) throw Error("path denied: invalid UTF-8");
    for (char ch : rel_utf8) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7F) throw Error("path denied: control character");
        if (c == ':') throw Error("path denied: ':' not allowed");
        if (c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*')
            throw Error("path denied: forbidden character");
    }
    if (rel_utf8[0] == '/' || rel_utf8[0] == '\\') throw Error("path denied: absolute path");

    std::vector<std::string> comps;
    for (const auto& c : split_components(rel_utf8)) {
        if (c == ".") continue;
        if (c == "..") throw Error("path denied: '..' component");
        if (c.back() == ' ' || c.back() == '.') throw Error("path denied: component ends with space or dot");
        if (is_reserved_device(c)) throw Error("path denied: reserved device name");
        comps.push_back(c);
    }
    if (comps.empty()) throw Error("path denied: empty path");

    fs::path root = fs::u8path(root_utf8);
    fs::path rel;
    for (const auto& c : comps) rel /= fs::u8path(c);
    fs::path joined = root / rel;

    std::error_code ec;
    fs::path root_c = fs::weakly_canonical(root, ec);
    if (ec) throw Error("path denied: cannot resolve root");
    fs::path full_c = fs::weakly_canonical(joined, ec);
    if (ec) throw Error("path denied: cannot resolve path");
    if (!is_inside(root_c, full_c)) throw Error("path denied: escapes root");

    // A dangling (or any) symlink at the leaf is followed by writers; make sure its target stays inside too.
    fs::path cur = joined;
    for (int depth = 0; depth < 40; ++depth) {
        fs::file_status st = fs::symlink_status(cur, ec);
        if (!ec && fs::is_symlink(st)) {
            fs::path tgt = fs::read_symlink(cur, ec);
            if (ec) throw Error("path denied: unreadable symlink");
            if (tgt.is_relative()) tgt = cur.parent_path() / tgt;
            fs::path tc = fs::weakly_canonical(tgt, ec);
            if (ec) throw Error("path denied: cannot resolve symlink");
            if (!is_inside(root_c, tc)) throw Error("path denied: symlink escapes root");
            cur = tc;
            continue;
        }
        break;
    }
    return joined;
}

std::string to_rel(const fs::path& root, const fs::path& abs) {
    std::error_code ec;
    fs::path r = fs::weakly_canonical(root, ec);
    if (ec) r = root.lexically_normal();
    fs::path a = fs::weakly_canonical(abs, ec);
    if (ec) a = abs.lexically_normal();
    if (!is_inside(r, a)) throw Error("path is outside root");
    fs::path rel = a.lexically_relative(r);
    if (rel.empty() || rel == ".") throw Error("path is the root itself");
    std::string s = rel.generic_u8string();
    if (s == ".." || s.rfind("../", 0) == 0) throw Error("path is outside root");
    return s;
}

}  // namespace mysync
