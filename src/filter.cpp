// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/filter.h"

#include <cmath>
#include <cstdio>
#include <ctime>

namespace mysync {
namespace {

std::string lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

bool ends_with(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool has_wildcard(const std::string& s) { return s.find_first_of("*?") != std::string::npos; }

// '*' and '?' stay inside one path component, "**" crosses '/'. "**/" also matches zero directories.
bool glob_rec(const char* p, const char* pe, const char* s, const char* se, const char* sbegin) {
    while (p < pe) {
        if (*p == '*') {
            if (p + 1 < pe && p[1] == '*') {
                const char* q = p + 2;
                bool slash = q < pe && *q == '/';
                if (slash) ++q;
                for (const char* t = s;; ++t) {
                    bool boundary = !slash || t == sbegin || t[-1] == '/';
                    if (boundary && glob_rec(q, pe, t, se, sbegin)) return true;
                    if (t == se) break;
                }
                return false;
            }
            ++p;
            for (const char* t = s;; ++t) {
                if (glob_rec(p, pe, t, se, sbegin)) return true;
                if (t == se || *t == '/') break;
            }
            return false;
        }
        if (s == se) return false;
        if (*p == '?') {
            if (*s == '/') return false;
        } else if (*p != *s) {
            return false;
        }
        ++p;
        ++s;
    }
    return s == se;
}

bool glob_match(const std::string& pat, const std::string& s) {
    return glob_rec(pat.data(), pat.data() + pat.size(), s.data(), s.data() + s.size(), s.data());
}

std::regex compile_regex(const std::string& p) {
    try {
        return std::regex(p, std::regex::ECMAScript | std::regex::optimize);
    } catch (const std::regex_error& e) {
        throw Error("invalid regular expression '" + p + "': " + e.what());
    }
}

bool in_range(int v, int lo, int hi) { return v >= lo && v <= hi; }

// Returns {relative?, value}: relative spans are ns, absolute values are unix ns (local time).
void parse_time(const std::string& text, bool& relative, int64_t& value) {
    std::string t;
    for (char c : text)
        if (c != ' ') t += c;
    if (t.empty()) throw Error("empty time expression");
    char unit = t.back();
    if (unit == 's' || unit == 'm' || unit == 'h' || unit == 'd' || unit == 'w') {
        std::string num = t.substr(0, t.size() - 1);
        if (num.empty() || num.size() > 9 || num.find_first_not_of("0123456789") != std::string::npos)
            throw Error("invalid relative time '" + text + "' (examples: 7d, 12h)");
        int64_t n = std::stoll(num);
        int64_t mult = unit == 's' ? 1 : unit == 'm' ? 60 : unit == 'h' ? 3600 : unit == 'd' ? 86400 : 604800;
        relative = true;
        value = n * mult * 1000000000LL;
        return;
    }
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0, used = 0;
    int got = std::sscanf(t.c_str(), "%d-%d-%d%n", &y, &mo, &d, &used);
    bool ok = got == 3;
    if (ok && static_cast<size_t>(used) < t.size()) {
        char sep = t[static_cast<size_t>(used)];
        int used2 = 0;
        int got2 = std::sscanf(t.c_str() + used + 1, "%d:%d:%d%n", &h, &mi, &se, &used2);
        ok = (sep == 'T' || sep == 't') && got2 == 3 &&
             static_cast<size_t>(used + 1 + used2) == t.size();
    }
    if (!ok || !in_range(mo, 1, 12) || !in_range(d, 1, 31) || !in_range(h, 0, 23) ||
        !in_range(mi, 0, 59) || !in_range(se, 0, 60) || y < 1970 || y > 2999)
        throw Error("invalid time '" + text + "' (use 2026-01-01T00:00:00, or 7d / 12h)");
    std::tm tmv{};
    tmv.tm_year = y - 1900;
    tmv.tm_mon = mo - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = h;
    tmv.tm_min = mi;
    tmv.tm_sec = se;
    tmv.tm_isdst = -1;
    std::time_t tt = std::mktime(&tmv);
    if (tt == static_cast<std::time_t>(-1)) throw Error("time out of range '" + text + "'");
    relative = false;
    value = static_cast<int64_t>(tt) * 1000000000LL;
}

} // namespace

bool is_temp_name(const std::string& name) {
    if (name.empty()) return false;
    if (name.compare(0, 12, ".mysync-tmp-") == 0) return true;
    if (name.compare(0, 2, "~$") == 0 || name.compare(0, 2, ".#") == 0) return true;
    if (name.back() == '~') return true;
    if (name.size() > 2 && name.front() == '#' && name.back() == '#') return true;
    std::string l = lower(name);
    if (ends_with(l, ".tmp")) return true;
    size_t dot = name.rfind('.');
    if (dot != std::string::npos && dot > 0 && name.find_first_of("$#~", dot) != std::string::npos) return true;
    return false;
}

uint64_t parse_size(const std::string& text) {
    size_t i = 0, n = text.size();
    while (i < n && text[i] == ' ') ++i;
    size_t ns = i;
    bool dot = false;
    while (i < n && ((text[i] >= '0' && text[i] <= '9') || text[i] == '_' || (text[i] == '.' && !dot))) {
        if (text[i] == '.') dot = true;
        ++i;
    }
    std::string num;
    for (size_t k = ns; k < i; ++k)
        if (text[k] != '_') num += text[k];
    if (num.empty() || num == ".") throw Error("invalid size '" + text + "'");
    while (i < n && text[i] == ' ') ++i;
    std::string unit = lower(text.substr(i));
    while (!unit.empty() && unit.back() == ' ') unit.pop_back();
    double mult = 1;
    if (unit.empty() || unit == "b") mult = 1;
    else if (unit == "k" || unit == "kb" || unit == "kib") mult = 1024.0;
    else if (unit == "m" || unit == "mb" || unit == "mib") mult = 1024.0 * 1024;
    else if (unit == "g" || unit == "gb" || unit == "gib") mult = 1024.0 * 1024 * 1024;
    else if (unit == "t" || unit == "tb" || unit == "tib") mult = 1024.0 * 1024 * 1024 * 1024;
    else throw Error("invalid size unit in '" + text + "'");
    double v;
    try {
        v = std::stod(num) * mult;
    } catch (const std::exception&) {
        throw Error("invalid size '" + text + "'");
    }
    if (!(v >= 0) || v >= 9.0e18) throw Error("size out of range '" + text + "'");
    return static_cast<uint64_t>(std::llround(v));
}

Filter::Filter(const FilterConfig& cfg) {
    for (const auto& raw : cfg.include) {
        std::string p = lower(raw);
        if (p.empty()) continue;
        if (has_wildcard(p)) include_glob_.push_back(p);
        else if (p[0] == '.') include_ext_.push_back(p);
        else include_glob_.push_back(p);  // exact file name (or relative path when it has '/')
    }
    for (const auto& r : cfg.include_regex) include_re_.push_back(compile_regex(r));
    for (const auto& e : cfg.exclude)
        if (!e.empty()) exclude_.push_back(lower(e));
    for (const auto& r : cfg.exclude_regex) exclude_re_.push_back(compile_regex(r));
    if (!cfg.size_min.empty()) { has_size_min_ = true; size_min_ = parse_size(cfg.size_min); }
    if (!cfg.size_max.empty()) { has_size_max_ = true; size_max_ = parse_size(cfg.size_max); }
    if (has_size_min_ && has_size_max_ && size_min_ > size_max_)
        throw Error("size_min is greater than size_max");
    if (!cfg.mtime_after.empty()) {
        after_.set = true;
        parse_time(cfg.mtime_after, after_.relative, after_.value);
    }
    if (!cfg.mtime_before.empty()) {
        before_.set = true;
        parse_time(cfg.mtime_before, before_.relative, before_.value);
    }
}

bool Filter::match_dir(const std::string& rel) const {
    if (rel.empty()) return true;
    size_t start = 0;
    for (;;) {
        size_t e = rel.find('/', start);
        std::string comp = rel.substr(start, e == std::string::npos ? std::string::npos : e - start);
        if (comp == "__sync" || comp.compare(0, 12, ".mysync-tmp-") == 0) return false;
        if (e == std::string::npos) break;
        start = e + 1;
    }
    if (!exclude_.empty()) {
        std::string l = lower(rel);
        for (const auto& x : exclude_)
            if (l.find(x) != std::string::npos) return false;
    }
    return true;
}

bool Filter::match(const std::string& rel, uint64_t size, int64_t mtime_ns) const {
    if (rel.empty()) return false;
    size_t start = 0;
    std::string base;
    for (;;) {
        size_t e = rel.find('/', start);
        bool last = e == std::string::npos;
        std::string comp = rel.substr(start, last ? std::string::npos : e - start);
        if (comp == "__sync" || comp.compare(0, 12, ".mysync-tmp-") == 0) return false;
        if (last) {
            if (is_temp_name(comp)) return false;
            base = std::move(comp);
            break;
        }
        start = e + 1;
    }

    if (has_size_min_ && size < size_min_) return false;
    if (has_size_max_ && size > size_max_) return false;

    std::string lrel = lower(rel);
    for (const auto& x : exclude_)
        if (lrel.find(x) != std::string::npos) return false;
    for (const auto& re : exclude_re_)
        if (std::regex_search(rel, re)) return false;

    if (!includes_all()) {
        std::string lbase = lower(base);
        bool ok = false;
        for (const auto& ext : include_ext_)
            if (ends_with(lbase, ext)) { ok = true; break; }
        if (!ok)
            for (const auto& g : include_glob_) {
                const std::string& subject = g.find('/') != std::string::npos ? lrel : lbase;
                if (glob_match(g, subject)) { ok = true; break; }
            }
        if (!ok)
            for (const auto& re : include_re_)
                if (std::regex_search(rel, re)) { ok = true; break; }
        if (!ok) return false;
    }

    if (after_.set || before_.set) {
        int64_t now = (after_.relative || before_.relative) ? now_unix_ns() : 0;
        if (after_.set) {
            int64_t bound = after_.relative ? now - after_.value : after_.value;
            if (mtime_ns < bound) return false;
        }
        if (before_.set) {
            int64_t bound = before_.relative ? now - before_.value : before_.value;
            if (mtime_ns >= bound) return false;
        }
    }
    return true;
}

} // namespace mysync
