// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "i18n_model.h"

#include <atomic>
#include <map>
#include <mutex>

namespace mysync::gui {

namespace {
struct Entry {
    const char* key;
    const char* vi;
    const char* en;
};
const Entry kTable[] = {
#include "i18n_strings.inc"
#include "i18n_strings_ui.inc"
};

std::atomic<int> g_lang{0};

const std::map<std::string, const Entry*>& index() {
    static const std::map<std::string, const Entry*> m = [] {
        std::map<std::string, const Entry*> r;
        for (const auto& e : kTable) r.emplace(e.key, &e);
        return r;
    }();
    return m;
}
}  // namespace

void set_lang(Lang l) { g_lang = static_cast<int>(l); }
Lang lang() { return g_lang == 1 ? Lang::En : Lang::Vi; }
const char* lang_code(Lang l) { return l == Lang::En ? "en" : "vi"; }
bool lang_from_code(const std::string& c, Lang& out) {
    if (c == "vi") { out = Lang::Vi; return true; }
    if (c == "en") { out = Lang::En; return true; }
    return false;
}

const std::string& tr(const char* key) {
    // Bộ nhớ đệm theo luồng: mỗi (khoá, ngôn ngữ) một std::string sống suốt chương trình.
    static std::mutex mu;
    static std::map<std::string, std::string> cache[2];
    std::lock_guard<std::mutex> lk(mu);
    int li = g_lang == 1 ? 1 : 0;
    auto& c = cache[li];
    auto it = c.find(key);
    if (it != c.end()) return it->second;
    auto f = index().find(key);
    std::string v = f == index().end() ? std::string("?") + key + "?" : (li ? f->second->en : f->second->vi);
    return c.emplace(key, std::move(v)).first->second;
}

std::string trf(const char* key, const std::vector<std::string>& args) {
    std::string s = tr(key), out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '{' && i + 2 < s.size() + 0 && s[i + 1] >= '0' && s[i + 1] <= '9' && s[i + 2] == '}') {
            size_t n = static_cast<size_t>(s[i + 1] - '0');
            if (n < args.size()) out += args[n];
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

size_t i18n_count() { return sizeof(kTable) / sizeof(kTable[0]); }
bool i18n_has(const char* key) { return index().count(key) != 0; }

std::vector<std::string> i18n_problems() {
    std::vector<std::string> p;
    std::map<std::string, int> seen;
    for (const auto& e : kTable) {
        if (++seen[e.key] == 2) p.push_back(std::string("duplicate key: ") + e.key);
        if (!e.vi || !*e.vi) p.push_back(std::string("missing vi: ") + e.key);
        if (!e.en || !*e.en) p.push_back(std::string("missing en: ") + e.key);
    }
    return p;
}

}  // namespace mysync::gui
