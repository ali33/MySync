// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/config.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#include "mysync/filter.h"
#include "mysync/keys.h"

namespace fs = std::filesystem;

namespace mysync {
namespace {

// ---------------------------------------------------------------- parsed document

struct Val {
    enum Type { Str, Int, Bool, Arr } type = Str;
    std::string s;
    int64_t i = 0;
    bool b = false;
    std::vector<Val> a;
    int line = 0;
};

struct Entry {
    std::string key;
    Val v;
    int line = 0;
};

struct Section {
    std::vector<std::string> path;  // empty = root
    bool is_array = false;
    int line = 0;
    std::vector<Entry> entries;
};

[[noreturn]] void fail(int line, const std::string& msg) {
    throw Error(msg + " at line " + std::to_string(line));
}

void append_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

bool is_bare(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

class Parser {
public:
    explicit Parser(const std::string& t) : t_(t) {
        if (t_.size() >= 3 && static_cast<uint8_t>(t_[0]) == 0xEF && static_cast<uint8_t>(t_[1]) == 0xBB &&
            static_cast<uint8_t>(t_[2]) == 0xBF)
            p_ = 3;
    }

    std::vector<Section> parse() {
        std::vector<Section> secs(1);
        secs[0].line = 1;
        for (;;) {
            skip_blank();
            if (eof()) break;
            if (cur() == '[') {
                Section s;
                s.line = line_;
                ++p_;
                if (!eof() && cur() == '[') { s.is_array = true; ++p_; }
                for (;;) {
                    skip_ws();
                    s.path.push_back(parse_key());
                    skip_ws();
                    if (!eof() && cur() == '.') { ++p_; continue; }
                    break;
                }
                if (eof() || cur() != ']') fail(line_, "expected ']' in table header");
                ++p_;
                if (s.is_array) {
                    if (eof() || cur() != ']') fail(line_, "expected ']]' in array-of-tables header");
                    ++p_;
                }
                end_of_line();
                secs.push_back(std::move(s));
            } else {
                Entry e;
                e.line = line_;
                e.key = parse_key();
                skip_ws();
                if (eof() || cur() != '=') fail(line_, "expected '=' after key '" + e.key + "'");
                ++p_;
                skip_ws();
                e.v = parse_value();
                end_of_line();
                for (const auto& o : secs.back().entries)
                    if (o.key == e.key) fail(e.line, "duplicate key '" + e.key + "'");
                secs.back().entries.push_back(std::move(e));
            }
        }
        return secs;
    }

private:
    const std::string& t_;
    size_t p_ = 0;
    int line_ = 1;

    bool eof() const { return p_ >= t_.size(); }
    char cur() const { return t_[p_]; }

    void skip_ws() {
        while (!eof() && (cur() == ' ' || cur() == '\t' || cur() == '\r')) ++p_;
    }
    void skip_comment() {
        if (!eof() && cur() == '#')
            while (!eof() && cur() != '\n') ++p_;
    }
    // blank lines, whitespace and comments (also used between array items)
    void skip_blank() {
        for (;;) {
            skip_ws();
            skip_comment();
            if (!eof() && cur() == '\n') { ++line_; ++p_; continue; }
            break;
        }
    }
    void end_of_line() {
        skip_ws();
        skip_comment();
        if (eof()) return;
        if (cur() != '\n') fail(line_, "unexpected characters after value");
    }

    std::string parse_key() {
        if (eof()) fail(line_, "expected a key");
        if (cur() == '"') return parse_basic();
        if (cur() == '\'') return parse_literal();
        size_t s = p_;
        while (!eof() && is_bare(cur())) ++p_;
        if (s == p_) fail(line_, std::string("invalid key character '") + cur() + "'");
        return t_.substr(s, p_ - s);
    }

    std::string parse_basic() {
        if (t_.compare(p_, 3, "\"\"\"") == 0) fail(line_, "multi-line strings are not supported");
        ++p_;
        std::string out;
        for (;;) {
            if (eof() || cur() == '\n') fail(line_, "unterminated string");
            char c = cur();
            ++p_;
            if (c == '"') break;
            if (c != '\\') { out += c; continue; }
            if (eof()) fail(line_, "unterminated string");
            char e = cur();
            ++p_;
            switch (e) {
                case '\\': out += '\\'; break;
                case '"': out += '"'; break;
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    if (p_ + 4 > t_.size()) fail(line_, "truncated \\u escape");
                    uint32_t cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = t_[p_ + static_cast<size_t>(k)];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= static_cast<uint32_t>(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= static_cast<uint32_t>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= static_cast<uint32_t>(h - 'A' + 10);
                        else fail(line_, "invalid \\u escape");
                    }
                    p_ += 4;
                    if (cp >= 0xD800 && cp <= 0xDFFF) fail(line_, "surrogate code point in \\u escape");
                    append_utf8(out, cp);
                    break;
                }
                default:
                    fail(line_, std::string("invalid escape '\\") + e +
                                    "' (for Windows paths double the backslash or use 'single quotes')");
            }
        }
        return out;
    }

    std::string parse_literal() {
        ++p_;
        size_t s = p_;
        while (!eof() && cur() != '\'' && cur() != '\n') ++p_;
        if (eof() || cur() != '\'') fail(line_, "unterminated string");
        std::string out = t_.substr(s, p_ - s);
        ++p_;
        return out;
    }

    Val parse_value() {
        if (eof()) fail(line_, "missing value");
        Val v;
        v.line = line_;
        char c = cur();
        if (c == '"') {
            v.type = Val::Str;
            v.s = parse_basic();
        } else if (c == '\'') {
            v.type = Val::Str;
            v.s = parse_literal();
        } else if (c == '[') {
            ++p_;
            v.type = Val::Arr;
            for (;;) {
                skip_blank();
                if (eof()) fail(line_, "unterminated array");
                if (cur() == ']') { ++p_; break; }
                v.a.push_back(parse_value());
                skip_blank();
                if (eof()) fail(line_, "unterminated array");
                if (cur() == ',') { ++p_; continue; }
                if (cur() == ']') { ++p_; break; }
                fail(line_, "expected ',' or ']' in array");
            }
        } else if (t_.compare(p_, 4, "true") == 0) {
            p_ += 4;
            v.type = Val::Bool;
            v.b = true;
        } else if (t_.compare(p_, 5, "false") == 0) {
            p_ += 5;
            v.type = Val::Bool;
            v.b = false;
        } else if ((c >= '0' && c <= '9') || c == '-' || c == '+') {
            size_t s = p_;
            if (c == '-' || c == '+') ++p_;
            size_t ds = p_;
            while (!eof() && ((cur() >= '0' && cur() <= '9') || cur() == '_')) ++p_;
            std::string digits = t_.substr(ds, p_ - ds);
            if (digits.empty() || digits.front() == '_' || digits.back() == '_' ||
                digits.find("__") != std::string::npos)
                fail(line_, "invalid number");
            if (!eof() && (cur() == '.' || cur() == 'e' || cur() == 'E' || cur() == ':' || cur() == '-' ||
                           cur() == 'x' || cur() == 'o' || cur() == 'b'))
                fail(line_, "unsupported number format (only decimal integers)");
            std::string clean;
            for (char d : digits)
                if (d != '_') clean += d;
            if (clean.size() > 18) fail(line_, "integer out of range");
            v.type = Val::Int;
            v.i = std::stoll(clean);
            if (t_[s] == '-') v.i = -v.i;
        } else {
            fail(line_, "invalid value (strings need quotes)");
        }
        return v;
    }
};

// ---------------------------------------------------------------- typed access

struct KV {
    const Section& sec;
    std::vector<bool> used;
    explicit KV(const Section& s) : sec(s), used(s.entries.size(), false) {}

    const Entry* take(const char* key) {
        for (size_t i = 0; i < sec.entries.size(); ++i)
            if (sec.entries[i].key == key) { used[i] = true; return &sec.entries[i]; }
        return nullptr;
    }
    void finish() const {
        for (size_t i = 0; i < sec.entries.size(); ++i)
            if (!used[i]) fail(sec.entries[i].line, "unknown key '" + sec.entries[i].key + "'");
    }
};

void get_str(KV& kv, const char* k, std::string& out) {
    if (const Entry* e = kv.take(k)) {
        if (e->v.type != Val::Str) fail(e->line, std::string("key '") + k + "' must be a string");
        out = e->v.s;
    }
}

void get_bool(KV& kv, const char* k, bool& out) {
    if (const Entry* e = kv.take(k)) {
        if (e->v.type != Val::Bool) fail(e->line, std::string("key '") + k + "' must be true or false");
        out = e->v.b;
    }
}

template <class T>
void get_num(KV& kv, const char* k, T& out, int64_t lo, int64_t hi) {
    if (const Entry* e = kv.take(k)) {
        if (e->v.type != Val::Int) fail(e->line, std::string("key '") + k + "' must be an integer");
        if (e->v.i < lo || e->v.i > hi)
            fail(e->line, std::string("key '") + k + "' out of range (" + std::to_string(lo) + ".." +
                              std::to_string(hi) + ")");
        out = static_cast<T>(e->v.i);
    }
}

void get_strs(KV& kv, const char* k, std::vector<std::string>& out) {
    if (const Entry* e = kv.take(k)) {
        out.clear();
        if (e->v.type == Val::Str) {
            out.push_back(e->v.s);
            return;
        }
        if (e->v.type != Val::Arr) fail(e->line, std::string("key '") + k + "' must be an array of strings");
        for (const auto& item : e->v.a) {
            if (item.type != Val::Str) fail(item.line, std::string("key '") + k + "' must contain only strings");
            out.push_back(item.s);
        }
    }
}

// "10MB" string or plain integer
void get_size_text(KV& kv, const char* k, std::string& out) {
    if (const Entry* e = kv.take(k)) {
        if (e->v.type == Val::Int) {
            if (e->v.i < 0) fail(e->line, std::string("key '") + k + "' must not be negative");
            out = std::to_string(e->v.i);
        } else if (e->v.type == Val::Str) {
            try { (void)parse_size(e->v.s); } catch (const Error& ex) { fail(e->line, ex.what()); }
            out = e->v.s;
        } else {
            fail(e->line, std::string("key '") + k + "' must be a size such as \"10MB\" or a number");
        }
    }
}

void get_size(KV& kv, const char* k, uint64_t& out, bool* explicit_zero = nullptr) {
    std::string txt;
    get_size_text(kv, k, txt);
    if (txt.empty()) return;
    out = parse_size(txt);
    if (explicit_zero && out == 0) *explicit_zero = true;
}

// Octal mode text key. line is used for the error position.
template <class F>
void get_mode(KV& kv, const char* k, uint32_t& out, F parse) {
    if (const Entry* e = kv.take(k)) {
        if (e->v.type != Val::Str) fail(e->line, std::string("key '") + k + "' must be an octal string such as \"0640\"");
        try {
            out = parse(e->v.s);
        } catch (const Error& ex) {
            fail(e->line, std::string("key '") + k + "': " + ex.what());
        }
    }
}

void get_time_text(KV& kv, const char* k, std::string& out) {
    if (const Entry* e = kv.take(k)) {
        if (e->v.type != Val::Str) fail(e->line, std::string("key '") + k + "' must be a string");
        out = e->v.s;
    }
}

void check_log_level(KV& kv, std::string& level) {
    const Entry* e = nullptr;
    for (const auto& x : kv.sec.entries)
        if (x.key == "log_level") e = &x;
    get_str(kv, "log_level", level);
    if (e && level != "debug" && level != "info" && level != "warn" && level != "error")
        fail(e->line, "log_level must be debug, info, warn or error");
}

bool valid_hhmm(const std::string& s) {
    if (s.size() != 5 || s[2] != ':') return false;
    for (int i : {0, 1, 3, 4})
        if (s[static_cast<size_t>(i)] < '0' || s[static_cast<size_t>(i)] > '9') return false;
    int h = (s[0] - '0') * 10 + (s[1] - '0'), m = (s[3] - '0') * 10 + (s[4] - '0');
    return h <= 23 && m <= 59;
}

bool valid_acl_entry(const std::string& s) {
    if (s == "*") return true;
    if (s.empty()) return false;
    size_t slash = s.find('/');
    std::string addr = s.substr(0, slash);
    if (addr.empty()) return false;
    for (char c : addr)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':'))
            return false;
    if (slash != std::string::npos) {
        std::string bits = s.substr(slash + 1);
        if (bits.empty() || bits.size() > 3 || bits.find_first_not_of("0123456789") != std::string::npos) return false;
        if (std::stoi(bits) > 128) return false;
    }
    return true;
}

bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    return true;
}

void get_pubkey(KV& kv, const char* k, PublicKey& out, bool& present) {
    std::string hex;
    const Entry* e = nullptr;
    for (const auto& x : kv.sec.entries)
        if (x.key == k) e = &x;
    get_str(kv, k, hex);
    present = e != nullptr;
    if (!e) return;
    try {
        out = parse_public_key_hex(hex);
    } catch (const Error&) {
        fail(e->line, std::string("key '") + k + "' must be 64 hexadecimal characters");
    }
}

// A positive cap below this is raised to it: the limiter's smallest useful piece is a few KiB.
constexpr uint32_t kMinBandwidthKbps = 64;

void raise_small_bandwidth(uint32_t& v, const char* where) {
    if (v > 0 && v < kMinBandwidthKbps) {
        log_warn(std::string("config: ") + where + " max_bandwidth_kbps = " + std::to_string(v) + " is too low; using " +
                 std::to_string(kMinBandwidthKbps));
        v = kMinBandwidthKbps;
    }
}

// ---------------------------------------------------------------- servers

void apply_server(const Section& sec, ServerConfig& c) {
    KV kv(sec);
    get_str(kv, "bind", c.bind);
    get_num(kv, "port", c.port, 1, 65535);
    get_str(kv, "root", c.root);
    get_str(kv, "key_file", c.key_file);
    get_num(kv, "max_connections", c.max_connections, 1, 100000);
    get_num(kv, "max_bandwidth_kbps", c.max_bandwidth_kbps, 0, INT32_MAX);
    raise_small_bandwidth(c.max_bandwidth_kbps, "[server]");
    get_num(kv, "max_auth_failures_per_min", c.max_auth_failures_per_min, 1, 1000000);
    get_bool(kv, "trash", c.trash);
    {
        const Entry* e = nullptr;
        for (const auto& x : sec.entries)
            if (x.key == "allow") e = &x;
        get_strs(kv, "allow", c.allow);
        if (e)
            for (const auto& a : c.allow)
                if (!valid_acl_entry(a)) fail(e->line, "invalid allow entry '" + a + "'");
    }
    {
        const Entry* e = nullptr;
        for (const auto& x : sec.entries)
            if (x.key == "deny") e = &x;
        get_strs(kv, "deny", c.deny);
        if (e)
            for (const auto& a : c.deny)
                if (!valid_acl_entry(a)) fail(e->line, "invalid deny entry '" + a + "'");
    }
    get_str(kv, "state_dir", c.state_dir);
    get_str(kv, "log_file", c.log_file);
    check_log_level(kv, c.log_level);
    {
        bool zero = false;
        get_size(kv, "max_file_size", c.max_file_size, &zero);
        if (zero) log_warn("config: max_file_size = 0 disables the per-file size limit; a client can then fill the disk");
        zero = false;
        get_size(kv, "max_trash_bytes", c.max_trash_bytes, &zero);
        if (zero) log_warn("config: max_trash_bytes = 0 leaves the trash unbounded");
    }
    get_mode(kv, "file_mode", c.file_mode, parse_file_mode);
    get_mode(kv, "dir_mode", c.dir_mode, parse_dir_mode);
    get_num(kv, "io_timeout_s", c.io_timeout_s, 1, 86400);
    kv.finish();
}

void apply_client_acl(const Section& sec, ClientAcl& a) {
    KV kv(sec);
    get_str(kv, "name", a.name);
    bool has_key = false;
    get_pubkey(kv, "public_key", a.public_key, has_key);
    if (!has_key) fail(sec.line, "[[client]] without 'public_key'");
    std::string access = "rw";
    const Entry* e = nullptr;
    for (const auto& x : sec.entries)
        if (x.key == "access") e = &x;
    get_str(kv, "access", access);
    if (e && access != "rw" && access != "ro") fail(e->line, "access must be \"rw\" or \"ro\"");
    a.read_only = access == "ro";
    get_num(kv, "max_sessions", a.max_sessions, 1, 10000);
    get_num(kv, "max_bandwidth_kbps", a.max_bandwidth_kbps, 0, INT32_MAX);
    raise_small_bandwidth(a.max_bandwidth_kbps, "[[client]]");
    get_size(kv, "max_write_bytes_per_hour", a.max_write_bytes_per_hour);
    const Entry* pe = nullptr;
    for (const auto& x : sec.entries)
        if (x.key == "prefix") pe = &x;
    get_str(kv, "prefix", a.prefix);
    if (pe) {
        std::string& pf = a.prefix;
        for (auto& ch : pf)
            if (ch == '\\') ch = '/';
        while (!pf.empty() && pf.back() == '/') pf.pop_back();
        bool bad = !pf.empty() && (pf[0] == '/' || (pf.size() > 1 && pf[1] == ':'));
        size_t start = 0;
        while (!bad && !pf.empty()) {
            size_t e2 = pf.find('/', start);
            std::string comp = pf.substr(start, e2 == std::string::npos ? std::string::npos : e2 - start);
            if (comp.empty() || comp == "." || comp == ".." || comp == "__sync") bad = true;
            if (e2 == std::string::npos) break;
            start = e2 + 1;
        }
        if (bad) fail(pe->line, "invalid prefix (must be a relative sub-directory of root)");
    }
    kv.finish();
}

// ---------------------------------------------------------------- clients

void apply_client(const Section& sec, ClientConfig& c) {
    KV kv(sec);
    get_str(kv, "key_file", c.key_file);
    get_strs(kv, "compress_skip_ext", c.compress_skip_ext);
    get_str(kv, "state_dir", c.state_dir);
    get_str(kv, "log_file", c.log_file);
    check_log_level(kv, c.log_level);
    get_num(kv, "connections", c.connections, 1, 64);
    {
        const Entry* e = nullptr;
        for (const auto& x : sec.entries)
            if (x.key == "compress") e = &x;
        get_str(kv, "compress", c.compress);
        if (e && c.compress != "none" && c.compress != "lz4") fail(e->line, "compress must be \"none\" or \"lz4\"");
    }
    get_num(kv, "max_bandwidth_kbps", c.max_bandwidth_kbps, 0, INT32_MAX);
    raise_small_bandwidth(c.max_bandwidth_kbps, "client");
    get_num(kv, "retry_min_ms", c.retry_min_ms, 1, INT32_MAX);
    get_num(kv, "retry_max_ms", c.retry_max_ms, 1, INT32_MAX);
    kv.finish();
}

void apply_watch(const Section& sec, WatchConfig& w) {
    KV kv(sec);
    get_str(kv, "name", w.name);
    get_str(kv, "path", w.path);
    get_bool(kv, "enabled", w.enabled);
    get_bool(kv, "recursive", w.recursive);
    get_num(kv, "quiet_ms", w.quiet_ms, 0, INT32_MAX);
    get_num(kv, "sync_delay_ms", w.sync_delay_ms, 0, INT32_MAX);
    get_bool(kv, "start_sync", w.start_sync);
    get_bool(kv, "propagate_delete", w.propagate_delete);
    {
        const Entry* e = nullptr;
        for (const auto& x : sec.entries)
            if (x.key == "schedule_at") e = &x;
        get_strs(kv, "schedule_at", w.schedule_at);
        if (e)
            for (const auto& t : w.schedule_at)
                if (!valid_hhmm(t)) fail(e->line, "schedule_at entry '" + t + "' must look like HH:MM");
    }
    get_num(kv, "schedule_interval_s", w.schedule_interval_s, 0, INT32_MAX);
    get_num(kv, "periodic_scan_s", w.periodic_scan_s, 0, INT32_MAX);
    kv.finish();
}

void apply_filter(const Section& sec, FilterConfig& f) {
    KV kv(sec);
    get_strs(kv, "include", f.include);
    get_strs(kv, "include_regex", f.include_regex);
    get_strs(kv, "exclude", f.exclude);
    get_strs(kv, "exclude_regex", f.exclude_regex);
    get_size_text(kv, "size_min", f.size_min);
    get_size_text(kv, "size_max", f.size_max);
    get_time_text(kv, "mtime_after", f.mtime_after);
    get_time_text(kv, "mtime_before", f.mtime_before);
    kv.finish();
}

void apply_target(const Section& sec, TargetConfig& t) {
    KV kv(sec);
    auto line_of = [&](const char* k) {
        for (const auto& x : sec.entries)
            if (x.key == k) return x.line;
        return 0;
    };
    get_str(kv, "host", t.host);
    get_num(kv, "port", t.port, 1, 65535);
    get_str(kv, "key_file", t.key_file);
    get_str(kv, "path", t.path);
    get_str(kv, "remote_prefix", t.remote_prefix);
    get_bool(kv, "enabled", t.enabled);
    get_mode(kv, "file_mode", t.file_mode, parse_file_mode);
    get_mode(kv, "dir_mode", t.dir_mode, parse_dir_mode);
    bool has_sk = false;
    get_pubkey(kv, "server_key", t.server_key, has_sk);
    kv.finish();
    if (t.is_local()) {
        for (const char* k : {"host", "port", "key_file", "server_key"})
            if (line_of(k))
                fail(line_of(k), std::string("target has both 'path' and '") + k +
                                     "' (a target is either local or network)");
    } else {
        for (const char* k : {"file_mode", "dir_mode"})
            if (line_of(k)) fail(line_of(k), std::string("'") + k + "' only applies to local targets (with 'path')");
        if (line_of("path")) fail(line_of("path"), "target 'path' must not be empty");
        if (t.host.empty()) fail(sec.line, "target needs either 'path' (local) or 'host' (network)");
        if (!has_sk) fail(sec.line, "network target '" + t.host + "' without 'server_key'");
    }
}

// [control] table, shared by the server and the client file.
template <class C>
void apply_control(const Section& sec, C& c) {
    KV kv(sec);
    get_bool(kv, "enabled", c.control_enabled);
    get_str(kv, "group", c.control_group);
    get_str(kv, "name", c.control_name);
    {
        const Entry* e = nullptr;
        for (const auto& x : sec.entries)
            if (x.key == "allow") e = &x;
        get_strs(kv, "allow", c.control_allow);
        if (e)
            for (const auto& a : c.control_allow) {
                bool bad = a.empty() || a.size() > 256;
                for (unsigned char ch : a)
                    if (ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\'') bad = true;
                if (bad) fail(e->line, "invalid control allow entry (use a SID like S-1-5-21-... or DOMAIN\\user)");
            }
    }
    {
        const Entry* e = nullptr;
        for (const auto& x : sec.entries)
            if (x.key == "name") e = &x;
        if (e && !c.control_name.empty()) {
            bool ok = c.control_name.size() <= 64 && c.control_name[0] != '-' && c.control_name[0] != '.';
            for (unsigned char ch : c.control_name)
                if (!(std::isalnum(ch) || ch == '_' || ch == '.' || ch == '-')) ok = false;
            if (!ok) fail(e->line, "control name must be 1..64 characters of A-Z a-z 0-9 _ . -");
        }
    }
    kv.finish();
}

std::string path_text(const std::vector<std::string>& p) {
    std::string s;
    for (size_t i = 0; i < p.size(); ++i) s += (i ? "." : "") + p[i];
    return s;
}

std::string read_text_file(const std::string& utf8_path) {
    std::ifstream f(fs::u8path(utf8_path), std::ios::binary);
    if (!f) throw Error("cannot open config file: " + utf8_path);
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (f.bad()) throw Error("cannot read config file: " + utf8_path);
    return s;
}

} // namespace

ServerConfig parse_server_config_text(const std::string& text) {
    auto secs = Parser(text).parse();
    ServerConfig c;
    for (const auto& s : secs) {
        if (s.path.empty() || (s.path.size() == 1 && s.path[0] == "server" && !s.is_array)) {
            apply_server(s, c);
        } else if (s.path.size() == 1 && s.path[0] == "control" && !s.is_array) {
            apply_control(s, c);
        } else if (s.path.size() == 1 && s.path[0] == "client" && s.is_array) {
            c.clients.emplace_back();
            apply_client_acl(s, c.clients.back());
            if (c.clients.back().name.empty()) c.clients.back().name = "client" + std::to_string(c.clients.size());
        } else {
            fail(s.line, std::string("unknown table '") + (s.is_array ? "[[" : "[") + path_text(s.path) +
                             (s.is_array ? "]]" : "]") + "'");
        }
    }
    if (c.root.empty()) throw Error("missing required key 'root'");
    if (c.key_file.empty()) throw Error("missing required key 'key_file'");
    if (c.clients.empty()) throw Error("at least one [[client]] with a public_key is required");
    std::set<std::string> cn;
    std::set<PublicKey> ck;
    for (const auto& a : c.clients) {
        if (!cn.insert(a.name).second) throw Error("duplicate client name '" + a.name + "'");
        if (!ck.insert(a.public_key).second)
            throw Error("client '" + a.name + "' repeats another client's public_key");
    }
    return c;
}

ClientConfig parse_client_config_text(const std::string& text) {
    auto secs = Parser(text).parse();
    ClientConfig c;
    bool filter_seen = false;
    for (const auto& s : secs) {
        if (s.path.empty() || (s.path.size() == 1 && s.path[0] == "client" && !s.is_array)) {
            apply_client(s, c);
        } else if (s.path.size() == 1 && s.path[0] == "control" && !s.is_array) {
            apply_control(s, c);
        } else if (s.path.size() == 1 && s.path[0] == "watch" && s.is_array) {
            c.watches.emplace_back();
            filter_seen = false;
            apply_watch(s, c.watches.back());
        } else if (s.path.size() == 2 && s.path[0] == "watch" && s.path[1] == "filter" && !s.is_array) {
            if (c.watches.empty()) fail(s.line, "[watch.filter] before any [[watch]]");
            if (filter_seen) fail(s.line, "duplicate [watch.filter]");
            filter_seen = true;
            apply_filter(s, c.watches.back().filter);
        } else if (s.path.size() == 2 && s.path[0] == "watch" && s.path[1] == "target" && s.is_array) {
            if (c.watches.empty()) fail(s.line, "[[watch.target]] before any [[watch]]");
            c.watches.back().targets.emplace_back();
            apply_target(s, c.watches.back().targets.back());
        } else {
            fail(s.line, std::string("unknown table '") + (s.is_array ? "[[" : "[") + path_text(s.path) +
                             (s.is_array ? "]]" : "]") + "'");
        }
    }
    if (c.retry_min_ms > c.retry_max_ms) throw Error("retry_min_ms must not exceed retry_max_ms");
    std::set<std::string> names;
    for (auto& w : c.watches) {
        if (w.path.empty()) throw Error("a [[watch]] has no 'path'");
        if (w.name.empty()) w.name = w.path;
        if (!names.insert(w.name).second) throw Error("duplicate watch name '" + w.name + "'");
        try {
            Filter probe(w.filter);  // validates regexes, sizes and times
            (void)probe;
        } catch (const Error& e) {
            throw Error("watch '" + w.name + "': " + e.what());
        }
        if (w.enabled && w.targets.empty())
            throw Error("watch '" + w.name + "' has no [[watch.target]]");
        for (const auto& t : w.targets) {
            if (t.is_local() || !t.enabled) continue;
            if (t.key_file.empty() && c.key_file.empty())
                throw Error("watch '" + w.name + "': target '" + t.host +
                            "' has no key_file (set it on the target or at client level)");
        }
    }
    return c;
}

ServerConfig load_server_config(const std::string& utf8_path) {
    std::string text = read_text_file(utf8_path);
    try {
        return parse_server_config_text(text);
    } catch (const Error& e) {
        throw Error(utf8_path + ": " + e.what());
    }
}

ClientConfig load_client_config(const std::string& utf8_path) {
    std::string text = read_text_file(utf8_path);
    try {
        return parse_client_config_text(text);
    } catch (const Error& e) {
        throw Error(utf8_path + ": " + e.what());
    }
}

PublicKey parse_public_key_hex(const std::string& hex) {
    if (!is_hex64(hex)) throw Error("public key must be exactly 64 hexadecimal characters");
    Bytes b = from_hex(hex);
    PublicKey k;
    std::copy(b.begin(), b.end(), k.begin());
    return k;
}

static uint32_t parse_mode_bits(const std::string& t, const char* what) {
    std::string d = t;
    if (d.size() > 1 && d[0] == '0') d.erase(0, 1);  // "0640" -> "640"
    if (d.empty() || d.size() > 3 || d.find_first_not_of("01234567") != std::string::npos)
        throw Error(std::string(what) + " must be an octal number such as \"0640\"");
    return uint32_t(std::stoul(d, nullptr, 8));
}

uint32_t parse_file_mode(const std::string& octal) {
    uint32_t m = parse_mode_bits(octal, "file mode");
    if (m & 0111) throw Error("file mode must not have execute bits");
    if ((m & 0600) != 0600) throw Error("file mode must keep read and write for the owner (at least 0600)");
    return m;
}

uint32_t parse_dir_mode(const std::string& octal) {
    uint32_t m = parse_mode_bits(octal, "directory mode");
    if ((m & 0700) != 0700) throw Error("directory mode must keep rwx for the owner (at least 0700)");
    return m;
}

Bytes load_secret_key_file(const std::string& utf8_path) {
    std::string raw = read_secret_file(utf8_path);  // ownership / mode / symlink checks live there
    char buf[1024];
    size_t n = raw.size();
    if (n >= sizeof buf) {
        secure_wipe(raw.data(), raw.size());
        throw Error("key file is too large: " + utf8_path);
    }
    std::memcpy(buf, raw.data(), n);
    secure_wipe(raw.data(), raw.size());
    size_t b = 0, e = n;
    auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (b < e && ws(buf[b])) ++b;
    while (e > b && ws(buf[e - 1])) --e;
    bool ok = e - b == 64;
    for (size_t i = b; ok && i < e; ++i) {
        char c = buf[i];
        ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    if (!ok) {
        secure_wipe(buf, sizeof buf);
        throw Error("key file " + utf8_path + " must contain exactly 64 hexadecimal characters");
    }
    std::string hex(buf + b, e - b);
    secure_wipe(buf, sizeof buf);
    Bytes key;
    try {
        key = from_hex(hex);
    } catch (...) {
        secure_wipe(&hex[0], hex.size());
        throw;
    }
    secure_wipe(&hex[0], hex.size());
    return key;
}

} // namespace mysync
