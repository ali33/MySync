// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/peers.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <set>
#include <thread>
#include <sstream>

#include "mysync/engine_lock.h"
#include "mysync/gui/config_io.h"
#include "mysync/hash.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>

#include <cerrno>
#include <cstring>
#endif

namespace fs = std::filesystem;

namespace mysync {
namespace {

constexpr uintmax_t kMaxPeerFile = 64 * 1024;
constexpr size_t kMaxExtraKeys = 8;

std::string resolve_in(const std::string& dir, const std::string& p) {
    if (p.empty()) return p;
    fs::path q = fs::u8path(p);
    if (q.is_absolute() || q.has_root_name() || q.has_root_directory()) return q.lexically_normal().u8string();
    return (fs::u8path(dir) / q).lexically_normal().u8string();
}

std::string abs_of(const std::string& p) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(p), ec);
    return (ec ? fs::u8path(p) : a).lexically_normal().u8string();
}

std::string config_dir_of(const std::string& config_path) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(config_path), ec);
    return (ec ? fs::u8path(config_path) : a).lexically_normal().parent_path().u8string();
}

bool read_small_file(const fs::path& p, std::string& out, std::string& why) {
    std::error_code ec;
    auto sz = fs::file_size(p, ec);
    if (ec) {
        why = "cannot read: " + ec.message();
        return false;
    }
    if (sz > kMaxPeerFile) {
        why = "file is larger than 64 KiB";
        return false;
    }
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        why = "cannot open";
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

std::string quote(const std::string& s) {
    std::string r = "\"";
    for (unsigned char c : s) {
        if (c == '\\') r += "\\\\";
        else if (c == '"') r += "\\\"";
        else if (c < 0x20 || c == 0x7f) {
            char b[8];
            std::snprintf(b, sizeof b, "\\u%04X", c);
            r += b;
        } else r += static_cast<char>(c);
    }
    return r + "\"";
}

std::string utc_date() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char b[48];
    std::snprintf(b, sizeof b, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return b;
}

bool same_acl(const ClientAcl& a, const ClientAcl& b) {
    return a.name == b.name && a.public_key == b.public_key && a.extra_keys == b.extra_keys && a.read_only == b.read_only &&
           a.prefix == b.prefix && a.max_sessions == b.max_sessions &&
           a.max_write_bytes_per_hour == b.max_write_bytes_per_hour && a.max_bandwidth_kbps == b.max_bandwidth_kbps;
}

// Everything a peers.d file would hold must survive the writer and the parser: this is how a name or prefix is validated.
ClientAcl validated(const ClientAcl& a) {
    std::string text = serialize_peer_file(a);
    ClientAcl b = parse_peer_file_text(text, a.name);
    b.source = a.source;
    return b;
}

std::string key_hex(const PublicKey& k) { return to_hex(k.data(), k.size()); }

bool any_key_shared(const ClientAcl& a, const ClientAcl& b) {
    if (acl_has_key(b, a.public_key)) return true;
    for (const auto& k : a.extra_keys)
        if (acl_has_key(b, k)) return true;
    return false;
}

}  // namespace

// ------------------------------------------------------------------------------------------------ paths and files
std::string peers_dir_path(const ServerConfig& cfg, const std::string& config_dir) {
    if (!cfg.peers_dir.empty()) return resolve_in(config_dir, cfg.peers_dir);
    std::string d = (fs::u8path(config_dir) / "peers.d").u8string();
    std::error_code ec;
    return fs::is_directory(fs::u8path(d), ec) ? d : std::string();
}

std::string revoked_list_path(const std::string& config_dir) {
    return (fs::u8path(config_dir) / "revoked-keys.txt").u8string();
}

std::vector<RevokedKey> load_revoked(const std::string& config_dir) {
    std::vector<RevokedKey> out;
    const std::string path = revoked_list_path(config_dir);
    std::error_code ec;
    fs::file_status st = fs::status(fs::u8path(path), ec);
    if (st.type() == fs::file_type::not_found) return out;  // no list = nothing revoked (the normal case)
    if (ec || st.type() != fs::file_type::regular)
        throw Error("revoked-keys.txt cannot be examined (" + path + (ec ? ": " + ec.message() : ": not a regular file") +
                    "): the configuration is refused");  // fail closed: any other doubt is not "nothing revoked"
    // A list that exists but cannot be used must NOT silently mean "nothing is revoked": that would re-admit a revoked
    // machine. Every problem below is an Error; the caller refuses the configuration.
    std::ifstream f(fs::u8path(path), std::ios::binary);
    if (!f) throw Error("revoked-keys.txt exists but cannot be read (" + path + "): the configuration is refused");
    std::string line;
    int no = 0;
    while (std::getline(f, line)) {
        ++no;
        if (no == 1 && line.size() >= 3 && line.compare(0, 3, "\xEF\xBB\xBF") == 0) line.erase(0, 3);  // UTF-8 BOM
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        size_t b0 = line.find_first_not_of(" \t");
        if (b0 == std::string::npos || line[b0] == '#') continue;
        std::istringstream in(line);
        std::string hex, name, when;
        in >> hex >> when;
        std::getline(in, name);
        while (!name.empty() && name.front() == ' ') name.erase(name.begin());
        try {
            RevokedKey r;
            r.key = parse_public_key_hex(hex);
            r.when = when;
            r.name = name;
            out.push_back(r);
        } catch (const Error&) {
            throw Error("revoked-keys.txt line " + std::to_string(no) +
                        " is malformed (expected a 64-hex key first): the configuration is refused until it is fixed");
        }
    }
    if (f.bad()) throw Error("revoked-keys.txt could not be read completely: the configuration is refused");
    return out;
}

namespace {
void save_revoked(const std::string& config_dir, const std::vector<RevokedKey>& v) {
    std::string t =
        "# Keys revoked with `mysync peer revoke`: the server never accepts them, in any file. One per line:\n"
        "# <public key hex> <date> <peer name>. Delete a line (or use `peer add --allow-revoked`) to allow a key again.\n";
    for (const auto& r : v) {
        std::string n = r.name;
        for (auto& c : n)
            if (static_cast<unsigned char>(c) < 0x20) c = ' ';
        t += key_hex(r.key) + " " + r.when + " " + n + "\n";
    }
    try {
        gui::write_file_atomic(revoked_list_path(config_dir), t, true);
    } catch (const Error& e) {
        throw RuntimeFailure(std::string("cannot write the revocation list: ") + e.what());
    }
}
}  // namespace

std::string peer_file_name(const std::string& name) {
    bool safe = !name.empty() && name.size() <= 64 && name[0] != '.' && name[0] != '-';
    for (unsigned char c : name)
        if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-')) safe = false;
    if (safe) return name + ".toml";
    Hash256 h = hash_bytes(name.data(), name.size());
    return "p-" + to_hex(h.data(), 8) + ".toml";
}

std::string serialize_peer_file(const ClientAcl& a) {
    for (unsigned char c : a.name)
        if (c < 0x20 || c == 0x7f) throw Error("peer name must not contain control characters");
    if (a.name.empty() || a.name.size() > 128) throw Error("peer name must be 1..128 characters");
    std::string o =
        "# MySync peer (one machine). Read from peers.d by the server; written by `mysync peer add`.\n";
    o += "name = " + quote(a.name) + "\n";
    o += "public_key = " + quote(key_hex(a.public_key)) + "\n";
    if (!a.extra_keys.empty()) {
        o += "public_keys = [";
        for (size_t i = 0; i < a.extra_keys.size(); ++i) o += (i ? ", " : "") + quote(key_hex(a.extra_keys[i]));
        o += "]\n";
    }
    o += std::string("access = ") + (a.read_only ? "\"ro\"" : "\"rw\"") + "\n";
    if (!a.prefix.empty()) o += "prefix = " + quote(a.prefix) + "\n";
    o += "max_sessions = " + std::to_string(a.max_sessions) + "\n";
    o += "max_bandwidth_kbps = " + std::to_string(a.max_bandwidth_kbps) + "\n";
    o += "max_write_bytes_per_hour = " + std::to_string(a.max_write_bytes_per_hour) + "\n";
    return o;
}

// ------------------------------------------------------------------------------------------------ loading
PeerLoad load_peers(ServerConfig& cfg, const std::string& config_dir,
                    const std::function<std::string(const std::string&)>& file_check, bool log_warnings) {
    PeerLoad rep;
    auto warn = [&](const std::string& m) {
        rep.warnings.push_back(m);
        if (log_warnings) log_warn("peers: " + m);
    };
    std::set<std::string> names;
    for (const auto& c : cfg.clients) names.insert(c.name);

    rep.dir = peers_dir_path(cfg, config_dir);
    std::error_code ec;
    if (!rep.dir.empty() && !fs::is_directory(fs::u8path(rep.dir), ec)) {
        if (!cfg.peers_dir.empty()) warn("peers_dir " + rep.dir + " does not exist (no peer is read from it)");
        rep.dir.clear();
    }
    if (!rep.dir.empty()) {
        std::vector<fs::path> files;
        for (fs::directory_iterator it(fs::u8path(rep.dir), ec), end; !ec && it != end; it.increment(ec)) {
            const fs::path& p = it->path();
            std::string fn = p.filename().u8string();
            if (fn.empty() || fn[0] == '.' || p.extension() != ".toml") continue;
            std::error_code e2;
            if (!it->is_regular_file(e2)) continue;
            files.push_back(p);
        }
        if (ec) warn("cannot list " + rep.dir + ": " + ec.message());
        std::sort(files.begin(), files.end());
        for (const fs::path& p : files) {
            ++rep.files;
            std::string fn = p.filename().u8string();
            if (file_check) {
                std::string why = file_check(p.u8string());
                if (!why.empty()) {
                    ++rep.bad;
                    warn(fn + ": refused, " + why);
                    continue;
                }
            }
            std::string text, why;
            if (!read_small_file(p, text, why)) {
                ++rep.bad;
                warn(fn + ": " + why);
                continue;
            }
            ClientAcl a;
            try {
                a = parse_peer_file_text(text, p.stem().u8string());
            } catch (const Error& e) {
                ++rep.bad;
                warn(fn + ": " + e.what());
                continue;
            }
            a.source = fn;
            std::string clash;
            if (names.count(a.name)) clash = "the name '" + a.name + "' is already used by another peer";
            for (const auto& c : cfg.clients)
                if (clash.empty() && any_key_shared(a, c))
                    clash = "its public key is already used by peer '" + c.name + "'";
            if (!clash.empty()) {
                ++rep.bad;
                warn(fn + ": skipped, " + clash + " (the earlier entry is kept)");
                continue;
            }
            names.insert(a.name);
            cfg.clients.push_back(std::move(a));
            ++rep.loaded;
        }
    }

    // revoked keys are removed wherever they came from
    std::vector<RevokedKey> rv = load_revoked(config_dir);
    if (!rv.empty()) {
        auto revoked = [&](const PublicKey& k) {
            for (const auto& r : rv)
                if (r.key == k) return true;
            return false;
        };
        std::vector<ClientAcl> keep;
        for (ClientAcl a : cfg.clients) {
            std::vector<PublicKey> keys{a.public_key};
            keys.insert(keys.end(), a.extra_keys.begin(), a.extra_keys.end());
            std::vector<PublicKey> ok;
            for (const auto& k : keys) {
                if (revoked(k)) warn("peer '" + a.name + "': key " + key_short(k) + " is on the revocation list and is ignored");
                else ok.push_back(k);
            }
            if (ok.empty()) continue;  // every key revoked: the peer is gone
            a.public_key = ok[0];
            a.extra_keys.assign(ok.begin() + 1, ok.end());
            keep.push_back(std::move(a));
        }
        cfg.clients = std::move(keep);
    }
    return rep;
}

std::string peers_fingerprint(const ServerConfig& cfg, const std::string& config_dir) {
    std::string fp;
    auto stamp = [&](const fs::path& p) {
        std::error_code ec;
        auto sz = fs::file_size(p, ec);
        if (ec) return;
        auto mt = fs::last_write_time(p, ec).time_since_epoch().count();
        fp += p.filename().u8string() + ":" + std::to_string(sz) + ":" + std::to_string(mt) + ";";
    };
    std::string dir = peers_dir_path(cfg, config_dir);
    std::error_code ec;
    if (!dir.empty() && fs::is_directory(fs::u8path(dir), ec)) {
        std::vector<fs::path> files;
        for (fs::directory_iterator it(fs::u8path(dir), ec), end; !ec && it != end; it.increment(ec))
            if (it->path().extension() == ".toml") files.push_back(it->path());
        std::sort(files.begin(), files.end());
        for (const auto& p : files) stamp(p);
    }
    stamp(fs::u8path(revoked_list_path(config_dir)));
    return fp;
}

// ------------------------------------------------------------------------------------------------ edits
namespace {

// One `mysync peer ...` read-modify-write at a time per configuration folder (between processes: flock / LockFileEx).
// Two concurrent `peer add` / `revoke` would otherwise overwrite each other's change.
struct PeersLock {
    std::unique_ptr<FileLock> lock;
    explicit PeersLock(const std::string& config_dir) {
        const std::string path = (fs::u8path(config_dir) / ".peers.lock").u8string();
        std::string holder;
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        for (;;) {
            try {
                lock = FileLock::try_acquire(path, &holder);
            } catch (const Error& e) {
                throw RuntimeFailure(std::string("cannot create the lock file ") + path + ": " + e.what());
            }
            if (lock) return;
            if (std::chrono::steady_clock::now() >= end)
                throw RuntimeFailure("another `mysync peer` command has held " + path + " for 20 s" +
                                     (holder.empty() ? "" : " (" + holder + ")") + ": try again");
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
};

// Creates `final_path` with `content` only if nothing is there (CREATE_NEW semantics): the content goes to a temporary
// name first, then link() / MoveFileEx-without-replace puts it in place, so a half-written file is never visible.
void create_new_file(const std::string& final_path, const std::string& content) {
    uint8_t r[6];
    random_bytes(r, sizeof r);
    const std::string tmp = final_path + ".tmp-" + to_hex(r, sizeof r);  // not *.toml: ignored by the loader
    gui::write_file_atomic(tmp, content, false);
#ifdef _WIN32
    bool ok = MoveFileExW(fs::u8path(tmp).wstring().c_str(), fs::u8path(final_path).wstring().c_str(), 0) != 0;
    DWORD err = ok ? 0 : GetLastError();
    if (!ok) DeleteFileW(fs::u8path(tmp).wstring().c_str());
    if (!ok)
        throw Error(err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS ? final_path + " already exists"
                                                                              : "cannot create " + final_path + " (error " + std::to_string(err) + ")");
#else
    int rc = ::link(tmp.c_str(), final_path.c_str());
    int e = errno;
    ::unlink(tmp.c_str());
    if (rc != 0) throw Error(e == EEXIST ? final_path + " already exists" : "cannot create " + final_path + ": " + std::strerror(e));
#endif
}

struct View {
    gui::ConfigEditor ed;
    std::string dir;                  // config folder
    std::string peers;                // peers dir path ("" = none)
    bool peers_explicit = false;
    ServerConfig merged;
    PeerLoad load;
};

View open_view(const std::string& config_path) {
    std::string abs;
    {
        std::error_code ec;
        fs::path a = fs::absolute(fs::u8path(config_path), ec);
        abs = (ec ? fs::u8path(config_path) : a).lexically_normal().u8string();
    }
    gui::ConfigEditor ed = gui::ConfigEditor::open(abs, gui::ConfigRole::Server);
    View v{ed, config_dir_of(abs), {}, false, {}, {}};
    v.merged = v.ed.server();
    v.peers_explicit = !v.merged.peers_dir.empty();
    v.peers = peers_dir_path(v.merged, v.dir);
    v.load = load_peers(v.merged, v.dir, {}, false);
    return v;
}

int find_by_key(const ServerConfig& c, const PublicKey& k) {
    for (size_t i = 0; i < c.clients.size(); ++i)
        if (acl_has_key(c.clients[i], k)) return int(i);
    return -1;
}

int find_by_name(const ServerConfig& c, const std::string& n) {
    for (size_t i = 0; i < c.clients.size(); ++i)
        if (c.clients[i].name == n) return int(i);
    return -1;
}

// Where a NEW peer goes: peers.d when declared / present, else the main file.
bool new_goes_to_peers_dir(const View& v) { return !v.peers.empty() || v.peers_explicit; }

std::string peers_dir_for_write(const View& v) {
    if (!v.peers.empty()) return v.peers;
    return resolve_in(v.dir, v.merged.peers_dir);
}

void write_peer_file(const std::string& dir, const std::string& file, const ClientAcl& a, bool must_be_new = false) {
    try {
        std::error_code ec;
        fs::create_directories(fs::u8path(dir), ec);
        std::string full = (fs::u8path(dir) / fs::u8path(file)).u8string();
        if (must_be_new) create_new_file(full, serialize_peer_file(a));
        else gui::write_file_atomic(full, serialize_peer_file(a), false);
    } catch (const RuntimeFailure&) {
        throw;
    } catch (const Error& e) {
        throw RuntimeFailure(std::string("cannot write ") + file + ": " + e.what());
    }
}

// Replaces / appends / removes one [[client]] of the main file, with a few retries when the file changes underneath.
template <class Fn>
void edit_main_file(const std::string& config_path, Fn fn) {
    for (int attempt = 0;; ++attempt) {
        gui::ConfigEditor ed = gui::ConfigEditor::open(config_path, gui::ConfigRole::Server);
        fn(ed.server());
        try {
            ed.save();
            return;
        } catch (const Error& e) {
            std::string m = e.what();
            bool race = m.find("changed") != std::string::npos;
            if (!race || attempt >= 3) {
                if (race) throw RuntimeFailure(m);
                // a configuration that would not load again (e.g. no peer left and no peers_dir) is the caller's problem
                if (m.find("cannot") != std::string::npos && m.find("write") != std::string::npos) throw RuntimeFailure(m);
                throw;
            }
        }
    }
}

}  // namespace

PeerEdit peer_add(const std::string& config_path, const PeerSpec& spec) {
    PeersLock guard(config_dir_of(abs_of(config_path)));
    View v = open_view(config_path);
    PeerEdit r;
    if (spec.name.empty()) throw Error("--name is required");

    // revocation list: read inside the lock; taking a key off it is written LAST, once the peer itself is in place,
    // so a failure half-way never leaves the key un-revoked with no peer to show for it
    std::vector<RevokedKey> rv = load_revoked(v.dir);
    bool unrevoke = false;
    {
        auto it = std::find_if(rv.begin(), rv.end(), [&](const RevokedKey& x) { return x.key == spec.key; });
        if (it != rv.end()) {
            if (!spec.allow_revoked)
                throw Error("this key was revoked on " + it->when + " (peer '" + it->name +
                            "'); use --allow-revoked to allow it again");
            rv.erase(it);
            unrevoke = true;
        }
    }

    int ik = find_by_key(v.merged, spec.key);
    int in = find_by_name(v.merged, spec.name);
    ClientAcl cur;
    bool existing = false;
    ClientAcl want;
    if (ik >= 0) {
        cur = v.merged.clients[size_t(ik)];
        existing = true;
        if (in >= 0 && in != ik)
            throw Error("the name '" + spec.name + "' is already used by another peer (with a different key)");
        want = cur;
        want.name = spec.name;
    } else if (in >= 0) {
        cur = v.merged.clients[size_t(in)];
        existing = true;
        if (!spec.rotate)
            throw Error("the name '" + spec.name + "' already belongs to a peer with a different key (" + key_short(cur.public_key) +
                        "); use --rotate to accept the new key next to the old one, or `mysync peer remove` first");
        want = cur;
        if (want.extra_keys.size() + 1 > kMaxExtraKeys) throw Error("too many keys on this peer: retire an old one first");
        want.extra_keys.insert(want.extra_keys.begin(), want.public_key);
        want.public_key = spec.key;
    } else {
        want.name = spec.name;
        want.public_key = spec.key;
    }
    want.read_only = spec.read_only;
    if (spec.prefix) want.prefix = *spec.prefix;  // absent = keep what the peer has (a new peer gets the whole root)
    if (spec.max_sessions) want.max_sessions = *spec.max_sessions;
    if (spec.max_bandwidth_kbps) want.max_bandwidth_kbps = *spec.max_bandwidth_kbps;
    if (spec.max_write_bytes_per_hour) want.max_write_bytes_per_hour = *spec.max_write_bytes_per_hour;
    if (existing) {
        want.source = cur.source;
    }
    want = validated(want);  // normalises the prefix, rejects a bad name / value

    if (existing && same_acl(cur, want)) {
        r.where = cur.source.empty() ? "main configuration" : "peers.d/" + cur.source;
        if (unrevoke) {
            save_revoked(v.dir, rv);
            r.changed = true;
        }
        r.message = r.changed ? "peer '" + want.name + "' unchanged (key taken off the revocation list)"
                              : "peer '" + want.name + "' unchanged";
        return r;
    }

    if (existing && !cur.source.empty()) {
        write_peer_file(v.peers, cur.source, want);
        r.where = "peers.d/" + cur.source;
    } else if (existing) {
        std::string oldname = cur.name;
        edit_main_file(v.ed.path(), [&](ServerConfig& sc) {
            int i = find_by_name(sc, oldname);
            if (i < 0) throw Error("peer '" + oldname + "' vanished from the configuration while it was being edited");
            ClientAcl w = want;
            w.source.clear();
            sc.clients[size_t(i)] = w;
        });
        r.where = "main configuration";
    } else if (new_goes_to_peers_dir(v)) {
        std::string file = peer_file_name(want.name);
        std::string dir = peers_dir_for_write(v);
        std::error_code ec;
        if (fs::exists(fs::u8path(dir) / fs::u8path(file), ec))
            throw Error("peers.d/" + file + " already exists but is not loaded as peer '" + want.name +
                        "' (invalid file or another name); fix or remove it first");
        write_peer_file(dir, file, want, true);
        r.where = "peers.d/" + file;
    } else {
        edit_main_file(v.ed.path(), [&](ServerConfig& sc) {
            ClientAcl w = want;
            w.source.clear();
            sc.clients.push_back(w);
        });
        r.where = "main configuration";
    }
    if (unrevoke) save_revoked(v.dir, rv);
    r.changed = true;
    r.message = std::string(existing ? "peer '" + want.name + "' updated" : "peer '" + want.name + "' added") + " (" +
                (want.read_only ? "ro" : "rw") + (want.prefix.empty() ? "" : ", prefix " + want.prefix) + ") in " + r.where;
    return r;
}

PeerEdit peer_remove(const std::string& config_path, const std::string& name_or_key, bool revoke) {
    PeersLock guard(config_dir_of(abs_of(config_path)));
    View v = open_view(config_path);
    PeerEdit r;
    int idx = -1;
    bool is_key = false;
    PublicKey k{};
    try {
        k = parse_public_key_hex(name_or_key);
        is_key = true;
    } catch (const Error&) {
    }
    if (is_key) idx = find_by_key(v.merged, k);
    if (idx < 0) idx = find_by_name(v.merged, name_or_key);
    std::vector<RevokedKey> rv = load_revoked(v.dir);
    auto add_revoked = [&](const std::vector<PublicKey>& keys, const std::string& name) {
        bool any = false;
        for (const auto& key : keys) {
            r.revoked_keys.push_back(key_hex(key));
            if (std::none_of(rv.begin(), rv.end(), [&](const RevokedKey& x) { return x.key == key; })) {
                rv.push_back(RevokedKey{key, name, utc_date()});
                any = true;
            }
        }
        if (any) save_revoked(v.dir, rv);
        return any;
    };
    if (idx < 0) {
        if (revoke && is_key) {  // revoking a key that is in no file still blocks it
            bool added = add_revoked({k}, "(not in the configuration)");
            r.changed = added;
            r.message = added ? "key put on the revocation list" : "key was already on the revocation list";
            return r;
        }
        r.message = "peer '" + name_or_key + "' not found: nothing to remove";
        return r;
    }
    ClientAcl cur = v.merged.clients[size_t(idx)];
    if (revoke) {  // the list FIRST: if removing the peer then fails, the keys are already refused
        std::vector<PublicKey> keys{cur.public_key};
        keys.insert(keys.end(), cur.extra_keys.begin(), cur.extra_keys.end());
        add_revoked(keys, cur.name);
    }
    if (!cur.source.empty()) {
        std::error_code ec;
        fs::remove(fs::u8path(v.peers) / fs::u8path(cur.source), ec);
        if (ec) throw RuntimeFailure("cannot remove peers.d/" + cur.source + ": " + ec.message());
        r.where = "peers.d/" + cur.source;
    } else {
        edit_main_file(v.ed.path(), [&](ServerConfig& sc) {
            int i = find_by_name(sc, cur.name);
            if (i < 0) throw Error("peer '" + cur.name + "' vanished from the configuration while it was being edited");
            sc.clients.erase(sc.clients.begin() + i);
            if (sc.clients.empty() && sc.peers_dir.empty())
                throw Error("removing the last peer of the main file would leave the server with none: set peers_dir first");
        });
        r.where = "main configuration";
    }
    r.changed = true;
    r.message = std::string("peer '") + cur.name + "' " + (revoke ? "revoked" : "removed") + " (" + r.where + ")";
    return r;
}

PeerEdit peer_retire_key(const std::string& config_path, const std::string& name, const PublicKey& key) {
    PeersLock guard(config_dir_of(abs_of(config_path)));
    View v = open_view(config_path);
    PeerEdit r;
    int i = find_by_name(v.merged, name);
    if (i < 0) throw Error("peer '" + name + "' not found");
    ClientAcl cur = v.merged.clients[size_t(i)];
    if (cur.public_key == key) throw Error("that is the primary key of '" + name + "': it cannot be retired, remove the peer instead");
    auto it = std::find(cur.extra_keys.begin(), cur.extra_keys.end(), key);
    if (it == cur.extra_keys.end()) {
        r.message = "peer '" + name + "' has no such extra key: nothing to retire";
        return r;
    }
    ClientAcl want = cur;
    want.extra_keys.erase(want.extra_keys.begin() + (it - cur.extra_keys.begin()));
    if (!cur.source.empty()) {
        write_peer_file(v.peers, cur.source, want);
        r.where = "peers.d/" + cur.source;
    } else {
        edit_main_file(v.ed.path(), [&](ServerConfig& sc) {
            int j = find_by_name(sc, name);
            if (j < 0) throw Error("peer '" + name + "' vanished from the configuration while it was being edited");
            ClientAcl w = want;
            w.source.clear();
            sc.clients[size_t(j)] = w;
        });
        r.where = "main configuration";
    }
    r.changed = true;
    r.message = "old key " + key_short(key) + " of peer '" + name + "' retired (" + r.where + ")";
    return r;
}

std::vector<ClientAcl> peer_list(const std::string& config_path, PeerLoad* report) {
    View v = open_view(config_path);
    if (report) *report = v.load;
    return v.merged.clients;
}

}  // namespace mysync
