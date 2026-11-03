// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/invite.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

#include "monocypher.h"
#include "mysync/config.h"
#include "mysync/engine_lock.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/key_mgr.h"
#include "mysync/linkcheck.h"
#include "mysync/net.h"
#include "mysync/protocol.h"
#include "mysync/quick_setup.h"
#include "mysync/secure_channel.h"
#include "mysync/simple/pair_code.h"
#include "mysync/simple/pairing.h"

namespace fs = std::filesystem;

namespace mysync::simple {
namespace {

constexpr uint8_t kCodeVersion = 1;
constexpr char kPrefix[] = "MSY2";
constexpr size_t kMaxHost = 100;
constexpr size_t kMaxCodeText = 2000;
constexpr uint8_t kByeByte = uint8_t(proto::MsgType::Bye);
constexpr uint8_t kRejectedByte = uint8_t(InviteMsg::Rejected);

[[noreturn]] void bad_code() { throw Error("this invitation code is not valid: check that it was copied completely"); }

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
int64_t wall_unix() { return int64_t(std::time(nullptr)); }

Hash256 blake2b256(const uint8_t* d, size_t n) {
    Hash256 h{};
    crypto_blake2b(h.data(), 32, d, n);
    return h;
}

std::string utc_minute(int64_t unix_s) {
    std::time_t t = std::time_t(unix_s);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char b[32];
    std::strftime(b, sizeof b, "%Y-%m-%d %H:%M", &tmv);
    return b;
}

bool is_hex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool label_ok(const std::string& s) { return s.empty() || (!clean_display_name(s).empty() && clean_display_name(s) == s); }

}  // namespace

// ============================================================================================ small helpers
const char* invite_perm_name(InvitePerm p) { return p == InvitePerm::ReadOnly ? "ro" : "rw"; }

std::string invite_id_hex(const InviteId& id) { return to_hex(id.data(), id.size()); }

bool parse_invite_id(const std::string& hex, InviteId& out) {
    if (!is_hex(hex, 16)) return false;
    Bytes b = from_hex(hex);
    std::memcpy(out.data(), b.data(), 8);
    return true;
}

std::string invite_fingerprint(const PubKey& k) { return gui::KeyManager::fingerprint(k); }

bool valid_invite_folder(const std::string& s) {
    if (s.empty() || s.size() > 600 || !proto::valid_utf8(s)) return false;
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7F) return false;
    // Network shares and device / extended prefixes are never a folder to hand out: \\host\share, \\?\..., \\.\...
    if (s.size() >= 2 && (s[0] == '\\' || s[0] == '/') && (s[1] == '\\' || s[1] == '/')) return false;
    const fs::path p = fs::u8path(s);
    if (!p.is_absolute()) return false;
    bool first = true;
    for (const auto& part : p) {
        std::string c = part.u8string();
        if (first) {   // the root (C:\ or /): the rest is checked below
            first = false;
            continue;
        }
        if (c == "\\" || c == "/") continue;
        for (char& ch : c) ch = char(std::tolower(static_cast<unsigned char>(ch)));
        if (c == ".." || c == "__sync") return false;
#ifdef _WIN32
        // Alternate data streams (a:b), and names Windows silently rewrites (trailing dot / space).
        if (c.find(':') != std::string::npos) return false;
        if (c.back() == '.' || c.back() == ' ') return false;
#endif
    }
    return true;
}

namespace {
#ifdef _WIN32
// The real long name of an EXISTING folder (8.3 names and junction-free spelling resolved), without the \\?\ prefix. "" when it cannot.
fs::path final_path(const fs::path& p) {
    HANDLE h = CreateFileW(p.wstring().c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    std::wstring buf(1024, L'\0');
    DWORD n = GetFinalPathNameByHandleW(h, buf.data(), DWORD(buf.size()), VOLUME_NAME_DOS);
    if (n >= buf.size()) {
        buf.assign(n + 1, L'\0');
        n = GetFinalPathNameByHandleW(h, buf.data(), DWORD(buf.size()), VOLUME_NAME_DOS);
    }
    CloseHandle(h);
    if (n == 0 || n >= buf.size()) return {};
    buf.resize(n);
    if (buf.compare(0, 8, L"\\\\?\\UNC\\") == 0) buf = L"\\\\" + buf.substr(8);
    else if (buf.compare(0, 4, L"\\\\?\\") == 0) buf = buf.substr(4);
    return fs::path(buf);
}
#endif
}  // namespace

std::string canonical_folder(const std::string& s) {
    std::error_code ec;
    fs::path p = fs::weakly_canonical(fs::u8path(s), ec).lexically_normal();
    if (ec) p = fs::u8path(s).lexically_normal();
#ifdef _WIN32
    {   // the real long spelling of the part that exists; the missing tail is appended as written
        fs::path head = p, tail;
        std::error_code e2;
        while (!head.empty() && head != head.root_path() && !fs::exists(head, e2)) {
            tail = head.filename() / tail;
            head = head.parent_path();
        }
        fs::path real = final_path(head);
        if (!real.empty()) p = (real / tail).lexically_normal();
    }
#endif
    std::string out = p.u8string();
    while (out.size() > 1 && (out.back() == '/' || out.back() == '\\') && !(out.size() == 3 && out[1] == ':')) out.pop_back();
    return out;
}

namespace {
// Components of a canonical folder, compared as the file system does (case-insensitively on Windows).
std::vector<std::string> folder_parts(const std::string& canon) {
    std::vector<std::string> v;
    for (const auto& part : fs::u8path(canon)) {
        std::string c = part.u8string();
        if (c.empty() || c == "/" || c == "\\") continue;
#ifdef _WIN32
        {   // the file system folds the whole of Unicode, not just ASCII
            std::wstring w = fs::u8path(c).wstring();
            if (!w.empty()) CharLowerBuffW(w.data(), DWORD(w.size()));
            c = fs::path(w).u8string();
        }
#endif
        v.push_back(std::move(c));
    }
    return v;
}
}  // namespace

bool folder_within(const std::string& inner, const std::string& outer) {
    const auto a = folder_parts(canonical_folder(inner)), b = folder_parts(canonical_folder(outer));
    if (b.size() > a.size()) return false;
    return std::equal(b.begin(), b.end(), a.begin());
}

bool same_folder(const std::string& a, const std::string& b) {
    return folder_parts(canonical_folder(a)) == folder_parts(canonical_folder(b));
}

std::string folder_conflict(const std::string& folder, const std::vector<FolderUse>& in_use, const std::vector<std::string>& protected_paths) {
    for (const std::string& p : protected_paths) {
        if (p.empty()) continue;
        if (folder_within(folder, p) || folder_within(p, folder))
            return "this folder contains, or lies inside, a place MySync keeps for itself (configuration, key or state): " + p;
    }
    for (const FolderUse& u : in_use) {
        if (u.path.empty()) continue;
        if (same_folder(folder, u.path)) {
            if (u.shareable) continue;   // the same folder of another invitation: shared on purpose
            return "this folder is already the shared folder of " + u.what;
        }
        if (folder_within(folder, u.path) || folder_within(u.path, folder))
            return "this folder overlaps the folder of " + u.what + " (" + u.path + "): two machines never get folders one inside the other";
    }
    return {};
}

std::vector<FolderUse> folders_in_use(const ServerConfig& cfg, const std::vector<ClientAcl>& peers, const std::vector<InviteRecord>& invites,
                                      int64_t now_unix) {
    std::vector<FolderUse> out;
    // The server's own folder is never handed out, not even partly or as a parent: an invite folder that equals, lies inside or
    // contains it is refused (shareable = false), whether or not any client owns the whole root.
    if (!cfg.root.empty()) out.push_back({canonical_folder(cfg.root), false, "the server's own folder"});
    for (const ClientAcl& c : peers) {
        const std::string base = c.root.empty() ? cfg.root : c.root;
        std::string area = base;
        if (!c.prefix.empty()) area = (fs::u8path(base) / fs::u8path(c.prefix)).u8string();
        out.push_back({area, !c.root.empty() && c.prefix.empty(), "the computer '" + c.name + "'"});
    }
    for (const InviteRecord& r : invites)
        if (r.state(now_unix) == InviteRecord::State::Live) out.push_back({r.folder, true, "invitation " + r.id_hex.substr(0, 8)});
    return out;
}

// ============================================================================================ the code
std::string encode_invite_code(const InviteCode& c) {
    if (c.addrs.empty() || c.addrs.size() > kInviteMaxAddrs) throw Error("invitation code: 1 to 3 addresses are needed");
    if (c.expires_unix <= 0 || c.expires_unix > int64_t(0xFFFFFFFFll)) throw Error("invitation code: the expiry is out of range");
    if (!label_ok(c.machine) || !label_ok(c.label)) throw Error("invitation code: the machine / folder name cannot be used");
    Bytes p;
    p.push_back(kCodeVersion);
    p.insert(p.end(), c.server_key.begin(), c.server_key.end());
    p.insert(p.end(), c.id.begin(), c.id.end());
    p.insert(p.end(), c.secret.begin(), c.secret.end());
    for (int sh = 24; sh >= 0; sh -= 8) p.push_back(uint8_t((uint64_t(c.expires_unix) >> sh) & 0xFF));
    p.push_back(uint8_t(c.perm));
    p.push_back(uint8_t(c.addrs.size()));
    for (const InviteAddr& a : c.addrs) {
        if (a.port == 0) throw Error("invitation code: the port must be 1..65535");
        if (!valid_pair_host(a.host)) throw Error("invitation code: an address is not a valid host");
        p.push_back(uint8_t(a.port >> 8));
        p.push_back(uint8_t(a.port & 0xFF));
        p.push_back(uint8_t(a.host.size()));
        p.insert(p.end(), a.host.begin(), a.host.end());
    }
    for (const std::string* s : {&c.machine, &c.label}) {
        p.push_back(uint8_t(s->size()));
        p.insert(p.end(), s->begin(), s->end());
    }
    Hash256 h = blake2b256(p.data(), p.size());
    p.insert(p.end(), h.begin(), h.begin() + 4);
    std::string body = crockford_encode(p);
    std::string out = kPrefix;
    for (size_t i = 0; i < body.size(); i += 5) out += "-" + body.substr(i, 5);
    return out;
}

bool looks_like_invite_code(const std::string& text) {
    size_t i = 0;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) ++i;
    if (text.size() - i < 4) return false;
    for (int k = 0; k < 4; ++k) {
        char c = text[i + size_t(k)];
        if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
        if (c != kPrefix[k]) return false;
    }
    return true;
}

InviteCode decode_invite_code(const std::string& text) {
    if (text.size() > kMaxCodeText || !looks_like_invite_code(text)) bad_code();
    size_t i = 0;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) ++i;
    Bytes p;
    try {
        p = crockford_decode(text.substr(i + 4));
    } catch (const Error&) {
        bad_code();
    }
    // 1 + 32 + 8 + 16 + 4 + 1 + 1 = 63 fixed bytes, then the addresses and two labels, then the 4-byte checksum.
    if (p.size() < 63 + 3 + 1 + 2 + 4 || p[0] != kCodeVersion) bad_code();
    Hash256 h = blake2b256(p.data(), p.size() - 4);
    if (!ct_equal(h.data(), p.data() + p.size() - 4, 4)) bad_code();
    const size_t end = p.size() - 4;
    InviteCode c;
    size_t o = 1;
    std::memcpy(c.server_key.data(), &p[o], 32); o += 32;
    std::memcpy(c.id.data(), &p[o], 8); o += 8;
    std::memcpy(c.secret.data(), &p[o], 16); o += 16;
    c.expires_unix = (int64_t(p[o]) << 24) | (int64_t(p[o + 1]) << 16) | (int64_t(p[o + 2]) << 8) | int64_t(p[o + 3]);
    o += 4;
    if (p[o] > 1) bad_code();
    c.perm = p[o] == 1 ? InvitePerm::ReadWrite : InvitePerm::ReadOnly;
    ++o;
    size_t n = p[o++];
    if (n == 0 || n > kInviteMaxAddrs) bad_code();
    for (size_t k = 0; k < n; ++k) {
        if (o + 3 > end) bad_code();
        InviteAddr a;
        a.port = uint16_t((p[o] << 8) | p[o + 1]);
        size_t hl = p[o + 2];
        o += 3;
        if (a.port == 0 || hl == 0 || hl > kMaxHost || o + hl > end) bad_code();
        a.host.assign(reinterpret_cast<const char*>(&p[o]), hl);
        o += hl;
        if (!valid_pair_host(a.host)) bad_code();
        c.addrs.push_back(std::move(a));
    }
    for (std::string* s : {&c.machine, &c.label}) {
        if (o + 1 > end) bad_code();
        size_t l = p[o++];
        if (o + l > end) bad_code();
        s->assign(reinterpret_cast<const char*>(&p[o]), l);
        o += l;
        if (!label_ok(*s)) bad_code();
    }
    if (o != end) bad_code();
    return c;
}

// ============================================================================================ proof
InviteProof derive_invite_proof(const InviteSecret& secret) {
    static const char kTag[] = "MSY2-seed";
    uint8_t in[sizeof kTag - 1 + 16];
    std::memcpy(in, kTag, sizeof kTag - 1);
    std::memcpy(in + sizeof kTag - 1, secret.data(), 16);
    uint8_t seed[32];
    crypto_blake2b(seed, 32, in, sizeof in);
    InviteProof pr;
    crypto_eddsa_key_pair(pr.eddsa_secret.data(), pr.verifier.data(), seed);   // wipes the seed
    secure_wipe(in, sizeof in);
    return pr;
}

namespace {
Bytes redeem_message(uint8_t flags, const std::array<uint8_t, 64>& hh, const PubKey& sender, const InviteId& id) {
    static const char kTag[] = "MSY2-redeem-v1";
    Bytes m(kTag, kTag + sizeof kTag - 1);
    m.push_back(flags);
    m.insert(m.end(), hh.begin(), hh.end());
    m.insert(m.end(), sender.begin(), sender.end());
    m.insert(m.end(), id.begin(), id.end());
    return m;
}
}  // namespace

std::array<uint8_t, 64> sign_redeem(const InviteSecret& secret, uint8_t flags, const std::array<uint8_t, 64>& hh,
                                    const PubKey& sender, const InviteId& id) {
    InviteProof pr = derive_invite_proof(secret);
    Bytes m = redeem_message(flags, hh, sender, id);
    std::array<uint8_t, 64> sig{};
    crypto_eddsa_sign(sig.data(), pr.eddsa_secret.data(), m.data(), m.size());
    secure_wipe(pr.eddsa_secret.data(), 64);
    return sig;
}

bool verify_redeem(const std::array<uint8_t, 32>& verifier, const std::array<uint8_t, 64>& sig, uint8_t flags,
                   const std::array<uint8_t, 64>& hh, const PubKey& sender, const InviteId& id) {
    Bytes m = redeem_message(flags, hh, sender, id);
    return crypto_eddsa_check(sig.data(), verifier.data(), m.data(), m.size()) == 0;
}

// ============================================================================================ store
InviteRecord::State InviteRecord::state(int64_t now_unix) const {
    if (revoked) return State::Revoked;
    if (uses_left <= 0) return State::UsedUp;
    if (now_unix >= expires_unix) return State::Expired;
    return State::Live;
}

namespace {

std::string serialize_record(const InviteRecord& r) {
    std::ostringstream o;
    o << "version = 1\n"
      << "id = " << r.id_hex << "\n"
      << "label = " << r.label << "\n"
      << "machine = " << r.machine << "\n"
      << "folder = " << r.folder << "\n"
      << "perm = " << invite_perm_name(r.perm) << "\n"
      << "verifier = " << to_hex(r.verifier.data(), 32) << "\n"
      << "uses_total = " << r.uses_total << "\n"
      << "uses_left = " << r.uses_left << "\n"
      << "created = " << r.created_unix << "\n"
      << "expires = " << r.expires_unix << "\n"
      << "created_by = " << r.created_by << "\n"
      << "ask = " << (r.ask ? 1 : 0) << "\n"
      << "revoked = " << (r.revoked ? 1 : 0) << "\n";
    for (const InviteJoined& j : r.joined) o << "joined = " << j.key_hex << "\t" << j.when_utc << "\t" << j.name << "\n";
    return o.str();
}

bool parse_int(const std::string& s, int64_t& v) {
    if (s.empty() || s.size() > 18) return false;
    size_t i = s[0] == '-' ? 1 : 0;
    if (i == s.size()) return false;
    for (size_t k = i; k < s.size(); ++k)
        if (s[k] < '0' || s[k] > '9') return false;
    v = std::stoll(s);
    return true;
}

bool parse_record(const std::string& text, InviteRecord& r) {
    InviteRecord out;
    bool have_id = false, have_ver = false;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find(" = ");
        if (eq == std::string::npos) {
            if (line.size() > 2 && line.compare(line.size() - 2, 2, " =") == 0) eq = line.size() - 2;
            else return false;
        }
        std::string k = line.substr(0, eq), v = eq + 3 <= line.size() ? line.substr(eq + 3) : std::string();
        int64_t n = 0;
        if (k == "version") { if (v != "1") return false; have_ver = true; }
        else if (k == "id") { if (!is_hex(v, 16)) return false; out.id_hex = v; have_id = true; }
        else if (k == "label") out.label = v;
        else if (k == "machine") out.machine = v;
        else if (k == "folder") out.folder = v;
        else if (k == "perm") { if (v == "ro") out.perm = InvitePerm::ReadOnly; else if (v == "rw") out.perm = InvitePerm::ReadWrite; else return false; }
        else if (k == "verifier") { if (!is_hex(v, 64)) return false; Bytes b = from_hex(v); std::memcpy(out.verifier.data(), b.data(), 32); }
        else if (k == "uses_total") { if (!parse_int(v, n) || n < 1 || n > kInviteMaxUses) return false; out.uses_total = int(n); }
        else if (k == "uses_left") { if (!parse_int(v, n) || n < 0 || n > kInviteMaxUses) return false; out.uses_left = int(n); }
        else if (k == "created") { if (!parse_int(v, n)) return false; out.created_unix = n; }
        else if (k == "expires") { if (!parse_int(v, n)) return false; out.expires_unix = n; }
        else if (k == "created_by") out.created_by = v;
        else if (k == "ask") out.ask = v == "1";
        else if (k == "revoked") out.revoked = v == "1";
        else if (k == "joined") {
            size_t t1 = v.find('\t');
            size_t t2 = t1 == std::string::npos ? t1 : v.find('\t', t1 + 1);
            if (t2 == std::string::npos) return false;
            InviteJoined j;
            j.key_hex = v.substr(0, t1);
            j.when_utc = v.substr(t1 + 1, t2 - t1 - 1);
            j.name = v.substr(t2 + 1);
            out.joined.push_back(std::move(j));
        }
        // unknown keys are ignored (a newer version may add them)
    }
    if (!have_id || !have_ver) return false;
    if (out.uses_left > out.uses_total) return false;
    if (!valid_invite_folder(out.folder)) return false;   // a tampered file never widens what is granted
    r = std::move(out);
    return true;
}

// One writer at a time across processes (mysync invite create | revoke in one process, the server redeeming in another).
struct StoreLock {
    std::unique_ptr<FileLock> lock;
    explicit StoreLock(const std::string& dir) {
        const std::string path = (fs::u8path(dir) / ".invites.lock").u8string();
        std::string holder;
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        for (;;) {
            lock = FileLock::try_acquire(path, &holder);
            if (lock) return;
            if (std::chrono::steady_clock::now() >= end) throw Error("the invitations folder is busy (locked by another process)");
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
};

// Refuses a folder that is, or sits behind, a symbolic link / junction, and (POSIX) one that others can write into.
void check_store_dir(const std::string& dir) {
    std::string link = link_component(dir);
    if (!link.empty()) throw Error(link_refusal_text(dir));
#ifndef _WIN32
    struct stat st;
    if (::stat(dir.c_str(), &st) == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)))
        throw Error("the invitations folder " + dir + " can be written by other accounts: refusing it");
#endif
}

std::string read_whole(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

InviteStore::InviteStore(std::string dir, Clock clock) : dir_(std::move(dir)), clock_(std::move(clock)) {}

int64_t InviteStore::now() const { return clock_ ? clock_() : wall_unix(); }

namespace {
fs::path file_of(const std::string& dir, const std::string& id_hex) { return fs::u8path(dir) / (id_hex + ".invite"); }

bool load_file(const std::string& dir, const std::string& id_hex, InviteRecord& r) {
    std::error_code ec;
    fs::path p = file_of(dir, id_hex);
    if (!fs::is_regular_file(p, ec) || fs::is_symlink(p, ec)) return false;
    if (!parse_record(read_whole(p), r)) return false;
    return r.id_hex == id_hex;
}

void save_file(const std::string& dir, const InviteRecord& r) {
    gui::write_file_atomic(file_of(dir, r.id_hex).u8string(), serialize_record(r), false);
}
}  // namespace

InviteCode InviteStore::create(const InviteNew& n) {
    if (!valid_invite_folder(n.folder)) throw Error("invitation: the folder must be an absolute path");
    if (!label_ok(n.label) || !label_ok(n.machine)) throw Error("invitation: the name contains characters that cannot be used");
    if (n.ttl_seconds < 1 || n.ttl_seconds > kInviteMaxTtlSeconds) throw Error("invitation: the lifetime must be 1 second to 30 days");
    if (n.uses < 1 || n.uses > kInviteMaxUses) throw Error("invitation: the number of uses must be 1 to 100");
    if (n.addrs.empty() || n.addrs.size() > kInviteMaxAddrs) throw Error("invitation: 1 to 3 addresses are needed");
    if (n.created_by != "cli" && n.created_by != "gui") throw Error("invitation: unknown origin");
    InviteCode code;
    code.server_key = n.server_key;
    code.perm = n.perm;
    code.addrs = n.addrs;
    code.machine = n.machine;
    code.label = n.label;
    code.expires_unix = now() + n.ttl_seconds;
    random_bytes(code.secret.data(), code.secret.size());
    encode_invite_code(code);   // validates the addresses / expiry before anything is written

    std::error_code ec;
    if (!fs::exists(fs::u8path(dir_), ec)) {
        fs::create_directories(fs::u8path(dir_), ec);
        if (ec) throw Error("cannot create the invitations folder " + dir_ + ": " + ec.message());
        make_folder_private(dir_);
    }
    check_store_dir(dir_);
    StoreLock lk(dir_);
    InviteRecord r;
    for (int tries = 0;; ++tries) {
        random_bytes(code.id.data(), code.id.size());
        r.id_hex = invite_id_hex(code.id);
        if (!fs::exists(file_of(dir_, r.id_hex), ec)) break;
        if (tries > 8) throw Error("cannot pick an unused invitation id");
    }
    InviteProof pr = derive_invite_proof(code.secret);
    secure_wipe(pr.eddsa_secret.data(), 64);
    r.label = n.label;
    r.machine = n.machine;
    r.folder = canonical_folder(n.folder);
    r.perm = n.perm;
    r.verifier = pr.verifier;
    r.uses_total = r.uses_left = n.uses;
    r.created_unix = now();
    r.expires_unix = code.expires_unix;
    r.created_by = n.created_by;
    r.ask = n.ask;
    save_file(dir_, r);
    return code;
}

std::vector<InviteRecord> InviteStore::list() const {
    std::vector<InviteRecord> out;
    std::error_code ec;
    if (!fs::is_directory(fs::u8path(dir_), ec)) return out;
    try {
        check_store_dir(dir_);
    } catch (const Error& e) {
        log_warn(e.what());
        return out;
    }
    for (fs::directory_iterator it(fs::u8path(dir_), ec), end; !ec && it != end; it.increment(ec)) {
        std::string name = it->path().filename().u8string();
        if (name.size() != 16 + 7 || name.compare(16, 7, ".invite") != 0) continue;
        InviteRecord r;
        if (!is_hex(name.substr(0, 16), 16) || !load_file(dir_, name.substr(0, 16), r)) {
            log_warn("invitation file " + name + " is unreadable or damaged: skipped");
            continue;
        }
        out.push_back(std::move(r));
    }
    std::sort(out.begin(), out.end(), [](const InviteRecord& a, const InviteRecord& b) {
        return a.created_unix != b.created_unix ? a.created_unix > b.created_unix : a.id_hex > b.id_hex;
    });
    return out;
}

bool InviteStore::get(const InviteId& id, InviteRecord& out) const {
    try {
        check_store_dir(dir_);
    } catch (const Error&) {
        return false;
    }
    return load_file(dir_, invite_id_hex(id), out);
}

bool InviteStore::revoke(const std::string& prefix) {
    std::string p;
    for (char c : prefix) p += char(std::tolower(static_cast<unsigned char>(c)));
    if (p.size() < 4 || p.size() > 16 || !is_hex(p, p.size())) throw Error("give at least 4 hex characters of the invitation id");
    std::error_code ec;
    if (!fs::is_directory(fs::u8path(dir_), ec)) return false;
    check_store_dir(dir_);
    StoreLock lk(dir_);
    std::vector<InviteRecord> hits;
    for (const InviteRecord& r : list())
        if (r.id_hex.compare(0, p.size(), p) == 0) hits.push_back(r);
    if (hits.empty()) return false;
    if (hits.size() > 1) throw Error("several invitations start with '" + p + "': give more characters");
    hits[0].revoked = true;
    save_file(dir_, hits[0]);
    return true;
}

bool InviteStore::has_live(bool include_cli, bool include_gui) const {
    const int64_t t = now();
    for (const InviteRecord& r : list()) {
        if (r.state(t) != InviteRecord::State::Live) continue;
        if (r.created_by == "gui" ? include_gui : include_cli) return true;
    }
    return false;
}

InviteStore::Consumed InviteStore::consume(const InviteId& id, const std::string& name, const std::string& key_hex, bool dry_run,
                                           bool allow_gui) {
    Consumed c;
    try {
        std::error_code ec;
        if (!fs::is_directory(fs::u8path(dir_), ec)) return c;
        check_store_dir(dir_);
        StoreLock lk(dir_);
        InviteRecord r;
        if (!load_file(dir_, invite_id_hex(id), r)) return c;
        if (r.state(now()) != InviteRecord::State::Live) return c;
        if (r.created_by == "gui" && !allow_gui) return c;
        if (!dry_run) {
            InviteRecord n = r;
            n.uses_left -= 1;
            if (!key_hex.empty()) n.joined.push_back({name, key_hex, utc_minute(now())});
            save_file(dir_, n);
        }
        c.ok = true;
        c.rec = std::move(r);
    } catch (const std::exception& e) {
        log_warn(std::string("invitation store: ") + e.what());
        c = Consumed{};
    }
    return c;
}

void InviteStore::refund(const InviteId& id, const std::string& key_hex) {
    try {
        std::error_code ec;
        if (!fs::is_directory(fs::u8path(dir_), ec)) return;
        check_store_dir(dir_);
        StoreLock lk(dir_);
        InviteRecord r;
        if (!load_file(dir_, invite_id_hex(id), r)) return;
        if (r.uses_left < r.uses_total) r.uses_left += 1;
        if (!key_hex.empty())
            for (size_t i = r.joined.size(); i-- > 0;)
                if (r.joined[i].key_hex == key_hex) { r.joined.erase(r.joined.begin() + std::ptrdiff_t(i)); break; }
        save_file(dir_, r);
    } catch (const std::exception& e) {
        log_warn(std::string("invitation store (refund): ") + e.what());
    }
}

void InviteStore::note_joined(const InviteId& id, const std::string& name, const std::string& key_hex) {
    try {
        std::error_code ec;
        if (!fs::is_directory(fs::u8path(dir_), ec)) return;
        check_store_dir(dir_);
        StoreLock lk(dir_);
        InviteRecord r;
        if (!load_file(dir_, invite_id_hex(id), r)) return;
        r.joined.push_back({name, key_hex, utc_minute(now())});
        save_file(dir_, r);
    } catch (const std::exception& e) {
        log_warn(std::string("invitation store (joined): ") + e.what());
    }
}

void InviteStore::purge_old(int64_t keep_days) {
    try {
        std::error_code ec;
        if (!fs::is_directory(fs::u8path(dir_), ec)) return;
        check_store_dir(dir_);
        StoreLock lk(dir_);
        const int64_t t = now();
        for (const InviteRecord& r : list()) {
            if (r.state(t) == InviteRecord::State::Live) continue;
            // "dead since": an expired invite since its expiry; the others conservatively since their creation
            int64_t since = r.state(t) == InviteRecord::State::Expired ? r.expires_unix : std::max(r.created_unix, r.expires_unix);
            if (t - since > keep_days * 86400) fs::remove(file_of(dir_, r.id_hex), ec);
        }
    } catch (const std::exception& e) {
        log_warn(std::string("invitation store (purge): ") + e.what());
    }
}

// ============================================================================================ wire
bool is_invite_wire(const Bytes& b) {
    return !b.empty() && (b[0] == uint8_t(InviteMsg::Redeem) || b[0] == uint8_t(InviteMsg::Granted) || b[0] == uint8_t(InviteMsg::Rejected));
}

Bytes encode_redeem_wire(const RedeemWire& m) {
    proto::Writer w;
    w.u8(uint8_t(InviteMsg::Redeem));
    w.raw(m.id.data(), m.id.size());
    w.u8(m.flags);
    w.raw(m.sig.data(), m.sig.size());
    w.str(m.name);
    return w.take();
}

RedeemWire decode_redeem_wire(const Bytes& b) {
    proto::Reader r(b);
    if (r.u8() != uint8_t(InviteMsg::Redeem)) throw Error("not a redeem message");
    RedeemWire m;
    r.raw(m.id.data(), m.id.size());
    m.flags = r.u8();
    r.raw(m.sig.data(), m.sig.size());
    m.name = r.str();
    r.expect_end();
    return m;
}

Bytes encode_granted_wire(const GrantedWire& g) {
    proto::Writer w;
    w.u8(uint8_t(InviteMsg::Granted));
    w.u8(g.flags);
    w.u8(uint8_t(g.perm));
    w.str(g.subdir);
    w.str(g.machine);
    w.str(g.label);
    w.i64(g.expires_unix);
    w.u32(g.uses_left);
    w.u32(g.seconds_left);
    return w.take();
}

GrantedWire decode_granted_wire(const Bytes& b) {
    proto::Reader r(b);
    if (r.u8() != uint8_t(InviteMsg::Granted)) throw Error("not a granted message");
    GrantedWire g;
    g.flags = r.u8();
    uint8_t p = r.u8();
    if (p > 1) throw Error("bad permission");
    g.perm = p == 1 ? InvitePerm::ReadWrite : InvitePerm::ReadOnly;
    g.subdir = r.str();
    g.machine = r.str();
    g.label = r.str();
    g.expires_unix = r.i64();
    g.uses_left = r.u32();
    g.seconds_left = r.u32();
    r.expect_end();
    return g;
}

// ============================================================================================ manager
namespace {
struct Window {
    std::deque<int64_t> q;
    bool allow(int64_t now, size_t max, int64_t win_ms = 60000) {
        while (!q.empty() && now - q.front() >= win_ms) q.pop_front();
        if (q.size() >= max) return false;
        q.push_back(now);
        return true;
    }
    bool empty_after(int64_t now, int64_t win_ms) {
        while (!q.empty() && now - q.front() >= win_ms) q.pop_front();
        return q.empty();
    }
};
constexpr size_t kFailLimit = 5;                 // failed redemptions...
constexpr int64_t kFailWindowMs = 10 * 60000;    // ...within this window...
constexpr int64_t kFailBlockMs = 10 * 60000;     // ...block the address for this long
constexpr int kAskTtlSeconds = 120;
constexpr size_t kMaxWaiting = 4;
}  // namespace

struct InviteManager::Impl {
    enum class St { Waiting, Approved, Denied };
    struct Pend {
        uint32_t id = 0;
        InviteId inv{};
        std::string name;
        PubKey key{};
        std::string ip;
        int64_t expires = 0, keep_until = 0;
        St st = St::Waiting;
        InviteRecord rec;       // as it was when the redemption was accepted
        std::string subdir;     // canonical, once approved
        bool reserved = false;  // a slot taken while the invitation is being consumed (not visible, not matched)
        bool busy = false;      // being approved: purge leaves it alone
    };

    PubKey server_pub{};
    ClockMs clock;
    std::mutex m;
    std::mutex approve_mu;
    GrantFn grant;
    std::atomic<bool> gui_allowed{true};
    std::map<std::string, Window> ip_hs, ip_fail;
    std::map<std::string, int64_t> blocked;
    Window global_hs;
    int active = 0;
    std::map<std::string, int> active_ip;
    std::vector<Pend> pend;
    uint32_t next_id = 1;
    std::vector<InviteId> refunds;    // uses to give back (waiting requests that expired), flushed outside the lock
    int64_t live_cache_until = 0;     // has_live() answered true until then (steady ms)

    int64_t now() const { return clock ? clock() : steady_ms(); }

    void purge(int64_t t) {
        for (auto it = blocked.begin(); it != blocked.end();) it = t >= it->second ? blocked.erase(it) : std::next(it);
        for (auto* tbl : {&ip_hs, &ip_fail})
            for (auto it = tbl->begin(); it != tbl->end();) it = it->second.empty_after(t, kFailWindowMs) ? tbl->erase(it) : std::next(it);
        for (auto it = pend.begin(); it != pend.end();) {
            const bool gone = it->reserved || it->busy ? false : (it->st == St::Waiting ? t >= it->expires : t >= it->keep_until);
            if (gone && it->st == St::Waiting) refunds.push_back(it->inv);   // the ask request timed out: the use goes back
            it = gone ? pend.erase(it) : std::next(it);
        }
    }
    bool is_blocked(const std::string& ip, int64_t t) const {
        auto it = blocked.find(ip);
        return it != blocked.end() && t < it->second;
    }
    void note_failure(const std::string& ip, int64_t t) {
        if (blocked.size() > 2000) blocked.clear();
        Window& w = ip_fail[ip];
        while (!w.q.empty() && t - w.q.front() >= kFailWindowMs) w.q.pop_front();
        w.q.push_back(t);
        if (w.q.size() >= kFailLimit) blocked[ip] = t + kFailBlockMs;   // the 5th failure inside the window blocks the address
    }
    Pend* find_key_inv(const PubKey& k, const InviteId& i) {
        for (Pend& p : pend)
            if (!p.reserved && ct_equal(p.key.data(), k.data(), 32) && ct_equal(p.inv.data(), i.data(), 8)) return &p;
        return nullptr;
    }
    Pend* find_key(const PubKey& k) {
        for (Pend& p : pend)
            if (!p.reserved && ct_equal(p.key.data(), k.data(), 32)) return &p;
        return nullptr;
    }
    Pend* find_id(uint32_t id) {
        for (Pend& p : pend)
            if (p.id == id) return &p;
        return nullptr;
    }
    static uint32_t secs_left(int64_t deadline, int64_t t) { return deadline > t ? uint32_t((deadline - t + 999) / 1000) : 0; }
};

InviteManager::InviteManager(const PubKey& server_pub, std::shared_ptr<InviteStore> store, ClockMs clock)
    : p_(std::make_shared<Impl>()), store_(std::move(store)) {
    p_->server_pub = server_pub;
    p_->clock = std::move(clock);
}

void InviteManager::set_grant_handler(GrantFn fn) {
    std::lock_guard<std::mutex> lk(p_->m);
    p_->grant = std::move(fn);
}

void InviteManager::set_gui_invites_allowed(bool allowed) { p_->gui_allowed = allowed; }

bool InviteManager::admit_handshake(const std::string& ip, const PubKey& key) {
    bool need_live_check = false;
    {
        std::lock_guard<std::mutex> lk(p_->m);
        int64_t t = p_->now();
        p_->purge(t);
        if (p_->is_blocked(ip, t)) return false;
        Impl::Pend* ex = p_->find_key(key);   // a sender that is waiting for its approval may reconnect
        if (ex) {
            if (p_->active >= kPairMaxSessions || p_->active_ip[ip] >= kPairMaxSessionsPerIp) return false;
            ++p_->active;
            ++p_->active_ip[ip];
            return true;
        }
        // The budgets come BEFORE any store I/O: a flood of handshakes costs a map lookup, not a directory scan.
        if (!p_->ip_hs[ip].allow(t, 12)) return false;      // 12 handshakes / minute / IP
        if (!p_->global_hs.allow(t, 40)) return false;      // 40 / minute overall
        need_live_check = steady_ms() >= p_->live_cache_until;
    }
    flush_refunds();
    if (need_live_check) {
        if (!store_->has_live(true, p_->gui_allowed.load())) return false;
        std::lock_guard<std::mutex> lk(p_->m);
        p_->live_cache_until = steady_ms() + 1000;   // only "yes" is remembered: a new invitation is honoured at once
    }
    std::lock_guard<std::mutex> lk(p_->m);
    int& per_ip = p_->active_ip[ip];
    if (p_->active >= kPairMaxSessions || per_ip >= kPairMaxSessionsPerIp) {
        if (per_ip == 0) p_->active_ip.erase(ip);
        return false;
    }
    ++p_->active;
    ++per_ip;
    return true;
}

void InviteManager::flush_refunds() const {
    std::vector<InviteId> r;
    {
        std::lock_guard<std::mutex> lk(p_->m);
        r.swap(p_->refunds);
    }
    for (const InviteId& id : r) store_->refund(id);
}

bool InviteManager::revoke(const std::string& prefix) {
    bool hit = store_->revoke(prefix);
    if (!hit) return false;
    std::string p;
    for (char c : prefix) p += char(std::tolower(static_cast<unsigned char>(c)));
    std::lock_guard<std::mutex> lk(p_->m);
    p_->pend.erase(std::remove_if(p_->pend.begin(), p_->pend.end(),
                                  [&](const Impl::Pend& e) { return !e.busy && invite_id_hex(e.inv).compare(0, p.size(), p) == 0; }),
                   p_->pend.end());
    p_->live_cache_until = 0;
    return true;
}

void InviteManager::session_ended(const std::string& ip) {
    std::lock_guard<std::mutex> lk(p_->m);
    auto it = p_->active_ip.find(ip);
    if (it != p_->active_ip.end() && --it->second <= 0) p_->active_ip.erase(it);
    if (p_->active > 0) --p_->active;
}

namespace {
void audit_line(InviteStore& store, const std::string& line) {
    log_info("invite AUDIT " + line);
    try {
        std::error_code ec;
        if (!fs::is_directory(fs::u8path(store.dir()), ec)) return;
        std::ofstream f(fs::u8path(store.dir()) / "audit.log", std::ios::app | std::ios::binary);
        if (f) f << utc_minute(store.now()) << " " << line << "\n";
    } catch (...) {
    }
}

std::string audit_name(const std::string& n) {
    std::string c = clean_display_name(n);
    return c.empty() ? "-" : "\"" + c + "\"";
}

GrantedWire granted_of(const InviteRecord& r, const std::string& subdir, uint32_t uses_left, uint8_t flags, uint32_t seconds_left) {
    GrantedWire g;
    g.flags = flags;
    g.perm = r.perm;
    g.subdir.clear();   // the sender no longer needs the folder: the receiver confines it to its own
    (void)subdir;
    g.machine = r.machine;
    g.label = r.label;
    g.expires_unix = r.expires_unix;
    g.uses_left = uses_left;
    g.seconds_left = seconds_left;
    return g;
}
}  // namespace

InviteManager::Reply InviteManager::on_message(const RedeemRequest& rq) {
    Reply rep;
    const std::string keyhex = key_to_hex(rq.sender_key);
    flush_refunds();
    // Every failure looks the same from outside: one byte, the connection closed. The reason goes to the audit line only.
    auto reject = [&](const char* why, const std::string& name, const std::string& id_hex, bool count) {
        rep.msg = Bytes{kRejectedByte};
        rep.close = true;
        rep.failed_auth = count;
        if (count) {
            std::lock_guard<std::mutex> lk(p_->m);
            p_->note_failure(rq.ip, p_->now());
        }
        audit_line(*store_, "id=" + (id_hex.empty() ? "-" : id_hex) + " name=" + audit_name(name) + " ip=" + rq.ip + " result=refused (" + why + ")");
        return rep;
    };
    try {
        if (rq.raw.size() == 1 && rq.raw[0] == kByeByte) {
            rep.close = true;
            return rep;
        }
        if (rq.raw.empty() || rq.raw[0] != uint8_t(InviteMsg::Redeem)) return reject("unexpected message", "", "", true);
        {
            std::lock_guard<std::mutex> lk(p_->m);
            int64_t t = p_->now();
            p_->purge(t);
            if (p_->is_blocked(rq.ip, t)) {
                rep.msg = Bytes{kRejectedByte};
                rep.close = true;
                return rep;
            }
        }
        RedeemWire w;
        try {
            w = decode_redeem_wire(rq.raw);
        } catch (const std::exception&) {
            return reject("malformed", "", "", true);
        }
        const std::string id_hex = invite_id_hex(w.id);
        std::string name = clean_display_name(w.name);
        if (name.empty()) return reject("unusable device name", "", id_hex, true);
        if ((w.flags & ~uint8_t(1)) != 0) return reject("unknown flags", name, id_hex, true);
        const bool dry = (w.flags & 1) != 0;

        // The signature is checked first, against the verifier of the invite (a public value). An unknown id is verified
        // against a dummy verifier so that both outcomes cost the same.
        InviteRecord rec;
        const bool known = store_->get(w.id, rec);
        std::array<uint8_t, 32> dummy{};
        const bool sig_ok = verify_redeem(known ? rec.verifier : dummy, w.sig, w.flags, rq.handshake_hash, rq.sender_key, w.id);
        if (!known || !sig_ok) return reject(known ? "bad signature" : "unknown invitation", name, id_hex, true);

        // Resume: the same key coming back for an `ask` invite it already redeemed (polling, or a reconnect).
        if (!dry) {
            std::lock_guard<std::mutex> lk(p_->m);
            Impl::Pend* e = p_->find_key_inv(rq.sender_key, w.id);
            if (e) {
                int64_t t = p_->now();
                if (e->st == Impl::St::Waiting) {
                    rep.msg = encode_granted_wire(granted_of(e->rec, "", uint32_t(e->rec.uses_left), 2, Impl::secs_left(e->expires, t)));
                    return rep;
                }
                if (e->st == Impl::St::Approved) {
                    rep.msg = encode_granted_wire(granted_of(e->rec, e->subdir, uint32_t(std::max(0, e->rec.uses_left - 1)), 0, 0));
                    rep.close = true;
                    return rep;
                }
                rep.msg = Bytes{kRejectedByte};
                rep.close = true;
                return rep;
            }
        }

        const bool gui_ok = p_->gui_allowed.load();
        if (dry) {
            InviteStore::Consumed c = store_->consume(w.id, name, "", true, gui_ok);
            if (!c.ok) return reject("not redeemable", name, id_hex, true);
            rep.msg = encode_granted_wire(granted_of(c.rec, c.rec.folder, uint32_t(c.rec.uses_left), 1, 0));
            rep.close = true;
            audit_line(*store_, "id=" + id_hex + " name=" + audit_name(name) + " ip=" + rq.ip + " result=probe ok");
            return rep;
        }

        GrantFn grant;
        uint32_t reserved_id = 0;
        bool too_many = false;
        {
            std::lock_guard<std::mutex> lk(p_->m);
            grant = p_->grant;
            if (rec.ask && grant) {
                // The count and the slot are ONE step under the lock: concurrent redemptions cannot all pass the check.
                size_t waiting = 0;
                for (const auto& e : p_->pend) waiting += e.st == Impl::St::Waiting;
                if (waiting >= kMaxWaiting) {
                    too_many = true;
                } else {
                    Impl::Pend slot;
                    slot.id = reserved_id = p_->next_id++;
                    slot.inv = w.id;
                    slot.name = name;
                    slot.key = rq.sender_key;
                    slot.ip = rq.ip;
                    slot.reserved = true;
                    slot.expires = p_->now() + int64_t(kAskTtlSeconds) * 1000;
                    p_->pend.push_back(slot);
                }
            }
        }
        if (too_many) return reject("too many requests waiting", name, id_hex, false);
        if (!grant) return reject("no grant handler", name, id_hex, false);

        if (rec.ask) {
            InviteStore::Consumed c = store_->consume(w.id, name, "", false, gui_ok);   // joined is written on approval
            bool filled = false;
            if (c.ok) {
                std::lock_guard<std::mutex> lk(p_->m);
                if (Impl::Pend* e = p_->find_id(reserved_id)) {
                    e->rec = c.rec;
                    e->reserved = false;
                    e->expires = p_->now() + int64_t(kAskTtlSeconds) * 1000;
                    filled = true;
                }
            }
            if (!filled) {
                {
                    std::lock_guard<std::mutex> lk(p_->m);
                    if (Impl::Pend* e = p_->find_id(reserved_id)) p_->pend.erase(p_->pend.begin() + (e - p_->pend.data()));
                }
                if (c.ok) store_->refund(w.id);   // consumed but the slot is gone: give the use back
                return reject("not redeemable", name, id_hex, true);
            }
            rep.msg = encode_granted_wire(granted_of(c.rec, "", uint32_t(c.rec.uses_left - 1), 2, uint32_t(kAskTtlSeconds)));
            audit_line(*store_, "id=" + id_hex + " name=" + audit_name(name) + " ip=" + rq.ip + " result=waiting for approval");
            return rep;
        }

        InviteStore::Consumed c = store_->consume(w.id, name, keyhex, false, gui_ok);
        if (!c.ok) return reject("not redeemable", name, id_hex, true);
        std::string canon;
        try {
            canon = grant(name, rq.sender_key, c.rec.perm, c.rec.folder);
        } catch (const std::exception& e) {
            store_->refund(w.id, keyhex);
            log_warn(std::string("invitation: the grant failed: ") + e.what());
            return reject("grant failed", name, id_hex, false);
        }
        rep.msg = encode_granted_wire(granted_of(c.rec, canon, uint32_t(std::max(0, c.rec.uses_left - 1)), 0, 0));
        rep.close = true;
        audit_line(*store_, "id=" + id_hex + " name=" + audit_name(name) + " ip=" + rq.ip + " key=" + keyhex.substr(0, 8) +
                                " result=granted " + invite_perm_name(c.rec.perm) + " folder=\"" + canon + "\"");
        return rep;
    } catch (const std::exception&) {
        rep.msg = Bytes{kRejectedByte};
        rep.close = true;
        return rep;
    }
}

std::vector<PendingInvite> InviteManager::pending() const {
    std::vector<PendingInvite> out;
    {
    std::lock_guard<std::mutex> lk(p_->m);
    int64_t t = p_->now();
    p_->purge(t);
    for (const auto& e : p_->pend) {
        if (e.st != Impl::St::Waiting || e.reserved) continue;
        PendingInvite pi;
        pi.id = e.id;
        pi.name = e.name;
        pi.sas = pair_sas(e.key, p_->server_pub);
        pi.ip = e.ip;
        pi.seconds_left = int(Impl::secs_left(e.expires, t));
        pi.label = e.rec.label;
        out.push_back(pi);
    }
    }
    flush_refunds();
    return out;
}

std::string InviteManager::approve(uint32_t id) {
    std::lock_guard<std::mutex> ap(p_->approve_mu);
    flush_refunds();
    std::string name;
    PubKey key{};
    InviteRecord rec;
    InviteId inv{};
    GrantFn fn;
    {
        std::lock_guard<std::mutex> lk(p_->m);
        p_->purge(p_->now());
        Impl::Pend* e = p_->find_id(id);
        if (!e || e->st != Impl::St::Waiting) throw Error("this request no longer exists (it expired or was already answered)");
        name = e->name;
        key = e->key;
        rec = e->rec;
        inv = e->inv;
        fn = p_->grant;
        e->busy = true;   // purge leaves it alone while it is being written
    }
    auto unbusy = [&] {
        std::lock_guard<std::mutex> lk(p_->m);
        if (Impl::Pend* e = p_->find_id(id)) e->busy = false;
    };
    std::string canon;
    try {
        if (!fn) throw Error("invitations are not available");
        if (rec.perm != InvitePerm::ReadOnly && rec.perm != InvitePerm::ReadWrite) throw Error("bad invitation");
        // The invitation may have been revoked (or run out of time) while the request was waiting: judge it now, from the store.
        InviteRecord cur;
        if (!store_->get(inv, cur) || cur.revoked || store_->now() >= cur.expires_unix)
            throw Error("this invitation was revoked or has expired: the request cannot be approved");
        canon = fn(name, key, cur.perm, cur.folder);   // throws to refuse: the request stays waiting
        rec = cur;
    } catch (...) {
        unbusy();
        throw;
    }
    store_->note_joined(inv, name, key_to_hex(key));
    {
        std::lock_guard<std::mutex> lk(p_->m);
        int64_t t = p_->now();
        if (Impl::Pend* e = p_->find_id(id)) {
            e->st = Impl::St::Approved;
            e->subdir = canon;
            e->busy = false;
            e->keep_until = t + 30000;
        } else {   // the request expired while the peer was being written: it IS in the allowlist, tell the sender
            Impl::Pend done;
            done.id = id;
            done.inv = inv;
            done.name = name;
            done.key = key;
            done.rec = rec;
            done.st = Impl::St::Approved;
            done.subdir = canon;
            done.keep_until = t + 30000;
            p_->pend.push_back(done);
        }
    }
    audit_line(*store_, "id=" + invite_id_hex(inv) + " name=" + audit_name(name) + " key=" + key_to_hex(key).substr(0, 8) +
                            " result=approved by the receiver, " + invite_perm_name(rec.perm) + " folder=\"" + canon + "\"");
    return canon;
}

void InviteManager::deny(uint32_t id) {
    std::lock_guard<std::mutex> ap(p_->approve_mu);
    flush_refunds();
    InviteId inv{};
    std::string name;
    {
        std::lock_guard<std::mutex> lk(p_->m);
        int64_t t = p_->now();
        p_->purge(t);
        Impl::Pend* e = p_->find_id(id);
        if (!e || e->st != Impl::St::Waiting) throw Error("this request no longer exists");
        e->st = Impl::St::Denied;
        e->keep_until = t + 30000;
        inv = e->inv;
        name = e->name;
    }
    store_->refund(inv);   // a denied request gives its use back
    audit_line(*store_, "id=" + invite_id_hex(inv) + " name=" + audit_name(name) + " result=denied by the receiver");
}

// ============================================================================================ sender
namespace {

struct Connected {
    std::optional<SecureChannel> ch;
    InviteAddr addr;
};

// Tries each address in order; a pinned-key mismatch and a dead address look the same (Unreachable).
bool connect_pinned(const InviteCode& code, const KeyPair& self, const std::atomic<bool>& cancel, Connected& out) {
    net::init();
    for (const InviteAddr& a : code.addrs) {
        if (cancel.load()) return false;
        try {
            net::Socket s = net::Socket::connect(a.host, a.port, 5000);
            out.ch.emplace(SecureChannel::client(std::move(s), self, code.server_key));
            out.ch->socket().set_timeouts(20000, 10000);
            out.addr = a;
            return true;
        } catch (const std::exception&) {
        }
    }
    return false;
}

InviteOutcome outcome(InviteOutcome::Kind k, const std::string& msg) {
    InviteOutcome o;
    o.kind = k;
    o.message = msg;
    return o;
}

void fill_grant(InviteOutcome& o, const InviteCode& code, const Connected& c, const GrantedWire& g) {
    o.grant.machine = g.machine.empty() ? code.machine : g.machine;
    o.grant.label = g.label.empty() ? code.label : g.label;
    o.grant.perm = g.perm;
    o.grant.subdir = g.subdir;
    o.grant.expires_unix = g.expires_unix;
    o.grant.uses_left = g.uses_left;
    o.grant.fingerprint = invite_fingerprint(code.server_key);
    o.grant.address = c.addr;
    o.grant.server_key = code.server_key;
}

InviteOutcome run_invite(const InviteCode& code, const KeyPair& self, const std::string& device_name, bool dry,
                         const std::atomic<bool>& cancel, const std::function<void(int)>& progress, int timeout_s) {
    if (code.expires_unix <= wall_unix()) return outcome(InviteOutcome::Expired, "this invitation has expired");
    std::string name = clean_display_name(device_name);
    if (name.empty()) return outcome(InviteOutcome::Failed, "the name of this computer cannot be used (empty, too long or has control characters)");
    const int64_t deadline = steady_ms() + int64_t(timeout_s) * 1000;
    Connected c;
    if (!connect_pinned(code, self, cancel, c)) {
        if (cancel.load()) return outcome(InviteOutcome::Cancelled, "cancelled");
        return outcome(InviteOutcome::Unreachable, "the other computer is not reachable, or this code is not for it");
    }
    SecureChannel& ch = *c.ch;
    try {
        RedeemWire w;
        w.id = code.id;
        w.flags = dry ? 1 : 0;
        w.name = name;
        w.sig = sign_redeem(code.secret, w.flags, ch.handshake_hash(), self.pub, code.id);
        const Bytes req = encode_redeem_wire(w);
        ch.send_msg(req);
        for (;;) {
            Bytes raw = ch.recv_msg_within(20000);
            if (raw.size() == 1 && raw[0] == kRejectedByte)
                return outcome(InviteOutcome::Refused, "the other computer did not accept this invitation");
            GrantedWire g = decode_granted_wire(raw);
            if (g.flags & 2) {   // waiting for the receiver's user
                if (progress) progress(int(g.seconds_left));
                for (int i = 0; i < 20 && !cancel.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (cancel.load()) {
                    try { ch.send_msg(Bytes{kByeByte}); } catch (const std::exception&) {}
                    return outcome(InviteOutcome::Cancelled, "cancelled");
                }
                if (steady_ms() >= deadline) {
                    try { ch.send_msg(Bytes{kByeByte}); } catch (const std::exception&) {}
                    return outcome(InviteOutcome::Expired, "no answer in time");
                }
                ch.send_msg(req);   // poll: the same request, same session, same signature
                continue;
            }
            InviteOutcome o = outcome(InviteOutcome::Ok, dry ? "the invitation works" : "joined");
            fill_grant(o, code, c, g);
            if (dry) {
                try { ch.send_msg(Bytes{kByeByte}); } catch (const std::exception&) {}
            }
            return o;
        }
    } catch (const std::exception& e) {
        return outcome(InviteOutcome::Failed, std::string("the exchange with the other computer failed: ") + e.what());
    }
}

}  // namespace

InviteOutcome probe_invite(const InviteCode& code, const KeyPair& self, const std::atomic<bool>& cancel) {
    return run_invite(code, self, default_device_name(), true, cancel, {}, 30);
}

InviteOutcome redeem_invite(const InviteCode& code, const KeyPair& self, const std::string& device_name, const std::atomic<bool>& cancel,
                            const std::function<void(int)>& progress, int timeout_s) {
    return run_invite(code, self, device_name, false, cancel, progress, timeout_s);
}

std::string invite_sas(const InviteCode& code, const KeyPair& self) { return pair_sas(self.pub, code.server_key); }

}  // namespace mysync::simple
