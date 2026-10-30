// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/trust.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <functional>
#include <set>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <climits>
#include <cstdlib>
#include <cstring>
#endif

namespace fs = std::filesystem;

namespace mysync::gui {
namespace {

std::string fix_hint(const std::string& path) {
#ifdef _WIN32
    return "; remove write access for that principal from the permissions of '" + path +
           "', or have an administrator add it with --trust-writer when installing the service";
#else
    return "; fix with: chown root '" + path + "' && chmod go-w '" + path +
           "', or have the administrator add the account with --trust-writer when installing the service";
#endif
}

}  // namespace

// ============================================================================================ Windows
#ifdef _WIN32
namespace {

std::string sid_text(PSID sid) {
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid, &s)) return {};
    std::wstring w(s);
    LocalFree(s);
    return fs::path(w).u8string();
}

constexpr DWORD kWriteMask = 0x2 /*WRITE_DATA / ADD_FILE*/ | 0x4 /*APPEND / ADD_SUBDIR*/ | 0x40 /*DELETE_CHILD*/ |
                             0x10000 /*DELETE*/ | 0x40000 /*WRITE_DAC*/ | 0x80000 /*WRITE_OWNER*/ | GENERIC_WRITE |
                             GENERIC_ALL;

const char* const kTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

bool is_admin_sid(const std::string& sid) {
    return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == kTrustedInstaller;
}

std::string own_sid() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return {};
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::string r;
    if (len) {
        std::vector<uint8_t> buf(len);
        if (GetTokenInformation(tok, TokenUser, buf.data(), len, &len))
            r = sid_text(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid);
    }
    CloseHandle(tok);
    return r;
}

// Every effective allow-ACE with a write-type right must satisfy `ok(sid)` (a whitelist); conditional / object ACEs
// are refused; the owner too must satisfy it when `check_owner`. Returns "" or the reason.
std::string scan(const std::string& path, const std::function<bool(const std::string&)>& ok, bool check_owner) {
    std::wstring wp = fs::u8path(path).wstring();
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD rc = GetNamedSecurityInfoW(wp.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                                     &owner, nullptr, &dacl, nullptr, &sd);
    if (rc != ERROR_SUCCESS) return "cannot read the permissions (error " + std::to_string(rc) + ")";
    std::string result;
    if (!dacl) {
        result = "has no access control list (everyone can write)";
    } else {
        for (DWORD i = 0; i < dacl->AceCount && result.empty(); ++i) {
            void* ace = nullptr;
            if (!GetAce(dacl, i, &ace)) continue;
            auto* h = static_cast<ACE_HEADER*>(ace);
            if (h->AceFlags & INHERIT_ONLY_ACE) continue;
            if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                auto* a = static_cast<ACCESS_ALLOWED_ACE*>(ace);
                if (!(a->Mask & kWriteMask)) continue;
                std::string s = sid_text(reinterpret_cast<PSID>(&a->SidStart));
                if (s != "S-1-3-0" && !ok(s)) result = "grants write access to " + s;
            } else if (h->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE || h->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                       h->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
                result = "has a conditional / object access entry that cannot be vetted";
            }
        }
        if (result.empty() && check_owner && owner) {
            std::string o = sid_text(owner);
            if (!ok(o)) result = "is owned by " + o;
        }
    }
    LocalFree(sd);
    return result;
}

}  // namespace

std::string untrusted_writer_reason(const std::string& path, const std::vector<std::string>& trusted, bool include_self) {
    std::set<std::string> t = {"S-1-5-18", "S-1-5-32-544", kTrustedInstaller};
    if (include_self) {
        std::string me = own_sid();
        if (!me.empty()) t.insert(me);
    }
    for (const auto& a : trusted) {
        try {
            t.insert(detail::resolve_principal_sid(a));
        } catch (const std::exception&) {
        }
    }
    std::string r = scan(path, [&](const std::string& sid) { return t.count(sid) != 0; }, true);
    return r.empty() ? r : r + fix_hint(path);
}

std::string untrusted_executable_reason(const std::string& exe) {
    auto ok = [](const std::string& sid) { return is_admin_sid(sid); };
    std::string r = scan(exe, ok, true);
    if (!r.empty()) return "'" + exe + "' " + r;
    std::string dir = fs::u8path(exe).parent_path().u8string();
    r = scan(dir, ok, true);
    if (!r.empty()) return "the folder '" + dir + "' " + r;
    return {};
}

#else
// ============================================================================================ POSIX
namespace {

struct Trusted {
    std::set<uid_t> uids;
    std::set<gid_t> gids;
};

Trusted parse_trusted(const std::vector<std::string>& entries, bool include_self) {
    Trusted t;
    t.uids.insert(0);
    if (include_self) t.uids.insert(::geteuid());
    for (const auto& e : entries) {
        try {
            if (e.rfind("uid:", 0) == 0) {
                t.uids.insert(static_cast<uid_t>(std::stoul(e.substr(4))));
            } else if (e.rfind("gid:", 0) == 0) {
                t.gids.insert(static_cast<gid_t>(std::stoul(e.substr(4))));
            } else if (!e.empty() && e[0] == '@') {
                struct group gr{}, *res = nullptr;
                char buf[4096];
                if (::getgrnam_r(e.c_str() + 1, &gr, buf, sizeof buf, &res) == 0 && res) t.gids.insert(gr.gr_gid);
            } else {
                struct passwd pw{}, *res = nullptr;
                char buf[4096];
                if (::getpwnam_r(e.c_str(), &pw, buf, sizeof buf, &res) == 0 && res) t.uids.insert(pw.pw_uid);
            }
        } catch (const std::exception&) {
        }
    }
    return t;
}

}  // namespace

std::string untrusted_writer_reason(const std::string& path, const std::vector<std::string>& trusted, bool include_self) {
    struct stat st{};
    if (::lstat(path.c_str(), &st) != 0) return "cannot be inspected";
    if (S_ISLNK(st.st_mode)) return "is a symbolic link" + fix_hint(path);
    Trusted t = parse_trusted(trusted, include_self);
    if (!t.uids.count(st.st_uid)) return "is owned by uid " + std::to_string(st.st_uid) + fix_hint(path);
    if (S_ISDIR(st.st_mode) && (st.st_mode & S_ISVTX)) return {};  // like /tmp: others may add files but cannot replace ours
    if (st.st_mode & S_IWOTH) return "is writable by every user" + fix_hint(path);
    if ((st.st_mode & S_IWGRP) && !t.gids.count(st.st_gid))
        return "is writable by its group (gid " + std::to_string(st.st_gid) + ")" + fix_hint(path);
    return {};
}

std::string untrusted_executable_reason(const std::string& exe) {
    char real[PATH_MAX];
    if (!::realpath(exe.c_str(), real)) return "'" + exe + "' cannot be resolved";
    if (fs::path(real).lexically_normal() != fs::path(exe).lexically_normal())
        return "'" + exe + "' reaches the program through a symbolic link (real path " + real + ")";
    fs::path p(real);
    while (true) {
        struct stat st{};
        if (::lstat(p.c_str(), &st) != 0) return "'" + p.string() + "' cannot be inspected";
        if (S_ISLNK(st.st_mode)) return "'" + p.string() + "' is a symbolic link";
        if (st.st_uid != 0) return "'" + p.string() + "' is not owned by root";
        if (st.st_mode & (S_IWGRP | S_IWOTH)) return "'" + p.string() + "' is writable by group or others";
        if (p == p.root_path() || !p.has_parent_path() || p.parent_path() == p) break;
        p = p.parent_path();
    }
    return {};
}
#endif

bool valid_trust_writer_entry(const std::string& a) {
    if (a.empty() || a.size() > 256 || a[0] == '-') return false;
    for (unsigned char c : a)
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\'' || c == '`') return false;
    return true;
}

void require_trusted_config(const std::string& config_path, const std::vector<std::string>& trusted, bool include_self) {
    std::string r = untrusted_writer_reason(config_path, trusted, include_self);
    if (!r.empty()) throw Error("refusing to trust the configuration file '" + config_path + "': it " + r);
    std::string dir = fs::u8path(config_path).parent_path().u8string();
    if (dir.empty()) dir = ".";
    r = untrusted_writer_reason(dir, trusted, include_self);
    if (!r.empty())
        throw Error("refusing to trust the configuration file '" + config_path + "': its folder '" + dir + "' " + r);
}

void require_trusted_dir(const std::string& dir, const std::string& what, const std::vector<std::string>& trusted) {
    if (dir.empty()) return;
    std::error_code ec;
    if (!fs::exists(fs::u8path(dir), ec)) return;
    std::string r = untrusted_writer_reason(dir, trusted);
    if (!r.empty()) throw Error("refusing " + what + " '" + dir + "': it " + r);
}

void require_trusted_run(const std::string& config_path, const std::string& state_dir, const std::string& log_file,
                         const std::vector<std::string>& trusted) {
    require_trusted_config(config_path, trusted);
    require_trusted_dir(state_dir, "state_dir", trusted);
    if (!log_file.empty())
        require_trusted_dir(fs::u8path(log_file).parent_path().u8string(), "the log folder", trusted);
}

bool need_strict_trust(bool elevated, bool service) { return elevated || service; }

// ------------------------------------------------------------------------------------------ broad principals
namespace {

// Names are also matched as text, so a name that cannot be resolved here (other domain, other language) is still
// caught when spelled the well-known way. Windows names are additionally resolved and compared by SID.
bool broad_name(const std::string& entry) {
    std::string n = entry;
    for (auto& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    size_t bs = n.find_last_of('\\');
    if (bs != std::string::npos) n = n.substr(bs + 1);
    if (!n.empty() && n[0] == '@') n.erase(0, 1);
    static const char* const kNames[] = {
        "*", "everyone", "world", "all", "users", "user", "other", "others", "authenticated users", "interactive",
        "network", "anonymous", "anonymous logon", "guests", "guest", "domain users", "domain guests",
        "domain computers", "local", "power users", "console logon", "this organization", "local account",
    };
    for (const char* k : kNames)
        if (n == k) return true;
    return false;
}

}  // namespace

namespace detail {

bool is_broad_sid(const std::string& sid) {
    static const char* const kBroad[] = {
        "S-1-1-0",       // Everyone
        "S-1-5-11",      // Authenticated Users
        "S-1-5-32-545",  // BUILTIN\Users
        "S-1-5-32-546",  // Guests
        "S-1-5-32-547",  // Power Users
        "S-1-5-32-554",  // Pre-Windows 2000 compatible access
        "S-1-5-7",       // Anonymous
        "S-1-5-2",       // Network
        "S-1-5-4",       // Interactive
        "S-1-2-0",       // Local
        "S-1-2-1",       // Console logon
        "S-1-5-14",      // Remote interactive logon
        "S-1-5-15",      // This organization
        "S-1-5-113",     // Local account
    };
    for (const char* k : kBroad)
        if (sid == k) return true;
    if (sid.rfind("S-1-5-21-", 0) == 0) {  // Domain Users / Guests / Computers of any domain or machine
        std::string rid = sid.substr(sid.find_last_of('-') + 1);
        if (rid == "513" || rid == "514" || rid == "515") return true;
    }
    return false;
}

}  // namespace detail

std::string broad_principal_reason(const std::string& entry) {
    std::string upper = entry;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    bool broad = broad_name(entry) || detail::is_broad_sid(upper);  // a SID spelled out, on any platform
    std::string what = entry;
#ifdef _WIN32
    if (!broad) {
        try {
            std::string sid = detail::resolve_principal_sid(entry);
            if (detail::is_broad_sid(sid)) {
                broad = true;
                if (sid != entry) what = entry + " (" + sid + ")";
            }
        } catch (const std::exception&) {  // unresolvable here: the install / the pipe rejects it on its own terms
        }
    }
#else
    if (!broad) {
        if (entry == "gid:100") {
            broad = true;
        } else if (entry.size() > 1 && entry[0] == '@') {
            struct group gr{}, *res = nullptr;
            char buf[4096];
            if (::getgrnam_r(entry.c_str() + 1, &gr, buf, sizeof buf, &res) == 0 && res && gr.gr_gid == 100) broad = true;
        }
    }
#endif
    if (!broad) return {};
    return "'" + what + "' is a broad group: granting it write access to the service configuration gives every local " +
           "user a way to escalate to the service's privileges";
}

std::string validate_install_inputs(const std::string& exe, const std::string& config_path,
                                    const std::vector<std::string>& trust_writers,
                                    const std::vector<std::string>& control_allow, const std::string& run_as) {
    if (exe.empty()) return "cannot determine the path of the mysync executable";
    std::string why = untrusted_executable_reason(exe);
    if (!why.empty()) return "refusing to install: the mysync program is not trustworthy: " + why;
    for (const auto* list : {&trust_writers, &control_allow})
        for (const auto& e : *list) {
            std::string r = broad_principal_reason(e);
            if (!r.empty()) return "refusing to install: " + r;
        }
    // Who may edit the configuration, as the SERVICE will judge it: built-ins, the named entries and its own account.
    // The installing administrator counts only when named (include_self=false).
    std::vector<std::string> trusted = trust_writers;
    trusted.insert(trusted.end(), control_allow.begin(), control_allow.end());
    if (!run_as.empty()) trusted.push_back(run_as);
    try {
        require_trusted_config(config_path, trusted, /*include_self=*/false);
    } catch (const Error& e) {
        return e.what();
    }
    return {};
}

}  // namespace mysync::gui
