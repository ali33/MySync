// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/user_paths.h"

#include <cstdlib>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace mysync::simple {
namespace {

#ifdef _WIN32
std::string current_sid_text() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) throw Error("cannot identify the current user");
    DWORD n = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &n);
    std::vector<unsigned char> buf(n ? n : 1);
    std::string out;
    if (GetTokenInformation(tok, TokenUser, buf.data(), n, &n)) {
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s)) {
            out = fs::path(std::wstring(s)).u8string();
            LocalFree(s);
        }
    }
    CloseHandle(tok);
    if (out.empty()) throw Error("cannot identify the current user");
    return out;
}
#endif

std::string getenv_str(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

std::string standard_dir() {
#ifdef _WIN32
    std::string base = getenv_str("APPDATA");
    if (base.empty()) {
        std::string up = getenv_str("USERPROFILE");
        if (up.empty()) throw Error("cannot find the user's application data folder (APPDATA is not set)");
        base = (fs::u8path(up) / "AppData" / "Roaming").u8string();
    }
    return (fs::u8path(base) / "MySync").u8string();
#else
    std::string x = getenv_str("XDG_CONFIG_HOME");
    if (!x.empty() && x[0] == '/') return (fs::path(x) / "mysync").string();
    std::string home = getenv_str("HOME");
    if (home.empty() || home[0] != '/') {
        struct passwd pw{}, *res = nullptr;
        char buf[4096];
        if (::getpwuid_r(::geteuid(), &pw, buf, sizeof buf, &res) == 0 && res && pw.pw_dir && pw.pw_dir[0] == '/')
            home = pw.pw_dir;
        else
            throw Error("cannot find the user's home folder");
    }
    return (fs::path(home) / ".config" / "mysync").string();
#endif
}

}  // namespace

std::string current_user_short_id() {
#ifdef _WIN32
    std::string sid = current_sid_text();
    size_t d = sid.find_last_of('-');
    return d == std::string::npos ? sid : sid.substr(d + 1);
#else
    return std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

std::string current_user_sid() {
#ifdef _WIN32
    return current_sid_text();
#else
    return {};
#endif
}

void restrict_to_current_user(const std::string& utf8_path, bool is_dir) {
    fs::path p = fs::u8path(utf8_path);
#ifdef _WIN32
    // Protected DACL (no inheritance from the parent): the current user and SYSTEM only. Administrators are NOT added.
    std::wstring sddl = L"D:P(A;" + std::wstring(is_dir ? L"OICI" : L"") + L";FA;;;" +
                        fs::u8path(current_sid_text()).wstring() + L")(A;" + std::wstring(is_dir ? L"OICI" : L"") +
                        L";FA;;;SY)";
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr))
        throw Error("cannot build the private permissions for '" + utf8_path + "'");
    BOOL present = FALSE, dflt = FALSE;
    PACL dacl = nullptr;
    DWORD rc = ERROR_INVALID_PARAMETER;
    if (GetSecurityDescriptorDacl(psd, &present, &dacl, &dflt) && present)
        rc = SetNamedSecurityInfoW(const_cast<LPWSTR>(p.c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl,
                                   nullptr);
    LocalFree(psd);
    if (rc != ERROR_SUCCESS)
        throw Error("cannot restrict '" + utf8_path + "' to the current user (error " + std::to_string(rc) + ")");
#else
    if (::chmod(p.c_str(), is_dir ? 0700 : 0600) != 0) throw Error("cannot restrict '" + utf8_path + "' to the current user");
#endif
}

UserPaths UserPaths::for_current_user(const std::string& dir_override) {
    UserPaths u;
    std::string d = dir_override.empty() ? standard_dir() : dir_override;
    fs::path base = fs::absolute(fs::u8path(d)).lexically_normal();
    while (!base.empty() && base.filename().empty() && base.has_parent_path() && base != base.root_path())
        base = base.parent_path();
    auto at = [&](const char* n) { return (base / n).u8string(); };
    u.dir = base.u8string();
    u.client_config = at("config.toml");
    u.receiver_config = at("server-user.toml");
    u.client_key = at("key");
    u.receiver_key = at("receiver.key");
    u.client_state = at("state");
    u.receiver_state = at("receiver-state");
    u.log_dir = at("log");
    u.client_log = (base / "log" / "client.log").u8string();
    u.receiver_log = (base / "log" / "receiver.log").u8string();
    u.instance_lock = at("gui.lock");
    std::string id = current_user_short_id();
    u.client_control_name = "mysync-user-" + id;
    u.receiver_control_name = "mysync-user-" + id + "-recv";
    return u;
}

void UserPaths::ensure_dirs() const {
    for (const std::string& d : {dir, client_state, receiver_state, log_dir}) {
        std::error_code ec;
        fs::path p = fs::u8path(d);
        bool existed = fs::is_directory(p, ec);
        fs::create_directories(p, ec);
        if (ec && !fs::is_directory(p)) throw Error("cannot create the folder '" + d + "': " + ec.message());
        // Tighten what we created; an existing top folder is tightened too (it is ours: <config>/MySync).
        if (!existed || d == dir) restrict_to_current_user(d, true);
    }
}

}  // namespace mysync::simple
