// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/linkcheck.h"

#include <cerrno>
#include <filesystem>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace mysync {

namespace {

enum class St { Missing, Plain, Link, Unknown };

struct Info {
    St st = St::Missing;
    bool system_owned = false;   // a link created by root / the system / an administrator (a user cannot plant one)
};

Info examine(const fs::path& p) {
    Info r;
#ifdef _WIN32
    HANDLE h = CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        // Only "it is not there" ends the walk; anything else (access denied, bad name ...) is a doubt, and a doubt refuses.
        r.st = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? St::Missing : St::Unknown;
        return r;
    }
    FILE_ATTRIBUTE_TAG_INFO ti{};
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ti, sizeof ti)) {
        CloseHandle(h);
        r.st = St::Unknown;
        return r;
    }
    bool link = (ti.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                (ti.ReparseTag == IO_REPARSE_TAG_SYMLINK || ti.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT);   // not OneDrive & co.
    r.st = link ? St::Link : St::Plain;
    if (link) {
        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &psd) == ERROR_SUCCESS && owner) {
            LPWSTR s = nullptr;
            if (ConvertSidToStringSidW(owner, &s)) {
                std::wstring sid(s);
                LocalFree(s);
                r.system_owned = sid == L"S-1-5-18" || sid == L"S-1-5-32-544" ||
                                 sid == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
            }
            LocalFree(psd);
        }
    }
    CloseHandle(h);
#else
    struct stat st{};
    if (::lstat(p.c_str(), &st) != 0) {
        r.st = (errno == ENOENT || errno == ENOTDIR) ? St::Missing : St::Unknown;
        return r;
    }
    if (S_ISLNK(st.st_mode)) {
        r.st = St::Link;
        r.system_owned = st.st_uid == 0;
    } else {
        r.st = St::Plain;
    }
#endif
    return r;
}

bool is_unc_root(const fs::path& p) {
#ifdef _WIN32
    std::string g = p.u8string();
    if (g.size() < 3 || !((g[0] == '\\' || g[0] == '/') && (g[1] == '\\' || g[1] == '/')) || g[2] == '?' || g[2] == '.') return false;
    size_t seps = 0;
    for (size_t i = 2; i < g.size(); ++i)
        if (g[i] == '\\' || g[i] == '/') ++seps;
    return seps <= 1;   // \\server or \\server\share: not examined (they are not folders of this machine)
#else
    (void)p;
    return false;
#endif
}

}  // namespace

std::string link_component(const std::string& utf8_path) {
    fs::path full = fs::u8path(utf8_path);
    std::vector<fs::path> parts;
    for (const auto& p : full)
        if (!p.empty()) parts.push_back(p);   // a trailing separator is not a component (and would make lstat follow the link)
    fs::path cur;
    for (size_t i = 0; i < parts.size(); ++i) {
        cur /= parts[i];
        if (cur.empty() || cur == cur.root_path()) continue;
#ifdef _WIN32
        if (cur.root_name() == cur) continue;   // "C:" or "\\server" alone
#endif
        if (is_unc_root(cur)) continue;
        Info in = examine(cur);
        if (in.st == St::Missing) break;        // the rest does not exist yet
        if (in.st == St::Unknown) return cur.u8string();   // cannot be examined: refused
        if (in.st == St::Link) {
            // A link made by root / the system / an administrator in the ANCESTORS of the root (/home -> /var/home, a
            // system junction) is part of how the machine is laid out. A link anybody else could have planted, and the root
            // folder itself, never pass.
            bool last = i + 1 == parts.size();
            if (in.system_owned && !last) continue;
            return cur.u8string();
        }
    }
    return {};
}

std::string link_refusal_text(const std::string& utf8_path) {
    std::string l = link_component(utf8_path);
    if (l.empty()) return {};
    return "'" + l + "' is a link (symbolic link or junction) or cannot be examined; links are not followed, so this folder is refused";
}

}  // namespace mysync
