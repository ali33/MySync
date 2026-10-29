// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// Helpers shared by the tests/test_gui_*.cpp files.
#include <filesystem>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <vector>
#else
#include <sys/stat.h>
#endif

namespace guitest {

// Lets every user write to `path` (a file or a folder): chmod o+w on POSIX, an Everyone allow-ACE on Windows.
// Returns false if it could not be done.
inline bool make_world_writable(const std::filesystem::path& path) {
#ifdef _WIN32
    std::wstring wp = path.wstring();
    PACL old = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(wp.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old, nullptr, &sd) != ERROR_SUCCESS)
        return false;
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone = nullptr;
    AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone);
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = FILE_GENERIC_WRITE | DELETE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(everyone);
    PACL ndacl = nullptr;
    bool ok = SetEntriesInAclW(1, &ea, old, &ndacl) == ERROR_SUCCESS &&
              SetNamedSecurityInfoW(const_cast<LPWSTR>(wp.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, ndacl, nullptr) == ERROR_SUCCESS;
    if (ndacl) LocalFree(ndacl);
    if (everyone) FreeSid(everyone);
    LocalFree(sd);
    return ok;
#else
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return false;
    return ::chmod(path.c_str(), (st.st_mode & 07777) | 0002) == 0;
#endif
}


// Gives a folder a protected DACL (inherited by what is created inside): SYSTEM, Administrators and the current user
// only. The default permissions of a user profile can include other accounts, which the trust whitelist rightly rejects.
inline void make_private_dir(const std::filesystem::path& dir) {
#ifdef _WIN32
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return;
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::vector<unsigned char> buf(len ? len : 1);
    bool ok = len && GetTokenInformation(tok, TokenUser, buf.data(), len, &len);
    CloseHandle(tok);
    if (!ok) return;
    LPWSTR sidw = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &sidw)) return;
    std::wstring sddl = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + std::wstring(sidw) + L")";
    LocalFree(sidw);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return;
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present) {
        std::wstring wp = dir.wstring();
        SetNamedSecurityInfoW(const_cast<LPWSTR>(wp.c_str()), SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    }
    LocalFree(sd);
#else
    (void)dir;
#endif
}

}  // namespace guitest
