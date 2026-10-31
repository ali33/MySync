// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/restricted.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "mysync/simple/service_account.h"
#include "mysync/util.h"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#endif

namespace mysync::simple {

namespace {

bool starts_with(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

unsigned long last_rid(const std::string& sid) {
    size_t d = sid.find_last_of('-');
    if (d == std::string::npos || d + 1 >= sid.size()) return 0;
    return std::strtoul(sid.c_str() + d + 1, nullptr, 10);
}

}  // namespace

bool is_dangerous_group_sid(const std::string& sid) {
    static const char* const builtin[] = {
        "S-1-5-32-544",   // Administrators
        "S-1-5-32-547",   // Power Users
        "S-1-5-32-548",   // Account Operators
        "S-1-5-32-549",   // Server Operators
        "S-1-5-32-550",   // Print Operators
        "S-1-5-32-551",   // Backup Operators
        "S-1-5-32-552",   // Replicator
        "S-1-5-32-556",   // Network Configuration Operators
        "S-1-5-32-569",   // Cryptographic Operators
        "S-1-5-32-562",   // Distributed COM Users
        "S-1-5-32-573",   // Event Log Readers
        "S-1-5-32-574",   // Certificate Service DCOM Access
        "S-1-5-32-578",   // Hyper-V Administrators
        "S-1-5-32-580",   // Remote Management Users
        "S-1-5-32-582",   // Storage Replica Administrators
        "S-1-5-32-583",   // Device Owners
        "S-1-5-114",      // Local account and member of Administrators group
    };
    for (const char* b : builtin)
        if (sid == b) return true;
    if (starts_with(sid, "S-1-5-21-")) {
        unsigned long rid = last_rid(sid);
        // Cert Publishers 517, Domain / Schema / Enterprise admins 512 / 518 / 519, Policy creators 520, Key Admins 526 / 527
        if (rid == 512 || rid == 517 || rid == 518 || rid == 519 || rid == 520 || rid == 526 || rid == 527) return true;
    }
    return false;
}

bool is_strong_privilege(const std::string& name) {
    static const char* const strong[] = {"SeDebugPrivilege",   "SeTcbPrivilege",           "SeLoadDriverPrivilege", "SeBackupPrivilege",
                                         "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeCreateTokenPrivilege", "SeSecurityPrivilege"};
    for (const char* s : strong)
        if (name == s) return true;
    return false;
}

std::string network_token_problem(const TokenReport& r) {
    const std::string way =
        " Use an ordinary Windows account to run the service, or turn on \"Start by itself when I sign in\" (no elevated rights needed).";
    if (!r.readable) return "The network sign-in of this account could not be examined, so the service is not set up." + way;
    const std::string intro =
        "The synchronisation engine shares the account's logon session, so it can sign in again over the network (for example to the "
        "local administrative shares) and that sign-in is NOT restricted like the engine's own token. For this account it still has ";
    for (const auto& g : r.groups)
        if (is_dangerous_group_sid(g.sid) && !(g.attributes & kSeGroupDenyOnly)) return intro + "the group " + g.sid + " switched on." + way;
    for (const auto& p : r.privileges)
        if (is_strong_privilege(p)) return intro + "the privilege " + p + "." + way;
    return {};
}

bool is_allowed_group_sid(const std::string& sid, const std::string& user_sid) {
    if (!user_sid.empty() && sid == user_sid) return true;
    // The logon SID of the session (S-1-5-5-x-y) guards the window station and desktop; with it deny-only the first DLL that
    // touches user32 fails to initialise (STATUS_DLL_INIT_FAILED). It names only this user's own logon session.
    if (sid.rfind("S-1-5-5-", 0) == 0) return true;
    static const char* const ok[] = {"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", "S-1-2-0", "S-1-2-1", "S-1-5-15", "S-1-5-113"};
    for (const char* s : ok)
        if (sid == s) return true;
    return false;
}

std::string restricted_token_problem(const TokenReport& r) {
    if (!r.readable) return "the token could not be read completely";
    if (r.user_sid.empty()) return "the account of the token is unknown";
    for (const auto& g : r.groups) {
        if (g.attributes & 0x20) continue;   // SE_GROUP_INTEGRITY: the mandatory label, not a group
        if (is_allowed_group_sid(g.sid, r.user_sid) || (g.attributes & kSeGroupDenyOnly)) continue;
        return "the group " + g.sid + " is still usable (only the user and a short list of everyday groups may stay; every other group must be deny-only)";
    }
    for (const auto& p : r.privileges)
        if (p != "SeChangeNotifyPrivilege") return "the privilege " + p + " is still in the token";
    if (r.integrity_rid == 0) return "the integrity level of the token is unknown";
    if (r.integrity_rid > kIntegrityMedium) return "the integrity level is above Medium";
    return {};
}

std::string describe_token(const TokenReport& r) {
    size_t deny = 0;
    for (const auto& g : r.groups)
        if (!(g.attributes & 0x20) && !is_allowed_group_sid(g.sid, r.user_sid) && (g.attributes & kSeGroupDenyOnly)) ++deny;
    const char* lvl = r.integrity_rid == kIntegrityMedium ? "medium" : r.integrity_rid < kIntegrityMedium ? "low" : "high";
    return "service token: restricted and verified (" + std::to_string(deny) + " group(s) deny-only, " +
           std::to_string(r.privileges.size()) + " privilege(s), " + lvl + " integrity)";
}

std::vector<std::string> build_engine_env(const std::string& system_root, const std::string& temp_dir, const std::string& userprofile,
                                          const std::string& appdata, const std::string& localappdata,
                                          const std::vector<std::string>& extra) {
    std::vector<std::string> v;
    auto add = [&](const char* n, const std::string& val) {
        if (!val.empty()) v.push_back(std::string(n) + "=" + val);
    };
    add("APPDATA", appdata);
    add("LOCALAPPDATA", localappdata);
    add("PATH", system_root.empty() ? std::string() : system_root + "\\system32;" + system_root);
    add("SystemRoot", system_root);
    add("TEMP", temp_dir);
    add("TMP", temp_dir);
    add("USERPROFILE", userprofile);
    add("windir", system_root);
    for (const auto& e : extra)
        if (e.find('=') != std::string::npos && e.back() != '=') v.push_back(e);
    return v;
}

std::string frame_refusal_text(int code) {
    switch (code) {
        case kFrameTokenNotBuilt:
            return "The service could not build the restricted token for the synchronisation engine, so it does not run it. "
                   "Details are in the MySync log of the service.";
        case kFrameTokenRejected:
            return "The restricted token of the synchronisation engine did not pass the service's own check (it still had "
                   "administrator groups or dangerous privileges), so the engine was not started. Details are in the MySync "
                   "log of the service.";
        case kFrameExposed:
            return "This account is now an administrator whose network logons Windows does not restrict (the built-in Administrator, a "
                   "domain administrator, or remote UAC filtering is turned off), so the service does not run the engine. Use an "
                   "ordinary Windows account for the service.";
        case kFrameCannotStart:
            return "The service could not start the synchronisation engine. Details are in the MySync log of the service.";
        default:
            return {};
    }
}

#ifdef _WIN32
namespace {

struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE x) : h(x) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    HANDLE release() {
        HANDLE x = h;
        h = nullptr;
        return x;
    }
};

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string narrow(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], n, nullptr, nullptr);
    return out;
}

std::string sid_text(PSID sid) {
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid, &s)) return {};
    std::string out = narrow(s);
    LocalFree(s);
    return out;
}

std::vector<unsigned char> token_info(HANDLE tok, TOKEN_INFORMATION_CLASS cls) {
    DWORD n = 0;
    GetTokenInformation(tok, cls, nullptr, 0, &n);
    std::vector<unsigned char> buf(n ? n : 1);
    if (!n || !GetTokenInformation(tok, cls, buf.data(), n, &n)) buf.clear();
    return buf;
}

// CommandLineToArgvW-compatible quoting.
std::wstring quote_arg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
    std::wstring q = L"\"";
    size_t bs = 0;
    for (wchar_t c : a) {
        if (c == L'\\') {
            ++bs;
            continue;
        }
        if (c == L'"') {
            q.append(bs * 2 + 1, L'\\');
            q.push_back(L'"');
        } else {
            q.append(bs, L'\\');
            q.push_back(c);
        }
        bs = 0;
    }
    q.append(bs * 2, L'\\');
    q.push_back(L'"');
    return q;
}

}  // namespace

TokenReport read_token_report(void* token) {
    TokenReport r;
    HANDLE tok = static_cast<HANDLE>(token);
    std::vector<unsigned char> ub = token_info(tok, TokenUser);
    if (ub.empty()) return r;
    r.user_sid = sid_text(reinterpret_cast<TOKEN_USER*>(ub.data())->User.Sid);
    std::vector<unsigned char> gb = token_info(tok, TokenGroups);
    if (gb.empty()) return r;
    auto* g = reinterpret_cast<TOKEN_GROUPS*>(gb.data());
    for (DWORD i = 0; i < g->GroupCount; ++i) {
        std::string s = sid_text(g->Groups[i].Sid);
        if (s.empty()) return TokenReport{};
        r.groups.push_back({s, g->Groups[i].Attributes});
    }
    std::vector<unsigned char> pb = token_info(tok, TokenPrivileges);
    if (pb.empty()) return TokenReport{};
    auto* p = reinterpret_cast<TOKEN_PRIVILEGES*>(pb.data());
    for (DWORD i = 0; i < p->PrivilegeCount; ++i) {
        wchar_t name[128];
        DWORD len = 128;
        if (!LookupPrivilegeNameW(nullptr, &p->Privileges[i].Luid, name, &len)) return TokenReport{};
        r.privileges.push_back(narrow(name));
    }
    std::vector<unsigned char> ib = token_info(tok, TokenIntegrityLevel);
    if (ib.empty()) return TokenReport{};
    auto* ml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ib.data());
    UCHAR cnt = *GetSidSubAuthorityCount(ml->Label.Sid);
    r.integrity_rid = cnt ? *GetSidSubAuthority(ml->Label.Sid, cnt - 1) : 0;
    r.readable = true;
    return r;
}

void* make_restricted_token(std::string* err, void* base) {
    auto fail = [&](const std::string& m) -> void* {
        if (err) *err = m;
        return nullptr;
    };
    Handle own;
    HANDLE src = static_cast<HANDLE>(base);
    if (!src) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &own.h))
            return fail("cannot open the token of this process (error " + std::to_string(GetLastError()) + ")");
        src = own.h;
    }
    std::vector<unsigned char> gb = token_info(src, TokenGroups);
    std::vector<unsigned char> pb = token_info(src, TokenPrivileges);
    std::vector<unsigned char> ub = token_info(src, TokenUser);
    if (gb.empty() || pb.empty() || ub.empty()) return fail("cannot read the groups / privileges / user of the token");
    auto* g = reinterpret_cast<TOKEN_GROUPS*>(gb.data());
    auto* p = reinterpret_cast<TOKEN_PRIVILEGES*>(pb.data());
    auto* u = reinterpret_cast<TOKEN_USER*>(ub.data());

    std::vector<SID_AND_ATTRIBUTES> disable;
    const std::string me = sid_text(u->User.Sid);
    for (DWORD i = 0; i < g->GroupCount; ++i) {
        if (g->Groups[i].Attributes & SE_GROUP_INTEGRITY) continue;   // the label is not a group
        if (!is_allowed_group_sid(sid_text(g->Groups[i].Sid), me)) disable.push_back({g->Groups[i].Sid, 0});
    }
    std::vector<LUID_AND_ATTRIBUTES> del;
    for (DWORD i = 0; i < p->PrivilegeCount; ++i) {
        wchar_t name[128];
        DWORD len = 128;
        if (!LookupPrivilegeNameW(nullptr, &p->Privileges[i].Luid, name, &len)) return fail("cannot name a privilege of the token");
        if (std::wcscmp(name, L"SeChangeNotifyPrivilege") != 0) del.push_back({p->Privileges[i].Luid, 0});
    }
    HANDLE out = nullptr;
    if (!CreateRestrictedToken(src, DISABLE_MAX_PRIVILEGE, static_cast<DWORD>(disable.size()), disable.empty() ? nullptr : disable.data(),
                               static_cast<DWORD>(del.size()), del.empty() ? nullptr : del.data(), 0, nullptr, &out))
        return fail("CreateRestrictedToken failed (error " + std::to_string(GetLastError()) + ")");
    Handle rt(out);

    // Medium integrity.
    SID_IDENTIFIER_AUTHORITY mand = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID medium = nullptr;
    if (!AllocateAndInitializeSid(&mand, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &medium))
        return fail("cannot build the Medium integrity SID");
    TOKEN_MANDATORY_LABEL tml{};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = medium;
    BOOL ok = SetTokenInformation(rt.h, TokenIntegrityLevel, &tml, sizeof tml + GetLengthSid(medium));
    DWORD e1 = GetLastError();
    FreeSid(medium);
    if (!ok) return fail("cannot lower the integrity level of the token (error " + std::to_string(e1) + ")");

    // Owner and default DACL: the user (and SYSTEM) - not the Administrators group, which is deny-only now.
    TOKEN_OWNER owner{u->User.Sid};
    if (!SetTokenInformation(rt.h, TokenOwner, &owner, sizeof owner)) return fail("cannot set the owner of the token (error " + std::to_string(GetLastError()) + ")");
    std::wstring sddl = L"D:(A;;GA;;;" + widen(sid_text(u->User.Sid)) + L")(A;;GA;;;SY)";
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr))
        return fail("cannot build the default permissions of the token");
    BOOL present = FALSE, dflt = FALSE;
    PACL dacl = nullptr;
    bool dok = GetSecurityDescriptorDacl(psd, &present, &dacl, &dflt) && present;
    TOKEN_DEFAULT_DACL td{dacl};
    bool sok = dok && SetTokenInformation(rt.h, TokenDefaultDacl, &td, sizeof td);
    DWORD e2 = GetLastError();
    LocalFree(psd);
    if (!sok) return fail("cannot set the default permissions of the token (error " + std::to_string(e2) + ")");
    return rt.release();
}

struct RestrictedChild::Impl {
    HANDLE process = nullptr;
    HANDLE job = nullptr;
    HANDLE stdin_write = nullptr;
    DWORD pid = 0;
    ~Impl() {
        if (stdin_write) CloseHandle(stdin_write);
        if (job) CloseHandle(job);   // KILL_ON_JOB_CLOSE: the engine dies with its job
        if (process) CloseHandle(process);
    }
};

RestrictedChild::~RestrictedChild() = default;
unsigned long RestrictedChild::pid() const { return p_ ? p_->pid : 0; }

bool RestrictedChild::wait(int timeout_ms, unsigned long* exit_code) {
    if (!p_ || !p_->process) return true;
    DWORD w = WaitForSingleObject(p_->process, static_cast<DWORD>(std::max(0, timeout_ms)));
    if (w != WAIT_OBJECT_0) return false;
    DWORD c = 0;
    GetExitCodeProcess(p_->process, &c);
    if (exit_code) *exit_code = c;
    return true;
}

void RestrictedChild::request_stop() {
    if (p_ && p_->stdin_write) {
        CloseHandle(p_->stdin_write);
        p_->stdin_write = nullptr;
    }
}

void RestrictedChild::kill() {
    if (p_ && p_->process) TerminateProcess(p_->process, 1);
}

TokenReport RestrictedChild::process_token_report() const {
    if (!p_ || !p_->process) return {};
    HANDLE t = nullptr;
    if (!OpenProcessToken(p_->process, TOKEN_QUERY, &t)) return {};
    Handle ht(t);
    return read_token_report(t);
}

std::unique_ptr<RestrictedChild> RestrictedChild::start(const std::string& exe, const std::vector<std::string>& args,
                                                        const std::string& workdir, std::string* err, std::string* token_note,
                                                        const std::string& temp_dir) {
    auto fail = [&](const std::string& m) -> std::unique_ptr<RestrictedChild> {
        if (err) *err = m;
        return nullptr;
    };
    std::string terr;
    Handle token(static_cast<HANDLE>(make_restricted_token(&terr)));
    if (!token.h) return fail("TOKEN-BUILD: " + terr);
    TokenReport before = read_token_report(token.h);
    std::string problem = restricted_token_problem(before);
    if (!problem.empty()) return fail("TOKEN-REJECTED: " + problem);
    const std::string note = describe_token(before);

    // The job: dies with the frame's handle, at most this one process, no window-station / clipboard / system-parameter access.
    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) return fail("START: cannot create the job object (error " + std::to_string(GetLastError()) + ")");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ex{};
    ex.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    ex.BasicLimitInformation.ActiveProcessLimit = 1;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_EXITWINDOWS |
                             JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                             JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &ex, sizeof ex) ||
        !SetInformationJobObject(job.h, JobObjectBasicUIRestrictions, &ui, sizeof ui))
        return fail("START: cannot set the limits of the job object (error " + std::to_string(GetLastError()) + ")");

    // stdin = a pipe the frame keeps (closing it asks the engine to stop); stdout / stderr = NUL. Only these two handles are
    // inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST): the engine gets nothing else of the frame.
    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return fail("START: cannot create the control pipe (error " + std::to_string(GetLastError()) + ")");
    Handle hrd(rd), hwr(wr);
    SetHandleInformation(hwr.h, HANDLE_FLAG_INHERIT, 0);
    Handle nul(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (nul.h == INVALID_HANDLE_VALUE) {
        nul.h = nullptr;
        return fail("START: cannot open NUL (error " + std::to_string(GetLastError()) + ")");
    }
    HANDLE inherit[2] = {hrd.h, nul.h};
    SIZE_T asz = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &asz);
    std::vector<unsigned char> abuf(asz);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(abuf.data());
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &asz)) return fail("START: cannot prepare the handle list");
    struct AttrGuard { LPPROC_THREAD_ATTRIBUTE_LIST a; ~AttrGuard() { DeleteProcThreadAttributeList(a); } } ag{attrs};
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof inherit, nullptr, nullptr))
        return fail("START: cannot restrict the inherited handles (error " + std::to_string(GetLastError()) + ")");

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = hrd.h;
    si.StartupInfo.hStdOutput = nul.h;
    si.StartupInfo.hStdError = nul.h;
    si.lpAttributeList = attrs;

    std::wstring cmd = quote_arg(widen(exe));
    for (const auto& a : args) cmd += L" " + quote_arg(widen(a));
    cmd += L" --exit-on-stdin-eof --frame-note " + quote_arg(widen(note));
    std::wstring wdir = widen(workdir);
    // A small environment of its own, not the frame's whole one.
    auto env_of = [](const char* n) {
        char b[2048];
        DWORD len = GetEnvironmentVariableA(n, b, sizeof b);
        return len > 0 && len < sizeof b ? std::string(b, len) : std::string();
    };
    // the plain machine-wide variables Windows components expect (none of them carries anything of the user's)
    std::vector<std::string> extra;
    for (const char* n : {"SystemDrive", "ProgramData", "ProgramFiles", "ALLUSERSPROFILE", "ComSpec", "PROCESSOR_ARCHITECTURE",
                          "NUMBER_OF_PROCESSORS", "OS", "PATHEXT", "USERNAME", "USERDOMAIN", "COMPUTERNAME"}) {
        std::string val = env_of(n);
        if (!val.empty()) extra.push_back(std::string(n) + "=" + val);
    }
    std::vector<std::string> envv = build_engine_env(env_of("SystemRoot"), temp_dir.empty() ? env_of("TEMP") : temp_dir, env_of("USERPROFILE"),
                                                     env_of("APPDATA"), env_of("LOCALAPPDATA"), extra);
    std::wstring envblock;
    for (const auto& e : envv) {
        envblock += widen(e);
        envblock.push_back(L'\0');
    }
    envblock.push_back(L'\0');
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessAsUserW(token.h, widen(exe).c_str(), &cmd[0], nullptr, nullptr, TRUE,
                                   CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                                   envv.empty() ? nullptr : static_cast<LPVOID>(&envblock[0]),
                                   wdir.empty() ? nullptr : wdir.c_str(), &si.StartupInfo, &pi);
    if (!ok) return fail("START: CreateProcessAsUser failed (error " + std::to_string(GetLastError()) + ")");
    Handle proc(pi.hProcess), thr(pi.hThread);
    auto kill_and_fail = [&](const std::string& m) {
        TerminateProcess(proc.h, 1);
        return fail(m);
    };
    if (!AssignProcessToJobObject(job.h, proc.h)) return kill_and_fail("START: cannot put the engine into its job (error " + std::to_string(GetLastError()) + ")");

    // Read back the token of the REAL, still suspended process and check it again before it runs a single instruction.
    std::unique_ptr<RestrictedChild> child(new RestrictedChild());
    child->p_.reset(new Impl());
    child->p_->process = proc.release();
    child->p_->job = job.release();
    child->p_->stdin_write = hwr.release();
    child->p_->pid = pi.dwProcessId;
    TokenReport after = child->process_token_report();
    std::string p2 = restricted_token_problem(after);
    if (!p2.empty()) {
        child->kill();
        if (err) *err = "TOKEN-REJECTED: the token of the started engine: " + p2;
        return nullptr;   // ~Impl closes the job
    }
    if (ResumeThread(thr.h) == static_cast<DWORD>(-1)) {
        child->kill();
        if (err) *err = "START: cannot resume the engine (error " + std::to_string(GetLastError()) + ")";
        return nullptr;
    }
    if (token_note) *token_note = describe_token(after);
    return child;
}

std::string describe_own_token() {
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return "service token: could not be examined";
    TokenReport rep = read_token_report(t);
    CloseHandle(t);
    std::string problem = restricted_token_problem(rep);
    return problem.empty() ? describe_token(rep) : "service token: NOT restricted (" + problem + ")";
}

int run_frame(const FrameParams& p, std::atomic<bool>& stop, std::string* last_error) {
    // The frame process is closed to everybody but SYSTEM and Administrators: the engine (the user, Administrators deny-only,
    // Medium integrity) cannot open it. Best effort - the integrity level already blocks writing up.
    if (p.protect_process) {
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;;;;OW)", SDDL_REVISION_1, &psd, nullptr)) {
            BOOL present = FALSE, dflt = FALSE;
            PACL dacl = nullptr;
            if (GetSecurityDescriptorDacl(psd, &present, &dacl, &dflt) && present) {
                DWORD rc = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                           nullptr, nullptr, dacl, nullptr);
                if (rc != ERROR_SUCCESS) log_warn("service frame: could not close the frame process to the engine (error " + std::to_string(rc) + ")");
            }
            LocalFree(psd);
        }
    }
    // The account may have become an administrator whose network logons are not restricted since the install: check at every start.
    {
        std::string exposed = p.exposure ? p.exposure() : account_exposure_problem_for_current_user();
        if (!exposed.empty()) {
            if (last_error) *last_error = exposed;
            log_error("service frame: " + exposed);
            return kFrameExposed;
        }
    }
    size_t step = 0;
    while (!stop) {
        std::string err, note;
        auto started = std::chrono::steady_clock::now();
        std::unique_ptr<RestrictedChild> child = RestrictedChild::start(p.exe, p.engine_args, p.workdir, &err, &note, p.temp_dir);
        if (!child) {
            if (last_error) *last_error = err;
            log_error("service frame: " + err);
            // A token that cannot be built or does not verify will not get better by retrying: fail closed, report it.
            if (err.rfind("TOKEN-BUILD:", 0) == 0) return kFrameTokenNotBuilt;
            if (err.rfind("TOKEN-REJECTED:", 0) == 0) return kFrameTokenRejected;
        } else {
            log_info("service frame: engine started (pid " + std::to_string(child->pid()) + "); " + note);
            unsigned long code = 0;
            while (!stop && !child->wait(250, &code)) {
            }
            if (stop) {
                child->request_stop();   // graceful: the engine ends when its standard input does
                if (!child->wait(15000, &code)) child->kill();
                return 0;
            }
            log_warn("service frame: the engine ended (code " + std::to_string(code) + ")");
            if (std::chrono::steady_clock::now() - started > std::chrono::seconds(60)) step = 0;
        }
        int d = p.backoff_ms.empty() ? 5000 : p.backoff_ms[std::min(step, p.backoff_ms.size() - 1)];
        if (step + 1 < p.backoff_ms.size()) ++step;
        for (int waited = 0; waited < d && !stop; waited += 100) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
#endif

}  // namespace mysync::simple
