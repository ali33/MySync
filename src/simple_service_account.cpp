// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/service_account.h"
#include "mysync/simple/restricted.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwchar>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

#include "mysync/hash.h"
#include "mysync/simple/user_paths.h"

#ifndef _WIN32
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <ntsecapi.h>
#include <sddl.h>
#endif

namespace fs = std::filesystem;

namespace mysync::simple {

bool valid_account_name(const std::string& a) {
    if (a.empty() || a.size() > 256 || a[0] == '-') return false;
    size_t backslashes = 0;
    for (unsigned char c : a) {
        if (c < 0x20 || c == 0x7F || c == '"' || c == '\'' || c == '`' || c == '/' || c == ':' || c == '*' || c == '?' ||
            c == '<' || c == '>' || c == '|')
            return false;
        if (c == '\\') ++backslashes;
    }
    return backslashes <= 1;
}

std::string user_service_name(const std::string& account) {
    std::string n = account;
    size_t bs = n.find_last_of('\\');
    if (bs != std::string::npos) n = n.substr(bs + 1);
    size_t at = n.find('@');
    if (at != std::string::npos && at > 0) n = n.substr(0, at);
    std::string out;
    for (unsigned char c : n) {
        char l = static_cast<char>(std::tolower(c));
        if ((l >= 'a' && l <= 'z') || (l >= '0' && l <= '9') || l == '_' || l == '-') out += l;
        else if (!out.empty() && out.back() != '-') out += '-';
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    if (out.empty()) out = "user";
    if (out.size() > 48) out.resize(48);
    return "mysync-" + out;
}

std::string user_service_name(const std::string& account, const std::string& owner_id) {
    Hash256 h = hash_bytes(owner_id.data(), owner_id.size());
    return user_service_name(account) + "-" + to_hex(h.data(), 2);
}

unsigned long min_login_uid() {
#ifdef _WIN32
    return 0;
#else
    unsigned long v = 1000;
    std::ifstream f("/etc/login.defs");
    std::string line;
    while (std::getline(f, line)) {
        size_t i = line.find_first_not_of(" 	");
        if (i == std::string::npos || line.compare(i, 7, "UID_MIN") != 0) continue;
        std::istringstream is(line.substr(i + 7));
        unsigned long x = 0;
        if (is >> x && x >= 100) v = x;
    }
    return v;
#endif
}

AdminState admin_state_from_facts(const TokenFacts& f) {
    if (!f.readable || f.linked_unreadable) return AdminState::Unknown;
    if (f.in_admins || f.in_operator_group || f.powerful_privilege || f.linked_elevated) return AdminState::Yes;
    return AdminState::No;
}

bool account_is_administrator(const std::string& sid) { return account_admin_state(sid) != AdminState::No; }

std::string remote_filtering_problem(const std::string& sid, const TokenFacts& f, bool domain_account, bool filter_policy_open) {
    const std::string way =
        " Use an ordinary Windows account to run the service, or turn on \"Start by itself when I sign in\" (no elevated rights needed).";
    if (!f.readable || f.linked_unreadable)
        return "It could not be verified that Windows restricts the network logons of this account (its rights could not be read), so the "
               "service is not set up." + way;
    if (!f.in_admins && !f.in_operator_group && !f.powerful_privilege && !f.linked_elevated) return {};   // an ordinary account
    if (!f.in_admins && (f.in_operator_group || f.powerful_privilege))
        return "This account is in an operators group or holds a strong privilege (for example Backup), and Windows does not remove those "
               "from its network sign-ins, which the synchronisation engine can repeat (it shares the logon session)." + way;
    const std::string why =
        "This account is an administrator (or in an operators group) and the synchronisation engine shares its logon session: a "
        "connection it makes over the network (for example to \\\\localhost\\C$) would use the account's full credentials. Windows "
        "prevents that only through remote UAC filtering, which does not apply to ";
    if (sid.size() >= 4 && sid.compare(sid.size() - 4, 4, "-500") == 0) return why + "the built-in Administrator account." + way;
    if (domain_account) return why + "a domain account." + way;
    if (filter_policy_open)
        return why + "this computer, where remote filtering is turned off (LocalAccountTokenFilterPolicy is on, or UAC / EnableLUA is off or cannot be read)." + way;
    return {};
}

bool release_logon_right(const std::string& service_dir, const std::string& sid, const ServiceDescribe& describe) {
    std::error_code ec;
    fs::path mine = fs::u8path(service_dir);
    const std::string label = owner_label(sid);
    // Every sibling folder is a MySync service folder named like its service. A service that still EXISTS (it has a description)
    // and carries this account's label needs the right too - installed before or after the markers were invented, no file
    // of ours needed.
    for (fs::directory_iterator it(mine.parent_path(), ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_directory(ec) || it->path() == mine) continue;
        std::string d = describe(it->path().filename().u8string());
        if (d.empty() || d.find(label) == std::string::npos) continue;
        std::ofstream m(it->path() / ".logon-right-added", std::ios::binary | std::ios::trunc);   // it becomes the one that takes it away
        m << sid;
        return false;
    }
    return true;
}

std::string requester_identity_problem(const std::string& requester_sid, const std::string& logon_sid) {
    if (!valid_user_sid(requester_sid)) return "the identity of the user who asked is missing or not valid";
    if (logon_sid != requester_sid) return "the password does not belong to the user who asked";
    return {};
}

bool looks_like_user_service_name(const std::string& name) {
    if (name.size() < std::string("mysync-x-0000").size() || name.rfind("mysync-", 0) != 0) return false;
    if (name == "mysync-server" || name == "mysync-client") return false;
    if (name[name.size() - 5] != '-') return false;
    for (size_t i = name.size() - 4; i < name.size(); ++i)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
    return true;
}

bool user_service_name_matches_owner(const std::string& name, const std::string& owner_id) {
    if (owner_id.empty() || name.size() < std::string("mysync-x-0000").size() || name.rfind("mysync-", 0) != 0) return false;
    if (name == "mysync-server" || name == "mysync-client") return false;
    Hash256 h = hash_bytes(owner_id.data(), owner_id.size());
    return name.compare(name.size() - 5, 5, "-" + to_hex(h.data(), 2)) == 0;
}

std::string owner_label(const std::string& owner_id) { return "[owner " + owner_id + "]"; }

std::string explain_logon_error(unsigned long e) {
    switch (e) {
        case 1326:  // ERROR_LOGON_FAILURE
            return "The account name or the password is not correct. For a Microsoft account use the password of the account "
                   "(the one used on the web), not the Windows Hello PIN.";
        case 1327:  // ERROR_ACCOUNT_RESTRICTION
            return "Windows does not allow this account to be used by a service: an account without a password cannot run one. "
                   "Give the account a password, or choose \"only while I am logged in\".";
        case 1328:  // ERROR_INVALID_LOGON_HOURS
            return "This account is not allowed to log on at this time (logon hours).";
        case 1329:  // ERROR_INVALID_WORKSTATION
            return "This account is not allowed to log on to this computer.";
        case 1330:  // ERROR_PASSWORD_EXPIRED
        case 1907:  // ERROR_PASSWORD_MUST_CHANGE
            return "The password of this account has expired: change it in Windows first, then try again.";
        case 1331:  // ERROR_ACCOUNT_DISABLED
            return "This account is disabled.";
        case 1909:  // ERROR_ACCOUNT_LOCKED_OUT
            return "This account is locked out because of too many wrong passwords. Wait, or unlock it, and try again.";
        case 1385:  // ERROR_LOGON_TYPE_NOT_GRANTED
            return "This account is not allowed to run services on this computer (a policy forbids it).";
        case 1355:  // ERROR_NO_SUCH_DOMAIN
            return "The domain of this account cannot be reached.";
        case 1789:  // ERROR_TRUSTED_RELATIONSHIP_FAILURE
            return "The trust with the domain of this account failed.";
        default:
            return "Windows refused the logon of this account (error " + std::to_string(e) + ").";
    }
}

#ifdef _WIN32
namespace {

std::wstring widen(const std::string& s) { return fs::u8path(s).wstring(); }
std::string narrow(const std::wstring& w) { return fs::path(w).u8string(); }

struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE x) : h(x) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) CloseHandle(h);
    }
    bool ok() const { return h != INVALID_HANDLE_VALUE && h != nullptr; }
};

std::string process_user_sid_of_token(HANDLE tok) {
    DWORD n = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &n);
    std::vector<unsigned char> buf(n ? n : 1);
    if (!n || !GetTokenInformation(tok, TokenUser, buf.data(), n, &n)) return {};
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s)) return {};
    std::string out = narrow(s);
    LocalFree(s);
    return out;
}

std::string process_user_sid(HANDLE process) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &tok)) return {};
    Handle ht(tok);
    return process_user_sid_of_token(tok);
}

// The elevated step may run as ANOTHER account than the application it must identify, whose process token an ordinary access
// check would not let it open. An administrator's token carries SeDebugPrivilege (disabled); turning it on is only used to READ
// the user of a process, and the scope turns it OFF again (only if this scope turned it on). Best effort: if the privilege is
// absent, the lookup simply fails and says why.
struct DebugPrivilegeScope {
    HANDLE tok = nullptr;
    LUID luid{};
    bool changed = false;
    DebugPrivilegeScope() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
        TOKEN_PRIVILEGES tp{}, prev{};
        tp.PrivilegeCount = 1;
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) return;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD prev_len = 0;
        if (AdjustTokenPrivileges(tok, FALSE, &tp, sizeof prev, &prev, &prev_len) && GetLastError() == ERROR_SUCCESS)
            changed = prev.PrivilegeCount > 0 && !(prev.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED);   // it was off: we turned it on
    }
    ~DebugPrivilegeScope() {
        if (tok && changed) {
            TOKEN_PRIVILEGES off{};
            off.PrivilegeCount = 1;
            off.Privileges[0].Luid = luid;
            off.Privileges[0].Attributes = 0;
            AdjustTokenPrivileges(tok, FALSE, &off, 0, nullptr, nullptr);
        }
        if (tok) CloseHandle(tok);
    }
};

std::string pid_user_sid(DWORD pid, DWORD* error = nullptr) {
    if (error) *error = 0;
    std::unique_ptr<DebugPrivilegeScope> debug;   // created on first need, undone when this function returns
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p && GetLastError() == ERROR_ACCESS_DENIED) {
        debug.reset(new DebugPrivilegeScope());
        p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!p) {
        if (error) *error = GetLastError();
        return {};
    }
    Handle hp(p);
    std::string s = process_user_sid(p);
    if (s.empty()) {
        if (error) *error = GetLastError();
        if (!debug) debug.reset(new DebugPrivilegeScope());
        s = process_user_sid(p);
        if (!s.empty() && error) *error = 0;
    }
    return s;
}

// Overlapped I/O with a hard deadline.
bool overlapped_wait(HANDLE pipe, OVERLAPPED& ov, int timeout_ms, DWORD* got) {
    DWORD r = WaitForSingleObject(ov.hEvent, static_cast<DWORD>(timeout_ms < 0 ? 0 : timeout_ms));
    if (r != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        DWORD ignore = 0;
        GetOverlappedResult(pipe, &ov, &ignore, TRUE);
        return false;
    }
    return GetOverlappedResult(pipe, &ov, got, FALSE) != 0;
}

bool read_exact(HANDLE pipe, void* buf, DWORD n, int timeout_ms) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    DWORD got = 0;
    char* p = static_cast<char*>(buf);
    while (got < n) {
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        Handle he(ov.hEvent);
        DWORD part = 0;
        BOOL ok = ReadFile(pipe, p + got, n - got, &part, &ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
        if (!ok) {
            int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count());
            if (!overlapped_wait(pipe, ov, left, &part)) return false;
        }
        if (part == 0) return false;
        got += part;
    }
    return true;
}

bool write_all(HANDLE pipe, const void* buf, DWORD n, int timeout_ms) {
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Handle he(ov.hEvent);
    DWORD done = 0;
    BOOL ok = WriteFile(pipe, buf, n, &done, &ov);
    if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
    if (!ok && !overlapped_wait(pipe, ov, timeout_ms, &done)) return false;
    return done == n;
}

}  // namespace

struct PasswordChannel::Impl {
    std::string name, nonce_hex;
    Bytes nonce;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    bool used = false;
    std::atomic<unsigned long> expect_pid{0};
    HANDLE cancel_ev = nullptr;
    ~Impl() {
        if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
        if (cancel_ev) CloseHandle(cancel_ev);
    }
};

PasswordChannel::PasswordChannel() : p_(new Impl) {}
PasswordChannel::~PasswordChannel() = default;
const std::string& PasswordChannel::pipe_name() const { return p_->name; }
const std::string& PasswordChannel::nonce_hex() const { return p_->nonce_hex; }

std::unique_ptr<PasswordChannel> PasswordChannel::create() {
    std::unique_ptr<PasswordChannel> c(new PasswordChannel());
    uint8_t r[8];
    random_bytes(r, sizeof r);
    c->p_->name = "mysync-pw-" + to_hex(r, sizeof r);
    c->p_->nonce.resize(16);
    random_bytes(c->p_->nonce.data(), c->p_->nonce.size());
    c->p_->nonce_hex = to_hex(c->p_->nonce.data(), c->p_->nonce.size());
    std::wstring sddl = L"D:P(A;;GA;;;" + widen(current_user_sid()) + L")(A;;GA;;;SY)(A;;GA;;;BA)";   // this user (the requester); an administrator who approved the UAC prompt may be another account, recognised by PID + nonce
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr))
        throw Error("cannot build the permissions of the private channel");
    std::wstring path = L"\\\\.\\pipe\\" + widen(c->p_->name);
    HANDLE h = CreateNamedPipeW(path.c_str(),
                                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &sa);
    DWORD e = GetLastError();
    LocalFree(sa.lpSecurityDescriptor);
    if (h == INVALID_HANDLE_VALUE) throw Error("cannot create the private channel (error " + std::to_string(e) + ")");
    c->p_->pipe = h;
    c->p_->cancel_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    return c;
}

void PasswordChannel::expect_client_pid(unsigned long pid) { p_->expect_pid = pid; }

void PasswordChannel::cancel() {
    if (p_->cancel_ev) SetEvent(p_->cancel_ev);
}

bool PasswordChannel::deliver(const SecretString& password, int timeout_ms, std::string* error) {
    auto fail = [&](const std::string& m) {
        if (error) *error = m;
        return false;
    };
    Impl& im = *p_;
    if (im.used || im.pipe == INVALID_HANDLE_VALUE) return fail("the private channel was already used");
    if (password.empty() || password.size() > 1000) return fail("the password has an unusable length");
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (int attempt = 0; attempt < 4; ++attempt) {
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        Handle he(ov.hEvent);
        BOOL ok = ConnectNamedPipe(im.pipe, &ov);
        DWORD le = GetLastError();
        if (!ok && le == ERROR_IO_PENDING) {
            int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count());
            DWORD ignore = 0;
            HANDLE evs[2] = {ov.hEvent, im.cancel_ev};
            DWORD w = left <= 0 ? WAIT_TIMEOUT : WaitForMultipleObjects(im.cancel_ev ? 2 : 1, evs, FALSE, static_cast<DWORD>(left));
            if (w != WAIT_OBJECT_0) {
                CancelIoEx(im.pipe, &ov);
                GetOverlappedResult(im.pipe, &ov, &ignore, TRUE);
                return fail(w == WAIT_OBJECT_0 + 1 ? "cancelled" : "the installer did not connect in time");
            }
            if (!GetOverlappedResult(im.pipe, &ov, &ignore, FALSE)) return fail("the private channel failed");
        } else if (!ok && le != ERROR_PIPE_CONNECTED) {
            return fail("the private channel failed (error " + std::to_string(le) + ")");
        }
        // who is on the other end? It must be a process of this very user.
        ULONG pid = 0;
        bool user_ok = GetNamedPipeClientProcessId(im.pipe, &pid) != 0;
        for (int w = 0; user_ok && im.expect_pid.load() == 0 && w < 50; ++w) std::this_thread::sleep_for(std::chrono::milliseconds(100));   // the caller learns the PID right after starting the process
        user_ok = user_ok && im.expect_pid.load() != 0 && pid == im.expect_pid.load();
        uint8_t got[16] = {};
        int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count());
        bool nonce_ok = false;
        if (user_ok && read_exact(im.pipe, got, 16, std::max(1, std::min(left, 10000))))
            nonce_ok = ct_equal(got, im.nonce.data(), 16);
        if (nonce_ok) {
            std::string msg;
            msg.push_back(static_cast<char>(password.size() >> 8));
            msg.push_back(static_cast<char>(password.size() & 0xFF));
            msg += password.reveal();
            left = int(std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count());
            bool sent = write_all(im.pipe, msg.data(), DWORD(msg.size()), std::max(1, std::min(left, 10000)));
            secure_wipe(&msg[0], msg.size());
            FlushFileBuffers(im.pipe);
            DisconnectNamedPipe(im.pipe);
            CloseHandle(im.pipe);   // the pipe disappears: no second client, no replay
            im.pipe = INVALID_HANDLE_VALUE;
            im.used = true;
            return sent ? true : fail("the password could not be handed over");
        }
        DisconnectNamedPipe(im.pipe);   // a stranger or a wrong nonce: dropped, then wait again (a few tries only)
    }
    CloseHandle(im.pipe);
    im.pipe = INVALID_HANDLE_VALUE;
    im.used = true;
    return fail("too many wrong attempts on the private channel");
}

bool receive_password(const std::string& pipe_name, const std::string& nonce_hex, SecretString* out, std::string* error,
                      const std::string& requester_sid) {
    auto fail = [&](const std::string& m) {
        if (error) *error = m;
        return false;
    };
    Bytes nonce;
    try {
        nonce = from_hex(nonce_hex);
    } catch (const std::exception&) {
        return fail("the channel code is not valid");
    }
    if (nonce.size() != 16 || pipe_name.rfind("mysync-pw-", 0) != 0 || pipe_name.size() > 64) return fail("the channel name is not valid");
    for (char c : pipe_name)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-')) return fail("the channel name is not valid");
    std::wstring path = L"\\\\.\\pipe\\" + widen(pipe_name);
    HANDLE h = INVALID_HANDLE_VALUE;
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    for (;;) {
        h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD e = GetLastError();
        if ((e != ERROR_PIPE_BUSY && e != ERROR_FILE_NOT_FOUND) || std::chrono::steady_clock::now() > end)
            return fail("cannot reach the private channel (error " + std::to_string(e) + ")");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    Handle hh(h);
    ULONG spid = 0;
    if (!requester_sid.empty() && !valid_user_sid(requester_sid)) return fail("the requester identity is not valid");
    const std::string want_sid = requester_sid.empty() ? current_user_sid() : requester_sid;
    DWORD sid_err = 0;
    if (!GetNamedPipeServerProcessId(h, &spid)) return fail("cannot tell which program is on the other end of the private channel: refusing to send anything");
    std::string server_sid = pid_user_sid(spid, &sid_err);
    if (server_sid.empty())
        return fail("cannot read the account of the program on the other end of the private channel (error " + std::to_string(sid_err) +
                    "): refusing to send anything");
    if (server_sid != want_sid)
        return fail("the other end of the private channel is not the application of this user: refusing to send anything");
    if (!write_all(h, nonce.data(), 16, 10000)) return fail("the private channel closed");
    uint8_t len[2];
    if (!read_exact(h, len, 2, 10000)) return fail("the application did not send the password (wrong code?)");
    size_t n = (size_t(len[0]) << 8) | len[1];
    if (n == 0 || n > 1000) return fail("the channel sent something unexpected");
    std::string buf(n, '\0');
    if (!read_exact(h, &buf[0], DWORD(n), 10000)) {
        secure_wipe(&buf[0], buf.size());
        return fail("the password was not received completely");
    }
    out->assign(buf.data(), buf.size());
    secure_wipe(&buf[0], buf.size());
    return true;
}

AdminState admin_state_of_token(HANDLE tok);

std::string exposure_problem_of_token(HANDLE tok, const std::string& sid, bool measured_network_token);

AccountCheck check_service_account(const std::string& account, const SecretString& password) {
    AccountCheck r;
    if (!valid_account_name(account)) {
        r.error = "The account name is not valid.";
        return r;
    }
    if (password.empty()) {
        r.error = explain_logon_error(1327);
        return r;
    }
    // split DOMAIN\user, user@upn, plain user ("." = this computer)
    std::wstring w = widen(account), user, domain;
    size_t bs = w.find(L'\\');
    if (bs != std::wstring::npos) {
        domain = w.substr(0, bs);
        user = w.substr(bs + 1);
    } else {
        user = w;
    }
    if (domain.empty() && user.find(L'@') == std::wstring::npos) domain = L".";
    HANDLE tok = nullptr;
    // converted straight into the wide buffer that is wiped below (fs::u8path() would leave an unwiped temporary copy)
    std::wstring wp;
    {
        const std::string& pw = password.reveal();
        int n = pw.empty() ? 0 : MultiByteToWideChar(CP_UTF8, 0, pw.data(), static_cast<int>(pw.size()), nullptr, 0);
        wp.assign(static_cast<size_t>(n), L'\0');
        if (n) MultiByteToWideChar(CP_UTF8, 0, pw.data(), static_cast<int>(pw.size()), &wp[0], n);
    }
    BOOL ok = LogonUserW(user.c_str(), user.find(L'@') != std::wstring::npos && domain.empty() ? nullptr : domain.c_str(),
                         wp.c_str(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &tok);
    DWORD e = GetLastError();
    SecureZeroMemory(&wp[0], wp.size() * sizeof(wchar_t));
    if (!ok) {
        r.error = explain_logon_error(e);
        return r;
    }
    Handle ht(tok);
    r.admin = admin_state_of_token(tok);   // the NEW token of the target account, not this process's
    r.sid = process_user_sid_of_token(tok);
    if (r.sid.empty()) {
        // fall back to the name lookup
        DWORD sn = 0, dn = 0;
        SID_NAME_USE use;
        std::wstring full = (bs != std::wstring::npos && domain != L".") ? w : (domain == L"." ? user : w);
        LookupAccountNameW(nullptr, full.c_str(), nullptr, &sn, nullptr, &dn, &use);
        std::vector<unsigned char> sid(sn ? sn : 1);
        std::wstring dom(dn ? dn : 1, L'\0');
        if (sn && LookupAccountNameW(nullptr, full.c_str(), sid.data(), &sn, &dom[0], &dn, &use)) {
            LPWSTR s = nullptr;
            if (ConvertSidToStringSidW(sid.data(), &s)) {
                r.sid = narrow(s);
                LocalFree(s);
            }
        }
    }
    if (r.sid.empty()) {
        r.error = "The account was accepted but its identity could not be determined.";
        return r;
    }
    r.exposure_problem = exposure_problem_of_token(tok, r.sid, /*measured_network_token=*/true);
    r.ok = true;
    return r;
}

std::string current_account_name() {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(widen(current_user_sid()).c_str(), &sid)) return {};
    struct Free { PSID p; ~Free() { LocalFree(p); } } fr{sid};
    wchar_t name[256] = {}, dom[256] = {};
    DWORD nn = 256, dn = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, sid, name, &nn, dom, &dn, &use)) return {};
    return narrow(std::wstring(dom, dn) + L"\\" + std::wstring(name, nn));
}

std::string account_sid(const std::string& account) {
    std::wstring full = widen(account);
    if (full.compare(0, 2, L".\\") == 0) full = full.substr(2);
    DWORD sn = 0, dn = 0;
    SID_NAME_USE use;
    LookupAccountNameW(nullptr, full.c_str(), nullptr, &sn, nullptr, &dn, &use);
    if (!sn) return {};
    std::vector<unsigned char> sid(sn);
    std::wstring dom(dn ? dn : 1, L'\0');
    if (!LookupAccountNameW(nullptr, full.c_str(), sid.data(), &sn, &dom[0], &dn, &use)) return {};
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &s)) return {};
    std::string out = narrow(s);
    LocalFree(s);
    return out;
}

std::string primary_group_of_user(const std::string&) { return {}; }

std::string current_owner_id() { return effective_user_sid(); }

// What the token tells about the account's power. EVERYTHING that cannot be read counts against the account (fail closed).
TokenFacts read_token_facts(HANDLE tok) {
    TokenFacts f;
    // ONE list of dangerous groups and strong privileges (restricted.cpp) serves the restricted token, this and the network
    // measurement. The groups count in ANY state (enabled, disabled, deny-only: a filtered token still carries them).
    TokenReport rep = read_token_report(tok);
    if (!rep.readable) return f;
    for (const auto& g : rep.groups) {
        if (g.sid == "S-1-5-32-544" || (g.sid.rfind("S-1-5-21-", 0) == 0 && g.sid.size() > 4 &&
                                         (g.sid.compare(g.sid.size() - 4, 4, "-512") == 0 || g.sid.compare(g.sid.size() - 4, 4, "-519") == 0 ||
                                          g.sid.compare(g.sid.size() - 4, 4, "-518") == 0)))
            f.in_admins = true;
        else if (is_dangerous_group_sid(g.sid))
            f.in_operator_group = true;
    }
    for (const auto& p : rep.privileges)
        if (is_strong_privilege(p)) f.powerful_privilege = true;
    // The other half of a split (UAC) token: if it is elevated, or we cannot tell, the account is an administrator.
    TOKEN_LINKED_TOKEN lt{};
    DWORD got = 0;
    if (GetTokenInformation(tok, TokenLinkedToken, &lt, sizeof lt, &got)) {
        TOKEN_ELEVATION el{};
        DWORD en = 0;
        if (!GetTokenInformation(lt.LinkedToken, TokenElevation, &el, sizeof el, &en)) f.linked_unreadable = true;
        else if (el.TokenIsElevated) f.linked_elevated = true;
        CloseHandle(lt.LinkedToken);
    } else if (GetLastError() != ERROR_NO_SUCH_LOGON_SESSION) {   // 1312: no linked token (an ordinary, unsplit token)
        f.linked_unreadable = true;
    }
    f.readable = true;
    return f;
}

AdminState admin_state_of_token(HANDLE tok) { return admin_state_from_facts(read_token_facts(tok)); }

AdminState account_admin_state(const std::string& sid) {
    if (sid.empty() || sid != current_user_sid()) return AdminState::Unknown;   // cannot be judged from here
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return AdminState::Unknown;
    Handle ht(tok);
    return admin_state_of_token(tok);
}

// Domain account? (the account's domain is not this computer's name). A lookup that fails counts as a domain account.
bool account_is_domain_account(const std::string& sid) {
    PSID psid = nullptr;
    if (!ConvertStringSidToSidW(widen(sid).c_str(), &psid)) return true;
    struct Free { PSID p; ~Free() { LocalFree(p); } } fr{psid};
    DWORD nn = 0, dn = 0;
    SID_NAME_USE use;
    LookupAccountSidW(nullptr, psid, nullptr, &nn, nullptr, &dn, &use);
    if (!nn || !dn) return true;
    std::wstring name(nn, L' '), dom(dn, L' ');
    if (!LookupAccountSidW(nullptr, psid, &name[0], &nn, &dom[0], &dn, &use)) return true;
    dom.resize(wcslen(dom.c_str()));
    wchar_t comp[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cn = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(comp, &cn)) return true;
    return _wcsicmp(dom.c_str(), comp) != 0;
}

// One DWORD of HKLM\...\Policies\System. found=false when the value (or key) does not exist; false return = any other read error.
bool read_system_policy_dword(const wchar_t* name, DWORD* value, bool* found) {
    DWORD sz = sizeof *value;
    LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", name, RRF_RT_REG_DWORD,
                           nullptr, value, &sz);
    *found = rc == ERROR_SUCCESS;
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND;
}

// Does Windows NOT filter the network sign-ins of local administrators on this computer? Remote filtering exists only while UAC
// is on (EnableLUA = 1) and LocalAccountTokenFilterPolicy is not 1. A missing EnableLUA, or any read error, counts as "not
// filtered" (fail closed).
bool local_account_filter_policy_open() {
    DWORD lua = 0, policy = 0;
    bool lua_found = false, policy_found = false;
    if (!read_system_policy_dword(L"EnableLUA", &lua, &lua_found)) return true;
    if (!lua_found || lua != 1) return true;
    if (!read_system_policy_dword(L"LocalAccountTokenFilterPolicy", &policy, &policy_found)) return true;
    return policy_found && policy != 0;
}

std::string exposure_problem_of_token(HANDLE tok, const std::string& sid, bool measured_network_token) {
    if (measured_network_token) {
        // the token of a real NETWORK sign-in of this account: whatever it still carries, the engine can get back over loopback
        std::string m = network_token_problem(read_token_report(tok));
        if (!m.empty()) return m;
    }
    TokenFacts f = read_token_facts(tok);
    // only an account that is (or may be) powerful needs the other two lookups
    bool powerful = !f.readable || f.linked_unreadable || f.in_admins || f.in_operator_group || f.powerful_privilege || f.linked_elevated;
    return remote_filtering_problem(sid, f, powerful && account_is_domain_account(sid), powerful && local_account_filter_policy_open());
}

std::string account_exposure_problem_for_current_user() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return remote_filtering_problem(current_user_sid(), TokenFacts{}, true, true);
    Handle ht(tok);
    return exposure_problem_of_token(tok, current_user_sid(), /*measured_network_token=*/false);
}

std::string account_name_from_sid(const std::string& sid) {
    PSID psid = nullptr;
    if (!ConvertStringSidToSidW(widen(sid).c_str(), &psid)) return {};
    struct Free { PSID p; ~Free() { LocalFree(p); } } fr{psid};
    DWORD nn = 0, dn = 0;
    SID_NAME_USE use;
    LookupAccountSidW(nullptr, psid, nullptr, &nn, nullptr, &dn, &use);
    if (!nn) return {};
    std::wstring name(nn, L' '), dom(dn ? dn : 1, L' ');
    if (!LookupAccountSidW(nullptr, psid, &name[0], &nn, &dom[0], &dn, &use)) return {};
    name.resize(wcslen(name.c_str()));
    dom.resize(wcslen(dom.c_str()));
    return narrow(dom.empty() ? name : dom + L"\\" + name);
}

std::string revoke_service_logon_right(const std::string& sid) {
    PSID psid = nullptr;
    if (!ConvertStringSidToSidW(widen(sid).c_str(), &psid)) return "invalid account identity";
    struct Free { PSID p; ~Free() { LocalFree(p); } } fr{psid};
    LSA_OBJECT_ATTRIBUTES oa{};
    LSA_HANDLE pol = nullptr;
    NTSTATUS st = LsaOpenPolicy(nullptr, &oa, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &pol);
    if (st != 0) return "cannot open the local security policy (error " + std::to_string(LsaNtStatusToWinError(st)) + ")";
    struct Close { LSA_HANDLE h; ~Close() { LsaClose(h); } } cl{pol};
    static wchar_t right[] = L"SeServiceLogonRight";
    LSA_UNICODE_STRING us;
    us.Buffer = right;
    us.Length = static_cast<USHORT>(wcslen(right) * sizeof(wchar_t));
    us.MaximumLength = static_cast<USHORT>(us.Length + sizeof(wchar_t));
    st = LsaRemoveAccountRights(pol, psid, FALSE, &us, 1);
    return st == 0 ? std::string() : "cannot take the service logon right away (error " + std::to_string(LsaNtStatusToWinError(st)) + ")";
}

std::string grant_service_logon_right(const std::string& sid, bool* added) {
    if (added) *added = false;
    PSID psid = nullptr;
    if (!ConvertStringSidToSidW(widen(sid).c_str(), &psid)) return "invalid account identity";
    struct Free { PSID p; ~Free() { LocalFree(p); } } fr{psid};
    LSA_OBJECT_ATTRIBUTES oa{};
    LSA_HANDLE pol = nullptr;
    NTSTATUS st = LsaOpenPolicy(nullptr, &oa, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &pol);
    if (st != 0) return "cannot open the local security policy (error " + std::to_string(LsaNtStatusToWinError(st)) + ")";
    struct Close { LSA_HANDLE h; ~Close() { LsaClose(h); } } cl{pol};
    static wchar_t right[] = L"SeServiceLogonRight";
    LSA_UNICODE_STRING us;
    us.Buffer = right;
    us.Length = static_cast<USHORT>(wcslen(right) * sizeof(wchar_t));
    us.MaximumLength = static_cast<USHORT>(us.Length + sizeof(wchar_t));
    PLSA_UNICODE_STRING have = nullptr;
    ULONG count = 0;
    st = LsaEnumerateAccountRights(pol, psid, &have, &count);
    // Only "this account has no rights at all" (STATUS_OBJECT_NAME_NOT_FOUND) means the right is absent; any other failure to
    // read must not be taken as "absent" (we would then record a right we did not add, and later remove one that was there).
    if (st != 0 && st != static_cast<NTSTATUS>(0xC0000034L))
        return "cannot read the rights of this account (error " + std::to_string(LsaNtStatusToWinError(st)) + ")";
    bool already = false;
    if (st == 0) {
        for (ULONG i = 0; i < count; ++i)
            if (have[i].Length == us.Length && std::memcmp(have[i].Buffer, right, us.Length) == 0) already = true;
        LsaFreeMemory(have);
    }
    if (already) return {};
    st = LsaAddAccountRights(pol, psid, &us, 1);
    if (st == 0 && added) *added = true;
    if (st != 0) return "cannot allow this account to run a service (error " + std::to_string(LsaNtStatusToWinError(st)) + ")";
    return {};
}

#else  // ------------------------------------------------------------------------------------------ not Windows
struct PasswordChannel::Impl {};
PasswordChannel::PasswordChannel() : p_(new Impl) {}
PasswordChannel::~PasswordChannel() = default;
const std::string& PasswordChannel::pipe_name() const {
    static const std::string s;
    return s;
}
const std::string& PasswordChannel::nonce_hex() const {
    static const std::string s;
    return s;
}
std::unique_ptr<PasswordChannel> PasswordChannel::create() { throw Error("the password channel is only used on Windows"); }
bool PasswordChannel::deliver(const SecretString&, int, std::string* error) {
    if (error) *error = "not supported on this system";
    return false;
}
bool receive_password(const std::string&, const std::string&, SecretString*, std::string* error, const std::string&) {
    if (error) *error = "not supported on this system";
    return false;
}
AccountCheck check_service_account(const std::string&, const SecretString&) {
    AccountCheck r;
    r.admin = AdminState::No;
    r.ok = true;
    return r;
}
std::string grant_service_logon_right(const std::string&, bool* added) {
    if (added) *added = false;
    return {};
}
std::string revoke_service_logon_right(const std::string&) { return {}; }
void PasswordChannel::cancel() {}
void PasswordChannel::expect_client_pid(unsigned long) {}
std::string current_owner_id() { return std::to_string(static_cast<unsigned long>(::geteuid())); }
AdminState account_admin_state(const std::string&) { return AdminState::No; }
std::string account_exposure_problem_for_current_user() { return {}; }
std::string current_account_name() {
    struct passwd pw{}, *res = nullptr;
    char buf[4096];
    if (::getpwuid_r(::geteuid(), &pw, buf, sizeof buf, &res) == 0 && res) return pw.pw_name;
    return {};
}
std::string account_sid(const std::string&) { return {}; }
std::string account_name_from_sid(const std::string&) { return {}; }
std::string primary_group_of_user(const std::string& user) {
    struct passwd pw{}, *res = nullptr;
    char buf[4096];
    if (::getpwnam_r(user.c_str(), &pw, buf, sizeof buf, &res) != 0 || !res) return {};
    struct group gr{}, *gres = nullptr;
    char gbuf[4096];
    if (::getgrgid_r(pw.pw_gid, &gr, gbuf, sizeof gbuf, &gres) != 0 || !gres) return {};
    return gr.gr_name;
}
#endif


}  // namespace mysync::simple
