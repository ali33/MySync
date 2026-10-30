// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/service_account.h - the service of the Simple mode runs AS THE USER (never SYSTEM / root at run time).
//
// Linux : a unit `mysync-<user>.service` with User=/Group= of the owner of the folders; only the INSTALL step (pkexec)
//         is root. Nothing here needs a password.
// Windows: the service logs on with the user's own account, so it needs that account's PASSWORD (a Microsoft account
//         uses the ACCOUNT password, not the Windows Hello PIN). The password is asked ONCE by the GUI and travels to
//         the elevated installer through a private named pipe, never through a command line, an environment variable,
//         a log or a file; both ends wipe it right after use. The elevated step then
//           1. checks it with LogonUser (a wrong password is reported at once, in plain words, without the password),
//           2. grants "log on as a service" to exactly that account's SID, only if it lacks it,
//           3. CreateService with the account and the password (the system keeps it as an LSA secret).
//         An account with an empty password cannot run a service: the install is refused with that explanation.
//         When the user later changes the password the service stops with logon failure 1069; the controller reports
//         ServiceState::needs_password_update and the same channel is used to set the new password.
#include <memory>
#include <functional>
#include <string>

#include "mysync/util.h"

namespace mysync::simple {

// A secret kept in memory only as long as needed: wiped on destruction / clear(); movable, not copyable.
class SecretString {
public:
    SecretString() = default;
    explicit SecretString(const std::string& s) : s_(s) {}
    SecretString(SecretString&& o) noexcept { s_.swap(o.s_); o.clear(); }
    SecretString& operator=(SecretString&& o) noexcept {
        if (this != &o) {
            clear();
            s_.swap(o.s_);
            o.clear();
        }
        return *this;
    }
    SecretString(const SecretString&) = delete;
    SecretString& operator=(const SecretString&) = delete;
    ~SecretString() { clear(); }
    void assign(const char* d, size_t n) {
        clear();
        s_.assign(d, n);
    }
    void clear() {
        // the whole buffer, not only the used part (an earlier longer value may have left bytes behind)
        if (s_.capacity() > 0) {
            s_.resize(s_.capacity(), '\0');
            secure_wipe(&s_[0], s_.size());
        }
        s_.clear();
    }
    bool empty() const { return s_.empty(); }
    size_t size() const { return s_.size(); }
    const std::string& reveal() const { return s_; }  // use, then let the object die; never log it

private:
    std::string s_;
};

struct ServiceCredential {
    std::string account;   // ".\\alice", "DOMAIN\\alice", "alice@example.com" (UPN) or "MicrosoftAccount\\alice@outlook.com"
    SecretString password;
};

// Account name syntax (no quotes, control characters, path separators other than the single domain backslash, <= 256).
bool valid_account_name(const std::string& account);
// "mysync-<name>" with the name reduced to [a-z0-9_-] (domain and UPN suffix dropped); the same rule names the Linux unit.
std::string user_service_name(const std::string& account);
// The same, made UNIQUE per user: a short hash of the owner's id (Windows SID / POSIX uid) is appended ("mysync-alice-3f9a"), so
// two accounts whose names reduce to the same text, or a name clashing with "mysync-client" / "mysync-server", never share a
// service. The service description carries the label owner_label(id) and uninstall / downgrade only act on a service whose
// label is the caller's.
std::string user_service_name(const std::string& account, const std::string& owner_id);
// Does `name` have the shape the Simple mode gives its services: "mysync-<account>-<4 hex of the owner id>" (and is not one of
// the plain mysync-server / mysync-client names)? The elevated step refuses to install or touch any other name.
// The lowest uid that belongs to a real login (UID_MIN of /etc/login.defs, 1000 when unreadable); 0 on Windows.
unsigned long min_login_uid();
bool user_service_name_matches_owner(const std::string& name, const std::string& owner_id);
std::string owner_label(const std::string& owner_id);   // "[owner <id>]"
// The id of the user running this process: Windows SID text, POSIX uid.
std::string current_owner_id();
// Windows: is this account (the requester) a member of Administrators? Then the service runs with FULL administrator rights
// and the GUI must say so before asking for the password. Evaluated for the user running this process; false elsewhere.
bool account_is_administrator(const std::string& sid);
// Plain-language reason a Simple-mode service is refused for an administrator account (Windows); empty when `is_admin` is false.
// The service token of an administrator is a full administrator token, and the source / destination trees are writable by the
// user's other software, so a junction swapped in after the checks would let the service write or delete anywhere.
std::string admin_account_refusal(bool is_admin);

// Counts wrong passwords in a row for the GUI flow: after 5 failures further tries are refused for 30 s, so a mistyped
// password cannot lock the Windows account out.
class PasswordAttemptLimiter {
public:
    bool allowed(int64_t now_ms) const { return now_ms >= locked_until_ms_; }
    int64_t seconds_left(int64_t now_ms) const { return allowed(now_ms) ? 0 : (locked_until_ms_ - now_ms + 999) / 1000; }
    void failed(int64_t now_ms) {
        if (++fails_ >= 5) {
            locked_until_ms_ = now_ms + 30000;
            fails_ = 0;
        }
    }
    void succeeded() { fails_ = 0; locked_until_ms_ = 0; }

private:
    int fails_ = 0;
    int64_t locked_until_ms_ = 0;
};

// ---- the private channel GUI -> elevated installer (Windows). On other systems create() throws Error.
// The GUI creates the channel, puts pipe_name() and nonce_hex() on the command line of the elevated child (neither is
// secret by itself), starts the child and calls deliver() from another thread. The pipe: random name, one instance
// (FILE_FLAG_FIRST_PIPE_INSTANCE: nobody can squat on the name), no remote clients, DACL = this user + SYSTEM +
// Administrators. deliver() only talks to a client whose process runs as the SAME user and who proves the 128-bit nonce;
// anything else is dropped (at most a few tries). The password is sent once and the pipe is destroyed.
class PasswordChannel {
public:
    static std::unique_ptr<PasswordChannel> create();
    ~PasswordChannel();
    PasswordChannel(const PasswordChannel&) = delete;
    PasswordChannel& operator=(const PasswordChannel&) = delete;
    const std::string& pipe_name() const;
    const std::string& nonce_hex() const;
    bool deliver(const SecretString& password, int timeout_ms, std::string* error);
    // Wakes a deliver() that is still waiting for the installer (it never started: UAC cancelled ...). Thread-safe.
    void cancel();

private:
    PasswordChannel();
    struct Impl;
    std::unique_ptr<Impl> p_;
};

// Elevated side: connects, checks that the server process runs as the current user, proves the nonce, receives the
// password. False + *error (plain words) otherwise.
bool receive_password(const std::string& pipe_name, const std::string& nonce_hex, SecretString* out, std::string* error);

// The account of the user running this process in the form a service logon wants (Windows: DOMAIN\\name from the
// system, SAM-compatible; POSIX: the user name). "" if unknown.
std::string current_account_name();
// SID of an account name ("" when it does not exist). Windows only; elsewhere "".
std::string account_sid(const std::string& account);
// The canonical "DOMAIN\name" of an account, looked up from its SID (Windows); empty when it cannot be resolved / elsewhere.
std::string account_name_from_sid(const std::string& sid);
// POSIX: the primary group NAME of a user ("" if unknown); the per-user unit runs with Group= that.
std::string primary_group_of_user(const std::string& user);

// ---- the elevated installer's account work (Windows; elsewhere check_service_account says ok and the others do nothing)
struct AccountCheck {
    bool ok = false;
    std::string sid;    // the account's SID ("S-1-5-21-...")
    std::string error;  // plain words, never contains the password
};
// LogonUser with the password (no change to the system). Resolves the SID.
AccountCheck check_service_account(const std::string& account, const SecretString& password);
// Adds SeServiceLogonRight to exactly this SID if it does not have it. "" on success (also when it already had it).
// *added (when given) tells whether THIS call added the right (so only then may it be taken away again).
std::string grant_service_logon_right(const std::string& sid, bool* added = nullptr);
// Takes SeServiceLogonRight away from this SID again (rollback of a failed install, removal of the service). "" on success.
std::string revoke_service_logon_right(const std::string& sid);

// Takes the logon-as-service right away again on EVERY way out of an installation that did not end with a working, recorded
// service (early return, exception, failed later step). `revoke` is replaceable for tests.
class LogonRightGuard {
public:
    using Revoke = std::function<void(const std::string& sid)>;
    explicit LogonRightGuard(Revoke revoke = [](const std::string& sid) { revoke_service_logon_right(sid); }) : revoke_(std::move(revoke)) {}
    LogonRightGuard(const LogonRightGuard&) = delete;
    LogonRightGuard& operator=(const LogonRightGuard&) = delete;
    // We granted the right to `sid` (only when it was really added by us).
    void granted(const std::string& sid) { sid_ = sid; armed_ = !sid.empty(); }
    void release() { armed_ = false; }   // the service works and its marker is on disk: it owns the right now
    ~LogonRightGuard() {
        if (armed_ && revoke_) revoke_(sid_);
    }

private:
    Revoke revoke_;
    std::string sid_;
    bool armed_ = false;
};

// Windows error code of a failed LogonUser -> what to tell the user. Pure (tested everywhere).
std::string explain_logon_error(unsigned long win_error);

}  // namespace mysync::simple
