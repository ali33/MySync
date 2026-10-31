// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
//
// Simple mode, Windows service as the user (d8): the service is only a FRAME. The synchronisation engine runs in a child
// process started with a RESTRICTED TOKEN built from the frame's own token:
//   - the Administrators group and the operator groups (and Domain/Enterprise/Schema admins) are DENY-ONLY,
//   - every privilege except SeChangeNotify is deleted (SeDebug, SeBackup, SeRestore, SeTakeOwnership, SeImpersonate ...),
//   - the integrity level is Medium,
//   - the owner and the default DACL are the user's SID.
// The child is created suspended, put into a Job Object (kill on close, one process, no UI), its token is READ BACK and
// verified, and only then resumed. Anything that does not verify is killed and refused (fail closed).
//
// The decision logic (is_dangerous_group_sid, restricted_token_problem) is pure so it can be tested without a token.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mysync::simple {

struct TokenGroupInfo {
    std::string sid;            // "S-1-5-32-544"
    uint32_t attributes = 0;    // SE_GROUP_* bits (0x10 = SE_GROUP_USE_FOR_DENY_ONLY)
};

struct TokenReport {
    bool readable = false;
    std::string user_sid;                    // the account of the token (TokenUser)                   // false: something could not be read (counts against the token)
    std::vector<TokenGroupInfo> groups;
    std::vector<std::string> privileges;     // every privilege PRESENT in the token (enabled or not), by name
    uint32_t integrity_rid = 0;              // 0x2000 = Medium, 0x3000 = High ...; 0 = unknown
};

constexpr uint32_t kSeGroupDenyOnly = 0x10;
constexpr uint32_t kIntegrityMedium = 0x2000;

// Administrators, the operator groups, Power Users, and the domain-wide admin groups (RIDs 512 / 518 / 519 / 520).
bool is_dangerous_group_sid(const std::string& sid);
// SeDebug, SeTcb, SeLoadDriver, SeBackup, SeRestore, SeTakeOwnership, SeCreateToken, SeSecurity. (SeImpersonate and
// SeAssignPrimaryToken are NOT here: ordinary service accounts have them.) One list for the restricted token, the account facts
// and the network measurement.
bool is_strong_privilege(const std::string& name);
// "" when the token of a NETWORK sign-in of the account has no dangerous group switched on (deny-only is fine) and no strong
// privilege: otherwise the plain-language reason. This is the sign-in the engine could repeat over the network (loopback / SMB).
std::string network_token_problem(const TokenReport& r);
// The ONLY groups the engine's token may keep usable (everything else is deny-only): the user's own SID, Everyone,
// BUILTIN Users, Authenticated Users, INTERACTIVE, LOCAL / CONSOLE LOGON, This Organization, Local account, and the session's
// own logon SID (needed for the window station / desktop - a process whose logon SID is deny-only cannot start). The mandatory-label
// group is not a real group and stays. Service SIDs, S-1-5-114, docker-users, Hyper-V Administrators, Remote
// Management, DCOM, Event Log Readers, Device Owners ... are all NOT on the list.
bool is_allowed_group_sid(const std::string& sid, const std::string& user_sid);
// "" when the token is acceptable for the engine, otherwise the reason (verbatim, for the log and the status).
std::string restricted_token_problem(const TokenReport& r);
// One line for the status: what the engine's token is ("restricted token verified: 3 groups deny-only, 0 privileges, medium integrity").
std::string describe_token(const TokenReport& r);

// The environment block of the engine (NAME=value lines): a handful of variables and a fixed PATH, never the frame's whole
// environment. Empty values are left out.
std::vector<std::string> build_engine_env(const std::string& system_root, const std::string& temp_dir, const std::string& userprofile,
                                          const std::string& appdata, const std::string& localappdata,
                                          const std::vector<std::string>& extra = {});

// Exit codes the frame reports through the service control manager (ServiceSpecificExitCode) when it refuses to start the engine.
constexpr int kFrameTokenNotBuilt = 1001;
constexpr int kFrameTokenRejected = 1002;
constexpr int kFrameCannotStart = 1003;
constexpr int kFrameExposed = 1004;       // the account became one whose network logons Windows does not restrict
std::string frame_refusal_text(int specific_exit_code);   // plain words for those codes ("" for others)

#ifdef _WIN32
TokenReport read_token_report(void* token);   // HANDLE

// The restricted primary token of the user running this process (or of `base` when given). nullptr + *err on failure;
// the caller closes it with CloseHandle.
void* make_restricted_token(std::string* err, void* base = nullptr);

class RestrictedChild {
public:
    // Starts `exe` with `args`: token built, process created suspended inside the job, token read back and verified, resumed.
    // Standard input is a pipe the frame holds: request_stop() closes it (the engine runs with --exit-on-stdin-eof).
    // nullptr + *err when anything fails (nothing keeps running). *token_note receives describe_token(...) on success.
    static std::unique_ptr<RestrictedChild> start(const std::string& exe, const std::vector<std::string>& args,
                                                  const std::string& workdir, std::string* err, std::string* token_note,
                                                  const std::string& temp_dir = {});
    ~RestrictedChild();   // closes the job: the engine dies with it
    RestrictedChild(const RestrictedChild&) = delete;
    RestrictedChild& operator=(const RestrictedChild&) = delete;
    unsigned long pid() const;
    bool wait(int timeout_ms, unsigned long* exit_code = nullptr);   // true when the process has ended
    void request_stop();   // graceful: close its standard input
    void kill();
    // The token of the RUNNING process read back (for tests and for the status).
    TokenReport process_token_report() const;

private:
    RestrictedChild() = default;
    struct Impl;
    std::unique_ptr<Impl> p_;
};

// The engine reads ITS OWN token and describes it ("service token: restricted and verified ..." or "... NOT restricted (why)"),
// instead of trusting what the frame told it on the command line.
std::string describe_own_token();

struct FrameParams {
    std::string exe;                          // the engine program (this executable)
    std::vector<std::string> engine_args;     // WITHOUT --frame-note and --exit-on-stdin-eof: the frame adds them
    std::string workdir;
    std::string temp_dir;                     // TEMP / TMP of the engine (the user's state folder: it exists and is the user's)
    std::vector<int> backoff_ms{1000, 2000, 5000, 10000, 30000, 60000};
    bool protect_process = true;              // close the frame process to the engine (DACL); tests turn it off for their own process
    std::function<std::string()> exposure;    // empty = account_exposure_problem_for_current_user() (tests inject)
};
// The frame loop: start the engine, restart it with a growing delay when it dies, stop on `stop`. Returns 0 after a requested
// stop, or one of the kFrame* codes when the engine can never be started (the caller reports it as the service's specific
// exit code). Nothing in this loop touches the user's folders.
int run_frame(const FrameParams& p, std::atomic<bool>& stop, std::string* last_error);
#endif

}  // namespace mysync::simple
