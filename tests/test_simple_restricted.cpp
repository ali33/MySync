// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
//
// d8: the restricted token of the engine, the frame around it, and the requester identity rules.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "mysync/simple/restricted.h"
#include "mysync/simple/service_account.h"
#include "mysync/simple/user_paths.h"
#include "testing.h"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#endif

using namespace mysync;
using namespace mysync::simple;
namespace fs = std::filesystem;

namespace {

struct RTmp {
    fs::path p;
    RTmp() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-restr-" + to_hex(r, sizeof r));
        fs::create_directories(p);
    }
    ~RTmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
};

TokenReport good_report() {
    TokenReport r;
    r.readable = true;
    r.user_sid = "S-1-5-21-1-2-3-1001";
    r.groups = {{"S-1-5-21-1-2-3-1001", 0x7}, {"S-1-5-32-544", kSeGroupDenyOnly}, {"S-1-1-0", 0x7}};
    r.privileges = {"SeChangeNotifyPrivilege"};
    r.integrity_rid = kIntegrityMedium;
    return r;
}

}  // namespace

TEST(d8_dangerous_groups_are_recognised) {
    for (const char* s : {"S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552",
                          "S-1-5-32-556", "S-1-5-32-569", "S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-518", "S-1-5-21-1-2-3-519",
                          "S-1-5-21-1-2-3-520"})
        CHECK(is_dangerous_group_sid(s));
    for (const char* s : {"S-1-1-0", "S-1-5-32-545", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-513", "S-1-5-4", "S-1-16-8192"})
        CHECK(!is_dangerous_group_sid(s));
}

TEST(d8_token_verdict_is_fail_closed) {
    CHECK(restricted_token_problem(good_report()).empty());
    TokenReport r = good_report();
    r.readable = false;
    CHECK(!restricted_token_problem(r).empty());                              // unreadable counts against the token
    r = good_report();
    r.groups[1].attributes = 0x7;                                             // Administrators usable again
    CHECK(restricted_token_problem(r).find("S-1-5-32-544") != std::string::npos);
    r = good_report();
    r.groups.push_back({"S-1-5-32-551", 0x7});                                // Backup Operators, enabled
    CHECK(!restricted_token_problem(r).empty());
    r = good_report();
    r.groups.push_back({"S-1-5-21-1-2-3-512", 0x7});                          // Domain Admins, enabled
    CHECK(!restricted_token_problem(r).empty());
    r = good_report();
    r.privileges.push_back("SeDebugPrivilege");                               // present, even if it were disabled
    CHECK(restricted_token_problem(r).find("SeDebugPrivilege") != std::string::npos);
    r = good_report();
    r.integrity_rid = 0x3000;                                                 // High
    CHECK(!restricted_token_problem(r).empty());
    r.integrity_rid = 0;                                                      // unknown
    CHECK(!restricted_token_problem(r).empty());
    r = good_report();
    r.integrity_rid = 0x1000;                                                 // Low is acceptable (not above Medium)
    CHECK(restricted_token_problem(r).empty());
    CHECK(describe_token(good_report()).find("restricted and verified") != std::string::npos);
}

TEST(d8_group_allowlist_is_the_only_way_to_stay_usable) {
    const std::string me = "S-1-5-21-1-2-3-1001";
    for (const char* s : {"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", "S-1-2-0", "S-1-2-1"}) CHECK(is_allowed_group_sid(s, me));
    CHECK(is_allowed_group_sid(me, me));
    CHECK(is_allowed_group_sid("S-1-5-5-0-123456", me));                       // the session's own logon SID
    for (const char* s : {"S-1-5-32-544", "S-1-5-32-578", "S-1-5-32-580", "S-1-5-32-562", "S-1-5-32-574", "S-1-5-32-573", "S-1-5-32-583",
                          "S-1-5-32-582", "S-1-5-114", "S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-3-1005", "S-1-5-21-1-2-3-1002"})
        CHECK(!is_allowed_group_sid(s, me));
    // a group that is not on the list and still usable fails the verdict, whatever it is called
    for (const char* s : {"S-1-5-32-578", "S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-3-1005", "S-1-5-114"}) {
        TokenReport r = good_report();
        r.groups.push_back({s, 0x7});
        CHECK(!restricted_token_problem(r).empty());
        r.groups.back().attributes = kSeGroupDenyOnly;                        // deny-only is fine
        CHECK(restricted_token_problem(r).empty());
    }
    TokenReport lbl = good_report();
    lbl.groups.push_back({"S-1-16-8192", 0x60});                              // the mandatory label (SE_GROUP_INTEGRITY) is not a group
    CHECK(restricted_token_problem(lbl).empty());
    TokenReport nouser = good_report();
    nouser.user_sid.clear();
    CHECK(!restricted_token_problem(nouser).empty());
}


TEST(d8_the_network_signin_token_is_measured) {
    TokenReport clean = good_report();                                        // Administrators deny-only, one privilege
    CHECK(network_token_problem(clean).empty());                              // a filtered local administrator: fine
    TokenReport r = clean;
    r.groups.push_back({"S-1-5-32-551", 0x7});                                // Backup Operators ENABLED in the network token
    CHECK(network_token_problem(r).find("S-1-5-32-551") != std::string::npos);
    r = clean;
    r.groups.push_back({"S-1-5-32-578", 0x7});                                // Hyper-V Administrators
    CHECK(!network_token_problem(r).empty());
    r = clean;
    r.groups.push_back({"S-1-5-21-1-2-3-512", 0x7});                          // Domain Admins
    CHECK(!network_token_problem(r).empty());
    r = clean;
    r.groups.push_back({"S-1-5-114", 0x7});                                   // local account and member of Administrators
    CHECK(!network_token_problem(r).empty());
    r = clean;
    r.groups[1].attributes = 0x7;                                             // Administrators NOT filtered (built-in Administrator, ...)
    CHECK(!network_token_problem(r).empty());
    r = clean;
    r.groups.push_back({"S-1-5-32-551", kSeGroupDenyOnly});                   // deny-only is fine
    CHECK(network_token_problem(r).empty());
    for (const char* p : {"SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege",
                          "SeTcbPrivilege", "SeCreateTokenPrivilege", "SeSecurityPrivilege"}) {
        r = clean;
        r.privileges.push_back(p);
        CHECK(network_token_problem(r).find(p) != std::string::npos);
        CHECK(is_strong_privilege(p));
    }
    r = clean;
    r.privileges.push_back("SeImpersonatePrivilege");                         // ordinary service accounts have it: not counted
    CHECK(network_token_problem(r).empty());
    CHECK(!is_strong_privilege("SeImpersonatePrivilege") && !is_strong_privilege("SeAssignPrimaryTokenPrivilege"));
    TokenReport unread;
    CHECK(network_token_problem(unread).find("could not be examined") != std::string::npos);
    // the one list serves every use
    for (const char* s : {"S-1-5-32-562", "S-1-5-32-573", "S-1-5-32-574", "S-1-5-32-578", "S-1-5-32-580", "S-1-5-32-582", "S-1-5-32-583",
                          "S-1-5-114", "S-1-5-21-1-2-3-517", "S-1-5-21-1-2-3-526", "S-1-5-21-1-2-3-527"})
        CHECK(is_dangerous_group_sid(s));
}

TEST(d8_engine_environment_is_small_and_fixed) {
    auto v = build_engine_env("C:/Win", "C:/u/state", "C:/u", "", "C:/u/Local");
    auto has = [&](const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); };
    CHECK(has("SystemRoot=C:/Win") && has("windir=C:/Win") && has("TEMP=C:/u/state") && has("TMP=C:/u/state"));
    CHECK(has("PATH=C:/Win\\system32;C:/Win"));
    CHECK(has("USERPROFILE=C:/u") && has("LOCALAPPDATA=C:/u/Local"));
    for (const auto& e : v) CHECK(e.back() != '=');                           // empty values are left out (APPDATA)
    CHECK_EQ(v.size(), size_t(7));
    CHECK(build_engine_env("", "", "", "", "").empty());
}

TEST(d8_frame_refusals_have_plain_words) {
    CHECK(!frame_refusal_text(kFrameTokenNotBuilt).empty());
    CHECK(!frame_refusal_text(kFrameTokenRejected).empty());
    CHECK(!frame_refusal_text(kFrameCannotStart).empty());
    CHECK(!frame_refusal_text(kFrameExposed).empty());
    CHECK(frame_refusal_text(1).empty());
}

TEST(d8_requester_identity_rules) {
    const std::string me = "S-1-5-21-111-222-333-1001", other = "S-1-5-21-111-222-333-1002";
    CHECK(requester_identity_problem(me, me).empty());
    CHECK(!requester_identity_problem(me, other).empty());                    // the password of ANOTHER account
    CHECK(!requester_identity_problem(me, "").empty());
    CHECK(!requester_identity_problem("", me).empty());                       // no requester named
    CHECK(!requester_identity_problem("S-1-5-18", "S-1-5-18").empty());       // SYSTEM is not a user
    CHECK(!requester_identity_problem("S-1-5-21-1-2-3-1001; calc", "S-1-5-21-1-2-3-1001; calc").empty());
    CHECK(valid_user_sid(me));
    CHECK(valid_user_sid("S-1-12-1-1-2-3-4"));
    CHECK(!valid_user_sid(""));
    CHECK(!valid_user_sid("S-1-5-21-"));
    CHECK(!valid_user_sid("S-1-5-32-544"));
    // the effective user: the requester when one is named, else the current user
    struct Reset { ~Reset() { set_requester_sid(""); } } reset;
    set_requester_sid(me);
    CHECK_EQ(effective_user_sid(), me);
    set_requester_sid("garbage");
    CHECK_EQ(effective_user_sid(), current_user_sid());
}

#ifdef _WIN32
TEST(d8_password_channel_recognises_the_client_by_pid_and_the_server_by_the_requester_sid) {
    SecretString secret(std::string("s3cret"));
    // a client that is not the process the caller started: dropped, the password is not handed over
    {
        auto ch = PasswordChannel::create();
        ch->expect_client_pid(GetCurrentProcessId() + 4);
        std::string derr, cerr_text;
        bool delivered = true;
        std::thread server([&] { delivered = ch->deliver(secret, 2500, &derr); });
        SecretString got;
        bool ok = receive_password(ch->pipe_name(), ch->nonce_hex(), &got, &cerr_text);
        server.join();
        CHECK(!delivered && !ok && got.empty());
    }
    // the other end names a different requester than the process that owns the pipe: the client sends nothing
    {
        auto ch = PasswordChannel::create();
        ch->expect_client_pid(GetCurrentProcessId());
        std::string derr, cerr_text;
        bool delivered = true;
        std::thread server([&] { delivered = ch->deliver(secret, 2500, &derr); });
        SecretString got;
        bool ok = receive_password(ch->pipe_name(), ch->nonce_hex(), &got, &cerr_text, "S-1-5-21-9-9-9-4242");
        server.join();
        CHECK(!ok && got.empty() && !delivered);
        CHECK(cerr_text.find("not the application of this user") != std::string::npos);
    }
    // the right requester (this user, named explicitly) works
    {
        auto ch = PasswordChannel::create();
        ch->expect_client_pid(GetCurrentProcessId());
        std::string derr, cerr_text;
        bool delivered = false;
        std::thread server([&] { delivered = ch->deliver(secret, 15000, &derr); });
        SecretString got;
        bool ok = receive_password(ch->pipe_name(), ch->nonce_hex(), &got, &cerr_text, current_user_sid());
        server.join();
        CHECK(ok && delivered);
        CHECK_EQ(got.reveal(), std::string("s3cret"));
    }
}

namespace {

std::string self_exe_path() {
    wchar_t buf[1024];
    DWORD n = GetModuleFileNameW(nullptr, buf, 1024);
    return fs::path(std::wstring(buf, n)).u8string();
}

bool process_gone(DWORD pid, int ms) {
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return true;
    DWORD w = WaitForSingleObject(h, static_cast<DWORD>(ms));
    CloseHandle(h);
    return w == WAIT_OBJECT_0;
}

}  // namespace

TEST(d8_a_real_restricted_token_has_denied_groups_no_privileges_and_medium_integrity) {
    std::string err;
    void* tok = make_restricted_token(&err);
    CHECK(tok != nullptr);
    if (!tok) {
        std::cerr << err << "\n";
        return;
    }
    TokenReport r = read_token_report(tok);
    CloseHandle(static_cast<HANDLE>(tok));
    CHECK(r.readable);
    CHECK(restricted_token_problem(r).empty());
    for (const auto& g : r.groups)
        if (!(g.attributes & 0x20) && !is_allowed_group_sid(g.sid, r.user_sid)) CHECK((g.attributes & kSeGroupDenyOnly) != 0);   // not on the list => deny-only
    CHECK_EQ(r.user_sid, current_user_sid());
    CHECK(r.privileges.size() <= 1);
    for (const auto& p : r.privileges) CHECK_EQ(p, std::string("SeChangeNotifyPrivilege"));
    CHECK_EQ(r.integrity_rid, kIntegrityMedium);
}

TEST(d8_engine_runs_under_the_restricted_token_and_stops_when_asked) {
    std::string err, note;
    auto child = RestrictedChild::start(self_exe_path(), {"--fake-engine", "wait"}, fs::temp_directory_path().u8string(), &err, &note);
    CHECK(child != nullptr);
    if (!child) {
        std::cerr << err << "\n";
        return;
    }
    CHECK(note.find("restricted and verified") != std::string::npos);
    CHECK(child->pid() != 0);
    CHECK(restricted_token_problem(child->process_token_report()).empty());   // the REAL process, read back
    unsigned long code = 99;
    bool early = child->wait(300, &code);
    if (early) std::cerr << "engine exited early with code " << code << std::endl;
    CHECK(!early);
    child->request_stop();                                                    // the frame closes it: the engine ends by itself
    CHECK(child->wait(10000, &code));
    CHECK_EQ(code, 0ul);
}

TEST(d8_closing_the_job_kills_the_engine) {
    std::string err;
    auto child = RestrictedChild::start(self_exe_path(), {"--fake-engine", "wait"}, fs::temp_directory_path().u8string(), &err, nullptr);
    CHECK(child != nullptr);
    if (!child) return;
    DWORD pid = child->pid();
    CHECK(!process_gone(pid, 200));
    child.reset();                                                            // KILL_ON_JOB_CLOSE
    CHECK(process_gone(pid, 10000));
}

TEST(d8_restricted_engine_cannot_write_where_only_administrators_may) {
    RTmp t;
    fs::path admin_only = t.p / "admin-only", user_dir = t.p / "user-dir";
    fs::create_directories(user_dir);
    // a folder whose only ACEs are Administrators and SYSTEM (no ACE for this user, whatever it is)
    PSECURITY_DESCRIPTOR psd = nullptr;
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", SDDL_REVISION_1, &psd, nullptr));
    SECURITY_ATTRIBUTES sa{sizeof sa, psd, FALSE};
    CHECK(CreateDirectoryW(admin_only.c_str(), &sa));
    LocalFree(psd);
    struct Restore { fs::path p; ~Restore() { restrict_to_current_user(p.u8string(), true); } } restore{admin_only};   // so the cleanup can delete it
    std::string err;
    auto probe = [&](const fs::path& target) {
        auto c = RestrictedChild::start(self_exe_path(), {"--fake-engine", "probe-write", (target / "x.txt").u8string()},
                                        fs::temp_directory_path().u8string(), &err, nullptr);
        if (!c) return -1;
        unsigned long code = 77;
        if (!c->wait(15000, &code)) return -2;
        return static_cast<int>(code);
    };
    CHECK_EQ(probe(user_dir), 0);                                             // the engine can write where the USER can
    CHECK_EQ(probe(admin_only), 3);                                           // and not where only administrators can
    CHECK(!fs::exists(admin_only / "x.txt"));
}

TEST(d8_frame_restarts_stops_gracefully_and_survives_an_unstartable_engine) {
    FrameParams p;
    p.exe = self_exe_path();
    p.workdir = fs::temp_directory_path().u8string();
    p.backoff_ms = {50, 100};
    p.engine_args = {"--fake-engine", "wait"};
    p.exposure = [] { return std::string(); };   // not about this machine's account
    p.protect_process = false;                                                // this IS the test process
    std::atomic<bool> stop{false};
    std::string why;
    int rc = -1;
    std::thread th([&] { rc = run_frame(p, stop, &why); });
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    stop = true;
    auto t0 = std::chrono::steady_clock::now();
    th.join();
    CHECK_EQ(rc, 0);
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(20));
    // an engine program that does not exist: the frame keeps trying with its backoff and still stops on request
    FrameParams q = p;
    q.exe = (fs::temp_directory_path() / "mysync-no-such-engine.exe").u8string();
    std::atomic<bool> stop2{false};
    int rc2 = -1;
    std::thread th2([&] { rc2 = run_frame(q, stop2, &why); });
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    stop2 = true;
    th2.join();
    CHECK_EQ(rc2, 0);
    CHECK(why.find("START:") != std::string::npos);                           // verbatim reason kept
}

TEST(d8_the_frame_writes_nothing_into_the_users_state_folder) {
    RTmp t;
    fs::path state = t.p / "state";
    fs::create_directories(state);
    FrameParams p;
    p.exe = self_exe_path();
    p.workdir = state.u8string();
    p.temp_dir = state.u8string();
    p.backoff_ms = {50};
    p.engine_args = {"--fake-engine", "wait"};            // an engine that itself writes nothing
    p.exposure = [] { return std::string(); };
    p.protect_process = false;
    std::atomic<bool> stop{false};
    std::string why;
    int rc = -1;
    std::thread th([&] { rc = run_frame(p, stop, &why); });
    struct J { std::thread& t; std::atomic<bool>& s; ~J() { s = true; if (t.joinable()) t.join(); } } j{th, stop};
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    stop = true;
    th.join();
    CHECK_EQ(rc, 0);
    CHECK(fs::is_empty(state));                            // the frame (full token) created no file, no folder, no log in the user's tree
}

TEST(d8_the_engine_describes_its_own_token) {
    std::string d = describe_own_token();
    // the test process is not restricted: it must say so (or, if its token happens to pass, say it is verified) - never claim a
    // verification it did not do
    std::string problem;
    {
        HANDLE t = nullptr;
        CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t));
        problem = restricted_token_problem(read_token_report(t));
        CloseHandle(t);
    }
    if (problem.empty()) CHECK(d.find("restricted and verified") != std::string::npos);
    else CHECK(d.find("NOT restricted") != std::string::npos);
}

#endif
