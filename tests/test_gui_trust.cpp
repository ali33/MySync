// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// The invariants that keep a privileged daemon / installer from obeying files that others can edit.
#include <filesystem>
#include <algorithm>
#include <fstream>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "gui_test_util.h"
#ifdef _WIN32
#include <sddl.h>
#endif
#include "mysync/gui/ipc.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/gui/trust.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;
namespace fs = std::filesystem;

namespace {

struct TrTmp {
    fs::path p;
    TrTmp() {
        uint8_t r[5];
        random_bytes(r, sizeof r);
        p = fs::temp_directory_path() / ("mysync-guitr-" + to_hex(r, sizeof r));
        fs::create_directories(p);
        guitest::make_private_dir(p);
#ifndef _WIN32
        fs::permissions(p, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read |
                               fs::perms::others_exec);
#endif
    }
    ~TrTmp() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
    fs::path file(const std::string& name, const std::string& text = "x") const {
        fs::path f = p / name;
        std::ofstream(f, std::ios::binary) << text;
        return f;
    }
};

}  // namespace

TEST(gui_trust_normal_private_config_is_accepted) {
    TrTmp t;
    fs::path f = t.file("server.toml");
    CHECK_EQ(untrusted_writer_reason(f.u8string(), {}), std::string());
    require_trusted_config(f.u8string(), {});
    require_trusted_dir(t.p.u8string(), "state_dir", {});
    require_trusted_dir((t.p / "does-not-exist").u8string(), "state_dir", {});  // missing: ignored
    require_trusted_dir("", "state_dir", {});
}

TEST(gui_trust_file_or_folder_writable_by_everyone_is_refused) {
    TrTmp t;
    fs::path f = t.file("server.toml");
    CHECK(guitest::make_world_writable(f));
    std::string why = untrusted_writer_reason(f.u8string(), {});
    CHECK(!why.empty());
    bool threw = false;
    try {
        require_trusted_config(f.u8string(), {});
    } catch (const Error& e) {
        threw = true;
        std::string m = e.what();
        CHECK(m.find("server.toml") != std::string::npos);
        CHECK(m.find("refusing") != std::string::npos);
    }
    CHECK(threw);

    // the same through the folder
    TrTmp t2;
    fs::path f2 = t2.file("client.toml");
    CHECK(guitest::make_world_writable(t2.p));
#ifndef _WIN32
    // /tmp-like sticky folders are tolerated, a plain world-writable one is not (chmod above has no sticky bit)
#endif
    CHECK_THROWS(require_trusted_config(f2.u8string(), {}));
    CHECK_THROWS(require_trusted_dir(t2.p.u8string(), "state_dir", {}));
}

#ifdef _WIN32
TEST(gui_trust_windows_allow_list_exempts_the_principal) {
    TrTmp t;
    fs::path f = t.file("server.toml");
    CHECK(guitest::make_world_writable(f));
    CHECK(untrusted_writer_reason(f.u8string(), {}).find("S-1-1-0") != std::string::npos);
    CHECK_EQ(untrusted_writer_reason(f.u8string(), {"S-1-1-0"}), std::string());  // an admin put Everyone in allow
}

TEST(gui_trust_windows_executable_rules) {
    TrTmp t;
    fs::path exe = t.file("mysync.exe");
    // a user-owned folder in %TEMP% is not good enough for an elevated program
    CHECK(!untrusted_executable_reason(exe.u8string()).empty());
    // System32 is administrator-only
    CHECK_EQ(untrusted_executable_reason("C:\\Windows\\System32\\cmd.exe"), std::string());
}
#else
TEST(gui_trust_posix_group_write_only_for_the_control_group) {
    TrTmp t;
    fs::path f = t.file("server.toml");
    fs::permissions(f, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::group_write);
    CHECK(!untrusted_writer_reason(f.u8string(), {}).empty());           // group write, no control group
    CHECK(!untrusted_writer_reason(f.u8string(), {"@no-such-group-xyz"}).empty());
    // a symbolic link is refused
    fs::path link = t.p / "link.toml";
    fs::create_symlink(f, link);
    CHECK(untrusted_writer_reason(link.u8string(), {}).find("symbolic link") != std::string::npos);
    // a sticky world-writable folder (like /tmp) is fine when the file itself is private
    TrTmp s;
    fs::path sf = s.file("a.toml");
    CHECK_EQ(::chmod(s.p.c_str(), 01777), 0);
    CHECK_EQ(untrusted_writer_reason(s.p.u8string(), {}), std::string());
    require_trusted_config(sf.u8string(), {});
}

TEST(gui_trust_posix_executable_rules) {
    TrTmp t;
    fs::path exe = t.file("mysync");
    CHECK(!untrusted_executable_reason(exe.u8string()).empty());  // not in a root-owned, non-writable tree
    CHECK(!untrusted_executable_reason("/no/such/mysync").empty());
    if (::geteuid() == 0 && fs::exists("/usr/bin/env") && !fs::is_symlink("/usr/bin/env"))
        CHECK_EQ(untrusted_executable_reason("/usr/bin/env"), std::string());
    // a path that reaches a root-owned file through a symlink is refused
    fs::path link = t.p / "mysync-link";
    fs::create_symlink("/usr/bin/env", link);
    CHECK(!untrusted_executable_reason(link.u8string()).empty());
}
#endif

TEST(gui_service_run_refuses_an_untrusted_executable_without_running_it) {
    TrTmp t;
#ifdef _WIN32
    fs::path exe = t.file("mysync.exe");
#else
    fs::path exe = t.file("mysync");
    fs::permissions(exe, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read |
                             fs::perms::others_exec);
#endif
    ServiceController sc(exe.u8string());
    ServiceRequest r;
    r.name = "mysync-trust-test-never";
    ServiceResult res = sc.run(ServiceAction::Start, r);
    CHECK(!res.ok);
    CHECK(!res.cancelled);
    CHECK_EQ(res.exit_code, int(kServiceAccessDenied));
    CHECK(res.message.find("Refusing to run with elevated rights") != std::string::npos);
}

TEST(gui_service_control_allow_entry_syntax) {
    CHECK(valid_control_allow_entry("S-1-5-21-1-2-3-1001"));
    CHECK(valid_control_allow_entry("CORP\\alice"));
    CHECK(valid_control_allow_entry("alice"));
    for (const char* bad : {"", "-x", "a\"b", "a'b", "a`b", "a\nb"}) CHECK(!valid_control_allow_entry(bad));
    CHECK(!valid_control_allow_entry(std::string(257, 'a')));
}

TEST(gui_ipc_pipe_rights_for_allowed_principals_exclude_instance_creation) {
    std::string s = detail::ipc_pipe_sddl({"S-1-5-21-1-2-3-1001"}, "S-1-5-21-1-2-3-1000");
    CHECK(s.find("(A;;0x12019b;;;S-1-5-21-1-2-3-1001)") != std::string::npos);  // read/write, no CREATE_PIPE_INSTANCE
    CHECK(s.find("(A;;GRGW;;;S-1-5-21-1-2-3-1000)") != std::string::npos);      // the daemon's own account creates instances
    CHECK(s.find("0x12019b") != std::string::npos);
    CHECK_EQ(0x0012019Fu & ~0x4u, 0x0012019Bu);
}

TEST(gui_trust_whitelist_rejects_an_ordinary_user_account) {
    // As a service account would see it: the file belongs to a normal user, who is NOT in the trusted set.
    TrTmp t;
    fs::path f = t.file("server.toml");
    std::string why = untrusted_writer_reason(f.u8string(), {}, /*include_self=*/false);
#ifdef _WIN32
    CHECK(!why.empty());  // the user-owned file in the user profile is not SYSTEM/Administrators/TrustedInstaller
    CHECK(untrusted_writer_reason(f.u8string(), {}, true).empty());  // but it is fine for that very user
#else
    if (::geteuid() != 0) CHECK(!why.empty());
    (void)why;
#endif
}

#ifdef _WIN32
TEST(gui_trust_windows_extra_writer_is_only_what_the_administrator_names) {
    TrTmp t;
    fs::path f = t.file("server.toml");
    // the account that owns the file, named explicitly by the administrator, becomes acceptable
    HANDLE tok = nullptr;
    CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok));
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::vector<uint8_t> buf(len);
    CHECK(GetTokenInformation(tok, TokenUser, buf.data(), len, &len));
    CloseHandle(tok);
    LPWSTR s = nullptr;
    CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s));
    std::wstring w(s);
    LocalFree(s);
    std::string me(w.begin(), w.end());
    CHECK(!untrusted_writer_reason(f.u8string(), {}, false).empty());
    CHECK(untrusted_writer_reason(f.u8string(), {me}, false).empty());
}
#else
TEST(gui_trust_posix_owner_and_group_from_the_administrator_list) {
    if (::geteuid() != 0) return;  // needs chown
    TrTmp t;
    fs::path f = t.file("server.toml");
    CHECK_EQ(::chown(f.c_str(), 1234, 4321), 0);
    fs::permissions(f, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read);
    // a file the unprivileged GUI user saved: owner is that user
    CHECK(!untrusted_writer_reason(f.u8string(), {}).empty());
    CHECK(!untrusted_writer_reason(f.u8string(), {"uid:99"}).empty());
    CHECK(untrusted_writer_reason(f.u8string(), {"uid:1234"}).empty());
    // group write is accepted only for a trusted group
    fs::permissions(f, fs::perms::group_write, fs::perm_options::add);
    CHECK(!untrusted_writer_reason(f.u8string(), {"uid:1234"}).empty());
    CHECK(untrusted_writer_reason(f.u8string(), {"uid:1234", "gid:4321"}).empty());
    // other-write is never acceptable
    fs::permissions(f, fs::perms::others_write, fs::perm_options::add);
    CHECK(!untrusted_writer_reason(f.u8string(), {"uid:1234", "gid:4321"}).empty());
    // the file cannot enlarge the set by itself: control entries in the file are not an input of this function
    CHECK(valid_trust_writer_entry("uid:1234"));
    CHECK(!valid_trust_writer_entry("-x"));
    CHECK(!valid_trust_writer_entry("a\"b"));
}
#endif

TEST(gui_service_build_args_carries_trust_writers) {
    TrTmp t;
#ifdef _WIN32
    fs::path exe = t.file("mysync.exe");
#else
    fs::path exe = t.file("mysync");
    fs::permissions(exe, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read |
                             fs::perms::others_exec);
#endif
    ServiceController sc(exe.u8string());
    fs::path cfg = t.file("c.toml");
    ServiceRequest r;
    r.name = "n";
    r.config_path = cfg.u8string();
    r.trust_writers = {"CORP-ops"};
    auto a = sc.build_args(ServiceAction::Install, r);
    CHECK(std::find(a.begin(), a.end(), std::string("--trust-writer")) != a.end());
    r.trust_writers = {"a\"b"};
    CHECK_THROWS(sc.build_args(ServiceAction::Install, r));
}
