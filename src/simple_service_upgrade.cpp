// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/service_upgrade.h"

#include <cctype>
#include <climits>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <iostream>
#include <sstream>

#include "mysync/config.h"
#include "mysync/gui/config_io.h"
#include "mysync/gui/key_mgr.h"
#include "mysync/gui/trust.h"
#include "mysync/hash.h"
#include "mysync/keys.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace mysync::simple {

const char* upgrade_step_name(UpgradeStep s) {
    switch (s) {
        case UpgradeStep::Preconditions: return "preconditions";
        case UpgradeStep::StopUserEngine: return "stop-user-engine";
        case UpgradeStep::MigrateConfig: return "migrate-config";
        case UpgradeStep::InstallService: return "install-service";
        case UpgradeStep::StartTheService: return "start-service";
        case UpgradeStep::StopService: return "stop-service";
        case UpgradeStep::UninstallService: return "uninstall-service";
        case UpgradeStep::RestoreConfig: return "restore-config";
        case UpgradeStep::StartUserEngine: return "start-user-engine";
        case UpgradeStep::Done: return "done";
    }
    return "?";
}

InvokerResult resolve_invoking_uid(const InvokerInput& in) {
    InvokerResult r;
    if (in.uid != 0 || in.euid != 0) {  // not root: nothing was elevated, the variables are just the caller's own text
        r.ok = true;
        r.uid = in.euid;
        return r;
    }
    auto num = [](const std::string& t, uint32_t* v) { return !t.empty() && gui::detail::parse_numeric_id(t, *v); };
    uint32_t pk = 0, su = 0;
    bool have_pk = num(in.pkexec_uid, &pk), have_su = num(in.sudo_uid, &su);
    if ((!in.pkexec_uid.empty() && !have_pk) || (!in.sudo_uid.empty() && !have_su)) {
        r.error = "PKEXEC_UID / SUDO_UID is not a plain number: refusing";
        return r;
    }
    if (have_pk && have_su && pk != su) {
        r.error = "PKEXEC_UID and SUDO_UID disagree: refusing to guess who asked for this";
        return r;
    }
    if (!have_pk && !have_su) {
        r.error = "cannot tell which user asked for this (run it through the application, which uses pkexec)";
        return r;
    }
    r.uid = have_pk ? pk : su;
    if (r.uid == 0) {
        r.error = "the requesting user is root: a personal configuration of root is not migrated this way";
        return r;
    }
    if (in.file_owner >= 0 && static_cast<uint32_t>(in.file_owner) != r.uid) {
        r.error = "the configuration file is not owned by the user who asked for this";
        return r;
    }
    if (in.loginuid >= 0 && in.loginuid != 4294967295LL && static_cast<uint32_t>(in.loginuid) != r.uid)
        r.warning = "the login uid (" + std::to_string(in.loginuid) + ") differs from the requesting user (su / ssh session?)";
    r.ok = true;
    return r;
}

namespace {

// Runs steps in order; every step registers its undo BEFORE it runs (a half-done step must be undone too), except that a
// step the user cancelled changed nothing, so its own undo is dropped (no second prompt after a "Cancel").
// On failure the undos run in reverse order, each guarded; what could not be undone is told verbatim.
class Run {
public:
    Run(const std::function<void(UpgradeStep)>& progress) : progress_(progress) {}

    bool step(UpgradeStep st, const std::function<void(bool*)>& body, const char* undo_name = nullptr,
              std::function<void()> undo = {}) {
        if (progress_) progress_(st);
        r_.log.push_back(std::string("step: ") + upgrade_step_name(st));
        if (undo_name) undo_.push_back({undo_name, std::move(undo)});
        bool cancelled = false;
        try {
            body(&cancelled);
        } catch (const std::exception& e) {
            fail(st, e.what());
            return false;
        }
        if (cancelled) {
            if (undo_name) undo_.pop_back();
            r_.cancelled = true;
            r_.failed_step = st;
            r_.error = "cancelled by the user";
            r_.log.push_back(std::string("cancelled at ") + upgrade_step_name(st));
            unwind();
            return false;
        }
        return true;
    }

    void fail(UpgradeStep st, const std::string& msg) {
        r_.failed_step = st;
        r_.error = msg;
        r_.log.push_back(std::string("failed at ") + upgrade_step_name(st) + ": " + msg);
        unwind();
    }

    void note(const std::string& line) { r_.log.push_back(line); }
    UpgradeResult finish_ok() {
        r_.ok = true;
        r_.failed_step = UpgradeStep::Done;
        r_.log.push_back("done");
        return r_;
    }
    UpgradeResult result() { return r_; }

private:
    void unwind() {
        std::string errs;
        while (!undo_.empty()) {
            auto u = std::move(undo_.back());
            undo_.pop_back();
            r_.log.push_back(std::string("undo: ") + u.first);
            try {
                u.second();
            } catch (const std::exception& e) {
                errs += std::string(errs.empty() ? "" : "; ") + u.first + ": " + e.what();
            }
        }
        r_.rollback_error = errs;
        r_.rolled_back = errs.empty();
    }

    const std::function<void(UpgradeStep)>& progress_;
    UpgradeResult r_;
    std::vector<std::pair<const char*, std::function<void()>>> undo_;
};

}  // namespace

UpgradeResult upgrade_to_service(UpgradeSteps& s, const std::function<void(UpgradeStep)>& progress) {
    Run run(progress);
    if (!run.step(UpgradeStep::Preconditions, [&](bool*) {
            std::string why = s.check_preconditions(true);
            if (!why.empty()) throw Error(why);
        }))
        return run.result();
    // From here on, the user engine must come back if anything fails.
    if (!run.step(UpgradeStep::StopUserEngine, [&](bool*) { s.stop_user_engine(); }, "start the user engine again",
                  [&] { s.start_user_engine(); }))
        return run.result();
    if (!run.step(UpgradeStep::MigrateConfig, [&](bool* c) { s.migrate_config_to_service(c); },
                  "remove the migrated configuration", [&] { s.remove_migrated_config(); }))
        return run.result();
    if (!run.step(UpgradeStep::InstallService, [&](bool* c) { s.install_service(c); }, "uninstall the service", [&] {
            bool c = false;
            if (s.service_installed()) s.uninstall_service(&c);  // a failed install may have left nothing behind
        }))
        return run.result();
    if (!run.step(UpgradeStep::StartTheService,
                  [&](bool* c) {
                      s.start_service(c);
                      if (!*c && !s.service_running()) throw Error("the service was started but is not running");
                  },
                  "stop the service", [&] {
                      bool c = false;
                      if (s.service_running()) s.stop_service(&c);
                  }))
        return run.result();
    return run.finish_ok();
}

UpgradeResult downgrade_to_user(UpgradeSteps& s, const std::function<void(UpgradeStep)>& progress,
                                const DowngradeOptions& opts) {
    Run run(progress);
    if (!run.step(UpgradeStep::Preconditions, [&](bool*) {
            std::string why = s.check_preconditions(false);
            if (!why.empty()) throw Error(why);
        }))
        return run.result();
    if (!run.step(UpgradeStep::StopService, [&](bool* c) { s.stop_service(c); }, "start the service again", [&] {
            bool c = false;
            if (s.service_installed() && !s.service_running()) s.start_service(&c);
        }))
        return run.result();
    if (!run.step(UpgradeStep::UninstallService, [&](bool* c) { s.uninstall_service(c); }, "install the service again", [&] {
            bool c = false;
            if (!s.service_installed()) s.install_service(&c);
        }))
        return run.result();
    if (!run.step(UpgradeStep::RestoreConfig, [&](bool*) { s.restore_config_from_service(); })) return run.result();
    // Never two engines: the service must be gone before the user engine starts.
    if (!run.step(UpgradeStep::StartUserEngine,
                  [&](bool*) {
                      if (s.service_running()) throw Error("the service is still running");
                      s.start_user_engine();
                  },
                  "stop the user engine", [&] { s.stop_user_engine(); }))
        return run.result();
    if (opts.remove_service_copy) {  // best effort: the switch itself succeeded
        try {
            s.remove_migrated_config();
            run.note("removed the service copy of the configuration and the key");
        } catch (const std::exception& e) {
            run.note(std::string("could not remove the service copy: ") + e.what());
        }
    }
    return run.finish_ok();
}

// ================================================================================================ locations
ServiceLocations service_locations(const std::string& name) {
    ServiceLocations l;
#ifdef _WIN32
    const char* pd = std::getenv("ProgramData");
    fs::path base = fs::u8path(pd && *pd ? pd : "C:\\ProgramData") / "MySync" / fs::u8path(name);
    l.dir = base.u8string();
    l.config = (base / "config.toml").u8string();
    l.key = (base / "key").u8string();
    l.state = (base / "state").u8string();
    l.log = (base / "log" / "client.log").u8string();
#else
    l.dir = "/etc/mysync";
    l.config = "/etc/mysync/" + name + ".toml";
    l.key = "/etc/mysync/" + name + ".key";
    l.state = "/var/lib/mysync/" + name;
    l.log = "/var/lib/mysync/" + name + "/mysync.log";
#endif
    return l;
}

// ================================================================================================ migration
namespace {

bool name_ok(const std::string& n) { return gui::ServiceController::valid_name(n); }

#ifdef _WIN32
std::string lower_s(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
#endif

std::string norm_key(const fs::path& p) {
    std::string s = p.lexically_normal().generic_u8string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
#ifdef _WIN32
    s = lower_s(s);
#endif
    return s;
}

bool inside_or_equal(const fs::path& a, const fs::path& root) {
    std::string ka = norm_key(a), kr = norm_key(root);
    if (kr.empty()) return false;
    if (ka == kr) return true;
    if (ka.size() <= kr.size() || ka.compare(0, kr.size(), kr) != 0) return false;
    return kr.back() == '/' || ka[kr.size()] == '/';
}

#ifdef _WIN32
// Administrators + SYSTEM only, protected, inherited by everything created inside. An existing folder must already be
// trusted (nobody else may have created it first).
void make_admin_dir(const fs::path& dir) {
    std::error_code ec;
    if (fs::exists(dir, ec)) {
        std::string why = gui::untrusted_writer_reason(dir.u8string(), {}, /*include_self=*/true);
        if (!why.empty()) throw Error("the folder '" + dir.u8string() + "' already exists and " + why);
        return;
    }
    fs::path parent = dir.parent_path();
    if (!fs::exists(parent, ec)) make_admin_dir(parent);
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", SDDL_REVISION_1, &psd,
                                                              nullptr))
        throw Error("cannot build the administrator-only permissions");
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = psd;
    BOOL ok = CreateDirectoryW(dir.c_str(), &sa);
    DWORD err = GetLastError();
    LocalFree(psd);
    if (!ok && err != ERROR_ALREADY_EXISTS)
        throw Error("cannot create '" + dir.u8string() + "' (error " + std::to_string(err) + ")");
    std::string why = gui::untrusted_writer_reason(dir.u8string(), {}, true);
    if (!why.empty()) throw Error("the folder '" + dir.u8string() + "' " + why);
}

bool reparse_or_missing_attr(const fs::path& p, bool* exists) {
    DWORD a = GetFileAttributesW(p.c_str());
    *exists = a != INVALID_FILE_ATTRIBUTES;
    return *exists && (a & FILE_ATTRIBUTE_REPARSE_POINT);
}

std::string env_u8(const char* n) {
    const char* v = std::getenv(n);
    return v ? std::string(v) : std::string();
}
#else
// The user behind a pkexec / sudo launch: resolve_invoking_uid on the real environment. `file` (optional) is the
// configuration being migrated: its owner must be that user.
InvokerInput invoker_input(const std::string& file) {
    InvokerInput in;
    const char* sp = std::getenv("SUDO_UID");
    const char* pp = std::getenv("PKEXEC_UID");
    in.sudo_uid = sp ? sp : "";
    in.pkexec_uid = pp ? pp : "";
    in.uid = ::getuid();
    in.euid = ::geteuid();
    std::ifstream lf("/proc/self/loginuid");
    long long l = -1;
    if (lf >> l) in.loginuid = l;
    struct stat st{};
    if (!file.empty() && ::lstat(file.c_str(), &st) == 0) in.file_owner = static_cast<int64_t>(st.st_uid);
    return in;
}

// Whose files the checked reads accept. In the elevated step it is the user resolved from PKEXEC_UID / SUDO_UID
// (OwnerScope); everywhere else (the GUI building a summary, tests) it is simply this very process' user.
thread_local bool tl_owner_set = false;
thread_local uid_t tl_owner = 0;
uid_t owner_uid() { return tl_owner_set ? tl_owner : ::geteuid(); }
struct OwnerScope {
    explicit OwnerScope(uid_t u) {
        tl_owner_set = true;
        tl_owner = u;
    }
    ~OwnerScope() { tl_owner_set = false; }
};

void make_admin_dir(const fs::path& dir) {
    std::error_code ec;
    struct stat lst{};
    if (::lstat(dir.c_str(), &lst) == 0) {  // already there: it must already be ours, never taken over
        std::string why = gui::untrusted_writer_reason(dir.string(), {}, true);
        if (!why.empty()) throw Error("the folder '" + dir.string() + "' already exists and " + why);
        if (lst.st_uid != 0) throw Error("the folder '" + dir.string() + "' is not owned by root");
        return;
    }
    fs::create_directories(dir, ec);
    struct stat st{};
    if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) throw Error("cannot create '" + dir.string() + "'");
    if (::chown(dir.c_str(), 0, 0) != 0 || ::chmod(dir.c_str(), 0700) != 0)
        throw Error("cannot make '" + dir.string() + "' private to root");
}
#endif

// Any existing component of `p` that is a symbolic link / junction / reparse point.
std::string link_in_path(const fs::path& p) {
    fs::path cur;
    for (const auto& part : p) {
        cur /= part;
        if (cur == cur.root_path()) continue;
#ifdef _WIN32
        bool exists = false;
        if (reparse_or_missing_attr(cur, &exists)) return cur.u8string();
        if (!exists) break;
#else
        struct stat st{};
        if (::lstat(cur.c_str(), &st) != 0) break;
        if (S_ISLNK(st.st_mode)) return cur.string();
#endif
    }
    return {};
}

// Reads a small file of the user's with every check made on the OPEN handle (no check-then-open gap): not a link, a
// regular file, owned by the user who asked. Used for the configuration and for the key.
std::string read_user_file_checked(const std::string& path, size_t max) {
#ifdef _WIN32
    HANDLE h = CreateFileW(fs::u8path(path).c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) throw Error("cannot open '" + path + "'");
    struct Closer { HANDLE h; ~Closer() { CloseHandle(h); } } closer{h};
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
        throw Error("'" + path + "' is a link or not a regular file");
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &psd) != ERROR_SUCCESS)
        throw Error("cannot read the owner of '" + path + "'");
    bool same = false;
    LPWSTR s = nullptr;
    if (ConvertSidToStringSidW(owner, &s)) {
        same = fs::path(std::wstring(s)).u8string() == current_user_sid();
        LocalFree(s);
    }
    LocalFree(psd);
    if (!same) throw Error("'" + path + "' belongs to another account: run the GUI as the account that owns it");
    std::string out;
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof buf, &n, nullptr) && n > 0) {
        out.append(buf, n);
        if (out.size() > max) throw Error("'" + path + "' is too large");
    }
    return out;
#else
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw Error("cannot open '" + path + "' (a link, or not readable)");
    struct Closer { int fd; ~Closer() { ::close(fd); } } closer{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) throw Error("'" + path + "' is not a regular file");
    if (st.st_uid != owner_uid()) throw Error("'" + path + "' is not owned by the user who asked for this");
    std::string out;
    char buf[4096];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        out.append(buf, size_t(n));
        if (out.size() > max) throw Error("'" + path + "' is too large");
    }
    return out;
#endif
}

std::string lower_hex(std::string h) {
    for (auto& c : h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return h;
}

std::string hash_of(const std::string& bytes) { return hash_hex(hash_bytes(bytes.data(), bytes.size())); }

KeyPair read_user_key(const std::string& path, const std::string& expect_hash) {
    std::string text = read_user_file_checked(path, 4096);
    if (!expect_hash.empty() && lower_hex(hash_of(text)) != lower_hex(expect_hash)) {
        secure_wipe(text.data(), text.size());
        throw Error("the key file changed after you saw the summary: nothing was copied");
    }
#ifndef _WIN32
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0 && (st.st_mode & 077) != 0) {
        secure_wipe(text.data(), text.size());
        throw Error("the key file '" + path + "' must have no access for others");
    }
#endif
    PubKey sk;
    try {
        sk = key_from_hex(text);
    } catch (...) {
        secure_wipe(text.data(), text.size());
        throw Error("invalid key file (expected 64 hex characters)");
    }
    secure_wipe(text.data(), text.size());
    KeyPair kp = keypair_from_secret(sk);
    secure_wipe(sk.data(), sk.size());
    return kp;
}

// Everything in a user configuration that the service (a different, far more powerful account) would act on, checked.
// `cfg` has absolute paths. Appends one sentence per problem.
void check_for_service(const ClientConfig& cfg, const std::string& user_key, const fs::path& udir, const PathPolicy& pol,
                       std::vector<std::string>* problems, std::vector<std::string>* confirm) {
    auto bad = [&](const std::string& m) { problems->push_back(m); };
    for (const auto& r : pol.allow_roots) {
        std::string why = allow_root_problem(r, pol);
        if (!why.empty()) bad("the allowed folder '" + r + "' " + why);
    }
    if (!inside_or_equal(fs::u8path(user_key), udir)) bad("the key '" + user_key + "' is not in your MySync folder");
    {
        std::string l = link_in_path(fs::u8path(user_key));
        if (!l.empty()) bad("the key path goes through a link ('" + l + "')");
    }
    auto check_path = [&](const char* what, const std::string& path) {
        PathVerdict v = service_path_verdict(path, pol);
        if (v.ok) {
            std::string l = link_in_path(fs::u8path(path));
            if (!l.empty()) bad(std::string(what) + " '" + path + "': '" + l + "' is a link");
            return;
        }
        if (v.confirmable && confirm) {
            confirm->push_back(path);
            return;
        }
        bad(std::string(what) + ": " + v.reason);
    };
    for (const auto& w : cfg.watches) {
        check_path("folder", w.path);
        for (const auto& t : w.targets) {
            if (t.is_local()) check_path("destination", t.path);
            else if (!t.key_file.empty()) bad("a destination has its own key file, which the service does not support");
        }
    }
}

}  // namespace

PathPolicy default_path_policy() {
    PathPolicy p;
#ifdef _WIN32
    for (const char* v : {"SystemRoot", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"}) {
        std::string e = env_u8(v);
        if (!e.empty()) p.forbidden_roots.push_back(canonical_for_policy(e));
    }
    std::string home = env_u8("USERPROFILE");
    if (!home.empty()) {
        p.own_home = canonical_for_policy(home);
        p.homes_root = fs::u8path(p.own_home).parent_path().u8string();
    }
#else
    for (const char* r : {"/etc", "/usr", "/var", "/opt", "/srv", "/mnt", "/boot", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
                          "/dev", "/proc", "/sys", "/run", "/root"}) {
        p.forbidden_roots.push_back(canonical_for_policy(r));
    }
    struct passwd pw{}, *res = nullptr;
    char buf[4096];
    if (::getpwuid_r(owner_uid(), &pw, buf, sizeof buf, &res) == 0 && res && pw.pw_dir)
        p.own_home = canonical_for_policy(pw.pw_dir);
    p.homes_root = "/home";
#endif
    return p;
}

// The path as the operating system really sees it: the deepest existing ancestor is resolved (symbolic links, junctions,
// 8.3 names, "\\?\" prefixes), the part that does not exist yet is appended lexically.
std::string canonical_for_policy(const std::string& path) {
    fs::path p = fs::u8path(path);
    if (path.empty() || !p.is_absolute()) return path;
    p = p.lexically_normal();
    fs::path cur = p, rest;
    std::error_code ec;
    while (!fs::exists(cur, ec) && cur != cur.root_path() && cur.has_parent_path()) {
        rest = rest.empty() ? cur.filename() : cur.filename() / rest;
        cur = cur.parent_path();
    }
    std::string resolved = cur.u8string();
#ifdef _WIN32
    HANDLE h = CreateFileW(cur.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        std::wstring buf(1024, L'\0');
        DWORD n = GetFinalPathNameByHandleW(h, &buf[0], DWORD(buf.size()), VOLUME_NAME_DOS);
        if (n >= buf.size()) {
            buf.resize(n + 1);
            n = GetFinalPathNameByHandleW(h, &buf[0], DWORD(buf.size()), VOLUME_NAME_DOS);
        }
        CloseHandle(h);
        if (n > 0 && n < buf.size()) {
            buf.resize(n);
            if (buf.compare(0, 8, L"\\\\?\\UNC\\") == 0) buf = L"\\\\" + buf.substr(8);
            else if (buf.compare(0, 4, L"\\\\?\\") == 0) buf = buf.substr(4);
            resolved = fs::path(buf).u8string();
        }
    }
#else
    char rp[PATH_MAX];
    if (::realpath(cur.c_str(), rp)) resolved = rp;
#endif
    fs::path out = fs::u8path(resolved);
    if (!rest.empty()) out = (out / rest).lexically_normal();
    return out.u8string();
}

namespace {
bool is_unc(const fs::path& p) {
#ifndef _WIN32
    (void)p;
    return false;
#else
    std::string g = p.u8string();   // native spelling: std::filesystem is vague about UNC paths
    auto sep = [](char c) { return c == '/' || c == '\\'; };
    return g.size() > 2 && sep(g[0]) && sep(g[1]) && !sep(g[2]) && g[2] != '?';
#endif
}
bool is_fs_root(const fs::path& p) {
    fs::path n = p.lexically_normal();
    if (is_unc(n)) {   // \servershare is the root of a share
        std::string g = n.u8string();
        size_t seps = 0;
        for (size_t i = 2; i < g.size(); ++i)
            if (g[i] == '/' || g[i] == '\\') ++seps;
        return seps <= 1;
    }
    return n == n.root_path() || n.filename().empty();
}
}  // namespace

PathVerdict service_path_verdict(const std::string& path, const PathPolicy& pol) {
    PathVerdict v;
    fs::path raw = fs::u8path(path);
    if (path.empty() || !(raw.is_absolute() || is_unc(raw))) {
        v.reason = "the path is not absolute";
        return v;
    }
    fs::path c = fs::u8path(pol.canonicalize ? canonical_for_policy(path) : raw.lexically_normal().u8string());
    const std::string shown = "'" + path + "'" + (norm_key(c) == norm_key(raw) ? "" : " (really " + c.u8string() + ")");
    if (is_fs_root(c) && !is_unc(c)) {
        v.reason = shown + " is a whole drive / the root of the file system";
        return v;
    }
    bool in_home = !pol.own_home.empty() && inside_or_equal(c, fs::u8path(pol.own_home));
    if (!in_home) {
        for (const std::string& r : pol.forbidden_roots)
            if (!r.empty() && inside_or_equal(c, fs::u8path(r))) {
                v.reason = shown + " is inside a system folder (" + r + ")";
                return v;
            }
        if (!pol.homes_root.empty() && inside_or_equal(c, fs::u8path(pol.homes_root))) {
            v.reason = shown + " is the profiles folder or the profile of another user";
            return v;
        }
    }
    if (in_home) {
        v.ok = true;
        return v;
    }
    for (const std::string& r : pol.allow_roots) {
        fs::path ar = fs::u8path(pol.canonicalize ? canonical_for_policy(r) : r);
        if (inside_or_equal(c, ar)) {
            v.ok = true;
            return v;
        }
    }
    v.confirmable = true;
    v.reason = shown + " is outside your home folder" + (is_unc(c) ? " (a network share)" : "") +
               ": the service would work there with full rights; it must be confirmed explicitly";
    return v;
}

std::string forbidden_service_path_reason(const std::string& path, const PathPolicy& pol) {
    PathVerdict v = service_path_verdict(path, pol);
    return v.ok ? std::string() : v.reason;
}

std::string allow_root_problem(const std::string& root, const PathPolicy& pol) {
    PathPolicy strict = pol;
    strict.allow_roots.clear();
    PathVerdict v = service_path_verdict(root, strict);
    if (v.ok) return {};
    if (v.confirmable) return {};  // an ordinary folder outside the home: exactly what an allow root is for
    return "cannot be allowed: " + v.reason;
}

namespace {

// Loads and normalises a user configuration the way the migration will see it.
ClientConfig load_user_config_absolute(const std::string& config_path, std::string* user_key, fs::path* udir,
                                       const std::string& text) {
    ClientConfig c = parse_client_config_text(text);
    *udir = fs::u8path(config_path).parent_path();
    auto absolute = [&](std::string p) {
        if (p.empty()) return p;
        fs::path q = fs::u8path(p);
        return (q.is_absolute() ? q : *udir / q).lexically_normal().u8string();
    };
    *user_key = absolute(c.key_file);
    for (auto& w : c.watches) {
        w.path = absolute(w.path);
        for (auto& t : w.targets) {
            if (t.is_local()) t.path = absolute(t.path);
            else if (!t.key_file.empty()) t.key_file = absolute(t.key_file);
        }
    }
    return c;
}

}  // namespace

MigrationSummary summarize_user_config(const UserPaths& paths, const std::vector<std::string>& allow_roots) {
    MigrationSummary m;
    // The same checked, single read the elevated step makes; the hash pins these exact bytes.
    std::string text = read_user_file_checked(paths.client_config, 1 << 20);
    m.config_hash = hash_of(text);
    std::string user_key;
    fs::path udir;
    ClientConfig c = load_user_config_absolute(paths.client_config, &user_key, &udir, text);
    for (const auto& w : c.watches) {
        if (!w.enabled) continue;
        m.sources.push_back(w.path);
        for (const auto& t : w.targets)
            if (t.enabled) m.destinations.push_back(t.is_local() ? t.path : t.host + ":" + std::to_string(t.port));
    }
    try {
        std::string kt = read_user_file_checked(user_key, 4096);
        m.key_hash = hash_of(kt);
        secure_wipe(kt.data(), kt.size());
        m.key_identity = gui::KeyManager::fingerprint(gui::KeyManager::public_key_of_file(user_key));
    } catch (const std::exception&) {
        m.key_identity = "(unreadable key)";
        m.problems.push_back("the key file cannot be read");
    }
#ifdef _WIN32
    m.service_account = "LocalSystem";
#else
    m.service_account = "root";
#endif
    m.warnings.push_back("The service runs as " + m.service_account +
                         " and will read and write the folders above with the rights of the whole computer, even when nobody is logged in.");
    m.warnings.push_back("Your key is copied to the service folder (administrators only); remove it when you go back to the personal mode if you wish.");
    PathPolicy pol = default_path_policy();
    pol.allow_roots = allow_roots;
    check_for_service(c, user_key, udir, pol, &m.problems, &m.needs_confirmation);
    return m;
}

MigrationPlan plan_migration(const std::string& user_config, const std::string& expect_hash, const std::string& expect_key_hash,
                             const std::vector<std::string>& allow_roots) {
    fs::path up = fs::u8path(user_config);
    if (!up.is_absolute()) throw Error("the user configuration path must be absolute");
    std::string link = link_in_path(up);
    if (!link.empty()) throw Error("'" + link + "' is a link: refusing");
    uint32_t who_uid = 0;
#ifndef _WIN32
    std::optional<OwnerScope> scope;
    {   // who asked: PKEXEC_UID is trusted only in a root process, and only if that user owns the file (resolve_invoking_uid)
        InvokerResult who = resolve_invoking_uid(invoker_input(user_config));
        if (!who.ok) throw Error(who.error);
        if (!who.warning.empty()) std::cerr << "mysync: warning: " << who.warning << "\n";
        scope.emplace(static_cast<uid_t>(who.uid));
        who_uid = who.uid;
    }
#endif
    // One open, every check on that handle (not a link, regular, owned by the user who asked).
    std::string text = read_user_file_checked(user_config, 1 << 20);
    // The bytes now in memory are the ONLY source of everything below (no second read of the file): they must be the
    // bytes whose summary the user approved.
    if (lower_hex(hash_of(text)) != lower_hex(expect_hash))
        throw Error("the configuration was changed after you saw the summary: nothing was done. Open the window again and review it.");
    MigrationPlan plan;
    fs::path udir;
    plan.config = load_user_config_absolute(user_config, &plan.user_key, &udir, text);  // throws with the line number
    bool any = false;
    for (const auto& w : plan.config.watches)
        if (w.enabled && !w.targets.empty()) any = true;
    if (!any) throw Error("the configuration has no enabled folder with a destination");
    // The service will act on this content with far more rights than the user has: look at it again here, in the
    // elevated process, whatever the GUI showed.
    std::vector<std::string> problems, confirm;
    PathPolicy policy = default_path_policy();
    for (const auto& r : allow_roots) policy.allow_roots.push_back(r);
    check_for_service(plan.config, plan.user_key, udir, policy, &problems, &confirm);
    for (const auto& p : confirm) problems.push_back("'" + p + "' is outside your home folder and was not confirmed");
    if (!problems.empty()) {
        std::string all;
        for (const auto& p : problems) all += (all.empty() ? "" : "; ") + p;
        throw Error("refusing to run this configuration as a service: " + all);
    }
    plan.key = read_user_key(plan.user_key, expect_key_hash);
    plan.who = who_uid;
    return plan;
}

int run_migrate_from_user(const std::vector<std::string>& args) {
    std::string user_config, name = "mysync-client";
    bool remove = false;
    std::string expect_hash, expect_key_hash;
    std::vector<std::string> allow_roots;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--user-config" && i + 1 < args.size()) user_config = args[++i];
        else if (args[i] == "--expect-hash" && i + 1 < args.size()) expect_hash = args[++i];
        else if (args[i] == "--expect-key-hash" && i + 1 < args.size()) expect_key_hash = args[++i];
        else if (args[i] == "--allow-root" && i + 1 < args.size()) allow_roots.push_back(args[++i]);
        else if (args[i] == "--name" && i + 1 < args.size()) name = args[++i];
        else if (args[i] == "--remove") remove = true;
        else {
            std::cerr << "mysync: unknown argument '" << args[i] << "'\n";
            return gui::kServiceBadArguments;
        }
    }
    auto bad = [](const std::string& m, int code) {
        std::cerr << "mysync: " << m << "\n";
        return code;
    };
    try {
        if (!name_ok(name)) return bad("invalid service name", gui::kServiceBadArguments);
        if (!remove && user_config.empty())
            return bad("service migrate-from-user needs --user-config <file>", gui::kServiceBadArguments);
        if (!remove && (expect_hash.empty() || expect_key_hash.empty()))
            return bad("service migrate-from-user needs --expect-hash and --expect-key-hash (the hashes shown in the summary)",
                       gui::kServiceBadArguments);
        if (!gui::ServiceController::is_elevated())
            return bad("this step needs administrator rights", gui::kServiceAccessDenied);
        ServiceLocations loc = service_locations(name);
        if (remove) {
            // The private copy made by a migration (configuration, its backup, key). The folder must already be ours.
            std::error_code ec;
            if (!fs::exists(fs::u8path(loc.dir), ec)) return 0;
            std::string why = gui::untrusted_writer_reason(loc.dir, {}, true);
            if (!why.empty()) return bad("the folder '" + loc.dir + "' " + why, gui::kServiceConfigError);
            for (const std::string& f : {loc.config, loc.config + ".bak", loc.key}) {
                fs::remove(fs::u8path(f), ec);
                if (ec) return bad("cannot remove '" + f + "': " + ec.message(), gui::kServiceGenericFailure);
            }
            std::cout << "removed the service copy of the configuration and key\n";
            return 0;
        }
        if (user_config.empty()) return bad("service migrate-from-user needs --user-config <file>", gui::kServiceBadArguments);
        MigrationPlan plan;
        try {
            plan = plan_migration(user_config, expect_hash, expect_key_hash, allow_roots);  // nothing is written before this passes
        } catch (const Error& e) {
            return bad(e.what(), gui::kServiceConfigError);
        }
        ClientConfig& c = plan.config;
        KeyPair& kp = plan.key;
        fs::path dir = fs::u8path(loc.dir);
        make_admin_dir(dir);
#ifndef _WIN32
        make_admin_dir(fs::u8path(loc.state).parent_path());
#endif
        make_admin_dir(fs::u8path(loc.state));
#ifdef _WIN32
        make_admin_dir(fs::u8path(loc.log).parent_path());
#endif
        // The key: a copy under the trusted folder (the service must not depend on the user's profile).
        std::error_code ec;
        fs::remove(fs::u8path(loc.key), ec);
        save_keypair(loc.key, kp);
        c.key_file = loc.key;
        c.state_dir = loc.state;
        c.log_file = loc.log;
        c.control_name.clear();  // the service answers under its own name
        c.control_allow.clear(); // who may control the service is decided by the administrator at install time
        c.control_group.clear();
#ifndef _WIN32
        {   // the user may talk to the daemon through the socket group of their own (private) group
            struct passwd pw{}, *res = nullptr;
            char buf[4096];
            if (::getpwuid_r(static_cast<uid_t>(plan.who), &pw, buf, sizeof buf, &res) == 0 && res) {
                struct group gr{}, *gres = nullptr;
                char gbuf[4096];
                if (::getgrgid_r(pw.pw_gid, &gr, gbuf, sizeof gbuf, &gres) == 0 && gres &&
                    gui::broad_principal_reason("@" + std::string(gr.gr_name)).empty())
                    c.control_group = gr.gr_name;
            }
        }
#endif
        std::string out = gui::serialize_client_config(c);
        parse_client_config_text(out);  // what we write must load
        gui::write_file_atomic(loc.config, out, /*keep_permissions=*/false);
#ifndef _WIN32
        ::chown(loc.config.c_str(), 0, 0);
        ::chmod(loc.config.c_str(), 0600);
        ::chown(loc.key.c_str(), 0, 0);
        ::chmod(loc.key.c_str(), 0600);
#endif
        // Fail now, not at service start: the result must satisfy the same trust rule the service applies.
        gui::require_trusted_config(loc.config, {}, /*include_self=*/false);
        std::cout << "configuration copied to " << loc.config << "\n";
        return 0;
    } catch (const Error& e) {
        return bad(e.what(), gui::kServiceConfigError);
    } catch (const std::exception& e) {
        return bad(e.what(), gui::kServiceGenericFailure);
    }
}

// ================================================================================================ real steps
namespace {

class RealSteps : public UpgradeSteps {
public:
    RealSteps(Supervisor& sup, gui::ServiceController& ctl, UserPaths paths, std::string name, std::vector<std::string> allow)
        : sup_(sup), ctl_(ctl), paths_(std::move(paths)), name_(std::move(name)), allow_roots_(std::move(allow)) {}

    std::string check_preconditions(bool to_service) override {
        if (!gui::ServiceController::valid_name(name_)) return "invalid service name";
        gui::ServiceState st = ctl_.query(name_);
        if (!st.error.empty()) return "cannot query the service: " + st.error;
        if (to_service) {
            std::error_code ec;
            if (!fs::is_regular_file(fs::u8path(paths_.client_config), ec))
                return "there is no configuration yet: finish the first-run wizard first";
            try {
                ClientConfig c = load_client_config(paths_.client_config);
                bool any = false;
                for (const auto& w : c.watches)
                    if (w.enabled && !w.targets.empty()) any = true;
                if (!any) return "the configuration has no enabled folder with a destination";
            } catch (const std::exception& e) {
                return std::string("the configuration cannot be used: ") + e.what();
            }
            try {
                MigrationSummary m = summarize_user_config(paths_, allow_roots_);
                if (!m.problems.empty()) return "the service would refuse this configuration: " + m.problems[0];
                if (!m.needs_confirmation.empty())
                    return "these folders are outside your home folder and need your explicit confirmation: " + m.needs_confirmation[0] +
                           (m.needs_confirmation.size() > 1 ? " (and " + std::to_string(m.needs_confirmation.size() - 1) + " more)" : "");
                summary_ = m;   // the migration uses exactly these bytes (hashes)
                have_summary_ = true;
            } catch (const std::exception& e) {
                return e.what();
            }
            if (st.installed) return "a service named '" + name_ + "' is already installed";
        } else if (!st.installed) {
            return "the service '" + name_ + "' is not installed";
        }
        return {};
    }

    void stop_user_engine() override {
        sup_.set_client_enabled(false);
        if (!sup_.wait_stopped(EngineKind::Client, 20000))
            throw Error("the sync engine did not stop in time (its folders are still locked)");
    }
    void start_user_engine() override {
        sup_.set_client_enabled(true);
        sup_.restart(EngineKind::Client);
    }

    void migrate_config_to_service(bool* cancelled) override {
        gui::ServiceRequest rq;
        rq.name = name_;
        rq.user_config = paths_.client_config;
        if (!have_summary_) throw Error("the configuration was not reviewed first (no summary)");
        rq.expect_config_hash = summary_.config_hash;
        rq.expect_key_hash = summary_.key_hash;
        rq.allow_roots = allow_roots_;
        done(ctl_.run(gui::ServiceAction::MigrateFromUser, rq), cancelled);
    }
    // The copy in the service folder is private to administrators and is reused by the next attempt: leaving it is
    // harmless, and removing it would need one more elevation prompt in the middle of a failure.
    void remove_migrated_config() override {
        gui::ServiceRequest rq;
        rq.name = name_;
        rq.remove_migrated = true;
        bool cancelled = false;
        done(ctl_.run(gui::ServiceAction::MigrateFromUser, rq), &cancelled);
        if (cancelled) throw Error("the removal of the service copy was cancelled; it stays in " + service_locations(name_).dir);
    }

    void install_service(bool* cancelled) override {
        gui::ServiceRequest rq;
        rq.name = name_;
        rq.config_path = service_locations(name_).config;
        rq.role = "client";
#ifdef _WIN32
        rq.run_as = "LocalSystem";  // must read the user's folders; LocalService cannot
        std::string sid = current_user_sid();
        if (!sid.empty()) rq.control_allow.push_back(sid);  // lets this user's GUI talk to the service
#endif
        done(ctl_.run(gui::ServiceAction::Install, rq), cancelled);
    }
    void uninstall_service(bool* cancelled) override { simple_action(gui::ServiceAction::Uninstall, cancelled); }
    void start_service(bool* cancelled) override { simple_action(gui::ServiceAction::Start, cancelled); }
    void stop_service(bool* cancelled) override { simple_action(gui::ServiceAction::Stop, cancelled); }

    // The user's own configuration was never touched by the upgrade, so going back needs no copy.
    void restore_config_from_service() override {
        std::error_code ec;
        if (!fs::is_regular_file(fs::u8path(paths_.client_config), ec))
            throw Error("your configuration file '" + paths_.client_config + "' is missing; the service copy is in " +
                        service_locations(name_).config);
    }
    bool service_running() override { return ctl_.query(name_).running; }
    bool service_installed() override { return ctl_.query(name_).installed; }

private:
    void simple_action(gui::ServiceAction a, bool* cancelled) {
        gui::ServiceRequest rq;
        rq.name = name_;
        done(ctl_.run(a, rq), cancelled);
    }
    static void done(const gui::ServiceResult& r, bool* cancelled) {
        if (r.cancelled) { *cancelled = true; return; }
        if (!r.ok) throw Error(r.message.empty() ? gui::service_exit_message(r.exit_code) : r.message);
    }

    Supervisor& sup_;
    gui::ServiceController& ctl_;
    UserPaths paths_;
    std::string name_;
    std::vector<std::string> allow_roots_;
    MigrationSummary summary_;
    bool have_summary_ = false;
};

}  // namespace

std::unique_ptr<UpgradeSteps> make_real_upgrade_steps(Supervisor& sup, gui::ServiceController& ctl, const UserPaths& paths,
                                                      const std::string& service_name,
                                                      const std::vector<std::string>& allow_roots) {
    return std::make_unique<RealSteps>(sup, ctl, paths, service_name, allow_roots);
}

}  // namespace mysync::simple
