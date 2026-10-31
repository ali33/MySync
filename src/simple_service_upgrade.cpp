// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/service_upgrade.h"

#include <cctype>
#include <cstring>
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
#include "mysync/linkcheck.h"
#include "mysync/keys.h"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <knownfolders.h>
#include <sddl.h>
#include <shlobj.h>
#else
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
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
    if (in.uid != 0 && in.euid == 0) {  // a setuid-root program: the environment is whatever the caller put there
        r.error = "running setuid: cannot tell who asked for this (the environment cannot be trusted)";
        return r;
    }
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
    // from the system, not from an environment variable the user (or malware running as the user) could have set
    std::string pd;
    {
        PWSTR w = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &w)) && w) pd = fs::path(std::wstring(w)).u8string();
        CoTaskMemFree(w);
    }
    if (pd.empty()) pd = "C:\\ProgramData";
    fs::path base = fs::u8path(pd) / "MySync" / fs::u8path(name);
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

ServiceLocations user_service_locations(const std::string& name) {
#ifdef _WIN32
    return service_locations(name);   // %ProgramData%\MySync\<name>\ (the ACL differs: it includes the user)
#else
    ServiceLocations l;
    l.dir = "/var/lib/mysync/" + name;
    l.config = l.dir + "/config.toml";
    l.key = l.dir + "/key";
    l.state = l.dir + "/state";
    l.log = l.dir + "/mysync.log";
    return l;
#endif
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
struct DirOwner {
    std::string sid;        // Windows: the user the service runs as
    uint32_t uid = 0, gid = 0;   // POSIX
};

// Admin: Administrators + SYSTEM only. ServiceTop: the same, plus READ (and traverse) for the user the service runs as: the
// configuration and the key are readable by the service but writable only by an administrator - a service that runs as an
// administrator must not take its orders from a file a user-level process can edit. UserFull: the service's state / log
// folders, the only places the user may write.
using DirKind = ServiceDirKind;

// An existing (or just created) service folder is acceptable only if NOBODY but SYSTEM / Administrators / TrustedInstaller
// can change it - not even the account the service runs as, which is the user and could have made it first. (The one
// exception is a UserFull folder, which may also be writable by the service's owner.) Links on the way are refused.
void check_service_dir_trust(const fs::path& dir, const DirOwner* owner, DirKind kind) {
    std::string lk = link_component(dir.u8string());
    if (!lk.empty()) throw Error("the folder '" + dir.u8string() + "' goes through a link ('" + lk + "'): refusing");
    std::vector<std::string> trusted;
    if (owner && kind == DirKind::UserFull) trusted.push_back(owner->sid);
    std::string why = gui::untrusted_writer_reason(dir.u8string(), trusted, /*include_self=*/false);
    if (!why.empty()) throw Error("the folder '" + dir.u8string() + "' is not acceptable as the service's folder: it " + why);
}

void make_admin_dir(const fs::path& dir, const DirOwner* owner = nullptr, DirKind kind = DirKind::Admin) {
    std::error_code ec;
    // Our own parent ("...\MySync") is created and checked like everything else (a user could have made it first and then
    // swap the folders below it); the system folders above it (ProgramData) are the system's.
    fs::path parent = dir.parent_path();
    if (!parent.empty() && parent != dir && !fs::exists(parent, ec)) {
        if (parent.filename() == "MySync") make_admin_dir(parent);
        else throw Error("the folder '" + parent.u8string() + "' does not exist");
    }
    std::wstring sddl = fs::u8path(service_dir_sddl(owner ? kind : DirKind::Admin, owner ? owner->sid : std::string())).wstring();
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr))
        throw Error("cannot build the administrator-only permissions");
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = psd;
    BOOL ok = CreateDirectoryW(dir.c_str(), &sa);   // created WITH its protected ACL from the first instant
    DWORD err = GetLastError();
    LocalFree(psd);
    if (!ok && err != ERROR_ALREADY_EXISTS)
        throw Error("cannot create '" + dir.u8string() + "' (error " + std::to_string(err) + ")");
    // An older folder of ours is fine; one somebody else made is not (see check_service_dir_trust).
    check_service_dir_trust(dir, owner, kind);
    if (parent.filename() == "MySync" && parent != dir) check_service_dir_trust(parent, nullptr, DirKind::Admin);
}

// A new file written through a handle opened with CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT in an administrator-only folder,
// then moved over the old one: the file system never follows a path somebody could have redirected.
void write_new_file_win(const std::string& path, const std::string& data) {
    fs::path p = fs::u8path(path);
    uint8_t r[6];
    random_bytes(r, sizeof r);
    fs::path tmp = p.parent_path() / (p.filename().u8string() + ".tmp-" + to_hex(r, sizeof r));
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) throw Error("cannot create '" + tmp.u8string() + "' (error " + std::to_string(GetLastError()) + ")");
    bool ok = true;
    size_t off = 0;
    while (ok && off < data.size()) {
        DWORD n = 0;
        ok = WriteFile(h, data.data() + off, DWORD(data.size() - off), &n, nullptr) && n > 0;
        off += n;
    }
    ok = ok && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || !MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str());
        throw Error("cannot write '" + path + "'");
    }
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

struct DirOwner {
    std::string sid;
    uint32_t uid = 0, gid = 0;
};

// ---------------------------------------------------------------------------------------------------------------------
// Writing the service's folder. NOTHING here follows a path that the user could have changed meanwhile.
//
// POSIX (root, via pkexec): the service folder is first made root-owned 0700 THROUGH A FILE DESCRIPTOR, after which the user
// can no longer rename or replace anything directly inside it; every file is created inside it with openat(O_EXCL |
// O_NOFOLLOW) and handed to the user with fchown() on the open descriptor; the folder itself goes to the user as the LAST
// step. There is no chown() / chmod() by path anywhere, and no recursion into directories the user already owned.
void install_service_files_posix(const ServiceLocations& loc, const DirOwner& owner, const std::string& config_text,
                                 const std::string* key_hex) {
    struct Fd {
        int fd;
        explicit Fd(int f = -1) : fd(f) {}
        ~Fd() { if (fd >= 0) ::close(fd); }
        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;
    };
    fs::path top = fs::u8path(loc.dir);
    fs::path mdir = top.parent_path();   // /var/lib/mysync
    std::error_code ec;
    fs::create_directories(mdir, ec);
    Fd mfd(::open(mdir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (mfd.fd < 0) throw Error("cannot open '" + mdir.string() + "' (a link, or not a folder)");
    struct stat st{};
    if (::fstat(mfd.fd, &st) != 0 || st.st_uid != 0 || (st.st_mode & 022) != 0)
        throw Error("'" + mdir.string() + "' must belong to root and not be writable by others");
    if (::fchmod(mfd.fd, 0711) != 0) throw Error("cannot set the mode of '" + mdir.string() + "'");   // names stay hidden
    const std::string leaf = top.filename().string();
    if (::mkdirat(mfd.fd, leaf.c_str(), 0700) != 0 && errno != EEXIST)
        throw Error("cannot create '" + top.string() + "': " + std::strerror(errno));
    Fd tfd(::openat(mfd.fd, leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (tfd.fd < 0) throw Error("'" + top.string() + "' is a link or not a folder: refusing");
    // A folder that already exists must be this user's own earlier service folder - or root's, holding only our own names
    // (an interrupted earlier run). Anything else (another account's, or one with foreign content) is refused BEFORE it is taken.
    {
        struct stat ts{};
        if (::fstat(tfd.fd, &ts) != 0) throw Error("cannot examine '" + top.string() + "'");
        if (ts.st_uid != static_cast<uid_t>(owner.uid)) {
            if (ts.st_uid != 0) throw Error("'" + top.string() + "' belongs to another account: refusing");
            int dfd = ::dup(tfd.fd);
            DIR* d = dfd >= 0 ? ::fdopendir(dfd) : nullptr;
            if (!d) {
                if (dfd >= 0) ::close(dfd);
                throw Error("cannot list '" + top.string() + "'");
            }
            std::string foreign;
            while (struct dirent* e = ::readdir(d)) {
                std::string n = e->d_name;
                if (n == "." || n == ".." || n == "config.toml" || n == "config.toml.bak" || n == "key" || n == "state") continue;
                foreign = n;
                break;
            }
            ::closedir(d);
            if (!foreign.empty()) throw Error("'" + top.string() + "' already holds '" + foreign + "' which is not ours: refusing");
        }
    }
    // From here the folder is root's: the user cannot put a link in it while we work.
    if (::fchown(tfd.fd, 0, 0) != 0 || ::fchmod(tfd.fd, 0700) != 0)
        throw Error("cannot take the folder '" + top.string() + "' (" + std::strerror(errno) + ")");
    auto drop = [&](const char* n) {
        if (::unlinkat(tfd.fd, n, 0) != 0 && errno != ENOENT)
            throw Error(std::string("cannot remove the old '") + n + "': " + std::strerror(errno));
    };
    drop("config.toml");
    drop("config.toml.bak");
    if (key_hex) drop("key");
    // state/: a new one is made for the user; one that already exists stays as it is (it is the user's own data, we do not
    // touch what is inside)
    if (::mkdirat(tfd.fd, "state", 0700) != 0 && errno != EEXIST) throw Error(std::string("cannot create state/: ") + std::strerror(errno));
    {
        Fd sfd(::openat(tfd.fd, "state", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (sfd.fd < 0) throw Error("state/ is a link or not a folder: refusing");
        struct stat ss{};
        if (::fstat(sfd.fd, &ss) != 0 || (ss.st_uid != 0 && ss.st_uid != static_cast<uid_t>(owner.uid)))
            throw Error("state/ belongs to somebody else: refusing");
        if (ss.st_uid == 0 && (::fchown(sfd.fd, owner.uid, owner.gid) != 0 || ::fchmod(sfd.fd, 0700) != 0))
            throw Error("cannot give state/ to the user");
    }
    auto put = [&](const char* name, const std::string& data) {
        Fd fd(::openat(tfd.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (fd.fd < 0) throw Error(std::string("cannot create '") + name + "': " + std::strerror(errno));
        struct stat fs_{};
        if (::fstat(fd.fd, &fs_) != 0 || !S_ISREG(fs_.st_mode) || fs_.st_nlink != 1) throw Error(std::string("'") + name + "' is not a plain new file");
        size_t off = 0;
        while (off < data.size()) {
            ssize_t n = ::write(fd.fd, data.data() + off, data.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw Error(std::string("cannot write '") + name + "'");
            off += size_t(n);
        }
        if (::fsync(fd.fd) != 0 || ::fchown(fd.fd, owner.uid, owner.gid) != 0 || ::fchmod(fd.fd, 0600) != 0)
            throw Error(std::string("cannot finish '") + name + "'");
    };
    if (key_hex) put("key", *key_hex);
    put("config.toml", config_text);
    // LAST: the folder itself goes to the user (through the descriptor).
    if (::fchown(tfd.fd, owner.uid, owner.gid) != 0) throw Error("cannot give the service folder to the user");
}
#endif

// Any existing component of `p` that is a symbolic link / junction / reparse point.
std::string link_in_path(const fs::path& p) { return link_component(p.u8string()); }

// Reads a small file of the user's with every check made on the OPEN handle (no check-then-open gap): not a link, a
// regular file, owned by the user who asked. Used for the configuration and for the key.
std::string read_user_file_checked(const std::string& path, size_t max, bool require_private = false) {
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
        same = fs::path(std::wstring(s)).u8string() == effective_user_sid();
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
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);   // a FIFO must not block us (it is refused below)
    if (fd < 0) throw Error("cannot open '" + path + "' (a link, or not readable)");
    struct Closer { int fd; ~Closer() { ::close(fd); } } closer{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) throw Error("'" + path + "' is not a regular file");
    if (st.st_uid != owner_uid()) throw Error("'" + path + "' is not owned by the user who asked for this");
    if (require_private && (st.st_mode & 077) != 0)   // on the open descriptor, not a second stat(path)
        throw Error("the key file '" + path + "' must have no access for group and others");
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

// Constant-time comparison of two hex digests (case-insensitive).
bool same_hex(const std::string& a, const std::string& b) {
    std::string x = lower_hex(a), y = lower_hex(b);
    return x.size() == y.size() && !x.empty() && ct_equal(x.data(), y.data(), x.size());
}

std::string hash_of(const std::string& bytes) { return hash_hex(hash_bytes(bytes.data(), bytes.size())); }

KeyPair read_user_key(const std::string& path, const std::string& expect_hash) {
    std::string text = read_user_file_checked(path, 4096, /*require_private=*/true);
    if (expect_hash.empty() || !same_hex(hash_of(text), expect_hash)) {
        secure_wipe(text.data(), text.size());
        throw Error("the key file changed after you saw the summary: nothing was copied");
    }
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
    if (!user_key.empty()) {   // (empty: the key is not being copied, e.g. a configuration change only)
        if (!inside_or_equal(fs::u8path(user_key), udir)) bad("the key '" + user_key + "' is not in your MySync folder");
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

ServiceDirKind data_dir_kind_for_account(const std::string& user_sid) {
    // d8: the engine runs with a restricted, medium-integrity token of the account itself - it can do no more through state/ and
    // log/ than the user can anyway - so these two folders are the account's to write (the frame, with the fuller token, only reads).
    if (valid_user_sid(user_sid)) return ServiceDirKind::UserFull;
    return ServiceDirKind::ServiceTop;
}

std::string service_dir_sddl(ServiceDirKind kind, const std::string& user_sid) {
    std::string s = "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
    if (kind == ServiceDirKind::ServiceTop) s += "(A;OICI;0x1200a9;;;" + user_sid + ")";   // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    if (kind == ServiceDirKind::UserFull) s += "(A;OICI;FA;;;" + user_sid + ")";
    return s;
}

#ifdef _WIN32
void create_service_dir(const std::string& dir, ServiceDirKind kind, const std::string& user_sid) {
    DirOwner o;
    o.sid = user_sid;
    make_admin_dir(fs::u8path(dir), &o, kind);
}
#else
void install_service_files(const ServiceLocations& loc, uint32_t uid, uint32_t gid, const std::string& config_text,
                           const std::string* key_hex) {
    DirOwner o;
    o.uid = uid;
    o.gid = gid;
    install_service_files_posix(loc, o, config_text, key_hex);
}
#endif

PathPolicy default_path_policy() {
    PathPolicy p;
#ifdef _WIN32
    // Asked from the system, never from environment variables (the user can set those).
    auto known = [](const KNOWNFOLDERID& id) {
        PWSTR w = nullptr;
        std::string out;
        if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &w)) && w) out = fs::path(std::wstring(w)).u8string();
        CoTaskMemFree(w);
        return out;
    };
    for (const std::string& e : {known(FOLDERID_Windows), known(FOLDERID_System), known(FOLDERID_ProgramData),
                                 known(FOLDERID_ProgramFiles), known(FOLDERID_ProgramFilesX86), known(FOLDERID_ProgramFilesCommon),
                                 known(FOLDERID_ProgramFilesCommonX86)}) {
        if (!e.empty()) p.forbidden_roots.push_back(canonical_for_policy(e));
    }
    wchar_t sysdir[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysdir, MAX_PATH)) p.forbidden_roots.push_back(canonical_for_policy(fs::path(sysdir).u8string()));
    // d8: the home is the REQUESTER's (the elevated process may run as another administrator, whose profile is not the user's)
    std::string home = effective_user_sid() == current_user_sid() ? known(FOLDERID_Profile) : profile_path_for_sid(effective_user_sid());
    if (!home.empty()) {
        p.own_home = canonical_for_policy(home);
        p.homes_root = canonical_for_policy(fs::u8path(p.own_home).parent_path().u8string());
    }
#else
    for (const char* r : {"/etc", "/usr", "/var", "/opt", "/srv", "/mnt", "/boot", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
                          "/dev", "/proc", "/sys", "/run", "/root", "/home"}) {
        p.forbidden_roots.push_back(canonical_for_policy(r));   // /home: the other users' profiles (the own home is handled first)
    }
    struct passwd pw{}, *res = nullptr;
    char buf[4096];
    if (::getpwuid_r(owner_uid(), &pw, buf, sizeof buf, &res) == 0 && res && pw.pw_dir) {
        p.own_home = canonical_for_policy(pw.pw_dir);
        p.homes_root = canonical_for_policy(fs::u8path(p.own_home).parent_path().u8string());
    }
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

// Spellings that are never an ordinary folder: device namespaces, GLOBALROOT, volume GUID paths, loopback and
// administrative UNC shares. Pure string tests (any platform).
std::string hard_path_refusal(const std::string& path) {
    std::string p = path;
    for (auto& c : p) {
        if (c == '/') c = '\\';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    auto starts = [&](const char* pre) { return p.compare(0, std::strlen(pre), pre) == 0; };
    if (starts("\\\\.\\")) return "a device path (\\\\.\\...) is not a folder";
    if (starts("\\\\?\\globalroot") || starts("\\??\\")) return "a GLOBALROOT / object-manager path is not a folder";
    if (starts("\\\\?\\volume{") || starts("\\\\?\\harddiskvolume")) return "a volume path is not a folder";
    std::string unc;
    if (starts("\\\\?\\unc\\")) unc = p.substr(8);
    else if (starts("\\\\") && !starts("\\\\?\\")) unc = p.substr(2);
    if (!unc.empty() || starts("\\\\?\\unc\\")) {
        size_t e = unc.find('\\');
        std::string host = unc.substr(0, e);
        std::string share = e == std::string::npos ? std::string() : unc.substr(e + 1, unc.find('\\', e + 1) - e - 1);
        if (host.empty() || host == "localhost" || host == "." || host == "127.0.0.1" || host == "::1" || host == "[::1]" ||
            host.compare(0, 4, "127.") == 0 || host == "0.0.0.0")
            return "a network path to this very computer is not accepted";
        if (!share.empty() && share.back() == '$') return "an administrative share (" + share + ") is not accepted";
#ifdef _WIN32
        wchar_t me[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(me, &n)) {
            std::string mine = fs::path(std::wstring(me, n)).u8string();
            for (auto& c : mine) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (host == mine) return "a network path to this very computer is not accepted";
        }
#endif
    }
    return {};
}

PathVerdict service_path_verdict(const std::string& path, const PathPolicy& pol) {
    PathVerdict v;
    {
        std::string hard = hard_path_refusal(path);
        if (!hard.empty()) {
            v.reason = "'" + path + "': " + hard;
            return v;
        }
    }
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
    // The home counts only when it is a genuine profile: strictly below the folder of profiles, not a drive root, and it
    // neither contains nor is inside a forbidden system folder (a "home" of C:\ or /etc must not open the system).
    bool home_valid = !pol.own_home.empty();
    if (home_valid) {
        fs::path h = fs::u8path(pol.own_home);
        if (is_fs_root(h) || pol.homes_root.empty() || !inside_or_equal(h, fs::u8path(pol.homes_root)) ||
            norm_key(h) == norm_key(fs::u8path(pol.homes_root)))
            home_valid = false;
        for (const std::string& r : pol.forbidden_roots)
            if (home_valid && !r.empty() && (inside_or_equal(fs::u8path(r), h) || inside_or_equal(h, fs::u8path(r)))) {
                // below the profiles folder is the one exception: /home (a forbidden root) contains every home
                if (!(norm_key(fs::u8path(r)) == norm_key(fs::u8path(pol.homes_root)))) home_valid = false;
            }
    }
    bool in_home = home_valid && inside_or_equal(c, fs::u8path(pol.own_home));

    if (!in_home) {
        for (const std::string& r : pol.forbidden_roots)
            if (!r.empty() && inside_or_equal(c, fs::u8path(r))) {
                v.reason = shown + " is inside a system folder (" + r + ")";
                return v;
            }
        // (a "folder of profiles" that is a drive root - root's /root, a profile directly on C: - is not a folder of profiles)
        if (!pol.homes_root.empty() && !is_fs_root(fs::u8path(pol.homes_root)) && inside_or_equal(c, fs::u8path(pol.homes_root))) {
            v.reason = shown + " is the profiles folder or the profile of another user";
            return v;
        }
    }
    if (in_home) {
        v.ok = true;
        return v;
    }
    for (const std::string& r : pol.allow_roots) {
        if (!allow_root_problem(r, pol).empty()) continue;   // a drive root, a system folder ... opens nothing
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

std::string service_config_path_problem(const ClientConfig& cfg, const std::string& config_dir, const std::vector<std::string>& allow_roots) {
    PathPolicy pol = default_path_policy();
    pol.allow_roots = allow_roots;
    for (const auto& r : allow_roots) {
        std::string why = allow_root_problem(r, pol);
        if (!why.empty()) return "the allowed folder '" + r + "' " + why;
    }
    auto absolute = [&](const std::string& p) {
        fs::path q = fs::u8path(p);
        return (q.is_absolute() ? q : fs::u8path(config_dir) / q).lexically_normal().u8string();
    };
    // The service's own files (state, log, key) must stay inside its folder: otherwise a configuration could make an elevated
    // service create / overwrite files anywhere (log_file = C:\Windows\...). Links on the way are refused as well.
    {
        fs::path base = fs::u8path(config_dir).lexically_normal();
        auto inside_dir = [&](const std::string& what, const std::string& p) -> std::string {
            if (p.empty()) return {};
            std::string abs = absolute(p);
            fs::path rel = fs::u8path(abs).lexically_relative(base);
            if (rel.empty() || *rel.begin() == ".." || rel.is_absolute())
                return what + " '" + p + "' is outside the service folder";
            std::string lk = link_component(abs);
            if (!lk.empty()) return what + " '" + p + "' goes through a link ('" + lk + "')";
            return {};
        };
        for (const auto& pr : {std::make_pair("state_dir", cfg.state_dir), std::make_pair("log_file", cfg.log_file), std::make_pair("key_file", cfg.key_file)}) {
            std::string why = inside_dir(pr.first, pr.second);
            if (!why.empty()) return why;
        }
    }
    for (const auto& w : cfg.watches) {
        if (!w.enabled) continue;
        PathVerdict v = service_path_verdict(absolute(w.path), pol);
        if (!v.ok) return "folder: " + v.reason;
        for (const auto& t : w.targets) {
            if (!t.enabled || !t.is_local()) continue;
            PathVerdict tv = service_path_verdict(absolute(t.path), pol);
            if (!tv.ok) return "destination: " + tv.reason;
        }
    }
    return {};
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

MigrationSummary summarize_user_config(const UserPaths& paths, const std::vector<std::string>& allow_roots, const AdminProbe& probe,
                                       const ExposureProbe& exposure) {
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
    m.service_account = current_account_name();
    const AdminState power = probe ? probe(current_user_sid()) : account_admin_state(current_user_sid());
    m.account_is_admin = power != AdminState::No;   // shown in the confirmation (d8): no account is refused for being an administrator...
    if (m.account_is_admin) {
        // ...except when Windows does not filter its network logons (built-in Administrator, domain account, policy turned on)
        std::string ex = exposure ? exposure() : account_exposure_problem_for_current_user();
        if (!ex.empty()) {
            m.problems.insert(m.problems.begin(), ex);
            m.exposed = true;
        }
    }
    {
        // each note travels twice: the English text (command line, logs) and a message key + argument the GUI translates
        auto note = [&m](const char* key, const std::string& arg, const std::string& english) {
            m.warnings.push_back(english);
            m.notes.push_back({key, arg});
        };
        const std::string who = m.service_account.empty() ? std::string("you") : m.service_account;
        note("simple.svc.note.runs_as", who, "The service runs as " + who + ", also when nobody is logged in.");
#ifdef _WIN32
        m.warnings.push_back("The administrator who approves the installation only grants permission to install; the service itself runs as " + who + ".");
        if (m.account_is_admin)
            note("simple.svc.note.admin_acct", who,
                 who + " is an administrator account: the synchronisation engine runs with a restricted token (administrator groups denied, "
                       "dangerous privileges removed, Medium integrity). It shares the account's logon session, so a network folder (for example "
                       "\\\\server\\share) is reached with your credentials; Windows filters the network logons of a local administrator.");
#endif
#ifdef _WIN32
        note("simple.svc.note.netidentity", "",
             "The restricted token does not separate the account's network identity: network folders and shares are reached with your credentials.");
#endif
        note("simple.svc.note.keycopy", "",
             "Your key is copied to the service folder (administrators only); remove it when you go back to the personal mode if you wish.");
    }
    PathPolicy pol = default_path_policy();
    pol.allow_roots = allow_roots;
    check_for_service(c, user_key, udir, pol, &m.problems, &m.needs_confirmation);
    return m;
}

MigrationPlan plan_migration(const std::string& user_config, const std::string& expect_hash, const std::string& expect_key_hash,
                             const std::vector<std::string>& allow_roots, bool with_key) {
    if (expect_hash.empty() || (with_key && expect_key_hash.empty()))
        throw Error("the hashes of the configuration and of the key that were shown to the user are required");
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
    if (!same_hex(hash_of(text), expect_hash))
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
    check_for_service(plan.config, with_key ? plan.user_key : std::string(), udir, policy, &problems, &confirm);
    for (const auto& p : confirm) problems.push_back("'" + p + "' is outside your home folder and was not confirmed");
    if (!problems.empty()) {
        std::string all;
        for (const auto& p : problems) all += (all.empty() ? "" : "; ") + p;
        throw Error("refusing to run this configuration as a service: " + all);
    }
    if (with_key) plan.key = read_user_key(plan.user_key, expect_key_hash);
    plan.who = who_uid;
    return plan;
}

int run_migrate_from_user(const std::vector<std::string>& args) {
    std::string user_config, name = "mysync-client";
    bool remove = false, config_only = false;
    std::string requester;
    std::string expect_hash, expect_key_hash, account;
    std::vector<std::string> allow_roots;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--user-config" && i + 1 < args.size()) user_config = args[++i];
        else if (args[i] == "--account" && i + 1 < args.size()) account = args[++i];
        else if (args[i] == "--expect-hash" && i + 1 < args.size()) expect_hash = args[++i];
        else if (args[i] == "--expect-key-hash" && i + 1 < args.size()) expect_key_hash = args[++i];
        else if (args[i] == "--allow-root" && i + 1 < args.size()) allow_roots.push_back(args[++i]);
        else if (args[i] == "--name" && i + 1 < args.size()) name = args[++i];
        else if (args[i] == "--requester-sid" && i + 1 < args.size()) requester = args[++i];
        else if (args[i] == "--remove") remove = true;
        else if (args[i] == "--config-only") config_only = true;   // apply-config: new configuration, same key
        else {
            std::cerr << "mysync: unknown argument '" << args[i] << "'\n";
            return gui::kServiceBadArguments;
        }
    }
    auto bad = [](const std::string& m, int code) {
        std::cerr << "mysync: " << m << "\n";
        return code;
    };
    if (!requester.empty()) {   // d8: the user who asked; this process may run under the administrator who approved the prompt
        if (!valid_user_sid(requester)) return bad("invalid --requester-sid", gui::kServiceBadArguments);
        set_requester_sid(requester);
#ifdef _WIN32
        if (requester != current_user_sid())   // not blocked: this is the normal UAC-with-another-administrator case
            std::cerr << "mysync: note: this step runs as another account than the user who asked; the service will belong to the user who asked\n";
#endif
    }
    try {
        if (!name_ok(name)) return bad("invalid service name", gui::kServiceBadArguments);
        if (!remove && user_config.empty())
            return bad("service migrate-from-user needs --user-config <file>", gui::kServiceBadArguments);
        if (!remove && (expect_hash.empty() || (!config_only && expect_key_hash.empty())))
            return bad("service migrate-from-user needs --expect-hash and --expect-key-hash (the hashes shown in the summary)",
                       gui::kServiceBadArguments);
        if (!gui::ServiceController::is_elevated())
            return bad("this step needs administrator rights", gui::kServiceAccessDenied);
#ifdef _WIN32
        if (!remove && !valid_user_sid(requester))   // d8: the user who asked must be named (this process may run as another administrator)
            return bad("the identity of the user who asked is missing (--requester-sid)", gui::kServiceBadArguments);
#endif
        ServiceLocations loc = user_service_locations(name);
        // The account the service will run as is the REQUESTER, never somebody else: Windows compares the SID of the
        // named account with the user of this (elevated) process; POSIX uses the uid resolved from pkexec / sudo.
        DirOwner owner;
        std::string trust_entry;
#ifdef _WIN32
        owner.sid = effective_user_sid();
        if (!account.empty()) {
            std::string asid = account_sid(account);
            if (asid.empty() || asid != owner.sid)
                return bad("the service must run as the account that owns the configuration (" + account + " is not this user)",
                           gui::kServiceConfigError);
        }
        trust_entry = owner.sid;
#endif
        if (remove) {
            // The private copy made by a migration (configuration, its backup, key). The folder must be the user's own.
#ifndef _WIN32
            {
                InvokerResult who = resolve_invoking_uid(invoker_input({}));
                if (!who.ok) return bad(who.error, gui::kServiceConfigError);
                trust_entry = "uid:" + std::to_string(who.uid);
            }
#endif
            std::error_code ec;
            if (!fs::exists(fs::u8path(loc.dir), ec)) return 0;
#ifdef _WIN32
            try {   // links on the way refused, and only SYSTEM / Administrators may have written the folder (no 'self' trust)
                check_service_dir_trust(fs::u8path(loc.dir), nullptr, DirKind::Admin);
            } catch (const Error& e) {
                return bad(e.what(), gui::kServiceConfigError);
            }
#else
            std::string why = gui::untrusted_writer_reason(loc.dir, {trust_entry}, true);
            if (!why.empty()) return bad("the folder '" + loc.dir + "' " + why, gui::kServiceConfigError);
#endif
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
            plan = plan_migration(user_config, expect_hash, expect_key_hash, allow_roots, !config_only);  // nothing is written before this passes
        } catch (const Error& e) {
            return bad(e.what(), gui::kServiceConfigError);
        }
        ClientConfig& c = plan.config;
        KeyPair& kp = plan.key;
#ifndef _WIN32
        {
            owner.uid = plan.who;
            struct passwd pw{}, *res = nullptr;
            char buf[4096];
            if (::getpwuid_r(static_cast<uid_t>(plan.who), &pw, buf, sizeof buf, &res) != 0 || !res)
                return bad("cannot find the requesting user", gui::kServiceConfigError);
            owner.gid = pw.pw_gid;
            trust_entry = "uid:" + std::to_string(plan.who);
        }
#endif
        c.key_file = loc.key;
        c.state_dir = loc.state;
        c.log_file = loc.log;
        c.control_name.clear();   // the service answers under its own name (the service name)
        c.control_allow.clear();  // not the user's call
        c.control_group.clear();  // the socket is the user's alone (RuntimeDirectory 0700)
        std::string out = gui::serialize_client_config(c);
        parse_client_config_text(out);  // what we write must load
#ifdef _WIN32
        {
            fs::path dir = fs::u8path(loc.dir);
            make_admin_dir(dir.parent_path());                              // administrators only
            make_admin_dir(dir, &owner, DirKind::ServiceTop);               // config + key: the service may READ, only admins write
            // An administrator account gives the service a FULL administrator token, so state/ and log/ must not be
            // user-writable either (a junction planted there would let the service write anywhere as an administrator): they
            // are readable by the account and writable by administrators only (which the service's token includes). Only an
            // ordinary account gets writable state/ and log/ - it can do no more through them than it could itself.
            const DirKind data_kind = data_dir_kind_for_account(owner.sid);   // unknown counts as administrator
            make_admin_dir(fs::u8path(loc.state), &owner, data_kind);
            make_admin_dir(fs::u8path(loc.log).parent_path(), &owner, data_kind);
            std::error_code ec;
            if (!config_only) {
                std::string kh = key_to_hex(kp.secret) + "\n";
                write_new_file_win(loc.key, kh);   // inherits the folder's ACL: readable by the account
                secure_wipe(&kh[0], kh.size());
            } else if (!fs::exists(fs::u8path(loc.key), ec)) {
                return bad("there is no service key yet: set the service up first", gui::kServiceConfigError);
            }
            write_new_file_win(loc.config, out);
        }
#else
        {
            std::string kh = key_to_hex(kp.secret) + "\n";
            install_service_files_posix(loc, owner, out, config_only ? nullptr : &kh);
            secure_wipe(&kh[0], kh.size());
        }
#endif
        // Fail now, not at service start: the result must satisfy the same trust rule the service applies (its own account
        // counts as trusted, the installing administrator does not).
#ifdef _WIN32
        gui::require_trusted_config(loc.config, {}, /*include_self=*/false);   // only administrators / SYSTEM may have written it
#else
        gui::require_trusted_config(loc.config, {trust_entry}, /*include_self=*/false);
#endif
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
    RealSteps(Supervisor& sup, gui::ServiceController& ctl, UserPaths paths, std::string name, std::vector<std::string> allow,
              std::string account, const SecretString* password)
        : sup_(sup), ctl_(ctl), paths_(std::move(paths)), allow_roots_(std::move(allow)), account_(std::move(account)),
          password_(password) {
        if (account_.empty()) account_ = current_account_name();
        name_ = name.empty() ? user_service_name(account_, current_owner_id()) : std::move(name);
    }

    std::string check_preconditions(bool to_service) override {
        if (!gui::ServiceController::valid_name(name_)) return "invalid service name";
        if (!valid_account_name(account_)) return "cannot tell which account the service should run as";
#ifdef _WIN32
        // The service logs on as the user: it needs that user's password, and only the owner of the configuration may ask.
        if (to_service && (!password_ || password_->empty()))
            return "Windows needs the password of your account (" + account_ + ") to run the service as you. A Microsoft account uses "
                   "the account password, not the Windows Hello PIN.";
        if (to_service && account_sid(account_) != current_user_sid()) return "the service must run as the account that owns the configuration";
#endif
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
        } else if (st.description.find(owner_label(current_owner_id())) == std::string::npos) {
            return "the service '" + name_ + "' was not installed for you: only its owner can remove it from here";
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
        rq.run_as = account_;   // the elevated step checks that this is the account of the requester
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
        if (cancelled) throw Error("the removal of the service copy was cancelled; it stays in " + user_service_locations(name_).dir);
    }

    void install_service(bool* cancelled) override {
        gui::ServiceRequest rq;
        rq.name = name_;
        rq.config_path = user_service_locations(name_).config;
        rq.role = "client";
        rq.user_service = true;
        rq.allow_roots = allow_roots_;
        // The service runs AS THE USER (Windows: the account + its password through the private channel; Linux: User= of
        // the unit). Never SYSTEM / root at run time.
#ifdef _WIN32
        rq.run_as = account_;
        rq.password = password_;
#else
        rq.run_as = account_;
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
                        user_service_locations(name_).config);
    }
    // Windows: the password changed in Windows, so the service cannot log on any more: give it the new one.
    bool service_needs_password_update() { return ctl_.query(name_).needs_password_update; }
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
    std::string account_;
    const SecretString* password_ = nullptr;
    MigrationSummary summary_;
    bool have_summary_ = false;
};

}  // namespace

std::unique_ptr<UpgradeSteps> make_real_upgrade_steps(Supervisor& sup, gui::ServiceController& ctl, const UserPaths& paths,
                                                      const std::string& service_name,
                                                      const std::vector<std::string>& allow_roots, const std::string& account,
                                                      const SecretString* password) {
    return std::make_unique<RealSteps>(sup, ctl, paths, service_name, allow_roots, account, password);
}

}  // namespace mysync::simple
