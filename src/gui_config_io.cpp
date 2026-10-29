// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/config_io.h"

#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#endif

#include "mysync/hash.h"
#include "mysync/keys.h"

namespace fs = std::filesystem;

namespace mysync::gui {
namespace {

// ---------------------------------------------------------------- TOML writer
std::string q(const std::string& s) {
    std::string r = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '\\': r += "\\\\"; break;
        case '"': r += "\\\""; break;
        case '\n': r += "\\n"; break;
        case '\t': r += "\\t"; break;
        case '\r': r += "\\r"; break;
        case '\b': r += "\\b"; break;
        case '\f': r += "\\f"; break;
        default:
            if (c < 0x20 || c == 0x7f) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04X", c);
                r += buf;
            } else {
                r += static_cast<char>(c);
            }
        }
    }
    return r + "\"";
}

std::string arr(const std::vector<std::string>& v) {
    std::string r = "[";
    for (size_t i = 0; i < v.size(); ++i) r += (i ? ", " : "") + q(v[i]);
    return r + "]";
}

std::string b(bool v) { return v ? "true" : "false"; }

std::string mode(uint32_t m) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "\"%04o\"", m & 0777u);
    return buf;
}

// Exact size text in the same 1024-based units the parser reads.
std::string size_text(uint64_t v) {
    if (v == 0) return "0";
    struct U { uint64_t mult; const char* name; };
    static const U units[] = {{1ull << 40, "TB"}, {1ull << 30, "GB"}, {1ull << 20, "MB"}, {1ull << 10, "KB"}};
    for (const U& u : units)
        if (v % u.mult == 0) return q(std::to_string(v / u.mult) + u.name);
    return std::to_string(v);
}

std::string hex_of(const PublicKey& k) { return to_hex(k.data(), k.size()); }

void kv(std::string& o, const char* key, const std::string& val) { o += std::string(key) + " = " + val + "\n"; }

void control_section(std::string& o, bool enabled, const std::vector<std::string>& allow, const std::string& group,
                     const std::string& name) {
    o += "\n# Local control channel used by mysync-gui (named pipe on Windows, unix socket on Linux; never TCP).\n";
    o += "# allow: Windows SIDs or DOMAIN\\user besides SYSTEM and Administrators. group: Linux group on the socket.\n";
    o += "[control]\n";
    kv(o, "enabled", b(enabled));
    kv(o, "allow", arr(allow));
    if (!group.empty()) kv(o, "group", q(group));
    if (!name.empty()) kv(o, "name", q(name));
}

const char* kHeader =
    "# SPDX-License-Identifier: GPL-2.0-or-later\n"
    "# MySync configuration written by mysync-gui. Comments typed by hand are not preserved when the GUI saves;\n"
    "# the previous version of the file is kept next to it as *.bak.\n";

std::string read_file(const std::string& utf8_path, bool* exists = nullptr) {
    std::ifstream f(fs::u8path(utf8_path), std::ios::binary);
    if (!f) {
        std::error_code ec;
        bool ex = fs::exists(fs::u8path(utf8_path), ec);
        if (exists) *exists = ex;
        if (ex) throw Error("cannot read " + utf8_path);
        return {};
    }
    if (exists) *exists = true;
    std::ostringstream ss;
    ss << f.rdbuf();
    if (f.bad()) throw Error("cannot read " + utf8_path);
    return ss.str();
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, e = s.size();
    while (a < e && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (e > a && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(a, e - a);
}

// ---------------------------------------------------------------- atomic write
std::string random_suffix() {
    uint8_t r[8];
    random_bytes(r, sizeof r);
    return to_hex(r, sizeof r);
}

#ifdef _WIN32
std::wstring wide(const std::string& s) { return fs::u8path(s).wstring(); }

void copy_dacl(const std::wstring& from, const std::wstring& to) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(from.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
                              &sd) != ERROR_SUCCESS)
        return;
    SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
    DWORD rev = 0;
    DWORD flag = UNPROTECTED_DACL_SECURITY_INFORMATION;
    if (GetSecurityDescriptorControl(sd, &ctrl, &rev) && (ctrl & SE_DACL_PROTECTED)) flag = PROTECTED_DACL_SECURITY_INFORMATION;
    SetNamedSecurityInfoW(const_cast<LPWSTR>(to.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | flag, nullptr,
                          nullptr, dacl, nullptr);
    LocalFree(sd);
}

void write_atomic(const std::string& path, const std::string& content, const std::string& perm_from) {
    std::wstring target = wide(path);
    std::wstring tmp = target + L".tmp-" + wide(random_suffix());
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw Error("cannot create a temporary file next to " + path + " (error " + std::to_string(GetLastError()) + ")");
    bool ok = true;
    size_t off = 0;
    while (ok && off < content.size()) {
        DWORD n = 0;
        ok = WriteFile(h, content.data() + off, static_cast<DWORD>(std::min<size_t>(content.size() - off, 1u << 20)), &n,
                       nullptr) != 0;
        off += n;
    }
    if (ok) ok = FlushFileBuffers(h) != 0;
    DWORD werr = GetLastError();
    CloseHandle(h);
    if (!ok) {
        DeleteFileW(tmp.c_str());
        throw Error("cannot write " + path + " (error " + std::to_string(werr) + ")");
    }
    if (!perm_from.empty() && fs::exists(fs::u8path(perm_from))) copy_dacl(wide(perm_from), tmp);
    if (!MoveFileExW(tmp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD e = GetLastError();
        DeleteFileW(tmp.c_str());
        throw Error("cannot replace " + path + " (error " + std::to_string(e) + ")");
    }
}
#else
void write_atomic(const std::string& path, const std::string& content, const std::string& perm_from) {
    std::string tmp = path + ".tmp-" + random_suffix();
    mode_t m = 0644;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    struct stat st{};
    if (!perm_from.empty() && ::stat(perm_from.c_str(), &st) == 0) {
        m = st.st_mode & 07777;
        uid = st.st_uid;
        gid = st.st_gid;
    }
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) throw Error("cannot create a temporary file next to " + path + ": " + std::strerror(errno));
    auto fail = [&](const std::string& what) {
        int e = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        throw Error(what + " " + path + ": " + std::strerror(e));
    };
    size_t off = 0;
    while (off < content.size()) {
        ssize_t n = ::write(fd, content.data() + off, content.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            fail("cannot write");
        }
        off += static_cast<size_t>(n);
    }
    if (::fchmod(fd, m) != 0) fail("cannot set the permissions of");
    if (uid != static_cast<uid_t>(-1) && ::geteuid() == 0) {
        if (::fchown(fd, uid, gid) != 0) fail("cannot set the owner of");
    } else if (gid != static_cast<gid_t>(-1)) {
        if (::fchown(fd, static_cast<uid_t>(-1), gid) != 0) errno = 0;  // best effort: not a member of that group
    }
    if (::fsync(fd) != 0) fail("cannot flush");
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        int e = errno;
        ::unlink(tmp.c_str());
        throw Error("cannot replace " + path + ": " + std::strerror(e));
    }
    std::string dir = fs::u8path(path).parent_path().u8string();
    if (dir.empty()) dir = ".";
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
}
#endif

}  // namespace

// ---------------------------------------------------------------------------------------------- serialisers
std::string serialize_server_config(const ServerConfig& c) {
    std::string o = kHeader;
    o += "\n[server]\n";
    kv(o, "bind", q(c.bind));
    kv(o, "port", std::to_string(c.port));
    kv(o, "root", q(c.root));
    kv(o, "key_file", q(c.key_file));
    kv(o, "max_connections", std::to_string(c.max_connections));
    kv(o, "max_bandwidth_kbps", std::to_string(c.max_bandwidth_kbps));
    kv(o, "max_auth_failures_per_min", std::to_string(c.max_auth_failures_per_min));
    kv(o, "trash", b(c.trash));
    kv(o, "max_trash_bytes", size_text(c.max_trash_bytes));
    kv(o, "file_mode", mode(c.file_mode));
    kv(o, "dir_mode", mode(c.dir_mode));
    kv(o, "allow", arr(c.allow));
    kv(o, "deny", arr(c.deny));
    kv(o, "state_dir", q(c.state_dir));
    kv(o, "log_file", q(c.log_file));
    kv(o, "log_level", q(c.log_level));
    kv(o, "max_file_size", size_text(c.max_file_size));
    kv(o, "io_timeout_s", std::to_string(c.io_timeout_s));
    control_section(o, c.control_enabled, c.control_allow, c.control_group, c.control_name);
    for (const ClientAcl& a : c.clients) {
        o += "\n[[client]]\n";
        kv(o, "name", q(a.name));
        kv(o, "public_key", q(hex_of(a.public_key)));
        kv(o, "access", q(a.read_only ? "ro" : "rw"));
        if (!a.prefix.empty()) kv(o, "prefix", q(a.prefix));
        kv(o, "max_sessions", std::to_string(a.max_sessions));
        kv(o, "max_bandwidth_kbps", std::to_string(a.max_bandwidth_kbps));
        kv(o, "max_write_bytes_per_hour", size_text(a.max_write_bytes_per_hour));
    }
    return o;
}

std::string serialize_client_config(const ClientConfig& c) {
    std::string o = kHeader;
    o += "\n[client]\n";
    kv(o, "key_file", q(c.key_file));
    kv(o, "state_dir", q(c.state_dir));
    kv(o, "log_file", q(c.log_file));
    kv(o, "log_level", q(c.log_level));
    kv(o, "connections", std::to_string(c.connections));
    kv(o, "compress", q(c.compress));
    kv(o, "max_bandwidth_kbps", std::to_string(c.max_bandwidth_kbps));
    kv(o, "retry_min_ms", std::to_string(c.retry_min_ms));
    kv(o, "retry_max_ms", std::to_string(c.retry_max_ms));
    kv(o, "compress_skip_ext", arr(c.compress_skip_ext));
    control_section(o, c.control_enabled, c.control_allow, c.control_group, c.control_name);
    for (const WatchConfig& w : c.watches) {
        o += "\n[[watch]]\n";
        kv(o, "name", q(w.name));
        kv(o, "path", q(w.path));
        kv(o, "enabled", b(w.enabled));
        kv(o, "recursive", b(w.recursive));
        kv(o, "quiet_ms", std::to_string(w.quiet_ms));
        kv(o, "sync_delay_ms", std::to_string(w.sync_delay_ms));
        kv(o, "start_sync", b(w.start_sync));
        kv(o, "propagate_delete", b(w.propagate_delete));
        kv(o, "schedule_at", arr(w.schedule_at));
        kv(o, "schedule_interval_s", std::to_string(w.schedule_interval_s));
        kv(o, "periodic_scan_s", std::to_string(w.periodic_scan_s));
        const FilterConfig& f = w.filter;
        o += "\n[watch.filter]\n";
        kv(o, "include", arr(f.include));
        kv(o, "include_regex", arr(f.include_regex));
        kv(o, "exclude", arr(f.exclude));
        kv(o, "exclude_regex", arr(f.exclude_regex));
        if (!f.size_min.empty()) kv(o, "size_min", q(f.size_min));
        if (!f.size_max.empty()) kv(o, "size_max", q(f.size_max));
        if (!f.mtime_after.empty()) kv(o, "mtime_after", q(f.mtime_after));
        if (!f.mtime_before.empty()) kv(o, "mtime_before", q(f.mtime_before));
        for (const TargetConfig& t : w.targets) {
            o += "\n[[watch.target]]\n";
            if (t.is_local()) {
                kv(o, "path", q(t.path));
                kv(o, "file_mode", mode(t.file_mode));
                kv(o, "dir_mode", mode(t.dir_mode));
            } else {
                kv(o, "host", q(t.host));
                kv(o, "port", std::to_string(t.port));
                kv(o, "server_key", q(hex_of(t.server_key)));
                if (!t.key_file.empty()) kv(o, "key_file", q(t.key_file));
            }
            if (!t.remote_prefix.empty()) kv(o, "remote_prefix", q(t.remote_prefix));
            kv(o, "enabled", b(t.enabled));
        }
    }
    return o;
}

void write_file_atomic(const std::string& utf8_path, const std::string& content, bool keep_permissions) {
    write_atomic(utf8_path, content, keep_permissions ? utf8_path : std::string());
}

std::string file_content_hash(const std::string& utf8_path) {
    bool exists = false;
    std::string text = read_file(utf8_path, &exists);
    if (!exists) return {};
    return hash_hex(hash_bytes(text.data(), text.size()));
}

// ---------------------------------------------------------------------------------------------- ConfigEditor
ConfigRole ConfigEditor::detect_role(const std::string& text) {
    bool server = false, client = false;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] != '[') continue;
        size_t e = t.rfind("[[", 0) == 0 ? t.find("]]") : t.find(']');
        size_t len = e == std::string::npos ? t.size() : e + (t.rfind("[[", 0) == 0 ? 2 : 1);
        std::string head = lower(trim(t.substr(0, len)));
        if (head == "[server]" || head == "[[client]]") server = true;
        else if (head == "[client]" || head.rfind("[[watch", 0) == 0 || head.rfind("[watch", 0) == 0) client = true;
    }
    if (server && client)
        throw Error("the file mixes server tables ([server]/[[client]]) and client tables ([client]/[[watch]]): "
                    "use one file per role");
    if (!server && !client)
        throw Error("cannot tell the role of the file: no [server]/[[client]]/[[watch]] table");
    return server ? ConfigRole::Server : ConfigRole::Client;
}

ConfigEditor ConfigEditor::open(const std::string& path) {
    bool exists = false;
    std::string text = read_file(path, &exists);
    if (!exists) throw Error("cannot open config file: " + path);
    ConfigRole role;
    try {
        role = detect_role(text);
    } catch (const Error& e) {
        throw Error(path + ": " + e.what());
    }
    return open(path, role);
}

ConfigEditor ConfigEditor::open(const std::string& path, ConfigRole role) {
    bool exists = false;
    std::string text = read_file(path, &exists);
    if (!exists) throw Error("cannot open config file: " + path);
    ConfigEditor e;
    e.role_ = role;
    e.path_ = path;
    try {
        if (role == ConfigRole::Server) {
            e.server_ = parse_server_config_text(text);
            e.clean_text_ = serialize_server_config(e.server_);
        } else {
            e.client_ = parse_client_config_text(text);
            e.clean_text_ = serialize_client_config(e.client_);
        }
    } catch (const Error& ex) {
        throw Error(path + ": " + ex.what());
    }
    e.disk_hash_ = hash_hex(hash_bytes(text.data(), text.size()));
    e.existed_ = true;
    return e;
}

ConfigEditor ConfigEditor::create(const std::string& path, ConfigRole role) {
    ConfigEditor e;
    e.role_ = role;
    e.path_ = path;
    e.existed_ = false;
    e.clean_text_.clear();  // a new file is always dirty
    return e;
}

ServerConfig& ConfigEditor::server() {
    if (role_ != ConfigRole::Server) throw Error("this is a client configuration");
    return server_;
}
const ServerConfig& ConfigEditor::server() const {
    if (role_ != ConfigRole::Server) throw Error("this is a client configuration");
    return server_;
}
ClientConfig& ConfigEditor::client() {
    if (role_ != ConfigRole::Client) throw Error("this is a server configuration");
    return client_;
}
const ClientConfig& ConfigEditor::client() const {
    if (role_ != ConfigRole::Client) throw Error("this is a server configuration");
    return client_;
}

std::string ConfigEditor::to_toml() const {
    return role_ == ConfigRole::Server ? serialize_server_config(server_) : serialize_client_config(client_);
}

void ConfigEditor::validate() const {
    std::string text = to_toml();
    if (role_ == ConfigRole::Server) (void)parse_server_config_text(text);
    else (void)parse_client_config_text(text);
}

bool ConfigEditor::dirty() const { return to_toml() != clean_text_; }

bool ConfigEditor::changed_on_disk() const { return file_content_hash(path_) != disk_hash_; }

void ConfigEditor::save(const SaveOptions& opts) {
    std::string text = to_toml();
    try {
        validate();
    } catch (const Error& e) {
        throw Error(std::string("the configuration is not valid and was not written: ") + e.what());
    }
    if (!opts.force && changed_on_disk()) {
        throw Error(existed_ ? "the configuration file was changed on disk since it was read (by hand or by another "
                               "program); reload it before saving, or save with force"
                             : "a file already exists at " + path_ + "; refusing to overwrite a file this editor did not read");
    }
    std::error_code ec;
    fs::path parent = fs::u8path(path_).parent_path();
    if (!parent.empty()) fs::create_directories(parent, ec);
    bool exists = false;
    std::string old = read_file(path_, &exists);
    if (exists && opts.make_backup) write_atomic(path_ + ".bak", old, path_);
    // second look just before the swap: shrinks the window in which a hand edit could be overwritten
    if (!opts.force && file_content_hash(path_) != disk_hash_)
        throw Error("the configuration file changed while saving; nothing was overwritten, reload and try again");
    write_atomic(path_, text, exists ? path_ : std::string());
    disk_hash_ = hash_hex(hash_bytes(text.data(), text.size()));
    clean_text_ = text;
    existed_ = true;
}

void ConfigEditor::reload() {
    ConfigEditor fresh = ConfigEditor::open(path_, role_);
    *this = std::move(fresh);
}

}  // namespace mysync::gui
