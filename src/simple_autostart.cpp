// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/autostart.h"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace mysync::simple {
namespace {

std::string self_exe() {
#ifdef _WIN32
    std::wstring buf(1024, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, &buf[0], static_cast<DWORD>(buf.size()));
        if (n == 0) return {};
        if (n < buf.size()) { buf.resize(n); break; }
        buf.resize(buf.size() * 2);
    }
    return fs::path(buf).u8string();
#else
    std::error_code ec;
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    return ec ? std::string() : p.string();
#endif
}

std::string checked_exe(const std::string& exe) {
    if (exe.empty()) throw Error("cannot determine the path of the application");
    for (unsigned char c : exe)
        if (c < 0x20 || c == 0x7F || c == '"') throw Error("the application path has characters that cannot be used for autostart");
    if (!fs::u8path(exe).is_absolute()) throw Error("the application path for autostart must be absolute");
    return exe;
}

}  // namespace

std::string autostart_command_line(const std::string& gui_exe) { return "\"" + checked_exe(gui_exe) + "\" --tray"; }

std::string desktop_exec_quote(const std::string& arg) {
    // Desktop Entry spec, "The Exec key": reserved characters force double quotes; inside them " ` $ \ get a backslash;
    // '%' is doubled; and the string value layer then doubles every backslash once more.
    for (unsigned char c : arg)
        if (c < 0x20 || c == 0x7F) throw Error("control characters cannot be used in an Exec line");
    static const char kReserved[] = " \t\n\"'\\><~|&;$*?#()`";
    bool need = arg.empty() || arg.find_first_of(kReserved) != std::string::npos;
    std::string q;
    for (char c : arg) {
        if (c == '%') { q += "%%"; continue; }
        if (need && (c == '"' || c == '`' || c == '$' || c == '\\')) q += '\\';
        q += c;
    }
    if (need) q = "\"" + q + "\"";
    std::string out;
    for (char c : q) {
        if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

std::string autostart_desktop_entry(const std::string& gui_exe) {
    std::string exe = checked_exe(gui_exe);
    return "[Desktop Entry]\n"
           "Type=Application\n"
           "Name=MySync\n"
           "Comment=File synchronisation\n"
           "Exec=" + desktop_exec_quote(exe) + " --tray\n"
           "Terminal=false\n"
           "Categories=Utility;\n"
           "X-GNOME-Autostart-enabled=true\n";
}

#ifdef _WIN32
namespace {
std::wstring run_key(const AutostartOptions& o) {
    return o.registry_key.empty() ? std::wstring(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                                  : fs::u8path(o.registry_key).wstring();
}
}  // namespace

bool autostart_enabled(const AutostartOptions& o) {
    try {
        HKEY k = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, run_key(o).c_str(), 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return false;
        DWORD type = 0, size = 0;
        LONG rc = RegQueryValueExW(k, L"MySync", nullptr, &type, nullptr, &size);
        RegCloseKey(k);
        return rc == ERROR_SUCCESS && type == REG_SZ && size > 2;
    } catch (...) {
        return false;
    }
}

void set_autostart(bool on, const AutostartOptions& o) {
    std::wstring key = run_key(o);
    if (on) {
        std::wstring cmd = fs::u8path(autostart_command_line(o.gui_exe.empty() ? self_exe() : o.gui_exe)).wstring();
        HKEY k = nullptr;
        LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
        if (rc != ERROR_SUCCESS) throw Error("cannot open the startup registry key (error " + std::to_string(rc) + ")");
        rc = RegSetValueExW(k, L"MySync", 0, REG_SZ, reinterpret_cast<const BYTE*>(cmd.c_str()),
                            static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
        if (rc != ERROR_SUCCESS) throw Error("cannot write the startup entry (error " + std::to_string(rc) + ")");
    } else {
        HKEY k = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return;
        LONG rc = RegDeleteValueW(k, L"MySync");
        RegCloseKey(k);
        if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND)
            throw Error("cannot remove the startup entry (error " + std::to_string(rc) + ")");
    }
}

#else  // ---------------------------------------------------------------------------------------- POSIX
namespace {
fs::path autostart_file(const AutostartOptions& o) {
    if (!o.autostart_dir.empty()) return fs::path(o.autostart_dir) / "mysync.desktop";
    const char* x = std::getenv("XDG_CONFIG_HOME");
    fs::path base;
    if (x && x[0] == '/') {
        base = x;
    } else {
        const char* h = std::getenv("HOME");
        if (!h || h[0] != '/') {
            struct passwd pw{}, *res = nullptr;
            char buf[4096];
            if (::getpwuid_r(::geteuid(), &pw, buf, sizeof buf, &res) == 0 && res && pw.pw_dir) h = pw.pw_dir;
            else throw Error("cannot find the home folder");
        }
        base = fs::path(h) / ".config";
    }
    return base / "autostart" / "mysync.desktop";
}
}  // namespace

bool autostart_enabled(const AutostartOptions& o) {
    try {
        std::error_code ec;
        return fs::is_regular_file(autostart_file(o), ec);
    } catch (...) {
        return false;
    }
}

void set_autostart(bool on, const AutostartOptions& o) {
    fs::path f = autostart_file(o);
    std::error_code ec;
    if (!on) {
        fs::remove(f, ec);
        if (ec) throw Error("cannot remove " + f.string() + ": " + ec.message());
        return;
    }
    std::string text = autostart_desktop_entry(o.gui_exe.empty() ? self_exe() : o.gui_exe);
    fs::create_directories(f.parent_path(), ec);
    if (ec) throw Error("cannot create " + f.parent_path().string() + ": " + ec.message());
    fs::path tmp = f.parent_path() / (".mysync.desktop.tmp-" + std::to_string(::getpid()));
    ::unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) throw Error("cannot write " + tmp.string());
    ::fchmod(fd, 0644);
    size_t off = 0;
    bool ok = true;
    while (ok && off < text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) ok = false;
        else off += size_t(n);
    }
    if (ok) ok = ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), f.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw Error("cannot write " + f.string());
    }
}
#endif

}  // namespace mysync::simple
