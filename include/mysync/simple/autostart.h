// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/autostart.h - start the GUI (hidden in the tray) when the user logs in. No administrator needed.
//   Windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Run, value "MySync" = "<gui exe>" --tray  (exe quoted)
//   Linux  : <config>/autostart/mysync.desktop (XDG; Exec quoted per the desktop-entry spec, mode 0644, atomic write)
// Default: ON once the first-run wizard finishes (the GUI calls set_autostart(true)).
#include <string>

#include "mysync/util.h"

namespace mysync::simple {

struct AutostartOptions {
    std::string gui_exe;        // absolute path of mysync-gui ("" = this process' executable)
    std::string registry_key;   // Windows test hook: key under HKCU ("" = Software\Microsoft\Windows\CurrentVersion\Run)
    std::string autostart_dir;  // Linux test hook: directory instead of <XDG_CONFIG_HOME>/autostart
};

// Pure builders (tested on every platform). Throw Error for a relative path or one with control characters / quotes.
std::string autostart_command_line(const std::string& gui_exe);   // "C:\...\mysync-gui.exe" --tray, exe in quotes
std::string autostart_desktop_entry(const std::string& gui_exe);  // full .desktop text
std::string desktop_exec_quote(const std::string& arg);            // desktop-entry Exec quoting of one argument

bool autostart_enabled(const AutostartOptions& o = {});   // does not throw (false on any problem)
void set_autostart(bool on, const AutostartOptions& o = {});  // throws Error with the system message

}  // namespace mysync::simple
