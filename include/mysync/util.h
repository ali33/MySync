// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// util.h - CONTRACT header shared by all modules (see docs/DESIGN.md).
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace mysync {

using Bytes = std::vector<uint8_t>;
using Hash256 = std::array<uint8_t, 32>;

// Every recoverable failure is thrown as Error. Messages must never contain secrets.
struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// ---- logging (thread-safe; never log keys / PSK) ----
enum class LogLevel { Debug = 0, Info, Warn, Error };
void log_set_level(LogLevel);
void log_set_file(const std::string& utf8_path);  // "" = stderr only; appends
void log_write(LogLevel, const std::string& msg); // timestamped single line
// Optional observer of Warn / Error lines (the message text only, as passed to log_write). Used by the GUI control
// channel to keep a ring of recent problems. Must be quick and must not log. nullptr removes it.
using LogTap = void (*)(LogLevel, const std::string& msg);
void log_set_tap(LogTap);
inline void log_debug(const std::string& m) { log_write(LogLevel::Debug, m); }
inline void log_info(const std::string& m) { log_write(LogLevel::Info, m); }
inline void log_warn(const std::string& m) { log_write(LogLevel::Warn, m); }
inline void log_error(const std::string& m) { log_write(LogLevel::Error, m); }

// ---- misc helpers ----
void random_bytes(void* out, size_t n);  // OS CSPRNG; throws Error on failure
std::string to_hex(const void* data, size_t n);
Bytes from_hex(const std::string& hex);  // throws Error on bad input
inline std::string hash_hex(const Hash256& h) { return to_hex(h.data(), h.size()); }
bool ct_equal(const void* a, const void* b, size_t n);  // constant time
void secure_wipe(void* p, size_t n);
int64_t now_unix_ns();  // wall clock

} // namespace mysync
