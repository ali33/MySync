// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/util.h"

#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace mysync {

namespace {
std::mutex g_log_mu;
std::atomic<int> g_level{static_cast<int>(LogLevel::Info)};
std::ofstream g_log_file;

const char* level_name(LogLevel l) {
    switch (l) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO ";
        case LogLevel::Warn: return "WARN ";
        case LogLevel::Error: return "ERROR";
    }
    return "?????";
}
}  // namespace

void log_set_level(LogLevel l) { g_level.store(static_cast<int>(l)); }

void log_set_file(const std::string& utf8_path) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    if (g_log_file.is_open()) g_log_file.close();
    g_log_file.clear();
    if (utf8_path.empty()) return;
    g_log_file.open(std::filesystem::u8path(utf8_path), std::ios::app | std::ios::binary);
    if (!g_log_file.is_open()) {
        std::fprintf(stderr, "cannot open log file\n");
    }
}

void log_write(LogLevel l, const std::string& msg) {
    if (static_cast<int>(l) < g_level.load()) return;
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    int ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char ts[40];
    std::snprintf(ts, sizeof ts, "%04d-%02d-%02d %02d:%02d:%02d.%03d", tmv.tm_year + 1900, tmv.tm_mon + 1,
                  tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ms);
    std::string line = std::string(ts) + " [" + level_name(l) + "] " + msg + "\n";
    std::lock_guard<std::mutex> lk(g_log_mu);
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
    if (g_log_file.is_open()) {
        g_log_file.write(line.data(), static_cast<std::streamsize>(line.size()));
        g_log_file.flush();
    }
}

void random_bytes(void* out, size_t n) {
    if (n == 0) return;
    auto* p = static_cast<uint8_t*>(out);
#ifdef _WIN32
    while (n > 0) {
        ULONG chunk = n > 0x10000000u ? 0x10000000u : static_cast<ULONG>(n);
        if (BCryptGenRandom(nullptr, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            throw Error("random_bytes: BCryptGenRandom failed");
        p += chunk;
        n -= chunk;
    }
#else
    size_t done = 0;
#if defined(__linux__)
    while (done < n) {
        ssize_t r = ::getrandom(p + done, n - done, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;  // fall back to /dev/urandom
        }
        done += static_cast<size_t>(r);
    }
    if (done == n) return;
#endif
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw Error("random_bytes: cannot open /dev/urandom");
    while (done < n) {
        ssize_t r = ::read(fd, p + done, n - done);
        if (r < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw Error("random_bytes: read /dev/urandom failed");
        }
        if (r == 0) {
            ::close(fd);
            throw Error("random_bytes: /dev/urandom EOF");
        }
        done += static_cast<size_t>(r);
    }
    ::close(fd);
#endif
}

std::string to_hex(const void* data, size_t n) {
    static const char* d = "0123456789abcdef";
    const auto* p = static_cast<const uint8_t*>(data);
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s[2 * i] = d[p[i] >> 4];
        s[2 * i + 1] = d[p[i] & 15];
    }
    return s;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Bytes from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw Error("from_hex: odd length");
    Bytes out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int a = hexval(hex[2 * i]), b = hexval(hex[2 * i + 1]);
        if (a < 0 || b < 0) throw Error("from_hex: invalid character");
        out[i] = static_cast<uint8_t>(a << 4 | b);
    }
    return out;
}

bool ct_equal(const void* a, const void* b, size_t n) {
    const auto* x = static_cast<const volatile uint8_t*>(a);
    const auto* y = static_cast<const volatile uint8_t*>(b);
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= static_cast<uint8_t>(x[i] ^ y[i]);
    return acc == 0;
}

void secure_wipe(void* p, size_t n) {
    if (!p || n == 0) return;
#ifdef _WIN32
    SecureZeroMemory(p, n);
#else
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) v[i] = 0;
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int64_t now_unix_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace mysync
