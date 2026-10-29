// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// Minimal test harness. Usage in tests/*.cpp:
//   #include "testing.h"
//   TEST(name) { CHECK(cond); CHECK_EQ(a, b); }
// tests/test_main.cpp runs all registered tests; exit code 0 only if all pass. Optional argv[1] = substring filter.
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace mytest {
struct Case { const char* name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
struct Reg { Reg(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); } };
struct Failure { std::string msg; };
}  // namespace mytest

#define TEST(name) \
    static void test_##name(); \
    static mytest::Reg reg_##name(#name, test_##name); \
    static void test_##name()
#define CHECK(c) do { if (!(c)) throw mytest::Failure{std::string(__FILE__) + ":" + std::to_string(__LINE__) + " CHECK failed: " #c}; } while (0)
#define CHECK_EQ(a, b) do { auto _a = (a); auto _b = (b); if (!(_a == _b)) throw mytest::Failure{std::string(__FILE__) + ":" + std::to_string(__LINE__) + " CHECK_EQ failed: " #a " == " #b}; } while (0)
#define CHECK_THROWS(expr) do { bool _t = false; try { (void)(expr); } catch (const std::exception&) { _t = true; } if (!_t) throw mytest::Failure{std::string(__FILE__) + ":" + std::to_string(__LINE__) + " expected exception: " #expr}; } while (0)
