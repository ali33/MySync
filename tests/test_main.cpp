// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "testing.h"

int main(int argc, char** argv) {
    std::string filter = argc > 1 ? argv[1] : "";
    int pass = 0, fail = 0;
    for (auto& c : mytest::registry()) {
        if (!filter.empty() && std::string(c.name).find(filter) == std::string::npos) continue;
        try {
            c.fn();
            ++pass;
            std::cout << "[ OK ] " << c.name << "\n";
        } catch (const mytest::Failure& f) {
            ++fail;
            std::cout << "[FAIL] " << c.name << " : " << f.msg << "\n";
        } catch (const std::exception& e) {
            ++fail;
            std::cout << "[FAIL] " << c.name << " : exception " << e.what() << "\n";
        }
    }
    std::cout << pass << " passed, " << fail << " failed\n";
    return fail == 0 ? 0 : 1;
}
