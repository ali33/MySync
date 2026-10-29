// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// Internal: contract between the platform watch backends and the debounce core in watcher.cpp.
#include <functional>
#include <memory>
#include <string>

#include "mysync/watcher.h"

namespace mysync::detail {

struct RawEvent {
    WatchEvent::Kind kind = WatchEvent::Modified;
    std::string rel;
    std::string rel_from;
    bool is_dir = false;
};

struct BackendSink {
    std::function<void(RawEvent&&)> push;  // thread-safe; backend thread calls it
    std::function<void()> degraded;        // backend cannot watch everything: owner must rely on periodic scans
};

class WatchBackend {
public:
    virtual ~WatchBackend() = default;
    virtual void start() = 0;  // throws Error if the root cannot be watched
    virtual void stop() = 0;   // idempotent; joins the backend thread, closes handles
};

// Implemented in watcher_win.cpp / watcher_linux.cpp (throws Error on other platforms).
std::unique_ptr<WatchBackend> make_watch_backend(const WatcherOptions& opt, BackendSink sink);

}  // namespace mysync::detail
