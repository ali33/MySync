// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/user_engine.h - the GUI supervises the sync engine as a CHILD PROCESS under the current user.
//   mysync run -c <config.toml> --role client            (always, once a configuration exists)
//   mysync run -c <server-user.toml> --role server --allow-pairing   (only while "receive from other machines" is on)
// Why a child process: an engine crash or hang never takes the window down, and the OS reclaims everything.
//  * the executable is looked for next to mysync-gui (absolute path, exists, regular file); the process is started
//    without a shell (CreateProcess with a quoted command line / posix_spawn), console hidden, no inherited handles;
//  * Windows: a Job Object with KILL_ON_JOB_CLOSE, so the engine dies with the GUI if the GUI is killed; Linux:
//    prctl(PR_SET_PDEATHSIG) in the child. Closing the WINDOW to the tray does not touch the engines: only
//    stop_all() ("Quit completely") does;
//  * an engine that exits is restarted after 1 s, 2 s, 5 s, 10 s, 30 s, 60 s (then 60 s); after max_fast_deaths
//    consecutive deaths within fast_death_ms of starting, the supervisor stops trying and reports the verbatim last
//    lines of the engine's output;
//  * a per-user instance lock keeps a second GUI from starting a second set of engines;
//  * every engine takes <folder>/__sync/engine.lock before it watches a folder (engine_lock.h), so even a service
//    and a user engine can never watch the same folder.
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mysync/simple/user_paths.h"
#include "mysync/util.h"

namespace mysync::simple {

enum class EngineKind { Client, Receiver };
enum class EngineState {
    Stopped,   // not wanted (disabled) or stopped by stop()
    Starting,  // process created, not yet known healthy
    Running,
    Backoff,   // died; waiting for the next attempt (next_retry_ms)
    GaveUp,    // too many fast deaths in a row: last_error has the verbatim text
};
const char* engine_state_name(EngineState);

struct EngineInfo {
    EngineKind kind = EngineKind::Client;
    EngineState state = EngineState::Stopped;
    uint32_t pid = 0;
    int restarts = 0;       // restarts since start()
    int fast_deaths = 0;    // consecutive deaths within fast_death_ms
    int next_retry_ms = 0;  // Backoff: time left
    int last_exit_code = 0;
    std::string last_error;    // verbatim last lines of stderr/stdout of the engine ("" = none)
    std::string control_name;  // endpoint to talk to this engine
};

struct SupervisorOptions {
    UserPaths paths;
    std::string mysync_exe;  // "" = find_engine_exe()
    bool run_client = true;
    bool run_receiver = false;
    // Overrides for tests: full argument vectors AFTER the executable (empty = the standard command line).
    std::vector<std::string> client_args, receiver_args;
    std::vector<int> backoff_ms{1000, 2000, 5000, 10000, 30000, 60000};
    int fast_death_ms = 10000;
    int max_fast_deaths = 5;
    int stop_grace_ms = 4000;  // stop: wait this long before killing
    std::function<void(const EngineInfo&)> on_change;  // called from the supervisor thread; must be quick
};

// Absolute path of the mysync executable next to the running program (mysync-gui). Throws Error with a clear text
// when it is missing, not a regular file or not absolute.
std::string find_engine_exe();

// One GUI (and so one set of engines) per user. Returns nullptr if another already holds it; *holder = "PID n".
class InstanceLock {
public:
    static std::unique_ptr<InstanceLock> try_acquire(const UserPaths& p, std::string* holder = nullptr);
    ~InstanceLock();

private:
    InstanceLock() = default;
    struct Impl;
    std::unique_ptr<Impl> p_;
};

class Supervisor {
public:
    explicit Supervisor(SupervisorOptions opts);
    ~Supervisor();  // stop_all()
    Supervisor(const Supervisor&) = delete;
    Supervisor& operator=(const Supervisor&) = delete;

    void start();                         // starts the thread; engines per run_client / run_receiver. Throws Error
    void stop_all();                      // terminate every engine and wait (releases folder locks); idempotent
    void set_receiver_enabled(bool on);   // start / stop the receiver engine
    void set_client_enabled(bool on);
    // Stop and start again (e.g. after the configuration was replaced); also clears GaveUp and the fast-death count.
    void restart(EngineKind k);
    // Wait until the engine of this kind is not running (its OS locks are released). False on timeout.
    bool wait_stopped(EngineKind k, int timeout_ms);

    std::vector<EngineInfo> info() const;  // thread-safe copy
    EngineInfo info(EngineKind k) const;

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

}  // namespace mysync::simple
