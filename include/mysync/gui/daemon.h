// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/daemon.h - the daemon side of the GUI control channel (used by `mysync run`, not by the GUI itself).
//
// ClientDaemon / ServerDaemon wrap SyncEngine / Server, start the IPC server (when [control] enabled is true),
// answer PING / GET_STATUS / GET_RECENT_ERRORS and implement RELOAD_CONFIG:
//   * the file is parsed and validated first; on any error the running configuration is kept and the verbatim
//     error (with the line number) goes back to the caller;
//   * client: the new engine is built and vetted (key files readable, at least one watch+target) BEFORE the old one
//     is stopped; then the old engine is stopped (saves its index), a new one starts on the same state_dir so the
//     index is kept;
//   * server: Server::apply_config swaps allowlist / limits / ACL for new sessions; a changed bind / port / root /
//     key_file / state_dir is refused with "needs a restart";
//   * [control] settings (enabled / allow / group / name) only take effect after a restart and are reported in
//     ReloadResult::needs_restart.
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "mysync/client_engine.h"
#include "mysync/config.h"
#include "mysync/gui/ipc.h"
#include "mysync/gui/status.h"
#include "mysync/server.h"

namespace mysync::gui {

// Keeps the last ~200 Warn / Error log lines (via log_set_tap). Idempotent.
void install_error_tap();
std::vector<ErrorEntry> recent_log_errors(size_t max);
void clear_recent_log_errors();  // tests

struct DaemonOptions {
    std::string service_name;  // from --name; default mysync-server / mysync-client
    std::string config_path;   // absolute path of the file being run
    std::string version;
    std::string control_dir_override;  // tests (Linux): socket directory
    // Refuse a configuration (at start and on every reload) whose file or folder can be changed by someone who is not
    // the daemon's account, SYSTEM/root, an Administrator, or in [control] allow/group (see gui/trust.h). `mysync run`
    // turns this on for services and for elevated processes.
    bool enforce_config_trust = false;
    // The administrator's additions to the set of accounts allowed to change the configuration (the service's
    // `--trust-writer` arguments; see gui/trust.h). Never read from the configuration file itself.
    std::vector<std::string> trusted_writers;
    // Two real reloads must be at least this far apart (a no-op reload is free).
    int reload_min_interval_ms = 2000;
};

// Same path resolution `mysync run` applies after loading the file (relative key_file / state_dir / log_file /
// root are made absolute against the config directory).
ServerConfig load_server_config_resolved(const std::string& path);
ClientConfig load_client_config_resolved(const std::string& path);

// Owns the IPC server and the dispatch of requests onto status / reload callbacks.
class ControlHost {
public:
    using StatusFn = std::function<StatusSnapshot()>;
    using ReloadFn = std::function<ReloadResult()>;
    ControlHost(Role role, DaemonOptions opts, IpcServerOptions ipc, StatusFn status, ReloadFn reload);
    ~ControlHost();
    void start();   // throws Error (the endpoint could not be created)
    void stop();
    const std::string& endpoint() const;
    // Fields every status carries: version, service name, uptime, taken time, config path / load time / error.
    void set_config_state(int64_t loaded_unix_ms, const std::string& config_error);

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

class ClientDaemon {
public:
    ClientDaemon(ClientConfig cfg, std::string config_dir, DaemonOptions opts);
    ~ClientDaemon();
    // Blocks until `stop`. Starts the IPC server first (a failure there is logged, sync continues). Rethrows a fatal
    // engine error (unusable configuration at start) like SyncEngine::run did.
    void run(std::atomic<bool>& stop);
    StatusSnapshot snapshot();     // thread-safe
    ReloadResult reload();         // thread-safe, serialised

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

class ServerDaemon {
public:
    ServerDaemon(ServerConfig cfg, std::string config_dir, DaemonOptions opts);
    ~ServerDaemon();
    void run(std::atomic<bool>& stop);   // constructs Server (throws Error on bind / key problems) and serves
    StatusSnapshot snapshot();
    ReloadResult reload();

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

}  // namespace mysync::gui
