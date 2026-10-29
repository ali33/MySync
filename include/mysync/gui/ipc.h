// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/ipc.h - local IPC between the daemon and the GUI. NO TCP port is ever opened.
//
// Windows : named pipe  \\.\pipe\mysync-<name>, created by the daemon with
//             * FILE_FLAG_FIRST_PIPE_INSTANCE on the first instance (a squatter cannot take the name),
//             * PIPE_REJECT_REMOTE_CLIENTS,
//             * a protected DACL: SYSTEM + Administrators + the account running the daemon + every SID /
//               account listed in `allow`. Never Everyone / Users / Authenticated Users / Anonymous.
// Linux   : unix socket <dir>/<name>.sock, dir = /run/mysync (root) or $XDG_RUNTIME_DIR/mysync (other users),
//             dir 0750, socket 0660 (group set) or 0600, a symlink at any step is refused, SO_PEERCRED is checked
//             on every accepted connection (uid == daemon's uid, or root, or member of `group`).
// A message larger than kMaxMessageBytes, a stalled peer (read timeout) and more than `max_connections`
// simultaneous peers are all refused / dropped. One request per message; the server answers on the same connection.
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "mysync/gui/control_protocol.h"

namespace mysync::gui {

// Name rule shared by pipe / socket / service names: [A-Za-z0-9_.-], 1..64, not starting with '-' or '.'.
bool valid_control_name(const std::string& name);
// Where the endpoint for `name` lives (pipe path or socket path). Throws Error on an invalid name.
// dir_override (Linux only, tests): directory instead of /run/mysync.
std::string control_endpoint_path(const std::string& name, const std::string& dir_override = "");

// The name a daemon listens under: [control] name when set, else the service name given with --name, else
// "mysync-server" / "mysync-client". The GUI uses the same function to find the daemon of a config file.
std::string effective_control_name(const std::string& configured_name, const std::string& service_name, bool is_server);

// Every place a client should look for the daemon's endpoint (Linux: /run/mysync first, then
// $XDG_RUNTIME_DIR/mysync; Windows: the single pipe path).
std::vector<std::string> control_endpoint_candidates(const std::string& name, const std::string& dir_override = "");

namespace detail {
// Linux/POSIX peer admission rule applied to SO_PEERCRED data (pure, testable everywhere): root, the daemon's own
// uid, or a member of the allowed group.
bool ipc_peer_allowed(uint32_t peer_uid, uint32_t self_uid, const std::vector<uint32_t>& peer_gids, bool has_group,
                      uint32_t group_gid);
// Windows: security descriptor text (SDDL) for the pipe, from SID strings. Refuses Everyone / Users /
// Authenticated Users / Anonymous / Network / Interactive / Guests / Local. Pure, testable everywhere.
std::string ipc_pipe_sddl(const std::vector<std::string>& extra_sids, const std::string& owner_sid);
}  // namespace detail

// ---------------------------------------------------------------- server (inside the daemon)
struct IpcServerOptions {
    std::string name;                      // control name (-> control_endpoint_path)
    std::vector<std::string> allow;        // Windows: "S-1-5-..." or "DOMAIN\\user" (extra to SYSTEM+Administrators)
    std::string group;                     // Linux: group allowed to connect ("" = owner and root only)
    size_t max_connections = 4;            // simultaneous peers
    int read_timeout_ms = 5000;            // a peer that stalls mid-message is dropped
    std::string dir_override;              // Linux test hook: directory instead of /run/mysync
    int idle_timeout_ms = 60000;           // a connection that sends nothing for this long is closed
    int max_lifetime_ms = 600000;          // no connection lives longer than this, however busy
};

// Handler runs on an IPC worker thread; it may throw (answered with status Failed + the message).
using ControlHandler = std::function<ControlResponse(const ControlRequest&)>;

class IpcServer {
public:
    IpcServer(IpcServerOptions opts, ControlHandler handler);
    ~IpcServer();  // stop()
    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    // Creates the endpoint and starts the accept thread. Throws Error (e.g. name already taken, bad allow entry).
    void start();
    void stop();   // idempotent, joins every thread
    const std::string& endpoint() const;
    uint64_t rejected_peers() const;  // connections refused for lack of permission or limit (diagnostics / tests)

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

// ---------------------------------------------------------------- client (inside the GUI / tools)
// Thread-safe: every call opens its own connection (one short exchange), so a daemon restart is transparent.
class ControlClient {
public:
    explicit ControlClient(std::string name, int timeout_ms = 5000, std::string dir_override = "");

    // Raw exchange. Throws Error when the daemon is not running / refuses / times out / answers garbage.
    ControlResponse call(const ControlRequest& req);

    bool ping();                                   // false (never throws) when nobody answers
    StatusSnapshot get_status();                   // throws Error
    ReloadResult reload_config();                  // throws Error for transport errors; config errors come back in .ok/.message
    std::vector<ErrorEntry> recent_errors(uint32_t max = 50);

    const std::string& name() const { return name_; }

    // Windows: before trusting any data the client checks which account runs the process behind the pipe
    // (GetNamedPipeServerProcessId). Accepted: SYSTEM, LocalService, NetworkService, a member of Administrators, the
    // calling user, and every account added here ("S-1-5-..." or a name). Elsewhere the owner of the socket is checked.
    void trust_server_account(const std::string& sid_or_name);

private:
    std::string name_;
    int timeout_ms_;
    std::string dir_override_;
    std::vector<std::string> trusted_accounts_;
    std::mutex m_;
    uint64_t next_token_ = 1;
};

}  // namespace mysync::gui
