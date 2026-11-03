// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// gui/invite_ops.h - what the desktop receiver (the GUI) asks of the receiving daemon about invites, over the local
// control channel (ControlOp::Invite*; encoded in gui/control_protocol.h). All of it is refused (ControlStatus::Denied,
// verbatim reason) when the daemon was not started with --allow-pairing or the configuration says [server] pairing = "off":
// "off" closes every invite path that goes through the GUI / control channel (the administrator's `mysync invite create`
// is not one of them). Nothing here ever carries a secret key; the invite CODE (which holds the invite secret) is returned
// once by InviteCreate and never again.
#include <cstdint>
#include <string>
#include <vector>

#include "mysync/simple/invite.h"

namespace mysync::gui {

struct InviteCreateReq {
    std::string folder;                        // ABSOLUTE folder on the receiver this code hands out (any folder)
    std::string label;                         // shown to the sender ("" = last component of the folder / "MySync")
    simple::InvitePerm perm = simple::InvitePerm::ReadWrite;
    uint32_t ttl_seconds = simple::kInviteDefaultTtlSeconds;
    uint32_t uses = simple::kInviteDefaultUses;
    bool ask = true;                           // "Hỏi tôi trước khi cho vào"
    std::vector<simple::InviteAddr> addrs;     // the addresses to put in the code (1..3), chosen by the GUI
};

struct InviteView {
    std::string id_hex, label, folder, created_by;
    simple::InvitePerm perm = simple::InvitePerm::ReadWrite;
    std::string state;                         // "live" | "expired" | "used-up" | "revoked"
    uint32_t uses_left = 0, uses_total = 0;
    int64_t expires_unix = 0;
    bool ask = false;
};

struct JoinedMachineView {                     // a machine that joined by invite (it is in the allowlist)
    std::string name, key_hex, when_utc, invite_id_hex, folder;
    simple::InvitePerm perm = simple::InvitePerm::ReadWrite;
};

struct InviteListInfo {
    bool allowed = false;                      // GUI invites allowed on this daemon (pairing not "off")
    std::string machine;                       // this machine's name
    std::string fingerprint;                   // of the receiver key (for "Chi tiết")
    uint16_t port = 0;
    std::string root;                          // the receiver configuration's own root (not a limit on invite folders)
    std::vector<InviteView> invites;           // newest first, at most ~50
    std::vector<JoinedMachineView> joined;
    std::vector<simple::PendingInvite> pending;   // `ask` invites waiting for "Đồng ý"
    std::string created_code;                  // InviteCreate only: the code (once)
};

}  // namespace mysync::gui
