// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// nettarget.h - ITarget that talks to a MySync server over a SecureChannel (pinned server public key).
//
// Connection loss and handshake failures are thrown as Error (the caller reconnects with open()). A request the
// server refuses for application reasons (path denied, read-only client, ...) is reported per file by
// put_file/put_batch (Failed) and as Error for remove/rename/mkdir/list_remote, without dropping the connection.
// A connection idle for more than ~10 s is checked with PING before reuse and re-opened transparently if dead.
// put_batch pipelines up to 64 OFFERs per window; a source that changes while it is read is reported as Failed
// ("changed during transfer") and the server never commits the partial result.
#include <memory>

#include "mysync/config.h"
#include "mysync/keys.h"
#include "mysync/ratelimit.h"
#include "mysync/target.h"

namespace mysync {

// limiter may be null (no bandwidth cap). `self` is the client identity; cfg.server_key must be set.
std::unique_ptr<ITarget> make_net_target(const TargetConfig& target, const ClientConfig& client, const KeyPair& self,
                                         std::shared_ptr<RateLimiter> limiter);

} // namespace mysync
