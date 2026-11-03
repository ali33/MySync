// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// The invite operations of the local control channel (gui/invite_ops.h, control_protocol.h): encoding of every new op,
// strict bounded decoding, the one-frame size bound, and the daemon side over a real IPC endpoint (create / list / revoke /
// remove machine / approve / deny, and "Denied" when pairing is off).
#include <atomic>
#include <thread>

#include "mysync/config.h"
#include "mysync/gui/control_protocol.h"
#include "mysync/gui/daemon.h"
#include "mysync/gui/ipc.h"
#include "mysync/peers.h"
#include "mysync/protocol.h"
#include "mysync/quick_setup.h"
#include "mysync/simple/invite.h"
#include "mysync/simple/pairing.h"
#include "mysync/simple/user_paths.h"
#include "so_util.h"

using namespace mysync;
using namespace mysync::gui;
using sotest::Tmp;

namespace {

InviteCreateReq sample_create() {
    InviteCreateReq q;
    q.folder = "Bao-cao/2026";
    q.label = "B\xC3\xA1o c\xC3\xA1o";
    q.perm = simple::InvitePerm::ReadOnly;
    q.ttl_seconds = 3600;
    q.uses = 5;
    q.ask = false;
    q.addrs = {{"192.168.1.20", 5656}, {"nhan.example.org", 6000}};
    return q;
}

InviteListInfo sample_info(size_t n_inv, size_t n_join, size_t name_len = 20) {
    InviteListInfo v;
    v.allowed = true;
    v.machine = "MAY-NHAN";
    v.fingerprint = "aaaa-bbbb-cccc-dddd-eeee";
    v.port = 5656;
    v.root = "D:/Nhan";
    v.created_code = "MSY2-ABCDE-FGHJK";
    for (size_t i = 0; i < n_inv; ++i) {
        InviteView x;
        x.id_hex = "0123456789abcdef";
        x.label = std::string(name_len, 'L');
        x.folder = std::string(name_len, 's');
        x.created_by = "gui";
        x.perm = i % 2 ? simple::InvitePerm::ReadOnly : simple::InvitePerm::ReadWrite;
        x.state = "live";
        x.uses_left = 1;
        x.uses_total = 2;
        x.expires_unix = 1900000000 + int64_t(i);
        x.ask = i % 2 == 0;
        v.invites.push_back(x);
    }
    for (size_t i = 0; i < n_join; ++i) {
        JoinedMachineView j;
        j.name = std::string(name_len, 'N');
        j.key_hex = std::string(64, 'b');
        j.when_utc = "2026-11-02 07:30";
        j.invite_id_hex = "0123456789abcdef";
        j.folder = std::string(name_len, 's');
        v.joined.push_back(j);
    }
    simple::PendingInvite p;
    p.id = 7;
    p.name = "MAY-GUI";
    p.sas = "ABCD-EFGH-JKMN-PQRS";
    p.ip = "192.168.1.30";
    p.seconds_left = 90;
    p.label = "Bao cao";
    v.pending.push_back(p);
    return v;
}

ControlResponse resp_with(const InviteListInfo& v, ControlOp op = ControlOp::InviteList) {
    ControlResponse r;
    r.op = op;
    r.token = 42;
    r.invites = v;
    return r;
}

}  // namespace

// ------------------------------------------------------------------------------------------------ requests
TEST(gui_invite_ops_request_round_trip_for_every_new_op) {
    {   // InviteCreate: the payload is the structured request
        ControlRequest q;
        q.op = ControlOp::InviteCreate;
        q.token = 9;
        q.payload = encode_invite_create(sample_create());
        ControlRequest d = decode_request(encode_request(q));
        CHECK(d.op == ControlOp::InviteCreate);
        CHECK_EQ(d.token, uint64_t(9));
        InviteCreateReq c = decode_invite_create(d.payload);
        CHECK_EQ(c.folder, std::string("Bao-cao/2026"));
        CHECK_EQ(c.label, std::string("B\xC3\xA1o c\xC3\xA1o"));
        CHECK(c.perm == simple::InvitePerm::ReadOnly);
        CHECK_EQ(c.ttl_seconds, uint32_t(3600));
        CHECK_EQ(c.uses, uint32_t(5));
        CHECK(!c.ask);
        CHECK_EQ(c.addrs.size(), size_t(2));
        CHECK_EQ(c.addrs[1].host, std::string("nhan.example.org"));
        CHECK_EQ(c.addrs[1].port, uint16_t(6000));
    }
    for (ControlOp op : {ControlOp::InviteRevoke, ControlOp::InviteRemoveMachine}) {
        ControlRequest q;
        q.op = op;
        q.token = 3;
        q.payload = encode_invite_text(op == ControlOp::InviteRevoke ? "0123456789abcdef" : std::string(64, 'c'));
        ControlRequest d = decode_request(encode_request(q));
        CHECK(d.op == op);
        CHECK_EQ(decode_invite_text(d.payload), decode_invite_text(q.payload));
    }
    for (ControlOp op : {ControlOp::InviteList, ControlOp::InviteApprove, ControlOp::InviteDeny}) {
        ControlRequest q;
        q.op = op;
        q.token = 5;
        q.arg = 77;
        ControlRequest d = decode_request(encode_request(q));
        CHECK(d.op == op);
        CHECK_EQ(d.arg, uint32_t(77));
        CHECK(d.payload.empty());
    }
    CHECK_EQ(std::string(control_op_name(ControlOp::InviteCreate)), std::string("INVITE_CREATE"));
    CHECK_EQ(std::string(control_op_name(ControlOp::InviteRemoveMachine)), std::string("INVITE_REMOVE_MACHINE"));
}

TEST(gui_invite_ops_old_requests_still_decode_and_stay_strict) {
    ControlRequest q;
    q.op = ControlOp::GetRecentErrors;
    q.token = 1;
    q.arg = 20;
    Bytes b = encode_request(q);
    CHECK_EQ(b.size(), size_t(2 + 1 + 8 + 4));   // the old form, byte for byte
    ControlRequest d = decode_request(b);
    CHECK_EQ(d.arg, uint32_t(20));
    Bytes extra = b;
    extra.push_back(0);
    CHECK_THROWS(decode_request(extra));          // an old op takes no trailing bytes
    q.payload = {1, 2, 3};
    CHECK_THROWS(encode_request(q));              // ... and no payload either
    // a Ping with a payload-shaped tail is not accepted
    ControlRequest p;
    Bytes pb = encode_request(p);
    pb.insert(pb.end(), {0, 0, 0, 1, 7});
    CHECK_THROWS(decode_request(pb));
}

TEST(gui_invite_ops_request_payload_is_bounded_and_strict) {
    ControlRequest q;
    q.op = ControlOp::InviteRevoke;
    q.payload = encode_invite_text("0123456789abcdef");
    Bytes good = encode_request(q);
    // every truncation fails, never reads past the end
    for (size_t n = 0; n < good.size(); ++n) CHECK_THROWS(decode_request(good.data(), n));
    // trailing bytes after the payload
    Bytes tail = good;
    tail.push_back(0);
    CHECK_THROWS(decode_request(tail));
    // the payload is required for these ops
    ControlRequest none;
    none.op = ControlOp::InviteCreate;
    CHECK_THROWS(encode_request(none));
    Bytes head = encode_request(ControlRequest{ControlOp::Ping, 1, 0, {}});
    head[2] = static_cast<uint8_t>(ControlOp::InviteRevoke);
    CHECK_THROWS(decode_request(head));                      // revoke without a payload length
    // length 0, absurd length, length beyond the data
    for (uint32_t len : {0u, kMaxRequestPayload + 1, 0xFFFFFFFFu, 1000u}) {
        Bytes b = head;
        proto::Writer w;
        w.u32(len);
        b.insert(b.end(), w.bytes().begin(), w.bytes().end());
        b.push_back(1);
        CHECK_THROWS(decode_request(b));
    }
    // too large on the encoding side
    ControlRequest big = q;
    big.payload.assign(kMaxRequestPayload + 1, 'x');
    CHECK_THROWS(encode_request(big));
    // create payload: absurd address count, bad perm, trailing bytes, truncation
    Bytes c = encode_invite_create(sample_create());
    for (size_t n = 0; n < c.size(); ++n) CHECK_THROWS(decode_invite_create(Bytes(c.begin(), c.begin() + n)));
    Bytes t2 = c;
    t2.push_back(0);
    CHECK_THROWS(decode_invite_create(t2));
    {
        proto::Writer w;
        w.str("");
        w.str("");
        w.u8(2);   // perm must be 0 or 1
        w.u32(1);
        w.u32(1);
        w.boolean(true);
        w.u8(0);
        CHECK_THROWS(decode_invite_create(w.take()));
    }
    {
        proto::Writer w;
        w.str("");
        w.str("");
        w.u8(1);
        w.u32(1);
        w.u32(1);
        w.boolean(true);
        w.u8(200);   // 200 addresses
        CHECK_THROWS(decode_invite_create(w.take()));
    }
    // text payload: trailing bytes
    Bytes t3 = encode_invite_text("abcd");
    t3.push_back(1);
    CHECK_THROWS(decode_invite_text(t3));
}

// ------------------------------------------------------------------------------------------------ responses
TEST(gui_invite_ops_response_round_trip_and_rejections) {
    InviteListInfo v = sample_info(3, 2);
    Bytes b = encode_response(resp_with(v));
    ControlResponse d = decode_response(b);
    CHECK(d.op == ControlOp::InviteList);
    CHECK_EQ(d.token, uint64_t(42));
    CHECK(d.invites.allowed);
    CHECK_EQ(d.invites.machine, std::string("MAY-NHAN"));
    CHECK_EQ(d.invites.fingerprint, std::string("aaaa-bbbb-cccc-dddd-eeee"));
    CHECK_EQ(d.invites.port, uint16_t(5656));
    CHECK_EQ(d.invites.root, std::string("D:/Nhan"));
    CHECK_EQ(d.invites.created_code, std::string("MSY2-ABCDE-FGHJK"));
    CHECK_EQ(d.invites.invites.size(), size_t(3));
    CHECK(d.invites.invites[1].perm == simple::InvitePerm::ReadOnly);
    CHECK(d.invites.invites[0].ask);
    CHECK_EQ(d.invites.invites[2].expires_unix, int64_t(1900000002));
    CHECK_EQ(d.invites.joined.size(), size_t(2));
    CHECK_EQ(d.invites.joined[0].when_utc, std::string("2026-11-02 07:30"));
    CHECK_EQ(d.invites.pending.size(), size_t(1));
    CHECK_EQ(d.invites.pending[0].sas, std::string("ABCD-EFGH-JKMN-PQRS"));
    CHECK_EQ(d.invites.pending[0].seconds_left, 90);
    for (ControlOp op : {ControlOp::InviteCreate, ControlOp::InviteRevoke, ControlOp::InviteRemoveMachine,
                         ControlOp::InviteApprove, ControlOp::InviteDeny}) {
        ControlResponse r = decode_response(encode_response(resp_with(v, op)));
        CHECK(r.op == op);
        CHECK_EQ(r.invites.invites.size(), size_t(3));
    }
    // a refusal carries the verbatim reason and an empty body
    ControlResponse den;
    den.op = ControlOp::InviteList;
    den.status = ControlStatus::Denied;
    den.error = "invites are switched off in the configuration";
    ControlResponse dd = decode_response(encode_response(den));
    CHECK(dd.status == ControlStatus::Denied);
    CHECK_EQ(dd.error, den.error);
    CHECK(!dd.invites.allowed);
    // every truncation fails
    for (size_t n = 0; n < b.size(); ++n) CHECK_THROWS(decode_response(b.data(), n));
    // trailing bytes
    Bytes tail = b;
    tail.push_back(0);
    CHECK_THROWS(decode_response(tail));
}

TEST(gui_invite_ops_response_rejects_absurd_counts_and_bad_values) {
    // Build the body by hand: a valid header, then a count above the cap.
    auto head = [](proto::Writer& w) {
        w.u16(kControlVersion);
        w.u8(static_cast<uint8_t>(ControlOp::InviteList));
        w.u64(1);
        w.u8(0);
        w.str("");
        w.boolean(true);
        w.str("m");
        w.str("f");
        w.u16(1);
        w.str("r");
        w.str("");
    };
    {
        proto::Writer w;
        head(w);
        w.u16(static_cast<uint16_t>(kMaxInviteRows + 1));   // too many invites
        CHECK_THROWS(decode_response(w.take()));
    }
    {
        proto::Writer w;
        head(w);
        w.u16(0);
        w.u16(60000);   // too many joined
        CHECK_THROWS(decode_response(w.take()));
    }
    {
        proto::Writer w;
        head(w);
        w.u16(0);
        w.u16(0);
        w.u16(9);   // too many waiting
        CHECK_THROWS(decode_response(w.take()));
    }
    {   // a valid empty body decodes
        proto::Writer w;
        head(w);
        w.u16(0);
        w.u16(0);
        w.u16(0);
        CHECK(decode_response(w.take()).invites.allowed);
    }
    {   // bad permission byte in an invite row
        proto::Writer w;
        head(w);
        w.u16(1);
        for (int i = 0; i < 4; ++i) w.str("x");
        w.u8(9);
        w.str("live");
        w.u32(1);
        w.u32(1);
        w.i64(5);
        w.boolean(false);
        w.u16(0);
        w.u16(0);
        CHECK_THROWS(decode_response(w.take()));
    }
    {   // a boolean that is neither 0 nor 1
        proto::Writer w;
        w.u16(kControlVersion);
        w.u8(static_cast<uint8_t>(ControlOp::InviteList));
        w.u64(1);
        w.u8(0);
        w.str("");
        w.u8(7);
        CHECK_THROWS(decode_response(w.take()));
    }
}

TEST(gui_invite_ops_response_always_fits_one_frame) {
    // The biggest legal answer: 50 invites and 50 joined machines with long names, and a pending request.
    InviteListInfo v = sample_info(kMaxInviteRows + 20, kMaxInviteRows + 20, 190);
    v.root = std::string(1000, 'r');
    v.created_code = std::string(1500, 'C');
    Bytes b = encode_response(resp_with(v));
    CHECK(b.size() <= kMaxMessageBytes);
    ControlResponse d = decode_response(b);
    CHECK_EQ(d.invites.invites.size(), kMaxInviteRows);   // the extra rows were dropped from the end, not the first ones
    CHECK_EQ(d.invites.joined.size(), kMaxInviteRows);
    CHECK_EQ(d.invites.created_code.size(), size_t(1500));
    CHECK_EQ(frame_message(b).size(), b.size() + 4);
    // the first rows survive (the list is newest first)
    CHECK_EQ(d.invites.invites[0].expires_unix, int64_t(1900000000));
}

// ------------------------------------------------------------------------------------------------ the daemon over IPC
namespace {

struct InvEnv {
    Tmp t;
    fs::path root, cfg, key, state;
    KeyPair skp = generate_keypair();
    uint16_t port = sotest::free_port();
    std::string ctl, dir;
    std::atomic<bool> stop{false};
    std::thread th;
    std::string fail;
    std::unique_ptr<ServerDaemon> sd;

    static fs::path private_cfg(const fs::path& p, bool strict) {   // strict trust accepts only a configuration folder nobody else can write
        fs::create_directories(p);
        if (strict) make_folder_private(p.u8string());
        return p;
    }
    InvEnv(const std::string& pairing_line, bool allow_pairing, bool strict = false) {
        uint8_t r[4];
        random_bytes(r, sizeof r);
        ctl = "gui-inv-" + to_hex(r, sizeof r);
        root = t.p / "root";
        cfg = t.p / "cfg" / "server.toml";
        key = t.p / "cfg" / "server.key";
        state = t.p / "cfg" / "state";
        fs::create_directories(root);
        private_cfg(t.p / "cfg", strict);
        save_keypair(key.u8string(), skp);
#ifndef _WIN32
        dir = (t.p / "ctl").u8string();
#endif
        std::string text = "[server]\nbind = \"127.0.0.1\"\nport = " + std::to_string(port) + "\nroot = \"" + t.s("root") +
                           "\"\nkey_file = \"" + t.s("cfg/server.key") + "\"\nstate_dir = \"" + t.s("cfg/state") +
                           "\"\nlog_level = \"error\"\n" + pairing_line + "\n[control]\nname = \"" + ctl + "\"\n\n[[client]]\nname = \"boot\"\npublic_key = \"" +
                           key_to_hex(generate_keypair().pub) + "\"\n";
        sotest::spit(cfg, text);
        DaemonOptions o;
        o.service_name = ctl;
        o.config_path = cfg.u8string();
        o.version = "test";
        o.allow_pairing = allow_pairing;
        o.control_dir_override = dir;
        o.enforce_config_trust = strict;
        o.peers_poll_ms = 0;
        o.reload_min_interval_ms = 0;
        sd = std::make_unique<ServerDaemon>(load_server_config_resolved(o.config_path), t.s(""), o);
        th = std::thread([this] {
            try {
                sd->run(stop);
            } catch (const std::exception& e) {
                fail = e.what();
            }
        });
    }
    ~InvEnv() {
        stop = true;
        if (th.joinable()) th.join();
    }
    ControlClient client() { return ControlClient(ctl, 8000, dir); }
    bool ready() {
        return sotest::wait_until([&] { return client().ping(); }, 15000) && sotest::wait_until([&] { return sd->invites() != nullptr; }, 15000);
    }
    int seq = 0;
    // Every code hands out its own ABSOLUTE folder (InviteCreateReq::folder carries it); two codes never overlap.
    InviteCreateReq req(bool ask) {
        InviteCreateReq q;
        q.folder = t.s("share" + std::to_string(++seq));
        q.label = "Bao cao";
        q.ask = ask;
        q.addrs = {{"127.0.0.1", port}};
        return q;
    }
};

std::string deny_reason(ControlClient& c, const std::function<void(ControlClient&)>& f) {
    try {
        f(c);
    } catch (const Error& e) {
        return e.what();
    }
    return "";
}

}  // namespace

TEST(gui_invite_ops_create_over_ipc_returns_a_decodable_msy2_code_and_lists_it) {
    InvEnv e("pairing = \"on-demand\"\n", /*allow_pairing=*/true);
    CHECK(e.ready());
    ControlClient c = e.client();
    InviteCreateReq q = e.req(false);
    q.perm = simple::InvitePerm::ReadOnly;
    q.ttl_seconds = 3600;
    q.uses = 3;
    InviteListInfo made = c.invite_create(q);
    CHECK(made.allowed);
    CHECK(!made.created_code.empty());
    CHECK(made.created_code.rfind("MSY2-", 0) == 0);
    simple::InviteCode code = simple::decode_invite_code(made.created_code);
    CHECK(code.server_key == e.skp.pub);                    // the receiver's PUBLIC key, never a secret
    CHECK(code.perm == simple::InvitePerm::ReadOnly);
    CHECK_EQ(code.label, std::string("Bao cao"));
    CHECK_EQ(code.machine, simple::default_device_name());
    CHECK_EQ(code.addrs.size(), size_t(1));
    CHECK_EQ(code.addrs[0].port, e.port);
    CHECK(code.expires_unix > int64_t(std::time(nullptr)) + 3000);
    CHECK(code.expires_unix <= int64_t(std::time(nullptr)) + 3700);
    CHECK_EQ(made.fingerprint, simple::invite_fingerprint(e.skp.pub));
    CHECK_EQ(made.port, e.port);
    // the code is not stored anywhere the list can return it again
    InviteListInfo list = c.invite_list();
    CHECK(list.created_code.empty());
    CHECK_EQ(list.invites.size(), size_t(1));
    CHECK_EQ(list.invites[0].id_hex, simple::invite_id_hex(code.id));
    CHECK_EQ(list.invites[0].state, std::string("live"));
    CHECK_EQ(list.invites[0].uses_left, uint32_t(3));
    CHECK_EQ(list.invites[0].created_by, std::string("gui"));
    CHECK(list.invites[0].perm == simple::InvitePerm::ReadOnly);
    CHECK_EQ(list.machine, simple::default_device_name());
    // ttl and uses are clamped, a bad folder and an empty address list are refused with the reason
    InviteCreateReq wild = e.req(false);
    wild.ttl_seconds = 0xFFFFFFFFu;
    wild.uses = 100000;
    InviteListInfo w = c.invite_create(wild);
    simple::InviteCode wc = simple::decode_invite_code(w.created_code);
    CHECK(wc.expires_unix <= int64_t(std::time(nullptr)) + simple::kInviteMaxTtlSeconds + 60);
    InviteCreateReq bad = e.req(false);
    bad.folder = "../escape";   // not an absolute folder
    CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_create(bad); }).empty());
    InviteCreateReq noaddr = e.req(false);
    noaddr.addrs.clear();
    CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_create(noaddr); }).empty());
    // nothing was created by the refused requests
    CHECK_EQ(c.invite_list().invites.size(), size_t(2));
}

TEST(gui_invite_ops_revoke_works_and_an_unknown_id_is_refused) {
    InvEnv e("pairing = \"on-demand\"\n", true);
    CHECK(e.ready());
    ControlClient c = e.client();
    simple::InviteCode code = simple::decode_invite_code(c.invite_create(e.req(false)).created_code);
    std::string id = simple::invite_id_hex(code.id);
    CHECK_EQ(c.invite_list().invites.size(), size_t(1));
    InviteListInfo after = c.invite_revoke(id);
    CHECK(after.invites.empty());                      // no longer live
    CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_revoke("ffffffffffffffff"); }).empty());
    // a revoked code is refused by the receiver
    std::atomic<bool> cancel{false};
    KeyPair me = generate_keypair();
    simple::InviteOutcome o = simple::probe_invite(code, me, cancel);
    // With no live invite left the receiver does not even finish the handshake of an unknown key: the sender sees the
    // same "cannot reach" as for a wrong address (the two are deliberately not told apart); a still-live other invite
    // would make it a plain refusal.
    if (o.kind != simple::InviteOutcome::Refused && o.kind != simple::InviteOutcome::Unreachable)
        throw mytest::Failure{"a revoked code gave kind " + std::to_string(int(o.kind)) + ": " + o.message};
}

TEST(gui_invite_ops_pairing_off_is_denied_with_the_verbatim_reason_on_every_request) {
    {   // the configuration says "off": the process flag is ignored
        InvEnv e("pairing = \"off\"\n", /*allow_pairing=*/true);
        CHECK(e.ready());
        ControlClient c = e.client();
        std::string r1 = deny_reason(c, [&](ControlClient& x) { x.invite_create(e.req(false)); });
        CHECK(r1.find("switched off") != std::string::npos);
        CHECK(r1.find("pairing") != std::string::npos);
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_list(); }).empty());
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_revoke("0123456789abcdef"); }).empty());
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_remove_machine(std::string(64, 'a')); }).empty());
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_approve(1); }).empty());
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_deny(1); }).empty());
        // the raw status is Denied
        ControlRequest q;
        q.op = ControlOp::InviteList;
        q.token = 11;
        ControlResponse resp = c.call(q);
        CHECK(resp.status == ControlStatus::Denied);
        CHECK(!resp.error.empty());
        CHECK(!resp.invites.allowed);
    }
    {   // the process was not started with --allow-pairing
        InvEnv e("pairing = \"on-demand\"\n", /*allow_pairing=*/false);
        CHECK(e.ready());
        ControlClient c = e.client();
        std::string r = deny_reason(c, [&](ControlClient& x) { x.invite_create(e.req(false)); });
        CHECK(r.find("--allow-pairing") != std::string::npos);
        ControlRequest q;
        q.op = ControlOp::InviteList;
        CHECK(c.call(q).status == ControlStatus::Denied);
    }
}

TEST(gui_invite_ops_join_remove_machine_and_the_ask_flow_end_to_end) {
    InvEnv e("pairing = \"on-demand\"\n", true);
    CHECK(e.ready());
    ControlClient c = e.client();
    std::atomic<bool> cancel{false};

    // ---- an invite without confirmation: the sender joins at once, the list shows its NAME (never a key)
    simple::InviteCode code = simple::decode_invite_code(c.invite_create(e.req(false)).created_code);
    KeyPair me = generate_keypair();
    simple::InviteOutcome o = simple::redeem_invite(code, me, "MAY-GUI", cancel);
    CHECK(o.kind == simple::InviteOutcome::Ok);
    InviteListInfo l = c.invite_list();
    CHECK_EQ(l.joined.size(), size_t(1));
    CHECK_EQ(l.joined[0].name, std::string("MAY-GUI"));
    CHECK_EQ(l.joined[0].key_hex, key_to_hex(me.pub));
    CHECK_EQ(l.joined[0].invite_id_hex, simple::invite_id_hex(code.id));
    CHECK(l.invites.empty());                          // used up: not live any more
    bool in_allowlist = false;
    for (const ClientAcl& a : peer_list(e.cfg.u8string())) in_allowlist |= a.public_key == me.pub;
    CHECK(in_allowlist);

    // ---- remove the machine: out of the allowlist at once, revoked, and it cannot come back with the same key
    InviteListInfo gone = c.invite_remove_machine(key_to_hex(me.pub));
    CHECK(gone.joined.empty());
    in_allowlist = false;
    for (const ClientAcl& a : peer_list(e.cfg.u8string())) in_allowlist |= a.public_key == me.pub;
    CHECK(!in_allowlist);
    CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_remove_machine(std::string(64, 'a')); }).empty());   // not one of ours
    CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_remove_machine("not hex"); }).empty());

    // ---- an invite that asks first: the receiver's user sees a pending request and agrees
    simple::InviteCode code2 = simple::decode_invite_code(c.invite_create(e.req(true)).created_code);
    KeyPair me2 = generate_keypair();
    simple::InviteOutcome o2;
    std::thread joiner([&] { o2 = simple::redeem_invite(code2, me2, "MAY-HAI", cancel); });
    uint32_t pid = 0;
    CHECK(sotest::wait_until([&] {
        InviteListInfo p = c.invite_list();
        if (p.pending.empty()) return false;
        pid = p.pending[0].id;
        return true;
    }, 15000));
    InviteListInfo pend = c.invite_list();
    CHECK_EQ(pend.pending.size(), size_t(1));
    CHECK_EQ(pend.pending[0].name, std::string("MAY-HAI"));
    CHECK_EQ(pend.pending[0].sas, simple::invite_sas(code2, me2));   // both screens show the same string
    c.invite_approve(pid);
    joiner.join();
    CHECK(o2.kind == simple::InviteOutcome::Ok);
    CHECK_EQ(c.invite_list().joined.size(), size_t(1));

    // ---- ... and a refusal keeps the sender out
    simple::InviteCode code3 = simple::decode_invite_code(c.invite_create(e.req(true)).created_code);
    KeyPair me3 = generate_keypair();
    simple::InviteOutcome o3;
    std::thread joiner3([&] { o3 = simple::redeem_invite(code3, me3, "MAY-BA", cancel); });
    CHECK(sotest::wait_until([&] {
        InviteListInfo p = c.invite_list();
        if (p.pending.empty()) return false;
        pid = p.pending[0].id;
        return true;
    }, 15000));
    c.invite_deny(pid);
    joiner3.join();
    CHECK(o3.kind == simple::InviteOutcome::Refused);
    CHECK_EQ(c.invite_list().joined.size(), size_t(1));
}

TEST(gui_invite_ops_refuse_the_servers_own_folders_and_network_or_device_paths) {
    InvEnv e("pairing = \"on-demand\"\n", /*allow_pairing=*/true);
    CHECK(e.ready());
    ControlClient c = e.client();
    // no client owns the whole root; still none of these may be handed out
    for (const std::string& bad : {e.t.s(""), e.t.s("root"), e.t.s("root/sub"), e.t.s("cfg/state")}) {
        InviteCreateReq q = e.req(false);
        q.folder = bad;
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_create(q); }).empty());
    }
    CHECK(!fs::exists(e.root / "sub"));
    for (const char* bad : {"\\\\host\\share\\dir", "\\\\?\\C:\\dir", "\\\\.\\C:\\dir", "//host/share/dir"}) {
        InviteCreateReq q = e.req(false);
        q.folder = bad;
        CHECK(!deny_reason(c, [&](ControlClient& x) { x.invite_create(q); }).empty());
    }
    // an ordinary folder still works, and the default label comes from its (cleaned) name
    InviteCreateReq ok = e.req(false);
    ok.label.clear();
    ok.folder = e.t.s("T\xC3\xA0i li\xE1\xBB\x87u");
    std::string code;
    CHECK(deny_reason(c, [&](ControlClient& x) { code = x.invite_create(ok).created_code; }).empty());
    CHECK_EQ(simple::decode_invite_code(code).label, std::string("T\xC3\xA0i li\xE1\xBB\x87u"));
}

TEST(gui_invite_ops_create_is_denied_when_the_daemon_runs_with_strict_trust) {
    InvEnv e("pairing = \"on-demand\"\n", /*allow_pairing=*/true, /*strict=*/true);
    if (!e.ready()) throw mytest::Failure{"the strict daemon did not start: " + e.fail};
    ControlClient c = e.client();
    ControlRequest q;
    q.op = ControlOp::InviteCreate;
    q.token = 5;
    q.payload = encode_invite_create(e.req(false));
    ControlResponse r = c.call(q);
    CHECK(r.status == ControlStatus::Denied);
    CHECK(r.error.find("administrator") != std::string::npos);
    CHECK(!fs::exists(fs::u8path(e.t.s("share1"))));
    // reading the list stays possible
    CHECK(deny_reason(c, [&](ControlClient& x) { x.invite_list(); }).empty());
}
