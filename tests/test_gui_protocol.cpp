// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

// GUI control protocol: encode/decode, size limits, mutation robustness, and the pure permission rules of the IPC.
#include <cstring>
#include <random>

#include "mysync/gui/control_protocol.h"
#include "mysync/gui/ipc.h"
#include "testing.h"

using namespace mysync;
using namespace mysync::gui;

namespace {

StatusSnapshot sample_snapshot() {
    StatusSnapshot s;
    s.role = Role::Client;
    s.version = "1.0.0";
    s.service_name = "mysync-client";
    s.config_path = "D:\\cfg\\client.toml";
    s.uptime_s = 12345;
    s.taken_unix_ms = 1760000000000;
    s.total_tx_bps = 1000;
    s.total_rx_bps = 2;
    s.total_sent = 7;
    s.total_skipped = 8;
    s.total_failed = 9;
    s.listen = "*:5656";
    s.sessions = 3;
    s.max_connections = 20;
    s.config_loaded_unix_ms = 1759999999000;
    s.config_error = "line 4: unknown key 'x'";
    for (int i = 0; i < 3; ++i) {
        TargetStatus t;
        t.watch = "tài liệu " + std::to_string(i);
        t.target = "net://may-chu:5656";
        t.state = static_cast<TargetState>(i % 4);
        t.queued = 10 + i;
        t.tx_bps = 5;
        t.sent = 1;
        t.skipped = 2;
        t.failed = 3;
        t.bytes = 4;
        t.last_error = "connection refused";
        t.last_error_unix_ms = 1760000000123;
        for (int k = 0; k < 20; ++k) t.active_files.push_back("thu-muc/tep-" + std::to_string(k) + ".docx");
        s.targets.push_back(t);
    }
    PeerStatus p;
    p.name = "van-phong-ha-noi";
    p.sessions = 2;
    p.rx_bps = 11;
    p.tx_bps = 12;
    p.bytes_rx = 13;
    p.bytes_tx = 14;
    s.peers.push_back(p);
    return s;
}

ControlResponse sample_response(ControlOp op) {
    ControlResponse r;
    r.op = op;
    r.token = 0x1122334455667788ull;
    switch (op) {
    case ControlOp::Ping: break;
    case ControlOp::GetStatus: r.snapshot = sample_snapshot(); break;
    case ControlOp::ReloadConfig:
        r.reload.ok = true;
        r.reload.message = "configuration reloaded";
        r.reload.applied = {"max_connections", "clients added: b"};
        r.reload.needs_restart = {"[control] allow"};
        break;
    case ControlOp::GetRecentErrors:
        for (int i = 0; i < 5; ++i) r.errors.push_back({1760000000000 + i, i % 2 ? "ERROR" : "WARN", "message " + std::to_string(i)});
        break;
    case ControlOp::PairModeOn:
    case ControlOp::PairModeOff:
    case ControlOp::PairList:
    case ControlOp::PairApprove:
    case ControlOp::PairDeny: break;
    }
    return r;
}

const ControlOp kAllOps[] = {ControlOp::Ping, ControlOp::GetStatus, ControlOp::ReloadConfig, ControlOp::GetRecentErrors};

}  // namespace

TEST(gui_protocol_request_roundtrip) {
    for (ControlOp op : kAllOps) {
        ControlRequest q;
        q.op = op;
        q.token = 0xDEADBEEFCAFEull;
        q.arg = 77;
        ControlRequest d = decode_request(encode_request(q));
        CHECK(d.op == op);
        CHECK_EQ(d.token, q.token);
        CHECK_EQ(d.arg, 77u);
    }
}

TEST(gui_protocol_response_roundtrip) {
    for (ControlOp op : kAllOps) {
        ControlResponse r = sample_response(op);
        ControlResponse d = decode_response(encode_response(r));
        CHECK(d.op == op);
        CHECK_EQ(d.token, r.token);
        CHECK(d.status == ControlStatus::Ok);
    }
    ControlResponse r = sample_response(ControlOp::GetStatus);
    ControlResponse d = decode_response(encode_response(r));
    CHECK_EQ(d.snapshot.version, std::string("1.0.0"));
    CHECK_EQ(d.snapshot.targets.size(), size_t(3));
    CHECK_EQ(d.snapshot.targets[1].watch, std::string("tài liệu 1"));
    CHECK_EQ(d.snapshot.targets[2].active_files.size(), size_t(20));
    CHECK(d.snapshot.targets[1].state == TargetState::Syncing);
    CHECK(d.snapshot.targets[2].state == TargetState::Error);
    CHECK_EQ(d.snapshot.targets[0].last_error, std::string("connection refused"));
    CHECK_EQ(d.snapshot.peers.size(), size_t(1));
    CHECK_EQ(d.snapshot.peers[0].name, std::string("van-phong-ha-noi"));
    CHECK_EQ(d.snapshot.config_error, std::string("line 4: unknown key 'x'"));
    ControlResponse e = decode_response(encode_response(sample_response(ControlOp::GetRecentErrors)));
    CHECK_EQ(e.errors.size(), size_t(5));
    CHECK_EQ(e.errors[3].level, std::string("ERROR"));
    ControlResponse rl = decode_response(encode_response(sample_response(ControlOp::ReloadConfig)));
    CHECK(rl.reload.ok);
    CHECK_EQ(rl.reload.applied.size(), size_t(2));
    CHECK_EQ(rl.reload.needs_restart[0], std::string("[control] allow"));
}

TEST(gui_protocol_every_truncation_is_rejected) {
    for (ControlOp op : kAllOps) {
        Bytes b = encode_response(sample_response(op));
        for (size_t n = 0; n < b.size(); ++n) {
            bool threw = false;
            try {
                decode_response(b.data(), n);
            } catch (const Error&) {
                threw = true;
            }
            CHECK(threw);
        }
        Bytes extra = b;
        extra.push_back(0);
        CHECK_THROWS(decode_response(extra));
    }
    Bytes q = encode_request(ControlRequest());
    for (size_t n = 0; n < q.size(); ++n) CHECK_THROWS(decode_request(q.data(), n));
    q.push_back(1);
    CHECK_THROWS(decode_request(q));
}

TEST(gui_protocol_bad_values_are_rejected) {
    Bytes q = encode_request(ControlRequest());
    Bytes bad_ver = q;
    bad_ver[1] = 9;
    CHECK_THROWS(decode_request(bad_ver));
    Bytes bad_op = q;
    bad_op[2] = 0;
    CHECK_THROWS(decode_request(bad_op));
    bad_op[2] = 200;
    CHECK_THROWS(decode_request(bad_op));
    Bytes r = encode_response(sample_response(ControlOp::Ping));
    Bytes bad_status = r;
    bad_status[11] = 99;  // u16 ver, u8 op, u64 token, then status
    CHECK_THROWS(decode_response(bad_status));
}

TEST(gui_protocol_mutations_never_crash) {
    std::mt19937_64 rng(12345);
    std::vector<Bytes> seeds;
    for (ControlOp op : kAllOps) seeds.push_back(encode_response(sample_response(op)));
    int threw = 0, ok = 0;
    for (int iter = 0; iter < 30000; ++iter) {
        Bytes b = seeds[rng() % seeds.size()];
        int edits = 1 + int(rng() % 4);
        for (int e = 0; e < edits; ++e) {
            switch (rng() % 4) {
            case 0: b[rng() % b.size()] = uint8_t(rng()); break;
            case 1: b[rng() % b.size()] ^= uint8_t(1u << (rng() % 8)); break;
            case 2: if (b.size() > 1) b.resize(1 + rng() % (b.size() - 1)); break;
            default: b.insert(b.begin() + long(rng() % b.size()), uint8_t(rng())); break;
            }
        }
        try {
            ControlResponse d = decode_response(b);
            // whatever decoded must re-encode within one frame
            CHECK(encode_response(d).size() <= kMaxMessageBytes);
            ++ok;
        } catch (const Error&) {
            ++threw;
        }
    }
    CHECK(threw > 0);
    // random garbage as requests
    for (int iter = 0; iter < 20000; ++iter) {
        Bytes b(rng() % 40);
        for (auto& x : b) x = uint8_t(rng());
        try {
            decode_request(b);
        } catch (const Error&) {
        }
    }
}

TEST(gui_protocol_frame_limits) {
    uint8_t h[4] = {0, 0, 0, 0};
    CHECK_THROWS(parse_frame_length(h));
    h[1] = 1;  // 65536
    CHECK_EQ(parse_frame_length(h), 65536u);
    h[1] = 1;
    h[3] = 1;  // 65537
    CHECK_THROWS(parse_frame_length(h));
    uint8_t big[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    CHECK_THROWS(parse_frame_length(big));
    CHECK_THROWS(frame_message(Bytes()));
    CHECK_THROWS(frame_message(Bytes(kMaxMessageBytes + 1)));
    Bytes f = frame_message(Bytes(10, 7));
    CHECK_EQ(f.size(), size_t(14));
    CHECK_EQ(parse_frame_length(f.data()), 10u);
}

TEST(gui_protocol_huge_status_still_fits_one_frame) {
    ControlResponse r;
    r.op = ControlOp::GetStatus;
    r.snapshot = sample_snapshot();
    std::string longname(250, 'x');
    for (int i = 0; i < 400; ++i) {
        TargetStatus t = r.snapshot.targets[0];
        t.watch = "w" + std::to_string(i);
        for (auto& f : t.active_files) f = longname;
        t.last_error = std::string(3000, 'e');
        r.snapshot.targets.push_back(t);
    }
    r.error = std::string(100000, 'z');
    Bytes b = encode_response(r);
    CHECK(b.size() <= kMaxMessageBytes);
    ControlResponse d = decode_response(b);
    CHECK(d.snapshot.targets.size() >= 1);
    CHECK(d.snapshot.targets.size() <= 1024);
}

TEST(gui_protocol_invalid_utf8_text_is_sanitised) {
    ControlResponse r;
    r.op = ControlOp::GetStatus;
    r.snapshot = sample_snapshot();
    r.snapshot.targets[0].active_files = {std::string("ok\xff\xfe""bad\xc3(") + std::string(1, '\0') + "tail"};
    r.snapshot.targets[0].last_error = "caf\xc3\xa9 \xed\xa0\x80";  // valid + a UTF-16 surrogate
    ControlResponse d = decode_response(encode_response(r));
    CHECK(d.snapshot.targets[0].active_files.size() == 1);
    CHECK(d.snapshot.targets[0].active_files[0].find('\0') == std::string::npos);
    CHECK(d.snapshot.targets[0].last_error.find("caf\xc3\xa9") == 0);
}

TEST(gui_protocol_names) {
    CHECK(valid_control_name("mysync-server"));
    CHECK(valid_control_name("a.b_c-1"));
    CHECK(!valid_control_name(""));
    CHECK(!valid_control_name("-x"));
    CHECK(!valid_control_name(".x"));
    CHECK(!valid_control_name("a b"));
    CHECK(!valid_control_name("a/b"));
    CHECK(!valid_control_name("..\\x"));
    CHECK(!valid_control_name(std::string(65, 'a')));
    CHECK_EQ(effective_control_name("custom", "svc", true), std::string("custom"));
    CHECK_EQ(effective_control_name("", "svc", true), std::string("svc"));
    CHECK_EQ(effective_control_name("", "", true), std::string("mysync-server"));
    CHECK_EQ(effective_control_name("", "", false), std::string("mysync-client"));
    CHECK_THROWS(control_endpoint_path("bad name"));
}

TEST(gui_ipc_pipe_sddl_never_grants_broad_principals) {
    std::string s = detail::ipc_pipe_sddl({"S-1-5-21-1-2-3-1001"}, "S-1-5-21-1-2-3-1000");
    CHECK(s.find(";;;SY)") != std::string::npos);
    CHECK(s.find(";;;BA)") != std::string::npos);
    CHECK(s.find("S-1-5-21-1-2-3-1001") != std::string::npos);
    CHECK(s.find("S-1-5-21-1-2-3-1000") != std::string::npos);
    CHECK(s.find(";;;WD)") == std::string::npos);
    CHECK(s.find("(D;;GA;;;NU)") != std::string::npos);  // network logons denied
    CHECK(s.rfind("D:P", 0) == 0);                       // protected: no inherited entries
    for (const char* bad : {"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-7", "S-1-5-32-546", "S-1-5-2", "S-1-5-4", "S-1-2-0"}) {
        CHECK_THROWS(detail::ipc_pipe_sddl({bad}, "S-1-5-21-1-2-3-1000"));
    }
    // duplicates and the built-in grants are not repeated
    std::string t = detail::ipc_pipe_sddl({"S-1-5-18", "S-1-5-32-544", "S-1-5-21-9-9-9-5", "S-1-5-21-9-9-9-5"}, "");
    size_t first = t.find("S-1-5-21-9-9-9-5");
    CHECK(first != std::string::npos);
    CHECK(t.find("S-1-5-21-9-9-9-5", first + 1) == std::string::npos);
}

TEST(gui_ipc_peer_admission_rule) {
    CHECK(detail::ipc_peer_allowed(0, 1000, {}, false, 0));                    // root
    CHECK(detail::ipc_peer_allowed(1000, 1000, {}, false, 0));                 // the daemon's own uid
    CHECK(!detail::ipc_peer_allowed(1001, 1000, {1001}, false, 0));            // someone else, no group configured
    CHECK(!detail::ipc_peer_allowed(1001, 1000, {1001, 50}, true, 77));        // group configured, not a member
    CHECK(detail::ipc_peer_allowed(1001, 1000, {1001, 50, 77}, true, 77));     // member of the allowed group
    CHECK(!detail::ipc_peer_allowed(1001, 1000, {77}, false, 77));             // group ignored when none configured
}
