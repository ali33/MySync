// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "server_wizard_model.h"

#include <cctype>
#include <filesystem>

#include "i18n_model.h"
#include "mysync/config.h"
#include "mysync/gui/key_mgr.h"
#include "mysync/gui/service_ctl.h"
#include "mysync/cli_ops.h"
#include "mysync/peers.h"

namespace mysync::gui {

namespace {
namespace fs = std::filesystem;

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}
InputCheck fail(const char* key) { return {false, tr(key)}; }
}  // namespace

InputCheck check_server_port(const std::string& text, uint16_t& port) {
    std::string t = trim(text);
    if (t.empty() || t.size() > 5) return fail("srv.err.port");
    uint32_t v = 0;
    for (unsigned char c : t) {
        if (!std::isdigit(c)) return fail("srv.err.port");
        v = v * 10 + (c - '0');
    }
    if (v < 1 || v > 65535) return fail("srv.err.port");
    port = static_cast<uint16_t>(v);
    return {true, ""};
}

InputCheck check_server_folder(const std::string& text, std::string& normalized) {
    std::string t = trim(text);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') t = trim(t.substr(1, t.size() - 2));
    if (t.empty()) return fail("srv.err.folder.empty");
    for (unsigned char c : t)
        if (c < 0x20 || c == 0x7f) return fail("srv.err.folder.bad");
    std::error_code ec;
    fs::path p = fs::u8path(t);
    if (fs::exists(p, ec) && !fs::is_directory(p, ec)) return fail("srv.err.folder.file");
    normalized = t;
    return {true, ""};
}

InputCheck check_client_key(const std::string& pasted, std::string& hex) {
    if (trim(pasted).empty()) return fail("srv.err.key.empty");
    try {
        hex = KeyManager::normalize_public_hex(pasted);
    } catch (const std::exception& e) {
        return {false, trf("srv.err.key.bad", {e.what()})};
    }
    return {true, ""};
}

InputCheck check_client_name(const std::string& text, std::string& normalized) {
    std::string t = trim(text);
    if (t.empty()) return fail("srv.err.name.empty");
    if (t.size() > 128) return fail("srv.err.name.long");
    for (unsigned char c : t)
        if (c < 0x20 || c == 0x7f) return fail("srv.err.name.bad");
    normalized = t;
    return {true, ""};
}

ServerButtons server_buttons(ServerStage stage, bool inputs_ok, bool client_ok, bool busy) {
    ServerButtons b;
    switch (stage) {
        case ServerStage::Input:
            b.create = inputs_ok;
            b.browse = true;
            b.close = true;
            break;
        case ServerStage::Creating:
            break;   // đang chờ lõi: không bấm được gì (kể cả đóng) cho tới khi xong
        case ServerStage::Result:
            b.copy = true;
            b.add_client = client_ok && !busy;
            b.install_service = !busy;
            b.close = !busy;
            break;
    }
    return b;
}

ServerResultTexts make_server_result_texts(const QuickResult& r) {
    ServerResultTexts t;
    const bool fresh = r.changed();
    t.headline = tr(fresh ? "srv.res.ready" : "srv.res.already");
    t.folder_line = tr("srv.res.folder") + " " + r.dir + (r.dir_created ? " " + tr("srv.res.created") : "");
    t.port_line = tr("srv.res.port") + " " + std::to_string(r.port);
    t.config_line = tr("srv.res.config") + " " + r.config_file + " " +
                    (r.config_created ? tr("srv.res.created") : r.config_replaced ? tr("srv.res.replaced") : tr("srv.res.kept"));
    t.key_line = tr("srv.res.keyfile") + " " + r.key_file + " " +
                 (r.key_created ? tr("srv.res.created") : tr("srv.res.kept")) + " - " + tr("srv.res.keynever");
    t.public_key = r.public_key;
    t.fingerprint = r.fingerprint;
    t.pairing_line = tr("srv.res.pairing") + " " + (r.pairing == "off" ? tr("srv.res.pairing.off") : r.pairing);
    t.notes = r.notes;
    t.client_snippet = r.client_snippet;
    t.peer_add_command = r.peer_add_command;
    return t;
}

QuickResult create_server(const std::string& folder, uint16_t port, bool fix_permissions) {
    QuickServerOptions o;
    o.dir = folder;
    o.port = port;
    o.fix_permissions = fix_permissions;
    o.vietnamese_comments = lang() == Lang::Vi;   // the comments of the snippet follow the UI language (the CLI stays English)
    return quick_server(o);
}

CreateServerOutcome create_server_outcome(const std::string& folder, uint16_t port, bool fix_permissions) {
    CreateServerOutcome out;
    try {
        out.result = create_server(folder, port, fix_permissions);
        out.ok = true;
    } catch (const UntrustedFolderError& e) {
        out.untrusted_folder = e.path;
        out.error = trf("srv.err.untrusted", {e.path});
    } catch (const std::exception& e) {
        out.error = trf("srv.err.create", {e.what()});
    }
    return out;
}

AddClientOutcome add_client(const std::string& config_file, const std::string& name, const std::string& key_text,
                            bool read_only) {
    AddClientOutcome out;
    std::string hex, nm;
    InputCheck k = check_client_key(key_text, hex);
    if (!k.ok) { out.message = k.error; return out; }
    InputCheck n = check_client_name(name, nm);
    if (!n.ok) { out.message = n.error; return out; }
    try {
        guard_server_config_for_edit(config_file);   // the same trust check as `mysync peer add`: never skipped
        PeerSpec spec;
        spec.name = nm;
        spec.key = parse_public_key_hex(hex);
        spec.read_only = read_only;
        PeerEdit e = peer_add(config_file, spec);
        out.ok = true;
        out.changed = e.changed;
        // peer_add's own sentence is English (the CLI prints it as is); the GUI says the same thing in its language
        const bool added = e.message.find("' added") != std::string::npos;
        const bool updated = e.message.find("' updated") != std::string::npos;
        const std::string where = e.where == "main configuration" ? tr("srv.add.main") : e.where;
        if (added || updated) out.message = trf(added ? "srv.add.added" : "srv.add.updated", {nm, read_only ? "ro" : "rw", where});
        else out.message = trf("srv.add.unchanged", {nm});
    } catch (const std::exception& e) {
        out.message = e.what();
    }
    return out;
}

ServiceOutcome install_server_service(const QuickResult& r, const std::string& service_name) {
    ServiceOutcome out;
    try {
        ServiceController ctl;   // ném Error nếu không có mysync hợp lệ -> hiện nguyên văn
        ServiceState st = ctl.query(service_name);
        std::string msg;
        if (!st.installed) {
            ServiceRequest rq;
            rq.name = service_name;
            rq.config_path = r.config_file;
            rq.role = r.role;
            ServiceResult res = ctl.run(ServiceAction::Install, rq);
            if (!res.ok) {
                out.cancelled = res.cancelled;
                out.message = trf("srv.svc.notinstalled", {service_name, res.message.empty() ? service_exit_message(res.exit_code) : res.message});
                return out;
            }
            msg = trf("srv.svc.installed", {service_name});
            st = res.state_after;
        } else {
            msg = trf("srv.svc.already", {service_name});
        }
        if (!st.running) {
            ServiceRequest rq;
            rq.name = service_name;
            ServiceResult res = ctl.run(ServiceAction::Start, rq);
            if (!res.ok) {
                out.cancelled = res.cancelled;
                out.message = msg + "; " + trf("srv.svc.notstarted", {res.message.empty() ? service_exit_message(res.exit_code) : res.message});
                return out;
            }
            msg += "; " + tr("srv.svc.started");
        } else {
            msg += "; " + tr("srv.svc.running");
        }
        out.ok = true;
        out.message = msg;
    } catch (const std::exception& e) {
        out.message = e.what();
    }
    return out;
}

}  // namespace mysync::gui
