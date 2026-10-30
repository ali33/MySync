// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/gui/daemon.h"
#include "mysync/gui/config_io.h"
#include "mysync/simple/pairing.h"

#include "mysync/gui/trust.h"
#include "mysync/peers.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <deque>
#include <exception>
#include <filesystem>
#include <mutex>
#include <set>
#include <thread>

namespace fs = std::filesystem;

namespace mysync::gui {
namespace {

// ---------------------------------------------------------------- recent errors ring
struct ErrorRing {
    std::mutex m;
    std::deque<ErrorEntry> q;
};
ErrorRing& ring() {
    static ErrorRing r;
    return r;
}
constexpr size_t kRingMax = 200;

void tap(LogLevel l, const std::string& msg) {
    ErrorEntry e;
    e.unix_ms = now_unix_ns() / 1000000;
    e.level = l == LogLevel::Error ? "ERROR" : "WARN";
    e.message = msg.size() > 1000 ? msg.substr(0, 1000) : msg;
    std::lock_guard<std::mutex> lk(ring().m);
    ring().q.push_back(std::move(e));
    while (ring().q.size() > kRingMax) ring().q.pop_front();
}

int64_t unix_ms() { return now_unix_ns() / 1000000; }

std::string resolve_in(const std::string& dir, const std::string& p) {
    if (p.empty()) return p;
    fs::path q = fs::u8path(p);
    if (q.is_absolute() || q.has_root_name() || q.has_root_directory()) return p;
    return (fs::u8path(dir) / q).lexically_normal().u8string();
}

std::string abs_of(const std::string& p) {
    std::error_code ec;
    fs::path a = fs::absolute(fs::u8path(p), ec);
    return ec ? p : a.lexically_normal().u8string();
}

void apply_logging(const std::string& level, const std::string& file) {
    std::string l = level;
    for (auto& c : l) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    log_set_level(l == "debug" ? LogLevel::Debug : l == "warn" || l == "warning" ? LogLevel::Warn
                  : l == "error" ? LogLevel::Error : LogLevel::Info);
    if (!file.empty()) {
        std::error_code ec;
        fs::create_directories(fs::u8path(file).parent_path(), ec);
        log_set_file(file);
    }
}

std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) s += (i ? ", " : "") + v[i];
    return s;
}

// Collects "what changed" lines; `restart` entries are settings that are not applied live.
struct Diff {
    std::vector<std::string> applied, restart;
    template <class T>
    void chk(const char* name, const T& a, const T& b) {
        if (!(a == b)) applied.push_back(name);
    }
    template <class T>
    void chk_restart(const char* name, const T& a, const T& b) {
        if (!(a == b)) restart.push_back(name);
    }
};

void diff_control(Diff& d, bool ea, const std::vector<std::string>& aa, const std::string& ga, const std::string& na,
                  bool eb, const std::vector<std::string>& ab, const std::string& gb, const std::string& nb) {
    d.chk_restart("[control] enabled", ea, eb);
    d.chk_restart("[control] allow", aa, ab);
    d.chk_restart("[control] group", ga, gb);
    d.chk_restart("[control] name", na, nb);
}

bool same_acl(const ClientAcl& a, const ClientAcl& b) {
    return a.name == b.name && a.public_key == b.public_key && a.extra_keys == b.extra_keys && a.read_only == b.read_only && a.prefix == b.prefix &&
           a.max_sessions == b.max_sessions && a.max_write_bytes_per_hour == b.max_write_bytes_per_hour &&
           a.max_bandwidth_kbps == b.max_bandwidth_kbps;
}

void diff_clients(Diff& d, const std::vector<ClientAcl>& a, const std::vector<ClientAcl>& b) {
    std::vector<std::string> added, removed, changed;
    for (const auto& n : b) {
        auto it = std::find_if(a.begin(), a.end(), [&](const ClientAcl& o) { return o.name == n.name; });
        if (it == a.end()) added.push_back(n.name);
        else if (!same_acl(*it, n)) changed.push_back(n.name);
    }
    for (const auto& o : a)
        if (std::none_of(b.begin(), b.end(), [&](const ClientAcl& n) { return n.name == o.name; })) removed.push_back(o.name);
    if (!added.empty()) d.applied.push_back("clients added: " + join(added));
    if (!removed.empty()) d.applied.push_back("clients removed: " + join(removed) + " (their open sessions end at the next request)");
    if (!changed.empty()) d.applied.push_back("clients changed: " + join(changed));
}

void diff_server(Diff& d, const ServerConfig& a, const ServerConfig& b) {
    d.chk("key_file", a.key_file, b.key_file);
    d.chk("key_file_next", a.key_file_next, b.key_file_next);
    d.chk("peers_dir", a.peers_dir, b.peers_dir);
    d.chk_restart("pairing", a.pairing, b.pairing);
    d.chk("max_connections", a.max_connections, b.max_connections);
    d.chk("max_auth_failures_per_min", a.max_auth_failures_per_min, b.max_auth_failures_per_min);
    d.chk("trash", a.trash, b.trash);
    d.chk("allow", a.allow, b.allow);
    d.chk("deny", a.deny, b.deny);
    d.chk("max_bandwidth_kbps", a.max_bandwidth_kbps, b.max_bandwidth_kbps);
    d.chk("max_file_size", a.max_file_size, b.max_file_size);
    d.chk("max_trash_bytes", a.max_trash_bytes, b.max_trash_bytes);
    d.chk("file_mode", a.file_mode, b.file_mode);
    d.chk("dir_mode", a.dir_mode, b.dir_mode);
    d.chk("io_timeout_s", a.io_timeout_s, b.io_timeout_s);
    d.chk("log_level", a.log_level, b.log_level);
    d.chk("log_file", a.log_file, b.log_file);
    diff_clients(d, a.clients, b.clients);
    diff_control(d, a.control_enabled, a.control_allow, a.control_group, a.control_name, b.control_enabled,
                 b.control_allow, b.control_group, b.control_name);
}

bool same_target(const TargetConfig& a, const TargetConfig& b) {
    return a.host == b.host && a.port == b.port && a.server_key == b.server_key && a.has_server_key_next == b.has_server_key_next &&
           (!a.has_server_key_next || a.server_key_next == b.server_key_next) && a.key_file == b.key_file &&
           a.path == b.path && a.remote_prefix == b.remote_prefix && a.enabled == b.enabled &&
           a.file_mode == b.file_mode && a.dir_mode == b.dir_mode;
}

bool same_filter(const FilterConfig& a, const FilterConfig& b) {
    return a.include == b.include && a.include_regex == b.include_regex && a.exclude == b.exclude &&
           a.exclude_regex == b.exclude_regex && a.size_min == b.size_min && a.size_max == b.size_max &&
           a.mtime_after == b.mtime_after && a.mtime_before == b.mtime_before;
}

bool same_watch(const WatchConfig& a, const WatchConfig& b) {
    if (a.name != b.name || a.path != b.path || a.enabled != b.enabled || a.recursive != b.recursive ||
        a.quiet_ms != b.quiet_ms || a.sync_delay_ms != b.sync_delay_ms || a.start_sync != b.start_sync ||
        a.propagate_delete != b.propagate_delete || a.schedule_at != b.schedule_at ||
        a.schedule_interval_s != b.schedule_interval_s || a.periodic_scan_s != b.periodic_scan_s ||
        !same_filter(a.filter, b.filter) || a.targets.size() != b.targets.size())
        return false;
    for (size_t i = 0; i < a.targets.size(); ++i)
        if (!same_target(a.targets[i], b.targets[i])) return false;
    return true;
}

void diff_client(Diff& d, const ClientConfig& a, const ClientConfig& b) {
    d.chk("key_file", a.key_file, b.key_file);
    d.chk("state_dir", a.state_dir, b.state_dir);
    d.chk("connections", a.connections, b.connections);
    d.chk("compress", a.compress, b.compress);
    d.chk("compress_skip_ext", a.compress_skip_ext, b.compress_skip_ext);
    d.chk("max_bandwidth_kbps", a.max_bandwidth_kbps, b.max_bandwidth_kbps);
    d.chk("retry_min_ms", a.retry_min_ms, b.retry_min_ms);
    d.chk("retry_max_ms", a.retry_max_ms, b.retry_max_ms);
    d.chk("log_level", a.log_level, b.log_level);
    d.chk("log_file", a.log_file, b.log_file);
    std::vector<std::string> added, removed, changed;
    for (const auto& n : b.watches) {
        auto it = std::find_if(a.watches.begin(), a.watches.end(), [&](const WatchConfig& o) { return o.name == n.name; });
        if (it == a.watches.end()) added.push_back(n.name);
        else if (!same_watch(*it, n)) changed.push_back(n.name);
    }
    for (const auto& o : a.watches)
        if (std::none_of(b.watches.begin(), b.watches.end(), [&](const WatchConfig& n) { return n.name == o.name; }))
            removed.push_back(o.name);
    if (!added.empty()) d.applied.push_back("watches added: " + join(added));
    if (!removed.empty()) d.applied.push_back("watches removed: " + join(removed));
    if (!changed.empty()) d.applied.push_back("watches changed: " + join(changed));
    diff_control(d, a.control_enabled, a.control_allow, a.control_group, a.control_name, b.control_enabled,
                 b.control_allow, b.control_group, b.control_name);
}

ReloadResult make_result(bool ok, const std::string& msg, Diff* d) {
    ReloadResult r;
    r.ok = ok;
    r.message = msg;
    if (d) {
        r.applied = d->applied;
        r.needs_restart = d->restart;
    }
    return r;
}

std::string summary(const Diff& d) {
    std::string s = "configuration reloaded";
    if (d.applied.empty() && d.restart.empty()) return s + " (no change)";
    if (!d.applied.empty()) s += ": " + std::to_string(d.applied.size()) + " change(s) applied";
    if (!d.restart.empty()) s += "; " + std::to_string(d.restart.size()) + " setting(s) need a restart";
    return s;
}

std::string trust_state_dir(const ClientConfig& c, const DaemonOptions& o) {
    return effective_client_state_dir(c.state_dir, o.config_path);
}
std::string trust_state_dir(const ServerConfig& c, const DaemonOptions& o) {
    return effective_server_state_dir(c.state_dir, c.root);
}

template <class C>
void check_trust(const C& c, const DaemonOptions& o) {
    if (!o.enforce_config_trust) return;
    // The DEFAULT state folder counts too (state_dir empty): it is where the engine writes its indexes.
    require_trusted_run(o.config_path, trust_state_dir(c, o), c.log_file, o.trusted_writers);
}

// "path:size:mtime" of every key file a configuration names: a rotated key is a change even when the path is not.
template <class C>
std::string key_stamp(const C& c);

std::string stamp_of(const std::string& p) {
    if (p.empty()) return {};
    std::error_code ec;
    auto sz = fs::file_size(fs::u8path(p), ec);
    if (ec) return p + ":missing;";
    auto mt = fs::last_write_time(fs::u8path(p), ec).time_since_epoch().count();
    return p + ":" + std::to_string(sz) + ":" + std::to_string(mt) + ";";
}

template <>
std::string key_stamp<ServerConfig>(const ServerConfig& c) {
    return stamp_of(c.key_file) + stamp_of(c.key_file_next);
}

template <>
std::string key_stamp<ClientConfig>(const ClientConfig& c) {
    std::string s = stamp_of(c.key_file);
    for (const auto& w : c.watches)
        for (const auto& t : w.targets)
            if (!t.key_file.empty()) s += stamp_of(t.key_file);
    return s;
}

// Spaces out real reloads.
struct ReloadGate {
    std::chrono::steady_clock::time_point last{};
    bool had = false;
    // Throws when the previous real reload was too recent. The clock is only started by stamp(), after the new
    // configuration has been vetted, so a refused attempt does not lock the next one out.
    void check(int min_ms) const {
        if (had && min_ms > 0) {
            auto since = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - last).count();
            if (since < min_ms)
                throw Error("reload requested too quickly: wait another " + std::to_string(min_ms - since) + " ms");
        }
    }
    void stamp() {
        had = true;
        last = std::chrono::steady_clock::now();
    }
};

}  // namespace

void install_error_tap() { log_set_tap(&tap); }

std::vector<ErrorEntry> recent_log_errors(size_t max) {
    std::lock_guard<std::mutex> lk(ring().m);
    size_t n = std::min(max, ring().q.size());
    return std::vector<ErrorEntry>(ring().q.end() - static_cast<std::ptrdiff_t>(n), ring().q.end());
}

void clear_recent_log_errors() {
    std::lock_guard<std::mutex> lk(ring().m);
    ring().q.clear();
}

ServerConfig load_server_config_resolved(const std::string& path, PeerLoad* report,
                                         const std::vector<std::string>* trust_writers) {
    std::string p = abs_of(path);
    std::string dir = fs::u8path(p).parent_path().u8string();
    ServerConfig c = load_server_config(p);
    c.root = resolve_in(dir, c.root);
    c.key_file = resolve_in(dir, c.key_file);
    c.key_file_next = resolve_in(dir, c.key_file_next);
    c.state_dir = resolve_in(dir, c.state_dir);
    c.log_file = resolve_in(dir, c.log_file);
    if (trust_writers) {
        // The peers folder decides who may connect: it is held to the same standard as the configuration folder.
        std::string pd = peers_dir_path(c, dir);
        if (!pd.empty()) require_trusted_dir(pd, "peers_dir", *trust_writers);
        // the revocation list too: whoever can edit it can re-admit a revoked machine by deleting a line
        std::string rl = revoked_list_path(dir);
        std::error_code ec;
        if (fs::exists(fs::u8path(rl), ec)) {
            std::string why = untrusted_writer_reason(rl, *trust_writers);
            if (!why.empty()) throw Error("refusing to trust the revocation list " + rl + ": " + why);
        }
    }
    std::function<std::string(const std::string&)> check;
    if (trust_writers) {
        std::vector<std::string> w = *trust_writers;
        check = [w](const std::string& f) { return untrusted_writer_reason(f, w); };
    }
    PeerLoad pl = load_peers(c, dir, check);
    if (report) *report = std::move(pl);
    return c;
}

ClientConfig load_client_config_resolved(const std::string& path) {
    std::string p = abs_of(path);
    std::string dir = fs::u8path(p).parent_path().u8string();
    ClientConfig c = load_client_config(p);
    c.key_file = resolve_in(dir, c.key_file);
    c.state_dir = resolve_in(dir, c.state_dir);
    c.log_file = resolve_in(dir, c.log_file);
    return c;
}

// ============================================================================================ ControlHost
struct ControlHost::Impl {
    Role role;
    DaemonOptions opts;
    IpcServerOptions ipc_opts;
    StatusFn status;
    ReloadFn reload;
    PairFn pair;
    std::unique_ptr<IpcServer> server;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    std::mutex m;
    int64_t loaded_ms = 0;
    std::string config_error;
    std::mutex reload_mu;

    ControlResponse handle(const ControlRequest& q) {
        ControlResponse r;
        r.op = q.op;
        r.token = q.token;
        switch (q.op) {
        case ControlOp::Ping:
            break;
        case ControlOp::GetStatus: {
            r.snapshot = status();
            StatusSnapshot& s = r.snapshot;
            s.role = role;
            s.version = opts.version;
            s.service_name = opts.service_name;
            s.config_path = opts.config_path;
            s.uptime_s = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started).count());
            s.taken_unix_ms = unix_ms();
            std::lock_guard<std::mutex> lk(m);
            s.config_loaded_unix_ms = loaded_ms;
            s.config_error = config_error;
            break;
        }
        case ControlOp::ReloadConfig: {
            std::lock_guard<std::mutex> lk(reload_mu);
            r.reload = reload();
            if (!r.reload.ok) {
                std::lock_guard<std::mutex> lk2(m);
                config_error = r.reload.message;
            } else {
                std::lock_guard<std::mutex> lk2(m);
                config_error.clear();
                loaded_ms = unix_ms();
            }
            break;
        }
        case ControlOp::GetRecentErrors:
            r.errors = recent_log_errors(q.arg == 0 ? 50 : std::min<size_t>(q.arg, kMaxErrorsReturned));
            break;
        case ControlOp::PairModeOn:
        case ControlOp::PairModeOff:
        case ControlOp::PairList:
        case ControlOp::PairApprove:
        case ControlOp::PairDeny:
            if (!pair) {
                r.status = ControlStatus::Unsupported;
                r.error = "pairing is not available on this daemon";
            } else {
                r = pair(q);
                r.op = q.op;
                r.token = q.token;
            }
            break;
        }
        return r;
    }
};

ControlHost::ControlHost(Role role, DaemonOptions opts, IpcServerOptions ipc, StatusFn status, ReloadFn reload)
    : p_(new Impl) {
    p_->role = role;
    p_->opts = std::move(opts);
    p_->ipc_opts = std::move(ipc);
    p_->status = std::move(status);
    p_->reload = std::move(reload);
    p_->loaded_ms = unix_ms();
}

ControlHost::~ControlHost() { stop(); }

void ControlHost::set_pair_handler(PairFn fn) { p_->pair = std::move(fn); }

void ControlHost::start() {
    Impl* im = p_.get();
    im->ipc_opts.user_only = im->opts.control_user_only;
    im->server = std::make_unique<IpcServer>(im->ipc_opts, [im](const ControlRequest& q) { return im->handle(q); });
    im->server->start();
    log_info("control channel on " + im->server->endpoint());
}

void ControlHost::stop() {
    if (p_ && p_->server) {
        p_->server->stop();
        p_->server.reset();
    }
}

const std::string& ControlHost::endpoint() const {
    static const std::string none;
    return p_->server ? p_->server->endpoint() : none;
}

void ControlHost::set_config_state(int64_t loaded_unix_ms, const std::string& config_error) {
    std::lock_guard<std::mutex> lk(p_->m);
    p_->loaded_ms = loaded_unix_ms;
    p_->config_error = config_error;
}

namespace {
IpcServerOptions ipc_options(const std::string& name, const std::vector<std::string>& allow, const std::string& group,
                             const std::string& dir) {
    IpcServerOptions o;
    o.name = name;
    o.allow = allow;
    o.group = group;
    o.dir_override = dir;
    return o;
}
}  // namespace

// ============================================================================================ ClientDaemon
struct ClientDaemon::Impl {
    DaemonOptions opts;
    std::string dir;
    ClientConfig cfg;
    std::mutex mu;  // guards eng / stop_flag / th
    std::shared_ptr<SyncEngine> eng;
    std::shared_ptr<std::atomic<bool>> eng_stop;
    std::thread th;
    std::exception_ptr fatal;
    std::atomic<bool> eng_dead{false};
    std::mutex reload_mu;
    std::unique_ptr<ControlHost> host;

    void start_engine(const ClientConfig& c) {
        auto e = std::make_shared<SyncEngine>(c, dir);
        auto stop = std::make_shared<std::atomic<bool>>(false);
        {
            std::lock_guard<std::mutex> lk(mu);
            fatal = nullptr;
        }
        eng_dead = false;
        std::thread t([this, e, stop] {
            try {
                e->run(*stop);
            } catch (...) {
                std::lock_guard<std::mutex> lk(mu);
                if (!fatal) fatal = std::current_exception();
            }
            eng_dead = true;
        });
        std::lock_guard<std::mutex> lk(mu);
        eng = e;
        eng_stop = stop;
        th = std::move(t);
    }

    void stop_engine() {
        std::shared_ptr<std::atomic<bool>> s;
        std::thread t;
        {
            std::lock_guard<std::mutex> lk(mu);
            s = eng_stop;
            t = std::move(th);
        }
        if (s) s->store(true);
        if (t.joinable()) t.join();
        std::lock_guard<std::mutex> lk(mu);
        eng.reset();
        eng_stop.reset();
    }

    StatusSnapshot snapshot() {
        std::shared_ptr<SyncEngine> e;
        {
            std::lock_guard<std::mutex> lk(mu);
            e = eng;
        }
        StatusSnapshot s;
        if (e) s = e->snapshot();
        s.role = Role::Client;
        return s;
    }

    ReloadGate gate;
    std::string key_stamp_running;

    ReloadResult reload() {
        std::lock_guard<std::mutex> rl(reload_mu);
        try {
            ClientConfig n = load_client_config_resolved(opts.config_path);
            check_trust(n, opts);
            Diff d;
            diff_client(d, cfg, n);
            std::string stamp_now = key_stamp(n);
            if (stamp_now != key_stamp_running) d.applied.push_back("key file contents");
            if (d.applied.empty()) {  // nothing the engine would notice: leave it running untouched
                log_info("reload: configuration unchanged");
                return make_result(true, summary(d), &d);
            }
            gate.check(opts.reload_min_interval_ms);
            {
                SyncEngine probe(n, dir);
                probe.check_config();  // throws exactly as run() would: nothing has been touched yet
            }
            gate.stamp();
            key_stamp_running = stamp_now;
            ClientConfig old = cfg;
            stop_engine();  // saves the index; the new engine reuses it from the same state_dir
            apply_logging(n.log_level, n.log_file);
            cfg = n;
            start_engine(cfg);
            // The new engine must be alive a moment after its start; if not, the old one is brought back.
            for (int i = 0; i < 30 && !eng_dead.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (eng_dead.load()) {
                std::string why = "unknown error";
                std::exception_ptr f;
                {
                    std::lock_guard<std::mutex> lk(mu);
                    f = fatal;
                    fatal = nullptr;
                }
                try {
                    if (f) std::rethrow_exception(f);
                } catch (const std::exception& e) {
                    why = e.what();
                }
                stop_engine();
                cfg = old;
                apply_logging(old.log_level, old.log_file);
                start_engine(cfg);
                std::string msg = "the new configuration failed to start (" + why + "); the previous configuration was restored";
                log_error(msg);
                return make_result(false, msg, nullptr);
            }
            log_info("configuration reloaded from " + opts.config_path);
            return make_result(true, summary(d), &d);
        } catch (const std::exception& e) {
            log_warn(std::string("reload refused, keeping the running configuration: ") + e.what());
            return make_result(false, e.what(), nullptr);
        }
    }
};

ClientDaemon::ClientDaemon(ClientConfig cfg, std::string config_dir, DaemonOptions opts) : p_(new Impl) {
    p_->cfg = std::move(cfg);
    p_->dir = std::move(config_dir);
    p_->opts = std::move(opts);
    if (p_->opts.service_name.empty()) p_->opts.service_name = "mysync-client";
}

ClientDaemon::~ClientDaemon() {
    if (p_->host) p_->host->stop();
    p_->stop_engine();
}

StatusSnapshot ClientDaemon::snapshot() { return p_->snapshot(); }
ReloadResult ClientDaemon::reload() { return p_->reload(); }

void ClientDaemon::run(std::atomic<bool>& stop) {
    Impl& im = *p_;
    install_error_tap();
    check_trust(im.cfg, im.opts);  // throws: an untrusted configuration stops the daemon
    im.key_stamp_running = key_stamp(im.cfg);
    if (im.cfg.control_enabled) {
        try {
            std::string name = effective_control_name(im.cfg.control_name, im.opts.service_name, false);
            im.host = std::make_unique<ControlHost>(
                Role::Client, im.opts, ipc_options(name, im.cfg.control_allow, im.cfg.control_group, im.opts.control_dir_override),
                [&im] { return im.snapshot(); }, [&im] { return im.reload(); });
            im.host->start();
        } catch (const std::exception& e) {
            log_error(std::string("control channel unavailable (the GUI cannot manage this client): ") + e.what());
            im.host.reset();
        }
    }
    im.start_engine(im.cfg);
    while (!stop.load()) {
        if (im.eng_dead.load()) {
            std::unique_lock<std::mutex> rl(im.reload_mu, std::try_to_lock);
            if (!rl.owns_lock()) {  // a reload is swapping engines right now
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            std::exception_ptr f;
            {
                std::lock_guard<std::mutex> lk(im.mu);
                f = im.fatal;
            }
            if (f) {
                rl.unlock();  // the IPC workers may be waiting for this lock: stopping the host must not hold it
                im.stop_engine();
                if (im.host) im.host->stop();
                std::rethrow_exception(f);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (im.host) im.host->stop();
    std::lock_guard<std::mutex> rl(im.reload_mu);  // a reload in progress finishes first
    im.stop_engine();
}

// ============================================================================================ ServerDaemon
struct ServerDaemon::Impl {
    DaemonOptions opts;
    std::string dir;
    ServerConfig cfg;
    std::mutex mu;
    Server* server = nullptr;
    std::mutex reload_mu;
    std::unique_ptr<ControlHost> host;

    StatusSnapshot snapshot() {
        StatusSnapshot s;
        {
            std::lock_guard<std::mutex> lk(mu);
            if (server) s = server->snapshot();
        }
        s.role = Role::Server;
        std::lock_guard<std::mutex> pl(info_mu);
        // what is really in effect: the process asked for it AND the (reloaded) configuration still allows it
        s.pairing = opts.allow_pairing && cfg_pairing != PairingMode::Off ? "on-demand" : "off";
        s.peer_file_errors = static_cast<uint32_t>(peers.bad);
        s.warnings = peers.warnings;
        if (rotation_under_way) s.warnings.push_back("server key rotation under way: key_file_next is set");
        return s;
    }

    ReloadGate gate;
    std::string key_stamp_running;
    std::mutex info_mu;  // guards peers / cfg_pairing / rotation_under_way (read by snapshot())
    PeerLoad peers;
    PairingMode cfg_pairing = PairingMode::Off;
    bool rotation_under_way = false;
    void note_config(const ServerConfig& c, const PeerLoad& pl) {
        std::lock_guard<std::mutex> lk(info_mu);
        peers = pl;
        cfg_pairing = c.pairing;
        rotation_under_way = !c.key_file_next.empty();
    }

    // ---- pairing by code (simple/pairing.h): runs on the thread of whoever calls approve (an IPC worker)
    // Adds the machine to the allowlist of THIS configuration file (ConfigEditor: atomic, .bak) and applies it at once
    // (Server::apply_config), bypassing the reload spacing: the operator just clicked "Approve".
    bool pairing_configured() {
        std::lock_guard<std::mutex> lk(info_mu);
        return cfg_pairing != PairingMode::Off;
    }

    void close_pairing_if_off() {
        if (!opts.allow_pairing || pairing_configured()) return;
        std::lock_guard<std::mutex> lk(mu);
        if (server) server->pairing().disable();
    }

    std::string pair_approve(const std::string& name, const PubKey& key) {
        std::lock_guard<std::mutex> rl(reload_mu);
        if (!pairing_configured()) throw Error("pairing is switched off in the configuration ([server] pairing = \"off\")");
        if (opts.config_path.empty()) throw Error("pairing needs a configuration file");
        std::set<std::string> prefixes, names;
        for (const ClientAcl& c : cfg.clients) {  // the running configuration also holds the peers.d entries
            prefixes.insert(c.prefix);
            names.insert(c.name);
            PublicKey k = key;
            if (acl_has_key(c, k)) throw Error("this computer is already paired");
        }
        std::string display = name;
        for (int n = 2; names.count(display) && n < 1000; ++n) display = name + " (" + std::to_string(n) + ")";
        // A folder that already exists may hold another machine's files: never hand it over.
        std::string prefix = simple::safe_pair_prefix(name, prefixes);
        for (int i = 0; i < 1000; ++i) {
            std::error_code ec;
            if (!fs::exists(fs::u8path(cfg.root) / fs::u8path(prefix), ec)) break;
            prefixes.insert(prefix);
            prefix = simple::safe_pair_prefix(name, prefixes);
        }
        // The one place peers are written (peers.h): `mysync peer list/remove` sees a machine paired by code too.
        PeerSpec spec;
        spec.name = display;
        spec.key = key;
        spec.read_only = false;  // "rw"
        spec.prefix = prefix;
        peer_add(opts.config_path, spec);
        PeerLoad pl;
        ServerConfig n = load_server_config_resolved(opts.config_path, &pl,
                                                     opts.enforce_config_trust ? &opts.trusted_writers : nullptr);
        check_trust(n, opts);
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!server) throw Error("the server is not running");
            server->apply_config(n);
        }
        cfg = n;
        note_config(n, pl);
        log_info("paired machine '" + display + "' added with folder '" + prefix + "'");
        return prefix;
    }

    ControlResponse pair_op(Server& srv, const ControlRequest& q) {
        ControlResponse r;
        simple::PairingManager& pm = srv.pairing();
        if (!pairing_configured()) {  // checked on EVERY request: a reload may have switched it off meanwhile
            pm.disable();
            r.status = ControlStatus::Unsupported;
            r.error = "pairing is switched off in the configuration ([server] pairing = \"off\")";
            return r;
        }
        try {
            switch (q.op) {
            case ControlOp::PairModeOn:
            {
                simple::PairToken tok = pm.enable(q.arg == 0 ? simple::kPairWindowSeconds : int(std::min<uint32_t>(q.arg, simple::kPairWindowSeconds)));
                r.pair.token_hex = to_hex(tok.data(), tok.size());
                secure_wipe(tok.data(), tok.size());
            }
                log_info("pairing mode switched on");
                break;
            case ControlOp::PairModeOff:
                pm.disable();
                log_info("pairing mode switched off");
                break;
            case ControlOp::PairApprove:
                r.pair.message = pm.approve(q.arg);
                break;
            case ControlOp::PairDeny:
                pm.deny(q.arg);
                break;
            default:
                break;  // PairList: just the state below
            }
        } catch (const Error& e) {
            r.status = ControlStatus::Failed;
            r.error = e.what();
        }
        PairInfo& p = r.pair;
        p.available = true;
        p.mode_on = pm.enabled();
        p.seconds_left = static_cast<uint32_t>(pm.seconds_left());
        p.public_hex = key_to_hex(srv.public_key());
        p.port = srv.port();
        for (const simple::PendingPair& w : pm.pending()) {
            PairPendingInfo i;
            i.id = w.id;
            i.name = w.name;
            i.sas = w.sas;
            i.ip = w.ip;
            i.seconds_left = static_cast<uint32_t>(w.seconds_left);
            p.pending.push_back(i);
        }
        return r;
    }

    ReloadResult reload() {
        std::lock_guard<std::mutex> rl(reload_mu);
        try {
            PeerLoad pl;

            ServerConfig n = load_server_config_resolved(opts.config_path, &pl,
                                                         opts.enforce_config_trust ? &opts.trusted_writers : nullptr);
            check_trust(n, opts);
            Diff d;
            diff_server(d, cfg, n);
            std::string new_stamp = key_stamp(n);
            if (new_stamp != key_stamp_running) d.applied.push_back("server key file(s) read again");
            bool structural = n.bind != cfg.bind || n.port != cfg.port || n.root != cfg.root || n.state_dir != cfg.state_dir;
            if (d.applied.empty() && !structural) {
                note_config(n, pl);  // a peer file that went bad / came back changes the report, not the policy
                close_pairing_if_off();  // (pairing "off" is a restart-only setting, but it must still stop an open window)
                log_info("reload: configuration unchanged");
                return make_result(true, summary(d), &d);
            }
            gate.check(opts.reload_min_interval_ms);
            {
                std::lock_guard<std::mutex> lk(mu);
                if (!server) throw Error("the server is not running");
                server->apply_config(n);  // throws and changes nothing when bind / port / root / key_file differ
            }
            gate.stamp();
            apply_logging(n.log_level, n.log_file);
            cfg = n;
            key_stamp_running = new_stamp;
            note_config(n, pl);
            close_pairing_if_off();  // switched off by this reload: close it now
            log_info("configuration reloaded from " + opts.config_path);
            return make_result(true, summary(d), &d);
        } catch (const std::exception& e) {
            log_warn(std::string("reload refused, keeping the running configuration: ") + e.what());
            return make_result(false, e.what(), nullptr);
        }
    }

    // Looks at the peers folder (and the revocation list) every few seconds; a change reloads the configuration, so a
    // peer added / removed by a script or a configuration-management tool takes effect without anyone calling reload.
    void watch_peers(std::atomic<bool>& stop, std::atomic<bool>& done) {
        std::string cdir = opts.config_path.empty() ? dir : fs::u8path(opts.config_path).parent_path().u8string();
        auto fp = [&] {
            ServerConfig c;
            {
                std::lock_guard<std::mutex> rl(reload_mu);
                c.peers_dir = cfg.peers_dir;
            }
            return peers_fingerprint(c, cdir);
        };
        std::string last = fp();
        while (!stop.load() && !done.load()) {
            for (int i = 0; i < opts.peers_poll_ms / 100 && !stop.load() && !done.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (stop.load() || done.load()) break;
            std::string now = fp();
            if (now == last) continue;
            ReloadResult rr = reload();
            // "too quickly" is the only refusal worth retrying on the same fingerprint
            if (rr.ok || rr.message.find("too quickly") == std::string::npos) last = now;
            if (rr.ok) log_info("peers folder changed: " + rr.message);
        }
    }
};

ServerDaemon::ServerDaemon(ServerConfig cfg, std::string config_dir, DaemonOptions opts) : p_(new Impl) {
    p_->cfg = std::move(cfg);
    p_->dir = std::move(config_dir);
    p_->opts = std::move(opts);
    if (p_->opts.service_name.empty()) p_->opts.service_name = "mysync-server";
    p_->cfg_pairing = p_->cfg.pairing;
    p_->rotation_under_way = !p_->cfg.key_file_next.empty();
    // [server] pairing = "off" (the default) closes every way into the pairing mode, the control channel included.
    if (p_->opts.allow_pairing && p_->cfg.pairing == PairingMode::Off) {
        log_warn("pairing was requested but [server] pairing = \"off\": the pairing mode stays unavailable");
        p_->opts.allow_pairing = false;
    }
}

ServerDaemon::~ServerDaemon() {
    if (p_->host) p_->host->stop();
}

StatusSnapshot ServerDaemon::snapshot() { return p_->snapshot(); }
bool ServerDaemon::pairing_allowed() const { return p_->opts.allow_pairing; }  // already cleared in the constructor when [server] pairing = "off"
ReloadResult ServerDaemon::reload() { return p_->reload(); }

void ServerDaemon::run(std::atomic<bool>& stop) {
    Impl& im = *p_;
    install_error_tap();
    check_trust(im.cfg, im.opts);  // throws: an untrusted configuration stops the daemon
    if (!im.opts.config_path.empty()) {
        // The report of what the first load skipped (status, log file). With the strict trust check on, the
        // configuration handed in may have been merged without it: the freshly loaded, vetted one replaces it.
        PeerLoad pl;
        ServerConfig fresh = load_server_config_resolved(im.opts.config_path, &pl,
                                                         im.opts.enforce_config_trust ? &im.opts.trusted_writers : nullptr);
        if (im.opts.enforce_config_trust) im.cfg = fresh;
        else im.cfg.clients = fresh.clients;  // peers.d may have changed since the caller loaded the file
        im.note_config(im.cfg, pl);
    }
    im.key_stamp_running = key_stamp(im.cfg);
    Server srv(im.cfg);
    if (im.opts.allow_pairing)
        srv.pairing().set_approve_handler([&im](const std::string& n, const PubKey& k) { return im.pair_approve(n, k); });
    log_info("MySync server " + im.opts.version + " listening on " + im.cfg.bind + ":" + std::to_string(srv.port()) +
             ", root " + im.cfg.root + ", public key " + key_to_hex(srv.public_key()));
    {
        std::lock_guard<std::mutex> lk(im.mu);
        im.server = &srv;
    }
    if (im.cfg.control_enabled) {
        try {
            std::string name = effective_control_name(im.cfg.control_name, im.opts.service_name, true);
            im.host = std::make_unique<ControlHost>(
                Role::Server, im.opts, ipc_options(name, im.cfg.control_allow, im.cfg.control_group, im.opts.control_dir_override),
                [&im] {
                    StatusSnapshot s = im.snapshot();
                    return s;
                },
                [&im] { return im.reload(); });
            if (im.opts.allow_pairing)
                im.host->set_pair_handler([&im, &srv](const ControlRequest& q) { return im.pair_op(srv, q); });
            im.host->start();
        } catch (const std::exception& e) {
            log_error(std::string("control channel unavailable (the GUI cannot manage this server): ") + e.what());
            im.host.reset();
        }
    }
    std::atomic<bool> watch_done{false};
    std::thread peers_watcher;
    if (im.opts.peers_poll_ms > 0 && !im.opts.config_path.empty())
        peers_watcher = std::thread([&im, &stop, &watch_done] { im.watch_peers(stop, watch_done); });
    struct Join {
        std::atomic<bool>& done;
        std::thread& th;
        ~Join() {
            done = true;
            if (th.joinable()) th.join();
        }
    } join_watcher{watch_done, peers_watcher};
    try {
        srv.run(stop);
    } catch (...) {
        if (im.host) im.host->stop();
        std::lock_guard<std::mutex> lk(im.mu);
        im.server = nullptr;
        throw;
    }
    if (im.host) im.host->stop();
    std::lock_guard<std::mutex> lk(im.mu);
    im.server = nullptr;
}

}  // namespace mysync::gui
