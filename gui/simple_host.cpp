// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn
#include "simple_host.h"

#include <cstdlib>
#include <filesystem>

#include "i18n_model.h"
#include "mysync/simple/wizard_model.h"
#include "simple_model.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace mysync::gui {

namespace fs = std::filesystem;

namespace {
bool exists_file(const std::string& u8) {
    std::error_code ec;
    return fs::is_regular_file(fs::u8path(u8), ec);
}
}  // namespace

bool SimpleHost::init(const std::string& dir_override, std::string* err) {
    try {
        paths_ = simple::UserPaths::for_current_user(dir_override);
        return true;
    } catch (const std::exception& e) {
        if (err) *err = e.what();
        return false;
    }
}

bool SimpleHost::has_config() const { return !paths_.client_config.empty() && exists_file(paths_.client_config); }
bool SimpleHost::has_receiver_config() const {
    return !paths_.receiver_config.empty() && exists_file(paths_.receiver_config);
}

void SimpleHost::start_supervisor(bool run_client, bool run_receiver) {
    std::lock_guard<std::mutex> lk(mu_);
    if (sup_) return;
    std::string holder;
    auto il = simple::InstanceLock::try_acquire(paths_, &holder);
    if (!il) throw Error(trf("simple.err.lock", {holder}));
    simple::SupervisorOptions o;
    o.paths = paths_;
    o.run_client = run_client && has_config();
    o.run_receiver = run_receiver && has_receiver_config();
    auto sup = std::make_unique<simple::Supervisor>(std::move(o));
    sup->start();
    lock_ = std::move(il);
    sup_ = std::move(sup);
}

bool SimpleHost::supervisor_ready() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sup_ != nullptr;
}

simple::Supervisor* SimpleHost::sup() {
    std::lock_guard<std::mutex> lk(mu_);
    return sup_.get();
}

void SimpleHost::apply_client_config() {
    if (!supervisor_ready()) {
        start_supervisor(true, false);
        return;  // nếu Supervisor vừa được tạo thì engine client đã chạy với cấu hình mới
    }
    simple::Supervisor* s = sup();
    s->set_client_enabled(true);
    s->restart(simple::EngineKind::Client);
}

KeyPair SimpleHost::load_or_create_client_key(const simple::UserPaths& p) {
    p.ensure_dirs();
    simple::ensure_user_key(p.client_key);
    return load_keypair(p.client_key);
}

simple::EngineInfo SimpleHost::client_info() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sup_ ? sup_->info(simple::EngineKind::Client) : simple::EngineInfo{};
}
simple::EngineInfo SimpleHost::receiver_info() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (!sup_) {
        simple::EngineInfo i;
        i.kind = simple::EngineKind::Receiver;
        return i;
    }
    return sup_->info(simple::EngineKind::Receiver);
}

void SimpleHost::stop_all() {
    simple::Supervisor* s = sup();
    if (s) s->stop_all();
}

std::string SimpleHost::default_receive_folder() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, buf)) && buf[0]) {
        return (fs::path(buf) / L"MySync-Nhan").u8string();
    }
    return "C:\\MySync-Nhan";
#else
    const char* h = std::getenv("HOME");
    return std::string(h && *h ? h : "/tmp") + "/MySync-Nhan";
#endif
}

namespace {
std::string g_demo_ip;
}
void SimpleHost::set_demo_address(const std::string& ip) { g_demo_ip = ip; }

std::vector<std::string> SimpleHost::local_addresses() {
    if (!g_demo_ip.empty()) return {g_demo_ip};
    std::vector<std::string> raw;
#ifdef _WIN32
    WSADATA wsa;
    bool started = WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    char host[256] = {};
    if (gethostname(host, sizeof host - 1) == 0) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host, nullptr, &hints, &res) == 0) {
            for (auto* p = res; p; p = p->ai_next) {
                char b[INET6_ADDRSTRLEN] = {};
                if (p->ai_family == AF_INET)
                    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr, b, sizeof b);
                else if (p->ai_family == AF_INET6)
                    inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr, b, sizeof b);
                if (b[0]) raw.push_back(b);
            }
            freeaddrinfo(res);
        }
    }
    if (started) WSACleanup();
#else
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) == 0) {
        for (auto* p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr) continue;
            char b[INET6_ADDRSTRLEN] = {};
            if (p->ifa_addr->sa_family == AF_INET)
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(p->ifa_addr)->sin_addr, b, sizeof b);
            else if (p->ifa_addr->sa_family == AF_INET6)
                inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(p->ifa_addr)->sin6_addr, b, sizeof b);
            if (b[0]) raw.push_back(b);
        }
        freeifaddrs(ifa);
    }
#endif
    return rank_addresses(raw);
}

}  // namespace mysync::gui
