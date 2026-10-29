// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/keys.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

#include "monocypher.h"

namespace mysync {

namespace fs = std::filesystem;

KeyPair generate_keypair() {
    PubKey sk;
    random_bytes(sk.data(), sk.size());
    KeyPair kp = keypair_from_secret(sk);
    secure_wipe(sk.data(), sk.size());
    return kp;
}

KeyPair keypair_from_secret(const PubKey& secret) {
    KeyPair kp;
    kp.secret = secret;
    crypto_x25519_public_key(kp.pub.data(), kp.secret.data());
    return kp;
}

std::string key_to_hex(const PubKey& k) { return to_hex(k.data(), k.size()); }

PubKey key_from_hex(const std::string& in) {
    size_t b = 0, e = in.size();
    while (b < e && std::isspace(static_cast<unsigned char>(in[b]))) b++;
    while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1]))) e--;
    std::string hex = in.substr(b, e - b);
    if (hex.size() != 64) throw Error("key must be exactly 64 hex characters");
    Bytes raw = from_hex(hex);
    if (raw.size() != 32) throw Error("key must be exactly 64 hex characters");
    PubKey k;
    std::copy(raw.begin(), raw.end(), k.begin());
    secure_wipe(raw.data(), raw.size());
    return k;
}

static std::string read_text(const std::string& utf8_path) {
    std::ifstream in(fs::u8path(utf8_path), std::ios::binary);
    if (!in) throw Error("cannot open key file");
    std::string s;
    char buf[256];
    while (in.read(buf, sizeof buf) || in.gcount() > 0) {
        s.append(buf, size_t(in.gcount()));
        if (s.size() > 4096) throw Error("key file too large");
    }
    return s;
}

#ifdef _WIN32
namespace {

struct HandleGuard {
    HANDLE h;
    ~HandleGuard() {
        if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
    }
};

bool sid_is(PSID sid, WELL_KNOWN_SID_TYPE type) {
    BYTE buf[SECURITY_MAX_SID_SIZE];
    DWORD n = sizeof buf;
    return ::CreateWellKnownSid(type, nullptr, buf, &n) && ::EqualSid(sid, buf);
}

// Broad principals that an ACCESS_ALLOWED ACE of the handle's DACL names. A NULL DACL grants everyone everything.
std::vector<std::string> broad_acl_of(HANDLE h) {
    std::vector<std::string> out;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (::GetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) !=
        ERROR_SUCCESS)
        return out;
    if (!dacl) {
        out.push_back("Everyone");
    } else {
        for (DWORD i = 0; i < dacl->AceCount; i++) {
            void* ace = nullptr;
            if (!::GetAce(dacl, i, &ace) || !ace) continue;
            auto* hdr = static_cast<ACE_HEADER*>(ace);
            if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
            PSID sid = &static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart;
            const char* name = sid_is(sid, WinWorldSid)               ? "Everyone"
                               : sid_is(sid, WinBuiltinUsersSid)      ? "Users"
                               : sid_is(sid, WinAuthenticatedUserSid) ? "Authenticated Users"
                                                                      : nullptr;
            if (name) out.push_back(name);
        }
    }
    ::LocalFree(sd);
    return out;
}

}  // namespace
#endif

std::vector<std::string> key_file_broad_acl(const std::string& utf8_path) {
#ifdef _WIN32
    HANDLE h = ::CreateFileW(fs::u8path(utf8_path).c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    HandleGuard g{h};
    return broad_acl_of(h);
#else
    (void)utf8_path;
    return {};
#endif
}

std::string read_secret_file(const std::string& utf8_path) {
    constexpr size_t kMax = 4096;
    std::string text;
    char buf[512];
#ifndef _WIN32
    int fd = ::open(fs::u8path(utf8_path).c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ELOOP) throw Error("key file is a symbolic link (refused): " + utf8_path);
        throw Error("cannot read key file: " + utf8_path);
    }
    struct Fd {
        int fd;
        ~Fd() { ::close(fd); }
    } guard{fd};
    struct stat st;
    if (::fstat(fd, &st) != 0) throw Error("cannot read key file: " + utf8_path);
    if (!S_ISREG(st.st_mode)) throw Error("key file is not a regular file: " + utf8_path);
    if (st.st_uid != ::geteuid() && st.st_uid != 0)
        throw Error("key file " + utf8_path + " is owned by another user");
    if (st.st_mode & 077)
        throw Error("key file " + utf8_path + " is accessible by group/other; run: chmod 600 " + utf8_path);
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            secure_wipe(buf, sizeof buf);
            secure_wipe(text.data(), text.size());
            throw Error("cannot read key file: " + utf8_path);
        }
        if (n == 0) break;
        text.append(buf, size_t(n));
        if (text.size() > kMax) {
            secure_wipe(buf, sizeof buf);
            secure_wipe(text.data(), text.size());
            throw Error("key file too large");
        }
    }
#else
    HANDLE h = ::CreateFileW(fs::u8path(utf8_path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) throw Error("cannot read key file: " + utf8_path);
    HandleGuard guard{h};
    if (::GetFileType(h) != FILE_TYPE_DISK) throw Error("key file is not a regular file: " + utf8_path);
    std::vector<std::string> broad = broad_acl_of(h);
    if (!broad.empty()) {
        std::string who;
        for (const auto& b : broad) who += (who.empty() ? "" : ", ") + b;
        log_warn("key file " + utf8_path + " is accessible by " + who +
                 "; restrict it to your own account (icacls <file> /inheritance:r /grant:r %USERNAME%:F)");
    }
    for (;;) {
        DWORD n = 0;
        if (!::ReadFile(h, buf, sizeof buf, &n, nullptr)) {
            secure_wipe(buf, sizeof buf);
            secure_wipe(text.data(), text.size());
            throw Error("cannot read key file: " + utf8_path);
        }
        if (n == 0) break;
        text.append(buf, size_t(n));
        if (text.size() > kMax) {
            secure_wipe(buf, sizeof buf);
            secure_wipe(text.data(), text.size());
            throw Error("key file too large");
        }
    }
#endif
    secure_wipe(buf, sizeof buf);
    return text;
}

static void write_new_file(const std::string& utf8_path, const std::string& text, bool secret) {
    fs::path p = fs::u8path(utf8_path);
#ifndef _WIN32
    // Exclusive create, never through a symlink; a secret file is owner-only from the first instant.
    int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, secret ? 0600 : 0644);
    if (fd < 0) {
        if (errno == EEXIST) throw Error("refusing to overwrite existing file");
        throw Error("cannot create file");
    }
    size_t off = 0;
    while (off < text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ::close(fd); throw Error("write failed"); }
        off += size_t(n);
    }
    if (::close(fd) != 0) throw Error("write failed");
#else
    // CREATE_NEW: fails if anything (file, symlink) is already there. The DACL is protected (no inheritance) and
    // names only the owner, SYSTEM and Administrators.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (secret) {
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
                                                                    SDDL_REVISION_1, &psd, nullptr))
            throw Error("cannot build a private ACL for the key file");
        sa.lpSecurityDescriptor = psd;
    }
    HANDLE h = ::CreateFileW(p.c_str(), GENERIC_WRITE, 0, secret ? &sa : nullptr, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    DWORD cerr = ::GetLastError();
    if (psd) ::LocalFree(psd);
    if (h == INVALID_HANDLE_VALUE) {
        if (cerr == ERROR_FILE_EXISTS || cerr == ERROR_ALREADY_EXISTS) throw Error("refusing to overwrite existing file");
        throw Error("cannot create file");
    }
    HandleGuard guard{h};
    size_t off = 0;
    while (off < text.size()) {
        DWORD n = 0;
        if (!::WriteFile(h, text.data() + off, DWORD(text.size() - off), &n, nullptr) || n == 0)
            throw Error("write failed");
        off += n;
    }
    if (!::FlushFileBuffers(h)) throw Error("write failed");
#endif
}

void save_keypair(const std::string& utf8_path, const KeyPair& kp) {
    std::string text = key_to_hex(kp.secret) + "\n";
    write_new_file(utf8_path, text, true);
    secure_wipe(text.data(), text.size());
}

KeyPair load_keypair(const std::string& utf8_path) {
    std::string text = read_secret_file(utf8_path);
    PubKey sk;
    try {
        sk = key_from_hex(text);
    } catch (...) {
        secure_wipe(text.data(), text.size());
        throw Error("invalid key file (expected 64 hex characters)");
    }
    secure_wipe(text.data(), text.size());
    KeyPair kp = keypair_from_secret(sk);
    secure_wipe(sk.data(), sk.size());
    return kp;
}

PubKey load_public_file(const std::string& utf8_path) {
    try {
        return key_from_hex(read_text(utf8_path));
    } catch (const Error& e) {
        throw Error(std::string("invalid public key file: ") + e.what());
    }
}

void save_public_file(const std::string& utf8_path, const PubKey& k) {
    write_new_file(utf8_path, key_to_hex(k) + "\n", false);
}

}  // namespace mysync
