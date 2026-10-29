// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/keys.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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

static void write_new_file(const std::string& utf8_path, const std::string& text, bool secret) {
    fs::path p = fs::u8path(utf8_path);
    std::error_code ec;
    if (fs::exists(p, ec)) throw Error("refusing to overwrite existing file");
#ifndef _WIN32
    int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL, secret ? 0600 : 0644);
    if (fd < 0) throw Error("cannot create file");
    size_t off = 0;
    while (off < text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n <= 0) { ::close(fd); throw Error("write failed"); }
        off += size_t(n);
    }
    if (::close(fd) != 0) throw Error("write failed");
#else
    (void)secret;
    std::ofstream o(p, std::ios::binary);
    if (!o) throw Error("cannot create file");
    o << text;
    o.flush();
    if (!o) throw Error("write failed");
#endif
}

void save_keypair(const std::string& utf8_path, const KeyPair& kp) {
    std::string text = key_to_hex(kp.secret) + "\n";
    write_new_file(utf8_path, text, true);
    secure_wipe(text.data(), text.size());
}

KeyPair load_keypair(const std::string& utf8_path) {
#ifndef _WIN32
    struct stat st;
    if (::stat(fs::u8path(utf8_path).c_str(), &st) != 0) throw Error("cannot open key file");
    if (st.st_mode & 077) throw Error("key file permissions too open (must be 0600)");
#endif
    std::string text = read_text(utf8_path);
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
