// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#include "mysync/simple/pair_code.h"

#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include "monocypher.h"

namespace mysync::simple {
namespace {

constexpr char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // Crockford: no I L O U
constexpr const char* kPrefix = "MSY1";
constexpr uint8_t kVersion = 2;
constexpr size_t kMaxHost = 100;

[[noreturn]] void bad() { throw Error("this pairing code is not valid: check that it was copied completely"); }

int digit_of(char c) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    if (c == 'O') c = '0';
    if (c == 'I' || c == 'L') c = '1';
    if (c == '\0') return -1;
    const void* p = std::memchr(kAlphabet, c, 32);
    return p ? int(static_cast<const char*>(p) - kAlphabet) : -1;
}

Hash256 blake2b256(const Bytes& b) {
    Hash256 h{};
    crypto_blake2b(h.data(), 32, b.data(), b.size());
    return h;
}

bool valid_ipv4(const std::string& s) {
    unsigned parts = 0;
    size_t i = 0;
    for (;;) {
        size_t j = i;
        unsigned v = 0;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
            v = v * 10 + unsigned(s[j] - '0');
            if (j - i >= 3) return false;
            ++j;
        }
        if (j == i || v > 255 || (j - i > 1 && s[i] == '0')) return false;
        ++parts;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
    }
    return parts == 4;
}

}  // namespace

std::string crockford_encode(const Bytes& in) {
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t b : in) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            out += kAlphabet[(acc >> (bits - 5)) & 31];
            bits -= 5;
        }
        acc &= (1u << bits) - 1;
    }
    if (bits > 0) out += kAlphabet[(acc << (5 - bits)) & 31];
    return out;
}

Bytes crockford_decode(const std::string& text) {
    Bytes out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        int d = digit_of(c);
        if (d < 0) bad();
        acc = (acc << 5) | uint32_t(d);
        bits += 5;
        if (bits >= 8) {
            out.push_back(uint8_t((acc >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
        acc &= (1u << bits) - 1;
    }
    if (bits >= 5 || acc != 0) bad();  // a whole character left over, or non-canonical padding bits
    return out;
}

bool valid_pair_host(const std::string& host) {
    if (host.empty() || host.size() > kMaxHost) return false;
    for (unsigned char c : host)
        if (c <= 0x20 || c >= 0x7F) return false;
    if (host.find(':') != std::string::npos) {  // IPv6 literal, no zone id, no brackets
        struct in6_addr a6;
        return host.find('%') == std::string::npos && host.find('[') == std::string::npos &&
               inet_pton(AF_INET6, host.c_str(), &a6) == 1;
    }
    bool digits_dots = true;
    for (char c : host)
        if (!((c >= '0' && c <= '9') || c == '.')) digits_dots = false;
    if (digits_dots) return valid_ipv4(host);
    size_t label = 0;
    char prev = '.';
    for (size_t i = 0; i < host.size(); ++i) {
        char c = host[i];
        if (c == '.') {
            if (label == 0 || prev == '-') return false;
            label = 0;
        } else {
            bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
            if (!ok || ++label > 63) return false;
            if (c == '-' && prev == '.') return false;
        }
        prev = c;
    }
    return label != 0 && prev != '-';
}

std::string encode_pair_code(const PairCode& pc) {
    if (pc.port == 0) throw Error("pairing code: the port must be 1..65535");
    if (!valid_pair_host(pc.host)) throw Error("pairing code: the host is not a valid address or name");
    Bytes p;
    p.push_back(kVersion);
    p.insert(p.end(), pc.server_key.begin(), pc.server_key.end());
    p.insert(p.end(), pc.token.begin(), pc.token.end());
    p.push_back(uint8_t(pc.port >> 8));
    p.push_back(uint8_t(pc.port & 0xFF));
    p.push_back(uint8_t(pc.host.size()));
    p.insert(p.end(), pc.host.begin(), pc.host.end());
    Hash256 h = blake2b256(p);
    p.insert(p.end(), h.begin(), h.begin() + 4);
    std::string body = crockford_encode(p);
    std::string out = kPrefix;
    for (size_t i = 0; i < body.size(); i += 5) out += "-" + body.substr(i, 5);
    return out;
}

bool looks_like_pair_code(const std::string& text) {
    size_t i = 0;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) ++i;
    if (text.size() - i < 4) return false;
    for (int k = 0; k < 4; ++k) {
        char c = text[i + size_t(k)];
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        if (c != kPrefix[k]) return false;
    }
    return true;
}

PairCode decode_pair_code(const std::string& text) {
    if (text.size() > 400) bad();
    size_t i = 0;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n')) ++i;
    if (!looks_like_pair_code(text)) bad();
    i += 4;
    // After the prefix a '-' or a space is allowed; the Crockford decoder skips them anywhere.
    Bytes p = crockford_decode(text.substr(i));
    if (p.size() < 1 + 32 + 16 + 2 + 1 + 1 + 4) bad();
    if (p[0] != kVersion) bad();
    size_t hl = p[51];
    if (hl == 0 || hl > kMaxHost || p.size() != 52 + hl + 4) bad();
    Bytes body(p.begin(), p.end() - 4);
    Hash256 h = blake2b256(body);
    if (!ct_equal(h.data(), p.data() + p.size() - 4, 4)) bad();
    PairCode pc;
    std::memcpy(pc.server_key.data(), p.data() + 1, 32);
    std::memcpy(pc.token.data(), p.data() + 33, 16);
    pc.port = uint16_t((p[49] << 8) | p[50]);
    pc.host.assign(reinterpret_cast<const char*>(p.data() + 52), hl);
    if (pc.port == 0 || !valid_pair_host(pc.host)) bad();
    return pc;
}

std::string pair_sas(const PubKey& client_pub, const PubKey& server_pub) {
    static const char kTag[] = "MySync-SAS-v1";
    Bytes m(kTag, kTag + sizeof kTag - 1);
    m.insert(m.end(), client_pub.begin(), client_pub.end());
    m.insert(m.end(), server_pub.begin(), server_pub.end());
    Hash256 h = blake2b256(m);
    std::string s = crockford_encode(Bytes(h.begin(), h.begin() + 10));  // 80 bits = 16 characters
    std::string out;
    for (size_t i = 0; i < s.size(); i += 4) out += (i ? "-" : "") + s.substr(i, 4);
    return out;
}

}  // namespace mysync::simple
