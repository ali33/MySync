// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 META.vn
// Author: Nguyễn Đức Sơn

#pragma once
// simple/pair_code.h - the one-line pairing code a receiving machine shows and a sending machine pastes.
//   "MSY1-" + Crockford base32 (alphabet 0-9 A-Z without I L O U; case-insensitive; '-' and spaces ignored on input;
//   O reads as 0, I and L as 1), written in groups of 5 separated by '-', of the payload:
//     version(1)=2 | receiver public key (32) | one-time token (16) | port (2, big-endian, 1..65535) | host length (1) | host (1..100 bytes)
//     | checksum (4) = first 4 bytes of BLAKE2b-256 of every byte before it.
//   host: IPv4 / IPv6 literal or a DNS name (letters, digits, '-', '.', no leading/trailing '-' or '.').
// The code NEVER contains a secret key (there is no field for one). decode throws Error (generic text, no echo of the
// input) for: wrong prefix or version, characters outside the alphabet, wrong length, bad checksum, absurd host or
// port, extra bytes.
#include <string>

#include "mysync/keys.h"
#include "mysync/util.h"

namespace mysync::simple {

struct PairCode {
    PubKey server_key{};
    std::array<uint8_t, 16> token{};  // one-time pairing token: proves the sender was handed this code (see pairing.h)
    uint16_t port = 0;
    std::string host;
};

bool valid_pair_host(const std::string& host);
std::string encode_pair_code(const PairCode&);                // throws Error for an invalid host / port 0
PairCode decode_pair_code(const std::string& text);           // throws Error
bool looks_like_pair_code(const std::string& text);           // cheap prefix test for the GUI (no checksum)

// Confirmation string both screens must show alike: BLAKE2b("MySync-SAS-v1" || client_pub || server_pub), first 80
// bits as 16 Crockford characters in 4 groups: "ABCD-EFGH-JKMN-PQRS".
std::string pair_sas(const PubKey& client_pub, const PubKey& server_pub);

// Crockford base32 helpers (exposed for tests).
std::string crockford_encode(const Bytes&);
Bytes crockford_decode(const std::string&);                   // throws Error on a character outside the alphabet

}  // namespace mysync::simple
