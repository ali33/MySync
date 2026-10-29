#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 META.vn
# Author: Nguyễn Đức Sơn
#
# Kiểm third_party/ khớp với third_party/CHECKSUMS.sha256 (SHA-256 từng tệp). Thoát 0 nếu khớp hết, khác 0 nếu có tệp
# sai / thiếu. Dùng sha256sum (GNU) hoặc shasum -a 256 (macOS/BSD).
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dir="$here/../third_party"
cd "$dir"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c CHECKSUMS.sha256
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c CHECKSUMS.sha256
else
    echo "verify-third-party: neither sha256sum nor shasum found" >&2
    exit 2
fi
echo "third_party: all checksums match"
