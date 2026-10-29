# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 META.vn
# Author: Nguyễn Đức Sơn
#
# Kiểm third_party/ khớp với third_party/CHECKSUMS.sha256 (SHA-256 từng tệp). Thoát 0 nếu khớp hết, 1 nếu có tệp sai / thiếu.
$ErrorActionPreference = 'Stop'
$dir = Join-Path (Split-Path -Parent $PSScriptRoot) 'third_party'
$bad = 0
foreach ($line in Get-Content -LiteralPath (Join-Path $dir 'CHECKSUMS.sha256')) {
    if ($line.Trim() -eq '') { continue }
    if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { Write-Error "bad line: $line"; $bad++; continue }
    $want = $Matches[1].ToLowerInvariant()
    $file = Join-Path $dir $Matches[2]
    if (-not (Test-Path -LiteralPath $file)) { Write-Host "MISSING  $($Matches[2])"; $bad++; continue }
    $got = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $want) { Write-Host "MISMATCH $($Matches[2])"; $bad++ }
}
if ($bad -ne 0) { Write-Host "third_party: $bad file(s) differ from CHECKSUMS.sha256"; exit 1 }
Write-Host 'third_party: all checksums match'
