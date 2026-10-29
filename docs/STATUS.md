# Trạng thái kiểm thử và hạn chế đã biết

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

## Đã kiểm (đo thật)
- Windows 11, MinGW-w64 g++ 15.2 + CMake 4.0 + Ninja, Release: `mysync_tests` **185 passed, 0 failed** (cộng `third_party_checksums` trong ctest: 2/2 đạt). Gồm unit + tích hợp client↔server loopback + engine + watcher thật; các test mới: hạn mức theo client, trash khi ghi đè, trần trash, quyền tệp, tên thiết bị Unicode, checksum third_party.
- Linux: Docker `gcc:14` (Debian, chạy bằng root — uid 0, không phải máy thật): build **không còn cảnh báo** (`-Wall -Wextra`, trước đây còn `-Wformat-truncation` ở util.cpp:71); `mysync_tests` **186 passed, 0 failed** (gồm 2 test quyền 0640/0750 chỉ chạy trên POSIX), chạy 2 lần liên tiếp đều đạt; `ctest` 2/2 đạt, ~37 s. Test quyền kiểm bit mode do `fchmod`/`chmod` đặt nên có ý nghĩa cả khi chạy bằng root; chưa kiểm trên Linux thật dưới tài khoản thường. WSL Ubuntu của máy này không có trình biên dịch nên không dùng.
- Chạy tay CLI trên Windows: `keygen` ×2 → server + `client --once` đồng bộ 3 tệp (3 MB ngẫu nhiên giống từng byte), lần chạy 2 gửi 0 tệp (đủ trùng hash/index).
- Đo loopback (thử nghiệm trong test, không phải benchmark chính thức): tệp 20 MiB đầy đủ ≈ 168 MiB/s; sửa 1 byte trong tệp 20 MiB → delta, ~29 KB trên dây; 500 tệp nhỏ OFFER pipeline ≈ 227 tệp/s; 500 tệp trùng (SKIP) ≈ 55 ms.

## CHƯA kiểm
- **MSVC** (không có trên máy): CMake đã có nhánh MSVC (`/MT`, cờ arch cho BLAKE3, `/utf-8`) nhưng chưa biên dịch thử.
- **Cài dịch vụ thật** (Windows SCM, systemd): chỉ test phần sinh tham số/unit và logic; cần quyền admin/root và chưa chạy trên máy này.
- **Event Log / journald** riêng: log ghi ra tệp + stderr (journald thu stderr khi chạy dưới systemd). Chưa có Windows Event Log.
- Hiệu năng mạng xa (WAN), nhiều GB, hàng triệu tệp; Linux inotify với `max_user_watches` thấp ngoài test.
- ACL Windows của tệp khoá trong môi trường nhiều người dùng.

## Hạn chế / khác biệt so với định hướng thiết kế
- Nén là **LZ4** (không phải zstd): đơn giản, vendor nhỏ, đủ nhanh; zstd tỷ lệ nén tốt hơn — có thể thêm sau.
- Mỗi tiến trình mở **N kết nối song song** (mặc định 4) kèm pipeline OFFER, chứ không phải một kết nối ghép kênh; tệp lớn trên đường dài không được cắt khúc đa luồng.
- Ghi tệp đích dùng `safe_join` + từ chối symlink khi kiểm tra; **không** dùng `openat/RESOLVE_BENEATH`: kẻ tấn công cục bộ có quyền ghi vào cây đích có thể đua TOCTOU (rà soát mục M4).
- Hạn mức server: `max_write_bytes_per_hour` tính byte đã nhận kể cả của lần truyền hỏng (không hoàn lại); đếm trong bộ nhớ nên **reset khi khởi động lại server**. Dung lượng trash `max_trash_bytes` quét lười một lần mỗi lần chạy (thư mục trash rất lớn làm lần xoá đầu tiên chậm). `LocalTarget` đưa bản cũ vào trash khi ghi đè nhưng chưa có hạn mức dung lượng trash.
- Băng thông server: tái dùng `RateLimiter` (token bucket); chặn bằng cách ngủ trong luồng phiên sau khi nhận/trước khi gửi, nên hiệu lực qua TCP backpressure; gộp nhận + gửi một bucket mỗi cấp (máy, toàn server); không theo giờ, không áp cho đích cục bộ.
- Đoạn ghi đè = "rename bản cũ vào trash rồi rename bản mới vào chỗ": giữa hai bước tệp đích tạm thời không tồn tại (cửa sổ vài micro-giây; nếu bước hai hỏng thì bản cũ được trả lại). Không dùng được `renameat2(RENAME_EXCHANGE)` trên mọi nền tảng.
- Test `net_many_parallel_clients` từng phụ thuộc tốc độ bắt tay (giới hạn 4 kết nối chưa xác thực/IP làm vài kết nối bị từ chối ở máy chậm/Linux); đã sửa test để máy khách thử lại như máy khách thật.
- Noise_IK là bản tự cài bằng Monocypher (XChaCha20-Poly1305), **không** tương thích thư viện Noise chuẩn; chưa được thẩm định bởi chuyên gia mật mã bên ngoài. Một lượt rà soát độc lập (agent) không thấy lỗi mật mã nghiêm trọng.
- Thư viện bên thứ ba ghim bằng `third_party/CHECKSUMS.sha256` + `third_party/README.md` (tag/commit/giấy phép); kiểm bằng `scripts/verify-third-party.sh|.ps1` hoặc `ctest -R third_party_checksums`.
- Không còn: cảnh báo email/Yahoo, FTP, NetworkMonitor, GUI WinForms, Bin/Bson/ProtoBuf — theo quyết định người dùng (xem `FEATURES.md`).
