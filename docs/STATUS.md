# Trạng thái kiểm thử và hạn chế đã biết

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

## Đã kiểm (đo thật)
- Windows 11, MinGW-w64 g++ 15.2 + CMake 4.0 + Ninja, Release: `mysync_tests` **170 passed, 0 failed** (sau khi sửa các lỗi bảo mật H1, M1, M2, M5, L1, L2, L5 từ lượt rà soát độc lập) (unit + tích hợp client↔server loopback + engine + watcher thật).
- Linux: Docker `gcc:14` (Debian, chạy bằng root, không phải máy thật) build và `ctest` chạy bộ test: **100% tests passed (1/1 gói mysync_tests), 35 s**; còn cảnh báo biên dịch `-Wformat-truncation` ở util.cpp:71. WSL Ubuntu của máy này không có trình biên dịch nên không dùng. Chưa kiểm trên Linux thật dưới tài khoản thường (test quyền 0600 do root nên ít ý nghĩa).
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
- Server không có hạn mức theo client (số phiên, byte ghi, thùng rác `__sync/__trash` không giới hạn dung lượng, `max_file_size` mặc định 0) — rà soát mục M3. Client có quyền `rw` hợp lệ về nguyên tắc tin cậy.
- Ghi đè tệp bằng upload không đưa bản cũ vào trash (chỉ DELETE/RENAME vào trash).
- Tệp trên server tạo quyền 0644 (Linux).
- Tên thiết bị Windows kiểu Unicode (`COM¹`…) chưa chặn trong `pathsafe`.
- Noise_IK là bản tự cài bằng Monocypher (XChaCha20-Poly1305), **không** tương thích thư viện Noise chuẩn; chưa được thẩm định bởi chuyên gia mật mã bên ngoài. Một lượt rà soát độc lập (agent) không thấy lỗi mật mã nghiêm trọng.
- Monocypher vendor ghi "version __git__" (bản chép từ tag 4.0.2 của GitHub, chưa có checksum ghim).
- Không còn: cảnh báo email/Yahoo, FTP, NetworkMonitor, GUI WinForms, Bin/Bson/ProtoBuf — theo quyết định người dùng (xem `FEATURES.md`).
