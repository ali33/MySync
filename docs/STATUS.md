# Trạng thái kiểm thử và hạn chế đã biết

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

## Đã kiểm (đo thật)
- Windows 11, MinGW-w64 g++ 15.2 + CMake 4.0 + Ninja, Release: `mysync_tests` **194 passed, 0 failed** (cộng `third_party_checksums` trong ctest: 2/2 đạt). Gồm unit + tích hợp client↔server loopback + engine + watcher thật; các test mới: hạn mức theo client, trash khi ghi đè, trần trash, quyền tệp, tên thiết bị Unicode, checksum third_party.
- Linux: Docker `gcc:14` (Debian, chạy bằng root — uid 0, không phải máy thật): build **không còn cảnh báo** (`-Wall -Wextra`, trước đây còn `-Wformat-truncation` ở util.cpp:71); `mysync_tests` **194 passed, 0 failed** (gồm 2 test quyền 0640/0750 chỉ chạy trên POSIX), chạy 2 lần liên tiếp đều đạt; `ctest` 2/2 đạt, ~54 s. Test quyền kiểm bit mode do `fchmod`/`chmod` đặt nên có ý nghĩa cả khi chạy bằng root; chưa kiểm trên Linux thật dưới tài khoản thường. WSL Ubuntu của máy này không có trình biên dịch nên không dùng.
- Chạy tay CLI trên Windows: `keygen` ×2 → server + `client --once` đồng bộ 3 tệp (3 MB ngẫu nhiên giống từng byte), lần chạy 2 gửi 0 tệp (đủ trùng hash/index).
- Đo loopback (thử nghiệm trong test, không phải benchmark chính thức): tệp 20 MiB đầy đủ ≈ 168 MiB/s; sửa 1 byte trong tệp 20 MiB → delta, ~29 KB trên dây; 500 tệp nhỏ OFFER pipeline ≈ 227 tệp/s; 500 tệp trùng (SKIP) ≈ 55 ms.

## Đã sửa sau rà soát (M1, M3, L6)
- **M1** (hạn mức chưa xác thực): thẻ "chưa xác thực" giờ giữ tới khi nhận được HELLO hợp lệ; chỉ sau đó mới tính `max_connections` (`active`) và `max_sessions`. Kẻ phát lại msg1 (khoá hợp lệ, không HELLO) không còn chiếm chỗ của máy bị mạo danh; kết nối đó vẫn bị đếm là chưa xác thực tới hết hạn HELLO 5 s (rồi `record_failure` cho IP). Test: `server_silent_authenticated_connection_does_not_take_a_session_slot`. Hệ quả nhỏ: từ chối do `max_sessions`/`max_connections` giờ đến sau HELLO chứ không ngay sau bắt tay.
- **M3** (băng thông): `RateLimiter::acquire(bytes, stop)` ngủ từng lát <= 100 ms và dừng sớm khi cờ stop bật (server truyền cờ của `Server::run`, dừng dịch vụ không treo); yêu cầu lớn bị chia miếng <= max(rate/4, 4 KiB) nên nợ token tối đa ~0,25 s mỗi lần, một phiên không làm trễ phiên khác qua bucket tổng quá một miếng. `max_bandwidth_kbps` dương < 64 được nâng lên 64 kèm cảnh báo WARN (server, `[[client]]`, client); 0 vẫn là không giới hạn. Test: `rate_limiter_stop_cuts_sleep_short`, `rate_limiter_big_request_does_not_starve_a_small_one`, `config_bandwidth_floor_raises_tiny_caps`.
- **L6** (`LocalTarget`): tệp tạm `.mysync-tmp-*` giờ được dọn bằng RAII ở mọi đường thoát (nguồn không mở được, ghi lỗi, ngoại lệ). Test `local_unreadable_source_leaves_no_temp_file` khoá nguồn bằng `CreateFileW` không chia sẻ nên **chỉ chạy trên Windows**; trên POSIX chạy bằng root không tạo được nguồn không đọc được nên chưa có test tương đương (lỗi đó chỉ gặp trên POSIX vì tệp tạm được tạo sẵn 0600).
- **M2 — ĐÁNH ĐỔI CÓ CHỦ Ý, giữ nguyên theo quyết định người dùng**: hạn mức chưa xác thực nhỏ — tổng mặc định `max(8, max_connections/2)`, 4 mỗi IP. Đổi lại, một nguồn chiếm đủ chỗ chưa xác thực có thể làm máy khách hợp lệ khác bị từ chối tạm thời trong lúc bắt tay; không đổi.

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
- Rà soát độc lập đợt M1/M3/L6: không còn High/Critical. Còn (chấp nhận): HELLO chậm giữ thẻ chưa-xác-thực tối đa 5 s (hệ quả của M1, M2 giữ nguyên), client chưa truyền cờ stop vào RateLimiter (dừng client có thể trễ ≤ ~0,5 s), `read_hello` còn tạo thư mục/nạp cây trước khi HELLO hợp lệ, `examples/mysync.service` thiếu vài dòng hardening mà `service install` sinh ra.
