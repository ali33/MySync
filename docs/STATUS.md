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

## Giao diện đồ hoạ `mysync-gui` (wxWidgets 3.2)
Đã kiểm (đo thật):
- Windows (MinGW g++ 15, Release): `mysync_tests` **276 passed, 0 failed** (có test IPC, giao thức điều khiển, ConfigEditor, ServiceController, KeyManager, kiểm tin cậy tệp cấu hình, tích hợp mô hình ↔ daemon không cần màn hình, viewmodel GUI). `mysync-gui.exe` dựng được với `-DMYSYNC_BUILD_GUI=ON` (wxWidgets 3.2.9 tải bằng FetchContent, ghim SHA-256).
- Linux (Docker `gcc:14` + GTK 3.24 + `libwxgtk3.2-dev` của Debian, chạy bằng root): dựng `mysync-gui` thành công và `ctest` "100% tests passed, 0 tests failed out of 2" (khoảng 65 s); `mysync_tests` **278 passed, 0 failed** (kèm các nhánh chỉ chạy được bằng root/POSIX), dựng không cảnh báo.
- Windows: GUI chạy tay và chụp ảnh trên Windows 11 (do agent giao diện báo, tôi không tự kiểm lại bằng mắt).
Chưa kiểm:
- **Chạy giao diện thật trên Linux** (chỉ dựng được), khay hệ thống phụ thuộc môi trường desktop.
- **Nâng quyền thật** (UAC, pkexec) và cài dịch vụ thật chưa chạy; pipe/socket kiểm bằng test trong tiến trình, chưa thử đa tài khoản thật.
- Lớp wx không có test tự động (chỉ lớp `*_model`).
Rà soát bảo mật độc lập 3 vòng (agent chỉ đọc). Vòng 1 thấy 1 High (dịch vụ nâng quyền tin cấu hình người dùng thường ghi được) + Medium; vòng 2 thấy High còn lại ở Windows (danh sách đen); vòng 3: **không còn Critical/High**. Medium (M-B, M-D, M-E đã sửa; M-A và M-C HOÃN):
- M-A: chủ sở hữu tệp/thư mục là thành viên của nhóm tin cậy vẫn bị từ chối (chỉ chấp nhận tài khoản cá nhân liệt kê trong `--trust-writer`); đóng an toàn nhưng gãy luồng "GUI người dùng thường lưu rồi reload" nếu liệt kê theo nhóm. **HOÃN** theo quyết định người dùng (giữ đóng an toàn).
- ~~M-B~~ **ĐÃ SỬA**: `mysync run --once` giờ gọi `require_trusted_run` (cùng hàm với daemon) khi `need_strict_trust(elevated, --service)`, tức khi chạy với quyền cao (Windows: token nâng quyền/SYSTEM; Linux: euid 0) hoặc có `--service`; tài khoản thường chạy tệp của chính mình vẫn chạy được. Test: `gui_trust_need_strict_trust_policy`, `gui_trust_run_check_refuses_files_others_can_write_and_passes_private_ones`. Chưa có test chạy cả `mysync run --once` bằng tiến trình thật.
- M-C: cấu hình chưa tin cậy đã được phân tích và có tác dụng phụ (tạo thư mục, mở log) trước khi bị từ chối. **HOÃN** theo quyết định người dùng.
- ~~M-D~~ **ĐÃ SỬA**: `broad_principal_reason` (gui_trust.cpp) từ chối nhóm rộng ở `service install`, cả CLI lẫn GUI (`build_args`); Windows so theo SID sau khi phân giải tên, Linux chặn `users`/gid 100/`other(s)`/`*`; danh sách SID dùng chung với DACL pipe (`detail::is_broad_sid`). Test: `gui_trust_broad_sids_and_names_are_recognised`, `gui_service_build_args_refuses_broad_principals`; test cũ chấp nhận Everyone đã đổi sang SID cá nhân.
- ~~M-E~~ **ĐÃ SỬA**: `validate_install_inputs` (một hàm) kiểm tệp `mysync`, nhóm rộng và tin cậy cấu hình, được `cmd_service` (CLI) và `ServiceController::run` cùng gọi; cấu hình được xét theo cách dịch vụ nhìn (`include_self=false`, thêm tài khoản `--user`; xử lý L-1). Test: `gui_trust_validate_install_inputs_rejects_untrusted_inputs` (không cài dịch vụ thật).
- Low: kiểm chỉ tới thư mục cha (không tổ tiên), thư mục sticky được dung thứ ở `state_dir`, tin cậy theo tên phân giải lại mỗi lần, mặc định `C:\ProgramData\<tên>` bị từ chối do ACL kế thừa (cần khoá ACL).
Bất biến thực sự được cưỡng chế: tệp cấu hình của dịch vụ chỉ được ghi bởi {tài khoản dịch vụ, SYSTEM/root, Administrators} và các principal admin liệt kê lúc `service install --trust-writer`/`--control-allow`; danh sách control allow tương đương quyền ghi cấu hình, tức đặc quyền của dịch vụ.
- Rà soát độc lập đợt M-B/M-D/M-E (vòng 4): không còn Critical/High; 3 Medium mới, chưa sửa (sẽ làm đầu đợt kế tiếp): F1 thư mục `state` mặc định (khi `state_dir` trống) không được kiểm tin cậy; F2 `setup_log`/`load_config` chạy trước kiểm tin cậy trong `run` (liên quan M-C); F3 (Linux) `--trust-writer gid:0100`/`gid:+100`/`gid:4294967396` lách được kiểm `gid:100` do so sánh chuỗi. Low: kiểm nhóm rộng chỉ ở lúc cài chứ không ở `run --trust-writer`; danh sách SID rộng chưa đủ (S-1-5-13, -555, -3, -6…); `--user` chưa qua `broad_principal_reason`.
- Số test sau đợt này: Windows 276 passed, 0 failed; Linux Docker (gcc:14 + GTK, root) ctest 100% (2/2).
