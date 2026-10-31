# Lớp lõi cho GUI (kênh điều khiển cục bộ)

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

Lớp này không phụ thuộc wxWidgets. Header ở `include/mysync/gui/`, cài đặt ở `src/gui_*.cpp`, đều nằm trong `mysync_core`.

| Header | Việc |
|---|---|
| `control_protocol.h` | thông điệp nhị phân (PING, GET_STATUS, RELOAD_CONFIG, GET_RECENT_ERRORS), khung 64 KiB |
| `ipc.h` | `IpcServer` (trong daemon), `ControlClient` (trong GUI); Windows named pipe, Linux unix socket |
| `status.h` | `StatusSnapshot`, `TargetStatus`, `PeerStatus`, `ReloadResult`, `RateMeter` |
| `daemon.h` | `ClientDaemon` / `ServerDaemon` (dùng trong `mysync run`): máy chủ IPC + nạp lại cấu hình nóng |
| `config_io.h` | `ConfigEditor`: đọc, sửa, ghi cấu hình TOML an toàn |
| `service_ctl.h` | `ServiceController`: trạng thái và cài/gỡ/chạy/dừng dịch vụ, tự nâng quyền |
| `key_mgr.h` | `KeyManager`: tạo khoá, vân tay, danh sách `[[client]]` |

## Kênh điều khiển

Không bao giờ mở cổng TCP. Tên điểm cuối: `[control] name`, nếu trống thì tên dịch vụ (`--name`), nếu trống nữa thì `mysync-server` / `mysync-client`.

**Windows** — `\\.\pipe\mysync-<tên>`:
- `FILE_FLAG_FIRST_PIPE_INSTANCE` ở thể hiện đầu: kẻ khác không chiếm trước được tên (tạo thất bại, daemon báo lỗi rõ).
- `PIPE_REJECT_REMOTE_CLIENTS`, thêm ACE từ chối đăng nhập mạng (`NU`).
- DACL bảo vệ (`D:P`, không kế thừa): SYSTEM và Administrators toàn quyền; tài khoản đang chạy daemon và từng SID / `DOMAIN\user` trong `[control] allow` được đọc-ghi. **Từ chối** Everyone, Users, Authenticated Users, Anonymous, Guests, Interactive, Network, Local (đưa vào `allow` thì `IpcServer::start` ném lỗi; daemon ghi log "control channel unavailable" và CHẠY TIẾP KHÔNG CÓ kênh điều khiển, không dừng đồng bộ). Lưu ý: người dùng thường chưa nằm trong `allow` sẽ bị hệ điều hành từ chối ngay khi mở pipe.
- Máy khách mở pipe với `SECURITY_IDENTIFICATION`: chủ pipe biết ta là ai nhưng không mạo danh được ta.
- Nhóm worker cố định `max_connections` (mặc định 4): hết chỗ thì máy khách nhận `ERROR_PIPE_BUSY` và chờ.

**Linux** — `/run/mysync/<tên>.sock` (root; hoặc `$RUNTIME_DIRECTORY` khi systemd cấp `RuntimeDirectory=mysync`), `$XDG_RUNTIME_DIR/mysync/<tên>.sock` (không phải root):
- thư mục 0750, socket 0660 (khi có `[control] group`) hoặc 0600; thư mục phải thuộc chính daemon hoặc root và không ghi được bởi nhóm+người khác; symlink ở thư mục hay ở đường dẫn socket bị từ chối; socket cũ không ai nghe thì xoá, socket đang sống thì từ chối chiếm.
- mỗi kết nối: `SO_PEERCRED` — chấp nhận uid root, uid của daemon, hoặc thành viên nhóm `group`. Máy khách (GUI) chỉ tin socket có chủ là root hoặc chính tiến trình đứng sau socket.
- vượt `max_connections` thì đóng ngay.

Chung: thông điệp > 64 KiB bị từ chối **trước khi đọc**, đối tác đứng im quá `read_timeout_ms` (5 s) bị ngắt, giải mã chặt (cắt cụt, thừa byte, op lạ, đếm vô lý đều là lỗi). Kênh **không bao giờ** mang khoá bí mật (cả hai chiều); trạng thái chỉ có tên, số liệu, tên tệp tương đối (tối đa 20 mỗi đích) và lỗi nguyên văn.

## Nạp lại cấu hình (RELOAD_CONFIG)

Tệp được đọc và kiểm hợp lệ trước; sai thì giữ cấu hình đang chạy và trả nguyên văn lỗi (có số dòng).
- **Client**: dựng thử engine mới (đọc khoá, kiểm có watch+đích) khi engine cũ còn chạy; đạt thì dừng engine cũ (lưu chỉ mục), khởi engine mới trên cùng `state_dir` nên chỉ mục được giữ.
- **Server**: `Server::apply_config` hoán đổi danh sách khách, allow/deny, hạn mức, băng thông, trash, quyền tệp, ngưỡng chống dò khoá cho **phiên mới**. Phiên đang mở giữ chính sách cũ nhưng bị cắt ở yêu cầu kế tiếp nếu khách bị xoá khỏi danh sách hoặc đổi `access`/`prefix`. Đổi `bind`/`port`/`root`/`key_file`/`state_dir` bị từ chối: "needs a restart".
- `[control]` đổi thì chỉ có hiệu lực sau khi khởi động lại; kết quả liệt kê trong `needs_restart`.

## ConfigEditor

Ghi: dựng TOML chuẩn (đủ trường, chú thích tiêu đề) → phân tích lại bằng `parse_*_config_text` → so băm nội dung tệp (tệp đổi từ lúc đọc thì từ chối, trừ `force`) → chép bản trước sang `<tệp>.bak` (chú thích viết tay mất khỏi tệp mới, còn trong `.bak`) → ghi `<tệp>.tmp-<ngẫu nhiên>` cùng thư mục, giữ quyền (POSIX mode/owner; Windows DACL), fsync, đổi tên nguyên tử. Kiểm băm lần hai ngay trước khi đổi tên. Không bao giờ đọc nội dung khoá bí mật.

## Nâng quyền dịch vụ

`ServiceController::run` luôn gọi lại `mysync service <hành động> ...` (cùng đường mã với dòng lệnh):
- Windows chưa nâng quyền: `ShellExecuteExW` verb `runas` (hộp UAC), ẩn cửa sổ, chờ tiến trình con, đọc **mã thoát**; đã nâng quyền: `CreateProcess` với ống ẩn danh để lấy nguyên văn lỗi.
- Linux không phải root: `pkexec <mysync> service ...`, lấy stdout+stderr qua pipe; root thì chạy trực tiếp. `pkexec` trả 126/127 (huỷ hoặc từ chối) → `cancelled`.
- Mã thoát có tên (`ServiceExit`): 20 tham số sai, 21 từ chối quyền, 22 chưa cài, 23 đã cài, 24 quá hạn, 25 lỗi cấu hình, 126 huỷ. Sau đó truy vấn lại trạng thái thật. Không tệp tạm, không tên pipe nào mà tiến trình quyền thấp có thể cài sẵn.
- Không qua shell: tên dịch vụ `[A-Za-z0-9_.-]`, đường dẫn tuyệt đối và tồn tại, vai trò/tài khoản/SID qua danh sách ký tự cho phép, trên Windows trích dẫn kiểu `CommandLineToArgvW`. Chỉ nâng quyền cho tệp tên `mysync[.exe]`, trên POSIX tệp đó không được ghi bởi nhóm/người khác.
- `mysync service install --control-allow <SID|DOMAIN\user>` (lặp được) ghi vào `[control] allow` của cấu hình trước khi cài (dùng `ConfigEditor`, nên tạo `.bak`).

## Rà soát độc lập: các ràng buộc bổ sung

**Người được ghi cấu hình (`--trust-writer`, và `--control-allow` lúc cài) tương đương đặc quyền của dịch vụ**: họ sửa được cấu hình rồi bấm nạp lại. Chỉ thêm người bạn tin như vậy. `[control] allow` trong tệp chỉ cho phép dùng kênh điều khiển.

- **Tin cậy cấu hình (`gui/trust.h`) — DANH SÁCH TRẮNG**: tại `service install`, khi daemon khởi động (dịch vụ hoặc tiến trình đã nâng quyền) và ở mỗi RELOAD, tệp cấu hình và thư mục cha (cùng `state_dir`, thư mục của `log_file`) chỉ được thay đổi bởi tập T: tài khoản chạy daemon, SYSTEM/root, Administrators (Windows thêm TrustedInstaller) và các mục `--trust-writer` do quản trị đặt lúc cài (nằm trong đối số lệnh của dịch vụ; `service install --control-allow X` cũng thêm X vào đây). **Tệp đang kiểm không bao giờ mở rộng T**, `[control] allow/group` cũng không: chúng chỉ quyết định ai dùng được pipe/socket. Windows: mọi ACE cho phép ghi/xoá/đổi DACL/đổi chủ (kể cả GENERIC_WRITE/ALL) phải thuộc T, chủ sở hữu phải thuộc T, ACE điều kiện/đối tượng bị từ chối. Hệ quả có chủ đích: tệp trong thư mục hồ sơ người dùng thường bị từ chối khi dịch vụ chạy bằng tài khoản khác, hãy đặt cấu hình ở nơi chỉ quản trị ghi được. POSIX: chủ là root, uid daemon hoặc uid/nhóm trong `--trust-writer` (`uid:N`, `gid:N`, tên người dùng, `@nhóm`), không có bit ghi cho "other", bit ghi cho "group" chỉ khi nhóm của tệp thuộc T, symlink bị từ chối, thư mục sticky kiểu `/tmp` được chấp nhận; nhờ vậy tệp do GUI (người dùng thường) lưu vẫn dùng được nếu quản trị đã đặt người đó vào `--trust-writer`. Chưa kiểm các thư mục tổ tiên. Vi phạm: khởi động thì dừng với thông báo nguyên văn, reload thì giữ cấu hình cũ.
- **Tệp nâng quyền**: trước khi nâng quyền, `mysync` và thư mục cha phải do quản trị sở hữu. Windows: chỉ Administrators/SYSTEM/TrustedInstaller được ghi (nên cài vào Program Files); trong lúc chạy, giữ một handle chỉ-đọc chia sẻ-đọc-không-ghi để tệp không bị thay giữa lúc kiểm và lúc chạy (giới hạn: không chặn quản trị đổi tên thư mục). POSIX: đường dẫn thật trùng đường dẫn đưa vào (không symlink), tệp và mọi thư mục cha thuộc root, không ghi được bởi group/other. Không đạt thì không nâng quyền, báo cách khắc phục.
- **Đường dẫn tuyệt đối**: `/usr/bin/pkexec`, `/usr/bin/systemctl` (hoặc `/bin/systemctl`), gọi bằng `execv`, không tra PATH (cả trong `service.cpp`).
- **Pipe Windows**: principal trong `allow` nhận quyền `0x12019b` (đọc/ghi, không `FILE_APPEND_DATA` = tạo thể hiện pipe); tài khoản chạy daemon giữ quyền đủ vì tự tạo các thể hiện. Máy khách gọi `GetNamedPipeServerProcessId`; không kiểm được tiến trình (bị từ chối `OpenProcess`) thì kiểm chủ sở hữu của chính pipe, không kiểm được nữa thì ĐÓNG (không bao giờ "tin vì không kiểm được"). Chỉ tin tiến trình/chủ pipe thuộc SYSTEM, LocalService, NetworkService, thành viên Administrators, chính người dùng hiện tại, hoặc tài khoản thêm qua `ControlClient::trust_server_account`.
- **RELOAD**: cấu hình không đổi (về phía engine) thì không làm gì; hai lần nạp thật cách nhau tối thiểu `reload_min_interval_ms` (2 s), tối đa 3 yêu cầu reload mỗi kết nối. Client: kiểm engine mới khi engine cũ còn chạy, rồi dừng cũ, khởi mới; nếu engine mới chết ngay (trong ~1,5 s) thì khôi phục cấu hình cũ và báo đúng sự thật.
- **Kết nối IPC**: nhàn rỗi tối đa 60 s, tổng thời gian sống tối đa 10 phút, tối đa 1000 yêu cầu mỗi kết nối. Unix socket tạo dưới `umask(0177)`; thư mục điều khiển không được ghi bởi group/other và đường dẫn không đi qua symlink (kể cả `RUNTIME_DIRECTORY`).
- **`service install --control-allow`**: kiểm cú pháp ở CLI; cấu hình chỉ được ghi SAU khi cài dịch vụ thành công, ghi lỗi thì gỡ dịch vụ vừa cài.
- **Quyền riêng tư của trạng thái**: mọi principal được phép điều khiển có thể thấy IP (trong log gần đây), tên máy khách, đường dẫn tương đối và đường dẫn cấu hình. Chưa ẩn theo từng người; chỉ cấp `allow` cho người được phép biết các thông tin đó.

## Hàm dùng chung trong `gui/trust.h` (vòng sửa M-B, M-D, M-E)

Mỗi quy tắc chỉ có MỘT cài đặt, được CLI (`main.cpp`), daemon và `ServiceController` cùng gọi:
- `need_strict_trust(elevated, service)` (= `elevated || service`): khi nào kiểm chặt. Tiến trình đang chạy với quyền cao (Windows: token đã nâng quyền hoặc SYSTEM/dịch vụ; Linux: euid 0) hoặc có `--service` thì kiểm; tài khoản thường chạy tệp của chính mình thì **không bị chặn**. Dùng cho `ClientDaemon`/`ServerDaemon` và cho `mysync run --once` (trước đây nhánh `--once` tạo `SyncEngine` thẳng và bỏ qua kiểm: tác vụ lên lịch chạy SYSTEM/root với cấu hình người dùng ghi được).
- `require_trusted_run(config, state_dir, log_file, trust_writers)`: cấu hình + thư mục cha + `state_dir` + thư mục của `log_file`. Daemon (khi khởi động và mỗi RELOAD) và `run --once` gọi cùng hàm này.
- `broad_principal_reason(entry)`: `""` hoặc lý do. `service install` từ chối `--trust-writer`/`--control-allow` trỏ tới nhóm rộng, ở cả CLI (qua `validate_install_inputs`) lẫn GUI (`ServiceController::build_args`). Windows: phân giải tên → SID rồi so SID (Everyone, Authenticated Users, BUILTIN\Users, Guests, Power Users, Pre-Windows 2000 Compatible Access, INTERACTIVE, Network, Anonymous, Local, Console logon, Local account, Domain Users/Guests/Computers theo RID 513/514/515 của mọi miền); ngoài ra so cả tên viết dạng quen thuộc để bắt tên không phân giải được ở máy này. Linux: nhóm `users`/gid 100, `other(s)`, `*`, `everyone`. Danh sách SID nằm ở `detail::is_broad_sid`, **cùng một danh sách** với bộ dựng DACL của pipe điều khiển (`ipc_pipe_sddl`). Thông báo: "đây là nhóm rộng: cấp quyền ghi cấu hình dịch vụ cho nhóm này = cho mọi người dùng cục bộ leo thang lên đặc quyền dịch vụ" (bản tiếng Anh trong mã).
- `validate_install_inputs(exe, config, trust_writers, control_allow, run_as)`: `""` hoặc lý do. Kiểm (1) chính tệp `mysync` (`untrusted_executable_reason`), (2) không có nhóm rộng, (3) tệp cấu hình theo cách **dịch vụ** sẽ nhìn: tập tin cậy = built-in + các mục nêu tên + tài khoản `--user`; người quản trị đang cài **không** tự động được tin (`include_self=false`), nên cấu hình của quản trị nằm trong hồ sơ cá nhân mà dịch vụ chạy bằng tài khoản khác sẽ bị từ chối ngay lúc cài thay vì lúc dịch vụ khởi động. `mysync service install` (CLI) và `ServiceController::run` (trước hộp UAC/pkexec) đều gọi hàm này; kết quả từ chối ra mã thoát `kServiceConfigError` (25).

## Vòng rà soát 3

- Phản hồi không khớp token bị từ chối (trừ câu "không giải mã được" token 0 của daemon), phản hồi Ok sai thao tác cũng vậy; phản hồi quá lớn không bao giờ làm kết nối cụt: peer nhận trạng thái Failed.
- RELOAD: đổi nội dung tệp khoá (kích thước/thời gian sửa) được coi là thay đổi: client khởi lại engine, server báo cần khởi động lại. Đồng hồ giãn cách chỉ chạy SAU khi cấu hình mới qua kiểm. Sửa kẹt giữa `reload_mu` và dừng kênh điều khiển khi engine chết lúc đang có reload.
- GUI nên đặt thời gian chờ reload >= 15 s (`tab_config.cpp` dùng 20 s) và gọi `ControlClient::trust_server_account` cho dịch vụ chạy bằng `--user` riêng.

## Lõi chế độ Đơn giản (`include/mysync/simple/`, `engine_lock.h`)

Không phụ thuộc wx; cài đặt ở `src/simple_*.cpp` và `src/engine_lock.cpp`, đều trong `mysync_core`. Thiết kế bảo mật của việc ghép máy: xem `docs/DESIGN.md`, mục "Ghép máy bằng mã" và "Chế độ Đơn giản".

| Header | Việc |
|---|---|
| `user_paths.h` | `UserPaths` (cấu hình, khoá, state, log của người dùng; tên kênh điều khiển `mysync-user-<id>` / `...-recv`), `ensure_dirs`, `restrict_to_current_user`, `current_user_sid` |
| `pair_code.h` | mã ghép `MSY1-...` (`encode_pair_code` / `decode_pair_code`), SAS `pair_sas`, Crockford base32 |
| `pairing.h` | `PairingManager` (bên nhận: chế độ ghép, hàng chờ, giới hạn), `PairingClient` (bên gửi), thông điệp ghép, `clean_display_name`, `safe_pair_prefix` |
| `user_engine.h` | `Supervisor` (engine con, khởi động lại có giãn cách, báo lỗi), `InstanceLock`, `find_engine_exe` |
| `autostart.h` | tự chạy khi đăng nhập: `HKCU\...\Run` / `~/.config/autostart/mysync.desktop` |
| `wizard_model.h` | lựa chọn đời thường → `ClientConfig` an toàn (`validate_wizard`, `build_client_config`, `save_wizard`), cấu hình máy nhận (`ensure_receiver_config`), `ensure_user_key` |
| `service_upgrade.h` | "chạy cả khi chưa đăng nhập": `upgrade_to_service` / `downgrade_to_user` (có hoàn tác), `run_migrate_from_user`, `service_locations` |
| `engine_lock.h` | `FileLock` + `<thư mục>/__sync/engine.lock`: khoá hệ điều hành chống hai engine cùng watch một thư mục |

### Thêm vào kênh điều khiển

- `ControlOp` 5..9: `PairModeOn` (arg = số giây, tối đa 600), `PairModeOff`, `PairList` (đồng thời là "lấy mã": trả khoá công khai + cổng + hàng chờ), `PairApprove` / `PairDeny` (arg = id). Phản hồi mang `PairInfo` (khoá CÔNG KHAI, không bao giờ khoá bí mật). Daemon không bật `--allow-pairing` (hoặc cấu hình `pairing = "off"`) trả `Unsupported`.
- `ControlClient::pair_info / pair_mode / pair_approve / pair_deny`.
- `IpcServerOptions::user_only` (`mysync run --user-mode`): pipe Windows chỉ cho người dùng hiện tại (không SYSTEM, không Administrators); Linux thư mục 0700, socket 0600; không kèm `allow`.
- `ServiceAction::MigrateFromUser` + `ServiceRequest::user_config`: chạy `mysync service migrate-from-user --user-config <tệp> --name <tên>` nâng quyền.

### Dòng lệnh mới

`mysync run ... --user-mode` (kênh điều khiển chỉ người dùng) · `--exit-on-stdin-eof` (dừng sạch khi tiến trình cha đóng stdin hoặc chết) · `--allow-pairing` (bên nhận) · `mysync service migrate-from-user --user-config <tệp> [--name N]` (nâng quyền, mã thoát theo `ServiceExit`).

### Sửa ba lỗi Medium của vòng rà soát 4 (F1, F2, F3)

- **F1** `state_dir` trống: engine dùng thư mục mặc định (client `<thư mục cấu hình>/state`, server `<root>/__sync/__meta`) mà trước đây không được kiểm. `effective_client_state_dir` / `effective_server_state_dir` (`gui/trust.h`) cho đúng thư mục đó; `require_trusted_run` của daemon và của `mysync run` nhận chính nó.
- **F2** trong `mysync run`, khi `need_strict_trust` (quyền cao hoặc `--service`), kiểm tin cậy chạy ngay sau `load_config` và TRƯỚC `setup_log` (không tạo thư mục log, không mở log từ cấu hình chưa tin); `--trust-writer` được kiểm cú pháp và `broad_principal_reason` ngay (lỗi cú pháp, mã 2). Kiểm của nhánh `--once` được gộp vào chỗ này.
- **F3** (Linux) `gid:N` / `uid:N` được phân tích chặt bằng MỘT hàm (`detail::parse_numeric_id`: chỉ chữ số, không `+`/khoảng trắng/số 0 đầu, ≤ 4294967295) cho cả `parse_trusted` lẫn `broad_principal_reason`, rồi so SỐ; `gid:` 100, 50, 65534 (users, staff, nogroup) và uid 65534 bị coi là nhóm rộng, `nogroup`/`nobody`/`staff` cũng vậy (tên và `@nhóm`); giá trị không phân tích được bị từ chối thẳng. Windows: thêm SID rộng S-1-5-13, S-1-5-32-555, S-1-5-3, S-1-5-6. `broad_principal_reason` còn áp cho `--user` (qua `validate_install_inputs`) và cho `run --trust-writer`.

## Đợt 7 (chế độ Đơn giản)
Xem `docs/DESIGN.md`, mục "Đợt 7": danh sách cho phép đường dẫn khi chuyển sang dịch vụ (`--allow-root`), băm đã duyệt (`--expect-hash`), duyệt ghép nguyên tử, và **vì sao không kiểm tiến trình cha của `pkexec`** (`pkexec` exec thẳng chương trình đích; `PKEXEC_UID` chỉ được tin trong tiến trình root, có kiểm chéo — xem `resolve_invoking_uid`).

## Đợt 7b: dịch vụ chạy bằng tài khoản người dùng
API: `include/mysync/simple/service_account.h` (`SecretString`, `ServiceCredential`, `PasswordChannel`, `receive_password`, `check_service_account`, `grant_service_logon_right`, `user_service_name`), `service_upgrade.h` (`user_service_locations`, `make_real_upgrade_steps(..., account, password)`), `gui/service_ctl.h` (`ServiceRequest::password`, `user_service`, `ServiceAction::SetPassword`, `ServiceState::needs_password_update`), `linkcheck.h`. Mô hình tin cậy, kênh mật khẩu, hai kiểu cài dịch vụ và giới hạn: `docs/DESIGN.md`, mục "Đợt 7b". Dòng lệnh mới: `mysync service install ... --user-service --password-pipe <tên> --password-nonce <hex>`, `mysync service set-password --name N --user ACCT --password-pipe .. --password-nonce ..`, `mysync service migrate-from-user ... --account ACCT`.

## Đợt 7c
Xem `docs/DESIGN.md`, mục "Đợt 7c". API mới: `ServiceAction::ApplyConfig` (`mysync service apply-config`), `ServiceState::description`, `service_dir_sddl` / `create_service_dir` (Windows) / `install_service_files` (Linux, root), `service_config_path_problem` + `DaemonOptions::config_check` (`mysync run --enforce-paths --allow-root`), `user_service_name(account, owner_id)`, `owner_label`, `current_owner_id`, `account_is_administrator`, `PasswordAttemptLimiter`, `revoke_service_logon_right`, `service_runs_program`, `link_component` (cờ doubt-refuses).

## Đợt 7d
Xem `docs/DESIGN.md`, mục "Đợt 7d". API mới: `MigrationSummary::account_is_admin`, `data_dir_kind_for_account`, `user_service_name_matches_owner`, `min_login_uid`, `LogonRightGuard`, `PasswordFlow::submit(account, has_password, now_ms)` (giới hạn 5 lần sai / 30 giây, bộ đếm sống qua `begin()`), `DaemonOptions::exclude_self_from_trust` + `state_writers`, `mysync run --state-writer <SID>`, `require_trusted_dir/require_trusted_run(..., include_self)`; khoá chuỗi mới `simple.svc.sum.warn_admin`, `simple.pwd.locked`. `service_config_path_problem` giờ kiểm cả `state_dir` / `log_file` / `key_file` (phải nằm trong thư mục dịch vụ).

## Đợt 7e
Xem `docs/DESIGN.md`, mục "Đợt 7e". API mới: `admin_account_refusal(bool)`, `account_name_from_sid`, `service_description`; `MigrationSummary::account_is_admin` nay làm `summarize_user_config` trả lời từ chối đầu tiên trong `problems`. GUI: nút chuyển sang dịch vụ bị khoá (kèm tooltip `simple.svc.admin_refused`) với tài khoản quản trị Windows; quay về chế độ cá nhân luôn được. Giới hạn: chưa có engine chạy bằng restricted token.

## Đợt 7f
Xem `docs/DESIGN.md`, mục "Đợt 7f". API: `AdminState`, `TokenFacts`, `admin_state_from_facts`, `account_admin_state`, `AdminProbe`, `admin_refusal_for`, `service_account_refusal`, `service_start_refusal`, `looks_like_user_service_name`, `AccountCheck::admin`; `summarize_user_config(paths, roots, probe)` và `run_migrate_from_user(args, probe)` nhận hàm tra cứu (test tiêm vào); `set_admin_probe_override_for_tests` đã bỏ. Khoá chuỗi mới: `simple.svc.win_unsupported`. Trên Windows nút chuyển sang dịch vụ bị khoá cho tới đợt 8.

## Đợt 8
Xem `docs/DESIGN.md`, mục "Đợt 8". API mới: `include/mysync/simple/restricted.h` (`TokenReport`, `is_dangerous_group_sid`, `restricted_token_problem`, `describe_token`, `frame_refusal_text`; trên Windows `read_token_report`, `make_restricted_token`, `RestrictedChild`, `FrameParams`, `run_frame`), `valid_user_sid` / `set_requester_sid` / `effective_user_sid` (`user_paths.h`), `requester_identity_problem`, `PasswordChannel::expect_client_pid`, `receive_password(..., requester_sid)`, `ServiceRequest::requester_sid` (`--requester-sid`), `ServiceSpecificError` (service.h), `DaemonOptions::frame_note` (`--frame-note`). Đã bỏ: `admin_account_refusal`, `service_account_refusal`, `service_start_refusal`, `AdminProbe` trong `run_migrate_from_user`. GUI: nút chuyển sang dịch vụ mở lại trên Windows cho mọi tài khoản; hộp xác nhận có dòng `simple.svc.sum.runas`; băng đỏ `simple.svc.frame` khi khung từ chối; một dòng "service token: ..." dưới trạng thái.

Đợt 8, vòng 2: `network_token_problem`, `is_strong_privilege`, `describe_own_token`, `release_logon_right(dir, sid, describe)` (thay `record_logon_right_use`), `simple.svc.note.netidentity`. Xem DESIGN.md.
