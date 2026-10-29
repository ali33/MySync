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

## Vòng rà soát 3

- Phản hồi không khớp token bị từ chối (trừ câu "không giải mã được" token 0 của daemon), phản hồi Ok sai thao tác cũng vậy; phản hồi quá lớn không bao giờ làm kết nối cụt: peer nhận trạng thái Failed.
- RELOAD: đổi nội dung tệp khoá (kích thước/thời gian sửa) được coi là thay đổi: client khởi lại engine, server báo cần khởi động lại. Đồng hồ giãn cách chỉ chạy SAU khi cấu hình mới qua kiểm. Sửa kẹt giữa `reload_mu` và dừng kênh điều khiển khi engine chết lúc đang có reload.
- GUI nên đặt thời gian chờ reload >= 15 s (`tab_config.cpp` dùng 20 s) và gọi `ControlClient::trust_server_account` cho dịch vụ chạy bằng `--user` riêng.
