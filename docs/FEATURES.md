# Bảng đối chiếu tính năng: MySync C# (trunk) -> MySync C++

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.
"Theo quyết định người dùng" = quyết định do người dùng đưa ra trong quá trình thực hiện.

| Tính năng cũ (tệp C#) | Quyết định | Cách làm mới / lý do |
|---|---|---|
| Watch thời gian thực (FileWatcher.cs, FileSystemWatcher + MemoryCache chờ) | Giữ, làm lại | `watcher.h`: ReadDirectoryChangesW (Windows), inotify (Linux). Debounce theo từng tệp (`quiet_ms` = `timeActionAfterChanged` cũ), chờ tệp hết bị khoá (thay IsFileLocked), gộp lô, xử lý tràn bộ đệm bằng quét lại, quét định kỳ dự phòng (`periodic_scan_s`). |
| Đẩy tệp tới nhiều server (`syncAddress`, SyncFileProvider/SyncFileWorker) | Giữ | `[[watch.target]]` nhiều đích; song song `connections` kết nối/đích, pipeline OFFER theo lô. |
| Đồng bộ xoá và đổi tên (OnDeleted/OnRenamed, _DELETE_, _MOVE_) | Giữ | Thông điệp DELETE/RENAME/MKDIR; `propagate_delete`. Bên nhận chuyển vào `__sync/__trash` (như `TRASH_DIR` cũ) thay vì xoá thật (`trash=true`). |
| Bỏ qua tệp trùng (_EXIST_/_M_EXIST_ kiểm tồn tại) | Đổi, mạnh hơn | Cũ chỉ kiểm tồn tại/kích thước. Mới: so size+mtime, rồi hash BLAKE3 nội dung; trùng nội dung thì không gửi dữ liệu (SKIP). Bộ nhớ đệm chỉ mục (`index.h`) để không băm lại tệp không đổi. |
| Truyền tệp nén LZ4 (_FILE_LZ_) | Giữ | `compress = "lz4"`, nén từng khối, tự bỏ nén nếu không giảm. |
| Truyền nhiều tệp (_M_FILE_) | Giữ, làm lại | Pipeline nhiều OFFER chưa chờ phản hồi + nhiều kết nối song song. |
| Delta theo khối | Mới | rsync-style (rolling checksum + BLAKE3 16B) cho tệp lớn đã có bản cũ ở đích. |
| Giao thức client/server (FTClient/FTServer/ServerWorker, TcpData, FileSend*) | Đổi — không tương thích ngược, theo quyết định người dùng | Giao thức nhị phân mới trong kênh mã hoá (xem DESIGN.md). |
| Mã hoá XOR + securityCode (Security/XorCryptographer.cs) | Đổi (bắt buộc) | Handshake X25519 + PSK 32 byte, XChaCha20-Poly1305, xác thực hai chiều, bộ đếm chống phát lại (Monocypher). `securityCode` ("12345") được thay bằng khoá 256-bit. |
| Danh sách IP cho phép/cấm (`allowIp`/`denyIP`) | Giữ | `allow`/`deny` hỗ trợ IP và CIDR, deny thắng. |
| `maxConnections`, `bindIpAddress`, `serverPort`, `path` (mirror) | Giữ | `[server] max_connections, bind, port, root`. |
| `useTempFiles` | Đổi | Luôn ghi tệp tạm rồi rename nguyên tử + kiểm hash (không còn là tuỳ chọn). |
| Bộ lọc `filter`, `excluded`, regex (update 2019-03-29/30), `fileSize`, `fileTime`, bỏ tệp tạm `~ $ # .tmp` | Giữ, đổi ngữ nghĩa regex | `[watch.filter]`. Regex nay áp lên đường dẫn TƯƠNG ĐỐI (cũ: full path nên dễ cấu hình sai). |
| `includeSubdirectories`, `notifyFilter` | Giữ / bỏ | `recursive` giữ; `notifyFilter` bỏ (API gốc luôn nghe đủ loại thay đổi cần thiết). |
| `startSync`, `syncDelay`, `enabled` | Giữ | `start_sync`, `sync_delay_ms`, `enabled`. |
| Lịch đồng bộ `syncTasks` (task time, sleepTimeSpan) | Giữ | `schedule_at = ["01:00","12:10"]`, `schedule_interval_s` (scheduler.h). |
| Thư mục hệ thống `__sync` (trash/error/meta) | Giữ ý tưởng | `__sync` không bao giờ được đồng bộ; trash trên đích. |
| Dịch vụ Windows (Service/ServiceInstaller.cs, ServicePart.cs) | Giữ + mở rộng | `mysync service install/uninstall/start/stop` (SCM) và unit systemd trên Linux; chạy độc lập foreground. |
| Giới hạn `Max_BandWidth` | Giữ | `max_bandwidth_kbps` (token bucket) ở máy khách; nay máy chủ cũng có `[server] max_bandwidth_kbps` (trần toàn máy) và `[[client]] max_bandwidth_kbps` (trần riêng từng máy, chung cho mọi kết nối của máy đó, gộp byte nhận + gửi; luôn qua cả hai bucket nên mức thấp hơn thắng, kể cả khi máy khách tự đặt giới hạn). Không theo khung giờ, không áp cho đích copy cục bộ. |
| Giới hạn `Max_Cpu` (ServerPerformance) | Đổi | Thay bằng `connections`/số luồng băm; không đo CPU toàn máy. |
| Nhật ký NLog | Đổi | `log.h` đơn giản: tệp + stderr, mức log; không ghi bí mật. |
| Đích copy trực tiếp (Simple/CopyClient.cs) | Giữ — theo quyết định người dùng | `[[watch.target]] path = "..."`: ổ khác, thư mục khác, UNC `\server\share` (Windows) hoặc điểm mount CIFS/NFS (Linux), không cần server MySync. Đủ: bỏ qua trùng hash, ghi tạm + rename nguyên tử, chặn thoát khỏi thư mục đích (safe_join). |
| Cảnh báo (AlertSender: email, Yahoo, SendAlertProvider, AlertAddressItem) | Bỏ — theo quyết định người dùng | Lỗi vận hành chỉ ghi log. Lưu ý: ClientSample/ServerSample.config cũ chứa mật khẩu SMTP/Yahoo ở dạng rõ trong repo nguồn. |
| FTP (Simple/FTPClient.cs) | Bỏ — theo quyết định người dùng | |
| NetworkMonitor (NetworkAdapter, NetworkMonitor) | Bỏ — theo quyết định người dùng | Mất mạng xử lý bằng retry/backoff (`retry_min_ms`, `retry_max_ms`). |
| Giao diện WinForms (FrmMain, FrmMirrorItem, MirrorItemView) | Đổi — thay bằng wxWidgets, theo quyết định người dùng | `mysync-gui` (binary riêng, tuỳ chọn `MYSYNC_BUILD_GUI`): xem trạng thái + icon khay, sửa cấu hình không cần mở TOML, quản lý service, ghép máy/khoá; nói chuyện với daemon qua IPC cục bộ (named pipe / Unix socket), xem `docs/GUI.md`. Lõi CLI vẫn không phụ thuộc wx. |
| Formater Bin / Bson / ProtoBuf / IFormater | Bỏ — theo quyết định người dùng | Giao thức dùng một mã hoá nhị phân gọn tự thiết kế (protocol.h). JSON chỉ nếu cần cho chẩn đoán. |
| FingerPrint (vân tay máy bằng WMI+MD5) | Bỏ | Chỉ dùng cho nhận dạng/giấy phép máy cũ; MD5 yếu; thay bằng xác thực khoá. (Không có yêu cầu nghiệp vụ nào được ghi nhận cho nó.) |
| PipeStream, TimeoutHelper, StackQueue, TimeTask, TaskScheduler | Đổi | Thay bằng hàng đợi/luồng chuẩn C++ và timeout của Socket. |
| Cấu hình App.config XML (`WatcherSettings`, `MirrorSettings`, appSettings) | Đổi | TOML: `examples/server.toml`, `examples/client.toml`. Tuỳ chọn mail/Yahoo bị bỏ cùng tính năng cảnh báo. |
