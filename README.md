# MySync (C++)

Đồng bộ tệp nhanh, an toàn, chạy trên **Windows và Linux** (C++17). Viết lại từ bản MySync C# (.NET/WinForms).

- Bản quyền (C) 2026 **META.vn** · Tác giả: **Nguyễn Đức Sơn**
- Giấy phép: **GPL-2.0-or-later** (xem `LICENSE`). Thư viện vendor đều tương thích GPLv2: Monocypher (BSD-2/CC0), BLAKE3 (CC0), LZ4 (BSD-2).

## Điểm chính
- **Watch realtime**: ReadDirectoryChangesW (Windows) / inotify (Linux), gộp sự kiện theo từng tệp (mặc định 300 ms), chờ tệp hết bị khoá, tràn hàng đợi thì quét lại, quét toàn bộ định kỳ để dự phòng.
- **Nhanh**: so size+mtime trước, chỉ băm BLAKE3 khi khác; chỉ mục hash lưu ra đĩa; tệp trùng nội dung không truyền; delta theo khối kiểu rsync cho tệp lớn sửa một phần; nén LZ4 (bỏ qua đuôi đã nén); nhiều kết nối song song, gửi OFFER theo lô không chờ từng tệp.
- **Bảo mật**: kênh Noise_IK (X25519 + XChaCha20-Poly1305 + BLAKE2b) với khoá công khai ghim sẵn hai chiều, allowlist client + quyền ro/rw + thư mục con, chặn path traversal, ghi tệp tạm → kiểm BLAKE3 → rename nguyên tử, xoá thì chuyển vào `__sync/__trash`, không log khoá. Chi tiết và giới hạn: `docs/DESIGN.md`.
- **Đích**: máy chủ MySync qua mạng, hoặc **copy trực tiếp** sang ổ/thư mục khác, UNC `\server\share`, điểm mount CIFS/NFS.
- **Chạy**: độc lập (foreground) hoặc dịch vụ (Windows Service / systemd). Một binary `mysync`.

## Build (một lệnh)
```
cmake -S . -B build && cmake --build build && ctest --test-dir build
```
Cần CMake >= 3.16 và trình biên dịch C++17 (MSVC, MinGW-w64 g++, GCC, Clang). Không phụ thuộc thư viện ngoài (đã vendor trong `third_party/`).

## Dùng nhanh
```
mysync keygen -o server.key                  # in khoá công khai
mysync run -c server.toml                    # máy chủ
mysync run -c client.toml [--once]           # máy khách, theo dõi liên tục hoặc một lượt
mysync service install -c server.toml        # cài dịch vụ (admin/root)
```
Ghép máy, cấu hình mẫu và dịch vụ: `docs/SETUP.md`, `docs/SERVICE.md`, `examples/`.

## Cài làm dịch vụ (từng bước)

> **Lưu ý trung thực:** việc cài dịch vụ thật (Windows SCM, systemd) **chưa được kiểm trên máy thật** (xem `docs/STATUS.md`).
> Đã kiểm: sinh tham số/unit, kiểm tên dịch vụ, chặn chèn lệnh, biên dịch. Hãy thử trên máy thử trước khi triển khai.
> Chi tiết quyền và hành vi: `docs/SERVICE.md`.

**Bước 0 — ghép máy chủ với máy khách (làm một lần):**
1. Trên mỗi máy: `mysync keygen -o <tên>.key`. Lệnh in ra **khoá công khai** (64 ký tự hex); khoá bí mật nằm trong tệp, không gửi đi đâu.
2. Máy chủ: dán khoá công khai của máy khách vào `server.toml`: `[[client]]` → `public_key = "..."`, `access = "rw"` hoặc `"ro"`.
3. Máy khách: dán khoá công khai của máy chủ vào `client.toml`: `[[watch.target]]` → `server_key = "..."`; `key_file` trỏ tới khoá bí mật của chính máy khách.
4. Kiểm thử foreground trước khi cài: `mysync run -c server.toml`, rồi `mysync run -c client.toml --once`.
5. Trong cấu hình đặt **đường dẫn tuyệt đối** và `log_file` (không đặt thì log chỉ ra stderr; dịch vụ Windows sẽ không có log).
Mẫu: `examples/server.toml`, `examples/client.toml`; từng bước ghép máy: `docs/SETUP.md`.

**Windows** (PowerShell/CMD chạy bằng *Run as administrator*; tên dịch vụ mặc định `mysync-server` / `mysync-client`, đổi bằng `--name`):
```
mysync service install   -c C:\mysync\server.toml     # vai trò (server/client) tự nhận từ cấu hình
mysync service start     -c C:\mysync\server.toml
mysync service stop      -c C:\mysync\server.toml
mysync service uninstall -c C:\mysync\server.toml
```
- Dịch vụ chạy bằng tài khoản **`NT AUTHORITY\LocalService`** (đặc quyền thấp); đổi bằng `--user`. Khởi động tự động (trễ), tự chạy lại khi lỗi.
- LocalService phải được cấp quyền trước, ví dụ: `icacls "D:\data" /grant "NT AUTHORITY\LocalService:(OI)(CI)M"` cho thư mục đồng bộ, `state_dir` và thư mục log; tệp khoá chỉ cho LocalService đọc.
- Log: tệp ở `log_file` trong cấu hình. Trạng thái: `sc query mysync-server` hoặc `services.msc`.

**Linux** (systemd, chạy bằng root):
```
useradd --system --no-create-home --shell /usr/sbin/nologin mysync
install -m 0755 build/mysync /usr/local/bin/mysync
install -d -o mysync -g mysync /srv/mysync /var/lib/mysync /var/log/mysync /etc/mysync
install -m 0600 -o mysync -g mysync server.key /etc/mysync/server.key     # khoá bí mật: chế độ 0600, chủ là user dịch vụ
install -m 0640 -o root -g mysync server.toml /etc/mysync/server.toml
mysync service install -c /etc/mysync/server.toml --user mysync          # sinh /etc/systemd/system/mysync-server.service
systemctl enable --now mysync-server
```
Hoặc chép tay `examples/mysync.service` vào `/etc/systemd/system/` rồi `systemctl daemon-reload && systemctl enable --now mysync` (cách này tên dịch vụ là `mysync`, **không phải** `mysync-server`; các lệnh trạng thái/log/gỡ bên dưới phải dùng đúng tên bạn cài). Lưu ý `mysync service install` chỉ cài và `enable`, **không tự chạy**: cần `systemctl start` hoặc `enable --now`. Thư mục cần **ghi** phải nằm trong `ReadWritePaths` (lệnh `service install` tự thêm từ cấu hình).
- Trạng thái: `systemctl status mysync-server`. Log: `journalctl -u mysync-server -f` (stderr được journald thu).
- Gỡ: `systemctl disable --now mysync-server && mysync service uninstall -c /etc/mysync/server.toml`.

## Giao diện đồ hoạ (tuỳ chọn)
`mysync-gui` (wxWidgets 3.2, Windows + Linux GTK3) là binary riêng, mặc định **không** dựng để lõi vẫn build một lệnh:
```
cmake -S . -B build-gui -DMYSYNC_BUILD_GUI=ON && cmake --build build-gui --target mysync-gui
```
Bốn tab: **Trạng thái** (kèm icon khay đổi màu), **Cấu hình** (sửa không cần mở TOML), **Dịch vụ** (cài/gỡ/start/stop, tự nâng quyền UAC/pkexec), **Ghép máy và Khoá**. GUI nói chuyện với daemon qua kênh cục bộ (named pipe/Unix socket, có phân quyền), không mở cổng TCP và không đưa khoá bí mật qua kênh. Chi tiết, hạn chế: `docs/GUI.md`, `docs/GUI-CORE.md`.

## Tài liệu
- `docs/FEATURES.md` — bảng đối chiếu tính năng cũ → mới (giữ / đổi / bỏ, kèm lý do)
- `docs/DESIGN.md` — kiến trúc, giao thức
- `docs/SETUP.md`, `docs/SERVICE.md` — triển khai
- `docs/GUI.md`, `docs/GUI-CORE.md` — giao diện đồ hoạ và kênh điều khiển cục bộ
- `docs/STATUS.md` — đã kiểm gì, chưa kiểm gì, hạn chế đã biết
