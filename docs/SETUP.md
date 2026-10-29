# Ghép hai máy MySync

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

Hai bên xác thực nhau bằng **khoá công khai được ghim** (không dùng mật khẩu chung, không cần CA). Mỗi bên có một
khoá bí mật (không bao giờ rời máy) và một khoá công khai (đưa cho bên kia).

## 1. Sinh khoá ở mỗi bên

```
# máy chủ
mysync keygen -o server.key        # in ra dòng hex 64 ký tự = khoá CÔNG KHAI của máy chủ
# máy khách
mysync keygen -o client.key        # in ra khoá công khai của máy khách
```

`keygen` từ chối ghi đè tệp có sẵn; tệp khoá bí mật có quyền 0600 trên Linux (Windows: đặt trong thư mục chỉ tài khoản
chạy dịch vụ đọc được). Khoá công khai cũng được lưu ở `<tệp khoá>.pub`.

## 2. Dán khoá công khai của bên kia

- Máy chủ, `server.toml`: thêm khối cho mỗi máy khách, `public_key` = khoá công khai của máy khách.
  ```toml
  [[client]]
  name = "van-phong"
  public_key = "…64 hex…"
  access = "rw"          # hoặc "ro"
  prefix = ""            # tuỳ chọn: chỉ cho thấy một thư mục con của root
  ```
- Máy khách, `client.toml`: trong `[[watch.target]]`, `server_key` = khoá công khai của máy chủ; `key_file` (mục `[client]`)
  trỏ tới khoá bí mật của chính máy khách.

Mẫu đầy đủ, có chú thích và ánh xạ từ tuỳ chọn cũ: `examples/server.toml`, `examples/client.toml`.
Một tệp cấu hình = một vai trò (tệp có `[server]`/`[[client]]` là máy chủ; có `[client]`/`[[watch]]` là máy khách).
Máy vừa là máy chủ vừa là máy khách thì chạy hai tiến trình / hai dịch vụ từ hai tệp.

Đích **copy trực tiếp** (ổ khác, `\\nas\share`, điểm mount) không cần máy chủ MySync và không cần khoá:
`[[watch.target]] path = "..."`.

## 3. Kiểm thử

```
mysync status -c server.toml       # in cấu hình đã nạp và khoá công khai (không in bí mật)
mysync run -c server.toml          # máy chủ, foreground (Ctrl+C để dừng)
mysync run -c client.toml --once   # máy khách: một lượt đồng bộ rồi thoát; mã thoát 0 = không có việc bị bỏ
mysync run -c client.toml          # máy khách: theo dõi liên tục
```

Mã thoát: 0 thành công · 1 lỗi khi chạy · 2 lỗi cú pháp lệnh hoặc cấu hình.

## 4. Cài thành dịch vụ

Cần quyền quản trị (Windows: Administrator; Linux: root). Chi tiết quyền: `docs/SERVICE.md`.

```
mysync service install -c C:\mysync\server.toml                 # Windows, tài khoản LocalService
mysync service install -c /etc/mysync/server.toml --user mysync # Linux, sinh unit systemd
mysync service start   -c /etc/mysync/server.toml
mysync service stop    -c /etc/mysync/server.toml
mysync service uninstall -c /etc/mysync/server.toml
```

Tên dịch vụ mặc định `mysync-server` / `mysync-client` (đổi bằng `--name`; dùng cùng `--name` cho start/stop/uninstall nếu
không truyền `-c`). Dùng **đường dẫn tuyệt đối** trong cấu hình: thư mục làm việc của dịch vụ không phải thư mục cấu hình.

Mẫu systemd viết tay: `examples/mysync.service`.

## 5. Quyền thư mục

| Thư mục | Ai cần gì |
|---|---|
| Thư mục gốc máy chủ (`root`) | tài khoản chạy máy chủ: ghi (kể cả `__sync/` bên trong) |
| `state_dir`, thư mục `log_file` | tài khoản chạy dịch vụ: ghi |
| Thư mục nguồn (`[[watch]] path`) | tài khoản máy khách: chỉ đọc là đủ |
| Đích copy trực tiếp (`path`) | tài khoản máy khách: ghi (kể cả `__sync/`) |
| Tệp khoá bí mật | chỉ tài khoản dịch vụ đọc được (Linux 0600) |

Windows: cấp bằng `icacls "D:\data" /grant "NT AUTHORITY\LocalService:(OI)(CI)M"`. Linux: `chown`/`setfacl` cho user `mysync`
và liệt kê thư mục ghi trong `ReadWritePaths` (lệnh `service install` tự điền từ cấu hình).

## 6. Mở cổng

Máy chủ lắng nghe TCP `port` (mặc định 5656). Mở cổng đó:

- Linux: `ufw allow 5656/tcp` hoặc `firewall-cmd --add-port=5656/tcp --permanent`
- Windows: `netsh advfirewall firewall add rule name="MySync" dir=in action=allow protocol=TCP localport=5656`

Nên giới hạn nguồn bằng `allow = ["203.0.113.0/24"]` trong `server.toml`. Máy khách chỉ cần kết nối ra (không mở cổng vào).
Cổng dưới 1024 trên Linux cần `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

## Gỡ lỗi nhanh

- `authentication failed`: sai `server_key`, khoá của máy khách chưa có trong `[[client]]`, hoặc IP bị `deny`/chặn tạm vì
  sai quá nhiều lần.
- `destination unavailable`: đích copy trực tiếp chưa gắn (ổ/UNC/mount); engine tự thử lại với chờ tăng dần.
- `REFUSING to delete …`: nguồn trông như trống bất thường; kiểm tra thư mục nguồn có được gắn không. Không có gì bị xoá.
