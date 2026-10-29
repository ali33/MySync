# Chạy MySync như dịch vụ

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

Cài / gỡ dịch vụ cần quyền quản trị (Windows: Administrator; Linux: root). API: `include/mysync/service.h`.

## Windows (SCM)

- Tài khoản mặc định: **`NT AUTHORITY\LocalService`** (đặc quyền thấp, không mật khẩu, có mạng). Đổi bằng `ServiceSpec::run_as`
  (`LocalSystem` nếu thật sự cần ghi mọi nơi; không khuyến nghị).
- LocalService **không có quyền** vào thư mục dữ liệu của người dùng. Phải cấp trước khi chạy:
  - thư mục đồng bộ (server: thư mục gốc nhận; client: thư mục nguồn): `icacls "D:\data" /grant "NT AUTHORITY\LocalService:(OI)(CI)M"`
    (client chỉ đọc nguồn thì dùng `(OI)(CI)RX`; thư mục `__sync` bên trong cần `M`)
  - thư mục trạng thái/index (`state_dir`) và tệp log: `M`
  - tệp cấu hình và tệp khoá PSK: `R` cho LocalService, và **gỡ quyền đọc của nhóm Users/Everyone** trên tệp khoá.
- Khởi động `Auto (Delayed)` để mạng lên trước. Recovery: tự khởi động lại sau 5 s, 5 s, 30 s (đặt lại bộ đếm sau 24 h), kể cả khi tiến trình thoát với mã khác 0.
- Dừng: SCM gửi STOP/SHUTDOWN → cờ `stop` bật → thân dịch vụ phải thoát trong 30 s.
- Đường dẫn trong cấu hình nên là tuyệt đối (thư mục làm việc của dịch vụ là `C:\Windows\System32`). Ổ ánh xạ mạng (`Z:`) không tồn tại trong phiên dịch vụ; dùng UNC và cấp quyền cho máy.

## Linux (systemd)

`systemd_unit_text()` sinh unit với: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices`,
`ProtectKernel*`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `Restart=on-failure`.

- Hệ thống tệp chỉ đọc theo mặc định: mọi thư mục cần ghi phải liệt kê ở `ServiceSpec::read_write_paths` (thư mục đồng bộ, `state_dir`, thư mục chứa log). Đường dẫn không được chứa khoảng trắng, nháy, `\`, `%`, `$`.
- Chạy bằng user riêng (`run_as`), tạo trước: `useradd --system --no-create-home mysync`; cấp quyền ghi cho user đó lên các thư mục trên; tệp khoá PSK mode 0600 thuộc user đó.
- Cổng < 1024 cần `AmbientCapabilities=CAP_NET_BIND_SERVICE` (unit sinh ra không cấp; dùng cổng cao hoặc chỉnh tay).
- Mọi lệnh `systemctl` chạy bằng `fork/execvp` với mảng đối số, tên dịch vụ chỉ nhận `[A-Za-z0-9_.-]`.

## Chưa kiểm trên máy phát triển

Cài/gỡ/khởi động thật trên Windows SCM và systemd chưa được chạy (cần quyền admin/root, không đụng máy dev). Đã kiểm: sinh unit, kiểm tên, chặn chèn lệnh, biên dịch.
