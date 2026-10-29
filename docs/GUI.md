# Giao diện đồ hoạ `mysync-gui`

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

Giao diện điều khiển daemon MySync (Windows + Linux GTK3) bằng wxWidgets 3.2. Lõi `mysync` **không** phụ thuộc wx; GUI nói chuyện với daemon qua kênh điều khiển cục bộ (named pipe / unix socket, không mở cổng TCP — xem `include/mysync/gui/ipc.h`).

## Dựng

```
cmake -S . -B build-gui -G Ninja -DMYSYNC_BUILD_GUI=ON      # mặc định OFF
cmake --build build-gui --target mysync-gui
```

- Có sẵn wxWidgets 3.2 trên máy (`libwxgtk3.2-dev`, MSYS2 `wxwidgets3.2`) thì dùng; không có thì CMake tự tải tarball chính thức v3.2.9 (SHA-256 ghim, xem `third_party/README.md`) và dựng tĩnh chỉ core + base + adv. `-DMYSYNC_WX_FETCH=ON` ép tải, `=OFF` cấm tải.
- Windows (MinGW g++ 15 + Ninja, 16 lõi): dựng wx ~2 phút lần đầu. Linux cần `libgtk-3-dev`.
- Phần logic thuần (`gui/*_model.*`: định dạng, kiểm hợp lệ, trạng thái→màu icon, băng báo lỗi, bảng chuỗi vi/en) luôn được dựng và kiểm bằng `mysync_tests` (`tests/test_gui_viewmodel.cpp`), kể cả khi không bật GUI.

## Tham số dòng lệnh

`--tray` (khởi động ẩn dưới khay) · `--tab=0..3` · `--config=<tệp.toml>` · `--daemon=<tên>` · `--lang=vi|en` · `--page=<ngoài*10+trong>` (trang con của tab Cấu hình) · `--dump-icons=<png>` (vẽ 5 trạng thái icon rồi thoát). Ba tham số cuối chủ yếu để kiểm thử/chụp ảnh.

## Bố cục

| Tab | Việc |
|---|---|
| Trạng thái | poll daemon mỗi 1 s trong luồng nền; bảng watch/đích (trạng thái, hàng đợi, tốc độ, gửi/bỏ qua/lỗi), tệp đang đồng bộ, lỗi gần nhất nguyên văn kèm giờ có thứ, nhật ký lỗi của daemon; chọn daemon theo tên dịch vụ |
| Cấu hình | sửa không cần mở TOML (client: chung, watch, bộ lọc, lịch, đích mạng/copy; server: bind/port/root, hạn mức, trash, allow/deny); kiểm từng ô; Lưu = ghi nguyên tử + `.bak` + `RELOAD_CONFIG`; cảnh báo mất chú thích lần đầu; phát hiện tệp bị sửa ngoài |
| Dịch vụ | cài / gỡ / khởi động / dừng qua `ServiceController` (UAC / pkexec), kết quả nguyên văn |
| Ghép máy và Khoá | tạo khoá, khoá công khai + vân tay + Sao chép, dán khoá bên kia (kiểm định dạng), ghim khoá máy chủ vào đích (client), allowlist máy khách (server) |

Icon khay đổi màu: xám = không nối được daemon, xanh lá = rảnh, xanh dương (xoay) = đang đồng bộ, vàng = cảnh báo (mất kết nối đích, daemon từ chối cấu hình, lỗi trong 10 phút gần đây), đỏ = có đích đang ở trạng thái lỗi. Đóng cửa sổ = thu xuống khay; chỉ "Thoát" ở menu khay/menu Tệp mới thoát thật.

## Quy ước đã áp dụng

- Mọi chờ máy chủ/dịch vụ có chỉ báo động (`BusyIndicator`: vòng quay; khi hệ điều hành bật giảm chuyển động thì đổi sang nhấp nháy chậm 800 ms, không bỏ tín hiệu) và vô hiệu hoá phần nội dung của tab để chặn bấm chồng (`BusyGate`).
- Lỗi hiện thành băng đỏ (chặn) / hổ phách (cảnh báo), nguyên văn, gộp trùng, tối đa 5 dòng; lỗi từ luồng nền, `wxLogError` và ngoại lệ lạc trong vòng lặp sự kiện đều đẩy về UI (`CallAfter` / `OnExceptionInMainLoop`), không chạm UI từ luồng nền.
- Thời gian theo ngày luôn ghi thứ (giờ địa phương); chỉ hiện tên máy khách/tên watch và vân tay ngắn, không hiện ID trần.
- Khoá bí mật không bao giờ được đọc, hiển thị, đưa vào clipboard hay log (chỉ đường dẫn tệp khoá và khoá công khai).

## Hạn chế đã biết

- Chưa có test tự động cho lớp wx (chỉ lớp `*_model` được kiểm headless); phần giao diện được chạy tay và chụp ảnh trên Windows 11.
- Linux GTK3: dựng thử trong Docker, **chưa chạy giao diện thật** trên màn hình Linux; khay dùng `wxTaskBarIcon` của wx 3.2 (X11/StatusNotifier tuỳ môi trường desktop, nếu không có khay thì đóng cửa sổ = thoát và có băng cảnh báo).
- Lưu cấu hình viết lại cả tệp theo mẫu chuẩn: chú thích viết tay mất (còn `.bak` một bản).
- Chưa có dark mode riêng (dùng màu hệ thống; các băng/ô báo lỗi dùng màu cố định đủ tương phản).


## Quyền điều khiển

Danh sách `[control] allow` / `group` tương đương đặc quyền của dịch vụ: họ sửa được cấu hình rồi nạp lại, và thấy IP, tên máy khách, đường dẫn trong nhật ký và trạng thái. Daemon chạy như dịch vụ chỉ nhận cấu hình mà tệp và thư mục cha không ghi được bởi người lạ; nâng quyền chỉ chạy `mysync` do quản trị sở hữu (trên Windows nên cài vào Program Files). Chi tiết: GUI-CORE.md.
