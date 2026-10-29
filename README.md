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

## Tài liệu
- `docs/FEATURES.md` — bảng đối chiếu tính năng cũ → mới (giữ / đổi / bỏ, kèm lý do)
- `docs/DESIGN.md` — kiến trúc, giao thức
- `docs/SETUP.md`, `docs/SERVICE.md` — triển khai
- `docs/STATUS.md` — đã kiểm gì, chưa kiểm gì, hạn chế đã biết
