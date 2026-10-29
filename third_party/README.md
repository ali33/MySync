# Thư viện bên thứ ba (đã chép vào cây mã)

Mỗi thư viện được chép nguyên văn từ tag phát hành của nguồn; `CHECKSUMS.sha256` ghim SHA-256 của từng tệp.
Kiểm: `scripts/verify-third-party.sh` (Linux/macOS), `scripts/verify-third-party.ps1` (Windows) hoặc
`ctest -R third_party_checksums`. Đổi bất kỳ byte nào thì phép kiểm báo lỗi — muốn nâng cấp thư viện thì thay tệp
rồi sinh lại `CHECKSUMS.sha256` trong cùng một lần đổi, và cập nhật bảng dưới đây.

| Thư viện | Phiên bản | Nguồn | Commit của tag | Giấy phép |
|---|---|---|---|---|
| Monocypher | 4.0.2 | https://github.com/LoupVaillant/Monocypher | `0d85f98c9d9b0227e42cf795cb527dff372b40a4` | BSD-2-Clause hoặc CC0-1.0 (chọn một) — `monocypher/LICENCE.md` |
| BLAKE3 (C) | 1.5.4 | https://github.com/BLAKE3-team/BLAKE3 (thư mục `c/`) | `95e42b84fc4709974c7b23c7ae885989ab36c31e` | CC0-1.0 hoặc Apache-2.0 — `blake3/LICENSE_CC0`, `blake3/LICENSE_A2` |
| LZ4 | v1.10.0 | https://github.com/lz4/lz4 (thư mục `lib/`) | `ebb370ca83af193212df4dcbadcc5d87bc0de2f0` | BSD-2-Clause (thư viện `lib/`) — `lz4/LICENSE` |

## Ghi chú

- **Monocypher**: so với tệp cùng tên ở commit trên, chỉ khác dòng 1 (`// Monocypher version __git__` đã thay bằng
  dòng ghi tag + commit) và kiểu xuống dòng (bản trong cây dùng CRLF, bản gốc dùng LF). Đã đối chiếu bằng diff sau
  khi bỏ ký tự CR và bỏ dòng 1 (ngày 2026-10-29): hai tệp `monocypher.c`, `monocypher.h` giống hệt.
- **BLAKE3**: chỉ biên dịch các tệp `.c` (kể cả biến thể SSE2/SSE4.1/AVX2/AVX-512 bằng intrinsics, xem
  `CMakeLists.txt`); các tệp `.S` / `.asm` đi kèm không được dùng nhưng vẫn nằm trong danh sách kiểm.
- Checksum tính trên byte thô của tệp. Đừng để git đổi kiểu xuống dòng: `third_party/.gitattributes` đặt `-text`.

## wxWidgets (chỉ khi dựng giao diện `mysync-gui`, không chép vào cây mã)

Chỉ dùng khi cấu hình `-DMYSYNC_BUILD_GUI=ON`; lõi `mysync`/`mysync_tests` không phụ thuộc wx. Logic ở `cmake/mysync_gui.cmake`.

| Mục | Giá trị |
|---|---|
| Phiên bản | 3.2.9 (bản 3.2.x ổn định mới nhất xác minh được trên GitHub Releases; 3.2.6 cũng tồn tại, SHA-256 `939e5b77ddc5b6092d1d7d29491fe67010a2433cf9b9c0d841ee4d04acb9dce7`, nhưng chọn 3.2.9 vì GCC 15 của MinGW mới) |
| Nguồn | https://github.com/wxWidgets/wxWidgets/releases/download/v3.2.9/wxWidgets-3.2.9.tar.bz2 |
| SHA-256 (tải về và tính thật) | `fb90f9538bffd6a02edbf80037a0c14c2baf9f509feac8f76ab2a5e4321f112b` (27 366 567 byte) |
| Giấy phép | wxWindows Library Licence 3.1 (LGPL-2 kèm ngoại lệ liên kết) — tương thích GPL-2.0-or-later; cho phép liên kết tĩnh |
| Cách lấy | Ưu tiên `find_package(wxWidgets 3.2)` (bản hệ thống). Dự phòng: `FetchContent` tarball trên, `URL_HASH SHA256=` ghim; `-DMYSYNC_WX_FETCH=ON` ép tải, `=OFF` cấm tải |
| Thành phần | core + base (+ adv cho `wxTaskBarIcon`), liên kết tĩnh; tắt html, richtext, aui, propgrid, ribbon, stc, xrc, webview, mediactrl, opengl, xml, webrequest, debugreport, sound; không dựng samples/tests/demos |
