<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 META.vn -->
<!-- Author: Nguyễn Đức Sơn -->

# Kịch bản kiểm tay MySync (Windows, kèm phần Linux ngắn)

Những phần dưới đây **chưa từng được kiểm trên dịch vụ, LSA, UAC, pkexec thật** (xem `STATUS.md`). Test tự động chỉ phủ phần logic. Kịch bản này dành cho người chạy tay trên **máy ảo (VM) hoặc máy phụ**, tuyệt đối không chạy trên máy đang dùng thật.

Cách dùng: làm lần lượt từng ca, đánh dấu `✅` (đúng như mong đợi) hoặc `❌` (sai). Ca nào `❌` thì thu thập đúng mục "Nếu sai, chụp lại" rồi gửi.

## 0. Chuẩn bị

- 2 VM Windows 11 (gọi là **VM-A** và **VM-B**) cùng mạng, đã cài MySync (`mysync.exe`, `mysync-gui.exe`) vào `C:\Program Files\MySync` (thư mục chỉ quản trị ghi được).
- Trên mỗi VM tạo sẵn 3 tài khoản, mỗi tài khoản **có mật khẩu**:
  - `thuong`: tài khoản cục bộ **người dùng chuẩn**.
  - `quantri`: tài khoản cục bộ thuộc nhóm **Administrators**.
  - `msft`: tài khoản **Microsoft** (đăng nhập bằng email; dịch vụ cần mật khẩu tài khoản Microsoft, không phải mã PIN).
- Mỗi tài khoản có thư mục thử `C:\Users\<tên>\Du-lieu-thu` chứa vài tệp nhỏ (một tệp lớn ~200 MB để thấy tiến độ).
- Thông tin cần có khi báo lỗi (gọi chung là **gói chẩn đoán**):
  1. Nguyên văn thông báo lỗi (chụp màn hình cả cửa sổ, không cắt).
  2. Kết quả lệnh `mysync status --json` (với dịch vụ: thêm `--service <tên>`).
  3. Nhật ký: chế độ cá nhân ở `%APPDATA%\MySync\log\`; dịch vụ ở `%ProgramData%\MySync\<tên dịch vụ>\` (thư mục `log`); sự kiện Windows: Event Viewer, Windows Logs, System, nguồn "Service Control Manager".
  4. Không gửi khoá bí mật (`key`), không gửi mật khẩu.

## 1. Chế độ cá nhân (Đơn giản) cho từng loại tài khoản

Lặp ca 1.1 đến 1.4 cho **cả 3 tài khoản** (`thuong`, `quantri`, `msft`). Ghi kết quả vào bảng cuối mục.

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 1.1 | Đăng nhập tài khoản, mở `mysync-gui.exe`. | Mở ở chế độ Đơn giản, không đòi quyền quản trị, không báo lỗi đỏ. | Ảnh cửa sổ; gói chẩn đoán |
| 1.2 | Bấm **Bắt đầu nhanh** (hoặc trình hướng dẫn 3 bước): nguồn = `Du-lieu-thu`, đích = thư mục khác trên cùng máy. | Tệp xuất hiện ở đích, trạng thái xanh; sửa một tệp nguồn thì đích đổi theo trong vài giây; tệp giống hệt không bị gửi lại. | Ảnh trạng thái; `status --json` |
| 1.3 | Bật **Tự chạy khi tôi đăng nhập**, đăng xuất rồi đăng nhập lại. | MySync tự chạy, sửa tệp nguồn vẫn đồng bộ. | Ảnh; Task Scheduler / mục Startup có gì |
| 1.4 | Tắt tuỳ chọn trên, đăng xuất, đăng nhập lại. | MySync không tự chạy. | Ảnh |

Bảng kết quả (điền tay):

| Tài khoản | 1.1 | 1.2 | 1.3 | 1.4 |
|---|---|---|---|---|
| `thuong` | ☐ | ☐ | ☐ | ☐ |
| `quantri` | ☐ | ☐ | ☐ | ☐ |
| `msft` | ☐ | ☐ | ☐ | ☐ |

## 2. Cài dịch vụ bằng nút "Chạy cả khi chưa đăng nhập máy (cài dịch vụ)"

Lặp cho **từng loại tài khoản**. Mong đợi khác nhau theo loại, ghi rõ ở cột kết quả.

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 2.1 | Bấm nút cài dịch vụ. Đọc hộp xác nhận. | Hộp xác nhận ngắn, lời thường: nói dịch vụ chạy bằng tài khoản nào, đọc/ghi thư mục nào. Phần kỹ thuật nằm trong mục "Chi tiết" (đóng sẵn). Thư mục nằm ngoài hồ sơ người dùng (nếu có) được cảnh báo ngay ở phần chính. | Ảnh hộp (cả bản đóng và bản mở Chi tiết) |
| 2.2 | Bấm tiếp tục, bấm **Có** ở hộp UAC, nhập mật khẩu tài khoản. | Cài xong, trạng thái "dịch vụ đang chạy". Tài khoản `quantri`: được cài nhưng engine chạy quyền thường (xem ca 6.3); nếu máy thuộc diện không đo được quyền mạng sạch thì bị từ chối **kèm lý do nguyên văn**. | Ảnh; nguyên văn lỗi; gói chẩn đoán |
| 2.3 | Nhập **sai** mật khẩu. | Được hỏi lại, không cài dở. Sai 5 lần liền thì chờ 30 giây. | Ảnh; gói chẩn đoán |
| 2.4 | Tài khoản không đặt mật khẩu (tạo thêm `khongmk`). | Báo rõ không cài được, gợi ý dùng "Tự chạy khi tôi đăng nhập". | Ảnh |
| 2.5 | Nhấn **Hủy** ở hộp UAC. | Không có gì thay đổi, không dịch vụ nửa vời (`sc query` không thấy dịch vụ mới). | `sc query` các dịch vụ `mysync*`; ảnh |
| 2.6 | Sau khi cài: `services.msc`, xem cột "Log On As". | Là đúng tài khoản người dùng, **không** phải LocalSystem. | Ảnh |

## 3. Khởi động lại máy, kiểm đồng bộ trước khi đăng nhập

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 3.1 | Sau ca 2.2: khởi động lại VM, **dừng ở màn hình đăng nhập, chưa đăng nhập**. Từ máy khác (hoặc VM-B), sửa một tệp ở nguồn/hoặc đẩy tệp tới đích của dịch vụ. | Tệp được đồng bộ dù chưa ai đăng nhập. | `status --json` (đăng nhập vào sau để lấy); nhật ký dịch vụ; Event Viewer |
| 3.2 | Đăng nhập, mở GUI. | GUI nhận ra dịch vụ đang chạy (không chạy engine cá nhân thứ hai tranh thư mục). | Ảnh |
| 3.3 | Đổi **mật khẩu** tài khoản trong Windows (Ctrl+Alt+Del hoặc `net user`), khởi động lại dịch vụ hoặc máy. | Dịch vụ không khởi động được; GUI hiện **băng thông báo cập nhật mật khẩu** với nút **Cập nhật mật khẩu**. Bấm, nhập mật khẩu mới thì dịch vụ chạy lại. | Ảnh băng; nguyên văn lỗi; gói chẩn đoán |

## 4. Gỡ dịch vụ, quay về chế độ cá nhân

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 4.1 | Bấm **Quay lại chạy dưới tài khoản của tôi**, đồng ý UAC. | Dịch vụ biến mất khỏi `services.msc`; cấu hình cá nhân còn nguyên; MySync chạy lại ở chế độ cá nhân và đồng bộ bình thường. | `sc query`; ảnh; gói chẩn đoán |
| 4.2 | Kiểm quyền "Log on as a service" của tài khoản (`secpol.msc`, Local Policies, User Rights Assignment). | Tài khoản **không còn** trong "Log on as a service" nếu không còn dịch vụ MySync nào dùng nó. Nếu còn dịch vụ khác của MySync cùng tài khoản thì **vẫn còn** (đếm tham chiếu). | Ảnh secpol |
| 4.3 | Thư mục `%ProgramData%\MySync\<tên>`. | Đã dọn (hoặc theo đúng điều tài liệu `SERVICE.md` nói). Không còn tệp khoá. | Danh sách tệp còn lại |

## 5. Ghép cặp hai VM, đích UNC

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 5.1 | VM-B: bật **Cho phép máy khác gửi file vào đây**, bấm **Tạo mã mới**. VM-A: dán mã `MSY1-…`. | Cả hai bên hiện cùng chuỗi xác nhận 4 nhóm. VM-B bấm **Đồng ý** thì ghép thành công, VM-A gửi được tệp sang. | Ảnh hai bên; gói chẩn đoán cả hai |
| 5.2 | VM-B bấm **Từ chối**. | VM-A báo bị từ chối, không có khoá nào được lưu. | Ảnh; `peers.d` có gì |
| 5.3 | **Mã hết hạn**: tạo mã, đợi hơn 10 phút, dán trên VM-A. | VM-A báo mã hết hạn; không ghép. | Nguyên văn lỗi |
| 5.4 | **Mã sai**: sửa một ký tự trong mã rồi dán. | Báo mã không hợp lệ; không ghép; lặp nhiều lần thì bị làm chậm (chống đoán). | Nguyên văn lỗi |
| 5.5 | Dùng lại **cùng mã đã ghép thành công** lần hai. | Bị từ chối (mã dùng một lần). | Nguyên văn lỗi |
| 5.6 | Đặt `pairing = "off"` ở VM-B, tạo mã. | Không tạo được / ghép bị từ chối. | Ảnh |
| 5.7 | Đích là **UNC** `\\VM-B\chia-se\thu` (thư mục chia sẻ có quyền ghi cho tài khoản). Chạy ở chế độ cá nhân rồi ở dịch vụ. | Chế độ cá nhân: đồng bộ được. Dịch vụ: đồng bộ được nếu tài khoản dịch vụ có quyền trên chia sẻ; nếu không, lỗi hiện rõ (không im lặng). | Nguyên văn lỗi; gói chẩn đoán |

## 6. Ca bảo mật (quan trọng nhất)

Làm trên dịch vụ đã cài (ca 2.2) cho `thuong` và `quantri`.

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 6.1 | Trong thư mục nguồn tạo **junction** tới thư mục hệ thống: `mklink /J C:\Users\<tên>\Du-lieu-thu\lien-ket C:\Windows`. Đợi đồng bộ. | Junction bị **từ chối** (không lần theo); đích **không** có nội dung `C:\Windows`; lỗi hiện rõ trong trạng thái. | Danh sách đích; nguyên văn lỗi; gói chẩn đoán |
| 6.2 | Tạo thư mục `C:\KhoaQuanTri` chỉ cho Administrators/SYSTEM (`icacls C:\KhoaQuanTri /inheritance:r /grant:r Administrators:(OI)(CI)F`). Cấu hình đích dịch vụ trỏ vào đó (hoặc tạo junction/symlink trỏ vào đó) và đợi đồng bộ. | Engine **không ghi được**: báo lỗi từ chối truy cập; không có tệp mới trong thư mục. | Danh sách thư mục; nguyên văn lỗi |
| 6.3 | **Kiểm token của engine** (tài khoản `quantri`, quan trọng nhất): chạy Process Explorer, tìm `mysync.exe` con của dịch vụ, tab Security. Hoặc cho engine chạy lệnh/tệp thử rồi xem `whoami /groups`. | Nhóm `BUILTIN\Administrators` ở trạng thái **Deny only** (không phải Enabled); không có đặc quyền nguy hiểm (SeDebug, SeBackup, SeRestore, SeTakeOwnership, SeLoadDriver...); mức toàn vẹn **Medium**; tiến trình nằm trong một Job. Với `thuong` cũng không có quyền thừa. | Ảnh tab Security (Groups và Privileges) |
| 6.4 | Cố sửa cấu hình/khoá của dịch vụ trong `%ProgramData%\MySync\<tên>` bằng chính tài khoản dịch vụ (hoặc `thuong`). | Bị từ chối ghi (thư mục thuộc quản trị). | Nguyên văn lỗi; `icacls` của thư mục |
| 6.5 | Dùng tài khoản quản trị đã thêm vào nhóm "Backup Operators" hoặc "Hyper-V Administrators" rồi cài dịch vụ. | Bị **từ chối cài** kèm lý do nguyên văn (nhóm quyền mạnh). Dịch vụ cũ của tài khoản đó, nếu thêm nhóm sau khi cài, **không khởi động** ở lần chạy kế tiếp. | Nguyên văn lỗi; Event Viewer |
| 6.6 | Thử gọi `mysync` (hoặc pipe điều khiển) từ tài khoản khác không được phép. | Bị từ chối. | Nguyên văn lỗi |
| 6.7 | Xem nhật ký và `status --json`. | Không có mật khẩu, khoá bí mật, hay mã ghép cặp dạng đầy đủ trong đó. | Đoạn nhật ký (đã che) |

## 7. Linux (ngắn)

Máy Linux có systemd, polkit (pkexec), GTK3 và wxWidgets 3.2.

| # | Thao tác | Kết quả mong đợi | Nếu sai, chụp lại |
|---|---|---|---|
| 7.1 | Mở `mysync-gui`, chế độ Đơn giản, bắt đầu nhanh như ca 1.2. | Đồng bộ được, không đòi root. | Ảnh; `mysync status --json` |
| 7.2 | Bật tự chạy. | Có đơn vị **systemd user** (`systemctl --user status`) chạy khi đăng nhập. | `systemctl --user status ...` |
| 7.3 | Bấm **Chạy cả khi chưa đăng nhập máy (cài dịch vụ)**, hộp pkexec hiện ra, nhập mật khẩu. | Có `mysync-<user>-<id>.service` chạy bằng `User=` đúng tài khoản (không root). `systemctl status` hiện active. | `systemctl status`; `journalctl -u ...`; ảnh |
| 7.4 | Khởi động lại máy, chưa đăng nhập, sửa tệp nguồn từ máy khác. | Dịch vụ đồng bộ. | `journalctl -u ...` |
| 7.5 | **Quay lại chạy dưới tài khoản của tôi**. | Đơn vị dịch vụ bị gỡ; chế độ cá nhân chạy lại. | `systemctl list-units 'mysync*'` |
| 7.6 | Tạo symlink trong thư mục nguồn trỏ ra `/etc`. | Bị từ chối, không sao chép `/etc`. | Danh sách đích; nguyên văn lỗi |

## 8. Tổng kết

Ghi vào `STATUS.md` (mục kiểm tay) ngày làm, bản dựng (`mysync --version` hoặc mã commit), danh sách ca `❌` kèm gói chẩn đoán. Ca bảo mật mục 6 không đạt thì **không** phát hành bản dịch vụ.
