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

## Chế độ Đơn giản

Dành cho người không chuyên: không cần cài dịch vụ, không cần quyền quản trị, không sửa tệp cấu hình, không chép khoá. Lời trong chế độ này là lời đời thường (không có chữ daemon, TOML, Noise, allowlist, IPC, SID). Bốn tab cũ vẫn còn, gọi là **chế độ nâng cao**.

### Cách hoạt động
- GUI chạy bộ đồng bộ như **tiến trình con của chính người dùng** (`mysync run`, ẩn cửa sổ console), tự khởi động lại nếu nó chết (chờ 1, 2, 5, 10, 30, 60 s; sau 5 lần chết liền trong 10 s đầu thì báo nguyên văn những dòng cuối nó in ra rồi dừng). Đóng cửa sổ = thu xuống khay, bộ đồng bộ vẫn chạy; chỉ **Thoát hẳn** (menu khay hoặc menu Tệp) mới dừng nó, và hỏi lại nếu đang đồng bộ. Cần `mysync[.exe]` nằm cạnh `mysync-gui[.exe]`.
- Dữ liệu của người dùng nằm trong `%APPDATA%\MySync\` (Windows) hoặc `~/.config/mysync` (Linux): `config.toml`, `key` (khoá bí mật, chỉ chủ sở hữu đọc được), `state/`, `log/`. `--user-dir=<thư mục>` đổi chỗ này (thử nghiệm / chạy xách tay).
- Cài đặt riêng của GUI (lưu bằng wxConfig): `mode` (`simple`/`advanced`), `svc.mode`, `recv.on`, `recv.root`, `simple.autostart_init`.

### Mở lần đầu: màn "Bắt đầu nhanh"
Khi chưa có cấu hình riêng và không có dịch vụ nào trả lời, GUI không hiện màn xám mà hiện hai lựa chọn:

```
+----------------------------------------------------------------+
|  Chào mừng đến với MySync                                      |
|  MySync giữ cho thư mục quan trọng của bạn luôn có một bản sao |
|  ở nơi khác ... Bạn không cần biết gì về kỹ thuật.             |
|                                                                |
|  [>] Dùng ngay, không cần cài đặt (khuyên dùng)                |
|      Chọn thư mục, chọn nơi lưu bản sao, xong.                 |
|  [>] Tôi đã có dịch vụ / cấu hình nâng cao                     |
|      Mở các màn hình chi tiết (bốn tab cũ).                    |
+----------------------------------------------------------------+
```
Nếu có dịch vụ đang chạy và trả lời, GUI vào thẳng chế độ nâng cao như trước. Menu **Cài đặt > Về chế độ Đơn giản** đưa bạn quay lại.

### Trình hướng dẫn 3 bước
1. **Thư mục nào cần được giữ bản sao?** Bấm *Chọn thư mục…*, gõ đường dẫn hoặc **kéo-thả một thư mục** từ Explorer vào cửa sổ. Lỗi hiện ngay dưới ô bằng lời dễ hiểu kèm đường dẫn/lỗi hệ thống nguyên văn (không thấy thư mục, là tệp chứ không phải thư mục, là cả ổ đĩa, nằm trong thư mục làm việc của MySync...).
2. **Bản sao sẽ được lưu ở đâu?**
   - *Một thư mục khác, ổ USB hoặc thư mục chia sẻ trong mạng*: chọn thư mục hoặc gõ `\\tên-máy\chia-sẻ`. GUI thử ghi một tệp nhỏ để chắc chắn ghi được.
   - *Một máy tính khác có cài MySync*: dán **mã ghép** (xem dưới), bấm *Gửi yêu cầu ghép*. Màn hình hiện **chuỗi xác nhận** (4 nhóm ký tự, chữ lớn), dòng "Đang chờ máy kia đồng ý…" có vòng quay và đếm ngược, nút *Huỷ*; quá 2 phút báo rõ "Hết thời gian chờ". Xong mới sang bước 3.
3. **Sẵn sàng.** Một câu tóm tắt ("MySync sẽ giữ thư mục "…" luôn có bản sao ở … Tệp tạm và tệp hệ thống được bỏ qua; tệp bị xoá hoặc ghi đè được cất vào thùng rác; mọi thay đổi được gửi đi ngay"). Bấm **Bắt đầu đồng bộ**: ghi cấu hình (kèm bản sao `.bak` nếu đã có), tạo khoá, khởi động bộ đồng bộ, bật *Tự chạy khi tôi đăng nhập* (mặc định bật sau lần đầu, tắt được ở màn Trạng thái) và chuyển sang màn Trạng thái.

### Màn Trạng thái gọn

```
+----------------------------------------------------------------+
|  Mọi thứ đã được đồng bộ                    (chữ lớn, xanh lá) |
|  Đã sao chép 128 tệp kể từ lúc mở.                             |
|  [==============>        ]  Đã xong 3 / 10 tệp   (khi bận)      |
|  Đang giữ bản sao của:                                         |
|  | Tài liệu  ->  E:\Sao-luu (thư mục)                       |   |
|  [Thêm thư mục] [Chế độ nâng cao]                              |
|  [x] Tự chạy khi tôi đăng nhập                                 |
|  [Chạy cả khi chưa đăng nhập máy (cài dịch vụ)]                |
|  +- Nhận file từ máy khác ---------------------------------+   |
|  | [ ] Cho phép máy khác gửi file vào đây                   |   |
|  +----------------------------------------------------------+  |
+----------------------------------------------------------------+
```
Câu lớn đổi theo tình hình, màu cũng đổi (icon khay đổi theo): *Đang đồng bộ 3 tệp…* (xanh dương, kèm tệp đang gửi và thanh tiến độ của đợt này), *Mọi thứ đã được đồng bộ* (xanh lá), *Chưa nối được tới nơi lưu: … MySync sẽ tự thử lại* (hổ phách), *Có lỗi: …* (đỏ, lỗi nguyên văn). Khi bộ đồng bộ chết và đang tự khởi động lại, có băng hổ phách "MySync vừa dừng đột ngột và đang tự khởi động lại (lần N)…"; hết số lần thử thì băng đỏ kèm những dòng cuối nó in ra.

- **Thêm thư mục**: chạy lại trình hướng dẫn, thư mục mới được **thêm** vào cấu hình hiện có.
- **Chế độ nâng cao**: nút bật/tắt hiện bốn tab cũ ngay bên dưới (cùng cấu hình `config.toml` của người dùng; Lưu ở tab Cấu hình sẽ nạp lại nóng).
- **Chạy cả khi chưa đăng nhập máy (cài dịch vụ)**: hỏi bằng lời thường, rồi chuyển từng bước (dừng bộ đồng bộ của bạn, chuyển cấu hình sang nơi an toàn của hệ thống, cài và chạy dịch vụ) qua hộp xin quyền quản trị; có chỉ báo động và tên bước đang chạy; lỗi hiện nguyên văn kèm bước hỏng, và hệ thống tự trả về như cũ nếu có thể (câu báo cho biết đã trả lại được hay chưa). Có chiều ngược **Quay lại chạy dưới tài khoản của tôi**. Khi đang chạy dịch vụ, nút *Thêm thư mục* tạm tắt (dùng chế độ nâng cao).

### Ghép hai máy bằng mã (không phải chép khoá)
**Máy NHẬN** (máy giữ bản sao): tại ô *Nhận file từ máy khác* bật *Cho phép máy khác gửi file vào đây*. Lần đầu GUI hỏi thư mục sẽ chứa file nhận được (mặc định `Documents\MySync-Nhan`), chạy bộ nhận, rồi mở **cửa sổ ghép 10 phút** (có đếm ngược). Màn hình hiện **mã ghép** một dòng (bắt đầu bằng `MSY1-`); mỗi lần bật là một mã MỚI có mật mã **dùng một lần** (hết hạn sau ít phút, có đếm ngược; nút *Tạo mã mới* và *Huỷ mã*): sau khi có một máy xin ghép (đồng ý hay không) mã cũ hết hiệu lực và màn hình nói rõ; máy gửi sai/thiếu mật mã hoặc dùng mã hết hạn/đã dùng chỉ thấy câu "Không ghép được…" chung và máy nhận không thấy hộp Đồng ý; nếu máy nhận cấm ghép bằng mã (`pairing = off`) công tắc báo "Máy này đang cấm ghép bằng mã" và không bật được. Mã ghép hiện ra, nút *Sao chép*, danh sách địa chỉ IP của máy này trong mạng (địa chỉ mạng nội bộ xếp đầu) và, nếu cần, nhắc mở tường lửa bằng lời thường. Khi máy kia xin ghép, hiện hộp thoại: **tên máy gửi + chuỗi xác nhận** lớn + "Hãy kiểm tra máy kia đang hiện đúng chuỗi này" + *Đồng ý* / *Từ chối*. Chỉ đồng ý khi hai chuỗi giống hệt nhau. Máy đã ghép vẫn gửi được sau khi cửa sổ ghép đóng; muốn ghép thêm máy bấm *Ghép thêm máy*.

**Máy GỬI**: ở bước 2 chọn "Một máy tính khác có cài MySync", dán mã. Mã hỏng (thiếu/sai ký tự) báo bằng lời thường. Không bước nào bắt sửa danh sách khoá hay chép khoá bằng tay; **mã ghép không bao giờ chứa khoá bí mật** và GUI không bao giờ hiện khoá bí mật.

### Quy ước đã áp dụng cho chế độ Đơn giản
Mọi chờ có chỉ báo động (BusyIndicator, vô hiệu hoá phần nội dung để không bấm chồng); lỗi nguyên văn trên băng đỏ/hổ phách, kể cả ngoại lệ trong luồng nền (`run_async`); tiếng Việt mặc định và tiếng Anh; không thao tác UI từ luồng nền (kết quả luôn qua `CallAfter`); không hiện ID trần (hiện tên watch + nơi lưu). Logic thuần nằm ở `gui/simple_model.*` (câu trạng thái, tiến độ, trạng thái từng bước của trình hướng dẫn, kiểm mã ghép, xếp địa chỉ IP), test headless ở `tests/test_gui_simple_viewmodel.cpp`.

### Tham số dòng lệnh thêm (kiểm thử)
`--user-dir=<thư mục>` · `--screenshot=<png>` `--shot-delay=<ms>` `--shot-exit` (chụp cửa sổ rồi thoát) · `--auto-src=<thư mục> --auto-dst=<thư mục>` (tự đi hết trình hướng dẫn bằng sự kiện giao diện thật) · `--auto-recv=<thư mục>` (bật nhận file vào thư mục đó). `--screenshot` chỉ vẽ lại chính cửa sổ MySync (PrintWindow), không chụp màn hình nên không lọt cửa sổ khác.

### Hạn chế của chế độ Đơn giản
- Một GUI (một bộ engine) cho mỗi người dùng; hai thư mục đồng bộ cùng lúc bởi hai tiến trình bị chặn bằng khoá `<thư mục>/__sync/engine.lock`.
- Đích kiểu "Máy tính khác" cần hai máy tới được nhau trực tiếp (cùng mạng/VPN, tường lửa cho cổng nhận). Chưa có xuyên NAT/relay.
- Chưa chạy giao diện thật trên Linux (xem "Hạn chế đã biết" ở trên); các nhánh Linux (autostart `.desktop`, `pkexec`) chỉ được dựng/kiểm bằng test headless.
- Đã chạy thật trên Windows 11: trình hướng dẫn (hai thư mục tạm, tệp sang được đích), bộ giám sát tự khởi động lại và báo "không tự khởi động lại được nữa" khi cấu hình hỏng, bật nhận file + mã ghép + hộp thoại duyệt + ghép xong với một máy gửi giả lập, "Thoát hẳn" dừng cả engine. **Chưa chạy thật** việc cài/gỡ dịch vụ từ nút "Chạy cả khi chưa đăng nhập máy" (cần quyền quản trị và đổi hệ thống; logic từng bước được kiểm bằng bộ giả trong test của lõi). Ô *Tự chạy khi tôi đăng nhập*: lần chạy thật đã thấy trình hướng dẫn ghi `HKCU\...\Run` (đã gỡ tay sau khi thử).
- Cửa sổ ghép cố định 10 phút, yêu cầu chờ duyệt cố định 2 phút (đặt trong lõi, không đổi từ GUI).
- Đổi thư mục nhận file hoặc tắt nhận không xoá các máy đã ghép (xoá ở chế độ nâng cao, tab *Ghép máy và Khoá*).

## README-snippet

### Dùng nhanh cho người mới
1. Dựng `mysync-gui` (xem "Giao diện đồ hoạ") và mở nó. Lần đầu bạn sẽ thấy màn **Bắt đầu nhanh**: chọn **Dùng ngay, không cần cài đặt**.
2. **Bước 1**: chọn (hoặc kéo-thả) thư mục cần giữ bản sao. **Bước 2**: chọn nơi lưu: thư mục khác, ổ USB, thư mục chia sẻ trong mạng (`\\máy\chia-sẻ`), hoặc một máy tính khác có MySync (dán mã ghép). **Bước 3**: bấm **Bắt đầu đồng bộ**.
3. Từ đó MySync chạy dưới biểu tượng ở khay hệ thống (xanh lá = đã xong, xanh dương = đang chép, vàng/đỏ = cần chú ý). Đóng cửa sổ chỉ thu xuống khay; chọn **Thoát hẳn** ở menu khay để dừng.
4. Gửi file sang máy khác: trên máy nhận bật **Cho phép máy khác gửi file vào đây**, sao chép **mã ghép**; trên máy gửi dán mã ở bước 2, so **chuỗi xác nhận** hai máy thấy giống nhau rồi bấm **Đồng ý** ở máy nhận.
5. Muốn chạy cả khi chưa đăng nhập máy: ở màn Trạng thái bấm **Chạy cả khi chưa đăng nhập máy (cài dịch vụ)**. Cần chỉnh sâu hơn: bấm **Chế độ nâng cao**.
