# MySync (C++) - thiết kế

Bản quyền (C) 2026 META.vn · Tác giả: Nguyễn Đức Sơn · GPL-2.0-or-later.

Tài liệu hợp đồng giữa các module. Agent viết module chỉ được đổi chữ ký trong include/mysync/*.h khi cập nhật tài liệu này.

## Cấu trúc
```
CMakeLists.txt        một lệnh build: cmake -S . -B build && cmake --build build && ctest --test-dir build
third_party/          monocypher (BSD-2/CC0), blake3 (CC0), lz4 (BSD-2) - đã vendor, ghim phiên bản
include/mysync/*.h    giao diện (header hợp đồng)
src/*.cpp             cài đặt; src/main.cpp = CLI
tests/                unit + integration (binary mysync_tests, đăng ký ctest)
docs/                 DESIGN.md, FEATURES.md, SECURITY.md
examples/             server.toml, client.toml, mysync.service
```
Namespace `mysync`. C++17. Chuỗi đường dẫn ngoài API luôn UTF-8; dùng std::filesystem (std::filesystem::u8path) bên trong. Đường dẫn tương đối trên dây luôn dùng '/' ngăn cách, Unicode NFC không bắt buộc, UTF-8 hợp lệ bắt buộc.

## Giao thức (mới, KHÔNG tương thích bản C# cũ - theo quyết định người dùng)
### Kênh bảo mật (secure_channel.h) - Noise_IK tự cài bằng Monocypher
Quyết định thiết kế (người dùng đã đồng ý định hướng): **khoá công khai ghim sẵn kiểu WireGuard/SSH, không CA, không PSK dùng chung**.
- Mỗi máy có một cặp khoá X25519 (`mysync keygen` ghi khoá bí mật hex 64 ký tự, Linux chế độ 0600, và in khoá công khai hex 64). Ghép máy = dán khoá công khai bên kia vào cấu hình (`server_key` ở client; `[[client]] public_key` ở server).
- Handshake theo mẫu Noise IK: `-> e, es, s, ss` / `<- e, ee, se`. Tên giao thức: `MySync_Noise_IK_25519_XChaCha20Poly1305_BLAKE2b` (BLAKE2b khoá làm HMAC trong HKDF; XChaCha20-Poly1305 của Monocypher, nên KHÔNG phải Noise chuẩn bit-for-bit và không thể tương tác với thư viện Noise ngoài). Client biết trước khoá server (server giả bị từ chối); server chỉ trả lời sau khi khoá tĩnh client được giải mã và nằm trong allowlist. DH cho kết quả toàn 0 bị từ chối. Forward secrecy từ khoá tạm.
- Tầng bản ghi: khung `[u32 độ dài BE][ciphertext][tag 16B]`, nonce = bộ đếm 64-bit mỗi chiều, AAD = 4 byte độ dài; bộ đếm chống phát lại/đảo thứ tự; khung tối đa 1 MiB + 16.
- Server: allow/deny IP (CIDR), `max_connections`, giới hạn xác thực thất bại theo IP, ACL theo client (`ro`/`rw`, `prefix`).
### Thông điệp (protocol.h) - payload mã hoá bên trong khung
Mỗi thông điệp: u8 type + các trường (u8/u16/u32/u64 big-endian, chuỗi = u16 len + UTF-8, blob = u32 len).
- HELLO{proto_ver=1, client_name, caps(bit0 lz4, bit1 delta)} / HELLO_OK{server_caps, max_chunk}
- LIST_REQ{prefix} -> LIST_ENTRY* / LIST_END : server trả (path,size,mtime_ns,hash32,is_dir) toàn cây dưới thư mục gốc (trừ __sync).
- OFFER{path, size, mtime_ns, hash32, mode_flags} -> server trả
  SKIP (đã có nội dung y hệt - cùng hash; chỉ cập nhật mtime nếu khác) | NEED_FULL | NEED_DELTA{block_size, n, sigs[n]{weak u32, strong16}}
- DATA{seq, flags(bit0 lz4), bytes} * ; ENDFILE{hash32} -> server ghi vào tệp tạm cùng thư mục (.mysync-tmp-<rand>), tính BLAKE3 khi nhận, so với hash khai báo + hash tính lại; khớp thì fsync + set mtime + rename nguyên tử; trả FILE_OK / FILE_ERR{code}.
- DELTA_OPS (thay DATA khi NEED_DELTA): chuỗi COPY{block_idx} | LITERAL{bytes}; server dựng lại từ tệp cũ -> tệp tạm -> kiểm hash như trên.
- DELETE{path} (chuyển vào __sync/__trash/<timestamp>/..., không xoá thật nếu config trash=true; upload ghi đè tệp có sẵn cũng chuyển bản cũ vào đó bằng rename trước khi đổi tên bản mới) | RENAME{from,to} | MKDIR{path}
- PING/PONG, BYE.
Pipeline: client giữ N kết nối song song (config `connections`, mặc định 4), mỗi kết nối xử lý tuần tự nhiều tệp; tệp nhỏ được OFFER theo lô (OFFER không chờ trả lời từng cái: gửi tới `window` OFFER rồi đọc phản hồi) để tránh RTT.
Giới hạn: kích thước tệp tối đa theo config; server từ chối đường dẫn xấu (xem pathsafe.h) với PATH_DENIED.

## Module (include/mysync/)
| Header | Nội dung | Ghi chú |
|---|---|---|
| util.h, net.h, hash.h | HỢP ĐỒNG, đã có | util/log/random, Socket, BLAKE3 |
| pathsafe.h | `std::filesystem::path safe_join(root, rel_utf8)` ném Error nếu: rỗng, tuyệt đối, có ".." sau chuẩn hoá, ổ đĩa/UNC, NUL, tên dành riêng Windows (CON,NUL,COM1..), ký tự cấm, kết thúc bằng dấu cách/chấm trên Windows, vượt root sau khi resolve symlink của thư mục cha. `bool is_internal_dir(rel)` (`__sync`). `std::string normalize_rel(...)` | |
| filter.h | `Filter` dựng từ FilterConfig: include (đuôi/glob/regex), exclude (chuỗi con / glob / regex), size_min/max, mtime_min/max (tương đối "7d" hoặc tuyệt đối), bỏ tệp tạm (`~ $ # .tmp`, `.mysync-tmp-*`), bỏ `__sync`. `bool match(rel_path, size, mtime_ns)`. Regex áp lên đường dẫn tương đối '/' (KHÁC bản cũ: bản cũ áp lên full path) | |
| config.h | Cấu trúc cấu hình + `load_config(path)` (parser TOML-subset tự viết: [bảng], [[mảng bảng]], chuỗi, số, bool, mảng; chú thích #). Báo lỗi có số dòng. | xem FEATURES.md |
| index.h | `IndexCache` (path -> size, mtime_ns, hash) lưu tệp nhị phân `<state_dir>/index-<id>.bin` ghi nguyên tử; `scan_tree(root, filter, cache, threads)` song song, chỉ băm tệp khi size/mtime khác cache; trả danh sách FileMeta | |
| secure_channel.h | `SecureChannel` (handshake client/server, send_msg/recv_msg) | |
| protocol.h | Mã hoá/giải mã thông điệp | |
| delta.h | chữ ký khối (rolling adler32-style + hash_block16), `compute_delta`, `apply_delta` | tệp >= 1 MiB mới dùng |
| compress.h | LZ4 khung `lz4_compress/decompress` với giới hạn kích thước giải nén | |
| server.h | `Server`: nhận kết nối, giới hạn max_connections, allow/deny IP (CIDR), thư mục gốc, trash | |
| client.h | `SyncClient`: `sync_tree`, `sync_file`, `remove`, `rename`; nhiều đích; giới hạn băng thông (token bucket) | |
| watcher.h | `Watcher(root, cb, opts)`: ReadDirectoryChangesW (Windows, overlapped, đệ quy) / inotify (Linux, tự thêm watch thư mục mới); debounce `quiet_ms` theo từng tệp + chờ tệp hết bị khoá; gộp sự kiện; overflow => yêu cầu quét lại; quét dự phòng định kỳ | |
| scheduler.h | giờ đồng bộ cố định ("01:00"), khoảng lặp | |
| service.h | `install/uninstall/start/stop` Windows SCM + `run_as_service`; Linux: sinh/cài unit systemd, `sd_notify` tuỳ chọn | |
| main.cpp | CLI | |

## CLI
```
mysync server  -c server.toml [--foreground]
mysync client  -c client.toml [--once | --watch]   (mặc định: theo mode trong cấu hình)
mysync keygen  [-o key.hex]
mysync hash    <file>
mysync service install|uninstall|start|stop  -c <config> --role server|client [--name N]
mysync version
```
Chạy độc lập: lệnh ở foreground, Ctrl+C / SIGTERM dừng sạch. Service: Windows SCM hoặc systemd (`Type=notify` hoặc simple).

## Hạn mức, thùng rác và quyền tệp của máy chủ

- **Theo từng client** (`[[client]]`): `max_sessions` (mặc định 4) — phiên thứ N+1 của cùng client bị từ chối bằng
  `FILE_ERR(BUSY)` rồi đóng, client khác không bị ảnh hưởng; `max_write_bytes_per_hour` (mặc định 50GB, 0 = không hạn) —
  cửa sổ trượt 1 giờ (60 xô theo phút) đếm byte thực sự ghi; OFFER mà chắc chắn vượt hạn mức bị từ chối ngay
  (`FILE_ERR(BUSY)`, log cảnh báo), vượt giữa chừng thì tệp đang nhận bị huỷ. Tệp trùng nội dung (SKIP) không tốn hạn mức;
  byte của lần truyền hỏng không được hoàn lại (tính thận trọng).
- **Thùng rác** (`[server] max_trash_bytes`, mặc định 10GB, 0 = không hạn): tổng dung lượng `__sync/__trash` được đếm
  lười (quét một lần khi cần, sau đó cộng trừ). Trước khi chuyển một mục vào thùng, nếu tổng sẽ vượt hạn mức thì xoá các
  thư mục mốc thời gian CŨ NHẤT (tên là mốc UTC nên sắp theo tên là sắp theo tuổi) cho tới khi đủ chỗ. Mục đơn lẻ lớn hơn
  hạn mức thì xoá/ghi đè bị từ chối (`FILE_ERR(TOO_LARGE)` "trash limit") — dữ liệu cũ giữ nguyên, không bao giờ vừa
  xoá vừa mất. Mọi thao tác trên thùng rác đi qua một khoá, nên hai phiên không dọn lẫn nhau.
- **Ghi đè bằng upload**: trước khi rename bản mới đè lên tệp có sẵn, bản cũ được rename vào thùng rác (cùng volume nên
  không sao chép); nếu rename bản mới hỏng thì bản cũ được trả về chỗ cũ. `LocalTarget` làm tương tự (thùng rác của đích,
  chưa có hạn mức dung lượng).
- **`max_file_size`** mặc định 10GB; đặt tường minh 0 vẫn là không giới hạn (có cảnh báo trong log lúc nạp cấu hình).
- **Quyền tệp (Linux/macOS)**: `file_mode` (mặc định 0640, không bit thực thi) và `dir_mode` (0750) áp cho mọi tệp /
  thư mục máy chủ và `LocalTarget` tạo ra (`[[watch.target]]` cục bộ có khoá `file_mode`/`dir_mode` riêng); dùng
  `fchmod`/`chmod` nên không phụ thuộc umask. Tệp tạm được tạo 0600. Windows bỏ qua.
- **Tên nguy hiểm trong `pathsafe`**: chặn `COM¹ COM² COM³ LPT¹ LPT² LPT³` (mọi kiểu chữ, có/không đuôi) trên mọi nền
  tảng; `__sync` và `.mysync-tmp-` được so sánh sau khi gấp chữ đơn giản, gồm U+017F (ſ → s) và U+212A (K Kelvin → k).

## Ghép máy bằng mã (chế độ Đơn giản)

Mục tiêu: người không chuyên nối hai máy mà không phải chép khoá, không cần quyền quản trị. Mã nguồn: `include/mysync/simple/pair_code.h`, `pairing.h`; phía máy chủ trong `server.cpp` (`serve_unpaired`) và `gui_daemon.cpp` (`pair_approve`, `pair_op`).

### Mã ghép (một dòng người dùng sao chép)

`MSY1-` + base32 Crockford (bỏ I L O U, không phân biệt hoa thường, bỏ qua `-` và khoảng trắng khi nhập; O đọc là 0, I/L đọc là 1), chia nhóm 5 ký tự, của payload:

```
version(1)=2 | khoá công khai máy nhận (32) | TOKEN dùng một lần (16) | cổng (2, big-endian) | độ dài host (1) | host (1..100) | checksum (4)
checksum = 4 byte đầu của BLAKE2b-256 trên mọi byte đứng trước
```

Host là IPv4 / IPv6 (không có zone) / tên DNS (nhãn `[A-Za-z0-9-]`, ≤ 63). Mã **không có trường nào cho khoá bí mật**. Token là 128 bit ngẫu nhiên do máy nhận tạo mỗi lần người dùng bật chế độ ghép; daemon chỉ giữ BĂM BLAKE2b của nó (không ghi log, không đưa vào trạng thái IPC; chỉ GUI nhận một lần trong câu trả lời `PAIR_MODE_ON` qua kênh chỉ-người-dùng để dựng mã). `decode` ném lỗi chung (không lặp lại nội dung đã nhập) khi: sai tiền tố hoặc phiên bản, ký tự ngoài bảng chữ, độ dài sai, bit đệm khác 0, checksum sai, host / cổng vô lý, thừa byte. Có vector kiểm cố định trong `tests/test_simple_core.cpp`, fuzz giải mã và kiểm "đổi một ký tự bất kỳ thì bị phát hiện".

### Chuỗi xác nhận (SAS)

`SAS = BLAKE2b("MySync-SAS-v1" || khoá_công_khai_máy_gửi || khoá_công_khai_máy_nhận)`, lấy 80 bit đầu, 16 ký tự Crockford, hiển thị `ABCD-EFGH-JKMN-PQRS`. Hai bên tự tính từ hai khoá công khai nên hiện cùng một chuỗi; người dùng so bằng mắt trước khi bấm Đồng ý. Nếu có kẻ chen vào giữa thì khoá của một trong hai phía khác đi và hai chuỗi khác nhau.

### Chế độ "đang ghép" trên máy nhận

- **Token một lần**: một khoá lạ chỉ đi tiếp khi `PAIR_REQUEST` (bên trong kênh Noise đã mã hoá, đã xác thực máy nhận nhờ khoá ghim) mang đúng token (so băm bằng `ct_equal`). Sai token thì phiên bị đóng không báo lý do và tính như xác thực sai của IP đó; token sai không làm hộp 'Đồng ý' hiện. Token bị huỷ ngay khi một yêu cầu dùng nó (dù sau đó được duyệt, bị từ chối hay hết hạn), khi tắt chế độ ghép, hoặc hết 10 phút; bật lại tạo token mới. Hết token thì khoá lạ bị từ chối ngay ở bắt tay, nên mỗi lần bật chỉ ghép được một máy (`BUSY` chỉ còn xảy ra khi token đúng nhưng vượt giới hạn tốc độ).
- Mặc định **tắt**. Chỉ bật khi người dùng bấm (qua kênh điều khiển cục bộ `PAIR_MODE_ON`), và chỉ khi daemon được khởi động với `--allow-pairing` **và** cấu hình có `[server] pairing = "on-demand"` (mặc định `off`: dịch vụ không có đường nào vào chế độ này).
- Tự tắt sau 10 phút (`kPairWindowSeconds`); đếm ngược lấy được qua IPC (`PairInfo::seconds_left`). Tắt tay hoặc hết giờ thì mọi yêu cầu đang chờ bị huỷ.
- Trong chế độ này `SecureChannel::server` cho một khoá **chưa có** trong allowlist đi qua bắt tay Noise, nhưng phiên được đánh dấu "chưa ghép" (`serve_unpaired`): nó **không** có `Policy`, `Tree`, chỗ phiên, hạn mức. Chỉ ba thông điệp được chấp nhận: `PAIR_REQUEST{tên}`, `PAIR_POLL`, `BYE`. Mọi thứ khác (HELLO, OFFER, LIST ...) nhận `PAIR_ERROR` rồi đóng, và tính một lần xác thực hỏng cho IP đó. Thông điệp ghép có byte đầu ≥ 0x40, không thể trùng `proto::MsgType`.
- Khi chế độ tắt, khoá lạ bị từ chối ngay ở bắt tay y như trước khi có tính năng này.

### Giới hạn

| Giới hạn | Giá trị |
|---|---|
| yêu cầu chờ duyệt cùng lúc | 1 (yêu cầu thứ hai nhận `BUSY`) |
| hạn dùng một yêu cầu | 2 phút |
| yêu cầu mới | 3 / phút / IP, 10 / phút toàn cục (vượt thì `BUSY`) |
| bắt tay của khoá lạ | 12 / phút / IP, 40 / phút toàn cục |
| một khoá hỏi quá 4 lần / phút | bị chặn 10 phút |
| khoá bị từ chối | bị chặn 10 phút (chặn ngay ở bắt tay) |
| phiên ghép đang sống | tối đa 4 cùng lúc, 2 mỗi IP, tính RIÊNG (không ăn vào hạn mức kết nối chưa xác thực của máy khách thường); mỗi phiên sống tối đa ~135 s |

Tên hiển thị của máy gửi: ≤ 40 ký tự UTF-8, không điều khiển, không ký tự định dạng (zero-width, đảo chiều, dấu phân dòng, tag); `clean_display_name` từ chối cả tên nếu có một ký tự xấu, không cố "sửa".

### Duyệt

`PAIR_APPROVE` (từ GUI, người dùng đã thấy tên và SAS) làm `ServerDaemon::pair_approve`: mở cấu hình người dùng bằng `ConfigEditor`, thêm `[[client]]` (tên làm duy nhất, `public_key`, `access = "rw"`, `prefix = from-<tên>` đã làm sạch), ghi nguyên tử (có `.bak`), nạp lại cấu hình đã kiểm tin cậy và `Server::apply_config` ngay (không qua giãn cách reload 2 s), rồi trả `PAIR_OK` cho máy gửi. `prefix` do `safe_pair_prefix` tạo: một thành phần đường dẫn `[a-z0-9._-]`, bỏ dấu tiếng Việt, không `.`/`..`/dấu chấm đầu, ≤ 48 byte, không trùng prefix đang dùng và **không trùng thư mục đã có** trên đĩa (tránh giao nhầm thư mục của máy khác). Máy gửi sau đó kết nối bình thường bằng khoá của nó. `PAIR_DENY` chặn khoá 10 phút.

### Bên gửi

`PairingClient` kiểm mã, đọc / tạo khoá của mình, kết nối `host:cổng` với **khoá máy chủ ghim từ mã** (Noise IK: máy không giữ khoá đó không trả lời được), gửi `PAIR_REQUEST`, tính SAS cục bộ để hiện, hỏi lại mỗi 2 s tối đa ~125 s, huỷ được bất cứ lúc nào. Mọi lỗi (không tới được, chế độ ghép tắt, mã không phải của máy đó, bị chặn) cho **cùng một thông điệp chung**, không phân biệt, để máy gửi không dò được gì.

### Mối đe doạ và điều không được bảo đảm

| Mối đe doạ | Cách chặn |
|---|---|
| Người lạ trong mạng gửi yêu cầu khi cửa sổ ghép đang mở | Không có quyền gì trước khi duyệt; chỉ 1 yêu cầu chờ; giới hạn tốc độ; người nhận thấy tên + SAS + IP và có thể từ chối (chặn 10 phút); cửa sổ chỉ mở 10 phút khi người dùng chủ động bật |
| Kẻ chen giữa (MITM) giả máy nhận | Máy gửi ghim khoá máy nhận lấy từ mã; không có khoá bí mật đó thì không hoàn tất bắt tay IK |
| Kẻ chen giữa giả máy gửi | Khoá tĩnh của máy gửi được mã hoá trong bắt tay và gắn với SAS; kẻ chen giữa phải dùng khoá khác, SAS hai bên sẽ khác nhau |
| Mã bị lộ (chụp màn hình, chia sẻ nhầm) | Mã chỉ chứa khoá công khai và địa chỉ, không cho quyền gì; kẻ cầm mã vẫn chỉ gửi được yêu cầu và phải được duyệt |
| Làm ngập yêu cầu | giới hạn trên; yêu cầu thừa nhận `BUSY` mà không tốn bộ nhớ lâu dài (bảng đếm có trần) |
| Tên độc hại (điều khiển, đảo chiều, `..`) | `clean_display_name` từ chối; thư mục dùng `safe_pair_prefix` |

Không được bảo đảm: (1) nếu người dùng bấm Đồng ý mà không so SAS thì không có gì ngăn một yêu cầu từ kẻ lạ trong cửa sổ ghép được chấp nhận (mọi cơ chế "bấm xác nhận" đều vậy); (2) mã đi qua kênh nào thì kênh đó thấy địa chỉ và khoá công khai; (3) chặn theo IP không chống được kẻ có nhiều địa chỉ, giới hạn toàn cục mới là chốt; (4) không chống kẻ đã kiểm soát máy nhận hay máy gửi; (5) địa chỉ trong mã phải tới được từ máy gửi (NAT, tường lửa là việc của người dùng); (6) ghép xong, quyền là đọc-ghi trong một thư mục riêng — thu hồi bằng cách xoá `[[client]]` tương ứng.

## Chế độ Đơn giản: engine con, khoá thư mục, nâng lên dịch vụ

- **Cấu hình người dùng** ở `%APPDATA%\MySync\` / `~/.config/mysync/` (`UserPaths`): `config.toml`, `server-user.toml`, `key`, `receiver.key`, `state/`, `receiver-state/`, `log/`. Thư mục và khoá chỉ người dùng đó truy cập (Windows: DACL có bảo vệ, chỉ người dùng + SYSTEM; Linux 0700/0600). Tin cậy cấu hình đi nhánh "tài khoản thường, tệp của chính mình" (`need_strict_trust` = false).
- **Supervisor** (`user_engine.h`): GUI chạy `mysync run -c ... --user-mode --exit-on-stdin-eof` (và `--allow-pairing` cho bên nhận) làm TIẾN TRÌNH CON dưới quyền người dùng; không qua shell, không thừa handle, ẩn cửa sổ console. Windows: Job Object `KILL_ON_JOB_CLOSE`; Linux: `PR_SET_PDEATHSIG`. Dừng sạch bằng cách đóng stdin của engine (engine thoát sạch, lưu chỉ mục), quá hạn mới ép buộc. Engine chết ngoài ý muốn thì khởi động lại sau 1, 2, 5, 10, 30, 60 s (rồi 60 s); sau 5 lần liên tiếp chết trong 10 s thì ngừng thử và báo `last_error` nguyên văn (cuối stderr/stdout). Đóng cửa sổ về khay không động đến engine.
- **Kênh điều khiển chỉ người dùng** (`IpcServerOptions::user_only`): pipe Windows có DACL chỉ chứa người dùng hiện tại (không SYSTEM, không Administrators, và vẫn từ chối đăng nhập mạng); Linux thư mục 0700 + socket 0600.
- **Khoá chống chạy đôi**: mỗi engine giữ khoá hệ điều hành độc quyền trên `<thư mục>/__sync/engine.lock` cho TỪNG watch trước khi watch (Windows `LockFileEx` một byte xa phần chữ, Linux `flock`); chết thì hệ điều hành tự nhả. Bị giữ bởi tiến trình khác (kể cả dịch vụ) thì engine **không watch và không đồng bộ** thư mục đó, báo "folder 'X' is already being synchronised by another process (PID n)" trên trạng thái đích, thử lại mỗi 5 s; `run --once` thất bại hẳn. Nguồn chỉ-đọc không tạo được tệp khoá thì chạy như cũ và ghi cảnh báo (không bảo đảm độc quyền). Mỗi người dùng chỉ một GUI (một bộ engine) nhờ `InstanceLock`.
- **Nâng lên dịch vụ** (`service_upgrade.h`): kiểm tiền điều kiện → dừng engine người dùng (chờ nhả khoá) → `mysync service migrate-from-user --user-config <đường dẫn>` chạy NÂNG QUYỀN (kiểm tệp là tệp thường thuộc đúng người gọi, phân tích được; chép cấu hình và khoá sang `%ProgramData%\MySync\<tên>\` ACL chỉ Administrators+SYSTEM, hoặc `/etc/mysync` + `/var/lib/mysync` của root; ghi lại đường dẫn khoá/state/log; kiểm lại bằng đúng luật tin cậy của dịch vụ) → `service install` (qua `validate_install_inputs`, chạy bằng LocalSystem để đọc được thư mục người dùng, cho SID người dùng vào `[control] allow`) → start → GUI theo dõi dịch vụ. Chiều ngược: dừng, gỡ dịch vụ, bật lại engine người dùng (cấu hình người dùng chưa từng bị sửa nên không cần chép về). Bước nào hỏng cũng hoàn tác theo thứ tự ngược (gỡ dịch vụ, bật lại engine người dùng), không để hai engine, không mất cấu hình; bước hoàn tác hỏng được báo nguyên văn.

### Vòng sửa sau rà soát độc lập Chế độ Đơn giản

- **Di chuyển cấu hình sang dịch vụ không tin nội dung của người dùng** (`migrate-from-user`, chạy nâng quyền). Dịch vụ chạy bằng tài khoản mạnh hơn người dùng, nên tiến trình nâng quyền tự kiểm lại: mở tệp cấu hình MỘT lần và kiểm ngay trên handle (không phải liên kết, tệp thường, đúng chủ sở hữu); từ chối thư mục nguồn / đích nằm trong thư mục hệ thống (`SystemRoot`, `ProgramData`, `Program Files`, `/etc`, `/usr`, `/root`...) hoặc trong hồ sơ của người dùng khác, hoặc có liên kết / junction trên đường đi; khoá phải nằm trong thư mục MySync của chính người dùng; khoá riêng của từng đích bị từ chối; `control_allow` / `control_group` do người dùng viết bị XOÁ (quyền điều khiển dịch vụ do quản trị đặt lúc cài). Thư mục đích (`C:\ProgramData\MySync`, `/etc/mysync`, `/var/lib/mysync`) nếu đã tồn tại phải đã thuộc quản trị, không bị chiếm lại. `PKEXEC_UID` chỉ được tin khi tiến trình cha là `pkexec`; `SUDO_UID` và `PKEXEC_UID` mâu thuẫn thì từ chối.
- **Bản tóm tắt trước hộp UAC**: `summarize_user_config` trả nguồn, đích, vân tay khoá, tài khoản chạy dịch vụ, lời cảnh báo và danh sách `problems` (không rỗng = sẽ bị từ chối); `check_preconditions` dùng nó nên lỗi hiện trước khi hỏi quyền.
- **Gỡ bản sao**: `mysync service migrate-from-user --remove --name N` xoá cấu hình, `.bak` và khoá đã sao; `DowngradeOptions::remove_service_copy` gọi nó sau khi chuyển ngược thành công (lỗi chỉ ghi vào nhật ký). Huỷ hộp UAC ở bước chuyển không còn kích hoạt hoàn tác gây hộp thứ hai.
- **Khoá thư mục (`engine_lock`)**: `__sync` hay `engine.lock` là liên kết / junction / thư mục bị từ chối thẳng (POSIX: `openat` từ descriptor của thư mục với `O_NOFOLLOW`; Windows: `FILE_FLAG_OPEN_REPARSE_POINT` rồi kiểm trước và sau khi mở; bỏ `FILE_SHARE_DELETE`). Chỉ `LockNotPossible` (thư mục chỉ-đọc / không ghi được) mới cho engine chạy không khoá, kèm cảnh báo; mọi lỗi khác trên thư mục ghi được thì engine KHÔNG đụng vào thư mục đó và báo lỗi nguyên văn. Thùng rác của `LocalTarget` và của máy chủ cũng từ chối `__sync` / `__trash` là liên kết.
- **Kênh chỉ người dùng, phía GUI**: `ControlClient::require_current_user_only()` — Windows chỉ chấp nhận tiến trình / chủ pipe là đúng SID người dùng hiện tại (không SYSTEM, LocalService, Administrators khác); POSIX chấp nhận socket do đúng euid này sở hữu.
- **Duyệt ghép máy khi cửa sổ vừa đóng**: bản duyệt đã ghi vào allowlist thì bên gửi nhận `OK` (không bị báo "hết hạn"); tắt chế độ ghép / hết cửa sổ chỉ huỷ yêu cầu ĐANG CHỜ, không xoá phán quyết đã có.

### Đợt 7: danh sách cho phép đường dẫn, băm đã duyệt, duyệt ghép nguyên tử

- **Danh sách cho phép (`migrate-from-user`)**: mọi `watch.path` / đích cục bộ, sau khi chuẩn hoá thật (symlink, junction, tên 8.3, `\\?\` được giải; phần chưa tồn tại ghép vào thư mục cha tồn tại sâu nhất), phải nằm TRONG hồ sơ của chính người dùng, hoặc trong một thư mục họ xác nhận rõ (`--allow-root`, lặp được; GUI lấy từ `MigrationSummary::needs_confirmation` sau khi người dùng đồng ý). So theo thành phần đường dẫn, không phân biệt hoa thường trên Windows. Không bao giờ được phép, kể cả khi nằm trong `--allow-root`: gốc ổ đĩa và `/`, thư mục hệ thống (`/etc /usr /var /opt /srv /mnt /boot /root ...`, `SystemRoot`, `Program Files*`, `ProgramData`), thư mục chứa mọi hồ sơ (`C:\Users`, `/home`) và hồ sơ người dùng khác; `--allow-root` cũng không thể là những thư mục đó. Đường UNC luôn nằm ngoài (cần `--allow-root` tường minh). Mọi lỗi nêu đường dẫn vi phạm và đường dẫn thật nó dẫn tới.
- **Băm đã duyệt**: `summarize_user_config` trả `config_hash` / `key_hash` (BLAKE3) của đúng các byte đã đọc; `ServiceController` truyền `--expect-hash` / `--expect-key-hash` (bắt buộc). Tiến trình nâng quyền mở tệp một lần, kiểm trên handle, đọc vào bộ nhớ, so băm (lệch: "the configuration was changed after you saw the summary", không làm gì), rồi chỉ phân tích từ chính bộ đệm đó; khoá cũng vậy. Phần quyết định trước khi ghi nằm trong `plan_migration` (kiểm thử được không cần quyền quản trị).
- **Duyệt ghép nguyên tử**: `peer_add` → nạp lại → kiểm tin cậy → `apply_config`. Bất kỳ bước nào sau `peer_add` hỏng thì `peer_remove` (không thu hồi), yêu cầu vẫn đang chờ, người nhận thấy lỗi nguyên văn, người gửi chưa được báo "đã duyệt". Từ khi `apply_config` thành công là đã cam kết và chỉ tiến lên (cửa sổ ghép đóng giữa chừng không làm mất kết quả). Nếu cả bước hoàn tác cũng hỏng, thông báo nói rõ và `deny` sau đó gỡ peer ngay (`set_revoke_handler`: `peer_remove` + `apply_config`, nên phiên đang mở của khoá bị cắt tức thì, không chờ trình theo dõi `peers.d`).
- **Vì sao không kiểm "cha là pkexec"**: `pkexec` `execv` thẳng chương trình đích nên tiến trình cha của nó không phải `pkexec`; kiểm đó vừa sai vừa vô nghĩa. Cách đúng (`resolve_invoking_uid`): `pkexec` đặt `PKEXEC_UID` và làm sạch môi trường, nên biến chỉ được tin trong một tiến trình ĐANG là root (uid và euid đều 0; người dùng thường không thể đã đi qua `pkexec`); số phải hợp lệ (cùng bộ phân tích chặt như `uid:`), khác 0, bằng `SUDO_UID` nếu có (mâu thuẫn thì từ chối), bằng chủ sở hữu tệp cấu hình đang di chuyển; `/proc/self/loginuid` lệch chỉ là cảnh báo.
- **Kiểm thử không treo**: `mysync_tests` có đồng hồ canh chừng (mặc định 300 s mỗi test, `MYSYNC_TEST_TIMEOUT_S` đổi được): test nào treo thì in `[HANG] <tên>` và kết thúc với mã 4. Luồng phụ trong test ghép máy được `JoinGuard` join trên mọi đường thoát.

### Đợt 7b: dịch vụ của chế độ Đơn giản chạy bằng CHÍNH tài khoản người dùng

**Hai kiểu cài dịch vụ, không lẫn nhau**
1. *Do quản trị cài bằng dòng lệnh* (`mysync service install`, máy chủ-máy chủ, dịch vụ hệ thống): tài khoản dịch vụ do quản trị chọn, cấu hình do quản trị sở hữu, tập tin cậy `--trust-writer`. KHÔNG đổi.
2. *Do nút "Chạy cả khi chưa đăng nhập máy" của GUI* (`--user-service`): dịch vụ chạy bằng đúng tài khoản người dùng, không SYSTEM, không root ở thời gian chạy. Chỉ bước CÀI cần quyền cao (UAC / pkexec).

**Mô hình tin cậy mới.** Daemon của kiểu 2 không mạnh hơn người dùng: mọi tệp nó đọc và ghi là của người dùng, nên cấu hình của người dùng không thể dùng để leo thang. Danh sách cho phép đường dẫn và băm đã duyệt (đợt 7) vẫn có, nhưng giờ chỉ còn vai trò chống cấu hình sai và chống đổi nội dung giữa lúc xem và lúc cài, không còn là hàng rào duy nhất. Dữ liệu dịch vụ (cấu hình, khoá, state, log) nằm trong một thư mục thuộc chính người dùng: Windows `%ProgramData%\MySync\<dịch-vụ>\` với ACL người dùng + SYSTEM + Administrators (các thư mục cha chỉ quản trị ghi); Linux `/var/lib/mysync/<dịch-vụ>/` chủ sở hữu người dùng, mode 0700 (cha của root, 0755 để người dùng đi qua được). Thư mục đã tồn tại mà không đúng chủ thì bị từ chối, không chiếm lại. Tên dịch vụ: `mysync-<tên>` (`user_service_name`, chỉ `[a-z0-9_-]`).

**Linux.** Unit riêng `mysync-<user>.service`: `User=` và `Group=` là chủ thư mục (uid gốc do `resolve_invoking_uid` xác định, uid 0 bị từ chối), giữ nguyên hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices`, `RestrictSUIDSGID`...), `ReadWritePaths` chỉ gồm state, thư mục log, các thư mục nguồn (để engine đặt `__sync/engine.lock`) và đích cục bộ, `RuntimeDirectory=mysync-<user>` mode 0700 cho socket điều khiển (socket 0600, người dùng + root). `SystemdOptions` (group, runtime_dir, mode) có kiểm chống chèn.

**Windows.** Dịch vụ đăng nhập bằng tài khoản người dùng nên cần MẬT KHẨU của tài khoản đó (tài khoản Microsoft dùng mật khẩu tài khoản, KHÔNG phải mã PIN Windows Hello). GUI hỏi một lần; mật khẩu đi tới bước nâng quyền qua một named pipe riêng (`PasswordChannel`): tên ngẫu nhiên, một thể hiện (`FILE_FLAG_FIRST_PIPE_INSTANCE`, không ai chiếm trước được tên), `PIPE_REJECT_REMOTE_CLIENTS`, DACL = người dùng + SYSTEM + Administrators. Tên pipe và nonce 128 bit nằm trên dòng lệnh nhưng không phải bí mật; mật khẩu thì không bao giờ nằm trên dòng lệnh, biến môi trường, nhật ký hay tệp. Máy chủ pipe chỉ nói chuyện với tiến trình của CHÍNH người dùng đó và chứng minh được nonce (so bằng `ct_equal`; sai thì bị cắt, tối đa vài lần); máy khách (bước nâng quyền) kiểm tiến trình đứng sau pipe cũng chạy bằng người dùng đó trước khi gửi nonce. Mật khẩu được gửi MỘT lần rồi pipe bị xoá (không phát lại được); cả hai đầu xoá bộ nhớ ngay (`SecretString`, `SecureZeroMemory`). Bước nâng quyền: (1) `LogonUser` kiểm mật khẩu và báo ngay nếu sai bằng câu dễ hiểu, không chứa mật khẩu; tài khoản không mật khẩu bị từ chối và khuyên dùng chế độ chạy khi đăng nhập; (2) `LsaAddAccountRights(SeServiceLogonRight)` cho đúng SID đó và chỉ khi còn thiếu; (3) `CreateService` với tài khoản + mật khẩu (khởi động trễ, hồi phục như cũ).

**Đổi mật khẩu.** Khi người dùng đổi mật khẩu Windows, dịch vụ dừng với lỗi đăng nhập 1069; `ServiceState::needs_password_update` báo điều đó để GUI hiện băng hướng dẫn, rồi `ServiceAction::SetPassword` (`mysync service set-password`, cùng kênh riêng, `ChangeServiceConfig`) đặt mật khẩu mới.

**Giới hạn còn lại.** Mật khẩu nằm trong LSA secrets do SCM giữ (đặc tính của dịch vụ Windows đăng nhập bằng tài khoản); đổi mật khẩu phải cập nhật dịch vụ; tài khoản không mật khẩu và một số chính sách miền không chạy được dịch vụ; bước nâng quyền chỉ phục vụ đúng người dùng đã yêu cầu (đăng nhập quản trị khác qua UAC bị từ chối, nêu rõ lý do). Khoảng TOCTOU hẹp còn lại ở kiểm liên kết (xem dưới).

**Không theo liên kết (lớp thứ hai, ở engine).** Mỗi lần quét đầy đủ, mỗi lần thử watch lại, mỗi kết nối tới đích cục bộ và khoá thư mục đều từ chối nếu BẤT KỲ thành phần nào của gốc nguồn / gốc đích là liên kết (symlink, junction, mount point; trên Windows chỉ các reparse point đổi hướng tên, không tính placeholder OneDrive). Lỗi hiện trong trạng thái của đích (`last_error`: "... is a link (symbolic link or junction); links are not followed"). Không hỗ trợ junction hợp pháp: bị từ chối và báo rõ. Giới hạn: đây là kiểm tra, không phải sandbox; giữa lúc kiểm và lúc dùng vẫn có khoảng hẹp. Riêng khoá thư mục dùng `openat` + `O_NOFOLLOW` từ descriptor của thư mục (POSIX) nên không đua được `__sync`.

**Sửa thêm.** Allowlist: từ chối `\\.\`, `\\?\GLOBALROOT`, `\\?\Volume{`, UNC về chính máy này (`localhost`, `127.*`, `::1`, tên máy) và chia sẻ quản trị `$`; UNC bình thường cần `--allow-root` tường minh; thư mục nhà và thư mục hệ thống lấy từ API (Windows `SHGetKnownFolderPath`, `GetSystemDirectory`; Linux `getpwuid_r`), thư mục nhà chỉ được tính khi nằm DƯỚI thư mục chứa các hồ sơ và không chứa / không nằm trong thư mục cấm; `homes_root` là cha thật của thư mục nhà (và `/home` vẫn cấm cho người khác). `deny()` không còn nuốt lỗi dọn dẹp: yêu cầu vẫn bị từ chối nhưng lỗi được ném kèm lệnh `mysync peer remove <khoá>`; chỉ khoá do một lần duyệt hỏng bỏ lại mới bị gỡ (peer của quản trị không bị đụng), và duyệt từ chối khoá đã có trong `peers.d`. `resolve_invoking_uid` từ chối tiến trình setuid; so băm bằng `ct_equal`; `plan_migration` đòi băm khoá; quyền khoá kiểm bằng `fstat` trên descriptor đã mở; test có `SKIP` đếm được (`[SKIP]` và tổng ở dòng cuối).

### Đợt 7c: sửa theo rà soát đợt 7b

**H1 (Linux): bước root không còn chown/chmod theo đường dẫn.** Thư mục dữ liệu của dịch vụ do người dùng sở hữu, nên một bước chạy root làm việc "theo tên" trong đó là mồi cho symlink/hardlink. Thứ tự mới (`install_service_files`): (1) `/var/lib/mysync` root-owned, mode 0711 (không lộ tên các dịch vụ); (2) thư mục dịch vụ mở bằng descriptor (`O_DIRECTORY|O_NOFOLLOW`), rồi `fchown(0,0)` + `fchmod(0700)`: từ lúc này người dùng không thể đổi tên/thay thế gì trực tiếp trong đó; (3) tệp cũ gỡ bằng `unlinkat` (không theo liên kết; hardlink chỉ mất tên), tệp mới tạo bằng `openat(O_CREAT|O_EXCL|O_NOFOLLOW, 0600)`, kiểm `S_ISREG` và `st_nlink==1`, trao cho người dùng bằng `fchown` trên descriptor; `state/` là thư mục mới thì trao bằng descriptor, đã có sẵn thì GIỮ NGUYÊN (dữ liệu của chính người dùng, root không đi vào), là liên kết thì từ chối; (4) BƯỚC CUỐI: `fchown` thư mục dịch vụ cho người dùng. Không có `chown`/`chmod` theo đường dẫn nào, không đệ quy vào thứ người dùng đã sở hữu. `service install --user-service` trực tiếp từ chối `root` và tài khoản hệ thống (uid < 1000). Unit của người dùng thêm `CapabilityBoundingSet=`, `AmbientCapabilities=`, `RestrictNamespaces=yes`, `ProtectKernelLogs`, `ProtectClock`, `ProtectProc=invisible`, `ProtectHostname`, `UMask=0077`. `SystemCallFilter=@system-service` CỐ Ý KHÔNG đặt: không thể kiểm chứng nó với inotify/flock/socket của engine nếu không có systemd thật, và một bộ lọc chưa kiểm chứng làm dịch vụ đang chạy tốt bỗng hỏng ngoài thực địa.

**H2 (Windows): người dùng quản trị không được biến cấu hình thành đường lên SYSTEM.** Một người dùng thuộc Administrators làm dịch vụ chạy với token quản trị đầy đủ; nếu cấu hình dịch vụ do tiến trình mức người dùng sửa được thì phần mềm độc hại cùng người dùng sửa đích thành `C:\Program Files\...` và dịch vụ ghi bằng quyền quản trị (vượt UAC). Quyết định: (a) thư mục chứa cấu hình + khoá (`%ProgramData%\MySync\<dịch vụ>\`, `ServiceDirKind::ServiceTop`) chỉ Administrators và SYSTEM được ghi, tài khoản dịch vụ chỉ có ĐỌC (và duyệt); chỉ `state\` và `log\` (`UserFull`) tài khoản dịch vụ ghi được. Đổi cấu hình dịch vụ cần bước nâng quyền `mysync service apply-config` (`ServiceAction::ApplyConfig`: cùng đường kiểm allowlist + băm đã duyệt như `migrate-from-user`, giữ nguyên khoá, chỉ ghi cấu hình), nên phần mềm độc hại không tự đổi được. (b) Daemon áp lại `service_path_verdict`/allowlist mỗi lần NẠP cấu hình (khởi động và reload; `mysync run --enforce-paths --allow-root ...`, các thư mục xác nhận nằm trong dòng lệnh của dịch vụ, không nằm trong cấu hình) và từ chối đường dẫn ngoài allowlist với lỗi rõ. Linux giữ (b), không cần (a) vì dịch vụ không mạnh hơn người dùng. (d) `account_is_administrator(sid)` cho GUI cảnh báo "dịch vụ sẽ chạy với quyền quản trị đầy đủ của bạn; khuyên dùng tài khoản thường". Việc nạp lại sau `apply-config` làm bằng RELOAD_CONFIG qua kênh điều khiển (không thêm hộp UAC).

**M1.** `link_component` không còn dùng `FindFirstFile`: Windows mở từng thành phần bằng `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS)` và đọc `FILE_ATTRIBUTE_TAG_INFO`; chỉ "không tồn tại" (`ENOENT`/`ENOTDIR`/`ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND`) mới kết thúc việc duyệt, MỌI lỗi khác (từ chối truy cập, tên sai) là nghi ngờ và bị từ chối; phần `\\server\share` của UNC được bỏ qua và kiểm các thành phần bên dưới; dấu phân cách ở cuối không che được liên kết. Hạn chế (L10): liên kết do root / hệ thống / quản trị tạo trong CÁC TỔ TIÊN của gốc (như `/home -> /var/home`) được coi là một phần cách bố trí máy và được bỏ qua; liên kết do bất kỳ ai khác có thể gài, và chính gốc nếu là liên kết, luôn bị từ chối.

**M2.** `hash_file` mở thành phần cuối không theo liên kết (`O_NOFOLLOW`; Windows `FILE_FLAG_OPEN_REPARSE_POINT`, reparse point kiểu OneDrive vẫn đọc bình thường). Phần TOCTOU hẹp còn lại: giữa lúc băm và lúc gửi, `ifstream` của luồng gửi mở lại tệp theo tên; nếu bị đổi thành liên kết thì nội dung lệch băm đã khai và bị máy nhận từ chối (hash `EndFile`), nhưng ý nghĩa "không đọc qua liên kết" ở bước gửi dựa vào kiểm băm đó chứ không phải vào cờ mở.

**M3.** Tên dịch vụ của người dùng là `mysync-<tên>-<4 hex của băm SID/uid>`: hai người dùng có tên rút gọn trùng nhau không dùng chung dịch vụ, không bao giờ trùng `mysync-client`/`mysync-server`. Mô tả dịch vụ (Windows) / `Description=` (unit) mang nhãn `[owner <SID|uid>]`; `ServiceState::description` đọc lại nhãn; gỡ / chuyển ngược chỉ làm khi nhãn là của người gọi.

**L.** `service install --user-service` so SID của `LogonUser` với SID người yêu cầu; `set-password` chỉ cho tài khoản của chính người yêu cầu và chỉ trên dịch vụ có đường dẫn chương trình là `mysync` của bản cài này (`service_runs_program`). Quyền "log on as a service" do ta vừa thêm được ghi nhớ (`.logon-right-added` trong thư mục admin-owned) và `LsaRemoveAccountRights` khi cài hỏng hoặc khi gỡ dịch vụ (không bao giờ gỡ quyền ta không thêm). Thư mục `ProgramData` lấy từ `SHGetKnownFolderPath`. `SecretString` xoá cả `capacity()`, di chuyển bằng `swap` rồi xoá nguồn. DACL của kênh mật khẩu chỉ còn người dùng (bước nâng quyền chạy bằng đúng người dùng đó). `PasswordAttemptLimiter`: 5 lần sai liên tiếp thì khoá 30 giây, để gõ nhầm mật khẩu không khoá tài khoản Windows.

## Đợt 7d: thư mục dịch vụ do người dùng dựng sẵn, tài khoản quản trị, đường dẫn ngoài thư mục dịch vụ

**HIGH-1 (Windows).** `make_admin_dir` không còn nhánh "đã có thì tin": tạo bằng `CreateDirectoryW` kèm DACL được bảo vệ ngay từ đầu, `ERROR_ALREADY_EXISTS` không phải lỗi nếu và chỉ nếu thư mục có sẵn qua được kiểm nghiêm — chỉ `{SYSTEM, Administrators, TrustedInstaller}` (và SID của chủ với loại `UserFull`) được quyền ghi, `include_self=false` (tài khoản đang chạy KHÔNG tự được tin: nó chính là người dùng, có thể đã dựng thư mục trước). Thư mục `...\MySync` cha cũng bị kiểm như vậy. Đường dẫn đi qua liên kết thì từ chối. Tệp `config.toml` và `key` ghi bằng `write_new_file_win`: tạo tệp tạm `CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT` rồi `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`, không còn `remove` rồi ghi theo tên. `apply-config` / `migrate-from-user` gọi `require_trusted_config(..., include_self=false)` với tập tin cậy rỗng. Dịch vụ chạy `--enforce-paths` cũng kiểm khi nạp cấu hình: `DaemonOptions::exclude_self_from_trust` bỏ tài khoản chạy khỏi tập tin cậy của cấu hình, `state_writers` (`--state-writer <SID>`, chỉ cấp cho tài khoản thường) được tin riêng cho `state/` và `log/`.

**HIGH-2.** Tài khoản quản trị chạy dịch vụ với token quản trị đầy đủ, nên `state/` và `log/` của nó là loại `ServiceTop` (tài khoản chỉ đọc), không phải `UserFull`: một junction cắm vào đó sẽ cho dịch vụ ghi ra mọi nơi bằng quyền quản trị. `data_dir_kind_for_account(sid)` chỉ trả `UserFull` khi biết chắc đó là chính người yêu cầu và không thuộc nhóm Administrators; tài khoản lạ hoặc không phán đoán được coi như quản trị viên.

**M-1.** `service_config_path_problem` kiểm thêm `state_dir`, `log_file`, `key_file`: phải nằm trong thư mục dịch vụ (đường dẫn tương đối tính từ thư mục cấu hình), không đi qua liên kết. Kiểm này chạy mỗi lần daemon nạp cấu hình (`DaemonOptions::config_check`), nên sửa tay cấu hình để trỏ nhật ký ra `C:\Windows\...` bị chặn.

**M-2.** `MigrationSummary::account_is_admin`: với tài khoản quản trị, cảnh báo của lõi và hộp xác nhận (khoá `simple.svc.sum.warn_admin`, vi/en) nói rõ dịch vụ sẽ có TOÀN QUYỀN quản trị, đổi cấu hình phải qua UAC, nên dùng tài khoản thường; câu "không phải quản trị viên" chỉ hiện cho tài khoản thường.

**M-3.** Bước nâng quyền chỉ nhận tên dịch vụ đúng dạng `mysync-<tên>-<4 hex băm của owner id người yêu cầu>` (`user_service_name_matches_owner`; không bao giờ `mysync-server` / `mysync-client`). Linux: thư mục dịch vụ đã có phải thuộc chính người dùng, hoặc thuộc root và chỉ chứa tên của ta (`config.toml`, `config.toml.bak`, `key`, `state`); thuộc người khác hoặc có nội dung lạ thì từ chối TRƯỚC khi `fchown`.

**M-5.** `PasswordFlow` nhúng `PasswordAttemptLimiter`: 5 lần sai liên tiếp thì khoá 30 giây, không gửi lên bước nâng quyền; mở lại hộp (`begin`) không xoá bộ đếm, thành công thì đặt lại.

**M-6.** `LogonRightGuard` (RAII): quyền "log on as a service" do ta vừa thêm được thu hồi trên MỌI lối thoát chưa kết thúc bằng một dịch vụ chạy được và có tệp đánh dấu (return sớm, ngoại lệ, `--control-allow` hỏng). Ghi tệp đánh dấu `.logon-right-added` được kiểm kết quả; ghi hỏng thì gỡ dịch vụ vừa cài và thu hồi quyền.

**Lows.** L-1: `--user-service` trên Linux từ chối uid 0, uid dưới `UID_MIN` của `/etc/login.defs` (mặc định 1000), uid 65534, và uid khác `PKEXEC_UID`/`SUDO_UID` của người yêu cầu. L-3: `RealSteps::install_service` truyền `allow_roots`, `build_args(Install)` đẩy `--allow-root` khi `user_service` (dịch vụ áp lại đúng danh sách cho phép khi nạp cấu hình). L-5: `read_user_file_checked` mở bằng `O_NONBLOCK` (FIFO không treo bước nâng quyền, vẫn bị từ chối vì không phải tệp thường). L-8: bản sao mật khẩu tạm trong `set-password` được xoá. L-9: đổi cấu hình dịch vụ Windows đi qua `ServiceAction::ApplyConfig` (`build_args` và `ServiceController::run` có sẵn). **Giới hạn còn lại:** màn hình sửa cấu hình của GUI CHƯA tự gọi `ApplyConfig` cho dịch vụ Windows chạy bằng tài khoản người dùng; việc nối vào GUI (một hộp UAC cho mỗi lần lưu) để lại cho phần wx. Người dùng không sửa tay tệp trong thư mục dịch vụ vì thư mục đó chỉ quản trị viên ghi được.

**Chưa kiểm trên máy thật:** DACL/`CreateDirectoryW` của HIGH-1 chạy trong test dưới tài khoản người dùng thường trên máy dev (thư mục dựng sẵn bị từ chối, thư mục của ta được nhận lại); việc đăng nhập thật của dịch vụ bằng tài khoản quản trị, và `pkexec` thật trên Linux, chưa chạy.

## Đợt 7e: từ chối dịch vụ-người-dùng cho tài khoản quản trị Windows

**Quyết định.** Trên Windows, `service install --user-service`, `migrate-from-user`, `apply-config` và nút "Chạy khi chưa đăng nhập" của GUI TỪ CHỐI khi `account_is_administrator(sid)` là true (bước nâng quyền trả `kServiceAccessDenied`; `summarize_user_config` đặt `MigrationSummary::account_is_admin` và đưa lời từ chối lên đầu `problems` nên GUI chặn ngay trước khi xin quyền; nút bị khoá kèm gợi ý, vẫn cho "quay về chế độ cá nhân" và `--remove`). Lời thường (`admin_account_refusal`, khoá `simple.svc.admin_refused`, vi/en): tài khoản quản trị chạy dịch vụ với token quản trị đầy đủ trên cây nguồn/đích mà phần mềm khác của người dùng ghi được; kẻ tráo junction sau lúc kiểm có thể ghi/xoá tuỳ ý; hãy dùng "Tự chạy khi tôi đăng nhập" hoặc một tài khoản Windows thường riêng. Tài khoản KHÔNG phải quản trị viên không có đường leo thang này (token của nó không hơn người dùng). Cảnh báo `simple.svc.sum.warn_admin` và `data_dir_kind_for_account` (state/log kiểu chỉ-đọc cho tài khoản admin) vẫn giữ: chúng áp cho dịch vụ do quản trị viên cài bằng CLI server-to-server, không đi đường Simple.

**Giới hạn hiện tại / hướng tương lai (CHƯA làm).** Muốn cho tài khoản quản trị chạy an toàn thì engine phải chạy với restricted token: SID Administrators ở dạng deny-only, mức toàn vẹn Medium, khởi chạy bằng `CreateProcessAsUser`; khi đó cây do người dùng ghi được không còn dẫn tới quyền quản trị.

**Các Low.** `--remove` gọi `check_service_dir_trust(dir, nullptr, Admin)` (kiểm liên kết, `include_self=false`) trước khi xoá. `--user-service` trên Windows bắt buộc có `--password-pipe` và `account_sid(--user) == current_user_sid()` ngoài nhánh kênh. `set-password` đòi tên dịch vụ đúng mã chủ và `service_description` mang nhãn `[owner <SID>]` của người gọi; `service_runs_program` so chặt: dòng lệnh phải bắt đầu đúng `"<exe này>" run ` và chứa ` --service`. Quyền "log on as a service" chỉ tính là do ta thêm khi `LsaEnumerateAccountRights` trả đúng `STATUS_OBJECT_NAME_NOT_FOUND` hoặc không có quyền đó; lỗi đọc khác thì dừng. `CreateService` / `ChangeServiceConfig` dùng tên chuẩn `DOMAIN\tên` tra từ SID (`account_name_from_sid`) thay chuỗi gõ vào. Mật khẩu đổi sang `wchar_t` thẳng bằng `MultiByteToWideChar` vào bộ đệm được xoá (`fs::u8path` để lại bản sao tạm không xoá).

**Kiểm.** Test chạy không nâng quyền nên dùng hàm thuần (`admin_account_refusal`, `data_dir_kind_for_account`, `user_service_name_matches_owner`); việc từ chối thật ở bước nâng quyền và nút GUI khoá chưa chạy trên máy với tài khoản quản trị thật.
