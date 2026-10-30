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
