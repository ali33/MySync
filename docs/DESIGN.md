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
- DELETE{path} (chuyển vào __sync/__trash/<timestamp>/..., không xoá thật nếu config trash=true) | RENAME{from,to} | MKDIR{path}
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
