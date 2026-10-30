<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 META.vn -->
<!-- Tác giả: Nguyễn Đức Sơn -->

# Đồng bộ giữa các máy chủ: chạy hoàn toàn bằng dòng lệnh

Tài liệu này dành cho môi trường server: không có người ngồi trước màn hình, cấu hình do Ansible/script rải ra, và
mọi việc phải **chạy lại được nhiều lần mà không hỏng** (idempotent). Không cần GUI, không có bước tương tác.

Mọi lệnh bên dưới chạy được trên Linux lẫn Windows (ví dụ viết cho Linux; trên Windows đổi đường dẫn).

## 1. Mã thoát (thống nhất cho mọi lệnh bên dưới)

| Mã | Nghĩa |
|---|---|
| 0 | Thành công — kể cả khi **không có gì để đổi** (đã đúng từ trước) |
| 1 | Lỗi chạy: không ghi được tệp, ... |
| 2 | Sai tham số, hoặc cấu hình sai/xung đột (tên đã dùng với khoá khác, khoá đã bị thu hồi, ...) |
| 3 | Lệnh `peer ...` / `key rotate` **đã ghi tệp nhưng daemon đang chạy từ chối áp dụng** (cấu hình mới không hợp lệ, không qua kiểm tin cậy...). Thay đổi chưa có hiệu lực; xem thông điệp ở stderr. `--json` có `daemon_applied: false` (`null` = không nối được daemon, không phải từ chối). "Reload quá nhanh" được thử lại vài lần trước khi coi là từ chối |
| 10 | **Có thay đổi** — chỉ khi thêm cờ `--changed-exit`; không có cờ thì có đổi cũng trả 0 |

`mysync health` có thang riêng (xem mục 8): 0 khoẻ, 1 cảnh báo, 2 nguy kịch, **64 = sai tham số** (để không lẫn với nguy kịch).

Thông điệp lỗi viết ra stderr, nguyên văn, kèm tên tệp / số dòng khi có. Kết quả máy đọc được ở stdout
(`--json` nếu lệnh hỗ trợ).

## 2. Ghép hai máy chủ: A đẩy sang B

A là **nguồn** (chạy client, đẩy tệp), B là **đích** (chạy server, nhận tệp). Khoá bí mật không bao giờ rời máy
của nó; hai bên chỉ trao **khoá công khai** (64 ký tự hex).

### 2.1 Trên B (máy nhận)

```sh
# khoá của B; --if-missing = đã có thì giữ nguyên (chạy lại không hỏng), in khoá công khai
mysync keygen --out /etc/mysync/server.key --if-missing
KEY_B=$(mysync key show --public -k /etc/mysync/server.key)     # gửi khoá này cho A

# cấu hình máy chủ tối thiểu; peers.d là nơi các máy khách được khai báo
cat > /etc/mysync/server.toml <<'EOF'
[server]
bind     = "*"
port     = 5656
root     = "/srv/mysync"
key_file = "/etc/mysync/server.key"
peers_dir = "/etc/mysync/peers.d"
pairing  = "off"
EOF

# cho phép A (KEY_A lấy từ A, bước 2.2). Chạy lại: không đổi gì, mã thoát 0.
mysync peer add "$KEY_A" --name a --perm rw --subdir a -c /etc/mysync/server.toml
mysync service install -c /etc/mysync/server.toml && mysync service start -c /etc/mysync/server.toml
```

`--perm ro|rw` bắt buộc; `--subdir` giới hạn máy đó trong một thư mục con của `root` (khuyến nghị: mỗi máy một
thư mục). Tuỳ chọn thêm: `--max-sessions N`, `--max-bandwidth-kbps N`.

### 2.2 Trên A (máy gửi)

```sh
mysync keygen --out /etc/mysync/client.key --if-missing
KEY_A=$(mysync key show --public -k /etc/mysync/client.key)     # gửi khoá này cho B

cat > /etc/mysync/client.toml <<EOF
[client]
key_file = "/etc/mysync/client.key"

[[watch]]
name = "du-lieu"
path = "/srv/du-lieu"

[[watch.target]]
host = "b.example.net"
port = 5656
server_key = "$KEY_B"
EOF
mysync service install -c /etc/mysync/client.toml && mysync service start -c /etc/mysync/client.toml
```

### 2.3 Kiểm

```sh
mysync status -c /etc/mysync/client.toml --json     # trạng thái từng đích: state, lag_seconds, last_error, ...
mysync health -c /etc/mysync/client.toml            # MYSYNC OK - 1/1 target(s) idle   (mã thoát 0)
```

## 3. `peers.d` — khai báo máy khách bằng tệp rời

Thư mục `peers_dir` (mặc định `<thư mục chứa server.toml>/peers.d` nếu có) chứa **mỗi máy một tệp `.toml`**:

```toml
# /etc/mysync/peers.d/a.toml
name       = "a"
public_key = "89d026eb1c2a9817d2ca8a5cbd80fc3aa5c9be5b6bd12e9ae22519a110beaa26"
access     = "rw"          # hoặc "ro"
prefix     = "a"           # thư mục con của root ("" = cả root)
# tuỳ chọn: max_sessions, max_bandwidth_kbps, max_write_bytes_per_hour, public_keys = [...]
```

Quy tắc ghép (cố định, giống nhau ở mọi lần nạp):

1. `[[client]]` trong `server.toml` **luôn đứng trước và thắng**; `peers.d` chỉ **bổ sung**.
2. Các tệp đọc theo thứ tự tên tệp. Tệp trùng **tên** hoặc trùng **khoá** với một máy đã nhận (tệp chính hoặc tệp
   đứng trước) bị **bỏ qua kèm cảnh báo**; máy đứng trước giữ nguyên chỗ.
3. Tệp đọc không được, sai cú pháp, hoặc bị kiểm tin cậy từ chối: **bỏ riêng tệp đó**, ghi cảnh báo nguyên văn
   (tên tệp + số dòng), đếm vào `peer_file_errors` của `status`. Không bao giờ làm hỏng các máy khác.
4. Tệp bắt đầu bằng `.` hoặc không có đuôi `.toml` bị bỏ qua; mỗi tệp tối đa 64 KiB.
5. Khoá nằm trong danh sách thu hồi (mục 7) bị loại ở **mọi** nguồn.
6. Có thể bỏ hẳn `[[client]]` trong `server.toml` khi đã khai `peers_dir` (tường minh).

**Nạp lại nóng:** daemon xem thư mục mỗi ~5 giây; thêm/sửa/xoá tệp là tự có hiệu lực, không cần ai gọi reload
(`mysync peer ...` cũng gọi reload ngay nếu truy cập được kênh điều khiển).

**Kiểm tin cậy:** khi chạy như dịch vụ (hoặc quyền cao), thư mục `peers.d` phải chỉ-admin-ghi-được, theo đúng
luật của tệp cấu hình (xem `docs/SERVICE.md`); thư mục sai quyền làm daemon từ chối nạp cấu hình, còn một tệp
sai quyền thì bị bỏ riêng tệp đó. Nếu không thì ai ghi được vào thư mục là tự cấp quyền vào cho mình.

## 4. Lệnh `mysync peer`

```sh
mysync peer add <khoá 64 hex> --name N --perm ro|rw [--subdir D] [--max-sessions N] [--max-bandwidth-kbps N]
                [--rotate] [--allow-revoked] -c server.toml [--changed-exit] [--no-reload] [--service-name S]
mysync peer remove <tên|khoá>  -c server.toml
mysync peer revoke <tên|khoá>  -c server.toml
mysync peer retire-key <tên> <khoá cũ> -c server.toml
mysync peer list [--json] -c server.toml
```

`peer add` cho kết quả xác định:

| Tình huống | Kết quả |
|---|---|
| chưa có | thêm (vào `peers.d` nếu cấu hình khai báo/đã có thư mục đó, nếu không thì thêm `[[client]]` vào `server.toml`, ghi nguyên tử + `.bak`) → mã 0 / 10 |
| trùng khoá, cùng mọi tham số | **không đổi** → 0 |
| trùng khoá, khác tham số (quyền, thư mục con, hạn mức) | **cập nhật** → 0 / 10 |
| trùng tên, khác khoá | **lỗi rõ** → 2 (dùng `--rotate` nếu muốn xoay khoá, mục 6) |
| khoá đã bị thu hồi | lỗi → 2 (trừ khi `--allow-revoked`) |

`peer remove` một máy không có = không đổi (mã 0): chạy lại được.

**Chạy đồng thời:** mọi lệnh sửa peer lấy khoá liên tiến trình `<thư mục cấu hình>/.peers.lock` (chờ tối đa 20 giây rồi báo lỗi rõ), nên nhiều lệnh `peer add/revoke` song song (Ansible `forks`) không ghi đè nhau. Tệp peer mới tạo theo kiểu "chỉ khi chưa có" (không đè tệp có sẵn). `peer add` chạy lại mà **không** nêu `--subdir` thì giữ thư mục con hiện có (không âm thầm mở rộng ra cả root); muốn mở rộng phải ghi rõ `--subdir ""`.

**Khi chạy bằng quyền cao (root/Administrator)** các lệnh này kiểm tin cậy tệp cấu hình, `peers.d`, thư mục khoá như daemon và từ chối ghi qua symlink. Các lệnh đổi cấu hình xong sẽ gọi
`RELOAD_CONFIG` qua kênh điều khiển cục bộ; không truy cập được (daemon không chạy, không đủ quyền) thì chỉ in
một dòng ghi chú — `peers.d` vẫn tự được nạp trong vài giây. Thêm `--service-name` nếu dịch vụ không mang tên
mặc định `mysync-server`.

## 5. Ansible (idempotent)

```yaml
- hosts: b_servers
  tasks:
    - name: Khoá của máy chủ (giữ nguyên nếu đã có)
      command: mysync keygen --out /etc/mysync/server.key --if-missing --changed-exit
      register: kg
      changed_when: kg.rc == 10
      failed_when: kg.rc not in [0, 10]

    - name: Cấu hình máy chủ
      copy: { src: server.toml, dest: /etc/mysync/server.toml, mode: "0640" }
      notify: restart mysync

    # Cách 1: rải tệp peers.d (không cần lệnh nào; daemon tự nạp trong ~5 giây)
    - name: Máy khách A
      copy:
        dest: /etc/mysync/peers.d/a.toml
        mode: "0640"
        content: |
          name = "a"
          public_key = "{{ hostvars['a'].mysync_pubkey }}"
          access = "rw"
          prefix = "a"

    # Cách 2: dùng lệnh (kiểm xung đột, tự sinh tệp)
    - name: Máy khách A bằng lệnh
      command: >
        mysync peer add {{ hostvars['a'].mysync_pubkey }} --name a --perm rw --subdir a
        -c /etc/mysync/server.toml --changed-exit
      register: pa
      changed_when: pa.rc == 10
      failed_when: pa.rc not in [0, 10]

    - name: Thu hồi máy đã loại
      command: mysync peer revoke {{ item }} -c /etc/mysync/server.toml --changed-exit
      register: rv
      changed_when: rv.rc == 10
      failed_when: rv.rc not in [0, 10]
      loop: "{{ mysync_retired_peers | default([]) }}"
```

Trên A, lấy khoá công khai để đưa vào biến Ansible:
`command: mysync key show --public -k /etc/mysync/client.key` → `register: pub`, `changed_when: false`.

## 6. Xoay khoá không gián đoạn

### 6.1 Khoá MÁY CHỦ (B)

Thiết kế: máy chủ giữ **hai** khoá bí mật trong lúc chuyển (`key_file` + `key_file_next`). Máy khách ghim khoá
nào cũng vào được. Với giao thức Noise_IK, bên khởi tạo mã hoá tới đúng khoá công khai mà nó ghim nhưng không nói
là khoá nào, nên máy chủ **thử lần lượt từng khoá** trên tin nhắn đầu và dùng khoá giải mã được. Công việc cho mỗi
khoá giống hệt nhau và không thoát sớm, nên thời gian không để lộ khoá nào khớp. Khoá lạ vẫn bị từ chối như cũ.

```sh
# 1. Trên B: tạo khoá mới, máy chủ trả lời cả hai khoá (không cần khởi động lại)
mysync key rotate --server-config /etc/mysync/server.toml --prepare --changed-exit
#    in khoá công khai MỚI; xem lại bất cứ lúc nào: mysync key rotate ... --status [--json]

# 2. Trên mỗi máy khách: thêm khoá mới cạnh khoá cũ, nạp lại (hot reload). Cho Ansible/script:
#       server_key      = "<khoá cũ>"
#       server_key_next = "<khoá mới>"
#    Máy khách thử khoá ghim trước, rồi server_key_next — CHỈ khi khoá đầu bị máy chủ TỪ CHỐI xác thực
#    (không phải khi lỗi kết nối/hết giờ/bị ngắt); mỗi lần phải rơi về khoá kia có cảnh báo trong log. Khoá nào chạy được
#    thì lần sau dùng trước (log "accepted server_key_next"). Chỉ các khoá viết trong cấu hình mới được thử.

# 3. Khi mọi máy khách đã có khoá mới: trên B, chuyển khoá mới thành chính thức
mysync key rotate --server-config /etc/mysync/server.toml --promote --changed-exit
#    key_file := khoá mới, key_file_next := trống. Khoá cũ không còn được chấp nhận; xoá tệp khoá cũ khi chắc chắn.

# 4. Trên MỌI máy khách (bắt buộc dọn): server_key := khoá mới, bỏ server_key_next. Nếu để nguyên, sau promote
#    mỗi lần khởi động client sẽ bị máy chủ từ chối một lần bằng khoá cũ (tính vào giới hạn xác thực sai/phút của IP đó).
```

`--prepare` **không** nhận nuôi tệp `<key_file>.next` có sẵn (nó có thể là khoá của ai đó): có sẵn thì lỗi, trừ khi thêm `--adopt` (dùng lại khoá sau một lần `--prepare` bị ngắt) hoặc chọn `--out` khác. `--prepare` và `--promote` chạy lại được (đã làm rồi thì không đổi, mã 0). `--promote` chỉ thao tác trên cấu hình
và gọi reload; tệp khoá cũ **không bị xoá**.

### 6.2 Khoá MÁY KHÁCH (A)

```sh
# 1. Trên A: tạo khoá mới ở tệp khác, lấy khoá công khai
mysync keygen --out /etc/mysync/client.key.new && mysync key show --public -k /etc/mysync/client.key.new

# 2. Trên B: nhận thêm khoá mới cho CÙNG máy đó (cùng tên/quyền/thư mục con/hạn mức); khoá cũ vẫn vào được
mysync peer add <khoá mới> --name a --perm rw --subdir a --rotate -c /etc/mysync/server.toml --changed-exit

# 3. Trên A: đổi key_file sang khoá mới, nạp lại

# 4. Trên B: bỏ khoá cũ
mysync peer retire-key a <khoá cũ> -c /etc/mysync/server.toml --changed-exit
```

Trong `server.toml` hoặc tệp `peers.d`, một máy có thể khai nhiều khoá: `public_key` (chính) và `public_keys = [...]`
(khoá khác của cùng máy; tối đa 8). Phiên đang mở bằng khoá nào thì bị ngắt khi **khoá đó** bị bỏ.

## 7. Thu hồi ngay

```sh
mysync peer revoke a -c /etc/mysync/server.toml        # hoặc theo khoá: mysync peer revoke <khoá 64 hex> -c ...
```

`revoke` = xoá máy khỏi cấu hình + đưa **mọi khoá** của nó vào `revoked-keys.txt` (cạnh `server.toml`) + nạp lại.
Các phiên đang mở của máy đó **bị ngắt ngay** (trong vòng chưa tới vài giây, kể cả phiên đang nằm im chờ), không phải
chờ yêu cầu tiếp theo. `revoke` ghi danh sách thu hồi **trước**, rồi mới xoá máy. Danh sách đọc không được hoặc có dòng hỏng (không phải "không có tệp") thì máy chủ **từ chối nạp cấu hình** thay vì coi như chưa thu hồi gì (giữ cấu hình đang chạy); dấu BOM UTF-8 và CRLF được chấp nhận; tệp này cũng phải qua kiểm tin cậy khi chạy dịch vụ. Danh sách thu hồi chặn việc thêm lại nhầm: `peer add` với khoá đó báo lỗi (mã 2) và máy chủ
loại khoá đó dù nó nằm ở tệp nào. Cho phép lại có chủ ý: `peer add ... --allow-revoked`.

Một thay đổi quyền/thư mục con của máy đang kết nối cũng làm phiên của riêng máy đó bị ngắt và nối lại với quyền mới;
các máy khác không bị đụng tới.

## 8. Giám sát

```sh
mysync status -c server.toml --json
mysync health -c server.toml [--max-lag-seconds 900] [--json] [--service-name S]
```

`status --json` (ổn định, trường chỉ thêm không bớt): `version`, `role`, `running`, `source` (`daemon` khi hỏi được
tiến trình đang chạy, `config` nếu không), `uptime_s`, `public_key`, `next_public_key`, `pairing`, `peers[]`
(tên, quyền, thư mục con, số khoá, số phiên, byte nhận/gửi), `targets[]` (đích, `state`, `queued`, `sent`, `failed`,
`lag_seconds`, `last_ok_unix_ms`, `last_error`, `last_error_unix_ms`), `errors`, `last_ok_unix_ms`,
`peer_file_errors`, `config_error`, `warnings[]`. Khi daemon không trả lời, `running=false` và `control_error`
ghi lý do nguyên văn. Cần chạy bằng tài khoản được phép dùng kênh điều khiển (cùng tài khoản dịch vụ, root, hoặc
được liệt kê trong `[control]`).

`health` in **một dòng** kiểu Nagios và trả mã:

| Mã | Khi nào |
|---|---|
| 0 | khoẻ |
| 1 | cảnh báo: một đích đang `Error`/`Disconnected` nhưng chưa quá `--max-lag-seconds`; lần nạp lại cấu hình gần nhất bị từ chối; có tệp `peers.d` không dùng được |
| 2 | nguy kịch: daemon không chạy/không trả lời; cấu hình không đọc được; một đích im quá `--max-lag-seconds` (mặc định 900 giây) |

Ví dụ systemd:

```ini
# /etc/systemd/system/mysync-health.service  (+ .timer mỗi phút)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/mysync health -c /etc/mysync/client.toml
# /etc/systemd/system/mysync-client.service (bản do `mysync service install` sinh) thêm vào [Unit]:
# OnFailure=mysync-alert@%n.service
```

Nagios/Icinga: dùng `mysync health` như một plugin (mã 0/1/2 đúng chuẩn).

## 9. `pairing = "off"` cho máy chủ không người trông

Trạng thái `pairing` trong `status` là trạng thái **đang hiệu lực** (tiến trình được chạy với `--allow-pairing` VÀ cấu hình không để `off`), không phải chỉ giá trị trong tệp; đổi sang `off` rồi reload thì cửa sổ ghép đang mở bị đóng ngay và mọi thao tác ghép bị từ chối. `[server] pairing = "off"` (mặc định) nghĩa là **không có đường nào** bật chế độ ghép bằng mã — kể cả qua kênh điều
khiển cục bộ hay `--allow-pairing`: tiến trình bỏ qua cờ đó và ghi cảnh báo. Chỉ `pairing = "on-demand"` cho phép
GUI Đơn giản của người dùng bật, và chỉ theo yêu cầu. Máy chủ chạy dịch vụ nên giữ `off`. Đổi giá trị này cần
khởi động lại.

## 10. Chịu lỗi khi vận hành không người trông

- Client tự nối lại với backoff có nhiễu (`retry_min_ms` … `retry_max_ms`, mặc định 1 s … 60 s); sự kiện không
  bao giờ bị bỏ, được xếp hàng. Máy chủ tắt rồi bật lại: client nối lại và gửi phần bị lỡ (có test).
- Mất kết nối lâu hoặc client khởi động lại: bước **đối chiếu toàn bộ** với đích chạy lại khi khởi động, nên
  thay đổi xảy ra lúc không ai theo dõi vẫn được tìm ra (có test).
- Tệp lớn đang truyền mà một bên khởi động lại: máy chủ ghi vào tệp tạm, kiểm BLAKE3 rồi mới đổi tên nguyên tử,
  nên tên cuối cùng không bao giờ chứa tệp dở; lần nối lại gửi lại tệp (có test lấy mẫu liên tục tên đích).
  **Chưa có tiếp tục truyền dở** (resume): tệp lớn bị cắt giữa chừng sẽ truyền lại từ đầu.
- Tệp tạm mồ côi trên máy chủ bị dọn khi khởi động nếu cũ hơn 1 giờ.

## 11. Chưa làm / cần biết

- Chưa kiểm trên máy thật nhiều máy chủ; test chạy ở loopback (Windows MinGW và Linux gcc:14). Xem `docs/STATUS.md`.
- `health`/`status --json` hỏi daemon qua kênh điều khiển cục bộ; nếu `[control] enabled = false` thì chỉ báo được
  "không hỏi được daemon" (`health` trả 2).
- Giao thức kênh điều khiển có thêm trường (`last_ok_unix_ms`, `pairing`, `peer_file_errors`, `warnings`): GUI và daemon
  phải cùng bản phát hành.
- Chưa có thông báo tự động khi khoá sắp hết hạn (khoá không có hạn dùng); xoay khoá là thao tác chủ động.
