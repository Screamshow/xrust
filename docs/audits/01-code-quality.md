# Аудит качества кода xrust 0.0.26

Дата: 2026-10-23. Объект: `` (commit `c5f567c`). Релизный профиль: `--features rust-x --no-default-features`, `panic = "abort"`, `overflow-checks = false`. Релизные цели по `.cargo/config.toml`: OpenWrt x86_64 и aarch64 (musl, 64-бит).

Темы аудита: архитектура, unsafe, паники на сетевых путях, конкурентность, утечки ресурсов, обработка ошибок, горячие пути, bbolt и вендоренные патчи.

## 0. Методология и статусы

- **Статический разбор.** Просмотрены все `unsafe` в `crates/`. Вендоренные `vendor/h2` и `vendor/blake3` сравнены через `diff -ru` с оригиналами h2 0.4.19 и blake3 1.8.7 со `static.crates.io`.
- **Паники.** Парсеры сетевых данных проверены построчно: inbound, DNS, sniff, SRS/TSRS, bbolt, WireGuard, TUN.
- **Подтверждения.**
  - Юнит-тесты в копиях кода в scratchpad: `…/scratchpad/cq/xrust`, `…/panics-inbound`, `…/panics-parsers`, `…/concurrency/ws`, `…/hotpath/ws`.
  - Мутационный фаззинг SRS простым xorshift-циклом (300k итераций).
  - Живой прогон релизного бинаря на loopback, порты 25010–25011.
  - Нагрузочные тесты UDP и cache.db на loopback, порты 25500–25699.
- **Сборка.** `cargo build --locked --release -p core-cli --features rust-x --no-default-features` в `CARGO_TARGET_DIR=…/target-quality` прошла успешно. Все 14 предупреждений `core-runtime` относятся к dead code.
- **Чего нет.** Репозиторий не менялся, если не считать этого файла. Root, docker, perf, qemu и miri недоступны. Поэтому TUN/auto_route не запускались, а ветки aarch64 NEON/AES в `fastgcm` не исполнялись.
- **Статусы находок:**
  - **ПОДТВЕРЖДЕНО** — указаны тест или команда;
  - **КОД** — подтверждено чтением кода, без запуска;
  - **ГИПОТЕЗА** — правдоподобно, не проверено.

Вывод сделан по совокупности находок. Самый срочный класс — паники, достижимые из сети. При `panic=abort` каждая из них роняет весь роутер-прокси одним пакетом или запросом:
- CQ-01: Clash API, без аутентификации;
- CQ-02: SOCKS5 UDP;
- CQ-03: удалённый SRS.

Второй класс — неограниченные структуры на UDP- и TUN-путях: при 128–256 МБ ОЗУ они ведут к OOM за секунды.

## 1. Архитектура core-runtime

### 1.1 Поток соединения

```
listener (inbound::*::serve, задача в BoxInstance.tasks)
  └─ accept → tokio::spawn(handle_conn)      ← задача на соединение, detached
       ├─ протокольный handshake (mixed/vless/hy2/tproxy/redirect/tun-smoltcp)
       ├─ ConnContext { source, destination, inbound, sniff_prefix, … }
       ├─ Router::route → RouterInner::route_walk_packet
       │     prepare(ctx) (find_process → /proc), линейный проход rules[]:
       │     sniff / resolve / route / reject / hijack-dns; final → default
       ├─ Outbound::connect(router, target) → Conn::{Plain, Shadowsocks, …}
       │     dial.rs: DialOptions (SO_MARK, bind_interface, netns, protect_path,
       │     keep-alive), happy-eyeballs, DNS через dns::current()
       └─ pump_conn_tracked: splice (TCP↔TCP, relay.rs), иначе пул буферов
             128 KiB (copy_bidirectional_pooled); clash_state::ConnHandle для
             /connections и DELETE
UDP: inbound → UdpHub (udp.rs): flows HashMap<key, Flow>, reverse-задача
     на поток, idle 120 s, sweeper по Weak.
DNS: direct-inbound/hijack → DnsService (dns/mod.rs): cache LRU, inflight
     dedup, FakeIP store (persist в cache.db), транспорты UDP/TCP/DoH/DoH3/DoQ.
```

### 1.2 Владение ресурсами

`BoxInstance` владеет следующим:
- `tasks: Vec<JoinHandle>` — листенеры, Clash API, NTP, тикер flush cache.db;
- `Arc<Router>`;
- `Arc<DnsService>`, который ещё и публикуется глобально через `dns::set_service`;
- `Arc<Mutex<CacheFile>>`, который передаётся ещё и в `clash_mode`.

`Router` хранит `RwLock<Arc<RouterInner>>`. В `RouterInner.probe_tasks` лежат задачи urltest и обновлятели remote rule-set.

Отслеживания нет у задач на соединение (TCP, Clash API, websocket) и у стека WireGuard: он живёт, пока жив хоть один `cmd_tx`. Arc-циклов нет: `JoinHandle` не владеет future.

### 1.3 Shutdown и hot reload

- **SIGTERM/SIGINT.** `shutdown_wait` прерывает и ждёт отслеживаемые задачи, затем синхронно делает flush cache.db, без fsync. Detached-соединения отменяются только при drop рантайма. Graceful drain нет.
- **SIGHUP** (Forkop использует его для DNS failover, `forkop/files/usr/lib/service/state.uc:520`):
  - Конфиг перечитывается и валидируется на async-потоке. Если он невалиден, работает старый.
  - **In-place reload** (`can_reload_in_place`: inbounds, clash_api, cache_file, ntp, netns не менялись):
    1. Строится новый `RouterInner` через prepared Router; скачиваются remote rule-set и запускаются endpoints.
    2. Мигрируют DNS-кэш и FakeIP.
    3. `apply_prepared_inner` копирует выборы selector/urltest, прерывает старые probe-задачи и атомарно подменяет inner.
    4. Подменяется DNS-сервис, применяется уровень логов.
    - Соединения в полёте держат старый inner.
  - **Полный reload** (`reload_instance`): `shutdown_wait`, затем `start(next)`. Если не вышло — `start(previous)`. Если не вышло и это, ошибка поднимается наверх и **процесс завершается**: см. CQ-14 и CQ-16.
  - Измерено в `audit_reload_accumulation`: 30 in-place reload дают задачи 5→6 и fd 12→12. 10 полных reload дают по +1 временной задаче, которая уходит через 31 с. **Накопления задач, таймеров и сокетов при reload нет.**
- **Рантайм** (`core-cli/src/main.rs:217-236`): число воркеров равно `available_parallelism`. **На одноядерном устройстве используется `current_thread`.** Любой блокирующий вызов на async-потоке там останавливает весь трафик. Это усиливает CQ-13, CQ-20 и CQ-31.

## 2. Таблица unsafe

Учтены все `unsafe` в `crates/` (503 вхождения вместе с тестами), включая core-crypto: отдельный субагент для него не запустился, проверял вручную. В `vendor/blake3` изменения безопасны: добавлены `derive_key_bytes` и `hash_derive_key_context_bytes`, а `&str` теперь делегирует в `&[u8]`; unsafe-код upstream не тронут. В `vendor/h2` дифф не содержит unsafe (см. §4).

| Место | Назначение | Корректность | Риск |
|---|---|---|---|
| `route/mmap_set/matcher.rs:84-93` `slice_at` | `from_raw_parts::<T>` по смещениям из файла | **Нарушено.** Выравнивание не проверяется, а `Ipv6Entry` (u128) требует align 16, тогда как компилятор выравнивает на 8. Арифметика без `checked_*`. → CQ-04 | **высокий** |
| `route/mmap_set/matcher.rs:70` | `&*(ptr as *const Header)` | OK: длина проверена в `Header::parse`, буфер mmap выровнен по странице | низкий |
| `route/mmap_set/format.rs:48` | `read_unaligned::<Header>` | OK | низкий |
| `route/mmap_set/mmap_io.rs:22-23` `unsafe impl Send/Sync for MmapBuffer` | разделяемый read-only mmap | Формально OK. Но `MAP_SHARED` позволяет менять память под `&[u8]`, а это UB и SIGBUS при правке на месте → CQ-19 | средний |
| `mmap_io.rs:41,56,86,103,129,144` | mmap, madvise, анонимный mmap + mprotect, munmap | OK. Если `from_bytes` не смог сделать mmap, он молча возвращает пустой буфер, и потом `view().expect` паникует → CQ-35 | средний |
| `mmap_set/compiler.rs:354-430` | `copy_nonoverlapping` POD-таблиц в `Vec` | OK: `output` имеет размер `offset`, области проверены | низкий |
| `inbound/relay.rs:43-70` | `pipe2`, `F_SETPIPE_SZ`, `splice`, `close` в Drop | OK: fd принадлежат `Pipe`, EAGAIN обрабатывается. Размер пайпа 1 МиБ → CQ-23 | низкий (память) |
| `inbound/tproxy.rs:376-495` | setsockopt, `recvmsg` + разбор cmsg | Длины и семейства проверяются. `cmsg_len - CMSG_LEN(0)` доверяет ядру. Буфер `oob` — `Vec<u8>` с выравниванием 1 по `Layout` (на практике его выравнивает аллокатор); в тесте это стековый `[u8;256]` | низкий |
| `inbound/redirect.rs:98-126` | `getsockopt(SO_ORIGINAL_DST)` | OK | низкий |
| `inbound/tun.rs:1419-1490` | `open(/dev/net/tun)`, TUNSETIFF/OFFLOAD, SIOCSIF* | Безопасность памяти OK. **fd никогда не закрывается** (`AsyncFd<RawFd>`) и открыт без `O_CLOEXEC` → CQ-16. Ошибки ioctl игнорируются → CQ-25 | средний |
| `inbound/tun.rs:1686,1725,1745` | `read`/`writev`/`write` на TUN | OK | низкий |
| `outbound/tailscale/lan.rs:101-144` | TUN через `OwnedFd` | OK (образцовый вариант) | низкий |
| `outbound/dial.rs:379-1546` | socket, setsockopt, bind, connect, `from_raw_fd`, ручные `close` | OK: все ошибки закрывают fd. Хрупко из-за ручного `close` вместо `OwnedFd` | низкий |
| `protect.rs:60-120` | `SCM_RIGHTS` sendmsg/recvmsg | `send_fd` OK. В `recv_fd` (сторона хелпера и тесты) нет проверок `cmsg_level`/`cmsg_len`/`MSG_CTRUNC` и нет `MSG_CMSG_CLOEXEC`. Буфер — `Vec<c_char>` (align 1) | низкий |
| `netns.rs:119,140,167-190` | `setns` в отдельном потоке, `unshare` в `pre_exec`, ioctl lo | OK: setns выполняется в одноразовом потоке. Утечка fd в `loopback_up` при ошибке SIOCGIFFLAGS → CQ-35 | низкий |
| `tls_utls.rs:210`, `inbound/tls.rs:550`, `outbound/transport/mod.rs:753`, `vision.rs:462`, `vmess/framing.rs:645` | `set_len` после `ReadBuf::uninit` | OK, если внутренний reader не подменяет `ReadBuf`. Внутренние типы этого не делают. Желательно `assert!(read.filled().as_ptr()==spare_ptr)`, как в tokio | низкий |
| `ntp.rs:154` `clock_settime`, `mdns.rs:343` `if_nametoindex`, `clash_api.rs:754` `sysconf` | libc | OK | низкий |
| `core-cli/main.rs:20-60,532-600` | `mi_option_set(15,0)`, `(43,0)`, `setrlimit` | OK для mimalloc v3, где индексы совпадают. В v2 `allow_thp`=37, так что жёстко прошитые индексы хрупки → CQ-35 | низкий |
| `core-cli/allocstat.rs:85-100` | `GlobalAlloc` поверх mimalloc | OK, только под фичей `allocstat` | низкий |
| `core-crypto/afalg.rs:92-475` | AF_ALG: socket, bind, setsockopt(KEY), accept, sendmsg с 3 cmsg, recvmsg | Протокол аккуратен: точные длины iov, EINTR, обнуление при EBADMSG. Но `cbuf=[0u8;128]` на стеке с align 1 → формально невыровненный `cmsghdr`. `seal` делает `.expect("afalg seal")` → паника при ошибке ядра. Вызовы блокирующие → CQ-22 | средний |
| `core-crypto/fastgcm.rs:137-580` (aarch64) | NEON/AES/PMULL-интринсики, `vld1q/vst1q`, `from_raw_parts_mut` для key schedule | OK: `is_aarch64_feature_detected!("aes")`, вычисление границ `len - off >= 128`, static assert на выравнивание. **Не исполнялось** (нет qemu) | низкий–средний |
| `core-crypto/fastgcm.rs:585-1000` (x86_64) | AES-NI/PCLMUL, `loadu/storeu` | OK: детект 4 фич, невыровненные load/store, границы проверены. Тесты `matches_rustcrypto_for_every_length` проходят | низкий |
| `core-crypto/fastchacha.rs:316-700` | AVX2 ChaCha20 и скалярный Poly1305 через `read_unaligned`+`from_le` | OK: окно `FAST_MIN..=FAST_MAX`, `emit` пишет ровно 512 Б при `len-done>=512`, тег сравнивается за постоянное время. Есть дифф-тест против RustCrypto | низкий |
| `core-crypto/misc.rs:15` | `transmute` массива нулевой длины в const | OK | нет |
| `vendor/blake3` (только дифф) | новые safe-функции | OK | нет |

Ручных `transmute` (кроме интринсиков), `unsafe impl Send/Sync` (кроме `MmapBuffer`) и `static mut` нет.

## 3. Находки

Формат каждой находки: статус, приоритет, место, причина, последствия, исправление, выигрыш и риск регрессии, влияние на Forkop X.

### P0 — удалённый крах

#### CQ-01. Clash API: паника в `percent_decode` до аутентификации

- **Статус:** ПОДТВЕРЖДЕНО живым прогоном.
- **Место:** `crates/core-runtime/src/clash_api.rs:1779` (`decode_impl`); вызовы в `:342`, `:1758-1759`.
- **Причина:** `&input[i + 1..i + 3]` режет `&str` по байтовым индексам. Если после `%` идут один ASCII-символ и затем многобайтовый символ, срез попадает внутрь символа и вызывает панику. Вызов стоит до `authorized()`, причём в разборе и пути, и query. `split_head` делает `from_utf8_lossy`, поэтому подходят любые байты: `0xFF` превращается в трёхбайтовый U+FFFD.
- **Подтверждение:** релизный `tachyon-core run` с `clash_api 127.0.0.1:25011` и `secret`. Команда:
  ```
  printf 'GET /%%a\xc3\xa9 HTTP/1.1\r\n\r\n' | nc 127.0.0.1 25011
  ```
  Результат: процесс DEAD, в логе `panicked at clash_api.rs:1779:33: end byte index 4 is not a char boundary`.
- **Последствия:** один TCP-запрос без секрета роняет весь прокси.
- **Исправление:** работать с байтами, как уже сделано в `inbound/transport.rs:924` `path_unescape`:
  ```rust
  b'%' if i + 2 < bytes.len() => match (hex(bytes[i+1]), hex(bytes[i+2])) {
      (Some(h), Some(l)) => { out.push(h << 4 | l); i += 3; continue }
      _ => { out.push(b'%'); i += 1 }
  }
  ```
  Добавить регрессионный тест на `"%aé"` и `"%\xff"`.
- **Выигрыш и риск:** закрывает удалённый DoS. Риск регрессии нулевой.
- **Forkop X:** прямое влияние. Forkop ставит `external_controller` на `service_address:9090` (LAN), а при `enable_yacd_wan_access` — на `0.0.0.0:9090` (`generator.uc:418-427`). Любой клиент LAN, а во втором случае и интернета, может уронить ядро.

#### CQ-02. SOCKS5 UDP: адрес типа domain вызывает выход за границу

- **Статус:** ПОДТВЕРЖДЕНО, тест `socks_udp_tests::correctly_sized_domain_datagram_panics` в `…/scratchpad/panics-inbound/repro`.
- **Место:** `inbound/mixed.rs:537-555`.
- **Причина:** ветка `0x03` возвращает `offset = end = 5+len+2`, то есть уже с учётом порта. Затем порт читается из `data[offset]`, и для датаграммы правильного размера это индекс `len`.
- **Последствия:** любая корректная датаграмма с domain-адресом даёт панику `index out of bounds` и роняет процесс. Без `users` это pre-auth. Заодно domain-цели SOCKS UDP никогда не работали.
- **Исправление:** `(ip, 5 + len)`, проверка `data.len() >= 5+len+2` остаётся.
- **Выигрыш и риск:** закрывает удалённый крах и чинит функцию. Риск минимальный.
- **Forkop X:** по умолчанию Forkop генерирует tproxy и direct, а не mixed. Влияет только на пользовательские конфиги с mixed/socks.

#### CQ-03. SRS-декодер: недоверенные счётчики и индексы

- **Статус:** ПОДТВЕРЖДЕНО фаззингом (`…/panics-parsers/srs-fuzz`, побайтовая копия `srs.rs`).
- **Место:** `crates/core-config/src/srs.rs:67`, `:107`, `:804` (`Vec::with_capacity(count)`); `:732` и `:740-741` (`label_bitmap[word]`, `index - ranks[word]`); `:60-64` (zlib без лимита).
- **Причина:** количество элементов (u64 varint) из файла уходит в `with_capacity` без проверки. Индексы succinct-set не проверяются.
- **Подтверждение:**
  - `count=2^60` даёт `capacity overflow`.
  - `count=2e8` даёт `memory allocation of 6.4 GB failed`.
  - Пустой bitmap даёт `index out of bounds`.
  - 300 тысяч мутаций: 5283 паники, и все исчезают после патча в копии.
  - Zip-бомба: 2,44 МБ файла дают 537 МБ RSS.
- **Последствия:** remote rule-set (`rule_set_remote.rs` → `srs::read`) роняет процесс при загрузке и при каждом старте из кэша. Достаточно владельца URL или MITM для http.
- **Исправление:**
  - Ограничить `with_capacity(count.min(remaining_bytes))`, как уже сделано в `str_vec`.
  - Индексы через `get()` и `checked_sub`, при несогласованном trie возвращать `Err`.
  - `ZlibDecoder::new(..).take(LIMIT)`, например 32 МБ.
  - Добавить фаззинг-тест в CI.
- **Выигрыш и риск:** закрывает удалённый крах и OOM. Риск низкий.
- **Forkop X:** прямое влияние. Forkop генерирует remote rule-set в формате `binary` (`generator.uc:370,395`), и если один из списков сообщества скомпрометирован, все роутеры уходят в crash-loop. Скачанный файл Forkop проверяет через `sing-box rule-set match --format binary` (`ruleset_cache.uc:279`), то есть тем же ядром: сломанный файл уронит и эту проверку, и cron-обновление.

### P1 — стабильность и ресурсы

#### CQ-04. TSRS: невыровненные `&[Ipv6Entry]` (UB) и непроверенные смещения

- **Статус:** ПОДТВЕРЖДЕНО, тест `cq_audit_ipv6_table_alignment` в `…/scratchpad/cq/xrust`.
- **Место:** `route/mmap_set/matcher.rs:84-93`, `compiler.rs:291` (`align_8`).
- **Подтверждение:** при `CQ_N=2` (2 домена и 1 v6 CIDR) получается `dest_v6_offset=88`, остаток по модулю 16 равен 8. В debug это `unsafe precondition(s) violated: slice::from_raw_parts requires the pointer to be aligned`. Субагент показал, что в release оптимизатор уже опирается на ложное выравнивание.
- **Причина:** UB возникает на легитимных файлах собственного компилятора. Кроме того, remote-ответ, начинающийся с `TSRS`, мапится напрямую (`rule_set_remote.rs:430`), а его смещения контролирует автор файла.
- **Последствия:** UB при каждом IPv6-матче, возможна неверная маршрутизация. На 64-битных целях краха пока не наблюдалось, поэтому P1, а не P0.
- **Исправление:**
  - `slice_at`: `offset % align_of::<T>() == 0`, `checked_mul` и `checked_add`.
  - Компилятор: выравнивать по `align_of::<T>()` (16); либо хранить адрес как `[u8;16]` или `[u64;2]` (align 8).
  - Поднять `TSRS_VERSION`, тогда старые кэши перекомпилируются автоматически.
- **Выигрыш и риск:** устраняет UB. Риск низкий; это внутренний формат кэша.
- **Forkop X:** влияние косвенное, через remote rule-set. Совместимость конфигов не затрагивается.

#### CQ-05. Hysteria2 inbound: неограниченный `pad_len`

- **Статус:** ПОДТВЕРЖДЕНО, `…/panics-inbound/repro/src/bin/hy2_pad_alloc.rs`: `memory allocation of 4611686018427387903 bytes failed`.
- **Место:** `inbound/hysteria2.rs:302-311` → `outbound/hysteria2.rs:644` `vec![0u8; n]`.
- **Причина:** varint до 2^62 не сверяется с `MAX_PADDING`, хотя outbound эту проверку делает.
- **Последствия:** аутентифицированный клиент роняет процесс.
- **Исправление:** `if pad_len > MAX_PADDING { return Err }`, padding пропускать потоком.
- **Выигрыш и риск:** высокий выигрыш, нулевой риск.
- **Forkop X:** нет; Forkop не генерирует hy2-inbound.

#### CQ-06. UDP: лавина задач, пока поток открывается

- **Статус:** ПОДТВЕРЖДЕНО тестами `audit_udp_slow_open_task_pileup` и `audit_udp_slow_open_drain`.
- **Место:**
  - `inbound/direct.rs:236-247`, `tproxy.rs:183-221`, `tun.rs:976-990`: на каждый промах `try_existing` выполняется spawn и `payload.to_vec()`;
  - `inbound/udp.rs:494-529`: очередь на gate, и после ошибки каждая задача дозванивается заново.
- **Подтверждение:**
  - outbound с «чёрной дырой» (vless+TLS без ответа): за 2 с задачи выросли с 3 до 83364, RSS с 64 до 775 МБ;
  - 500 пакетов одного потока дали 500 задач, которые рассасываются по одной на 15-секундный таймаут.
- **Последствия:** один QUIC-клиент к заблокированному DPI серверу доводит роутер до OOM.
- **Исправление:**
  - ограниченная очередь пакетов на ключ (8–64), которой владеет открывающая задача; лишнее отбрасывать;
  - кэш неудач на ключ (N секунд);
  - семафор на одновременные открытия.
- **Выигрыш и риск:** выигрыш критический, риск средний (UDP-семантика).
- **Forkop X:** прямое влияние, это tproxy UDP. Забаненные QUIC-сервисы типичны для сценариев Forkop.

#### CQ-07. UDP NAT без лимита потоков, 64 КиБ на поток

- **Статус:** ПОДТВЕРЖДЕНО, `audit_udp_flows_unbounded`: 4000 источников дают +4000 fd, +4000 задач и +86 МБ.
- **Место:** `udp.rs:334` (HashMap), `udp.rs:877` и `tproxy.rs:223` (`vec![0;64K]` на поток, у tproxy их два).
- **Последствия:** BitTorrent/DHT или P2P за 120 с idle набирают тысячи потоков, это OOM.
- **Исправление:**
  - `max_flows` с вытеснением самого старого idle-потока и лимит на источник;
  - приёмный буфер 2–4 КиБ с ростом по `MSG_TRUNC` или общий пул;
  - инкрементальная очистка вместо `retain` на каждый новый поток. Сейчас это O(N²) (`tproxy.rs:186`).
- **Выигрыш и риск:** на 128 МБ выигрыш большой, риск низкий–средний.
- **Forkop X:** прямое влияние (tproxy).

#### CQ-08. Дефрагментатор Hysteria2 и TUIC без срока жизни

- **Статус:** ПОДТВЕРЖДЕНО, `audit_defragger_never_expires`: +92 МБ, при повторном использовании id ещё +60 МБ.
- **Место:** `outbound/quic.rs:1128-1172`.
- **Исправление:** хранить 1–4 пакета в сборке (так делает upstream Hysteria), ввести лимит по байтам и TTL.
- **Выигрыш и риск:** высокий выигрыш, низкий риск.
- **Forkop X:** влияет на hy2-outbound, который Forkop поддерживает (`generator.uc:544,724`). Злонамеренный или сломанный сервер может съесть память роутера.

#### CQ-09. TUN: полуоткрытые TCP-сессии не удаляются

- **Статус:** ПОДТВЕРЖДЕНО на модели smoltcp 0.14 (`…/panics-parsers/tun-synrecv`): 1000 SYN дают 1000 сокетов в SYN-RECEIVED и 125 МиБ через час; путь утечки подтверждён чтением кода.
- **Место:**
  - `inbound/tun.rs:1003-1029` и `:1141`: каждый SYN выделяет 2×64 КиБ и запускает `drive_framed` с дозвоном до завершения handshake;
  - `:852-896`: очистка только по Closed/TimeWait или `app_closed`;
  - нигде не вызывается `set_timeout`, поле `created` не читается;
  - RST в SynReceived возвращает сокет в Listen.
- **Последствия:** SYN-скан из LAN без ограничений растит память. Каждый пакет стоит O(сессий).
- **Исправление:** лимит полуоткрытых сессий, `set_timeout` и `set_keep_alive`, сбор сессий старше 10 с без Established и сессий в Listen; буферы выделять после Established.
- **Выигрыш и риск:** высокий выигрыш, средний риск.
- **Forkop X:** нет, Forkop не использует TUN.

#### CQ-10. DNS hijack: задача и 64 КиБ на каждый запрос без ограничения

- **Статус:** КОД.
- **Место:** `inbound/udp.rs:563` (`hijack_one` на каждый пакет), `dns/transport.rs:1181` (`vec![0;65535]` на обмен), `dns/mod.rs:662` (`inflight.retain` O(n)).
- **Последствия:** флуд случайными именами из LAN приводит к OOM или исчерпанию fd. С `store_fakeip` к этому добавляется блокировка cache.db (CQ-13).
- **Исправление:** семафор на одновременные обмены (при переполнении отвечать SERVFAIL), буфер 1232–4096 Б, удаление из inflight через drop-guard.
- **Выигрыш и риск:** средний выигрыш, низкий риск.
- **Forkop X:** прямое влияние: DNS-inbound `direct` и FakeIP.

#### CQ-11. DNS по UDP: не проверяются ID и question ответа

- **Статус:** КОД. Безопасность, передаю аудитору безопасности.
- **Место:** `dns/transport.rs:1163-1214` принимает первую датаграмму на connected-сокете; `dns/mod.rs:683-711` кэширует по имени из запроса.
- **Последствия:** off-path подмена с перебором только порта; отравление кэша и неверные решения FakeIP и маршрутизации.
- **Исправление:** в цикле до таймаута отбрасывать ответы, где `id != query.id` или question не совпадает.
- **Выигрыш и риск:** высокий выигрыш, низкий риск.
- **Forkop X:** прямое влияние.

#### CQ-12. bbolt: бесконечная рекурсия на циклах страниц

- **Статус:** ПОДТВЕРЖДЕНО, `…/panics-parsers/bbolt-cycle`: `has overflowed its stack`, exit 134.
- **Место:** `crates/core-experimental/src/bbolt.rs:215`, `:282`, `:350`.
- **Причина:** нет множества посещённых страниц и лимита глубины. Для DAG рост экспоненциальный, потому что `load_page` делает `to_vec`.
- **Последствия:** повреждённый `cache.db`, например после отключения питания (см. CQ-13), даёт crash-loop при каждом старте, пока файл не удалят.
- **Исправление:**
  - visited-set и глубина не больше 64;
  - `2 <= child < meta.pgid`;
  - лимит общего числа элементов;
  - при ошибке переименовывать файл в `.corrupt`.
- **Выигрыш и риск:** высокий выигрыш, нулевой риск.
- **Forkop X:** есть. Путь `/tmp/sing-box/cache.db` лежит в tmpfs, это снижает вероятность, но у пользователя может быть путь на flash.

#### CQ-13. cache.db переписывается целиком, синхронно и под блокировками, без fsync

- **Статус:** ПОДТВЕРЖДЕНО, `audit_cache_flush_cost`: база 8 МБ даёт в среднем 84 мс на смену selector на x86.
- **Место:**
  - `cache_file.rs:197-209, 274-327`;
  - `core-experimental/src/bbolt.rs:648-654` (`fs::write` без `sync_all`);
  - `route/mod.rs:1315-1364` (flush при каждой смене selector и при reload);
  - `clash_state.rs:236-246` (flush под глобальным Mutex реестра соединений);
  - `dns/transport.rs:444-515` (persist FakeIP под state-локом);
  - `rule_set_remote.rs:296-316` (тела rule-set в cache.db).
- **Последствия:**
  - DNS и FakeIP стоят на время записи; на MIPS/ARM и flash это сотни миллисекунд и больше. На одноядерном `current_thread` останавливается весь трафик.
  - Износ flash: при `store_fakeip` полный файл пишется каждые 60 с.
  - В RAM 3–4 копии БД.
  - После отключения питания возможен пустой или рваный файл, и тогда срабатывает CQ-12.
- **Исправление:**
  - rule-set хранить в отдельных файлах (в cache.db только etag, время и хэш);
  - snapshot малых бакетов под локом, запись в `spawn_blocking` вне всех локов;
  - debounce persist для selector;
  - `sync_all` для tmp и fsync каталога перед `rename`.
- **Выигрыш и риск:** высокий выигрыш, средний риск (формат и миграция).
- **Forkop X:** прямое влияние: `store_fakeip: true` (`generator.uc:528`). Совместимость формата bbolt с sing-box надо сохранить, Forkop читает cache-файлы (`priority.uc:155`).

#### CQ-14. WireGuard с `listen_port` ломает in-place reload

- **Статус:** ПОДТВЕРЖДЕНО, `audit_wireguard_listen_port_breaks_in_place_reload`: `bind udp port 25510: Address already in use`, хотя изменился только `log.level`.
- **Место:** `route/mod.rs:1111-1117`, `outbound/wireguard/mod.rs:400`, `:1858`.
- **Причина:** новый стек делает bind, пока старый ещё держит порт. Старый живёт, пока жив хоть один `cmd_tx`.
- **Последствия:** SIGHUP отвергается. Гипотеза: при полном reload старые соединения держат старый Router, `start(previous)` тоже падает, и процесс завершается.
- **Исправление:** переиспользовать неизменённые endpoint между inner; явный Stop или CancellationToken старого стека до rebind.
- **Выигрыш и риск:** высокий выигрыш, средний риск.
- **Forkop X:** прямое влияние: DNS failover через SIGHUP перестаёт работать у пользователей WG-сервера.

#### CQ-15. WireGuard-респондер не проверяет TAI64N, `index_peer` только растёт

- **Статус:** КОД. Передаю аудитору безопасности.
- **Место:** `outbound/wireguard/mod.rs:1246-1290`. Для сравнения, в `tailscale/mesh.rs:675` проверка есть.
- **Последствия:** повтор перехваченного initiation сбрасывает сессию и переводит `resolved` на адрес атакующего; память растёт.
- **Исправление:** хранить на пира `latest_timestamp` и отвергать значения `<=`; ограничить частоту initiation; удалять старый index.
- **Выигрыш и риск:** высокий выигрыш, низкий риск.
- **Forkop X:** при WG-конфигурациях.

#### CQ-16. fd TUN никогда не закрывается, полный reload с TUN роняет процесс

- **Статус:** КОД. Нужен root, поэтому не запускалось. `grep close inbound/tun.rs` находит закрытие только на ошибочном пути.
- **Место:** `inbound/tun.rs:173,278` (`AsyncFd<RawFd>` не закрывает fd), `:569` (Drop только чистит маршруты), `:1419` (нет `O_CLOEXEC`), `lib.rs:502-519`.
- **Последствия:**
  - После `shutdown_wait` интерфейс остаётся привязан к старому fd, и новый `TUNSETIFF` с тем же именем получает EBUSY.
  - `start(next)` и `start(previous)` оба падают, и `run_with_loader` возвращает Err: процесс выходит.
  - Кроме того, fd наследуется дочерними `ip` и `netns-holder`.
- **Исправление:** хранить `AsyncFd<OwnedFd>`, как в `tailscale/lan.rs:110`; открывать с `O_CLOEXEC`.
- **Выигрыш и риск:** высокий выигрыш, низкий риск.
- **Forkop X:** по умолчанию нет; Forkop не генерирует tun.

#### CQ-17. Свидетельство Clash-правила считается на каждое соединение

- **Статус:** ПОДТВЕРЖДЕНО бенчмарком `…/hotpath/ws/crates/core-runtime/examples/clashmatch.rs`. Для 5000 `domain_suffix`: `matches` 20 мкс, `clash_match` 1,56 мс.
- **Место:** `route/mod.rs:1199` → `rule.rs:627-640`, `:808-822`.
- **Причина:** на каждое соединение клонируются списки, `format!` делается на каждый элемент, `matches()` выполняется повторно. Так происходит даже без Clash API.
- **Исправление:** описание правила считать один раз как `Arc<str>`, evidence вычислять лениво.
- **Выигрыш и риск:** при больших inline-списках снимает до 99% CPU маршрутизации на соединение. Риск низкий.
- **Forkop X:** inline-правила Forkop небольшие, но пользовательские списки доменов могут быть большими.

#### CQ-18. NTP с именем хоста блокирует старт и делает его фатальным

- **Статус:** ПОДТВЕРЖДЕНО: `ntp.server: "ntp.invalid"` даёт выход с rc=1.
- **Место:** `ntp.rs:188` (синхронный `ToSocketAddrs`), `lib.rs:303`.
- **Последствия:** при загрузке без WAN ядро не стартует. Блокирующий getaddrinfo выполняется на async-потоке.
- **Исправление:** резолвить при синхронизации через `dial::resolve` с повтором, учитывать `DialOptions`.
- **Выигрыш и риск:** высокий выигрыш, низкий риск.
- **Forkop X:** только если Forkop или пользователь включают `ntp`.

### P2 — заметные краевые случаи и оптимизации

#### CQ-19. TSRS через `MAP_SHARED`: изменение файла на месте

- **Статус:** ПОДТВЕРЖДЕНО, `…/panics-parsers/tsrs/src/bin/sigbus.rs`: «Bus error», exit 135.
- **Место:** `mmap_io.rs:46`, `mmap_set/mod.rs:94` (`view()` разбирает файл заново на каждый матч и вызывает `.expect`).
- **Последствия:** `cp` или `curl -o` поверх `type: local` TSRS дают SIGBUS или панику. Собственные писатели используют tmp+rename и безопасны.
- **Исправление:** проверенные срезы кэшировать один раз при открытии; `MAP_PRIVATE`; документировать «замена только через rename»; убрать `expect`.
- **Риск:** низкий.
- **Forkop X:** Forkop пишет через rename (`ruleset_cache.uc:449`), так что влияния нет.

#### CQ-20. Дубль: блокирующий getaddrinfo в NTP

Описано в CQ-18. Также `dns/mod.rs:939` (CQ-24).

#### CQ-21. Вендоренный h2: недокументированные буферы и нет `max_concurrent_streams`

- **Статус:** КОД (дифф с upstream 0.4.19).
- **Место:** `vendor/h2/src/codec/framed_write.rs:64` (`DEFAULT_BUFFER_CAPACITY` 16→128 КиБ) и `vendor/h2/src/codec/mod.rs:43-52` (`FramedRead::with_capacity(…, 256 КиБ)`).
- **Причина:** обе правки не упомянуты ни в `Cargo.toml`, ни в README; документирован только `UNCLAIMED_DENOMINATOR` 2→32.
  - **Буферы.** Около 384 КиБ выделяется заранее на каждое h2-соединение: DoH, gRPC, xhttp, h2mux, masque, tailscale. Upstream выделяет около 24 КиБ.
  - **`UNCLAIMED_DENOMINATOR`.** Само изменение корректно (тест `UNCLAIMED_NUMERATOR < DENOMINATOR` сохраняется), но WINDOW_UPDATE отправляется в 16 раз чаще.
  - **`max_concurrent_streams`.** Серверные h2-транспорты (`inbound/transport.rs:575-620`) работают без этого лимита и копят сессии в неограниченный `Vec`. Это ГИПОТЕЗА.
- **Исправление:**
  - вернуть 16 КиБ и 8 КиБ, оставив большие буферы опцией только для bulk-транспортов, или документировать цену;
  - выставить `max_concurrent_streams(…)`;
  - описать все три изменения в `vendor/h2/RUST-X-PATCH.md`.
- **Риск:** низкий, нужен замер throughput. Передаю аудитору памяти и RSS.
- **Forkop X:** DoH и gRPC-подписки.

#### CQ-22. AF_ALG: `expect` в `seal`, невыровненный cmsg, блокирующие вызовы

- **Статус:** КОД и ГИПОТЕЗА.
- **Место:** `core-crypto/src/afalg.rs:291` (`.expect("afalg seal")`), `:197` (`cbuf=[0u8;128]`), `:221` и `:471` (синхронные sendmsg/recvmsg), `:513-560` (калибровка в первом `Gcm::new`).
- **Последствия:**
  - ENOMEM или ошибка DMA-драйвера (EIP97 на aarch64 MT798x) вызывают панику, а значит abort.
  - Каждый экземпляр `Gcm` держит 2 fd.
  - Зависший драйвер блокирует воркер.
- **Исправление:**
  - при ошибке ядра fallback на `self.sw.seal`, который даёт идентичный результат;
  - `#[repr(C, align(8))]` для `cbuf`;
  - `self_test` должен возвращать false вместо паники.
- **Риск:** низкий.
- **Forkop X:** нет.

#### CQ-23. splice: пайп 1 МиБ на направление

- **Статус:** ГИПОТЕЗА, передаю аудитору RSS.
- **Место:** `inbound/relay.rs:26-29, 50`.
- **Последствия:** при медленном Wi-Fi-клиенте в ядре висит до rcvbuf + 1 МиБ + sndbuf на соединение. Под root лимит pipe-user-pages не действует.
- **Исправление:** 64–128 КиБ с ростом при устойчивом потоке, либо ручка в конфиге.
- **Риск:** низкий.
- **Forkop X:** прямое влияние, это основной TCP-путь tproxy.

#### CQ-24. `domain_resolver` в объектной форме игнорируется

- **Статус:** ПОДТВЕРЖДЕНО: 5 запросов дают 5 строк WARN.
- **Место:** `dns/transport.rs:866-869`, `dns/mod.rs:939-944`.
- **Последствия:** строка лога и системный lookup (getaddrinfo) на каждый запрос, возможна петля через dnsmasq.
- **Исправление:** разбирать обе формы, кэшировать адрес, предупреждать один раз.
- **Риск:** низкий.
- **Forkop X:** проверить, какую форму генерирует Forkop. Если объектную — влияние прямое.

#### CQ-25. TUN auto_route и ioctl: ошибки проглатываются

- **Статус:** ГИПОТЕЗА, нужен root.
- **Место:** `tun.rs:1454-1497`, `:1529-1600`.
- **Причина:** `let _ =` стоит на SIOCSIFMTU, SIOCSIFFLAGS, SIOCSIFADDR и на `ip rule` и `ip -6`. Если SIOCGIFFLAGS провалился, в flags записывается мусор из union. Свой SO_MARK 0x2022 не выставляется.
- **Последствия:** петля маршрутизации или blackhole после abort.
- **Исправление:** проверять каждый шаг и откатывать.
- **Риск:** средний.
- **Forkop X:** нет.

#### CQ-26. TCP-inbound: нет дедлайна handshake, keepalive и idle

- **Статус:** КОД.
- **Причина:**
  - В `mixed.rs` и plain vless нет таймаутов.
  - На принятые сокеты не ставится SO_KEEPALIVE.
  - Relay (`relay.rs:217-253`) держит соединение до закрытия обеих сторон.
  - Accept-цикл Clash API завершается при первой ошибке (`clash_api.rs:281-296`) и читает заголовок по одному байту за syscall (`:1720`).
  - Лимита соединений нет.
- **Исправление:** дедлайн handshake, keepalive при accept (умолчания sing-box), `serve_stalled` в Clash API.
- **Риск:** низкий.
- **Forkop X:** tproxy TCP, Clash API.

#### CQ-27. Логирование синхронно, `eprintln!` паникует при EPIPE

- **Статус:** ГИПОТЕЗА.
- **Место:** `logging.rs:205-247`.
- **Последствия:** если перезапустить logd или procd, то при закрытом stderr `eprintln!` паникует, и это abort. Заполненный pipe блокирует воркер.
- **Исправление:** `let _ = writeln!(stderr, …)` или отдельный поток-писатель с ограниченным каналом; ограничение частоты повторяющихся ошибок (`tun.rs:467` пишет 10 строк в секунду).
- **Риск:** низкий.
- **Forkop X:** прямое влияние, ядро запускается под procd.

#### CQ-28. TSO-сегментация неверна для IPv6 и флагов FIN/PSH

- **Статус:** ПОДТВЕРЖДЕНО, тест `cq_audit_tso::cq_tso_ipv6_and_fin` в `…/scratchpad/cq/xrust`.
- **Место:** `inbound/tun.rs:1192-1243`.
- **Подтверждение:** IPv6-сегменты получают `payload_len=3020` при фактических 1020 и одинаковый `seq=1000`. FIN|PSH копируется во все сегменты, IPv4 тоже. Подразумевается IHL=5.
- **Последствия:** при `gso: true` IPv6 TCP теряется, возможно преждевременное закрытие.
- **Исправление:** для v6 обновлять `payload_len` и seq по смещению `40 + 4`; FIN/PSH только в последнем сегменте; учитывать IHL и `csum_start`; либо запретить gso.
- **Риск:** низкий (опция по умолчанию выключена).
- **Forkop X:** нет.

#### CQ-29. DNS-кэш отдаёт исходный TTL; `parse_query` выполняется дважды

- **Статус:** КОД.
- **Место:** `dns/mod.rs:652-679`, `:431` и `:577`.
- **Исправление:** хранить `expires` и переписывать TTL через существующий `codec::rewrite_ttl`; передавать `QueryInfo` дальше.
- **Выигрыш и риск:** корректность плюс около −50% CPU на попадание в кэш. Риск низкий.
- **Forkop X:** прямое влияние.

#### CQ-30. TUN: копирования на пакет и O(сессий) на пакет

- **Статус:** КОД.
- **Место:** `tun.rs:480` (`vec![raw.to_vec()]`), `:1052`, `:868`, `:974`, `:851`; новый `sleep` на каждой итерации.
- **Исправление:** передавать срез без TSO, пул буферов, «грязное» множество сессий, `Sleep::reset`.
- **Выигрыш и риск:** 2–3 аллокации меньше на пакет. Риск низкий.
- **Forkop X:** нет.

#### CQ-31. Блокирующая работа на async-потоках

- **Статус:** КОД.
- **Места:**
  - `protect::protect` (`dial.rs:832,885`): синхронные connect и read UnixStream без таймаута, причём protect выполняется **после** connect;
  - `netns::in_namespace`: новый OS-поток на каждый dial;
  - `checked_config` и `Router::prepare` (компиляция rule-set и regex);
  - `std::fs::write` у TSRS (`rule_set_remote.rs:139-146`);
  - `find_process` по `/proc` (`route/process.rs:205-240`);
  - чтение hosts-файла на каждый lookup (`dns/transport.rs:95-110`).
- **Исправление:** `spawn_blocking`; protect до connect; долгоживущий поток на netns.
- **Риск:** низкий.
- **Forkop X:** reload по SIGHUP на одноядерном роутере стопорит трафик.

#### CQ-32. DNS-кодек: краевые случаи

- **Статус:** КОД.
- **Места:**
  - `codec.rs:413` `set_client_subnet` добавляет OPT, но не увеличивает ARCOUNT, хотя hijack пересылает клиентские байты;
  - тела DoH/DoH3 не ограничены (`transport.rs:1393`, `:1635`, `:1440-1513`);
  - TCP hijack пишет `resp.len() as u16` (`route/mod.rs:1802`);
  - у кэша нет бюджета в байтах: 1024 × 64 КБ.
- **Исправление:** EDNS через hickory, лимит 65535, бюджет в байтах.
- **Риск:** низкий.
- **Forkop X:** прямое влияние.

#### CQ-33. Mixed и Hysteria2 inbound: head-of-line и лишние fd

- **Статус:** КОД.
- **Место:** `inbound/hysteria2.rs:357-378` (UDP-цикл ждёт `hub.handle` и `resolve_host` прямо в цикле), `outbound/quic.rs:1177-1186` (loopback-пара сокетов с буферами 4 МиБ на UDP-сессию).
- **Риск:** низкий.
- **Forkop X:** hy2-outbound.

#### CQ-34. Пул relay-буферов «дребезжит»

- **Статус:** ГИПОТЕЗА.
- **Место:** `inbound/mod.rs:678-724`, `:798-875`.
- **Причина:** 128 КиБ возвращаются в глобальный пул (до 16) на каждом Pending; когда соединений больше 16, это mmap и munmap на каждое пробуждение.
- **Исправление:** отдавать буфер после 1 с простоя.
- **Риск:** низкий.

### P3 — чистка

#### CQ-35. Сводная чистка

Каждый пункт — КОД, риск низкий, на Forkop не влияет.

- 14 предупреждений dead code в rust-x. Модули `shadowsocks`, `vmess`, `fptn` и `proxy` компилируются в rust-x без пользы.
- Вне релизного профиля:
  - `inbound/vmess.rs:457-474`: заголовок длиной 38–39 байт вызывает OOB-панику (ПОДТВЕРЖДЕНО тестом). Модуль под `legacy-protocols`.
  - 32-битные усечения не касаются релизных целей x86_64 и aarch64, но мешают переносу на MIPS и armv7: `inbound/transport.rs:1466,1490` (`remaining as usize`), `matcher.rs:26,89` (переполнение `offset + count*size`), `compiler.rs:239` (`len as u16`).
- В mmap и rule-set:
  - `mmap_io.rs` `from_bytes` при неудачном mmap молча даёт пустой буфер; надо возвращать `Result`.
  - `matcher.rs` `matches_domain` вызывает `to_ascii_lowercase` на каждый вызов, хотя комментарий обещает «0 аллокаций».
  - `rule_set_index.rs:587`: ошибка сборки Aho-Corasick прячется в `.ok()`, и `domain_keyword` молча перестаёт работать.
- В работе с fd и syscalls:
  - `netns.rs:181`: утечка fd при ошибке SIOCGIFFLAGS. `dial.rs`: перейти на `OwnedFd`.
  - `tailscale/lan.rs:143`: `vec![0;1280]` на каждую попытку чтения, даже при WouldBlock.
  - `protect.rs` `recv_fd`: `MSG_CMSG_CLOEXEC`, проверки cmsg.
  - Буферы cmsg (`tproxy.rs:153`, `protect.rs:53`): явное выравнивание.
- Прочее:
  - `main.rs:600`: индексы `mi_option_set` брать из `libmimalloc_sys`.
  - Игнорируемые `getrandom` для крипто-материала (`quic.rs:148,505,…`, `xhttp.rs:111,…`, `wireguard/mod.rs:84`): заменить на `expect`.
  - Секрет Clash сравнивается через `==`, а не за постоянное время (`clash_api.rs:1623`).
  - `tls_client.rs:803`, `vmess/kdf.rs:143`: срез `&str` на конфиг-данных с не-ASCII паникует при загрузке конфига.
  - FakeIP: обратный порядок локов в `attach_cache` (cache→state против state→cache). Сейчас безопасно, но хрупко.
  - Окно двойной выдачи FakeIP между `migrate_from` и `set_service` (`lib.rs:159-171`): микросекунды.

## 4. core-experimental (bbolt) и вендоренные патчи

**bbolt.** Реализован минимальный читатель и писатель формата bbolt.
- Файл целиком читается в память (`fs::read`).
- Используется только meta-страница 0, без выбора по txid. Контрольная сумма meta: см. `parse_meta`.
- Поиск идёт DFS по всем детям, без бинарного поиска, и каждая страница копируется через `to_vec`. Это O(страниц) на `get`.
- Запись пересобирает файл целиком и пишет через `fs::write` без fsync.
- Для объёма бакетов Forkop (selector, mode, FakeIP) это приемлемо, но не для тел rule-set.
- Найденные риски: CQ-12 (циклы), CQ-13 (стоимость и атомарность). Также рекурсия `build_branch` уходит в бесконечность при ключах больше 2 КБ; сейчас это недостижимо (P3).
- Совместимость с sing-box по формату надо сохранить, Forkop работает с cache-файлами.

**vendor/blake3.** Патч корректный и минимальный: добавлены API для байтового контекста, хэш-ядро не тронуто, `RUST-X-PATCH.md` описывает изменение точно. Рисков нет.

**vendor/h2.**
- `UNCLAIMED_DENOMINATOR = 32`: корректно и обосновано замером в `Cargo.toml`.
- Ещё две правки, буферы записи 128 КиБ и чтения 256 КиБ, **не задокументированы**. Они увеличивают память на соединение примерно в 16 раз (CQ-21).
- Удалён комментарий о минимальном размере для HEADERS. Функционально это не важно, потому что 128 КиБ больше 16 КиБ.
- Рекомендация: файл `vendor/h2/RUST-X-PATCH.md` со всеми тремя изменениями и пересмотр размеров буферов для 128 МБ.

## 5. Порядок исправлений

1. **Срочно:** CQ-01, CQ-02, CQ-03, CQ-05, CQ-12, а также `.take()` для zlib в CQ-03. Это точечные правки, каждая на несколько строк.
2. **Ресурсы на роутере:** CQ-06, CQ-07, CQ-08, CQ-10, CQ-13 (вынести тела rule-set, fsync, запись вне локов), CQ-04, CQ-16, CQ-14.
3. **Безопасность**, вместе с аудитором TLS и крипто: CQ-11, CQ-15.
4. **Остальное:** P2 и P3 по мере работы.

Совместимость с Forkop X:
- Ни одна правка не меняет схему конфигурации.
- CQ-04 меняет только внутренний формат TSRS-кэша; старые кэши пересоберутся через `TSRS_VERSION`.
- В CQ-13 формат cache.db должен остаться bbolt-совместимым.
