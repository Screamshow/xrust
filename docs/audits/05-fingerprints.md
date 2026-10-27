# Аудит 05: сетевые отпечатки и совместимость наблюдаемого поведения

Дата: 2026-10-23. Объект: xrust v0.0.26 (коммит `c5f567c`), бинарник `tachyon-core`
(release, `--locked`, x86_64-gnu, собран в scratchpad). Конфиги сверялись с генератором
Forkop X (`forkop/files/usr/lib/singbox/generator.uc`, `forkop/files/usr/lib/subscription/parser.uc`).

Статусы находок: **подтверждено** — есть данные захвата или воспроизводимый loopback-тест;
**гипотеза** — вывод из кода или по памяти, захватом не подтверждён; **не проверено** — проверить
в этой среде нельзя.

## 1. Методология и ограничения

### 1.1 Эталоны

| Компонент | Версия | Источник | SHA-256 архива |
|---|---|---|---|
| Xray-core | **v26.10.21** (1b1647c, go1.27.3), uTLS `v1.8.3-0.20260301010127-aa6edf4b11af` (go.mod) | GitHub release `Xray-linux-64.zip` | `0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978` (совпадает с `.dgst`) |
| sing-box | **v1.14.3** (7054cac, go1.26.8, tags with_utls,with_quic,…) | GitHub release `sing-box-1.14.3-linux-amd64.tar.gz` | `e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee` |
| xrust | 0.0.26, `cargo build --locked --release -p core-cli` | локальная сборка | — |

Эталонные бинарники лежат только в scratchpad (`…/scratchpad/ref/`) и запускались только на
127.0.0.1. Для сверки поведения в `…/scratchpad/ref/src/` сохранены несколько исходных файлов
Xray v26.10.21: splithttp, tls, reality, grpc, websocket, httpupgrade, конфиг hysteria.

### 1.2 Стенд

* Все клиенты получали одинаковые outbound: sing-box JSON для xrust и sing-box, эквивалентный
  JSON для Xray. Схема: SOCKS5 на loopback → outbound → захватывающий сервер на loopback.
* `capsrv.py` — userspace-сервер. Режимы:
  * `raw` — сохраняет ClientHello;
  * `tls` — терминирует TLS через python `ssl` + `MemoryBIO`, поэтому одновременно пишутся
    сырой поток записей с таймингами и расшифрованный поток. Сервер отвечает минимальным
    HTTP/2 (SETTINGS/ACK, `:status 200`, WINDOW_UPDATE, при необходимости вталкивает DATA для
    измерения WINDOW_UPDATE клиента), HTTP/1.1 Upgrade (101 с правильным Accept) и HTTP/1.1;
  * `udp` — сохраняет датаграммы QUIC.
* Initial-пакеты QUIC расшифровывались по RFC 9001: ключи выводятся из DCID, снимается
  header protection, AES-128-GCM, затем CRYPTO-фреймы собираются по смещениям.
* JA3/JA3N/JA4/JA4_o/JA3S/JA4S, HPACK (с Huffman) и отпечаток HTTP/2 в стиле Akamai считаются
  собственным кодом (`fplib.py`). Его JA4 на фикстурах репозитория совпал с ожидаемым видом
  `t13d1516h2_8daaf6152771_…`.
* Совместимость проверялась так: клиент → **официальный сервер Xray/sing-box** на loopback →
  freedom/direct → локальный echo. Через туннель гоняется 256 KiB случайных данных с побайтовой
  сверкой. Цель REALITY — локальный TLS 1.3-сервер на python.
* Повторы: 12 соединений на каждый профиль TLS/REALITY (у Xray с REALITY было 50 из-за его
  ретраев). `random` и `randomized`: 8 и 5 перезапусков процесса соответственно.

### 1.3 Ограничения

* Нет root, tcpdump и tshark. TCP-опции на проводе (MSS, WScale, SACK, TS, порядок опций, TTL)
  **не проверены**. Сравнивались только `setsockopt` через strace.
* Loopback не даёт реальных RTT и потерь. Тайминги здесь — нижняя граница и порядок событий,
  а не сетевые задержки.
* Сервер на python OpenSSL 3.0.13 не поддерживает X25519MLKEM768 и всегда выбирает X25519.
  Ветка гибридного ключа на сервере, HRR и TLS 1.2 этим стендом не проверялись.
* **Сравнение с настоящими браузерами не выполнено захватом.** Браузеров на стенде нет. После
  нового ограничения пользователя (никаких внешних подключений) опубликованные эталонные JA4
  FoxIO/ja4db/tls.peet.ws не загружались. Браузерные значения ниже взяты из фикстур репозитория
  (это захваты uTLS, а не браузера) и из памяти. Они помечены как **гипотеза** и требуют сверки
  с опубликованной базой JA4 с указанием даты.
* Реальный ECH, возобновление сессий (PSK) и долгоживущие соединения не проверялись.

### 1.4 Скрипты и данные

Каталог `<scratch>/fp/`:

| Файл | Назначение |
|---|---|
| `fplib.py`, `huff_table.py` | разбор ClientHello, JA3/JA3N/JA4/JA4_o, JA3S/JA4S, расшифровка QUIC Initial, HPACK, разбор фреймов H2, отпечаток Akamai (таблица Huffman извлечена из `vendor/h2`) |
| `capsrv.py` | захватывающий сервер (`raw`/`tls`/`udp`, ответчики H2/H1, `--push` для теста WINDOW_UPDATE) |
| `run.py` | сценарии (`run.py list`), генерация конфигов трёх клиентов, SOCKS-нагрузка |
| `analyze.py` | сводка JA3/JA4, вариативность порядка, GREASE и ECH, раскладка записей → `analysis.json` |
| `h2dump.py` | дамп HTTP/2 и HTTP/1.1: SETTINGS, HEADERS, WINDOW_UPDATE, размеры DATA по времени |
| `quic_analyze.py` | JA4 (q) и transport parameters по расшифрованным Initial |
| `reality_open.py` | вскрытие session_id REALITY тестовым приватным ключом сервера |
| `compat.py` | матрица совместимости с официальными серверами Xray и sing-box |
| `cert.pem`/`key.pem`, `reality_keys.txt` | тестовые ключи (только для loopback) |

Сырые захваты лежат в `…/scratchpad/fp/captures/<сценарий>__<клиент>/`: `NNN.ch.bin`,
`NNN.c2s.bin`, `NNN.s2c.bin`, `NNN.plain.bin`, `NNN.meta.json`, конфиги и логи клиентов, для QUIC
`datagrams.jsonl`. Результаты совместимости — в `captures/compat/results.json` и логах.

## 2. Что реально задаёт Forkop X

Источники: `subscription/parser.uc:629-650,686-730,1459-1490` и `singbox/generator.uc:1809-1935`.

* `utls.fingerprint` берётся из `fp` ссылки или подписки. Допустимы `chrome, firefox, edge,
  safari, 360, ios, android, randomized`; `randomizedalpn/randomizednoalpn` → `randomized`;
  **всё остальное, включая `random` и `qq`, превращается в `chrome`**. Без `fp` поле utls не
  ставится, но для REALITY (и для Clash с `reality-opts`) по умолчанию подставляется `chrome`.
* ALPN: для XHTTP без явного значения — `["h2","http/1.1"]`; для WS и HTTPUpgrade любой ALPN
  принудительно заменяется на `["http/1.1"]`; в остальных случаях берётся значение из ссылки
  или не задаётся.
* У Hysteria2 блок `tls.utls` вырезается (`generator.uc:724`).
* XHTTP: `mode` из ссылки (по умолчанию `auto`), `x_padding_bytes: "100-1000"`,
  `sc_max_each_post_bytes: 1000000`, `sc_min_posts_interval_ms: 30`, `no_grpc_header: false`,
  поле `host`; поля `extra`/xmux из ссылки.
* WS: `path`, `headers.Host`, `max_early_data` из `ed`. **`early_data_header_name` генератор
  не задаёт** (`generator.uc:1904-1909`).
* Транспорты: `ws, grpc, httpupgrade, http (h2), xhttp`, плюс hysteria2.

Отсюда приоритетные для сравнения конфигурации: **REALITY + chrome** (умолчание), TLS +
`fp=chrome/firefox/safari`, XHTTP (h2), gRPC, WS/HTTPUpgrade с `http/1.1`, Hysteria2.

## 3. ClientHello: TLS поверх TCP

### 3.1 Сводная таблица (12 захватов на ячейку, SNI `www.example.com`, ALPN h2,http/1.1)

| Профиль | Клиент | JA4 | различных JA3 / 12 | порядков расширений | ECH payload (уникальных) | длина hello | GREASE |
|---|---|---|---|---|---|---|---|
| chrome | **xrust** | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | **1** (`b0fee100f411ab4f00ca161d3c566910`) | **1** | **1** (тот же, что в фикстуре) | **1784 всегда** | меняются только ID двух GREASE-расширений; cipher `7a7a`, groups/key_share `8a8a`, versions `0a0a` **статичны** |
| chrome | Xray 26.10.21 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 12 | 12 | 12 | 1720/1752/1784/1816 | всё случайно |
| chrome | sing-box 1.14.3 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 12 | 12 | 12 | 1720…1816 | всё случайно |
| firefox | **xrust** | `t13d1715h2_5b57614c22b0_a54fffd0eb61` | 1 | 1 | **1** | 1885 | нет (как у Firefox) |
| firefox | Xray | `t13d1715h2_5b57614c22b0_a54fffd0eb61` | 1 | 1 | 12 | 1885 | нет |
| firefox | sing-box | `t13d1715h2_5b57614c22b0_5c2c66f702b0` (старый, без MLKEM) | 1 | 1 | 12 | 658 | нет |
| safari | **xrust** | `t13d2013h2_a09f3c656075_7f0f34a4126d` | 1 | 1 | — | 1533 | ID расширений меняются, остальное статично |
| safari | Xray | `t13d2013h2_a09f3c656075_7f0f34a4126d` | 1 | 1 | — | 1533 | всё случайно |
| safari | sing-box | `t13d2014h2_a09f3c656075_14788d8d241b` (старый, padding, без MLKEM) | 1 | 1 | — | 512 | всё случайно |
| edge / ios / qq | все три | совпадают между клиентами (`t13d1515h2_…de4a06bb82e3`, `t13d2613h2_…845d286b0d67`, `t13d1516h2_…e5627efa2ab1`) | 1 | 1 | — | 512 (padding) | у xrust для qq статичны те же поля, что у chrome |
| android / 360 | **xrust** | **соединение не устанавливается** | — | — | — | — | — |
| android / 360 | Xray, sing-box | `t12d120700_…`, `t12d2010s2_…` | 1 | 1 | — | 185/245 | — |
| нет utls | **xrust** | `t13d151500_8daaf6152771_d8a2da3f94cd` (Chrome без ALPN) | 1 | 1 | 1 | 1766 | как у chrome |
| нет utls | sing-box | `t13d131100_f57a46bbacb6_e5728521abd4` (Go crypto/tls) | 1 | 1 | — | 1506 | — |
| randomized | **xrust** | 5 разных на 5 процессов (`t13d0713h2…`, `t13d1014h2…` и т. д.) | 5 | 5 | **1 на все процессы** | 1751–1767 | есть GREASE |
| randomized | Xray / sing-box | 5 разных на 5 процессов | 5 | 5 | — | 1488–1579 / 512 | GREASE нет |
| random | xrust | chrome/firefox/edge/safari/ios (на процесс) | — | — | 1 | — | — |

JA3N (отсортированные расширения) у xrust, Xray и sing-box для chrome совпадает:
`8e19337e7524d2573be54efb2b0784c9`. Состав расширений, supported_groups
(`GREASE, X25519MLKEM768, x25519, secp256r1, secp384r1`), key_share (`GREASE(1), X25519MLKEM768(1216),
x25519(32)`), signature_algorithms (`0403 0804 0401 0503 0805 0501 0806 0601`), compress_certificate
(`brotli`), ALPS `h2` (новый код `0x44cd`), `psk_key_exchange_modes=[1]`, session_ticket (пустой),
`status_request` и `SCT` у xrust chrome **совпадают с uTLS**. PSK и early_data не отправляет ни
один клиент. `record_size_limit=16385` есть только у Firefox (у всех трёх клиентов).

Различие в REALITY + chrome: sing-box 1.14.3 **не** предлагает X25519MLKEM768 (hello 498–594 B),
а Xray и xrust предлагают (1720–1816 / 1784 B).

### 3.2 REALITY

`reality_open.py` вскрыл session_id тестовым приватным ключом сервера:

| Клиент | версия в session_id | время | short_id | шифрование |
|---|---|---|---|---|
| xrust | **26.3.27** (константа) | unix-время | верный | AES-256-GCM, nonce = random[20:], AAD = hello с обнулённым sid — **совпадает с Xray** |
| Xray 26.10.21 | 26.10.21 | unix-время | верный | эталон |
| sing-box 1.14.3 | 1.8.1 | unix-время | верный | то же |

Снаружи session_id выглядит как 32 случайных байта у всех трёх клиентов (12/12 уникальных).
Сам ClientHello REALITY у xrust — тот же статичный шаблон chrome/firefox/safari, что и в
таблице 3.1.

### 3.3 Hysteria2 / QUIC Initial

| Клиент | JA4 (QUIC) | состав | Initial |
|---|---|---|---|
| **xrust** (rustls + quinn) | `q13d0311h3_55b375c5d22e_2ef3b9f41feb` | только x25519 (без MLKEM), без compress_cert, ECH и ALPS; sigalgs в порядке rustls `0807,0403,…`; TP: `grease_quic_bit`, `min_ack_delay` (`0xff04de1b`), `active_connection_id_limit=5`, `max_udp_payload_size=1472`, `initial_max_data=20 MiB`, stream `8 MiB` | датаграмма **1200 B**, DCID 20 B, SCID 8 B, один CRYPTO + PADDING, PTO 1 с / 2 с |
| sing-box 1.14.3 | `q13d0311h3_55b375c5d22e_653d80c3fe9d` | X25519MLKEM768, ECH, ALPS, brotli; TP в стиле Chrome (`google_connection_options`, `version_information`, `max_datagram_frame_size=65536`) | **1250 B**, DCID 8 B, SCID 0, CRYPTO разрезан на куски вперемешку с PING и PADDING (chaos protection) |
| Xray 26.10.21 | `q13d0311h3_55b375c5d22e_653d80c3fe9d` | то же, что у sing-box | то же |

## 4. HTTP/2 поверх TLS (gRPC, XHTTP, H2)

| Параметр | xrust (gRPC, XHTTP, H2 одинаково) | Xray (XHTTP) | Xray (gRPC) | sing-box (gRPC / H2) | Chrome (гипотеза, по памяти) |
|---|---|---|---|---|---|
| SETTINGS | `4:8388608; 5:262144` | `2:0;4:4194304;5:1048576;6:10485760` | пусто | `2:0;4:4194304;5:16384;6:10485760` | `1:65536;2:0;4:6291456;6:262144` |
| начальный WINDOW_UPDATE | `33488897` | `1073741824` | нет | `1073741824` | `15663105` |
| PRIORITY-фреймы / флаг в HEADERS | нет / нет | нет | нет | нет | нет / флаг PRIORITY есть |
| псевдозаголовки | `m,s,a,p` | `a,m,p,s` | `m,s,p,a` | `a,m,p,s` | `m,a,s,p` |
| Akamai | `4:8388608;5:262144\|33488897\|0\|m,s,a,p` | `2:0;4:4194304;5:1048576;6:10485760\|1073741824\|0\|a,m,p,s` | `\|00\|0\|m,s,p,a` | `2:0;4:4194304;5:16384;6:10485760\|1073741824\|0\|a,m,p,s` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| user-agent | gRPC: `grpc-go/1.48.0`; XHTTP/H2: **нет** | Chrome 151 UA + `sec-ch-ua*`, `sec-fetch-*`, `priority`, `pragma`, `dnt`, `accept-language` (порядок меняется) | Chrome UA | gRPC `grpc-go/1.48.0`; H2 `Go-http-client/2.0` + `accept-encoding: gzip` | Chrome |
| `:authority` в gRPC | `host:port` | — | без порта | `host:port` | — |
| `:scheme` в gRPC | https | — | **http** | https | — |
| TLS-соединений на 3 SOCKS-потока (gRPC, H2) | **3** | — | 1 | **1** (мультиплекс) | — |
| записи TLS при заливке | пары **1041 + 15386** на каждый DATA 16 KiB | 16401 | 16401 | 16401 | 16401 (гипотеза) |
| WINDOW_UPDATE при скачивании 48 MiB | **225** (stream примерно каждые 256–300 KiB, conn примерно каждые 1 MiB) | 12 289 (примерно каждые 8 KiB) | — | 2 829 (16–32 KiB) | около 20 (порог 1/2 окна, гипотеза) |
| конец потока | DATA с END_STREAM | RST_STREAM | RST_STREAM | RST_STREAM | — |

### 4.1 XHTTP: детали (xrust против Xray)

| | xrust | Xray 26.10.21 |
|---|---|---|
| auto без REALITY | packet-up | packet-up |
| auto + REALITY | **packet-up** (`xhttp.rs:819`) | **stream-one** (`dialer.go:333-340`) |
| путь | `/xh/<uuid>/<seq>` (packet-up), `/xh/<uuid>` (stream-up), `/xh/` (stream-one) | так же |
| session id | UUID-подобный, **версия и вариант не выставлены** (`e06760ba-1f87-5c42-44c4-…`) | UUIDv4 (`…-4d4d-8d…`) |
| Referer (padding) | `https://host/xh/<uuid>?x_padding=000…` (**символ `0`**, путь сессии) | `https://host/xh/?x_padding=XXX…` (базовый путь, `X`) |
| content-type POST | `application/octet-stream` (packet-up), `application/grpc` (stream) | так же |
| UA и браузерные заголовки | нет | есть (см. выше), порядок случайный |
| первый POST в packet-up | **34 B — только заголовок VLESS** | заголовок VLESS + данные (8226/24610 B) |
| последующие POST | ровно **131 072 B** каждые примерно 43–45 мс | кратно 8 KiB, примерно каждые 31 мс |
| HPACK для `:path` | literal without indexing | incremental indexing |

## 5. WebSocket и HTTPUpgrade (HTTP/1.1, ALPN http/1.1)

| | xrust | sing-box 1.14.3 | Xray 26.10.21 |
|---|---|---|---|
| WS, строки после request-line | `Host, Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version` | `Host, Upgrade, Connection, Sec-WebSocket-Version, Sec-WebSocket-Key, User-Agent: Go-http-client/1.1` | `Host, User-Agent(Chrome 151), Accept, Accept-Language, Cache-Control, Connection, DNT, Pragma, Sec-CH-UA*, Sec-Fetch-*, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade` (по алфавиту, Go) |
| Sec-WebSocket-Key | 16 случайных байт, base64 | то же | то же |
| early data (`Sec-WebSocket-Protocol`) | **base64 standard с `+/` и `=`** | base64url без паддинга | base64url без паддинга |
| что входит в early data | только заголовок VLESS (34 B) | только заголовок VLESS | заголовок VLESS + первые данные |
| HTTPUpgrade | `Host, Upgrade, Connection` | `Host, User-Agent(Go), Connection, Upgrade` | браузерный набор, `Sec-Websocket-Key` |

## 6. TCP и поведение соединений (strace)

| | xrust | sing-box | Xray |
|---|---|---|---|
| `TCP_NODELAY` | да | да | да |
| `SO_KEEPALIVE` | **нет** | да (idle 300, intvl 75, cnt 9) | да (idle 45, intvl 45) |
| буферы сокета | не трогает | `SO_RCVBUF=1 MiB` на inbound | не трогает |
| CH одним сегментом | да (1789 B за один recv) | да | да |
| CCS + Finished | одним recv (80 B) | так же | так же |
| задержка CH → первые данные приложения (loopback) | 1.5–7 мс (значимая разница с эталонами не видна) | 2–4 мс | 2–9 мс |
| заголовок VLESS и первые данные | отдельные записи (51 + 74) | отдельные (51 + 74) | одна запись (108) |

## 7. Совместимость с официальными серверами (loopback, 256 KiB echo)

Клиенты против официальных серверов Xray 26.10.21 и sing-box 1.14.3. Сервер Xray выводит трафик
через socks-outbound в локальный echo: freedom в v26 по умолчанию блокирует приватные адреса
(`blocked target … blackholing`), это не ошибка клиента. Полный лог —
`…/scratchpad/fp/compat_run.log`, результаты — `captures/compat/results.json`.

| Сервер / конфигурация | xrust | sing-box (контроль) | Xray (контроль) |
|---|---|---|---|
| Xray VLESS+TLS, fp chrome / firefox / safari / qq | OK / OK / OK / OK | OK | OK |
| Xray VLESS+TLS, fp randomized | OK | FAIL (`CurvePreferences includes unsupported curve`, баг эталона) | OK |
| Xray VLESS+TLS, fp **android** (и 360 по захвату) | **FAIL**: клиент закрывает TCP без единого байта, в debug-логе `the fingerprint offers no key share` | OK | OK |
| Xray REALITY chrome / firefox / safari | OK / OK / OK | FAIL (x509, эталон 1.14.3 с Xray 26 — вне рамок) | OK |
| Xray REALITY random | FAIL | FAIL | FAIL (у всех; причина в стенде не установлена) |
| Xray XHTTP+TLS auto / packet-up / stream-up / stream-one | OK ×4 | — | OK ×4 |
| Xray XHTTP+REALITY auto / stream-one / packet-up | OK ×3 (auto у xrust = packet-up) | — | OK ×3 (auto = stream-one) |
| Xray gRPC / WS / WS+ED(header) / HTTPUpgrade | OK / OK / OK / OK | OK ×4 | OK ×4 |
| Xray Hysteria2 | OK | OK | OK |
| sing-box TLS / REALITY / gRPC / WS / HTTPUpgrade / H2 / Hysteria2 | OK ×7 | OK | OK (HTTPUpgrade — reset у контроля Xray) |
| sing-box **WS + early data** (`early_data_header_name: Sec-WebSocket-Protocol`) | **FAIL**: сервер `decode early data: illegal base64 data at input byte 14` | OK | OK |
| Конфиг как от Forkop (`max_early_data`, без `early_data_header_name`): сервер sing-box (path-mode) | **FAIL** | OK | — |
| То же: сервер Xray (ED в заголовке) | OK | FAIL (sing-box кладёт ED в путь) | — |

Итог по совместимости: на loopback xrust совместим с Xray и sing-box во всех основных
конфигурациях Forkop, кроме (1) профилей `android`/`360` и (2) WebSocket early data с
серверами sing-box (см. FP-05 и FP-06).

## 8. Находки

Формат: ID, статус, приоритет, место, причина, последствия, исправление, риск, влияние на
Forkop X. Ни одно исправление не ослабляет криптографию: ключи, MLKEM, проверка сертификатов и
REALITY-печать остаются как есть.

### FP-01 — ECH GREASE в шаблонах Chrome и Firefox — статичные байты, общие для всех установок
* **Статус:** подтверждено (12/12 chrome, 12/12 firefox, 12/12 REALITY-chrome, 15/15 randomized:
  один и тот же `enc` и payload; sha256 `bd0770d28b02` / `db0ce1643d92` совпадают с фикстурой
  `tests/spikes/clienthello/captures-sing-box-x/chrome.bin`). У Xray и sing-box — 12 из 12 уникальных.
* **Приоритет:** **P0.**
* **Место:** `crates/core-tls/src/fingerprints.rs:157` (chrome, `Ext::Static(0xfe0d, …)`), `:1306`
  (firefox), а также `:319,:472,:753,:913,:968` (варианты chrome_*); `hello.rs:149-230` (`build`
  переписывает только ID GREASE-расширений).
* **Причина:** шаблон — снимок одного ClientHello uTLS. Тело ECH-расширения (config_id `213`,
  32-байтный HPKE `enc`, 208-байтный payload) хранится как статичные данные, и `hello::build`
  его не меняет. README фикстур это признаёт: «captured ECH GREASE payloads remain templates».
* **Последствия:** однобайтовая сигнатура. Достаточно сравнить 32 байта `enc` (`f6c0a14b72eb5110…`)
  в расширении `0xfe0d`, чтобы с нулевыми ложными срабатываниями выделить любой xrust с fp
  chrome (это умолчание REALITY в Forkop), firefox, randomized и random→chrome/firefox. Заодно
  это ломает статистическое правдоподобие: длина hello всегда 1784, хотя у Chrome и uTLS она
  бывает 1720/1752/1784/1816.
* **Исправление:** ввести `Ext::EchGrease { kdf, aead }` и генерировать тело на каждое
  рукопожатие так же, как BoringSSL и uTLS (`GREASEEncryptedClientHelloExtension`): случайный
  config_id; `enc` — публичный ключ **свежей** эфемерной X25519-пары (настоящая точка кривой, не
  случайные байты); длина payload из набора {144,176,208,240} (128..224 + 16) со случайным
  содержимым. Шаблон должен хранить только kdf/aead. К криптографии сессии GREASE ECH отношения
  не имеет.
* **Риск исправления:** низкий. Серверы игнорируют GREASE ECH. Нужно обновить
  `tests/fingerprints.rs`: побайтовое сравнение заменить сравнением структуры.
* **Forkop X:** затрагивает **все REALITY-узлы** (fp по умолчанию chrome), TLS с fp chrome и
  firefox, XHTTP (chrome), а также `randomized`.

### FP-02 — Профиль chrome не перемешивает расширения: JA3 постоянен
* **Статус:** подтверждено. У xrust 12/12 одинаковый порядок, JA3 всегда
  `b0fee100f411ab4f00ca161d3c566910`; у Xray и sing-box 12 порядков и 12 JA3 из 12. JA4 у всех
  трёх одинаковый: `t13d1516h2_8daaf6152771_d8a2da3f94cd`.
* **Приоритет:** **P1** (вместе с FP-01 — часть P0-сигнатуры).
* **Место:** `fingerprints.rs:133-292` (порядок зафиксирован в шаблоне), `hello.rs:182-224`.
* **Причина:** Chrome с версии 110 и uTLS (`ShuffleChromeTLSExtensions`) перемешивают
  расширения на каждом соединении. Шаблон хранит одну случайную перестановку.
* **Последствия:** правило «JA4 Chrome, но JA3/JA4_o одинаковы на N соединениях одного клиента»
  выделяет xrust среди настоящих Chrome, Xray и sing-box. Сам JA4 при этом не уникален.
* **Исправление:** при сборке hello для chrome-семейства перемешивать расширения, кроме GREASE в
  начале и в конце (и `pre_shared_key` в конце, если появится), как в uTLS. Профили, которые не
  перемешивают (Firefox, Safari, iOS, Edge, QQ — у эталонов порядок тоже постоянен), оставить как
  есть.
* **Риск:** низкий. Порядок расширений семантики не несёт; REALITY-печать считается после сборки.
* **Forkop X:** REALITY, TLS и XHTTP с fp chrome.

### FP-03 — GREASE в шифрах, supported_groups/key_share и supported_versions статичен
* **Статус:** подтверждено. 12/12 захватов: cipher `7a7a`, groups и key_share `8a8a`, versions
  `0a0a`; меняются только два GREASE-ID расширений. У эталонов меняется всё.
* **Приоритет:** **P1.**
* **Место:** `fingerprints.rs:138` (cipher), `:155` (`0x002b`), `:186` и key_share; `hello.rs:166-196`
  (из пула исключаются только GREASE в supported_groups); то же в профиле qq.
* **Причина:** случайное значение получают только `Ext::Static` с GREASE-ID. GREASE внутри тел
  шаблона остаётся снимком.
* **Последствия:** постоянная тройка `7a7a/8a8a/0a0a` даёт ещё одну дешёвую сигнатуру: у
  настоящего Chrome вероятность такой тройки примерно 1/4096 на соединение.
* **Исправление:** на каждое рукопожатие брать уникальные GREASE для шифров, versions, groups,
  sigalgs (если есть) и ext. В key_share подставлять **то же** значение, что в supported_groups:
  связь уже соблюдается, нужно только переписать оба места.
* **Риск:** низкий. Тесты должны проверять согласованность groups и key_share.
* **Forkop X:** chrome, REALITY-chrome, qq, randomized.

### FP-04 — Hysteria2: отпечаток rustls/quinn, отличный от всех клиентов на quic-go
* **Статус:** подтверждено. Расшифрованные Initial: xrust `q13d0311h3_55b375c5d22e_2ef3b9f41feb`;
  sing-box и Xray `q13d0311h3_55b375c5d22e_653d80c3fe9d`.
* **Приоритет:** **P1.**
* **Место:** `crates/core-runtime/src/tls_client.rs:560-603` (rustls-конфиг QUIC),
  `crates/core-runtime/src/outbound/quic.rs:150-185`, `outbound/hysteria2.rs`.
* **Причина:** QUIC идёт через rustls + quinn. Отсюда только x25519 без X25519MLKEM768, нет
  compress_certificate/ECH/ALPS, sigalgs в порядке rustls, TP quinn (`min_ack_delay 0xff04de1b`,
  `active_connection_id_limit=5`), Initial 1200 B, DCID 20 B / SCID 8 B, один CRYPTO-фрейм без
  «chaos protection». У эталонов: 1250 B, DCID 8 / SCID 0, CRYPTO нарезан и перемешан с PING и
  PADDING.
* **Последствия:** среди Hysteria2-клиентов (официальный apernet, sing-box, Xray — все на
  quic-go) xrust опознаётся по первому же Initial. Заодно нет постквантового обмена.
* **Исправление (поэтапно):** (1) добавить X25519MLKEM768 первым в kx-groups провайдера —
  криптография от этого только **усиливается**; (2) Initial 1250 B, DCID 8 B, SCID 0;
  (3) TP и их порядок как у quic-go; (4) при желании — нарезка CRYPTO как у Chrome/quic-go.
* **Риск:** средний. Это quinn-специфичные настройки, нужен регресс с серверами Hysteria2.
* **Forkop X:** все Hysteria2-узлы (utls Forkop всё равно вырезает).

### FP-05 — Профили `android` и `360` не работают
* **Статус:** подтверждено. 0 ClientHello на 12 попыток; против сервера Xray — FAIL; в debug-логе
  `the fingerprint offers no key share`; на уровне warn ничего нет.
* **Приоритет:** **P1** (P0 для узлов, у которых в подписке `fp=android` или `fp=360`).
* **Место:** `crates/core-tls/src/client.rs:122`; шаблоны `fingerprints.rs:71-131` (только
  TLS 1.2: нет key_share и supported_versions); `by_name` их принимает (`fingerprints.rs:40,43`).
* **Причина:** собственный стек поддерживает только TLS 1.3, а оба шаблона — TLS 1.2-hello.
  `check` конфига такие профили пропускает.
* **Последствия:** узел молча не работает. URLTest видит отказ, но пользователь не понимает
  причину.
* **Исправление:** отклонять `android`/`360` при проверке конфига с понятной ошибкой либо
  явно подменять на ближайший TLS 1.3-профиль с предупреждением в логе. В Forkop
  `normalize_utls_fingerprint` можно сопоставить их с `chrome`, как другие неизвестные значения.
* **Риск:** низкий.
* **Forkop X:** `parser.uc:629-650` эти значения разрешает.

### FP-06 — WebSocket early data: base64 standard и игнорирование `early_data_header_name`
* **Статус:** подтверждено. Против сервера sing-box с `early_data_header_name` — FAIL (`illegal
  base64 data at input byte 14`: это символ `+`). Против sing-box в path-mode (без имени
  заголовка, как генерирует Forkop) — FAIL. С сервером Xray — OK (Xray декодирует такое значение).
* **Приоритет:** **P0** для серверов sing-box с early data (несовместимость на реальной форме
  конфига Forkop); для Xray-серверов проблемы нет.
* **Место:** `crates/core-runtime/src/outbound/transport/mod.rs:493-533` (`base64_std(&early…)`,
  ED всегда в `Sec-WebSocket-Protocol`). `early_data_header_name` проходит валидацию
  (`core-config/src/validate.rs:5600`), но рантайм его не читает.
* **Причина:** Xray и sing-box используют base64url без паддинга (RawURL). sing-box с пустым
  `early_data_header_name` передаёт ED в пути, а не в заголовке.
* **Последствия:** при `ed=` в ссылке на sing-box-сервер соединения рвутся. В захватах xrust ещё и
  отличается (`+`, `/`, `=`) от обоих эталонов.
* **Исправление:** кодировать RawURL; уважать `early_data_header_name`: пустое значение — ED в
  путь (семантика sing-box), иначе — в указанный заголовок. Отдельно для Forkop: для ссылок в
  стиле Xray (`ed=`) генерировать `early_data_header_name: "Sec-WebSocket-Protocol"`, иначе
  upstream sing-box с Xray-сервером не работает (подтверждено захватом с контрольным клиентом
  sing-box).
* **Риск:** низкий. Нужно проверить обе формы против Xray и sing-box.
* **Forkop X:** `generator.uc:1904-1909` (`max_early_data` без имени заголовка).

### FP-07 — Записи TLS режутся парами 1041 + 15386 на транспортах поверх HTTP/2
* **Статус:** подтверждено (gRPC, XHTTP, H2 у xrust: сплошные пары `1041/15386`; у Go — `16401`).
* **Приоритет:** **P1** (видно пассивному наблюдателю по длинам записей).
* **Место:** `vendor/h2/src/codec/framed_write.rs:74,83` (`CHAIN_THRESHOLD_WITHOUT_VECTORED_IO=1024`);
  `crates/core-runtime/src/tls_utls.rs:216` (`poll_write`, нет `poll_write_vectored` и
  `is_write_vectored`).
* **Причина:** без векторного ввода-вывода h2 пишет сначала 1024 байта (заголовок фрейма и начало
  данных), затем остаток. `FingerprintStream` запечатывает каждый вызов в отдельную запись.
* **Последствия:** устойчивый периодический узор длин записей, которого нет ни у Chrome, ни у Go.
  Лишняя запись на каждые 16 KiB стоит и CPU.
* **Исправление:** реализовать в `FingerprintStream` `is_write_vectored()=true` и
  `poll_write_vectored`, собирая iovec до `MAX_FRAGMENT` в одну запись, либо поставить
  буферизацию между h2 и TLS.
* **Риск:** низкий; ожидается выигрыш в производительности.
* **Forkop X:** XHTTP (основной транспорт), gRPC, H2.

### FP-08 — gRPC и H2 открывают отдельное TLS-соединение на каждый поток
* **Статус:** подтверждено. 3 SOCKS-потока дают у xrust 3 ClientHello, у Xray и sing-box — 1
  (несколько H2-стримов в одном соединении).
* **Приоритет:** **P1.**
* **Место:** `crates/core-runtime/src/outbound/transport/grpc.rs:60-100`, `http.rs:60-95`
  (`client_builder().handshake(stream)` на каждый dial; пула, как у XHTTP/xmux, нет).
* **Последствия:** частые рукопожатия к одному серверу по числу пользовательских потоков: это
  другой поведенческий профиль, чем у эталонов, плюс лишняя задержка и нагрузка на сервер.
* **Исправление:** пул H2-соединений на outbound с лимитом стримов и временем жизни, по образцу
  `xmux.rs`.
* **Риск:** средний (head-of-line blocking, корректное закрытие); нужен регресс.
* **Forkop X:** узлы gRPC и H2.

### FP-09 — Отпечаток HTTP/2 (Akamai) — набор h2-crate, не совпадает ни с Go, ни с Chrome
* **Статус:** подтверждено захватом для xrust, Xray и sing-box. Значения Chrome — гипотеза (по
  памяти).
* **Приоритет:** **P2** (видно только тому, кто терминирует TLS: CDN, обратный прокси, сам сервер).
* **Место:** `crates/core-runtime/src/outbound/transport/h2io.rs:22-41`; порядок псевдозаголовков
  `m,s,a,p` задаётся h2-crate.
* **Причина:** SETTINGS `4:8388608;5:262144`, WU `33488897`, без `ENABLE_PUSH=0` и
  `MAX_HEADER_LIST_SIZE`.
* **Последствия:** при XHTTP через CDN (основной сценарий XHTTP) клиент выделяется по H2-отпечатку.
  У Xray отпечаток тоже Go-шный, но он хотя бы общий у всей массы клиентов Xray.
* **Исправление:** H2-профиль, привязанный к fp: для chrome — Chrome-подобные SETTINGS, их порядок,
  WU `15663105` и `m,a,s,p`. Это потребует патча vendor/h2 (порядок псевдозаголовков и SETTINGS).
  Минимум — добавить `ENABLE_PUSH=0` и `MAX_HEADER_LIST_SIZE`, как у Go.
* **Риск:** средний. Окна влияют на пропускную способность.
* **Forkop X:** XHTTP, gRPC, H2.

### FP-10 — WINDOW_UPDATE после патча h2: порог 1/32 окна
* **Статус:** подтверждено (скачивание 48 MiB: xrust — 225 WU, stream примерно каждые 256–300 KiB,
  conn примерно каждые 1 MiB; Xray — 12 289; sing-box — 2 829). Значение для Chrome (порог 1/2,
  около 20 WU) — гипотеза.
* **Приоритет:** **P2.**
* **Место:** `vendor/h2/src/proto/streams/flow_control.rs:19` (`UNCLAIMED_DENOMINATOR = 32`, в
  upstream 2) вместе с окнами из `h2io.rs:22-23`.
* **Последствия:** частота коротких клиентских записей (WU примерно 30 B) во время скачивания —
  промежуточная и ни на что не похожая. Пассивно видна как ритм мелких c2s-записей.
* **Исправление:** вынести порог в H2-профиль: Go-подобный для совместимости с массой Xray или
  Chrome-подобный (1/2 при окнах Chrome) для fp chrome. Решение принимать вместе с замерами
  пропускной способности (см. `docs/transport-performance-2026-10-23.md`).
* **Риск:** средний (пропускная способность на RTT).
* **Forkop X:** XHTTP, gRPC, H2.

### FP-11 — XHTTP: нет UA и браузерных заголовков, Referer-паддинг отличается от Xray
* **Статус:** подтверждено (HPACK-дамп).
* **Приоритет:** **P2** (видно CDN или серверу).
* **Место:** `crates/core-runtime/src/outbound/transport/xhttp.rs:1742-1756` (`"0".repeat`, путь с
  session id), `:1765-1790` (заголовки), `:1804` (session id без битов версии и варианта UUIDv4).
* **Последствия:** запросы без `user-agent` при `fp=chrome`; Referer
  `https://host/xh/<uuid>?x_padding=000…` против `https://host/xh/?x_padding=XXX…` у Xray. У Xray
  есть Chrome-UA, `sec-ch-ua*`, `sec-fetch-*`, `priority`. Сервер проверяет только длину паддинга,
  поэтому совместимость не страдает.
* **Исправление:** символ `X` и базовый путь в Referer, как у Xray; UUIDv4 для session id; набор
  заголовков по умолчанию, согласованный с fp (UA и client hints той же версии Chrome, что
  эмулирует TLS-профиль; переопределяется через `headers`).
* **Риск:** низкий (длина паддинга сохраняется).
* **Forkop X:** все XHTTP-узлы.

### FP-12 — XHTTP: `auto` с REALITY выбирает packet-up, у Xray — stream-one
* **Статус:** подтверждено (код и захват: у xrust POST `/xh/<uuid>/<seq>`); совместимость с
  сервером в режиме `auto` — OK.
* **Приоритет:** **P2.**
* **Место:** `xhttp.rs:815-825`; эталон — Xray `transport/internet/splithttp/dialer.go:333-340`.
* **Последствия:** при REALITY+XHTTP трафик xrust — множество POST (примерно 128 KiB каждые
  43 мс) вместо одного долгого POST, как у Xray. Если сервер явно настроен на `stream-one`,
  `auto` в xrust с ним не договорится (гипотеза; проверено только `auto↔auto` и явные режимы).
* **Исправление:** повторить логику Xray: REALITY → stream-one, REALITY + downloadSettings →
  stream-up.
* **Риск:** низкий.
* **Forkop X:** ссылки XHTTP+REALITY без `mode` (Forkop ставит `auto`).

### FP-13 — XHTTP packet-up: первый POST содержит только заголовок VLESS, дальше фиксированные 128 KiB
* **Статус:** подтверждено (xrust: 34 B, затем 131 072 B каждые примерно 43–45 мс; Xray: заголовок
  вместе с данными, размеры кратны 8 KiB, примерно 31 мс).
* **Приоритет:** **P2.**
* **Место:** `xhttp.rs:1076-1230`, `packet_upload_worker` (`:1613`).
* **Последствия:** постоянный узор «маленький POST и затем ровные блоки», отличный от Xray и
  видимый по длинам записей.
* **Исправление:** склеивать заголовок с первыми данными (как WS/H2 у Xray), варьировать размер
  блока в пределах `sc_max_each_post_bytes`.
* **Риск:** низкий.
* **Forkop X:** XHTTP в режимах packet-up и auto.

### FP-14 — TLS без utls показывает шаблон Chrome без ALPN
* **Статус:** подтверждено (`t13d151500_8daaf6152771_d8a2da3f94cd`; sing-box без utls —
  `t13d131100_…` от Go).
* **Приоритет:** **P2.**
* **Место:** `crates/core-runtime/src/tls_client.rs:627-667` (свой стек по умолчанию, `:653` —
  ALPN подставляется только при fingerprint или REALITY).
* **Последствия:** hello «Chrome без ALPN», которого в природе нет, и вдобавок со статичным ECH
  (FP-01).
* **Исправление:** без fingerprint и ALPN подставлять `h2,http/1.1` (как делает uTLS-Chrome), либо
  использовать rustls/Go-подобный hello.
* **Риск:** низкий (для raw VLESS ALPN не важен).
* **Forkop X:** TLS-ссылки без `fp`.

### FP-15 — `random` и `randomized` отличаются от uTLS
* **Статус:** подтверждено. У `randomized` xrust сохраняет GREASE и статичный ECH (1 уникальный
  payload на 5 процессов); у uTLS randomized GREASE нет и размеры другие. `random` выбирает один
  из 5 шаблонов на процесс.
* **Приоритет:** **P2.**
* **Место:** `crates/core-tls/src/random_fingerprints.rs:16-71`.
* **Последствия:** «случайные» профили выдаёт тот же ECH-маркер, что и в FP-01.
* **Исправление:** после FP-01–FP-03 всё это генерируется само. Документировать, что распределение
  не совпадает с uTLS.
* **Forkop X:** `randomized` проходит; **`random` Forkop превращает в `chrome`**
  (`parser.uc:629-650`), так что этот путь у Forkop не используется.

### FP-16 — WS/HTTPUpgrade без User-Agent
* **Статус:** подтверждено.
* **Приоритет:** **P2** (видно CDN или серверу).
* **Место:** `crates/core-runtime/src/outbound/transport/mod.rs:503-533` и `httpupgrade_handshake`.
* **Последствия:** запрос Upgrade без UA. sing-box шлёт `Go-http-client/1.1`, Xray — полный
  браузерный набор. Порядок заголовков свой (Host, Upgrade, Connection, Key, Version).
* **Исправление:** UA и заголовки по умолчанию, согласованные с fp (или хотя бы как у sing-box).
* **Риск:** низкий.
* **Forkop X:** WS- и HTTPUpgrade-узлы, в том числе через CDN.

### FP-17 — REALITY-версия клиента зашита как 26.3.27
* **Статус:** подтверждено (вскрытие session_id).
* **Приоритет:** **P3** (видно только серверу).
* **Место:** `crates/core-tls/src/reality.rs:30`.
* **Последствия:** сервер с `minClientVer` выше 26.3.27 отвергнет клиента. Снаружи session_id
  неотличим.
* **Исправление:** сделать версию настраиваемой и сопровождать её по актуальному Xray (сейчас
  26.10.21).
* **Forkop X:** только при серверах с `minClientVer`.

### FP-18 — Нет TCP keepalive на исходящих сокетах
* **Статус:** подтверждено strace (у xrust нет `SO_KEEPALIVE`; у sing-box 300/75/9, у Xray
  45/45). Влияние на провод не проверено (нет захвата).
* **Приоритет:** **P3** (отпечаток); для долгих простаивающих соединений за NAT — надёжность.
* **Место:** исходящий TCP-dial в `crates/core-runtime` (поиск `keepalive` вне fptn/masque пуст).
* **Исправление:** включить keepalive по умолчанию как в sing-box (`tcp_keep_alive` 5 мин,
  интервал 75 с) и учитывать опцию конфига.
* **Forkop X:** все TCP-узлы.

### FP-19 — Актуальность браузерных профилей (гипотеза, не сверено с внешней базой)
* **Статус:** частично подтверждено. JA4 xrust совпадают с Xray 26.10.21 (uTLS `aa6edf4`, март
  2026) для chrome, firefox, safari, edge, ios и qq. Совпадение с настоящими браузерами —
  **гипотеза**: внешняя база JA4 недоступна по ограничениям.
* **Приоритет:** **P3** (те же значения у Xray, не уникально для xrust).
* **Детали:** chrome ≈ HelloChrome_Auto uTLS (X25519MLKEM768, ALPS 0x44cd, ECH) — Chrome
  133+; по памяти это и есть JA4 нынешнего Chrome. firefox — «Firefox 148»
  (`docs/RUST-X-UTLS-2026-10-10.md`), но 15 расширений без `session_ticket` и
  `psk_key_exchange_modes`. Настоящий Firefox, насколько помню, даёт `t13d1717h2_…` (гипотеза).
  safari — «Safari 26.3», 13 расширений без padding. edge, ios и 360/qq/android — старые (hello
  512 B с padding, без MLKEM; Chrome/Edge до 2024). UA Xray заявляет Chrome 151, а TLS-шаблон
  моложе.
* **Исправление:** сверить с опубликованной базой JA4 (FoxIO ja4db) с датой; не выставлять
  устаревшие профили пользователю без предупреждения.
* **Forkop X:** firefox и safari используются в подписках, edge и ios — реже.

### FP-20 — gRPC: UA `grpc-go/1.48.0`, `:authority` с портом
* **Статус:** подтверждено (совпадает с sing-box 1.14.3; Xray шлёт Chrome-UA, `:scheme http`, без
  порта).
* **Приоритет:** **P3.**
* **Место:** `crates/core-runtime/src/outbound/transport/grpc.rs:87`.
* **Исправление:** при желании — UA как у Xray, если цель — мимикрия под клиентов Xray.
* **Forkop X:** gRPC-узлы.

## 9. Что не ломается (подтверждено)

* Состав и тела расширений chrome, firefox и safari, supported_groups с X25519MLKEM768, key_share
  (у chrome и safari ключи независимые), sigalgs, ALPN, compress_cert, ALPS, record_size_limit у
  Firefox — совпадают с Xray 26.10.21 байт в байт, кроме ECH, GREASE и порядка.
* session_id случайный, 32 B; REALITY-печать совместима с Xray-сервером (рукопожатия OK).
* CH уходит одним сегментом, CCS и Finished — одной отправкой; заголовок VLESS отдельной записью,
  как у sing-box.
* Совместимость: все основные конфигурации Forkop (TLS/REALITY/XHTTP×4/gRPC/WS/HTTPUpgrade/H2/HY2)
  с серверами Xray и sing-box — OK, кроме FP-05 и FP-06.

## 10. Чего не утверждает этот отчёт

* Ни одна строка выше не означает, что xrust незаметен для DPI. Наоборот, FP-01–FP-04 и FP-07
  дают пассивные признаки, достаточные для классификации. После их исправления уровень
  заметности нужно заново измерить тем же стендом (`run.py` + `analyze.py`) и дополнительно —
  захватом на реальном интерфейсе (TCP-опции, тайминги с RTT).

## Сводка приоритетов

| ID | Приоритет | Кратко |
|---|---|---|
| FP-01 | P0 | статичный ECH GREASE (байты общие для всех установок) |
| FP-06 | P0 (sing-box-серверы) | WS early data: base64 standard, игнорируется `early_data_header_name` |
| FP-02 | P1 | chrome без перемешивания расширений, постоянный JA3 |
| FP-03 | P1 | статичный GREASE в шифрах, groups и versions |
| FP-04 | P1 | Hysteria2: отпечаток rustls/quinn, без MLKEM |
| FP-05 | P1 (P0 для узла) | android/360 не работают |
| FP-07 | P1 | записи TLS 1041+15386 поверх H2 |
| FP-08 | P1 | gRPC/H2 — одно TLS-соединение на поток |
| FP-09…FP-16 | P2 | H2-отпечаток, WU 1/32, заголовки XHTTP/WS, режим auto, узор POST, TLS без fp, random/randomized |
| FP-17…FP-20 | P3 | версия REALITY, keepalive, актуальность профилей, UA gRPC |

