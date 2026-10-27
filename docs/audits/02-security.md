# Аудит безопасности xrust 0.0.26 (профиль `rust-x`)

- **Дата:** 2026-10-23
- **Объект:** `` на коммите `c5f567c` («Prepare Xrust 0.0.26 release») и генератор Forkop X `forkop-x`.
- **Рабочее дерево:** не изменялось. Все стенды лежат в scratchpad сессии:
  `<scratch>/`
  (`sec-e2e/`, `sec-masque/`, `crypto-kat/`, `vlessenc-probe/`, `clash/`, `evil_http.py`, `fake_dns.py`, `udp_assoc.py`).

## 0. Краткие итоги

| ID | Приоритет | Статус | Суть |
|----|-----------|--------|------|
| SEC-01 | **P0** | подтверждено (e2e) | Клиент REALITY принимает сервер, не прошедший аутентификацию REALITY. При `insecure` это полный MITM: UUID VLESS и трафик получает любой сервер |
| SEC-02 | **P0** | подтверждено (unit + e2e) | `insecure: true` отключает пины сертификата. Forkop передаёт `pcs` вместе с `allowInsecure=1` |
| SEC-03 | **P0** | подтверждено (код + стенд rustls) | MASQUE: пин по публичному ключу без проверки `CertificateVerify`, поэтому возможен MITM с чужим публичным сертификатом |
| SEC-04 | **P0** | подтверждено (e2e) | http_client падает (abort) на chunked-ответе с огромным размером чанка: удалённый крах ядра |
| SEC-05 | **P1** | подтверждено (e2e) | Remote rule-set и external_ui скачиваются без проверки сертификата (AcceptAny) |
| SEC-06 | **P1** | подтверждено (e2e) | Clash API в конфигурации Forkop открыт в LAN без secret, CORS `*`, Host не проверяется |
| SEC-07 | **P1** | подтверждено (e2e) | http_client: неограниченное потребление памяти при большом `Content-Length` |
| SEC-08 | **P1** | подтверждено (стенд) | DNS: ответ не сверяется с запросом (ID и question), ID последовательный |
| SEC-09 | **P1** | подтверждено (стенд) | VLESS encryption 0-RTT: два сообщения под одним nonce, к тому же 0-RTT не работает |
| SEC-10 | **P1** | подтверждено (код) | Сервер Hysteria2: `padding` неограниченной длины, аутентифицированный клиент роняет процесс |
| SEC-11 | **P1** | подтверждено (e2e) | Сервер REALITY не уводит на `handshake.server` (нет fallback) и выдаёт себя активному зондированию |
| SEC-12 | P2 | подтверждено (e2e) | `tls.ech` принимается и молча игнорируется, SNI уходит открытым |
| SEC-13 | P2 | подтверждено (код) | Нет лимитов использования AEAD и KeyUpdate: собственный стек игнорирует KeyUpdate, в rustls/QUIC лимит равен `u64::MAX` |
| SEC-14 | P2 | подтверждено (код) | AF_ALG: `expect` на ошибке ядра приводит к abort всего процесса |
| SEC-15 | P2 | подтверждено (стенд) | SOCKS5 UDP ASSOCIATE не проверяет источник датаграмм |
| SEC-16 | P2 | подтверждено (код) | external_ui: распаковка zip без лимитов (zip-bomb) |
| SEC-17 | P2 | подтверждено (код) | Сервер Hysteria2: `mem::forget(h3_conn)` даёт утечку памяти; на неверную аутентификацию отвечает отличимым 401 |
| SEC-18 | P2 | подтверждено частично | Clash API: нет таймаута чтения заголовков; при ошибке `accept` слушатель останавливается насовсем |
| SEC-19 | P2 | подтверждено (e2e) | SSRF через mixed/direct к loopback роутера, включая Clash API |
| SEC-20 | P2 | гипотеза | TProxy: нет защиты от петли при прямом подключении к порту tproxy |
| SEC-21 | P2 | подтверждено (код) | http_client: редирект https→http, перенос заголовков на чужой хост |
| SEC-22 | P2 | подтверждено (код Forkop) | Forkop: DNS по умолчанию — plain UDP мимо туннеля, `insecure` из подписки ставится молча; в xrust ECS добавляется в каждый запрос |
| SEC-23 | P2 | гипотеза (код) | TLS-сервер в core-tls: сборка handshake-сообщения до 16 МБ на соединение (DoS памяти) |
| SEC-24 | P3 | подтверждено (код) | Отклонения core-tls от RFC 8446: RSA PKCS#1 в CertificateVerify, ALPN без проверки на «предложенный», IP в SNI и др. |
| SEC-25 | P3 | подтверждено (код) | Ошибки `getrandom` игнорируются в нескольких местах |
| SEC-26 | P3 | подтверждено (код) | Нет проверки «нулевого» результата X25519 в kx/WireGuard/VLESS-enc |
| SEC-27 | P3 | подтверждено (код) | Сравнение secret и паролей не в постоянном времени |
| SEC-28 | P3 | подтверждено (код) | Ключ кэша `ClientConfig` — 64-битный `DefaultHasher` |
| SEC-29 | P3 | подтверждено (код) | Секреты не затираются (zeroize) |
| SEC-30 | P3 | гипотеза | Нет минимального размера ключа RSA при проверке; RUSTSEC-2023-0071 (Marvin) для серверного RSA |
| SEC-31 | P3 | подтверждено (e2e) | `cache.db` создаётся с правами 0644; rule-set кэшируется по предсказуемому пути в `/tmp` |
| SEC-32 | P3 | подтверждено (e2e) | User-Agent `sing-box 0.0.26` и `grpc-go/1.48.0` выдают форк |
| SEC-33 | P3 | подтверждено (код) | NTP-клиент не проверяет источник и origin timestamp |

## 1. Методология

1. **Ручное чтение кода** по всем путям, где принимается решение о доверии:
   - `core-tls`: `client.rs`, `server.rs`, `verify.rs`, `reality.rs`, `record.rs`, `tls13.rs`, `messages.rs`, `keyshare.rs`, `certificate_compression.rs`, `hello.rs`;
   - `core-runtime`: `tls_client.rs`, `tls_utls.rs`, `http_client.rs`, `outbound/masque/tls.rs`, `inbound/tls.rs`, `dns/`, `clash_api.rs`, `inbound/mixed.rs`, `inbound/hysteria2.rs`, `ntp.rs`, `outbound/vless_enc.rs`, `outbound/tailscale/session.rs`;
   - `core-crypto` целиком;
   - Forkop: `singbox/generator.uc`, `subscription/parser.uc`, `subscription/share_link.uc`, `dns.uc`, `route.uc`.
2. **Поиск по шаблонам:**
   - `dangerous()`, `AcceptAny*`, `ServerCertVerifier for`, `insecure`;
   - `thread_rng`, `rand::random`, `seed_from_u64`, `fastrand`;
   - `==` на секретах, `expect`/`unwrap` на сетевых путях, `ech`, `0rtt`.
3. **Динамические проверки:** только loopback, порты 26000–26999, без root.
   - Сборка: `cargo build --locked --offline -p core-cli --no-default-features --features rust-x`.
   - Тестовые серверы на python3 (`ssl`, `cryptography`) и на Rust (rustls + провайдер `core-crypto`):
     - поддельный CA, чужое имя, просроченный сертификат, TLS 1.2-only;
     - «не-REALITY» сервер вместо REALITY;
     - сертификат с несовпадающим ключом подписи;
     - вредоносный HTTP-сервер (chunked, Content-Length);
     - поддельный DNS.
4. **Сверка с эталонами:** fastgcm и fastchacha против RustCrypto `aes-gcm`/`chacha20poly1305` (`crypto-kat`). Прогон `cargo test -p core-crypto`, точечные unit-тесты `core-runtime`.
5. **Ограничение:** поведение sing-box и Xray, на которое ссылается отчёт, описано по памяти об их исходниках. Офлайн сверить его не с чем, такие места помечены.

## 2. Модель угроз

| Нарушитель | Возможности | Активы под угрозой |
|---|---|---|
| **A1. Пассивный наблюдатель на пути** (провайдер, DPI) | видит весь трафик роутера | SNI и метаданные, связывание сессий, nonce-reuse |
| **A2. Активный нарушитель на пути** (MITM, цензор с активным зондированием) | подменяет и перенаправляет TCP/UDP, отвечает на DNS, зондирует сервер | конфиденциальность туннеля, UUID и пароли, целостность rule-set и UI, доступность |
| **A3. Вредоносный или скомпрометированный сервер** (прокси-узел из подписки, сервер rule-set или UI, DNS upstream) | произвольные ответы протокола | крах или OOM ядра, отравление кэша, обход маршрутизации |
| **A4. Вредоносный LAN-клиент** (или веб-страница в браузере LAN-пользователя через CORS и DNS rebinding) | доступ к портам роутера в LAN | управление ядром через Clash API, открытый прокси, SSRF к сервисам роутера, история посещений |
| **A5. Вредоносный клиент inbound-сервера** (если xrust работает сервером) | аутентифицированный или анонимный клиент VLESS/REALITY/Hysteria2 | доступность сервера, его обнаружение |

Основной сценарий развёртывания — роутер OpenWrt с конфигурацией от Forkop X (клиентская роль). Inbound-серверы VLESS, REALITY и Hysteria2 вторичны.

## 3. Находки

### SEC-01 — Клиент REALITY принимает сервер, не прошедший аутентификацию REALITY

- **Статус:** подтверждено e2e, стенд `sec-e2e/cfgA.json`, `cfgB.json`, `tlssrv.py`.
- **Приоритет:** **P0**.
- **Где:**
  - `crates/core-runtime/src/tls_client.rs:665-668` — при `insecure` fallback-верификатор `AcceptsAnything`;
  - `:710-748` — verdict только пишется в debug-лог, затем `result?` и соединение используется;
  - `crates/core-tls/src/verify.rs:384-407` — `RealityVerifier::verify_chain` при несовпадении HMAC или при отсутствии ключа Ed25519 передаёт решение `fallback`;
  - `verify.rs:411-422` — `CertificateVerify` проверяется тем же fallback (при `insecure` не проверяется вовсе).
- **Причина:** провал аутентификации REALITY не считается ошибкой. Xray (`UClient`: `if !uConn.Verified { … spider …; return error }`) и sing-box (`reality verification failed`) по памяти об эталонах обрывают такое соединение. Здесь оно проходит, если сертификат принимает обычная проверка цепочки, а при `insecure: true` — любой сертификат.
- **Доказательство:** обычный TLS 1.3 сервер на python с сертификатом от недоверенного CA. Outbound VLESS+REALITY+uTLS chrome, `curl` через mixed.
  - Конфигурация A (`insecure: true`). Лог ядра: `REALITY www.example.com: the certificate carries no Ed25519 key` → `tls: established chrome`. Поддельный сервер получил открытый заголовок VLESS:
    `00 11111111222233334444555555555555 00 01 0050 02 0b "target.test" "GET /secret-path HTTP/1.1…"`,
    то есть UUID, адрес назначения и открытые данные.
  - Конфигурация B (`insecure: false`, сертификат «действительный» для `server_name` через `tls.certificate`) — результат тот же. В реальности это значит: если цензор перенаправит соединение на настоящий `dest`-сайт (или REALITY-сервер не узнает клиента, например из-за рассинхронизации часов), UUID и первый запрос уходят третьей стороне.
- **Последствия:**
  - при `insecure` — полный MITM туннеля и кража UUID, после чего атакующий может пользоваться сервером;
  - без `insecure` — утечка UUID и адресов назначения на `dest`-сайт и тихая неработоспособность вместо явной ошибки.
- **Исправление:**
  1. В `establish()`, если задан `reality`, требовать `verdict == "the borrowed certificate checks out"`. Лучше заменить строку на enum `RealityVerdict::Verified`, а иначе возвращать ошибку до создания `Connection` (по желанию — с «паучьим» запросом, как в Xray).
  2. Для REALITY не использовать fallback на цепочку вовсе: `RealityVerifier::verify_chain` должен возвращать ошибку, если HMAC не совпал.
  3. `CertificateVerify` проверять функцией `verify_leaf_signature` всегда, независимо от `insecure`.
  4. Флаг `insecure` при включённом `reality` игнорировать, предупредив в логе.
- **Риск исправления:** низкий. Узлы, которые «работали» через fallback, на самом деле не работали как REALITY.
- **Влияние на Forkop X:** `subscription/parser.uc:687,713` и `singbox/generator.uc:1836-1837` переносят `allowInsecure=1`/`insecure=1` из ссылки `vless://…security=reality` в `tls.insecure`. Ссылки вида `…security=reality&allowInsecure=1` в подписках встречаются, такие узлы уязвимы прямо сейчас. Рекомендуется в Forkop удалять `insecure` у REALITY-узлов (временная мера до исправления ядра).

### SEC-02 — `insecure: true` молча отключает certificate pins

- **Статус:** подтверждено.
  - Unit-тест `tls_client::tests::ordinary_tls_requires_matching_pins_in_addition_to_the_ca` закрепляет это поведение строкой таблицы `(vec![[0;32]], vec![[0;32]], true, true)`, тест проходит: `cargo test --locked --offline -p core-runtime --no-default-features --features rust-x --lib ordinary_tls_requires_matching_pins` → `1 passed`.
  - e2e `sec-e2e/cfgC.json`: при `insecure: true` и неверном `certificate_sha256` handshake прошёл, сервер получил заголовок VLESS с UUID.
  - Контроль `cfgD.json` (тот же неверный пин без `insecure`): `server certificate does not match tls.certificate_sha256`, отказ.
- **Приоритет:** **P0**.
- **Где:**
  - `crates/core-runtime/src/tls_client.rs:667-668` (собственный стек) — ветка `insecure` перед пинами;
  - `:510-514` (rustls TCP);
  - `:571-575` (QUIC: Hysteria2, DoQ/H3);
  - `crates/core-tls/src/verify.rs:812-820` — `PinVerifier` всегда требует валидную цепочку.
- **Причина:** приоритет флагов перевёрнут. Пин сужает доверие, но `insecure` его отменяет. А из-за того что пину нужна валидная цепочка, самоподписанный сертификат запинить нельзя: пользователь вынужден ставить `insecure` и теряет пин. В Xray `pinnedPeerCertificateChainSha256` проверяется в `VerifyPeerCertificate`, который вызывается и при `InsecureSkipVerify`; в sing-box пин заменяет проверку CA, а не наоборот (по памяти).
- **Последствия:** MITM для всех узлов с `pcs` и `allowInsecure=1`, именно так панели 3x-ui/Xray 25.x публикуют самоподписанные узлы. Атакующий на пути получает UUID и пароли (VLESS, Hysteria2) и трафик.
- **Исправление:**
  - если задан любой пин: игнорировать `insecure` (предупредив в логе) и проверять подпись `CertificateVerify` против ключа leaf;
  - проверку цепочки пропускать, только если `insecure` и пин вместе: «пин вместо CA», как в Xray;
  - без пина — текущее поведение;
  - обновить строку тестовой таблицы: `insecure=true` с неверными пинами должен давать `false`.
- **Риск исправления:** низкий. Конфиги с неверными пинами и `insecure` перестанут подключаться, и именно это требуется.
- **Влияние на Forkop X:**
  - `parser.uc:681` (`pcs` → `certificate_sha256`) и `:713` (`insecure`) задают оба поля одновременно; `generator.uc:1833-1837` для ручных ссылок — так же;
  - `runtime_supports_certificate_pins` (`generator.uc:3473`) считает xrust поддерживающим пины. Это неверно, пока `insecure` их отключает;
  - ссылки `hy2://…&pinSHA256=` Forkop не разбирает вовсе (`grep pinSHA256` пуст), пин теряется молча. Это задача Forkop.

### SEC-03 — MASQUE: пин публичного ключа без проверки CertificateVerify

- **Статус:** подтверждено. По коду обе функции возвращают `assertion()` безусловно. Стенд `sec-masque/` воспроизводит семантику на rustls с провайдером `core-crypto`: сервер предъявляет сертификат с ключом K1 (как публичный сертификат WARP), а `CertificateVerify` подписывает ключом K2.
  - Вывод: `masque-like (signature not checked): Ok(())`.
  - С проверкой подписи: `Err(InvalidCertificate(BadSignature))`.
- **Приоритет:** **P0**.
- **Где:**
  - `crates/core-runtime/src/outbound/masque/tls.rs:254-305`: `PinVerifier::verify_tls12_signature` (:284) и `verify_tls13_signature` (:297) всегда возвращают `HandshakeSignatureValid::assertion()`;
  - пин проверяется по любому сертификату из цепочки, включая intermediates (:265).
- **Причина:** комментарий «only the key holder can complete the handshake» неверен. Владение ключом доказывает только подпись `CertificateVerify`, а её проверку как раз отключили. Сертификат публичен: его можно получить одним подключением к настоящему endpoint.
- **Последствия:** активный MITM без ключа Cloudflare или сервера: всё, что идёт через MASQUE/WARP-туннель, видно и изменяемо. Клиентский mTLS не мешает: атакующий сам выступает выходом туннеля.
- **Исправление:**
  - оставить пин в `verify_server_cert` (только по `end_entity`);
  - `verify_tls13_signature`/`verify_tls12_signature` делегировать `rustls::crypto::verify_tls13_signature(msg, cert, dss, &provider.signature_verification_algorithms)` (соответственно `verify_tls12_signature`);
  - добавить тест с несовпадающим ключом, как в стенде.
- **Риск исправления:** низкий. Если реальные endpoint'ы WARP подписывают ключом из сертификата (а иначе TLS невозможен), ничего не сломается.
- **Влияние на Forkop X:** нет специфики, затронуты все MASQUE-узлы.

### SEC-04 — Удалённый крах ядра через chunked-ответ http_client

- **Статус:** подтверждено e2e (`evil_http.py`): размер чанка `ffffffffffffffff`.
  - release: `panicked at http_client.rs:382:39: slice index starts at 18 but ends at 17`, `panic = "abort"`, exit 134;
  - debug: `attempt to add with overflow` (:374).
- **Приоритет:** **P0**: крах из сети. Вместе с SEC-05 хватает любого MITM на пути загрузки.
- **Где:** `crates/core-runtime/src/http_client.rs:367-382`, `let needed = start + size + 2` без `checked_add`.
- **Последствия:** ядро падает при старте и при каждом обновлении remote rule-set или UI. На OpenWrt procd перезапускает процесс, ядро снова качает rule-set и снова падает: устойчивый DoS, весь трафик LAN без туннеля или без сети вовсе.
- **Исправление:** `size.checked_add(2)` и `start.checked_add(..)`; если `size > MAX_BODY - body.len()`, возвращать ошибку. Добавить fuzz-тест `read_response`.
- **Риск исправления:** минимальный.
- **Влияние на Forkop X:** remote rule-sets (`generator.uc:400-410`) и загрузка Yacd затронуты напрямую.

### SEC-05 — Remote rule-set и external_ui загружаются без проверки сертификата

- **Статус:** подтверждено e2e (`sec-e2e/rs.sh`, `https_srv.py`): HTTPS-сервер на 127.0.0.1:26050 с сертификатом от недоверенного «Evil CA». Rule-set без `http_client.tls`.
  - Сервер получил `GET /rules.json UA=sing-box 0.0.26`.
  - Ядро: `INFO updated rule-set rs`, то есть подменённые правила приняты.
- **Приоритет:** **P1**.
- **Где:**
  - `crates/core-runtime/src/http_client.rs:221-225` — без `tls`-блока используется `wrap_probe_stream`;
  - `crates/core-runtime/src/tls_client.rs:809-823` — `wrap_probe_stream`, верификатор `AcceptAny`;
  - `clash_api.rs:257-260` — `download_client` для external_ui всегда без `tls`.
- **Причина:** комментарий «the reference fetches through the same accept-any path» не соответствует sing-box: по памяти, его HTTP-клиенты rule-set и UI проверяют сертификат по системному или встроенному хранилищу.
- **Последствия:**
  - атакующий на пути загрузки (detour по умолчанию часто `direct`) подменяет rule-set: снимает туннелирование с выбранных доменов, перенаправляет трафик или блокирует;
  - подменяет архив Yacd: JS выполняется на origin Clash API роутера, при входе пользователя получает `secret` и полный контроль над ядром;
  - вместе с SEC-04, SEC-07 и SEC-16 — DoS ядра.
- **Исправление:** в `wrap_probe_stream` использовать `probe_connector`-подобный конфиг: встроенные Mozilla roots и `certificate` из корня, `with_root_certificates`. Явный `insecure` допускать только через `http_client.tls.insecure`.
- **Риск исправления:** низкий. Зеркала с самоподписанными сертификатами потребуют явного `tls` в `http_client`.
- **Влияние на Forkop X:** Forkop генерирует remote rule-sets и `external_ui` с URL Yacd на GitHub (`clash_api.rs:186`). Затронуты все установки.

### SEC-06 — Clash API в Forkop: LAN-bind без secret, CORS `*`, нет проверки Host

- **Статус:** подтверждено e2e.
  - Без secret кросс-доменный `GET /connections` → 200 с `Access-Control-Allow-Origin: *`.
  - Preflight PUT с `Origin: http://evil.example` → 200, затем `PUT /proxies/sel` → 204.
  - Запрос с `Host: attacker.example` → 200.
- **Приоритет:** **P1**.
- **Где:**
  - `crates/core-runtime/src/clash_api.rs:105-118` — пустой allow-origin превращается в `*`;
  - `:1612-1614` — без secret авторизация всегда успешна;
  - проверки Host нет;
  - Forkop `generator.uc:419-436`: `external_controller` = LAN-IP:9090, secret только при `enable_yacd` и непустом `yacd_secret_key`.
- **Последствия:**
  - любой LAN-клиент или любая веб-страница в браузере LAN-пользователя (CORS или DNS rebinding) читает `/connections` и `/logs` — история посещений всей LAN;
  - переключает селекторы, вплоть до `direct-out` (`generator.uc:1330-1332`), то есть снимает туннель;
  - закрывает соединения, запускает `/proxies/*/delay?url=` (blind SSRF через любой outbound).
- **Исправление:**
  - xrust: без явного `access_control_allow_origin` не отдавать `*`, разрешать только same-origin. Принимать Host только IP-литерал, `localhost` или явно разрешённые имена (защита от rebinding). Предупреждать в логе, если bind не на loopback, а secret пуст.
  - Forkop: всегда генерировать случайный secret; bind на 127.0.0.1, пока не включён Yacd.
- **Риск исправления:** внешние дашборды с другого origin потребуют явного allow-origin; это отклонение от умолчаний sing-box.
- **Влияние на Forkop X:** изменить генератор; `runtime.uc`/`hot_reload.uc` должны передавать Bearer.

### SEC-07 — http_client: неограниченная память при большом Content-Length

- **Статус:** подтверждено e2e: `Content-Length: 100000000000` и 400 МБ нулей дали VmHWM 551 340 kB при `MAX_BODY` = 64 МБ.
- **Приоритет:** **P1** (OOM на роутерах с 128–256 МБ).
- **Где:** `crates/core-runtime/src/http_client.rs:315-323`, лимит проверяется после чтения всего тела.
- **Исправление:** если `length > MAX_BODY` — сразу ошибка; в цикле чтения проверять `body.len() + n <= MAX_BODY` (и в chunked-ветке).
- **Риск исправления:** нет.
- **Влияние на Forkop X:** как SEC-04.

### SEC-08 — DNS: ответ upstream не сверяется с запросом, ID предсказуем

- **Статус:** подтверждено (`fake_dns.py`). Ответ с ID+0x1234 и вопросом `evil.attacker A 6.6.6.6` принят клиентом через hijack-dns, ID переписан на клиентский.
- **Приоритет:** **P1**.
- **Где:**
  - `crates/core-runtime/src/dns/transport.rs:1161-1200` — `exchange_udp` берёт первую датаграмму;
  - `dns/mod.rs:787-805` — проверки нет;
  - `dns/mod.rs:1305-1309` — `rand_id()` на деле последовательный `AtomicU16`;
  - пересылаемые запросы уходят с ID клиента.
- **Последствия:** off-path отравление кэша по Каминскому: угадывать нужно только порт. Под угрозой и резолв адресов самих прокси-серверов.
- **Исправление:**
  - ID каждого upstream-запроса — случайный, из `getrandom`, с восстановлением ID клиента в ответе;
  - отбрасывать ответы с чужим ID или question и ждать дальше до таймаута;
  - для TCP/DoT/DoH сверять question.
- **Риск исправления:** низкий.
- **Влияние на Forkop X:** по умолчанию DNS — plain UDP 77.88.8.8 без detour (`dns.uc:50-53`), риск прямой (см. SEC-22).

### SEC-09 — VLESS encryption 0-RTT: повтор nonce и неработающий 0-RTT

- **Статус:** подтверждено стендом `vlessenc-probe` (копия `vless_enc.rs` с заглушками) и чтением кода.
  - `0-RTT first write: Err("vless-enc: 0rtt aead not ready")`.
  - Тикет открывается под nonce 1, а не 2, как ждёт Xray (по памяти об эталоне).
  - XOR двух шифртекстов под одним nonce восстанавливает начало тикета: `abab (real abab)`.
- **Приоритет:** **P1**.
- **Где:** `crates/core-runtime/src/outbound/vless_enc.rs`:
  - :425 — nonce увеличен один раз;
  - :434 и :437 — длина и тикет запечатаны под одним `nfs_nonce`;
  - :446 — `aead: Some((ctx, None))`, AEAD записи не создаётся;
  - :761 — ошибка на первой записи.
- **Последствия:**
  - сейчас: после первого полного handshake с ключом `.0rtt.` сервер выдаёт тикет (:556-563), и все соединения в пределах срока тикета падают — DoS;
  - если починить только создание AEAD, без nonce, возникнет повтор nonce GCM: восстановление тикета пассивным наблюдателем, связывание сессий, подделка под nfs-ключом.
- **Исправление:** `increase_nonce(&mut nfs_nonce)` между :434 и :437; создать `RecordAead` из `aead_ctx`/`united`; тест 0-RTT против Go-эталона.
- **Риск исправления:** низкий, затронута только ветка 0-RTT.
- **Влияние на Forkop X:** `parser.uc:866-897` и `generator.uc:2041` передают `encryption` из подписки как есть. До исправления ключи `.0rtt.` лучше переводить в 1-RTT или отклонять.

### SEC-10 — Сервер Hysteria2: неограниченный padding

- **Статус:** подтверждено чтением кода, стенда нет (нужен QUIC-клиент).
- **Приоритет:** **P1** для многопользовательского сервера.
- **Где:** `crates/core-runtime/src/inbound/hysteria2.rs:298-305`. `pad_len` (varint до 2^62) идёт в `read_exact_vec` → `vec![0; n]`. У клиента лимит есть (`outbound/hysteria2.rs:680`).
- **Последствия:** любой аутентифицированный пользователь вызывает abort сервера (capacity overflow или ошибка аллокации).
- **Исправление:** `if pad_len > MAX_PADDING { return Err }`.
- **Риск исправления:** нет.
- **Влияние на Forkop X:** нет (клиентская роль).

### SEC-11 — Сервер REALITY без fallback: обнаружение активным зондированием

- **Статус:** подтверждено e2e, `sec-e2e/cfgR.json`: inbound VLESS+REALITY с `handshake.server = 127.0.0.1:26021`.
  - Зонд — обычный TLS-клиент python.
  - Результат: `SSLEOFError … UNEXPECTED_EOF`, ядро пишет `the session id does not open under that auth key`.
  - На `dest` не пришло ни одного соединения.
  - Отдельно: валидатор (`core-config/src/validate.rs:8899-8902`) требует `certificate` даже для REALITY-inbound, хотя сертификат не используется.
- **Приоритет:** **P1** для серверной роли.
- **Где:**
  - `crates/core-runtime/src/inbound/tls.rs:132-197` — `handshake` не читается;
  - `crates/core-tls/src/server.rs:202-246` — любая ошибка REALITY приводит к закрытию соединения;
  - родственные: VLESS без fallback на неизвестный UUID (`inbound/proxy.rs:731-734`, P3), Hysteria2 отвечает 401 вместо masquerade (`inbound/hysteria2.rs:417-426`, P2).
- **Последствия:**
  - сервер отличим от `dest` по первому же зонду (RST/EOF вместо настоящего handshake сайта);
  - нет мимикрии размеров записей, как в Xray, и нет кэша повторов. Повтор перехваченного ClientHello в пределах `max_time_difference` (по умолчанию 600 с) получает от сервера flight с маленьким самоподписанным сертификатом, что тоже отличимо. Это гипотеза о практической различимости, не измерялось.
- **Исправление:**
  - при любой ошибке аутентификации REALITY прозрачно проксировать уже прочитанные байты ClientHello и дальнейший поток на `handshake.server:server_port`, как Xray/sing-box;
  - мимикрия длин записей по ответу `dest`;
  - необязательный кэш повторов (session_id) на окно времени;
  - снять требование `certificate` в валидаторе для REALITY.
- **Риск исправления:** средний: новая сетевая логика в пути accept; нужны интеграционные тесты против Xray-клиента.
- **Влияние на Forkop X:** нет.

### SEC-12 — `tls.ech` молча игнорируется

- **Статус:** подтверждено e2e (`sec-e2e/cfgE.json`):
  - `tachyon-core check` → rc=0;
  - в ClientHello `www.example.com` виден открытым текстом;
  - `fe0d` присутствует только как GREASE ECH из шаблона chrome;
  - предупреждения в логе нет.
- **Приоритет:** P2.
- **Где:** валидатор принимает `ech` (`core-config/src/validate.rs:2424`, `:6405-6410`), но `TlsOptions::from_outbound` (`core-runtime/src/tls_client.rs:216-376`) поле `ech` не читает (`grep '"ech"' crates/core-runtime/src` пуст).
- **Последствия:** пользователь считает SNI скрытым, а наблюдатель A1 его видит.
- **Исправление:** до реализации ECH отклонять `ech.enabled: true` на этапе `check`/`run` с понятной ошибкой.
- **Риск исправления:** конфиги с ECH перестанут запускаться (и это честнее).
- **Влияние на Forkop X:** Forkop ECH не генерирует.

### SEC-13 — Лимиты использования AEAD и KeyUpdate

- **Статус:** подтверждено чтением кода.
- **Приоритет:** P2 (hardening).
- **Где:**
  - `crates/core-crypto/src/lib.rs:260,274,365,378,393` и `crates/core-crypto/src/quic.rs:392` — лимит конфиденциальности `u64::MAX`;
  - `crates/core-tls/src/record.rs:151,236` — ограничено только переполнением seq;
  - `crates/core-tls/src/client.rs:614-616` и `crates/core-runtime/src/inbound/tls.rs:519-524` — post-handshake `KeyUpdate` пропускается как Skip, ключи не меняются.
- **Последствия:**
  - на долгих туннелях превышаются пределы RFC 8446 §5.5 (около 2^24.5 записей AES-GCM) и RFC 9001 §6.6 (2^23 пакета);
  - если пир пришлёт KeyUpdate, следующая запись не расшифруется и соединение оборвётся.
- **Исправление:**
  - для AES-GCM — 1<<24 (TLS) и 1<<23 (QUIC), ChaCha не трогать;
  - в core-tls обрабатывать `KeyUpdate` (обновить opener и при `update_requested` ответить) и по лимиту инициировать KeyUpdate или закрыть соединение.
- **Риск исправления:** низкий.
- **Влияние на Forkop X:** нет.

### SEC-14 — AF_ALG: abort процесса при ошибке ядра

- **Статус:** подтверждено чтением кода. Динамически не проверялось: в стенде `bind(gcm(aes))` даёт ENOENT.
- **Приоритет:** P2.
- **Где:** `crates/core-crypto/src/afalg.rs:295` (`expect("afalg seal")`), профиль `panic = "abort"` (`Cargo.toml:90`).
- **Исправление:** при ошибке шифровать через уже имеющийся `self.sw` и выключать AF_ALG глобальным флагом.
- **Риск исправления:** низкий.

### SEC-15 — SOCKS5 UDP ASSOCIATE не проверяет источник

- **Статус:** подтверждено (`udp_assoc.py`). Датаграмма с 127.0.0.2 была ретранслирована, ответ вернулся атакующему.
- **Приоритет:** P2.
- **Где:** `crates/core-runtime/src/inbound/mixed.rs:446-500`.
- **Последствия:** обход аутентификации mixed для UDP, рефлектор, пока жива ассоциация.
- **Исправление:** принимать датаграммы только с IP TCP-клиента; при заданном DST.ADDR:PORT фиксировать адрес.
- **Риск исправления:** клиенты за NAT с другим IP (редкость).
- **Влияние на Forkop X:** mixed-секции и `direct_proxy` слушают LAN-IP.

### SEC-16 — external_ui: zip-bomb

- **Статус:** подтверждено чтением кода. Zip-slip отклоняется (тест `a_zip_slip_entry_is_refused`), symlink'и не создаются.
- **Приоритет:** P2.
- **Где:** `crates/core-runtime/src/zip.rs:182-190`, `DeflateDecoder::read_to_end` без лимита.
- **Исправление:** `take(limit)` на запись, общий лимит распаковки, лимит числа записей.
- **Риск исправления:** нет.

### SEC-17 — Сервер Hysteria2: утечка h3 и отличимый ответ на аутентификацию

- **Статус:** подтверждено чтением кода.
- **Приоритет:** P2.
- **Где:** `crates/core-runtime/src/inbound/hysteria2.rs:445` (`std::mem::forget(h3_conn)`), `:417-426` (401 и закрытие без masquerade).
- **Исправление:** держать драйвер h3 в задаче соединения; masquerade или 404 как в эталоне.

### SEC-18 — Clash API: нет таймаута заголовков, остановка слушателя при ошибке accept

- **Статус:**
  - подтверждено: 28 231 простаивающее соединение без закрытия;
  - остановка слушателя на EMFILE — гипотеза по коду (`Err(e) => return`).
- **Приоритет:** P2.
- **Где:** `crates/core-runtime/src/clash_api.rs:280-296`, `:1719`.
- **Исправление:** таймаут чтения заголовка около 10 с, лимит соединений, повтор `accept` с паузой (как `serve_stalled` в inbound).

### SEC-19 — SSRF к loopback роутера через прокси

- **Статус:** подтверждено e2e: через HTTP- и SOCKS5h-mixed без аутентификации получены `/configs` и `/version` Clash API на 127.0.0.1 и `localhost`.
- **Приоритет:** P2.
- **Где:** route и direct-outbound не запрещают loopback и собственные адреса.
- **Последствия:** в Forkop `direct_proxy` (LAN-IP:2080, без аутентификации) открывает LAN-клиенту сервисы роутера на 127.0.0.1: ubus/rpcd, служебный mixed 127.0.0.1:4534 с VPN-детуром, Clash API.
- **Исправление:** опция inbound или route, по умолчанию отклоняющая 127.0.0.0/8, ::1 и адреса интерфейсов роутера для неавторизованных inbound (с opt-out).
- **Риск исправления:** сломает намеренный доступ к localhost через прокси.

### SEC-20 — TProxy: возможная петля

- **Статус:** гипотеза, без root (IP_TRANSPARENT) не проверить.
- **Приоритет:** P2.
- **Где:** `crates/core-runtime/src/inbound/tproxy.rs:115`, destination = `local_addr`. Аналога `loopBackDetector` из sing-box нет.
- **Последствия:** прямое подключение LAN-клиента к router:1602 (Forkop слушает 0.0.0.0) ведёт к рекурсивному самоподключению и исчерпанию fd.
- **Исправление:** отклонять соединения, у которых destination совпадает с адресом слушателя или локальным адресом; в Forkop слушать 127.0.0.1.

### SEC-21 — http_client: небезопасные редиректы

- **Статус:** подтверждено чтением кода.
- **Приоритет:** P2.
- **Где:** `crates/core-runtime/src/http_client.rs:192-200` (`Url::join` принимает `http://`), `:236` — пользовательские заголовки уходят на каждый хоп.
- **Исправление:** запретить https→http; при смене authority снимать пользовательские заголовки; запретить редирект на loopback и приватные адреса.

### SEC-22 — Forkop: DNS по умолчанию в открытом виде, `insecure` молча, ECS

- **Статус:** подтверждено чтением кода Forkop. ECS подтверждён e2e: в запросе к `fake_dns` был `client_subnet` `203.0.113.0/24` (`cb0071`).
- **Приоритет:** P2.
- **Где:**
  - Forkop `dns.uc:50-53` — UDP 77.88.8.8, тот же bootstrap, без detour;
  - `subscription/parser.uc:713,1081,1474,1596,2215,2436` — `insecure` из подписки без предупреждения в UI;
  - xrust добавляет `client_subnet` в каждый upstream-запрос.
- **Последствия:** провайдер видит все DNS-имена LAN; данные подписки молча отключают проверку сертификата (вкупе с SEC-01 и SEC-02).
- **Исправление (Forkop):** DoH/DoT или detour по умолчанию; бейдж «проверка сертификата отключена провайдером» в UI; не передавать `insecure` для REALITY.

### SEC-23 — TLS-сервер core-tls: сборка сообщения до 16 МБ

- **Статус:** гипотеза по коду, без стенда (нужен собственный TLS-клиент).
- **Приоритет:** P2.
- **Где:** `crates/core-tls/src/server.rs:491-545`. Длина handshake-сообщения 24-битная, `pending` растёт без лимита до прихода всего сообщения. Ограничивает только `HANDSHAKE_TIMEOUT` = 10 с (`inbound/tls.rs:30`).
- **Последствия:** десятки параллельных соединений по 16 МБ приводят к OOM на роутере.
- **Исправление:** ограничить длину handshake-сообщения на сервере (64 КБ хватает и для ClientHello, и для Finished); лимит одновременных handshake.

### SEC-24 — Отклонения core-tls от RFC 8446 (без практической эксплуатации)

- **Статус:** подтверждено чтением кода.
- **Приоритет:** P3.
- **Пункты:**
  - `verify.rs:321-327`: `algorithm_for` берёт схемы из общей таблицы TLS 1.2/1.3 и принимает `rsa_pkcs1_*` в TLS 1.3 `CertificateVerify` (RFC 8446 §4.4.3 запрещает). Схема не сверяется с отправленным `signature_algorithms`.
  - `client.rs:404-408`: выбранный сервером ALPN не проверяется на вхождение в предложенные (RFC 7301 §3.2).
  - `hello.rs:232`: IP-литерал попадает в SNI (RFC 6066 §3 запрещает), при `server_name` = IP получается отличимый hello.
  - `client.rs:471`, `server.rs:479`: Finished сравнивается через `!=`. Практического оракула нет, но стоит `subtle::ConstantTimeEq`.
  - Неверные комментарии `client.rs:538-546` и `server.rs:415-418`: RFC 8446 §7.1 выводит *оба* application-секрета из транскрипта до server Finished, то есть код соответствует RFC, а не «отступает от него ради rustls». Неверен и комментарий `record.rs:118` (`set_keys`, мёртвый код): RFC 8446 §5.3 требует сбрасывать seq при смене ключей.
  - Байты после ServerHello в той же записи и хвост `pending` при смене ключей молча отбрасываются (RFC 8446 §5.1 требует ошибку).
  - EOF без `close_notify` считается нормальным концом (`tls_utls.rs:197-200`), усечение не детектируется. Для прокси это допустимо: внутренний протокол сам задаёт границы.
- **Исправление:** таблица схем только для TLS 1.3 (`ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `ed25519`, `rsa_pss_*`); проверка ALPN; не ставить IP в SNI; поправить комментарии.
- **Риск исправления:** низкий.

### SEC-25 — Ошибки `getrandom` игнорируются

- **Приоритет:** P3, подтверждено.
- **Где:**
  - `outbound/quic.rs:148` — ключ stateless reset;
  - `:505` — соль salamander;
  - `transport/mod.rs:779` — маска WS;
  - `xmux.rs:72,395`;
  - `hysteria2.rs:239`.
- **Исправление:** пробрасывать ошибку или `expect`, как в `awg::fill_random`.

### SEC-26 — Нет проверки нулевого результата X25519

- **Приоритет:** P3, подтверждено.
- **Где:** `core-crypto/src/kx.rs:40-48` (провайдер rustls), `outbound/wireguard/noise.rs:175`, `outbound/vless_enc.rs:389`, около `:533`. В core-tls (`keyshare.rs:232,300`) проверка есть.
- **Исправление:** `if !shared.was_contributory() { return Err }`.

### SEC-27 — Сравнения секретов не в постоянном времени

- **Приоритет:** P3, подтверждено.
- **Где:**
  - `clash_api.rs:1622-1626` (`token == secret`);
  - `inbound/mixed.rs:193,305-306,1111` (`==` и `any()` с ранним выходом);
  - `core-tls/src/verify.rs:395` (HMAC REALITY — безвредно, ключ новый в каждом handshake);
  - `core-tls/src/server.rs` short_id (после AEAD, безвредно).
- **Исправление:** `subtle::ConstantTimeEq`; в mixed перебирать всех пользователей без раннего выхода.

### SEC-28 — Ключ кэша `ClientConfig` — 64-битный хеш

- **Приоритет:** P3, подтверждено.
- **Где:** `crates/core-runtime/src/tls_client.rs:471-486`. CA и пины сворачиваются в `DefaultHasher` с фиксированным ключом.
- **Последствия:** при коллизии два outbound с разными CA или пинами получат один верификатор. Практически недостижимо (второй прообраз 64 бит), но это граница доверия.
- **Исправление:** класть в ключ сами байты или SHA-256.

### SEC-29 — Секреты не затираются

- **Приоритет:** P3, подтверждено.
- **Не затираются:**
  - `KeySchedule` (`tls13.rs`, `Vec<u8>`);
  - `auth_key` в `client::Handshake`;
  - раундовые ключи `Gcm`;
  - `nfs_key`/`united_key` в vless_enc;
  - статические ключи WireGuard;
  - пароли и UUID в `String`.
- **Затирается:** `x25519-dalek` (feature `zeroize` включена в core-crypto).
- **Исправление:** `zeroize::Zeroizing` для производных ключей, `Drop` с затиранием.

### SEC-30 — RSA: минимальный размер ключа и Marvin

- **Статус:** гипотеза. `cargo audit` офлайн недоступен.
- **Приоритет:** P3.
- **Где:** `core-crypto/src/verify/rsa.rs:37` — минимум модуля не задан (у ring — 2048 бит).
- **Прочее:** rsa 0.9.10 подпадает под RUSTSEC-2023-0071 для операций с приватным ключом, то есть для inbound TLS с RSA-ключом.
- **Исправление:** отклонять модуль меньше 2048 бит; для сервера рекомендовать ECDSA/Ed25519.

### SEC-31 — Права `cache.db` и путь кэша rule-set

- **Статус:** подтверждено e2e: `cache.db` создаётся `-rw-r--r--`. В нём DNS-кэш, FakeIP-сопоставления и выбор селекторов, то есть история посещений.
- **Приоритет:** P3.
- **Где:** `crates/core-runtime/src/cache_file.rs:320-322`; `route/rule_set_remote.rs:45-48` — предсказуемый путь в общем `/tmp`, tag без санитизации.
- **Исправление:** 0600 для файлов, 0700 для каталога, проверка владельца каталога, санитизация tag.

### SEC-32 — Метаданные User-Agent

- **Статус:** подтверждено (`rs.log`: `UA=sing-box 0.0.26`).
- **Приоритет:** P3.
- **Где:** `http_client.rs:231` — номер версии xrust не совпадает с версиями sing-box и выдаёт форк; `transport/grpc.rs:87` — `grpc-go/1.48.0`. Подробный разбор отпечатков у другого аудитора.

### SEC-33 — NTP без проверки ответа

- **Статус:** подтверждено чтением кода.
- **Приоритет:** P3 (в Forkop `ntp: {}` — выключено).
- **Где:** `crates/core-runtime/src/ntp.rs:96-126`. Источник ответа (`_from`) игнорируется, transmit timestamp запроса нулевой, origin не сверяется, запрос идёт мимо detour.
- **Последствия:** при `write_to_system` атакующий на пути (или off-path, угадавший порт) сдвигает системное время. Это ломает проверку сроков сертификатов в обе стороны и окно времени REALITY.
- **Исправление:** случайный transmit timestamp и проверка origin; проверка адреса источника; ограничение величины шага.

## 4. Что проверено и признано корректным

**Проверка сертификатов (обычный TLS, без REALITY, `insecure`, пинов):**
- Собственный стек и rustls отвергают недоверенный CA, чужое имя и просроченный сертификат. Проверено e2e, `sec-e2e/cfgVown.json`, `cfgVrustls.json`, `t12.sh`:
  - `certificate expired: … not valid after …`;
  - `certificate not valid for name "www.example.com"; … DnsName("evil.example.net")`;
  - для rustls то же при TLS 1.2.
- Проверка цепочки, имени, IP SAN и срока идёт через `rustls-webpki` 0.103 (`WebPkiServerVerifier`) с текущим временем.
- Корневое хранилище — встроенный `webpki-roots` 0.26 (Mozilla). Работает на OpenWrt без пакета CA. `tls.certificate`/`certificate_path` заменяют хранилище, а не дополняют. Это поведение эталона.
- Пины без `insecure` работают: неверный пин даёт отказ (e2e `cfgD.json`, unit-тест).
  - `certificate_sha256` — SHA-256 всего DER leaf;
  - `certificate_public_key_sha256` — SHA-256 элемента SPKI вместе с тегом. Разбор SPKI учитывает X.509 v1;
  - пины публичны, постоянное время сравнения не требуется.
- **Даунгрейд TLS 1.2:** собственный стек принимает только `supported_versions = 0x0304` (`client.rs:299-307`). Против TLS 1.2-only сервера — `the server did not negotiate TLS 1.3` (e2e). В пути rustls (`max_version: 1.2` или `ALL_VERSIONS`) sentinel проверяет сам rustls. TLS 1.2-наборы провайдера — только ECDHE+AEAD (`core-crypto/src/lib.rs:184-213`).
- **HRR:** собственный клиент не поддерживает HRR и отказывает при разборе: `key_share` без ключа приводит к ошибке (`messages.rs` `ServerHello::parse`). Это fail-closed.
- **Машина состояний клиента** (`client.rs`):
  - строгий порядок EE → Certificate/CompressedCertificate → (CertificateStatus) → CertificateVerify → Finished;
  - session_id echo, cipher suite и group сверяются с предложенными;
  - транскрипт ведётся по сообщениям; `CertificateVerify` проверяется по транскрипту до него, Finished — по транскрипту до Finished;
  - application data до Finished отвергается;
  - `server_name` в EE с непустым телом отвергается.
- **Ключевое расписание** (`tls13.rs`) соответствует RFC 8446 §7.1. Nonce = iv XOR seq, при исчерпании seq — отказ. Записи больше 2^14+256 на сервере отвергаются.
- **Сжатие сертификатов RFC 8879** (`certificate_compression.rs`):
  - алгоритм должен быть предложен в шаблоне;
  - объявленная длина ≤ 1 МиБ;
  - распаковка через `take(expected+1)` с точной сверкой длины;
  - zip-bomb невозможна.
- **Key share (`keyshare.rs`):** проверка длин ML-KEM (1088+32, 1184), `was_contributory` для X25519 и REALITY, точка P-256 через `from_sec1_bytes`.

**Пути без «тихого» отключения проверки (кроме SEC-05):**
- DoH/DoT/DoQ/H3: `dns/transport.rs:840-860` синтезирует `tls.enabled`, используется `TlsOptions` с Mozilla roots.
- urltest probe: `probe_connector`, Mozilla roots и корневой `certificate`.
- Tailscale control/DERP: `outbound/tailscale/session.rs:75-94`, `with_root_certificates(mozilla)`, только HTTPS-origin.
- MASQUE без пина и без `insecure`: пустое хранилище плюс `certificate`, то есть fail-closed.
- QUIC 0-RTT включается только в TUIC (legacy). Hysteria2 0-RTT не использует.

**REALITY-клиент (кроме SEC-01):**
- session_id: версия, время, short_id.
- `auth_key` = HKDF-SHA256(salt=random[0..20], info="REALITY").
- AES-256-GCM с nonce = random[20..32] и AAD = ClientHello с обнулённым session_id.
- Сертификат = HMAC-SHA512(auth_key, ed25519_pub).
- Всё это совпадает со схемой Xray (по памяти) и покрыто тестами `reality.rs`/`verify.rs`. `RealityVerifier` создаётся на каждое соединение, гонок за `auth_key` нет.

**REALITY-сервер (кроме SEC-11):** проверяются AEAD session_id, версия, окно времени (по умолчанию 600 с) и short_id — после аутентификации. X25519 низкого порядка отвергается.

**Криптография (подробности в стенде `crypto-kat`):**
- fastgcm и fastchacha против RustCrypto `aes-gcm`/`chacha20poly1305`: 128/256-битные ключи, длины 0…65543 со всеми границами блоков, AAD 0…1000; подделка тега, шифртекста и AAD.
  - Итог: `cases=21780 failures=0`.
  - Пути AArch64 NEON и AF_ALG динамически не проверены.
- `cargo test --locked --offline -p core-crypto` — 25 passed.
- Сравнение тегов в fast-путях — в постоянном времени, при ошибке открытый текст затирается. AF_ALG включается только после самопроверки против эталона.
- Источник случайности — `getrandom`/`OsRng`. `thread_rng`, `SmallRng`, `seed_from_u64` в рабочем коде нет.
- **WireGuard/AmneziaWG:**
  - nonce из счётчика, `REJECT_AFTER_MESSAGES`;
  - окно повторов 2048 бит;
  - таймеры rekey.
- Tailscale noise: `checked_add` на nonce.
- VLESS encryption 1-RTT: последовательность nonce, разделение направлений, лимиты длины и padding.
- XUDP: клиент не отправляет GlobalID.

**Clash API и inbound (кроме SEC-06, SEC-18, SEC-19):**
- Bearer-аутентификация: 401/401/200.
- `?token=` принимается только при WebSocket-upgrade (WS без token → 401, с верным → 101).
- `PUT /configs` с `path` ничего не читает и не меняет. `PATCH` меняет только log-level и mode.
- `GET /configs` и `/proxies` секретов не отдают.
- `/ui`: все варианты обхода пути (`../`, `%2e%2e`, `..%2f`, `%252e`, `..%5c`) → 404.
- Лимиты тела (64 КБ) и заголовка (16 КБ).
- Аутентификация mixed для HTTP (407) и SOCKS5 работает. Mixed без `listen` слушает 127.0.0.1.
- Распаковка zip: zip-slip и zip64 отклоняются, смещения через `checked_add`.

**Логи:** UUID, пароли, приватные ключи и URL подписок в логах не найдены. В лог попадают URL rule-set и external_ui. Секреты в query-строке этих URL утекли бы (не проверялось).

## 5. Не проверено

- Пути AArch64/NEON fastgcm и AF_ALG на реальном железе.
- TProxy и TUN (нужен root): SEC-20 — гипотеза.
- Серверный Hysteria2 и падение на padding (SEC-10) — без QUIC-стенда.
- SEC-23 — без собственного TLS-клиента.
- Поведение против настоящих Xray/sing-box-серверов: офлайн, эталонных бинарей нет.
- `cargo audit` по advisory-базе: офлайн.
- Утечки через логи уровня `trace` во всех протоколах (выборочная проверка только для debug).
