# Журнал задач по итогам аудита xrust 0.0.26

Общий журнал разработки и независимой проверки. Задачи взяты из плана
P0–P3 по аудиту от 2026-10-23. Работа идёт в ветке `dev`; `main`, теги
и релизы меняются только отдельным решением.

## Статусы

| Статус | Значение |
|---|---|
| исправлено | коммит в `dev`, проверки разработки пройдены |
| проверено | независимое ревью и тесты пройдены, в том числе на OpenWrt VM |
| слито | изменение в `main` |
| выпущено | изменение вошло в опубликованный релиз |

## Сводка

| ID | Описание | Приоритет | Статус | Коммит |
|---|---|---|---|---|
| CQ-01 | Паника `percent_decode` в Clash API до проверки secret | P0 | исправлено, проверено | `49987e66b78e14fc4f57ff367ece1f2fd9d88569` |
| SEC-04 | Переполнение размера чанка в HTTP-клиенте (`decode_chunked`) | P0 | исправлено, проверено | `5de21230da8bf883f3616f7b7b952917646e9cdb`, `2b49308ed8af6fa4fe1cce16fe1b290b9e4aa325` |
| SEC-07 | Тело по `Content-Length` не ограничено до чтения | P1 | исправлено, проверено | `48c70f91e32a30a2f2a281a66a46703891604bb5` |
| SEC-05 | HTTPS-загрузки rule-set и external_ui без проверки сертификата | P1 | исправлено, проверено | `11ada8206da3ccdd5cbb54c6758133c7c290d362` |
| BLD-02 | `rustls-webpki` и `webpki-roots`: доверие к скомпрометированным промежуточным emSign | P0 | исправлено, проверено | `e0404da672defc885295297a8e4cf3c2087f2d44` |
| FX-01 | Forkop X: legacy-протоколы в подписке или ручной ссылке валят весь конфиг на rust-x | P0 | исправлено, проверено | forkop-x `7acb5411814dc247629116be8b35962b57db0801`, `589f659aca7d15cc308c3741126140a757310e5e` |
| FX-02 | Forkop X: ByeDPI генерирует outbound `socks`, запрещённый в rust-x — решено удалением ByeDPI | P0 | исправлено, проверено | forkop-x `f6d10ef6cf5628cf7e9b34673a677dd970cbe1cb` |
| CQ-03 | SRS-декодер: недоверенные счётчики и индексы, zlib без лимита | P0 | исправлено, проверено | `fced50992b3ac7f12fb7136286b8c08d05dc9b32`, `ffb4988939fb376082ba427c609c618d2f7808ba` |
| CN-02 / MEM-01 | XHTTP packet-up не завершает сессию после закрытия клиентом: утечка fd и памяти | P0 | исправлено, проверено | `9af27fd0f702c8fbc851ce1285c163f9d31224f5`, `22162e7822f9a03c174cfe57fd929c3224216e7e` |
| SEC-01 / SEC-02 | REALITY без аутентификации проходит через обычный TLS; `insecure: true` отключает certificate pins | P0 | исправлено, проверено | `434217b2319498a7cbc9e4c9b85dcc30443f5da4` |
| CQ-06 | UDP: лавина задач открытия, пока поток открывается | P1 | исправлено, проверено | `b0bc97be3a552e98cf2b128d67ab167ca92b3481` |
| CN-01 | XHTTP: мёртвое HTTP/2-соединение навсегда остаётся в пуле | P0 | исправлено, проверено | `fd03c0aabd38a2b954dbd7e5695667326d7613c5` |
| CN-03 | Hysteria2: `server_ports` без `server_port` не запускается; port hopping течёт и рвёт соединения | P0 | исправлено, проверено | `c90ab92c9415072ebfe6fba27a9f875f0b0204bd` |
| FP-06 / CN-18 | WebSocket early data: стандартный base64, `early_data_header_name` игнорируется, сервер не читает early data | P0 (серверы sing-box) | исправлено, проверено | `808bfa4c0fc1b3ceced6d6c386a2d22fa38a2e3b` |
| BLD-08 | Таблицы раскрутки в release-сборке aarch64 | P2 | исправлено, проверено | `477d0826627f2a8ad6706f8df874ff90550a0064` |
| BLD-06 / BLD-07 | Профиль `opt-level="s"` и per-package `opt-level=3` | P2 | не применено: по замерам исполнителя теряется скорость TLS ChaCha20; независимо не повторялось | — (комментарий в `477d082`) |
| FP-01 | Статичный ECH GREASE в шаблонах Firefox и Chrome | P0 | исправлено, проверено | `4be666f3c8ed722eaed284847958d0b82a1b7166` |
| MEM-07 | Rule sets: SRS загружается через промежуточные копии, пик ×2–3 | P1 | частично исправлено, проверено (промежуточный `Vec<Value>` остаётся) | `fc143dc9a2207816db6fe06d1ad6c4fb01d0b415` |
| MEM-08 | cache.db: flush клонирует всё дерево | P1 | исправлено, проверено (только клонирование при сериализации) | `cc6c8829108d5428b06246a4b5410bfcc5f53abc` |
| RS-01 | Правило rule set только с `domain_regex` совпадает с любым соединением; в смешанных правилах regex игнорируется | P1 | исправлено, проверено | `79fb8be31263157aabd07c7c5c1419528c4e40f0`, `08d35a3814dac7d528d9d1e1a8a9ee336cce647c`, `9c688b2e9c28f8b78dba7833f1ccc71e2e13f5ed` |
| SEC-08 / CQ-11 | DNS: ответ upstream не сверяется с запросом, ID предсказуем | P1 | исправлено, проверено | `2506df64e37b5a119c10724a5e7d6287f5e837d8` |
| CQ-12 | bbolt: бесконечная рекурсия на повреждённом cache.db | P1 | исправлено, проверено | `41c8be591e4c8a664a480498f1aec47192923761` |
| CQ-13 (частично) | cache.db: запись без fsync файла и каталога — исправлена только долговечность записи | P1 | исправлено (частично), ожидает независимой проверки | `6c7d0da0c6a481d091a0e681c4805517a09c8804` |

## Задачи

### CQ-01 — паника `percent_decode` в Clash API до проверки secret

- **Приоритет:** P0, удалённый отказ в обслуживании.
- **Статус:** исправлено, проверено. В `main` не слито, не выпущено.
- **Коммит:** [`49987e66b78e14fc4f57ff367ece1f2fd9d88569`](https://github.com/Screamshow/xrust/commit/49987e66b78e14fc4f57ff367ece1f2fd9d88569), в `dev` с 2026-10-23.
- **Файлы:**
  - `crates/core-runtime/src/clash_api.rs`;
  - `crates/core-runtime/tests/clash_api.rs`.
- **Суть:**
  - `decode_impl` резал `&str` по байтовым индексам. Запрос `GET /%a\xc3\xa9` попадал внутрь многобайтового символа и вызывал панику. Это происходило до проверки secret, а при `panic = "abort"` такой запрос ронял всё ядро.
  - Теперь hex-цифры разбираются побайтно.
  - Побочный эффект: `%+1` больше не декодируется в `0x01`.
  - Порядок ответов без secret не изменился: неизвестный путь даёт `404`, известный маршрут — `401`.

#### Проверки разработки

Отрицательная проверка: новый интеграционный тест на исходном коде (`c5f567c`) падает с паникой `clash_api.rs:1779:33` и сообщением «connection closed before response head».

Профиль legacy:

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --features legacy-protocols -- -D warnings` | exit 0 |
| `cargo test -p core-runtime --features legacy-protocols --lib clash_api::tests::percent_decoding` | 2 passed, 0 failed |
| `cargo test -p core-runtime --features legacy-protocols --test clash_api` | 7 passed, 0 failed |
| `cargo test --workspace --features legacy-protocols` | 78 бинарников: 1495 passed, 0 failed, 19 ignored |

Профиль rust-x:

| Команда | Результат |
|---|---|
| `cargo check --workspace --no-default-features --features rust-x` | exit 0; 14 прежних предупреждений `dead_code`, новых нет |
| `cargo test -p core-config --no-default-features --features rust-x --test rust_x_profile` | 3 passed, 0 failed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib clash_api::tests::percent_decoding` | 2 passed, 0 failed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test clash_api` | 7 passed, 0 failed |
| `cargo build --locked -p core-cli --no-default-features --features rust-x --release` (x86_64-gnu) | собран |

Повтор атаки на release-бинарнике rust-x (x86_64-gnu, loopback, Clash API с secret):
- `GET /%a\xc3\xa9` → `404`;
- `GET /%a\xff` → `404`;
- `GET /version?x=%a\xc3\xa9` без secret → `401`;
- `/version` с secret → `200`;
- процесс жив; после SIGTERM код выхода 0, паник в логе нет.

#### Независимая проверка (Codex)

- Ревью без замечаний.
- 12 целевых тестов rust-x прошли.
- Отдельный release-процесс на OpenWrt 25 VM прошёл успешно.

#### Ограничения

- ARM (aarch64) не проверялся.
- Установка пакета не проверялась.
- Интерфейс LuCI не проверялся.
- Полный набор тестов в профиле rust-x не запускался: там есть прежние падения legacy-тестов, не связанные с задачей (см. аудит, BLD-12).

### SEC-04 — переполнение размера чанка в HTTP-клиенте

- **Приоритет:** P0, удалённый отказ в обслуживании.
- **Статус:** исправлено, проверено. В `main` не слито, не выпущено.
- **Коммиты:**
  - [`5de21230da8bf883f3616f7b7b952917646e9cdb`](https://github.com/Screamshow/xrust/commit/5de21230da8bf883f3616f7b7b952917646e9cdb) — исправление;
  - [`2b49308ed8af6fa4fe1cce16fe1b290b9e4aa325`](https://github.com/Screamshow/xrust/commit/2b49308ed8af6fa4fe1cce16fe1b290b9e4aa325) — исправление регрессии P2 (CR и LF строки размера приходят раздельно).
- **Файл:** `crates/core-runtime/src/http_client.rs`.
- **Суть:**
  - `decode_chunked` складывал размер чанка от пира со смещением без проверок. Строка размера `ffffffffffffffff` в release (`overflow-checks = false`) давала переполнение `start + size + 2`, срез паниковал, и при `panic = "abort"` процесс завершался.
  - Через этот клиент идут remote rule-set и загрузка external_ui.
- **Исправление:**
  - размер разбирается строго: только hex-цифры, checked-умножение и сложение, extensions после `;` игнорируются;
  - до чтения и буферизации данных размер сравнивается с остатком лимита тела (64 МиБ) с учётом уже накопленного;
  - смещения считаются checked-сложением;
  - после данных обязателен CRLF;
  - строка размера ограничена 4 КиБ.
- **Изменение поведения:** раньше молча принимались размеры со знаком (`+5`) и данные без CRLF после чанка. Теперь это ошибка. Корректные chunked-ответы декодируются так же, как раньше.

#### Проверки разработки

Отрицательная проверка: новые тесты на исходном `decode_chunked` (`2de795e`, временная копия с обёрткой без лимита) — 4 из 14 падают:

| Тест | Результат на исходном коде |
|---|---|
| `chunked_huge_sizes_are_errors_not_panics` | паника `attempt to add with overflow` на `start + size + 2` |
| `get_refuses_an_overflowing_chunk_size` | та же паника |
| `chunked_total_over_the_limit_is_refused` | декодер ждёт данные слишком большого чанка, таймаут 5 с |
| `chunked_malformed_sizes_are_errors` | `+5` принят как размер |

Профиль legacy:

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --features legacy-protocols -- -D warnings` | exit 0 |
| `cargo test -p core-runtime --features legacy-protocols --lib http_client` | 14 passed, 0 failed (6 новых) |
| `cargo test --workspace --features legacy-protocols` | 78 бинарников: 1501 passed, 0 failed, 19 ignored |

Профиль rust-x:

| Команда | Результат |
|---|---|
| `cargo check --workspace --no-default-features --features rust-x` | exit 0; 14 прежних предупреждений `dead_code`, новых нет |
| `cargo test -p core-config --no-default-features --features rust-x --test rust_x_profile` | 3 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib http_client` | 14 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib rule_set_remote` | 9 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test clash_api` | 7 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test rule_set_compiled` | 13 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test hot_reload` | 9 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test dns_resolver` | 18 passed, 1 failed: `tcp_transport_uses_the_detour_outbound`. Тест прежний, падает так же и на `2de795e`: в его конфиге outbound `socks`, которого нет в rust-x |

Сквозная проверка на release-бинарниках rust-x (x86_64-gnu, loopback): remote rule-set с локального HTTP-сервера, который отвечает `Transfer-Encoding: chunked` и строкой размера `ffffffffffffffff`.

| Бинарник | Результат |
|---|---|
| до исправления (`49987e6`) | `panicked at http_client.rs:382:39`, abort, код выхода 134 |
| после исправления | без паники; загрузка завершается ошибкой `initial rule-set: evil: response body too large`, код выхода 1 |

#### Регрессия CR/LF (найдена при независимой проверке `5de2123`)

- **Суть.** Пока CRLF не найден, лимит строки размера сравнивался со всей длиной буфера, а в неё входил уже полученный CR. Строка ровно 4096 байт принималась с CRLF целиком, но отвергалась, если CR и LF приходили разными чтениями. Приоритет P2.
- **Исправление (`2b49308`).** Пока ждём LF, допускается один лишний байт под CR. Лимит содержимого строки остаётся 4096 байт.
- **Тест** `chunk_size_line_limit_is_the_same_whole_or_split` проверяет строки 4095, 4096 и 4097 байт: CRLF вместе и раздельно (CR в начальном буфере, LF из потока).
  - До исправления падал только случай 4096 байт при раздельной доставке.
  - После — 50 из 50 повторных запусков проходят.

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --features legacy-protocols -- -D warnings` | exit 0 |
| `cargo test -p core-runtime --features legacy-protocols --lib http_client` | 15 passed, 0 failed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib http_client` | 15 passed, 0 failed |
| `cargo check --workspace --no-default-features --features rust-x` | exit 0; 14 прежних предупреждений `dead_code` |
| rust-x: `--lib rule_set_remote` / `--test clash_api` / `--test rule_set_compiled` / `--test hot_reload` | 9 / 7 / 13 / 9 passed |

После `2b49308` полный набор тестов workspace не перезапускался, только целевые HTTP-тесты.

#### Независимая проверка (Codex)

- **`5de2123`.** Исходная паника устранена, 45 целевых тестов и основной сценарий на OpenWrt 25 VM прошли. Найдена регрессия P2 с раздельной доставкой CR/LF, см. выше.
- **`2b49308` (итоговый).** Ревью без замечаний, 15 HTTP-тестов и 10 сценариев на OpenWrt 25 VM прошли. Регрессия CR/LF устранена.

#### Ограничения

- В `main` не слито, не выпущено.
- ARM, установка пакета и LuCI не проверялись.
- Ошибка **начальной** загрузки remote rule-set по-прежнему завершает запуск — так же, как при 404 или таймауте. Это прежнее поведение, вне задачи. При обновлении после старта сохраняется старый набор: тест `failed_remote_download_keeps_previous_router`.
- Связанные проблемы вне задачи, не исправлялись:
  - путь с `Content-Length` (SEC-07): тело читается до заявленной длины, и лимит 64 МиБ проверяется только после чтения. Исправлено отдельно в задаче SEC-07;
  - загрузка rule-set и external_ui без проверки сертификата (SEC-05).

### SEC-07 — тело по `Content-Length` не ограничено до чтения

- **Приоритет:** P1, исчерпание памяти и зависание загрузки.
- **Статус:** исправлено, проверено. В `main` не слито, не выпущено.
- **Коммит:** [`48c70f91e32a30a2f2a281a66a46703891604bb5`](https://github.com/Screamshow/xrust/commit/48c70f91e32a30a2f2a281a66a46703891604bb5).
- **Файл:** `crates/core-runtime/src/http_client.rs`.
- **Суть.** Тело читалось до заявленной длины или до закрытия соединения, и только потом сравнивалось с `MAX_BODY` (64 МиБ). Из-за этого:
  - сервер мог заявить огромную длину и слать данные — всё буферизовалось до таймаута ввода-вывода (60 с);
  - мог держать соединение открытым без тела — загрузка висела;
  - усечённое тело возвращалось как успешный ответ.
- **Исправление.** Заявленная длина сравнивается с лимитом **до** чтения оставшегося тела. При превышении — немедленная ошибка `response body too large`. Chunked-путь и чтение до EOF не изменены, кроме того, что они получают тот же лимит.

#### Сопутствующие изменения поведения

1. **Строгий разбор и списки `Content-Length`.**
   - Значение — только десятичные цифры. Раньше некорректное значение молча игнорировалось, и тело читалось до EOF; теперь это ошибка `bad content-length`.
   - Список одинаковых значений (`5, 5`) по RFC 9112 §6.3 считается одной длиной и принимается. Без этого строгий разбор превратил бы такой допустимый ответ в ошибку.
   - Разные значения (в списке или в нескольких заголовках) — ошибка.
2. **Ответы 204 и 304 читаются без тела** (RFC 9110). 304 может указывать длину представления, на которое ссылается. Remote rule-set использует условные запросы (`If-None-Match`, обработка 304). Раньше 304 с `Content-Length` ждал тело до закрытия соединения и молча обрезался. С новой проверкой усечения он стал бы ошибкой и сломал бы обновление rule-set.
3. **Усечённое тело** (соединение закрыто раньше заявленной длины) — теперь ошибка `truncated body: N of M bytes`.

#### Проверки разработки

Тесты разделены на три группы. Результаты на старом коде получены во временной копии (`78ccd03`) с новым тестовым модулем и обёрткой `read_response_limited`, которая игнорирует лимит.

| Тест | Группа | Старый код | Новый код |
|---|---|---|---|
| `content_length_valid_bodies_are_read` | корректные ответы | проходит | проходит |
| `content_length_at_the_limit_is_read` | корректные ответы | проходит | проходит |
| `sec07_declared_length_over_max_body_is_refused_before_reading` | SEC-07 | падает: ждёт тело, таймаут теста 5 с | проходит |
| `sec07_get_refuses_a_content_length_over_the_limit` | SEC-07 | падает: усечённое тело возвращено как успех | проходит |
| `content_length_one_over_the_limit_is_refused` | граница новой проверки | падает: проверки нет, ждёт тело | проходит |
| `content_length_identical_list_is_one_length` | сопутствующее (1) | падает: заголовок игнорируется, чтение до EOF | проходит |
| `content_length_malformed_values_are_errors` | сопутствующее (1) | падает: заголовок игнорируется, чтение до EOF | проходит |
| `bodiless_statuses_ignore_content_length` | сопутствующее (2) | падает: 304/204 ждут тело | проходит |
| `content_length_truncated_body_is_an_error` | сопутствующее (3) | падает: усечённое тело возвращено как успех | проходит |

Уязвимость SEC-07 подтверждают только два теста с префиксом `sec07_`. Остальные падения на старом коде отражают намеренно изменённое поведение. Все 15 прежних тестов http_client, включая тесты SEC-04, проходят и на старом, и на новом коде.

Профиль legacy:

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --features legacy-protocols -- -D warnings` | exit 0 |
| `cargo test -p core-runtime --features legacy-protocols --lib http_client` | 24 passed, 0 failed |
| `cargo test --workspace --features legacy-protocols` | 78 бинарников: 1511 passed, 0 failed, 19 ignored. Исправлено 2026-10-24: раньше было указано 1510 — в логе вывод одного бинарника (1 тест) склеился с соседним и не попал в подсчёт |

Профиль rust-x:

| Команда | Результат |
|---|---|
| `cargo check --workspace --no-default-features --features rust-x` | exit 0; 14 прежних предупреждений `dead_code` |
| `cargo test -p core-config --no-default-features --features rust-x --test rust_x_profile` | 3 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib http_client` | 24 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib rule_set_remote` | 9 passed, включая условный запрос с 304 |
| `cargo test -p core-runtime --no-default-features --features rust-x --test clash_api` | 7 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test rule_set_compiled` | 13 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test hot_reload` | 9 passed |

Однократный прогон на release-бинарниках rust-x (x86_64-gnu, loopback). Remote rule-set с локального сервера, который заявляет `Content-Length` 1 ТБ и передаёт до 512 МиБ. Прогон не повторялся.

| Бинарник | Результат |
|---|---|
| до исправления (`5de2123`) | через 8 с всё ещё загружает; пиковый RSS (VmHWM) 1048 МиБ; остановлен SIGTERM |
| после исправления | ошибка `initial rule-set: big: response body too large` через ~0,2 с, без заметного роста памяти |

#### Независимая проверка (Codex)

- **`48c70f9`.** Ревью без замечаний, 55 целевых тестов rust-x и 10 сценариев на OpenWrt 25 VM прошли.

#### Ограничения

- В `main` не слито, не выпущено.
- ARM, установка пакета и LuCI не проверялись.
- Связанные проблемы вне задачи, не исправлялись:
  - путь без `Content-Length` и без chunked (чтение до EOF): лимит проверяется перед каждым чтением, поэтому тело может превысить его не более чем на один буфер 8 КиБ до отказа;
  - строка состояния и заголовки ограничены 64 КиБ, но таймаут на них общий (60 с) — медленный сервер может держать загрузку до таймаута;
  - загрузка rule-set и external_ui без проверки сертификата (SEC-05).

### SEC-05 — HTTPS-загрузки rule-set и external_ui без проверки сертификата

- **Приоритет:** P1. В сводном отчёте аудита повышен до P0: вместе с SEC-04 и CQ-03 давал удалённый отказ в обслуживании через MITM.
- **Статус:** исправлено, проверено. В `main` не слито, не выпущено.
- **Коммит:** [`11ada8206da3ccdd5cbb54c6758133c7c290d362`](https://github.com/Screamshow/xrust/commit/11ada8206da3ccdd5cbb54c6758133c7c290d362).
- **Файлы:**
  - `crates/core-runtime/src/http_client.rs`, `crates/core-runtime/src/tls_client.rs` — исправление;
  - `crates/core-runtime/src/route/rule_set_remote.rs` — модульные тесты;
  - `crates/core-runtime/tests/fetch_tls.rs`, `crates/core-runtime/tests/support/https_fixture.rs` — интеграционные тесты и локальный HTTPS-сервер.
- **Суть.** HTTPS-загрузки HTTP-клиента без явного блока `tls` шли через `wrap_probe_stream`, а он принимал любой сертификат. Посредник на пути мог:
  - подменить remote rule-set;
  - подменить архив external_ui — то есть выполнить свой скрипт на origin Clash API;
  - подать произвольные данные в парсеры ответа.

#### Затронутые потребители

`wrap_probe_stream` вызывался только из `HttpClient::request` (`http_client.rs`). `HttpClient` используют:
- remote rule-set маршрутизации (`route/mod.rs`, `build_rule_sets`), включая rule-set, на которые ссылаются DNS-правила (`dns/mod.rs`);
- реестр `http_clients`, `route.default_http_client` и устаревший `download_detour`;
- загрузку external_ui (`clash_api.rs`, `ensure_external_ui`).

URLTest и delay-пробы Clash API уже проверяли сертификат через тот же `probe_tls` — их поведение не изменилось.

#### Исправление и контракт

- **Без явного `tls` у HTTP-клиента:** сервер проверяется через `probe_tls` роутера — тот же коннектор, что у URLTest. Проверяются цепочка, имя сервера (DNS-имя или IP из URL) и срок действия.
- **Доверенные корни:** встроенный набор Mozilla плюс верхнеуровневая опция `certificate` (`certificate`, `certificate_path`). Это существующая настройка проекта.
- **Detour.** Detour-outbound только переносит соединение. Его собственные TLS-настройки, включая `insecure`, к серверу загрузки не применяются.
- **Нового отключения проверки и fallback на AcceptAny нет.** `wrap_probe_stream` удалён.
- **Явный блок `tls` у HTTP-клиента** (`http_clients[].tls` с `enabled: true`) используется как прежде, через разбор TLS-опций outbound:
  - его поля, включая явно заданный `insecure`, `certificate` и pins, действуют как написано;
  - `server_name` берётся из `tls.server_name`, затем из `server_name` клиента, иначе по умолчанию `localhost` (см. ограничения).
- **Без изменений:** обычный HTTP, редиректы, маршрутизация и detour.
- **Изменение поведения.** Серверы rule-set и UI с самоподписанным или частным сертификатом без доверенного CA теперь отклоняются. Чтобы такой сервер снова работал, его CA добавляется в верхнеуровневый `certificate`.

#### Проверки разработки

Тесты используют существующие тестовые сертификаты (`tests/golden/certs/urltest-*`) и локальный HTTPS-сервер. Результаты на старом коде получены во временной копии (`6b34832`): исходные `http_client.rs` и `tls_client.rs`, новые тесты.

| Тест | Что проверяет | Старый код | Новый код |
|---|---|---|---|
| `https_fetch_with_a_trusted_ca_and_the_right_name_fills_the_set` | доверенный CA и правильное имя, напрямую и через detour | проходит | проходит |
| `https_fetch_refuses_an_unverified_server` | неизвестный CA, чужая подпись, неправильное имя, просроченный | падает: сертификат принят | проходит |
| `failed_https_update_keeps_the_previous_set` | обновление с непроверяемым сертификатом сохраняет старый набор | падает: набор заменён | проходит |
| `remote_rule_set_over_https_is_verified` | rule-set через конфиг (`certificate` → роутер → загрузка), 1 успех и 4 отказа | падает: rule-set загружен с неизвестным CA | проходит |
| `external_ui_over_https_is_verified` | external_ui, 1 успех и 4 отказа; ядро запускается, каталог пуст | падает: UI установлен с неизвестным CA | проходит |
| `external_ui_tls_failure_keeps_an_existing_ui` | ошибка TLS не трогает установленный UI | проходит: при непустом каталоге загрузка не выполняется и в старом коде | проходит |

Ожидаемые ошибки: `UnknownIssuer`, `BadSignature`, `certificate not valid for name "127.0.0.1"`, `certificate expired`. Во всех случаях отказа сервер не получает запрос — проверяется счётчиком.

Профиль legacy:

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --features legacy-protocols -- -D warnings` | exit 0 |
| `cargo test --workspace --features legacy-protocols` | 79 бинарников: 1517 passed, 0 failed, 19 ignored |

Профиль rust-x:

| Команда | Результат |
|---|---|
| `cargo check --workspace --no-default-features --features rust-x` | exit 0; 14 прежних предупреждений `dead_code` |
| `cargo test -p core-config --no-default-features --features rust-x --test rust_x_profile` | 3 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib http_client` | 24 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --lib rule_set_remote` | 12 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test fetch_tls` | 3 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test clash_api` | 7 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test urltest_tls` | 1 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test rule_set_compiled` | 13 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test hot_reload` | 9 passed |
| `cargo test -p core-runtime --no-default-features --features rust-x --test dns_resolver` | 18 passed, 1 failed: прежний `tcp_transport_uses_the_detour_outbound`, в его конфиге outbound `socks`, которого нет в rust-x |

#### Независимая проверка (Codex)

- **`11ada82`.** Ревью без замечаний, 47 целевых тестов rust-x и 15 сценариев на OpenWrt 25 VM прошли.

#### Ограничения

- В `main` не слито, не выпущено.
- ARM, установка пакета и LuCI не проверялись.
- Живая загрузка UI с GitHub не проверялась.
- Связанные проблемы вне задачи, не исправлялись:
  - при явном `tls` у HTTP-клиента без `server_name` проверка идёт по имени `localhost`, а не по хосту из URL — для обычных серверов это отказ;
  - доверенные корни берутся из `webpki-roots 1.0.9` и `rustls-webpki 0.103.15` с известными advisory (BLD-02);
  - ошибка **начальной** загрузки remote rule-set по-прежнему завершает запуск — как при 404 или таймауте;
  - REALITY, pins при `insecure`, MASQUE и прочие находки TLS (SEC-01…03) не затрагивались.

### BLD-02 — `rustls-webpki` и `webpki-roots`: доверие к скомпрометированным промежуточным emSign

- **Приоритет:** P0.
- **Статус:** исправлено, проверено. В `main` не слито, не выпущено.
- **Коммит:** [`e0404da672defc885295297a8e4cf3c2087f2d44`](https://github.com/Screamshow/xrust/commit/e0404da672defc885295297a8e4cf3c2087f2d44).
- **Файл:** `Cargo.lock`. Исходный код, `Cargo.toml`, TLS-политика, REALITY, pins и криптография не менялись.

#### Применимость advisories

Обе advisory относятся к CVE-2026-111943: могли приниматься цепочки через промежуточные сертификаты emSign, закрытые ключи которых теперь известны.

| Advisory | Пакет | Исправлено в | До | Применимо к проекту |
|---|---|---|---|---|
| RUSTSEC-2026-0382 | `rustls-webpki` | `>= 0.103.16` (ветка 0.103) | 0.103.15 | да: используется `core-tls` напрямую и через `rustls 0.23.45` |
| RUSTSEC-2026-0381 | `webpki-roots` | `>= 1.0.10` | 1.0.9 | да: корни Mozilla приходят в `core-tls` через совместимый пакет `webpki-roots 0.26.11` |

Пакет `webpki-roots 0.26.11` в advisory отмечен как `unaffected`. Но своего набора корней у него нет: он реэкспортирует отдельно разрешённую зависимость 1.x. Поэтому решает версия 1.x.

#### Обновление

Адресное, без общего `cargo update`:

```
cargo update -p rustls-webpki --precise 0.103.16
cargo update -p webpki-roots@1.0.9 --precise 1.0.10
```

| Пакет | До | После |
|---|---|---|
| `rustls-webpki` | 0.103.15 | 0.103.16 |
| `webpki-roots` (1.x) | 1.0.9 | 1.0.10 |
| `webpki-roots` (0.26, совместимый) | 0.26.11 | 0.26.11 — изменилась только ссылка на 1.x |

- **Транзитивных обновлений нет.** Зависимости новых версий совпадают с прежними: `ring`, `rustls-pki-types`, `untrusted`.
- **Выбор версий.** Взяты минимальные исправленные. `webpki-roots 1.0.11` опубликован, но для этой задачи не нужен.
- **Источники:** база RustSec advisory-db (официальный репозиторий, состояние на 2026-10-23) и индекс crates.io. Контрольные суммы проверены cargo при загрузке.

#### Проверки разработки

- **Корни:** в `webpki-roots 1.0.10` записей `emSign ECC Root CA - G3` — 0, в 1.0.9 было 4.
- **cargo audit** (advisory-db от 2026-10-23, `--no-fetch`):

| | Уязвимости | Предупреждения |
|---|---|---|
| до | 8, включая RUSTSEC-2026-0381 и -0382 | 5 |
| после | 6 — обе advisory ушли, остальное без изменений | 5 |

Профиль legacy:

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --locked --workspace --all-targets --features legacy-protocols -- -D warnings` | exit 0 |
| `cargo test --locked --workspace --features legacy-protocols` | 79 бинарников: 1517 passed, 0 failed, 19 ignored |

Профиль rust-x и TLS:

| Команда | Результат |
|---|---|
| `cargo check --locked --workspace --no-default-features --features rust-x` | exit 0; 14 прежних предупреждений `dead_code` |
| `cargo test --locked -p core-config --no-default-features --features rust-x --test rust_x_profile` | 3 passed |
| `cargo test --locked -p core-tls` | 10 бинарников: 88 passed, 0 failed |
| rust-x `--lib http_client` / `--lib rule_set_remote` / `--lib tls_client` | 24 / 12 / 9 passed |
| rust-x `--test fetch_tls` (SEC-05) / `--test urltest_tls` | 3 / 1 passed |
| rust-x `--test tls_interop` / `--test tls_own_stack` / `--test imported_pins` | 4 / 4 / 1 passed |
| rust-x `--test clash_api` / `--test rule_set_compiled` / `--test hot_reload` | 7 / 13 / 9 passed |

Релизные сборки rust-x (`cargo build --locked -p core-cli --no-default-features --features rust-x --release --target …`, без `RUSTFLAGS` в окружении):

| Цель | Результат |
|---|---|
| `aarch64-unknown-linux-musl` | собран, 10 220 032 байт (до: 10 220 464). Флаги из `.cargo/config.toml` подтверждены по `-v`: `--cfg aes_armv8`, `polyval_armv8`, `chacha20_force_neon`, `rust-lld`, `link-self-contained=yes`, `--icf=safe`, `noseparate-code`, `norelro` |
| `x86_64-unknown-linux-musl` | **не собран в этом окружении**: нет `x86_64-linux-musl-gcc` (пакет `musl-tools`) для `libmimalloc-sys`. Это прежнее ограничение окружения, не связанное с изменением |
| `x86_64-unknown-linux-gnu` (замена для проверки кода) | собран, 12 408 216 байт |

#### Независимая проверка (Codex)

- **`e0404da`.** Ревью без замечаний, 122 теста и 14 TLS-сценариев на OpenWrt 25 VM прошли.
- **Релизные musl-сборки rust-x** для `x86_64-unknown-linux-musl` и `aarch64-unknown-linux-musl` успешны, флаги `.cargo/config.toml` сохранены. Это закрывает сборку x86_64-musl, которую разработка выполнить не смогла.

#### Ограничения

- В `main` не слито, не выпущено.
- ARM: бинарник для aarch64 **собран**, но **не запускался** — исполнение на ARM не проверено.
- Установка пакета и LuCI не проверялись.
- Живые загрузки с GitHub не проверялись.

#### Остальные advisories (не обновлялись, отдельные задачи)

| Advisory | Пакет | Версия | Суть | Исправлено в |
|---|---|---|---|---|
| RUSTSEC-2026-0349 | `rustls` | 0.23.45 | неаутентифицированный ServerHello может понизить последующие соединения до классического обмена ключами | 0.23.46 (BLD-03) |
| RUSTSEC-2026-0346 | `rustls` | 0.23.45 | `Debug` клиентских сессий раскрывает секреты TLS | 0.23.46 |
| RUSTSEC-2026-0347 | `rustls` | 0.23.45 | буферизованные данные уходят внешнему серверу после отказа ECH | 0.23.46 |
| RUSTSEC-2026-0348 | `rustls` | 0.23.45 | распаковка Brotli-сертификата до 1 ГиБ до аутентификации | 0.23.46 |
| RUSTSEC-2026-0344 | `ruzstd` | 0.8.3 | OOM при распаковке (BLD-01) | ≥ 0.9.1, нужна правка `Cargo.toml` |
| RUSTSEC-2023-0071 | `rsa` | 0.9.10 | Marvin, тайминговая атака | исправления нет |
| RUSTSEC-2026-0002, -0253 | `lru` | 0.12.5 | unsound | см. BLD-16 |
| RUSTSEC-2026-0386 | `tokio` | 1.53.1 | unsound `AsyncFd<RawFd>` (BLD-05) | см. advisory |
| RUSTSEC-2024-0436 | `paste` | 1.0.15 | не поддерживается | — |
| RUSTSEC-2025-0134 | `rustls-pemfile` | 2.2.0 | не поддерживается | — |

Также `cargo audit` сообщает, что `yoke-derive` отозван (yanked).

### FX-01 — legacy-протоколы в подписке или ручной ссылке валят весь конфиг на rust-x

- **Приоритет:** P0.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Репозиторий:** Screamshow/forkop-x, ветка `dev`. Xrust, XHTTP и ByeDPI не менялись.
- **Коммиты:**
  - [`7acb5411814dc247629116be8b35962b57db0801`](https://github.com/Screamshow/forkop-x/commit/7acb5411814dc247629116be8b35962b57db0801) — генератор, `forkop/files/usr/lib/singbox/generator.uc`;
  - [`589f659aca7d15cc308c3741126140a757310e5e`](https://github.com/Screamshow/forkop-x/commit/589f659aca7d15cc308c3741126140a757310e5e) — тесты `tests/subscription_protocol_compatibility.{sh,uc}` и разрешение их в `.gitignore`.

#### Проблема

Профиль rust-x собран без `legacy-protocols`, и `check` отвергает весь конфиг, если в нём есть outbound `vmess`, `trojan`, `shadowsocks`, `socks` и другие исключённые типы. Forkop пропускал узлы подписки только из-за пинов и XHTTP. Один trojan- или ss-узел в смешанной подписке останавливал старт или любой reload.

#### Исправление и контракт

- **Определение ядра.** Ядро считается rust-x, если версия содержит `-rust-x.` (обёртка пакета) или `-tachyon.` (бинарник без обёртки). Так же уже определялась поддержка пинов. Список исключённых типов повторяет `core-config` `validate()`: `naive`, `vmess`, `trojan`, `shadowsocks`, `tuic`, `anytls`, `snell`, `shadowtls`, `fptn`, `openvpn`, `openvpn-client`, `socks`.
- **Подписка.** Такие узлы пропускаются с предупреждением в журнале: `skipped incompatible subscription outbound for rule '<секция>': <имя> (protocol trojan is not included in Xrust)`. Действующий механизм удаляет вслед за ними узлы с `detour` на пропущенный узел и группы без оставшихся участников. Участники и `default` групп переписываются только на сохранённые теги. Кэш подписки не меняется: при смене ядра узлы вернутся.
- **Нет совместимых узлов.** Генерация завершается ошибкой `connection section '<секция>' has no outbounds compatible with Xrust; skipped subscription outbounds with unsupported protocols: shadowsocks (1), trojan (1). Settings were not applied`. Переключения в Direct нет. Временный файл удаляется, рабочий конфиг остаётся прежним.
- **Ручные ссылки и JSON-outbound.** Отклоняются явно: `manual outbound '<имя>' uses protocol trojan, which is not included in Xrust; remove it or use a VLESS or Hysteria2 connection`, для JSON — `JSON outbound '<имя>' …`.
- **Другие ядра** (Go X, Extended, upstream) получают все узлы, как раньше.

#### Проверки разработки

`tests/subscription_protocol_compatibility.sh` (ucode, генератор в режиме fixture; с `RUST_X_BINARY` и `LEGACY_BINARY` вывод дополнительно проверяется реальным `check`):

| Сценарий | Результат |
|---|---|
| Смешанная подписка (vless, hysteria2, trojan, ss, vmess, socks, vless с `detour` на trojan, смешанная группа, группа и вложенная группа только из legacy), версии `1.14.2-rust-x.0.0.26` и `v0.0.26-tachyon.0` | остались vless и hysteria2; смешанная группа сокращена до `vless-a` с `default` `vless-a`; legacy-группы и узел с `detour` удалены; все ссылки на outbound (группы, `detour`, `default`, `route`, DNS) указывают на существующие теги; предупреждения по каждому узлу; кэш не изменён; `check` релизного rust-x — exit 0 |
| Та же подписка, `1.14.2-x-1.0.4` | все 4 legacy-узла на месте, предупреждений о Xrust нет; `check` профиля legacy — exit 0 |
| Подписка только из trojan, ss и legacy-группы на rust-x | ненулевой код, понятная ошибка с перечнем протоколов, прежний конфиг не тронут |
| Ручные ссылки vless + trojan на rust-x; ss и socks5 на tachyon | явная ошибка с именем узла и протоколом, прежний конфиг не тронут |
| Ручная ссылка trojan на Go X | генерация успешна |
| JSON-outbound vmess на rust-x | явная ошибка, прежний конфиг не тронут |

- **Регрессия.** На генераторе до исправления тест падает на первом же сценарии: `unsupported protocol generated`.
- **Соседние тесты** проходят: `subscription_pin_compatibility.uc` с реальным rust-x, `subscription_certificate_pins`, `json_outbound_connection`, `subscription_filter_selection`, `xhttp_capabilities`, `urltest_groups`, `urltest_empty_groups`, `urltest_name_filter`, `filtered_outbound_runtime`.
- **Весь набор без VM** (100 скриптов `tests/*.sh` без `*_vm.sh`) на исходном `dev` и после изменений даёт одинаковые коды возврата; добавился только новый тест. Около 30 скриптов падают в обоих случаях: им нужны пути OpenWrt (`/usr/lib/forkop`), VM или утилиты, которых нет в среде разработки. Среди них `sing_box_runtime.sh` (`provider group removes XHTTP member`), `rust_x_hot_reload.sh` и `tachyon_improvements.sh`.

#### Независимая проверка (Codex)

Дата: 2026-10-24.

- **Ревью** коммитов `7acb541` и `589f659` без замечаний. Проверялся точный Git-снимок `589f659`. Повторный аудит не проводился. `git diff --check` прошёл.
- **Целевые тесты.** Прошли 10 точек входа: `subscription_protocol_compatibility.sh`, `subscription_certificate_pins.sh`, `subscription_filter_selection.sh` (31 проверка и сценарии URLTest), `urltest_groups.sh`, `urltest_empty_groups.sh`, `subscription_pin_compatibility.uc`, `xhttp_capabilities.sh`, `subscription_version_snapshot.sh`, `subscription_runtime_unchanged.sh`, `rust_x_hot_reload.sh`. Тесты совместимости протоколов и пинов дополнительно запускали реальный `check` Rust X. Общее число внутренних проверок не подсчитывалось.
- **Отрицательный контроль.** На генераторе до исправления новый тест падает с `unsupported protocol generated`.

OpenWrt VM: OpenWrt 25.12.5 x86_64, установлен Rust X 0.0.25-r1. Проверки шли отдельными процессами во временном каталоге, на loopback-портах.

| Сценарий | Результат |
|---|---|
| Изолированный cold start со смешанной подпиской | генерация и `check` успешны; HTTP-трафик прошёл по цепочке SOCKS → сгенерированный selector → VLESS → HTTP |
| Подписка только с Trojan | генерация отклонена, в ошибке названы секция и протокол; активный файл и PID сохранены, прежний трафик работает |
| `singbox/runtime.uc prepare-config-stage` с несовместимой подпиской | отклонено до публикации stage-файла; активная конфигурация, PID и трафик сохранены; ошибка генератора видна в syslog. Подготовка и загрузка кэша обходились явным аргументом deferred-sections |
| Hot reload изолированного процесса (восстановлен смешанный кэш, генерация, SIGHUP) | PID сохранён, трафик работает; `/rust-x/applied-config`: `generation: 2`, `ready: true`, `hot_reload: true` |
| Возврат узлов для Go X | подтверждён на уровне генератора из неизменённого кэша |
| Ручные ссылки и JSON-outbound с неподдерживаемыми протоколами | на уровне генератора: явный отказ, прежний файл сохраняется |

PID основной службы и контрольные суммы `/etc/config/forkop`, `/etc/config/dhcp`, `/etc/sing-box/config.json` не изменились. Пакеты, настройки службы и firewall командами проверки не менялись. В период проверки были предупреждения существующего watchdog о доступности. Общее состояние production-рантайма и DNS отдельно не проверялось.

#### Ограничения

- В `main` не слито, не выпущено.
- Это не полный CI и не полная проверка LuCI и жизненного цикла службы. Не проверялись:
  - полный подписочный reload через RPC и жизненный цикл установленной службы Forkop;
  - cold start всей установленной службы без совместимых узлов;
  - сохранение и применение ручной ссылки через LuCI, показ ошибки в интерфейсе;
  - фактическое переключение установленного ядра на Go X и работа конфигурации с legacy-протоколами;
  - реальные загрузки подписки у провайдера;
  - ARM, установка пакетов, полный CI.
- На VM стоял Rust X 0.0.25-r1, а не текущая сборка `dev`.
- Версия `-tachyon.` у бинарника без обёртки одинакова для профилей с legacy-протоколами и без них. Такое ядро всегда считается rust-x, и legacy-узлы пропускаются даже там, где ядро их поддерживает. Пакет Forkop ставит только rust-x с обёрткой. Точное определение требует нативного списка протоколов в `version` (FX-04).
- Предупреждения о пропуске пишутся в журнал, отдельного показа в UI нет.
- ByeDPI (outbound `socks`, FX-02) в этой задаче не менялся; позже удалён из Forkop X (см. FX-02).

### FX-02 — ByeDPI на rust-x не работает (решено удалением функции)

- **Приоритет:** P0 для пользователей ByeDPI.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Решение:** ByeDPI полностью удалён из Forkop X, а не адаптирован к rust-x. Миграции старых настроек, уведомлений об удалении и очистки процессов ciadpi нет — так решено.
- **Репозиторий:** Screamshow/forkop-x, ветка `dev`. Xrust, XHTTP и другие компоненты не менялись.
- **Коммит:** [`f6d10ef6cf5628cf7e9b34673a677dd970cbe1cb`](https://github.com/Screamshow/forkop-x/commit/f6d10ef6cf5628cf7e9b34673a677dd970cbe1cb).

#### Проблема

Секция с действием ByeDPI генерировала outbound `socks` к локальному ciadpi. Профиль rust-x собран без outbound `socks` и отвергает такой конфиг целиком.

#### Что удалено

- **Runtime:** модули `providers/byedpi`, запуск, остановка и перезапуск ciadpi при старте и reload, ByeDPI в сигнатурах состояния и плане перезагрузки, в nft, маршрутах, кэше подписок и UI-состоянии.
- **Генерация:** локальный SOCKS-outbound ByeDPI и цель маршрута; проверка стратегий и требований провайдера в валидаторе.
- **Компонент:** установка, обновление, удаление и автопроверка обновлений, выбор пакета; CLI-методы `check_byedpi_runtime`, `get_byedpi_status`, `validate_byedpi_strategy_json`.
- **Интерфейс:** действие ByeDPI, редактор стратегии и опции mixed proxy для него в LuCI, проверка в диагностике, карточка на вкладке обновлений.
- **Тесты и переводы:** ByeDPI-тесты и ByeDPI-части других тестов; 31 строка перевода, использовавшаяся только удалённым кодом.
- **Позиционные аргументы:** из режимов `reload.uc plan` и `system-info-json` убраны поля ByeDPI, тест `list_update_reload_policy.sh` обновлён.

#### Что сохранено

- Ручные ссылки `socks4://` и `socks5://` и SOCKS JSON-outbound генерируются как раньше.
- Старые UCI-настройки не переписываются.
- `main.js` и сжатые LuCI-ресурсы пересобраны через `yarn build`; файлы переводов правились точечно, потому что `yarn locales:actualize` даже на чистом `dev` переписывает тысячи строк.

#### Проверки разработки

- **`tests/byedpi_removed.sh`:** в runtime, LuCI (исходных, собранных и сжатых), фронтенде и переводах нет упоминаний ByeDPI и ciadpi; ссылки SOCKS4, SOCKS5 и SOCKS JSON-outbound дают outbound `socks`. На коде до удаления тест падает.
- **Фронтенд:** 607 тестов — 594 прошли, 13 упали; все 13 в `tests/whatsapp-settings.test.ts` и падали до изменений. Удалены 2 ByeDPI-теста. Lint, typecheck, форматирование изменённых файлов и `tests/luci_save_apply.cjs` проходят. Контрольные суммы `generated/source.sha256` сходятся.
- **Shell-тесты без VM** (101 скрипт до, 102 после): коды возврата совпадают, кроме добавленного теста. Около 30 скриптов падают в обоих случаях — им нужны пути OpenWrt, VM или отсутствующие утилиты; среди них `sing_box_runtime.sh`, который падает до ByeDPI-фикстур.
- **Целевые:** `list_update_reload_policy`, `provider_shutdown`, `ui_sing_box_probe`, тест FX-01 с реальным rust-x и `subscription_pin_compatibility.uc` проходят.

#### Независимая проверка (Codex)

- 55 frontend-тестов прошли; typecheck, lint и LuCI save/apply успешны.
- Все 10 контрольных сумм `generated` совпали.
- На OpenWrt 25.12.5 x86_64 прошли тест удаления ByeDPI, план reload, остановка оставшихся провайдеров Zapret и Zapret2 и тест FX-01 с реальным Rust X 0.0.25-r1.
- Ссылки SOCKS4 и SOCKS5 и SOCKS JSON-outbound продолжают генерироваться.
- Изолированный VLESS-трафик и hot reload работают. При отклонении несовместимой конфигурации прежние файл, PID и трафик сохраняются.
- Старый `action=byedpi` явно отклоняется без перезаписи выходного файла — ожидаемо по согласованному решению.
- Новый тест на родительском коммите падает.
- `shell_inventory.sh` и `sing_box_runtime.sh` падают одинаково до и после патча, успешными не засчитаны. Изменённые provider-фикстуры проверены отдельно.

#### Ограничения

- В `main` не слито, не выпущено.
- Не проверялись живой LuCI, обновление пакета, полный жизненный цикл установленной службы, ARM и полный CI.
- Миграции и очистки нет намеренно: секции `action=byedpi` после обновления дают ошибку генерации `unsupported action byedpi`, валидатор их отвергает, а в LuCI они отображаются как «Proxy». Пользователь должен сменить действие или удалить секцию.
- Установленный пакет ByeDPI и уже запущенные Forkop процессы ciadpi не удаляются и не останавливаются; Forkop просто перестаёт ими управлять.
- Датированные отчёты в `docs/` forkop-x не менялись.

### CQ-03 — SRS-декодер: недоверенные счётчики и индексы, zlib без лимита

- **Приоритет:** P0 (в сводке аудита — №3): remote rule-set или повреждённый кэш роняет процесс при загрузке и каждом старте.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммиты:** [`fced50992b3ac7f12fb7136286b8c08d05dc9b32`](https://github.com/Screamshow/xrust/commit/fced50992b3ac7f12fb7136286b8c08d05dc9b32), исправление замечания — [`ffb4988939fb376082ba427c609c618d2f7808ba`](https://github.com/Screamshow/xrust/commit/ffb4988939fb376082ba427c609c618d2f7808ba).
- **Файл:** `crates/core-config/src/srs.rs` (код и тесты). Вызывающие (`rule_set_remote.rs`, `route/mod.rs`, `validate.rs`, CLI `rule-set`) не менялись: они уже передают `Err` дальше. На remote-пути плохой файл отвергается до замены правил и записи кэша.

#### Места и исправление

| Место (до исправления) | Было | Стало |
|---|---|---|
| `Vec::with_capacity(count)` для правил, логических подправил, диапазонов IP-set (`:67`, `:107`, `:804`) и все счётные списки | `capacity overflow` при 2^60, аварийное завершение `memory allocation of 6400000000 bytes failed` при 2e8 | счётчик больше, чем вмещает остаток данных при минимальном размере элемента, — `Err`; предвыделение не больше 4096 |
| `count_zeros` / `select_ith_one` (`:732`, `:739-741`) | `index out of bounds` на пустом bitmap | проверенные `get`/`checked_sub`, несогласованный trie — `Err` |
| zlib (`:60-64`) | без лимита: файл 260 КБ распаковывался в 256 МиБ | лимит распакованных данных 64 МиБ; первый проход только считает, поэтому бомба ничего не выделяет |
| обход trie (рекурсия на каждый узел), найдено дополнительно | файл 11,5 КБ в виде одной цепочки — `stack overflow`, аварийное завершение | итеративный обход с тем же порядком |
| размер декодированных правил, найдено дополнительно | 36 КБ пустых строк — 455 МБ RSS; квадратичный trie — около 200 МБ | бюджет 256 МиБ (длина строки + 64 байта на значение), сверх — `Err` |

#### Лимиты

- **64 МиБ распакованных данных.** Реальные списки распаковываются примерно в 1,7 раза: 300 тыс. доменов — файл 3,97 МБ, данные 6,86 МБ. Лимит вмещает около 2,9 млн доменов (≈9× крупнейшего образца) и равен лимиту загрузки HTTP-клиента.
- **256 МиБ декодированных значений.** 300 тыс. доменов расходуют около 26 МБ бюджета. Специально собранный файл может занять до ≈260 МБ RSS до отказа — примерно столько же, сколько настоящий список на 3 млн доменов.

#### Воспроизведение до исправления

- Проверено разработкой на копии `HEAD` (release): `count = 2^60` — паника `capacity overflow`; zlib-бомба 260 745 байт — `Ok`, распаковано 256 МиБ. После исправления: `rule-set element count … exceeds the remaining 0 bytes` и `decompress rule-set: payload exceeds 67108864 bytes`.
- Отдельным стендом на копии старого `srs.rs`: `count = 2e8` — `memory allocation of 6400000000 bytes failed`; пустой bitmap — `index out of bounds: the len is 0 but the index is 0` (`srs.rs:732`); цепочка глубиной 2 млн — `stack overflow`; 8 млн пустых строк — `Ok`, 455 МБ RSS.

#### Проверки разработки

- 11 новых тестов, всего тестов `srs` 19: огромные счётчики, граница счётчика, несогласованный trie, глубокий trie, бюджет и его граница, граница распаковки (4096 OK, 4097 — отказ), сгенерированная zip-бомба, эталонный файл `local.srs` с ожидаемым JSON, round-trip большого списка, 4000 детерминированных мутаций без паники.
- На старом коде падают: огромные счётчики, несогласованный trie, глубокий trie (SIGABRT), мутации (аварийное завершение на выделении 1,4·10^18 байт), бюджет и zip-бомба (`Ok` вместо `Err`). Граничные тесты используют новые внутренние лимиты и на старом коде не запускаются.
- 11 образцов `.srs` (включая список на 300 тыс. доменов) декодируются байт-в-байт как раньше, `bad.srs` даёт ту же ошибку. Декодирование крупнейшего образца медленнее примерно на 10 % (674 → 760 мс) из-за второго прохода распаковки.

| Команда | Результат |
|---|---|
| `rustfmt --check --edition 2024 crates/core-config/src/srs.rs` | чисто |
| `cargo clippy --locked -p core-config --all-targets -- -D warnings` (и с `--no-default-features --features rust-x`) | чисто |
| `cargo test --locked -p core-config --lib srs` (оба профиля) | 19 passed |
| `cargo test --locked -p core-config` | lib 301 passed; интеграционные 3 + 1 + 0, 0 failed |
| `cargo test --locked -p core-runtime --no-default-features --features rust-x --lib rule_set` / `--test rule_set_compiled` | 18 / 13 passed |
| `cargo test --locked -p core-cli --no-default-features --features rust-x rule_set` | 4 passed |

- **Ранее существовавшие падения:** в профиле rust-x 108 тестов lib `core-config` (`fptn::tests::*`, `validate::endpoint_probe_parity_tests::*`, `validate::tests::{tuic_*, …}`) падают одинаково на `HEAD` и после изменения: это тесты legacy-протоколов, запускаемые без соответствующей feature.

#### Ограничения

- В `main` не слито, не выпущено.
- OpenWrt, release-бинарник на роутере и полный CI не проверялись. Фаззинг в CI не добавлен — только детерминированный цикл мутаций в тестах.
- Не исправлено (вне задачи): `read_domain_matcher` вызывает `contains` и `retain` в цикле — O(n²) по CPU на списках v1 или специально собранных файлах. Это зависание CPU, не паника и не выделение памяти.
- CQ-04 (TSRS) не затронут.
- Текст части ошибок для усечённых данных изменился («element count … exceeds» вместо «unexpected end of rule-set»); на этот текст никто не опирается.

#### Замечание независимой проверки `fced509` и исправление

- **Замечание (Codex):** стек обхода `Frame` и буфер ключа `current` (`srs.rs:780-785`) не учитывались в бюджете. Глубокий trie с редкими листьями проходил лимиты, но требовал рабочей памяти пропорционально глубине: около 323 МиБ RSS; на OpenWrt при ограничении процесса 256 МиБ — аварийное завершение вместо ошибки декодера.
- **Исправление:** [`ffb4988939fb376082ba427c609c618d2f7808ba`](https://github.com/Screamshow/xrust/commit/ffb4988939fb376082ba427c609c618d2f7808ba). Ключ доменного matcher'а длиннее 4096 байт (`MAX_DOMAIN_KEY_LEN`) отвергается до роста буфера и стека, поэтому глубина обхода ограничена. DNS-имя — не более 253 байт, реальные списки не затронуты.
- **Воспроизведение (разработка, release, чтение отдельным процессом):** файл 10 778 байт — цепочка из 8 млн узлов и один короткий домен. На `fced509`: `Ok`, пик VmHWM 2,9 → 166,7 МБ. После: `invalid domain matcher: key longer than 4096 bytes`, пик 2,9 → 26 МБ; остаток — сами массивы trie, ограниченные лимитом распакованных данных.
- **Тесты:** `deep_trie_does_not_overflow_the_stack` теперь ожидает ошибку для ключа 200 000 байт; новые `domain_key_length_boundary` (4096 — OK, 4097 — отказ) и `deep_trie_with_rare_leaves_is_rejected` (цепочка 2 млн узлов и один лист). `srs` — 21/21 в обоих профилях, `core-config` lib — 303 passed, `rule_set_compiled` — 13 passed; fmt и clippy чистые.
- **Пройдено при независимой проверке `fced509` (Codex):** 19 SRS-тестов. ARM и полный CI не проверялись.
- **Ограничение:** бюджет декодированных значений (256 МиБ) не менялся; рабочая память обхода теперь мала, но декодированные правила вместе с распакованными данными по-прежнему могут занять сотни мегабайт до отказа.

#### Независимая проверка (Codex)

- **`ffb4988`:** прошли 21 SRS-тест. На OpenWrt 25.12.5 x86_64 при лимите процесса 256 МиБ прежние глубокие SRS-примеры отклоняются контролируемой ошибкой декодера, без аварийного завершения.
- Рабочая служба VM, её PID и контрольные суммы конфигурации сохранены.
- **Не проверялись в этом цикле:** ARM, legacy-профиль, длительный RSS-прогон, полный CI.
- **Граница результата:** лимиты SRS не гарантируют отсутствия OOM на устройствах с малым объёмом памяти.

### CN-02 / MEM-01 — XHTTP packet-up не завершает сессию после закрытия клиентом

- **Приоритет:** P0 (в сводке аудита — №11): режим `auto` в Forkop X всегда даёт packet-up; по аудиту fd 114 → 908 и RSS 37 → 229 МБ за 6 минут.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммиты:** [`9af27fd0f702c8fbc851ce1285c163f9d31224f5`](https://github.com/Screamshow/xrust/commit/9af27fd0f702c8fbc851ce1285c163f9d31224f5), исправление замечания — [`22162e7822f9a03c174cfe57fd929c3224216e7e`](https://github.com/Screamshow/xrust/commit/22162e7822f9a03c174cfe57fd929c3224216e7e).
- **Файлы:** `crates/core-runtime/src/outbound/transport/xhttp.rs`, `crates/core-runtime/src/inbound/transport.rs`, новый `crates/core-runtime/tests/xhttp_packet_up_sessions.rs`.

#### Причина

- **Клиент** (`xhttp.rs`, `poll_shutdown` для `Up::Packets`): закрывается только upload. В packet-up нет сигнала об окончании upload, сервер не передаёт FIN апстриму, апстрим, ждущий EOF, не отвечает и не закрывается. Relay ждёт обе стороны, поэтому соединение не освобождается, `Drop` не срабатывает: download-GET, локальный сокет (CLOSE_WAIT), апстрим и серверная сессия живут бесконечно.
- **Сервер** (`inbound/transport.rs`): отмену GET клиентом (закрытое H1-соединение, RST_STREAM в H2) сессия считала обычным half-close. Апстрим, не закрывающийся по EOF, держал relay, сокет и запись в таблице сессий.

#### Исправление

- **Клиент — лимит тишины после half-close, только packet-up.** `poll_shutdown` ничего не прерывает и только запускает таймер; каждый фрагмент download перезапускает его. Если 10 с после half-close нет download-трафика, сессия завершается: download-запрос отменяется (H1 — закрытие соединения, H2 — сброс потока), upload и подтверждения останавливаются, чтение возвращает EOF. Значение — константа `HALF_CLOSE_IDLE` в `xhttp.rs`, переопределяется переменной `TACHYON_XHTTP_HALF_CLOSE_IDLE_MS`. До half-close лимита нет; stream-up и stream-one не менялись.
- **Как выполнено требование half-close:** EOF отправки не считается концом приёма, безусловного прерывания download в `poll_shutdown` нет. Ответ, который идёт после half-close без пауз дольше лимита, дочитывается до конца, даже если в сумме дольше 10 с.
- **Сервер — отмена download — это отмена, а не half-close.** При закрытии GET клиентом или ошибке записи сессия помечается отменённой: чтение протокола получает `ConnectionAborted`, запись — ошибку, relay останавливается, апстрим и запись в таблице освобождаются. Нормальное завершение download работает как раньше. Формат на проводе не менялся.
- **Сервер — сопутствующее исправление (за пределами аудита, но без него проверка повторных соединений через H1 невозможна).** Каждый следующий запрос на переиспользованном POST-соединении шёл в первую сессию этого соединения, а клиент через пул xmux переиспользует POST-соединения между сессиями. На старом коде 27 из 40 последовательных H1-сессий и 14 из 20 в режиме `auto` не получали ответа. Теперь запрос направляется в сессию, указанную в нём; если её GET ещё не зарегистрирован, сервер ждёт до 1 с, затем отвечает 404.

#### Воспроизведение до исправления

Те же тесты на копии `HEAD`; измеряются открытые fd процесса (`/proc/self/fd`) и живые соединения тестового апстрима, не RSS.

| Сценарий | До | После |
|---|---|---|
| packet-up H2, 40 закрытых сессий | fd 26 → 150 и не возвращаются; 41 соединение апстрима открыто | fd 35 → 126 (пик) → 39; апстрим 0 |
| packet-up H1, 40 сессий | 27 из 40 без ответа; fd 24 → 61 и не возвращаются | все с ответом; fd 47 → 197 (пик) → 47 |
| `auto` H1, 20 сессий | 14 из 20 без ответа; fd 48 → 62 и не возвращаются | все с ответом; fd возвращаются к исходным |
| H2, 30 сбросов к молчащему апстриму | после окна освобождения осталось +66 fd | +32: 30 соединений тестовый апстрим держит намеренно, плюс 2 |

#### Проверки разработки

- **Новые тесты:** 5 модульных в `xhttp.rs`, 3 в `inbound/transport.rs`, 10 интеграционных в `xhttp_packet_up_sessions.rs` (клиент и сервер xrust в одном процессе, H1, H2 и `auto`).
- **Падают на старом коде (8):** `packet_up_half_close_with_a_silent_download_ends_the_session`, `h2_packet_up_half_close_with_a_silent_download_resets_the_get`, `a_cancelled_xhttp_download_fails_the_protocol_and_frees_the_session`, `a_reused_upload_connection_feeds_the_session_each_request_names`, `closed_packet_up_sessions_leave_no_fds_or_upstreams_h1` / `_h2`, `closed_auto_sessions_leave_no_fds_or_upstreams`, `client_reset_frees_the_session_on_both_sides_h2`.
- **Охраняют требования и проходят до и после:** ответ после half-close, идущий дольше лимита (`packet_up_half_close_still_reads_the_whole_response`, `half_closed_packet_up_client_still_gets_the_whole_response_h1` / `_h2`); отсутствие лимита без half-close; закрытие download при drop; нормальное завершение download — не отмена; сброс клиентом через H1; ошибки сервера (500 на POST, оборванный download, 404 на сессию).

| Команда (оба профиля: `--features legacy-protocols` и `--no-default-features --features rust-x`) | Результат |
|---|---|
| `cargo fmt --all -- --check` | чисто |
| `cargo clippy --locked -p core-runtime --all-targets --features legacy-protocols -- -D warnings` | чисто |
| `--test xhttp_packet_up_sessions` | 10/10 в обоих профилях |
| `--lib -- xhttp inbound::transport` | 44/44 в обоих профилях |
| `--test hot_reload` / `--test transports_interop` / `--test connection_recovery` | 9 / 1 / 6 passed в обоих профилях |
| `cargo test -p core-config --test xhttp_compat` | 1/1 |

- Полный `--lib` (по отчёту исполнителя): legacy 839 passed, 9 ignored; rust-x 673 passed, 1 failed — `chain_golden_lx_loads_in_router`, падает так же на `HEAD`. `--test server_inbounds` в rust-x: 18 тестов trojan, vmess и shadowsocks падают так же на `HEAD`.

#### Ограничения

- В `main` не слито, не выпущено.
- OpenWrt, musl-сборка, реальные серверы Xray и sing-box, REALITY и TLS-отпечатки не проверялись: только сервер xrust и тестовые H1/H2-пиры на loopback. Полный CI не запускался.
- **Компромисс лимита:** half-closed клиент, который ждёт ответа дольше 10 с полной тишины download, теперь получает EOF. Значение выбрано как удвоенный `downlinkOnly` Xray (5 с по аудиту CN-06; по исходникам Xray не сверялось); меняется константой или переменной окружения.
- **Не исправлено (вне задачи):** сервер xrust не передаёт half-close для stream-up (H1 и H2 upload-задачи не вызывают `close_up` по окончании тела POST) — закрытые stream-up-сессии со своим сервером по-прежнему висят; у packet-up-сессии, получившей только POST без GET, нет очистки на сервере; общий таймер half-close в relay (CN-06) не добавлялся.

#### Замечание независимой проверки `9af27fd` и исправление

- **Замечание (Codex):** `xhttp.rs:1689-1690` — если чтение уже вернуло `Pending`, а `shutdown` вызывает другая задача, созданный таймер не будит задачу чтения; при молчащем download таймер никто не опрашивает, и сессия не завершается. Воспроизведение: `packet_up_over_fake_h1`, запрос с flush, `tokio::io::split`, ожидающее чтение, затем `shutdown` из writer — EOF не приходит за несколько `TEST_IDLE`.
- **Исправление:** [`22162e7822f9a03c174cfe57fd929c3224216e7e`](https://github.com/Screamshow/xrust/commit/22162e7822f9a03c174cfe57fd929c3224216e7e). Пока лимит не запущен, `poll_read` запоминает waker стороны чтения; запуск лимита в `poll_shutdown` будит его, и чтение начинает опрашивать таймер. Получение ответа после half-close не изменилось.
- **Тесты:** `split_half_close_with_a_pending_read_ends_a_silent_session` (сценарий из замечания; на `9af27fd` падает: чтение не просыпается за `5 × TEST_IDLE`) и `split_half_close_with_a_pending_read_still_gets_the_response` (ответ после half-close при разделённом соединении дочитывается). Модульные XHTTP — 46/46, `xhttp_packet_up_sessions` — 10/10, `hot_reload` 9, `transports_interop` 1, `connection_recovery` 6 — в обоих профилях; fmt и clippy чистые.
- **Пройдено при независимой проверке `9af27fd` (Codex):** 36 модульных XHTTP-тестов, musl release-сборка, все 10 новых интеграционных тестов на OpenWrt 25.12.5 x86_64. Два H2-теста падают в WSL, но проходят на VM; отдельной регрессией не объявлено. ARM и полный CI не проверялись.

#### Независимая проверка (Codex)

- **`22162e7`:** прошли 38 модульных XHTTP-тестов, включая оба сценария с ожидающим чтением и half-close из другой задачи.
- На OpenWrt 25.12.5 x86_64 с новой musl release-сборкой прошли все 10 интеграционных XHTTP-тестов: ответ после half-close дочитывается, завершённые сессии освобождаются.
- Рабочая служба VM, её PID и контрольные суммы конфигурации сохранены.
- **Не проверялись в этом цикле:** ARM, legacy-профиль, внешние серверы Xray и sing-box, длительный RSS-прогон, полный CI.
- **Сохраняющееся поведение:** таймер завершает download после 10 секунд тишины после half-close.

### SEC-01 / SEC-02 — REALITY без аутентификации и pins при `insecure`

- **Приоритет:** P0 (обе).
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`434217b2319498a7cbc9e4c9b85dcc30443f5da4`](https://github.com/Screamshow/xrust/commit/434217b2319498a7cbc9e4c9b85dcc30443f5da4).
- **Файлы:** `crates/core-tls/src/verify.rs`, `crates/core-runtime/src/tls_client.rs`, новый `crates/core-runtime/tests/reality_auth.rs`. Отпечатки, TLS-зависимости и другие TLS-находки не менялись.

#### Эталонное поведение

- **Xray v26.10.21** (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`):
  - `transport/internet/reality/reality.go:101-140` — `Verified` только при совпадении HMAC ключа Ed25519 leaf; `:148-150` — `insecure` и pins под REALITY не используются; `:207`, `:298` — непроверенный сервер: «spider» и ошибка `REALITY: processed invalid connection`, соединение вызывающему не отдаётся.
  - `transport/internet/tls/config.go:284-353`, `:401-404` — при заданных pins включается `InsecureSkipVerify`, совпавший pin принимается без цепочки и имени («pin вместо CA»); `infra/conf/transport_security.go:362-363` — `allowInsecure` удалён.
- **sing-box** (`824dbcfb4dd0a95921840b1737b950cde590241e`): `common/tls/reality_client.go:136-142`, `:238-240` — непроверенный сервер даёт `reality verification failed`; `std_client.go:133-145`, `utls_client.go:205-219` — pin заменяет CA.
- **Контракт проекта:** без `insecure` pin сужает доверие, цепочка по-прежнему проверяется; при обоих списках pins должны совпасть оба (строже sing-box, сохранено).

#### Причина

- **SEC-01:** `RealityVerifier::verify_chain` (`verify.rs:384-407`) при любом провале передавал решение fallback-проверке (при `insecure` — `AcceptsAnything`), `CertificateVerify` (`:411-422`) — тоже; итог аутентификации (`tls_client.rs:741-748`) только писался в debug-лог. Дополнительно найдено: на путях rustls (TCP и QUIC) `reality` молча игнорировался и шёл обычный TLS.
- **SEC-02:** ветка `insecure` проверялась раньше pins (`tls_client.rs:510-514` rustls TCP, `:571-575` QUIC, `:667-668` собственный стек); `PinVerifier` (`verify.rs:812-820`) всегда требовал валидную цепочку.

#### Новое поведение

| REALITY | `insecure` | pin | Результат |
|---|---|---|---|
| вкл. | любое | любой | обязательны HMAC REALITY и `CertificateVerify`; иначе отказ до отправки любых данных приложения. `insecure` и pins игнорируются с предупреждением |
| выкл. | false | нет | цепочка CA, имя, подпись (без изменений) |
| выкл. | false | задан | цепочка, имя, pins (оба списка), подпись (без изменений) |
| выкл. | true | задан | **pins и подпись `CertificateVerify`; цепочка, имя и срок не проверяются** («pin вместо CA», как в Xray). Раньше принималось всё |
| выкл. | true | нет | принимается любой сертификат (без изменений) |

#### Изменения, заметные пользователю

- REALITY-узлы, которые «работали» только через fallback (неверный `public_key`/`short_id`, расхождение часов, перенаправление на `dest`, MITM), теперь не подключаются: `REALITY <sni>: authentication failed (<verdict>); connection refused, check public_key, short_id and the clock`.
- REALITY с `insecure` и/или pins подключается как раньше; при загрузке конфигурации — предупреждение, что настройка игнорируется.
- `insecure` с неверным pin теперь отказ (`server certificate does not match tls.certificate_sha256`); с верным pin, но без закрытого ключа у сервера — тоже отказ. `insecure` с pin пишет в лог, что pin заменяет проверку CA и имени.
- REALITY на путях rustls и QUIC теперь ошибка вместо обычного TLS.
- **Forkop X:** `allowInsecure=1` у REALITY-ссылок больше не ослабляет защиту; `runtime_supports_certificate_pins` теперь соответствует действительности. Несовместимость сохраняется: в Xray v26 и sing-box pin без `insecure` заменяет CA, а в xrust pin без `insecure` по-прежнему требует валидную цепочку, поэтому самоподписанный узел с `pcs` без `allowInsecure` не подключается. Требует отдельного решения.

#### Воспроизведение до исправления

- Тесты `reality_auth.rs` на копии `HEAD` (разработка, rust-x): `an_ordinary_tls_server_with_a_valid_certificate_gets_no_user_data` — соединение с обычным TLS-сервером принято (`the connection must be refused`); `an_ed25519_certificate_under_another_auth_key_is_refused` и `the_rustls_paths_refuse_reality` тоже падают.
- По данным исполнителя на старом коде: обычный TLS-сервер с CA-валидным сертификатом при `insecure` false и true — соединение установлено, клиент отправил записи `[22,20,23,23]`, сервер расшифровал `\0 1111…5555 GET /secret-path HTTP/1.1` (заголовок с UUID и запрос). После исправления во всех случаях — `REALITY authentication failed: …`, клиент отправил только ClientHello (`[22]`), сервер не получил данных.

#### Проверки разработки

- **Новые и обновлённые тесты:** 5 тестов в `reality_auth.rs` (принимается сервер REALITY, знающий клиента, в том числе с `insecure` и с ложным pin; неверный ключ или `short_id`; обычный TLS-сервер и чужой Ed25519 leaf при `insecure` false и true — без пользовательских данных у сервера; отказ путей rustls); таблица `ordinary_tls_requires_matching_pins_in_addition_to_the_ca` — 26 строк на собственном стеке и rustls, строка аудита `insecure=true` с неверным pin теперь ожидает отказ; `quic_requires_matching_certificate_and_public_key_pins` дополнен строками `insecure`; 3 модульных теста в `verify.rs`.
- **Падают на старом коде:** `ordinary_tls_requires_matching_pins_in_addition_to_the_ca`, `quic_requires_matching_certificate_and_public_key_pins` (по данным исполнителя), `an_ordinary_tls_server_with_a_valid_certificate_gets_no_user_data`, `an_ed25519_certificate_under_another_auth_key_is_refused`, `the_rustls_paths_refuse_reality`. Проходят и на старом коде, как и ожидалось: `a_reality_server_that_recognises_us_is_accepted`, `a_wrong_reality_key_or_short_id_is_refused` (наш сервер сам отвергает чужих клиентов).

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | чисто |
| `cargo clippy --locked -p core-tls --all-targets -- -D warnings` | чисто |
| `cargo clippy --locked -p core-runtime --all-targets --features legacy-protocols -- -D warnings` | чисто |
| `cargo test --locked -p core-tls` | 0 failed |
| `--lib tls_client` (legacy / rust-x) | 10 / 9 passed |
| `--test reality_auth`, `tls_interop`, `tls_own_stack`, `imported_pins`, `fetch_tls`, `urltest_tls`, `hy2_tuic_interop`, `dns_quic_h3`, `transports_interop` (оба профиля) | 5, 4, 4, 1, 3, 1, 2, 2, 1 passed |

- Полный `core-runtime` по отчёту исполнителя: legacy 1118 passed, 0 failed; rust-x — 27 падений, тот же набор на `HEAD` (тесты legacy-протоколов, `socks_*`, `selector_*`, `chain_golden_lx_loads_in_router` и др.).

#### Ограничения

- В `main` не слито, не выпущено.
- OpenWrt, release-бинарник, реальные серверы Xray и sing-box REALITY не проверялись: успешное подключение проверено только против REALITY-сервера core-tls. Полный CI не запускался.
- «Spider» Xray не реализован: при провале проверки соединение обрывается посреди handshake, а не завершается обходом сайта; активный зонд может различить это поведение (тема отпечатков, вне задачи).
- Сравнение HMAC не в постоянное время, как и раньше.
- `RealityVerifier::new(_)` сохранил параметр для совместимости вызовов, но игнорирует его; `docs/reference/common/tls-client.md` (описание `insecure`) не обновлён.

#### Независимая проверка (Codex)

- Локально прошёл 141 тест (общий для SEC-01/SEC-02 и CQ-06): core-tls, TLS и pins, REALITY, UDP и соседние сценарии.
- На OpenWrt 25.12.5 x86_64 прошли 5 проверок REALITY.
- Отказ REALITY происходит без передачи пользовательских данных; pins при `insecure: true` проверяются.
- **Не проверялись:** ARM, внешние серверы Xray и sing-box, полный маршрут через nft и LAN, нагрузка 20 пользователей, полный CI.
- **Политика без изменений:** pin без `insecure` по-прежнему требует доверенную цепочку.

### CQ-06 — UDP: лавина задач, пока поток открывается

- **Приоритет:** P1 (влияние на Forkop X прямое: tproxy UDP).
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`b0bc97be3a552e98cf2b128d67ab167ca92b3481`](https://github.com/Screamshow/xrust/commit/b0bc97be3a552e98cf2b128d67ab167ca92b3481).
- **Файлы:** `crates/core-runtime/src/inbound/{udp,direct,tproxy,tun}.rs`, новый `crates/core-runtime/tests/udp_open_burst.rs`.

#### Причина

- `direct.rs:233-247`, `tproxy.rs:180-221` (и цикл ответного сокета `:239-251`), `tun.rs:976-990` и `:1114-1127`: каждый датаграм, не попавший в открытый поток, порождал задачу с копией данных; в tun копировался каждый датаграм.
- `udp.rs`, `handle_routed` (`:465-536`): шлюз на ключ только сериализовал открытия; после неудачного открытия каждая ожидающая задача открывала поток заново.

#### Исправление

- `UdpHub::offer` синхронен: отправляет в открытый поток, ставит в очередь за открывающимся или возвращает единственный `FlowOpener` для ключа, который приёмный цикл запускает отдельной задачей. Запись о ключе создаётся под одной блокировкой, поэтому открывающий на ключ всегда один.
- **Очередь:** за первым датаграмом — до 16 (`MAX_OPENING_DATAGRAMS`); сохраняются первые, остальные отбрасываются. После открытия очередь отправляется в порядке поступления, затем запись освобождается под той же блокировкой; пока запись есть, новые датаграмы потока встают в очередь, а не обгоняют её. Худший случай — 17 × 64 КиБ ≈ 1,06 МиБ на открывающийся поток (≈25 КиБ при MTU 1500). 16 ≥ `MAX_SNIFF_DATAGRAMS` (8), так что сниффинг многодатаграммного ClientHello сохраняется.
- **Ошибка и повтор:** при ошибке или уничтожении открывающего запись и очередь освобождаются; повторного дозвона нет. Следующий датаграм потока начинает одну новую попытку; кэша неудач и задержек нет.
- **Другие потоки не блокируются:** у каждого ключа своя задача, `offer` не ждёт. Шлюз на ключ сохранён для таймера сниффинга и прочих вызовов `handle()`.
- **DNS hijack:** каждый запрос по-прежнему обрабатывается отдельной задачей.
- Глобальные лимиты UDP, новые таймауты, вытеснение, ограничение скорости и изменения буферов (MEM-02/CQ-07) не вводились.

#### Изменения поведения

- Датаграмы сверх 16, пришедшие во время открытия потока, отбрасываются; раньше каждый в итоге отправлялся или сам пытался открыть поток.
- После неудачного открытия очередь отбрасывается вместо повторных попыток каждого датаграма.
- Порядок датаграмов из очереди относительно последующих теперь сохраняется.

#### Воспроизведение до исправления

| Сценарий (поток с удерживаемым открытием, 500 датаграмов, всего 4 потока) | До | После |
|---|---|---|
| Живые задачи рантайма | 3 → 510 | 3 → 11 |
| Открытия во время ожидания | 4 | 4 |
| Открытия после отказа (все открытия отвергаются 1 с) | 164, задачи 504 → 340 и продолжают рассасываться | 1, задачи 3 → 3 |
| 100 датаграмов во время одного открытия | доставлены все 100 | доставлены первые 17, по порядку |

- Проверено разработкой: оба теста `udp_open_burst.rs` на копии `HEAD` падают (`sent 100 during the open, delivered 100`; лишние задачи).

#### Проверки разработки

- **Новые тесты:** `udp_open_burst.rs` — 2 теста через реальный direct inbound (500 датаграмов одного потока и ещё 3 потока → 4 открытия и меньше 50 лишних задач; отказ → задачи возвращаются к исходным, следующий датаграм — одна новая попытка и доставка; очередь отправляется первой и ограничена, затем прямой путь, без оставшихся задач). 4 модульных теста в `udp.rs`: очередь за единственным открывающим, медленный поток не задерживает другой, ошибка отбрасывает очередь и следующий датаграм повторяет попытку, уничтоженный открывающий освобождает поток.
- Проверено на копии `HEAD` + файлы CQ-06 с отдельным каталогом сборки:

| Команда (оба профиля) | Результат |
|---|---|
| `cargo fmt --all -- --check` | чисто |
| `cargo clippy --locked -p core-runtime --all-targets --features legacy-protocols -- -D warnings` | чисто |
| `--lib inbound::` | legacy 75 passed, 3 ignored; rust-x 58 passed |
| `--test udp_open_burst` / `udp_sniff` / `udp_quic_sniff` / `udp_dns_sniff` / `inbounds` | 2 / 8 / 3 / 3 / 12 passed |
| `--test loopback` / `routing` | 4 / 13 passed |

- По отчёту исполнителя: в rust-x падают `chain_golden_lx_loads_in_router` и `socks_inbound_takes_socks4_and_5_refuses_http` — так же на `HEAD`; clippy rust-x с `-D warnings` — те же 14 предупреждений `dead_code`, что и на `HEAD`.

#### Ограничения

- В `main` не слито, не выпущено.
- tproxy и tun end-to-end не запускались (нужны CAP_NET_ADMIN или TUN-устройство); они используют тот же путь `offer`/`run`, покрытый тестами hub. OpenWrt, реальный QUIC-клиент, заблокированный DPI-сервер и замеры RSS не проверялись. Полный CI не запускался.
- Число одновременно открывающихся потоков не ограничено (глобальных лимитов по условию нет); память ограничена только на поток.
- Остальные вызовы `UdpHub::handle()` вне этих файлов не переведены на новый путь: `mixed.rs:474` (цикл relay ждёт `handle`, медленное открытие задерживает другие потоки той же ассоциации), `mux.rs`, `fptn.rs`, `proxy.rs`, shadowsocks, hysteria2, tuic.

#### Независимая проверка (Codex)

- Локально прошёл 141 тест (общий для SEC-01/SEC-02 и CQ-06): core-tls, TLS и pins, REALITY, UDP и соседние сценарии.
- На OpenWrt 25.12.5 x86_64 прошли 4 проверки: 2 теста UDP burst и 2 дополнительных через настоящий TProxy-listener.
- UDP-поток открывается один раз; ошибка очищает очередь; соседние потоки не блокируются.
- **Уточнение:** очередь хранит 16 дополнительных датаграмов плюс первый. В TProxy пакеты могут ещё ждать в буфере ядра, поэтому 17 — не универсальный предел сохраняемых пакетов.
- **Не проверялись:** ARM, полный маршрут через nft и LAN, нагрузка 20 пользователей, полный CI.

### CN-01 — XHTTP: мёртвое HTTP/2-соединение навсегда остаётся в пуле

- **Приоритет:** P0: после NAT-таймаута, смены WAN или перезагрузки сервера без RST узел XHTTP становится недоступен на минуты.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`fd03c0aabd38a2b954dbd7e5695667326d7613c5`](https://github.com/Screamshow/xrust/commit/fd03c0aabd38a2b954dbd7e5695667326d7613c5).
- **Файлы:** `crates/core-runtime/src/outbound/transport/xhttp.rs`, `crates/core-runtime/src/outbound/transport/xmux.rs`, новый `crates/core-runtime/tests/xhttp_h2_keepalive.rs`.

#### Эталон (Xray v26.10.21, `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`)

- `transport/internet/splithttp/dialer.go:148-151` — `keepAlivePeriod = Xmux.HKeepAlivePeriod`; `:247-260` (h2) — 0 означает `net.ChromeH2KeepAlivePeriod`, отрицательное значение отключает PING; `http2.Transport{IdleConnTimeout: net.ConnIdleTimeout, ReadIdleTimeout: keepAlivePeriod}`, `PingTimeout` не задан (в Go по умолчанию 15 с).
- `common/net/net.go:14` — `ConnIdleTimeout` 300 с; `:20` — `ChromeH2KeepAlivePeriod` 45 с.
- Семантика Go: если `ReadIdleTimeout` ничего не прочитано — PING; нет ответа за `PingTimeout` — соединение закрывается, его потоки завершаются ошибкой.

#### Причина

- `H2Pool::acquire` (`xhttp.rs`) вытеснял соединение только при ошибке `ready()`; тихо умершее соединение ошибки не даёт, и пул выбирал его как наименее загруженное.
- Задачи-драйверы соединения в обоих местах установления только ждали `Connection`; `ping_pong()` не использовался. `xmux.rs` разбирал `h_keep_alive_period` и предупреждал, что он игнорируется.

#### Исправление

- Чтение из сокета отмечается временем последнего полученного байта. Для каждого HTTP/2-соединения задача keep-alive: если `h_keep_alive_period` ничего не прочитано — PING и ожидание 15 с (`H2_PING_TIMEOUT`). Ответ на PING сбрасывает цикл; ошибка PING или 15 с полной тишины — соединение мёртвое. Если во время ожидания пришли любые данные, ожидание продлевается (чуть мягче Go).
- Значения как в Xray: `h_keep_alive_period` 0 или не задан — 45 с; больше 0 — N с; меньше 0 — PING отключён. Обнаружение по умолчанию — 45 + 15 = 60 с.
- Соединение, завершившееся по любой причине (провал PING, закрытие, RST), сразу удаляется из пула; его потоки получают ошибку. Задача держит пул через `Weak`.
- Как различаются случаи: тихо умершее — ничего не прочитано за период и 15 с, вытесняется; простаивающее исправное — отвечает на PING, остаётся и переиспользуется; занятое или медленное — кадры продолжают приходить, PING не отправляется.
- Исправления CN-02 (освобождение сессий, ответ после half-close) сохранены; их тесты проходят.

#### Изменения поведения

- Простаивающие HTTP/2-соединения XHTTP раз в 45 с отправляют PING.
- Мёртвое соединение вытесняется примерно через 60 с; сессии, ещё оставшиеся на нём, получают ошибку.
- Закрытое или сброшенное соединение покидает пул сразу, а не при следующем `ready()`.
- Предупреждение «h_keep_alive_period ignored» удалено.

#### Воспроизведение до исправления

- Стенд: клиент → TCP-relay, который можно «заморозить» или сбросить → сервер xrust, TLS+h2, `xmux {max_connections: 1, h_keep_alive_period: 1}`; таймаут PING — настоящие 15 с.
- На старом коде (по отчёту исполнителя): после «заморозки» relay каждая новая сессия (t = 5, 10, …, 30 с) зависает, соединение одно, повторного дозвона нет; с xmux по умолчанию — отказ и через 63 с (аудит: более 330 с на loopback). После исправления: сессии до ≈16 с зависают на мёртвом соединении, в t = 17,1–17,2 с — успех на втором соединении; с xmux по умолчанию — восстановление за 45 + 15 с.
- Проверено разработкой на копии `HEAD` (отдельный каталог сборки, rust-x): `xhttp_h2_keepalive` — 2 passed, 4 failed. Падают `silent_pooled_connection_is_evicted_packet_up`, `_stream_one`, `_with_default_xmux` и `healthy_idle_connection_is_pinged_and_reused`; проходят `reset_pooled_connection_is_replaced` (сброс и раньше давал ошибку `ready()`) и `slow_transfer_outlives_the_ping_timeout`.

#### Проверки разработки

- Новые тесты: 6 интеграционных в `xhttp_h2_keepalive.rs` (тихая потеря с packet-up, stream-one и xmux по умолчанию; сброс; исправное простаивающее соединение получает PING и переиспользуется; медленная передача — 1 байт раз в 2,5 с в течение 20 с — переживает таймаут PING), 3 модульных в `xhttp.rs`, 1 в `xmux.rs`.
- Проверено на копии `HEAD` + файлы CN-01 с отдельным каталогом сборки:

| Команда (оба профиля) | Результат |
|---|---|
| `cargo fmt --all -- --check` | чисто |
| `cargo clippy --locked -p core-runtime --all-targets --features legacy-protocols -- -D warnings` | чисто |
| `--lib -- xhttp xmux inbound::transport` | 57 passed |
| `--test xhttp_h2_keepalive` | 6 passed (≈63 с) |
| `--test xhttp_packet_up_sessions` (CN-02) | 10 passed |
| `--test transports_interop` / `hot_reload` / `connection_recovery` | 1 / 9 / 6 passed |
| `cargo test -p core-config --test xhttp_compat` | 1 passed |

#### Ограничения

- В `main` не слито, не выпущено.
- OpenWrt, реальный сервер Xray, реальная потеря пакетов (только «заморозка» relay на loopback), H3/QUIC и H1 (PING в H1 нет) не проверялись. Полный CI не запускался.
- Не сделано (требует решения): закрытие соединений, простаивающих без потоков 300 с (`IdleConnTimeout` Xray), таймаут ожидания заголовков ответа при открытии сессии и `TCP_USER_TIMEOUT` из рекомендаций аудита.
- Сессии, начатые в окне обнаружения (до ≈60 с), попадают на мёртвое соединение и завершаются ошибкой — как в Xray/Go.
- Загрузка, во время которой сервер 60 с не присылает ни одного кадра, будет оборвана, как в Go; на практике WINDOW_UPDATE поддерживает соединение.

#### Независимая проверка (Codex)

- На OpenWrt 25.12.5 x86_64 с новыми musl-сборками: `xhttp_h2_keepalive` — 6/6 (восстановление после потери, PING и переиспользование, медленная передача); повторная проверка CN-02 `xhttp_packet_up_sessions` — 10/10.
- Локальные модульные проверки и проверки конфигурации прошли. Весь локальный набор успешным не засчитан: в WSL остаются падения по fd в двух тестах Hysteria2 и двух H2-тестах; на VM они не повторились.
- **Не проверялись:** ARM, внешние серверы Xray, Hysteria и sing-box, настоящий WAN и DNAT, пакетное обновление, полный CI.
- Дополнительные таймауты не добавлялись.

### CN-03 — Hysteria2: `server_ports` без `server_port`; port hopping течёт и рвёт соединения

- **Приоритет:** P0: одна ссылка с диапазоном портов кладёт весь сервис; затронуты все узлы HY2 с hopping в Forkop X.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`c90ab92c9415072ebfe6fba27a9f875f0b0204bd`](https://github.com/Screamshow/xrust/commit/c90ab92c9415072ebfe6fba27a9f875f0b0204bd).
- **Файлы:** `crates/core-runtime/src/outbound/hysteria2.rs`, `crates/core-runtime/src/outbound/proxy.rs`, `crates/core-config/src/validate.rs` (путь `check`), новый `crates/core-runtime/tests/hy2_port_hopping.rs`. `quic.rs` не менялся.

#### Эталон

- **sing-box** (`824dbcfb4dd0a95921840b1737b950cde590241e`): `docs/configuration/outbound/hysteria2.md:89` — `server_port` игнорируется, если задан `server_ports`; формат `"2080:3000"` (`:23-25`). Исходников sing-quic на диске нет; поведение проверено на бинарнике sing-box 1.14.3: `server_ports` без `server_port` принимают и `check`, и `run`; начальный порт случайный в диапазоне.
- **Hysteria app/v2.13.0** (`extras/transport/udphop/conn.go`): начальный порт случайный (`:89`); hop происходит внутри того же соединения (`:172-224`); неудачный hop просто пропускается, потери восстанавливает QUIC (`:178-185`).

#### Причина

- `hysteria2.rs` вызывал `server_endpoint` (`proxy.rs`), требующий `server_port`, до разбора `server_ports`; `check` порт не требовал.
- Hopping уже реализован внутри соединения (`spawn_hop_relay`, `quic.rs`), но пул ещё и «старил» соединение по `hop_deadline` и открывал новое. С UDP демультиплексор и задачи UDP-сессий держали `Arc<Hy2Shared>`, поэтому `Drop` не срабатывал: сокет, 2 сокета relay, задачи и keepalive каждого «состаренного» соединения оставались. С `network: tcp` демультиплексора нет, соединение закрывалось, и живые потоки обрывались (`LocallyClosed`). Тот же цикл держал и соединение с одним портом после удаления outbound (например, при перезагрузке конфигурации).

#### Исправление

- Один разборщик `core_config::validate::hysteria2_server_ports()` для `check` и запуска: диапазоны `a:b` (пустое начало — 1, пустой конец — 65535), сохранены прежние формы `a-b` и одиночный порт; перевёрнутые и некорректные записи пропускаются. При наличии пригодного диапазона `server_port` игнорируется. Начальный порт — случайный в диапазонах, как в эталоне.
- `check` теперь отвергает то, что отверг бы запуск: без realm, без `server_port` и без пригодного `server_ports` — `{at}: missing server_port` (sing-box такие конфигурации принимает — сознательное отличие).
- Пул удаляет только закрытые соединения; `hop_deadline` убран, hopping остаётся внутри соединения.
- Демультиплексор и задачи UDP-сессий держат `Weak<Hy2Shared>`; `Drop` прерывает их и закрывает соединение.
- Режим с одним портом: путь данных не изменился; ресурсы теперь освобождаются при удалении outbound.

#### Воспроизведение до исправления

- **Запуск:** старый бинарник — `check` rc=0, `run` — `outbounds[0]: missing server_port` rc=1 для `"20000:30000"`, списка и двух диапазонов (по отчёту исполнителя). Новый тест `check_agrees_with_start` — 8 случаев, `check` и запуск согласованы.

| Сценарий (`hop_interval` 300 мс, запросы каждые 150 мс в течение 4 с) | До | После |
|---|---|---|
| QUIC-соединения клиента | 11 на 21 запрос | 1 на 26 запросов |
| fd во время запросов | 35 → 75 | +1 |
| fd после удаления outbound | остаются 75 | исходные + 1 (сокет апстрима стенда) |
| Один порт, fd после удаления | +2 | 0 |
| TCP-поток через hop (`network: tcp`) | обрыв `ConnectionLost(LocallyClosed)` после 7 соединений | ≈4,1 МБ без потерь, 1 соединение, использованы все 3 порта |
| Используемый порт закрыт посреди передачи | — | ≈5 МБ без потерь, 1 соединение; самая длинная пауза 0,31–1,27 с (до следующего hop и восстановления потерь QUIC) |

- Проверено разработкой на копии `HEAD` (отдельный каталог сборки, rust-x): все 6 тестов `hy2_port_hopping.rs` падают.

#### Проверки разработки

- Новые тесты: 6 интеграционных в `hy2_port_hopping.rs` (стенд из 3 UDP-портов, эмулирующих DNAT на один inbound HY2: передача только с `server_ports`, TCP-поток через несколько hop, hop на закрытый порт и восстановление, освобождение ресурсов после hop и после удаления, согласованность `check` и запуска, режим с одним портом), модульные `server_ports_without_server_port`, `hy2_out_needs_a_port`, `hy2_server_ports_ranges`.
- Проверено на копии `HEAD` + файлы CN-03 с отдельным каталогом сборки:

| Команда | Результат |
|---|---|
| `cargo fmt --all -- --check` | чисто |
| `cargo clippy --locked -p core-runtime -p core-config --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто |
| `--lib hysteria2` (legacy / rust-x) | 7 / 7 passed |
| `--lib quic` (legacy / rust-x) | 23 / 22 passed |
| `--test hy2_port_hopping` (оба профиля) | 6 passed |
| `cargo test --locked -p core-config --lib` | 305 passed (из них hy2 — 19) |
| `cargo test --locked -p core-cli --test run_smoke` | 5 passed |

- По отчёту исполнителя: `hy2_tuic_interop` с `SING_BOX_REF` (sing-box 1.14.3) — hy2 проходит; без переменной тест пропускается. Ранее существовавшие падения в rust-x (108 тестов `core-config`, 3 из 4 `core-cli golden`, `interop_tuic`) совпадают со старым кодом.

#### Ограничения

- В `main` не слито, не выпущено.
- Только loopback: OpenWrt, реальный сервер Hysteria, настоящий DNAT через iptables (эмулирован стендом) и замеры RSS не проверялись. Полный CI не запускался.
- При hop меняется только порт назначения; в отличие от hysteria, новый локальный сокет на каждый hop не создаётся (с серверами на DNAT работает; изменение — более широкая переработка).
- Тесты используют интервал hop 300 мс; hysteria требует не меньше 5 с, в xrust минимума нет.
- `check` по-прежнему принимает отсутствующий `server` и конфигурации с realm, которые отвергает запуск; такой же разрыв `check`/запуска для `server_port` есть у других протоколов — вне задачи.

#### Независимая проверка (Codex)

- На OpenWrt 25.12.5 x86_64 с новыми musl-сборками: `hy2_port_hopping` — 6/6 (`server_ports`, сохранение TCP-потока, недоступный порт, освобождение ресурсов). Вместе с CN-01 и CN-02 — 22 теста на VM.
- Локальные модульные проверки и проверки конфигурации прошли. Весь локальный набор успешным не засчитан: в WSL остаются падения по fd в двух тестах Hysteria2 и двух H2-тестах; на VM они не повторились.
- **Не проверялись:** ARM, внешние серверы Xray, Hysteria и sing-box, настоящий WAN и DNAT, пакетное обновление, полный CI.
- Дополнительные таймауты не добавлялись.

### FP-06 / CN-18 — WebSocket early data

- **Приоритет:** P0 для серверов sing-box.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`808bfa4c0fc1b3ceced6d6c386a2d22fa38a2e3b`](https://github.com/Screamshow/xrust/commit/808bfa4c0fc1b3ceced6d6c386a2d22fa38a2e3b).
- **Файлы:** `crates/core-runtime/src/outbound/transport/mod.rs`, `outbound/transport/tests.rs`, WS-часть `crates/core-runtime/src/inbound/transport.rs` (XHTTP не менялся), `docs/reference/common/transports.md`, новые `crates/core-runtime/tests/ws_early_data.rs` и `crates/core-config/tests/ws_early_data_options.rs`. Forkop X не менялся.

#### Эталоны

- **sing-box** (`824dbcfb4dd0a95921840b1737b950cde590241e`), `transport/v2raywebsocket/conn.go`: `:164-169` — первая запись делится по `max_early_data`; `:171` — base64url без паддинга (`RawURLEncoding`); `:172-174` — пустое `early_data_header_name` означает early data в пути URL; `:177-178` — заданное имя — в этом заголовке. `server.go`: `:75-79`, `:86-93` — path-режим с совпадением по префиксу; `:94-102` — заголовок, строгое декодирование; `:104-106` — ошибка декодирования даёт 400.
- **Xray** v26.10.21 (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`): `transport/internet/websocket/dialer.go:143-146` — early data только в `Sec-WebSocket-Protocol`, base64url; `:194-197` — если первая запись больше `ed`, early data не отправляется; `hub.go:47` — точный путь; `:55-58` — нестрогое декодирование `Sec-WebSocket-Protocol`; `infra/conf/transport_method.go:630-637` — `?ed=` убирается из пути. Настройки имени заголовка нет.
- **Forkop X:** `subscription/parser.uc:749-756`, `singbox/generator.uc:1953-1957` превращают `ed=` в `max_early_data` без `early_data_header_name`.

#### Причина

- Клиент (`outbound/transport/mod.rs:493-533`): стандартный base64 с `+/=`, всегда в `Sec-WebSocket-Protocol`; `early_data_header_name` не разбирался. Серверы sing-box отвергали такое соединение.
- Сервер (`inbound/transport.rs:218-248`) early data не читал вовсе: даже xrust ↔ xrust с early data терял эти байты.

#### Исправление (решение владельца проекта)

- **Клиент:** base64url без паддинга; заголовок — `early_data_header_name`, а при пустом или отсутствующем имени — `Sec-WebSocket-Protocol` (как Xray; так работают конфигурации Forkop X из ссылок с `ed=`). Первая запись делится по `max_early_data`, как в sing-box: оба сервера просто ставят декодированные байты перед следующими кадрами без проверки длины. Early data заменяет одноимённый заголовок из конфигурации. Путь не меняется.
- **Сервер:** если задан `max_early_data` или имя заголовка, early data читается из этого заголовка (по умолчанию `Sec-WebSocket-Protocol`), декодируется строго (base64url без паддинга) и ставится перед потоком WS; недекодируемое значение — отказ. Путь сравнивается точно.
- **Проверка типов:** для WS-inbound `max_early_data` (uint32) и `early_data_header_name` (строка) проверяются при запуске.
- **Отличие от sing-box (задокументировано в `docs/reference/common/transports.md` и в коде):** в sing-box пустое имя заголовка означает path-режим, в xrust — `Sec-WebSocket-Protocol`. Path-режим не поддерживается; полной совместимости всех режимов нет. Пользовательское имя заголовка работает только с sing-box и xrust.

#### Поведение по форме конфигурации и серверу

| Конфигурация | Сервер Xray | Сервер sing-box | Сервер xrust |
|---|---|---|---|
| без early data | OK | OK | OK |
| как в Forkop X (`max_early_data` без имени), бюджеты 2048/25/26/27/1 | OK | **отказ**: sing-box трактует такую форму как path-режим | OK |
| явный `Sec-WebSocket-Protocol`, бюджеты 2048/25/26/27 | OK | OK | OK |
| пользовательский заголовок (2048, 1) | неприменимо (настройки нет) | OK | OK |

- Клиент Xray (`?ed=`) → сервер xrust: OK; клиент sing-box с именем заголовка → xrust: OK; клиент sing-box без имени (path-режим) → xrust: отказ, ожидаемо.

#### Воспроизведение до исправления

- Проверено разработкой на копии `HEAD` (legacy, отдельный каталог сборки, sing-box 1.14.3 и Xray 26.10.21): `ws_early_data` — 1 passed, 4 failed. Падают `our_client_against_our_server`, `our_client_against_the_reference_server`, `the_reference_client_against_our_server`, `xray_against_our_server`. Проходит `our_client_against_xray`: нестрогий сервер Xray принимал прежний base64 с паддингом.
- По ручным запускам исполнителя на старом коде: сервер sing-box — `decode early data: illegal base64 data at input byte 14` (заголовок `Sec-WebSocket-Protocol`), `unknown version: 114` (пользовательский заголовок).

#### Проверки разработки

- Тесты: 5 интеграционных в `ws_early_data.rs` (xrust ↔ xrust, xrust → sing-box, sing-box → xrust, xrust → Xray, Xray → xrust; эталонные — при `SING_BOX_REF` / `XRAY_REF`), в каждом — передача 9 Б и 40 КБ со всеми значениями байтов в обе стороны; конфигурация Forkop X (`forkop_ws()`, включая `headers.Host`) — против Xray и xrust; модульные тесты формата, разбиения по `max_early_data`, замены заголовка, отказа сервера и проверки типов; 2 теста `ws_early_data_options`.
- Проверено на копии `HEAD` + файлы FP-06 с отдельным каталогом сборки, `SING_BOX_REF` и `XRAY_REF` заданы:

| Команда | legacy | rust-x |
|---|---|---|
| `cargo fmt --all -- --check` | чисто | — |
| `cargo clippy --locked -p core-runtime --all-targets --features legacy-protocols -- -D warnings` | чисто | — |
| `--lib transport` | 114 passed | 113 passed |
| `--test ws_early_data` | 5 passed | 5 passed |
| `--test xhttp_packet_up_sessions` | 10 passed | 10 passed |
| `--test transports_interop` / `server_inbounds` | 1 / 49 passed | — |
| `cargo test -p core-config --test ws_early_data_options` | 2 passed | — |

- По отчёту исполнителя: в rust-x `transports_interop` 0/1, `server_interop` 3/9, `server_inbounds` 31/49 — те же числа на `HEAD` (vmess, trojan, shadowsocks не реализованы); в legacy `server_interop` 7/9 — 2 случая XHTTP падают и на `HEAD` (в sing-box 1.14.3 нет XHTTP).

#### Ограничения

- В `main` не слито, не выпущено.
- Конфигурация в форме Forkop X не работает с серверами sing-box (они ждут path-режим); для них нужен явный `early_data_header_name`. Path-режим sing-box не поддерживается ни на клиенте, ни на сервере.
- Сервер xrust читает early data, только если в inbound задан `max_early_data` или имя заголовка; без них early data клиента Xray с `?ed=` теряется.
- Декодирование строгое: base64 с паддингом или стандартный алфавит отвергаются (Xray их принимает).
- Заголовок запроса ограничен 8 КиБ, поэтому early data больше ≈6 КиБ отвергается.
- `core-config` по-прежнему не проверяет типы полей транспорта inbound в целом.
- OpenWrt и другие архитектуры не проверялись; полный CI не запускался.

#### Независимая проверка (Codex)

- Прошли 113 транспортных модульных тестов и 2 проверки настроек (`ws_early_data_options`).
- Все 5 тестов `ws_early_data` выполнены с реальными Xray 26.10.21 и sing-box 1.14.3 — локально и на OpenWrt 25.12.5 x86_64; пропусков внешних сценариев нет.
- Поведение пустого имени заголовка для Forkop X и Xray сохранено; отличие от path-режима sing-box остаётся задокументированным.
- Полный CI не запускался.

### BLD-06 / BLD-07 / BLD-08 — размер бинарника

- **Приоритет:** P2.
- **Статус:** BLD-08 — исправлено (только aarch64), проверено в границах, указанных ниже. BLD-06 и BLD-07 — не применены: безопасный выигрыш замерами не подтверждён. В `main` не слито, не выпущено.
- **Коммит:** [`477d0826627f2a8ad6706f8df874ff90550a0064`](https://github.com/Screamshow/xrust/commit/477d0826627f2a8ad6706f8df874ff90550a0064): в `.cargo/config.toml` к rustflags `aarch64-unknown-linux-musl` добавлен `-C force-unwind-tables=no` (существующие записи и комментарии сохранены); в `Cargo.toml` — только комментарий над per-package `opt-level`. Профиль, зависимости, `Cargo.lock`, аллокатор, набор функций и упаковка не менялись.

#### Среда замеров

- rustc 1.99.1, LLVM 23.1.1; Xeon E5-2690 v4 (AES-NI, PCLMUL, AVX2). Сборки `cargo build --locked -p core-cli --no-default-features --features rust-x --release --target …` без `RUSTFLAGS`, каждая — в своей копии `HEAD` со своим каталогом сборки.
- x86_64-musl собран с musl 1.2.5, собранным из исходников во временном каталоге (передан только `CC_x86_64_unknown_linux_musl`); `cargo build -v` подтверждает флаги `.cargo/config.toml`.

#### Размеры (stripped, байт; по отчёту исполнителя)

| Вариант | x86_64-musl | aarch64-musl |
|---|---:|---:|
| A: текущий профиль (opt 3) | 12 615 856 | 10 282 664 |
| B: `"s"` + `core-crypto`=3 (и прежний список) | 8 994 864 (−28,7 %) | 7 420 856 (−27,8 %) |
| C: B + `force-unwind-tables=no` | 8 994 864 (как B) | 7 191 768 (−30,1 %) |
| D: `"z"` + `core-crypto`=3 | 8 365 440 (−33,7 %) | 6 438 240 (−37,4 %) |
| E: B + `core-tls`=3 + `core-runtime`=3 | 10 991 792 (−12,9 %) | 8 980 568 (−12,7 %) |
| G: B + `core-cli`=3 (корень LTO) | 12 857 704 (+1,9 %) | 11 744 400 (+14,2 %) |
| Принятый: A + флаг только для aarch64 | без изменений (флаг не добавлен) | 9 995 544 (−2,79 %) |

- Проверено разработкой на текущем `HEAD` (`808bfa4`), aarch64-musl release: 10 285 480 → 9 995 544 байт (−289 936, −2,8 %); во всех 199 вызовах rustc для aarch64 присутствуют `--cfg aes_armv8`, `--cfg polyval_armv8`, `--cfg chacha20_force_neon`, `force-unwind-tables=no`; флаги компоновщика (`rust-lld`, `link-self-contained=yes`, `--icf=safe`, `-z noseparate-code`, `-z norelro`) на месте.
- На x86_64 флаг размер не меняет (`.eh_frame` 665 КБ остаётся), поэтому туда не добавлен. На aarch64 `.eh_frame` уменьшается с 679 до 393 КБ (остаток — из готовой std).

#### Производительность x86_64 (musl release; по отчёту исполнителя)

- `perf_aead` (одно ядро, 5 чередующихся прогонов, ГиБ/с, медиана): fastgcm и fastchacha из `core-crypto` при `"s"` не теряют скорость; AEAD из крейтов RustCrypto, инстанцируемые вне per-package переопределений, — около 3 раз медленнее (aes-128-gcm 64K: 0,91 → 0,32; chacha20poly1305: 1,03 → 0,33).
- Сквозной тест `scripts/bench/proto.py` (VLESS, клиент и сервер — тот же бинарник, медиана 3 серий): plain и TLS AES-128/256 — в пределах шума; **TLS с ChaCha20-Poly1305 при `"s"`: 1 поток 2,6 → 1,93 Гбит/с, 8 потоков 6,4 → 5,0 Гбит/с, CPU на ГиБ +≈30 %**. Возврат `core-tls`, `core-runtime` или `rustls` к opt 3 потерю не устраняет: при fat LTO оптимизация идёт с opt-level корневого крейта, поэтому per-package `opt-level=3` (BLD-07) в текущем виде ничего не дают.
- Пиковая RSS при `"s"` ниже на ≈2,3 МиБ; время `check` ≈2 мс для всех вариантов.
- Smoke (x86_64-musl, варианты A–D): `version`, `check` (rc 0), `run` с mixed inbound (HTTP-запрос через SOCKS5 и HTTP-прокси), выход по SIGTERM с кодом 0.

#### Решение

- Профиль остаётся `opt-level = 3`. BLD-06 в описанном виде не применять: возвращаться к нему вместе с изменением кода (например, перевести TLS ChaCha на собственную реализацию `core-crypto`) и после A/B-замера на Cortex-A53 (`perf_aead`, `proto.py`).
- BLD-07: предложенное в аудите «исправление» при fat LTO не работает; комментарий в `Cargo.toml` исправлен.
- BLD-08 применён только для aarch64.

#### Цена BLD-08

- При `panic = "abort"` и `strip = "symbols"` раскрутки нет, а backtrace и так без имён; сообщение о панике по-прежнему выводится. Теряются обход стека по `RUST_BACKTRACE` и профилировщики на основе DWARF CFI на устройстве.

#### Ограничения

- **Скорость на ARM не измерялась** — ни для принятого флага, ни для вариантов `"s"`: здесь нет ARM-устройства и эмулятора; aarch64-бинарник не запускался. Выводы по ARM — только по статическому подсчёту инструкций: в принятом варианте число `aese`, `aesmc`, `pmull`, `pmull2` не изменилось (1002/904/83/74).
- Быстрый путь `fastchacha` на AVX2 есть только на x86, поэтому замеры x86 не заменяют ARM для ChaCha.
- Сквозные замеры — только VLESS plain/TLS/Vision; Hysteria2 и XHTTP не замерялись.
- Замеры сделаны исполнителем; разработкой повторно проверены только размер и флаги aarch64 на текущем `HEAD`. Полный CI не запускался.

#### Независимая проверка (Codex)

- **BLD-08:** независимая сборка aarch64-musl — 10 299 016 → 10 009 016 байт, экономия 290 000 байт (≈2,82 %). ARM crypto cfg и флаги компоновщика сохранены.
- Это проверка сборки и размера: aarch64-бинарник не исполнялся, скорость на ARM не измерялась.
- **BLD-06 / BLD-07** остаются неприменёнными; замеры производительности исполнителя независимо не повторялись.
- Полный CI не запускался.

### FP-01 — статичный ECH GREASE в шаблонах Firefox и Chrome

- **Приоритет:** P0: 32 байта `enc` в расширении `0xfe0d` выделяли любой xrust с fp firefox, chrome (умолчание REALITY в Forkop X), random и randomized.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`4be666f3c8ed722eaed284847958d0b82a1b7166`](https://github.com/Screamshow/xrust/commit/4be666f3c8ed722eaed284847958d0b82a1b7166).
- **Файлы:** `crates/core-tls/src/hello.rs`, `crates/core-tls/src/fingerprints.rs` (сгенерирован заново), `tools/fingerprint_tables.py`, новый `crates/core-tls/tests/ech_grease.rs`, `crates/core-tls/tests/{fingerprints,chrome_hello,handshake_e2e}.rs`, `crates/core-runtime/tests/reality_auth.rs`, тест в `crates/core-runtime/src/tls_client.rs`, `tests/spikes/clienthello/captures-sing-box-x/README.md`.
- **Организация:** реализация — один исполнитель; независимая проверка захватов и совместимости — второй, без правки файлов репозитория, на замороженном снимке рабочего дерева.

#### Эталон

- Xray v26.10.21 (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`), `go.mod:18` — uTLS `v1.8.3-0.20260301010127-aa6edf4b11af` (ревизия `aa6edf4b11af82e110eea845bb2983d30138d651`).
- uTLS: расширение собирается один раз на ClientHello, переиспользуется только при HRR (`u_ech.go:65-72`); config_id — случайный байт (`:73-80`); набор шифров — случайный из кандидатов (`:95-109`); `enc` — открытый ключ свежей эфемерной пары DHKEM(X25519) (`:111-128`, `u_hpke.go:18`, `internal/hpke/hpke.go:88-108`); длина payload — случайная из кандидатов плюс 16 байт тега, содержимое случайное (`u_ech.go:130-160`); формат на проводе (`:171-200`).
- Параметры профилей: Chrome — `BoringGREASEECH`, HKDF-SHA256 / AES-128-GCM, длины 128/160/192/224 (`u_ech.go:296-306`, `u_parrots.go:963`, `u_common.go:616`); Firefox 148 — (0x0001, 0x0001) или (0x0001, 0x0003), длина 223 (`u_parrots.go:1577-1589`, `u_common.go:605`). Safari 26.3, Edge 85, iOS 14, QQ, 360, Android — без ECH GREASE; randomized (`generateRandomizedSpec`, `u_parrots.go:3231`) ECH не добавляет.

#### Причина

- `fingerprints.rs` хранил тело `0xfe0d` как `Ext::Static` из одного захвата uTLS (chrome-семейство `:157`, `:319`, `:472`, `:753`, `:913`, `:968`; firefox `:1306`), `hello::build` переписывал только идентификаторы GREASE.

#### Исправление

- Новый `Ext::EchGrease { cipher_suites, payload_lens }` с константами `EchGrease::CHROME` и `EchGrease::FIREFOX`; тело строится в `hello::build` для каждого ClientHello: случайный config_id, набор шифров и длина — равномерный выбор из кандидатов, `enc` — открытый ключ X25519 свежего секрета, payload — случайные байты длины + 16. Если источник энтропии недоступен, ClientHello не строится (фиксированного запасного тела нет).
- Шаблоны хранят только параметры; генератор таблиц выдаёт новый вариант и отвергает захваты, не совпадающие с параметрами профиля. Порядок расширений и тела остальных расширений не менялись; перестановки нет.
- `parse_record` и fptn-приманка, воспроизводящая захваченные записи, не менялись.

#### Охват по профилям

| Профиль | ECH GREASE в uTLS | xrust до | xrust после |
|---|---|---|---|
| chrome и псевдонимы (`""`, `chrome_psk`, `chrome_psk_shuffle`, `chrome_padding_psk_shuffle`, `chrome_pq`, `chrome_pq_psk`) и таблицы вариантов chrome | да (Boring) | статичный (config_id 213, payload 208) | на каждое рукопожатие, параметры Chrome |
| firefox | да (Firefox 148) | статичный (config_id 155, aead 0x0003, payload 239) | на каждое рукопожатие, параметры Firefox |
| safari, edge, ios, qq, 360, android | нет | нет | нет, без изменений |
| random | как у выбранного браузера | статичное тело браузера | параметры выбранного браузера на каждое рукопожатие |
| randomized | нет | статичное тело chrome | **свежий ECH в стиле chrome на каждое рукопожатие** — эталон ECH не отправляет; удаление относится к FP-15 и требует решения |

- Исправление Chrome было необходимо: это тот же дефект в том же механизме, и chrome — умолчание REALITY.

#### Воспроизведение до исправления

- Захваты независимой проверки (loopback, по 12 последовательных и 12 параллельных соединений на профиль; Xray с повторами — по 60):

| Профиль | Старый xrust | Новый xrust | Xray v26.10.21 |
|---|---|---|---|
| chrome | config_id, enc, payload — по 1 значению; длина ClientHello 1784; payload 208 | все `enc` и payload различны; длины 1720/1752/1784/1816; payload 144/176/208/240 | то же распределение длин; 60/60 различных `enc` |
| firefox | 1 значение; набор всегда 0001/0003; config_id 155; payload 239 | все различны; наборы 0001/0001 и 0001/0003; payload 239; длина 1885 | наборы 1/1 и 1/3; payload 239; длина 1885 |
| safari / edge | без `0xfe0d` | без `0xfe0d` | без `0xfe0d` |
| randomized | 15/15 со статичным телом chrome | 15/15 со свежим ECH | 0 из 75 с `0xfe0d` |

- Во всех 111 новых ClientHello с ECH: `enc` и payload различны, не совпадают со старыми статичными значениями и с key_share того же hello; тип 0, `enc` 32 байта, длины согласованы; каждый `enc` — каноническая точка кривой X25519, не малого порядка.
- Структура вне ECH (версия, длина session id, шифры, сжатие, порядок расширений, хэши тел, без GREASE, key_share, `0xfe0d`, padding, PSK) у старого и нового кода идентична во всех 8 прогонах; JA4 не изменился и совпадает с Xray; позиция ECH прежняя (chrome — 6, firefox — 14).
- Проверено разработкой на копии `HEAD`: `ech_grease` — 1 passed, 4 failed (chrome, таблицы вариантов chrome, firefox, политики random — «enc repeats»); проходит только тест профилей без ECH. По отчёту исполнителя на 192 ClientHello: до — по одному `enc`, payload и config_id; после — 192 различных `enc` и payload.

#### Проверки разработки

- Проверено на копии снимка с отдельным каталогом сборки:

| Команда | legacy | rust-x |
|---|---|---|
| `cargo fmt --all -- --check` | чисто | — |
| `cargo clippy --locked -p core-tls --all-targets -- -D warnings` | чисто | — |
| `cargo test --locked -p core-tls` | 96 passed, 0 failed | — |
| `--lib tls_client` | 11 passed | 10 passed |
| `--test reality_auth` (включая все браузерные профили против REALITY-сервера xrust) | 6 passed | 6 passed |
| `--test tls_own_stack` / `--test fetch_tls` | 4 / 3 passed | 4 / 3 passed |

- Новые тесты на рукопожатия, REALITY и проверку сертификата проходят и на старом коде — они защищают от регрессий, а не выявляют исправление.
- По отчёту исполнителя: в rust-x `tls_interop` 1/4 — 3 падения (trojan, naive, anytls не реализованы), так же на `HEAD`.

#### Независимая проверка совместимости (второй исполнитель)

- Клиент xrust передаёт 3 × 256 КиБ случайных данных через SOCKS и сервер на локальный echo, сверка побайтно; проверка сертификата включена (тестовый CA через `certificate_path`, без `insecure` и pins).

| fp | Xray VLESS+TLS | sing-box 1.14.3 VLESS+TLS | Xray REALITY (независимый сервер) |
|---|---|---|---|
| firefox | 3/3 (старый и новый) | 3/3 | 3/3 |
| safari | 3/3 | 3/3 | 3/3 |
| edge | 3/3 | 3/3 | **отказ** и на старом, и на новом коде; клиент Xray с fp edge к тому же серверу тоже не подключается |
| chrome | 3/3 | 3/3 | 3/3 |

- Отрицательные контроли для firefox, safari, edge (старый и новый код): чужой CA отвергается 3/3; неверный открытый ключ REALITY отвергается 3/3.
- Причина отказа edge с REALITY: в `signature_algorithms` профиля Edge 85 нет ed25519 (`0x0807`), клиент xrust сообщает `the certificate carries no Ed25519 key`. Это ограничение профиля, не регрессия.

#### Ограничения

- В `main` не слито, не выпущено.
- Изменяется только расширение ECH. Порядок расширений и JA3 Chrome (FP-02), GREASE в шифрах, группах и версиях (FP-03), randomized и random (FP-15) не менялись — xrust по-прежнему различим; неотличимость от браузера не заявляется.
- randomized теперь отправляет свежий ECH в стиле chrome, тогда как эталон ECH не отправляет; решение отложено (FP-15).
- Распределение длин ClientHello Chrome соответствует uTLS (4 значения через 32 байта); с реальными браузерами не сравнивалось.
- HRR не поддерживается, поэтому правило uTLS о повторном использовании ECH при HRR неприменимо.
- fptn-приманка по-прежнему воспроизводит захваченный ECH (вне FP-01).
- Только loopback; эталон — Xray и его uTLS; реальные браузеры, захваты клиента sing-box, OpenWrt и полный CI не проверялись. Выборки по 12 на режим достаточны для проверки изменчивости, но не для статистики распределений.

#### Независимая проверка (Codex)

- **Объект:** коммит `4be666f3c8ed722eaed284847958d0b82a1b7166` на чистом detached checkout `ed63bd0c4e34cbeaf3464da35b2418797d6fc33c`. Повторный аудит не проводился.
- **Ревью:** блокирующих замечаний нет. ECH GREASE строится заново при каждом построении ClientHello; используется свежий открытый ключ X25519; ошибки источника случайности возвращаются вызывающему коду. Параметры Firefox и Chrome разделены. Safari и Edge не получают ECH.
- **Локально (WSL) прошли 112 тестов:** core-tls — 96; `tls_client` (rust-x) — 10; `reality_auth` (rust-x) — 6. Проверки TLS включают успешное соединение с доверенным сертификатом и отказ при несовпадающем имени для четырёх профилей. REALITY — успешные подключения к собственному серверу проекта и отрицательные контроли аутентификации.
- **Отрицательный контроль:** новый `ech_grease.rs` на родителе исправления в отдельной копии — 4 теста падают, 1 проходит; на исправленном коде проходят все 5.
- **OpenWrt:** существующая VMware VM, OpenWrt 25.12.5 r33051-f5dae5ece4, x86_64. Отдельно собранные release musl тестовые бинарники запускались из `/tmp` через loopback: ECH GREASE — 5/5, REALITY — 6/6; всего на VM — 11/11.
- ECH-тесты проверяют последовательные и параллельные построения, уникальность `enc` и payload, структуру и допустимые длины, отсутствие ECH у соответствующих профилей. Для каждого проверяемого шаблона с ECH — 192 построения: 64 последовательно и 8 потоков по 16.
- **Состояние VM:** установленное ядро не заменялось. Список пакетов, PID основных процессов и контрольные суммы UCI `forkop`/`dhcp` сохранились. Сгенерированный `config.json` изменился из-за штатного cron-обновления подписки — это подтверждено журналом VM, hot reload сохранил процесс; обновление не откатывалось.
- **Границы:** Codex не повторял внешние сценарии Xray и sing-box, сравнение сетевых захватов и JA4, проверку по исходникам конкретной ревизии uTLS, реальные браузеры, ARM, WAN, производительность и полный CI. Собственный REALITY-сервер не подтверждает совместимость Edge с Xray REALITY. Неотличимость от браузера не заявляется.
- **Решение:** randomized остаётся для FP-15 и сейчас не меняется. FP-02, FP-03 и остальные особенности отпечатков этой проверкой не закрываются.

### MEM-07 — SRS загружается через промежуточные копии

- **Приоритет:** P1.
- **Статус:** частично исправлено, проверено в границах, указанных ниже: промежуточный `Vec<Value>` остаётся. В `main` не слито, не выпущено.
- **Коммит:** [`fc143dc9a2207816db6fe06d1ad6c4fb01d0b415`](https://github.com/Screamshow/xrust/commit/fc143dc9a2207816db6fe06d1ad6c4fb01d0b415).
- **Файлы:** `crates/core-config/src/srs.rs`, `crates/core-runtime/src/route/{mod.rs,rule_set.rs,rule_set_index.rs,rule_set_remote.rs}` (в `rule_set_remote.rs` — только путь разбора), `crates/core-runtime/tests/rule_set_compiled.rs`, новый `crates/core-runtime/tests/rule_set_load_memory.rs`.

#### Причина (счётчик выделений, `big-domains.srs` — 300 тыс. суффиксов, release)

- `serde_json` собран с `preserve_order`, `Value` — 72 байта; дерево для 300 тыс. суффиксов — 28,2 МиБ, скомпилированный индекс — 15,1 МиБ. Два пика примерно по 59 МиБ:
  1. в декодере (`srs.rs`, `read_domain_matcher` / `SuccinctSet::keys`): все ключи собирались в `Vec<String>`, пока строились префиксы; `SuccinctSet` (≈8 МиБ) жил до конца функции; преобразование `Vec<String>` → `Vec<Value>` шло с неиспользованной ёмкостью;
  2. в компиляции (`rule_set_index.rs`, `RuleSetIndex::compile(&[Value])`): каждая строка клонировалась, и дерево с индексом держали её дважды.

#### Исправление

- `SuccinctSet::keys(budget, emit)` передаёт каждый ключ в замыкание; бюджет декодированного размера списывается за ключ, как раньше. `read_domain_matcher` классифицирует ключи во время обхода, затем освобождает набор и ужимает векторы до преобразования.
- `RuleSetIndex::compile` принимает правила по значению и переносит строки в индекс вместо копирования.
- Локальный и remote-пути освобождают файл, запись кэша и исходный JSON сразу после декодирования.
- Защита CQ-03 (лимиты распаковки и бюджета, проверки счётчиков и индексов, ограничение длины ключа и глубины обхода) не менялась; сигнатуры и результат `srs::read` / `read_with_version` прежние.

#### Эквивалентность (старый `HEAD` и новый код, по отчёту исполнителя)

- Временный стенд (в репозиторий не вошёл): хэш вывода `srs::read` и ответы `RuleSet::matches` на ≈5,6 млн запросов (записи как есть, с поддоменом, префиксом и суффиксом, родительский домен, верхний регистр; границы CIDR ±1/255/65535; 50 тыс. случайных IPv4 и IPv6 с разными портами и сетями; перебор портов) на 16 файлах: `local.srs`, `big.srs` из Forkop, `big-domains`, `geoip-like`, `geosite-med`, `small0`–`small5`, golden `tests/golden/rule-set/local.srs`, а также смешанные фикстуры (домены, суффиксы, ключевые слова, regex, CIDR v4/v6, source CIDR, порты и диапазоны, сеть, invert, вложенные логические правила). Хэши декодирования и совпадений **идентичны**.
- `rule-set decompile` и `rule-set match` CLI: вывод побайтно совпадает на 8 файлах.

#### Память и время (по отчёту исполнителя)

- **Метод:** release `rust-x`, отдельные процессы; конфигурация — один локальный binary rule set и правило маршрутизации; готовность — когда mixed-порт принимает соединения; VmHWM, VmRSS и RssAnon читаются из `/proc` через 1,5 с; 5 прогонов, медиана; `TACHYON_WORKERS=2`, `MIMALLOC_ALLOW_THP=0`. Разброс между прогонами меньше 1 %.
- **Платформа:** x86_64 Linux; «gnu» — сборка по умолчанию (mimalloc на x86_64); «musl» — `x86_64-unknown-linux-musl` с musl-gcc, собранным из исходников во временном каталоге, без `RUSTFLAGS` (аллокатор musl).

| Набор | Сборка | VmHWM до → после, КиБ | VmRSS до → после | RssAnon до → после | Готовность, мс |
|---|---|---|---|---|---|
| big-domains (300 тыс.) | musl | 67 344 → **52 240** | 24 784 → 24 724 | 19 480 → 18 916 | 2376 → 2229 |
| big-domains | gnu | 69 428 → **54 332** | 27 292 → 27 192 | 19 556 → 19 004 | 2330 → 2202 |
| big.srs Forkop (180 тыс.) | musl | 36 672 → **30 036** | 15 148 → 15 224 | 9 844 → 9 416 | 773 → 701 |
| big.srs | gnu | 38 984 → **31 684** | 17 908 → 17 424 | 9 924 → 9 504 | 746 → 692 |
| geosite-med | musl | 20 608 → **18 768** | 12 348 → 12 416 | 6 956 → 6 416 | 569 → 538 |
| geosite-med | gnu | 22 920 → **20 864** | 15 124 → 14 924 | 7 040 → 6 504 | 554 → 526 |

- Счётчик кучи на big-domains: пик декодирования 59,6 → 45,1 МиБ, пик компиляции 59,3 → 40,6 МиБ; компиляция 108 → 55 мс, декодирование 808 → 726 мс.

#### Проверки разработки

- Проверено на копии `HEAD` + файлы MEM-07 с отдельным каталогом сборки:

| Команда | legacy | rust-x |
|---|---|---|
| `cargo fmt --all -- --check` | чисто | — |
| `cargo clippy --locked -p core-config -p core-runtime --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто | — |
| `cargo test -p core-config --lib srs` (включая отрицательные тесты CQ-03) | 21 passed | 21 passed |
| `cargo test -p core-config --lib` | 305 passed | — |
| `--lib rule_set` / `--lib rule_set_remote` | 18 / 12 passed | 18 / 12 passed |
| `--test rule_set_compiled` | 15 passed | 15 passed |
| `--test rule_set_load_memory` / `--test rule_set_memory` | 1 / 1 passed | 1 / 1 passed |
| `--test hot_reload` / `--test fakeip_ech` | 9 / 1 passed | 9 / 1 passed |
| `cargo test -p core-cli rule_set` | 4 passed | 4 passed |

- **На старом коде:** `rule_set_load_memory` падает (проверено разработкой; по отчёту исполнителя — 10,18 МБ сверх декодированных правил при 8,0 МБ строк). Новые тесты эквивалентности в `rule_set_compiled.rs` проходят и на старом коде — они защищают от регрессий.
- По отчёту исполнителя: в rust-x `core-config --lib` — 108 ранее существовавших падений (legacy-тесты), `--lib route` — `chain_golden_lx_loads_in_router`; на `HEAD` так же.

#### Ограничения

- В `main` не слито, не выпущено.
- Сам `Vec<Value>` из `srs::read` (72 байта на элемент) остаётся крупнейшей временной структурой. Полное устранение требует типизированного декодирования и построения индекса из типизированных правил, общего с mmap-компиляцией, CLI и `validate`: оценка исполнителя — `srs.rs`, `rule_set_index.rs`, `rule_set.rs`, `route/mod.rs`, `rule_set_remote.rs` (и `mmap_set` при общей компиляции TSRS), ≈400–700 строк, ещё ≈15–20 МиБ пика на 300 тыс. записей; риск — два пути декодирования, которые должны совпадать. Не делалось.
- Путь загрузки по сети по-прежнему держит тело ответа во время компиляции: оно нужно для записи в кэш (область MEM-08, не менялась). Переиспользование неизменённых наборов при hot reload не делалось.
- **Побочная находка (существующее поведение, не менялось):** правило, содержащее только `domain_regex` (без других групп), попадает в fallback как пустое plain-правило и совпадает с любым соединением; старый и новый код и интерпретатор `match_rule` ведут себя одинаково. Требует отдельной задачи.
- OpenWrt и роутер не проверялись; полный CI не запускался.

Проверка Codex для MEM-07 и MEM-08 общая — см. раздел «Независимая проверка (Codex, MEM-07 и MEM-08)» в MEM-08.

### MEM-08 — cache.db: flush клонирует всё дерево

- **Приоритет:** P1.
- **Статус:** исправлено в объёме «без клонирования при сериализации», проверено в границах, указанных ниже. Ленивое чтение, формат хранения и периодичность flush не менялись. В `main` не слито, не выпущено.
- **Коммит:** [`cc6c8829108d5428b06246a4b5410bfcc5f53abc`](https://github.com/Screamshow/xrust/commit/cc6c8829108d5428b06246a4b5410bfcc5f53abc).
- **Файлы:** `crates/core-experimental/src/bbolt.rs` (writer), `crates/core-runtime/src/cache_file.rs` (`flush`, `build_tree`), новые `crates/core-experimental/tests/writer_bytes.rs`, `crates/core-runtime/tests/cache_file_compat.rs`, `crates/core-runtime/tests/cache_file_flush_alloc.rs`, фикстура `crates/core-runtime/tests/data/cache-file-v0026.db` (135 КБ, записана старым кодом).

#### Причина

- Каждый flush копировал каждый ключ и значение примерно четыре раза: `build_tree` (`cache_file.rs:476`) клонировал всё в `NodeSpec`; `bbolt::write` → `sorted_tree` клонировал дерево ещё раз (с `to_vec()` в каждом сравнении); `materialize` клонировал в `Inode`; `partition` клонировал `Inode` в `Vec<Vec<Inode>>`; затем writer собирал файл в `Vec`.

#### Исправление

- В `bbolt.rs` — заимствующее дерево (`EntryRef<'a>` / `NodeRef<'a>`) и `write_ref`; `Inode` хранит срезы, `partition` возвращает диапазоны индексов, ключи ветвей заимствуются; каждый узел сортируется на месте перед записью детей, поэтому страницы выделяются в прежнем порядке и байты файла совпадают. `write(&NodeSpec)` сохранён и идёт через тот же путь.
- `cache_file::build_tree` строит дерево из своих bucket'ов без копий. `flush` по-прежнему пишет во временный файл и переименовывает его; при ошибке состояние в памяти, прежний файл и признак `dirty` сохраняются.

#### Совместимость (по отчёту исполнителя; старый код — отдельная копия `HEAD`)

- База 9,4 МБ, записанная с нуля старым и новым кодом, побайтно идентична (sha256 совпадает). Старый файл, изменённый новым кодом, и тот же файл, изменённый старым кодом, — побайтно идентичны; новый файл, изменённый старым кодом, — тоже.
- Фикстура детерминирована (дважды сгенерирована старым кодом с одинаковыми байтами); новый код переписывает её побайтно — и с нуля, и при открытии → изменении → flush.
- `writer_bytes` фиксирует длину и хэш FNV-64 вывода writer по старому коду (несортированный вход, вложенные и пустые bucket'ы, `seq`, overflow-значение, двоичные ключи, ветвь из ветвей).

#### Память и время (по отчёту исполнителя)

- **Метод:** x86_64 Linux, release `rust-x`, системный аллокатор со счётчиком, 5 чередующихся прогонов в отдельных процессах; стенд открывает базу, изменяет один ключ, сбрасывает VmHWM (`/proc/self/clear_refs` = 5), замеряет `flush()`. musl не измерялся.
- **Данные:** база 9,4 МБ: 5,16 МБ — тела двух rule set (`big-domains.srs` 3,97 МБ, `big.srs` 1,19 МБ); 16 384 + 16 384 пар FakeIP v4/v6 с 32 768 записями адресов, 2000 rdrc2, 2000 dns_cache, selected/expand/mode/chain и дополнительный bucket.

| | До | После |
|---|---|---|
| VmRSS после открытия | 20,25 МБ | 20,25 МБ |
| Живая куча после открытия | 14,2 МБ | 14,2 МБ |
| VmHWM во время flush | 79,35 МБ (+59,1) | 41,49 МБ (+21,2) |
| Дополнительная куча на пике flush | 49,9 МБ | 16,4 МБ |
| Время flush (медиана 5 прогонов) | 76,7 мс (75,5–94,3) | 22,6 мс (21,8–54,6) |

- Оставшийся пик — почти целиком `Vec` образа файла, растущий удвоением (для файла 9,2 МБ — ёмкость 16 МиБ).

#### Проверки разработки

- Проверено на копии `HEAD` + файлы MEM-08 с отдельным каталогом сборки:

| Команда | legacy | rust-x |
|---|---|---|
| `cargo fmt --all -- --check` | чисто | — |
| `cargo clippy --locked -p core-experimental -p core-runtime --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто | — |
| `cargo test -p core-experimental` | все наборы прошли (1 + 2 + 1) | — |
| `--lib cache_file` / `--lib rule_set_remote` / `--lib fakeip` | 1 / 12 / 3 passed | 1 / 12 / 3 passed |
| `--test cache_file` / `cache_file_compat` / `cache_file_flush_alloc` | 10 / 5 (1 ignored — генератор фикстуры) / 1 passed | так же |
| `--test fakeip_persistence` / `selector_persistence` / `hot_reload` | 6 / 1 / 9 passed | так же |

- `cache_file_compat` покрывает: восстановление каждого bucket из старого файла; побайтное равенство при записи с нуля и перезаписи; изменение → повторное открытие; каталог только для чтения — flush возвращает ошибку, состояние в памяти, прежний файл и `dirty` сохраняются, временный файл не остаётся, повтор после chmod успешен (процесс не root); перезапуск — remote rule set, загруженный один раз, восстанавливается из кэша без сервера, отображения FakeIP из старого файла переживают два перезапуска.
- **На старом коде:** `cache_file_flush_alloc` падает — проверено разработкой: flush выделил 25 124 940 байт для файла 5 070 848 байт (лимит теста — 2,5 размера файла; новый код — ≈10,1 МБ). `writer_bytes` и `cache_file_compat` проходят и на старом коде, как и должно быть для изменения без смены вывода.
- По отчёту исполнителя: `cache_file_interop` — 1 passed (часть с Go пропущена: Go не установлен); в rust-x `dns_resolver` — 1 ранее существовавшее падение (`tcp_transport_uses_the_detour_outbound`, socks не реализован), на `HEAD` так же.

#### Ограничения

- В `main` не слито, не выпущено.
- Образ файла по-прежнему собирается целиком в одном `Vec` с ростом удвоением (до ≈2× размера файла); точное предвыделение или потоковая запись требуют изменения writer — не делалось.
- Не менялось по условию: чтение всей базы в `BTreeMap` (`read_all`, копии в `Db::open` / `load_page`), немедленный flush в `save_to_cache`, интервал flush.
- Ошибка записи после частичного создания временного файла (например, нехватка места) по-прежнему оставляет `cache.db.tmp`, как и раньше.
- OpenWrt и роутер не проверялись; полный CI не запускался.

#### Независимая проверка (Codex, MEM-07 и MEM-08)

- **Объект:** MEM-08 `cc6c8829108d5428b06246a4b5410bfcc5f53abc`, MEM-07 `fc143dc9a2207816db6fe06d1ad6c4fb01d0b415`, checkout `2e35c8405cdd9c60c9f3b44aae29a1b8a498d626`. Блокирующих регрессий не обнаружено.
- **Локально (WSL) прошли 83 разных теста:** SRS — 21; `writer_bytes` — 1; `cache_file` — 10; `cache_file_compat` — 5; `cache_file_flush_alloc` — 1; `hot_reload` — 9; `rule_set_compiled` — 15; `rule_set_load_memory` — 1; модульные `rule_set` / `rule_set_remote` — 18; дополнительные независимые проверки — 2. Генератор фикстуры штатно `ignored`.
- Проверены старая cache.db, побайтная перезапись, повторное открытие, восстановление FakeIP и remote rule set, hot reload и сохранение состояния при ошибках.
- **Дополнительные независимые проверки:** 14 корректных SRS-правил проверены по одному против интерпретатора; блокировка пути `cache.db.tmp` вызывает ошибку flush, сохраняет старый файл и новые данные в памяти, после устранения помехи повторная запись успешна — проверка работает и от root.
- **Отрицательный контроль:** на родителе MEM-08 оба новых теста памяти падают, на новом коде проходят; `writer_bytes` проходит и на старом коде с тем же ожидаемым результатом.
- **OpenWrt 25.12.5 x86_64** (существующая VM): прошли 25/25 — SRS 21, `writer_bytes` 1, два теста выделений памяти и независимая проверка ошибки flush; отдельные release musl-бинарники запускались из `/tmp`. Пакеты, PID службы и контрольные суммы UCI и `config.json` до и после совпали.
- **Границы:** точные значения RSS и времени из отчёта разработки, сравнение на 16 настоящих SRS, 5,6 млн запросов и сравнение CLI независимо не повторялись. Счётчики выделений не являются RSS. Профиль legacy, ARM, пакетное обновление и полный CI не проверялись.
- **Неблокирующее замечание к тесту:** `srs_decoded_set_agrees_with_the_interpreter` включает `domain_regex` в общий набор правил; существующее поведение «совпадает со всем» (RS-01) может маскировать ошибки других правил. Рекомендуется проверять правила по отдельности, с положительными и отрицательными случаями.

### RS-01 — `domain_regex` в rule set: правило только с regex совпадает с любым соединением

- **Приоритет:** P1 (неверная маршрутизация: трафик уходит не в тот outbound).
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммиты:** [`79fb8be31263157aabd07c7c5c1419528c4e40f0`](https://github.com/Screamshow/xrust/commit/79fb8be31263157aabd07c7c5c1419528c4e40f0) — исправление; [`08d35a3814dac7d528d9d1e1a8a9ee336cce647c`](https://github.com/Screamshow/xrust/commit/08d35a3814dac7d528d9d1e1a8a9ee336cce647c) — доработка по ревью: Go `\Q...\E` и исключение наборов, которые теряет TSRS; [`9c688b2e9c28f8b78dba7833f1ccc71e2e13f5ed`](https://github.com/Screamshow/xrust/commit/9c688b2e9c28f8b78dba7833f1ccc71e2e13f5ed) — исправление замечания Codex к `08d35a3` (сохранение TSRS при неудачном обновлении).
- **Происхождение:** найдено при проверке MEM-07, подтверждено замечанием независимой проверки MEM-07/MEM-08.
- **Файлы:** `crates/core-runtime/src/route/{rule_set_index.rs,rule_set.rs,mod.rs,rule_set_remote.rs}`, `crates/core-config/src/validate.rs`; вызовы в тестах `route/rule.rs`, `dns/rules.rs`; тесты `crates/core-runtime/tests/{rule_set_domain_regex.rs (новый),hot_reload.rs,rule_set_compiled.rs,rule_set_cost.rs,fakeip_ech.rs,rule_set_load_memory.rs}`.
- **Организация:** исправление — один исполнитель; независимое ревью — второй, только чтение, на замороженном снимке.

#### Эталон (sing-box `824dbcfb4dd0a95921840b1737b950cde590241e`, бинарник 1.14.3)

- `route/rule/rule_headless.go:54-78` — `domain`, `domain_suffix`, `domain_keyword`, `domain_regex` входят в группу адреса назначения; `rule_abstract.go:132-137` — туда же `ip_cidr`; остальные группы (адрес и порт источника, порт назначения, network и др.) объединяются по И (`rule_abstract.go:71-143`).
- `rule_item_domain_regex.go:40-56` — проверяется `metadata.Domain` или `Destination.Fqdn` в нижнем регистре; пустой хост — нет совпадения.
- `rule_abstract.go:54-66` — `invert` применяется к результату правила; `rule_headless.go:230-235` — логические правила, ошибка подправила `sub rule[i]`.
- `rule_item_domain_regex.go:22-25`, `rule_headless.go:74`, `rule_set_local.go:134-136`, `rule_set_remote.go:206-208` — неверное выражение: `parse rule_set.rules.[i]: domain_regex: parse expression k: …`; при неудачном обновлении старые правила остаются.

#### Причина

- **Индекс в памяти** (`rule_set_index.rs`, `poolable`): `domain_regex` не входил в группу адреса назначения. Правило только с regex попадало в fallback как `PlainRule` без условий и совпадало со всем; `{domain_regex, port}` попадало в пул по порту и совпадало с любым хостом на этом порту; `{domain, domain_regex}` игнорировало regex.
- **Интерпретатор** `match_default` (`rule_set.rs`): тот же пробел в `has_domain`.
- **Правила маршрутизации верхнего уровня** (`route/rule.rs:410-417`, `:1029`) обрабатывали `domain_regex` правильно — не затронуты.
- **`check`** (`validate.rs`) не проверял выражения внутри rule set.

#### Исправление

- `domain_regex` добавлен в группу адреса назначения; правила только с regex собираются в отдельный пул скомпилированных выражений; `PlainRule` хранит свои выражения, `has_domains` учитывает `domain_regex`. Выражения компилируются один раз при загрузке.
- Интерпретатор учитывает `domain_regex`.
- Неверное выражение — ошибка загрузки в формате sing-box: `parse rule_set.rules.[N]: [sub rule[J]: ]domain_regex: parse expression I: …`. `check` сообщает её для inline, локального source и локального SRS (включая логические подправила); `run` и перезагрузка отклоняют конфигурацию (`route.rule_set[i]: …`).
- `RuleSet::new` и `replace_rules` возвращают `Result`; `replace_rules` компилирует до взятия блокировки. Неудачное обновление remote rule set не трогает текущие правила, etag, `last_updated` и кэш; ошибка при восстановлении из кэша — предупреждение и повторная загрузка; при hot reload работающий маршрутизатор сохраняется.

#### Изменения поведения (конфигурации, которые теперь маршрутизируются иначе)

1. Правило rule set только с `domain_regex` совпадает только с подходящими хостами; раньше — с любым соединением, включая IP-only.
2. `domain_regex` вместе с domain/suffix/keyword/ip_cidr теперь тоже даёт совпадение по regex; раньше regex игнорировался.
3. `domain_regex` вместе с портом, network, адресом или портом источника теперь требует совпадения regex; раньше такие правила совпадали с любым хостом.
4. `invert` с `domain_regex` и `domain_regex` в логических правилах следуют эталону.
5. Неверное `domain_regex` в inline, локальном или remote rule set — теперь ошибка `check`, запуска и перезагрузки; раньше молча принималось. Нестроковый элемент `domain_regex` тоже отвергается `check`.
- Семантика остальных правил не менялась.

#### Воспроизведение до исправления

- Проверено разработкой на копии `HEAD` (rust-x, отдельный каталог сборки; из тестов убран только `.expect` под старый API): `rule_set_domain_regex` — 1 passed, 7 failed. Падают: regex-only, объединение групп, invert и логические правила, JSON и SRS, ошибка неверного выражения, remote-обновление, сверка с sing-box; проходит `route_rule_regex_matches_only_matching_domains` (верхний уровень и раньше был корректен).
- По отчёту исполнителя на старом коде также падают новый тест `hot_reload` и переписанный `srs_decoded_set_agrees_with_the_interpreter` (`{"domain_regex":["^re[0-9]+\\.test$"]} must not match Domain("rex.test", 443)`); примеры: `bar.test` уходил в outbound rule set, `re42.test` не совпадал, конфигурация с неверным выражением принималась.

#### Сверка с sing-box 1.14.3

- Исполнитель: `sing-box rule-set match` на source JSON и на SRS из `rule-set compile` — 10 правил × 12 запросов = 120 ответов (regex отдельно, с domain, с suffix и keyword, с ip_cidr, invert, logical or/and, inverted logical and, с портом, шаблон в верхнем регистре); закреплены в `regex_answers_agree_with_reference_rule_set_match` для интерпретатора, inline-маршрутизатора и маршрутизатора из SRS-файла. Все совпадают. Текст ошибки `check` совпадает по структуре.
- Независимое ревью: 17 дополнительных нестандартных случаев, 55 запросов (regex + suffix + порт 0/443, `or` с инвертированным подправилом, инвертированный `or`, invert + ip_cidr на IPv4/IPv6, хосты в верхнем регистре с `^foo`/`(?i)FOO`/`FOO`, неякорный `oo`, выражения, совпадающие со строкой IP, инвертированный `.*` на IP, пул `{regex}` с `{port:[0]}`, вложенные and/or, строка вместо массива, хост с точкой в конце и др.) — 100 % совпадение с sing-box для набора целиком и для каждого правила, и для скомпилированного набора, и для интерпретатора.

#### Правила без `domain_regex` (независимое ревью)

- Дифференциальный корпус на `HEAD` и новом коде: ≈5900 наборов из одного правила (все подмножества до 3 из 18 вариантов полей, с invert и без), 3000 случайных логических деревьев and/or/xor, пустые и некорректные правила, 3000 случайных многоправильных наборов (проверка пулов) × 48 контекстов (домены, верхний регистр, пустой хост, IPv4/IPv6, sniff поверх IP, FakeIP, адреса источника, tcp/udp, порты). Вывод побайтно идентичен (8972 строки) и для скомпилированного набора, и для интерпретатора.

#### Исправление маскирующего теста

- `srs_decoded_set_agrees_with_the_interpreter` проверяет каждое из 15 декодированных правил в отдельном наборе: для каждого — явное соединение, которое должно совпасть, и соединение, которое не должно; затем сравнение с интерпретатором на всех контекстах; общее сравнение набора сохранено. В корпус добавлены 3 формы с regex.

#### Проверки разработки

- Проверено на копии снимка с отдельным каталогом сборки:

| Команда | legacy | rust-x |
|---|---|---|
| `cargo fmt --all -- --check` | чисто | — |
| `cargo clippy --locked -p core-config -p core-runtime --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто | — |
| `--test rule_set_domain_regex` | 8 passed | 8 passed |
| `--test rule_set_compiled` / `--test routing` / `--test hot_reload` | 15 / 13 / 10 passed | 15 / 13 / 10 passed |
| `--lib rule_set` / `--lib rule_set_remote` / `--lib mmap` | 18 / 12 / 3 passed | 18 / 12 / 3 passed |
| `--lib route` | 82 passed | 80 passed, 1 failed (`chain_golden_lx_loads_in_router` — так же на `HEAD`) |
| `--test rule_set_load_memory` / `--test fakeip_ech` | 1 / 1 passed | 1 / 1 passed |
| `cargo test -p core-config --lib srs` / `--lib` | 21 / 305 passed | 21 passed |
| `cargo test -p core-cli rule_set` | 4 passed | 4 passed |

- Независимое ревью: блокирующих замечаний нет; все вызовы изменённого API обработаны, `unwrap`/`expect` вне тестов не добавлены; на горячем пути выражения скомпилированы заранее, для наборов без regex добавлена только проверка пустого списка.

#### Ограничения

- В `main` не слито, не выпущено.
- **Различие синтаксиса Go `regexp` и Rust `regex`:** после `08d35a3` Go `\Q...\E` поддерживается. Остающиеся известные различия (выборочная проверка против sing-box 1.14.3): `a{1001}`, `a**`, `(?x) a` отвергаются sing-box, но принимаются xrust; отвергаются обоими: `\C`, `\Z`, `\k<n>`, `(unclosed`; принимаются обоими: `(?<n>a)`, `\pN`, `[[:word:]]`, `(?U)a+`, `\z`. Выражение, допустимое в Go, но не в Rust, останавливает загрузку rule set (неудачное remote-обновление сохраняет прежние правила). Полная совместимость не заявляется; валидатор всего синтаксиса не разрабатывался (`docs/rule-set-regex.md`).
- **mmap/TSRS:** после `08d35a3` наборы, которые TSRS не может представить, загружаются в память (см. раздел доработки). Уже собранные файлы `.tsrs` используются как есть: формат не хранит сведений о потерянных условиях (подробности — в разделе доработки).
- **CLI `rule-set match`** использует собственный упрощённый сопоставитель без `domain_regex` — не менялся.
- Проверяемый хост: xrust проверяет sniff-имя, затем адрес назначения, затем FakeIP (совпадение по любому), sing-box — только `metadata.Domain` или `Destination.Fqdn`; это поведение уже было у domain/suffix/keyword и сохранено. Пример расхождения — инвертированное правило при разных sniff-имени и адресе назначения.
- Текст ошибки после префикса — формат библиотеки Rust `regex` (многострочный), а не Go.
- Etag и реальный файл кэша при неудачном remote-обновлении проверены чтением кода, не тестом; ошибки выражений при восстановлении из кэша не покрыты тестом с файлом кэша.
- Интерпретатор `match_rule` компилирует выражение при каждом вызове — используется только в тестах. Для больших списков regex возможна оптимизация (`RegexSet`) — не делалась.
- OpenWrt и полный CI не проверялись.

#### Доработка по ревью (`08d35a3`)

- **Указания владельца:** поддержать Go-совместимый `\Q...\E` с правильным экранированием и сверить с sing-box 1.14.3; остальные различия синтаксиса зафиксировать без заявления полной совместимости; не пускать наборы с `domain_regex` в mmap-компиляцию, которая теряет условие; не выдумывать обнаружение потерь в готовых TSRS; предположения ревью о потере invert/logical и сочетаний условий сначала воспроизвести; изменение формата TSRS или новая зависимость — только по предварительному плану.
- **Файлы:** новые `crates/core-config/src/go_regex.rs`, `docs/rule-set-regex.md`; изменены `crates/core-config/src/{lib.rs,validate.rs}`, `crates/core-runtime/src/route/{rule_set_index.rs,rule_set.rs,rule.rs,mod.rs,rule_set_remote.rs}`, `crates/core-runtime/src/route/mmap_set/{compiler.rs,mod.rs}`, `crates/core-runtime/src/dns/rules.rs`; тесты `crates/core-runtime/tests/{rule_set_domain_regex.rs,hot_reload.rs}`. Формат TSRS не менялся, новых зависимостей нет.

##### `\Q...\E`

- `core_config::go_regex::translate` изменяет только выражения, содержащие `\Q`: всё после `\Q` до первого `\E` (или до конца выражения, если `\E` нет) — литеральный текст, включая обратные слэши; каждый символ выводится как есть (буквы, цифры, `_`) или как `\x{..}`, чтобы `(?i)` и `(?x)` не могли его переосмыслить; `\\` перед `Q` — экранированный слэш, а не начало цитаты; классы символов копируются без изменений по правилам Go (ведущий `]` — литерал, `[:name:]` — единица), поэтому `[\Q]` и лишний `\E` по-прежнему отвергаются, как в sing-box.
- Применяется везде, где компилируется `domain_regex`: индекс rule set, интерпретатор, правила маршрутизации верхнего уровня, правила DNS, `check` (только для `domain_regex`, не для `process_path_regex`).
- Поведение Go проверено на бинарнике sing-box 1.14.3 (Go-тулчейна и исходников regexp здесь нет): 39 случаев (закрытая и незакрытая цитата, слэши внутри, `\Qa\\E`, `\\\Q`, повтор после цитаты, группы, `(?i)`, `|`, `$`, `(`, `[a-z]`, пробел, `#`, не-ASCII; ошибки `^[\Q]` и `^x\E`) — все совпадают.

##### mmap/TSRS: воспроизведение предположения ревью

- Стенд на копии `39913a5` (вне репозитория) сравнил TSRS с путём в памяти на 15 соединениях:

| Правило | Результат TSRS |
|---|---|
| `domain_regex` | никогда не совпадает |
| `invert` | ответ не инвертируется (неверно на всех 15 контекстах) |
| логические `or` / `and` | никогда не совпадают |
| `{domain, port}` | превращается в ИЛИ (любой хост на 443 и and.com на любом порту) |
| `{domain_suffix, network}` | network игнорируется |
| `{ip_cidr, source_ip_cidr}` | источник игнорируется |
| `{source_port}` | отбрасывается |
| простые `{domain}`, `{port}` | как в памяти |

- Предположение подтвердилось. Исправление оказалось небольшим и единообразным с regex, поэтому сделано без переделки TSRS.

##### Исправление mmap

- `mmap_set::tsrs_unsupported(rules)` называет первое, что TSRS не может сохранить: логическое правило, `invert`, `domain_regex`, `source_ip_cidr`, `source_port`, `source_port_range`, `network`, поле назначения вместе с портом в одном правиле. В этом случае пишется `rule-set <tag>: mmap cannot keep <reason>, using memory rules` и набор загружается в память.
- Покрыты: локальные и inline-наборы (обе ветки mmap в `route/mod.rs`, включая hot reload), remote-наборы (`compile_and_cache_mmap` возвращает `None` → загрузка в память и удаление старого `.tsrs` этого набора, чтобы после перезапуска набор восстанавливался из cache.db в память; обрабатываются fetch и `initial_path`), восстановление из кэша (и раньше шло в память). Наборы, которые TSRS может представить, по-прежнему идут в mmap.
- **Изменение поведения:** наборы с `mmap: true` и такими формами (например, geosite с regex) теперь занимают обычную память процесса.

##### Готовые TSRS

- Формат не хранит сведений о том, что было отброшено при сборке, поэтому обнаружение не добавлялось. Используются как есть: локальный файл `.tsrs`, загруженное тело TSRS, `initial_path` `.tsrs`, а при старте remote — кэш `.tsrs`, записанный старой версией с потерями; он используется до следующей полной загрузки, которая переводит набор в память и удаляет файл. Дельта-обновление TSRS изменило бы старый файл вместо этого; удаление файла кэша сокращает ожидание.

##### Проверки доработки

- Новые тесты: `go_quoted_literals_match_like_the_reference`, `go_quoted_literals_pass_check_and_bad_escapes_fail`, `mmap_sets_with_rules_tsrs_cannot_hold_stay_in_memory` (7 форм × inline / локальный source / локальный SRS с `mmap: true`, положительные и отрицательные случаи, `.tsrs` не записывается; простой набор по-прежнему компилируется в TSRS), `remote_mmap_set_with_regex_stays_in_memory` (fetch при наличии старого `.tsrs` — удаляется; простой набор — в mmap и обратно; перезапуск из cache.db в память; `initial_path`), `mmap_local_set_switches_to_memory_when_reloaded_with_regex` (hot reload); модульные тесты транслятора и правила DNS.
- **На старом коде** (копия `39913a5`, отдельный каталог сборки, `--no-fail-fast`; проверено разработкой): падают все 5 новых интеграционных тестов — 4 в `rule_set_domain_regex` (8 passed, 4 failed) и 1 в `hot_reload` (10 passed, 1 failed). Модульные тесты нового модуля на старом коде не собираются.
- Проверено на копии `HEAD` + файлы доработки с отдельным каталогом сборки:

| Команда | legacy | rust-x |
|---|---|---|
| `cargo fmt --all -- --check` | чисто | — |
| `cargo clippy --locked -p core-config -p core-runtime --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто | — |
| `--lib rule_set` / `--lib rule_set_remote` / `--lib mmap` / `--lib dns::rules` | 18 / 12 / 3 / 14 passed | 18 / 12 / 3 / 14 passed |
| `--test rule_set_domain_regex` | 12 passed | 12 passed |
| `--test rule_set_compiled` / `--test routing` / `--test hot_reload` | 15 / 13 / 11 passed | 15 / 13 / 11 passed |
| `--test rule_set_load_memory` / `--test fakeip_ech` | 1 / 1 passed | 1 / 1 passed |
| `--lib route` | 82 passed | 80 passed, 1 failed (`chain_golden_lx_loads_in_router` — так же на `HEAD`) |
| `cargo test -p core-config --lib go_regex` / `srs` / весь `--lib` | 1 / 21 / 306 passed | 1 / 21 passed |
| `cargo test -p core-cli rule_set` | 4 passed | 4 passed |

##### Ограничения доработки

- Остающиеся различия синтаксиса Go и Rust — см. «Ограничения» выше; проверены выборочно.
- Готовые файлы `.tsrs` используются как есть.
- Не исправлено, найдено только чтением кода (не проверялось тестами): TSRS приводит сохранённые записи к нижнему регистру; суффикс с ведущей точкой трактует как суффикс метки; принимает голый IP в `ip_cidr`; никогда не совпадает с портом 0.
- **Новая находка (не исправлялась):** правило только с необработанными полями (например, `process_name`) на пути в памяти совпадает со всем, а в TSRS — ни с чем. Требует отдельной задачи, аналогичной RS-01.
- CLI `rule-set match` по-прежнему игнорирует `domain_regex`.
- OpenWrt и полный CI не проверялись. Отчёт внутреннего ревью не заменяет независимую проверку Codex.

#### Замечание независимой проверки `08d35a3` и исправление (`9c688b2`)

- **Замечание (Codex, checkout `7df6331`):** `compile_and_cache_mmap` (`rule_set_remote.rs:139`) удалял существующий TSRS до компиляции новых правил в памяти через `replace_rules` (`:488`). Воспроизведение: remote-набор `mmap: true` с `domain: plain.com` создаёт TSRS; следующее обновление содержит `domain_regex: (unclosed`; fetch возвращает ошибку, старые правила в памяти сохранены, но рабочий TSRS-файл уже удалён. Сценарий воспроизведён с отключённым общим cache.db; дополнительный независимый тест падает: `failed update deleted the working TSRS cache`.
- **Результаты Codex на `7df6331` до исправления:** `go_regex` 1, `hot_reload` 11, `routing` 13, `rule_set_compiled` 15, `rule_set_domain_regex` 12 — все 52 прошли; дополнительный тест сохранности кэша упал. Модульный набор, musl/OpenWrt, legacy, полный CI и живой sing-box на этом этапе не запускались.
- **Исправление:** `compile_and_cache_mmap` только сообщает, что TSRS не может сохранить правила; устаревший `.tsrs` удаляет вызывающий код (`remove_stale_tsrs`) после успешного `replace_rules` — и на пути обновления, и на пути `initial_path`. Неудачное обновление сохраняет текущие правила, файл TSRS и метаданные; успешный переход mmap → память по-прежнему удаляет устаревший TSRS.
- **Регрессионный тест:** `failed_move_from_mmap_to_memory_keeps_the_tsrs` — plain-набор в mmap; обновление с `domain_regex: (unclosed` завершается ошибкой, набор остаётся в mmap, `plain.com` совпадает, байты TSRS, `etag` и `last_updated` не изменились; затем корректное обновление с regex переводит набор в память и удаляет TSRS. На `7df6331` тест падает с `failed update deleted or changed the working TSRS cache` (проверено разработкой, отдельная копия и каталог сборки).
- **Проверки разработки** (копия `HEAD` + исправление, отдельный каталог сборки, оба профиля): fmt и clippy (legacy, `-D warnings`) чисто; `rule_set_domain_regex` 13, `hot_reload` 11, `routing` 13, `rule_set_compiled` 15, `--lib rule_set_remote` 12, `--lib rule_set` 18, `--lib mmap` 3 — все прошли.

#### Независимая проверка (Codex)

- **Объект:** исправление `9c688b2e9c28f8b78dba7833f1ccc71e2e13f5ed` на checkout `f1c3e3fd033c83861362bb5304a2c948d31e7288`, вместе с предыдущими изменениями RS-01 (`79fb8be`, `08d35a3`).
- Замечание об удалении рабочего TSRS при ошибочном обновлении закрыто: исходный независимый тест Codex теперь проходит (на `7df6331` падал); тест исполнителя подтверждает сохранность правил, байтов TSRS, `etag` и `last_updated` при ошибке и удаление устаревшего TSRS после успешного перехода в память.
- **Локально прошли 89 тестов:** `go_regex` 1, `hot_reload` 11, `routing` 13, `rule_set_compiled` 15, `rule_set_domain_regex` 13 и независимый 1, модульные по фильтру `rule_set` 18, правила DNS 14, `mmap` 3.
- **OpenWrt 25.12.5 x86_64** (существующая VM): прошли 25/25 — `rule_set_domain_regex` 14 (с независимым тестом) и `hot_reload` 11; отдельные release musl-бинарники из `/tmp`. Проверены ошибки regex, переходы mmap → память, remote-обновление, сохранность TSRS и hot reload с сохранением TCP. Пакеты, PID службы и контрольные суммы UCI `forkop`/`dhcp` и `config.json` до и после совпали.
- Блокирующих замечаний больше не обнаружено.
- **Границы:** legacy, ARM, полный CI, пакетное обновление и полный жизненный цикл Forkop не проверялись. Живые sing-box и Xray не запускались; сравнения используют сохранённые ожидаемые ответы.
- **Этой проверкой не закрываются:** ограничения готовых TSRS и старого автокэша `.tsrs` до полного обновления; CLI `rule-set match` без `domain_regex`; остальные различия синтаксиса Go и Rust regex; правила только с необработанными полями (например, `process_name`).

### SEC-08 / CQ-11 — DNS: ответ upstream не сверяется с запросом, ID предсказуем

- **Приоритет:** P1.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`2506df64e37b5a119c10724a5e7d6287f5e837d8`](https://github.com/Screamshow/xrust/commit/2506df64e37b5a119c10724a5e7d6287f5e837d8).
- **Файлы:** `crates/core-runtime/src/dns/{transport.rs,mod.rs}`, новый `crates/core-runtime/tests/dns_response_matching.rs`, `crates/core-runtime/tests/{dns_quic_h3.rs,dns_resolver.rs,dns_logical.rs}`.

#### Причина

- **UDP** (`dns/transport.rs:1163-1214`, `exchange_udp`): первая датаграмма на подключённом сокете принималась без проверки ID, вопроса и бита QR; таймер `timeout(1500ms)` перезапускался на каждой принятой датаграмме.
- **TCP / DoT** (`:1216-1233`, `exchange_stream`): первое сообщение принималось как есть.
- **DoH (h2, h1), DoQ, H3** (`:1235+`, `:1517`, `:1579`): ID 0 (как в эталоне), тело возвращалось без проверки вопроса.
- **ID upstream** (`dns/mod.rs:804`, `exchange_remote`): уходил ID клиента; `rand_id` (`:1305-1309`) — последовательный `AtomicU16` для bootstrap и `resolve`.
- ID клиента в ответе уже восстанавливался (`codec::set_id` в `exchange_target`, и при попадании в кэш).

#### Эталон (sing-box `824dbcfb4dd0a95921840b1737b950cde590241e`)

- `dns/transport/udp.go:147-153` — `writeQuery` подставляет `queryId`; `:158-172` — некорректные датаграммы отбрасываются, чтение продолжается.
- `dns/transport/multiplexer.go:357-387` — последовательный `queryId++` на запрос; `:452-462`, `:420-428` — ответы с неизвестным ID игнорируются, ID запроса восстанавливается; `:161-200` — `exchangeSingle` ID не проверяет; вопрос эталон не проверяет нигде.
- `dns/transport/https.go:212-214`, `quic/http3.go:158` — ID 0; ответ (`https.go:242-262`) без проверки ID и вопроса. `dns/client.go:291,389` — ID клиента восстанавливается.
- miekg/dns v1.1.72 и проверка `checkResponse` стандартного резолвера Go (бит ответа, ID, вопрос: имя без учёта регистра, тип, класс) — по памяти исполнителя, офлайн не сверялись. Итог: xrust строже эталона (проверка вопроса и QR, случайные ID).

#### Исправление

- Всё в `transport::exchange`, поэтому действует для всех вызывающих (сервис, участники групп, bootstrap `lookup_via`).
- `response_matches(query, resp, check_id)` разбирает «сырой» ответ без выделений: полный 12-байтовый заголовок с QR, тот же ID (при `check_id`), тот же первый вопрос — имя (ASCII без учёта регистра по меткам, безопасно для 0x20), тип и класс. Указатель сжатия или метка длиннее 63 в начале вопроса, имя длиннее 255, qdcount 0 или усечённое сообщение — несовпадение.
- **UDP:** несовпадающая датаграмма отбрасывается (debug-лог), ожидание продолжается; таймер повтора — абсолютный срок (`timeout_at`), поэтому поддельные датаграммы не сдвигают повторы; интервал 1,5 с, 3 попытки и общий `cfg.timeout` прежние.
- **TCP / DoT:** чтение кадров до совпадающего в пределах прежнего `cfg.timeout`.
- **После любого пути:** итоговая проверка (для DoH/DoQ/H3 — только вопрос); несовпадение — ошибка `dns: response does not match the query`; затем в ответ записывается ID вызывающего.
- **ID:** для `Udp | Tcp | Tls` на провод уходит свежий случайный ID из `getrandom::fill` (`random_id()`); при ошибке RNG обмен завершается ошибкой, предсказуемой замены нет. DoH/DoQ/H3 сохраняют ID 0 (TLS, поток на запрос; эталон так же). `rand_id()` в `mod.rs` берёт значение из `random_id()`.
- Запрос короче 12 байт — ошибка `dns: short query`.
- Новые лимиты, изменения кэша, таймаутов и соединений не вводились.

#### Изменения поведения

- Ответы с чужим ID, другим вопросом или без бита QR отбрасываются; если правильного ответа нет — прежний таймаут.
- На провод UDP/TCP/TLS уходит случайный ID, а не ID клиента.
- **Изменение тестов из-за более строгой проверки:** в `tests/dns_logical.rs` поддельный upstream возвращал запрос без бита QR — теперь он отвечает как сервер (тот же ID и вопрос, QR установлен); `tests/dns_resolver.rs` сравнивает запрос без поля ID (`raw[2..]`); в `dns/mod.rs` тестовый `bootstrap_fixture` отвечает совпадающим ответом без записи, чтобы по-прежнему быстро завершаться ошибкой декодирования; `tests/dns_quic_h3.rs` проверяет ID 0 на проводе и ID вызывающего в ответе.

#### Проверки разработки

- Сборки в постоянном месте candidate (рабочее дерево), отрицательные контроли — в baseline (`2144127` + новые тесты).

| Команда (`cargo test --locked -p core-runtime`) | legacy | rust-x |
|---|---|---|
| `rustfmt --edition 2024 --check` (изменённые файлы) | чисто | — |
| `clippy --all-targets --features legacy-protocols -- -D warnings` | чисто | в изменённых файлах DNS предупреждений нет |
| `--test dns_response_matching` | 10 passed | 10 passed |
| `--test dns_quic_h3` / `dns_logical` / `dns_hosts` / `dns_reverse_mapping` / `udp_dns_sniff` | 3 / 1 / 3 / 3 / 3 passed | 3 / 1 / 3 / 3 / 3 passed |
| `--test dns_resolver` | 19 passed | 18 passed, 1 failed (`tcp_transport_uses_the_detour_outbound` — socks нет в rust-x, так же на `HEAD`) |
| `--test routing` / `hot_reload` / `udp_sniff` / `inbounds` | 13 / 11 / 8 / 12 passed | 13 / 11 / 8 / 12 passed |
| `--lib dns::` (включая модульные `response_matching_checks_reply_bit_id_and_question`, `random_ids_are_not_a_counter`) | 66 passed | 66 passed |

- **Отрицательные контроли (baseline, legacy):** `dns_response_matching` — 2 passed, 8 failed: падают `udp_forged_reply_is_dropped_and_the_real_one_returned`, `udp_only_forged_replies_end_in_the_usual_timeout`, `udp_wire_ids_are_random_and_never_the_caller_id`, `udp_parallel_queries_each_get_their_own_answer`, `service_restores_the_client_id_after_a_forged_reply`, `tcp_forged_messages_are_skipped`, `tcp_only_forged_messages_end_in_the_usual_timeout`, `doh_answer_must_match_the_question`; проходят, как и ожидалось, `udp_matching_answer_is_accepted_with_the_caller_id`, `udp_question_name_case_does_not_matter`. `dns_quic_h3` — 0 passed, 3 failed (`doq_answer_to_another_question_is_refused`, `doq_transport_queries_a_local_server`, `h3_transport_queries_a_local_server` — старый транспорт возвращает ID 0 вместо ID вызывающего).

#### Ограничения

- В `main` не слито, не выпущено.
- Поведение miekg/dns и резолвера Go описано по памяти, офлайн не сверялось.
- OpenWrt, реальные DNS-серверы, DoH/DoQ против внешних серверов и полный CI не проверялись.
- **Соседние находки (не исправлялись):** нет повтора по TCP при бите TC в UDP-ответе (эталон повторяет, `udp.go:105-108`); ICMP port-unreachable на подключённом UDP-сокете сразу прерывает обмен — подделанный ICMP может вызвать отказ (без отравления).

Проверка Codex для SEC-08/CQ-11 и CQ-12 общая — см. раздел «Независимая проверка (Codex, SEC-08/CQ-11 и CQ-12)» в CQ-12.

### CQ-12 — bbolt: бесконечная рекурсия на повреждённом cache.db

- **Приоритет:** P1.
- **Статус:** исправлено, проверено в границах, указанных ниже. В `main` не слито, не выпущено.
- **Коммит:** [`41c8be591e4c8a664a480498f1aec47192923761`](https://github.com/Screamshow/xrust/commit/41c8be591e4c8a664a480498f1aec47192923761).
- **Файлы:** `crates/core-experimental/src/bbolt.rs` (только чтение; writer не менялся), `crates/core-runtime/src/cache_file.rs` (путь открытия и `read_all`), новые `crates/core-experimental/tests/corrupt_pages.rs` (10 тестов), `crates/core-runtime/tests/cache_file_corrupt.rs` (2 теста).

#### Причина

- `bbolt.rs` `find_in_page` (`:215`), `all_elems` (`:282`), `find_bucket_in` (`:350`) рекурсивно следовали дочерним страницам без учёта прочитанных и без ограничения глубины: страница, указывающая на себя, или цикл страниц — переполнение стека (exit 134); поддерево с несколькими родителями — обход на каждом пути (экспоненциально), `load_page` (`:309`) копировал каждую страницу.
- `load_page` не сверял номер страницы с `meta.pgid`; на подобранном номере `start + page_size` переполнялось (паника в debug, перенос на 32-битном release). Число элементов не сверялось с размером страницы, элементы могли перекрываться.

#### Исправление

- Ключи и значения заимствуются из образа файла, `load_page` возвращает срез.
- Каждый вызов (`get`, `has_bucket`, `bucket_names`, `bucket_page_raw`) ведёт множество прочитанных страниц, включая overflow; повторное попадание — ошибка `page N reached twice (page cycle or shared subtree)`. В корректном файле bbolt каждая страница принадлежит одному узлу, поэтому это ловит самоссылки, циклы, общие поддеревья и страницу внутри overflow другой страницы, а также ограничивает работу.
- Номер страницы: `2 <= pgid` и `pgid + overflow < meta.pgid`, вся арифметика размеров проверяемая (важно для 32-бит MIPS); корень meta ниже 2 отвергается при открытии.
- Глубина — не более 64 уровней ветвей на дерево bucket (bbolt держит не менее 2 детей на ветвь, реальная глубина ≈ log2 числа страниц; обе фикстуры — глубины 2). Множество посещённых страниц само по себе не останавливает длинную цепочку из разных страниц с одним потомком, поэтому нужен лимит глубины.
- Таблица элементов должна помещаться в страницу, ключи и значения страницы не могут в сумме превышать её размер, перекрытие — ошибка `page elements overlap`; один вызов возвращает не больше размера файла.
- Обе фикстуры (`tests/spikes/bbolt/golden.db`, записан Go bbolt, с inline-bucket; `cache-file-v0026.db`) проходят новые проверки.
- `cache_file`: список bucket читается один раз; нечитаемый корень — прежний путь `read failed (...); starting empty`, рантайм стартует без кэша; повреждённый bucket пропускается с предупреждением `bucket B unreadable (...); skipped`, остальные загружаются. Файл не удаляется, не переименовывается и не пишется при открытии. Flush не менялся: повреждённый файл, как и раньше, заменяется при следующей записи (по интервалу или размеру буфера при наличии изменений, при остановке `lib.rs:209`; при заданном `cache_id`, которого нет в файле, изменения есть сразу).

#### Изменения поведения

- Номера страниц за `meta.pgid`, корень ниже 2, overflow за пределом, перекрывающиеся элементы, более 64 уровней — теперь ошибки `InvalidData`, а не падение, зависание или молчаливое чтение.
- Повреждённый bucket пропускается, а не добавляется пустым.
- Если нечитаем список bucket верхнего уровня, весь кэш стартует пустым (раньше могли загрузиться известные bucket до повреждённой страницы).

#### Проверки разработки

- Сборки в candidate (`2144127` + файлы CQ-12, файлы DNS на тот момент возвращены к `HEAD`), отрицательные контроли — в baseline (`2144127` + новые тесты).

| Команда | Результат |
|---|---|
| `rustfmt --edition 2024 --check` (4 файла) | чисто |
| `clippy --locked -p core-experimental -p core-runtime --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто (после исправления `explicit_counter_loop` в тесте) |
| `cargo test -p core-experimental` | lib 1, `corrupt_pages` 10, `golden_roundtrip` 2, `writer_bytes` 1 — passed |
| core-runtime, оба профиля: `--lib cache_file` / `cache_file` / `cache_file_compat` / `cache_file_corrupt` / `cache_file_flush_alloc` / `cache_file_interop` | 1 / 10 / 5 (+1 ignored) / 2 / 1 / 1 passed |
| core-runtime, оба профиля: `fakeip_persistence` / `selector_persistence` / `hot_reload` | 6 / 1 / 11 passed |

- **Отрицательные контроли (baseline, каждый тест отдельно — переполнение стека роняет весь бинарник):** все 12 новых тестов падают: переполнение стека (SIGABRT) — `self_referencing_branch_is_an_error`, `page_cycle_inside_a_bucket_is_an_error`, `deep_page_chains_are_bounded`, `page_cycle_at_the_root_starts_empty_and_keeps_the_file`, `damaged_bucket_is_skipped_and_the_rest_loads`; `attempt to add with overflow` — `child_page_ids_outside_the_tree_are_errors`; неверный результат — `shared_subtrees_fail_fast`, `overflow_past_the_high_water_mark_is_an_error`, `root_on_a_meta_page_is_refused_at_open`, `a_page_inside_another_pages_overflow_is_an_error`, `overlapping_elements_are_an_error`, `element_count_past_the_page_is_an_error`.

#### Ограничения

- В `main` не слито, не выпущено.
- OpenWrt, 32-битные цели и полный CI не проверялись.
- **Соседние находки (не исправлялись):**
  1. Читатель всегда берёт meta-страницу 0, если она корректна, и не учитывает txid; bbolt выбирает более новую. В файле, записанном sing-box, meta 0 может быть старой транзакцией, чьи страницы уже переиспользованы; теперь это ошибка или устаревшие данные, а не падение.
  2. Нет fsync перед rename при flush (CQ-13): после отключения питания возможен «рваный» файл; теперь он обрабатывается без падения.
  3. Поиск обходит детей подряд, а не по ключу ветви — влияет только на скорость.
  4. Имена bucket читаются как lossy UTF-8; bucket с некорректным UTF-8 теперь логируется и пропускается.
  5. Writer кладёт маленькие и пустые bucket на отдельные страницы, где bbolt хранил бы их inline; совместимость сохраняется.

#### Независимая проверка (Codex, SEC-08/CQ-11 и CQ-12)

- **Объект:** CQ-12 `41c8be591e4c8a664a480498f1aec47192923761`, SEC-08/CQ-11 `2506df64e37b5a119c10724a5e7d6287f5e837d8`, checkout `b510b2ce56884de8025a0f42d278904f9dd20d9b`. Блокирующих замечаний не обнаружено.
- **Локально (WSL, rust-x) прошли 123 теста:** core-experimental 14, `cache_file` 10, `cache_file_compat` 5, `cache_file_corrupt` 2, `dns_logical` 1, `dns_quic_h3` 3, `dns_response_matching` 10, `hot_reload` 11, модульные `dns::` 66, дополнительный независимый тест 1. Генератор фикстуры штатно `ignored` и не засчитан.
- **Независимый DNS-тест:** сервер присылает неправильный ответ каждые 100 мс; при таймауте 3400 мс клиент делает три запланированные отправки и завершается по исходному таймауту. Прошёл локально и на VM.
- **Отрицательные контроли CQ-12:** «root на meta-странице» и «overflow за high-water mark» падают на прежнем bbolt и проходят на новом. Остальные отрицательные контроли разработки и DNS-контроли на старом коде независимо не повторялись.
- **OpenWrt 25.12.5 x86_64:** 26/26 — `corrupt_pages` 10, `cache_file_corrupt` 2, `dns_response_matching` 11 (с независимым тестом), `dns_quic_h3` 3. Проверены повреждённые деревья, сохранность файла и исправного bucket; DNS ID/question/QR, параллельные запросы, восстановление ID вызывающего, TCP, отрицательные DoH/DoQ и корректный H3. Отдельные release musl-бинарники запускались из `/tmp`. Пакеты, PID службы и контрольные суммы UCI `forkop`/`dhcp` и `config.json` до и после совпали.
- **Границы:** legacy, ARM, полный CI, пакетное обновление, WAN/LAN/nft и полный жизненный цикл службы не проверялись. Отдельных отрицательных стендов DoT/H3 не было. Исходники miekg/dns и Go не сверялись — эквивалентность им не заявляется. Полный фаззинг bbolt не выполнялся.
- **Остаются отдельными вопросами:** txid при выборе meta-страницы, fsync (CQ-13), повтор по TCP при усечённом UDP-ответе, прерывание UDP-обмена подделанным ICMP.

### CQ-13 (частично) — долговечность записи cache.db

- **Приоритет:** P1.
- **Статус:** исправлено частично, ожидает независимой проверки. В `main` не слито, не выпущено.
- **Объём:** исправлена только долговечность атомарной замены cache.db. **Не закрываются:** flush под блокировками и в асинхронных потоках, flush при каждой смене selector, тела rule set внутри cache.db, полные перезаписи раз в минуту при `store_fakeip`, выбор meta-страницы по txid.
- **Коммит:** [`6c7d0da0c6a481d091a0e681c4805517a09c8804`](https://github.com/Screamshow/xrust/commit/6c7d0da0c6a481d091a0e681c4805517a09c8804).
- **Файлы:** `crates/core-experimental/src/bbolt.rs` (новая `encode_ref`; `write_ref` прежний, без синхронизации), `crates/core-runtime/src/cache_file.rs` (`flush`, `replace_synced`, `sync_dir`, тесты `durable_flush_tests`).

#### Причина

- `cache_file.rs:320-322`: `flush` писал `<path>.db.tmp` через `bbolt::write_ref` (`fs::write`, `bbolt.rs:758`) и делал `rename` без синхронизации файла и каталога. После отключения питания cache.db мог оказаться пустым или «рваным» (rename попадает на диск раньше данных) либо rename терялся.

#### Исправление

- `flush`: образ из `bbolt::encode_ref` → `File::create(tmp)`, `write_all`, `sync_all` → `rename(tmp, path)` → `sync_all` родительского каталога (Unix). Пустой родитель (голое имя `cache.db`) — текущий каталог `.`; `dir/cache.db` — `dir`. Синхронизация добавлена только для cache.db; другие вызовы общего writer не меняются. Формат, байты, периодичность и условия flush прежние.
- **Ошибка до или во время rename:** cache.db не тронут, временный файл удаляется (раньше оставался), ошибка возвращается, `dirty`, `pending` и `last_flush` не меняются — следующий flush повторяет запись целиком.
- **Ошибка синхронизации каталога после rename:** возвращается как `replaced, but directory sync failed: …`; прежний файл уже заменён, отката нет и он не заявляется; `dirty` остаётся установленным, поэтому следующий flush перезаписывает файл и снова синхронизирует каталог.
- `EINVAL` и `ENOTSUP` от fsync каталога считаются успехом — для файловых систем, которые не умеют синхронизировать каталоги (иначе `dirty` никогда бы не сбрасывался и каждый `put` вёл бы к полной перезаписи).
- Тестовый шов `sync_hook` (`#[cfg(all(test, unix))]`) записывает синхронизированные каталоги и может отказать в следующей синхронизации; в обычной сборке отсутствует.

#### Изменения поведения

- Каждый flush cache.db делает два fsync (файл и каталог). На tmpfs (путь Forkop X по умолчанию `/tmp/sing-box/cache.db`) это почти бесплатно; на flash (jffs2, ubifs, f2fs, ext4 на eMMC) fsync образа в несколько МБ может занимать десятки–сотни мс и добавляется к существующей стоимости flush (CQ-13, не исправлена).
- При ошибке до rename временный файл теперь удаляется.

#### Проверки разработки

- Сборки в candidate (рабочее дерево; файлы параллельной задачи XHTTP на время прогона возвращены к `HEAD`), отрицательный контроль — в baseline.

| Команда | Результат |
|---|---|
| `rustfmt --edition 2024 --check` (2 файла) | чисто |
| `clippy --locked -p core-experimental -p core-runtime --all-targets --features core-runtime/legacy-protocols -- -D warnings` | чисто; в rust-x новых предупреждений нет |
| `--lib cache_file::` (оба профиля; включая 5 новых `durable_flush_tests`) | 6 passed |
| rust-x: `cache_file` / `cache_file_compat` / `cache_file_corrupt` / `cache_file_flush_alloc` / `cache_file_interop` / `fakeip_persistence` / `hot_reload` | 10 / 5 (+1 ignored) / 2 / 1 / 1 / 6 / 11 passed |
| `cargo test -p core-experimental` | lib 1, `corrupt_pages` 10, `golden_roundtrip` 2, `writer_bytes` 1 — passed |

- **strace** (`strace -f -e trace=openat,write,fsync,fdatasync,rename,renameat,renameat2` на тестовом бинарнике):
  - абсолютный путь: `openat(".../cache.db.tmp", O_WRONLY|O_CREAT|O_TRUNC)` → `fsync` файла → `rename(".../cache.db.tmp", ".../cache.db")` → `openat(<каталог>, O_RDONLY)` → `fsync` каталога;
  - относительный путь (дочерний процесс с `current_dir` во временном каталоге): `cache.db.tmp` → `fsync` → `rename("cache.db.tmp","cache.db")` → `openat(".")` → `fsync`; затем то же для `dir/cache.db` с `openat("dir")`.
- **Отрицательный контроль** (baseline `26f105b` + новый `cache_file.rs`, `flush` возвращён к `fs::write` + `rename`): падают `flush_syncs_the_parent_directory`, `directory_sync_error_is_reported_and_retried`, `relative_path_flush_syncs_the_right_directory`; проходят, как и ожидалось, `error_before_rename_keeps_old_file_and_retries` и `parent_of_a_bare_name_is_the_current_directory` (защищают от регрессий).

#### Ограничения

- В `main` не слито, не выпущено.
- Настоящий обрыв питания не проверялся: тесты проверяют только порядок вызовов и обработку ошибок.
- Ошибка записи временного файла после успешного создания (например, ENOSPC) отдельным тестом не проверялась; путь удаления тот же.
- Если процесс прерывается посреди записи, оставшийся временный файл при старте не удаляется (как и раньше).
- OpenWrt и полный CI не проверялись.
- **Соседние находки (не исправлялись):** запись через tmp + rename без fsync файла и каталога в `route/rule_set_remote.rs:150, :406, :484, :759` (кэш rule set и TSRS) и в `outbound/tailscale/service.rs:83` (файл состояния); `outbound/tailscale/control.rs:366-370` уже делает синхронизацию файла, rename и синхронизацию каталога — позже можно вынести общий помощник.
