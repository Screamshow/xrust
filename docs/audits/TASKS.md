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
| CQ-03 | SRS-декодер: недоверенные счётчики и индексы, zlib без лимита | P0 | исправлено, ожидает независимой проверки | `fced50992b3ac7f12fb7136286b8c08d05dc9b32`, `ffb4988939fb376082ba427c609c618d2f7808ba` |
| CN-02 / MEM-01 | XHTTP packet-up не завершает сессию после закрытия клиентом: утечка fd и памяти | P0 | исправлено, ожидает независимой проверки | `9af27fd0f702c8fbc851ce1285c163f9d31224f5`, `22162e7822f9a03c174cfe57fd929c3224216e7e` |

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
- **Статус:** исправлено, ожидает независимой проверки. В `main` не слито, не выпущено.
- **Коммит:** [`fced50992b3ac7f12fb7136286b8c08d05dc9b32`](https://github.com/Screamshow/xrust/commit/fced50992b3ac7f12fb7136286b8c08d05dc9b32).
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

### CN-02 / MEM-01 — XHTTP packet-up не завершает сессию после закрытия клиентом

- **Приоритет:** P0 (в сводке аудита — №11): режим `auto` в Forkop X всегда даёт packet-up; по аудиту fd 114 → 908 и RSS 37 → 229 МБ за 6 минут.
- **Статус:** исправлено, ожидает независимой проверки. В `main` не слито, не выпущено.
- **Коммит:** [`9af27fd0f702c8fbc851ce1285c163f9d31224f5`](https://github.com/Screamshow/xrust/commit/9af27fd0f702c8fbc851ce1285c163f9d31224f5).
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
