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
| SEC-05 | HTTPS-загрузки rule-set и external_ui без проверки сертификата | P1 | исправлено, ожидает независимой проверки | `11ada8206da3ccdd5cbb54c6758133c7c290d362` |

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
- **Статус:** исправлено, ожидает независимой проверки. В `main` не слито, не выпущено.
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

#### Ограничения

- Независимая проверка ещё не проводилась.
- ARM, установка пакета и LuCI не проверялись.
- Связанные проблемы вне задачи, не исправлялись:
  - при явном `tls` у HTTP-клиента без `server_name` проверка идёт по имени `localhost`, а не по хосту из URL — для обычных серверов это отказ;
  - доверенные корни берутся из `webpki-roots 1.0.9` и `rustls-webpki 0.103.15` с известными advisory (BLD-02);
  - ошибка **начальной** загрузки remote rule-set по-прежнему завершает запуск — как при 404 или таймауте;
  - REALITY, pins при `insecure`, MASQUE и прочие находки TLS (SEC-01…03) не затрагивались.
