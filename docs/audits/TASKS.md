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
  - путь с `Content-Length` (SEC-07): тело читается до заявленной длины, и лимит 64 МиБ проверяется только после чтения;
  - загрузка rule-set и external_ui без проверки сертификата (SEC-05).
