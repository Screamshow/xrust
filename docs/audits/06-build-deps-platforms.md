# Аудит 06: сборка, профили, размер, зависимости, платформы

Дата: 2026-10-23. Объект: `xrust` v0.0.26 (commit `c5f567c`), Forkop X (`forkop-x`, `components/action.uc`).
Автор: аудит. Код и конфигурация репозиториев не менялись. Коммитов, публикаций, подписей и обращений к зеркалу не было.

Обозначения статуса:
- **Подтверждено**: есть команда и цифры.
- **Гипотеза**: вывод сделан по коду, но не воспроизведён.
- **Не проверено**: проверить не удалось, причина указана.

## 0. Сводка

| ID | P | Статус | Кратко |
|---|---|---|---|
| BLD-01 | **P0** | подтверждено (достижимость по коду) | `ruzstd 0.8.3` — RUSTSEC-2026-0344 (7.5 high), OOM при распаковке сертификата zstd в uTLS-профиле `firefox` |
| BLD-02 | **P0** | подтверждено | `rustls-webpki 0.103.15` + `webpki-roots 1.0.9` — RUSTSEC-2026-0382/0381: доверие к emSign-интермедиатам с известными ключами |
| BLD-03 | P1 | подтверждено | `rustls 0.23.45` — 4 advisory, применима 0349 (откат PQ на классический обмен ключами); исправлено в 0.23.46 |
| BLD-04 | P1 | подтверждено | В CI нет cargo audit/deny/dependabot; вендоренные `[patch]`-крейты аудит не видит |
| BLD-05 | P2 | подтверждено (код) | tokio `AsyncFd<RawFd>` (RUSTSEC-2026-0386) в TUN, а TUN-fd вообще не закрывается: утечка при reload |
| BLD-06 | P2 | подтверждено | Профиль: `opt-level="s"` + `core-crypto`=3 даёт **−2,83 МБ (−27,7 %)**, скорость AEAD на x86 сохраняется |
| BLD-07 | P2 | подтверждено | Per-package `opt-level=3` для крипто-крейтов сейчас ничего не делают; при s/z без `core-crypto` скорость AES-GCM падает в 1,7–2,8 раза |
| BLD-08 | P2 | подтверждено | `-C force-unwind-tables=no` даёт −281 КиБ (−2,8 %) без потери функций |
| BLD-09 | P2 | подтверждено | Вендоренный h2: три изменения вместо одного документированного, +368 КиБ буферов на соединение, отставание от 0.4.20 |
| BLD-10 | P2 | подтверждено (код) | Forkop/упаковка: только `aarch64_cortex-a53`; на OpenWrt 24 `aarch64_generic`/`cortex-a72` rust-x не находится |
| BLD-11 | P2 | подтверждено | release.yml: x86_64 через `RUSTFLAGS` перекрывает `.cargo/config.toml`; бинарники к релизу не прикладываются, поэтому `openwrt-packages.yml` для новых тегов сломан; недостающие файлы дают warn |
| BLD-12 | P2 | подтверждено | Пробелы CI: тесты rust-x не запускаются (1189 ok / 139 fail), aarch64 не исполняется, toolchain плавает, нет `-D warnings` для rust-x |
| BLD-13 | P2 | подтверждено | Воспроизводимость: на одном хосте бит-в-бит, но в бинарнике 397 путей `/home/<user>/.cargo` |
| BLD-14 | P2 | подтверждено (код) | MIPS32: `std::sync::atomic::AtomicU64` в 5 файлах (сборка сломается), `TUNSETOFFLOAD` зашит под x86/ARM, переполнение `usize` в `mmap_set` на 32-битных |
| BLD-15 | P3 | подтверждено | armv7 собирается (10 824 572 Б); без NEON и без AES |
| BLD-16 | P3 | подтверждено | `lru 0.12.5` unsound ×2, `paste`/`rustls-pemfile` unmaintained, `yoke-derive 0.8.3` yanked, `rsa` Marvin (используется подпись RSA) |
| BLD-17 | P3 | подтверждено | 14 предупреждений rust-x: всё dead_code из legacy-протоколов, багов не прячут |
| BLD-18 | P3 | подтверждено | Документация расходится с фактом: `SIZING.md` (z, panic=abort «0 эффекта»), комментарии в Cargo.toml, `main.rs` про аллокатор |
| BLD-19 | P3 | подтверждено | Лицензии совместимы с GPL-3.0-only, но в пакете нет third-party notices; `Source:` указывает на другой репозиторий |
| BLD-20 | P3 | подтверждено | Дубли версий: rand 0.8/0.10, getrandom ×3, chacha20 ×2, hashbrown ×2, webpki-roots ×2, syn ×2 |

## 1. Методология и окружение

- Rust 1.99.1 (stable), cargo 1.99.1. Хост 28 ядер, load average 17–23 из-за параллельных аудиторов, поэтому время сборки и бенчмарки шумные (±10 %).
- `CARGO_TARGET_DIR` и рабочие файлы лежат в scratchpad: `<scratch>/{target-*,build}`.
- Все сборки шли с `--locked`, после введения сетевого запрета ещё и с `--offline`. Варианты профиля задавались только через `CARGO_PROFILE_RELEASE_*` и `--config`. Команда матрицы:
  `cargo build --locked -p core-cli --no-default-features --features rust-x --release --target aarch64-unknown-linux-musl` с переменной окружения варианта (скрипт `scratchpad/build/variant.sh`).
- Что поставлено на пользовательском уровне, без root:
  - `cargo-audit` и `cargo-bloat` в `scratchpad/tools`;
  - rustup-таргет `armv7-unknown-linux-musleabihf`;
  - rustup-компонент `llvm-tools` (llvm-objdump, llvm-nm, llvm-size).
  - nightly не ставился.
- Сетевые обращения до запрета пользователя:
  - cargo-audit клонировал RustSec advisory-db (HEAD `84d943a6`, 2026-10-23, 1351 advisory);
  - скачаны `.crate` h2 0.4.19/0.4.20 и blake3 1.8.7 с static.crates.io для диффа;
  - сделаны запросы к crates.io API и sparse-индексу (последние версии и yanked-статус 276 крейтов);
  - установлены инструменты.
- После запрета внешних подключений не было, все сборки шли `--offline`.
- Попытку `cargo update` в копии репозитория отклонил классификатор прав. Совместимость обновлений поэтому подтверждена только по semver и данным crates.io, сборкой не проверена.
- Ограничения:
  - нет qemu: aarch64 и armv7 бинарники не запускались;
  - нет `musl-gcc`: x86_64-musl (mimalloc) не собирается;
  - нет nightly: MIPS оценён только по коду;
  - loopback-throughput полного прокси-пути не измерялся. Путь mixed→direct идёт через `splice(2)` и от opt-level почти не зависит; для зашифрованных путей нужен локальный сервер, это не делалось.

## 2. Матрица сборок (aarch64-unknown-linux-musl, rust-x, если не указано иное)

Базовый бинарник `base` бит-в-бит совпал с `target/aarch64-unknown-linux-musl/release/tachyon-core` (sha256 `3692c4f2…6d71`), хотя собирался в другом `CARGO_TARGET_DIR`.

| Вариант | Параметр | Байт | Δ к base | gzip -9 | xz -9e | Сборка, с* |
|---|---|---:|---:|---:|---:|---:|
| **base** (релизный профиль) | opt 3, fat LTO, cgu 1, abort, strip symbols | **10 220 464** | — | 4 897 684 | 3 271 928 | 267 |
| strip_none | `STRIP=none` | 15 826 528 | +5 606 064 | 6 071 759 | 4 017 668 | 233 |
| full_legacy | default-фичи (`full`+`legacy-protocols`) | 11 666 672 | +1 446 208 (+14,2 %) | 5 563 232 | 3 749 800 | 256 |
| noclash | `--features core-config/full` (без `clash-api` и `core-cli/full`) | 9 726 296 | −494 168 (−4,8 %) | 4 675 240 | 3 157 268 | 219 |
| **opt_s** | `OPT_LEVEL=s` | **7 282 656** | −2 937 808 (−28,7 %) | 3 573 016 | 2 520 436 | 154 |
| **opt_z** | `OPT_LEVEL=z` | **6 251 840** | −3 968 624 (−38,8 %) | 3 262 922 | 2 438 020 | 132 |
| **s_cc** | `opt-level="s"` + `package.core-crypto.opt-level=3` | **7 386 880** | −2 833 584 (−27,7 %) | — | 2 557 920 | 144 |
| lto_thin | `LTO=thin` | 11 673 184 | +1 452 720 (+14,2 %) | 5 303 253 | 3 489 412 | 150 |
| lto_off | `LTO=false` (thin-local) | 10 560 592 | +340 128 (+3,3 %) | 4 958 262 | 3 325 340 | 140 |
| cgu16 | `CODEGEN_UNITS=16` | 10 974 664 | +754 200 (+7,4 %) | 5 183 382 | 3 434 820 | 177 |
| unwind | `PANIC=unwind` | 12 057 968 | +1 837 504 (+18,0 %) | 5 760 042 | 3 845 288 | 240 |
| uwt | `--config target.aarch64…rustflags=["-C","force-unwind-tables=no"]` | 9 932 752 | −287 712 (−2,8 %) | — | 3 243 532 | 220 |
| armv7 | `armv7-unknown-linux-musleabihf`, rust-lld через `--config` | 10 824 572 | (+604 108) | — | 3 516 992 | 222 |

\* Полная сборка с нуля под нагрузкой. Абсолютные секунды сравнивать грубо, но LTO и opt-level дают устойчивый тренд: s/z собираются примерно на 40–50 % быстрее.

Выводы:
- **`opt-level` — единственный крупный рычаг размера.** s даёт −2,94 МБ, z −3,97 МБ.
- `panic=abort` экономит 1,84 МБ. `SIZING.md` утверждает «0 эффекта», но тот замер был на Windows (BLD-18).
- fat LTO против thin даёт −1,45 МБ, `codegen-units=1` против 16 даёт −0,75 МБ. Текущие значения верны.
- `strip=symbols` верен. `strip=debuginfo` бессмыслен: debuginfo уже нет, лишние 5,6 МБ — это символы и `.debug_*` из std.
- legacy-protocols весит 1,45 МБ (+14 %). Профиль rust-x действительно их исключает.
- `clash-api` вместе с `core-cli/full` весят 483 КиБ. Это в 5 раз больше оценки `SIZING.md` («−0,1 МБ»). Forkop использует Clash API (теги `with_clash_api`), отключать нельзя, цифра приведена для бюджета.
- Состав разделов в base по `llvm-size -A`:
  - `.text` 8,11 МБ;
  - `.rodata` 0,97 МБ;
  - `.eh_frame` + `.eh_frame_hdr` 0,76 МБ, несмотря на `panic=abort`;
  - `.data.rel.ro` 0,36 МБ.

### 2.1. Производительность (x86_64-gnu, `core-crypto/tests/perf_aead.rs`)

Команда: `CARGO_PROFILE_RELEASE_OPT_LEVEL=<o> cargo test --release -p core-crypto --test perf_aead -- --ignored --nocapture`. Числа в GiB/s, размер записи 65535 Б, `afalg threshold: 0`.

| Шейп | opt 3 | opt s | opt z | opt s + core-crypto=3 |
|---|---:|---:|---:|---:|
| fastgcm seal gcm128 | 2,50 / 2,52 / 2,47 | 1,45 | 0,91 | **2,48** |
| fastgcm seal gcm256 | 1,87 / 1,88 / 1,90 | 1,11 | 0,72 | **1,86** |
| fastgcm open gcm128 (16 KiB) | 2,39 / 2,45 / 2,37 | 1,28 | 0,86 | **2,45** |
| fastchacha seal | 1,16 / 1,15 / 1,28 | 1,08 | 1,06 | **1,16** |
| крейт aes-gcm (Aes128Gcm) | 0,92 | **0,33** | 0,25 | 0,92 |
| крейт chacha20poly1305 | 1,01 | 0,37 | 0,32 | 1,01 |
| chachapoly, блок длины 2 Б, нс/оп | 340 | 814 | 1011 | — |

- **Подтверждено.** При глобальном s/z per-package `opt-level=3` для `aes`, `aes-gcm`, `ghash`, `chacha20`… скорость не сохраняют: крейтовый AES-GCM падает в 2,8 раза.
- **Подтверждено.** Добавление одного `core-crypto` в список override полностью восстанавливает скорость всех AEAD-путей на x86.
- **Гипотеза.** На aarch64 картина та же: `aese`/`pmull` в `s_cc` сохранились (958 и 157 против 1002 и 157 в base). Но NEON-сложений `add v.4s` 332 против 1872, а на aarch64 ChaCha идёт через крейт `chacha20`, не через x86-only `fastchacha`. Скорее всего, ChaCha на aarch64 при s частично деградирует. Нужен замер на устройстве (Cortex-A53). Возможно, придётся добавить в override `core-runtime` или `core-tls`.

### 2.2. ARM-crypto cfgs в aarch64-сборке

`llvm-objdump -d` бинарника base:

| Инструкция | aese | aesmc | aesimc | pmull | pmull2 | `add v*.4s` | sha256h |
|---|---:|---:|---:|---:|---:|---:|---:|
| base | 1002 | 904 | 22 | 83 | 74 | 1872 | 0 |

В не-stripped сборке (`llvm-nm -C`) есть символы:
- `aes::armv8::expand::*` и `aes::autodetect::aes_intrinsics::STORAGE` (runtime-детект);
- `polyval::backend::autodetect::mul_intrinsics::STORAGE`;
- `chacha20::backends::neon::*`;
- `core_crypto::fastgcm::v8::*` и `core_crypto::afalg::*`.

**Подтверждено:** все три cfg (`aes_armv8`, `polyval_armv8`, `chacha20_force_neon`) попадают в сборку. При этом `sha256h = 0`: `sha2 0.10.9` на aarch64 работает программно. Это касается только рукопожатий и HKDF, P3.

Объединение `--config target.….rustflags=[…]` с файловым массивом сохраняет ARM-cfgs: в `uwt` те же 1002 `aese`. Ловушка с `RUSTFLAGS` описана в BLD-11.

## 3. Состав бинарника (cargo-bloat, aarch64 rust-x, strip=none)

`cargo bloat --release -p core-cli --bin tachyon-core --no-default-features --features rust-x --target aarch64-unknown-linux-musl --crates -n 45`. `.text` 7,7 МиБ:

| Крейт | .text | Крейт | .text |
|---|---:|---|---:|
| core_runtime | 2,2 МиБ (28,5 %) | hickory_proto | 98 КиБ |
| std (+core/alloc generic) | 1,2 МиБ | serde_json | 93 КиБ |
| tokio | 908 КиБ | aho_corasick | 92 КиБ |
| core_config | 452 КиБ | quinn | 73 КиБ |
| rustls | 331 КиБ | brotli_decompressor | 66 КиБ (+120 КиБ словарь в .rodata) |
| h2 | 279 КиБ | ruzstd | 50 КиБ |
| regex_automata | 254 КиБ | num_bigint_dig + rsa | 78 КиБ |
| quinn_proto | 191 КиБ | smoltcp | 45 КиБ |
| core_tls | 147 КиБ | miniz_oxide | 39 КиБ |
| h3 | 144 КиБ | idna (+ICU, данные в .rodata) | 24 КиБ + ~45 КиБ |
| regex_syntax | 126 КиБ | core_crypto | 108 КиБ |

Разбивка `core_runtime` по модулям (`llvm-nm -S`, text):

| Модуль | Размер |
|---|---:|
| tailscale | 693 КиБ |
| dns | 408 |
| route | 370 |
| transport | 323 |
| masque | 253 |
| hysteria2 | 161 |
| wireguard | 141 |
| clash_api | 112 |
| udp | 101 |
| tun | 86 |
| shadowsocks | 11,5 (общие хелперы) |
| fptn | 2,9 |

Крупнейшие функции:
- `core_config::validate::validate_outbound` — 53,6 КиБ;
- `regex_automata::meta::strategy::new` — 50,5 КиБ;
- `core_runtime::start_inner` — 50,5 КиБ;
- `tailscale::engine::spawn_tailscale_engine_with_tun` — 47,5 КиБ;
- `RouterInner::build` — 46,9 КиБ.

Что и зачем тянется:
- **quinn, quinn-proto, h3, h3-quinn (~410 КиБ)** — Hysteria2, MASQUE, DoQ/DoH3. Нужны профилю rust-x.
- **hickory-proto (~100 КиБ + idna/ICU ~70 КиБ + rand 0.10/chacha20 0.10/getrandom 0.4)** — `idna` и `rand` в hickory-proto 0.26 не опциональны.
- **smoltcp** — userspace-стек для WireGuard, Tailscale и TUN. Нужен.
- **regex (~480 КиБ вместе с aho-corasick)** — правила `*_regex`. Фича `core-config/full → regex` ничего не отключает: `regex` в `core-runtime` не опционален.
- **brotli (~186 КиБ)** и **ruzstd (50 КиБ)** — декомпрессия сертификатов RFC 8879 для отпечатков uTLS. Brotli-энкодера в бинарнике нет.
- **rsa и p384** — проверка цепочек и серверная подпись. Нужны.
- **Tailscale (693 КиБ своего кода, плюс crypto_box и blake2)** — самый тяжёлый модуль. Есть в профиле rust-x, но не за фичей.
- **std backtrace-машинерия (gimli, rustc_demangle, libunwind ~70 КиБ)** остаётся даже при `panic=abort`. Убрать её можно только через nightly `-Zbuild-std` + `panic_immediate_abort`.

Что попадает в бинарник, хотя профилю rust-x не нужно:
- общие хелперы Shadowsocks и FPTN (~14 КиБ);
- legacy-ветки `core_config::validate` для исключённых протоколов, валидатор отвергает их сообщением;
- остальное убирает LTO. pkcs5, scrypt, pbkdf2, cbc, md5, cfb-mode имеют 0–1 КиБ.

Крупных лишних зависимостей нет. Значимый резерв размера — это профиль (BLD-06), а не граф зависимостей.

Дубли версий (`cargo tree -d -e normal`, BLD-20):

| Крейт | Версии | Источники |
|---|---|---|
| rand | 0.8.8 / 0.10.3 | rsa→num-bigint-dig / hickory-proto, quinn-proto |
| getrandom | 0.2 / 0.3 / 0.4 | rand_core 0.6 / прямой / rand 0.10 |
| chacha20 | 0.9.1 / 0.10.2 | прямой / rand 0.10 |
| hashbrown | 0.15 / 0.17 | lru 0.12 / std-путь |
| webpki-roots | 0.26 / 1.0 | shim / реальный |
| syn | 2 / 3 | build-time |

Всего в `Cargo.lock` 284 пакета, в нормальном графе rust-x для aarch64 — 215.

## 4. Аудит зависимостей

`cargo-audit audit --db <advisory-db> -f Cargo.lock`: 8 vulnerabilities, 5 warnings.

| Advisory | Крейт | Применимость к rust-x | Исправление |
|---|---|---|---|
| RUSTSEC-2026-0344 (7.5) | ruzstd 0.8.3 | **Да.** `core-tls/src/certificate_compression.rs:37`, zstd предлагается в `fingerprints.rs:1304` (`firefox`) | ruzstd ≥0.9.1: semver-break, правка `core-tls/Cargo.toml:29` |
| RUSTSEC-2026-0382 | rustls-webpki 0.103.15 | **Да**: проверка всех цепочек, `core-tls/src/verify.rs:569` | 0.103.16, `cargo update -p rustls-webpki` |
| RUSTSEC-2026-0381 | webpki-roots 1.0.9 | **Да**: `webpki_roots::TLS_SERVER_ROOTS` (`verify.rs:569`) | 1.0.10+ (есть 1.0.11), `cargo update -p webpki-roots@1.0.9` |
| RUSTSEC-2026-0349 (3.7) | rustls 0.23.45 | **Вероятно**: клиент rustls (DoH, rule-set, MASQUE, Tailscale) с резюмпцией по умолчанию и X25519MLKEM768 (`core-crypto/src/kx.rs:131`) | 0.23.46 |
| RUSTSEC-2026-0346/0347/0348 | rustls 0.23.45 | Нет: собственного `ClientSessionStore` нет, ECH не включён, фича `brotli` у rustls выключена (`cargo tree -e features`) | 0.23.46 (тот же апдейт) |
| RUSTSEC-2023-0071 (5.9) | rsa 0.9.10 | Частично: `core-crypto/src/sign/rsa.rs:22` подписывает приватным RSA-ключом (TLS-сервер с RSA-сертификатом). Исправленной версии нет | P3: рекомендовать ECDSA/Ed25519 для серверных инбаундов |
| RUSTSEC-2026-0386 (unsound) | tokio 1.53.1 | Да: `inbound/tun.rs:278` `AsyncFd::new(raw_fd)` | 1.53.3 / 1.54.1 + `AsyncFd<OwnedFd>` |
| RUSTSEC-2026-0253, -0002 (unsound) | lru 0.12.5 | Нет в релизе (`panic=abort`); в тестах (unwind) теоретически да | lru 0.18.2+ (API почти совместим) |
| RUSTSEC-2024-0436, RUSTSEC-2025-0134 | paste, rustls-pemfile | unmaintained | `rustls-pki-types::pem::PemObject`; paste — заменить макрос |
| yanked | yoke-derive 0.8.3 | proc-macro через ICU/idna, только build-time | точечный `cargo update -p yoke-derive` |

Yanked-статус проверен по sparse-индексу crates.io для всех 276 registry-пакетов: cargo-audit не смог обновить индекс. Найден один yanked — `yoke-derive 0.8.3`. Вендоренные `h2` и `blake3` cargo-audit не сканирует: у path-крейтов нет `source`.

### 4.1. C-код и build.rs

- `cc` используется в двух местах:
  - `blake3` build-deps, при фиче `pure` C не компилируется (`vendor/blake3/build.rs:8,345`);
  - `libmimalloc-sys 0.1.49` (mimalloc **v3.3.2**) только на x86_64.
- На aarch64 C-кода нет. На x86_64 нужен `musl-gcc` (`CC_x86_64_unknown_linux_musl`). Это противоречит правилу «no-c» из комментариев Cargo.toml (BLD-18).
- Индексы `mi_option_set(15, 0)` и `mi_option_set(43, 0)` в `core-cli/src/main.rs:602-603` соответствуют v3 (`purge_delay`, `allow_thp`). Но если включить фичу `v2`, индекс 43 молча станет невалидным.
- build.rs-крейты в графе: anyhow, crc32fast, curve25519-dalek, generic-array, getrandom ×2, heapless, icu_*_data, libc, libm, num-bigint-dig, num-traits, paste, portable-atomic, proc-macro2, quinn, quinn-udp, rustls, serde*, smoltcp, thiserror, zerocopy, zmij. Все чистый Rust.
- `ring` есть в `Cargo.lock`, но в граф aarch64 и x86_64 не входит.

### 4.2. Лицензии (215 крейтов rust-x)

| Лицензия | Число крейтов |
|---|---:|
| MIT/Apache-2.0 (dual) | 140 |
| MIT | 21 |
| Unicode-3.0 | 18 |
| BSD-3-Clause | 6 (curve25519/ed25519/x25519-dalek, subtle, alloc-*stdlib) |
| 0BSD | 2 (smoltcp, managed) |
| ISC | 2 (webpki, untrusted) |
| CDLA-Permissive-2.0 | 2 (webpki-roots) |
| Zlib | 1 (foldhash) |
| прочие | CC0/MIT-0 и др. |

Несовместимых с GPL-3.0-only нет (Apache-2.0 совместима с GPLv3).

Замечание (BLD-19): MIT, BSD и ISC требуют воспроизводить copyright notice при бинарном распространении. В APK/IPK (`scripts/package_openwrt.py`) лежат только бинарник, wrapper и build.json, файла third-party лицензий нет.

### 4.3. Вендоренные крейты

**vendor/h2** = crates.io `h2 0.4.19` (vcs `d57d1b85`). Дифф по исходникам, без Cargo.lock и dot-файлов, `scratchpad/build/h2.diff`:
1. `src/proto/streams/flow_control.rs:19`: `UNCLAIMED_DENOMINATOR` 2 → 32. Задокументировано в `Cargo.toml:12`.
2. `src/codec/framed_write.rs:64`: `DEFAULT_BUFFER_CAPACITY` 16 КиБ → 128 КиБ. **Не задокументировано.**
3. `src/codec/mod.rs:45-52`: read-буфер через `FramedRead::with_capacity(…, 256 KiB)`, upstream по умолчанию 8 КиБ. **Не задокументировано.**

Следствие: около 368 КиБ дополнительной памяти на каждое h2-соединение. Это касается клиента (gRPC, h2, DoH, XHTTP) и сервера: `h2io::server_builder` используется в инбаундах `inbound/transport.rs`. На роутере с 128–256 МБ ОЗУ много входящих h2-соединений превращаются в рычаг memory-DoS (гипотеза).

Upstream 0.4.20 (2026-10-06) содержит исправления надёжности без RUSTSEC:
- подсчёт refused streams в лимите локальных reset (класс rapid-reset);
- отказ при дублирующемся `content-length` с разными значениями;
- отказ на GOAWAY с ненулевым stream id;
- ответ без `:status`;
- гонка при shutdown.

RUSTSEC-2026-0258 (empty DATA flood) исправлен в 0.4.16, вендор 0.4.19 его уже содержит.

**vendor/blake3** = `blake3 1.8.7`, последняя версия. Изменения только в `src/lib.rs:1003-1013` (`derive_key_bytes`) и `src/hazmat.rs:560-570` (`hash_derive_key_context_bytes`). Описаны в `vendor/blake3/RUST-X-PATCH.md`. Алгоритм не тронут. Advisory по blake3 нет.

Процедура обновления (рекомендация):
1. `cargo download h2@X` / blake3, распаковать в `vendor/`.
2. Применить `vendor/*.patch`, хранить их отдельными файлами.
3. Сверить `diff -ru` с upstream в CI.

## 5. Платформы

| Платформа | Статус | Комментарий |
|---|---|---|
| aarch64 musl | собирается, релиз | не исполнялся (нет qemu, нет устройства) |
| x86_64 musl | локально не собирается | нужен `musl-gcc` для mimalloc; CI ставит `musl-tools` |
| **armv7 musleabihf** | **`cargo check` и release-сборка OK** | `--config target.armv7….linker="rust-lld"` + link-self-contained; 10 824 572 Б; те же 14 предупреждений |
| mips / mipsel (tier 3) | не проверено (нет nightly) | по коду: сломается сборка, см. BLD-14 |

Платформозависимые места в коде (`cfg(target_arch)`, атомики, ioctl, endian):

- `std::sync::atomic::AtomicU64` используется в `outbound/hysteria2.rs:8`, `dns/transport.rs:8`, `outbound/masque/mod.rs:783`, `outbound/transport/xhttp.rs:677,678,978,979,1255,1256,1617,1934,1984,1991` и в тесте `route/rule_set_remote.rs:697`.
  - На mips32 и powerpc32 `AtomicU64` в std нет, будет ошибка компиляции.
  - Комментарий `core-runtime/Cargo.toml` про `portable-atomic` выполнен только для `clash_state.rs`, `logging.rs`, `udp.rs`, `xmux.rs`.
- `inbound/tun.rs:1407` `TUNSETOFFLOAD = 0x400454d0` зашит под кодировку `_IOW` x86/ARM. На MIPS и PPC правильное значение `0x800454d0`.
  - Ошибка игнорируется (`let _ =`), а `vnet_hdr=true` остаётся. GSO-оффлоад там просто не включится: потеря скорости, не поломка (гипотеза).
  - `TUNSETIFF` берётся из `libc`, значение корректное.
- `SO_ORIGINAL_DST = 80` (`redirect.rs:95`) и `AF_ALG = 38` (`afalg.rs:52`) не зависят от архитектуры, корректно.
- Endian:
  - virtio_net_hdr читается через `from_ne_bytes` (`tun.rs:109-112`). Корректно для legacy-режима TUN (native endian).
  - `/proc/net` hex (`process.rs:89`) обрабатывается корректно.
  - WS-маска (`transport/mod.rs:676`) endian-нейтральна.
  - Кэш `.tsrs` (`mmap_set/compiler.rs:356`, `format.rs:48`) пишется и читается в native endian. Это нормально для локального кэша, но непереносимо между архитектурами.
- `route/mmap_set/matcher.rs:84-93` `slice_at`:
  - `count * size_of::<T>()` и `offset + byte_len` считаются без `checked_*`, а `overflow-checks=false`;
  - на 32-битных (armv7, mips) `u32 count × 16` переполняет `usize`, проверка границ обходится, получается `from_raw_parts` за пределы буфера. Достаточно повреждённого кэш-файла на флеше, например после потери питания;
  - выравнивание не проверяется (`&*(ptr as *const Header)` в `matcher.rs:70`). На MIPS невыровненный доступ — исключение и эмуляция ядром, в Rust это UB.
- Мягкое плавание: `core-cli/src/main.rs:30-45` определяет `fmaximum_num` для arm и mips. Авторы уже собирали armv6 и mips, то есть следы портирования есть.
- armv7: целевой CPU по умолчанию без NEON (`+v7,+vfp3,-neon`), аппаратного AES нет. AES-GCM пойдёт через `AF_ALG` (если откалибрует) или программно. Для ipq40xx (`arm_cortex-a7_neon-vfpv4`) имеет смысл добавить `-C target-feature=+neon`.

## 6. CI и релиз

Что проверяется:
- `fmt`;
- `clippy --features legacy-protocols -D warnings` (только полный профиль);
- `cargo test -p core-config --features rust-x --test rust_x_profile`;
- `cargo check --features rust-x` без `-D warnings`;
- `cargo test --workspace --features legacy-protocols`;
- привилегированные тесты exit_gate/inbounds;
- дифференциальный тест против sing-box-lx (полный профиль);
- cross-сборка rust-x для x86_64 и aarch64 musl с бюджетом ≤12 МиБ.

Чего нет (BLD-12):
- тестов runtime в профиле rust-x. Я запустил `cargo test --workspace --no-default-features --features rust-x --no-fail-fast`: **1189 passed, 139 failed, 15 ignored**. Почти все падения — тесты исключённых протоколов (golden-корпус, trojan/vmess/ss/socks/fptn/openvpn-паритет), тесты не знают о профиле.
  - Отдельно: `clash_state::tests::registration_after_switch_is_not_closed_by_that_switch` упал один раз под нагрузкой, в 40 одиночных и 3 полных повторах не воспроизвёлся. Это flaky-тест.
  - Runtime-сообщение для исключённых протоколов — «outbound type "socks" not implemented yet» (вводит в заблуждение), а `check` пишет «excluded from Rust X»;
- исполнения aarch64-бинарника (qemu-user) и тестов на aarch64;
- cargo audit, cargo deny, dependabot (BLD-04);
- pinned toolchain: `rust-toolchain.toml` отсутствует, везде `stable`. Релиз в разные дни собирается разными rustc;
- `--locked` в `scripts/size.sh:11` и в CI-шагах `test`/`clippy`.

`cargo clippy --workspace --all-targets --no-default-features --features rust-x` даёт только 14 rustc dead_code-предупреждений, clippy-lint'ов нет. Так что `-D warnings` для rust-x добавляется дёшево после cfg-гейтинга.

Подпись и пакеты (только чтение):
- `sign_openwrt.py` сверяет входные sha256 с манифестом и подписывает только APK (`adbsign`). Затем делает `apk verify` по одному доверенному ключу и сохраняет `unsigned_sha256`.
- `finalize_release.py`:
  - проверяет, что релиз — draft;
  - проверяет совпадение тега с `binary_source_commit` через `gh api`;
  - валидирует 4 ассета (версия, размер, sha256);
  - подписывает на зеркале, сверяет digest ассетов после загрузки;
  - публикует только с `--publish`.
- Ключ не покидает хост. Логика выглядит корректной.
- Слабые места:
  1. IPK не подписаны, их целостность держится только на `SHA256SUMS` с GitHub.
  2. Манифест валидируется против самого себя (из того же draft), независимой сверки `binary_sha256` в `build.json` с CI-артефактом нет.
  3. `release.yml` и `openwrt-packages.yml` запускают `package_openwrt.py` через `sudo`.
- Reproducible build:
  - на одном хосте бит-в-бит (см. §2);
  - между машинами нет: в бинарнике 397 строк `~/.cargo/registry/src/index.crates.io-…` (BLD-13);
  - `SOURCE_DATE_EPOCH=0` задан только в `openwrt-packages.yml`, mtime=0 для tar/gzip уже выставляется в скрипте.

## 7. Предупреждения rust-x (все 14, `cargo check --workspace --no-default-features --features rust-x`)

| # | Файл:строка | Что | Оценка |
|---|---|---|---|
| 1 | `inbound/udp.rs:180` | `DatagramFrame::Shadowsocks` не конструируется | legacy SS-инбаунд, не баг |
| 2 | `inbound/udp.rs:274` | `ReplyTarget::Shadowsocks` | то же |
| 3 | `outbound/fptn/proto.rs:290` | `encode_ip_assignment` | FPTN исключён |
| 4 | `outbound/quic.rs:242` | `tuic` | TUIC исключён |
| 5 | `outbound/quic.rs:28` | `TUIC_MAX_UDP` | то же |
| 6–10 | `outbound/quic.rs:351,360,382,386,431` | `sing_addr_*` хелперы | кодек адресов TUIC |
| 11 | `outbound/quic.rs:66` | `CongestionKind::{Cubic,NewReno}` | конструируются только TUIC и Naive; Hysteria2 всегда BBR (`hysteria2.rs:180,288`, brutal → BBR с warn) |
| 12 | `outbound/shadowsocks/crypto.rs:124` | `Method::open` | SS-инбаунд |
| 13 | `outbound/transport/h3io.rs:19` | `H3Stream` | используется только Naive (`naive.rs:500`) |
| 14 | `outbound/transport/h3io.rs:36` | `H3Stream::new` | то же |

Багов предупреждения не прячут: каждое объясняется исключённым протоколом. Но они создают шум, на фоне которого новый настоящий dead_code в rust-x станет незаметен (BLD-17).

## 8. Находки

### BLD-01 — ruzstd 0.8.3: OOM от сервера в uTLS-рукопожатии
- **Статус:** подтверждено по advisory и достижимости в коде. Эксплойт не воспроизводился. **P0.**
- **Где:** `crates/core-tls/Cargo.toml:29` (`ruzstd = "0.8"`), `crates/core-tls/src/certificate_compression.rs:35-43`, `crates/core-tls/src/fingerprints.rs:1304` (firefox предлагает zlib, brotli и zstd).
- **Причина:** RUSTSEC-2026-0344. В ruzstd до 0.9.1 вывод одного блока не ограничен, кадр меньше 128 КБ аллоцирует гигабайты. Внешний `.take(expected+1)` и лимит 1 МиБ на `expected` не помогают: аллокация происходит внутри декодера, до возврата байтов.
- **Последствия:**
  - сервер или активный MITM (до аутентификации сервера: CompressedCertificate приходит раньше проверки) роняет процесс по OOM;
  - на роутере OOM-killer может зацепить и соседние процессы;
  - атаковать может любой, кто контролирует путь, в том числе DPI-цензор.
- **Исправление:** `ruzstd = "0.9.1"` (MSRV 1.87, проект 1.89). API `StreamingDecoder::new` сверить при сборке. До обновления временно не декодировать zstd (вернуть ошибку для алгоритма 3), отпечаток при этом не меняется.
- **Выигрыш:** закрыт удалённый DoS.
- **Риск:** низкий, затрагивается только путь RFC 8879 zstd.
- **Forkop X:** нужен новый пакет rust-x, обычное обновление. Откат на 0.0.26 возвращает уязвимость. Размер ±0.

### BLD-02 — rustls-webpki 0.103.15 и webpki-roots 1.0.9: доверие к скомпрометированным emSign-интермедиатам
- **Статус:** подтверждено. **P0** (по шкале: уязвимость в используемой зависимости, к тому же ключи публичны).
- **Где:** `Cargo.lock` (rustls-webpki 0.103.15, webpki-roots 1.0.9 под shim 0.26.11), `crates/core-tls/Cargo.toml:26,30`, `crates/core-tls/src/verify.rs:569`.
- **Причина:** RUSTSEC-2026-0382 и RUSTSEC-2026-0381.
- **Последствия:** цепочка через distrusted emSign-интермедиат с известным приватным ключом принимается. Получается MITM любого TLS с проверкой сертификата: DoH/DoT, скачивание rule-set, VLESS+TLS без pinning, Tailscale control.
- **Исправление:** `cargo update -p rustls-webpki -p webpki-roots@1.0.9` (semver-совместимо: 0.103.16 и 1.0.11 уже есть). Сборкой не проверено, апдейт запрещён ограничениями аудита.
- **Выигрыш:** закрыт MITM-вектор.
- **Риск:** минимальный.
- **Forkop X:** пакет `ca-bundle` (зависимость пакета) не используется этим путём: корни зашиты в бинарник. Нужна новая версия rust-x. Размер примерно −1 КиБ.

### BLD-03 — rustls 0.23.45
- **Статус:** подтверждено. **P1.**
- **Где:** `Cargo.lock`, `crates/core-tls/Cargo.toml:11`, `crates/core-crypto/src/kx.rs:131`.
- **Причина:** RUSTSEC-2026-0349. Незааутентифицированный ServerHello запоминает группу, и последующие соединения к имени идут без ML-KEM.
- **Применимость остальных:**
  - 0346 нет: своего `ClientSessionStore` нет;
  - 0347 нет: ECH не используется;
  - 0348 нет: фича `brotli` у rustls выключена.
- **Последствия:** потеря PQ-конфиденциальности («harvest now, decrypt later») для клиентских соединений через rustls.
- **Исправление:** `cargo update -p rustls` до 0.23.46.
- **Выигрыш:** PQ-гарантия.
- **Риск:** низкий.
- **Forkop X:** обычное обновление, размер ±0.

### BLD-04 — нет автоматического аудита зависимостей
- **Статус:** подтверждено. **P1.**
- **Где:** `.github/workflows/ci.yml` (нет шага), нет `.github/dependabot.yml` и `deny.toml`, `Cargo.toml:18-21` (`[patch.crates-io]`).
- **Причина:** 8 vulnerabilities, из них 4 пришли за последние 2 недели (2026-10-11…20), и никто не узнал. Вендоренные `h2` и `blake3` cargo-audit не видит: path-крейты.
- **Исправление:**
  - шаг `cargo audit --deny warnings` или `cargo deny check advisories bans licenses` в CI и по cron;
  - dependabot для cargo и github-actions;
  - для вендора скрипт сверки «версия vendor ≥ последний патч-релиз с исправлениями» и ручной проверки advisory по имени.
- **Выигрыш:** реакция на CVE за часы вместо случайности.
- **Риск:** шум, лечится через allowlist (`rsa`, `paste`).
- **Forkop X:** косвенно: меньше уязвимых версий на роутерах.

### BLD-05 — TUN: `AsyncFd<RawFd>` и незакрываемый fd
- **Статус:** код подтверждён. Утечка при reload — гипотеза, не воспроизводилась (нужны CAP_NET_ADMIN и /dev/net/tun). **P2.**
- **Где:** `crates/core-runtime/src/inbound/tun.rs:173,278` (`AsyncFd::new(raw_fd)`), `tun.rs:569-582` (`Drop` не делает `close`), `tun.rs:1419` (`open` без `O_CLOEXEC`).
- **Причина:**
  - RUSTSEC-2026-0386: I/O safety при `AsyncFd<RawFd>`;
  - fd TUN нигде не закрывается: `close` есть только на ошибочных путях `open_tun`.
- **Последствия:**
  - при hot-reload (Forkop использует reload rust-x) остаётся старый fd, а с ним и TUN-интерфейс;
  - повторный `TUNSETIFF` с тем же именем может получить `EBUSY`, либо копятся fd;
  - без `O_CLOEXEC` fd наследуется дочерними процессами.
- **Исправление:** `OwnedFd::from_raw_fd` → `AsyncFd<OwnedFd>`, `O_CLOEXEC`, tokio ≥1.53.3.
- **Выигрыш:** корректный reload TUN.
- **Риск:** низкий.
- **Forkop X:** надёжность hot-reload и отката без перезапуска процесса.

### BLD-06 — профиль: `opt-level="s"` + `core-crypto`=3
- **Статус:** размер подтверждён (aarch64). Скорость AEAD подтверждена на x86_64. Скорость на aarch64 и сквозная пропускная способность не проверены. **P2.**
- **Где:** `Cargo.toml` `[profile.release] opt-level = 3`.
- **Причина:** профиль ориентирован на скорость, а размер `.text` при s падает на 2,9 МБ.
- **Цифры:**

  | Вариант | Байт | Δ к base | xz |
  |---|---:|---:|---:|
  | base | 10 220 464 | — | 3 271 928 |
  | s_cc | 7 386 880 | −2 833 584 (−27,7 %) | 2 557 920 |
  | opt_z | 6 251 840 | −38,8 % | — |

  - z не рекомендую: fastgcm в z теряет 64 %, короткие записи ChaCha в 3 раза медленнее.
  - s + `core-crypto`=3 сохраняет fastgcm и fastchacha на x86 в пределах шума (2,48 против 2,50 GiB/s).
  - Сборка s в 1,7 раза быстрее.
- **Исправление:**
  1. `opt-level = "s"` и `[profile.release.package.core-crypto] opt-level = 3`.
  2. Замерить на Cortex-A53: AES-GCM, ChaCha (NEON-сложений в s_cc в 5,6 раза меньше) и `scripts/bench/bench.py` (mixed, VLESS-Vision, Hysteria2, XHTTP).
  3. При деградации ChaCha добавить в override `core-runtime` и/или `core-tls` и перемерить.
- **Выигрыш:** −2,8 МБ на флеше. rust-x (7,39 МБ) станет меньше UPX-пакета Sing-Box X (payload ARM64 8,63 МБ). При свободном месте пользователей 3,6–7,9 МиБ (скриншоты в `forkop-x/docs/sing-box-storage-review-2026-10-09.md`) это решающая разница. RSS по коду тоже уменьшится.
- **Риск:** регрессия скорости вне AEAD (tokio, h2, quinn, relay-циклы). Нужен A/B на устройстве.
- **Forkop X:** preflight в `action.uc:778-790,857-880` считает payload, требование к flash снижается примерно на 2,77 МиБ. Установка и обновление проходят на большем числе роутеров. На F2FS (без сжатия) выигрыш полный. На UBIFS и JFFS2 меньше: ФС сама сжимает, Forkop считает логический размер.

### BLD-07 — per-package `opt-level=3` бесполезны в текущем виде
- **Статус:** подтверждено (перф-таблица §2.1). **P2.**
- **Где:** `Cargo.toml:86-90` (комментарий «size-first profile above») и `Cargo.toml:91-125` (список из 17 крейтов без `core-crypto`).
- **Причина:**
  - при `opt-level=3` глобально overrides ничего не делают;
  - при s/z не помогают: generic-инстанциации (`AesGcm<Aes128>`, `ChaCha20Poly1305`) и `core_crypto::fastgcm` компилируются в downstream-крейтах. Результат — 0,33 вместо 0,92 GiB/s.
- **Исправление:** добавить `core-crypto` (это ключевое), убрать бесполезные пункты или пояснить их, исправить комментарий.
- **Выигрыш:** корректная основа для BLD-06.
- **Риск:** нет.
- **Forkop X:** косвенно.

### BLD-08 — unwind-таблицы при `panic=abort`
- **Статус:** подтверждено. **P2.**
- **Где:** `.cargo/config.toml:` `[target.aarch64-unknown-linux-musl] rustflags` и аналог для x86_64.
- **Причина:** `.eh_frame` занимает 673 КиБ, `.eh_frame_hdr` 87 КиБ. Rust генерирует uwtables по умолчанию, даже при abort.
- **Исправление:** добавить `"-C","force-unwind-tables=no"`. Проверено: 9 932 752 Б (−287 712), `.eh_frame` 673 → 391 КиБ (остаток — prebuilt std), ARM-crypto на месте (1002 `aese`).
- **Выигрыш:** −281 КиБ. Вместе с BLD-06 эффект суммируется (не измерено вместе).
- **Риск:** нет бэктрейсов: при strip=symbols и abort их и так нет. Профайлеры по DWARF-CFI на устройстве работать перестанут.
- **Forkop X:** −0,27 МиБ на флеше.

### BLD-09 — вендоренный h2: недокументированные буферы и отставание
- **Статус:** подтверждено (дифф). Память — гипотеза. **P2.**
- **Где:** `vendor/h2/src/codec/framed_write.rs:64`, `vendor/h2/src/codec/mod.rs:45-52`, `vendor/h2/src/proto/streams/flow_control.rs:19`, `Cargo.toml:12-19`.
- **Причина:** три изменения, задокументировано одно. Версия 0.4.19, upstream 0.4.20 с пятью исправлениями надёжности протокола.
- **Последствия:** около +368 КиБ на h2-соединение, в том числе на входящих (`server_builder`). Не получены исправления 0.4.20 (refused-stream reset limit и другие).
- **Исправление:**
  - перебазировать патчи на 0.4.20, хранить `vendor/h2.patch`;
  - вынести 128/256 КиБ в задокументированные константы, оценить меньший read-буфер, например 64 КиБ;
  - попробовать upstream-API `initial_connection_window_size` и `max_send_buffer_size` для части эффекта.
- **Выигрыш:** надёжность и память.
- **Риск:** регресс tput gRPC, нужен перемер vmess-grpc и vless-grpc.
- **Forkop X:** память на роутере, размер ±0.

### BLD-10 — архитектуры aarch64 в пакетах и Forkop
- **Статус:** код подтверждён, на устройствах не проверялось. **P2.**
- **Где:** `scripts/package_openwrt.py:65` (только `aarch64_cortex-a53` и `x86_64`), `forkop-x/forkop/files/usr/lib/components/action.uc:1952-1956` (сравнение с `DISTRIB_ARCH` строго на равенство, исключение только `apk` + `aarch64`).
- **Причина:**
  - бинарник собирается под generic ARMv8-A без `target-cpu`, поэтому подходит любому aarch64;
  - пакет помечен только a53, а на opkg (OpenWrt 24) для `aarch64_generic` (rockchip, NanoPi R4S/R5S/R6S) и `aarch64_cortex-a72` (bcm2711, RPi4) ассет не найдётся, и opkg отвергнет архитектуру.
- **Исправление:**
  - паковать тот же бинарник ещё под `aarch64_generic` и `aarch64_cortex-a72` (+4 файла в манифесте, `finalize_release.py:29` ожидает ровно 4);
  - в Forkop сопоставлять через `resolve_arch_candidates()` (`action.uc:1522`), а не по равенству `DISTRIB_ARCH`.
- **Выигрыш:** поддержка популярных aarch64-роутеров без новой сборки.
- **Риск:** низкий. Без аппаратного AES (RPi4/bcm2711) скорость упадёт: runtime-детект откатится на soft AES или AF_ALG.
- **Forkop X:** установка и обновление на новых классах устройств, откат не затрагивается.

### BLD-11 — релизный pipeline
- **Статус:** подтверждено (чтение YAML). **P2.**
- **Где:** `.github/workflows/release.yml:51,70-73` (`RUSTFLAGS` для x86_64), `release.yml:119` (`if-no-files-found: warn`), `release.yml:175-183` (`files:` без `rust-x-*.tar.gz`, `fail_on_unmatched_files: false`), `.github/workflows/openwrt-packages.yml:26`.
- **Причина и последствия:**
  1. `RUSTFLAGS` полностью перекрывает `target.x86_64….rustflags` из `.cargo/config.toml`. Сейчас набор эквивалентен (нет только `target-cpu=x86-64`, это дефолт). Но любой новый флаг в config попадёт в CI cross-сборку и **не попадёт** в релиз: это ровно тот класс ошибки, что уже дал 0,03 GiB/s на A53 (комментарий в config).
  2. Бинарные tar.gz к релизу не прикладываются, а `openwrt-packages.yml` их скачивает. Для релизов из `release.yml` ручная перепаковка сломана.
  3. Пропавший артефакт даёт только warning, draft соберётся частично. `finalize_release.py` потом упадёт на «ровно 4 ассета», но поздно.
- **Исправление:**
  - убрать шаг `Link musl with rust-lld` (config уже содержит всё);
  - `if-no-files-found: error`, `fail_on_unmatched_files: true`;
  - приложить `rust-x-*.tar.gz` и их хэши или переписать `openwrt-packages.yml`.
- **Выигрыш:** протестированный бинарник совпадает с релизным.
- **Риск:** нет.
- **Forkop X:** исключается выпуск пакета, собранного не так, как в CI.

### BLD-12 — пробелы CI-тестирования
- **Статус:** подтверждено. **P2.**
- **Где:** `.github/workflows/ci.yml:29-33`.
- **Причина:**
  - runtime-тесты rust-x не гоняются (локально 1189/139/15);
  - нет `-D warnings` для rust-x;
  - aarch64 не исполняется;
  - `stable` не закреплён;
  - нет `--locked` в test, clippy и `scripts/size.sh:11`.
- **Исправление:**
  - пометить legacy-тесты `#[cfg(feature = "legacy-protocols")]`, после этого `cargo test --no-default-features --features rust-x` в CI;
  - `cargo clippy … --features rust-x -- -D warnings`;
  - job с `qemu-user-static` и `cargo test --target aarch64-unknown-linux-musl` через `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER`, хотя бы `core-crypto` (fastgcm/v8, afalg) и smoke `check`;
  - `rust-toolchain.toml` с точной версией;
  - исправить flaky `clash_state` и сообщение «not implemented yet» для исключённых протоколов.
- **Выигрыш:** ловить регрессии именно поставляемого профиля и архитектуры.
- **Риск:** время CI.
- **Forkop X:** меньше откатов на роутерах.

### BLD-13 — воспроизводимость между машинами
- **Статус:** подтверждено (`strings` даёт 397 путей). **P2.**
- **Где:** `.cargo/config.toml` (нет `--remap-path-prefix`).
- **Причина:** пути `$CARGO_HOME/registry/src/…` из `panic!`/`Location` попадают в бинарник. Хэш зависит от домашнего каталога сборщика, в бинарник утекает имя пользователя.
- **Исправление:** в rustflags для обоих таргетов `"--remap-path-prefix", "<CARGO_HOME>=/cargo"` (через `CARGO_HOME` в CI) или `trim-paths`, когда стабилизируют. Плюс закрепить toolchain (BLD-12).
- **Выигрыш:** независимая проверка релиза пересборкой, несколько КиБ строк.
- **Риск:** нет.
- **Forkop X:** можно будет сверить `binary_sha256` из `build.json` с собственной пересборкой.

### BLD-14 — MIPS и 32-битные платформы
- **Статус:** по коду. MIPS не собирался (нет nightly). **P2** — если MIPS в планах (mipsel_24kc, MT7621, самая массовая платформа OpenWrt), иначе P3.
- **Где:** `AtomicU64` из std в `outbound/hysteria2.rs:8`, `dns/transport.rs:8`, `outbound/masque/mod.rs:783`, `outbound/transport/xhttp.rs:677…1991`; `inbound/tun.rs:1407`; `route/mmap_set/matcher.rs:84-93,70`.
- **Причина и последствия:**
  - ошибка компиляции на mips32;
  - не включается GSO-оффлоад TUN на MIPS/PPC;
  - на 32-битных (включая armv7, который собирается) переполнение в проверке границ `slice_at` даёт выход за пределы буфера на повреждённом `.tsrs`;
  - невыровненные ссылки — UB.
- **Исправление:**
  - `portable_atomic::AtomicU64` во всех местах (lint `disallowed-types` в clippy.toml);
  - `TUNSETOFFLOAD` через `libc::_IOW` / `nix::request_code_write!`;
  - `checked_mul`/`checked_add` и проверка выравнивания (`align_offset`) или `read_unaligned` в `mmap_set`.
- **Выигрыш:** путь к MIPS и безопасность на armv7.
- **Риск:** низкий.
- **Forkop X:** сейчас MIPS-устройства rust-x не получают. Пакеты для них потребуют отдельной ветки манифеста.

### BLD-15 — armv7
- **Статус:** подтверждено (сборка). **P3.**
- **Где:** `.cargo/config.toml` (нет секции armv7).
- **Цифры:** с `--config` linker=rust-lld и link-self-contained release собирается за 222 с, 10 824 572 Б, xz 3 516 992.
- **Исправление (если нужна платформа):** секция `[target.armv7-unknown-linux-musleabihf]` как у aarch64. Для `arm_cortex-a7_neon-vfpv4` добавить `+neon` и `chacha20_force_neon` (проверить совместимость cfg на ARMv7). Сначала BLD-14 (`mmap_set`).
- **Риск:** скорость без AES.
- **Forkop X:** +2 ассета (`arm_cortex-a7_neon-vfpv4`, `arm_cortex-a9_vfpv3-d16`). Размер как у aarch64, при s около 7,5 МБ (экстраполяция).

### BLD-16 — второстепенные advisories
- **Статус:** подтверждено. **P3.**
- **Где:** `Cargo.toml:71` (lru 0.12), `Cargo.toml:78` (rustls-pemfile), `crates/core-crypto/Cargo.toml` (paste, rsa), yanked `yoke-derive 0.8.3`.
- **Исправление:** lru → 0.18.2+, `PemObject` из rustls-pki-types, точечный `cargo update -p yoke-derive`. Для `rsa` (Marvin, исправления нет) — документировать: предпочитать ECDSA/Ed25519 ключи для серверных TLS-инбаундов.
- **Forkop X:** нет.

### BLD-17 — 14 предупреждений rust-x
- **Статус:** подтверждено (§7). **P3.**
- **Исправление:** `#[cfg(feature = "legacy-protocols")]` на перечисленные элементы или на модули TUIC, FPTN, SS-inbound и `h3io`, затем `-D warnings` в CI.
- **Выигрыш:** около 0 байт (LTO уже выбрасывает), но сигнал о новом мёртвом коде.
- **Риск:** нет.

### BLD-18 — документация не совпадает с фактом
- **Статус:** подтверждено. **P3.**
- **Где:**
  - `docs/SIZING.md`: «opt-level = "z"», «panic=abort ничего не даёт», «без clash_api −0,1 МБ»;
  - `Cargo.toml:86` «size-first profile above»;
  - `crates/core-cli/src/main.rs:1-2`: комментарий про аллокатор на «musl/aarch64», а mimalloc только x86_64, на aarch64 используется musl mallocng;
  - правило «no-c» против mimalloc C.
- **Исправление:** обновить `SIZING.md` таблицей из §2 этого отчёта, поправить комментарии. Для aarch64 отдельно измерить musl malloc против mimalloc (гипотеза: на ARM аллокатор — заметная доля CPU и RSS).

### BLD-19 — лицензионные уведомления в пакете
- **Статус:** подтверждено. **P3.**
- **Где:** `scripts/package_openwrt.py:78-85`, файлы пакета. `package_openwrt.py:94` `Source: https://github.com/Screamshow/xrust`, в `Cargo.toml` `repository = github.com/Dushnilin/tachyon-core`.
- **Исправление:** генерировать `usr/share/rust-x/THIRD-PARTY-LICENSES` (`cargo about` / `cargo deny list`, около 60–100 КиБ, в xz около 15 КиБ) или ссылку на файл в релизе. Унифицировать URL исходников (требование GPL-3.0: corresponding source).
- **Forkop X:** +несколько КиБ на флеше, при варианте со ссылкой 0.

### BLD-20 — дубли версий
- **Статус:** подтверждено. **P3.**
- **Где:** `Cargo.lock`, таблица §3.
- **Исправление:** ждать rsa 0.10 (rand 0.9+), lru ≥0.16 (hashbrown 0.15→новее). Выигрыш десятки КиБ, не приоритет.

## 9. Влияние на Forkop X (итог)

- Сейчас rust-x 0.0.26 ARM64 весит 10,22 МБ, packed=false, на флеше нужно около 10 236 КиБ + 256 КиБ запаса после удаления прежнего варианта (`action.uc:772-790`).
- На F2FS это полный размер. На UBIFS и JFFS2 фактическое занятие меньше: ФС сжимает, xz даёт 3,27 МБ, у ФС коэффициент хуже. Forkop консервативно считает логический размер.
- Самый эффективный шаг для флеша — BLD-06 + BLD-08: оценочно 7,1 МБ (−3,1 МБ). Пакет станет меньше Sing-Box X (8,63 МБ payload), и rust-x встанет на роутеры с 7,5–8 МиБ свободного места.
- BLD-01, BLD-02 и BLD-03 закрываются одним обновлением rust-x. Механика обновления и отката Forkop не меняется, но откат на ≤0.0.26 возвращает уязвимости. Стоит пометить 0.0.26 в каталоге зеркала как не рекомендуемый для отката после выхода исправления.
- BLD-10 расширяет круг устройств без новой сборки.

## 10. Не проверено

- запуск бинарников aarch64 и armv7, скорость на Cortex-A53;
- сквозная loopback-пропускная способность при s против 3;
- сборка x86_64-musl (нет musl-gcc);
- MIPS (нет nightly);
- PoC для ruzstd;
- реальная утечка TUN-fd при reload;
- компиляция после `cargo update` исправленных версий (запрещено правами).
