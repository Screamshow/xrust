# Штатная и компактная ARM64-сборки Xrust, 2026-10-26

Два ARM64-бинарника и тестовые пакеты из **одного** коммита: штатный профиль
(`opt-level = 3`) и компактный (`opt-level = "s"`). Нужны для A/B-замера на
MT6000 (`aarch64_cortex-a53`).

Контекст: размерный профиль BLD-06 был отложен из-за замедления TLS
ChaCha20-Poly1305 на x86_64. На роутере в выборке из 66 внешних TLS-рукопожатий
ChaCha20 не согласовывался ни разу, только AES-GCM
(`docs/router90-tls-ciphers-2026-10-26.md`). Поддержка ChaCha20 сохраняется:
Xray/REALITY могут его выбрать, набор и порядок шифров в ClientHello не
менялись.

**Решение не принято.** Пока нет замера скорости, CPU, трафика и отката на
MT6000, компактный профиль стандартным не становится: `main`, релизный профиль
в `Cargo.toml` и публичные релизы не меняются.

## Источник

| Параметр | Значение |
|---|---|
| Ветка | `dev` |
| Коммит исходника (оба варианта) | `e7fbe00bfd8d3cac2564c1db2c84ee2db925ca90` |
| Отслеживаемые файлы при сборке | без изменений (`git status --porcelain -uno` пусто) |
| Версия | 0.0.27 |
| Цель | `aarch64-unknown-linux-musl` |
| Инструменты | rustc 1.99.1 (58cf8f9c3 2026-10-13), cargo 1.99.1 |
| `Cargo.lock` | не менялся (сборки с `--locked`) |

Профиль в `Cargo.toml` не менялся; компактный вариант задаётся только ключами
`--config` в командной строке. Поэтому «два варианта из одного коммита» —
буквально: разница лишь в двух аргументах `cargo build`.

## Команды сборки

Из корня репозитория, `RUSTFLAGS` в окружении **не задавать** (иначе массив
`rustflags` из `.cargo/config.toml` молча отбрасывается — BLD-11; именно так
когда-то получили 0,03 ГиБ/с AES-GCM на A53). Каждый вариант собирается в своём
каталоге (`CARGO_TARGET_DIR` или `--target-dir`), потому что отличается ключ
профиля и общий каталог пересобирался бы каждый раз.

Штатный (`opt-level = 3`):

```sh
cargo build --locked -p core-cli --no-default-features --features rust-x \
    --release --target aarch64-unknown-linux-musl
```

Компактный (`opt-level = "s"`, `core-crypto` остаётся на 3):

```sh
cargo build --locked -p core-cli --no-default-features --features rust-x \
    --release --target aarch64-unknown-linux-musl \
    --config 'profile.release.opt-level="s"' \
    --config 'profile.release.package.core-crypto.opt-level=3'
```

Результат: `target/aarch64-unknown-linux-musl/release/tachyon-core`.

`core-crypto` на 3 — единственное отличие от «чистого» `"s"`. В этом крейте
лежат `fastgcm` и `fastchacha`; по замерам x86_64 (BLD-06) именно он
восстанавливает скорость собственных AEAD. **Гарантией это не является:**
при fat LTO generic-инстанциации RustCrypto (`AesGcm<Aes128>`,
`ChaCha20Poly1305`) компилируются в крейтах-потребителях и попадают под
`"s"`, а per-package `opt-level = 3` для `aes`, `aes-gcm`, `ghash`,
`chacha20`… на них не влияет (BLD-07). На ARM собственного GCM-цикла пока нет,
AES-GCM идёт через крейты RustCrypto с ARM-cfg, поэтому вывод по скорости
даёт только замер на устройстве.

## Что в обеих сборках одинаково

Проверено по `cargo build -v` (279 вызовов rustc в каждой сборке):

| Что | Результат |
|---|---|
| Набор крейтов и версий | 223 строки `Compiling`, списки совпадают побайтно |
| Фичи | `rust-x`, `full`, `clash-api`; `--no-default-features`, без `legacy-protocols` |
| ARM crypto cfg | `--cfg aes_armv8 --cfg polyval_armv8 --cfg chacha20_force_neon` — в 199 вызовах rustc для цели в каждой сборке |
| Прочие флаги из `.cargo/config.toml` | `rust-lld`, `link-self-contained=yes`, `--icf=safe`, `-z noseparate-code`, `-z norelro`, `force-unwind-tables=no` |
| Остальное в профиле | fat LTO, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `overflow-checks = false` |
| ELF | `ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped` |

Отличие по `opt-level` в компактной сборке: 180 вызовов rustc с `opt-level=s`,
20 с `opt-level=3` (per-package список из `Cargo.toml` плюс `core-crypto`).
Проверено точечно: `core_crypto` — 3, `aes_gcm` — 3, `core_tls` — `s`.

Аппаратные пути шифрования в обеих сборках на месте (`llvm-objdump -d`):

| Инструкции | opt 3 | opt s |
|---|---:|---:|
| `aese` | 1002 | 958 |
| `aesmc` | 904 | 858 |
| `pmull`/`pmull2` | 157 | 157 |
| `sha256h` | 0 | 0 |
| `add v*.4s` (NEON) | 2025 | 334 |

`sha256h` нет в обеих сборках: `sha2` на aarch64 работает программно
(известно, касается только рукопожатий и HKDF). Падение числа NEON-сложений
в 6 раз — главный кандидат на регрессию: это ChaCha20 и прочий векторный код,
собранный по размеру. Для AES-GCM `aese`/`pmull` сохранены.

## Размеры

| Метрика | opt 3 | opt s | Δ |
|---|---:|---:|---:|
| ELF, байт | 10 050 952 | 7 237 400 | −2 813 552 (−28,0 %) |
| `.text` | 8 217 368 | 5 428 280 | −2 789 088 (−33,9 %) |
| `.rodata` | 972 688 | 927 104 | −45 584 (−4,7 %) |
| `.eh_frame` + `.eh_frame_hdr` | 482 864 | 498 504 | +15 640 (+3,2 %) |
| `gzip -9` | 4 908 770 | 3 631 545 | −1 277 225 (−26,0 %) |
| `xz -9e` | 3 278 888 | 2 560 960 | −717 928 (−21,9 %) |
| Время полной сборки | 3 мин 37 с | 2 мин 37 с | −28 % |

Бюджет 12 МиБ (`scripts/size.sh`, `scripts/pack_all_architectures.sh`)
соблюдён в обоих вариантах: 9,59 МиБ и 6,90 МиБ.

| Пакет | opt 3 | opt s | Δ |
|---|---:|---:|---:|
| IPK (OpenWrt 24) | 4 905 608 | 3 626 665 | −1 278 943 (−26,1 %) |
| APK (OpenWrt 25) | 4 911 584 | 3 631 882 | −1 279 702 (−26,1 %) |
| `installed-size` | 10 053 275 | 7 239 722 | −2 813 553 (−28,0 %) |

На флеше компактный вариант экономит 2,683 МиБ установленного размера —
столько же вычитается из требования preflight в Forkop X. Для сжимающих ФС
(UBIFS, JFFS2) выигрыш меньше: Forkop считает логический размер.

## Упаковка

Существующий путь: `scripts/package_openwrt.py` с host-инструментом `apk` из
OpenWrt SDK (`scripts/openwrt_apk_tool.sh`, SDK 25.12.3, apk-tools 3.0.5).

```sh
install -m 755 target/aarch64-unknown-linux-musl/release/tachyon-core \
    <binaries>/rust-x-aarch64-v0.0.27
SOURCE_DATE_EPOCH=0 python3 scripts/package_openwrt.py \
    --binaries <binaries> --output <out> --apk-tool <путь к apk> \
    --version 0.0.27 --revision <1|2> \
    --source-commit e7fbe00bfd8d3cac2564c1db2c84ee2db925ca90 \
    --cpus aarch64
```

Ревизии различаются намеренно: штатный вариант — `r1`, компактный — `r2`,
иначе на роутере два пакета неотличимы и не ставятся друг поверх друга.

Пакеты **не подписаны** (`apk_signed: false` в манифесте), это тестовые
артефакты, не часть фида и не релиз. Подпись (`scripts/sign_openwrt.py`,
ключ зеркала) к ним не применялась.

Два замечания по запуску упаковки вне CI:

- `--cpus` — новый необязательный аргумент (по умолчанию `aarch64,x86_64`,
  то есть поведение релизного конвейера не меняется). Он нужен, чтобы собрать
  ARM64-пакеты, не собирая x86_64-бинарник, который этой задаче не требуется
  (x86_64 тянет `mimalloc`, то есть cross-cc для musl).
- Скрипт раскладывает payload от root. В CI это `sudo env …`; без root
  подходит `fakeroot`, но `apk` из SDK запускается через собственный загрузчик
  и теряет `LD_PRELOAD`, из-за чего владельцем файлов в APK становится
  текущий пользователь. Лечится запуском `staging_dir/host/bin/.apk.bin`
  системным загрузчиком (`exec -a apk`). Проверено: в готовых APK
  `user: root`, `group: root`, права `0755`/`0644` как в релизных.

## Артефакты и SHA-256

Передаются отдельно (в репозиторий бинарники не кладутся).

Штатный, `opt-level = 3`:

| Файл | SHA-256 |
|---|---|
| `rust-x-aarch64-v0.0.27` | `63bf3e3524f43a69f09717012ea900c0f04362db2d1d6705455a5d4d430d6462` |
| `rust-x_0.0.27-r1_aarch64_cortex-a53.apk` | `b653821b6c9643b247629a0ce49265b147bd1997a380cc11dec630cc05074809` |
| `rust-x_0.0.27-1_aarch64_cortex-a53.ipk` | `31db87538815912cfc8eb7f5bd68024c42efb9165a5b30c5a6702e7239d10b4a` |
| `openwrt-manifest.json` | `1418d516190c47055322092b56eb0424fffc2584dda6f8e110c1f0cc8cf581b4` |

Компактный, `opt-level = "s"`:

| Файл | SHA-256 |
|---|---|
| `rust-x-aarch64-v0.0.27` | `fae433b91901623336a7f4dad1d1e032c60c21a828faf7cc765d2840ee5146c8` |
| `rust-x_0.0.27-r2_aarch64_cortex-a53.apk` | `84fbafbb10df2bc94d247937c0ad898b9fcd4212c3790d9198e5eb1b16fa531b` |
| `rust-x_0.0.27-2_aarch64_cortex-a53.ipk` | `95fbd72c9a3c650b338b2a7f105398aca43da746b3e1587861d020d1aa138e3a` |
| `openwrt-manifest.json` | `0ffc8b44a451e9f92d3008de548740deab384b9e26f17314aff7e0170f512999` |

SHA-256 бинарника внутри пакета совпадает с переданным файлом и записан в
`/usr/share/rust-x/build.json` (`binary_sha256`, `binary_bytes`).

## Установка и откат на роутере

Пакеты неподписанные, поэтому нужен `--allow-untrusted`. Установка
останавливает Forkop (`prerm`/`pre-upgrade`) и поднимает обратно
(`postinst`/`post-install`), конфигурация `/etc/config/sing-box` сохраняется.

OpenWrt 25 (APK):

```sh
apk add --allow-untrusted /tmp/rust-x_0.0.27-r2_aarch64_cortex-a53.apk   # компактный
apk add --allow-untrusted /tmp/rust-x_0.0.27-r1_aarch64_cortex-a53.apk   # обратно на штатный
```

OpenWrt 24 (IPK):

```sh
opkg install --force-reinstall /tmp/rust-x_0.0.27-2_aarch64_cortex-a53.ipk
opkg install --force-downgrade /tmp/rust-x_0.0.27-1_aarch64_cortex-a53.ipk
```

Если `apk` откажется из-за того, что пакет не из репозитория или версия уже
стоит, помогают `--force-non-repository` и `--force-reinstall`. Полный возврат
к опубликованному состоянию — переустановка подписанного пакета с зеркала.

Какой вариант сейчас стоит, видно по
`sha256sum /usr/lib/rust-x/sing-box` или по
`/usr/share/rust-x/build.json`; строка `sing-box version` у обоих вариантов
одинаковая — различать по ней нельзя.

## Что нужно замерить на MT6000

До замера решение не принимается. Минимум, который нужен, чтобы профиль стал
стандартным:

1. Пропускная способность и CPU на ГиБ на тех же профилях нагрузки, что в
   `scripts/bench/bench.py` (mixed, VLESS+TLS, VLESS+REALITY+Vision,
   Hysteria2, XHTTP), оба варианта чередовать, медианы.
2. Отдельно AES-GCM (основной путь на этом роутере) и ChaCha20-Poly1305
   (на случай Xray/REALITY), в том числе короткие записи.
3. Трафик и поведение под реальной нагрузкой: отсутствие роста ретрансмиссий,
   задержек, обрывов.
4. Память: RSS процесса в покое и под нагрузкой.
5. Откат: установка штатного пакета обратно, Forkop поднимается, конфигурация
   и службы на месте.

## Чего здесь не проверяли

- ARM64-бинарники не запускались: в этом окружении нет ни устройства, ни
  эмуляции aarch64. `version`, `check` и запуск под Forkop должны пройти на
  роутере или на OpenWrt VM.
- Скорость, CPU, трафик, RSS и откат на MT6000 — не измерялись.
- x86_64-варианты не собирались и не упаковывались: задача только про ARM64.
- Подпись пакетов и установка без `--allow-untrusted` не проверялись.
- `armv7` не рассматривался: там нет аппаратного AES, приоритет шифров другой
  и вывод о ChaCha20 неприменим.
