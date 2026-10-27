# 07. Совместимость Forkop X ↔ xrust (rust-x 0.0.26)

Дата: 2026-10-23. Объекты: xrust `c5f567c` (0.0.26), Forkop X в `forkop-x` (рабочая копия без git).
Обозначения путей: **F** = `forkop-x/forkop/files/usr/lib/…`, **FE** = `forkop-x/fe-app-forkop/src/…`, **X** = `xrust/crates/…`.
Скретч: `S=<scratch>`.

## 1. Итог

Основной путь Forkop X на rust-x работает. Проверены: генерация конфигов, `check`, `run`, Clash API, SIGHUP/`reload-plan`, `rule-set match/decompile`, VLESS REALITY/TLS поверх TCP-Vision, gRPC, XHTTP, WS и HTTPUpgrade против локального xrust-сервера, Hysteria2 с Salamander, FakeIP DNS.

Найдено два блокера (P0). Оба про то, что Forkop генерирует протоколы, которые профиль rust-x **отвергает целиком**, а не по одному узлу:
- подписка с хотя бы одним узлом trojan, ss или vmess;
- любая секция ByeDPI.

Ниже ещё пять заметных проблем (P1–P2) и мелочи.

| ID | Приор. | Статус | Кратко |
|---|---|---|---|
| FX-01 | **P0** | ❌ подтверждено | Узел trojan, ss, vmess или socks в подписке или ручной ссылке валит `check`, и весь старт или reload Forkop прерывается |
| FX-02 | **P0** | ❌ подтверждено | Секция ByeDPI генерирует outbound `socks`; rust-x его запрещает |
| FX-03 | P1 | ❌ подтверждено | `log_level=panic` есть в LuCI, но xrust его не принимает, и конфиг не проходит check |
| FX-04 | P1 | ⚠️ подтверждено | Версия и возможности (XHTTP, Tailscale, 1.14 DNS) зашиты в shell-обёртку; без неё Forkop видит «stable 0.0», XHTTP-ссылки ломают генерацию |
| FX-05 | P2 | ❌ подтверждено | `sing-box tools fetch` отсутствует, диагностика `check_proxy` всегда падает |
| FX-06 | P2 | ❌ подтверждено | SIGTERM игнорируется до конца `start()` (58,7 с в тесте); Forkop через 15 с шлёт SIGKILL |
| FX-07 | P2 | ⚠️ подтверждено | `/group/{name}/delay` отдаёт `{"delay":N}`, а не карту участник→задержка |
| FX-08 | P2 | ❌ подтверждено | HTTP-forward (absolute-URI) через mixed не попадает в `/connections` и totals; Monitoring слеп для DirectProxy и mixed HTTP |
| FX-09 | P2 | ⚠️ подтверждено | `timeout` в delay — `i16`: при `check_timeout` от 33 с получаем 400, и все узлы выглядят мёртвыми |
| FX-10 | P2 | ⚠️ по коду и тесту | Shell-вызовы Forkop шлют Bearer, только если `enable_yacd_wan_access=1`; при заданном secret без WAN — 401 |
| FX-11 | P2 | ⚠️ по коду и замеру | `sing-box check` и `rule-set match` запускаются рядом с живым ядром: пик до 43 МиБ на 1,2 МБ SRS |
| FX-12 | P3 | ⚠️ гипотеза о Go | Порядок `chains` у xrust: группа→лист (в Go, по памяти, лист→группа); Forkop терпим |
| FX-13 | P3 | ⚠️ по коду | Тип `Reject` у block-outbound; в фильтре латентности Forkop есть только `block` |
| FX-14 | P3 | ❌ подтверждено | Серверный inbound Hysteria2 с Salamander не работает: ответ шлётся в неподключённый сокет |
| FX-15 | P3 | ❓ причина не найдена | Серверный VLESS с правилом `ip_cidr` ломает delay-пробы клиента; обычный трафик идёт |
| FX-16 | P3 | ⚠️ по коду | Устаревший `openwrt/Makefile` (tachyon-core, без обёртки, профиль default) несовместим с Forkop |
| FX-17 | P3 | ❓ по коду, не проверено | Мелочи Forkop: жёсткий путь `/etc/sing-box/config.json` в post-upgrade проверке; `full-uninstall.sh` не удаляет `/usr/lib/rust-x` |

## 2. Методология и что сработало

### 2.1. ucode собран из исходников — генератор Forkop прогнан по-настоящему
- json-c (`github.com/json-c/json-c`, HEAD) и ucode (`github.com/jow-/ucode`, HEAD) собраны cmake в `$S/forkop/prefix`. Флаги: `-DUBUS_SUPPORT=OFF -DUCI_SUPPORT=OFF -DULOOP_SUPPORT=OFF -DRTNL_SUPPORT=OFF -DNL80211_SUPPORT=OFF`. В систему ничего не ставилось.
- Модуль UCI не понадобился. В генераторе Forkop есть штатный fixture-режим `generate-config-fixture` (F `singbox/generator.uc:3543-3548`, `use_fixture_cursor` на :144). UCI подменяется JSON-фикстурой; так же работают тесты Forkop (`tests/reality_xhttp.uc`, `tests/urltest_groups.sh`).
- Подписка готовилась штатным парсером: `subscription/parser.uc normalize-content` над base64-списком ссылок. Результат клался в кэш `TMP_SUBSCRIPTION_FOLDER/<section>-subscription-1.{json,url,user_agent}`, как в `tests/urltest_groups.sh`.
- Обнаружение варианта и версии проверено вызовом `ucode … singbox/runtime.uc version|supports-xhttp|supports-tailscale|variant`. Использовались два PATH: копия штатной обёртки `/usr/bin/sing-box` из `scripts/package_openwrt.py:71-79` и голый бинарник с именем `sing-box`.
- Версия, передаваемая генератору: `1.14.2-rust-x.0.0.26`. Это ровно то, что вернёт `sing_box_version()` (F `singbox/runtime.uc:262-268`) с обёрткой; проверено, см. §3.1.

Скрипты: `$S/forkop/scripts/fixtures.py`, `gen.sh`, `localize.py`, `salamander_relay.py`, `ws.py`, `blackhole.py`.

### 2.2. Сборки xrust
- **rust-x**: `CARGO_TARGET_DIR=$S/target-forkop cargo build --locked -p core-cli --no-default-features --features rust-x`. Debug, плюс отдельно release для замеров памяти: 12 404 248 B, x86_64 glibc, не musl.
- **default**: `CARGO_TARGET_DIR=$S/target-forkop-default cargo build --locked -p core-cli` (features `full,legacy-protocols`).
- ⚠️ Бинарник `target/debug/tachyon-core` собран **в профиле rust-x**, а не default: он отвергает trojan с сообщением «excluded from Rust X». Другим аудиторам не стоит считать его дефолтной сборкой.

### 2.3. Локальный стенд (только loopback, порты 21000–21999)
- Сервер — тот же rust-x бинарник, `$S/forkop/server/server.json`. На нём VLESS REALITY+Vision (21443), REALITY gRPC (21444), REALITY XHTTP (21445), TLS WS (21446), TLS gRPC (21447), TLS HTTPUpgrade (21448), TLS XHTTP stream-one (21449), plain VLESS (21450) и Hysteria2 с Salamander (21451).
- Сертификат самоподписанный, ключ REALITY сгенерирован `tachyon-core generate reality-keypair` только для стенда. Handshake-цель REALITY — Python TLS 1.3 на 21998, HTTP-цель — `python3 -m http.server` на 21999.
- Клиент — конфиги, сгенерированные Forkop, после механической «локализации» (`localize.py`):
  - inbound `tproxy` заменён на `mixed` с тем же тегом (tproxy без root даёт `Operation not permitted`, проверено);
  - порты перенесены в 21xxx;
  - remote rule sets заменены на local SRS. Forkop на роутере делает то же самое через `ruleset_cache.uc materialize-config` (F `singbox/ruleset_cache.uc:633-655`), то есть в реальном рантайме remote rule sets не скачиваются;
  - `external_ui` удалён (иначе ядро пошло бы скачивать UI);
  - для части тестов `route.final` → группа секции.

### 2.4. Отклонение от ограничений (раскрываю)
Один раз нарушен принцип «только loopback»: при коротком прогоне `c03-urltest` URLTest сам начал пробы на `https://www.gstatic.com/generate_204` через локальный сервер. Сервер с `final: direct` открыл 8 TCP-соединений на `www.gstatic.com:443` (`$S/forkop/server/server.log`).

Это не прокси-узел, не роутер и не mirror, но это внешний хост. После этого egress сервера ограничен правилом `ip_cidr 127.0.0.0/8 → direct, final → block`, а URL в urltest переписан на `http://127.0.0.1:21999/`. К реальным узлам подписок, роутерам и `mirror.51343.ru` обращений не было: все адреса в фикстурах — `127.0.0.1` или `*.fixture.test`.

### 2.5. Чего не было
- root, tproxy, nft, procd, ubus и настоящего OpenWrt;
- musl/aarch64;
- внешних узлов, Tailscale control plane и загрузки UI.

## 3. Интеграция Forkop с ядром (архитектура)

### 3.1. Выбор и детект варианта
- Версия: `sing-box version`, последнее поле первой строки (F `singbox/runtime.uc:262-268`).
- Вариант `rust-x`: установлен пакет `rust-x` либо версия матчит `/-rust-x[.]/` (F `singbox/runtime.uc:354-372`).
- XHTTP: строка `Features:` содержит `transport.xhttp` (F `singbox/runtime.uc:293-304`). Tailscale: тег `with_tailscale` (:306-317).
- Пины сертификатов: только при `-(rust-x|tachyon).` (F `singbox/generator.uc:3473`).
- DNS 1.14 (`evaluate`/`match_response`, без `independent_cache`): для версии ≥ 1.14 (F `singbox/generator.uc:3495-3500`).
- Путь кэша `cache.db.forkop-rust-x` (F `singbox/cache_identity.uc`, `generator.uc:455`).
- Hot reload определяется по возможности, а не по версии: `GET /rust-x/applied-config` (F `service/hot_reload.uc:52-56`).

Проверка (`$S/forkop/root/usr/bin` — копия штатной обёртки):
```
== PATH = обёртка           version: [1.14.2-rust-x.0.0.26]  supports-xhttp rc=0  supports-tailscale rc=0  variant: [rust-x]
== PATH = голый sing-box    version: [v0.0.26-tachyon.0]     supports-xhttp rc=1  supports-tailscale rc=1  variant: [stable]
```

### 3.2. CLI-вызовы

| Вызов Forkop (F файл:строка) | xrust | Статус |
|---|---|---|
| `sing-box version` (`singbox/runtime.uc:206,262`; `config/validator.uc:1768`; `components/action.uc:1857`) | обёртка `scripts/package_openwrt.py:71-79`; нативно `X core-cli/src/main.rs:58-77` | ✅ с обёрткой; ⚠️ без неё (FX-04) |
| `sing-box -c <cfg> check` (`singbox/runtime.uc:724-733`, `diagnostics/runtime.uc:558`) | `main.rs:629-640,743-748`; ошибка в stderr, rc=1 | ✅ проверено на 18 конфигах |
| `run -c <conf> -D <workdir>` (procd-скрипт пакета `packaging/files/etc/init.d/sing-box`) | `main.rs:621,682-691` | ✅ `run -c` проверен; `-D` проверен через `tools`-вызов не был, только парсинг |
| `rule-set match --format binary <srs> forkop-validation.invalid` (`singbox/ruleset_cache.uc:279`, `components/updates.uc:523`) | `X core-cli/src/rule_set.rs:344-380` | ✅ `no match` rc=0; повреждённый файл rc=1 |
| `rule-set decompile <in> -o <out>` (`components/updates.uc:3444,3477,3610`) | `rule_set.rs:234-257` | ✅ rc=0; на выходе `version: 2` |
| `/usr/bin/sing-box reload-plan --current A -c B` (`service/hot_reload.uc:118`) | `main.rs:246-272` | ✅ no-op → `in_place:true`; смена listener → `in_place:false`; битый файл rc=1. `tests/rust_x_hot_reload.sh` PASS |
| `/usr/lib/rust-x/sing-box tailscale-{native,ssh,exit}-capability`, `tailscale-luci` (`tailscale/action.uc:10-12`, `init.d/forkop-tailscale:17`) | `main.rs:703-722` | ✅ печатает `1` rc=0; `tailscale-luci` не запускался |
| `sing-box tools fetch ifconfig.me -c … -D … --disable-color [-o tag]` (`diagnostics/runtime.uc:585`) | нет | ❌ FX-05 |
| `sing-box -v` / `--version` (в Forkop не используется) | нативная строка `v0.0.26-tachyon.0` | ⚠️ обходит обёртку |

### 3.3. Сигналы, reload и остановка
**Hot reload (F `service/lifecycle.uc:1814-1849,1908-1963`, `service/hot_reload.uc`):**
1. `reload-plan`;
2. nft-guard, commit stage, затем `kill -HUP <pid>` (`hot_reload.uc:142`);
3. опрос `/rust-x/applied-config` до роста `generation` и совпадения sha256 (тайм-аут 30 с);
4. `POST /rust-x/revalidate-connections`;
5. при ошибке — откат конфига и повторный HUP.

**xrust (X `core-runtime/src/lib.rs:584-636`):**
- невалидный кандидат: `WARN reload configuration rejected; keeping current runtime: …`, generation не растёт;
- смена inbound, clash_api или cache_file: перезапуск внутри процесса.

**Проверено (`$S/forkop/run/hup.log`):**
```
applied-config: generation 1 → (HUP, правка конфига) → generation 2, новый sha256, тот же pid
'{bad json' + HUP      → WARN reload configuration rejected; keeping current runtime: key must be a string … ; процесс жив; generation 2
trojan outbound + HUP  → WARN reload configuration rejected; keeping current runtime: outbounds[12]: protocol "trojan" is excluded from Rust X
POST /rust-x/revalidate-connections → {"closed":0,"skipped":0,"superseded":false}
SIGTERM → "INFO shutting down", rc=0 (все прогоны)
```

**Остановка в Forkop (F `service/state.uc:878-900`):** `ubus call service delete sing-box`, затем TERM 15 с, затем KILL. Недостаток описан в FX-06.

### 3.4. Логи
- Forkop не разбирает уровни sing-box. Он грепает `logread` по подстрокам (F `diagnostics/runtime.uc:675,690`, `diagnostics/status.uc:1325-1380`), а свои сообщения пишет через `logger -t forkop`.
- Ошибка `check` целиком попадает в лог Forkop как `Generated sing-box configuration is invalid: <stderr>` (F `singbox/runtime.uc:1022-1029`).
- Формат xrust: `LEVEL[secs] msg`, с меткой времени, если `timestamp:true`; так же, как в Go.
- Фатальная ошибка старта приходит без префикса `FATAL`: `run: inbounds[0]: tproxy: … Operation not permitted`. Для Forkop это безразлично.
- Фильтр Forkop `"UDP is not supported by outbound:"` (F `diagnostics/status.uc:1325`) рассчитан на текст Go и на xrust ничего не ловит. Это косметика.

### 3.5. Watchdog и health
- `dns-watchdog` — procd-инстанс (F `etc/init.d/forkop:32-40`, `service/watchdog.uc:15-100`). Каждые **5 с** он запускает 2 процесса ucode (`state.uc sing-box-current-owned-service-runtime`, `ui.uc package-upgrade-transition-active`). Grace 90 с; после 60 с нездоровья — `forkop stop` и восстановление dnsmasq.
- Здоровье (F `service/state.uc:465-700`, `core/netstat.uc:66-91`, `core/runtime_health.uc:2-38`):
  - pid из ubus;
  - `/proc/<pid>/exe` с basename `sing-box`. Обёртка делает `exec /usr/lib/rust-x/sing-box`, поэтому basename сохраняется ✅;
  - ровно один такой процесс;
  - неизменный start_ticks;
  - listener'ы `:1602` tcp+udp и `127.0.0.42:53` должны принадлежать этому pid.
- Транзиентные `check`, `match` и `reload-plan` временно дают второй процесс `sing-box`; для этого есть окно settle (`state.uc:720+`).
- Память для UI: VmRSS из `/proc` (F `core/process_memory.uc:9-46`).

### 3.6. Установка, обновление, откат
- Каталог: `${mirror}/forkop/rust-x/latest.json`. Проверяются sha256, размер, URL и строгий regex версии `^v?N.N.N-rust-x[.](N.N.N)$` (F `components/action.uc:1932-1963`).
- Установка: `opkg install --force-overwrite --force-reinstall --force-downgrade`, `apk add --force-reinstall --no-network --allow-untrusted` (F `components/action.uc:477-488`). Подпись APK не требуется; целостность держится на sha256 каталога.
- Откат: точный предыдущий пакет из `/forkop/sing-box-archive/packages.json` (F `components/action.uc:1079-1083`). Перед установкой удаляются все пакеты-варианты (:917-921).
- Пакет xrust (`scripts/package_openwrt.py`): `rust-x`; Depends `ca-bundle, kmod-tun`; Conflicts `sing-box, sing-box-x, sing-box-tiny, sing-box-extended`; Provides `sing-box`. Состав: `/usr/lib/rust-x/sing-box`, обёртка `/usr/bin/sing-box`, `/usr/share/rust-x/build.json`, `/etc/init.d/sing-box`, `/etc/config/sing-box`. Хуки prerm/postinst останавливают и перезапускают Forkop через маркер `/var/run/forkop/rust-x-package-restart`.
- Установка пакетов в этом аудите **не проверялась**: нет OpenWrt и apk/opkg. Выводы выше сделаны по коду.

## 4. Сгенерированные конфиги и результаты `check`

Все конфиги ниже созданы **реальным генератором Forkop X**. Каталог `$S/forkop/configs/`, рядом лежат `<name>.json.rulesets/` (материализованные subnet-наборы) и `.section-cache/`. Фикстуры — в `$S/forkop/fixtures/*.fixture.json`.

| Конфиг | Что покрывает | default `check` | rust-x `check` | rust-x `run` (локализ.) |
|---|---|---|---|---|
| `c01-reality-vision.json` | VLESS REALITY + Vision, community `youtube` (remote SRS + local subnets), FakeIP, tproxy v4/v6, Clash API, cache_file | ✅ 0 | ✅ 0 | ✅ |
| `c02-multi-transport-selector.json` | selector из 9 узлов: REALITY tcp/gRPC/XHTTP, TLS WS/gRPC/HTTPUpgrade/XHTTP, plain, Hysteria2+Salamander | ✅ | ✅ | ✅, трафик через все VLESS ✅ |
| `c03-urltest.json` | URLTest (3m, tolerance 50) внутри selector | ✅ | ✅ | ✅ |
| `c04-hysteria2.json` | Hysteria2 + Salamander | ✅ | ✅ | ✅ |
| `c05-dns-doh-failover.json` | DoH по домену и IP, 2 main + 2 bootstrap (failover), `ipv4_only`, `rewrite_ttl 120`, `disable_cache` | ✅ | ✅ | ✅ |
| `c06-dns-dot-detour-whatsapp.json` | DoT с `detour` через прокси, `domain_resolver`, `whatsapp_real_dns` → `reverse_mapping`, `evaluate`, community meta+telegram | ✅ | ✅ | ✅ |
| `c07-rulesets-lists.json` | community youtube/discord/meta, remote SRS, local `.json`/`.srs`, `rule_set_with_subnets`, domain/keyword/regex, source CIDR, fully_routed/excluded IP, ports, logical `and` | ✅ | ✅ | ✅ |
| `c08-vpn-bypass-block-dns.json` | секции `vpn` (bind_interface wg0, routing_mark), `bypass`, `block`, `dns` | ✅ | ✅ | ✅ (без wg0 ошибок на старте нет) |
| `c09-mixed-yacd-direct.json` | Clash API `secret` + `external_ui`, DirectProxy mixed, mixed с логином/паролем | ✅ | ✅ | ✅; 401 без токена, 200 с Bearer, 407 при неверном пароле |
| `c10-legacy-protocols.json` | trojan, ss, vmess-ws, socks5 + vless | ✅ | ❌ `outbounds[2]: protocol "trojan" is excluded from Rust X` | ❌ rc=1 |
| `c11-outbound-json-detour.json` | JSON-outbound и `outbound_detour` (цепочка) | ✅ | ✅ | ✅ |
| `c12-byedpi.json` | секция ByeDPI + прокси | ✅ | ❌ `outbounds[2]: protocol "socks" is excluded from Rust X` | ❌ rc=1 |
| `c13-quic-ipv6-out-iface.json` | disable_quic (+vpn), `default_interface`, `prefer_ipv6`, action `resolve` | ✅ | ✅ | ✅ |
| `c14-interface-domain-resolver.json` | секция-интерфейс с отдельным DoH resolver и detour | ✅ | ✅ | ✅ |
| `c15-subscription.json` | подписка (base64): REALITY, XHTTP, WS, gRPC, Hy2, **trojan, ss** + URLTest + флаги стран | ✅ | ❌ `outbounds[7]: protocol "trojan" is excluded from Rust X` | ❌ rc=1 |
| `c16-log-panic.json` | `log_level=panic` (выбор в LuCI) | ❌ `create log factory: parse log level: unknown log level: panic` | ❌ то же | ❌ |
| `c16-log-fatal.json`, `c16-log-trace.json` | прочие уровни | ✅ | ✅ | ✅ |

Дополнительно, `$S/forkop/configs-bare/`: те же фикстуры с версией голого бинарника `v0.0.26-tachyon.0` и `supports_xhttp=0`. Результат:
- `c02`: генерация падает с ошибкой `manual outbound 'Reality XHTTP' uses XHTTP transport, but installed sing-box does not advertise XHTTP support`;
- `c06` и `c07`: 31–34 различия, `evaluate` превращается в legacy `route`, появляется `independent_cache` (FX-04).

**Предупреждения и молчаливое игнорирование.**
- `check` не выдал ни одного WARN ни на одном конфиге.
- xrust строго отвергает неизвестные поля. Проверка: `outbounds[2].foo_bar` → `json: unknown field "foo_bar"`, rc=1. Значит, «молча игнорируемых» полей в выводе Forkop нет: всё, что генерирует Forkop (кроме FX-01, FX-02, FX-03), xrust распознаёт.
- Исключения, принятые без проверки на деле:
  - `default_mark` и `routing_mark` без CAP_NET_ADMIN: прямые соединения работали, то есть ошибка SO_MARK, видимо, не фатальна; на роутере с root неактуально;
  - `bind_interface: wg0` без интерфейса старт не ломает.

Полный вывод: `$S/forkop/check-results.txt`, `$S/forkop/run-results.txt`.

**Чего генератор Forkop не производит вообще:** TUN-inbound, `endpoints` (Tailscale и WireGuard как endpoint), `services`. Tailscale живёт отдельным процессом `tailscale-luci` (`init.d/forkop-tailscale`). Поэтому TUN и Tailscale в этой матрице — ❓.

## 5. Рантайм-проверки на loopback

### 5.1. Транспорты (клиент из `c02`, сервер xrust)
Через Clash API delay на `http://127.0.0.1:21999/` и через HTTP CONNECT по mixed:
```
main-1-out REALITY+Vision   delay=120  put=204 body=hello
main-2-out REALITY gRPC     delay=90   put=204 body=hello
main-3-out REALITY XHTTP    delay=105  put=204 body=hello
main-4-out TLS WS           delay=39   put=204 body=hello
main-5-out TLS gRPC         delay=44   put=204 body=hello
main-6-out TLS HTTPUpgrade  delay=48   put=204 body=hello
main-7-out TLS XHTTP s-one  delay=44   put=204 body=hello
main-8-out plain VLESS      delay=1    put=204 body=hello
main-9-out Hysteria2+Salamander  {"message":"Timeout"}   ← виноват сервер xrust (FX-14)
```

Hysteria2 разобран отдельно:
- без obfs клиент и сервер xrust работают: `[hello]`;
- клиент xrust с Salamander, пропущенный через **независимую** реализацию Salamander на Python по спецификации (`salamander_relay.py`, BLAKE2b-256(pw‖salt) XOR) к plain-серверу xrust: `[hello]`. Значит, клиентская реализация Salamander в xrust корректна; ломается серверный inbound.

### 5.2. Clash API в формах Forkop
Список запросов Forkop: F `diagnostics/runtime.uc:1512-1918`, `service/hot_reload.uc:53,87,96`, FE `helpers/getClashApiUrl.ts`, `tabs/dashboard/initController.ts:498,543,688`, `tabs/monitoring/initController.ts:374,1394,1454`, `getDashboardSections.ts:156-186,944-1550`, `runSectionsCheck.ts:72-126`.

| Запрос Forkop | Поля, которые читает Forkop | xrust (X `core-runtime/src/clash_api.rs`) | Статус и доказательство |
|---|---|---|---|
| `GET /proxies` | `proxies{}.type` (в нижнем регистре), `now`, `all`, `history[0].delay`, `udp` | :549, `proxies_view` :1259-1366 | ✅ `Selector`/`URLTest`/`VLESS`/`Hysteria2`/`Direct`, плюс `GLOBAL` типа `Fallback` (Forkop пропускает fallback) |
| `GET /proxies/{tag}/delay?url&timeout` | `delay`, `message` | :575-591, :1236-1495 | ✅ 200 `{"delay":N}`; 504 `Timeout`; 503 ошибка; 404 неизвестный тег. ⚠️ `timeout=40000` → 400 `Body invalid` (FX-09) |
| `GET /group/{tag}/delay` | **карта** участник→delay (`types.ts:682`, `Object.values`) | :595-604 → тот же `Route::Delay` | ⚠️ FX-07: отдаётся `{"delay":N}` или ошибка |
| `PUT /proxies/{sel}` `{"name":…}` (form-urlencoded) | только HTTP-код | :1182-1234 | ✅ 204; выбор сохраняется в cache_file между рестартами (после рестарта `now` = ранее выбранный узел) |
| `GET /connections` (rpcd fallback, hot_reload) | `connections[].id/metadata.{sourceIP,destinationIP,destinationPort,host,network,type}/chains/rule/rulePayload/upload/download/start`, `uploadTotal/downloadTotal/memory` | :552, :771-882 | ✅ для CONNECT и SOCKS (`chains:["main-out","main-4-out"]`, `rule:"final"`, `type:"Clash"`). ❌ для HTTP-forward (FX-08). `sniffHost` и `processPath` не выдаются; у Forkop они опциональны |
| WS `/traffic?token=` | `up`, `down` | :715-739, auth :1608-1631 | ✅ `101`, затем `{"up":0,"down":0}` раз в секунду |
| WS `/connections?token=&interval=` | как у GET | :805-811 | ✅ `101` и снимок |
| `DELETE /connections[/{id}]` | код | :556-562, :819-857 | ✅ по коду; в тесте не вызывался |
| `GET /rust-x/applied-config` | `schema, ready, hot_reload, generation, config_sha256, pid, connection_revalidation` | :547, X `route/mod.rs:1379-1396` | ✅ все поля на месте |
| `POST /rust-x/revalidate-connections` | `closed, skipped, superseded` | :548, `clash_state.rs:251-334` | ✅ |
| Auth и CORS | Bearer; `?token=` только для WS | :1608-1679 | ✅ без токена 401; Bearer 200; `?token=` на обычном GET 401 (как в Go); preflight `Allow-Origin:*`, `Allow-Headers: Authorization` |
| Имена с пробелами, кириллицей и эмодзи | percent-encoding | percent-decode + `from_utf8_lossy` (тесты :2190-2210) | ✅ по коду и юнит-тестам; вживую проверены только ASCII-теги |

### 5.3. DNS (`dns-in` из `c09`)
```
dig fakeip.podkop.fyi A            → 198.18.0.2        (FakeIP ✅)
dig example.org HTTPS              → NOERROR, ANSWER 0 (predefined ✅)
dig use-application-dns.net A      → REFUSED           (reject ✅)
```
Внешние DNS (1.1.1.1, DoH, DoT) намеренно не опрашивались: это внешние хосты.

### 5.4. Тесты самого Forkop против локального окружения
- С собранным ucode проходят: `xhttp_capabilities.sh`, `urltest_groups.sh`, `remote_lists_routing.sh`, `ipv6_tproxy.sh`, `quic_modes.sh`, `sing_box_dns114.sh`, `json_outbound_connection.sh`, `subscription_certificate_pins.sh`, `ruleset_cache.sh`.
- `tests/rust_x_hot_reload.sh` с `FORKOP_LIB=<repo>` и `FORKOP_SING_BOX_BIN=<обёртка → rust-x>`: **PASS**.
- Не прошли по причинам окружения, не xrust:
  - `tachyon_improvements.sh` — нужен модуль `uci`;
  - `sing_box_runtime.sh` — `FAIL: provider group removes XHTTP member`, нужен `sing-box` в PATH или VM; не разбирался.

## 6. Матрица совместимости

Статусы: ✅ подтверждено тестом; ⚠️ частично; ❌ несовместимо; ❓ не проверено.

| Возможность / вызов | Forkop (F/FE файл:строка) | xrust (X файл:строка) | Статус | Доказательство |
|---|---|---|---|---|
| Детект варианта rust-x | `singbox/runtime.uc:354-372` | `scripts/package_openwrt.py:71-79` | ✅ / ⚠️ без обёртки | §3.1 |
| XHTTP-возможность | `singbox/runtime.uc:293-304`, `generator.uc:561,615` | обёртка (Features захардкожены) | ⚠️ | FX-04 |
| `check -c` | `singbox/runtime.uc:724-750` | `main.rs:743-748` | ✅ | 18 конфигов |
| `run -c -D` | init.d пакета | `main.rs:621,682-691` | ✅ (`-D` — по коду) | §4 |
| `rule-set match` | `singbox/ruleset_cache.uc:279` | `rule_set.rs:344-380` | ✅ | §3.2 |
| `rule-set decompile` | `components/updates.uc:3444` | `rule_set.rs:234-257` | ✅ | §3.2 |
| `reload-plan` | `service/hot_reload.uc:118` | `main.rs:246-272` | ✅ | Forkop-тест PASS |
| SIGHUP hot reload | `service/hot_reload.uc:142` | `core-runtime/src/lib.rs:596-636` | ✅ | generation 1→2 |
| Отказ невалидного reload | `service/lifecycle.uc:640,1280` | `lib.rs:~605` | ✅ | WARN, старый рантайм жив |
| SIGTERM в работе | `service/state.uc:878-900` | `lib.rs:609-612` | ✅ rc=0 | все прогоны |
| SIGTERM во время старта | то же | `lib.rs:584-596` | ❌ | FX-06 |
| `tools fetch` | `diagnostics/runtime.uc:585` | `main.rs:740` | ❌ | FX-05 |
| `log.level` | settings.js:787, `generator.uc:453` | `core-config/src/validate.rs:34` | ⚠️ panic ❌ | FX-03 |
| VLESS REALITY+Vision | `generator.uc` (ссылки), `subscription/parser.uc` | outbound vless | ✅ | §5.1 |
| VLESS gRPC / WS / HTTPUpgrade (TLS, REALITY) | там же | transports | ✅ | §5.1 |
| VLESS XHTTP (auto, stream-one, packet-up) | `generator.uc`, `tests/reality_xhttp.uc` | xhttp | ✅ auto и stream-one; packet-up — только `check` | §5.1 |
| Hysteria2 + Salamander (клиент) | `generator.uc:2163` | `outbound/hysteria2.rs`, `outbound/quic.rs:503-530` | ✅ против spec-реле | §5.1 |
| trojan / ss / vmess / socks outbound | `generator.uc:536-545,1946-2160,2474-2484` | `validate.rs:4216-4242` | ❌ | FX-01, FX-02 |
| URLTest и selector | `singbox/urltest.uc`, `generator.uc` | route/urltest | ✅ selector; ⚠️ URLTest (`now` есть, история после 3–4 с пустая) | §5.2 |
| DNS UDP / DoH / DoT, bootstrap, `domain_resolver`, `detour` | `singbox/dns.uc:95-140` | dns | ✅ check и run; ❓ реальный upstream | §4 |
| DNS failover (смена сервера) | `singbox/dns_failover.uc`, `runtime.uc:905-930` | — | ⚠️ рабочий механизм — перегенерация и `check` рядом с ядром | FX-11 |
| FakeIP, `store_fakeip` | `generator.uc` base | dns/fakeip | ✅ | §5.3 |
| DNS `predefined`, `reject`, `evaluate`, `reverse_mapping` | `generator.uc:2832-2932` | `dns/rules.rs:153,207` | ✅ check и run; ✅ predefined и reject вживую | §4, §5.3 |
| TProxy v4/v6 | `generator.uc` base | `inbound/tproxy.rs` | ❓ нужен root (EPERM вживую) | §2.3 |
| Rule sets local source/binary, remote binary | `generator.uc:359-413,2486-2660` | route/rule_set | ✅ local; remote — только check (Forkop материализует) | §4 |
| Clash API (все формы Forkop) | §5.2 | `clash_api.rs` | ✅, кроме FX-07, FX-08 | §5.2 |
| `external_ui` | `generator.uc:430` | `clash_api.rs:168` | ❓ скачивание UI не проверялось | — |
| Mixed inbound с auth, DirectProxy | `generator.uc:1633-1743` | `inbound/mixed.rs` | ✅ (407 на неверный пароль) | §4 |
| `bind_interface`, `routing_mark`, `default_mark`, `default_interface` | `generator.uc` (vpn, zapret) | dialer | ❓ без root | §4 |
| cache_file и сохранённый selector | `singbox/cache_identity.uc` | cache_file | ✅ | §5.2 |
| Tailscale | `tailscale/*`, `init.d/forkop-tailscale` | `main.rs:703-722` | ⚠️ capability ✅, рантайм ❓ | §3.2 |
| TUN | не генерируется (только health `runtime_health.uc:9`) | `inbound/tun.rs` | ❓ | — |
| Установка, обновление, откат IPK/APK | `components/action.uc:477-488,917-921,1079,1932-1963,2650-2664` | `scripts/package_openwrt.py` | ❓ по коду согласовано | §3.6 |
| Процесс `sing-box` в `/proc/exe` | `service/state.uc:465-668` | обёртка `exec` | ✅ по коду; ❓ на роутере | §3.5 |

## 7. Проблемы

### FX-01 — Legacy-протоколы в подписке или ручной ссылке валят весь конфиг на rust-x
- **Статус:** ❌ подтверждено (`c10`, `c15`). **Приоритет:** P0.
- **Forkop:**
  - `singbox/generator.uc:536-545` (`supported_subscription_outbound` пропускает vmess, trojan, shadowsocks, socks);
  - `generator.uc:605-620` (`compatible_subscription_outbounds` отсекает только узлы с пинами и XHTTP);
  - ручные ссылки: `generator.uc:1946-2160`;
  - парсер: `subscription/parser.uc:920,959,1051,1129,1540-1609`;
  - прерывание: `singbox/runtime.uc:1022-1029`.
- **xrust:** `crates/core-config/src/validate.rs:4216-4242` — `#[cfg(not(feature="legacy-protocols"))]` возвращает ошибку на весь конфиг.
- **Причина.** Forkop умеет пропускать несовместимые узлы, но знает про это лишь для пинов и XHTTP. О наборе протоколов профиля rust-x ему ничего не известно; в выводе `version` этой информации нет.
- **Последствия.** Подписка у типичного провайдера часто смешанная (VLESS + trojan/ss). Одного такого узла достаточно, чтобы ядро не стартовало, а cold reload или подписочный reload завершился с `Generated sing-box configuration is invalid … excluded from Rust X`. На hot reload xrust сохраняет старый рантайм (проверено), но новые узлы так и не применяются.
- **Исправление.**
  1. xrust: в `version` (нативно, см. FX-04) печатать `Protocols: vless,hysteria2,wireguard,…` или `Excluded: vmess,trojan,shadowsocks,socks-outbound,…`, сгенерированные из cargo-features.
  2. Forkop: флаг `runtime_supports_legacy_protocols`; в `compatible_subscription_outbounds` пропускать такие узлы через `warn_skipped_subscription_outbound(..., "protocol X is not included in Xrust")`. Для ручных ссылок и JSON-outbound — понятная ошибка в `config/validator.uc` до генерации.
  3. Опционально в xrust: режим «skip unsupported outbound with WARN» вместо фатальной ошибки. Здесь аккуратно со ссылками selector и urltest на удалённые теги.
- **Риск исправления.** Пользователь молча теряет узлы, поэтому предупреждение нужно показывать в UI. Пропуск может оставить URLTest-группу пустой; Forkop уже fail-closed для пустых групп (`tests/urltest_groups.sh`).

### FX-02 — ByeDPI на rust-x не работает
- **Статус:** ❌ подтверждено (`c12`). **Приоритет:** P0 для пользователей ByeDPI.
- **Forkop:** `singbox/generator.uc:2474-2484` (`add_byedpi_outbound` → `type:"socks"`, `127.0.0.1:<BYEDPI_PORT_BASE+i>`, `version:"5"`).
- **xrust:** `validate.rs:4236` (`section == "outbounds" && ty == "socks"`); `docs/RUST-X.md` («outbound SOCKS» исключён).
- **Причина.** Outbound SOCKS исключён из профиля, а Forkop использует его как локальный мост к процессу ByeDPI.
- **Последствия.** Любая включённая секция ByeDPI не даёт ядру стартовать (`run: outbounds[2]: protocol "socks" is excluded from Rust X`, rc=1). Выключить её можно только вручную.
- **Исправление.** Предпочтительно в xrust вернуть в профиль rust-x минимальный SOCKS5 outbound: код не удалён и закрыт feature-флагом. Если размер критичен — разрешить его только для loopback-адресов. Альтернатива на стороне Forkop: валидатор запрещает ByeDPI при варианте rust-x, а LuCI скрывает действие.
- **Риск.** Около десятков КБ к бинарнику. Для loopback-only нужна проверка адреса в validate.

### FX-03 — `log_level=panic` из LuCI не принимается
- **Статус:** ❌ подтверждено (`c16-log-panic`: `check: create log factory: parse log level: unknown log level: panic`; так же в default-сборке). **Приоритет:** P1.
- **Forkop:** `luci-app-forkop/htdocs/luci-static/resources/view/forkop/settings.js:787` (`o.value("panic", "Panic")`); `singbox/generator.uc:453`; валидатор значение не проверяет.
- **xrust:** `crates/core-config/src/validate.rs:34` (`LOG_LEVELS` без `panic`); `core-runtime/src/logging.rs:28-35`.
- **Причина.** В Go sing-box уровень `panic` есть, в xrust нет.
- **Последствия.** Пользователь выбирает «Panic» в настройках, после чего Forkop не может применить ни один конфиг.
- **Исправление.** xrust: принимать `panic` как синоним `fatal` (маппинг в Error). Forkop, страховка: маппить `panic`→`fatal`, если `variant == rust-x`.
- **Риск.** Минимальный.

### FX-04 — Идентичность ядра держится на shell-обёртке с захардкоженными возможностями
- **Статус:** ⚠️ подтверждено (§3.1, `configs-bare/`). **Приоритет:** P1.
- **Forkop:** `singbox/runtime.uc:262-268,293-317,354-372`; `generator.uc:3473-3500`; `config/validator.uc:1994-2004` (минимальная версия); `components/action.uc:1932-1935,2650-2664`.
- **xrust:** `crates/core-cli/src/main.rs:58-77` (нативно `sing-box version v0.0.26-tachyon.0`); `scripts/package_openwrt.py:71-79` (обёртка с фиксированными `Features:` и `Tags:`); `openwrt/Makefile:53-60` (символическая ссылка без обёртки).
- **Причина.** Строку версии `1.14.2-rust-x.X` и возможности печатает shell-скрипт, а не бинарник.
- **Последствия.**
  - Если бинарник окажется в PATH без обёртки (ручная установка, сборка через `openwrt/Makefile`, `-v`/`--version`), Forkop определит вариант `stable` и версию `0.0`. Отключится DNS 1.14: `evaluate` станет legacy `route` и появится `independent_cache` (34 различия в `c07`). Отключится XHTTP: генерация падает на XHTTP-ссылке. Перестанет проходить проверка минимальной версии.
  - Обёртка не отражает реальные cargo-features. Сборка без `transport.xhttp` или `with_tailscale` всё равно заявит их.
  - Каждый `version` порождает лишний `sh` (мелочь).
- **Исправление.** Печатать полный совместимый вывод (`sing-box version 1.14.2-rust-x.<ver>`, `Features:`, `Tags:`, `Protocols:`) из самого бинарника при argv0 `sing-box`. Строки собирать из `cfg!(feature=…)`, baseline задавать константой в `core-cli`. Обёртку свести к `exec` или убрать. Обрабатывать `-v` и `--version` так же. `openwrt/Makefile` удалить или пометить как непригодный для Forkop (FX-16).
- **Риск.** Нужно синхронно обновить regex `components/action.uc:1932-1935`, если формат поменяется. Формат лучше не менять.

### FX-05 — Нет `sing-box tools fetch`
- **Статус:** ❌ подтверждено (`unknown command 'tools'`, rc=1). **Приоритет:** P2.
- **Forkop:** `diagnostics/runtime.uc:580-590` (`check_proxy`: 5 попыток `tools fetch ifconfig.me -c <tmp> -D <dir> --disable-color [-o tag]`, stderr в `/dev/null`).
- **xrust:** `crates/core-cli/src/main.rs:740` (нет команды `tools`).
- **Последствия.** Диагностика «Проверить прокси» на rust-x всегда сообщает об ошибке, причём без причины, потому что stderr подавлен.
- **Исправление.**
  - xrust: минимальный `tools fetch <url> [-o outbound]` — один HTTP(S) GET через указанный outbound на основе того же кода, что delay-test. Также `tools synctime` и `tools connect` по желанию.
  - Или Forkop для rust-x: через Clash API delay или поднять временный mixed-inbound.
- **Риск.** Низкий.

### FX-06 — SIGTERM не обрабатывается, пока `start()` не завершился
- **Статус:** ❌ подтверждено. **Приоритет:** P2.
- **Forkop:** `service/state.uc:878-900` (TERM, через 15 с KILL); `service/lifecycle.uc:1916-1937`.
- **xrust:** `crates/core-runtime/src/lib.rs:584-596`. Сигналы регистрируются заранее, но `start(&root).await?` стоит до `select!`.
- **Доказательство.** remote rule set на «чёрную дыру» `127.0.0.1:21997`, TERM через 1,5 с после старта. Процесс жил ещё **58,7 с** и вышел с rc=1 (`run: initial rule-set: … fetching /x.srs timed out`).
- **Последствия.** На роутере Forkop материализует rule sets заранее, так что основной триггер — другие медленные старты: endpoints, DNS для `domain_resolver`, большие SRS на медленном флеше. При остановке в момент старта Forkop шлёт SIGKILL, cache_file не сбрасывается, а stop/restart тормозится на 15 с.
- **Исправление.** `tokio::select! { r = start(&root) => r?, _ = term.recv() => return Ok(()) }` (то же для ctrl_c), с отменой фоновых задач. Плюс тест: «TERM во время старта завершает процесс за <1 с».
- **Риск.** Частично стартовавшие inbound'ы нужно корректно дропнуть.

### FX-07 — `/group/{name}/delay` возвращает не тот формат
- **Статус:** ⚠️ подтверждено (`{"message":"Timeout"}` или `{"delay":N}` вместо карты). **Приоритет:** P2.
- **Forkop:** FE `tabs/diagnostic/…/runSectionsCheck.ts:92-117`, `types.ts:682`; F `diagnostics/runtime.uc:1781-1786,1875-1885`; `service/ui.uc:1554`.
- **xrust:** `crates/core-runtime/src/clash_api.rs:595-604` (тот же `Route::Delay`), `:1488-1491`.
- **Последствия.**
  - В диагностике секций без выбранного узла показывается «не отвечает».
  - `Object.values` даёт `[N]`, и состояние латентности подписки искажается.
  - Если один участник группы (например, недоступный Hy2) упирается в тайм-аут, вся группа отвечает Timeout, хотя рабочие узлы есть (в тесте c03: Timeout при двух живых VLESS).
- **Исправление.** Для `/group/` параллельно тестировать всех участников и возвращать `{tag: delay}` только для успешных — семантика mihomo/sing-box. Писать историю каждому участнику.
- **Риск.** Нагрузка: N параллельных проб. Ограничить конкуренцию (например, 8).

### FX-08 — HTTP-forward через mixed не отслеживается в Clash API
- **Статус:** ❌ подтверждено. **Приоритет:** P2.
- **Forkop:** FE `tabs/monitoring/initController.ts:1394,1454`; DirectProxy и mixed-прокси секций (`generator.uc:1633-1743`).
- **xrust:** `crates/core-runtime/src/inbound/mixed.rs:660+` (`http_forward` использует `route_raw` и прямой dial, без `connect_tracked`; для сравнения `mixed.rs:397,650` и `inbound/mod.rs:1168-1182`).
- **Доказательство.** Во время скачивания 50 МБ:
  ```
  forward n=0 totals 0 0
  tunnel  n=1 totals 81 19524218
  socks   n=1 totals 162 38855263
  ```
- **Последствия.** Соединения LAN-клиентов, которые используют DirectProxy или mixed как обычный HTTP-прокси (не CONNECT), не видны в «Мониторинге». Они не входят в счётчики, и `DELETE /connections` их не закрывает. Hot-reload `revalidate-connections` такие соединения тоже не видит и не может закрыть устаревшие.
- **Исправление.** В `http_forward` использовать `connect_tracked` и `pump_conn_tracked`, отдельный трекер на каждый повторный dial при смене хоста.
- **Риск.** Низкий.

### FX-09 — `timeout` delay-запроса ограничен `i16`
- **Статус:** ⚠️ подтверждено (`timeout=40000` → 400 `{"message":"Body invalid"}`). **Приоритет:** P2.
- **Forkop:** `singbox/priority.uc:146,225` (`check_timeout` без ограничения), `diagnostics/runtime.uc:1812-1825`.
- **xrust:** `clash_api.rs:1238`.
- **Последствия.** При `check_timeout ≥ 33s` в приоритетных группах все узлы считаются мёртвыми. По словам субагента, Go ведёт себя так же; сам я это не проверял.
- **Исправление.** Forkop: ограничить до 30000 мс. xrust: парсить `u32` и обрезать до разумного максимума, чтобы не отдавать 400.
- **Риск.** Нет.

### FX-10 — Bearer в shell-вызовах только при WAN-доступе
- **Статус:** ⚠️ по коду; 401 без Bearer подтверждён на `c09`. **Приоритет:** P2. Это ошибка Forkop, не xrust.
- **Forkop:** `diagnostics/runtime.uc:1512-1517` (`clash_auth_args` смотрит на `enable_yacd_wan_access`); `generator.uc:428-433` (secret пишется при `enable_yacd`); `service/state.uc:1060` (`clash_api_ready`).
- **xrust:** auth на `clash_api.rs:1608-1631`, работает корректно.
- **Последствия.** Если ключ задан (например, через UCI CLI), а WAN-доступ выключен, readiness, задержки и восстановление selector'а получают 401.
- **Исправление.** Слать Bearer всегда, когда `secret` есть в конфиге; secret брать из сгенерированного конфига, как в `hot_reload.uc:96`.
- **Риск.** Нет.

### FX-11 — Пиковая память CLI-вызовов рядом с живым ядром
- **Статус:** ⚠️ замер + код. **Приоритет:** P2. На 128 МБ ближе к P1, если rule sets большие.
- **Forkop:** DNS failover перегенерирует конфиг и вызывает `sing_box_check` при живом ядре (`singbox/runtime.uc:905-930`), хотя комментарий на `:735-737` предупреждает о пиках. `rule-set match` вызывается на каждый обновлённый SRS (`singbox/ruleset_cache.uc:279`).
- **xrust:** `core-cli/src/rule_set.rs:344-380`, `main.rs` check.
- **Замеры** (мои, release x86_64 glibc, `/usr/bin/time %M`): см. §8. `match` на SRS 1,19 МБ (180 тыс. доменов) — **42 832 KiB**, `compile` — 128 084 KiB (Forkop его не вызывает), `check` — 9,7–12,5 МиБ.
- **Исправление.**
  - xrust: потоковая валидация в `rule-set match` без построения полного матчера (достаточно проверить формат и пройти структуру).
  - Forkop: при rust-x и hot reload валидировать DNS failover через `reload-plan` (он уже делает полный check, а пик ~10 МБ).
- **Риск.** Слабая валидация может пропустить битый SRS. Нужны негативные тесты (есть `tests/ruleset_binary_validation_vm.sh`).

### FX-12 — Порядок `chains`
- **Статус:** ⚠️ xrust подтверждён (`["main-out","main-4-out"]`, группа первой); поведение Go — **гипотеза** по памяти о `common.Reverse` в tracker. **Приоритет:** P3.
- **Forkop:** FE `tabs/monitoring/initController.ts:374-375` (`reverse().find(getRouteDisplayNameByTag)` — работает при любом порядке).
- **xrust:** `core-runtime/src/inbound/mod.rs:476-500`.
- **Исправление.** Сверить с эталоном. Если в Go лист идёт первым, развернуть порядок, чтобы сторонние дашборды (yacd/zashboard на `external_ui`) показывали цепочку правильно.
- **Риск.** Нет.

### FX-13 — Тип `Reject` у block
- **Статус:** ⚠️ по коду. **Приоритет:** P3.
- **Forkop:** `diagnostics/runtime.uc:1565-1569` (исключает `block`, но не `reject`).
- **xrust:** `clash_api.rs:1332-1333`.
- Генератор Forkop block-outbound не создаёт (block реализован как `action: reject`), поэтому влияния нет. Исправление: добавить `reject` в список исключений Forkop.

### FX-14 — Серверный Hysteria2 + Salamander сломан
- **Статус:** ❌ подтверждено: клиент и сервер xrust с obfs — тайм-аут; без obfs работает; клиент через spec-реле работает. **Приоритет:** P3 (Forkop серверную часть не использует, но она ломает интеграционные тесты и любые серверные сценарии).
- **xrust:** `crates/core-runtime/src/inbound/hysteria2.rs:120-160`. В `out_task` вызывается `pub_out.send(&sealed)` на **неподключённом** UDP-сокете; адрес пира из `recv_from` выбрасывается (`_peer`). Это гипотеза о причине, сделанная по коду: `send` без `connect` даёт ошибку, которая игнорируется через `let _ =`.
- **Исправление.** Хранить карту «пир ↔ сокет» или хотя бы последний пир и отвечать через `send_to(peer)`. Для нескольких клиентов нужен отдельный loop-сокет на каждого.
- **Риск.** Без NAT-карты на каждого клиента мультиклиентский сценарий сломается.

### FX-15 — Серверный VLESS с правилом `ip_cidr` ломает delay-пробы
- **Статус:** ❓ симптом подтверждён, причина не установлена. **Приоритет:** P3.
- **Доказательство.** Серверные варианты A (`final: direct`) и B (правило по `inbound`) дают `delay` OK. Вариант C (`ip_cidr 127.0.0.0/8 → direct, final block`) отвечает «An error occurred in the delay test», хотя CONNECT и SOCKS через тот же сервер работают, а сервер логирует `inbound connection to 127.0.0.1:21999`.
- **Гипотеза.** Ранние данные (HEAD, отправленные вместе с VLESS-заголовком) теряются или задерживаются на пути с IP-правилом. На клиентской стороне (tproxy/mixed + `ip_cidr`) проблема не воспроизводится: проверено, `forward`, `tunnel` и `socks` вернули `[hello]`.
- **Исправление.** Отладить `inbound/proxy.rs` / `route_raw` для VLESS-inbound с буфером ранних данных.
- **Риск.** Если та же логика используется и на клиенте для каких-то inbound'ов, это был бы P1. Для tproxy это не проверено (нужен root).

### FX-16 — Устаревший `openwrt/Makefile`
- **Статус:** ⚠️ по коду. **Приоритет:** P3.
- **xrust:** `openwrt/Makefile:24-60`:
  - пакет `tachyon-core`;
  - `cargo build --release` в профиле **default**, а не rust-x;
  - `/usr/bin/sing-box` — символическая ссылка без обёртки;
  - собственный init `tachyon-core` и ссылка `/etc/init.d/sing-box`;
  - `PROVIDES:=sing-box` без `CONFLICTS`.
- **Последствия.** Сборка через OpenWrt SDK дала бы ядро, которое Forkop видит как `stable 0.0` (FX-04), с другим init-скриптом.
- **Исправление.** Удалить или переписать по `scripts/package_openwrt.py`; в `docs/OPENWRT-PACKAGES.md` прямо указать, что для Forkop годится только он.

### FX-17 — Мелочи на стороне Forkop (по отчёту субагента, вживую не проверено)
- **Статус:** ❓. **Приоритет:** P3.
- `components/action.uc:2996-3001`: проверка владельца после обновления жёстко ждёт `/usr/bin/sing-box run -c /etc/sing-box/config.json`. Не совпадёт, если в LuCI выбран `config_path=/tmp/sing-box/config.json`.
- `full-uninstall.sh:157-170` не удаляет `/usr/lib/rust-x` и `/usr/share/rust-x`.
- `service/state.uc:518-526` — мёртвый `hup_sing_box_runtime`.

## 8. Память: Forkop X + xrust на роутере

### 8.1. Цифры из документов (не мои)

| Источник | Цифра |
|---|---|
| Forkop `docs/tachyon-core-vm-smoke-2026-10-10.md:25` | RSS tachyon после smoke-трафика: 8076 kB (OpenWrt 25), 7984 kB (OpenWrt 24) |
| Forkop `docs/tachyon-core-primary-vm25-2026-10-10.md:18` | RSS 12276 kB на полном `/etc/sing-box/config.json` |
| Forkop `docs/sing-box-x-1.14.2-verification-2026-10-07.md:48-57` | Go X: ~43,5 МиБ в работе; пик `check` 47–49 МиБ; пик `match` ~50 МиБ |
| Forkop `docs/sing-box-x-router90-verification-2026-10-07.md:20` | Go X на роутере: 49 404 KiB |
| Forkop `docs/oom-ruleset-validation.md:31-37,63-74` | HaGeZi Pro SRS 1 784 157 B: старый `decompile` 139 740 KiB (OOM 137), `match` 32 380 KiB; рантайм с этим набором 28 836 KiB; Extended 76–114 МиБ на `match` |
| Forkop `docs/forkop-rust-x-hot-reload-2026-10-12.md:88` | 256 МиБ RAM и все узлы подписки не проверялись |
| xrust `docs/RUST-X.md` | бинарник 11 017 744 B (rust-x) против 12 752 656 B (full); это размер файла, не RAM |
| xrust `docs/adr/0002*` | цели: бинарник ≤ 12 МиБ, стартовый RSS ≤ 15 МиБ |
| xrust `docs/transport-performance-2026-10-23.md:111,132` | пик RSS клиента под нагрузкой: XHTTP 95–97 МиБ; WG/AWG 17,3 → 10,3 МиБ |

### 8.2. Мои замеры
Условия: release rust-x, **x86_64 glibc + mimalloc**, хост с 28 CPU. На роутере musl, 2–4 ядра, поэтому цифры ориентировочные и, вероятно, завышены за счёт арен аллокатора и потоков.

| Сценарий | 28 CPU | `taskset -c 0-1` |
|---|---|---|
| `run` c01 (1 узел, FakeIP, community), простой | 19 888 kB | 17 448 kB |
| `run` c02 (9 узлов), простой | 21 316 kB | 19 088 kB |
| c02 после 150 МБ трафика (WS) и 8 delay-проб | 41 696 kB | 32 844 kB (HWM 33 408) |
| c02 + 3 × SRS по 180 тыс. доменов (1,19 МБ каждый), в DNS и route | RSS 47 252 kB, HWM 55 836 | RSS 38 636 kB, **HWM 60 212** |
| `check` c02 / c07 | 9 764 / 12 480 kB (пик) | — |
| `reload-plan` | 9 988 kB | — |
| `rule-set match` big.srs (1,19 МБ) | **42 832 kB** | — |
| `rule-set decompile` big.srs | 46 564 kB | — |
| `rule-set compile` big.json (Forkop не вызывает) | 128 084 kB | — |
| ucode: генератор (c02, c15) | 4 256 kB, 0,05–0,06 с | — |
| ucode: загрузка `service.state` (как каждый тик watchdog) | 3 360 kB | — |
| ucode пустой | 2 240 kB | — |

Debug-сборка (не показатель): RSS 45–83 МБ.

### 8.3. Оценка бюджета для роутера (гипотеза на основе 8.1 и 8.2)
- **Постоянно:**
  - xrust 15–35 МиБ: по VM-документам 8–12 МиБ на малых конфигах, у меня 17–33 МиБ на x86 glibc;
  - плюс rule sets примерно 5–7 МиБ на каждые ~180 тыс. доменов;
  - плюс процессы Forkop: procd-инстанс `dns-watchdog` (sh) и при наличии воркеры priority и DNS failover — ucode по 2–4 МиБ.
- **Каждые 5 с** watchdog запускает 2 коротких ucode-процесса по ~3–4 МиБ. Это не RSS-нагрузка, а CPU и fork-нагрузка: около 35 000 запусков в сутки.
- **Пики:**
  - `rule-set match` при обновлении списков — +35–45 МиБ на большой SRS;
  - `check` при DNS failover — +10–13 МиБ;
  - пик HWM ядра при загрузке больших наборов — +20 МиБ к стационарному.
- **На 128 МиБ** (свободно обычно 60–80) при больших наборах вроде HaGeZi Pro реален риск OOM. Опасна одновременность: старый рантайм + `match` + `check` во время обновления списков и cold reload. На 256 МиБ запас есть.
- **DNS-кэш xrust** не замерялся; размер кэша в конфиге Forkop не задаётся. FakeIP-таблица сохраняется в cache_file (`store_fakeip`). В xrust `cache_file.rs:1-8` весь bbolt-образ переписывается в памяти при каждом flush: это пик, пропорциональный размеру файла (гипотеза о масштабе, не замерялось).

## 9. Интеграционные тесты, которые стоит добавить

Все тесты — offline, loopback, генерация штатным `generate-config-fixture` через собранный ucode. Скрипты стенда можно взять из `$S/forkop/scripts/`.

1. **Матрица «генератор Forkop → check» в CI xrust.** Хранить фикстуры `c01…c16` в `tests/forkop/fixtures` и выход генератора, зафиксированный на версии Forkop. Проверять, что для профиля rust-x падают **только** ожидаемые (legacy). Это регрессия на FX-01, FX-02, FX-03 и защита от «unknown field».
2. **Подписка со смешанными протоколами.** Обязательный тест на стороне Forkop: после исправления FX-01 генерация для `1.14.2-rust-x.*` исключает trojan, ss и vmess с WARN, а `check` проходит.
3. **ByeDPI + rust-x.** Либо `check` проходит (socks loopback разрешён), либо валидатор Forkop отказывает с понятным текстом.
4. **Все `log_level` из LuCI** проходят `check`.
5. **Транспорты против локального xrust-сервера:** REALITY Vision, gRPC, XHTTP (auto, stream-one, packet-up), TLS WS, HTTPUpgrade, gRPC; delay через Clash API и реальный CONNECT. После исправления FX-14 — Hy2 + Salamander сервер↔клиент; до тех пор — клиент через spec-реле.
6. **Hot reload по-forkop'овски:** `reload-plan`, затем HUP, затем рост `generation` и совпадение sha256, затем `revalidate-connections`. Плюс кейсы: невалидный JSON, legacy-протокол, смена inbound (`in_place:false`, перезапуск в процессе), откат.
7. **SIGTERM во время медленного старта** (blackhole remote rule set): процесс завершается за ≤ 1 с (FX-06). Плюс TERM в работе: rc=0 и сброшенный cache_file.
8. **Контракт Clash API** на формы Forkop:
   - `/proxies` (типы, `now`, `all`, `history`);
   - delay с `timeout` 1000/30000/40000;
   - `/group/*/delay` — карта (FX-07);
   - PUT selector: 204/404/400;
   - `/connections` для CONNECT, SOCKS и **HTTP-forward** (FX-08);
   - WS `/traffic` и `/connections?token=`, 401 без токена, CORS preflight;
   - DELETE соединения;
   - имена с пробелом, кириллицей и эмодзи (`🇱🇻 Riga A`).
9. **`version`-контракт:** вывод бинарника под argv0 `sing-box` содержит `-rust-x.`, `Features: transport.xhttp`, `Tags: with_tailscale` и `Protocols:`. Прогон `ucode singbox/runtime.uc variant|supports-xhttp|supports-tailscale` должен дать `rust-x`/0/0, в том числе для `-v` (FX-04).
10. **CLI-контракт Forkop:** `rule-set match --format binary <srs> forkop-validation.invalid` (rc=0 и rc=1 на битом файле), `decompile -o`, `tools fetch` (после FX-05), `tailscale-*-capability`.
11. **Память:** `/usr/bin/time` для `match`/`check`/`run` на синтетическом 180k-SRS и на HaGeZi-подобном наборе в musl-сборке; бюджет, например, `match` ≤ 35 МиБ и `run` + 3 SRS ≤ 45 МиБ. Регрессия на FX-11.
12. **DNS:** `dns-in` отвечает FakeIP для `fakeip.podkop.fyi`, `predefined NOERROR` на HTTPS, REFUSED на `use-application-dns.net`. Плюс локальный DoH/DoT-сервер на loopback для проверки цепочки `domain_resolver` → bootstrap и `detour` (сейчас ❓).
13. **На VM OpenWrt** (вне этого хоста): tproxy + nft + `forkop start/stop/restart`, watchdog с убийством ядра, установка, обновление и откат IPK/APK `rust-x` с проверкой `/proc/<pid>/exe` и единственности процесса.

## 10. Ограничения аудита
- Нет root, OpenWrt, procd и nft: TProxy, `routing_mark`/`default_mark`, `bind_interface`, watchdog, init-скрипты и установка пакетов проверены только по коду.
- Измерения памяти сделаны на x86_64 glibc, а не musl или aarch64 (§8.2).
- Внешние DNS, узлы, Tailscale и скачивание `external_ui` не трогались.
- Один эпизод внешнего трафика к `www.gstatic.com` описан в §2.4.
- Статусы «по коду» в FX-12, FX-13 и FX-17 частично основаны на отчётах двух субагентов, которые читали код. Утверждения о поведении Go sing-box не проверялись запуском эталона.
- Репозитории не изменялись. Создан только этот файл; всё остальное лежит в `$S`.

## 11. Артефакты
- Конфиги генератора: `$S/forkop/configs/c01…c16*.json` (+ `.rulesets/`, `.section-cache/`), варианты под голый бинарник — `$S/forkop/configs-bare/`.
- Фикстуры UCI: `$S/forkop/fixtures/*.fixture.json`, подписка — `$S/forkop/fixtures/subscription.txt`.
- Локализованные копии для `run` и логи: `$S/forkop/run/r-*.json`, `*.log`. Сервер стенда: `$S/forkop/server/`.
- Итоги: `$S/forkop/check-results.txt`, `$S/forkop/run-results.txt`. Сборки: `$S/target-forkop` (rust-x debug + release), `$S/target-forkop-default`. ucode: `$S/forkop/prefix/bin/ucode`.
- В конфигах только тестовые ключи и UUID, сгенерированные для стенда. В `forkop/files/etc/config/forkop` есть адрес оператора поддержки и URL зеркала; их значения здесь не воспроизводятся.
