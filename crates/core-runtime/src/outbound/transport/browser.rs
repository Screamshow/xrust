//! The browser headers Xray puts on its XHTTP, WebSocket and HTTPUpgrade
//! requests (`common/utils/browser.go`, `TryDefaultHeadersWith`): with no
//! `User-Agent` in the config the request is dressed as Chrome on Windows,
//! and a `User-Agent` of `chrome`, `edge`, `firefox`, `safari`, `curl` or
//! `golang` names a profile instead of being sent literally. Any other
//! `User-Agent` is the user's own and nothing is added.
//!
//! Versions follow the calendar the way the reference does. The reference
//! holds each one back by a lag it draws from a PRNG seeded with the CPU's
//! identity, so the version it advertises is a constant of the machine; the
//! lag here comes from `/proc/cpuinfo` for the same reason. Drawing it per
//! process instead would move the advertised version on every restart, which
//! no browser does.

use std::sync::OnceLock;

/// Which request the headers belong to: the reference's variant argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Variant {
    /// `fetch`: the XHTTP requests.
    Fetch,
    /// `ws`: the WebSocket and HTTPUpgrade upgrade requests.
    Ws,
}

/// The browsers the reference can dress a request as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Profile {
    Chrome,
    Edge,
    Firefox,
    Safari,
    Curl,
    Golang,
}

/// What to put on a request. The reference sets the browser block and the
/// `Sec-Fetch-*` headers over whatever the config carries, and fills
/// `Accept`, `Cache-Control`, `Pragma` and `Priority` only where the config
/// said nothing.
pub(crate) struct Defaults {
    /// Headers that replace a configured one of the same name.
    pub(crate) force: Vec<(&'static str, String)>,
    /// Headers to add only where the config has no header of that name.
    pub(crate) fill: Vec<(&'static str, String)>,
    /// Whether the configured `User-Agent` named a profile and so must not be
    /// sent as it stands.
    pub(crate) drop_configured_ua: bool,
}

impl Defaults {
    fn empty() -> Self {
        Self {
            force: Vec::new(),
            fill: Vec::new(),
            drop_configured_ua: false,
        }
    }

    /// Whether `name` is replaced by this set.
    pub(crate) fn replaces(&self, name: &str) -> bool {
        self.force
            .iter()
            .any(|(known, _)| known.eq_ignore_ascii_case(name))
    }
}

/// The headers for a request whose config carries `configured_ua`, if any.
pub(crate) fn defaults(configured_ua: Option<&str>, variant: Variant) -> Defaults {
    // The reference matches the special values exactly: a `User-Agent` that is
    // not one of them is sent as it stands.
    let (profile, named) = match configured_ua {
        None => (Profile::Chrome, false),
        Some("chrome") => (Profile::Chrome, true),
        Some("edge") => (Profile::Edge, true),
        Some("firefox") => (Profile::Firefox, true),
        Some("safari") => (Profile::Safari, true),
        Some("curl") => (Profile::Curl, true),
        Some("golang") => (Profile::Golang, true),
        Some(_) => return Defaults::empty(),
    };
    let mut set = Defaults {
        drop_configured_ua: named,
        ..Defaults::empty()
    };
    match profile {
        Profile::Chrome | Profile::Edge => {
            let version = chrome_version();
            set.force
                .push(("sec-ch-ua", greased_ch_ua(version, profile)));
            set.force.push(("sec-ch-ua-mobile", "?0".to_string()));
            set.force
                .push(("sec-ch-ua-platform", "\"Windows\"".to_string()));
            set.force.push(("dnt", "1".to_string()));
            set.force.push(("user-agent", chrome_ua(version, profile)));
            set.force
                .push(("accept-language", "en-US,en;q=0.9".to_string()));
        }
        Profile::Firefox => {
            set.force.push(("user-agent", firefox_ua()));
            set.force.push(("dnt", "1".to_string()));
            set.force
                .push(("accept-language", "en-US,en;q=0.5".to_string()));
        }
        Profile::Safari => {
            set.force.push(("user-agent", safari_ua()));
            set.force
                .push(("accept-language", "en-US,en;q=0.9".to_string()));
        }
        Profile::Curl => {
            set.force
                .push(("user-agent", format!("curl/{}", curl_version())));
            return set;
        }
        Profile::Golang => {
            // The reference drops the header and lets Go's `net/http` put its
            // own back on the requests it writes. A websocket upgrade is not
            // one of those: the reference's ws dialer writes the headers it
            // was handed, so that request carries no `User-Agent` at all.
            if variant != Variant::Ws {
                set.force
                    .push(("user-agent", "Go-http-client/1.1".to_string()));
            }
            return set;
        }
    }
    match variant {
        Variant::Ws => {
            set.force.push(("sec-fetch-mode", "websocket".to_string()));
            // Safari is not web-compliant here, and the reference follows it.
            let dest = if profile == Profile::Safari {
                "websocket"
            } else {
                "empty"
            };
            set.force.push(("sec-fetch-dest", dest.to_string()));
            set.force
                .push(("sec-fetch-site", "same-origin".to_string()));
            set.fill.push(("cache-control", "no-cache".to_string()));
            set.fill.push(("pragma", "no-cache".to_string()));
            set.fill.push(("accept", "*/*".to_string()));
        }
        Variant::Fetch => {
            set.force.push(("sec-fetch-mode", "cors".to_string()));
            set.force.push(("sec-fetch-dest", "empty".to_string()));
            set.force
                .push(("sec-fetch-site", "same-origin".to_string()));
            let priority = match profile {
                Profile::Firefox => "u=4",
                Profile::Safari => "u=3, i",
                _ => "u=1, i",
            };
            set.fill.push(("priority", priority.to_string()));
            set.fill.push(("cache-control", "no-cache".to_string()));
            set.fill.push(("pragma", "no-cache".to_string()));
            set.fill.push(("accept", "*/*".to_string()));
        }
    }
    set
}

/// How the reference spells a header name on an HTTP/1 request. The names
/// above are the lower-case ones HPACK wants on the XHTTP requests; an upgrade
/// request carries them with the capitalization the reference writes, which
/// for the client hints is the one Chromium itself uses rather than Go's
/// canonical form (the reference assigns them into the header map directly).
pub(crate) fn h1_name(lower: &str) -> &'static str {
    match lower {
        "sec-ch-ua" => "Sec-CH-UA",
        "sec-ch-ua-mobile" => "Sec-CH-UA-Mobile",
        "sec-ch-ua-platform" => "Sec-CH-UA-Platform",
        "dnt" => "DNT",
        "user-agent" => "User-Agent",
        "accept-language" => "Accept-Language",
        "sec-fetch-mode" => "Sec-Fetch-Mode",
        "sec-fetch-dest" => "Sec-Fetch-Dest",
        "sec-fetch-site" => "Sec-Fetch-Site",
        "cache-control" => "Cache-Control",
        "pragma" => "Pragma",
        "accept" => "Accept",
        "priority" => "Priority",
        other => {
            debug_assert!(false, "no HTTP/1 spelling for {other:?}");
            "X-Unknown"
        }
    }
}

/// The `User-Agent` of a profile on its own, for a request that takes no
/// other browser header: the reference's gRPC dialer dresses its connection
/// in one of these and nothing else (`grpc/dial.go`, `utils.ChromeUA` and the
/// `firefox`/`edge`/`golang` cases). `None` is a request that carries no
/// `User-Agent` at all, which is what `golang` means there.
pub(crate) fn profile_user_agent(configured_ua: Option<&str>) -> Option<String> {
    match configured_ua {
        None | Some("chrome") => Some(chrome_ua(chrome_version(), Profile::Chrome)),
        Some("edge") => Some(chrome_ua(chrome_version(), Profile::Edge)),
        Some("firefox") => Some(firefox_ua()),
        Some("safari") => Some(safari_ua()),
        Some("curl") => Some(format!("curl/{}", curl_version())),
        Some("golang") => None,
        Some(own) => Some(own.to_string()),
    }
}

/// `ChromeVersion` in the reference: the major version a current Chrome has
/// today, held back by the machine's lag.
fn chrome_version() -> u64 {
    static VERSION: OnceLock<u64> = OnceLock::new();
    *VERSION.get_or_init(|| {
        let lag = (unit("chrome").powi(2) * 105.0).floor() as i64;
        // Chrome 144 was released on 2026-01-13, one major every 35 days.
        let diff = today() - days_from_civil(2026, 1, 13) - 35 - lag;
        (144 + diff.div_euclid(35)).max(144) as u64
    })
}

/// `FirefoxVersion`: 128 ESR on 2024-07-29, one major every 30 days.
fn firefox_version() -> u64 {
    static VERSION: OnceLock<u64> = OnceLock::new();
    *VERSION.get_or_init(|| {
        let lag = (unit("firefox").powi(2) * 50.0).floor() as i64;
        let diff = today() - days_from_civil(2024, 7, 29) - 25 - lag;
        (128 + diff.div_euclid(30)).max(128) as u64
    })
}

/// `CurlVersion`: 8.0.0 on 2023-03-20, a minor every 57 days.
fn curl_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let lag = (unit("curl").powi(2) * 165.0).floor() as i64;
        let diff = today() - days_from_civil(2023, 3, 20) - 60 - lag;
        format!("8.{}.0", diff.div_euclid(57).max(0))
    })
}

/// How many minor releases a Safari major has had, by fortnight since its
/// September release: `safariMinorMap` in the reference.
const SAFARI_MINORS: [u64; 25] = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
];

/// `SafariVersion`: the major is the year less 1999, released every September
/// 23rd, and the minor follows the fortnight since that release.
fn safari_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let now = unix_time();
        let delayed = (unit("safari").powi(3) * 75.0).floor() as i64;
        let mut year = civil_year(now.div_euclid(86_400));
        let mut split = (days_from_civil(year, 9, 23) + delayed) * 86_400;
        if now < split {
            year -= 1;
            split = (days_from_civil(year, 9, 23) + delayed) * 86_400;
        }
        // A fortnight is 1_296_000 seconds; the table covers one release year.
        let index = ((now - split).div_euclid(1_296_000) as usize).min(SAFARI_MINORS.len() - 1);
        format!("{}.{}", year - 1999, SAFARI_MINORS[index])
    })
}

fn chrome_ua(version: u64, profile: Profile) -> String {
    let chrome = format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
    );
    match profile {
        // `MSEdgeUA = ChromeUA + "Edg/..."` in the reference, with no space
        // before `Edg/`. Kept as it is: this is the string on the wire.
        Profile::Edge => format!("{chrome}Edg/{version}.0.0.0"),
        _ => chrome,
    }
}

fn firefox_ua() -> String {
    let version = firefox_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) \
         Gecko/20100101 Firefox/{version}.0"
    )
}

fn safari_ua() -> String {
    format!(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
         (KHTML, like Gecko) Version/{} Safari/605.1.15",
        safari_version()
    )
}

/// `getGreasedChUa(version, fork)`: the invalid brand, Chromium and the fork,
/// in an order the major version picks.
fn greased_ch_ua(version: u64, profile: Profile) -> String {
    const NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const NA_VERSION: [&str; 3] = ["8", "99", "24"];
    const SHUFFLE: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let seed = version as usize;
    let fork = match profile {
        Profile::Edge => "Microsoft Edge",
        _ => "Google Chrome",
    };
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            NA[seed % NA.len()],
            NA[(seed + 1) % NA.len()],
            NA_VERSION[seed % NA_VERSION.len()]
        ),
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"{fork}\";v=\"{version}\""),
    ];
    let order = SHUFFLE[seed % SHUFFLE.len()];
    let mut shuffled = [String::new(), String::new(), String::new()];
    for (i, at) in order.iter().enumerate() {
        shuffled[*at] = brands[i].clone();
    }
    shuffled.join(", ")
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn today() -> i64 {
    unix_time().div_euclid(86_400)
}

/// A number in `[0, 1)` that is a constant of this machine, one per name. The
/// reference seeds its PRNG with a hash of the CPU's identity; the hash here
/// is over what `/proc/cpuinfo` says about it, with the machine id and then
/// the host name as fallbacks.
fn unit(name: &str) -> f64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        let mut facts = String::new();
        if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
            let mut cores = 0usize;
            for line in info.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let key = key.trim();
                if matches!(
                    key,
                    "cpu family" | "model" | "model name" | "cache_alignment" | "cpu model"
                ) {
                    facts.push_str(value.trim());
                    facts.push('/');
                }
                if key == "processor" {
                    cores += 1;
                }
            }
            if cores > 0 {
                facts.push_str(&cores.to_string());
            }
        }
        if facts.is_empty() {
            facts = std::fs::read_to_string("/etc/machine-id").unwrap_or_default();
        }
        if facts.trim().is_empty() {
            facts = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        }
        fnv1a64(facts.trim().as_bytes())
    });
    let mixed = fnv1a64(&[&seed.to_le_bytes()[..], name.as_bytes()].concat());
    // The top 53 bits, the mantissa of an f64, as the reference's `Float64`.
    ((mixed >> 11) as f64) / ((1u64 << 53) as f64)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Days from the Unix epoch to a UTC calendar date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The UTC year a day since the Unix epoch falls in.
fn civil_year(days: i64) -> i64 {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    if month_prime >= 10 { year + 1 } else { year }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference's brand list for Chrome 144: version 144 picks `NA[1]`,
    /// `NA[2]`, `"8"` and the shuffle `[0, 1, 2]`.
    #[test]
    fn ch_ua_is_greased_like_chromium() {
        assert_eq!(
            greased_ch_ua(144, Profile::Chrome),
            "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\""
        );
        // another seed, another order: 145 % 6 = 1 puts Chromium last
        assert_eq!(
            greased_ch_ua(145, Profile::Chrome),
            "\"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\""
        );
        assert_eq!(
            greased_ch_ua(144, Profile::Edge),
            "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Microsoft Edge\";v=\"144\""
        );
    }

    #[test]
    fn the_version_follows_the_date() {
        let version = chrome_version();
        // late October 2026: (286 - 35 - lag) / 35 over 144
        assert!((144..=152).contains(&version), "{version}");
        let ua = profile_user_agent(None).expect("a user agent");
        assert!(ua.contains(&format!("Chrome/{version}.0.0.0")), "{ua}");
    }

    /// The lag is a constant of the machine, so two draws of the same name
    /// agree and different names do not have to.
    #[test]
    fn the_lag_is_stable_for_this_machine() {
        assert_eq!(unit("chrome"), unit("chrome"));
        assert!((0.0..1.0).contains(&unit("chrome")));
        assert!((0.0..1.0).contains(&unit("safari")));
    }

    #[test]
    fn civil_dates_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 1, 13), 20_466);
        assert_eq!(civil_year(days_from_civil(2026, 1, 13)), 2026);
        assert_eq!(civil_year(days_from_civil(2026, 12, 31)), 2026);
        assert_eq!(civil_year(days_from_civil(2027, 1, 1)), 2027);
        assert_eq!(civil_year(0), 1970);
    }

    #[test]
    fn the_versions_are_plausible() {
        let firefox = firefox_version();
        assert!((128..=200).contains(&firefox), "{firefox}");
        let safari = safari_version();
        let (major, minor) = safari.split_once('.').expect("major.minor");
        assert!(
            (25..=40).contains(&major.parse::<u64>().expect("major")),
            "{safari}"
        );
        assert!(minor.parse::<u64>().expect("minor") <= 6, "{safari}");
        let curl = curl_version();
        assert!(curl.starts_with("8.") && curl.ends_with(".0"), "{curl}");
    }

    /// With no `User-Agent` configured the upgrade request is dressed as
    /// Chrome making a websocket request, the reference's `ws` variant.
    #[test]
    fn the_ws_variant_is_the_reference_set() {
        let set = defaults(None, Variant::Ws);
        let names: Vec<&str> = set.force.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "dnt",
                "user-agent",
                "accept-language",
                "sec-fetch-mode",
                "sec-fetch-dest",
                "sec-fetch-site",
            ]
        );
        let value = |list: &[(&str, String)], want: &str| {
            list.iter()
                .find(|(name, _)| *name == want)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            value(&set.force, "sec-fetch-mode").as_deref(),
            Some("websocket")
        );
        assert_eq!(
            value(&set.force, "sec-fetch-dest").as_deref(),
            Some("empty")
        );
        let fill: Vec<&str> = set.fill.iter().map(|(name, _)| *name).collect();
        assert_eq!(fill, ["cache-control", "pragma", "accept"]);
        assert!(!set.drop_configured_ua);
        // no `Priority` on a websocket upgrade, unlike the fetch variant
        assert!(value(&set.fill, "priority").is_none());
    }

    #[test]
    fn safari_asks_for_a_websocket_destination() {
        let set = defaults(Some("safari"), Variant::Ws);
        let dest = set
            .force
            .iter()
            .find(|(name, _)| *name == "sec-fetch-dest")
            .expect("sec-fetch-dest");
        assert_eq!(dest.1, "websocket");
        assert!(set.drop_configured_ua);
        assert!(set.replaces("User-Agent"));
    }

    /// A `User-Agent` that names no profile is the user's own: nothing is
    /// added and nothing is replaced.
    #[test]
    fn an_own_user_agent_is_left_alone() {
        let set = defaults(Some("mine/1.0"), Variant::Ws);
        assert!(set.force.is_empty() && set.fill.is_empty());
        assert!(!set.drop_configured_ua);
        assert!(!set.replaces("user-agent"));
    }

    /// `curl` and `golang` carry no browser block and no `Sec-Fetch-*`.
    #[test]
    fn the_tool_profiles_are_bare() {
        let curl = defaults(Some("curl"), Variant::Fetch);
        assert_eq!(curl.force.len(), 1);
        assert!(curl.force[0].1.starts_with("curl/8."));
        assert!(curl.fill.is_empty());

        let go_fetch = defaults(Some("golang"), Variant::Fetch);
        assert_eq!(
            go_fetch.force,
            [("user-agent", "Go-http-client/1.1".into())]
        );
        // the reference's ws dialer sends no user agent at all for `golang`
        let go_ws = defaults(Some("golang"), Variant::Ws);
        assert!(go_ws.force.is_empty());
        assert!(go_ws.drop_configured_ua);
    }

    /// Every name a profile can return has an HTTP/1 spelling.
    #[test]
    fn every_name_has_an_http1_spelling() {
        for ua in [
            None,
            Some("chrome"),
            Some("edge"),
            Some("firefox"),
            Some("safari"),
            Some("curl"),
            Some("golang"),
        ] {
            for variant in [Variant::Fetch, Variant::Ws] {
                let set = defaults(ua, variant);
                for (name, _) in set.force.iter().chain(set.fill.iter()) {
                    let spelled = h1_name(name);
                    assert_eq!(
                        spelled.to_ascii_lowercase(),
                        *name,
                        "{name} is spelled {spelled}"
                    );
                }
            }
        }
    }

    /// The bare `User-Agent` of a profile, for the gRPC connection.
    #[test]
    fn a_profile_has_a_user_agent_on_its_own() {
        let chrome = profile_user_agent(None).expect("chrome");
        assert!(chrome.contains("Chrome/") && chrome.contains("Windows NT 10.0"));
        assert_eq!(profile_user_agent(Some("chrome")), Some(chrome));
        assert!(
            profile_user_agent(Some("firefox"))
                .expect("firefox")
                .contains("Firefox/")
        );
        assert!(
            profile_user_agent(Some("edge"))
                .expect("edge")
                .contains("Edg/")
        );
        // `golang` means no user agent on the connection at all
        assert_eq!(profile_user_agent(Some("golang")), None);
        // anything else is the user's own, sent as it stands
        assert_eq!(
            profile_user_agent(Some("mine/1.0")),
            Some("mine/1.0".to_string())
        );
    }

    #[test]
    fn firefox_and_edge_differ_from_chrome() {
        let firefox = defaults(Some("firefox"), Variant::Fetch);
        let names: Vec<&str> = firefox.force.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "user-agent",
                "dnt",
                "accept-language",
                "sec-fetch-mode",
                "sec-fetch-dest",
                "sec-fetch-site"
            ]
        );
        assert!(firefox.force[0].1.contains("Gecko/20100101 Firefox/"));
        assert_eq!(
            firefox
                .force
                .iter()
                .find(|(name, _)| *name == "accept-language")
                .expect("accept-language")
                .1,
            "en-US,en;q=0.5"
        );
        assert_eq!(
            firefox
                .fill
                .iter()
                .find(|(name, _)| *name == "priority")
                .expect("priority")
                .1,
            "u=4"
        );

        let edge = defaults(Some("edge"), Variant::Fetch);
        let ua = &edge
            .force
            .iter()
            .find(|(name, _)| *name == "user-agent")
            .expect("user-agent")
            .1;
        assert!(ua.contains("Safari/537.36Edg/"), "{ua}");
        let brands = &edge
            .force
            .iter()
            .find(|(name, _)| *name == "sec-ch-ua")
            .expect("sec-ch-ua")
            .1;
        assert!(brands.contains("Microsoft Edge"), "{brands}");
    }
}
