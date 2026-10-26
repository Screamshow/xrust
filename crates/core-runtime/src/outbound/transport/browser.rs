//! The browser headers Xray puts on its XHTTP requests when the config names
//! no `User-Agent` (`common/utils/browser.go`, `TryDefaultHeadersWith(header,
//! "fetch")`): Chrome on Windows making a same-origin `fetch`.
//!
//! Xray derives the Chrome major version from the date -- 144 on 2026-01-13,
//! one more every 35 days, held back by a random lag of up to 105 days drawn
//! once per process -- and greases `Sec-CH-UA` the way Chromium does. The
//! same here; the lag is drawn once per process rather than from a hash of
//! the CPU model.

use std::sync::OnceLock;

/// `ChromeVersion` in Xray: the major version a current Chrome has today.
fn chrome_version() -> u64 {
    static VERSION: OnceLock<u64> = OnceLock::new();
    *VERSION.get_or_init(|| {
        let mut seed = [0u8; 8];
        let _ = crate::util::random_bytes(&mut seed);
        let unit = (u64::from_le_bytes(seed) >> 11) as f64 / (1u64 << 53) as f64;
        let lag = (unit * unit * 105.0).floor() as i64;
        let today = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 86_400)
            .unwrap_or(0) as i64;
        // 2026-01-13, in days since the epoch
        const START: i64 = 20_466;
        let diff = today - START - 35 - lag;
        (144 + diff.max(0) / 35) as u64
    })
}

/// `getGreasedChUa(version, "chrome")`.
fn greased_ch_ua(version: u64) -> String {
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
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            NA[seed % NA.len()],
            NA[(seed + 1) % NA.len()],
            NA_VERSION[seed % NA_VERSION.len()]
        ),
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"Google Chrome\";v=\"{version}\""),
    ];
    let order = SHUFFLE[seed % SHUFFLE.len()];
    let mut shuffled = [String::new(), String::new(), String::new()];
    for (i, at) in order.iter().enumerate() {
        shuffled[*at] = brands[i].clone();
    }
    shuffled.join(", ")
}

/// The headers, in the order Xray sets them. Go sends a request's headers in
/// map order, which varies from request to request, so the order is not
/// something a peer can rely on either way.
pub(crate) fn chrome_fetch_headers() -> &'static [(&'static str, String)] {
    static HEADERS: OnceLock<Vec<(&'static str, String)>> = OnceLock::new();
    HEADERS.get_or_init(|| {
        let version = chrome_version();
        vec![
            ("sec-ch-ua", greased_ch_ua(version)),
            ("sec-ch-ua-mobile", "?0".to_string()),
            ("sec-ch-ua-platform", "\"Windows\"".to_string()),
            ("dnt", "1".to_string()),
            (
                "user-agent",
                format!(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
                ),
            ),
            ("accept-language", "en-US,en;q=0.9".to_string()),
            ("sec-fetch-mode", "cors".to_string()),
            ("sec-fetch-dest", "empty".to_string()),
            ("sec-fetch-site", "same-origin".to_string()),
            ("priority", "u=1, i".to_string()),
            ("cache-control", "no-cache".to_string()),
            ("pragma", "no-cache".to_string()),
            ("accept", "*/*".to_string()),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Xray's brand list for Chrome 144: version 144 picks `NA[1]`, `NA[2]`,
    /// `"8"` and the shuffle `[0, 1, 2]`.
    #[test]
    fn ch_ua_is_greased_like_chromium() {
        assert_eq!(
            greased_ch_ua(144),
            "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\""
        );
        // another seed, another order: 145 % 6 = 1 puts Chromium last
        assert_eq!(
            greased_ch_ua(145),
            "\"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\""
        );
    }

    #[test]
    fn the_version_follows_the_date() {
        let version = chrome_version();
        // late October 2026: (286 - 35 - lag) / 35 over 144
        assert!((144..=152).contains(&version), "{version}");
        let ua = &chrome_fetch_headers()[4].1;
        assert!(ua.contains(&format!("Chrome/{version}.0.0.0")), "{ua}");
    }
}
