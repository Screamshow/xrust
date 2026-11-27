//! Options from Xray's streamSettings.finalmask.quicParams on a native XHTTP
//! client endpoint. Keep parsing shared by the config check and the dialer.

use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
    #[default]
    Bbr,
    Reno,
    Brutal {
        up_bytes_per_second: u64,
        compensate_loss: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub congestion: Congestion,
    pub idle_seconds: u64,
    pub keep_alive_seconds: Option<u64>,
    pub stream_window: u64,
    pub max_stream_window: u64,
    pub connection_window: u64,
    pub max_connection_window: u64,
    pub incoming_bidi_streams: u64,
    pub chrome: bool,
    pub disable_pmtud: bool,
    pub disable_gso: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            congestion: Congestion::Bbr,
            idle_seconds: 30,
            keep_alive_seconds: None,
            stream_window: 6 << 20,
            max_stream_window: 6 << 20,
            connection_window: 15 << 20,
            max_connection_window: 15 << 20,
            incoming_bidi_streams: 100,
            chrome: true,
            disable_pmtud: false,
            disable_gso: false,
        }
    }
}

impl Params {
    pub fn parse(value: Option<&Value>, at: &str) -> Result<Self, String> {
        let Some(value) = value.filter(|v| !v.is_null()) else {
            return Ok(Self::default());
        };
        let obj = value
            .as_object()
            .ok_or_else(|| format!("{at}: expected an object"))?;
        const KNOWN: &[&str] = &[
            "congestion",
            "bbr_profile",
            "brutal_up",
            "brutal_down",
            "brutal_disable_loss_compensation",
            "init_stream_receive_window",
            "max_stream_receive_window",
            "init_connection_receive_window",
            "max_connection_receive_window",
            "max_idle_timeout",
            "keep_alive_period",
            "max_incoming_streams",
            "disable_path_mtu_discovery",
            "disable_chrome_parrot",
            "disable_gso",
            "disable_stateless_reset",
            "udp_hop",
        ];
        for key in obj.keys() {
            if !KNOWN.contains(&key.as_str()) {
                return Err(format!("{at}.{key}: unknown field"));
            }
        }
        if obj.get("udp_hop").is_some_and(|v| !v.is_null()) {
            return Err(format!(
                "{at}.udp_hop: Xray UDP hopping is not supported by native XHTTP"
            ));
        }
        let text = |key: &str| {
            obj.get(key).filter(|v| !v.is_null()).map_or(Ok(""), |v| {
                v.as_str()
                    .ok_or_else(|| format!("{at}.{key}: expected a string"))
            })
        };
        let uint = |key: &str, min: u64, max: u64| {
            let Some(value) = obj.get(key).filter(|v| !v.is_null()) else {
                return Ok(0);
            };
            value
                .as_u64()
                .filter(|n| *n == 0 || (min..=max).contains(n))
                .ok_or_else(|| {
                    format!("{at}.{key}: expected zero or an integer from {min} to {max}")
                })
        };
        let boolean = |key: &str| {
            obj.get(key)
                .filter(|v| !v.is_null())
                .map_or(Ok(false), |v| {
                    v.as_bool()
                        .ok_or_else(|| format!("{at}.{key}: expected a boolean"))
                })
        };
        let bandwidth = |key: &str| {
            bandwidth_bytes(text(key)?).filter(|n| *n == 0 || *n >= 65_536).ok_or_else(|| {
                format!("{at}.{key}: expected a bandwidth string of at least 65536 bytes/sec or zero")
            })
        };
        let profile = text("bbr_profile")?.to_ascii_lowercase();
        if !matches!(
            profile.as_str(),
            "" | "standard" | "conservative" | "aggressive"
        ) {
            return Err(format!("{at}.bbr_profile: unknown profile {profile:?}"));
        }
        let up = bandwidth("brutal_up")?;
        // These are accepted by Xray's config builder but do not affect the
        // plain outbound XHTTP dialer.
        bandwidth("brutal_down")?;
        boolean("disable_stateless_reset")?;
        let compensate_loss = !boolean("brutal_disable_loss_compensation")?;
        let congestion = match text("congestion")?.to_ascii_lowercase().as_str() {
            "reno" => Congestion::Reno,
            "" | "bbr" if matches!(profile.as_str(), "" | "standard") => Congestion::Bbr,
            "" | "bbr" => {
                return Err(format!(
                    "{at}.bbr_profile: native XHTTP BBR supports only standard"
                ));
            }
            "force-brutal" if up > 0 => Congestion::Brutal {
                up_bytes_per_second: up,
                compensate_loss,
            },
            "force-brutal" => {
                return Err(format!("{at}.brutal_up: force-brutal requires a bitrate"));
            }
            mode => {
                return Err(format!(
                    "{at}.congestion: unsupported XHTTP congestion {mode:?}"
                ));
            }
        };
        let chrome = !boolean("disable_chrome_parrot")?;
        let idle = uint("max_idle_timeout", 4, 120)?;
        let keep_alive = uint("keep_alive_period", 2, 60)?;
        // Quinn preallocates stream slots. A transport cap large enough
        // for XHTTP is necessary here even though quic-go uses sparse state.
        let bidi = uint("max_incoming_streams", 8, 4096)?;
        let window = |initial_key, max_key, standard_initial, default_max| {
            const MAX_QUIC_VARINT: u64 = (1 << 62) - 1;
            let initial = uint(initial_key, 16_384, MAX_QUIC_VARINT)?;
            let max = uint(max_key, 16_384, MAX_QUIC_VARINT)?;
            let start = if chrome {
                default_max
            } else if initial > 0 {
                initial
            } else {
                standard_initial
            };
            let max = if max > 0 { max } else { default_max };
            // If the caller supplied a lower maximum, quic-go still starts
            // at the configured initial window and does not grow it.
            Ok::<_, String>((start, max.max(start)))
        };
        let (stream_window, max_stream_window) = window(
            "init_stream_receive_window",
            "max_stream_receive_window",
            2 << 20,
            6 << 20,
        )?;
        let (connection_window, max_connection_window) = window(
            "init_connection_receive_window",
            "max_connection_receive_window",
            3 << 20,
            15 << 20,
        )?;
        Ok(Self {
            congestion,
            idle_seconds: if chrome {
                30
            } else if idle > 0 {
                idle
            } else {
                300
            },
            keep_alive_seconds: (keep_alive > 0).then_some(keep_alive),
            stream_window,
            max_stream_window,
            connection_window,
            max_connection_window,
            incoming_bidi_streams: if chrome { 100 } else { bidi },
            chrome,
            disable_pmtud: boolean("disable_path_mtu_discovery")?,
            disable_gso: boolean("disable_gso")?,
        })
    }
}

fn bandwidth_bytes(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(0);
    }
    let split = raw
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(raw.len());
    let val: f64 = raw[..split].parse().ok()?;
    let unit = match raw[split..].trim().to_ascii_lowercase().as_str() {
        "" | "b" | "bps" => 1.0,
        "k" | "kb" | "kbps" => 1_000.0,
        "m" | "mb" | "mbps" => 1_000_000.0,
        "g" | "gb" | "gbps" => 1_000_000_000.0,
        "t" | "tb" | "tbps" => 1_000_000_000_000.0,
        _ => return None,
    };
    let bits = val * unit;
    (bits.is_finite() && bits < (u64::MAX as f64)).then_some(bits as u64 / 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chrome_uses_pinned_windows_and_honors_keepalive_and_pmtud() {
        let options = json!({
            "max_idle_timeout": 22, "keep_alive_period": 5, "max_incoming_streams": 24,
            "init_stream_receive_window": 32768, "init_connection_receive_window": 65536,
            "disable_path_mtu_discovery": true, "disable_gso": true
        });
        let result = Params::parse(Some(&options), "quic").unwrap();
        assert_eq!(result.idle_seconds, 30);
        assert_eq!(result.incoming_bidi_streams, 100);
        assert_eq!(result.stream_window, 6 << 20);
        assert_eq!(result.connection_window, 15 << 20);
        assert_eq!(result.keep_alive_seconds, Some(5));
        assert!(result.disable_pmtud);
        assert!(result.disable_gso);
    }

    #[test]
    fn ordinary_quic_uses_independent_initial_and_maximum_windows() {
        let mut options = json!({
            "disable_chrome_parrot": true, "congestion": "force-brutal", "brutal_up": "8.5mbps",
            "brutal_disable_loss_compensation": true, "max_idle_timeout": 22,
            "max_incoming_streams": 8, "init_stream_receive_window": 32_768,
            "max_stream_receive_window": 32_768,
        });
        let result = Params::parse(Some(&options), "quic").unwrap();
        assert!(!result.chrome);
        assert_eq!(result.idle_seconds, 22);
        assert_eq!(result.incoming_bidi_streams, 8);
        assert_eq!(result.stream_window, 32_768);
        assert_eq!(result.connection_window, 3 << 20);
        assert_eq!(
            result.congestion,
            Congestion::Brutal {
                up_bytes_per_second: 1_062_500,
                compensate_loss: false,
            }
        );
        options["max_stream_receive_window"] = json!(65_536);
        let result = Params::parse(Some(&options), "quic").unwrap();
        assert_eq!(result.stream_window, 32_768);
        assert_eq!(result.max_stream_window, 65_536);
        options["udp_hop"] = json!({"remotePorts": "443,8443"});
        assert!(
            Params::parse(Some(&options), "quic")
                .unwrap_err()
                .contains("udp_hop")
        );
    }
}
