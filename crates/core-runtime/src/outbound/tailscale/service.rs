//! Experimental OpenWrt service using the native Rust X Tailscale implementation.
//! Auth is read once from a root-only volatile file and never stored in config.
use super::Tailscale;
use std::{path::Path, sync::atomic::Ordering, time::Duration};
const STATUS: &str = "/var/run/forkop/ui-state/tailscale-status.json";
const AUTH: &str = "/var/run/forkop/ui-state/tailscale-auth";
fn safe_failure_reason(error: &std::io::Error) -> String {
    let reason = error.to_string();
    // Only fixed local protocol diagnostics may enter UI status. Never echo
    // arbitrary transport/server errors, which can contain credentials.
    if matches!(
        reason.as_str(),
        "tailscale: invalid control key response"
            | "tailscale: missing Noise public key"
            | "tailscale: zero control key"
            | "tailscale: control upgrade refused"
            | "tailscale: invalid upgrade response"
            | "tailscale: invalid Noise handshake response"
            | "tailscale: invalid Noise record"
            | "tailscale: invalid registration response"
            | "tailscale: truncated map header"
            | "tailscale: invalid map frame length"
            | "tailscale: invalid map response"
            | "tailscale: invalid assigned address"
            | "tailscale: missing or excessive assigned addresses"
            | "tailscale: registration has no assigned address"
    ) {
        reason
    } else {
        format!("{:?}", error.kind())
    }
}
fn compatible() -> bool {
    std::fs::read_to_string("/etc/forkop/sing-box-variant").is_ok_and(|v| v.trim() == "rust-x")
        && std::process::Command::new("/usr/lib/rust-x/sing-box")
            .arg("tailscale-native-capability")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        && std::process::Command::new("ucode")
            .args(["/usr/lib/forkop/tailscale/compat.uc", "check"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}
fn cleanup_network() {
    // Embedded: an old incoming Forkop package removes the newer helper files.
    let script = r#"
nft -a list chain inet fw4 input 2>/dev/null | sed -n '/comment "forkop-native-tailscale-udp"/s/.*# handle \([0-9][0-9]*\).*/\1/p' | while read -r handle; do
 nft delete rule inet fw4 input handle "$handle" 2>/dev/null || true
done
rm -f /var/run/forkop/ui-state/tailscale-udp-owned
for chain in forward input; do
 nft -a list chain inet fw4 "$chain" 2>/dev/null | sed -n '/comment "forkop-native-tailscale"/s/.*# handle \([0-9][0-9]*\).*/\1/p' | while read -r handle; do
  nft delete rule inet fw4 "$chain" handle "$handle" 2>/dev/null || true
 done
done
nft flush chain inet fw4 forkop_native_ts_input 2>/dev/null || true
nft delete chain inet fw4 forkop_native_ts_input 2>/dev/null || true
if [ -f /var/run/forkop/ui-state/tailscale-lan-owned ]; then
 nft delete table inet forkop_native_tailscale 2>/dev/null || true
 ip rule del priority 104 fwmark 0x880000/0xff0000 table 52743 2>/dev/null || true
 ip route flush table 52743 2>/dev/null || true
 ip -6 rule del priority 104 fwmark 0x880000/0xff0000 table 52743 2>/dev/null || true
 ip -6 route flush table 52743 2>/dev/null || true
 table=$(ucode /usr/lib/forkop/core/constants.uc get NFT_TABLE_NAME 2>/dev/null)
 interfaces=$(ucode /usr/lib/forkop/core/constants.uc get NFT_INTERFACE_SET_NAME 2>/dev/null)
 configured=$(uci -q get forkop.settings.source_network_interfaces)
 case " $configured " in *' forkop-tslan '*) ;; *)
  nft delete element inet "${table:-ForkopTable}" "${interfaces:-forkop_interfaces}" '{ "forkop-tslan" }' 2>/dev/null || true;;
 esac
 rm -f /var/run/forkop/ui-state/tailscale-lan-owned
fi
"#;
    let _ = std::process::Command::new("/bin/sh")
        .args(["-c", script])
        .status();
}
fn status(value: serde_json::Value) -> std::io::Result<()> {
    std::fs::write(format!("{STATUS}.new"), value.to_string())?;
    std::fs::rename(format!("{STATUS}.new"), STATUS)
}
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if !compatible() {
        cleanup_network();
        return Ok(());
    }
    let result = tokio::select! {
        result = run_inner() => result,
        _ = async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if !compatible() { break }
            }
        } => {
            cleanup_network();
            let _ = status(serde_json::json!({"state":"disconnected", "message":"Требуются Forkop 2.3.4 или новее и совместимый Rust X"}));
            let _ = std::process::Command::new("ubus").args(["call", "service", "delete", "{\"name\":\"forkop-tailscale\"}"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
            Ok(())
        }
    };
    cleanup_network();
    if result.is_err() {
        let _ = status(
            serde_json::json!({"state":"error", "message":"Не удалось запустить нативный Tailscale. Проверьте настройки Rust X."}),
        );
    }
    result
}
async fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    status(serde_json::json!({"state":"connecting"}))?;
    let auth = match std::fs::read_to_string(AUTH) {
        Ok(value) => {
            std::fs::remove_file(AUTH)?;
            value.trim().to_owned()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut config = serde_json::json!({"type":"tailscale", "tag":"luci",
        "hostname":"forkop-router", "state_directory":"/etc/forkop-tailscale",
        "listen_port":41642, "luci_access":true});
    config["ssh_access"] = Path::new("/etc/forkop-tailscale/ssh-enabled")
        .exists()
        .into();
    if !auth.is_empty() {
        config["auth_key"] = auth.into();
    }
    let lan_config: Option<serde_json::Value> =
        std::fs::read_to_string("/etc/forkop-tailscale/lan.json")
            .ok()
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
    let exit_enabled = Path::new("/etc/forkop-tailscale/exit-enabled").exists();
    config["advertise_exit_node"] = exit_enabled.into();
    if exit_enabled {
        config["system_interface"] = true.into();
    }
    if let Some(lan) = &lan_config {
        config["system_interface"] = true.into();
        config["advertise_routes"] = lan["routes"].clone();
    }
    let endpoint = Tailscale::build(config.as_object().unwrap(), "tailscale")?;
    let mut delay = 2;
    let shared = loop {
        match endpoint.shared().await {
            Ok(shared) => break shared,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    status(serde_json::json!({"state":"error", "message":
                    if error.to_string() == "tailscale: server returned no assigned address" {
                        "Сервер Tailscale не назначил адрес устройству. Проверьте авторизацию и совместимость клиента."
                    } else {
                        "Ключ отклонён или требуется авторизация устройства в Tailscale."
                    }}))?;
                    return Ok(());
                }
                status(
                    serde_json::json!({"state":"reconnecting", "message":"Ожидаем доступ к интернету и серверу Tailscale…",
                        "error_kind":format!("{:?}", error.kind()), "error_reason":safe_failure_reason(&error), "retry_in_seconds":delay}),
                )?;
                if !Path::new("/etc/forkop-tailscale/enabled").exists() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(30);
            }
        }
    };
    loop {
        if Path::new("/var/run/forkop/ui-state/tailscale-stopping").exists() {
            break;
        }
        let udp_ready = std::process::Command::new("/usr/lib/forkop/tailscale/transport.sh")
            .arg("setup")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        let lan_ready = if lan_config.is_some() || exit_enabled {
            std::process::Command::new("/usr/lib/forkop/tailscale/lan.sh")
                .arg("setup")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        } else {
            true
        };
        if shared
            .cmd_tx
            .send(super::engine::Cmd::UpdateForwardingReady { ready: lan_ready })
            .await
            .is_err()
        {
            break;
        }
        status(
            serde_json::json!({"state":if shared.control_connected.load(Ordering::Relaxed) {"connected"} else {"reconnecting"}, "ip":shared.local_ip().to_string(),
            "udp_ready":udp_ready,"transport":shared.transport.read().unwrap().clone(),
            "lan_ready":lan_ready, "exit_ready":exit_enabled && lan_ready, "exit_approved":shared.exit_approved.load(Ordering::Relaxed), "routes_approved":shared.routes_approved.load(Ordering::Relaxed),
            "message":if lan_ready {None} else {Some("Не удалось настроить передачу трафика Tailscale")},
            "updated_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()}),
        )?;
        // Service stop kills the process and closes every remote listener.
        if !Path::new("/etc/forkop-tailscale/enabled").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_status_does_not_echo_server_or_transport_secrets() {
        let secret_error = std::io::Error::other("server echoed tskey-auth-test-secret");
        assert_eq!(safe_failure_reason(&secret_error), "Other");
        let local = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tailscale: invalid map response",
        );
        assert_eq!(
            safe_failure_reason(&local),
            "tailscale: invalid map response"
        );
    }
}
