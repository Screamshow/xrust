use serde_json::json;
use tokio::io::AsyncReadExt;
#[tokio::test]
async fn unchanged_wg_and_awg_reload_probe() {
    for (awg, tagged) in [(false, false), (false, true), (true, false), (true, true)] {
        let p = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut ep = json!({"type":"wireguard","tag":"wg","private_key":"ERERERERERERERERERERERERERERERERERERERERERE=","address":["10.66.66.1/24"],"listen_port":p,"peers":[]});
        if awg {
            ep["h1"] = json!(101);
            ep["h2"] = json!(102);
            ep["h3"] = json!(103);
            ep["h4"] = json!(104);
        }
        if !tagged {
            ep.as_object_mut().unwrap().remove("tag");
        }
        let root = json!({"inbounds":[],"endpoints":[ep],"outbounds":[{"type":"direct","tag":"d"}],"route":{"final":"d"}});
        let mut b = core_runtime::start(&root).await.unwrap();
        let result = b.reload_in_place(&root).await;
        println!("AWG={awg} unchanged reload={result:?}");
        assert!(result.is_ok(), "unchanged reload failed: {result:?}");
        assert!(b.reload_in_place(&root).await.is_ok());
        b.shutdown_wait().await;
    }
}
#[tokio::test]
async fn reality_pq_preference_wire_probe() {
    for (reality, preference) in [
        (true, None),
        (true, Some(false)),
        (true, Some(true)),
        (false, None),
    ] {
        let mut out = json!({"tls":{"enabled":true,"server_name":"example.com","reality":{"enabled":true,"public_key":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"}}});
        if let Some(p) = preference {
            out["tls"]["reality"]["support_x25519mlkem768"] = json!(p);
        }
        if !reality {
            out["tls"].as_object_mut().unwrap().remove("reality");
            out["tls"]["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
        }
        let opts = core_runtime::tls_client::TlsOptions::from_outbound(
            out.as_object().unwrap(),
            "example.com",
            "probe",
        )
        .unwrap()
        .unwrap();
        let (a, mut b) = tokio::io::duplex(8192);
        let t = tokio::spawn(async move {
            let _ = opts.establish(a, &[]).await;
        });
        let mut head = [0; 5];
        b.read_exact(&mut head).await.unwrap();
        let mut payload = vec![0; u16::from_be_bytes([head[3], head[4]]) as usize];
        b.read_exact(&mut payload).await.unwrap();
        let mut pos = 4 + 2 + 32;
        pos += 1 + payload[pos] as usize;
        let n = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2 + n;
        pos += 1 + payload[pos] as usize;
        pos += 2;
        let mut hybrid = false;
        while pos + 4 <= payload.len() {
            let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let n = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;
            if id == 51 {
                let mut k = pos + 2;
                while k < pos + n {
                    let g = u16::from_be_bytes([payload[k], payload[k + 1]]);
                    let sz = u16::from_be_bytes([payload[k + 2], payload[k + 3]]) as usize;
                    hybrid |= g == 0x11ec;
                    k += 4 + sz;
                }
            }
            pos += n;
        }
        println!(
            "PQ preference={preference:?} record_bytes={} hybrid={hybrid}",
            payload.len() + 5
        );
        assert_eq!(hybrid, !reality || preference == Some(true));
        if reality && preference != Some(true) {
            assert!(payload.len() + 5 < 1400);
        }
        t.abort();
    }
}

#[tokio::test]
async fn live_wg_and_awg_stream_survives_reload_and_rejected_change() {
    use base64::Engine;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };
    let b64 = |key: &[u8]| base64::engine::general_purpose::STANDARD.encode(key);
    for awg in [false, true] {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let echo = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let route_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        route_socket.connect("192.0.2.1:9").unwrap();
        let std::net::IpAddr::V4(target_ip) = route_socket.local_addr().unwrap().ip() else {
            panic!("IPv4 fixture required")
        };
        let target = echo.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let key1 = [17u8; 32];
        let key2 = [34u8; 32];
        let pub1 = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(key1));
        let pub2 = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(key2));
        let mut server_ep = json!({"type":"wireguard","tag":"wg","private_key":b64(&key1),"address":["10.66.66.1/24"],"listen_port":port,"peers":[{"public_key":b64(pub2.as_bytes()),"allowed_ips":["10.66.66.2/32"]}]});
        let mut client_ep = json!({"type":"wireguard","tag":"wg","private_key":b64(&key2),"address":["10.66.66.2/24"],"peers":[{"public_key":b64(pub1.as_bytes()),"address":"127.0.0.1","port":port,"allowed_ips":["0.0.0.0/0"]}]});
        if awg {
            for ep in [&mut server_ep, &mut client_ep] {
                for (k, v) in [("h1", 101), ("h2", 102), ("h3", 103), ("h4", 104)] {
                    ep[k] = json!(v);
                }
            }
        }
        let server_root = json!({"endpoints":[server_ep],"outbounds":[{"type":"direct","tag":"d"}],"route":{"final":"d"}});
        let Some(reference) = std::env::var_os("SING_BOX_REF") else {
            eprintln!("SKIP live WG/AWG: SING_BOX_REF unset");
            task.abort();
            return;
        };
        struct Reference {
            child: std::process::Child,
            path: std::path::PathBuf,
        }
        impl Drop for Reference {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_file(&self.path);
            }
        }
        let path =
            std::env::temp_dir().join(format!("wg-reload-{}-{port}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&server_root).unwrap()).unwrap();
        let _server = Reference {
            child: std::process::Command::new(reference)
                .args(["run", "-c"])
                .arg(&path)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap(),
            path,
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let client_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        client_ep["listen_port"] = json!(client_port);
        let root = json!({"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":0}],"endpoints":[client_ep],"route":{"final":"wg"}});
        let mut client = core_runtime::start(&root).await.unwrap();
        let mut s = TcpStream::connect(client.inbound_addrs()[0].1)
            .await
            .unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth = [0; 2];
        s.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0]);
        let mut req = vec![5, 1, 0, 1];
        req.extend_from_slice(&target_ip.octets());
        req.extend_from_slice(&target.port().to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut reply = [0; 10];
        timeout(Duration::from_secs(10), s.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[1], 0);
        for iteration in 0..4 {
            let bytes = vec![iteration as u8; 65536];
            s.write_all(&bytes).await.unwrap();
            let mut got = vec![0; bytes.len()];
            timeout(Duration::from_secs(10), s.read_exact(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, bytes);
            client.reload_in_place(&root).await.unwrap();
        }
        let mut invalid = root.clone();
        invalid["endpoints"][0]["mtu"] = json!(1300);
        assert!(client.reload_in_place(&invalid).await.is_err());
        client.reload_in_place(&root).await.unwrap();
        s.write_all(b"after-rejected-change").await.unwrap();
        let mut got = [0; 21];
        timeout(Duration::from_secs(5), s.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, b"after-rejected-change");
        println!(
            "AWG={awg}: live TCP survived client reloads and rejected same-port config change"
        );
        drop(s);
        client.shutdown_wait().await;

        task.abort();
    }
}
