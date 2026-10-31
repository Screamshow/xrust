//! Optional classification must select DIRECT before a catch-all proxy route.
use core_runtime::inbound::Target;
use core_runtime::route::{ConnContext, Decision, Router};
use serde_json::json;
use tokio::io::{AsyncWriteExt, duplex};

fn router(extended: bool) -> std::sync::Arc<Router> {
    let sniff = if extended {
        // HTTP deliberately precedes the optional classifier.
        json!({"action":"sniff", "sniffer":["http","tls","dns","bittorrent-extended","quic","stun"]})
    } else {
        json!({"action":"sniff"})
    };
    Router::new(&json!({
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"proxy"}],
        "route":{"rules":[sniff,{"protocol":"bittorrent","outbound":"direct"},{"outbound":"proxy"}],"final":"proxy"}
    })).unwrap()
}

fn context(network: &'static str, ipv6: bool) -> ConnContext {
    ConnContext::new(
        "lan",
        "127.0.0.1:30000".parse().unwrap(),
        Target::Ip(
            if ipv6 {
                "[2001:db8::1]:4000"
            } else {
                "192.0.2.1:4000"
            }
            .parse()
            .unwrap(),
        ),
        network,
    )
}

#[tokio::test]
async fn split_tcp_is_classified_and_preserved_before_direct() {
    for ipv6 in [false, true] {
        for payload in [
            b"\x13BitTorrent protocol".as_slice(),
            b"GET /announce?info_hash=x&peer_id=y&port=6881 HTTP/1.1\r\nHost: tracker.test\r\n\r\n",
            b"GET /seed HTTP/1.1\r\nHost: seed.test\r\nUser-Agent: qBittorrent/5\r\n\r\n",
        ] {
            for split in [1, payload.len() / 2, payload.len() - 1] {
                let (mut tx, mut rx) = duplex(4096);
                let bytes = payload.to_vec();
                let writer = tokio::spawn(async move {
                    tx.write_all(&bytes[..split]).await.unwrap();
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    tx.write_all(&bytes[split..]).await.unwrap();
                });
                let mut ctx = context("tcp", ipv6);
                assert_eq!(
                    router(true).route(&mut rx, &mut ctx).await.unwrap(),
                    Decision::Outbound(0)
                );
                assert_eq!(ctx.protocol.as_deref(), Some("bittorrent"));
                assert_eq!(ctx.sniff_prefix, payload);
                writer.await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn dht_is_opt_in_and_other_udp_stays_on_normal_route() {
    let ping = b"d1:ad2:id20:abcdefghijklmnopqrste1:q4:ping1:t2:aa1:y1:qe";
    for ipv6 in [false, true] {
        for extended in [false, true] {
            let router = router(extended);
            let mut ctx = context("udp", ipv6);
            assert_eq!(
                router.route_datagrams(&mut ctx, &[ping]).await.unwrap(),
                Decision::Outbound(if extended { 0 } else { 1 })
            );
            let mut wg = vec![0x5a; 148];
            wg[..4].copy_from_slice(&[1, 0, 0, 0]);
            for packet in [wg.as_slice(), b"d1:ad", b"ordinary UDP"] {
                let mut ctx = context("udp", ipv6);
                assert_eq!(
                    router.route_datagrams(&mut ctx, &[packet]).await.unwrap(),
                    Decision::Outbound(1)
                );
                assert_ne!(ctx.protocol.as_deref(), Some("bittorrent"));
            }
        }
    }
}

#[tokio::test]
async fn ordinary_http_and_disabled_extension_keep_normal_routing() {
    for (extended, payload) in [
        (
            false,
            b"GET /?info_hash=x&peer_id=y&port=1 HTTP/1.1\r\nHost: tracker.test\r\n\r\n".as_slice(),
        ),
        (
            true,
            b"GET /search?info_hash=x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
        (
            true,
            b"GET /announce?x=y HTTP/1.1\r\nHost: example.test\r\n\r\n",
        ),
    ] {
        let (mut tx, mut rx) = duplex(4096);
        tx.write_all(payload).await.unwrap();
        drop(tx);
        let mut ctx = context("tcp", false);
        assert_eq!(
            router(extended).route(&mut rx, &mut ctx).await.unwrap(),
            Decision::Outbound(1)
        );
        assert_eq!(ctx.protocol.as_deref(), Some("http"));
        assert_eq!(ctx.sniff_prefix, payload);
    }
}
