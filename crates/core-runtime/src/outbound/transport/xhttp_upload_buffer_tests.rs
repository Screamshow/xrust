use super::*;

#[test]
fn reclaims_storage_without_copy() {
    let mut buf = BytesMut::zeroed(1_000_000);
    buf[..4].copy_from_slice(b"test");
    let address = buf.as_ptr();
    let owner = buf.freeze();
    let view = owner.slice(..4);
    assert_eq!(&view[..], b"test");
    drop(view);
    let mut reuse = true;
    let buf = reclaim_upload_buffer(owner, 1_000_000, &mut reuse);
    assert!(reuse);
    assert_eq!(buf.as_ptr(), address);
    assert_eq!(buf.len(), 1_000_000);
    assert_eq!(&buf[..4], b"test");
}

#[test]
fn retained_storage_disables_reuse_and_stays_immutable() {
    let owner = BytesMut::zeroed(1_000_000).freeze();
    let held = owner.slice(..16);
    let mut reuse = true;
    let mut next = reclaim_upload_buffer(owner, 1_000_000, &mut reuse);
    assert!(!reuse);
    next[..16].fill(0xff);
    assert_eq!(&held[..], &[0; 16]);
}

#[tokio::test]
async fn preserves_large_upload_under_backpressure_and_reports_rejection() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for limit in [65536, 1_000_000] {
            for reject in [false, true] {
                let (client_io, server_io) = tokio::io::duplex(4096);
                let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
                let server = tokio::spawn(async move {
                    let mut conn = h2::server::Builder::new()
                        .initial_window_size(16384)
                        .initial_connection_window_size(32768)
                        .handshake::<_, Bytes>(server_io)
                        .await
                        .unwrap();
                    while let Some(request) = conn.accept().await {
                        let (req, mut respond) = request.unwrap();
                        let seen_tx = seen_tx.clone();
                        tokio::spawn(async move {
                            let seq: usize = req.uri().path().rsplit('/').next().unwrap().parse().unwrap();
                            let length: usize = req.headers()["content-length"].to_str().unwrap().parse().unwrap();
                            let mut body = req.into_body();
                            let mut data = Vec::new();
                            while let Some(chunk) = body.data().await {
                                let chunk = chunk.unwrap();
                                data.extend_from_slice(&chunk);
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                                body.flow_control().release_capacity(chunk.len()).unwrap();
                            }
                            assert_eq!(data.len(), length);
                            assert!(length <= limit);
                            let status = if reject && seq == 1 { 403 } else { 200 };
                            seen_tx.send((seq, data, status)).unwrap();
                            respond.send_response(http::Response::builder().status(status).body(()).unwrap(), true).unwrap();
                        });
                    }
                });
                let (client, connection) = super::super::h2io::client_builder()
                    .handshake::<_, Bytes>(client_io).await.unwrap();
                let driver = tokio::spawn(async move { let _ = connection.await; });
                let (mut input, reader) = tokio::io::duplex(128 * 1024);
                let failure = Failure::default();
                let flushed = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
                let config = serde_json::json!({"mode":"packet-up", "path":"/probe", "sc_max_each_post_bytes":limit});
                let writer = PostWriter {
                    cfg: XhttpConfig::parse(config.as_object().unwrap()).unwrap(),
                    scheme: "https".into(), authority: "local".into(),
                    session_id: "session".into(), seq: 0,
                    dialer: std::sync::Arc::new(|| Box::pin(async { Err(io::Error::other("must not use H1")) })),
                    h2_client: Some(client),
                };
                let worker = tokio::spawn(packet_upload_worker(reader, writer, failure.clone(), flushed.clone(), std::sync::Arc::new(tokio::sync::Notify::new())));
                let data: Vec<u8> = (0..2_100_013).map(|i| (i % 251) as u8).collect();
                let written = input.write_all(&data).await;
                drop(input);
                worker.await.unwrap();
                let mut received = Vec::new();
                let mut seq = 0;
                let mut accepted = 0;
                loop {
                    let (actual_seq, chunk, status) = seen_rx.recv().await.unwrap();
                    assert_eq!(actual_seq, seq);
                    received.extend_from_slice(&chunk);
                    seq += 1;
                    if status != 200 { break; }
                    accepted += chunk.len();
                    if accepted == data.len() { break; }
                }
                assert_eq!(received, data[..received.len()]);
                assert_eq!(flushed.load(std::sync::atomic::Ordering::Acquire), accepted as u64);
                if reject {
                    assert_eq!(seq, 2);
                    assert!(failure.take().unwrap().to_string().contains("403"));
                } else {
                    written.unwrap();
                    assert_eq!(received, data);
                    assert!(failure.take().is_none());
                }
                driver.abort(); server.abort();
            }
        }
    }).await.expect("worker test timed out");
}
