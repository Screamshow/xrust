//! Bounded DNS-only PeerAPI, carried by the authenticated userspace mesh.
//! No TCP listener is opened on LAN/WAN; queries use the router's local DNS.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

pub const PORT: u16 = 41643;
const MAX_QUERY: usize = 4096;
const MAX_HEADER: usize = 8192;

fn parse_request(bytes: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid DNS request");
    let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") else {
        return if bytes.len() > MAX_HEADER {
            Err(bad())
        } else {
            Ok(None)
        };
    };
    if end > MAX_HEADER {
        return Err(bad());
    }
    let header = std::str::from_utf8(&bytes[..end]).map_err(|_| bad())?;
    let mut lines = header.split("\r\n");
    let request: Vec<_> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if request.len() != 3 || !matches!(request[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err(bad());
    }
    let mut length = None;
    let mut dns_type = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(bad());
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| bad())?);
        }
        if name.eq_ignore_ascii_case("content-type") {
            dns_type = value.trim().eq_ignore_ascii_case("application/dns-message");
        }
    }
    let query = match request[0] {
        "GET" => {
            let encoded = request[1].strip_prefix("/dns-query?dns=").ok_or_else(bad)?;
            if encoded.len() > MAX_QUERY * 2 {
                return Err(bad());
            }
            URL_SAFE_NO_PAD
                .decode(encoded.trim_end_matches('='))
                .map_err(|_| bad())?
        }
        "POST" if request[1] == "/dns-query" && dns_type => {
            let length = length.filter(|n| *n <= MAX_QUERY).ok_or_else(bad)?;
            if bytes.len() < end + 4 + length {
                return Ok(None);
            }
            bytes[end + 4..end + 4 + length].to_vec()
        }
        _ => return Err(bad()),
    };
    if query.len() < 12 || query.len() > MAX_QUERY {
        return Err(bad());
    }
    let message = hickory_proto::op::Message::from_vec(&query).map_err(|_| bad())?;
    if message.message_type != hickory_proto::op::MessageType::Query
        || message.op_code != hickory_proto::op::OpCode::Query
        || message.queries.len() != 1
    {
        return Err(bad());
    }
    Ok(Some(query))
}

async fn resolve(query: &[u8], resolver: std::net::SocketAddr) -> io::Result<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(resolver).await?;
    socket.send(query).await?;
    let mut reply = vec![0; 65535];
    let n = socket.recv(&mut reply).await?;
    reply.truncate(n);
    if reply.len() < 12 || reply[..2] != query[..2] || reply[2] & 0x80 == 0 {
        return Err(io::Error::other("invalid local DNS response"));
    }
    if reply[2] & 2 != 0 {
        let mut tcp = tokio::net::TcpStream::connect(resolver).await?;
        tcp.write_u16(query.len() as u16).await?;
        tcp.write_all(query).await?;
        let n = tcp.read_u16().await? as usize;
        reply.resize(n, 0);
        tcp.read_exact(&mut reply).await?;
        if reply.len() < 12 || reply[..2] != query[..2] || reply[2] & 0x80 == 0 {
            return Err(io::Error::other("invalid local DNS response"));
        }
    }
    Ok(reply)
}

pub async fn serve(mut input: mpsc::Receiver<Vec<u8>>, output: mpsc::Sender<Vec<u8>>) {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = vec![];
        while let Some(chunk) = input.recv().await {
            if bytes.len() + chunk.len() > MAX_HEADER + 4 + MAX_QUERY {
                return Err(io::Error::other("request too large"));
            }
            bytes.extend_from_slice(&chunk);
            if let Some(query) = parse_request(&bytes)? {
                return resolve(&query, "127.0.0.1:53".parse().unwrap()).await;
            }
        }
        Err(io::Error::other("incomplete request"))
    })
    .await;
    let (status, body) = match result {
        Ok(Ok(body)) => ("200 OK", body),
        Ok(Err(_)) => ("400 Bad Request", vec![]),
        Err(_) => ("504 Gateway Timeout", vec![]),
    };
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend(body);
    let _ = output.send(response).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]
    }
    #[tokio::test]
    async fn local_dns_udp_and_truncated_tcp_fallback() {
        for truncated in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
            let q = query();
            let expected = q.clone();
            let server = tokio::spawn(async move {
                let mut packet = vec![0; 4096];
                let (n, peer) = udp.recv_from(&mut packet).await.unwrap();
                assert_eq!(&packet[..n], &expected);
                packet.truncate(n);
                packet[2] |= 0x80;
                if truncated {
                    packet[2] |= 2;
                }
                udp.send_to(&packet, peer).await.unwrap();
                if truncated {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let n = stream.read_u16().await.unwrap() as usize;
                    let mut request = vec![0; n];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(request, expected);
                    packet[2] &= !2;
                    stream.write_u16(packet.len() as u16).await.unwrap();
                    stream.write_all(&packet).await.unwrap();
                }
            });
            let response = tokio::time::timeout(Duration::from_secs(2), resolve(&q, addr))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response[..2], &q[..2]);
            assert_eq!(response[2] & 0x82, 0x80);
            server.await.unwrap();
        }
    }
    #[test]
    fn dns_only_http_get_post_and_partial_requests() {
        let q = query();
        let get = format!(
            "GET /dns-query?dns={} HTTP/1.1\r\nHost: peer\r\n\r\n",
            URL_SAFE_NO_PAD.encode(&q)
        );
        assert_eq!(parse_request(get.as_bytes()).unwrap(), Some(q.clone()));
        let mut post = format!("POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", q.len()).into_bytes();
        assert!(parse_request(&post).unwrap().is_none());
        post.extend(&q);
        assert_eq!(parse_request(&post).unwrap(), Some(q));
        for bad in [
            "GET / HTTP/1.1\r\n\r\n",
            "POST /dns-query HTTP/1.1\r\nContent-Length: 99999\r\n\r\n",
            "GET /dns-query?dns=AAAA HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_request(bad.as_bytes()).is_err());
        }
        assert!(parse_request(&vec![b'a'; MAX_HEADER + 1]).is_err());
    }
}
