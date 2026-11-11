//! Optional BitTorrent classifiers. No peer cache or payload copies.
//! These signals identify a connection, never every service on a peer IP.

// Bounds apply only to optional DHT inspection, not datagram forwarding.
const DHT_BYTES: usize = 4096;
const DHT_ITEMS: usize = 256;
const DHT_DEPTH: usize = 8;

pub(super) fn utp_syn(p: &[u8]) -> bool {
    // TURN ChannelData can share 0x4100 with uTP SYN. Prefer a complete
    // ChannelData frame; this is a framing heuristic, not authentication.
    if p.len() >= 4
        && (0x4000..=0x7fff).contains(&u16::from_be_bytes([p[0], p[1]]))
        && usize::from(u16::from_be_bytes([p[2], p[3]])) == p.len() - 4
    {
        return false;
    }
    if p.len() < 20 || p[0] != 0x41 || p[8..12] != [0; 4] {
        return false;
    }
    let mut extension = p[1];
    let mut pos = 20;
    while extension != 0 {
        let (Some(&next), Some(&len)) = (p.get(pos), p.get(pos + 1)) else {
            return false;
        };
        if !matches!((extension, len), (1, 4..=252) if len % 4 == 0) && (extension, len) != (2, 8) {
            return false;
        }
        pos += 2 + usize::from(len);
        if pos > p.len() {
            return false;
        }
        extension = next;
    }
    pos == p.len()
}

struct Bencode<'a> {
    data: &'a [u8],
    pos: usize,
    items: usize,
}

type Fields<'a> = [Option<(&'a [u8], &'a [u8])>; 32];

fn field<'a>(fields: &Fields<'a>, key: &[u8]) -> Option<&'a [u8]> {
    fields
        .iter()
        .flatten()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
}

impl<'a> Bencode<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        self.items = self.items.checked_sub(1)?;
        let start = self.pos;
        let mut len = 0usize;
        while let Some(b'0'..=b'9') = self.data.get(self.pos) {
            len = len
                .checked_mul(10)?
                .checked_add(usize::from(self.data[self.pos] - b'0'))?;
            self.pos += 1;
        }
        if self.pos == start
            || self.data.get(self.pos) != Some(&b':')
            || (self.pos > start + 1 && self.data[start] == b'0')
        {
            return None;
        }
        self.pos += 1;
        let end = self.pos.checked_add(len)?;
        let value = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(value)
    }

    fn skip(&mut self, depth: usize) -> Option<()> {
        if depth > DHT_DEPTH {
            return None;
        }
        match *self.data.get(self.pos)? {
            b'0'..=b'9' => {
                self.string()?;
            }
            b'i' => {
                self.items = self.items.checked_sub(1)?;
                self.pos += 1;
                let start = self.pos;
                if self.data.get(self.pos) == Some(&b'-') {
                    self.pos += 1;
                }
                let digits = self.pos;
                while matches!(self.data.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
                if self.pos == digits
                    || self.data.get(self.pos) != Some(&b'e')
                    || (self.data[digits] == b'0' && (self.pos > digits + 1 || digits != start))
                {
                    return None;
                }
                self.pos += 1;
            }
            kind @ (b'l' | b'd') => {
                self.items = self.items.checked_sub(1)?;
                self.pos += 1;
                while self.data.get(self.pos) != Some(&b'e') {
                    if kind == b'd' {
                        self.string()?;
                    }
                    self.skip(depth + 1)?;
                }
                self.pos += 1;
            }
            _ => return None,
        }
        Some(())
    }

    fn fields(&mut self) -> Option<Fields<'a>> {
        // Fixed stack storage; arbitrary nested values are skipped in place.
        if self.data.get(self.pos) != Some(&b'd') {
            return None;
        }
        self.pos += 1;
        let mut fields = [None; 32];
        let mut count = 0;
        while self.data.get(self.pos) != Some(&b'e') {
            if count == fields.len() {
                return None;
            }
            let key = self.string()?;
            if field(&fields, key).is_some() {
                return None;
            }
            let start = self.pos;
            self.skip(1)?;
            fields[count] = Some((key, &self.data[start..self.pos]));
            count += 1;
        }
        self.pos += 1;
        Some(fields)
    }
}

fn string_value(data: &[u8]) -> Option<&[u8]> {
    let mut p = Bencode {
        data,
        pos: 0,
        items: DHT_ITEMS,
    };
    let value = p.string()?;
    (p.pos == data.len()).then_some(value)
}

// Read a canonical nonnegative bencoded integer without allocation.
fn integer_value(data: &[u8]) -> Option<u64> {
    let digits = data.strip_prefix(b"i")?.strip_suffix(b"e")?;
    if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
        return None;
    }
    digits.iter().try_fold(0u64, |value, &digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

pub(super) fn dht(data: &[u8]) -> bool {
    fn check(data: &[u8]) -> Option<()> {
        if data.len() > DHT_BYTES {
            return None;
        }
        let mut parser = Bencode {
            data,
            pos: 0,
            items: DHT_ITEMS,
        };
        let fields = parser.fields()?;
        if parser.pos != data.len() {
            return None;
        }
        let get = |key: &[u8]| field(&fields, key);
        let transaction = string_value(get(b"t")?)?;
        if transaction.is_empty() || transaction.len() > 64 {
            return None;
        }
        let kind = string_value(get(b"y")?)?;
        let body = match kind {
            b"q" => get(b"a")?,
            b"r" => get(b"r")?,
            // Error replies alone do not establish that a flow is BitTorrent.
            _ => return None,
        };
        let mut nested = Bencode {
            data: body,
            pos: 0,
            items: DHT_ITEMS,
        };
        let args = nested.fields()?;
        let arg = |key: &[u8]| field(&args, key).and_then(string_value);
        if arg(b"id")?.len() != 20 {
            return None;
        }
        if kind == b"q" {
            match string_value(get(b"q")?)? {
                b"ping" => (),
                b"find_node" | b"sample_infohashes" if arg(b"target")?.len() == 20 => (),
                b"get_peers" if arg(b"info_hash")?.len() == 20 => (),
                b"announce_peer" if arg(b"info_hash")?.len() == 20 => {
                    if arg(b"token")?.is_empty() {
                        return None;
                    }
                    let port = integer_value(field(&args, b"port")?)?;
                    let implied = match field(&args, b"implied_port") {
                        Some(value) => integer_value(value)?,
                        None => 0,
                    };
                    if port > 65535 || (port == 0 && implied == 0) {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        Some(())
    }
    check(data).is_some()
}

// Match a decoded 20-byte info hash without allocating or accepting malformed
// percent escapes. BEP 17 uses the binary hash, not a hex string in the URL.
fn binary_info_hash(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut pos = 0;
    let mut decoded = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'%' {
            if !bytes.get(pos + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(pos + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            pos += 3;
        } else {
            pos += 1;
        }
        decoded += 1;
        if decoded > 20 {
            return false;
        }
    }
    decoded == 20
}

fn http_seed(query: &str) -> bool {
    let mut hash = None;
    let mut piece = None;
    for (key, value) in query.split('&').filter_map(|p| p.split_once('=')) {
        let slot = match key {
            "info_hash" => &mut hash,
            "piece" => &mut piece,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return false;
        }
    }
    hash.is_some_and(binary_info_hash)
        && piece.is_some_and(|value| {
            !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit())
                && value.parse::<u32>().is_ok()
        })
}

pub(super) fn http(method: &str, target: &str, _headers: &str) -> bool {
    // Require tracker parameters together, rather than matching arbitrary text
    // containing "torrent", magnet links, or a generic /announce endpoint.
    if method == "GET"
        && let Some((_, query)) = target.split_once('?')
    {
        let has = |name: &str| {
            query.split('&').any(|p| {
                p.split_once('=')
                    .is_some_and(|(k, v)| k == name && !v.is_empty())
            })
        };
        if (has("info_hash") && has("peer_id") && has("port")) || http_seed(query) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dht_requires_a_complete_krpc_message() {
        let ping = b"d1:ad2:id20:abcdefghijklmnopqrste1:q4:ping1:t2:aa1:y1:qe";
        assert!(dht(ping));
        assert!(dht(b"d1:rd2:id20:abcdefghijklmnopqrste1:t2:aa1:y1:re"));
        for len in 0..ping.len() {
            assert!(!dht(&ping[..len]));
        }
        for bad in [
            b"d1:ad".as_slice(),
            b"d1:ad2:id20:abcdefghijklmnopqrstee",
            b"d1:ad2:id3:abce1:q4:ping1:t2:aa1:y1:qe",
            b"d1:ad2:id20:abcdefghijklmnopqrste1:q9:get_peers1:t2:aa1:y1:qe",
        ] {
            assert!(!dht(bad));
        }
        let mut trailing = ping.to_vec();
        trailing.push(b'x');
        assert!(!dht(&trailing));
        assert!(!dht(&vec![b'd'; DHT_BYTES + 1]));
    }

    #[test]
    fn http_requires_specific_signals() {
        assert!(http(
            "GET",
            "/announce?info_hash=x&peer_id=y&port=6881",
            "Host: tracker"
        ));
        assert!(!http(
            "GET",
            "/file",
            "User-Agent: qBittorrent/5.0\r\nHost: seed"
        ));
        for target in [
            "/announce?x=y",
            "/search?info_hash=x",
            "/?q=urn:btih:abc",
            "/?info_hash=x&peer_id=y&port=",
        ] {
            assert!(!http("GET", target, "User-Agent: Mozilla/5.0"));
        }
        assert!(!http("GET", "/", "User-Agent: qBittorrent-fake/1"));
        assert!(!http(
            "POST",
            "/?info_hash=x&peer_id=y&port=1",
            "Host: example.com"
        ));
    }

    #[test]
    fn seed_requires_binary_hash_and_unsigned_piece() {
        let hash = "%01".repeat(20);
        for query in [
            format!("info_hash={hash}&piece=0"),
            format!("piece=4294967295&info_hash={hash}&ranges=0-1023"),
            "info_hash=abcdefghijklmnopqrst&piece=3".into(),
        ] {
            assert!(http("GET", &format!("/seed?{query}"), "Host: seed"));
        }
        for query in [
            "info_hash=short&piece=0".into(),
            format!("info_hash={hash}&piece=-1"),
            format!("info_hash={hash}&piece=+1"),
            format!("info_hash={hash}&piece="),
            format!("info_hash={hash}&piece=1x"),
            format!("info_hash={hash}&piece=4294967296"),
            format!("info_hash={hash}&piece=1&piece=2"),
            format!("info_hash={hash}&piece=1&info_hash={hash}"),
            format!("info_hash={hash}%&piece=0"),
            format!("info_hash={hash}&other_piece=0"),
            format!("info_hash={hash}"),
        ] {
            assert!(
                !http("GET", &format!("/seed?{query}"), "Host: seed"),
                "{query}"
            );
        }
        assert!(!http(
            "POST",
            &format!("/seed?info_hash={hash}&piece=0"),
            "Host: seed"
        ));
        for value in ["%", "%0", "%xx", &"%01".repeat(19), &"%01".repeat(21)] {
            assert!(!binary_info_hash(value));
        }
    }

    #[test]
    fn user_agent_alone_never_establishes_bittorrent() {
        for client in [
            "BiglyBT",
            "TorrServer",
            "Flud",
            "BitComet",
            "LibreTorrent",
            "WebTorrent",
        ] {
            for suffix in ["", "/1.0", " 1.0"] {
                assert!(!http(
                    "GET",
                    "/file",
                    &format!("User-Agent: {client}{suffix}")
                ));
            }
            for value in [
                format!("Mozilla/5.0 {client}/1"),
                format!("{client}-docs/1"),
                format!("{client}Index/1"),
            ] {
                assert!(!http("GET", "/file", &format!("User-Agent: {value}")));
            }
        }
    }

    #[test]
    fn utp_checks_syn_and_extension_bounds() {
        let mut p = vec![0; 20];
        p[0] = 0x41;
        assert!(utp_syn(&p));
        p[1] = 1;
        p.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
        assert!(utp_syn(&p));
        for len in 0..p.len() {
            assert!(!utp_syn(&p[..len]));
        }
        p[21] = 8;
        assert!(!utp_syn(&p));
        p[21] = 4;
        p[8] = 1;
        assert!(!utp_syn(&p));
        assert!(!utp_syn(&[0; 148]));
    }

    #[test]
    fn complete_turn_frame_is_not_utp_syn() {
        let mut packet = [0u8; 20];
        packet[..4].copy_from_slice(&[0x41, 0, 0, 16]);
        packet[16] = 1;
        assert!(!utp_syn(&packet));
        // Same SYN fields without the TURN length coincidence still match.
        packet[3] = 17;
        assert!(utp_syn(&packet));
    }

    #[test]
    fn announce_requires_token_and_valid_port_state() {
        for (extra, expected) in [
            ("4:porti6881e5:token2:aa", true),
            ("4:porti0e12:implied_porti1e5:token2:aa", true),
            ("4:porti6881e", false),
            ("4:porti6881e5:token0:", false),
            ("5:token2:aa12:implied_porti1e", false),
            ("4:porti0e5:token2:aa", false),
            ("4:porti65536e5:token2:aa", false),
            ("4:porti-1e5:token2:aa", false),
            ("4:port4:68815:token2:aa", false),
            ("4:porti0e12:implied_porti2e5:token2:aa", true),
            ("4:porti6881e12:implied_port1:x5:token2:aa", false),
        ] {
            let packet = format!(
                "d1:ad2:id20:abcdefghijklmnopqrst9:info_hash20:abcdefghijklmnopqrst{extra}e1:q13:announce_peer1:t2:aa1:y1:qe"
            );
            assert_eq!(dht(packet.as_bytes()), expected, "{extra}");
        }
    }

    #[test]
    fn dht_queries_and_resource_limits() {
        for (query, argument) in [
            ("find_node", "6:target20:abcdefghijklmnopqrst"),
            ("get_peers", "9:info_hash20:abcdefghijklmnopqrst"),
            (
                "announce_peer",
                "9:info_hash20:abcdefghijklmnopqrst4:porti6881e5:token2:aa",
            ),
        ] {
            let packet = format!(
                "d1:ad2:id20:abcdefghijklmnopqrst{argument}e1:q{}:{query}1:t2:aa1:y1:qe",
                query.len()
            );
            assert!(dht(packet.as_bytes()), "{query}");
        }
        let repeated = "d1:ad2:id20:abcdefghijklmnopqrste1:q4:ping1:t2:aa1:y1:q1:y1:qe";
        assert!(!dht(repeated.as_bytes()));
        for extra in [
            format!("{}0:{}", "l".repeat(16), "e".repeat(16)),
            format!("l{}e", "0:".repeat(300)),
        ] {
            let packet =
                format!("d1:ad2:id20:abcdefghijklmnopqrste1:q4:ping1:t2:aa1:y1:q1:z{extra}e");
            assert!(!dht(packet.as_bytes()));
        }
        for len in 0..512 {
            assert!(!dht(&vec![b'd'; len]));
        }
    }
}
