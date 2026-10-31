//! Optional BitTorrent classifiers. No peer cache or payload copies.
//! These signals identify a connection, never every service on a peer IP.

// Bounds apply only to optional DHT inspection, not datagram forwarding.
const DHT_BYTES: usize = 4096;
const DHT_ITEMS: usize = 256;
const DHT_DEPTH: usize = 8;

pub(super) fn utp_syn(p: &[u8]) -> bool {
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
                b"get_peers" | b"announce_peer" if arg(b"info_hash")?.len() == 20 => (),
                _ => return None,
            }
        }
        Some(())
    }
    check(data).is_some()
}

pub(super) fn http(method: &str, target: &str, headers: &str) -> bool {
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
        if has("info_hash") && has("peer_id") && has("port") {
            return true;
        }
    }
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("user-agent")
                && [
                    "qbittorrent",
                    "transmission",
                    "deluge",
                    "libtorrent",
                    "utorrent",
                    "rtorrent",
                ]
                .iter()
                .any(|client| {
                    let value = value.trim();
                    value
                        .get(..client.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(client))
                        && value
                            .as_bytes()
                            .get(client.len())
                            .is_none_or(|c| matches!(c, b'/' | b' '))
                })
        })
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
        assert!(http(
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
