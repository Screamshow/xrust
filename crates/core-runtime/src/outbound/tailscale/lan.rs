//! Optional Linux TUN for approved subnet forwarding; absent in LuCI-only mode.
use super::access::{Rule, allows_protocol};
use smoltcp::wire::IpCidr;
use std::{io, net::IpAddr};

/// Internet forwarding must not implicitly grant access to LAN, router services
/// or other tailnet nodes. FakeIP pools are deliberately eligible for Forkop.
pub fn internet_destination(dst: IpAddr) -> bool {
    let excluded: &[&str] = match dst {
        IpAddr::V4(_) => &[
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/3",
        ],
        IpAddr::V6(_) => {
            // Forkop's existing IPv6 FakeIP pool is fc00::/18.
            if "fc00::/18"
                .parse::<IpCidr>()
                .unwrap()
                .contains_addr(&dst.into())
            {
                return true;
            }
            &[
                "::/96",
                "::ffff:0:0/96",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
            ]
        }
    };
    !excluded
        .iter()
        .any(|r| r.parse::<IpCidr>().unwrap().contains_addr(&dst.into()))
}

pub fn exit_permitted(packet: &[u8], rules: &[Rule]) -> bool {
    let Some((src, dst, len)) = super::mesh::packet_ips(packet) else {
        return false;
    };
    if !internet_destination(dst) {
        return false;
    }
    // Reject fragments and IPv6 extension headers until explicitly supported;
    // transport grants must never be bypassed by an unparsed header.
    let (proto, offset) = match dst {
        IpAddr::V4(_) if packet[0] == 0x45 && packet[6] & 0x3f == 0 && packet[7] == 0 => {
            (packet[9] as u16, 20)
        }
        IpAddr::V6(_) => (packet[6] as u16, 40),
        _ => return false,
    };
    let port = match proto {
        6 if len >= offset + 20 => u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
        17 if len >= offset + 8 => u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
        1 if src.is_ipv4() && len >= offset + 8 => 0,
        58 if src.is_ipv6() && len >= offset + 8 => 0,
        _ => return false,
    };
    allows_protocol(rules, src, dst, port, proto)
}
pub fn permitted(packet: &[u8], routes: &[IpCidr], rules: &[Rule]) -> bool {
    let Some((src, dst, len)) = super::mesh::packet_ips(packet) else {
        return false;
    };
    if !routes.iter().any(|r| r.contains_addr(&dst.into())) {
        return false;
    }
    if !matches!(dst, IpAddr::V4(_))
        || packet[0] != 0x45
        || len < 20
        || packet[6] & 0x3f != 0
        || packet[7] != 0
    {
        return false;
    }
    let proto = packet[9] as u16;
    let port = match proto {
        6 if len >= 40 => u16::from_be_bytes([packet[22], packet[23]]),
        17 if len >= 28 => u16::from_be_bytes([packet[22], packet[23]]),
        1 if len >= 28 => 0,
        _ => return false,
    };
    allows_protocol(rules, src, dst, port, proto)
}
#[cfg(target_os = "linux")]
pub struct LanTun {
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl LanTun {
    pub fn open() -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, b) in b"forkop-tslan".iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, &req) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: tokio::io::unix::AsyncFd::new(fd)?,
        })
    }
    pub fn write(&self, bytes: &[u8]) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let n = unsafe {
            libc::write(
                self.fd.get_ref().as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != bytes.len() {
            return Err(io::Error::other("short TUN write"));
        }
        Ok(())
    }
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        use std::os::fd::AsRawFd;
        match self.fd.try_io(tokio::io::Interest::READABLE, |fd| {
            let mut bytes = vec![0; 1280];
            let n = unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed"));
            }
            bytes.truncate(n as usize);
            Ok(bytes)
        }) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub async fn readable(&self) -> io::Result<()> {
        let _ready = self.fd.readable().await?;
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
pub struct LanTun;
#[cfg(not(target_os = "linux"))]
impl LanTun {
    pub fn open() -> io::Result<Self> {
        Err(io::Error::other("LAN forwarding requires Linux"))
    }
    pub fn write(&self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    pub async fn readable(&self) -> io::Result<()> {
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tun_readiness_wakes_on_packets_and_clears_after_draining() {
        let (left, right) = std::os::unix::net::UnixDatagram::pair().unwrap();
        left.set_nonblocking(true).unwrap();
        right.set_nonblocking(true).unwrap();
        let tun = LanTun {
            fd: tokio::io::unix::AsyncFd::new(std::os::fd::OwnedFd::from(left)).unwrap(),
        };
        assert!(tun.read().unwrap().is_none());
        right.send(b"packet").unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(100), tun.readable())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tun.read().unwrap().unwrap(), b"packet");
        assert!(tun.read().unwrap().is_none());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), tun.readable())
                .await
                .is_err()
        );
    }
    #[test]
    fn exit_does_not_grant_lan_tailnet_or_special_networks() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.1.2",
            "192.168.1.1",
            "100.100.100.100",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:192.168.1.1",
            "fd7a:115c:a1e0::1",
            "fd26:4417:c71c::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!internet_destination(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "198.18.1.1",
            "2606:4700:4700::1111",
            "fc00::1234",
        ] {
            assert!(internet_destination(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn exit_ipv4_ipv6_obeys_grants_and_rejects_fragments() {
        let rules: Vec<Rule> = serde_json::from_value(serde_json::json!([{"SrcIPs":["100.64.0.0/10", "fd7a:115c:a1e0::/48"],"IPProto":[17],"DstPorts":[{"IP":"*","Ports":{"First":53,"Last":53}}]}])).unwrap();
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        assert!(exit_permitted(&packet, &rules));
        assert!(!exit_permitted(&packet, &[]));
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert!(!exit_permitted(&packet, &rules));
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[6] = 0x20;
        assert!(!exit_permitted(&packet, &rules));
        let mut v6 = vec![0; 48];
        v6[0] = 0x60;
        v6[4..6].copy_from_slice(&8u16.to_be_bytes());
        v6[6] = 17;
        v6[8..24].copy_from_slice(
            &"fd7a:115c:a1e0::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        v6[24..40].copy_from_slice(
            &"2606:4700:4700::1111"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        v6[42..44].copy_from_slice(&53u16.to_be_bytes());
        assert!(exit_permitted(&v6, &rules));
        v6[6] = 44;
        assert!(!exit_permitted(&v6, &rules));
    }
    #[test]
    fn subnet_acl_rejects_other_destinations_protocols_and_fragments() {
        let rules: Vec<Rule> = serde_json::from_value(serde_json::json!([{"SrcIPs":["100.64.0.0/10"],"IPProto":[17],"DstPorts":[{"IP":"192.168.1.0/24","Ports":{"First":53,"Last":53}}]}])).unwrap();
        let routes = vec!["192.168.1.0/24".parse().unwrap()];
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 168, 1, 2]);
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        assert!(permitted(&packet, &routes, &rules));
        assert!(!permitted(&packet, &routes, &[]));
        packet[22..24].copy_from_slice(&54u16.to_be_bytes());
        assert!(!permitted(&packet, &routes, &rules));
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[16] = 8;
        assert!(!permitted(&packet, &routes, &rules));
        packet[16] = 192;
        packet[6] = 0x20;
        assert!(!permitted(&packet, &routes, &rules));
    }
}
