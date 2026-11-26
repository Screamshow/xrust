use std::{io, net::SocketAddr};

use tokio::net::UdpSocket;

pub(super) const MAX_DATAGRAM: usize = 2048;
const BUFFER_SIZE: usize = MAX_DATAGRAM + 1;
const POLL_BUDGET: usize = 256;

#[cfg(target_os = "linux")]
const BATCH_SIZE: usize = 16;

#[derive(Default)]
pub(super) struct Receiver {
    #[cfg(target_os = "linux")]
    buffers: Vec<[u8; BUFFER_SIZE]>,
    #[cfg(target_os = "linux")]
    batch_unavailable: bool,
}

impl Receiver {
    pub(super) fn drain_ready(
        &mut self,
        socket: &UdpSocket,
        mut receive: impl FnMut(&[u8], SocketAddr),
    ) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        if !self.batch_unavailable {
            match self.drain_batch(socket, &mut receive) {
                Ok(full) => return Ok(full),
                Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
                    self.batch_unavailable = true;
                    self.buffers = Vec::new();
                }
                Err(error) => return Err(error),
            }
        }

        let mut buffer = [0; BUFFER_SIZE];
        for _ in 0..POLL_BUDGET {
            match socket.try_recv_from(&mut buffer) {
                Ok((length, source)) if length <= MAX_DATAGRAM => {
                    receive(&buffer[..length], source);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    fn drain_batch(
        &mut self,
        socket: &UdpSocket,
        mut receive: impl FnMut(&[u8], SocketAddr),
    ) -> io::Result<bool> {
        use std::{mem, os::fd::AsRawFd, ptr};
        use tokio::io::Interest;

        let mut addresses: [libc::sockaddr_in; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut messages: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
        let mut remaining = POLL_BUDGET;
        while remaining != 0 {
            let capacity = BATCH_SIZE.min(remaining);
            let result = socket.try_io(Interest::READABLE, || {
                if self.buffers.is_empty() {
                    self.buffers.resize(BATCH_SIZE, [0; BUFFER_SIZE]);
                }
                let buffers = self.buffers.as_mut_ptr();
                let addresses = addresses.as_mut_ptr();
                let iovecs = iovecs.as_mut_ptr();
                for (index, message) in messages[..capacity].iter_mut().enumerate() {
                    // Each header references its own slot. Take pointers from
                    // the array bases without reborrowing the whole arrays.
                    unsafe {
                        let iovec = iovecs.add(index);
                        *iovec = libc::iovec {
                            iov_base: buffers.add(index).cast(),
                            iov_len: BUFFER_SIZE,
                        };
                        message.msg_hdr.msg_name = addresses.add(index).cast();
                        message.msg_hdr.msg_namelen =
                            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                        message.msg_hdr.msg_iov = iovec;
                        message.msg_hdr.msg_iovlen = 1;
                    }
                }
                // The message headers, addresses, iovecs and byte buffers all
                // remain live and at fixed addresses for the nonblocking call.
                let received = unsafe {
                    libc::recvmmsg(
                        socket.as_raw_fd(),
                        messages.as_mut_ptr(),
                        capacity as _,
                        libc::MSG_DONTWAIT as _,
                        ptr::null_mut(),
                    )
                };
                if received < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(received as usize)
            });
            let received = match result {
                Ok(0) => return Ok(false),
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            remaining -= received;
            for index in 0..received {
                let message = &messages[index];
                let length = message.msg_len as usize;
                let address = &addresses[index];
                if length > MAX_DATAGRAM
                    || message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0
                    || message.msg_hdr.msg_namelen as usize != mem::size_of_val(address)
                    || i32::from(address.sin_family) != libc::AF_INET
                {
                    continue;
                }
                let source = SocketAddr::from((
                    address.sin_addr.s_addr.to_ne_bytes(),
                    u16::from_be(address.sin_port),
                ));
                receive(&self.buffers[index][..length], source);
            }
        }
        Ok(true)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drains_ready_datagrams_in_order_and_discards_oversize() {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let target = socket.local_addr().unwrap();
        sender.send_to(&[1], target).await.unwrap();
        sender.send_to(&[2; BUFFER_SIZE + 1], target).await.unwrap();
        sender.send_to(&[3; MAX_DATAGRAM], target).await.unwrap();
        for marker in 4..=24 {
            sender.send_to(&[marker], target).await.unwrap();
        }
        socket.readable().await.unwrap();
        let mut receiver = Receiver::default();
        let mut packets = Vec::new();
        assert!(
            !receiver
                .drain_ready(&socket, |packet, source| {
                    assert_eq!(source, sender.local_addr().unwrap());
                    packets.push(packet.to_vec());
                })
                .unwrap()
        );
        let mut expected = vec![vec![1], vec![3; MAX_DATAGRAM]];
        expected.extend((4..=24).map(|marker| vec![marker]));
        assert_eq!(packets, expected);
        assert!(
            !receiver
                .drain_ready(&socket, |_, _| panic!("socket should be drained"))
                .unwrap()
        );
    }
}
