//! Bounded userspace TCP listeners forwarding LuCI and optional SSH to loopback.
use super::access::{Rule, allows};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::tcp::{Socket, SocketBuffer, State},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
};

struct Connection {
    handle: SocketHandle,
    port: u16,
    task: Option<JoinHandle<()>>,
    to_local: Option<mpsc::Sender<Vec<u8>>>,
    from_local: Option<mpsc::Receiver<Vec<u8>>>,
    pending: Vec<u8>,
    activity: Instant,
}
impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
pub struct WebBridge {
    connections: HashMap<SocketHandle, Connection>,
    rules: Vec<Rule>,
    ssh_access: bool,
    exit_access: bool,
    exit_approved: bool,
}
impl WebBridge {
    pub fn new(ssh_access: bool) -> Self {
        Self::with_exit(ssh_access, false)
    }
    pub fn with_exit(ssh_access: bool, exit_access: bool) -> Self {
        Self {
            connections: HashMap::new(),
            rules: vec![],
            ssh_access,
            exit_access,
            exit_approved: false,
        }
    }
    pub fn set_exit_approved(&mut self, approved: bool) {
        self.exit_approved = approved;
    }
    /// A connection past its listener, which the stack loop has to pump.
    pub fn active(&self, sockets: &SocketSet<'static>) -> bool {
        self.connections.values().any(|connection| {
            connection.task.is_some()
                || sockets.get::<Socket>(connection.handle).state() != State::Listen
        })
    }
    pub fn update_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
    }
    pub fn poll(&mut self, sockets: &mut SocketSet<'static>) {
        let mut remove = vec![];
        for connection in self.connections.values_mut() {
            let socket = sockets.get_mut::<Socket>(connection.handle);
            if socket.state() == State::Listen {
                continue;
            }
            let permitted = match (socket.remote_endpoint(), socket.local_endpoint()) {
                (Some(src), Some(_)) if connection.port == super::peer_dns::PORT => {
                    self.exit_approved
                        && super::access::allows_exit_dns(&self.rules, src.addr.into())
                }
                (Some(src), Some(dst)) => allows(
                    &self.rules,
                    src.addr.into(),
                    dst.addr.into(),
                    connection.port,
                ),
                _ => false,
            };
            if !permitted || connection.activity.elapsed() > Duration::from_secs(120) {
                socket.abort();
                remove.push(connection.handle);
                continue;
            }
            if socket.state() == State::Established && connection.task.is_none() {
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
                let (reply, replies) = mpsc::channel::<Vec<u8>>(16);
                let port = connection.port;
                connection.task = Some(tokio::spawn(async move {
                    if port == super::peer_dns::PORT {
                        super::peer_dns::serve(rx, reply).await;
                        return;
                    }
                    let stream = match tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)),
                    )
                    .await
                    {
                        Ok(Ok(s)) => s,
                        _ => return,
                    };
                    let (mut read, mut write) = stream.into_split();
                    let reader = async {
                        let mut buffer = [0; 8192];
                        loop {
                            let n = read.read(&mut buffer).await?;
                            if n == 0 {
                                break;
                            }
                            if reply.send(buffer[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Ok::<_, std::io::Error>(())
                    };
                    let writer = async {
                        while let Some(bytes) = rx.recv().await {
                            write.write_all(&bytes).await?;
                        }
                        write.shutdown().await
                    };
                    tokio::select! { _=reader=>{}, _=writer=>{} }
                }));
                connection.to_local = Some(tx);
                connection.from_local = Some(replies);
            }
            if let Some(tx) = &connection.to_local {
                while socket.can_recv() {
                    let consumed = socket.recv(|bytes| {
                        let size = bytes.len().min(8192);
                        if tx.try_send(bytes[..size].to_vec()).is_ok() {
                            (size, true)
                        } else {
                            (0, false)
                        }
                    });
                    if !matches!(consumed, Ok(true)) {
                        break;
                    }
                    connection.activity = Instant::now();
                }
            }
            if let Some(rx) = &mut connection.from_local {
                if connection.pending.is_empty()
                    && let Ok(bytes) = rx.try_recv()
                {
                    connection.pending = bytes;
                }
                if !connection.pending.is_empty()
                    && socket.can_send()
                    && let Ok(n) = socket.send_slice(&connection.pending)
                {
                    connection.pending.drain(..n);
                    connection.activity = Instant::now();
                }
                if rx.is_closed() && rx.is_empty() && connection.pending.is_empty() {
                    socket.close();
                }
            }
            if matches!(socket.state(), State::Closed | State::TimeWait) {
                remove.push(connection.handle);
            }
        }
        for handle in remove {
            self.connections.remove(&handle);
            sockets.remove(handle);
        }
        for port in [80, 443, 22, super::peer_dns::PORT] {
            if port == super::peer_dns::PORT && !self.exit_access {
                continue;
            }
            if port == 22 && !self.ssh_access {
                continue;
            }
            if self.connections.len() >= 32 {
                break;
            }
            if self
                .connections
                .values()
                .any(|c| c.port == port && sockets.get::<Socket>(c.handle).state() == State::Listen)
            {
                continue;
            }
            let mut socket = Socket::new(
                SocketBuffer::new(vec![0; 32768]),
                SocketBuffer::new(vec![0; 32768]),
            );
            if socket.listen(port).is_err() {
                continue;
            }
            let handle = sockets.add(socket);
            self.connections.insert(
                handle,
                Connection {
                    handle,
                    port,
                    task: None,
                    to_local: None,
                    from_local: None,
                    pending: vec![],
                    activity: Instant::now(),
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listeners_alone_do_not_keep_the_stack_busy() {
        let mut sockets = SocketSet::new(vec![]);
        let mut bridge = WebBridge::with_exit(true, true);
        assert!(!bridge.active(&sockets));
        bridge.poll(&mut sockets);
        assert!(!bridge.connections.is_empty());
        assert!(!bridge.active(&sockets));
    }

    #[test]
    fn ssh_listener_is_opt_in() {
        for enabled in [false, true] {
            let mut sockets = SocketSet::new(vec![]);
            let mut bridge = WebBridge::new(enabled);
            bridge.poll(&mut sockets);
            let mut ports: Vec<_> = bridge.connections.values().map(|c| c.port).collect();
            ports.sort();
            assert_eq!(
                ports,
                if enabled {
                    vec![22, 80, 443]
                } else {
                    vec![80, 443]
                }
            );
            bridge.poll(&mut sockets);
            assert_eq!(bridge.connections.len(), if enabled { 3 } else { 2 });
        }
    }
}
