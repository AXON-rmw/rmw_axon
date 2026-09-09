use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::security_mode::SecurityMode;

pub const DAEMON_MULTICAST_ADDR: &str = "239.255.0.2";
pub const DAEMON_HELLO_INTERVAL_MS: u64 = 500;
pub const DAEMON_MULTICAST_PORT: u16 = 7403;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloDaemon {
    pub daemon_id: u64,
    pub quic_port: u16,
    pub domains: Vec<u32>,
    pub generation: u64,
    /// SAE identity advertised only when this daemon runs in QKD mode.
    pub qkd_sae_id: Option<String>,
    pub security_mode: SecurityMode,
}

#[derive(Debug, Clone)]
pub struct HelloDaemonMessage {
    pub hello: HelloDaemon,
    pub src_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct QkdControlMessage {
    pub data: Vec<u8>,
    pub src_addr: SocketAddr,
}

pub fn encode_hello_daemon(hello: &HelloDaemon) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.push(0xDD);
    buf.extend(&hello.daemon_id.to_le_bytes());
    buf.extend(&hello.quic_port.to_le_bytes());
    buf.extend(&hello.generation.to_le_bytes());
    buf.extend(&(hello.domains.len() as u16).to_le_bytes());
    for d in &hello.domains {
        buf.extend(&d.to_le_bytes());
    }
    let qkd_sae = hello.qkd_sae_id.as_deref().unwrap_or("").as_bytes();
    buf.extend(&(qkd_sae.len() as u16).to_le_bytes());
    buf.extend(qkd_sae);
    buf.push(hello.security_mode.wire_value());
    buf
}

pub fn decode_hello_daemon(buf: &[u8]) -> Result<HelloDaemon, &'static str> {
    if buf.len() < 21 || buf[0] != 0xDD {
        return Err("bad magic");
    }
    let daemon_id = u64::from_le_bytes(buf[1..9].try_into().unwrap());
    let quic_port = u16::from_le_bytes(buf[9..11].try_into().unwrap());
    let generation = u64::from_le_bytes(buf[11..19].try_into().unwrap());
    let domain_count = u16::from_le_bytes(buf[19..21].try_into().unwrap()) as usize;
    let mut domains = Vec::with_capacity(domain_count);
    let mut off = 21;
    for _ in 0..domain_count {
        if off + 4 > buf.len() {
            return Err("truncated");
        }
        domains.push(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()));
        off += 4;
    }
    let (qkd_sae_id, security_mode) = if off == buf.len() {
        // Backward compatibility with daemons built before QKD support.
        (None, SecurityMode::Classic)
    } else {
        if off + 2 > buf.len() {
            return Err("truncated qkd sae length");
        }
        let len = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()) as usize;
        off += 2;
        if off + len > buf.len() {
            return Err("truncated qkd sae id");
        }
        let qkd_sae_id = if len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&buf[off..off + len])
                    .map_err(|_| "invalid qkd sae id")?
                    .to_string(),
            )
        };
        off += len;
        let security_mode = if off == buf.len() {
            // Compatibility with the initial QKD-capable HELLO format.
            SecurityMode::Classic
        } else if off + 1 == buf.len() {
            SecurityMode::from_wire(buf[off]).ok_or("invalid security mode")?
        } else {
            return Err("trailing hello data");
        };
        (qkd_sae_id, security_mode)
    };
    Ok(HelloDaemon {
        daemon_id,
        quic_port,
        domains,
        generation,
        qkd_sae_id,
        security_mode,
    })
}

pub fn start_daemon_multicast_listener(
    port: u16,
    hello_tx: std::sync::mpsc::Sender<HelloDaemonMessage>,
    qkd_tx: std::sync::mpsc::Sender<QkdControlMessage>,
) -> std::io::Result<()> {
    let socket = bind_multicast_listener_socket(port)?;
    let mcast_addr: Ipv4Addr = DAEMON_MULTICAST_ADDR.parse().unwrap();
    socket.join_multicast_v4(&mcast_addr, &Ipv4Addr::UNSPECIFIED)?;
    for ip in non_loopback_ipv4s() {
        let _ = socket.join_multicast_v4(&mcast_addr, &ip);
    }
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    if buf[..n].first() == Some(&0xDD) {
                        let Ok(hello) = decode_hello_daemon(&buf[..n]) else {
                            continue;
                        };
                        let _ = hello_tx.send(HelloDaemonMessage {
                            hello,
                            src_addr: src,
                        });
                    } else if matches!(
                        buf[..n].first(),
                        Some(&crate::qkd::MSG_QKD_KEY_ANNOUNCE)
                            | Some(&crate::qkd::MSG_QKD_KEY_ACK)
                            | Some(&crate::qkd::MSG_QKD_KEY_ERROR)
                    ) {
                        let _ = qkd_tx.send(QkdControlMessage {
                            data: buf[..n].to_vec(),
                            src_addr: src,
                        });
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
    });
    Ok(())
}

fn bind_multicast_listener_socket(port: u16) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // Docker host networking places the host and container daemons in the same
    // network namespace. Set reuse before bind so both receive discovery.
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    Ok(socket.into())
}

pub fn send_hello_multicast(socket: &UdpSocket, hello: &HelloDaemon, port: u16) {
    let encoded = encode_hello_daemon(hello);
    let addr: std::net::SocketAddr = format!("{}:{}", DAEMON_MULTICAST_ADDR, port)
        .parse()
        .unwrap();
    let _ = socket.send_to(&encoded, addr);
}

pub fn send_hello_multicast_all_interfaces(sockets: &[UdpSocket], hello: &HelloDaemon, port: u16) {
    let encoded = encode_hello_daemon(hello);
    let mcast_addr: std::net::SocketAddr = format!("{}:{}", DAEMON_MULTICAST_ADDR, port)
        .parse()
        .unwrap();
    let bcast_addr: std::net::SocketAddr = format!("255.255.255.255:{}", port).parse().unwrap();
    for socket in sockets {
        let _ = socket.send_to(&encoded, mcast_addr);
        let _ = socket.send_to(&encoded, bcast_addr);
    }
}

fn non_loopback_ipv4s() -> Vec<Ipv4Addr> {
    let mut addrs = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 {
            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = &*cur;
                if !ifa.ifa_addr.is_null() && !ifa.ifa_name.is_null() {
                    let family = (*ifa.ifa_addr).sa_family as i32;
                    if family == libc::AF_INET {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                        if !ip.is_loopback() && !ip.is_unspecified() && !addrs.contains(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
                cur = (*cur).ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }
    addrs
}

fn set_multicast_interface(socket: &UdpSocket, ip: Ipv4Addr) -> std::io::Result<()> {
    let iface = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &iface as *const libc::in_addr as *const libc::c_void,
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Enumerate all non-loopback IPv4 interfaces and bind a UDP socket to each one.
/// This ensures the HelloDaemon multicast reaches peers on all connected networks.
pub fn bind_per_interface_sockets() -> Vec<UdpSocket> {
    let mut sockets = Vec::new();
    for ip in non_loopback_ipv4s() {
        if let Ok(sock) = UdpSocket::bind(SocketAddr::from((ip, 0))) {
            let _ = sock.set_multicast_loop_v4(true);
            let _ = sock.set_multicast_ttl_v4(1);
            let _ = sock.set_broadcast(true);
            if set_multicast_interface(&sock, ip).is_ok() {
                sockets.push(sock);
            }
        }
    }
    if sockets.is_empty() {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            let mcast_addr: Ipv4Addr = DAEMON_MULTICAST_ADDR.parse().unwrap();
            let _ = sock.join_multicast_v4(&mcast_addr, &Ipv4Addr::UNSPECIFIED);
            let _ = sock.set_multicast_loop_v4(true);
            let _ = sock.set_multicast_ttl_v4(1);
            let _ = sock.set_broadcast(true);
            sockets.push(sock);
        }
    }
    sockets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_daemon_encode_decode() {
        let hello = HelloDaemon {
            daemon_id: 0x1234,
            quic_port: 7402,
            domains: vec![0, 1, 5],
            generation: 42,
            qkd_sae_id: Some("sae-1".into()),
            security_mode: SecurityMode::Qkd,
        };
        let encoded = encode_hello_daemon(&hello);
        let decoded = decode_hello_daemon(&encoded).unwrap();
        assert_eq!(hello.daemon_id, decoded.daemon_id);
        assert_eq!(hello.quic_port, decoded.quic_port);
        assert_eq!(hello.domains, decoded.domains);
        assert_eq!(hello.generation, decoded.generation);
        assert_eq!(hello.qkd_sae_id, decoded.qkd_sae_id);
        assert_eq!(hello.security_mode, decoded.security_mode);
    }

    #[test]
    fn pre_profile_qkd_hello_decodes_as_classic() {
        let hello = HelloDaemon {
            daemon_id: 1,
            quic_port: 7402,
            domains: vec![7],
            generation: 2,
            qkd_sae_id: Some("sae-old".into()),
            security_mode: SecurityMode::Qkd,
        };
        let mut old = encode_hello_daemon(&hello);
        old.pop();
        assert_eq!(
            decode_hello_daemon(&old).unwrap().security_mode,
            SecurityMode::Classic
        );
    }

    #[test]
    fn multicast_listener_port_can_be_shared_by_host_network_containers() {
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let first = bind_multicast_listener_socket(port).unwrap();
        let second = bind_multicast_listener_socket(port).unwrap();
        assert_eq!(first.local_addr().unwrap().port(), port);
        assert_eq!(second.local_addr().unwrap().port(), port);
    }

    #[test]
    fn test_decode_empty_buffer() {
        assert!(decode_hello_daemon(&[]).is_err());
        assert!(decode_hello_daemon(&[0xDD, 0x00]).is_err());
    }

    #[test]
    fn test_decode_bad_magic() {
        assert!(decode_hello_daemon(&[0x00; 20]).is_err());
    }
}
