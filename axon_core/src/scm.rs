use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const SHM_SOCKET_DIR: &str = "/tmp/axon_shm";

fn shm_socket_path(topic_hash: u64) -> String {
    format!("{}/{:016x}.sock", SHM_SOCKET_DIR, topic_hash)
}

/// Publisher side: listen on a UNIX socket and serve eventfd to subscribers.
pub struct EventFdServer {
    listener: UnixListener,
    socket_path: String,
}

impl EventFdServer {
    pub fn bind(topic_hash: u64) -> io::Result<Self> {
        let _ = std::fs::create_dir_all(SHM_SOCKET_DIR);
        let path = shm_socket_path(topic_hash);
        match UnixListener::bind(&path) {
            Ok(listener) => Ok(Self {
                listener,
                socket_path: path,
            }),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => match UnixStream::connect(&path) {
                Ok(_) => Err(e),
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                    let listener = UnixListener::bind(&path)?;
                    Ok(Self {
                        listener,
                        socket_path: path,
                    })
                }
            },
            Err(e) => Err(e),
        }
    }

    /// Accept a single subscriber connection and send them the eventfd (for tests).
    pub fn serve_eventfd_single(&self, eventfd: RawFd) -> io::Result<()> {
        let (stream, _peer_addr) = self.listener.accept()?;
        let mut creds: libc::ucred = unsafe { std::mem::zeroed() };
        let mut creds_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut creds as *mut _ as *mut std::ffi::c_void,
                &mut creds_len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if creds.uid != 0 && creds.uid != unsafe { libc::getuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted peer",
            ));
        }
        send_fd(&stream, eventfd)?;
        Ok(())
    }

    /// Accept subscriber connections in a loop and send them the eventfd.
    pub fn serve_eventfd_loop(&self, eventfd: RawFd) {
        let stop = Arc::new(AtomicBool::new(false));
        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if wake_fd < 0 {
            return;
        }
        self.serve_eventfd_loop_until(eventfd, stop, wake_fd);
        let _ = unsafe { libc::close(wake_fd) };
    }

    /// Accept subscriber connections until `stop` is set or `wake_fd` is signaled.
    pub fn serve_eventfd_loop_until(&self, eventfd: RawFd, stop: Arc<AtomicBool>, wake_fd: RawFd) {
        let _ = self.listener.set_nonblocking(true);
        let mut poll_fds = [
            libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        while !stop.load(Ordering::Acquire) {
            poll_fds[0].revents = 0;
            poll_fds[1].revents = 0;
            let ret =
                unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, -1) };
            if ret < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if poll_fds[1].revents & libc::POLLIN != 0 || stop.load(Ordering::Acquire) {
                break;
            }
            if poll_fds[0].revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                match self.listener.accept() {
                    Ok((stream, _peer_addr)) => {
                        let mut creds: libc::ucred = unsafe { std::mem::zeroed() };
                        let mut creds_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                        let ret = unsafe {
                            libc::getsockopt(
                                stream.as_raw_fd(),
                                libc::SOL_SOCKET,
                                libc::SO_PEERCRED,
                                &mut creds as *mut _ as *mut std::ffi::c_void,
                                &mut creds_len,
                            )
                        };
                        if ret >= 0 && (creds.uid == 0 || creds.uid == unsafe { libc::getuid() }) {
                            let _ = send_fd(&stream, eventfd);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
    }
}

impl Drop for EventFdServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Subscriber side: connect to a publisher's socket and receive the eventfd.
pub fn receive_eventfd(topic_hash: u64) -> io::Result<RawFd> {
    let path = shm_socket_path(topic_hash);
    let stream = UnixStream::connect(&path)?;
    receive_fd(&stream)
}

fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    let data = [0u8; 1];
    let mut iov = [std::io::IoSlice::new(&data)];
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len();

    unsafe {
        let cmsg_hdr = libc::CMSG_FIRSTHDR(&mut msg as *mut libc::msghdr);
        if cmsg_hdr.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR failed"));
        }
        (*cmsg_hdr).cmsg_level = libc::SOL_SOCKET;
        (*cmsg_hdr).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg_hdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(cmsg_hdr) as *mut RawFd, fd);
        msg.msg_controllen = (*cmsg_hdr).cmsg_len as _;
    }

    let ret = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn receive_fd(stream: &UnixStream) -> io::Result<RawFd> {
    let mut data = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg.len();

    let ret = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        let cmsg_hdr = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr);
        if cmsg_hdr.is_null() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no cmsg"));
        }
        if (*cmsg_hdr).cmsg_level != libc::SOL_SOCKET || (*cmsg_hdr).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected cmsg type",
            ));
        }
        let fd = std::ptr::read(libc::CMSG_DATA(cmsg_hdr) as *const RawFd);
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::eventfd::{EfdFlags, EventFd};

    #[test]
    fn test_scm_rights_roundtrip() {
        let efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();
        let efd_raw = efd.as_raw_fd();

        let server = EventFdServer::bind(0x1234).unwrap();
        let server_handle = std::thread::spawn(move || {
            server.serve_eventfd_single(efd_raw).unwrap();
        });

        let received = receive_eventfd(0x1234).unwrap();
        server_handle.join().unwrap();

        assert!(received >= 0);
        let ret = unsafe { libc::write(received, &1u64 as *const u64 as *const _, 8) };
        assert_eq!(ret, 8);
    }

    #[test]
    fn test_eventfd_server_loop_can_stop() {
        let efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();
        let wake = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK).unwrap();
        let wake_raw = wake.as_raw_fd();
        let server = EventFdServer::bind(0x5678).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            server.serve_eventfd_loop_until(efd.as_raw_fd(), stop_thread, wake_raw);
        });

        stop.store(true, Ordering::Release);
        wake.write(1).unwrap();
        handle.join().unwrap();
    }
}
