//! epoll-based wait set for multiplexing file descriptors.
//!
//! Wraps Linux `epoll` to wait on multiple file descriptors with
//! optional periodic timerfd polling.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd, RawFd};
use std::time::Duration;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::timerfd::ClockId;
use nix::sys::timerfd::{Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};

/// Sentinel index returned when the periodic poll timer fires.
pub const TIMER_READY_INDEX: usize = usize::MAX;

/// epoll-based wait set supporting multiple file descriptors and an optional timer.
pub struct WaitSet {
    epoll: Epoll,
    fd_to_index: HashMap<RawFd, usize>,
    timerfd: Option<TimerFd>,
}

impl WaitSet {
    /// Create a new wait set without a periodic timer.
    pub fn new() -> std::io::Result<Self> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        Ok(Self {
            epoll,
            fd_to_index: HashMap::new(),
            timerfd: None,
        })
    }

    /// Create a wait set with a periodic timer firing every `interval_ms`.
    pub fn new_with_poller(interval_ms: u64) -> std::io::Result<Self> {
        let mut ws = Self::new()?;
        let flags = TimerFlags::TFD_NONBLOCK | TimerFlags::TFD_CLOEXEC;
        let timer = TimerFd::new(ClockId::CLOCK_MONOTONIC, flags)?;
        timer.set(
            Expiration::Interval(Duration::from_millis(interval_ms).into()),
            TimerSetTimeFlags::empty(),
        )?;
        let event = EpollEvent::new(EpollFlags::EPOLLIN, TIMER_READY_INDEX as u64);
        ws.epoll
            .add(timer.as_fd(), event)
            .map_err(std::io::Error::other)?;
        ws.timerfd = Some(timer);
        Ok(ws)
    }

    /// Register a file descriptor with an associated index.
    ///
    /// # Arguments
    /// * `fd` - Raw file descriptor
    /// * `index` - User-defined index returned on readiness
    pub fn add_fd(&mut self, fd: RawFd, index: usize) -> std::io::Result<()> {
        let event = EpollEvent::new(EpollFlags::EPOLLIN, index as u64);
        self.epoll
            .add(unsafe { BorrowedFd::borrow_raw(fd) }, event)?;
        self.fd_to_index.insert(fd, index);
        Ok(())
    }

    /// Remove a file descriptor from the wait set.
    pub fn remove_fd(&mut self, fd: RawFd) -> std::io::Result<()> {
        self.epoll.delete(unsafe { BorrowedFd::borrow_raw(fd) })?;
        self.fd_to_index.remove(&fd);
        Ok(())
    }

    /// Remove all registered file descriptors.
    pub fn remove_all(&mut self) {
        let fds: Vec<RawFd> = self.fd_to_index.keys().copied().collect();
        for fd in fds {
            let _ = self.epoll.delete(unsafe { BorrowedFd::borrow_raw(fd) });
        }
        self.fd_to_index.clear();
    }

    /// Block until at least one fd is ready or the timeout expires.
    ///
    /// Returns the list of ready indices. A negative timeout blocks indefinitely.
    ///
    /// # Arguments
    /// * `timeout_ms` - Timeout in milliseconds
    pub fn wait(&self, timeout_ms: i32) -> std::io::Result<Vec<usize>> {
        let mut events = vec![EpollEvent::empty(); 64];
        let timeout = if timeout_ms < 0 {
            EpollTimeout::NONE
        } else if timeout_ms > (u16::MAX as i32) {
            EpollTimeout::MAX
        } else {
            EpollTimeout::from(timeout_ms as u16)
        };
        let n = self.epoll.wait(&mut events, timeout)?;

        let mut ready = Vec::new();
        for event in events.iter().take(n as usize) {
            let index = event.data() as usize;
            if index == TIMER_READY_INDEX {
                ready.push(TIMER_READY_INDEX);
            } else {
                ready.push(index);
                let fd = self
                    .fd_to_index
                    .iter()
                    .find(|(_, v)| **v == index)
                    .map(|(k, _)| k)
                    .copied()
                    .ok_or(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "fd not found",
                    ))?;
                let mut buf: [u8; 8] = [0; 8];
                let _ = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
            }
        }

        Ok(ready)
    }

    /// Drain the periodic timer counter to prevent immediate re-trigger.
    pub fn drain_poll_timer(&self) {
        if let Some(ref timer) = self.timerfd {
            let _ = timer.wait();
        }
    }

    /// Return the number of registered file descriptors.
    pub fn fd_count(&self) -> usize {
        self.fd_to_index.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::eventfd::{EfdFlags, EventFd};
    use std::os::fd::AsRawFd;

    #[test]
    fn test_waitset_signals() {
        let mut ws = WaitSet::new().unwrap();
        let efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();
        let raw_fd = efd.as_raw_fd();

        ws.add_fd(raw_fd, 0).unwrap();

        efd.write(1u64).unwrap();

        let ready = ws.wait(100).unwrap();
        assert_eq!(ready, vec![0]);
    }

    #[test]
    fn test_waitset_timeout() {
        let mut ws = WaitSet::new().unwrap();
        let efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();

        ws.add_fd(efd.as_raw_fd(), 0).unwrap();

        let ready = ws.wait(10).unwrap();
        assert!(ready.is_empty());
    }

    #[test]
    fn test_waitset_multiple_fds() {
        let mut ws = WaitSet::new().unwrap();
        let efd0 = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();
        let efd1 = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();

        ws.add_fd(efd0.as_raw_fd(), 0).unwrap();
        ws.add_fd(efd1.as_raw_fd(), 1).unwrap();

        assert_eq!(ws.fd_count(), 2);

        efd1.write(1u64).unwrap();

        let ready = ws.wait(100).unwrap();
        assert_eq!(ready, vec![1]);
    }

    #[test]
    fn test_waitset_add_remove() {
        let mut ws = WaitSet::new().unwrap();
        let efd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();

        ws.add_fd(efd.as_raw_fd(), 0).unwrap();
        ws.remove_fd(efd.as_raw_fd()).unwrap();

        assert_eq!(ws.fd_count(), 0);
    }

    #[test]
    fn test_waitset_remove_all() {
        let mut ws = WaitSet::new().unwrap();
        let efd0 = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();
        let efd1 = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE).unwrap();

        ws.add_fd(efd0.as_raw_fd(), 0).unwrap();
        ws.add_fd(efd1.as_raw_fd(), 1).unwrap();
        assert_eq!(ws.fd_count(), 2);

        ws.remove_all();
        assert_eq!(ws.fd_count(), 0);
    }

    #[test]
    fn test_waitset_poller_fires() {
        let ws = WaitSet::new_with_poller(10).unwrap();

        let ready = ws.wait(100).unwrap();
        assert!(
            ready.contains(&TIMER_READY_INDEX),
            "poller should fire within 100ms: {:?}",
            ready
        );

        ws.drain_poll_timer();
    }
}
