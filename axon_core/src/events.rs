use nix::sys::eventfd::{EfdFlags, EventFd};
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Interval at which the background monitor thread checks deadlines/liveliness.
const MONITOR_INTERVAL: Duration = Duration::from_millis(100);

/// Opaque handle for an event.
pub type EventHandle = u64;
type DeadlineMonitorKey = (EventHandle, u64, u64);
type DeadlineMonitorState = (Duration, Instant);

/// Kind of RMW event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Liveliness lost by a publisher.
    LivelinessLost,
    /// Liveliness changed for a subscription.
    LivelinessChanged,
    /// Deadline missed by a publisher.
    DeadlineMissed,
    /// Message lost by a subscription.
    MessageLost,
    /// QoS compatibility issue.
    RequestedQosCompatibility,
}

/// Internal state for a single event.
pub struct EventState {
    pub kind: EventKind,
    pub count: AtomicI64,
    pub alive_count: AtomicI64,
    pub not_alive_count: AtomicI64,
    pub last_triggered: Arc<std::sync::Mutex<Instant>>,
}

/// Monitor for RMW events (deadline, liveliness, etc.).
///
/// Each event has a handle, kind, count, and last-triggered timestamp.
/// Events are signaled via an eventfd for use with `rmw_wait`.
pub struct EventMonitor {
    events: std::sync::RwLock<HashMap<EventHandle, EventState>>,
    eventfd: EventFd,
    next_handle: AtomicU64,
    stop: Arc<AtomicBool>,
    /// Deadline monitors: maps (event_handle, topic_hash, publisher_gid) to deadline Duration and last publish Instant
    deadline_monitors: std::sync::RwLock<HashMap<DeadlineMonitorKey, DeadlineMonitorState>>,
    /// Liveliness monitors: maps (event_handle, node_id) to (liveliness_lease_duration, last_asserted_instant)
    liveliness_monitors: std::sync::RwLock<HashMap<(EventHandle, u64), (Duration, Instant)>>,
}

impl EventMonitor {
    /// Create a new EventMonitor.
    ///
    /// # Returns
    /// `Ok(EventMonitor)` on success, or an I/O error if eventfd creation fails.
    pub fn new() -> std::io::Result<Self> {
        let eventfd = EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE)?;
        Ok(Self {
            events: std::sync::RwLock::new(HashMap::new()),
            eventfd,
            next_handle: AtomicU64::new(1),
            stop: Arc::new(AtomicBool::new(false)),
            deadline_monitors: std::sync::RwLock::new(HashMap::new()),
            liveliness_monitors: std::sync::RwLock::new(HashMap::new()),
        })
    }

    /// Create a new event and return its handle.
    ///
    /// # Arguments
    /// * `kind` - The kind of event
    ///
    /// # Returns
    /// Opaque event handle.
    pub fn create_event(&self, kind: EventKind) -> EventHandle {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.events.write().unwrap().insert(
            handle,
            EventState {
                kind,
                count: AtomicI64::new(0),
                alive_count: AtomicI64::new(0),
                not_alive_count: AtomicI64::new(0),
                last_triggered: Arc::new(std::sync::Mutex::new(Instant::now())),
            },
        );
        handle
    }

    /// Take an event, returning count, timestamp, alive_count and not_alive_count if triggered.
    ///
    /// # Arguments
    /// * `handle` - The event handle
    ///
    /// # Returns
    /// `(count, instant, alive_count, not_alive_count)` if the event was triggered, `None` otherwise.
    pub fn take_event(&self, handle: EventHandle) -> Option<(i64, Instant, i64, i64)> {
        let events = self.events.read().unwrap();
        let state = events.get(&handle)?;
        let count = state.count.load(Ordering::Relaxed);
        let alive = state.alive_count.load(Ordering::Relaxed);
        let not_alive = state.not_alive_count.load(Ordering::Relaxed);
        let instant = *state.last_triggered.lock().unwrap();
        if count > 0 {
            state.count.store(0, Ordering::Relaxed);
            // Drain the eventfd so the WaitSet doesn't keep waking up
            let _ = self.eventfd.read();
            Some((count, instant, alive, not_alive))
        } else {
            None
        }
    }

    /// Destroy an event.
    ///
    /// # Arguments
    /// * `handle` - The event handle to destroy
    pub fn destroy_event(&self, handle: EventHandle) {
        self.events.write().unwrap().remove(&handle);
    }

    /// Trigger an event, incrementing its count.
    ///
    /// # Arguments
    /// * `handle` - The event handle to trigger
    pub fn trigger_event(&self, handle: EventHandle) {
        let events = self.events.read().unwrap();
        if let Some(state) = events.get(&handle) {
            state.count.fetch_add(1, Ordering::Relaxed);
            *state.last_triggered.lock().unwrap() = Instant::now();
        }
        let _ = self.eventfd.write(1u64);
    }

    /// Trigger a LivelinessChanged event, setting alive/not_alive counts and incrementing the event count.
    ///
    /// # Arguments
    /// * `handle` - The event handle
    /// * `alive` - Number of alive publishers
    /// * `not_alive` - Number of not_alive publishers
    pub fn trigger_liveliness_changed(&self, handle: EventHandle, alive: i64, not_alive: i64) {
        let events = self.events.read().unwrap();
        if let Some(state) = events.get(&handle) {
            state.alive_count.store(alive, Ordering::Relaxed);
            state.not_alive_count.store(not_alive, Ordering::Relaxed);
            state.count.fetch_add(1, Ordering::Relaxed);
            *state.last_triggered.lock().unwrap() = Instant::now();
        }
        let _ = self.eventfd.write(1u64);
    }

    /// Update the alive/not_alive counts for a LivelinessChanged event without incrementing the event count.
    ///
    /// # Arguments
    /// * `handle` - The event handle
    /// * `alive` - Number of alive publishers
    /// * `not_alive` - Number of not_alive publishers
    pub fn update_liveliness_counts(&self, handle: EventHandle, alive: i64, not_alive: i64) {
        let events = self.events.read().unwrap();
        if let Some(state) = events.get(&handle) {
            state.alive_count.store(alive, Ordering::Relaxed);
            state.not_alive_count.store(not_alive, Ordering::Relaxed);
        }
    }

    /// Get the eventfd for polling.
    ///
    /// # Returns
    /// Raw file descriptor for the eventfd.
    pub fn event_fd(&self) -> std::os::fd::RawFd {
        self.eventfd.as_raw_fd()
    }

    /// Register a deadline monitor for a topic-publisher pair.
    ///
    /// # Arguments
    /// * `event_handle` - The event handle to trigger on deadline miss
    /// * `topic_hash` - The topic hash to monitor
    /// * `publisher_gid` - The publisher GID to monitor (0 = any publisher)
    /// * `deadline` - The deadline duration
    pub fn register_deadline_monitor(
        &self,
        event_handle: EventHandle,
        topic_hash: u64,
        publisher_gid: u64,
        deadline: Duration,
    ) {
        self.deadline_monitors.write().unwrap().insert(
            (event_handle, topic_hash, publisher_gid),
            (deadline, Instant::now()),
        );
    }

    /// Update the last publish time for deadline monitors matching a topic-publisher pair.
    ///
    /// When `publisher_gid` is non-zero, only the specific publisher's monitors are reset.
    /// When `publisher_gid` is 0, all monitors for the topic are reset (legacy fallback).
    ///
    /// # Arguments
    /// * `topic_hash` - The topic hash
    /// * `publisher_gid` - The publisher GID (0 = all publishers on topic)
    pub fn update_deadline_publish_time(&self, topic_hash: u64, publisher_gid: u64) {
        let now = Instant::now();
        let mut monitors = self.deadline_monitors.write().unwrap();
        if publisher_gid == 0 {
            for ((_eh, th, _gid), (_dl, last)) in monitors.iter_mut() {
                if *th == topic_hash {
                    *last = now;
                }
            }
        } else {
            for ((_eh, th, gid), (_dl, last)) in monitors.iter_mut() {
                if *th == topic_hash && *gid == publisher_gid {
                    *last = now;
                }
            }
        }
    }

    /// Check all deadline monitors and trigger events for expired deadlines.
    pub fn check_deadlines(&self) {
        let now = Instant::now();
        let monitors = self.deadline_monitors.read().unwrap();
        let mut expired_handles: Vec<EventHandle> = Vec::new();
        for ((eh, _th, _gid), (deadline, last)) in monitors.iter() {
            if now.duration_since(*last) > *deadline {
                expired_handles.push(*eh);
            }
        }
        drop(monitors);
        for eh in expired_handles {
            self.trigger_event(eh);
        }
    }

    /// Register a liveliness monitor for a node.
    ///
    /// # Arguments
    /// * `event_handle` - The event handle to trigger on liveliness loss
    /// * `node_id` - The node ID to monitor
    /// * `lease_duration` - The liveliness lease duration
    pub fn register_liveliness_monitor(
        &self,
        event_handle: EventHandle,
        node_id: u64,
        lease_duration: Duration,
    ) {
        self.liveliness_monitors
            .write()
            .unwrap()
            .insert((event_handle, node_id), (lease_duration, Instant::now()));
    }

    /// Assert liveliness for a node, updating last_asserted for all monitors.
    ///
    /// # Arguments
    /// * `node_id` - The node ID
    pub fn assert_liveliness(&self, node_id: u64) {
        let now = Instant::now();
        let mut monitors = self.liveliness_monitors.write().unwrap();
        for ((_eh, nid), (_dl, last)) in monitors.iter_mut() {
            if *nid == node_id {
                *last = now;
            }
        }
    }

    /// Check all liveliness monitors and trigger events for expired leases.
    /// Also computes alive/not_alive counts and triggers LivelinessChanged events.
    pub fn check_liveliness(&self) {
        let now = Instant::now();
        let monitors = self.liveliness_monitors.read().unwrap();
        let total = monitors.len() as i64;
        let mut expired_handles: Vec<EventHandle> = Vec::new();
        let mut alive = 0i64;
        for ((eh, _nid), (lease_duration, last)) in monitors.iter() {
            if now.duration_since(*last) > *lease_duration {
                expired_handles.push(*eh);
            } else {
                alive += 1;
            }
        }
        let not_alive = total - alive;
        drop(monitors);

        // Trigger LivelinessLost for expired monitors
        for eh in &expired_handles {
            self.trigger_event(*eh);
        }

        // Update LivelinessChanged events with current alive/not_alive counts
        let mut changed_handles: Vec<(EventHandle, i64, i64)> = Vec::new();
        {
            let events = self.events.read().unwrap();
            for (handle, state) in events.iter() {
                if state.kind == EventKind::LivelinessChanged {
                    let old_alive = state.alive_count.load(Ordering::Relaxed);
                    let old_not_alive = state.not_alive_count.load(Ordering::Relaxed);
                    if old_alive != alive || old_not_alive != not_alive {
                        changed_handles.push((*handle, alive, not_alive));
                    }
                }
            }
        }
        for (handle, a, na) in changed_handles {
            self.trigger_liveliness_changed(handle, a, na);
        }
    }

    /// Spawn a background thread that periodically checks deadlines and liveliness.
    pub fn spawn_monitor(self: &Arc<Self>) -> thread::JoinHandle<()> {
        let stop = self.stop.clone();
        let monitor = Arc::clone(self);
        thread::Builder::new()
            .name("axon-qos-monitor".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    thread::sleep(MONITOR_INTERVAL);
                    monitor.check_deadlines();
                    monitor.check_liveliness();
                }
            })
            .expect("failed to spawn QoS monitor thread")
    }

    /// Shutdown the monitor.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_monitor_create_trigger_take() {
        let monitor = EventMonitor::new().unwrap();
        let handle = monitor.create_event(EventKind::DeadlineMissed);
        monitor.trigger_event(handle);
        let (count, _instant, _, _) = monitor.take_event(handle).unwrap();
        assert_eq!(count, 1);
        assert!(monitor.take_event(handle).is_none());
        monitor.destroy_event(handle);
    }

    #[test]
    fn test_event_monitor_multiple_triggers() {
        let monitor = EventMonitor::new().unwrap();
        let handle = monitor.create_event(EventKind::LivelinessLost);
        for _ in 0..5 {
            monitor.trigger_event(handle);
        }
        let (count, _instant, _, _) = monitor.take_event(handle).unwrap();
        assert_eq!(count, 5);
        monitor.destroy_event(handle);
    }

    #[test]
    fn test_event_monitor_destroy() {
        let monitor = EventMonitor::new().unwrap();
        let handle = monitor.create_event(EventKind::MessageLost);
        monitor.destroy_event(handle);
        assert!(monitor.take_event(handle).is_none());
    }
}
