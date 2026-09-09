use super::Session;
use crate::events::EventKind;

impl Session {
    pub fn create_event(&self, kind: EventKind) -> Option<u64> {
        self.event_monitor.as_ref().map(|m| m.create_event(kind))
    }

    pub fn take_event(&self, handle: u64) -> Option<(i64, std::time::Instant, i64, i64)> {
        self.event_monitor
            .as_ref()
            .and_then(|m| m.take_event(handle))
    }

    pub fn destroy_event(&self, handle: u64) {
        if let Some(m) = self.event_monitor.as_ref() {
            m.destroy_event(handle);
        }
    }

    pub fn event_monitor_fd(&self) -> Option<std::os::fd::RawFd> {
        self.event_monitor.as_ref().map(|m| m.event_fd())
    }
}
