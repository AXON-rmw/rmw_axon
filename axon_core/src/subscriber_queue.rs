use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

pub struct SubscriberQueue {
    messages: Mutex<VecDeque<(u64, Vec<u8>)>>,
    capacity: usize,
    next_seq: AtomicU64,
    len: AtomicU64,
    active: AtomicBool,
    keep_all: bool,
    timestamps: Mutex<HashMap<u64, Instant>>,
}

impl SubscriberQueue {
    pub fn new(capacity: usize) -> Self {
        Self::with_seq_and_mode(capacity, 0, false)
    }

    pub fn with_seq(capacity: usize, start_seq: u64) -> Self {
        Self::with_seq_and_mode(capacity, start_seq, false)
    }

    pub fn with_seq_and_mode(capacity: usize, start_seq: u64, keep_all: bool) -> Self {
        Self {
            messages: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity: capacity.max(1),
            next_seq: AtomicU64::new(start_seq),
            len: AtomicU64::new(0),
            active: AtomicBool::new(false),
            keep_all,
            timestamps: Mutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, data: Vec<u8>) -> Option<u64> {
        let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
        let mut msgs = self.messages.lock().unwrap();
        if self.keep_all && msgs.len() >= self.capacity {
            return None;
        }
        while msgs.len() >= self.capacity {
            let (dropped_seq, _) = msgs.pop_front().unwrap();
            self.timestamps.lock().unwrap().remove(&dropped_seq);
        }
        msgs.push_back((seq, data));
        self.timestamps.lock().unwrap().insert(seq, Instant::now());
        self.len.store(msgs.len() as u64, Ordering::Release);
        self.active.store(true, Ordering::Release);
        Some(seq)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn timestamp_for(&self, seq: u64) -> Option<Instant> {
        self.timestamps.lock().unwrap().get(&seq).copied()
    }

    pub fn try_take(&self, seq: u64, out: &mut [u8]) -> Option<(usize, u64)> {
        let mut msgs = self.messages.lock().unwrap();
        if msgs.is_empty() {
            return None;
        }
        let oldest = msgs[0].0;
        if seq < oldest {
            let (actual_seq, data) = msgs.back().unwrap();
            if data.len() > out.len() {
                return Some((data.len(), *actual_seq));
            }
            let len = data.len();
            out[..len].copy_from_slice(data);
            let ret_seq = *actual_seq;
            msgs.clear();
            self.len.store(0, Ordering::Release);
            self.timestamps.lock().unwrap().clear();
            return Some((len, ret_seq));
        }
        let offset = (seq.saturating_sub(oldest)) as usize;
        if offset >= msgs.len() {
            return None;
        }
        let (actual_seq, data) = &msgs[offset];
        if data.len() > out.len() {
            return Some((data.len(), *actual_seq));
        }
        let len = data.len();
        out[..len].copy_from_slice(data);
        let ret_seq = *actual_seq;
        msgs.drain(0..=offset);
        self.len.store(msgs.len() as u64, Ordering::Release);
        {
            let mut timestamps = self.timestamps.lock().unwrap();
            for dropped_seq in oldest..=ret_seq {
                timestamps.remove(&dropped_seq);
            }
        }
        Some((len, ret_seq))
    }

    /// Read a message for a subscriber without removing it from the queue.
    ///
    /// A ROS topic has fan-out semantics: every subscription must observe the
    /// same sample stream independently.  The transport queue is shared by
    /// all subscriptions in a session, so consuming samples here would make
    /// the first subscriber steal them from the others.  The bounded queue
    /// already provides retention/overwrite semantics; each subscription's
    /// `next_seq` is the cursor that determines when it has consumed a sample.
    pub fn read_at(&self, seq: u64, out: &mut [u8]) -> Option<(usize, u64)> {
        let msgs = self.messages.lock().unwrap();
        if msgs.is_empty() {
            return None;
        }
        let oldest = msgs.front()?.0;
        let newest = msgs.back()?.0;
        // A cursor ahead of the newest sample has no data available.  Do not
        // clamp it back to `newest`: doing so re-delivers the last message on
        // every poll once a subscriber has caught up (and can create an
        // unbounded ROS callback/replanning loop).
        if seq > newest {
            return None;
        }
        let actual_seq = if seq < oldest { newest } else { seq };
        let offset = (actual_seq.saturating_sub(oldest)) as usize;
        let (_, data) = msgs.get(offset)?;
        if data.len() > out.len() {
            return Some((data.len(), actual_seq));
        }
        out[..data.len()].copy_from_slice(data);
        Some((data.len(), actual_seq))
    }

    pub fn data_available_from(&self, seq: u64) -> bool {
        let msgs = self.messages.lock().unwrap();
        msgs.back().is_some_and(|(newest, _)| seq <= *newest)
    }

    pub fn is_full(&self) -> bool {
        self.len.load(Ordering::Acquire) as usize >= self.capacity
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn message_size(&self, seq: u64) -> Option<usize> {
        let msgs = self.messages.lock().unwrap();
        if msgs.is_empty() {
            return None;
        }
        let oldest = msgs[0].0;
        if seq < oldest {
            return msgs.back().map(|(_, d)| d.len());
        }
        let offset = (seq.saturating_sub(oldest)) as usize;
        msgs.get(offset).map(|(_, d)| d.len())
    }

    pub fn peek_prefix(&self, requested_seq: u64) -> Option<([u8; 5], u64)> {
        let msgs = self.messages.lock().unwrap();
        if msgs.is_empty() {
            return None;
        }
        let oldest = msgs[0].0;
        let newest = msgs.back().unwrap().0;
        if requested_seq > newest {
            return None;
        }
        let actual_seq = if requested_seq >= oldest {
            requested_seq
        } else {
            newest
        };
        let offset = (actual_seq.saturating_sub(oldest)) as usize;
        msgs.get(offset).map(|(_, raw)| {
            let mut prefix = [0u8; 5];
            let copy_len = raw.len().min(5);
            prefix[..copy_len].copy_from_slice(&raw[..copy_len]);
            (prefix, actual_seq)
        })
    }

    pub fn peek_size(&self, requested_seq: u64) -> Option<(usize, u64)> {
        let msgs = self.messages.lock().unwrap();
        if msgs.is_empty() {
            return None;
        }
        let oldest = msgs[0].0;
        let newest = msgs.back().unwrap().0;
        if requested_seq > newest {
            return None;
        }
        let actual_seq = if requested_seq >= oldest {
            requested_seq
        } else {
            newest
        };
        let offset = (actual_seq.saturating_sub(oldest)) as usize;
        msgs.get(offset).map(|(_, d)| (d.len(), actual_seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_take() {
        let q = SubscriberQueue::new(10);
        q.push(vec![1, 2, 3]);
        let mut out = vec![0u8; 64];
        let (len, seq) = q.try_take(0, &mut out).unwrap();
        assert_eq!(len, 3);
        assert_eq!(&out[..3], &[1, 2, 3]);
        assert_eq!(seq, 0);
    }

    #[test]
    fn test_capacity_keep_last() {
        let q = SubscriberQueue::new(2);
        q.push(vec![1]);
        q.push(vec![2]);
        q.push(vec![3]);
        let mut out = vec![0u8; 64];
        let (len, _seq) = q.try_take(0, &mut out).unwrap();
        assert_eq!(len, 1);
        assert_eq!(out[0], 3);
    }

    #[test]
    fn test_data_available() {
        let q = SubscriberQueue::new(10);
        assert!(!q.data_available_from(0));
        q.push(vec![1, 2, 3]);
        assert!(q.data_available_from(0));
        q.try_take(0, &mut [0u8; 64]);
        assert!(!q.data_available_from(0));
    }

    #[test]
    fn test_read_at_is_fanout_safe() {
        let q = SubscriberQueue::new(8);
        q.push(b"shared sample".to_vec());

        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        let (n1, seq1) = q.read_at(0, &mut first).unwrap();
        let (n2, seq2) = q.read_at(0, &mut second).unwrap();

        assert_eq!(seq1, 0);
        assert_eq!(seq2, 0);
        assert_eq!(&first[..n1], b"shared sample");
        assert_eq!(&second[..n2], b"shared sample");
        assert!(q.data_available_from(0));
    }

    #[test]
    fn test_read_at_does_not_repeat_latest_for_future_cursor() {
        let q = SubscriberQueue::new(8);
        q.push(vec![1]);

        let mut out = [0u8; 8];
        assert_eq!(q.read_at(0, &mut out).unwrap().0, 1);
        assert!(q.read_at(1, &mut out).is_none());
        assert!(q.peek_prefix(1).is_none());
        assert!(q.peek_size(1).is_none());
    }

    #[test]
    fn test_with_nonzero_start_seq() {
        let q = SubscriberQueue::with_seq(2, 100);
        q.push(vec![1]);
        q.push(vec![2]);
        // Consumer cursor matches queue seqs
        let mut out = vec![0u8; 64];
        let (len, seq) = q.try_take(100, &mut out).unwrap();
        assert_eq!(len, 1);
        assert_eq!(out[0], 1);
        assert_eq!(seq, 100);
    }

    #[test]
    fn test_keep_all_drops_new_when_full() {
        let q = SubscriberQueue::with_seq_and_mode(2, 0, true);
        assert_eq!(q.push(vec![1]), Some(0));
        assert_eq!(q.push(vec![2]), Some(1));
        assert_eq!(q.push(vec![3]), None);
        let mut out = vec![0u8; 64];
        let (len, seq) = q.try_take(0, &mut out).unwrap();
        assert_eq!(len, 1);
        assert_eq!(out[0], 1);
        assert_eq!(seq, 0);
    }

    #[test]
    fn test_timestamp_recorded() {
        let q = SubscriberQueue::with_seq_and_mode(10, 0, false);
        q.push(vec![1, 2, 3]);
        assert!(q.timestamp_for(0).is_some());
        assert!(q.timestamp_for(99).is_none());
    }
}
