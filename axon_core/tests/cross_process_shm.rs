use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use axon_core::local::RingBuffer;

const SHM_NAME: &str = "integration_test_cross_shm";

fn spawn_publisher(stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let buf = RingBuffer::create_or_open(SHM_NAME, 64, 4096, false)
            .expect("publisher create_or_open");
        let mut seq = 0u64;
        while !stop.load(Ordering::Relaxed) && seq < 50 {
            let msg = format!("msg_from_publisher_{}", seq);
            if buf.write(msg.as_bytes()).is_ok() {
                seq += 1;
            }
            thread::sleep(Duration::from_micros(100));
        }
    })
}

fn spawn_subscriber(stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let buf = RingBuffer::create_or_open(SHM_NAME, 64, 4096, false)
            .expect("subscriber create_or_open");
        let mut next_seq = 0u64;
        let mut out = vec![0u8; 4096];
        let mut received = 0u64;
        while !stop.load(Ordering::Relaxed) && received < 50 {
            if let Ok(n) = buf.read(next_seq, &mut out) {
                let msg = String::from_utf8_lossy(&out[..n]);
                assert!(msg.starts_with("msg_from_publisher_"));
                received += 1;
                next_seq += 1;
            } else {
                thread::sleep(Duration::from_micros(500));
            }
        }
        assert_eq!(received, 50, "subscriber should receive all 50 messages");
    })
}

#[test]
fn test_cross_process_shm_pub_sub() {
    // Clean up any stale segment before test
    let _ = std::fs::remove_file(format!("/dev/shm/axon_{}", SHM_NAME));

    let stop = Arc::new(AtomicBool::new(false));
    let sub = spawn_subscriber(stop.clone());
    thread::sleep(Duration::from_millis(10));
    let pub_h = spawn_publisher(stop.clone());

    pub_h.join().expect("publisher panicked");
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    sub.join().expect("subscriber panicked");
}
