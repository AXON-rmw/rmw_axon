use nix::fcntl::OFlag;
use nix::sys::mman::{mmap, munmap, shm_open, shm_unlink, MapFlags, ProtFlags};
use nix::unistd::{close, ftruncate};
use std::ffi::CString;
use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

pub const SHM_NAME: &str = "/axon_daemon";
pub const MAGIC: u32 = 0x41584441;
pub const MAX_NODES: usize = 256;
pub const MAX_TOPICS_PER_NODE: usize = 256;
pub const MAX_MATCHES: usize = 1024;
pub const MAX_TOPIC_NAME_LEN: usize = 128;
pub const MAX_TOPIC_TYPE_LEN: usize = 128;
pub const MAX_NODE_NAME_LEN: usize = 128;
pub const MAX_NODE_NS_LEN: usize = 128;
pub const MAX_QUIC_ADDRS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotState {
    Empty = 0,
    Pending = 1,
    Active = 2,
    Leaving = 3,
    Claiming = 4,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TopicEntry {
    pub hash: u64,
    pub type_hash: u64,
    pub qos_reliability: u8,
    pub qos_durability: u8,
    pub qos_history_kind: u8,
    pub qos_history_depth: i32,
    pub qos_deadline_sec: u32,
    pub qos_deadline_nsec: u32,
    pub qos_lifespan_sec: u32,
    pub qos_lifespan_nsec: u32,
    pub qos_liveliness: u8,
    pub qos_liveliness_lease_sec: u32,
    pub qos_liveliness_lease_nsec: u32,
    pub topic_name: [u8; MAX_TOPIC_NAME_LEN],
    pub topic_type: [u8; MAX_TOPIC_TYPE_LEN],
    pub node_name: [u8; MAX_NODE_NAME_LEN],
    pub node_namespace: [u8; MAX_NODE_NS_LEN],
}

impl Default for TopicEntry {
    fn default() -> Self {
        Self {
            hash: 0,
            type_hash: 0,
            qos_reliability: 0,
            qos_durability: 0,
            qos_history_kind: 0,
            qos_history_depth: 0,
            qos_deadline_sec: 0,
            qos_deadline_nsec: 0,
            qos_lifespan_sec: 0,
            qos_lifespan_nsec: 0,
            qos_liveliness: 0,
            qos_liveliness_lease_sec: 0,
            qos_liveliness_lease_nsec: 0,
            topic_name: [0u8; MAX_TOPIC_NAME_LEN],
            topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
            node_name: [0u8; MAX_NODE_NAME_LEN],
            node_namespace: [0u8; MAX_NODE_NS_LEN],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct MatchEntry {
    pub node_id: u64,
    pub topic_hash: u64,
    pub port: u16,
    pub addr: [u8; 4],
}

#[repr(C)]
pub struct NodeTableEntry {
    pub state: AtomicU8,                       // 1 byte
    pub domain_id: u32,                        // 4 bytes
    pub pid: u32,                              // 4 bytes
    pub proc_starttime: u64, // 8 bytes: /proc/pid/stat field 22 (clock ticks since boot)
    pub pub_count: u32,      // 4 bytes
    pub sub_count: u32,      // 4 bytes
    pub quic_port: u16,      // 2 bytes
    pub match_count: u32,    // 4 bytes
    pub node_id: u64,        // 8 bytes
    pub response_gen: AtomicU64, // 8 bytes
    pub quic_addr_count: u32, // 4 bytes
    pub quic_addrs: [[u8; 4]; MAX_QUIC_ADDRS], // MAX_QUIC_ADDRS * 4 bytes
    pub daemon_origin: u64,  // 8 bytes: 0=local, non-zero=remote daemon_id
    pub last_seen_secs: u64, // 8 bytes: UNIX timestamp in seconds, set on sync for remote entries
    pub node_name: [u8; MAX_NODE_NAME_LEN],
    pub node_namespace: [u8; MAX_NODE_NS_LEN],
    pub published_topics: [TopicEntry; MAX_TOPICS_PER_NODE],
    pub subscribed_topics: [TopicEntry; MAX_TOPICS_PER_NODE],
    pub remote_matches: [MatchEntry; MAX_MATCHES],
}

#[repr(C)]
pub struct ShmHeader {
    pub magic: u32,
    pub daemon_pid: u32,
    pub daemon_proc_starttime: u64,
    pub generation: AtomicU64,
    pub max_nodes: u32,
    pub max_topics: u32,
    pub max_matches: u32,
}

pub struct ShmDiscovery {
    fd: ManuallyDrop<OwnedFd>,
    header: NonNull<ShmHeader>,
    node_table: NonNull<NodeTableEntry>,
    size: usize,
}

fn shm_full_size(max_nodes: u32) -> usize {
    let header_size = std::mem::size_of::<ShmHeader>();
    let table_size = std::mem::size_of::<NodeTableEntry>() * max_nodes as usize;
    let total = header_size + table_size;
    (total + 4095) & !4095
}

fn nix_to_io_error(e: nix::Error) -> std::io::Error {
    let kind = match e {
        nix::Error::ENOENT => std::io::ErrorKind::NotFound,
        nix::Error::EACCES | nix::Error::EPERM => std::io::ErrorKind::PermissionDenied,
        nix::Error::EEXIST => std::io::ErrorKind::AlreadyExists,
        _ => std::io::ErrorKind::Other,
    };
    std::io::Error::new(kind, e.to_string())
}

impl ShmDiscovery {
    pub fn create(name: &str, max_nodes: u32, _max_topics: u32) -> std::io::Result<Self> {
        let cname = CString::new(name).unwrap();
        let fd = shm_open(
            cname.as_c_str(),
            OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_EXCL,
            nix::sys::stat::Mode::S_IRWXU,
        )
        .map_err(nix_to_io_error)?;

        let size = shm_full_size(max_nodes);
        ftruncate(&fd, size as i64).map_err(|e| std::io::Error::other(e.to_string()))?;

        let ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new(size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )
        }
        .map_err(|e| std::io::Error::other(e.to_string()))?;

        let header = NonNull::new(ptr.as_ptr() as *mut ShmHeader).unwrap();

        unsafe {
            let pid = std::process::id();
            header.as_ptr().write(ShmHeader {
                // Publish the magic value only after the node table has been
                // fully initialized. Clients treat MAGIC as "ready".
                magic: 0,
                daemon_pid: pid,
                daemon_proc_starttime: read_proc_starttime(pid).unwrap_or(0),
                generation: AtomicU64::new(0),
                max_nodes,
                max_topics: MAX_TOPICS_PER_NODE as u32,
                max_matches: MAX_MATCHES as u32,
            });
        }

        let node_table_ptr = unsafe { header.as_ptr().add(1) as *mut NodeTableEntry };
        let node_table = NonNull::new(node_table_ptr).unwrap();

        let table_bytes = max_nodes as usize * std::mem::size_of::<NodeTableEntry>();
        unsafe {
            std::ptr::write_bytes(node_table.as_ptr() as *mut u8, 0, table_bytes);
            std::sync::atomic::fence(Ordering::Release);
            (*header.as_ptr()).magic = MAGIC;
        }

        Ok(Self {
            fd: ManuallyDrop::new(fd),
            header,
            node_table,
            size,
        })
    }

    pub fn open(name: &str) -> std::io::Result<Self> {
        let cname = CString::new(name).unwrap();
        let fd = shm_open(
            cname.as_c_str(),
            OFlag::O_RDWR,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(nix_to_io_error)?;

        let hdr_size = std::mem::size_of::<ShmHeader>();
        let hdr_ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new(hdr_size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )
        }
        .map_err(|e| std::io::Error::other(e.to_string()))?;

        let header = NonNull::new(hdr_ptr.as_ptr() as *mut ShmHeader).unwrap();
        if unsafe { header.as_ref() }.magic != MAGIC {
            unsafe {
                let _ = munmap(std::ptr::NonNull::new(hdr_ptr.as_ptr()).unwrap(), hdr_size);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad magic",
            ));
        }

        let hdr = unsafe { header.as_ref() };
        let max_nodes = hdr.max_nodes;
        if max_nodes == 0 || max_nodes > 1024 {
            unsafe {
                let _ = munmap(std::ptr::NonNull::new(hdr_ptr.as_ptr()).unwrap(), hdr_size);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid max_nodes in header",
            ));
        }
        if hdr.max_topics != MAX_TOPICS_PER_NODE as u32 || hdr.max_matches != MAX_MATCHES as u32 {
            unsafe {
                let _ = munmap(std::ptr::NonNull::new(hdr_ptr.as_ptr()).unwrap(), hdr_size);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "discovery SHM layout does not match this build",
            ));
        }
        let full_size = shm_full_size(max_nodes);

        unsafe {
            let _ = munmap(std::ptr::NonNull::new(hdr_ptr.as_ptr()).unwrap(), hdr_size);
        }

        let stat = nix::sys::stat::fstat(fd.as_raw_fd())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if stat.st_size < full_size as i64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "discovery SHM is smaller than expected for this build",
            ));
        }

        let ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new(full_size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )
        }
        .map_err(|e| std::io::Error::other(e.to_string()))?;

        let header = NonNull::new(ptr.as_ptr() as *mut ShmHeader).unwrap();

        let node_table_ptr = unsafe { header.as_ptr().add(1) as *mut NodeTableEntry };
        let node_table = NonNull::new(node_table_ptr).unwrap();

        Ok(Self {
            fd: ManuallyDrop::new(fd),
            header,
            node_table,
            size: full_size,
        })
    }

    pub fn destroy(name: &str) -> std::io::Result<()> {
        let cname = CString::new(name).unwrap();
        shm_unlink(cname.as_c_str()).map_err(|e| std::io::Error::other(e.to_string()))
    }

    pub fn header(&self) -> &ShmHeader {
        unsafe { self.header.as_ref() }
    }

    pub fn node_table(&self) -> &[NodeTableEntry] {
        let max = self.header().max_nodes as usize;
        unsafe { std::slice::from_raw_parts(self.node_table.as_ptr(), max) }
    }

    /// Mutable view of the shared-memory node table.
    ///
    /// # Safety contract (not enforced by the type system)
    /// The table lives in shared memory that other processes read and write
    /// concurrently; Rust aliasing rules cannot be upheld across processes
    /// anyway. Callers must only write to slots they own (claimed via
    /// [`claim_free_slot`](Self::claim_free_slot)) and use the `state` /
    /// `generation` atomics to publish changes.
    #[allow(clippy::mut_from_ref)]
    pub fn node_table_mut(&self) -> &mut [NodeTableEntry] {
        let max = self.header().max_nodes as usize;
        unsafe { std::slice::from_raw_parts_mut(self.node_table.as_ptr(), max) }
    }

    pub fn find_free_slot(&self) -> Option<usize> {
        self.node_table()
            .iter()
            .position(|e| e.state.load(Ordering::Acquire) == 0)
    }

    pub fn claim_free_slot(&self) -> Option<usize> {
        self.node_table()
            .iter()
            .enumerate()
            .find_map(|(idx, entry)| {
                entry
                    .state
                    .compare_exchange(
                        SlotState::Empty as u8,
                        SlotState::Claiming as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .ok()
                    .map(|_| idx)
            })
    }

    pub fn find_slot_by_node_id(&self, node_id: u64) -> Option<usize> {
        self.node_table()
            .iter()
            .position(|e| e.state.load(Ordering::Acquire) != 0 && e.node_id == node_id)
    }
}

// SAFETY: ShmDiscovery only wraps mmap'd shared memory accessed via atomics.
// The raw pointers (NonNull) are valid for the lifetime of the struct and accessed
// with proper synchronization. It is safe to send and share across threads.
unsafe impl Send for ShmDiscovery {}
unsafe impl Sync for ShmDiscovery {}

impl Drop for ShmDiscovery {
    fn drop(&mut self) {
        unsafe {
            let _ = munmap(
                std::ptr::NonNull::new(self.header.as_ptr() as *mut libc::c_void).unwrap(),
                self.size,
            );
        }
        let _ = close(self.fd.as_raw_fd());
    }
}

pub fn futex_wake(addr: &AtomicU64) {
    let ptr = addr as *const AtomicU64 as *const u32;
    unsafe {
        libc::syscall(libc::SYS_futex, ptr, libc::FUTEX_WAKE, 1);
    }
}

pub fn futex_wait(addr: &AtomicU64, expected: u32) -> Result<(), nix::Error> {
    let ptr = addr as *const AtomicU64 as *const u32;
    unsafe {
        let res = libc::syscall(
            libc::SYS_futex,
            ptr,
            libc::FUTEX_WAIT,
            expected,
            std::ptr::null::<libc::timespec>(),
        );
        if res == -1 {
            Err(nix::errno::Errno::last())
        } else {
            Ok(())
        }
    }
}

pub fn find_matches_by_hash(publishers: &[TopicEntry], subscribers: &[TopicEntry]) -> Vec<u64> {
    let mut result = Vec::new();
    for sub in subscribers {
        if publishers.iter().any(|p| p.hash == sub.hash) {
            result.push(sub.hash);
        }
    }
    result
}

pub fn find_matching_nodes(
    node_table: &[NodeTableEntry],
    domain_id: u32,
    publishers: &[TopicEntry],
) -> Vec<(usize, u64, u64)> {
    let mut result = Vec::new();
    for (idx, entry) in node_table.iter().enumerate() {
        let state = entry.state.load(std::sync::atomic::Ordering::Acquire);
        if state != 2 {
            continue;
        }
        if entry.domain_id != domain_id {
            continue;
        }
        let subs = &entry.subscribed_topics[..entry.sub_count as usize];
        for sub in subs {
            if publishers.iter().any(|p| p.hash == sub.hash) {
                result.push((idx, entry.node_id, sub.hash));
            }
        }
    }
    result
}

pub fn topic_entry_qos_compatible(pub_entry: &TopicEntry, sub_entry: &TopicEntry) -> bool {
    if pub_entry.qos_reliability == 0 && sub_entry.qos_reliability == 1 {
        return false;
    }
    if sub_entry.qos_durability == 1 && pub_entry.qos_durability == 0 {
        return false;
    }
    // KEEP_LAST depth is local queue capacity in ROS 2. A publisher with a
    // smaller depth can still match a subscriber with a larger depth.
    let pub_dl_ns =
        (pub_entry.qos_deadline_sec as u64) * 1_000_000_000 + pub_entry.qos_deadline_nsec as u64;
    let sub_dl_ns =
        (sub_entry.qos_deadline_sec as u64) * 1_000_000_000 + sub_entry.qos_deadline_nsec as u64;
    if pub_dl_ns > 0 && sub_dl_ns > 0 && pub_dl_ns > sub_dl_ns {
        return false;
    }
    if sub_entry.qos_liveliness == 1 && pub_entry.qos_liveliness == 0 {
        return false;
    }
    if sub_entry.qos_liveliness == 2 && pub_entry.qos_liveliness != 2 {
        return false;
    }
    let pub_ls_ns =
        (pub_entry.qos_lifespan_sec as u64) * 1_000_000_000 + pub_entry.qos_lifespan_nsec as u64;
    let sub_ls_ns =
        (sub_entry.qos_lifespan_sec as u64) * 1_000_000_000 + sub_entry.qos_lifespan_nsec as u64;
    if pub_ls_ns > 0 && sub_ls_ns > 0 && pub_ls_ns < sub_ls_ns {
        return false;
    }
    true
}

/// Read the process starttime from /proc/{pid}/stat (field 22, in clock ticks since boot).
/// Returns None if the file can't be read or parsed.
pub fn read_proc_starttime(pid: u32) -> Option<u64> {
    use std::io::Read;
    let path = format!("/proc/{}/stat", pid);
    let mut file = std::fs::File::open(&path).ok()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    let after_paren = buf.rfind(')')?;
    let rest = &buf[after_paren + 2..]; // skip ") "
                                        // fields: state(3), ppid(4), ..., starttime(22) = 20th token after state
    let starttime_str = rest.split_whitespace().nth(19)?;
    starttime_str.parse::<u64>().ok()
}

/// Check whether a process with the given PID and expected starttime is still alive.
/// Returns false if: the process doesn't exist, the pid was recycled (different starttime),
/// or the process is a zombie.
pub fn is_process_alive(pid: u32, expected_starttime: u64) -> bool {
    use std::io::Read;
    if pid == 0 {
        return false;
    }
    let path = format!("/proc/{}/stat", pid);
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_err() {
        return false;
    }
    let after_paren = match buf.rfind(')') {
        Some(p) => p,
        None => return false,
    };
    if after_paren + 2 >= buf.len() {
        return false;
    }
    let state_char = buf.as_bytes().get(after_paren + 2).copied().unwrap_or(0);
    if state_char == b'Z' || state_char == b'X' {
        return false;
    }
    let rest = &buf[after_paren + 2..];
    let starttime_str = match rest.split_whitespace().nth(19) {
        Some(s) => s,
        None => return false,
    };
    let current_starttime: u64 = match starttime_str.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    current_starttime == expected_starttime
}

pub fn is_daemon_node_alive(entry: &NodeTableEntry) -> bool {
    if entry.pid > 0 {
        is_process_alive(entry.pid, entry.proc_starttime)
    } else {
        entry.daemon_origin != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shm_create_open_destroy() {
        let _ = ShmDiscovery::destroy("__axon_test_shm");

        let shm = ShmDiscovery::create("__axon_test_shm", 64, 8).unwrap();
        assert!(shm.header().magic == MAGIC);
        assert!(shm.header().max_nodes == 64);

        let opened = ShmDiscovery::open("__axon_test_shm").unwrap();
        assert!(opened.header().magic == MAGIC);

        drop(shm);
        drop(opened);
        ShmDiscovery::destroy("__axon_test_shm").unwrap();
    }

    #[test]
    fn test_shm_open_nonexistent() {
        let _ = ShmDiscovery::destroy("__axon_test_shm_nonexist");
        let result = ShmDiscovery::open("__axon_test_shm_nonexist");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_free_slot_empty() {
        let _ = ShmDiscovery::destroy("__axon_test_shm_slots");
        let shm = ShmDiscovery::create("__axon_test_shm_slots", 8, 8).unwrap();
        let slot = shm.find_free_slot();
        assert_eq!(slot, Some(0));
        let _ = ShmDiscovery::destroy("__axon_test_shm_slots");
    }

    #[test]
    fn test_claim_free_slot_is_exclusive() {
        let _ = ShmDiscovery::destroy("__axon_test_shm_claim_slots");
        let shm = ShmDiscovery::create("__axon_test_shm_claim_slots", 8, 8).unwrap();
        let first = shm.claim_free_slot();
        let second = shm.claim_free_slot();
        assert_eq!(first, Some(0));
        assert_eq!(second, Some(1));
        assert_eq!(
            shm.node_table()[0].state.load(Ordering::Acquire),
            SlotState::Claiming as u8
        );
        assert_eq!(
            shm.node_table()[1].state.load(Ordering::Acquire),
            SlotState::Claiming as u8
        );
        let _ = ShmDiscovery::destroy("__axon_test_shm_claim_slots");
    }

    #[test]
    fn test_topic_match_pub_sub() {
        let pubs = vec![
            TopicEntry {
                hash: 0x42,
                type_hash: 0x100,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
            TopicEntry {
                hash: 0x43,
                type_hash: 0x101,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
        ];
        let subs = vec![
            TopicEntry {
                hash: 0x42,
                type_hash: 0x100,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
            TopicEntry {
                hash: 0x44,
                type_hash: 0x102,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
        ];
        let matches = find_matches_by_hash(&pubs, &subs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], 0x42);
    }

    #[test]
    fn test_topic_no_match() {
        let pubs = vec![TopicEntry {
            hash: 0x42,
            type_hash: 0x100,
            qos_reliability: 0,
            qos_durability: 0,
            qos_history_kind: 0,
            qos_history_depth: 0,
            qos_deadline_sec: 0,
            qos_deadline_nsec: 0,
            qos_lifespan_sec: 0,
            qos_lifespan_nsec: 0,
            qos_liveliness: 0,
            qos_liveliness_lease_sec: 0,
            qos_liveliness_lease_nsec: 0,
            topic_name: [0u8; MAX_TOPIC_NAME_LEN],
            topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
            ..Default::default()
        }];
        let subs = vec![TopicEntry {
            hash: 0x99,
            type_hash: 0x200,
            qos_reliability: 0,
            qos_durability: 0,
            qos_history_kind: 0,
            qos_history_depth: 0,
            qos_deadline_sec: 0,
            qos_deadline_nsec: 0,
            qos_lifespan_sec: 0,
            qos_lifespan_nsec: 0,
            qos_liveliness: 0,
            qos_liveliness_lease_sec: 0,
            qos_liveliness_lease_nsec: 0,
            topic_name: [0u8; MAX_TOPIC_NAME_LEN],
            topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
            ..Default::default()
        }];
        let matches = find_matches_by_hash(&pubs, &subs);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_topic_multi_match() {
        let pubs = vec![
            TopicEntry {
                hash: 0x42,
                type_hash: 0x100,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
            TopicEntry {
                hash: 0x43,
                type_hash: 0x101,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
            TopicEntry {
                hash: 0x44,
                type_hash: 0x102,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
        ];
        let subs = vec![
            TopicEntry {
                hash: 0x42,
                type_hash: 0x100,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
            TopicEntry {
                hash: 0x43,
                type_hash: 0x101,
                qos_reliability: 0,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                ..Default::default()
            },
        ];
        let matches = find_matches_by_hash(&pubs, &subs);
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&0x42));
        assert!(matches.contains(&0x43));
    }

    #[test]
    fn test_read_proc_starttime_self() {
        let pid = std::process::id();
        let st = read_proc_starttime(pid);
        assert!(st.is_some(), "should read starttime for own process");
        assert!(st.unwrap() > 0, "starttime should be positive");
    }

    #[test]
    fn test_is_process_alive_self() {
        let pid = std::process::id();
        let st = read_proc_starttime(pid).unwrap();
        assert!(is_process_alive(pid, st), "own process should be alive");
    }

    #[test]
    fn test_is_process_alive_wrong_starttime() {
        let pid = std::process::id();
        let st = read_proc_starttime(pid).unwrap();
        assert!(
            !is_process_alive(pid, st + 1),
            "wrong starttime should return false"
        );
    }

    #[test]
    fn test_is_process_alive_pid_zero() {
        assert!(!is_process_alive(0, 0), "pid 0 always dead");
    }

    #[test]
    fn test_is_process_alive_nonexistent_pid() {
        assert!(
            !is_process_alive(99999999, 0),
            "nonexistent pid should return false"
        );
    }

    #[allow(clippy::too_many_arguments)] // Compact fixture builder for QoS field combinations.
    fn make_entry(
        reliability: u8,
        durability: u8,
        history_kind: u8,
        history_depth: i32,
        deadline_s: u32,
        deadline_ns: u32,
        lifespan_s: u32,
        lifespan_ns: u32,
        liveliness: u8,
    ) -> TopicEntry {
        TopicEntry {
            hash: 1,
            type_hash: 1,
            qos_reliability: reliability,
            qos_durability: durability,
            qos_history_kind: history_kind,
            qos_history_depth: history_depth,
            qos_deadline_sec: deadline_s,
            qos_deadline_nsec: deadline_ns,
            qos_lifespan_sec: lifespan_s,
            qos_lifespan_nsec: lifespan_ns,
            qos_liveliness: liveliness,
            qos_liveliness_lease_sec: 0,
            qos_liveliness_lease_nsec: 0,
            topic_name: [0u8; MAX_TOPIC_NAME_LEN],
            topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
            ..Default::default()
        }
    }

    #[test]
    fn test_qos_best_effort_vs_reliable_incompatible() {
        assert!(!topic_entry_qos_compatible(
            &make_entry(0, 0, 1, 10, 0, 0, 0, 0, 0),
            &make_entry(1, 0, 1, 10, 0, 0, 0, 0, 0),
        ));
    }

    #[test]
    fn test_qos_matching_is_compatible() {
        let e = make_entry(1, 0, 1, 10, 0, 0, 0, 0, 0);
        assert!(topic_entry_qos_compatible(&e, &e));
    }

    #[test]
    fn test_qos_volatile_pub_transient_sub_incompatible() {
        assert!(!topic_entry_qos_compatible(
            &make_entry(1, 0, 1, 10, 0, 0, 0, 0, 0),
            &make_entry(1, 1, 1, 10, 0, 0, 0, 0, 0),
        ));
    }

    #[test]
    fn test_qos_depth_mismatch_compatible() {
        assert!(topic_entry_qos_compatible(
            &make_entry(1, 0, 1, 5, 0, 0, 0, 0, 0),
            &make_entry(1, 0, 1, 10, 0, 0, 0, 0, 0),
        ));
    }
}
