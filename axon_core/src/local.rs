//! Local shared-memory ring buffer and pub/sub transport.
//!
//! Uses POSIX shared memory (`shm_open`) and `mmap` for same-host communication
//! between processes. Loaned-message paths can access ring slots directly;
//! ordinary ROS publish/take paths still serialize and copy payloads. An
//! `eventfd` signals data availability.

use std::collections::HashMap;
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::io::{self, Error, ErrorKind};
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::fcntl::{fallocate, FallocateFlags};
use nix::sys::eventfd::{EfdFlags, EventFd};
use nix::sys::mman::{mmap, munmap, shm_open, shm_unlink, MapFlags, ProtFlags};
use nix::sys::stat::fstat;

use crate::types::RingBufferHeader;

pub(crate) fn max_ring_data_bytes() -> usize {
    std::env::var("AXON_RING_BUFFER_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(256 * 1024 * 1024)
}

/// Return available bytes on the `/dev/shm` tmpfs, or `None` if
/// the path does not exist or `statvfs` fails.
fn available_shm_bytes() -> Option<usize> {
    let vfs = nix::sys::statvfs::statvfs("/dev/shm").ok()?;
    let frag = vfs.fragment_size() as usize;
    let avail = vfs.blocks_available() as usize;
    frag.checked_mul(avail)
}

// Keep enough history for high-fanout reliable topics.  The requested depth
// is still bounded by `max_ring_data_bytes()` and available `/dev/shm`, so
// increasing this ceiling does not bypass the memory guard.
const MAX_RING_SLOTS: usize = 4096;
const SHM_CREATE_RACE_RETRIES: usize = 100;
const SHM_CREATE_RACE_SLEEP: Duration = Duration::from_millis(5);
const SLOT_SEQ_OFFSET: usize = 0;
const SLOT_LEN_OFFSET: usize = 8;
const SLOT_DATA_OFFSET: usize = 16;

fn slot_stride_for_payload(payload_size: u32) -> io::Result<u32> {
    let raw = (payload_size as usize)
        .checked_add(SLOT_DATA_OFFSET)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "slot size overflow"))?;
    let aligned = (raw + 7) & !7;
    u32::try_from(aligned).map_err(|_| Error::new(ErrorKind::InvalidInput, "slot size overflow"))
}

fn payload_capacity_from_stride(slot_stride: u32) -> usize {
    (slot_stride as usize).saturating_sub(SLOT_DATA_OFFSET)
}

/// Lock-free ring buffer backed by POSIX shared memory.
///
/// Supports concurrent single-producer / single-consumer access via
/// atomic write and read indices.
pub struct RingBuffer {
    header: *mut RingBufferHeader,
    data_ptr: *mut u8,
    slot_count: u32,
    slot_size: u32,
}

unsafe impl Send for RingBuffer {}
unsafe impl Sync for RingBuffer {}

/// Convert a string to a C string, returning an error on embedded null bytes.
fn cstring(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| Error::new(ErrorKind::InvalidInput, "null byte in string"))
}

impl RingBuffer {
    /// Create a new shared-memory ring buffer.
    ///
    /// # Arguments
    /// * `name` - Name used for the shared memory segment
    /// * `slot_count` - Number of slots in the ring
    /// * `slot_size` - Size of each slot in bytes
    pub fn create(name: &str, slot_count: u32, slot_size: u32, keep_all: bool) -> io::Result<Self> {
        if slot_count == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "slot count must be non-zero",
            ));
        }
        let slot_stride = slot_stride_for_payload(slot_size)?;
        let shm_name = format!("/axon_{}", name);
        let cname = cstring(&shm_name)?;

        let _ = shm_unlink(cname.as_c_str());

        let fd = shm_open(
            cname.as_c_str(),
            OFlag::O_CREAT | OFlag::O_RDWR,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )?;

        Self::create_with_fd(fd, slot_count, slot_stride, keep_all)
    }

    fn create_with_fd(
        fd: std::os::fd::OwnedFd,
        slot_count: u32,
        slot_stride: u32,
        _keep_all: bool,
    ) -> io::Result<Self> {
        let header_size = std::mem::size_of::<RingBufferHeader>();
        let max_slots = (max_ring_data_bytes() / (slot_stride as usize)).clamp(1, MAX_RING_SLOTS);

        // Clamp slot_count so the ring buffer fits in available /dev/shm
        // space instead of failing with ENOSPC.
        let slot_count = {
            let mut sc = slot_count as usize;
            sc = sc.min(max_slots);
            if let Some(avail) = available_shm_bytes() {
                let max_by_shm = avail / (slot_stride as usize);
                if max_by_shm > 0 && max_by_shm < sc {
                    tracing::warn!(
                        "reduced ring buffer slots from {} to {} ({} MB /dev/shm available)",
                        sc,
                        max_by_shm,
                        avail / (1024 * 1024)
                    );
                    sc = max_by_shm;
                }
            }
            sc.max(1).min(u32::MAX as usize) as u32
        };

        // fallocate with progressive backoff on ENOSPC.  statvfs can
        // over-report available space on Docker tmpfs when other segments
        // were created with ftruncate (which doesn't actually reserve pages).
        // We start at the request size and halve slots until fallocate
        // succeeds.
        let total_size = {
            let mut sc = slot_count;
            loop {
                let sz = header_size + (sc as usize) * (slot_stride as usize);
                match fallocate(fd.as_raw_fd(), FallocateFlags::empty(), 0, sz as i64) {
                    Ok(()) => break sz,
                    Err(nix::Error::ENOSPC) if sc > 1 => {
                        let next = sc.max(2) / 2;
                        tracing::warn!("fallocate ENOSPC for {} slots, retrying with {}", sc, next);
                        sc = next;
                        continue;
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::StorageFull,
                            format!(
                                "insufficient shared memory for {} byte ring buffer: {}",
                                sz, e
                            ),
                        ));
                    }
                }
            }
        };
        let slot_count =
            slot_count.min(((total_size - header_size) / (slot_stride as usize)) as u32);

        let total_len = NonZeroUsize::new(total_size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "total size is zero"))?;

        let ptr = unsafe {
            mmap(
                None,
                total_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )?
        };

        drop(fd);

        let header = ptr.as_ptr() as *mut RingBufferHeader;
        let data_ptr = unsafe { ptr.as_ptr().add(header_size) as *mut u8 };

        unsafe {
            (*header).capacity = slot_count;
            (*header).slot_size = slot_stride;
            (*header).write_index = AtomicU64::new(0);
            (*header).read_index = AtomicU64::new(0);
            (*header).epoch = AtomicU64::new(0);
        }

        // Zero all data slots to prevent stale data from shared memory reuse
        let total_data = (slot_count as usize) * (slot_stride as usize);
        unsafe {
            std::ptr::write_bytes(data_ptr, 0, total_data);
        }

        Ok(Self {
            header,
            data_ptr,
            slot_count,
            slot_size: slot_stride,
        })
    }

    /// Create-or-open a shared-memory ring buffer.
    ///
    /// Tries to create a new segment exclusively; if one already exists,
    /// opens the existing one instead.
    pub fn create_or_open(
        name: &str,
        slot_count: u32,
        slot_size: u32,
        keep_all: bool,
    ) -> io::Result<Self> {
        let slot_stride = slot_stride_for_payload(slot_size)?;
        let shm_name = format!("/axon_{}", name);
        let cname = cstring(&shm_name)?;

        match shm_open(
            cname.as_c_str(),
            OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        ) {
            Ok(fd) => match Self::create_with_fd(fd, slot_count, slot_stride, keep_all) {
                Ok(rb) => Ok(rb),
                Err(e) => {
                    let _ = shm_unlink(cname.as_c_str());
                    Err(e)
                }
            },
            Err(nix::errno::Errno::EEXIST) => {
                if let Some(rb) = Self::wait_open_compatible(name, slot_stride, keep_all)? {
                    return Ok(rb);
                }
                // Segment exists but has wrong slot size, is not yet
                // initialized after the retry window, or is corrupted — unlink
                // and create fresh. Do not reject smaller slot_count: a
                // late-joining endpoint may request a deeper queue than the
                // active publisher. Replacing that live segment isolates the
                // endpoints into different SHM rings.
                let _ = shm_unlink(cname.as_c_str());
                Self::open_or_create(name, slot_count, slot_stride, keep_all)
            }
            Err(err) => Err(io::Error::from(err)),
        }
    }

    fn is_compatible_with_request(&self, requested_slot_stride: u32) -> bool {
        self.slot_count > 0 && self.slot_size >= requested_slot_stride
    }

    fn wait_open_compatible(
        name: &str,
        requested_slot_stride: u32,
        keep_all: bool,
    ) -> io::Result<Option<Self>> {
        for _ in 0..SHM_CREATE_RACE_RETRIES {
            match Self::open(name, keep_all) {
                Ok(rb) => {
                    if rb.is_compatible_with_request(requested_slot_stride) {
                        return Ok(Some(rb));
                    }
                    return Ok(None);
                }
                Err(e) if matches!(e.kind(), ErrorKind::InvalidData | ErrorKind::UnexpectedEof) => {
                    std::thread::sleep(SHM_CREATE_RACE_SLEEP);
                }
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Try to open an existing segment; if it doesn't exist, create it.
    fn open_or_create(
        name: &str,
        slot_count: u32,
        slot_stride: u32,
        keep_all: bool,
    ) -> io::Result<Self> {
        let shm_name = format!("/axon_{}", name);
        let cname = cstring(&shm_name)?;

        for _ in 0..SHM_CREATE_RACE_RETRIES {
            match shm_open(
                cname.as_c_str(),
                OFlag::O_RDWR,
                nix::sys::stat::Mode::empty(),
            ) {
                Ok(fd) => match Self::from_fd(fd, keep_all) {
                    Ok(rb) => {
                        if rb.is_compatible_with_request(slot_stride) {
                            return Ok(rb);
                        }
                        let _ = shm_unlink(cname.as_c_str());
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                        ) =>
                    {
                        std::thread::sleep(SHM_CREATE_RACE_SLEEP);
                    }
                    Err(e) => {
                        let _ = shm_unlink(cname.as_c_str());
                        return Err(e);
                    }
                },
                Err(nix::errno::Errno::ENOENT) => {
                    match shm_open(
                        cname.as_c_str(),
                        OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR,
                        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                    ) {
                        Ok(fd) => {
                            return match Self::create_with_fd(fd, slot_count, slot_stride, keep_all)
                            {
                                Ok(rb) => Ok(rb),
                                Err(e) => {
                                    let _ = shm_unlink(cname.as_c_str());
                                    Err(e)
                                }
                            };
                        }
                        Err(nix::errno::Errno::EEXIST) => {
                            std::thread::sleep(SHM_CREATE_RACE_SLEEP);
                        }
                        Err(err) => return Err(io::Error::from(err)),
                    }
                }
                Err(nix::errno::Errno::EEXIST) => {
                    std::thread::sleep(SHM_CREATE_RACE_SLEEP);
                }
                Err(err) => return Err(io::Error::from(err)),
            }
        }

        Err(Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "shared memory segment {} stayed busy during create/open race",
                shm_name
            ),
        ))
    }

    /// Open an existing SHM segment from an already-opened fd.
    fn from_fd(fd: std::os::fd::OwnedFd, _keep_all: bool) -> io::Result<Self> {
        let header_size = std::mem::size_of::<RingBufferHeader>();
        let shm_len = fstat(fd.as_raw_fd())
            .map_err(io::Error::from)?
            .st_size
            .try_into()
            .unwrap_or(0usize);
        if shm_len < header_size {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "shared memory segment is too small for ring header ({} < {})",
                    shm_len, header_size
                ),
            ));
        }

        // A stale segment may have file size but no reserved tmpfs pages. Reserve
        // the header before touching it so ENOSPC is reported as an error instead
        // of surfacing as SIGBUS on mmap page fault.
        fallocate(
            fd.as_raw_fd(),
            FallocateFlags::empty(),
            0,
            header_size as i64,
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::StorageFull,
                format!(
                    "stale shared memory header cannot be allocated ({} bytes): {}",
                    header_size, e
                ),
            )
        })?;
        let probe_len = NonZeroUsize::new(header_size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "header size is zero"))?;

        let probe_ptr = unsafe {
            mmap(
                None,
                probe_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )?
        };

        let probe_header = probe_ptr.as_ptr() as *const RingBufferHeader;
        let cap = unsafe { (*probe_header).capacity };
        let ssz = unsafe { (*probe_header).slot_size };
        let _write_idx = unsafe { (*probe_header).write_index.load(Ordering::Relaxed) };
        let _read_idx = unsafe { (*probe_header).read_index.load(Ordering::Relaxed) };

        if cap == 0 || ssz == 0 {
            unsafe {
                munmap(probe_ptr, header_size)?;
            }
            return Err(Error::new(
                ErrorKind::InvalidData,
                "stale segment with zero capacity or slot_size",
            ));
        }

        unsafe {
            munmap(probe_ptr, header_size)?;
        }

        let data_size = (cap as usize)
            .checked_mul(ssz as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "ring buffer size overflow"))?;
        let total_size = header_size
            .checked_add(data_size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "ring buffer size overflow"))?;
        let total_len = NonZeroUsize::new(total_size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "total size is zero"))?;

        // Pre-allocate all backing pages for this existing SHM segment.
        // A stale segment from a crashed process may have a valid header
        // but no backing pages (tmpfs over-commit on ftruncate followed
        // by a process kill before the pages were faulted in).  fallocate
        // returns ENOSPC when the filesystem lacks space, instead of
        // SIGBUS on later mmap page access.
        fallocate(
            fd.as_raw_fd(),
            FallocateFlags::empty(),
            0,
            total_size as i64,
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::StorageFull,
                format!(
                    "stale shared memory segment cannot be allocated ({} bytes): {}",
                    total_size, e
                ),
            )
        })?;

        let ptr = unsafe {
            mmap(
                None,
                total_len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )?
        };

        drop(fd);

        let header = ptr.as_ptr() as *mut RingBufferHeader;
        let data_ptr = unsafe { ptr.as_ptr().add(header_size) as *mut u8 };

        Ok(Self {
            header,
            data_ptr,
            slot_count: cap,
            slot_size: ssz,
        })
    }

    /// Open an existing shared-memory ring buffer by name.
    pub fn open(name: &str, keep_all: bool) -> io::Result<Self> {
        let shm_name = format!("/axon_{}", name);
        let cname = cstring(&shm_name)?;
        let fd = shm_open(
            cname.as_c_str(),
            OFlag::O_RDWR,
            nix::sys::stat::Mode::empty(),
        )?;
        Self::from_fd(fd, keep_all)
    }

    /// Write data into the next available slot.
    ///
    /// Returns the sequence number of the written slot, or an error if the
    /// buffer is full or the data exceeds slot size.
    pub fn write(&self, data: &[u8]) -> Result<u64, &'static str> {
        if data.len() > payload_capacity_from_stride(self.slot_size) {
            return Err("data exceeds slot size");
        }

        let write_idx = unsafe { (*self.header).write_index.fetch_add(1, Ordering::AcqRel) };
        let read_idx = unsafe { (*self.header).read_index.load(Ordering::Acquire) };
        // A concurrent reader may advance read_index past this writer's
        // reserved write_idx (another writer reserved a later slot and a
        // reader already consumed it). `write_idx - read_idx` would then
        // underflow and the CAS below would drag read_index backwards,
        // re-exposing already-consumed slots. checked_sub skips the
        // overwrite handling in that case.
        if write_idx
            .checked_sub(read_idx)
            .is_some_and(|lag| lag >= self.slot_count as u64)
        {
            // AXON rings are bounded. If a writer outruns active consumers or
            // no consumer is alive, degrade KeepAll to bounded latest-data
            // retention instead of failing rmw_publish and killing publishers
            // such as camera nodes.
            let new_read = write_idx.saturating_sub((self.slot_count as u64) - 1);
            unsafe {
                let _ = (*self.header).read_index.compare_exchange(
                    read_idx,
                    new_read,
                    Ordering::Release,
                    Ordering::Relaxed,
                );
            }
        }

        let slot = (write_idx % (self.slot_count as u64)) as usize;
        let slot_off = slot * (self.slot_size as usize);
        unsafe {
            let dst = self.data_ptr.add(slot_off);
            let seq_atomic = &*(dst.add(SLOT_SEQ_OFFSET) as *const std::sync::atomic::AtomicU64);
            let len_atomic = &*(dst.add(SLOT_LEN_OFFSET) as *const std::sync::atomic::AtomicU32);
            seq_atomic.store(u64::MAX, Ordering::Release);
            len_atomic.store(0, Ordering::Release);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(SLOT_DATA_OFFSET), data.len());
            len_atomic.store(data.len() as u32, Ordering::Release);
            seq_atomic.store(write_idx, Ordering::Release);
        }

        Ok(write_idx)
    }

    /// Read data from a specific sequence number slot.
    ///
    /// # Arguments
    /// * `sequence_number` - Slot sequence to read
    /// * `out` - Output buffer to receive the data
    pub fn read(&self, sequence_number: u64, out: &mut [u8]) -> Result<usize, &'static str> {
        let n = self.read_slot(sequence_number, out)?;

        // Advance read_index watermark so producer knows this slot is consumed
        unsafe {
            let read_idx = (*self.header).read_index.load(Ordering::Relaxed);
            if sequence_number >= read_idx {
                (*self.header)
                    .read_index
                    .store(sequence_number + 1, Ordering::Release);
            }
        }

        Ok(n)
    }

    /// Read data from a specific sequence number without advancing the
    /// shared read watermark. This is required for multiplexed service
    /// response rings: each ROS client owns an independent cursor and must be
    /// able to inspect responses addressed to the other clients.
    pub fn read_without_consuming(
        &self,
        sequence_number: u64,
        out: &mut [u8],
    ) -> Result<usize, &'static str> {
        self.read_slot(sequence_number, out)
    }

    fn read_slot(&self, sequence_number: u64, out: &mut [u8]) -> Result<usize, &'static str> {
        let write_idx = unsafe { (*self.header).write_index.load(Ordering::Acquire) };

        if sequence_number >= write_idx {
            return Err("no data at this sequence number");
        }

        if write_idx - sequence_number > (self.slot_count as u64) {
            return Err("slot overwritten");
        }

        let slot = (sequence_number % (self.slot_count as u64)) as usize;
        let slot_off = slot * (self.slot_size as usize);

        let len = unsafe {
            let src = self.data_ptr.add(slot_off);
            let seq_atomic = &*(src.add(SLOT_SEQ_OFFSET) as *const std::sync::atomic::AtomicU64);
            if seq_atomic.load(Ordering::Acquire) != sequence_number {
                return Err("slot not yet written");
            }
            let len_atomic = &*(src.add(SLOT_LEN_OFFSET) as *const std::sync::atomic::AtomicU32);
            let n = len_atomic.load(Ordering::Acquire) as usize;
            if n == 0 {
                return Err("slot not yet written");
            }
            if n > out.len() {
                return Err("output buffer too small");
            }
            std::ptr::copy_nonoverlapping(src.add(SLOT_DATA_OFFSET), out.as_mut_ptr(), n);
            if seq_atomic.load(Ordering::Acquire) != sequence_number {
                return Err("slot overwritten");
            }
            n
        };
        Ok(len)
    }

    /// Peek at the data size for a given sequence number without consuming it.
    ///
    /// Returns the size of the data stored at that slot, or an error if the
    /// slot is unavailable (no data / overwritten).
    pub fn slot_data_size(&self, sequence_number: u64) -> Result<usize, &'static str> {
        let write_idx = unsafe { (*self.header).write_index.load(Ordering::Acquire) };
        if sequence_number >= write_idx {
            return Err("no data at this sequence number");
        }
        if write_idx - sequence_number > (self.slot_count as u64) {
            return Err("slot overwritten");
        }
        let slot = (sequence_number % (self.slot_count as u64)) as usize;
        let slot_off = slot * (self.slot_size as usize);
        unsafe {
            let src = self.data_ptr.add(slot_off);
            let seq_atomic = &*(src.add(SLOT_SEQ_OFFSET) as *const std::sync::atomic::AtomicU64);
            if seq_atomic.load(Ordering::Acquire) != sequence_number {
                return Err("slot not yet written");
            }
            let len_atomic = &*(src.add(SLOT_LEN_OFFSET) as *const std::sync::atomic::AtomicU32);
            let n = len_atomic.load(Ordering::Acquire) as usize;
            if n == 0 {
                return Err("slot not yet written");
            }
            Ok(n)
        }
    }

    /// Return a raw pointer to the ring buffer header.
    pub fn header_ptr(&self) -> *mut RingBufferHeader {
        self.header
    }

    /// Return a raw pointer to the data region.
    pub fn data_ptr(&self) -> *mut u8 {
        self.data_ptr
    }

    /// Return the current write index (next sequence number to be written).
    pub fn current_seq(&self) -> u64 {
        unsafe { (*self.header).write_index.load(Ordering::Acquire) }
    }

    /// Return the oldest sequence number that may still be read.
    pub fn oldest_available_seq(&self) -> u64 {
        self.current_seq().saturating_sub(self.slot_count as u64)
    }

    /// Mark the start of a new publisher generation.
    ///
    /// Records the current write index in the ring's `epoch` field. A ring in
    /// POSIX shared memory outlives the process that created it, so a relaunched
    /// publisher re-opens a segment still holding frames written by the previous
    /// run. Those frames carry valid sequence numbers, so a late-joining
    /// `TRANSIENT_LOCAL` subscriber would otherwise read them and briefly show
    /// stale latched data (e.g. an old point cloud, `/map`, or `/tf_static`).
    /// Stamping the generation start lets subscribers ignore anything published
    /// before this publisher came up.
    pub fn mark_generation(&self) {
        let w = unsafe { (*self.header).write_index.load(Ordering::Acquire) };
        unsafe {
            (*self.header).epoch.store(w, Ordering::Release);
        }
    }

    /// Oldest sequence number valid for the current publisher generation.
    pub fn generation_start(&self) -> u64 {
        unsafe { (*self.header).epoch.load(Ordering::Acquire) }
    }

    /// Check whether data is available at or after a consumer sequence.
    ///
    /// Returns true when valid data exists at `sequence_number` OR when the
    /// consumer has fallen behind but the ring buffer still holds newer frames
    /// that `receive_next` can skip ahead to.  Without the fallback a slow or
    /// late-joining subscriber whose cursor was overwritten by another reader
    /// would be permanently stuck because rmw_wait never marks it ready, so
    /// rmw_take (which would call receive_next and skip ahead) is never invoked.
    pub fn data_available_from(&self, sequence_number: u64) -> bool {
        match self.slot_data_size(sequence_number) {
            Ok(n) => n > 0,
            Err("slot not yet written") => {
                // `write_index` is reserved before the producer fills the
                // slot.  A reader can therefore observe the new index after
                // an eventfd wake-up while the slot's publish marker is still
                // being committed.  Keep the entity ready in that case so
                // rmw_wait retries the same cursor instead of draining the
                // only wake-up and dropping the client from the wait set.
                // This is especially important for service responses, where
                // one lost readiness notification leaves an action future
                // waiting forever even though the server completed it.
                let write_idx = unsafe { (*self.header).write_index.load(Ordering::Acquire) };
                sequence_number < write_idx
            }
            Err(_) => {
                let write_idx = unsafe { (*self.header).write_index.load(Ordering::Acquire) };
                let read_idx = unsafe { (*self.header).read_index.load(Ordering::Acquire) };
                sequence_number < write_idx && write_idx > read_idx
            }
        }
    }

    /// Check whether unread data is available.
    pub fn data_available(&self) -> bool {
        let write_idx = unsafe { (*self.header).write_index.load(Ordering::Acquire) };
        let read_idx = unsafe { (*self.header).read_index.load(Ordering::Acquire) };
        write_idx > read_idx
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        let total_size = std::mem::size_of::<RingBufferHeader>()
            + (self.slot_count as usize) * (self.slot_size as usize);
        if let Some(addr) = NonNull::new(self.header as *mut std::ffi::c_void) {
            unsafe {
                let _ = munmap(addr, total_size);
            }
        }
    }
}

/// Local pub/sub channel backed by a shared-memory ring buffer and eventfd.
pub struct LocalPubSub {
    ring_buf: RingBuffer,
    eventfd: EventFd,
    /// Cross-process eventfd received via SCM_RIGHTS, or -1 if not available.
    cross_process_eventfd: std::os::fd::RawFd,
    eventfd_server_stop: Option<Arc<AtomicBool>>,
    eventfd_server_wake: Option<EventFd>,
    eventfd_server_thread: Mutex<Option<JoinHandle<()>>>,
    /// Per-sequence-number publish timestamps for lifespan enforcement.
    pub timestamps: Mutex<HashMap<u64, Instant>>,
    /// Per-sequence-number publisher GID for deadline per-publisher tracking.
    pub publisher_gids: Mutex<HashMap<u64, u64>>,
    loaned_sequences: Mutex<HashMap<usize, u64>>,
}

type EventFdServerParts = (
    Option<Arc<AtomicBool>>,
    Option<EventFd>,
    Mutex<Option<JoinHandle<()>>>,
);

fn spawn_eventfd_server(
    server: crate::scm::EventFdServer,
    eventfd_raw: RawFd,
    topic_hash: u64,
) -> EventFdServerParts {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let Ok(wake) = EventFd::from_value_and_flags(0, EfdFlags::EFD_NONBLOCK | EfdFlags::EFD_CLOEXEC)
    else {
        return (None, None, Mutex::new(None));
    };
    let wake_raw = wake.as_raw_fd();
    match std::thread::Builder::new()
        .name(format!("axon-evtfd-{:x}", topic_hash))
        .spawn(move || {
            server.serve_eventfd_loop_until(eventfd_raw, stop_thread, wake_raw);
        }) {
        Ok(handle) => (Some(stop), Some(wake), Mutex::new(Some(handle))),
        Err(_) => (None, None, Mutex::new(None)),
    }
}

impl LocalPubSub {
    /// Create a new local pub/sub channel.
    ///
    /// # Arguments
    /// * `name` - Name for the shared memory segment
    /// * `slots` - Number of ring buffer slots
    /// * `slot_size` - Size of each slot in bytes
    /// * `keep_all` - If true, buffer will not overwrite oldest data when full
    pub fn new(name: &str, slots: u32, slot_size: u32, keep_all: bool) -> io::Result<Self> {
        let ring_buf = RingBuffer::create(name, slots, slot_size, keep_all)?;
        let efd =
            EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE | EfdFlags::EFD_NONBLOCK)?;
        let topic_hash = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        let (eventfd_server_stop, eventfd_server_wake, eventfd_server_thread) =
            if let Ok(server) = crate::scm::EventFdServer::bind(topic_hash) {
                spawn_eventfd_server(server, efd.as_raw_fd(), topic_hash)
            } else {
                (None, None, Mutex::new(None))
            };
        Ok(Self {
            ring_buf,
            eventfd: efd,
            cross_process_eventfd: -1,
            eventfd_server_stop,
            eventfd_server_wake,
            eventfd_server_thread,
            timestamps: Mutex::new(HashMap::new()),
            publisher_gids: Mutex::new(HashMap::new()),
            loaned_sequences: Mutex::new(HashMap::new()),
        })
    }

    /// Create or open a shared-memory pub/sub channel.
    ///
    /// Each process that calls this gets its own local eventfd for process-local
    /// notification. Cross-process wakeup relies on polling the shared write_index
    /// (via the rmw_wait timeout fallback). This is by design — eventfds are not
    /// shareable across processes.
    pub fn create_or_open(
        name: &str,
        slots: u32,
        slot_size: u32,
        keep_all: bool,
    ) -> io::Result<Self> {
        let ring_buf = RingBuffer::create_or_open(name, slots, slot_size, keep_all)?;
        let efd =
            EventFd::from_value_and_flags(0, EfdFlags::EFD_SEMAPHORE | EfdFlags::EFD_NONBLOCK)?;
        let topic_hash = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        };
        let efd_server = crate::scm::EventFdServer::bind(topic_hash).ok();
        let cross_proc_efd = if efd_server.is_some() {
            -1
        } else {
            crate::scm::receive_eventfd(topic_hash).ok().unwrap_or(-1)
        };
        let (eventfd_server_stop, eventfd_server_wake, eventfd_server_thread) =
            if let Some(server) = efd_server {
                spawn_eventfd_server(server, efd.as_raw_fd(), topic_hash)
            } else {
                (None, None, Mutex::new(None))
            };
        Ok(Self {
            ring_buf,
            eventfd: efd,
            cross_process_eventfd: cross_proc_efd,
            eventfd_server_stop,
            eventfd_server_wake,
            eventfd_server_thread,
            timestamps: Mutex::new(HashMap::new()),
            publisher_gids: Mutex::new(HashMap::new()),
            loaned_sequences: Mutex::new(HashMap::new()),
        })
    }

    /// Publish data to the ring buffer, tagged with a publisher GID, and signal readers via eventfd.
    pub fn publish_with_gid(&self, data: &[u8], publisher_gid: u64) -> Result<u64, &'static str> {
        let seq = self.ring_buf.write(data)?;
        self.timestamps.lock().unwrap().insert(seq, Instant::now());
        if publisher_gid != 0 {
            self.publisher_gids
                .lock()
                .unwrap()
                .insert(seq, publisher_gid);
        }
        let _ = self.eventfd.write(1u64);
        if self.cross_process_eventfd >= 0 && self.cross_process_eventfd != self.eventfd.as_raw_fd()
        {
            let _ = unsafe {
                libc::write(
                    self.cross_process_eventfd,
                    &1u64 as *const u64 as *const libc::c_void,
                    std::mem::size_of::<u64>(),
                )
            };
        }
        Ok(seq)
    }

    /// Publish data to the ring buffer and signal readers via eventfd (legacy, no GID).
    pub fn publish(&self, data: &[u8]) -> Result<u64, &'static str> {
        self.publish_with_gid(data, 0)
    }

    /// Read data from a specific sequence number.
    pub fn receive(&self, sequence_number: u64, out: &mut [u8]) -> Result<usize, &'static str> {
        self.ring_buf.read(sequence_number, out)
    }

    /// Read a message without advancing the shared ring watermark.
    pub fn receive_peek(
        &self,
        sequence_number: u64,
        out: &mut [u8],
    ) -> Result<usize, &'static str> {
        self.ring_buf.read_without_consuming(sequence_number, out)
    }

    /// Peek at the data size of a specific sequence number without consuming it.
    pub fn message_size(&self, sequence_number: u64) -> Result<usize, &'static str> {
        self.ring_buf.slot_data_size(sequence_number)
    }

    /// Return the raw file descriptor of the eventfd.
    ///
    /// Returns the SCM_RIGHTS shared eventfd when available so that a
    /// remote publisher's signal is visible to this subscriber.  Falls
    /// back to the local eventfd when no cross-process fd exists (i.e.
    /// the only writer is in the same process).
    pub fn event_fd(&self) -> std::os::fd::RawFd {
        if self.cross_process_eventfd >= 0 {
            self.cross_process_eventfd
        } else {
            self.eventfd.as_raw_fd()
        }
    }

    /// Return the current write sequence number.
    pub fn current_seq(&self) -> u64 {
        self.ring_buf.current_seq()
    }

    /// Maximum payload size accepted by this channel.
    pub fn payload_capacity(&self) -> usize {
        payload_capacity_from_stride(self.ring_buf.slot_size)
    }

    /// Return the oldest sequence number that has not been overwritten.
    pub fn oldest_available_seq(&self) -> u64 {
        self.ring_buf.oldest_available_seq()
    }

    /// Mark the start of a new publisher generation (see
    /// [`RingBuffer::mark_generation`]).
    pub fn mark_generation(&self) {
        self.ring_buf.mark_generation();
    }

    /// Oldest sequence number valid for the current publisher generation.
    pub fn generation_start(&self) -> u64 {
        self.ring_buf.generation_start()
    }

    /// Check whether data is available at or after a consumer sequence.
    pub fn data_available_from(&self, sequence_number: u64) -> bool {
        self.ring_buf.data_available_from(sequence_number)
    }

    /// Check whether unread data is available.
    pub fn data_available(&self) -> bool {
        self.ring_buf.data_available()
    }

    pub fn skip_all_pending(&self) {
        use std::sync::atomic::Ordering;
        let write_idx = unsafe { (*self.ring_buf.header).write_index.load(Ordering::Acquire) };
        unsafe {
            (*self.ring_buf.header)
                .read_index
                .store(write_idx, Ordering::Release);
        }
    }

    /// Borrow a buffer from the ring buffer for direct writing.
    ///
    /// # Arguments
    /// * `max_size` - Maximum size of the buffer to borrow
    ///
    /// # Returns
    /// `(pointer, max_size)` on success, or `None` if buffer is full.
    pub fn borrow_buffer(&self, max_size: usize) -> Option<(*mut u8, usize)> {
        let payload_capacity = payload_capacity_from_stride(self.ring_buf.slot_size);
        if max_size > payload_capacity {
            return None;
        }
        let write_idx = unsafe {
            (*self.ring_buf.header)
                .write_index
                .fetch_add(1, Ordering::AcqRel)
        };
        let read_idx = unsafe { (*self.ring_buf.header).read_index.load(Ordering::Acquire) };
        if write_idx - read_idx >= (self.ring_buf.slot_count as u64) {
            // Buffer full — cannot borrow. Roll back fetch_add.
            unsafe {
                (*self.ring_buf.header)
                    .write_index
                    .fetch_sub(1, Ordering::Release);
            }
            return None;
        }
        let slot = (write_idx % (self.ring_buf.slot_count as u64)) as usize;
        let slot_off = slot * (self.ring_buf.slot_size as usize);
        let ptr = unsafe {
            let slot_start = self.ring_buf.data_ptr.add(slot_off);
            let seq_atomic =
                &*(slot_start.add(SLOT_SEQ_OFFSET) as *const std::sync::atomic::AtomicU64);
            let len_atomic =
                &*(slot_start.add(SLOT_LEN_OFFSET) as *const std::sync::atomic::AtomicU32);
            seq_atomic.store(u64::MAX, Ordering::Release);
            len_atomic.store(0, Ordering::Release);
            slot_start.add(SLOT_DATA_OFFSET)
        };
        self.loaned_sequences
            .lock()
            .unwrap()
            .insert(ptr as usize, write_idx);
        Some((ptr, max_size))
    }

    /// Commit a borrowed buffer to the ring buffer.
    ///
    /// # Arguments
    /// * `ptr` - Pointer to the borrowed buffer
    /// * `size` - Actual data size written
    /// * `_sequence` - Sequence number (unused, kept for ABI compatibility)
    ///
    /// # Returns
    /// `true` if commit succeeded.
    pub fn commit_buffer(&self, ptr: *const u8, size: usize, _sequence: i64) -> bool {
        let base = self.ring_buf.data_ptr;
        let offset = (unsafe { ptr.offset_from(base) }) as usize;
        let slot_size = self.ring_buf.slot_size as usize;
        if offset % slot_size != SLOT_DATA_OFFSET
            || size > payload_capacity_from_stride(self.ring_buf.slot_size)
        {
            return false;
        }
        let Some(sequence) = self
            .loaned_sequences
            .lock()
            .unwrap()
            .remove(&(ptr as usize))
        else {
            return false;
        };
        // write_index was already incremented by borrow_buffer()'s fetch_add.
        // Publish the sequence last so readers never accept a partially written slot.
        unsafe {
            let slot_start = base.add(offset - SLOT_DATA_OFFSET);
            let seq_atomic =
                &*(slot_start.add(SLOT_SEQ_OFFSET) as *const std::sync::atomic::AtomicU64);
            let len_atomic =
                &*(slot_start.add(SLOT_LEN_OFFSET) as *const std::sync::atomic::AtomicU32);
            len_atomic.store(size as u32, Ordering::Release);
            seq_atomic.store(sequence, Ordering::Release);
        }
        let _ = self.eventfd.write(1u64);
        true
    }

    /// Take a loaned message from the ring buffer.
    ///
    /// # Arguments
    /// * `sequence_number` - Sequence number of the message to take
    ///
    /// # Returns
    /// `(pointer, size)` on success, or `None` if no message available.
    pub fn take_loaned(&self, sequence_number: u64) -> Option<(*const u8, usize)> {
        let write_idx = unsafe { (*self.ring_buf.header).write_index.load(Ordering::Acquire) };
        if sequence_number >= write_idx {
            return None;
        }
        let read_idx = unsafe { (*self.ring_buf.header).read_index.load(Ordering::Relaxed) };
        if sequence_number < read_idx {
            return None;
        }
        let slot = (sequence_number % (self.ring_buf.slot_count as u64)) as usize;
        let slot_off = slot * (self.ring_buf.slot_size as usize);
        let len = unsafe {
            let src = self.ring_buf.data_ptr.add(slot_off);
            let seq_atomic = &*(src.add(SLOT_SEQ_OFFSET) as *const std::sync::atomic::AtomicU64);
            if seq_atomic.load(Ordering::Acquire) != sequence_number {
                return None;
            }
            let len_atomic = &*(src.add(SLOT_LEN_OFFSET) as *const std::sync::atomic::AtomicU32);
            len_atomic.load(Ordering::Acquire) as usize
        };
        if len == 0 {
            return None;
        }
        let data_ptr = unsafe { self.ring_buf.data_ptr.add(slot_off + SLOT_DATA_OFFSET) };
        // Advance read index
        unsafe {
            (*self.ring_buf.header)
                .read_index
                .store(sequence_number + 1, Ordering::Release);
        }
        Some((data_ptr, len))
    }

    /// Signal the eventfd without writing data.
    ///
    /// Used by the remote transport receiver to notify subscribers
    /// that new data is already available in shared memory (written
    /// by the publisher's local write), avoiding duplicate data in
    /// the ring buffer.
    pub fn signal(&self) {
        let _ = self.eventfd.write(1u64);
        if self.cross_process_eventfd >= 0 && self.cross_process_eventfd != self.eventfd.as_raw_fd()
        {
            let _ = unsafe {
                libc::write(
                    self.cross_process_eventfd,
                    &1u64 as *const u64 as *const libc::c_void,
                    std::mem::size_of::<u64>(),
                )
            };
        }
    }

    /// Return a loaned message (no-op for SHM).
    ///
    /// # Arguments
    /// * `_ptr` - Pointer to the loaned buffer
    /// * `_size` - Size of the buffer
    pub fn return_loaned(&self, _ptr: *const u8, _size: usize) {}
}

impl Drop for LocalPubSub {
    fn drop(&mut self) {
        if let Some(stop) = &self.eventfd_server_stop {
            stop.store(true, Ordering::Release);
        }
        if let Some(wake) = &self.eventfd_server_wake {
            let _ = wake.write(1);
        }
        if let Ok(mut handle) = self.eventfd_server_thread.lock() {
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
        if self.cross_process_eventfd >= 0 {
            let _ = unsafe { libc::close(self.cross_process_eventfd) };
            self.cross_process_eventfd = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_ring_buffer_write_read() {
        let buf = RingBuffer::create("test_axon_rb", 4, 64, false).unwrap();
        let data: &[u8] = b"hello axon";

        let slot = buf.write(data).unwrap();
        assert_eq!(slot, 0);

        let mut out = vec![0u8; 64];
        let n = buf.read(0, &mut out).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&out[..n], data);
    }

    #[test]
    fn test_ring_buffer_wraparound() {
        let buf = RingBuffer::create("test_axon_wrap", 4, 64, false).unwrap();
        let mut out = vec![0u8; 64];

        // Fill buffer with 4 messages
        for i in 0..4 {
            let msg = format!("hello_{}", i);
            buf.write(msg.as_bytes()).unwrap();
        }
        // Consume first 4
        for i in 0..4 {
            let n = buf.read(i, &mut out).unwrap();
            assert_eq!(&out[..n], format!("hello_{}", i).as_bytes());
        }
        // Write 4 more (wrap around — reuses slots 0-3)
        for i in 4..8 {
            let msg = format!("hello_{}", i);
            buf.write(msg.as_bytes()).unwrap();
        }
        // Consume next 4 (wrapped)
        for i in 4..8 {
            let n = buf.read(i, &mut out).unwrap();
            assert_eq!(&out[..n], format!("hello_{}", i).as_bytes());
        }
    }

    #[test]
    fn test_ring_buffer_rejects_stale_wrapped_slot_before_publish() {
        let buf = RingBuffer::create("test_axon_stale_wrap", 1, 64, false).unwrap();
        assert_eq!(buf.write(b"old_clock").unwrap(), 0);

        unsafe {
            (*buf.header).write_index.fetch_add(1, Ordering::AcqRel);
        }

        let mut out = vec![0u8; 64];
        assert_eq!(buf.read(1, &mut out), Err("slot not yet written"));
        assert_eq!(buf.slot_data_size(1), Err("slot not yet written"));
    }

    #[test]
    fn test_write_does_not_regress_read_index_when_reader_is_ahead() {
        // A reader that consumed a slot reserved by a faster concurrent
        // writer can leave read_index ahead of a slower writer's reserved
        // write_idx. The overwrite fallback must not drag read_index
        // backwards in that case.
        let buf = RingBuffer::create("test_axon_read_ahead", 2, 64, false).unwrap();
        unsafe {
            (*buf.header).write_index.store(1, Ordering::Release);
            (*buf.header).read_index.store(2, Ordering::Release);
        }
        buf.write(b"slow writer").unwrap();
        let read_idx = unsafe { (*buf.header).read_index.load(Ordering::Acquire) };
        assert_eq!(read_idx, 2, "read_index must not move backwards");
    }

    #[test]
    fn test_keep_all_ring_overwrites_oldest_when_bounded() {
        let buf = RingBuffer::create("test_axon_keep_all_bounded", 2, 64, true).unwrap();
        assert_eq!(buf.write(b"first").unwrap(), 0);
        assert_eq!(buf.write(b"second").unwrap(), 1);
        assert_eq!(buf.write(b"third").unwrap(), 2);

        let mut out = vec![0u8; 64];
        assert!(buf.read(0, &mut out).is_err());
        let n = buf.read(1, &mut out).unwrap();
        assert_eq!(&out[..n], b"second");
        let n = buf.read(2, &mut out).unwrap();
        assert_eq!(&out[..n], b"third");
    }

    #[test]
    fn test_ring_buffer_empty_read() {
        let buf = RingBuffer::create("test_axon_empty", 4, 64, false).unwrap();
        let mut out = vec![0u8; 64];
        let result = buf.read(0, &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn test_ring_buffer_concurrent() {
        // Use 128 slots to prevent producer from overwriting unconsumed messages
        let buf = Arc::new(RingBuffer::create("test_axon_conc", 128, 256, false).unwrap());
        let buf_w = Arc::clone(&buf);
        let buf_r = Arc::clone(&buf);

        let producer = thread::spawn(move || {
            for i in 0..100 {
                let msg = format!("msg_{}", i);
                loop {
                    if buf_w.write(msg.as_bytes()).is_ok() {
                        break;
                    }
                    thread::yield_now();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut out = vec![0u8; 256];
            let mut next_seq = 0;
            for _ in 0..100 {
                loop {
                    if let Ok(n) = buf_r.read(next_seq, &mut out) {
                        let expected = format!("msg_{}", next_seq);
                        assert_eq!(&out[..n], expected.as_bytes());
                        next_seq += 1;
                        break;
                    }
                    thread::yield_now();
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();
        // All messages received correctly despite wrap-around
    }

    #[test]
    fn test_localpubsub_single_message() {
        let pubsub = LocalPubSub::new("test_lps_1", 8, 256, false).unwrap();

        let data = b"hello world";
        pubsub.publish(data).unwrap();

        let mut out = vec![0u8; 256];
        let n = pubsub.receive(0, &mut out).unwrap();
        assert_eq!(&out[..n], data);
    }

    #[test]
    fn test_localpubsub_multiple_messages() {
        let pubsub = LocalPubSub::new("test_lps_2", 8, 256, false).unwrap();

        for i in 0..5 {
            let msg = format!("msg_{}", i);
            pubsub.publish(msg.as_bytes()).unwrap();
        }

        for i in 0..5 {
            let expected = format!("msg_{}", i);
            let mut out = vec![0u8; 256];
            let n = pubsub.receive(i, &mut out).unwrap();
            assert_eq!(&out[..n], expected.as_bytes());
        }
    }

    #[test]
    fn test_localpubsub_eventfd_valid() {
        let pubsub = LocalPubSub::new("test_lps_3", 8, 256, false).unwrap();
        // Eventfd should be a valid fd
        assert!(pubsub.event_fd() >= 0);
        pubsub.publish(b"test").unwrap();
    }

    #[test]
    fn test_loaned_message_roundtrip() {
        let pubsub = LocalPubSub::new("test_loaned", 8, 256, false).unwrap();
        let (ptr, _size) = pubsub.borrow_buffer(64).unwrap();
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello loaned".as_ptr(), ptr, 12);
        }
        pubsub.commit_buffer(ptr, 12, 0);
        let (rptr, rsize) = pubsub.take_loaned(0).unwrap();
        assert_eq!(rsize, 12);
        let data = unsafe { std::slice::from_raw_parts(rptr, rsize) };
        assert_eq!(data, b"hello loaned");
        pubsub.return_loaned(rptr, rsize);
    }

    fn cleanup_shm(name: &str) {
        let full = format!("/axon_{}", name);
        if let Ok(cname) = cstring(&full) {
            let _ = shm_unlink(cname.as_c_str());
        }
    }

    #[test]
    fn test_create_or_open_roundtrip() {
        let name = "test_create_or_open_axon";
        cleanup_shm(name);
        // Ensure no stale segment from a prior test that might have used the
        // same name via the O_EXCL race path
        if let Err(e) = RingBuffer::create_or_open(name, 4, 64, false) {
            panic!("first create_or_open failed: {}", e);
        }
        let created = RingBuffer::create_or_open(name, 4, 64, false).unwrap();
        assert_eq!(created.current_seq(), 0);

        let opened = RingBuffer::create_or_open(name, 4, 64, false).unwrap();
        assert_eq!(opened.current_seq(), 0);

        created.write(b"cross-process data").unwrap();
        let mut out = vec![0u8; 64];
        let n = opened.read(0, &mut out).unwrap();
        assert_eq!(&out[..n], b"cross-process data");
    }

    #[test]
    fn test_generation_hides_stale_transient_local_data() {
        let name = "test_generation_stale_axon";
        cleanup_shm(name);

        // Generation 1: a publisher writes retained frames, then "dies". We
        // keep the segment mapped-but-unlinked to mimic an orphaned SHM ring
        // left behind by a killed process (Ctrl-C on a relaunched sim).
        let gen1 = RingBuffer::create_or_open(name, 4, 64, false).unwrap();
        gen1.write(b"old-frame-0").unwrap();
        gen1.write(b"old-frame-1").unwrap();
        let stale_write_idx = gen1.current_seq();
        assert_eq!(stale_write_idx, 2);
        drop(gen1); // segment persists (not unlinked)

        // Generation 2: a new publisher re-opens the SAME orphaned segment.
        let gen2 = RingBuffer::create_or_open(name, 4, 64, false).unwrap();
        assert_eq!(
            gen2.current_seq(),
            stale_write_idx,
            "reused segment keeps the previous run's write index"
        );
        // The stale frames are still physically readable — this is the bug
        // that a late TRANSIENT_LOCAL subscriber would surface.
        let mut out = vec![0u8; 64];
        assert!(
            gen2.read(0, &mut out).is_ok(),
            "previous-run frame still present in the reused ring"
        );

        gen2.mark_generation();
        assert_eq!(gen2.generation_start(), stale_write_idx);

        // A TRANSIENT_LOCAL subscriber floors its start at the generation, so
        // it skips every frame from the previous run.
        let sub_start = gen2.oldest_available_seq().max(gen2.generation_start());
        assert_eq!(
            sub_start, stale_write_idx,
            "subscriber skips all stale frames"
        );
        assert!(
            gen2.read(sub_start, &mut out).is_err(),
            "nothing to deliver until the new generation publishes"
        );

        // Once the new publisher writes, the subscriber sees only fresh data.
        gen2.write(b"new-frame").unwrap();
        let n = gen2.read(sub_start, &mut out).unwrap();
        assert_eq!(&out[..n], b"new-frame");

        cleanup_shm(name);
    }

    #[test]
    fn test_create_or_open_keeps_existing_smaller_depth() {
        let name = "test_create_or_open_smaller_depth_axon";
        cleanup_shm(name);

        let publisher_ring = RingBuffer::create_or_open(name, 7, 64, false).unwrap();
        publisher_ring.write(b"publisher data").unwrap();

        let subscriber_ring = RingBuffer::create_or_open(name, 10, 64, false).unwrap();
        assert_eq!(subscriber_ring.current_seq(), 1);

        let mut out = vec![0u8; 64];
        let n = subscriber_ring.read(0, &mut out).unwrap();
        assert_eq!(&out[..n], b"publisher data");

        cleanup_shm(name);
    }

    #[test]
    fn test_create_or_open_concurrent_creators() {
        let name = "test_create_or_open_concurrent_axon";
        cleanup_shm(name);

        let workers = 16;
        let barrier = Arc::new(std::sync::Barrier::new(workers));
        let mut handles = Vec::new();
        for _ in 0..workers {
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                RingBuffer::create_or_open(name, 8, 64, false)
                    .map(|ring| ring.current_seq())
                    .map_err(|e| e.to_string())
            }));
        }

        for handle in handles {
            assert_eq!(handle.join().unwrap().unwrap(), 0);
        }

        cleanup_shm(name);
    }

    #[test]
    fn test_ring_buffer_multi_producer() {
        let name = "test_multi_prod_axon";
        cleanup_shm(name);
        let buf = Arc::new(RingBuffer::create(name, 512, 256, false).unwrap());

        let buf1 = Arc::clone(&buf);
        let buf2 = Arc::clone(&buf);

        let h1 = std::thread::spawn(move || {
            for i in 0..200 {
                let msg = format!("p1_msg_{}", i);
                loop {
                    if buf1.write(msg.as_bytes()).is_ok() {
                        break;
                    }
                    std::thread::yield_now();
                }
            }
        });

        let h2 = std::thread::spawn(move || {
            for i in 0..200 {
                let msg = format!("p2_msg_{}", i);
                loop {
                    if buf2.write(msg.as_bytes()).is_ok() {
                        break;
                    }
                    std::thread::yield_now();
                }
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Read all messages back — check for corruption
        let mut out = vec![0u8; 256];
        let mut count = 0u64;
        while let Ok(n) = buf.read(count, &mut out) {
            let msg = String::from_utf8_lossy(&out[..n]);
            assert!(msg.starts_with("p1_msg_") || msg.starts_with("p2_msg_"));
            count += 1;
        }
        assert_eq!(count, 400);
    }

    #[test]
    fn test_create_or_open_shared_memory() {
        let name = "test_shm_shared_axon";
        cleanup_shm(name);
        let a = RingBuffer::create_or_open(name, 8, 256, false).unwrap();
        a.write(b"msg_from_a").unwrap();

        let b = RingBuffer::create_or_open(name, 8, 256, false).unwrap();
        let mut out = vec![0u8; 256];
        let n = b.read(0, &mut out).unwrap();
        assert_eq!(&out[..n], b"msg_from_a");
    }
}
