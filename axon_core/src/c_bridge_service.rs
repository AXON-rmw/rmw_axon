use crate::c_bridge::{duration_from_rmw_parts, liveliness_from_ffi, with_session};
use crate::session::service::ServiceResponseTake;
use std::ffi::CStr;
use std::os::raw::c_char;

use crate::types::{fxhash, Durability, HistoryKind, QosProfile, Reliability};

/// Return a bounded max_message_size for services.
///
/// Services create two internal topics per endpoint and most ROS 2 nodes create
/// several parameter services. A blanket multi-MB slot size burns SHM quickly.
/// Large custom services can still opt in through AXON_MAX_MESSAGE_SIZE.
fn service_max_message_size(service_type: &str) -> usize {
    if let Some(value) = std::env::var("AXON_MAX_MESSAGE_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        return value;
    }
    match service_type {
        "example_interfaces/srv/AddTwoInts" => 4 * 1024,
        "std_srvs/srv/Empty" | "std_srvs/srv/SetBool" | "std_srvs/srv/Trigger" => 4 * 1024,
        service if service.starts_with("rcl_interfaces/srv/") => 256 * 1024,
        service if service.starts_with("example_interfaces/srv/") => 64 * 1024,
        _ => 1024 * 1024,
    }
}

#[allow(clippy::too_many_arguments)] // Mirrors the fixed rmw_qos_profile_t fields.
fn qos_from_ffi(
    service_type: &str,
    reliability: i32,
    durability: i32,
    history_kind: i32,
    depth: i32,
    deadline_s: u64,
    deadline_ns: u32,
    lifespan_s: u64,
    lifespan_ns: u32,
    liveliness: i32,
    liveliness_lease_s: u64,
    liveliness_lease_ns: u32,
) -> QosProfile {
    let deadline = duration_from_rmw_parts(deadline_s, deadline_ns);
    let lifespan = duration_from_rmw_parts(lifespan_s, lifespan_ns);
    let liveliness = liveliness_from_ffi(liveliness);
    let liveliness_lease_duration =
        duration_from_rmw_parts(liveliness_lease_s, liveliness_lease_ns);
    QosProfile {
        reliability: if reliability == 0 {
            Reliability::BestEffort
        } else {
            Reliability::Reliable
        },
        durability: if durability == 0 {
            Durability::Volatile
        } else {
            Durability::TransientLocal
        },
        history: if history_kind == 0 {
            HistoryKind::KeepAll
        } else {
            HistoryKind::KeepLast {
                depth: if depth <= 0 { 10 } else { depth as usize },
            }
        },
        bandwidth_limit: None,
        max_message_size: service_max_message_size(service_type),
        deadline,
        lifespan,
        liveliness,
        liveliness_lease_duration,
    }
}

/// Create a service server endpoint with full QoS.
///
/// # Safety
/// `service_name` and `service_type` must be valid null-terminated C strings.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `service_type` - Null-terminated service type string
/// * `reliability` - 0 for best-effort, non-zero for reliable
/// * `durability` - 0 for volatile, non-zero for transient_local
/// * `history_kind` - 0 for KeepAll, non-zero for KeepLast
/// * `depth` - History depth for KeepLast
/// * `deadline_s` / `deadline_ns` - Deadline duration
/// * `lifespan_s` / `lifespan_ns` - Lifespan duration
/// * `liveliness` - 0=Automatic, 1=ManualByTopic, 2=ManualByParticipant
/// * `liveliness_lease_s` / `liveliness_lease_ns` - Liveliness lease duration
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_create_service_with_qos(
    session_id: u64,
    service_name: *const c_char,
    service_type: *const c_char,
    reliability: i32,
    durability: i32,
    history_kind: i32,
    depth: i32,
    deadline_s: u64,
    deadline_ns: u32,
    lifespan_s: u64,
    lifespan_ns: u32,
    liveliness: i32,
    liveliness_lease_s: u64,
    liveliness_lease_ns: u32,
) -> i32 {
    if service_name.is_null() || service_type.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let Ok(typ) = (unsafe { CStr::from_ptr(service_type) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let qos = qos_from_ffi(
        typ,
        reliability,
        durability,
        history_kind,
        depth,
        deadline_s,
        deadline_ns,
        lifespan_s,
        lifespan_ns,
        liveliness,
        liveliness_lease_s,
        liveliness_lease_ns,
    );
    match with_session(session_id, |s| s.create_named_service(sid, name, typ, &qos)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_create_service('{}', '{}'): {}",
                name, typ, e
            );
            -1
        }
    }
}
///
/// # Safety
/// `service_name` and `service_type` must be valid null-terminated C strings.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `service_type` - Null-terminated service type string
/// * `reliability` - 0 for best-effort, non-zero for reliable
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_create_service(
    session_id: u64,
    service_name: *const c_char,
    service_type: *const c_char,
    reliability: i32,
) -> i32 {
    if service_name.is_null() || service_type.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let Ok(typ) = (unsafe { CStr::from_ptr(service_type) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let qos = if reliability == 0 {
        let mut qos = QosProfile::default_sensor();
        qos.max_message_size = service_max_message_size(typ);
        qos
    } else {
        let mut qos = QosProfile::default_command();
        qos.max_message_size = service_max_message_size(typ);
        qos
    };
    match with_session(session_id, |s| s.create_named_service(sid, name, typ, &qos)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_create_service('{}', '{}'): {}",
                name, typ, e
            );
            -1
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_session_destroy_service(
    session_id: u64,
    service_name: *const c_char,
) -> i32 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    with_session(session_id, |s| s.destroy_service(fxhash(name))).map_or(-1, |_| 0)
}
/// Take a service request from the server side.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `out` must point to a buffer of at least `*out_len` bytes.
/// `out_len` must be a valid pointer; updated with actual byte count.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `seq` - Message sequence number
/// * `out` - Output buffer
/// * `out_len` - Pointer to buffer size (in/out)
///
/// # Returns
/// 0 on success, -1 on failure, -2 if buffer too small (required size in *out_len),
/// -3 if the selected slot is still being written.
#[no_mangle]
pub extern "C" fn axon_session_take_request(
    session_id: u64,
    service_name: *const c_char,
    seq: u64,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if service_name.is_null() || out.is_null() || out_len.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let max_len = (unsafe { *out_len }) as usize;

    // First check the actual message size
    let msg_size = match with_session(session_id, |s| s.request_message_size(sid, seq)) {
        Ok(s) => s,
        Err(e) if e == "slot not yet written" => return -3,
        Err(_) => return -1,
    };
    if max_len == 0 || msg_size > max_len {
        unsafe {
            *out_len = msg_size as u32;
        }
        return -2;
    }

    let mut buf = vec![0u8; max_len];
    match with_session(session_id, |s| s.take_request(sid, seq, &mut buf)) {
        Ok(n) => {
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n);
                *out_len = n as u32;
            }
            0
        }
        Err(e) if e == "slot not yet written" => -3,
        Err(_) => -1,
    }
}

/// Take a service request and return its client/request correlation metadata.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `out` must point to a buffer of at least `*out_len` bytes.
/// `client_gid_out` must point to at least 16 writable bytes.
/// `request_sequence_out` and `out_len` must be valid pointers.
#[no_mangle]
pub extern "C" fn axon_session_take_request_with_info(
    session_id: u64,
    service_name: *const c_char,
    seq: u64,
    out: *mut u8,
    out_len: *mut u32,
    client_gid_out: *mut u8,
    request_sequence_out: *mut i64,
) -> i32 {
    if service_name.is_null()
        || out.is_null()
        || out_len.is_null()
        || client_gid_out.is_null()
        || request_sequence_out.is_null()
    {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let max_len = (unsafe { *out_len }) as usize;

    let msg_size = match with_session(session_id, |s| s.request_message_size(sid, seq)) {
        Ok(s) => s,
        Err(e) if e == "slot not yet written" => return -3,
        Err(_) => return -1,
    };
    if max_len == 0 || msg_size > max_len {
        unsafe {
            *out_len = msg_size as u32;
        }
        return -2;
    }

    let mut buf = vec![0u8; max_len];
    match with_session(session_id, |s| s.take_request_with_info(sid, seq, &mut buf)) {
        Ok((n, client_gid, request_sequence)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n);
                std::ptr::copy_nonoverlapping(client_gid.as_ptr(), client_gid_out, 16);
                *request_sequence_out = request_sequence;
                *out_len = n as u32;
            }
            0
        }
        Err(e) if e == "slot not yet written" => -3,
        Err(_) => -1,
    }
}
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
///
/// # Returns
/// Current write index (initial read sequence) on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_service_initial_seq(
    session_id: u64,
    service_name: *const c_char,
) -> i64 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    with_session(session_id, |s| Ok(s.service_initial_seq(sid) as i64)).unwrap_or(-1)
}
/// Send a service response from the server side.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `data` must point to at least `len` valid bytes.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `data` - Pointer to response bytes
/// * `len` - Response length in bytes
///
/// # Returns
/// Sequence number on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_send_response(
    session_id: u64,
    service_name: *const c_char,
    data: *const u8,
    len: u32,
) -> i64 {
    if service_name.is_null() || data.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let data_slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    match with_session(session_id, |s| s.send_response(sid, data_slice)) {
        Ok(seq) => seq as i64,
        Err(e) => {
            eprintln!("[rmw_axon] axon_session_send_response('{}'): {}", name, e);
            -1
        }
    }
}

/// Send a service response with ROS request correlation metadata.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `client_gid` must point to 16 readable bytes.
/// `data` must point to at least `len` readable bytes.
#[no_mangle]
pub extern "C" fn axon_session_send_response_with_info(
    session_id: u64,
    service_name: *const c_char,
    client_gid: *const u8,
    request_sequence: i64,
    data: *const u8,
    len: u32,
) -> i64 {
    if service_name.is_null() || client_gid.is_null() || data.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let mut gid = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(client_gid, gid.as_mut_ptr(), 16);
    }
    let data_slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    match with_session(session_id, |s| {
        s.send_response_with_info(sid, gid, request_sequence, data_slice)
    }) {
        Ok(seq) => seq as i64,
        Err(e) => {
            eprintln!("[rmw_axon] axon_session_send_response('{}'): {}", name, e);
            -1
        }
    }
}
/// Create a service client endpoint with full QoS.
///
/// # Safety
/// `service_name` and `service_type` must be valid null-terminated C strings.
#[no_mangle]
pub extern "C" fn axon_session_create_client_with_qos(
    session_id: u64,
    service_name: *const c_char,
    service_type: *const c_char,
    reliability: i32,
    durability: i32,
    history_kind: i32,
    depth: i32,
    deadline_s: u64,
    deadline_ns: u32,
    lifespan_s: u64,
    lifespan_ns: u32,
    liveliness: i32,
    liveliness_lease_s: u64,
    liveliness_lease_ns: u32,
) -> i32 {
    if service_name.is_null() || service_type.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let Ok(typ) = (unsafe { CStr::from_ptr(service_type) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let qos = qos_from_ffi(
        typ,
        reliability,
        durability,
        history_kind,
        depth,
        deadline_s,
        deadline_ns,
        lifespan_s,
        lifespan_ns,
        liveliness,
        liveliness_lease_s,
        liveliness_lease_ns,
    );
    match with_session(session_id, |s| s.create_named_client(sid, name, typ, &qos)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_create_client('{}', '{}'): {}",
                name, typ, e
            );
            -1
        }
    }
}
/// Create a service client endpoint.
///
/// # Safety
/// `service_name` and `service_type` must be valid null-terminated C strings.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `service_type` - Null-terminated service type string
/// * `reliability` - 0 for best-effort, non-zero for reliable
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_create_client(
    session_id: u64,
    service_name: *const c_char,
    service_type: *const c_char,
    reliability: i32,
) -> i32 {
    if service_name.is_null() || service_type.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let Ok(typ) = (unsafe { CStr::from_ptr(service_type) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let qos = if reliability == 0 {
        let mut qos = QosProfile::default_sensor();
        qos.max_message_size = service_max_message_size(typ);
        qos
    } else {
        let mut qos = QosProfile::default_command();
        qos.max_message_size = service_max_message_size(typ);
        qos
    };
    match with_session(session_id, |s| s.create_named_client(sid, name, typ, &qos)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_create_client('{}', '{}'): {}",
                name, typ, e
            );
            -1
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_session_destroy_client(session_id: u64, service_name: *const c_char) -> i32 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    with_session(session_id, |s| s.destroy_client(fxhash(name))).map_or(-1, |_| 0)
}
/// Send a service request from the client side.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `data` must point to at least `len` valid bytes.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `data` - Pointer to request bytes
/// * `len` - Request length in bytes
///
/// # Returns
/// Sequence number on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_send_request(
    session_id: u64,
    service_name: *const c_char,
    data: *const u8,
    len: u32,
) -> i64 {
    if service_name.is_null() || data.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let data_slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    match with_session(session_id, |s| s.send_request(sid, data_slice)) {
        Ok(seq) => seq as i64,
        Err(e) => {
            eprintln!("[rmw_axon] axon_session_send_request('{}'): {}", name, e);
            -1
        }
    }
}

/// Send a service request with an endpoint-specific client GID.
#[no_mangle]
pub extern "C" fn axon_session_send_request_with_gid(
    session_id: u64,
    service_name: *const c_char,
    client_gid: *const u8,
    data: *const u8,
    len: u32,
) -> i64 {
    if service_name.is_null() || client_gid.is_null() || data.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let mut gid = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(client_gid, gid.as_mut_ptr(), gid.len());
    }
    let data_slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    match with_session(session_id, |s| {
        s.send_request_with_gid(sid, gid, data_slice)
    }) {
        Ok(seq) => seq as i64,
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_send_request_with_gid('{}'): {}",
                name, e
            );
            -1
        }
    }
}
/// Take a service response from the client side.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `out` must point to a buffer of at least `*out_len` bytes.
/// `out_len` must be a valid pointer; updated with actual byte count.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
/// * `seq` - Message sequence number
/// * `out` - Output buffer
/// * `out_len` - Pointer to buffer size (in/out)
///
/// # Returns
/// 0 on success, -1 on failure, -2 if buffer too small (required size in *out_len).
#[no_mangle]
pub extern "C" fn axon_session_take_response(
    session_id: u64,
    service_name: *const c_char,
    seq: u64,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if service_name.is_null() || out.is_null() || out_len.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let max_len = (unsafe { *out_len }) as usize;

    // First check the actual message size
    let msg_size = match with_session(session_id, |s| s.response_message_size(sid, seq)) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    if max_len == 0 || msg_size > max_len {
        unsafe {
            *out_len = msg_size as u32;
        }
        return -2;
    }

    let mut buf = vec![0u8; max_len];
    match with_session(session_id, |s| s.take_response(sid, seq, &mut buf)) {
        Ok(n) => {
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n);
                *out_len = n as u32;
            }
            0
        }
        Err(_) => -1,
    }
}

/// Take the next service response addressed to a specific client GID.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `next_seq_inout`, `out_len`, `client_gid`, and `request_sequence_out` must be valid pointers.
/// `out` must point to a buffer of at least `*out_len` bytes.
#[no_mangle]
pub extern "C" fn axon_session_take_response_for_client(
    session_id: u64,
    service_name: *const c_char,
    next_seq_inout: *mut u64,
    client_gid: *const u8,
    out: *mut u8,
    out_len: *mut u32,
    request_sequence_out: *mut i64,
) -> i32 {
    if service_name.is_null()
        || next_seq_inout.is_null()
        || client_gid.is_null()
        || out.is_null()
        || out_len.is_null()
        || request_sequence_out.is_null()
    {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let next_seq = unsafe { *next_seq_inout };
    let max_len = unsafe { *out_len } as usize;
    let mut gid = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(client_gid, gid.as_mut_ptr(), 16);
    }
    let mut buf = vec![0u8; max_len];

    match with_session(session_id, |s| {
        s.take_response_for_client(sid, next_seq, gid, &mut buf)
    }) {
        Ok(ServiceResponseTake::Taken {
            size,
            next_seq,
            request_sequence,
        }) => {
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr(), out, size);
                *next_seq_inout = next_seq;
                *request_sequence_out = request_sequence;
                *out_len = size as u32;
            }
            0
        }
        Ok(ServiceResponseTake::BufferTooSmall { required }) => {
            unsafe {
                *out_len = required as u32;
            }
            -2
        }
        Ok(ServiceResponseTake::NoMatch { next_seq }) => {
            unsafe {
                *next_seq_inout = next_seq;
            }
            -1
        }
        Err(_) => -1,
    }
}
/// Get the initial sequence number for a client's response subscription.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
///
/// # Returns
/// Current write index (initial read sequence) on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_client_initial_seq(
    session_id: u64,
    service_name: *const c_char,
) -> i64 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    with_session(session_id, |s| Ok(s.client_initial_seq(sid) as i64)).unwrap_or(-1)
}
/// Check whether service request data is available at or after a sequence number.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
///
/// # Returns
/// 1 if data is available, 0 otherwise, -1 on error.
#[no_mangle]
pub extern "C" fn axon_session_service_request_data_available(
    session_id: u64,
    service_name: *const c_char,
    next_seq: u64,
) -> i32 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let available = with_session(session_id, |s| {
        Ok(s.service_request_data_available(sid, next_seq))
    });
    match available {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}
/// Check whether service response data is available at or after a sequence number.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
///
/// # Returns
/// 1 if data is available, 0 otherwise, -1 on error.
#[no_mangle]
pub extern "C" fn axon_session_service_response_data_available(
    session_id: u64,
    service_name: *const c_char,
    next_seq: u64,
) -> i32 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let available = with_session(session_id, |s| {
        Ok(s.service_response_data_available(sid, next_seq))
    });
    match available {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}
/// Get the eventfd for a service's request subscription.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
///
/// # Returns
/// Eventfd file descriptor on success, -1 if not available.
#[no_mangle]
pub extern "C" fn axon_session_service_request_eventfd(
    session_id: u64,
    service_name: *const c_char,
) -> i64 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    with_session(session_id, |s| {
        s.ensure_request_sub(sid);
        Ok(s.service_request_eventfd(sid))
    })
    .ok()
    .flatten()
    .map(|fd| fd as i64)
    .unwrap_or(-1)
}
/// Get the eventfd for a service's response subscription.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `service_name` - Null-terminated service name
///
/// # Returns
/// Eventfd file descriptor on success, -1 if not available.
#[no_mangle]
pub extern "C" fn axon_session_service_response_eventfd(
    session_id: u64,
    service_name: *const c_char,
) -> i64 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    with_session(session_id, |s| {
        s.ensure_response_sub(sid);
        Ok(s.service_response_eventfd(sid))
    })
    .ok()
    .flatten()
    .map(|fd| fd as i64)
    .unwrap_or(-1)
}
