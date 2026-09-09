use crate::c_bridge::with_session;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;

use crate::events::EventKind;
use crate::types::{fxhash, make_gid, service_request_topic};

#[allow(clippy::too_many_arguments)] // Mirrors the fixed C ABI output layout.
unsafe fn write_qos_to_output(
    qos: &crate::types::QosProfile,
    reliability_out: *mut i32,
    durability_out: *mut i32,
    history_out: *mut i32,
    depth_out: *mut usize,
    liveliness_out: *mut i32,
    ll_s_out: *mut u64,
    ll_ns_out: *mut u32,
    dl_s_out: *mut u64,
    dl_ns_out: *mut u32,
    ls_s_out: *mut u64,
    ls_ns_out: *mut u32,
) {
    use crate::types::{Durability, HistoryKind, Liveliness, Reliability};
    *reliability_out = match qos.reliability {
        Reliability::Reliable => 1,
        _ => 0,
    };
    *durability_out = match qos.durability {
        Durability::TransientLocal => 1,
        _ => 0,
    };
    match qos.history {
        HistoryKind::KeepAll => {
            *history_out = 0;
            *depth_out = 0;
        }
        HistoryKind::KeepLast { depth } => {
            *history_out = 1;
            *depth_out = depth;
        }
    }
    *liveliness_out = match qos.liveliness {
        Liveliness::Automatic => 0,
        Liveliness::ManualByTopic => 1,
        Liveliness::ManualByParticipant => 2,
        Liveliness::Unknown => 0,
    };
    let (s, ns) = qos
        .liveliness_lease_duration
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    *ll_s_out = s;
    *ll_ns_out = ns;
    let (s, ns) = qos
        .deadline
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    *dl_s_out = s;
    *dl_ns_out = ns;
    let (s, ns) = qos
        .lifespan
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    *ls_s_out = s;
    *ls_ns_out = ns;
}

/// Get the list of known node names.
///
/// # Safety
/// `out` must point to a buffer of at least `out_len` bytes.
/// `count_out` must be a valid pointer; updated with the number of names written.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `out` - Output buffer for null-terminated name strings
/// * `out_len` - Buffer size in bytes
/// * `count_out` - Pointer to receive the count of names
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_get_node_names(
    session_id: u64,
    out: *mut u8,
    out_len: u32,
    count_out: *mut u32,
) -> i32 {
    if out.is_null() || count_out.is_null() {
        return -1;
    }
    let names = match with_session(session_id, |s| Ok(s.get_node_names())) {
        Ok(n) => n,
        Err(_) => return -1,
    };
    let required: usize = names.iter().map(|name| name.len() + 1).sum();
    if required > out_len as usize {
        unsafe {
            *count_out = names.len() as u32;
        }
        return -2;
    }
    let mut offset: usize = 0;
    let mut count: u32 = 0;
    for name in &names {
        let bytes = name.as_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(offset), bytes.len());
            std::ptr::write(out.add(offset + bytes.len()), 0);
        }
        offset += bytes.len() + 1;
        count += 1;
    }
    unsafe {
        *count_out = count;
    }
    0
}
/// Get null-terminated `(name, namespace)` pairs for all known nodes.
#[no_mangle]
pub extern "C" fn axon_session_get_node_names_with_namespaces(
    session_id: u64,
    out: *mut u8,
    out_len: u32,
    count_out: *mut u32,
) -> i32 {
    if out.is_null() || count_out.is_null() {
        return -1;
    }
    let nodes = match with_session(session_id, |s| Ok(s.get_node_names_and_namespaces())) {
        Ok(nodes) => nodes,
        Err(_) => {
            return -1;
        }
    };
    let required: usize = nodes
        .iter()
        .map(|(name, namespace)| name.len() + 1 + namespace.len() + 1)
        .sum();
    if required > out_len as usize {
        unsafe {
            *count_out = nodes.len() as u32;
        }
        return -2;
    }
    let mut offset = 0usize;
    let mut count = 0u32;
    for (name, namespace) in nodes {
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), out.add(offset), name.len());
            *out.add(offset + name.len()) = 0;
            offset += name.len() + 1;
            std::ptr::copy_nonoverlapping(namespace.as_ptr(), out.add(offset), namespace.len());
            *out.add(offset + namespace.len()) = 0;
            offset += namespace.len() + 1;
        }
        count += 1;
    }
    unsafe {
        *count_out = count;
    }
    0
}
/// Get the list of known topic names.
///
/// # Safety
/// `out` must point to a buffer of at least `out_len` bytes.
/// `count_out` must be a valid pointer; updated with the number of names written.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `out` - Output buffer for null-terminated name strings
/// * `out_len` - Buffer size in bytes
/// * `count_out` - Pointer to receive the count of names
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_get_topic_names(
    session_id: u64,
    out: *mut u8,
    out_len: u32,
    count_out: *mut u32,
) -> i32 {
    if out.is_null() || count_out.is_null() {
        return -1;
    }
    let names = match with_session(session_id, |s| Ok(s.get_topic_names())) {
        Ok(n) => n,
        Err(_) => return -1,
    };
    let required: usize = names.iter().map(|name| name.len() + 1).sum();
    if required > out_len as usize {
        unsafe {
            *count_out = names.len() as u32;
        }
        return -2;
    }
    let mut offset: usize = 0;
    let mut count: u32 = 0;
    for name in &names {
        let bytes = name.as_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(offset), bytes.len());
            std::ptr::write(out.add(offset + bytes.len()), 0);
        }
        offset += bytes.len() + 1;
        count += 1;
    }
    unsafe {
        *count_out = count;
    }
    0
}
/// Get the message type for a topic.
///
/// # Safety
/// `topic_name` must be a valid null-terminated C string.
/// The caller must free the returned string with `free()`.
#[no_mangle]
pub extern "C" fn axon_session_get_topic_type(
    session_id: u64,
    topic_name: *const c_char,
) -> *mut c_char {
    if topic_name.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return std::ptr::null_mut();
    };
    match with_session(session_id, |s| {
        let topics = s.get_topic_names_and_types();
        for (tn, tt) in &topics {
            if tn == name {
                return Ok(std::ffi::CString::new(tt.clone())
                    .unwrap_or_default()
                    .into_raw());
            }
        }
        Err("topic not found".into())
    }) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}
/// Get service names and types as C string arrays.
///
/// # Safety
/// All pointer arguments must be valid. The caller is responsible for freeing
/// the allocated arrays and strings using `free()`.
///
/// # Arguments
/// * `session_id` - Session handle
/// * `count` - Pointer to receive the number of entries
/// * `names` - Pointer to receive array of null-terminated service names
/// * `types` - Pointer to receive array of null-terminated service types
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_get_service_names_and_types(
    session_id: u64,
    count: *mut usize,
    names: *mut *mut *mut c_char,
    types: *mut *mut *mut c_char,
) -> i32 {
    if count.is_null() || names.is_null() || types.is_null() {
        return -1;
    }
    let entries = match with_session(session_id, |s| {
        Ok::<_, String>(s.get_service_names_and_types())
    }) {
        Ok(e) => e,
        Err(_) => {
            return -1;
        }
    };
    let n = entries.len();
    unsafe {
        let names_arr = std::alloc::alloc(std::alloc::Layout::array::<*mut c_char>(n).unwrap())
            as *mut *mut c_char;
        let types_arr = std::alloc::alloc(std::alloc::Layout::array::<*mut c_char>(n).unwrap())
            as *mut *mut c_char;
        for (i, (name, typ)) in entries.iter().enumerate() {
            let c_name = std::ffi::CString::new(name.clone()).unwrap();
            let c_type = std::ffi::CString::new(typ.clone()).unwrap();
            *names_arr.add(i) = c_name.into_raw();
            *types_arr.add(i) = c_type.into_raw();
        }
        *count = n;
        *names = names_arr;
        *types = types_arr;
    }
    0
}
/// Count publishers on a topic.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid UTF-8 C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_count_publishers(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
) -> i32 {
    if topic_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *count_out = s.get_publishers_info(topic).len() as u32;
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Count subscribers on a topic.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid UTF-8 C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_count_subscribers(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
) -> i32 {
    if topic_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *count_out = s.get_subscriptions_info(topic).len() as u32;
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Count services with a given name.
///
/// # Safety
/// `session_id` must be valid, `service_name` must be a valid UTF-8 C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_count_services(
    session_id: u64,
    service_name: *const c_char,
    count_out: *mut u32,
) -> i32 {
    if service_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *count_out = s.count_services(name) as u32;
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Count clients for a given service name.
///
/// # Safety
/// `session_id` must be valid, `service_name` must be a valid UTF-8 C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_count_clients(
    session_id: u64,
    service_name: *const c_char,
    count_out: *mut u32,
) -> i32 {
    if service_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *count_out = s.count_clients(name) as u32;
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Count matched subscriptions for a topic.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid UTF-8 C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_count_matched_subs(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
) -> i32 {
    if topic_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *count_out = s.count_matched_subscriptions(topic) as u32;
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Count matched publishers for a topic.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid UTF-8 C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_count_matched_pubs(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
) -> i32 {
    if topic_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *count_out = s.count_matched_publishers(topic) as u32;
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Check whether a service is available.
///
/// # Safety
/// `session_id` must be valid, `service_name` must be a valid UTF-8 C string, `available_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_service_available(
    session_id: u64,
    service_name: *const c_char,
    available_out: *mut i32,
) -> i32 {
    if service_name.is_null() || available_out.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        unsafe {
            *available_out = if s.service_available(name) { 1 } else { 0 };
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Check whether data is available on a subscription topic.
///
/// # Safety
/// `topic_name` must be a valid null-terminated C string.
#[no_mangle]
pub extern "C" fn axon_session_data_available(
    session_id: u64,
    topic_name: *const c_char,
    next_seq: u64,
) -> i32 {
    if topic_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    let available = with_session(session_id, |s| Ok(s.data_available_from(hash, next_seq)));
    match available {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}
/// Get the serialized message size for a type.
///
/// # Safety
/// `session_id` must be valid, `type_name` must be a valid UTF-8 C string, `size_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_get_serialized_message_size(
    _session_id: u64,
    type_name: *const c_char,
    size_out: *mut usize,
) -> i32 {
    if type_name.is_null() || size_out.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(type_name) }).to_str() else {
        return -1;
    };
    unsafe {
        *size_out = crate::session::topic_message_capacity(name, 65536);
    }
    0
}
/// Get `(name, namespace)` pairs for node names with enclaves.
///
/// # Safety
/// `session_id` must be valid, `out` must point to a buffer of `out_len` bytes, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_get_node_names_with_enclaves(
    session_id: u64,
    out: *mut u8,
    out_len: u32,
    count_out: *mut u32,
) -> i32 {
    axon_session_get_node_names_with_namespaces(session_id, out, out_len, count_out)
}
/// Get the 16-byte GID for a publisher on the given topic.
///
/// # Safety
/// `topic_name` must be a valid null-terminated C string.
/// `gid_out` must point to a buffer of at least 16 bytes.
///
/// # Returns
/// 0 on success, -1 if no publisher found.
#[no_mangle]
pub extern "C" fn axon_session_publisher_gid(
    session_id: u64,
    topic_name: *const c_char,
    gid_out: *mut u8,
) -> i32 {
    if topic_name.is_null() || gid_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        if let Some(gid) = s.publisher_gid(topic) {
            unsafe {
                std::ptr::copy_nonoverlapping(gid.as_ptr(), gid_out, 16);
            }
            Ok(())
        } else {
            Err("no publisher".into())
        }
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get the 16-byte GID for a subscription on the given topic.
///
/// # Safety
/// `topic_name` must be a valid null-terminated C string.
/// `gid_out` must point to a buffer of at least 16 bytes.
///
/// # Returns
/// 0 on success, -1 if no subscription found.
#[no_mangle]
pub extern "C" fn axon_session_subscription_gid(
    session_id: u64,
    topic_name: *const c_char,
    gid_out: *mut u8,
) -> i32 {
    if topic_name.is_null() || gid_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        if let Some(gid) = s.subscription_gid(topic) {
            unsafe {
                std::ptr::copy_nonoverlapping(gid.as_ptr(), gid_out, 16);
            }
            Ok(())
        } else {
            Err("no subscription".into())
        }
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Get the 16-byte GID for a client request publisher on the given service.
///
/// # Safety
/// `service_name` must be a valid null-terminated C string.
/// `gid_out` must point to a buffer of at least 16 bytes.
///
/// # Returns
/// 0 on success, -1 if no client found.
#[no_mangle]
pub extern "C" fn axon_session_client_gid(
    session_id: u64,
    service_name: *const c_char,
    gid_out: *mut u8,
) -> i32 {
    if service_name.is_null() || gid_out.is_null() {
        return -1;
    }
    let Ok(service) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        if s.service_actual_qos(service, 2).is_none() {
            return Err("no client".into());
        }
        let service_id = fxhash(service);
        let req_topic = service_request_topic(service_id);
        let gid = make_gid("pub", s.node_id, req_topic);
        unsafe {
            std::ptr::copy_nonoverlapping(gid.as_ptr(), gid_out, 16);
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Serialize endpoint info records into the output buffer.
/// Returns the number of records written.
///
/// # Safety
/// `info_buf` must point to a valid buffer of at least `info_buf_len` bytes.
unsafe fn write_endpoint_infos_to_buf(
    infos: &[crate::session::TopicEndpointInfo],
    info_buf: *mut u8,
    info_buf_len: u32,
) -> u32 {
    let mut offset: usize = 0;
    let mut written = 0u32;
    for info in infos {
        let name_bytes = info.node_name.as_bytes();
        let name_len = name_bytes.len() + 1;
        if offset + name_len > (info_buf_len as usize) {
            break;
        }
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), info_buf.add(offset), name_bytes.len());
        std::ptr::write(info_buf.add(offset + name_bytes.len()), 0);
        offset += name_len;

        let ns_bytes = info.node_namespace.as_bytes();
        let ns_len = ns_bytes.len() + 1;
        if offset + ns_len > (info_buf_len as usize) {
            break;
        }
        std::ptr::copy_nonoverlapping(ns_bytes.as_ptr(), info_buf.add(offset), ns_bytes.len());
        std::ptr::write(info_buf.add(offset + ns_bytes.len()), 0);
        offset += ns_len;

        let type_bytes = info.topic_type.as_bytes();
        let type_len = type_bytes.len() + 1;
        if offset + type_len > (info_buf_len as usize) {
            break;
        }
        std::ptr::copy_nonoverlapping(type_bytes.as_ptr(), info_buf.add(offset), type_bytes.len());
        std::ptr::write(info_buf.add(offset + type_bytes.len()), 0);
        offset += type_len;

        if offset + 16 > (info_buf_len as usize) {
            break;
        }
        std::ptr::copy_nonoverlapping(info.gid.as_ptr(), info_buf.add(offset), 16);
        offset += 16;

        if offset + 4 > (info_buf_len as usize) {
            break;
        }
        let rel: i32 = match info.qos.reliability {
            crate::types::Reliability::Reliable => 1,
            _ => 0,
        };
        std::ptr::write_unaligned(info_buf.add(offset) as *mut i32, rel);
        offset += 4;

        if offset + 4 > (info_buf_len as usize) {
            break;
        }
        let dur: i32 = match info.qos.durability {
            crate::types::Durability::TransientLocal => 1,
            _ => 0,
        };
        std::ptr::write_unaligned(info_buf.add(offset) as *mut i32, dur);
        offset += 4;

        if offset + 4 > (info_buf_len as usize) {
            break;
        }
        let hist: i32 = match info.qos.history {
            crate::types::HistoryKind::KeepAll => 0,
            crate::types::HistoryKind::KeepLast { .. } => 1,
        };
        std::ptr::write_unaligned(info_buf.add(offset) as *mut i32, hist);
        offset += 4;

        if offset + 4 > (info_buf_len as usize) {
            break;
        }
        let d: i32 = match info.qos.history {
            crate::types::HistoryKind::KeepLast { depth } => depth as i32,
            crate::types::HistoryKind::KeepAll => 0,
        };
        std::ptr::write_unaligned(info_buf.add(offset) as *mut i32, d);
        offset += 4;

        if offset + 4 > (info_buf_len as usize) {
            break;
        }
        let ll: i32 = match info.qos.liveliness {
            crate::types::Liveliness::ManualByTopic => 1,
            crate::types::Liveliness::ManualByParticipant => 2,
            _ => 0,
        };
        std::ptr::write_unaligned(info_buf.add(offset) as *mut i32, ll);
        offset += 4;

        let (ll_s, ll_ns) = match info.qos.liveliness_lease_duration {
            Some(d) => (d.as_secs(), d.subsec_nanos()),
            None => (0u64, 0u32),
        };
        if offset + 12 > (info_buf_len as usize) {
            break;
        }
        std::ptr::write_unaligned(info_buf.add(offset) as *mut u64, ll_s);
        std::ptr::write_unaligned(info_buf.add(offset + 8) as *mut u32, ll_ns);
        offset += 12;

        let (dl_s, dl_ns) = match info.qos.deadline {
            Some(d) => (d.as_secs(), d.subsec_nanos()),
            None => (0u64, 0u32),
        };
        if offset + 12 > (info_buf_len as usize) {
            break;
        }
        std::ptr::write_unaligned(info_buf.add(offset) as *mut u64, dl_s);
        std::ptr::write_unaligned(info_buf.add(offset + 8) as *mut u32, dl_ns);
        offset += 12;

        let (ls_s, ls_ns) = match info.qos.lifespan {
            Some(d) => (d.as_secs(), d.subsec_nanos()),
            None => (0u64, 0u32),
        };
        if offset + 12 > (info_buf_len as usize) {
            break;
        }
        std::ptr::write_unaligned(info_buf.add(offset) as *mut u64, ls_s);
        std::ptr::write_unaligned(info_buf.add(offset + 8) as *mut u32, ls_ns);
        offset += 12;

        written += 1;
    }
    written
}

fn endpoint_info_serialized_len(info: &crate::session::TopicEndpointInfo) -> usize {
    info.node_name.len()
        + 1
        + info.node_namespace.len()
        + 1
        + info.topic_type.len()
        + 1
        + 16
        + 4 * 5
        + 12 * 3
}

unsafe fn get_endpoint_info_impl<F>(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
    info_buf: *mut u8,
    info_buf_len: u32,
    query_fn: F,
) -> i32
where
    F: FnOnce(&crate::session::Session, &str) -> Vec<crate::session::TopicEndpointInfo>,
{
    if topic_name.is_null() || count_out.is_null() || info_buf.is_null() {
        return -1;
    }
    let Ok(topic) = CStr::from_ptr(topic_name).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let infos = query_fn(s, topic);
        let required: usize = infos.iter().map(endpoint_info_serialized_len).sum();
        if required > info_buf_len as usize {
            *count_out = infos.len() as u32;
            return Err("endpoint info buffer too small".into());
        }
        let written = write_endpoint_infos_to_buf(&infos, info_buf, info_buf_len);
        *count_out = written;
        Ok(())
    }) {
        Ok(_) => 0,
        Err(e) if e == "endpoint info buffer too small" => -2,
        Err(_) => -1,
    }
}

/// Get publisher endpoint info for a topic (serialized).
///
/// Fills `count_out` with the number of publishers, and writes serialized
/// endpoint records into `info_buf`. Each record is:
///   [node_name: null-term][node_namespace: null-term][topic_type: null-term]
///   [gid: 16 bytes][reliability: i32][durability: i32][history_kind: i32][depth: i32]
///
/// # Safety
/// `topic_name` must be a valid null-terminated C string.
/// `count_out`, `info_buf` must be valid pointers.
/// `info_buf_len` is the size of the output buffer in bytes.
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_get_publishers_info(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
    info_buf: *mut u8,
    info_buf_len: u32,
) -> i32 {
    unsafe {
        get_endpoint_info_impl(
            session_id,
            topic_name,
            count_out,
            info_buf,
            info_buf_len,
            |s, topic| s.get_publishers_info(topic),
        )
    }
}

/// Get subscription endpoint info for a topic (serialized).
///
/// Same record format as `axon_session_get_publishers_info`.
///
/// # Safety
/// `topic_name` must be a valid null-terminated C string.
/// `count_out`, `info_buf` must be valid pointers.
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn axon_session_get_subscriptions_info(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut u32,
    info_buf: *mut u8,
    info_buf_len: u32,
) -> i32 {
    unsafe {
        get_endpoint_info_impl(
            session_id,
            topic_name,
            count_out,
            info_buf,
            info_buf_len,
            |s, topic| s.get_subscriptions_info(topic),
        )
    }
}
/// Take a serialized message with info (timestamps, sequence number).
///
/// # Safety
/// `session_id` must be valid, `topic` must be a valid UTF-8 C string, `out` must point to a buffer,
/// `out_len` must be non-null, timestamp/sequence pointers may be null.
#[no_mangle]
pub extern "C" fn axon_session_take_serialized_message_with_info_next(
    session_id: u64,
    topic: *const c_char,
    seq_inout: *mut u64,
    out: *mut u8,
    out_len: *mut u32,
    source_timestamp: *mut i64,
    received_timestamp: *mut i64,
    sequence_number: *mut i64,
) -> i32 {
    if seq_inout.is_null() {
        return -1;
    }
    let ret = crate::c_bridge::axon_session_take_next(session_id, topic, seq_inout, out, out_len);
    if ret == 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        unsafe {
            if !source_timestamp.is_null() {
                *source_timestamp = now;
            }
            if !received_timestamp.is_null() {
                *received_timestamp = now;
            }
            if !sequence_number.is_null() {
                *sequence_number = (*seq_inout).saturating_sub(1) as i64;
            }
        }
    }
    ret
}
#[no_mangle]
pub extern "C" fn axon_session_take_serialized_message_with_info(
    session_id: u64,
    topic: *const c_char,
    seq: u64,
    out: *mut u8,
    out_len: *mut u32,
    source_timestamp: *mut i64,
    received_timestamp: *mut i64,
    sequence_number: *mut i64,
) -> i32 {
    let ret = crate::c_bridge::axon_session_take(session_id, topic, seq, out, out_len);
    if ret == 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        unsafe {
            if !source_timestamp.is_null() {
                *source_timestamp = now;
            }
            if !received_timestamp.is_null() {
                *received_timestamp = now;
            }
            if !sequence_number.is_null() {
                *sequence_number = seq as i64;
            }
        }
    }
    ret
}
/// Get publishers by node.
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
fn fill_names_and_types(
    result: Vec<(String, Vec<String>)>,
    count_out: *mut usize,
    names_out: *mut *mut *mut c_char,
    types_out: *mut *mut *mut c_char,
) {
    unsafe {
        *count_out = result.len();
        let count = result.len();
        if count == 0 {
            *names_out = std::ptr::null_mut();
            *types_out = std::ptr::null_mut();
            return;
        }
        let mut name_ptrs: Vec<*mut c_char> = Vec::with_capacity(count);
        let mut type_ptrs: Vec<*mut c_char> = Vec::with_capacity(count);
        for (name, types) in result {
            let c_name = std::ffi::CString::new(name).unwrap_or_default();
            name_ptrs.push(c_name.into_raw());
            let type_str = types.first().map(|s| s.as_str()).unwrap_or("unknown");
            let c_type = std::ffi::CString::new(type_str).unwrap_or_default();
            type_ptrs.push(c_type.into_raw());
        }
        *names_out = name_ptrs.as_mut_ptr();
        std::mem::forget(name_ptrs);
        *types_out = type_ptrs.as_mut_ptr();
        std::mem::forget(type_ptrs);
    }
}
/// Get publishers by node.
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
pub extern "C" fn axon_session_get_publishers_by_node(
    session_id: u64,
    node_name: *const c_char,
    node_ns: *const c_char,
    count_out: *mut usize,
    names_out: *mut *mut *mut c_char,
    types_out: *mut *mut *mut c_char,
) -> i32 {
    if node_name.is_null() || count_out.is_null() || names_out.is_null() || types_out.is_null() {
        return -1;
    }
    let nn = (unsafe { CStr::from_ptr(node_name) })
        .to_str()
        .unwrap_or("");
    let nns = if node_ns.is_null() {
        ""
    } else {
        (unsafe { CStr::from_ptr(node_ns) }).to_str().unwrap_or("")
    };
    match with_session(session_id, |s| {
        let result = s.get_publishers_by_node(nn, nns);
        fill_names_and_types(result, count_out, names_out, types_out);
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get subscribers by node.
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
pub extern "C" fn axon_session_get_subscribers_by_node(
    session_id: u64,
    node_name: *const c_char,
    node_ns: *const c_char,
    count_out: *mut usize,
    names_out: *mut *mut *mut c_char,
    types_out: *mut *mut *mut c_char,
) -> i32 {
    if node_name.is_null() || count_out.is_null() || names_out.is_null() || types_out.is_null() {
        return -1;
    }
    let nn = (unsafe { CStr::from_ptr(node_name) })
        .to_str()
        .unwrap_or("");
    let nns = if node_ns.is_null() {
        ""
    } else {
        (unsafe { CStr::from_ptr(node_ns) }).to_str().unwrap_or("")
    };
    match with_session(session_id, |s| {
        let result = s.get_subscribers_by_node(nn, nns);
        fill_names_and_types(result, count_out, names_out, types_out);
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get services by node.
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
pub extern "C" fn axon_session_get_services_by_node(
    session_id: u64,
    node_name: *const c_char,
    node_ns: *const c_char,
    count_out: *mut usize,
    names_out: *mut *mut *mut c_char,
    types_out: *mut *mut *mut c_char,
) -> i32 {
    if node_name.is_null() || count_out.is_null() || names_out.is_null() || types_out.is_null() {
        return -1;
    }
    let nn = (unsafe { CStr::from_ptr(node_name) })
        .to_str()
        .unwrap_or("");
    let nns = if node_ns.is_null() {
        ""
    } else {
        (unsafe { CStr::from_ptr(node_ns) }).to_str().unwrap_or("")
    };
    match with_session(session_id, |s| {
        let result = s.get_services_by_node(nn, nns);
        fill_names_and_types(result, count_out, names_out, types_out);
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get clients by node.
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
pub extern "C" fn axon_session_get_clients_by_node(
    session_id: u64,
    node_name: *const c_char,
    node_ns: *const c_char,
    count_out: *mut usize,
    names_out: *mut *mut *mut c_char,
    types_out: *mut *mut *mut c_char,
) -> i32 {
    if node_name.is_null() || count_out.is_null() || names_out.is_null() || types_out.is_null() {
        return -1;
    }
    let nn = (unsafe { CStr::from_ptr(node_name) })
        .to_str()
        .unwrap_or("");
    let nns = if node_ns.is_null() {
        ""
    } else {
        (unsafe { CStr::from_ptr(node_ns) }).to_str().unwrap_or("")
    };
    match with_session(session_id, |s| {
        let result = s.get_clients_by_node(nn, nns);
        fill_names_and_types(result, count_out, names_out, types_out);
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get actual QoS for a publisher.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid C string, output pointers must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_publisher_actual_qos_full(
    session_id: u64,
    topic_name: *const c_char,
    reliability_out: *mut i32,
    durability_out: *mut i32,
    history_out: *mut i32,
    depth_out: *mut usize,
    liveliness_out: *mut i32,
    liveliness_lease_s_out: *mut u64,
    liveliness_lease_ns_out: *mut u32,
    deadline_s_out: *mut u64,
    deadline_ns_out: *mut u32,
    lifespan_s_out: *mut u64,
    lifespan_ns_out: *mut u32,
) -> i32 {
    if topic_name.is_null()
        || reliability_out.is_null()
        || durability_out.is_null()
        || history_out.is_null()
        || depth_out.is_null()
        || liveliness_out.is_null()
        || liveliness_lease_s_out.is_null()
        || liveliness_lease_ns_out.is_null()
        || deadline_s_out.is_null()
        || deadline_ns_out.is_null()
        || lifespan_s_out.is_null()
        || lifespan_ns_out.is_null()
    {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let qos = s.publisher_actual_qos(topic).ok_or("publisher not found")?;
        unsafe {
            write_qos_to_output(
                &qos,
                reliability_out,
                durability_out,
                history_out,
                depth_out,
                liveliness_out,
                liveliness_lease_s_out,
                liveliness_lease_ns_out,
                deadline_s_out,
                deadline_ns_out,
                lifespan_s_out,
                lifespan_ns_out,
            );
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_publisher_actual_qos(
    session_id: u64,
    topic_name: *const c_char,
    reliability_out: *mut i32,
    durability_out: *mut i32,
) -> i32 {
    let mut history = 0;
    let mut depth = 0usize;
    let mut liveliness = 0;
    let mut ll_s = 0u64;
    let mut ll_ns = 0u32;
    let mut dl_s = 0u64;
    let mut dl_ns = 0u32;
    let mut ls_s = 0u64;
    let mut ls_ns = 0u32;
    axon_session_publisher_actual_qos_full(
        session_id,
        topic_name,
        reliability_out,
        durability_out,
        &mut history,
        &mut depth,
        &mut liveliness,
        &mut ll_s,
        &mut ll_ns,
        &mut dl_s,
        &mut dl_ns,
        &mut ls_s,
        &mut ls_ns,
    )
}
/// Get actual QoS for a subscription.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid C string, output pointers must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_subscription_actual_qos_full(
    session_id: u64,
    topic_name: *const c_char,
    reliability_out: *mut i32,
    durability_out: *mut i32,
    history_out: *mut i32,
    depth_out: *mut usize,
    liveliness_out: *mut i32,
    liveliness_lease_s_out: *mut u64,
    liveliness_lease_ns_out: *mut u32,
    deadline_s_out: *mut u64,
    deadline_ns_out: *mut u32,
    lifespan_s_out: *mut u64,
    lifespan_ns_out: *mut u32,
) -> i32 {
    if topic_name.is_null()
        || reliability_out.is_null()
        || durability_out.is_null()
        || history_out.is_null()
        || depth_out.is_null()
        || liveliness_out.is_null()
        || liveliness_lease_s_out.is_null()
        || liveliness_lease_ns_out.is_null()
        || deadline_s_out.is_null()
        || deadline_ns_out.is_null()
        || lifespan_s_out.is_null()
        || lifespan_ns_out.is_null()
    {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let qos = s
            .subscription_actual_qos(topic)
            .ok_or("subscription not found")?;
        unsafe {
            write_qos_to_output(
                &qos,
                reliability_out,
                durability_out,
                history_out,
                depth_out,
                liveliness_out,
                liveliness_lease_s_out,
                liveliness_lease_ns_out,
                deadline_s_out,
                deadline_ns_out,
                lifespan_s_out,
                lifespan_ns_out,
            );
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_subscription_actual_qos(
    session_id: u64,
    topic_name: *const c_char,
    reliability_out: *mut i32,
    durability_out: *mut i32,
) -> i32 {
    let mut history = 0;
    let mut depth = 0usize;
    let mut liveliness = 0;
    let mut ll_s = 0u64;
    let mut ll_ns = 0u32;
    let mut dl_s = 0u64;
    let mut dl_ns = 0u32;
    let mut ls_s = 0u64;
    let mut ls_ns = 0u32;
    axon_session_subscription_actual_qos_full(
        session_id,
        topic_name,
        reliability_out,
        durability_out,
        &mut history,
        &mut depth,
        &mut liveliness,
        &mut ll_s,
        &mut ll_ns,
        &mut dl_s,
        &mut dl_ns,
        &mut ls_s,
        &mut ls_ns,
    )
}
#[no_mangle]
pub extern "C" fn axon_session_service_qos(
    session_id: u64,
    service_name: *const c_char,
    role: i32,
    rel_out: *mut i32,
    dur_out: *mut i32,
    hist_out: *mut i32,
    depth_out: *mut usize,
    liveliness_out: *mut i32,
    ll_s_out: *mut u64,
    ll_ns_out: *mut u32,
    dl_s_out: *mut u64,
    dl_ns_out: *mut u32,
    ls_s_out: *mut u64,
    ls_ns_out: *mut u32,
) -> i32 {
    if service_name.is_null()
        || rel_out.is_null()
        || dur_out.is_null()
        || hist_out.is_null()
        || depth_out.is_null()
        || liveliness_out.is_null()
    {
        return -1;
    }
    let name = match unsafe { CStr::from_ptr(service_name) }.to_str() {
        Ok(n) => n,
        Err(_) => return -1,
    };
    match with_session(session_id, |s| {
        let qos = s.service_actual_qos(name, role as u8).ok_or("not found")?;
        unsafe {
            write_qos_to_output(
                &qos,
                rel_out,
                dur_out,
                hist_out,
                depth_out,
                liveliness_out,
                ll_s_out,
                ll_ns_out,
                dl_s_out,
                dl_ns_out,
                ls_s_out,
                ls_ns_out,
            );
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get publisher flow endpoints.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_publisher_flow_endpoints(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut usize,
    addrs_out: *mut *mut *mut c_char,
) -> i32 {
    if topic_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let addrs = s.publisher_flow_endpoints(topic);
        unsafe {
            *count_out = addrs.len();
            if !addrs_out.is_null() {
                *addrs_out = socket_addrs_to_c_array(&addrs)?;
            }
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get subscription flow endpoints.
///
/// # Safety
/// `session_id` must be valid, `topic_name` must be a valid C string, `count_out` must be non-null.
#[no_mangle]
pub extern "C" fn axon_session_subscription_flow_endpoints(
    session_id: u64,
    topic_name: *const c_char,
    count_out: *mut usize,
    addrs_out: *mut *mut *mut c_char,
) -> i32 {
    if topic_name.is_null() || count_out.is_null() {
        return -1;
    }
    let Ok(topic) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let addrs = s.subscription_flow_endpoints(topic);
        unsafe {
            *count_out = addrs.len();
            if !addrs_out.is_null() {
                *addrs_out = socket_addrs_to_c_array(&addrs)?;
            }
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

unsafe fn socket_addrs_to_c_array(
    addrs: &[std::net::SocketAddr],
) -> Result<*mut *mut c_char, String> {
    if addrs.is_empty() {
        return Ok(std::ptr::null_mut());
    }

    let array = libc::calloc(addrs.len(), std::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
    if array.is_null() {
        return Err("calloc flow endpoint array".into());
    }

    for (i, addr) in addrs.iter().enumerate() {
        let cstr = std::ffi::CString::new(addr.to_string())
            .map_err(|_| "flow endpoint address contains interior nul".to_string())?;
        *array.add(i) = cstr.into_raw();
    }
    Ok(array)
}
/// Create an event for a given entity.
///
/// # Safety
/// `session_id` must be valid. `event_kind` maps to EventKind: 0=LivelinessLost, 1=LivelinessChanged, 2=DeadlineMissed, 3=MessageLost, 4=RequestedQosCompatibility.
#[no_mangle]
pub extern "C" fn axon_session_create_event(
    session_id: u64,
    _entity_handle: u64,
    event_kind: u32,
) -> u64 {
    let kind = match event_kind {
        0 => EventKind::LivelinessLost,
        1 => EventKind::LivelinessChanged,
        2 => EventKind::DeadlineMissed,
        3 => EventKind::MessageLost,
        _ => EventKind::RequestedQosCompatibility,
    };
    match with_session(session_id, |s| Ok(s.create_event(kind))) {
        Ok(Some(handle)) => handle,
        _ => 0,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_take_event(
    session_id: u64,
    event_handle: u64,
    count_out: *mut i64,
    timestamp_out: *mut i64,
    alive_count_out: *mut i64,
    not_alive_count_out: *mut i64,
) -> i32 {
    if count_out.is_null() || timestamp_out.is_null() {
        return -1;
    }
    match with_session(session_id, |s| Ok(s.take_event(event_handle))) {
        Ok(Some((count, instant, alive, not_alive))) => {
            unsafe {
                *count_out = count;
                *timestamp_out = instant.elapsed().as_nanos() as i64;
                if !alive_count_out.is_null() {
                    *alive_count_out = alive;
                }
                if !not_alive_count_out.is_null() {
                    *not_alive_count_out = not_alive;
                }
            }
            0
        }
        _ => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_destroy_event(session_id: u64, event_handle: u64) -> i32 {
    let _ = with_session(session_id, |s| {
        s.destroy_event(event_handle);
        Ok(())
    });
    0
}
/// Assert liveliness for the session's node.
///
/// # Safety
/// `session_id` must be valid.
#[no_mangle]
pub extern "C" fn axon_session_assert_liveliness(session_id: u64) -> i32 {
    match with_session(session_id, |s| {
        s.assert_liveliness();
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_event_monitor_fd(session_id: u64) -> i64 {
    match with_session(session_id, |s| Ok(s.event_monitor_fd())) {
        Ok(Some(fd)) => fd as i64,
        _ => -1,
    }
}
/// Set a content filter on a subscription.
///
/// # Safety
/// `session_id` must be valid, `topic`, `name`, `expression` must be valid C strings.
#[no_mangle]
pub extern "C" fn axon_session_set_content_filter(
    session_id: u64,
    topic: *const c_char,
    name: *const c_char,
    expression: *const c_char,
    _params_keys: *const *const c_char,
    _params_values: *const *const c_char,
    _params_count: usize,
) -> i32 {
    if topic.is_null() || name.is_null() || expression.is_null() {
        return -1;
    }
    let Ok(topic_str) = (unsafe { CStr::from_ptr(topic) }).to_str() else {
        return -1;
    };
    let Ok(name_str) = (unsafe { CStr::from_ptr(name) }).to_str() else {
        return -1;
    };
    let Ok(expr_str) = (unsafe { CStr::from_ptr(expression) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        s.set_content_filter(topic_str, name_str, expr_str, HashMap::new());
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// Get a content filter from a subscription.
///
/// # Safety
/// `session_id` must be valid, `topic` must be a valid C string, output buffers must be valid.
#[no_mangle]
pub extern "C" fn axon_session_get_content_filter(
    session_id: u64,
    topic: *const c_char,
    name_out: *mut u8,
    name_len: u32,
    expression_out: *mut u8,
    expression_len: u32,
) -> i32 {
    if topic.is_null() || name_out.is_null() || expression_out.is_null() {
        return -1;
    }
    let Ok(topic_str) = (unsafe { CStr::from_ptr(topic) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let filter = s.get_content_filter(topic_str).ok_or("no content filter")?;
        let name_bytes = filter.name.as_bytes();
        let expr_bytes = filter.expression.as_bytes();
        let name_copy_len = name_bytes.len().min((name_len - 1) as usize);
        let expr_copy_len = expr_bytes.len().min((expression_len - 1) as usize);
        unsafe {
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_out, name_copy_len);
            name_out.add(name_copy_len).write(0);
            std::ptr::copy_nonoverlapping(expr_bytes.as_ptr(), expression_out, expr_copy_len);
            expression_out.add(expr_copy_len).write(0);
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
