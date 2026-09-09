use crate::daemon::rpc::{serialize_response, RpcMethodCall, RpcMethodResponse, RpcValue};
use crate::session::Session;
use std::collections::BTreeMap;

pub fn handle_call(session: &Session, call: &RpcMethodCall) -> Result<Vec<u8>, String> {
    let result = match call.method_name.as_str() {
        "get_topic_names_and_types" => handle_get_topic_names_and_types(session, call),
        "get_node_names" => handle_get_node_names(session),
        "get_service_names_and_types" => handle_get_service_names_and_types(session),
        "get_publishers_info_by_topic" => handle_get_publishers_info_by_topic(session, call),
        "get_subscriptions_info_by_topic" => handle_get_subscriptions_info_by_topic(session, call),
        _ => return Err(format!("unknown method: {}", call.method_name)),
    }?;
    serialize_response(&result).map_err(|e| format!("serialization error: {}", e))
}

fn handle_get_topic_names_and_types(
    session: &Session,
    _call: &RpcMethodCall,
) -> Result<RpcMethodResponse, String> {
    let topics = session.get_topic_names_and_types();
    let mut result: Vec<RpcValue> = Vec::new();
    for (name, typ) in topics {
        let pubs_count = session.count_publishers(&name) as i32;
        let subs_count = session.count_subscribers(&name) as i32;
        // Only include topics that have at least one active endpoint.
        // Remote topics discovered via HELLO are cached in topic_name_cache
        // indefinitely even after the remote node disappears; the count check
        // prevents stale cache entries from appearing as live topics.
        if pubs_count == 0 && subs_count == 0 {
            continue;
        }
        let mut entry = BTreeMap::new();
        entry.insert("name".into(), RpcValue::String(name.clone()));
        entry.insert("type".into(), RpcValue::String(typ));
        entry.insert("publishers_count".into(), RpcValue::Int(pubs_count));
        entry.insert("subscribers_count".into(), RpcValue::Int(subs_count));
        result.push(RpcValue::Struct(entry));
    }
    Ok(RpcMethodResponse {
        value: RpcValue::Array(result),
    })
}

fn handle_get_node_names(session: &Session) -> Result<RpcMethodResponse, String> {
    let nodes = session.get_node_names_and_namespaces();
    let mut result: Vec<RpcValue> = Vec::new();
    for (name, ns) in nodes {
        let mut entry = BTreeMap::new();
        entry.insert("name".into(), RpcValue::String(name.clone()));
        entry.insert("namespace".into(), RpcValue::String(ns.clone()));
        let full_name = if ns == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", ns, name)
        };
        entry.insert("full_name".into(), RpcValue::String(full_name));
        result.push(RpcValue::Struct(entry));
    }
    Ok(RpcMethodResponse {
        value: RpcValue::Array(result),
    })
}

fn handle_get_service_names_and_types(session: &Session) -> Result<RpcMethodResponse, String> {
    let services = session.get_service_names_and_types();
    let mut result: Vec<RpcValue> = Vec::new();
    for (name, typ) in services {
        let mut entry = BTreeMap::new();
        entry.insert("name".into(), RpcValue::String(name));
        entry.insert("type".into(), RpcValue::String(typ));
        result.push(RpcValue::Struct(entry));
    }
    Ok(RpcMethodResponse {
        value: RpcValue::Array(result),
    })
}

fn endpoint_info_to_rpc(info: &crate::session::TopicEndpointInfo) -> RpcValue {
    let mut entry = BTreeMap::new();
    entry.insert("node_name".into(), RpcValue::String(info.node_name.clone()));
    entry.insert(
        "node_namespace".into(),
        RpcValue::String(info.node_namespace.clone()),
    );
    entry.insert(
        "topic_type".into(),
        RpcValue::String(info.topic_type.clone()),
    );
    entry.insert(
        "topic_name".into(),
        RpcValue::String(info.topic_name.clone()),
    );
    entry.insert(
        "transport_kind".into(),
        RpcValue::String(info.transport_kind.clone()),
    );
    // GID as hex string
    let gid_hex: String = info.gid.iter().map(|b| format!("{:02x}", b)).collect();
    entry.insert("gid".into(), RpcValue::String(gid_hex));
    // QoS struct
    let qos = &info.qos;
    let mut qos_map = BTreeMap::new();
    qos_map.insert(
        "reliability".into(),
        RpcValue::String(format!("{:?}", qos.reliability)),
    );
    qos_map.insert(
        "durability".into(),
        RpcValue::String(format!("{:?}", qos.durability)),
    );
    qos_map.insert(
        "history".into(),
        RpcValue::String(format!("{:?}", qos.history)),
    );
    entry.insert("qos".into(), RpcValue::Struct(qos_map));
    RpcValue::Struct(entry)
}

fn handle_get_publishers_info_by_topic(
    session: &Session,
    call: &RpcMethodCall,
) -> Result<RpcMethodResponse, String> {
    let topic = call
        .params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing topic parameter".to_string())?;
    let info = session.get_publishers_info(topic);
    let result: Vec<RpcValue> = info.iter().map(endpoint_info_to_rpc).collect();
    Ok(RpcMethodResponse {
        value: RpcValue::Array(result),
    })
}

fn handle_get_subscriptions_info_by_topic(
    session: &Session,
    call: &RpcMethodCall,
) -> Result<RpcMethodResponse, String> {
    let topic = call
        .params
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing topic parameter".to_string())?;
    let info = session.get_subscriptions_info(topic);
    let result: Vec<RpcValue> = info.iter().map(endpoint_info_to_rpc).collect();
    Ok(RpcMethodResponse {
        value: RpcValue::Array(result),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn test_unknown_method_returns_error() {
        let session = Session::new(42, 0);
        let call = RpcMethodCall {
            method_name: "nonexistent".into(),
            params: vec![],
        };
        let result = handle_call(&session, &call);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown method"));
    }

    #[test]
    fn test_get_node_names_local_only() {
        let session = Session::new(42, 0);
        let call = RpcMethodCall {
            method_name: "get_node_names".into(),
            params: vec![],
        };
        let result = handle_call(&session, &call).unwrap();
        let s = String::from_utf8_lossy(&result);
        assert!(s.contains("node_42"));
        assert!(s.contains("</methodResponse>"));
    }

    #[test]
    fn test_get_topic_names_empty() {
        let session = Session::new(42, 0);
        let call = RpcMethodCall {
            method_name: "get_topic_names_and_types".into(),
            params: vec![RpcValue::Bool(false)],
        };
        let result = handle_call(&session, &call).unwrap();
        let s = String::from_utf8_lossy(&result);
        // Should be an empty array
        assert!(s.contains("<array>"));
    }

    #[test]
    fn test_get_service_names_empty() {
        let session = Session::new(42, 0);
        let call = RpcMethodCall {
            method_name: "get_service_names_and_types".into(),
            params: vec![],
        };
        let result = handle_call(&session, &call).unwrap();
        let s = String::from_utf8_lossy(&result);
        assert!(s.contains("<array>"));
    }

    #[test]
    fn test_get_publishers_info_missing_param() {
        let session = Session::new(42, 0);
        let call = RpcMethodCall {
            method_name: "get_publishers_info_by_topic".into(),
            params: vec![],
        };
        let result = handle_call(&session, &call);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing topic parameter"));
    }
}
