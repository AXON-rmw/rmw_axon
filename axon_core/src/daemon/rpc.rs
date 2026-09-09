use std::collections::BTreeMap;

#[derive(Debug)]
pub enum RpcError {
    Xml(quick_xml::Error),
    Message(String),
}

impl From<quick_xml::Error> for RpcError {
    fn from(e: quick_xml::Error) -> Self {
        RpcError::Xml(e)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Xml(e) => write!(f, "XML error: {}", e),
            RpcError::Message(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for RpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RpcError::Xml(e) => Some(e),
            RpcError::Message(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RpcValue {
    Int(i32),
    Bool(bool),
    String(String),
    Array(Vec<RpcValue>),
    Struct(BTreeMap<String, RpcValue>),
}

impl RpcValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            RpcValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i32(&self) -> Option<i32> {
        match self {
            RpcValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            RpcValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[RpcValue]> {
        match self {
            RpcValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<&BTreeMap<String, RpcValue>> {
        match self {
            RpcValue::Struct(s) => Some(s),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&RpcValue> {
        self.as_struct()?.get(key)
    }
}

#[derive(Debug)]
pub struct RpcMethodCall {
    pub method_name: String,
    pub params: Vec<RpcValue>,
}

#[derive(Debug)]
pub struct RpcMethodResponse {
    pub value: RpcValue,
}

use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

fn write_value(writer: &mut Writer<Vec<u8>>, val: &RpcValue) -> Result<(), RpcError> {
    match val {
        RpcValue::Int(n) => {
            writer.write_event(Event::Start(BytesStart::new("int")))?;
            writer.write_event(Event::Text(BytesText::new(&n.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("int")))?;
        }
        RpcValue::Bool(b) => {
            writer.write_event(Event::Start(BytesStart::new("boolean")))?;
            writer.write_event(Event::Text(BytesText::new(if *b { "1" } else { "0" })))?;
            writer.write_event(Event::End(BytesEnd::new("boolean")))?;
        }
        RpcValue::String(s) => {
            writer.write_event(Event::Start(BytesStart::new("string")))?;
            writer.write_event(Event::Text(BytesText::new(s)))?;
            writer.write_event(Event::End(BytesEnd::new("string")))?;
        }
        RpcValue::Array(arr) => {
            writer.write_event(Event::Start(BytesStart::new("array")))?;
            writer.write_event(Event::Start(BytesStart::new("data")))?;
            for item in arr {
                writer.write_event(Event::Start(BytesStart::new("value")))?;
                write_value(writer, item)?;
                writer.write_event(Event::End(BytesEnd::new("value")))?;
            }
            writer.write_event(Event::End(BytesEnd::new("data")))?;
            writer.write_event(Event::End(BytesEnd::new("array")))?;
        }
        RpcValue::Struct(map) => {
            writer.write_event(Event::Start(BytesStart::new("struct")))?;
            for (name, val) in map {
                writer.write_event(Event::Start(BytesStart::new("member")))?;
                writer.write_event(Event::Start(BytesStart::new("name")))?;
                writer.write_event(Event::Text(BytesText::new(name)))?;
                writer.write_event(Event::End(BytesEnd::new("name")))?;
                writer.write_event(Event::Start(BytesStart::new("value")))?;
                write_value(writer, val)?;
                writer.write_event(Event::End(BytesEnd::new("value")))?;
                writer.write_event(Event::End(BytesEnd::new("member")))?;
            }
            writer.write_event(Event::End(BytesEnd::new("struct")))?;
        }
    }
    Ok(())
}

pub fn serialize_response(resp: &RpcMethodResponse) -> Result<Vec<u8>, RpcError> {
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;
    writer.write_event(Event::Start(BytesStart::new("methodResponse")))?;
    writer.write_event(Event::Start(BytesStart::new("params")))?;
    writer.write_event(Event::Start(BytesStart::new("param")))?;
    writer.write_event(Event::Start(BytesStart::new("value")))?;
    write_value(&mut writer, &resp.value)?;
    writer.write_event(Event::End(BytesEnd::new("value")))?;
    writer.write_event(Event::End(BytesEnd::new("param")))?;
    writer.write_event(Event::End(BytesEnd::new("params")))?;
    writer.write_event(Event::End(BytesEnd::new("methodResponse")))?;
    Ok(writer.into_inner())
}

pub fn serialize_fault(code: i32, message: &str) -> Result<Vec<u8>, RpcError> {
    let mut fault = BTreeMap::new();
    fault.insert("faultCode".into(), RpcValue::Int(code));
    fault.insert("faultString".into(), RpcValue::String(message.into()));
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;
    writer.write_event(Event::Start(BytesStart::new("methodResponse")))?;
    writer.write_event(Event::Start(BytesStart::new("fault")))?;
    writer.write_event(Event::Start(BytesStart::new("value")))?;
    write_value(&mut writer, &RpcValue::Struct(fault))?;
    writer.write_event(Event::End(BytesEnd::new("value")))?;
    writer.write_event(Event::End(BytesEnd::new("fault")))?;
    writer.write_event(Event::End(BytesEnd::new("methodResponse")))?;
    Ok(writer.into_inner())
}

use quick_xml::events::Event as ReaderEvent;
use quick_xml::Reader;

fn expect_start(reader: &mut Reader<&[u8]>, name: &str) -> Result<(), RpcError> {
    loop {
        match reader.read_event()? {
            ReaderEvent::Start(e) if e.name().as_ref() == name.as_bytes() => return Ok(()),
            ReaderEvent::Empty(e) if e.name().as_ref() == name.as_bytes() => return Ok(()),
            ReaderEvent::Text(t) => {
                let text = t.unescape()?;
                if !text.trim().is_empty() {
                    return Err(RpcError::Message(format!("unexpected text: {}", text)));
                }
            }
            ReaderEvent::Comment(_) | ReaderEvent::Decl(_) | ReaderEvent::PI(_) => continue,
            other => {
                return Err(RpcError::Message(format!(
                    "expected <{}>, got {:?}",
                    name, other
                )));
            }
        }
    }
}

fn expect_end(reader: &mut Reader<&[u8]>, name: &str) -> Result<(), RpcError> {
    loop {
        match reader.read_event()? {
            ReaderEvent::End(e) if e.name().as_ref() == name.as_bytes() => return Ok(()),
            ReaderEvent::Text(t) => {
                let text = t.unescape()?;
                if !text.trim().is_empty() {
                    return Err(RpcError::Message(format!("unexpected text: {}", text)));
                }
            }
            ReaderEvent::Comment(_) | ReaderEvent::Decl(_) | ReaderEvent::PI(_) => continue,
            other => {
                return Err(RpcError::Message(format!(
                    "expected </{}>, got {:?}",
                    name, other
                )));
            }
        }
    }
}

fn read_text(reader: &mut Reader<&[u8]>) -> Result<String, RpcError> {
    loop {
        match reader.read_event()? {
            ReaderEvent::Text(t) => return Ok(t.unescape()?.to_string()),
            ReaderEvent::Comment(_) | ReaderEvent::Decl(_) | ReaderEvent::PI(_) => continue,
            other => {
                return Err(RpcError::Message(format!("expected text, got {:?}", other)));
            }
        }
    }
}

fn parse_value(reader: &mut Reader<&[u8]>) -> Result<RpcValue, RpcError> {
    loop {
        match reader.read_event()? {
            ReaderEvent::Text(t) => {
                let text = t.unescape()?;
                if !text.trim().is_empty() {
                    return Ok(RpcValue::String(text.to_string()));
                }
            }
            ReaderEvent::Start(e) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match tag.as_str() {
                    "int" | "i4" => {
                        let text = read_text(reader)?;
                        let n = text
                            .parse::<i32>()
                            .map_err(|e| RpcError::Message(format!("invalid int: {}", e)))?;
                        expect_end(reader, &tag)?;
                        return Ok(RpcValue::Int(n));
                    }
                    "boolean" => {
                        let text = read_text(reader)?;
                        let b = text == "1";
                        expect_end(reader, "boolean")?;
                        return Ok(RpcValue::Bool(b));
                    }
                    "string" => {
                        let text = read_text(reader)?;
                        expect_end(reader, "string")?;
                        return Ok(RpcValue::String(text.to_string()));
                    }
                    "array" => {
                        expect_start(reader, "data")?;
                        let mut items = Vec::new();
                        loop {
                            match reader.read_event()? {
                                ReaderEvent::Start(e) if e.name().as_ref() == b"value" => {
                                    items.push(parse_value(reader)?);
                                    expect_end(reader, "value")?;
                                }
                                ReaderEvent::End(e) if e.name().as_ref() == b"data" => break,
                                ReaderEvent::Text(t) => {
                                    if !t.unescape()?.trim().is_empty() {
                                        return Err(RpcError::Message(format!(
                                            "unexpected text: {}",
                                            t.unescape()?
                                        )));
                                    }
                                }
                                ReaderEvent::Comment(_)
                                | ReaderEvent::Decl(_)
                                | ReaderEvent::PI(_) => continue,
                                other => {
                                    return Err(RpcError::Message(format!(
                                        "expected <value> or </data>, got {:?}",
                                        other
                                    )));
                                }
                            }
                        }
                        expect_end(reader, "array")?;
                        return Ok(RpcValue::Array(items));
                    }
                    "struct" => {
                        let mut map = BTreeMap::new();
                        loop {
                            match reader.read_event()? {
                                ReaderEvent::Start(e) if e.name().as_ref() == b"member" => {
                                    expect_start(reader, "name")?;
                                    let name = read_text(reader)?;
                                    expect_end(reader, "name")?;
                                    expect_start(reader, "value")?;
                                    let val = parse_value(reader)?;
                                    expect_end(reader, "value")?;
                                    expect_end(reader, "member")?;
                                    map.insert(name, val);
                                }
                                ReaderEvent::End(e) if e.name().as_ref() == b"struct" => break,
                                ReaderEvent::Text(t) => {
                                    if !t.unescape()?.trim().is_empty() {
                                        return Err(RpcError::Message(format!(
                                            "unexpected text: {}",
                                            t.unescape()?
                                        )));
                                    }
                                }
                                ReaderEvent::Comment(_)
                                | ReaderEvent::Decl(_)
                                | ReaderEvent::PI(_) => continue,
                                other => {
                                    return Err(RpcError::Message(format!(
                                        "expected <member> or </struct>, got {:?}",
                                        other
                                    )));
                                }
                            }
                        }
                        return Ok(RpcValue::Struct(map));
                    }
                    tag => {
                        return Err(RpcError::Message(format!("unknown XML-RPC type: {}", tag)));
                    }
                }
            }
            ReaderEvent::Comment(_) | ReaderEvent::Decl(_) | ReaderEvent::PI(_) => continue,
            other => {
                return Err(RpcError::Message(format!(
                    "expected <value>, got {:?}",
                    other
                )));
            }
        }
    }
}

pub fn parse_request(data: &[u8]) -> Result<RpcMethodCall, RpcError> {
    let mut reader = Reader::from_reader(data);
    loop {
        match reader.read_event()? {
            ReaderEvent::Start(e) if e.name().as_ref() == b"methodCall" => break,
            ReaderEvent::Text(t) => {
                let text = t.unescape()?;
                if !text.trim().is_empty() {
                    return Err(RpcError::Message(format!("unexpected text: {}", text)));
                }
            }
            ReaderEvent::Decl(_) | ReaderEvent::Comment(_) | ReaderEvent::PI(_) => continue,
            other => {
                return Err(RpcError::Message(format!(
                    "expected <methodCall>, got {:?}",
                    other
                )));
            }
        }
    }
    expect_start(&mut reader, "methodName")?;
    let method_name = read_text(&mut reader)?;
    expect_end(&mut reader, "methodName")?;

    let mut params = Vec::new();
    loop {
        match reader.read_event()? {
            ReaderEvent::Start(e) if e.name().as_ref() == b"params" => {
                loop {
                    match reader.read_event()? {
                        ReaderEvent::Start(e) if e.name().as_ref() == b"param" => {
                            expect_start(&mut reader, "value")?;
                            params.push(parse_value(&mut reader)?);
                            expect_end(&mut reader, "value")?;
                            expect_end(&mut reader, "param")?;
                        }
                        ReaderEvent::End(e) if e.name().as_ref() == b"params" => break,
                        ReaderEvent::Text(t) => {
                            if !t.unescape()?.trim().is_empty() {
                                return Err(RpcError::Message(format!(
                                    "unexpected text: {}",
                                    t.unescape()?
                                )));
                            }
                        }
                        ReaderEvent::Comment(_) | ReaderEvent::Decl(_) | ReaderEvent::PI(_) => {
                            continue
                        }
                        other => {
                            return Err(RpcError::Message(format!(
                                "expected <param> or </params>, got {:?}",
                                other
                            )));
                        }
                    }
                }
                expect_end(&mut reader, "methodCall")?;
                return Ok(RpcMethodCall {
                    method_name,
                    params,
                });
            }
            ReaderEvent::End(e) if e.name().as_ref() == b"methodCall" => {
                return Ok(RpcMethodCall {
                    method_name,
                    params,
                });
            }
            ReaderEvent::Text(t) => {
                let text = t.unescape()?;
                if !text.trim().is_empty() {
                    return Err(RpcError::Message(format!("unexpected text: {}", text)));
                }
            }
            ReaderEvent::Comment(_) | ReaderEvent::Decl(_) | ReaderEvent::PI(_) => continue,
            other => {
                return Err(RpcError::Message(format!(
                    "expected <params> or </methodCall>, got {:?}",
                    other
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_roundtrip() {
        let resp = RpcMethodResponse {
            value: RpcValue::Int(42),
        };
        let xml = serialize_response(&resp).unwrap();
        let s = String::from_utf8_lossy(&xml);
        assert!(s.contains("<int>42</int>") || s.contains("<int>42"));
    }

    #[test]
    fn test_bool_roundtrip() {
        let resp = RpcMethodResponse {
            value: RpcValue::Bool(true),
        };
        let xml = serialize_response(&resp).unwrap();
        let s = String::from_utf8_lossy(&xml);
        assert!(s.contains("<boolean>1</boolean>") || s.contains("<boolean>1"));
    }

    #[test]
    fn test_struct_roundtrip() {
        let mut map = BTreeMap::new();
        map.insert("name".into(), RpcValue::String("test".into()));
        map.insert("count".into(), RpcValue::Int(3));
        let xml = serialize_response(&RpcMethodResponse {
            value: RpcValue::Struct(map),
        })
        .unwrap();
        let s = String::from_utf8_lossy(&xml);
        assert!(s.contains("<name>name</name>"));
        assert!(s.contains("<name>count</name>"));
    }

    #[test]
    fn test_parse_basic_request() {
        let xml = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_topic_names_and_types</methodName>
  <params>
    <param><value><boolean>0</boolean></value></param>
  </params>
</methodCall>"#;
        let call = parse_request(xml).unwrap();
        assert_eq!(call.method_name, "get_topic_names_and_types");
        assert_eq!(call.params.len(), 1);
        assert_eq!(call.params[0].as_bool(), Some(false));
    }

    #[test]
    fn test_parse_request_no_params() {
        let xml = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_node_names</methodName>
</methodCall>"#;
        let call = parse_request(xml).unwrap();
        assert_eq!(call.method_name, "get_node_names");
        assert!(call.params.is_empty());
    }

    #[test]
    fn test_fault_serialization() {
        let xml = serialize_fault(-1, "method not found").unwrap();
        let s = String::from_utf8_lossy(&xml);
        assert!(s.contains("<int>-1</int>") || s.contains("<int>-1"));
        assert!(s.contains("method not found"));
    }

    #[test]
    fn test_string_value() {
        let resp = RpcMethodResponse {
            value: RpcValue::String("hello".into()),
        };
        let xml = serialize_response(&resp).unwrap();
        let s = String::from_utf8_lossy(&xml);
        assert!(s.contains("<string>hello</string>") || s.contains("<string>hello"));
    }

    #[test]
    fn test_parse_with_types() {
        let xml = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>test</methodName>
  <params>
    <param><value><int>42</int></value></param>
    <param><value><string>foo</string></value></param>
  </params>
</methodCall>"#;
        let call = parse_request(xml).unwrap();
        assert_eq!(call.params.len(), 2);
        assert_eq!(call.params[0].as_i32(), Some(42));
        assert_eq!(call.params[1].as_str(), Some("foo"));
    }

    #[test]
    fn test_parse_array() {
        let xml = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>test</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>a</string></value>
            <value><string>b</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>"#;
        let call = parse_request(xml).unwrap();
        let arr = call.params[0].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str(), Some("a"));
        assert_eq!(arr[1].as_str(), Some("b"));
    }
}
