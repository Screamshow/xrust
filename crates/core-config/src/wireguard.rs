//! Shared normalization for WireGuard peer reserved bytes. The empty value
//! disables the extension; every nonempty representation must contain 3 bytes.
use base64::Engine as _;
use serde_json::Value;

pub fn parse_reserved(value: &Value) -> Result<[u8; 3], String> {
    let bytes = match value {
        Value::Null => return Ok([0; 3]),
        Value::Object(map) if map.is_empty() => return Ok([0; 3]),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| "reserved: expected integer bytes in 0..255".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Ok([0; 3]);
            }
            if text.contains(',') || text.chars().any(|c| c.is_ascii_whitespace()) {
                // Commas separate actual values: reject missing elements.
                if text.contains(',') && text.split(',').any(|part| part.trim().is_empty()) {
                    return Err("reserved: empty byte in list".into());
                }
                text.split(|c: char| c == ',' || c.is_ascii_whitespace())
                    .filter(|part| !part.is_empty())
                    .map(|part| {
                        part.parse::<u8>()
                            .map_err(|_| "reserved: expected integer bytes in 0..255".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(text))
                    .map_err(|_| "reserved: expected Base64 or three decimal bytes".to_string())?
            }
        }
        _ => return Err("reserved: expected an array, Base64 or three decimal bytes".into()),
    };
    if bytes.is_empty() {
        return Ok([0; 3]);
    }
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("reserved: required 3 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reserved_representations_have_one_identity() {
        for value in [
            json!([19, 81, 203]),
            json!("E1HL"),
            json!("19 81 203"),
            json!("19,81,203"),
            json!("19, 81, 203"),
        ] {
            assert_eq!(parse_reserved(&value).unwrap(), [19, 81, 203]);
        }
        for value in [Value::Null, json!([]), json!(""), json!([0, 0, 0])] {
            assert_eq!(parse_reserved(&value).unwrap(), [0; 3]);
        }
    }

    #[test]
    fn malformed_reserved_is_rejected() {
        for value in [
            json!([1]),
            json!([1, 2]),
            json!([1, 2, 3, 4]),
            json!([1, -2, 3]),
            json!([1, 256, 3]),
            json!([1, 2.5, 3]),
            json!([1, true, 3]),
            json!([1, null, 3]),
            json!("1,,2,3"),
            json!("1,2,3,"),
            json!("1 2 999"),
            json!("AQI="),
            json!("invalid!"),
            json!(true),
        ] {
            assert!(parse_reserved(&value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn reserved_config_checks_length_and_rejects_awg_header_conflicts() {
        let mut root = json!({"endpoints":[{
            "type":"wireguard", "tag":"wg", "private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "address":["10.0.0.2/32"], "peers":[{
                "public_key":"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=", "allowed_ips":["0.0.0.0/0"]
            }]
        }]});
        for reserved in [
            json!([19, 81, 203]),
            json!("E1HL"),
            json!("19 81 203"),
            json!("19,81,203"),
        ] {
            root["endpoints"][0]["peers"][0]["reserved"] = reserved;
            crate::check_str(&root.to_string()).unwrap();
        }
        root["endpoints"][0]["peers"][0]["reserved"] = json!([1, 2]);
        assert!(
            crate::check_str(&root.to_string())
                .unwrap_err()
                .contains("required 3 bytes")
        );
        root["endpoints"][0]["peers"][0]["reserved"] = json!([19, 81, 203]);
        root["endpoints"][0]["s1"] = json!(16);
        assert!(
            crate::check_str(&root.to_string())
                .unwrap_err()
                .contains("cannot be combined")
        );
        root["endpoints"][0]["peers"][0]["reserved"] = json!([0, 0, 0]);
        crate::check_str(&root.to_string()).unwrap();
    }
}
