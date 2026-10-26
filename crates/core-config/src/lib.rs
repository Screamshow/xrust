pub mod asn1_x509;
pub mod go_regex;
pub mod netip_parse;
pub mod srs;
pub mod validate;
pub mod vless_enc;

use serde_json::Value;

/// Named session alphabets used by Xray/sing-box X XHTTP configurations.
pub fn xhttp_session_table(table: &str) -> &str {
    match table {
        "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX" => "0123456789ABCDEF",
        "alphabet" => "abcdefghijklmnopqrstuvwxyz",
        "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        "number" => "0123456789",
        _ => table,
    }
}

/// Full `sing-box check` equivalent plus the reference's warning lines
/// (deprecated `route.lx_idle_*` aliases and friends), which do not fail the
/// check.
///
/// The config is read as a `Value` and every section is taken apart by the
/// module that needs it: a struct with one `Option<Value>` per section was only
/// ever a second copy of the schema.
pub fn check_str_warnings(raw: &str) -> Result<Vec<String>, String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    validate::validate_with_warnings(&value)
}

/// Full `sing-box check` equivalent: schema parse + semantic validation.
pub fn check_str(raw: &str) -> Result<(), String> {
    check_str_warnings(raw).map(|_| ())
}

/// `check` of a parsed document whose local rule-set files named in `loaded`
/// were already decoded and verified by the caller (a running instance that
/// loaded the very same files). Their payload is not decoded again; every
/// other part of the document is checked as `check_str` does.
pub fn check_value_with_loaded_rule_sets(
    value: &Value,
    loaded: &std::collections::HashSet<String>,
) -> Result<(), String> {
    validate::with_loaded_rule_set_files(loaded, || validate::validate_with_warnings(value))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_json() {
        assert!(check_str("{not json").is_err());
    }

    #[test]
    fn loaded_rule_set_files_are_not_decoded_again() {
        let path =
            std::env::temp_dir().join(format!("xrust-loaded-set-{}.json", std::process::id()));
        std::fs::write(&path, "{broken").unwrap();
        let path_text = path.to_string_lossy().to_string();
        let root = serde_json::json!({"route": {"rule_set": [
            {"type": "local", "tag": "set", "format": "source", "path": path_text}
        ]}});
        let mut loaded = std::collections::HashSet::new();
        assert!(check_value_with_loaded_rule_sets(&root, &loaded).is_err());
        loaded.insert(path_text.clone());
        assert!(check_value_with_loaded_rule_sets(&root, &loaded).is_ok());
        // the exemption ends with the call
        assert!(check_str(&root.to_string()).is_err());
        // the rest of the document is still checked
        let mut bad = root.clone();
        bad["inbounds"] = serde_json::json!([{"type": "unknown"}]);
        assert!(check_value_with_loaded_rule_sets(&bad, &loaded).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn accepts_a_minimal_config() {
        check_str(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct"}]}"#).unwrap();
    }

    #[test]
    fn a_section_it_knows_nothing_about_fails_the_check() {
        // the permissive struct this used to parse into is gone; the reference
        // rejects a section it does not know, and so do we
        let err = check_str(r#"{"futureSection":{"a":1}}"#).unwrap_err();
        assert!(err.contains("futureSection"), "{err}");
    }
}
