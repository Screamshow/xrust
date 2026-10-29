use super::*;

fn config(session: &str, seq: &str, path: &str, mode: &str, obfs: bool) -> XhttpConfig {
    let value = serde_json::json!({
        "session_placement":session, "seq_placement":seq, "path":path, "mode":mode,
        "x_padding_bytes":"16-16", "x_padding_obfs_mode":obfs,
        "x_padding_placement":"queryInHeader", "x_padding_header":"referer"
    });
    XhttpConfig::parse(value.as_object().unwrap()).unwrap()
}

#[test]
fn non_path_metadata_preserves_exact_resource_and_padding_url() {
    for session in ["header", "query", "cookie"] {
        for seq in ["header", "query", "cookie"] {
            for mode in ["packet-up", "stream-up", "stream-one"] {
                for path in ["/media.ts", "/media.ts/"] {
                    for obfs in [false, true] {
                        let c = config(session, seq, path, mode, obfs);
                        for (sid, sequence) in
                            [(None, None), (Some("SID"), None), (Some("SID"), Some("7"))]
                        {
                            let req = c
                                .build_request("https", "example.test", "POST", sid, sequence, true)
                                .unwrap();
                            assert_eq!(req.uri().path(), path, "{session}/{seq}, {mode}");
                            assert_eq!(
                                req.headers()["referer"],
                                format!("https://example.test{path}?x_padding={}", "X".repeat(16))
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_path_placements_keep_separator_for_download_upload_and_stream_one() {
    for (session, seq, download, upload) in [
        ("path", "path", "/media.ts/SID", "/media.ts/SID/7"),
        ("path", "header", "/media.ts/SID", "/media.ts/SID"),
        ("query", "path", "/media.ts/", "/media.ts/7"),
        ("cookie", "path", "/media.ts/", "/media.ts/7"),
        ("path", "cookie", "/media.ts/SID", "/media.ts/SID"),
        ("path", "query", "/media.ts/SID", "/media.ts/SID"),
        ("header", "path", "/media.ts/", "/media.ts/7"),
    ] {
        let c = config(session, seq, "/media.ts", "packet-up", false);
        for (sid, sequence, expected) in [
            (None, None, "/media.ts/"),
            (Some("SID"), None, download),
            (Some("SID"), Some("7"), upload),
        ] {
            let req = c
                .build_request("https", "example.test", "POST", sid, sequence, true)
                .unwrap();
            assert_eq!(req.uri().path(), expected);
            assert!(
                req.headers()["referer"]
                    .to_str()
                    .unwrap()
                    .starts_with("https://example.test/media.ts/?")
            );
        }
    }
}

#[test]
fn empty_relative_and_root_paths_stay_valid_with_non_path_metadata() {
    for (path, expected) in [("", "/"), ("/", "/"), ("media.ts", "/media.ts")] {
        let c = config("header", "cookie", path, "stream-one", false);
        assert_eq!(
            c.build_request("https", "example.test", "POST", None, None, true)
                .unwrap()
                .uri()
                .path(),
            expected
        );
    }
}
