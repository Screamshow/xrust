//! `domain_regex` in rule sets.
//!
//! In the reference a headless rule puts `domain_regex` into the destination
//! address group together with `domain`, `domain_suffix`, `domain_keyword`
//! and `ip_cidr` (`rule_headless.go`); the groups are ANDed
//! (`rule_abstract.go`). A connection without a domain never matches the
//! regex item (`rule_item_domain_regex.go`), and a bad expression fails the
//! rule-set load. These tests go through the router, a JSON source file, an
//! SRS file and a remote update.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use core_runtime::inbound::Target;
use core_runtime::route::rule_set::{RuleSet, match_rule};
use core_runtime::route::{ConnContext, Decision, Router};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REGEX: &str = "^foo\\.example$";

fn domain(host: &str, port: u16) -> ConnContext {
    ConnContext::new(
        "mixed-in",
        "10.0.0.2:1234".parse::<SocketAddr>().expect("source"),
        Target::Domain(host.to_string(), port),
        "tcp",
    )
}

fn ip(address: &str, port: u16) -> ConnContext {
    ConnContext::new(
        "mixed-in",
        "10.0.0.2:1234".parse::<SocketAddr>().expect("source"),
        Target::Ip(format!("{address}:{port}").parse().expect("ip")),
        "tcp",
    )
}

/// A router whose only rule sends the rule set's hits to `hit`.
fn router_with(rule_set: Value) -> anyhow::Result<Arc<Router>> {
    Router::new(&json!({
        "log": {"level": "error"},
        "outbounds": [
            {"type": "direct", "tag": "hit"},
            {"type": "direct", "tag": "miss"}
        ],
        "route": {
            "final": "miss",
            "rule_set": [rule_set],
            "rules": [{"rule_set": ["set"], "outbound": "hit"}]
        }
    }))
}

fn inline(rules: Value) -> Arc<Router> {
    router_with(json!({"type": "inline", "tag": "set", "rules": rules})).expect("router")
}

async fn hits(router: &Router, mut ctx: ConnContext) -> bool {
    match router.route_raw(&mut ctx).await.expect("route") {
        Decision::Outbound(index) => index == router.index_of("hit").expect("hit"),
        Decision::HijackDns => panic!("unexpected hijack"),
    }
}

/// A temp file removed on drop.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rule-set-regex-{}-{nonce}-{name}",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("write");
        TempFile(path)
    }

    fn path(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn regex_only_rule_matches_only_matching_domains() {
    let router = inline(json!([{"domain_regex": [REGEX]}]));
    assert!(hits(&router, domain("foo.example", 443)).await);
    // the host is lowercased before matching
    assert!(hits(&router, domain("FOO.Example", 443)).await);
    assert!(!hits(&router, domain("bar.test", 443)).await);
    assert!(!hits(&router, domain("sub.foo.example", 443)).await);
    assert!(!hits(&router, domain("foo.example.org", 443)).await);
    // no domain at all: the regex item cannot match
    assert!(!hits(&router, ip("8.8.8.8", 443)).await);
    assert!(!hits(&router, ip("10.1.2.3", 80)).await);
    // a sniffed name over an IP destination is a domain
    let mut sniffed = ip("203.0.113.9", 443);
    sniffed.domain = Some("foo.example".into());
    assert!(hits(&router, sniffed).await);
}

/// Top-level route rules already compile `domain_regex`; keep them in step.
#[tokio::test]
async fn route_rule_regex_matches_only_matching_domains() {
    let router = Router::new(&json!({
        "log": {"level": "error"},
        "outbounds": [
            {"type": "direct", "tag": "hit"},
            {"type": "direct", "tag": "miss"}
        ],
        "route": {
            "final": "miss",
            "rules": [
                {"domain_regex": [REGEX], "outbound": "hit"},
                {"domain_regex": ["^re[0-9]+\\.test$"], "port": [443], "outbound": "hit"}
            ]
        }
    }))
    .expect("router");
    assert!(hits(&router, domain("foo.example", 80)).await);
    assert!(hits(&router, domain("re1.test", 443)).await);
    assert!(!hits(&router, domain("re1.test", 80)).await);
    assert!(!hits(&router, domain("bar.test", 443)).await);
    assert!(!hits(&router, ip("8.8.8.8", 443)).await);
    let error = Router::new(&json!({
        "outbounds": [{"type": "direct", "tag": "hit"}],
        "route": {"rules": [{"domain_regex": ["(unclosed"], "outbound": "hit"}]}
    }))
    .err()
    .expect("bad route regex");
    assert!(
        format!("{error:#}").contains("parse expression 0"),
        "{error:#}"
    );
}

#[tokio::test]
async fn regex_joins_the_domain_group_and_other_groups_are_anded() {
    // same group as domain / suffix / keyword / ip_cidr: any of them is enough
    let router = inline(json!([{
        "domain": ["exact.test"],
        "domain_suffix": ["suf.test"],
        "domain_keyword": ["kw"],
        "domain_regex": ["^re[0-9]+\\.test$"],
        "ip_cidr": ["10.0.0.0/8"]
    }]));
    for host in ["exact.test", "x.suf.test", "akwb.test", "re42.test"] {
        assert!(hits(&router, domain(host, 443)).await, "{host}");
    }
    assert!(hits(&router, ip("10.1.2.3", 443)).await);
    assert!(!hits(&router, domain("rex.test", 443)).await);
    assert!(!hits(&router, ip("8.8.8.8", 443)).await);

    // a port group is ANDed with the domain group
    let router = inline(json!([{"domain_regex": [REGEX], "port": [443]}]));
    assert!(hits(&router, domain("foo.example", 443)).await);
    assert!(!hits(&router, domain("foo.example", 80)).await);
    assert!(!hits(&router, domain("bar.test", 443)).await);
    assert!(!hits(&router, ip("8.8.8.8", 443)).await);

    // and so are network and source address
    let router = inline(json!([{
        "domain_regex": [REGEX],
        "network": ["tcp"],
        "source_ip_cidr": ["10.0.0.0/8"]
    }]));
    assert!(hits(&router, domain("foo.example", 443)).await);
    let mut udp = domain("foo.example", 443);
    udp.network = "udp";
    assert!(!hits(&router, udp).await);
    let mut outside = domain("foo.example", 443);
    outside.source = "192.0.2.1:1234".parse().expect("source");
    assert!(!hits(&router, outside).await);
    assert!(!hits(&router, domain("bar.test", 443)).await);
}

#[tokio::test]
async fn regex_with_invert_and_logical_rules() {
    let router = inline(json!([{"invert": true, "domain_regex": [REGEX]}]));
    assert!(!hits(&router, domain("foo.example", 443)).await);
    assert!(hits(&router, domain("bar.test", 443)).await);
    // no domain: the regex misses, so the inverted rule matches
    assert!(hits(&router, ip("8.8.8.8", 443)).await);

    let router = inline(json!([{"type": "logical", "mode": "or", "rules": [
        {"domain_regex": [REGEX]},
        {"ip_cidr": ["192.0.2.0/24"]}
    ]}]));
    assert!(hits(&router, domain("foo.example", 443)).await);
    assert!(hits(&router, ip("192.0.2.5", 443)).await);
    assert!(!hits(&router, domain("bar.test", 443)).await);
    assert!(!hits(&router, ip("8.8.8.8", 443)).await);

    let router = inline(json!([{"type": "logical", "mode": "and", "rules": [
        {"domain_regex": ["^foo"]},
        {"domain_suffix": ["example"]}
    ]}]));
    assert!(hits(&router, domain("foo.example", 443)).await);
    assert!(!hits(&router, domain("bar.example", 443)).await);
    assert!(!hits(&router, domain("foo.test", 443)).await);
    assert!(!hits(&router, ip("8.8.8.8", 443)).await);

    let router = inline(
        json!([{"type": "logical", "mode": "and", "invert": true, "rules": [
            {"domain_regex": ["^foo"]},
            {"domain_suffix": ["example"]}
        ]}]),
    );
    assert!(!hits(&router, domain("foo.example", 443)).await);
    assert!(hits(&router, domain("bar.example", 443)).await);
    assert!(hits(&router, ip("8.8.8.8", 443)).await);
}

/// The same rules from a JSON source file and from an SRS file.
#[tokio::test]
async fn regex_from_source_and_binary_files() {
    let source = json!({"version": 3, "rules": [
        {"domain_regex": [REGEX]},
        {"domain_regex": ["^re[0-9]+\\.test$"], "port": [443]}
    ]});
    let json_file = TempFile::new("set.json", source.to_string().as_bytes());
    let srs_file = TempFile::new(
        "set.srs",
        &core_config::srs::compile(&source, 3).expect("compile srs"),
    );
    for (format, file) in [("source", &json_file), ("binary", &srs_file)] {
        let router = router_with(json!({
            "type": "local", "tag": "set", "format": format, "path": file.path()
        }))
        .expect("router");
        assert!(hits(&router, domain("foo.example", 80)).await, "{format}");
        assert!(hits(&router, domain("re7.test", 443)).await, "{format}");
        assert!(!hits(&router, domain("re7.test", 80)).await, "{format}");
        assert!(!hits(&router, domain("bar.test", 443)).await, "{format}");
        assert!(!hits(&router, ip("8.8.8.8", 443)).await, "{format}");
    }
}

/// Cases checked with sing-box 1.14.3 `rule-set match` (source and binary
/// gave the same answers). Its queries carry no port, network or source, so
/// these contexts use port 0.
#[tokio::test]
async fn regex_answers_agree_with_reference_rule_set_match() {
    let queries = [
        "foo.example",
        "bar.test",
        "FOO.EXAMPLE",
        "sub.foo.example",
        "re42.test",
        "exact.test",
        "x.suf.test",
        "akwb.test",
        "foo.example.org",
        "10.1.2.3",
        "192.0.2.5",
        "8.8.8.8",
    ];
    let table: [(Value, [u8; 12]); 10] = [
        (
            json!({"domain_regex": [REGEX]}),
            [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            json!({"domain": ["exact.test"], "domain_regex": ["^re[0-9]+\\.test$"]}),
            [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        ),
        (
            json!({"domain_suffix": ["suf.test"], "domain_keyword": ["kw"], "domain_regex": [REGEX]}),
            [1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        ),
        (
            json!({"domain_regex": [REGEX], "ip_cidr": ["10.0.0.0/8"]}),
            [1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        ),
        (
            json!({"invert": true, "domain_regex": [REGEX]}),
            [0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        ),
        (
            json!({"type": "logical", "mode": "or", "rules": [
                {"domain_regex": [REGEX]}, {"ip_cidr": ["192.0.2.0/24"]}
            ]}),
            [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        ),
        (
            json!({"type": "logical", "mode": "and", "rules": [
                {"domain_regex": ["^foo"]}, {"domain_suffix": ["example"]}
            ]}),
            [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (json!({"domain_regex": [REGEX], "port": [443]}), [0; 12]),
        // an upper-case pattern never sees an upper-case host
        (json!({"domain_regex": ["FOO"]}), [0; 12]),
        (
            json!({"type": "logical", "mode": "and", "invert": true, "rules": [
                {"domain_regex": ["^foo"]}, {"domain_suffix": ["example"]}
            ]}),
            [0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        ),
    ];
    for (rule, expected) in table {
        let source = json!({"version": 3, "rules": [rule.clone()]});
        let srs_file = TempFile::new(
            "ref.srs",
            &core_config::srs::compile(&source, 3).expect("compile srs"),
        );
        let routers = [
            ("inline", inline(json!([rule.clone()]))),
            (
                "binary",
                router_with(json!({
                    "type": "local", "tag": "set", "format": "binary", "path": srs_file.path()
                }))
                .expect("router"),
            ),
        ];
        for (query, want) in queries.iter().zip(expected) {
            let ctx = || match query.parse::<std::net::IpAddr>() {
                Ok(_) => ip(query, 0),
                Err(_) => domain(query, 0),
            };
            assert_eq!(
                match_rule(&rule, &ctx()),
                want == 1,
                "interpreter {rule} {query}"
            );
            for (kind, router) in &routers {
                assert_eq!(
                    hits(router, ctx()).await,
                    want == 1,
                    "{kind} {rule} {query}"
                );
            }
        }
    }
}

#[test]
fn invalid_regex_is_a_load_error() {
    let bad = json!([{"domain": ["ok.test"]}, {"domain_regex": ["(unclosed"]}]);
    let error = router_with(json!({"type": "inline", "tag": "set", "rules": bad}))
        .err()
        .expect("inline set with a bad regex");
    let text = format!("{error:#}");
    assert!(
        text.contains("parse rule_set.rules.[1]: domain_regex: parse expression 0"),
        "{text}"
    );

    // nested in a logical rule, from a source file and from an SRS file
    let source = json!({"version": 3, "rules": [{"type": "logical", "mode": "or", "rules": [
        {"domain": ["ok.test"]},
        {"domain_regex": ["(unclosed"]}
    ]}]});
    let json_file = TempFile::new("bad.json", source.to_string().as_bytes());
    let srs_file = TempFile::new(
        "bad.srs",
        &core_config::srs::compile(&source, 3).expect("compile srs"),
    );
    for (format, file) in [("source", &json_file), ("binary", &srs_file)] {
        let entry = json!({"type": "local", "tag": "set", "format": format, "path": file.path()});
        let error = router_with(entry.clone()).err().expect(format);
        let text = format!("{error:#}");
        assert!(
            text.contains(
                "parse rule_set.rules.[0]: sub rule[1]: domain_regex: parse expression 0"
            ),
            "{format}: {text}"
        );
        // `check` reports it too
        let config = json!({
            "outbounds": [{"type": "direct", "tag": "hit"}],
            "route": {
                "rule_set": [entry],
                "rules": [{"rule_set": ["set"], "outbound": "hit"}]
            }
        });
        let error = core_config::check_str(&config.to_string()).expect_err(format);
        assert!(
            error.contains("initialize router: parse rule-set[0]: parse rule_set.rules.[0]: sub rule[1]: domain_regex: parse expression 0: error parsing regexp"),
            "{format}: {error}"
        );
    }
    let config = json!({
        "outbounds": [{"type": "direct", "tag": "hit"}],
        "route": {
            "rule_set": [{"type": "inline", "tag": "set", "rules": bad}],
            "rules": [{"rule_set": ["set"], "outbound": "hit"}]
        }
    });
    let error = core_config::check_str(&config.to_string()).expect_err("inline");
    assert!(
        error.contains("initialize router: parse rule-set[0]: parse rule_set.rules.[1]: domain_regex: parse expression 0: error parsing regexp"),
        "{error}"
    );
}

/// Serves the bodies in order, then the last one forever.
async fn serve_in_order(bodies: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let mut served = 0usize;
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut head = [0u8; 1024];
            let _ = stream.read(&mut head).await;
            let body = &bodies[served.min(bodies.len() - 1)];
            served += 1;
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            let _ = stream.write_all(&response).await;
            let _ = stream.flush().await;
        }
    });
    (format!("http://{addr}/rules.json"), handle)
}

#[tokio::test]
async fn remote_update_with_regex_and_a_bad_update_keeps_the_set() {
    use core_runtime::http_client::HttpClient;
    use core_runtime::route::rule_set_remote::{RemoteRuleSet, RemoteSpec};

    let source = |regex: &str| {
        json!({"version": 3, "rules": [{"domain_regex": [regex]}]})
            .to_string()
            .into_bytes()
    };
    let srs = core_config::srs::compile(
        &json!({"version": 3, "rules": [{"domain_regex": ["^srs\\.example$"]}]}),
        3,
    )
    .expect("compile srs");
    let (url, server) = serve_in_order(vec![
        source(REGEX),
        source("(unclosed"),
        srs,
        source("^bar\\.test$"),
    ])
    .await;
    let router = Router::new(&json!({
        "log": {"level": "error"},
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }))
    .expect("router");
    let tags = vec!["remote".to_string()];
    let set = Arc::new(RuleSet::new(tags.clone(), Vec::new()).expect("rule set"));
    let mut remote = RemoteRuleSet {
        tags,
        spec: RemoteSpec {
            url,
            initial_path: None,
            update_interval: Duration::ZERO,
            client: HttpClient::default(),
            format: None,
            mmap: false,
            delta_update: false,
            cache_interval: Duration::ZERO,
            cache_file: None,
            mode: core_runtime::route::mmap_set::MmapMode::Auto,
        },
        set: Arc::clone(&set),
        etag: None,
        last_updated: None,
    };

    remote
        .fetch(&router, true, None)
        .await
        .expect("first fetch");
    assert!(set.matches(&domain("foo.example", 443)));
    assert!(!set.matches(&domain("bar.test", 443)));
    assert!(!set.matches(&ip("8.8.8.8", 443)));
    let updated = remote.last_updated;

    // a set that does not compile: the update fails, the old rules stay
    let error = remote.fetch(&router, false, None).await.unwrap_err();
    assert!(error.to_string().contains("domain_regex"), "{error}");
    assert!(set.matches(&domain("foo.example", 443)));
    assert!(!set.matches(&domain("bar.test", 443)));
    assert_eq!(remote.last_updated, updated);

    // binary updates are compiled the same way
    remote.fetch(&router, false, None).await.expect("srs fetch");
    assert!(set.matches(&domain("srs.example", 443)));
    assert!(!set.matches(&domain("foo.example", 443)));
    assert!(!set.matches(&ip("8.8.8.8", 443)));

    remote
        .fetch(&router, false, None)
        .await
        .expect("next fetch");
    assert!(set.matches(&domain("bar.test", 443)));
    assert!(!set.matches(&domain("srs.example", 443)));
    server.abort();
}
