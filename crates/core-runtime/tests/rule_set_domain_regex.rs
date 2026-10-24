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

/// Go's `\Q...\E` literal spans. Expected answers from sing-box 1.14.3
/// `rule-set match` (it lowercases the host first).
const GO_QUOTES: &[(&str, &str, bool)] = &[
    (r"^\Qa.b\E$", "a.b", true),
    (r"^\Qa.b\E$", "axb", false),
    (r"^\Qa.b\E$", "a.b.c", false),
    // unterminated: the span runs to the end of the pattern
    (r"^\Qa.b", "a.b", true),
    (r"^\Qa.b", "axb", false),
    (r"^\Qa.b", "a.bc", true),
    (r"\Qa.b\E\.c$", "a.b.c", true),
    (r"\Qa.b\E\.c$", "a.bxc", false),
    (r"\Qa.b\E\.c$", "xa.b.c", true),
    // backslashes inside the span are literal; the first \E ends it
    (r"^\Qa\b\E", r"a\b", true),
    (r"^\Qa\b\E", "ab", false),
    (r"^\Qa\\E", r"a\", true),
    (r"^\Qa\\E", "a", false),
    // an escaped backslash, then a quoted span
    (r"^\\\Qa.\E", r"\a.", true),
    (r"^\\\Qa.\E", r"\ax", false),
    (r"^\\\Qa.\E", "a.", false),
    // a repeat applies to the last quoted character only
    (r"^\Qa*\E+$", "a*", true),
    (r"^\Qa*\E+$", "a***", true),
    (r"^\Qa*\E+$", "aa*", false),
    (r"^(\Qa.\E)+$", "a.a.", true),
    (r"^(\Qa.\E)+$", "a.a", false),
    (r"^a\Q\E*$", "aaa", true),
    (r"(?i)^\QFOO.\E", "foo.x", true),
    (r"(?i)^\QFOO.\E", "fooxx", false),
    (r"(?i)\Qa.B\E", "xA.b", true),
    (r"(?i)\Qa.B\E", "xaxb", false),
    (r"^\Q[a-z]\E$", "[a-z]", true),
    (r"^\Q[a-z]\E$", "b", false),
    (r"^\Qa|b\E$", "a|b", true),
    (r"^\Qa|b\E$", "a", false),
    (r"^\Q(\E", "(x", true),
    (r"^\Q(\E", "x", false),
    (r"\Q$\E$", "a$", true),
    (r"\Q$\E$", "a", false),
    (r"^\Q a\E$", " a", true),
    (r"^\Q a\E$", "a", false),
    (r"^\Q#x\E$", "#x", true),
    (r"^\Qé.\E", "é.x", true),
    (r"^\Qé.\E", "éxx", false),
];

#[tokio::test]
async fn go_quoted_literals_match_like_the_reference() {
    for (pattern, host, expected) in GO_QUOTES {
        let rule = json!({"domain_regex": [pattern]});
        assert_eq!(
            match_rule(&rule, &domain(host, 443)),
            *expected,
            "interpreter {pattern} {host}"
        );
        let set = inline(json!([rule]));
        assert_eq!(
            hits(&set, domain(host, 443)).await,
            *expected,
            "rule set {pattern} {host}"
        );
        let route = Router::new(&json!({
            "log": {"level": "error"},
            "outbounds": [{"type": "direct", "tag": "hit"}, {"type": "direct", "tag": "miss"}],
            "route": {"final": "miss", "rules": [{"domain_regex": [pattern], "outbound": "hit"}]}
        }))
        .expect("router");
        assert_eq!(
            hits(&route, domain(host, 443)).await,
            *expected,
            "route rule {pattern} {host}"
        );
    }
}

#[test]
fn go_quoted_literals_pass_check_and_bad_escapes_fail() {
    let config = |regex: &str| {
        json!({
            "dns": {
                "servers": [{"type": "local", "tag": "local"}],
                "rules": [{"domain_regex": [regex], "server": "local"}]
            },
            "outbounds": [{"type": "direct", "tag": "hit"}],
            "route": {
                "rule_set": [{"type": "inline", "tag": "set", "rules": [{"domain_regex": [regex]}]}],
                "rules": [
                    {"domain_regex": [regex], "outbound": "hit"},
                    {"rule_set": ["set"], "outbound": "hit"}
                ]
            }
        })
        .to_string()
    };
    for (pattern, _, _) in GO_QUOTES {
        core_config::check_str(&config(pattern)).unwrap_or_else(|err| panic!("{pattern}: {err}"));
    }
    // rejected by the reference too: \Q inside a class, a stray \E
    for pattern in [r"^[\Q]", r"^x\E"] {
        let error = core_config::check_str(&config(pattern)).expect_err(pattern);
        assert!(error.contains("parse expression 0"), "{pattern}: {error}");
        assert!(
            router_with(
                json!({"type": "inline", "tag": "set", "rules": [{"domain_regex": [pattern]}]})
            )
            .is_err(),
            "{pattern}"
        );
    }
}

/// Rule shapes the flat TSRS tables cannot hold. Each with connections it
/// must and must not match, as the in-memory matcher answers them.
fn tsrs_lossy_cases() -> Vec<(Value, Vec<ConnContext>, Vec<ConnContext>)> {
    let mut udp = domain("s.com", 443);
    udp.network = "udp";
    let mut lan = ip("10.1.1.1", 443);
    lan.source = "192.168.1.2:1234".parse().expect("source");
    vec![
        (
            json!({"domain_regex": [REGEX]}),
            vec![domain("foo.example", 443)],
            vec![domain("bar.test", 443), ip("8.8.8.8", 443)],
        ),
        (
            json!({"invert": true, "domain": ["a.com"]}),
            vec![domain("b.com", 443), ip("8.8.8.8", 443)],
            vec![domain("a.com", 443)],
        ),
        (
            json!({"type": "logical", "mode": "or", "rules": [{"domain": ["l.com"]}, {"port": [8080]}]}),
            vec![domain("l.com", 80), domain("x.test", 8080)],
            vec![domain("x.test", 443)],
        ),
        (
            json!({"domain": ["and.com"], "port": [443]}),
            vec![domain("and.com", 443)],
            vec![domain("and.com", 80), domain("x.test", 443)],
        ),
        (
            json!({"domain_suffix": ["s.com"], "network": ["udp"]}),
            vec![udp],
            vec![domain("s.com", 443)],
        ),
        (
            json!({"ip_cidr": ["10.0.0.0/8"], "source_ip_cidr": ["192.168.0.0/16"]}),
            vec![lan],
            vec![ip("10.1.1.1", 443)],
        ),
        (
            json!({"source_port": [1234]}),
            vec![domain("x.test", 443)],
            vec![],
        ),
    ]
}

#[tokio::test]
async fn mmap_sets_with_rules_tsrs_cannot_hold_stay_in_memory() {
    for (n, (rule, hit, miss)) in tsrs_lossy_cases().into_iter().enumerate() {
        let source = json!({"version": 3, "rules": [rule.clone()]});
        let json_file = TempFile::new("lossy.json", source.to_string().as_bytes());
        let srs_file = TempFile::new(
            "lossy.srs",
            &core_config::srs::compile(&source, 3).expect("compile srs"),
        );
        let cache = TempFile::new("lossy.tsrs", b"");
        let _ = std::fs::remove_file(&cache.0);
        let entries = [
            json!({"type": "inline", "tag": "set", "rules": [rule.clone()], "mmap": true, "cache_file": cache.path()}),
            json!({"type": "local", "tag": "set", "format": "source", "path": json_file.path(), "mmap": true, "cache_file": cache.path()}),
            json!({"type": "local", "tag": "set", "format": "binary", "path": srs_file.path(), "mmap": true, "cache_file": cache.path()}),
        ];
        for entry in entries {
            let router = router_with(entry.clone()).expect("router");
            for ctx in &hit {
                let ctx = ctx.clone();
                assert!(hits(&router, ctx).await, "{n} {entry} must match");
            }
            for ctx in &miss {
                let ctx = ctx.clone();
                assert!(!hits(&router, ctx).await, "{n} {entry} must not match");
            }
            assert!(!cache.0.exists(), "{n} {entry} was compiled to TSRS");
        }
    }

    // a set TSRS can hold is still compiled to it
    let cache = TempFile::new("plain.tsrs", b"");
    let _ = std::fs::remove_file(&cache.0);
    let router = router_with(json!({
        "type": "inline", "tag": "set", "rules": [{"domain": ["plain.com"]}, {"port": [8443]}],
        "mmap": true, "cache_file": cache.path()
    }))
    .expect("router");
    assert!(cache.0.exists(), "plain set not compiled to TSRS");
    assert!(hits(&router, domain("plain.com", 443)).await);
    assert!(hits(&router, domain("x.test", 8443)).await);
    assert!(!hits(&router, domain("x.test", 443)).await);
}

fn remote_set(
    url: String,
    cache_file: &TempFile,
    initial_path: Option<String>,
) -> core_runtime::route::rule_set_remote::RemoteRuleSet {
    use core_runtime::http_client::HttpClient;
    use core_runtime::route::rule_set_remote::{RemoteRuleSet, RemoteSpec};
    let tags = vec!["remote".to_string()];
    RemoteRuleSet {
        tags: tags.clone(),
        spec: RemoteSpec {
            url,
            initial_path,
            update_interval: Duration::ZERO,
            client: HttpClient::default(),
            format: None,
            mmap: true,
            delta_update: false,
            cache_interval: Duration::ZERO,
            cache_file: Some(cache_file.path()),
            mode: core_runtime::route::mmap_set::MmapMode::Auto,
        },
        set: Arc::new(RuleSet::new(tags, Vec::new()).expect("rule set")),
        etag: None,
        last_updated: None,
    }
}

#[tokio::test]
async fn remote_mmap_set_with_regex_stays_in_memory() {
    use core_runtime::cache_file::{CacheFile, CacheFileOptions};
    use core_runtime::route::mmap_set::RuleSetCompiler;

    let regex_rules = json!({"version": 3, "rules": [{"domain_regex": [REGEX]}]});
    let plain_rules = json!({"version": 3, "rules": [{"domain": ["plain.com"]}]});
    let (url, server) = serve_in_order(vec![
        regex_rules.to_string().into_bytes(),
        plain_rules.to_string().into_bytes(),
        regex_rules.to_string().into_bytes(),
    ])
    .await;
    let router = Router::new(&json!({
        "log": {"level": "error"},
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }))
    .expect("router");
    let tsrs = TempFile::new("remote.tsrs", b"");
    // a TSRS left by an earlier build of this regex set
    std::fs::write(
        &tsrs.0,
        RuleSetCompiler::new()
            .compile(&[json!({"domain_regex": [REGEX]})])
            .expect("tsrs"),
    )
    .expect("write tsrs");
    let db = TempFile::new("cache.db", b"");
    let _ = std::fs::remove_file(&db.0);
    let cache = Arc::new(std::sync::Mutex::new(
        CacheFile::open(CacheFileOptions {
            enabled: true,
            path: db.path(),
            ..CacheFileOptions::default()
        })
        .expect("open cache")
        .expect("cache enabled"),
    ));

    let mut remote = remote_set(url.clone(), &tsrs, None);
    remote
        .fetch(&router, true, Some(&cache))
        .await
        .expect("fetch");
    assert!(remote.set.mmap().is_none(), "regex set compiled to TSRS");
    assert!(
        !tsrs.0.exists(),
        "the stale TSRS is left for the next start"
    );
    assert!(remote.set.matches(&domain("foo.example", 443)));
    assert!(!remote.set.matches(&domain("bar.test", 443)));
    assert!(!remote.set.matches(&ip("8.8.8.8", 443)));

    // a set TSRS can hold still goes to mmap
    remote
        .fetch(&router, false, Some(&cache))
        .await
        .expect("plain fetch");
    assert!(remote.set.mmap().is_some(), "plain set not mmapped");
    assert!(remote.set.matches(&domain("plain.com", 443)));
    assert!(tsrs.0.exists());

    // and back to memory, removing the TSRS again
    remote
        .fetch(&router, false, Some(&cache))
        .await
        .expect("regex fetch");
    assert!(remote.set.mmap().is_none());
    assert!(!tsrs.0.exists());
    server.abort();

    // restart (same URL, server gone): no TSRS, so the cache restores the
    // regex set into memory
    let mut restarted = remote_set(url, &tsrs, None);
    restarted
        .start(&router, Some(&cache))
        .await
        .expect("restore");
    assert!(restarted.set.mmap().is_none());
    assert!(restarted.set.matches(&domain("foo.example", 443)));
    assert!(!restarted.set.matches(&domain("bar.test", 443)));

    // an initial path with a regex set loads into memory as well
    let initial = TempFile::new("initial.json", regex_rules.to_string().as_bytes());
    let mut first = remote_set(
        "http://127.0.0.1:1/rules.json".into(),
        &tsrs,
        Some(initial.path()),
    );
    first.start(&router, None).await.expect("initial path");
    assert!(first.set.mmap().is_none());
    assert!(!tsrs.0.exists());
    assert!(first.set.matches(&domain("foo.example", 443)));
    assert!(!first.set.matches(&domain("bar.test", 443)));
}
