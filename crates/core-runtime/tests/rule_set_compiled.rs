//! The compiled index must answer exactly what the old interpreter answered.
//!
//! `RuleSet` used to be `Vec<Value>` walked per connection, and `match_rule` is
//! still there -- now only for `logical` and `invert` rules. So the strongest
//! possible guard is to run both over the same corpus and demand agreement: the
//! interpreter is the oracle, not a hand-written expectation. Every semantic slip
//! in flattening rules into shared pools shows up here as a disagreement.

use std::net::SocketAddr;

use core_runtime::inbound::Target;
use core_runtime::route::ConnContext;
use core_runtime::route::rule_set::{RuleSet, match_rule};
use serde_json::{Value, json};

/// Every field the reference's headless rules carry, plus the shapes that must
/// *not* be flattened: `logical`, `invert`, and values no parser accepts.
fn corpus() -> Vec<Value> {
    vec![
        json!({"domain": ["a.com"]}),
        json!({"domain": "single-string.com"}),
        json!({"domain": []}),
        json!({"domain": [1, 2, "mixed.com"]}),
        json!({"domain_suffix": ["example.com"]}),
        json!({"domain_suffix": ["a.com"]}),
        json!({"domain_suffix": [".com"]}),
        json!({"domain_suffix": [".a.com"]}),
        json!({"domain_suffix": [""]}),
        json!({"domain_keyword": ["ads", "tracker"]}),
        json!({"domain_keyword": []}),
        json!({"ip_cidr": ["10.0.0.0/8"]}),
        json!({"ip_cidr": ["192.168.1.0/24", "0.0.0.0/0"]}),
        json!({"ip_cidr": ["2001:db8::/32"]}),
        json!({"ip_cidr": ["10.0.0.0"]}),
        json!({"ip_cidr": ["10.0.0.0/notanumber"]}),
        json!({"ip_cidr": ["10.0.0.0/33"]}),
        json!({"ip_cidr": ["2001:db8::/200"]}),
        json!({"ip_cidr": [123]}),
        json!({"source_ip_cidr": ["10.0.0.0/8"]}),
        json!({"source_ip_cidr": ["0.0.0.0/0"]}),
        json!({"port": [80, 443]}),
        json!({"port": 8443}),
        json!({"port": "9999"}),
        json!({"port": [70000]}),
        json!({"port_range": ["8000-9000"]}),
        json!({"port_range": ["100-200", "bad", "300-"]}),
        json!({"source_port": [1234]}),
        json!({"source_port_range": ["1000-2000"]}),
        json!({"network": ["tcp"]}),
        json!({"network": ["udp"]}),
        json!({"network": ["tcp", "udp"]}),
        // Destination fields OR together; source/port/network restrictions
        // require a separate compiled fallback to preserve conjunction.
        json!({"domain": ["multi.com"], "port": [443], "network": ["tcp"]}),
        json!({"domain": ["split.com"], "ip_cidr": ["10.1.0.0/16"]}),
        json!({"domain_regex": ["^cdn\\.a\\.com$", "track"]}),
        json!({"domain_regex": ["^nota"], "port": [443]}),
        json!({"domain_regex": ["^a\\.com$"], "invert": true}),
        // Not flattenable.
        json!({"invert": true, "domain": ["inverted.com"]}),
        json!({"invert": false, "domain": ["plain-invert-flag.com"]}),
        json!({"type": "logical", "mode": "or", "rules": [
            {"domain": ["logical-or.com"]},
            {"port": [8080]}
        ]}),
        json!({"type": "logical", "mode": "and", "rules": [
            {"domain": ["logical-and.com"]},
            {"port": [443]}
        ]}),
        json!({"type": "logical", "mode": "and", "rules": []}),
        json!({"type": "logical"}),
        // The tree shapes: invert on the logical node itself, a logical rule
        // inside a logical rule, an inverted sub-rule, and a sub-rule that is
        // not an object at all.
        json!({"type": "logical", "mode": "or", "invert": true, "rules": [
            {"domain": ["inverted-logical.com"]},
            {"port": [9999]}
        ]}),
        json!({"type": "logical", "mode": "and", "rules": [
            {"type": "logical", "mode": "or", "rules": [
                {"domain": ["nested.com"]},
                {"port": [8443]}
            ]},
            {"invert": true, "domain": ["never-nested.com"]}
        ]}),
        json!({"type": "logical", "mode": "or", "rules": [
            "not-an-object",
            {"domain": ["sub-with-junk.com"]}
        ]}),
        json!({"type":"logical","mode":"and","rules":[null,{"domain":"a.com"}]}),
        json!({"type":"logical","mode":"or","invert":true,"rules":[null,{"domain":"a.com"}]}),
        json!({}),
        json!({"unknown_field": ["ignored.com"]}),
        Value::String("not-an-object".into()),
        Value::Null,
        Value::Array(vec![]),
    ]
}

/// A connection to test against. `domain` sets the destination when `ip` is
/// `None`, and is also the sniffed name in that case -- which is how the
/// reference prefers it.
fn context(
    domain: Option<&str>,
    ip: Option<&str>,
    port: u16,
    source: &str,
    network: &'static str,
) -> ConnContext {
    ConnContext::new(
        "mixed-in",
        source.parse::<SocketAddr>().expect("source"),
        match ip {
            Some(ip) => Target::Ip(ip_target(ip, port)),
            None => Target::Domain(domain.expect("a domain or an ip").to_string(), port),
        },
        network,
    )
}

/// `SocketAddr` from a bare address and a port, bracketing IPv6.
fn ip_target(address: &str, port: u16) -> SocketAddr {
    let literal = if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    };
    literal.parse().expect("ip target")
}

fn contexts() -> Vec<ConnContext> {
    let mut out = Vec::new();

    // Domains, including the cases that separate a label boundary from a string
    // suffix, and the bare domain against its own parent.
    for host in [
        "a.com",
        "cdn.a.com",
        "deep.cdn.a.com",
        "nota.com",
        "xa.com",
        "single-string.com",
        "sub.single-string.com",
        "example.com",
        "cdn.example.com",
        "com",
        "mixed.com",
        "ads.example.net",
        "tracker.net",
        "no-ads-here.org",
        "logical-or.com",
        "logical-and.com",
        "inverted.com",
        "not-inverted.com",
        "plain-invert-flag.com",
        "multi.com",
        "split.com",
        "ignored.com",
        "UPPER.COM",
        "MiXeD.example.com",
        "inverted-logical.com",
        "nested.com",
        "never-nested.com",
        "sub-with-junk.com",
    ] {
        out.push(context(Some(host), None, 443, "10.0.0.2:1234", "tcp"));
        out.push(context(Some(host), None, 80, "192.168.1.50:5000", "udp"));
    }
    // Sniffed domain over an IP destination: the case that catches `ip_cidr`
    // being consulted for a domain target.
    let mut sniffed = context(None, Some("203.0.113.9"), 443, "10.0.0.2:1234", "tcp");
    sniffed.domain = Some("a.com".into());
    out.push(sniffed);

    // IP targets, v4 and v6, across the prefixes above.
    for ip in [
        "10.0.0.1",
        "10.255.255.254",
        "192.168.1.7",
        "203.0.113.9",
        "8.8.8.8",
        "0.0.0.0",
        "255.255.255.255",
        "2001:db8::1",
        "2001:db9::1",
        "::1",
    ] {
        out.push(context(None, Some(ip), 443, "10.0.0.2:1234", "tcp"));
        out.push(context(None, Some(ip), 8080, "203.0.113.1:1", "udp"));
    }
    // Source address and source port driven.
    for source in [
        "10.0.0.2:1234",
        "203.0.113.1:1",
        "10.0.0.2:1500",
        "8.8.8.8:65535",
    ] {
        out.push(context(Some("a.com"), None, 443, source, "tcp"));
    }
    // Port driven.
    for port in [80u16, 443, 3000, 8000, 8500, 9000, 9001, 8080, 8443, 9999] {
        out.push(context(Some("a.com"), None, port, "10.0.0.2:1234", "tcp"));
    }
    out
}

/// The invariant: one rule set holding the whole corpus must answer the same as
/// the interpreter answering rule by rule.
#[test]
fn compiled_index_agrees_with_the_interpreter() {
    let rules = corpus();
    let set = RuleSet::new(vec!["corpus".into()], rules.clone()).expect("rule set");
    let cases = contexts();

    let mut checked = 0usize;
    for ctx in &cases {
        let expected = rules.iter().any(|rule| match_rule(rule, ctx));
        let actual = set.matches(ctx);
        assert_eq!(
            actual, expected,
            "disagreement on {:?} -> {:?}\n  rule: {:?}",
            ctx.destination, ctx.network, ctx.domain,
        );
        checked += 1;
    }
    assert!(
        checked >= 80,
        "the corpus is too small to mean anything: {checked}"
    );
}

/// Same corpus, but one rule per set: the shape an SRS domain list actually has,
/// and the shape where flattening is worth the most.
#[test]
fn one_rule_per_set_agrees_with_the_interpreter() {
    let rules = corpus();
    let cases = contexts();
    for (at, rule) in rules.iter().enumerate() {
        let set = RuleSet::new(vec!["one".into()], vec![rule.clone()]).expect("rule set");
        for ctx in &cases {
            assert_eq!(
                set.matches(ctx),
                match_rule(rule, ctx),
                "rule {at} ({rule}) disagrees on {:?} -> {:?}",
                ctx.destination,
                ctx.network
            );
        }
    }
}

/// Prefixes must behave at the edges, including the two the old code got wrong
/// or only got right by accident.
#[test]
fn prefix_edges() {
    let set = RuleSet::new(
        vec!["cidr".into()],
        vec![
            json!({"ip_cidr": ["10.0.0.0/8"]}),
            json!({"ip_cidr": ["192.168.1.0/24"]}),
            json!({"ip_cidr": ["172.16.0.0/12"]}),
            json!({"ip_cidr": ["2001:db8::/32"]}),
        ],
    )
    .expect("rule set");

    let all = RuleSet::new(
        vec!["all".into()],
        vec![
            json!({"ip_cidr": ["0.0.0.0/0"]}),
            json!({"ip_cidr": ["::/0"]}),
        ],
    )
    .expect("rule set");

    let ip = |addr: &str, port: u16| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Ip(ip_target(addr, port)),
            "tcp",
        )
    };

    // /0 matched everything in release and panicked in debug: the old code
    // computed `u32::MAX << 32`.
    assert!(all.matches(&ip("8.8.8.8", 443)), "0.0.0.0/0 matches any v4");
    assert!(all.matches(&ip("2001:db8::1", 443)), "::/0 matches any v6");
    // Boundary of each prefix: first and last address inside, first outside.
    assert!(set.matches(&ip("10.0.0.0", 443)));
    assert!(set.matches(&ip("10.255.255.255", 443)));
    assert!(!set.matches(&ip("11.0.0.0", 443)), "11/8 is outside 10/8");
    assert!(set.matches(&ip("192.168.1.0", 443)));
    assert!(set.matches(&ip("192.168.1.255", 443)));
    assert!(!set.matches(&ip("192.168.2.0", 443)), "outside /24");
    assert!(set.matches(&ip("172.16.0.0", 443)));
    assert!(set.matches(&ip("172.31.255.255", 443)));
    assert!(!set.matches(&ip("172.32.0.0", 443)), "outside 172.16/12");
    assert!(set.matches(&ip("2001:db8::1", 443)));
    assert!(!set.matches(&ip("2001:db9::1", 443)), "outside 2001:db8/32");
    // A v4 prefix never matches a v6 address and the other way round.
    assert!(
        !set.matches(&ip("::1", 443)),
        "10/8 is not in ::/0's absence"
    );
}

/// `domain_suffix` is label-boundary, `".suffix"` is a plain string suffix. The
/// two differ on exactly one input and getting it backwards would leak every
/// `notexample.com` into an `example.com` rule.
#[test]
fn suffix_is_label_bounded_but_dot_suffix_is_not() {
    let bare = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain_suffix": ["example.com"]})],
    )
    .expect("rule set");
    let dotted = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain_suffix": [".example.com"]})],
    )
    .expect("rule set");
    let domain = |host: &str| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Domain(host.to_string(), 443),
            "tcp",
        )
    };

    assert!(bare.matches(&domain("example.com")), "the host itself");
    assert!(bare.matches(&domain("cdn.example.com")), "a child");
    assert!(
        !bare.matches(&domain("notexample.com")),
        "not a label boundary"
    );
    assert!(
        !bare.matches(&domain("example.com.evil.net")),
        "suffix, not prefix"
    );

    assert!(
        !dotted.matches(&domain("example.com")),
        "a dot suffix skips the bare host"
    );
    assert!(dotted.matches(&domain("cdn.example.com")));
    assert!(
        !dotted.matches(&domain("notexample.com")),
        "still label bounded"
    );
}

/// `invert` and `logical` must not be flattened: `invert` inverts the whole rule,
/// so merging it into shared pools would invert the wrong thing.
#[test]
fn inverted_and_logical_rules_stay_on_the_interpreter() {
    let inverted = RuleSet::new(
        vec!["s".into()],
        vec![json!({"invert": true, "domain": ["a.com"]})],
    )
    .expect("rule set");
    assert_eq!(inverted.fallback_count(), 1, "invert kept as a fallback");
    assert!(
        inverted.index().is_empty(),
        "and contributed no pool entries"
    );

    let logical = RuleSet::new(
        vec!["s".into()],
        vec![json!({"type": "logical", "mode": "or", "rules": [
            {"domain": ["a.com"]},
            {"port": [443]}
        ]})],
    )
    .expect("rule set");
    assert_eq!(logical.fallback_count(), 1, "logical kept as a fallback");
    assert!(logical.index().is_empty());

    let mixed = RuleSet::new(
        vec!["s".into()],
        vec![
            json!({"domain": ["pooled.com"]}),
            json!({"invert": true, "domain": ["never.com"]}),
        ],
    )
    .expect("rule set");
    assert_eq!(
        mixed.fallback_count(),
        1,
        "only the inverted one is kept back"
    );
    assert!(mixed.index().has_domain("pooled.com"));
    assert!(
        !mixed.index().has_domain("never.com"),
        "and it pooled nothing"
    );
}

/// An empty set, or one whose every entry was unparsable, must never match.
/// A bare `{}` is deliberately not on this list: it is a rule with no
/// criteria at all, the interpreter answers true for it, and `corpus` pins
/// that same answer.
#[test]
fn nothing_to_match_means_no_match() {
    for rules in [
        vec![],
        vec![json!({"domain": []})],
        vec![json!({"ip_cidr": ["nonsense"]})],
        vec![json!({"port_range": ["nonsense"]})],
        vec![Value::Null],
    ] {
        let set = RuleSet::new(vec!["s".into()], rules.clone()).expect("rule set");
        for ctx in contexts().iter().take(20) {
            assert!(
                !set.matches(ctx),
                "{rules:?} matched {:?} -> {:?}",
                ctx.destination,
                ctx.network
            );
        }
        assert_eq!(
            set.rule_count(),
            rules.len(),
            "rule_count still counts as loaded"
        );
    }
}

/// A matcher-free object is the interpreter's catch-all; an empty set is not.
#[test]
fn matcher_free_objects_preserve_catch_all_semantics() {
    for rule in [
        json!({}),
        json!({"unknown_field":"ignored"}),
        json!({"invert":true}),
    ] {
        let set = RuleSet::new(vec!["s".into()], vec![rule.clone()]).expect("rule set");
        assert_eq!(set.fallback_count(), 1);
        for ctx in contexts() {
            assert_eq!(set.matches(&ctx), match_rule(&rule, &ctx));
            assert_eq!(
                set.matches(&ctx),
                rule.get("invert") != Some(&Value::Bool(true))
            );
        }
    }
}

/// Stored domains keep their case and only the query is lowercased, which is
/// what the old code did: `domain_host` lowercases and the entries were compared
/// raw. The consequence is that a mixed-case entry can *never* match, because
/// every query arrives lowercased. That is inherited behaviour, kept here on
/// purpose -- deciding whether the reference matches case-insensitively belongs
/// in its own commit against the reference, not inside a performance change.
#[test]
fn stored_case_is_left_alone_and_the_query_is_lowered() {
    let set = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain": ["Mixed.Example.COM"]})],
    )
    .expect("rule set");
    let domain = |host: &str| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Domain(host.to_string(), 443),
            "tcp",
        )
    };
    // The query is lowered, the entry is not: no match, exactly as before.
    assert!(!set.matches(&domain("mixed.example.com")));
    assert!(!set.matches(&domain("Mixed.Example.COM")));
    assert!(!set.matches(&domain("MIXED.EXAMPLE.COM")));
    // The entry is stored verbatim, which `has_domain` shows.
    assert!(set.index().has_domain("Mixed.Example.COM"));

    // A lowercase entry does match, and does so case-insensitively on the query.
    let lower = RuleSet::new(
        vec!["s".into()],
        vec![json!({"domain": ["mixed.example.com"]})],
    )
    .expect("rule set");
    assert!(lower.matches(&domain("mixed.example.com")));
    assert!(lower.matches(&domain("Mixed.Example.COM")));
    assert!(lower.matches(&domain("MIXED.EXAMPLE.COM")));
}

/// A remote update swaps the compiled form wholesale, and the new one is what
/// answers immediately after.
#[test]
fn a_remote_update_replaces_the_compiled_form() {
    let set =
        RuleSet::new(vec!["s".into()], vec![json!({"domain": ["old.com"]})]).expect("rule set");
    let domain = |host: &str| {
        ConnContext::new(
            "mixed-in",
            "10.0.0.2:1234".parse().expect("source"),
            Target::Domain(host.to_string(), 443),
            "tcp",
        )
    };
    assert!(set.matches(&domain("old.com")));

    set.replace_rules(vec![
        json!({"domain": ["new.com"]}),
        json!({"domain_suffix": ["suffix.com"]}),
    ])
    .expect("rule set");
    assert!(!set.matches(&domain("old.com")), "the old entry is gone");
    assert!(set.matches(&domain("new.com")));
    assert!(set.matches(&domain("cdn.suffix.com")));
    assert_eq!(set.rule_count(), 2);
    assert_eq!(set.fallback_count(), 0);

    // And an update that empties the set empties the matching too.
    set.replace_rules(Vec::new()).expect("rule set");
    assert!(!set.matches(&domain("new.com")));
    assert_eq!(set.rule_count(), 0);
}

/// The pools must hold what went in, which is what `rule-set match` and the
/// remote-rule-set tests read.
#[test]
fn the_index_reports_what_it_holds() {
    let set = RuleSet::new(
        vec!["s".into()],
        vec![
            json!({"domain": ["a.com", "b.com"]}),
            json!({"domain_suffix": ["example.com", ".dot.com"]}),
            json!({"domain_keyword": ["ads"]}),
            json!({"ip_cidr": ["10.0.0.0/8"]}),
            json!({"port": [80, 443]}),
        ],
    )
    .expect("rule set");
    let index = set.index();
    assert_eq!(index.domain_count(), 2);
    assert!(index.has_domain("a.com") && index.has_domain("b.com"));
    assert!(!index.has_domain("c.com"));
    assert!(index.has_suffix("example.com"));
    assert!(
        index.has_suffix(".dot.com"),
        "a dot suffix is still a suffix"
    );
    assert!(index.has_keyword("cdn.ads.net"));
    assert!(!index.has_keyword("cdn.net"));
    assert!(index.has_prefix("10.1.2.3".parse().expect("ip"), 8));
    assert!(!index.has_prefix("11.1.2.3".parse().expect("ip"), 8));
    assert_eq!(index.len(), 2 + 2 + 1 + 1 + 2);
    assert_eq!(set.fallback_count(), 0);
    assert_eq!(set.rule_count(), 5);
    let outside = ConnContext::new(
        "in",
        "192.0.2.1:1234".parse().unwrap(),
        Target::Domain("outside-the-pools.test".into(), 443),
        "tcp",
    );
    assert!(
        set.matches(&outside),
        "the fallback's port 443 still matches"
    );
}

#[test]
fn discord_colon_tuple_matches_in_interpreter_and_compiled_paths() {
    for separator in [":", "-"] {
        let rule = json!({"network":"udp","ip_cidr":["104.16.0.0/12"],"port_range":[format!("19294{separator}19344")]});
        // Logical wrapping exercises the compiled fallback tree too.
        for entry in [
            rule.clone(),
            json!({"type":"logical","mode":"and","rules":[rule.clone()]}),
        ] {
            let set = RuleSet::new(vec!["discord".into()], vec![entry.clone()]).expect("rule set");
            for (ip, port, network, expected) in [
                ("104.29.155.207", 19314, "udp", true),
                ("104.29.155.207", 19294, "udp", true),
                ("104.29.155.207", 19344, "udp", true),
                ("104.29.155.207", 19293, "udp", false),
                ("104.29.155.207", 19345, "udp", false),
                ("105.29.155.207", 19314, "udp", false),
                ("104.29.155.207", 19314, "tcp", false),
            ] {
                let ctx = ConnContext::new(
                    "tproxy-in",
                    "192.168.90.201:40000".parse().unwrap(),
                    Target::Ip(format!("{ip}:{port}").parse().unwrap()),
                    network,
                );
                assert_eq!(
                    match_rule(&entry, &ctx),
                    expected,
                    "interpreter {entry} {ip}:{port}/{network}"
                );
                assert_eq!(
                    set.matches(&ctx),
                    expected,
                    "compiled {entry} {ip}:{port}/{network}"
                );
            }
        }
    }
    for (range, port, expected) in [
        (":100", 100, true),
        ("200:", 65535, true),
        ("200:100", 150, false),
        ("bad:100", 50, false),
        ("19294:19344:1", 19314, false),
    ] {
        let rule = json!({"source_port_range":[range]});
        let ctx = ConnContext::new(
            "tproxy-in",
            format!("192.168.90.201:{port}").parse().unwrap(),
            Target::Ip("104.29.155.207:19314".parse().unwrap()),
            "udp",
        );
        assert_eq!(match_rule(&rule, &ctx), expected);
        assert_eq!(
            RuleSet::new(vec!["source".into()], vec![rule])
                .expect("rule set")
                .matches(&ctx),
            expected
        );
    }
}

#[test]
fn mmap_compiler_accepts_colon_and_legacy_port_ranges() {
    use core_runtime::route::mmap_set::{MmapRuleSet, RuleSetCompiler};
    for (n, range) in ["19294:19344", "19294-19344"].iter().enumerate() {
        let path = std::env::temp_dir().join(format!(
            "rust-x-discord-port-{}-{n}.tsrs",
            std::process::id()
        ));
        let bytes = RuleSetCompiler::new()
            .compile(&[json!({"port_range":[range]})])
            .unwrap();
        std::fs::write(&path, bytes).unwrap();
        let set = MmapRuleSet::open(&path).unwrap();
        for (port, expected) in [
            (19293, false),
            (19294, true),
            (19314, true),
            (19344, true),
            (19345, false),
        ] {
            let ctx = ConnContext::new(
                "tproxy-in",
                "192.168.90.201:40000".parse().unwrap(),
                Target::Ip(format!("104.29.155.207:{port}").parse().unwrap()),
                "udp",
            );
            assert_eq!(set.matches(&ctx), expected, "{range}/{port}");
        }
        drop(set);
        std::fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn discord_packet_routes_to_proxy_and_fallback_overwrites_sniff_metadata() {
    use core_runtime::route::{Decision, Router};
    let root = json!({"outbounds":[{"type":"direct","tag":"dis_youtube-out"},{"type":"direct","tag":"direct-out"}],"route":{"final":"direct-out","rule_set":[{"type":"inline","tag":"discord","rules":[{"network":"udp","ip_cidr":["104.16.0.0/12"],"port_range":["19294:19344"]}]}],"rules":[{"inbound":"tproxy-in","action":"sniff"},{"rule_set":"discord","outbound":"dis_youtube-out"}]}});
    let router = Router::new(&root).unwrap();
    for (port, expected) in [(19314, "dis_youtube-out"), (19345, "direct-out")] {
        let mut ctx = ConnContext::new(
            "tproxy-in",
            "192.168.90.201:40000".parse().unwrap(),
            Target::Ip(format!("104.29.155.207:{port}").parse().unwrap()),
            "udp",
        );
        let decision = router
            .route_packet(&mut ctx, b"discord voice payload")
            .await
            .unwrap();
        let Decision::Outbound(index) = decision else {
            panic!("outbound expected")
        };
        assert_eq!(Some(index), router.index_of(expected));
        if expected == "direct-out" {
            assert_eq!(
                ctx.matched_rule,
                Some(("final".into(), "direct-out".into()))
            );
        } else {
            assert!(!ctx.matched_rule.unwrap().0.contains("sniff"));
        }
    }
}

/// The SRS load path: decode the container and compile the decoded rules
/// (which `RuleSet::new` consumes). The set must answer what the
/// interpreter answers on a kept copy of the same decoded rules.
fn assert_srs_agrees(srs: &[u8], extra: &[ConnContext]) {
    let rules = core_config::srs::read(srs).expect("decode srs");
    let set = RuleSet::new(vec!["srs".into()], rules.clone()).expect("rule set");
    assert_eq!(set.rule_count(), rules.len());
    for ctx in contexts().iter().chain(extra) {
        assert_eq!(
            set.matches(ctx),
            rules.iter().any(|rule| match_rule(rule, ctx)),
            "srs set disagrees on {:?} {:?} {:?}",
            ctx.destination,
            ctx.network,
            ctx.source
        );
    }
}

/// Each decoded rule on its own, with a connection it must match and one it
/// must not: in one shared set a rule that matches almost everything (such as
/// `network`) would hide a wrong answer from any other rule.
#[test]
fn srs_decoded_set_agrees_with_the_interpreter() {
    let d = |host: &str| context(Some(host), None, 443, "10.0.0.2:1234", "tcp");
    let at = |host: &str, port: u16, source: &str, network: &'static str| {
        context(Some(host), None, port, source, network)
    };
    let ip = |address: &str| context(None, Some(address), 443, "10.0.0.2:1234", "tcp");
    let cases: Vec<(Value, ConnContext, ConnContext)> = vec![
        (
            json!({"domain": ["a.com", "exact.org"], "domain_suffix": ["example.com", ".com", "a.com"]}),
            d("exact.org"),
            d("x.exact.org"),
        ),
        (
            json!({"domain_suffix": ["cdn.example.net"]}),
            d("a.cdn.example.net"),
            d("example.net"),
        ),
        (
            json!({"domain_keyword": ["ads", "tracker"]}),
            d("ads.example.net"),
            d("example.org"),
        ),
        (
            json!({"domain_regex": ["^re[0-9]+\\.test$"]}),
            d("re42.test"),
            d("rex.test"),
        ),
        (
            json!({"ip_cidr": ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]}),
            ip("10.1.2.3"),
            ip("8.8.8.8"),
        ),
        (
            json!({"source_ip_cidr": ["10.0.0.0/8"]}),
            d("a.com"),
            at("a.com", 443, "203.0.113.5:1234", "tcp"),
        ),
        (
            json!({"port": [80, 443]}),
            d("a.com"),
            at("a.com", 8443, "10.0.0.2:1234", "tcp"),
        ),
        (
            json!({"port_range": ["8000:9000"]}),
            at("a.com", 8500, "10.0.0.2:1234", "tcp"),
            d("a.com"),
        ),
        (
            json!({"source_port": [1234]}),
            d("a.com"),
            at("a.com", 443, "10.0.0.2:1500", "tcp"),
        ),
        (
            json!({"source_port_range": ["1000:2000"]}),
            d("a.com"),
            at("a.com", 443, "10.0.0.2:5000", "tcp"),
        ),
        (
            json!({"network": ["udp"]}),
            at("a.com", 443, "10.0.0.2:1234", "udp"),
            d("a.com"),
        ),
        (
            json!({"domain": ["multi.com"], "port": [443], "network": ["tcp"]}),
            d("multi.com"),
            at("multi.com", 443, "10.0.0.2:1234", "udp"),
        ),
        (
            json!({"invert": true, "domain": ["inverted.com"], "domain_suffix": ["inv.net"]}),
            d("other.org"),
            d("x.inv.net"),
        ),
        (
            json!({"type": "logical", "mode": "or", "rules": [
                {"domain": ["logical-or.com"]},
                {"port": [8080]}
            ]}),
            d("logical-or.com"),
            d("other.org"),
        ),
        (
            json!({"type": "logical", "mode": "and", "invert": true, "rules": [
                {"domain_suffix": ["nested.com"]},
                {"type": "logical", "mode": "or", "rules": [
                    {"port": [8443]},
                    {"invert": true, "ip_cidr": ["203.0.113.0/24"]}
                ]}
            ]}),
            d("other.org"),
            d("a.nested.com"),
        ),
    ];
    let source = json!({
        "version": 3,
        "rules": cases.iter().map(|(rule, _, _)| rule.clone()).collect::<Vec<_>>()
    });
    let srs = core_config::srs::compile(&source, 3).expect("compile srs");
    let decoded = core_config::srs::read(&srs).expect("decode srs");
    assert_eq!(decoded.len(), cases.len());
    let extra: Vec<ConnContext> = [
        "exact.org",
        "x.exact.org",
        "cdn.example.net",
        "a.cdn.example.net",
        "example.net",
        "re42.test",
        "inv.net",
        "x.inv.net",
        "nested.com",
        "a.nested.com",
    ]
    .iter()
    .flat_map(|host| {
        [
            context(Some(host), None, 443, "10.0.0.2:1234", "tcp"),
            context(Some(host), None, 8443, "203.0.113.5:1500", "udp"),
        ]
    })
    .collect();
    for (rule, (source_rule, hit, miss)) in decoded.iter().zip(&cases) {
        let set = RuleSet::new(vec!["one".into()], vec![rule.clone()]).expect("rule set");
        assert!(
            set.matches(hit),
            "{source_rule} must match {:?}",
            hit.destination
        );
        assert!(
            !set.matches(miss),
            "{source_rule} must not match {:?}",
            miss.destination
        );
        for ctx in contexts().iter().chain(&extra).chain([hit, miss]) {
            assert_eq!(
                set.matches(ctx),
                match_rule(rule, ctx),
                "{source_rule} disagrees on {:?} {:?} {:?}",
                ctx.destination,
                ctx.network,
                ctx.source
            );
        }
    }
    // and all of them in one set, as loaded
    assert_srs_agrees(&srs, &extra);
}

#[test]
fn srs_golden_file_agrees_with_the_interpreter() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/rule-set/local.srs"
    );
    let srs = std::fs::read(path).expect("golden local.srs");
    assert_srs_agrees(&srs, &[]);
}
