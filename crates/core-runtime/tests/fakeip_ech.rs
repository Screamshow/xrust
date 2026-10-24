use core_runtime::dns;
use core_runtime::inbound::Target;
use core_runtime::route::rule::Rule;
use core_runtime::route::rule_set::{RuleSet, match_rule};
use core_runtime::route::{ConnContext, Decision};
use serde_json::json;

#[tokio::test]
async fn fakeip_domain_survives_ech_and_resolve_for_inline_and_compiled_rules() {
    let instance = core_runtime::start(&json!({
        "dns": {"servers": [
            {"type":"hosts", "tag":"real", "predefined":{"inner.example":["192.0.2.1"]}},
            {"type":"fakeip", "tag":"fake", "inet4_range":"198.18.0.0/15"}
        ], "final":"real"},
        "outbounds":[{"type":"direct","tag":"hit"},{"type":"block","tag":"miss"}],
        "route":{"rules":[{"action":"resolve","server":"real"},
            {"domain_suffix":["inner.example"],"outbound":"hit"}],"final":"miss"}
    }))
    .await
    .unwrap();
    let service = dns::current().unwrap();
    let ip = service.fakeip_stores()[0]
        .create("inner.example", false)
        .unwrap();
    let mut ctx = ConnContext::new(
        "tproxy-in",
        "192.0.2.20:1234".parse().unwrap(),
        Target::Ip(std::net::SocketAddr::new(ip, 443)),
        "tcp",
    );
    // This is the ECH outer SNI recorded by the sniffer, independent of the DNS name.
    ctx.domain = Some("public.example".into());
    let router = instance.router();
    assert_eq!(
        router.route_raw(&mut ctx).await.unwrap(),
        Decision::Outbound(router.index_of("hit").unwrap())
    );
    assert!(
        matches!(ctx.destination, Target::Ip(_)),
        "resolve must overwrite destination"
    );
    assert_eq!(ctx.fakeip_domain.as_deref(), Some("inner.example"));
    for matcher in [
        json!({"domain":["inner.example"]}),
        json!({"domain_suffix":["inner.example"]}),
        json!({"domain_regex":["^inner\\.example$"]}),
    ] {
        assert!(Rule::build(&matcher, "r", false).unwrap().matches(&ctx));
    }
    for matcher in [
        json!({"domain":["inner.example"]}),
        json!({"domain_suffix":["inner.example"]}),
        json!({"domain_suffix":["inner.example"],"port":[443]}),
    ] {
        assert!(match_rule(&matcher, &ctx), "interpreted {matcher}");
        let set = RuleSet::new(vec!["test".into()], vec![matcher.clone()]).expect("rule set");
        assert!(set.matches(&ctx), "compiled {matcher}");
    }
    let bytes = core_runtime::route::mmap_set::RuleSetCompiler::new()
        .compile(&[json!({"domain_suffix":["inner.example"]})])
        .unwrap();
    let mmap = core_runtime::route::mmap_set::MmapRuleSet::from_bytes(&bytes).unwrap();
    assert!(mmap.matches(&ctx), "memory-mapped domain matcher");
    assert!(
        !Rule::build(&json!({"domain_suffix":["unrelated.example"]}), "r", false)
            .unwrap()
            .matches(&ctx)
    );
    instance.shutdown_wait().await;
}
