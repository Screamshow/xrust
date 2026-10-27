//! `reload-plan`: the planner a manager runs beside the live core. With
//! `--skip-rule-set-payloads` it leaves list bodies to the core but still
//! refuses a broken config and a list file that does not open.

use std::process::Command;

use serde_json::json;

fn plan(dir: &std::path::Path, next: &serde_json::Value, skip: bool) -> Option<serde_json::Value> {
    let current = dir.join("current.json");
    let candidate = dir.join("next.json");
    std::fs::write(
        &current,
        json!({"outbounds":[{"type":"direct","tag":"direct"}]}).to_string(),
    )
    .unwrap();
    std::fs::write(&candidate, next.to_string()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_xrust"));
    command
        .arg("reload-plan")
        .arg("--current")
        .arg(&current)
        .arg("-c")
        .arg(&candidate);
    if skip {
        command.arg("--skip-rule-set-payloads");
    }
    let output = command.output().unwrap();
    output
        .status
        .success()
        .then(|| serde_json::from_slice(&output.stdout).unwrap())
}

#[test]
fn skipping_rule_set_payloads_still_refuses_broken_configs_and_missing_files() {
    let dir = std::env::temp_dir().join(format!("xrust-reload-plan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("list.json");
    std::fs::write(&list, "{broken").unwrap();
    let with_list = |path: &std::path::Path| {
        json!({"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rule_set":[
            {"type":"local","tag":"list","format":"source","path":path}]}})
    };

    // the full check decodes the body and refuses it
    assert!(plan(&dir, &with_list(&list), false).is_none());
    // the planner leaves the body to the core
    let skipped = plan(&dir, &with_list(&list), true).expect("planned");
    assert_eq!(skipped["rule_set_payloads_checked"], false);
    assert_eq!(skipped["in_place"], true);
    // a missing file and a broken config are still refused
    assert!(plan(&dir, &with_list(&dir.join("missing.json")), true).is_none());
    assert!(plan(&dir, &json!({"inbounds":[{"type":"unknown"}]}), true).is_none());
    // a valid list passes both ways
    std::fs::write(
        &list,
        json!({"version":3,"rules":[{"domain":["a.example"]}]}).to_string(),
    )
    .unwrap();
    assert_eq!(
        plan(&dir, &with_list(&list), false).unwrap()["rule_set_payloads_checked"],
        true
    );
    let _ = std::fs::remove_dir_all(&dir);
}
