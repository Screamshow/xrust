//! A hot reload keeps the neighbour resolver that reads the same lease files,
//! and a replaced resolver stops refreshing. Its own test binary: the
//! resolver is process-wide.

use core_runtime::route::neighbor;

#[tokio::test]
async fn same_lease_files_keep_the_resolver_and_a_replaced_one_is_released() {
    let dir = std::env::temp_dir();
    let first = dir.join(format!(
        "xrust-neighbor-reuse-a-{}.leases",
        std::process::id()
    ));
    let second = dir.join(format!(
        "xrust-neighbor-reuse-b-{}.leases",
        std::process::id()
    ));
    std::fs::write(&first, "").unwrap();
    std::fs::write(&second, "").unwrap();
    let first = vec![first.to_string_lossy().into_owned()];
    let second = vec![second.to_string_lossy().into_owned()];

    neighbor::ensure(&first);
    let running = neighbor::current().unwrap();
    neighbor::ensure(&first);
    assert!(std::sync::Arc::ptr_eq(
        &running,
        &neighbor::current().unwrap()
    ));

    neighbor::ensure(&second);
    assert!(!std::sync::Arc::ptr_eq(
        &running,
        &neighbor::current().unwrap()
    ));
    // only this test holds the replaced resolver; its refresh task does not
    tokio::task::yield_now().await;
    assert_eq!(std::sync::Arc::strong_count(&running), 1);
}
