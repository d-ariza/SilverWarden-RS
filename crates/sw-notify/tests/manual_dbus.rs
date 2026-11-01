use sw_notify::{DbusNotifier, Notifier};

#[tokio::test]
#[ignore]
async fn test_dbus_notifier_returns_error_without_session() {
    let original = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");

    let notifier = DbusNotifier::new();
    let res = notifier.notify("Manual Test", "No session test").await;
    assert!(res.is_err());

    if let Some(val) = original {
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", val);
    }
}

#[tokio::test]
#[ignore]
async fn test_dbus_notifier_smoke() {
    let notifier = DbusNotifier::new();
    let res = notifier
        .notify("SilverWarden Test", "Smoke test notification")
        .await;
    match res {
        Ok(()) => println!("Notification sent successfully"),
        Err(e) => println!("Notification failed gracefully: {e}"),
    }
}
