use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use zbus::zvariant::Value;
use zbus::Connection;

#[derive(Error, Debug)]
pub enum NotifyError {
    #[error("Notification service error: {0}")]
    Service(String),
}

#[async_trait::async_trait]
pub trait Notifier: Send + Sync + std::fmt::Debug {
    async fn notify(&self, title: &str, body: &str) -> Result<(), NotifyError>;
}

/// D-Bus Desktop Notifications backend (`org.freedesktop.Notifications`).
#[derive(Debug, Default, Clone)]
pub struct DbusNotifier;

impl DbusNotifier {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Notifier for DbusNotifier {
    async fn notify(&self, title: &str, body: &str) -> Result<(), NotifyError> {
        let connection = Connection::session()
            .await
            .map_err(|e| NotifyError::Service(format!("No D-Bus session: {e}")))?;

        let proxy = zbus::proxy::Proxy::new(
            &connection,
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        )
        .await
        .map_err(|e| NotifyError::Service(format!("No notifications service: {e}")))?;

        let hints: HashMap<&str, Value<'_>> = HashMap::new();
        let actions: Vec<&str> = Vec::new();

        let _: u32 = proxy
            .call(
                "Notify",
                &(
                    "silverwarden",       // app_name
                    0u32,                 // replaces_id
                    "dialog-information", // app_icon
                    title,                // summary
                    body,                 // body
                    &actions,             // actions
                    &hints,               // hints (a{sv})
                    -1i32,                // expire_timeout (-1 = default)
                ),
            )
            .await
            .map_err(|e| NotifyError::Service(format!("Notify call failed: {e}")))?;

        Ok(())
    }
}

/// In-memory mock notifier for testing without D-Bus.
#[derive(Debug, Default)]
pub struct MockNotifier {
    pub notifications: Mutex<Vec<(String, String)>>,
    pub should_fail: bool,
}

impl MockNotifier {
    pub fn new() -> Self {
        Self {
            notifications: Mutex::new(Vec::new()),
            should_fail: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            notifications: Mutex::new(Vec::new()),
            should_fail: true,
        }
    }

    pub fn notifications(&self) -> Vec<(String, String)> {
        self.notifications.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Notifier for MockNotifier {
    async fn notify(&self, title: &str, body: &str) -> Result<(), NotifyError> {
        if self.should_fail {
            return Err(NotifyError::Service(
                "Mock notification failure".to_string(),
            ));
        }
        self.notifications
            .lock()
            .unwrap()
            .push((title.to_string(), body.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_notifier_records_calls() {
        let notifier = MockNotifier::new();
        notifier
            .notify("Title 1", "Body 1")
            .await
            .expect("First notification should succeed");
        notifier
            .notify("Title 2", "Body 2")
            .await
            .expect("Second notification should succeed");

        let recorded = notifier.notifications();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], ("Title 1".to_string(), "Body 1".to_string()));
        assert_eq!(recorded[1], ("Title 2".to_string(), "Body 2".to_string()));
    }

    #[tokio::test]
    async fn test_mock_notifier_failing_returns_error() {
        let notifier = MockNotifier::failing();
        let res = notifier.notify("Error Title", "Error Body").await;
        assert!(res.is_err());
        match res.unwrap_err() {
            NotifyError::Service(msg) => assert_eq!(msg, "Mock notification failure"),
        }
        assert!(notifier.notifications().is_empty());
    }

    #[test]
    #[allow(clippy::default_constructed_unit_structs)]
    fn test_notify_error_display_and_default_dbus_notifier() {
        let err = NotifyError::Service("Custom test error".to_string());
        assert_eq!(
            err.to_string(),
            "Notification service error: Custom test error"
        );

        let notifier = DbusNotifier::default();
        let _ = format!("{notifier:?}");
        let cloned = notifier.clone();
        let _ = DbusNotifier::new();
        let _ = cloned;
    }

    #[tokio::test]
    async fn test_dbus_notifier_returns_error_with_invalid_address() {
        // Test DbusNotifier when D-Bus address is invalid
        let original = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/dbus/bus.sock",
        );

        let notifier = DbusNotifier::new();
        let res = notifier.notify("Title", "Body").await;
        assert!(res.is_err());

        // Restore env
        if let Some(val) = original {
            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", val);
        } else {
            std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
        }
    }

    #[tokio::test]
    async fn test_dbus_notifier_environment_dispatch() {
        if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok() {
            let notifier = DbusNotifier::new();
            let _ = notifier.notify("SilverWarden", "Prueba de entorno").await;
        }
    }
}
