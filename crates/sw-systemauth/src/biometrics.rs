use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use zbus::zvariant::Value;

use crate::CallingContext;

#[derive(thiserror::Error, Debug)]
pub enum BiometricsError {
    #[error("Biometric authentication cancelled")]
    Cancelled,
    #[error("Biometric authentication failed: {0}")]
    Failed(String),
    #[error("Polkit service unavailable: {0}")]
    ServiceUnavailable(String),
}

#[async_trait]
pub trait Biometrics: Send + Sync + std::fmt::Debug {
    async fn authenticate(
        &self,
        reason: &str,
        ctx: &CallingContext,
    ) -> Result<bool, BiometricsError>;
}

/// Linux Polkit authentication backend using `org.freedesktop.PolicyKit1`.
#[derive(Debug, Default, Clone)]
pub struct PolkitBiometrics;

impl PolkitBiometrics {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Biometrics for PolkitBiometrics {
    async fn authenticate(
        &self,
        reason: &str,
        ctx: &CallingContext,
    ) -> Result<bool, BiometricsError> {
        let connection = zbus::Connection::system()
            .await
            .map_err(|e| BiometricsError::ServiceUnavailable(format!("No system bus: {e}")))?;

        let proxy = zbus::proxy::Proxy::new(
            &connection,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
        )
        .await
        .map_err(|e| BiometricsError::ServiceUnavailable(format!("Polkit proxy: {e}")))?;

        let start_time = crate::get_process_start_time(ctx.process_pid);

        let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
        subject_details.insert("pid", Value::U32(ctx.process_pid));
        subject_details.insert("start-time", Value::U64(start_time));

        let subject = ("unix-process", subject_details);
        let mut details: HashMap<&str, &str> = HashMap::new();
        if !reason.is_empty() {
            details.insert("polkit.message", reason);
        }
        let flags: u32 = 0x1; // AllowUserInteraction
        let cancellation_id = "";

        // Action ID: org.silverwarden.unlock installed via `silverwarden setup-systemd` (SW-054).
        let action_id = "org.silverwarden.unlock";

        let result: (bool, bool, HashMap<String, String>) = proxy
            .call(
                "CheckAuthorization",
                &(subject, action_id, &details, flags, cancellation_id),
            )
            .await
            .map_err(|e| BiometricsError::Failed(format!("Polkit CheckAuthorization: {e}")))?;

        Ok(result.0)
    }
}

/// In-memory mock for `Biometrics` for deterministic unit testing.
#[derive(Debug, Default)]
pub struct MockBiometrics {
    pub should_succeed: bool,
    pub should_fail: bool,
    pub call_count: AtomicUsize,
}

impl MockBiometrics {
    pub fn new(succeed: bool) -> Self {
        Self {
            should_succeed: succeed,
            should_fail: false,
            call_count: AtomicUsize::new(0),
        }
    }

    pub fn failing() -> Self {
        Self {
            should_succeed: false,
            should_fail: true,
            call_count: AtomicUsize::new(0),
        }
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Biometrics for MockBiometrics {
    async fn authenticate(
        &self,
        _reason: &str,
        _ctx: &CallingContext,
    ) -> Result<bool, BiometricsError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if self.should_fail {
            Err(BiometricsError::Failed("Mock biometrics failure".into()))
        } else {
            Ok(self.should_succeed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_biometrics_success_and_count() {
        let mock = MockBiometrics::new(true);
        let ctx = CallingContext::default();
        let res = mock.authenticate("reason", &ctx).await;
        assert!(res.unwrap());
        assert_eq!(mock.call_count(), 1);

        let res2 = mock.authenticate("reason2", &ctx).await;
        assert!(res2.unwrap());
        assert_eq!(mock.call_count(), 2);
    }

    #[tokio::test]
    async fn test_mock_biometrics_failing() {
        let mock = MockBiometrics::failing();
        let ctx = CallingContext::default();
        let res = mock.authenticate("reason", &ctx).await;
        assert!(matches!(res, Err(BiometricsError::Failed(_))));
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn test_polkit_biometrics_new_default() {
        let p = PolkitBiometrics::new();
        assert_eq!(format!("{p:?}"), "PolkitBiometrics");
    }

    #[test]
    fn test_biometrics_error_display() {
        let err1 = BiometricsError::Cancelled;
        assert_eq!(err1.to_string(), "Biometric authentication cancelled");

        let err2 = BiometricsError::Failed("timeout".into());
        assert_eq!(err2.to_string(), "Biometric authentication failed: timeout");

        let err3 = BiometricsError::ServiceUnavailable("no dbus".into());
        assert_eq!(err3.to_string(), "Polkit service unavailable: no dbus");
    }

    #[test]
    fn test_polkit_biometrics_uses_silverwarden_action_id() {
        let code = include_str!("biometrics.rs");
        assert!(code.contains(r#"let action_id = "org.silverwarden.unlock";"#));
    }
}
