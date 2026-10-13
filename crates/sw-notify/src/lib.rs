use thiserror::Error;

#[derive(Error, Debug)]
pub enum NotifyError {
    #[error("Notification service error: {0}")]
    Service(String),
}

pub trait Notifier {
    fn notify(&self, title: &str, body: &str) -> Result<(), NotifyError>;
}
