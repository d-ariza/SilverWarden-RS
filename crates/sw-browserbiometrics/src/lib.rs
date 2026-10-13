use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrowserBiometricsError {
    #[error("Native messaging error: {0}")]
    NativeMessaging(String),
}
