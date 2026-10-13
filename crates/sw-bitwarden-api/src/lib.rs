use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: Option<u32>,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

pub struct BitwardenClient {
    client: reqwest::Client,
    base_url: String,
}

impl BitwardenClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, ApiError> {
        let url = format!("{}/api/accounts/prelogin", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?
            .json::<PreloginResponse>()
            .await?;
        Ok(resp)
    }
}
