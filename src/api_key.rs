use crate::{
    error::{AppError, Result},
    AppState,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

#[derive(Debug, Serialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub api_key: String,
    pub name: String,
    pub created_at: String,
}

pub async fn create_api_key(
    state: &AppState,
    access_token: &str,
    key_name: &str,
) -> Result<String> {
    // Try to create an API key using the OAuth token
    let url = "https://api.anthropic.com/v1/api-keys";

    debug!("Creating API key with name: {}", key_name);

    let request = CreateApiKeyRequest {
        name: key_name.to_string(),
    };

    let response = state
        .http_client
        .post(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .json(&request)
        .send()
        .await
        .map_err(|e| AppError::RequestError(e))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        debug!("Failed to create API key: {}", error_text);

        // If this endpoint doesn't exist, try the console API
        return create_api_key_console(state, access_token, key_name).await;
    }

    let api_key_response = response
        .json::<ApiKeyResponse>()
        .await
        .map_err(|e| AppError::RequestError(e))?;

    info!("Successfully created API key: {}", api_key_response.name);
    Ok(api_key_response.api_key)
}

async fn create_api_key_console(
    state: &AppState,
    access_token: &str,
    key_name: &str,
) -> Result<String> {
    // Try the console API endpoint
    let url = "https://console.anthropic.com/api/organizations/keys";

    debug!("Trying console API to create API key");

    let request = CreateApiKeyRequest {
        name: key_name.to_string(),
    };

    let response = state
        .http_client
        .post(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| AppError::RequestError(e))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(AppError::ProxyError(format!(
            "Failed to create API key: {}",
            error_text
        )));
    }

    let api_key_response = response
        .json::<ApiKeyResponse>()
        .await
        .map_err(|e| AppError::RequestError(e))?;

    info!(
        "Successfully created API key via console API: {}",
        api_key_response.name
    );
    Ok(api_key_response.api_key)
}
