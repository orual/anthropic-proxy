use crate::{
    error::{AppError, Result},
    session::SessionStore,
    types::{OAuthTokens, SessionData, TokenRequest, TokenResponse},
    AppState,
};
use axum::{extract::State, http::header, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, error, info};

pub const SESSION_COOKIE_NAME: &str = "anthropic_session";

// Generate PKCE verifier (matching OpenCode's 64 byte default)
pub fn generate_code_verifier() -> String {
    let random_bytes: Vec<u8> = (0..64).map(|_| rand::thread_rng().gen()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
}

// Generate PKCE challenge from verifier
pub fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

// Generate random state parameter (matching OpenCode's length)
pub fn generate_state() -> String {
    let random_bytes: Vec<u8> = (0..64).map(|_| rand::thread_rng().gen()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
}

// Logout endpoint
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Result<impl IntoResponse> {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        state.session_store.delete_session(cookie.value());
    }

    let jar = jar.remove(SESSION_COOKIE_NAME);
    Ok((jar, Json(json!({ "message": "Successfully logged out" }))))
}

// Check authentication status
pub async fn status(State(state): State<AppState>, jar: CookieJar) -> Result<impl IntoResponse> {
    let authenticated = if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        state.session_store.get_session(cookie.value()).is_some()
    } else {
        false
    };

    Ok(Json(json!({
        "authenticated": authenticated
    })))
}

// Refresh access token
pub async fn refresh(State(state): State<AppState>, jar: CookieJar) -> Result<impl IntoResponse> {
    let cookie = jar.get(SESSION_COOKIE_NAME).ok_or(AppError::Unauthorized)?;

    let mut session_data = state
        .session_store
        .get_session(cookie.value())
        .ok_or(AppError::Unauthorized)?;

    let refresh_token = session_data
        .tokens
        .refresh_token
        .clone()
        .ok_or_else(|| AppError::TokenRefreshError("No refresh token available".into()))?;

    let token_request = TokenRequest {
        grant_type: "refresh_token".to_string(),
        client_id: state.config.client_id.clone(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: Some(refresh_token),
        state: None,
    };

    let token_response = exchange_tokens(&state, token_request).await?;

    // Update session with new tokens
    session_data.tokens = OAuthTokens {
        access_token: token_response.access_token,
        refresh_token: token_response
            .refresh_token
            .or(session_data.tokens.refresh_token),
        expires_at: Utc::now() + Duration::seconds(token_response.expires_in as i64),
    };

    state
        .session_store
        .update_session(cookie.value(), session_data);

    Ok(Json(json!({ "message": "Token refreshed successfully" })))
}

// Helper function to exchange tokens
pub async fn exchange_tokens(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    let client = &state.http_client;
    let token_url = "https://console.anthropic.com/v1/oauth/token";

    debug!("Exchanging tokens at: {}", token_url);

    let response = client
        .post(token_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .form(&request)
        .send()
        .await
        .map_err(|e| AppError::TokenExchangeError(e.to_string()))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        error!("Token exchange failed: {}", error_text);
        return Err(AppError::TokenExchangeError(error_text));
    }

    let response_text = response
        .text()
        .await
        .map_err(|e| AppError::TokenExchangeError(e.to_string()))?;

    info!("Token exchange response: {}", response_text);
    debug!("Token response: {}", response_text);

    let token_response: TokenResponse = serde_json::from_str(&response_text).map_err(|e| {
        AppError::TokenExchangeError(format!("Failed to parse token response: {}", e))
    })?;

    Ok(token_response)
}

// Middleware to check authentication
pub fn get_session_from_cookies(
    jar: &CookieJar,
    session_store: &Arc<SessionStore>,
) -> Option<SessionData> {
    jar.get(SESSION_COOKIE_NAME)
        .and_then(|cookie| session_store.get_session(cookie.value()))
}
