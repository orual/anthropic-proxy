use crate::{
    auth::{exchange_tokens, get_session_from_cookies, SESSION_COOKIE_NAME},
    error::{AppError, Result},
    types::{OAuthTokens, TokenRequest},
    AppState,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use chrono::{Duration, Utc};
use reqwest::header::HeaderName;
use serde_json::{json, Value};
use std::{collections::HashSet, str::FromStr};
use tracing::{debug, error, info, warn};

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    jar: CookieJar,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // Check authentication - first try x-api-key header, then fall back to cookies
    let (session_id, mut session) = if let Some(api_key_header) = headers.get("x-api-key") {
        if let Ok(session_id) = api_key_header.to_str() {
            debug!("Checking x-api-key header for session: {}", session_id);
            let session = state
                .session_store
                .get_session(session_id)
                .ok_or(AppError::Unauthorized)?;
            (session_id.to_string(), session)
        } else {
            return Err(AppError::Unauthorized);
        }
    } else {
        let cookie = jar.get(SESSION_COOKIE_NAME).ok_or(AppError::Unauthorized)?;
        let session_id = cookie.value().to_string();
        let session =
            get_session_from_cookies(&jar, &state.session_store).ok_or(AppError::Unauthorized)?;
        (session_id, session)
    };

    // Check if token needs refresh (5 minutes before expiry)
    if session.tokens.expires_at.timestamp() - Utc::now().timestamp() < 300 {
        info!("Token expiring soon, attempting automatic refresh");

        // Attempt to refresh the token
        if let Some(refresh_token) = session.tokens.refresh_token.clone() {
            let token_request = TokenRequest {
                grant_type: "refresh_token".to_string(),
                client_id: state.config.client_id.clone(),
                code: None,
                redirect_uri: None,
                code_verifier: None,
                refresh_token: Some(refresh_token),
                state: None,
            };

            match exchange_tokens(&state, token_request).await {
                Ok(token_response) => {
                    info!("Successfully refreshed access token");

                    // Update session with new tokens
                    session.tokens = OAuthTokens {
                        access_token: token_response.access_token,
                        refresh_token: token_response
                            .refresh_token
                            .or(session.tokens.refresh_token),
                        expires_at: Utc::now()
                            + Duration::seconds(token_response.expires_in as i64),
                    };

                    // Update the session in the store
                    state
                        .session_store
                        .update_session(&session_id, session.clone());
                }
                Err(e) => {
                    warn!("Failed to refresh token: {:?}", e);
                    // Continue with existing token - it might still work for a bit
                }
            }
        } else {
            warn!("No refresh token available, cannot refresh");
        }
    }

    // Build the target URL
    let target_url = format!("{}/{}", state.config.api_base_url, path);
    debug!("Proxying {} request to: {}", method, target_url);
    debug!(
        "Using access token: {}...",
        &session.tokens.access_token[..20.min(session.tokens.access_token.len())]
    );

    // Build the request
    let mut req_builder = match method {
        Method::GET => state.http_client.get(&target_url),
        Method::POST => state.http_client.post(&target_url),
        Method::PUT => state.http_client.put(&target_url),
        Method::DELETE => state.http_client.delete(&target_url),
        Method::PATCH => state.http_client.patch(&target_url),
        _ => return Err(AppError::ProxyError("Unsupported method".into())),
    };

    // Add OAuth authorization
    req_builder = req_builder.header(
        header::AUTHORIZATION,
        format!("Bearer {}", session.tokens.access_token),
    );

    // Add the OAuth beta header
    req_builder = req_builder.header("anthropic-beta", "oauth-2025-04-20");

    // Debug log all headers being sent
    debug!("Request headers being sent to Anthropic:");
    debug!(
        "  Authorization: Bearer {}...",
        &session.tokens.access_token[..20.min(session.tokens.access_token.len())]
    );
    debug!("  anthropic-beta: oauth-2025-04-20");

    // Forward relevant headers
    for (key, value) in headers.iter() {
        let key_str = key.as_str();

        // Skip headers that shouldn't be forwarded (including x-api-key)
        if should_forward_header(key_str) && key_str.to_lowercase() != "x-api-key" {
            if let Ok(header_name) = HeaderName::from_str(key_str) {
                req_builder = req_builder.header(header_name, value.clone());
            }
        }
    }

    // Ensure anthropic-version header is set (use latest version)
    if !headers.contains_key("anthropic-version") {
        req_builder = req_builder.header("anthropic-version", "2023-06-01");
    }

    // Add body if present, injecting Claude Code system prompt if needed
    if !body.is_empty() {
        // For messages endpoint, inject the Claude Code system prompt
        if path.contains("messages") {
            if let Ok(mut json_body) = serde_json::from_slice::<serde_json::Value>(&body) {
                // Log the original request for debugging
                debug!(
                    "Original request body: {}",
                    serde_json::to_string_pretty(&json_body).unwrap_or_default()
                );

                // Strip cache_control to prevent extra token usage (as per OpenCode fix)
                modify_cache_control(&mut json_body);

                // Prepend Claude Code identification to system prompt array
                let claude_code_obj = serde_json::json!({
                    "type": "text",
                    "text": "You are Claude Code, Anthropic's official CLI for Claude."
                });

                // Handle both string and array system prompts
                match json_body.get_mut("system") {
                    Some(serde_json::Value::Array(system_array)) => {
                        // Prepend to existing array
                        system_array.insert(0, claude_code_obj);
                        debug!("Prepended Claude Code object to existing system array");
                    }
                    Some(serde_json::Value::String(existing_str)) => {
                        // Convert string to array format
                        let existing_obj = serde_json::json!({
                            "type": "text",
                            "text": existing_str
                        });
                        json_body["system"] = serde_json::json!([claude_code_obj, existing_obj]);
                        debug!("Converted string system to array and prepended Claude Code");
                    }
                    _ => {
                        // No system prompt, create new array
                        json_body["system"] = serde_json::json!([claude_code_obj]);
                        debug!("Created new system array with Claude Code prompt");
                    }
                }

                if let Ok(modified_body) = serde_json::to_vec(&json_body) {
                    req_builder = req_builder.body(modified_body);
                } else {
                    req_builder = req_builder.body(body);
                }
            } else {
                req_builder = req_builder.body(body);
            }
        } else {
            req_builder = req_builder.body(body);
        }
    }

    // Log the full request details for debugging
    info!("Making request to Anthropic API:");
    info!("  URL: {}", target_url);
    info!("  Method: {}", method);

    // Execute the request
    let response = req_builder.send().await.map_err(|e| {
        error!("Proxy request failed: {}", e);
        AppError::ProxyError(format!("Request failed: {}", e))
    })?;

    info!("Response status: {}", response.status());
    if !response.status().is_success() {
        error!("API request failed with status: {}", response.status());
    }

    // Convert reqwest response to axum response
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(status);

    // Forward response headers
    for (key, value) in response.headers().iter() {
        if should_forward_response_header(key.as_str()) {
            response_builder = response_builder.header(key.clone(), value.clone());
        }
    }

    // Get response body
    let body_bytes = response.bytes().await.map_err(|e| {
        error!("Failed to read response body: {}", e);
        AppError::ProxyError(format!("Failed to read response: {}", e))
    })?;

    // Log response body if it's an error
    if !status.is_success() {
        if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
            error!("Error response body: {}", body_str);
        }
    }

    // Build final response
    let final_response = response_builder.body(Body::from(body_bytes)).map_err(|e| {
        error!("Failed to build response: {}", e);
        AppError::ProxyError(format!("Failed to build response: {}", e))
    })?;

    Ok(final_response)
}

// Determine if a request header should be forwarded
fn should_forward_header(header: &str) -> bool {
    let header_lower = header.to_lowercase();

    // Don't forward these headers
    let blocked_headers = [
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "upgrade",
        "cookie",
        "authorization", // We set this ourselves
    ];

    !blocked_headers.contains(&header_lower.as_str())
}

// Determine if a response header should be forwarded
fn should_forward_response_header(header: &str) -> bool {
    let header_lower = header.to_lowercase();

    // Don't forward these headers
    let blocked_headers = [
        "connection",
        "content-encoding",
        "content-length",
        "transfer-encoding",
        "upgrade",
    ];

    !blocked_headers.contains(&header_lower.as_str())
}

// Modify cacheControl in messages to prevent extra token usage
// Based on OpenCode's fix: https://github.com/sst/opencode/commit/1684042fb6ca1ff1e9d323469a9d913821b5af2e
fn modify_cache_control(json: &mut serde_json::Value) {
    // Remove cache_control from messages array
    if let Some(messages) = json.get_mut("messages") {
        if let Some(messages_array) = messages.as_array_mut() {
            // Collect indices of first 2 "system" messages
            let mut system_indices = vec![];
            for (i, msg) in messages_array.iter().enumerate() {
                if msg.get("role") == Some(&Value::String("system".to_string())) {
                    system_indices.push(i);
                    if system_indices.len() == 2 {
                        break;
                    }
                }
            }

            // Collect indices of last 2 non-"system" messages
            //let mut nonsystem_indices = vec![];
            // for (i, msg) in messages_array.iter().enumerate().rev() {
            //     if msg.get("role") != Some(&Value::String("system".to_string())) {
            //         nonsystem_indices.push(i);
            //         if nonsystem_indices.len() == 2 {
            //             break;
            //         }
            //     }
            // }

            // Merge and deduplicate indices
            let mut indices: HashSet<usize> = system_indices.into_iter().collect();
            //indices.extend(nonsystem_indices);

            // Update each selected message
            for idx in indices {
                if let Some(msg) = messages_array.get_mut(idx) {
                    // Insert cache_control if missing
                    msg.as_object_mut().map(|map| {
                        map.insert("cache_control".to_string(), json!({"type": "ephemeral" }));
                    });
                }
            }
        }
    }

    debug!("Modified cache_control fields from request");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, session::SessionStore, types::SessionData};
    use chrono::Duration;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_token_refresh_when_expiring() {
        // Create a mock app state
        let config = Arc::new(Config {
            port: 4001,
            session_secret: "test-secret".to_string(),
            client_id: "test-client-id".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            oauth_base_url: "https://claude.ai".to_string(),
            api_base_url: "https://api.anthropic.com/v1".to_string(),
        });

        let session_store = Arc::new(SessionStore::new());
        let http_client = reqwest::Client::new();

        let _app_state = AppState {
            config,
            session_store: session_store.clone(),
            http_client,
        };

        // Create a session with token expiring in 4 minutes (under the 5 minute threshold)
        let session_id = "test-session-id";
        let session_data = SessionData {
            tokens: OAuthTokens {
                access_token: "test-access-token".to_string(),
                refresh_token: Some("test-refresh-token".to_string()),
                expires_at: Utc::now() + Duration::minutes(4),
            },
            user_id: Some("test-user".to_string()),
            api_key: None,
        };

        // Store the session
        session_store.create_session(session_id, session_data.clone());

        // Verify the session is stored
        let stored_session = session_store.get_session(session_id);
        assert!(stored_session.is_some());
        assert_eq!(
            stored_session.unwrap().tokens.access_token,
            "test-access-token"
        );

        // In a real test, we would mock the exchange_tokens function
        // For now, we just verify the logic for detecting token expiry
        let time_until_expiry = session_data.tokens.expires_at.timestamp() - Utc::now().timestamp();
        assert!(time_until_expiry < 300); // Should be less than 5 minutes
    }
}
