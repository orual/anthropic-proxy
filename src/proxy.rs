use crate::{
    auth::get_session_from_cookies,
    error::{AppError, Result},
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
use chrono::Utc;
use reqwest::header::HeaderName;
use std::str::FromStr;
use tracing::{debug, error, info};

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    jar: CookieJar,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // Check authentication
    let session =
        get_session_from_cookies(&jar, &state.session_store).ok_or(AppError::Unauthorized)?;

    // Check if token needs refresh (5 minutes before expiry)
    if session.tokens.expires_at.timestamp() - Utc::now().timestamp() < 300 {
        info!("Token expiring soon, consider refreshing");
        // In a production app, you might want to automatically refresh here
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
