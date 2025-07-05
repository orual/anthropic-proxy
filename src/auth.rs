use crate::{
    error::{AppError, Result},
    session::SessionStore,
    types::{OAuthCallback, OAuthTokens, PkceChallenge, SessionData, TokenRequest, TokenResponse},
    AppState,
};
use axum::{
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Redirect, Response},
    Json,
};
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

// Initiate OAuth login flow
pub async fn login(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);
    let oauth_state = generate_state();

    // Store PKCE challenge for later verification
    let pkce_challenge = PkceChallenge {
        verifier,
        challenge: challenge.clone(),
        state: oauth_state.clone(),
    };
    state
        .session_store
        .store_pkce_challenge(&oauth_state, pkce_challenge);

    // Build authorization URL
    let auth_params = vec![
        ("response_type", "code"),
        ("client_id", &state.config.client_id),
        ("redirect_uri", &state.config.redirect_uri),
        ("scope", "org:create_api_key user:profile user:inference"),
        ("state", &oauth_state),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ];

    let auth_url = format!(
        "{}/oauth/authorize?{}",
        state.config.oauth_base_url,
        serde_urlencoded::to_string(auth_params).unwrap()
    );

    info!("Redirecting to OAuth authorization: {}", auth_url);
    debug!(
        "Auth params: client_id={}, redirect_uri={}, state={}",
        state.config.client_id, state.config.redirect_uri, oauth_state
    );
    Ok(Redirect::to(&auth_url))
}

// Handle OAuth callback
pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallback>,
    jar: CookieJar,
) -> Result<impl IntoResponse> {
    debug!("OAuth callback received with params: {:?}", params);

    // Handle OAuth errors
    if let Some(error) = params.error {
        error!("OAuth error: {} - {:?}", error, params.error_description);
        return Err(AppError::OAuthError(format!(
            "{}: {}",
            error,
            params.error_description.unwrap_or_default()
        )));
    }

    let code = params
        .code
        .ok_or_else(|| AppError::OAuthError("Missing authorization code".into()))?;
    let state_param = params
        .state
        .ok_or_else(|| AppError::OAuthError("Missing state parameter".into()))?;

    // Check if this looks like a manual code entry flow
    // If so, display the code for the user to copy
    if state.config.redirect_uri.contains("localhost")
        || state.config.redirect_uri.contains("127.0.0.1")
    {
        info!("Displaying authorization code for manual entry");
        return Ok(axum::response::Html(format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Code</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }}
        .container {{
            text-align: center;
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 500px;
        }}
        h1 {{
            color: #2d3748;
            margin-bottom: 1rem;
        }}
        p {{
            color: #4a5568;
            margin-bottom: 1.5rem;
        }}
        .code {{
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            padding: 1rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
            word-break: break-all;
            user-select: all;
            cursor: pointer;
        }}
        .instruction {{
            color: #718096;
            font-size: 0.9rem;
            margin-top: 1rem;
        }}
    </style>
    <script>
        function copyCode() {{
            const codeElement = document.getElementById('auth-code');
            navigator.clipboard.writeText(codeElement.textContent);
            document.getElementById('copy-status').textContent = 'Copied!';
            setTimeout(() => {{
                document.getElementById('copy-status').textContent = 'Click to copy';
            }}, 2000);
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>Authorization Code</h1>
        <p>Copy this code and paste it into Claude Code:</p>
        <div class="code" id="auth-code" onclick="copyCode()">{}</div>
        <p class="instruction" id="copy-status">Click to copy</p>
        <p class="instruction">This code will be exchanged for an access token automatically.</p>
    </div>
</body>
</html>
        "#,
            code
        ))
        .into_response());
    }

    // Retrieve and validate PKCE challenge
    let pkce_challenge = state
        .session_store
        .get_pkce_challenge(&state_param)
        .ok_or(AppError::InvalidState)?;

    // Exchange authorization code for tokens
    let token_request = TokenRequest {
        grant_type: "authorization_code".to_string(),
        client_id: state.config.client_id.clone(),
        code: Some(code),
        redirect_uri: Some(state.config.redirect_uri.clone()),
        code_verifier: Some(pkce_challenge.verifier),
        refresh_token: None,
        state: Some(state_param.clone()),
    };

    let token_response = exchange_tokens(&state, token_request).await?;

    // Clean up PKCE challenge
    state.session_store.remove_pkce_challenge(&state_param);

    // Create session
    let session_id = SessionStore::generate_session_id();
    let session_data = SessionData {
        tokens: OAuthTokens {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_at: Utc::now() + Duration::seconds(token_response.expires_in as i64),
        },
        user_id: None,
        api_key: None,
    };

    state
        .session_store
        .create_session(&session_id, session_data);

    // Set session cookie
    let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE_NAME, session_id))
        .http_only(true)
        .secure(false) // Set to true in production with HTTPS
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .build();

    let updated_jar = jar.add(cookie);
    Ok((updated_jar, Redirect::to("/auth/success")).into_response())
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

// Success page after OAuth
pub async fn success(State(state): State<AppState>, jar: CookieJar) -> Result<impl IntoResponse> {
    // Check if authenticated
    if get_session_from_cookies(&jar, &state.session_store).is_none() {
        return Err(AppError::Unauthorized);
    }

    Ok(axum::response::Html(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 400px;
        }
        h1 {
            color: #2d3748;
            margin-bottom: 1rem;
        }
        p {
            color: #4a5568;
            margin-bottom: 1.5rem;
        }
        .success {
            color: #48bb78;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Authentication Successful</h1>
        <p class="success">You have successfully authenticated with Anthropic!</p>
        <p>You can now use the API proxy endpoints.</p>
        <p>The session cookie has been set in your browser.</p>
    </div>
</body>
</html>
    "#,
    ))
}
