use crate::{
    auth::{
        exchange_tokens, generate_code_challenge, generate_code_verifier, generate_state,
        SESSION_COOKIE_NAME,
    },
    error::{AppError, Result},
    session::SessionStore,
    types::{OAuthTokens, PkceChallenge, SessionData, TokenRequest, TokenResponse},
    AppState,
};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    Json,
};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use tracing::{debug, info, warn};

#[derive(Debug, Serialize)]
pub struct DeviceAuthResponse {
    pub auth_url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCodeSubmit {
    pub code: String,
    pub state: String,
}

// Start device authorization flow
pub async fn start_device_flow(State(state): State<AppState>) -> Result<impl IntoResponse> {
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

    // Build authorization URL (matching OpenCode's exact format)
    let auth_params = vec![
        ("code", "true"),
        ("client_id", &state.config.client_id),
        ("response_type", "code"),
        ("redirect_uri", &state.config.redirect_uri),
        ("scope", "org:create_api_key user:profile user:inference"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", &oauth_state),
    ];

    let auth_url = format!(
        "{}/oauth/authorize?{}",
        state.config.oauth_base_url,
        serde_urlencoded::to_string(auth_params).unwrap()
    );

    info!("Device flow auth URL: {}", auth_url);

    Ok(Json(DeviceAuthResponse {
        auth_url,
        state: oauth_state,
    }))
}

// Submit authorization code from device flow
pub async fn submit_device_code(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(mut payload): Json<DeviceCodeSubmit>,
) -> Result<impl IntoResponse> {
    debug!("Device code submitted: {:?}", payload);

    // Handle case where code contains both code and state (separated by #)
    if payload.code.contains('#') {
        let parts: Vec<String> = payload.code.split('#').map(str::to_string).collect();
        if parts.len() == 2 {
            payload.code = parts[0].to_string();
            payload.state = parts[1].to_string();
            debug!(
                "Parsed code and state from combined input: code={}, state={}",
                payload.code, payload.state
            );
        }
    }

    // Retrieve and validate PKCE challenge
    let pkce_challenge = state
        .session_store
        .get_pkce_challenge(&payload.state)
        .ok_or(AppError::InvalidState)?;

    // Exchange authorization code for tokens
    let token_request = TokenRequest {
        grant_type: "authorization_code".to_string(),
        client_id: state.config.client_id.clone(),
        code: Some(payload.code),
        redirect_uri: Some(state.config.redirect_uri.clone()),
        code_verifier: Some(pkce_challenge.verifier),
        refresh_token: None,
        state: Some(payload.state.clone()),
    };

    let token_response = exchange_tokens(&state, token_request).await?;

    // Clean up PKCE challenge
    state.session_store.remove_pkce_challenge(&payload.state);

    // EXPERIMENTAL: Try refreshing immediately - maybe initial tokens aren't valid for API use
    info!("Initial token obtained, attempting immediate refresh...");
    let final_tokens = if let Some(refresh_token) = &token_response.refresh_token {
        let refresh_request = TokenRequest {
            grant_type: "refresh_token".to_string(),
            client_id: state.config.client_id.clone(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(refresh_token.clone()),
            state: None,
        };

        match exchange_tokens(&state, refresh_request).await {
            Ok(refreshed) => {
                info!("✅ Immediate token refresh successful!");
                if !refreshed.extra.is_empty() {
                    info!("Extra fields in refreshed token: {:?}", refreshed.extra);
                }
                TokenResponse {
                    access_token: refreshed.access_token,
                    token_type: refreshed.token_type,
                    expires_in: refreshed.expires_in,
                    refresh_token: refreshed.refresh_token.or(token_response.refresh_token),
                    scope: refreshed.scope.or(token_response.scope),
                    extra: refreshed.extra,
                }
            }
            Err(e) => {
                warn!(
                    "Immediate token refresh failed: {:?}, using original tokens",
                    e
                );
                token_response
            }
        }
    } else {
        token_response
    };

    // Create session
    let session_id = SessionStore::generate_session_id();
    let session_data = SessionData {
        tokens: OAuthTokens {
            access_token: final_tokens.access_token,
            refresh_token: final_tokens.refresh_token,
            expires_at: Utc::now() + Duration::seconds(final_tokens.expires_in as i64),
        },
        user_id: None,
        api_key: None,
    };

    state
        .session_store
        .create_session(&session_id, session_data);

    // Set session cookie
    let cookie =
        axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE_NAME, session_id.clone()))
            .http_only(true)
            .secure(false) // Set to true in production with HTTPS
            .same_site(axum_extra::extract::cookie::SameSite::Lax)
            .path("/")
            .build();

    let updated_jar = jar.add(cookie);

    // Log the session cookie value for easy testing
    info!("✅ Authentication successful!");
    info!("Session cookie created: anthropic_session={}", session_id);
    info!("To test with curl or the example client:");
    info!("  export ANTHROPIC_SESSION={}", session_id);
    info!("  cargo run --example client");

    Ok((
        updated_jar,
        Json(serde_json::json!({
            "success": true,
            "message": "Authentication successful",
            "session_id": session_id
        })),
    )
        .into_response())
}

// Interactive device flow page
pub async fn device_flow_page() -> impl IntoResponse {
    Html(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Anthropic OAuth - Device Flow</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2d3748;
            margin-bottom: 1rem;
        }
        .step {
            margin: 1.5rem 0;
            padding: 1rem;
            background: #f7fafc;
            border-radius: 4px;
            border-left: 4px solid #4299e1;
        }
        button {
            background: #4299e1;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
            margin: 0.5rem 0;
        }
        button:hover {
            background: #3182ce;
        }
        input[type="text"] {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            font-size: 1rem;
            margin: 0.5rem 0;
        }
        .url-container {
            background: #f7fafc;
            padding: 1rem;
            border-radius: 4px;
            margin: 1rem 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9rem;
        }
        .success {
            color: #48bb78;
            font-weight: bold;
        }
        .error {
            color: #f56565;
            font-weight: bold;
        }
        #status {
            margin-top: 1rem;
            padding: 1rem;
            border-radius: 4px;
            display: none;
        }
        #status.success {
            background: #c6f6d5;
            display: block;
        }
        #status.error {
            background: #fed7d7;
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Anthropic OAuth - Device Flow</h1>

        <div class="step">
            <h3>Step 1: Start Authorization</h3>
            <p>Click the button below to generate an authorization URL:</p>
            <button onclick="startAuth()">Start Authorization</button>
            <div id="auth-url" class="url-container" style="display: none;"></div>
        </div>

        <div class="step">
            <h3>Step 2: Authorize in Claude</h3>
            <p>Visit the URL above (or click the button to open it) and authorize the application.</p>
            <button id="open-url" onclick="openAuthUrl()" style="display: none;">Open Authorization URL</button>
        </div>

        <div class="step">
            <h3>Step 3: Paste Authorization Code</h3>
            <p>After authorizing, copy the code from Claude and paste it here:</p>
            <input type="text" id="auth-code" placeholder="Paste authorization code here">
            <button onclick="submitCode()">Submit Code</button>
        </div>

        <div id="status"></div>
    </div>

    <script>
        let currentState = '';
        let authUrl = '';

        async function startAuth() {
            try {
                const response = await fetch('/auth/device/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                const data = await response.json();

                if (response.ok) {
                    currentState = data.state;
                    authUrl = data.auth_url;

                    document.getElementById('auth-url').textContent = authUrl;
                    document.getElementById('auth-url').style.display = 'block';
                    document.getElementById('open-url').style.display = 'inline-block';

                    showStatus('Authorization URL generated! Visit the URL to continue.', 'success');
                } else {
                    showStatus('Failed to start authorization: ' + (data.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'error');
            }
        }

        function openAuthUrl() {
            if (authUrl) {
                window.open(authUrl, '_blank');
            }
        }

        async function submitCode() {
            const code = document.getElementById('auth-code').value.trim();

            if (!code) {
                showStatus('Please enter an authorization code', 'error');
                return;
            }

            if (!currentState) {
                showStatus('Please start authorization first', 'error');
                return;
            }

            try {
                const response = await fetch('/auth/device/submit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        code: code,
                        state: currentState
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    let statusMessage = '✅ Authentication successful!<br><br>';
                    
                    if (data.session_id) {
                        statusMessage += '<strong>Your session cookie value:</strong><br>';
                        statusMessage += '<code style="background: #f0f0f0; padding: 8px; border-radius: 4px; display: inline-block; margin: 8px 0; user-select: all; font-family: monospace;">' + data.session_id + '</code><br><br>';
                        statusMessage += '<strong>To use with the example client:</strong><br>';
                        statusMessage += '<code style="background: #f0f0f0; padding: 8px; border-radius: 4px; display: inline-block; margin: 8px 0; font-family: monospace;">ANTHROPIC_SESSION=' + data.session_id + ' cargo run --example client</code>';
                    }
                    
                    showStatus(statusMessage, 'success');
                    document.getElementById('auth-code').value = '';
                } else {
                    showStatus('Authentication failed: ' + (data.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'error');
            }
        }

        function showStatus(message, type) {
            const status = document.getElementById('status');
            status.innerHTML = message;  // Changed from textContent to innerHTML to support HTML
            status.className = type;
        }
    </script>
</body>
</html>
    "#,
    )
}
