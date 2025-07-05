//! Example client demonstrating how to use the OAuth proxy
//!
//! Run with: cargo run --example client

use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy_base = "http://localhost:4001";

    // Get session cookie from environment or command line
    let session_cookie = std::env::var("ANTHROPIC_SESSION").ok();

    let client = Client::builder().cookie_store(true).build()?;

    println!("Anthropic OAuth Proxy Client Example");
    println!("====================================\n");

    if let Some(cookie) = &session_cookie {
        println!("Using session cookie from ANTHROPIC_SESSION env var");
        println!("Cookie value: {}...", &cookie[..20.min(cookie.len())]);
    } else {
        println!("NOTE: No ANTHROPIC_SESSION env var found.");
        println!(
            "After authenticating at {}/auth/device, get your session cookie from:",
            proxy_base
        );
        println!("  - Browser DevTools > Application > Cookies > localhost:4001");
        println!("  - Look for 'anthropic_session' cookie");
        println!("  - Run: ANTHROPIC_SESSION=<cookie-value> cargo run --example client");
    }
    println!();

    // Check authentication status
    println!("Checking authentication status...");
    let mut request = client.get(format!("{}/auth/status", proxy_base));

    // Add session cookie if provided
    if let Some(cookie) = &session_cookie {
        request = request.header("Cookie", format!("anthropic_session={}", cookie));
    }

    let status_resp = request.send().await?;

    let status: serde_json::Value = status_resp.json().await?;

    if !status["authenticated"].as_bool().unwrap_or(false) {
        println!("❌ Not authenticated!");
        println!("\nTo authenticate:");
        println!("1. Visit {}/auth/device", proxy_base);
        println!("2. Click 'Start Authorization'");
        println!("3. Visit the generated URL in your browser");
        println!("4. Copy the authorization code from Claude");
        println!("5. Paste it back in the proxy interface");
        println!("\nNote: The code from Claude will be in format: code#state");
        println!("\nThe proxy automatically handles OAuth token restrictions by");
        println!("injecting the Claude Code system prompt into your requests.");
        return Ok(());
    }

    // Make an API request
    println!("\nMaking a test API request...");

    let request_body = json!({
        "model": "claude-opus-4-20250514",
        "messages": [{
            "role": "user",
            "content": "Say 'Hello from the Rust OAuth proxy!' in a creative way."
        }],
        "max_tokens": 100,
        "system": "You are a helpful assistant."
    });

    let mut request = client
        .post(format!("{}/v1/messages", proxy_base))
        .header("Content-Type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .json(&request_body);

    // Add session cookie if provided
    if let Some(cookie) = &session_cookie {
        request = request.header("Cookie", format!("anthropic_session={}", cookie));
    }

    let response = request.send().await?;

    let status = response.status();
    let body: serde_json::Value = response.json().await?;

    println!("\nResponse Status: {}", status);
    println!("Response Body: {}", serde_json::to_string_pretty(&body)?);

    // Test token refresh
    println!("\nTesting token refresh...");
    let mut refresh_request = client.post(format!("{}/auth/refresh", proxy_base));

    // Add session cookie if provided
    if let Some(cookie) = &session_cookie {
        refresh_request = refresh_request.header("Cookie", format!("anthropic_session={}", cookie));
    }

    let refresh_resp = refresh_request.send().await?;

    println!("Refresh response: {}", refresh_resp.status());
    if refresh_resp.status().is_success() {
        println!("Token refreshed successfully!");
    }

    Ok(())
}
