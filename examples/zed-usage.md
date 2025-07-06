# Using the OAuth Proxy with Zed

This guide shows how to configure Zed to use the OAuth proxy instead of connecting directly to Anthropic.

## Setup Steps

### 1. Start the OAuth Proxy

```bash
cargo run
```

The proxy will start on `http://localhost:4001`

### 2. Authenticate with the Proxy

Visit `http://localhost:4001/auth/device` and complete the OAuth flow. After authentication, you'll see your session ID in the logs:

```
Session cookie created: anthropic_session=12b8bbf5-493a-46ef-a69f-b8d6480a4f16
```

### 3. Configure Zed

Add the example configuration to your Zed settings.json (press `Ctrl+,` or `Cmd+,`):

```json
{
  "language_models": {
    "anthropic": {
      "api_url": "http://localhost:4001"
    }
  }
}
```

Or copy the full configuration from `examples/zed-config.json`.

### 4. Set Your Session as API Key

In Zed, you can provide the session ID as an API key in two ways:

#### Option A: Environment Variable
```bash
export ANTHROPIC_API_KEY=12b8bbf5-493a-46ef-a69f-b8d6480a4f16
zed
```

#### Option B: Through Zed's UI
1. Open the Agent Panel in Zed
2. Click on the Anthropic settings
3. Enter your session ID (e.g., `12b8bbf5-493a-46ef-a69f-b8d6480a4f16`) as the API key

## How It Works

The proxy now accepts session IDs through the `x-api-key` header, which is how Zed sends API keys. When Zed makes a request:

1. It sends the session ID in the `x-api-key` header
2. The proxy looks up the session and retrieves the OAuth tokens
3. The proxy forwards the request to Anthropic with proper OAuth authentication
4. The response is returned to Zed

## Benefits

- **No API Key Management**: Uses OAuth tokens from your Claude Max subscription
- **Session-based Auth**: One authentication works across multiple tools
- **Automatic Token Refresh**: The proxy handles token expiration
- **Works with Any Tool**: Any tool that supports custom API endpoints can use this approach

## Troubleshooting

If Zed shows authentication errors:

1. Check the proxy logs for the exact error
2. Verify your session is still valid: `curl http://localhost:4001/auth/status -H "x-api-key: YOUR_SESSION_ID"`
3. Re-authenticate if needed at `http://localhost:4001/auth/device`