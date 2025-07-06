# Anthropic OAuth Proxy

A Rust-based OAuth proxy server for Anthropic's API, enabling OAuth authentication for Claude Pro/Max plans. This proxy implements the device authorization flow similar to how apps authenticate on TVs or limited-input devices.

**Note**: This proxy implements OAuth authentication for Anthropic's API, similar to other tools in the ecosystem. See [TECHNICAL.md](TECHNICAL.md) for implementation details.

## Features

- OAuth 2.0 authentication flow with PKCE for enhanced security
- Secure session management with signed cookies
- Session ID can be used as API key via `x-api-key` header
- Automatic token refresh
- API request proxying to Anthropic endpoints
- Built with Axum (web framework) and Reqwest (HTTP client)
- Full async/await support on Tokio runtime

## Prerequisites

- Rust 1.75 or later
- A Claude Pro or Claude Max account (required for OAuth authentication)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd anthropic-proxy
```

2. Copy the example environment file and configure:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Build the project:
```bash
cargo build --release
```

## Configuration

Create a `.env` file with the following variables:

```env
# Server Configuration
PORT=4001
SESSION_SECRET=your-strong-session-secret-here

# OAuth Configuration (these are the correct values for Anthropic)
CLIENT_ID=9d1c250a-e61b-44d9-88ed-5944d1962f5e
REDIRECT_URI=https://console.anthropic.com/oauth/code/callback
OAUTH_BASE_URL=https://claude.ai
API_BASE_URL=https://api.anthropic.com/v1

# Logging
RUST_LOG=anthropic_proxy=info,tower_http=info
```

**Note**: The CLIENT_ID and REDIRECT_URI are fixed values for Anthropic's OAuth system.

## Usage

1. Start the server:
```bash
cargo run --release
```

2. Navigate to `http://localhost:4000/auth/device` for the interactive authentication flow:
   - Click "Start Authorization" to generate an auth URL
   - Visit the URL in Claude.ai and authorize the application
   - Copy the authorization code from Claude
   - Paste it back into the proxy interface
   - The proxy will exchange the code for access tokens

3. After authentication, make API requests through the proxy:
```bash
curl -X POST http://localhost:4001/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -b "anthropic_session=your-session-cookie" \
  -d '{
    "model": "claude-opus-4-20250514",
    "messages": [{"role": "user", "content": "Hello, Claude!"}],
    "max_tokens": 1024
  }'
```


### Device Authorization Flow

This proxy uses the device authorization flow, similar to how TV apps authenticate:
1. The proxy generates an authorization URL with PKCE parameters
2. You visit this URL in your browser and log into Claude
3. Claude displays an authorization code in format: `{code}#{state}`
4. You copy this entire string back to the proxy
5. The proxy parses the code and state, then exchanges for API access tokens

### Using the Proxy with API Clients

Once authenticated, you can use any Anthropic API client by pointing it at the proxy:

#### Option 1: Using Session ID as API Key (Recommended)
```python
from anthropic import Anthropic

# Get your session ID from the proxy logs after authentication
client = Anthropic(
    base_url="http://localhost:4001/v1",
    api_key="12b8bbf5-493a-46ef-a69f-b8d6480a4f16"  # Your session ID
)

response = client.messages.create(
    model="claude-3-opus-20240229",
    messages=[{"role": "user", "content": "Hello!"}],
    max_tokens=100
)
```

#### Option 2: Using Cookies
```python
from anthropic import Anthropic

client = Anthropic(
    base_url="http://localhost:4001/v1",
    api_key="dummy",  # Required but ignored
    default_headers={
        "Cookie": "anthropic_session=YOUR_SESSION_ID"
    }
)
```

#### Integration with Tools (e.g., Zed Editor)
Many tools that support custom API endpoints can use the proxy:

```json
{
  "language_models": {
    "anthropic": {
      "api_url": "http://localhost:4001"
    }
  }
}
```

Then set your session ID as the API key in the tool's configuration.

#### Getting Your Session ID
After authenticating, your session ID is shown in the proxy logs:
```
Session cookie created: anthropic_session=12b8bbf5-493a-46ef-a69f-b8d6480a4f16
```

You can also:
1. Check browser DevTools > Application > Cookies > localhost:4001 > anthropic_session
2. Use the `/auth/status` endpoint to verify authentication
3. Run the example client: `ANTHROPIC_SESSION=<session-id> cargo run --example client`

## API Endpoints

### Authentication
- `GET /auth/device` - Interactive device flow authentication page
- `POST /auth/device/start` - Start device authorization (returns auth URL)
- `POST /auth/device/submit` - Submit authorization code
- `POST /auth/logout` - Clear session
- `GET /auth/status` - Check authentication status
- `POST /auth/refresh` - Manually refresh access token

### API Proxy
- `ALL /v1/*` - Proxy all Anthropic API requests

### Health
- `GET /health` - Health check endpoint

## Development

### Running Tests
```bash
cargo test
```

### Checking Code
```bash
cargo check
cargo clippy -- -D warnings
cargo fmt -- --check
```

### Building with Nix
This project includes Nix flake support:
```bash
nix develop  # Enter development shell
nix build    # Build the project
```

## Security Considerations

- Always use HTTPS in production
- Set a strong `SESSION_SECRET`
- Consider using a proper session store (Redis) in production
- Enable CORS only for trusted origins
- Implement rate limiting for production use

## License

[Add your license here]

## Contributing

[Add contribution guidelines]