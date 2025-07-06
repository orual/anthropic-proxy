# CLAUDE.md - Anthropic OAuth Proxy

A Rust-based OAuth proxy server for Anthropic's API, built with Axum and Reqwest. This proxy handles OAuth authentication flow with PKCE and provides a secure interface to Anthropic's API endpoints.

## Project Overview

This proxy server enables OAuth-based authentication to Anthropic's API (for Claude Max plans) instead of API keys. It implements:
- OAuth 2.0 flow with PKCE for enhanced security
- Session management with secure token storage
- API request proxying with automatic token refresh
- Rate limiting and security middleware

## Architecture

- **Axum**: Modern async web framework for the HTTP server
- **Reqwest**: HTTP client for proxying requests to Anthropic
- **Tower**: Middleware stack for security, tracing, and rate limiting
- **Tower-sessions**: Session management with signed cookies

## Development Principles

- **Security first**: All auth flows use PKCE, sessions are signed, tokens are never exposed
- **Type safety**: Leverage Rust's type system for compile-time guarantees
- **Error handling**: Use Result types everywhere, no panics in production code
- **Async all the way**: Fully async/await based on Tokio runtime

## Build & Validation Commands

**Required validation before any commit:**

```bash
# 1. Check compilation
cargo check

# 2. Build the project
cargo build

# 3. Run tests
cargo test

# 4. Check formatting
cargo fmt -- --check

# 5. Run clippy lints
cargo clippy -- -D warnings
```

## Configuration

Create a `.env` file with:

```env
# Server
PORT=4001
SESSION_SECRET=your-strong-session-secret-here

# OAuth (fixed values for Anthropic)
CLIENT_ID=9d1c250a-e61b-44d9-88ed-5944d1962f5e
REDIRECT_URI=https://console.anthropic.com/oauth/code/callback
OAUTH_BASE_URL=https://claude.ai
API_BASE_URL=https://api.anthropic.com/v1
```

## API Endpoints

### Authentication
- `GET /auth/device` - Interactive device flow authentication page
- `POST /auth/device/start` - Start device authorization (returns auth URL)
- `POST /auth/device/submit` - Submit authorization code
- `POST /auth/logout` - Clear session
- `GET /auth/status` - Check auth status
- `POST /auth/refresh` - Refresh access token

### API Proxy
- `ALL /v1/*` - Proxy all Anthropic API requests

### Health
- `GET /health` - Health check endpoint

## Security Features

1. **PKCE Implementation**: Prevents authorization code interception
2. **State Validation**: CSRF protection on OAuth flow
3. **Secure Sessions**: Signed cookies, httpOnly, secure in production
4. **Rate Limiting**: Configurable limits on auth and API endpoints
5. **Request Sanitization**: Headers and body validation before proxying

## Usage

1. Start the server: `cargo run`
2. Navigate to `http://localhost:4001/auth/device`
3. Click "Start Authorization" and visit the generated URL
4. Copy the authorization code from Claude (format: `code#state`)
5. Paste it back in the proxy interface
6. Make API requests to `http://localhost:4001/v1/*`

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_oauth_flow
```

## Project Structure

```
src/
├── main.rs          # Server setup and routing
├── auth.rs          # OAuth token management and refresh
├── device_flow.rs   # Device authorization flow implementation
├── config.rs        # Configuration management
├── error.rs         # Error types and handling
├── proxy.rs         # API request proxying with automatic token refresh
├── session.rs       # Session store implementation
└── types.rs         # Shared types and structs
```

## Key Implementation Details

### OAuth Flow Type
This proxy implements a **Device Authorization Flow** where:
1. The proxy generates an authorization URL with PKCE parameters
2. User visits the URL in their browser and logs into Claude
3. Claude displays a code in format: `{authorization_code}#{state}`
4. User copies and pastes this combined code back to the proxy
5. Proxy parses the code, validates state, and exchanges for tokens

### OAuth Endpoints
- Authorization: `https://claude.ai/oauth/authorize`
- Token Exchange: `https://console.anthropic.com/v1/oauth/token`
- Redirect URI: `https://console.anthropic.com/oauth/code/callback` (fixed)
- Scopes: `org:create_api_key user:profile user:inference`

### PKCE Implementation
- Generates 64-byte code verifier (matching OpenCode's implementation)
- Generates 64-byte state parameter for security
- Uses SHA-256 for code challenge
- Validates state parameter to prevent CSRF attacks

### Important Discoveries
- The authorization code from Claude includes both code and state separated by `#`
- PKCE verifier and state must be 64 bytes (not 32 or 16)
- The redirect URI must be the Anthropic console callback URL
- Session cookies work for auth (no need to pass bearer tokens)

### OAuth Implementation

The proxy handles OAuth token compatibility by:

1. **Request Modification**: Automatically adjusts requests for OAuth compatibility
2. **Required Headers**:
   - `anthropic-beta: oauth-2025-04-20` (enables OAuth support)
   - `Authorization: Bearer {access_token}`
   - Standard Anthropic headers (anthropic-version, etc.)
3. **Header Filtering**: Removes any conflicting authentication headers

See TECHNICAL.md for detailed implementation notes.

## TODO

- [x] Implement proper error types with thiserror
- [x] Implement OAuth token compatibility
- [ ] Add comprehensive test suite
- [x] Implement token refresh middleware
- [ ] Add request/response logging
- [ ] Create Docker container
- [ ] Add metrics and monitoring
- [ ] Implement CORS configuration
- [ ] Add request retry logic
- [x] Create example client implementations