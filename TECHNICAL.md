# Technical Implementation Details

This document describes the technical details of how the OAuth proxy works with Anthropic's API.

## OAuth Flow Implementation

The proxy implements a device authorization flow with the following endpoints:
- Authorization: `https://claude.ai/oauth/authorize`
- Token Exchange: `https://console.anthropic.com/v1/oauth/token`
- Fixed Redirect URI: `https://console.anthropic.com/oauth/code/callback`

## Key Technical Details

### PKCE Parameters
- Code verifier: 64 bytes (base64url encoded)
- State parameter: 64 bytes (base64url encoded)
- Code challenge method: S256

### Authorization Code Format
The authorization code from Claude is returned in a combined format:
```
{authorization_code}#{state}
```

The proxy automatically parses this format.

### Required Headers

The proxy adds these headers to all API requests:
1. `anthropic-beta: oauth-2025-04-20` - Enables OAuth support
2. `Authorization: Bearer {access_token}` - OAuth authentication
3. Removes any `x-api-key` headers that might conflict

### System Prompt Handling

For `/v1/messages` endpoints, the proxy modifies the request to ensure compatibility with OAuth tokens by prepending identification to the system prompt. This is done automatically and transparently.

The implementation handles both string and array system prompt formats, converting as needed to maintain the original prompt while adding required identification.

## Session Management

Sessions are managed through secure HTTP-only cookies:
- Cookie name: `anthropic_session`
- Sessions are stored in-memory (consider Redis for production)
- Session IDs are cryptographically random

## Error Handling

The proxy handles common OAuth errors:
- Invalid state parameters
- Expired tokens (with automatic refresh support)
- Network failures with appropriate error messages

## Security Considerations

- All PKCE parameters use cryptographically secure random generation
- State validation prevents CSRF attacks
- Session cookies are HTTP-only and signed
- Tokens are never exposed to the client