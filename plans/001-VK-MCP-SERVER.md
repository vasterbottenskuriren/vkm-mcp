# 001: VK MCP Server Implementation Plan

## Overview

Build an MCP (Model Context Protocol) server on Cloudflare Workers that allows Claude (Claude.ai and Claude Code) and ChatGPT to search VK.se articles using the user's existing authentication.

**MCP Spec Compliance**: November 2025 specification with OAuth 2.1, PKCE, Resource Indicators (RFC 8707), and Authorization Server Metadata (RFC 8414).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Discovery & Registration                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Client ──► /.well-known/oauth-authorization-server                     │
│                  │                                                       │
│                  ▼                                                       │
│         Returns metadata:                                                │
│         - authorization_endpoint                                         │
│         - token_endpoint                                                 │
│         - registration_endpoint                                          │
│         - supported scopes, PKCE methods                                │
│                                                                          │
│  Client ──► /oauth/register (Dynamic Client Registration)               │
│                  │                                                       │
│                  ▼                                                       │
│         Returns client_id (+ client_secret for confidential clients)    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                           OAuth 2.1 Flow                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Client ──► /oauth/authorize                                            │
│             (with code_challenge, resource indicator)                   │
│                  │                                                       │
│                  ▼                                                       │
│         Browser ──► mcp.content.vk.se                                   │
│                          │                                               │
│                          ▼                                               │
│              ┌──────────────────────┐                                   │
│              │ No auth_token cookie? │                                   │
│              └──────────┬───────────┘                                   │
│                         │                                                │
│        ┌────────────────┴────────────────┐                              │
│        ▼                                 ▼                               │
│  Redirect to                      Read cookie                            │
│  konto.vkmedia.se/login          Store in KV with auth_code             │
│                                          │                               │
│                                          ▼                               │
│                                Redirect to Client                        │
│                                with auth_code                            │
│                                          │                               │
│  Client ──► /oauth/token ◄──────────────┘                               │
│             (with code_verifier, resource indicator)                    │
│                  │                                                       │
│                  ▼                                                       │
│         Validate PKCE, resource indicator                               │
│         Generate access_token (scoped to resource)                      │
│         Store: access_token → auth_token in KV                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    MCP Tool Call (Streamable HTTP)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Client ──► /mcp (POST with Bearer access_token)                        │
│                  │                                                       │
│                  ▼                                                       │
│         Validate token audience matches this server                     │
│         KV lookup: access_token → auth_token                            │
│                  │                                                       │
│                  ▼                                                       │
│         Call VK API with auth_token                                      │
│         https://news.content.vk.se/vk/rest/articles/search              │
│                  │                                                       │
│                  ▼                                                       │
│         Return sanitized results (streamable HTTP response)             │
│         (headline, preamble, section, authors, publishDate)             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## MCP 2025 Spec Compliance

| Requirement | Status | Notes |
|-------------|--------|-------|
| OAuth 2.1 | ✅ | Authorization code flow with PKCE |
| PKCE (RFC 7636) | ✅ | Required, S256 method |
| Resource Indicators (RFC 8707) | ✅ | Prevents token mis-redemption |
| Auth Server Metadata (RFC 8414) | ✅ | `/.well-known/oauth-authorization-server` |
| Dynamic Client Registration (RFC 7591) | ✅ | `/oauth/register` endpoint |
| Streamable HTTP Transport | ✅ | Replaces SSE-only |

## Implementation Steps

### Phase 1: Project Setup

- [ ] **1.1** Add required dependencies
  - `@cloudflare/workers-oauth-provider` - OAuth provider framework (if available)
  - `@modelcontextprotocol/sdk` - MCP server implementation
  - `hono` - Lightweight router for Workers (optional)

- [ ] **1.2** Configure wrangler.jsonc
  - Add KV namespace binding (`OAUTH_KV`)
  - Add rate limit bindings (`OAUTH_RATE_LIMIT`, `MCP_RATE_LIMIT`)
  - Set up route for `mcp.content.vk.se`

- [ ] **1.3** Generate TypeScript types
  - Run `npm run cf-typegen` after updating bindings

### Phase 2: OAuth 2.1 Discovery & Registration

- [ ] **2.1** Implement `/.well-known/oauth-authorization-server` endpoint
  ```json
  {
    "issuer": "https://mcp.content.vk.se",
    "authorization_endpoint": "https://mcp.content.vk.se/oauth/authorize",
    "token_endpoint": "https://mcp.content.vk.se/oauth/token",
    "registration_endpoint": "https://mcp.content.vk.se/oauth/register",
    "scopes_supported": ["vk:search"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["S256"],
    "token_endpoint_auth_methods_supported": ["none", "client_secret_post"]
  }
  ```

- [ ] **2.2** Implement `/oauth/register` endpoint (Dynamic Client Registration)
  - Accept `redirect_uris`, `client_name`, `token_endpoint_auth_method`
  - Generate `client_id` (UUID)
  - For confidential clients: generate `client_secret`
  - Store in KV: `client:{client_id}` → `{ redirect_uris, client_name, client_secret_hash }`
  - Return registration response

### Phase 3: OAuth 2.1 Authorization Flow

- [ ] **3.1** Implement `/oauth/authorize` endpoint
  - Validate required params: `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`
  - Validate `resource` parameter (RFC 8707) matches `https://mcp.content.vk.se`
  - Look up client in KV, validate `redirect_uri` against registered URIs
  - Read `auth_token` cookie from request
  - If missing: redirect to `https://konto.vkmedia.se/login?redirect={encoded_current_url}`
  - Generate auth_code (UUID)
  - Store in KV: `auth_code:{code}` → `{auth_token, code_challenge, client_id, redirect_uri, resource}` (TTL: 5 min)
  - Redirect to `redirect_uri?code={auth_code}&state={state}`

- [ ] **3.2** Implement `/oauth/token` endpoint
  - Validate `grant_type=authorization_code`
  - Validate auth_code exists in KV
  - Validate PKCE: hash `code_verifier` with SHA256, compare to stored `code_challenge`
  - Validate `resource` parameter matches stored resource
  - For confidential clients: validate `client_secret`
  - Generate MCP access_token (UUID)
  - Store in KV: `access_token:{token}` → `{auth_token, client_id, resource}` (TTL: 7 days)
  - Delete auth_code from KV
  - Return:
    ```json
    {
      "access_token": "uuid",
      "token_type": "Bearer",
      "expires_in": 604800,
      "scope": "vk:search"
    }
    ```

### Phase 4: MCP Server Implementation

- [ ] **4.1** Set up MCP server with Streamable HTTP transport
  - Handle POST requests to `/mcp`
  - Support both single request/response and streaming
  - Extract Bearer token from Authorization header
  - Validate token exists in KV and `resource` matches this server
  - Look up auth_token from KV

- [ ] **4.2** Implement `vk_search` tool
  - Parameters:
    - `search` (string, required) - search query
    - `limit` (number, optional, default: 15, max: 50)
    - `page` (number, optional, default: 0)
  - Call VK API: `https://news.content.vk.se/vk/rest/articles/search?limit={limit}&page={page}&search={search}`
  - Pass auth_token as cookie in request
  - Transform response to only include: headline, preamble, section.name, authors[].name, publishDate
  - Return formatted results
  - On VK API errors: return "Unable to access VK at this time"

- [ ] **4.3** Handle token expiry / invalid tokens
  - If KV lookup returns null, return MCP error prompting re-authentication
  - Return appropriate HTTP 401 with `WWW-Authenticate` header

### Phase 5: Security Implementation

- [ ] **5.1** Rate limiting
  - `/.well-known/*`: 100 requests/minute per IP (discovery is lightweight)
  - `/oauth/register`: 5 requests/minute per IP (prevent registration spam)
  - `/oauth/authorize`: 10 requests/minute per IP
  - `/oauth/token`: 10 requests/minute per IP
  - `/mcp`: 60 requests/minute per access_token

- [ ] **5.2** PKCE implementation (mandatory)
  - Require `code_challenge` and `code_challenge_method=S256` on authorize
  - Validate `code_verifier` on token exchange using SHA256
  - Reject requests without valid PKCE

- [ ] **5.3** Resource Indicators (RFC 8707)
  - Require `resource=https://mcp.content.vk.se` on authorize and token requests
  - Store resource with auth_code and access_token
  - Validate resource on token use (prevents token from being used on other servers)

- [ ] **5.4** Redirect URI validation
  - Only allow URIs registered via `/oauth/register`
  - Exact match validation (no wildcards)

- [ ] **5.5** Response sanitization
  - Never return auth_token or internal IDs to clients
  - Only return the 5 specified article fields

### Phase 6: Testing

- [ ] **6.1** Unit tests
  - OAuth metadata endpoint
  - Dynamic client registration
  - OAuth flow: authorize, token exchange
  - PKCE validation
  - Resource indicator validation
  - Rate limiting
  - MCP tool execution

- [ ] **6.2** Integration tests
  - Full OAuth flow with mock cookies
  - MCP search with mock VK API responses
  - Token rejection for wrong resource

### Phase 7: Deployment

- [ ] **7.1** Create KV namespace
  ```bash
  wrangler kv namespace create OAUTH_KV
  ```

- [ ] **7.2** Configure DNS
  - Add `mcp.content.vk.se` CNAME pointing to Workers

- [ ] **7.3** Deploy
  ```bash
  npm run deploy
  ```

- [ ] **7.4** Test with Claude Code
  - Configure MCP server in Claude Code settings
  - Test OAuth flow and search

- [ ] **7.5** Test with ChatGPT (optional)
  - Enable developer mode
  - Add MCP connector
  - Test OAuth flow and search

## File Structure

```
src/
├── index.ts                  # Main worker entry, routing
├── well-known/
│   └── oauth-metadata.ts     # /.well-known/oauth-authorization-server
├── oauth/
│   ├── register.ts           # /oauth/register - Dynamic Client Registration
│   ├── authorize.ts          # /oauth/authorize
│   ├── token.ts              # /oauth/token
│   └── pkce.ts               # PKCE utilities (S256 hash, validation)
├── mcp/
│   ├── server.ts             # MCP server setup, streamable HTTP handler
│   └── tools/
│       └── search.ts         # vk_search tool implementation
├── utils/
│   ├── rate-limit.ts         # Rate limiting helpers
│   ├── cookies.ts            # Cookie parsing
│   └── resource-indicator.ts # RFC 8707 validation
└── types.ts                  # TypeScript interfaces
```

## KV Schema

| Key Pattern | Value | TTL |
|-------------|-------|-----|
| `client:{uuid}` | `{ redirect_uris[], client_name, client_secret_hash?, created_at }` | none |
| `auth_code:{uuid}` | `{ auth_token, code_challenge, client_id, redirect_uri, resource }` | 5 min |
| `access_token:{uuid}` | `{ auth_token, client_id, resource, created_at }` | 7 days |

## Configuration (wrangler.jsonc)

```jsonc
{
  "name": "vkm-mcp",
  "main": "src/index.ts",
  "compatibility_date": "2025-12-19",
  "routes": [
    { "pattern": "mcp.content.vk.se", "zone_name": "content.vk.se" }
  ],
  "kv_namespaces": [
    { "binding": "OAUTH_KV", "id": "xxx" }
  ],
  "rate_limits": [
    { "binding": "DISCOVERY_RATE_LIMIT", "limit": 100, "period": 60 },
    { "binding": "REGISTER_RATE_LIMIT", "limit": 5, "period": 60 },
    { "binding": "OAUTH_RATE_LIMIT", "limit": 10, "period": 60 },
    { "binding": "MCP_RATE_LIMIT", "limit": 60, "period": 60 }
  ]
}
```

## Dependencies to Add

```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0"
  }
}
```

## Endpoints Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.1 metadata discovery |
| `/oauth/register` | POST | Dynamic Client Registration (RFC 7591) |
| `/oauth/authorize` | GET | Authorization endpoint (user redirect) |
| `/oauth/token` | POST | Token exchange |
| `/mcp` | POST | MCP streamable HTTP transport |

## Decisions

1. **Token TTL**: 7 days, no refresh tokens - user re-authenticates after expiry
2. **Tools**: Only `vk_search` for now, structured for future extensibility
3. **Error handling**: On VK API errors (401, 500, etc.), return generic "Unable to access VK at this time" message
4. **Transport**: Streamable HTTP (newer spec, supported by both Claude and ChatGPT)
5. **Client types**: Support both public clients (PKCE only) and confidential clients (with secret)

## Security Checklist

- [ ] auth_token never returned to clients
- [ ] PKCE enforced on all OAuth flows (S256 only)
- [ ] Resource Indicators validated (prevents token mis-redemption)
- [ ] Rate limiting on all endpoints
- [ ] Short TTL on auth codes (5 min)
- [ ] Redirect URI exact-match validation against registered URIs
- [ ] No sensitive data in logs
- [ ] Client secrets hashed before storage

## References

- [MCP Authorization Spec (March 2025)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [MCP Spec Updates (June 2025)](https://auth0.com/blog/mcp-specs-update-all-about-auth/)
- [MCP November 2025 Release](https://blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/)
- [Cloudflare MCP Authorization](https://developers.cloudflare.com/agents/model-context-protocol/authorization/)
- [RFC 8707 - Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8414 - OAuth Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591 - Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
