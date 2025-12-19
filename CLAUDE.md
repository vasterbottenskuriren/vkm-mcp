# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `npm run dev` - Start local development server (runs on http://localhost:8787)
- `npm run deploy` - Deploy worker to Cloudflare
- `npm test` - Run tests with Vitest
- `npm run cf-typegen` - Regenerate TypeScript types for Cloudflare bindings

## Architecture

This is an MCP (Model Context Protocol) server for searching newspaper articles across VK Media properties, deployed on Cloudflare Workers.

**Simple architecture: No Durable Objects, no external dependencies.** Just a Cloudflare Worker with KV for OAuth token storage.

### Supported Sites

The same worker handles multiple newspaper domains:

| Site | MCP Server URL |
|------|----------------|
| VK | `mcp.content.vk.se` |
| Folkbladet | `mcp.content.folkbladet.nu` |
| Västerbottningen | `mcp.content.vasterbottningen.se` |
| Lokaltidningen | `mcp.content.lokaltidningen.nu` |
| Nordsverige | `mcp.content.nordsverige.se` |
| Mellanbygden | `mcp.content.mellanbygden.nu` |

The worker automatically detects which site based on the request hostname.

### Key Components

- **OAuth handling** - Manual OAuth 2.1 implementation with PKCE (no external libraries)
- **MCP JSON-RPC** - Direct JSON-RPC handling over HTTP POST
- **KV Storage** - Stores OAuth tokens, authorization codes, and client registrations
- **SITES config** - Maps domains to their search API endpoints

### Authentication Flow

1. Claude.ai hits `/` and discovers OAuth via `/.well-known/oauth-protected-resource`
2. Claude registers client via `/register` (dynamic client registration)
3. OAuth flow via `/authorize` → VK Media login → callback with code
4. Token exchange via `/token` with PKCE verification
5. MCP calls to `/` (POST) with Bearer token
6. Worker validates token, extracts VK auth_token, calls VK search API

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Server info with OAuth discovery |
| `/` | POST | MCP JSON-RPC (main endpoint for Claude.ai) |
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 - tells Claude where to authenticate |
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.1 metadata (RFC 8414) |
| `/register` | POST | Dynamic client registration (RFC 7591) |
| `/authorize` | GET | OAuth authorization (reads VK cookie) |
| `/token` | POST | Token exchange with PKCE |
| `/sse` | GET | SSE transport (for Claude Code) |
| `/sse/message` | POST | SSE message endpoint |
| `/mcp` | POST | Alternative MCP endpoint |
| `/health` | GET | Health check |

### MCP Tool: search_articles

Parameters:
- `search` (string, required) - Search query
- `limit` (number, 1-50, default: 15) - Results per page
- `page` (number, default: 0) - Page number

Returns sanitized article data: headline, preamble, section, authors, publishDate

### KV Keys

| Pattern | Purpose | TTL |
|---------|---------|-----|
| `mcp_client:{id}` | OAuth client registration | 7 days |
| `mcp_code:{code}` | Authorization code | 10 minutes |
| `mcp_token:{token}` | Access token + VK auth_token | 1 hour |
| `mcp_refresh:{token}` | Refresh token | 7 days |
| `mcp_session:{id}` | SSE session data | 1 hour |

## Adding a New Site

1. Add entry to `SITES` in `src/index.ts`:
   ```typescript
   'newsite.se': {
     name: 'New Site',
     domain: 'newsite.se',
     searchApiBase: 'https://news.content.newsite.se',
     apiPathPrefix: 'newsite',
   },
   ```
2. Configure DNS: `mcp.content.newsite.se` CNAME to Workers
3. Deploy

## Deployment

1. Create KV namespace (if not exists):
   ```bash
   wrangler kv namespace create OAUTH_KV
   ```
2. Update `wrangler.jsonc` with the KV namespace ID
3. Configure DNS for each site
4. Deploy: `npm run deploy`

## MCP Spec Compliance

- OAuth 2.1 with PKCE (S256)
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)
- Dynamic Client Registration (RFC 7591)
- HTTP POST transport (Claude.ai)
- SSE transport (Claude Code)
