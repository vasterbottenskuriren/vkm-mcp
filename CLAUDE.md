# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- `npm run dev` - Start local development server (runs on http://localhost:8787)
- `npm run deploy` - Deploy worker to Cloudflare
- `npm test` - Run tests with Vitest (some tests skipped due to MCP SDK limitations)
- `npm run cf-typegen` - Regenerate TypeScript types for Cloudflare bindings

## Architecture

This is an MCP (Model Context Protocol) server for searching newspaper articles across VK Media properties, deployed on Cloudflare Workers.

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

- **OAuthProvider** (`@cloudflare/workers-oauth-provider`) - Handles OAuth 2.1 flow with PKCE
- **McpAgent** (`agents/mcp`) - MCP server implementation with Durable Objects for state
- **VKMcpAgent** (`src/index.ts`) - Custom MCP agent exposing the `search_articles` tool
- **SITES config** - Maps domains to their search API endpoints

### Authentication Flow

1. Claude/ChatGPT initiates OAuth with `/authorize`
2. Worker detects site from hostname (e.g., `mcp.content.folkbladet.nu` → folkbladet.nu)
3. Reads `auth_token` cookie from `.content.{domain}`
4. If no cookie: redirect to `konto.vkmedia.se/login`
5. OAuthProvider encrypts token + site domain into MCP access token
6. MCP tool calls use decrypted token to call the correct site's API

### Endpoints (per site)

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/oauth-authorization-server` | OAuth 2.1 metadata (RFC 8414) |
| `/authorize` | OAuth authorization (reads site cookie) |
| `/token` | Token exchange (handled by OAuthProvider) |
| `/register` | Dynamic client registration (RFC 7591) |
| `/mcp` | MCP streamable HTTP transport |

### MCP Tool: search_articles

Parameters:
- `search` (string, required) - Search query
- `limit` (number, 1-50, default: 15) - Results per page
- `page` (number, default: 0) - Page number

Returns sanitized article data: site name, headline, preamble, section, authors, publishDate

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

## Deployment Prerequisites

1. Create KV namespace:
   ```bash
   wrangler kv namespace create OAUTH_KV
   ```
2. Update `wrangler.jsonc` with the KV namespace ID
3. Configure DNS for each site: `mcp.content.{domain}` CNAME to Workers
4. Deploy: `npm run deploy`

## MCP Spec Compliance

- OAuth 2.1 with PKCE (S256)
- Resource Indicators (RFC 8707)
- Authorization Server Metadata (RFC 8414)
- Dynamic Client Registration (RFC 7591)
- Streamable HTTP transport
