/**
 * VK Media MCP Server
 *
 * An MCP server for searching newspaper articles across VK Media properties,
 * using the user's existing authentication cookie for API access.
 *
 * Supported sites:
 * - vk.se
 * - folkbladet.nu
 * - vasterbottningen.se
 * - lokaltidningen.se
 * - nordsverige.se
 * - mellanbygden.nu
 *
 * Compliant with MCP November 2025 spec:
 * - OAuth 2.1 with PKCE
 * - Resource Indicators (RFC 8707)
 * - Authorization Server Metadata (RFC 8414)
 * - Dynamic Client Registration (RFC 7591)
 * - Streamable HTTP transport
 */

import { OAuthProvider, type OAuthHelpers } from '@cloudflare/workers-oauth-provider';
import { McpAgent } from 'agents/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AuthContext, VKSearchResponse, SanitizedArticle } from './types';

// Supported newspaper sites
interface SiteConfig {
	name: string;
	domain: string;
	searchApiBase: string;
	apiPathPrefix: string; // e.g., 'vk' for vk.se, 'folkbladet' for folkbladet.nu
}

const SITES: Record<string, SiteConfig> = {
	'vk.se': {
		name: 'VK',
		domain: 'vk.se',
		searchApiBase: 'https://news.content.vk.se',
		apiPathPrefix: 'vk',
	},
	'folkbladet.nu': {
		name: 'Folkbladet',
		domain: 'folkbladet.nu',
		searchApiBase: 'https://news.content.folkbladet.nu',
		apiPathPrefix: 'folkbladet',
	},
	'vasterbottningen.se': {
		name: 'Västerbottningen',
		domain: 'vasterbottningen.se',
		searchApiBase: 'https://news.content.vasterbottningen.se',
		apiPathPrefix: 'vasterbottningen',
	},
	'lokaltidningen.nu': {
		name: 'Lokaltidningen',
		domain: 'lokaltidningen.nu',
		searchApiBase: 'https://news.content.lokaltidningen.nu',
		apiPathPrefix: 'lokaltidningen',
	},
	'nordsverige.se': {
		name: 'Nordsverige',
		domain: 'nordsverige.se',
		searchApiBase: 'https://news.content.nordsverige.se',
		apiPathPrefix: 'nordsverige',
	},
	'mellanbygden.nu': {
		name: 'Mellanbygden',
		domain: 'mellanbygden.nu',
		searchApiBase: 'https://news.content.mellanbygden.nu',
		apiPathPrefix: 'mellanbygden',
	},
};

// Default site (fallback)
const DEFAULT_SITE = SITES['vk.se'];

// Login URL (shared across all VK Media sites)
const VK_LOGIN_URL = 'https://konto.vkmedia.se/login';

/**
 * Extract the site domain from the request hostname
 * e.g., mcp.content.vk.se -> vk.se
 */
function getSiteFromHost(hostname: string): SiteConfig {
	// Try to match against known sites
	for (const [siteDomain, config] of Object.entries(SITES)) {
		if (hostname.endsWith(siteDomain) || hostname.includes(siteDomain)) {
			return config;
		}
	}
	// Fallback to default
	return DEFAULT_SITE;
}

/**
 * Get the server URL for a site
 */
function getServerUrl(site: SiteConfig): string {
	return `https://mcp.content.${site.domain}`;
}

/**
 * Get the search API URL for a site
 */
function getSearchApiUrl(site: SiteConfig): string {
	return `${site.searchApiBase}/${site.apiPathPrefix}/rest/articles/search`;
}

// Extend Env to include OAuth provider helpers
interface EnvWithOAuth extends Env {
	OAUTH_PROVIDER: OAuthHelpers;
}

// Extended auth context with site info
interface ExtendedAuthContext extends AuthContext {
	siteDomain: string;
}

/**
 * MCP Agent for newspaper article search
 */
export class VKMcpAgent extends McpAgent<Env, unknown, ExtendedAuthContext> {
	server = new McpServer({
		name: 'VK Media Article Search',
		version: '1.0.0',
	});

	async init() {
		// Register the search tool
		this.server.tool(
			'search_articles',
			'Search newspaper articles',
			{
				search: z.string().describe('Search query for articles'),
				limit: z.number().min(1).max(50).default(15).describe('Number of results to return (1-50)'),
				page: z.number().min(0).default(0).describe('Page number for pagination'),
			},
			async ({ search, limit, page }) => {
				try {
					// Get the auth token and site from context
					const authToken = this.props?.authToken;
					const siteDomain = this.props?.siteDomain || 'vk.se';
					const site = SITES[siteDomain] || DEFAULT_SITE;

					if (!authToken) {
						return {
							content: [{
								type: 'text' as const,
								text: `Session expired - please reconnect to ${site.name} MCP server`,
							}],
							isError: true,
						};
					}

					// Call search API for this site
					const apiUrl = new URL(getSearchApiUrl(site));
					apiUrl.searchParams.set('search', search);
					apiUrl.searchParams.set('limit', String(limit));
					apiUrl.searchParams.set('page', String(page));

					const response = await fetch(apiUrl.toString(), {
						headers: {
							'Cookie': `auth_token=${authToken}`,
							'Content-Type': 'application/json',
						},
					});

					if (!response.ok) {
						return {
							content: [{
								type: 'text' as const,
								text: `Unable to access ${site.name} at this time`,
							}],
							isError: true,
						};
					}

					const data = await response.json() as VKSearchResponse;

					// Sanitize response - only return safe fields
					const articles: SanitizedArticle[] = data.result.hits.map(article => ({
						headline: article.headline,
						preamble: article.preamble,
						section: article.section?.name || 'Unknown',
						authors: article.authors?.map(a => a.name) || [],
						publishDate: article.publishDate,
					}));

					return {
						content: [{
							type: 'text' as const,
							text: JSON.stringify({
								site: site.name,
								totalHits: data.result.totalHits,
								page,
								limit,
								articles,
							}, null, 2),
						}],
					};
				} catch (error) {
					return {
						content: [{
							type: 'text' as const,
							text: 'Unable to access the newspaper at this time',
						}],
						isError: true,
					};
				}
			}
		);
	}
}

/**
 * Parse a specific cookie from the Cookie header
 */
function parseCookie(cookieHeader: string, name: string): string | null {
	const cookies = cookieHeader.split(';');
	for (const cookie of cookies) {
		const [cookieName, ...cookieValue] = cookie.trim().split('=');
		if (cookieName === name) {
			return cookieValue.join('=');
		}
	}
	return null;
}

/**
 * OAuth/Authorization handler
 * Handles the authorization flow using the site's existing cookie
 */
const authHandler = {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	async fetch(request: Request, env: any, ctx: ExecutionContext): Promise<Response> {
		const oauthEnv = env as EnvWithOAuth;
		const url = new URL(request.url);
		const site = getSiteFromHost(url.hostname);
		const serverUrl = getServerUrl(site);

		// OAuth Protected Resource Metadata (RFC 9728) - tells Claude where to find auth
		if (url.pathname === '/.well-known/oauth-protected-resource') {
			return Response.json({
				resource: serverUrl,
				authorization_servers: [serverUrl],
				scopes_supported: ['articles:search'],
			}, {
				headers: {
					'Content-Type': 'application/json',
					'Cache-Control': 'public, max-age=3600',
				},
			});
		}

		// OAuth 2.1 Authorization Server Metadata (RFC 8414)
		if (url.pathname === '/.well-known/oauth-authorization-server') {
			return Response.json({
				issuer: serverUrl,
				authorization_endpoint: `${serverUrl}/authorize`,
				token_endpoint: `${serverUrl}/token`,
				registration_endpoint: `${serverUrl}/register`,
				scopes_supported: ['articles:search'],
				response_types_supported: ['code'],
				grant_types_supported: ['authorization_code'],
				code_challenge_methods_supported: ['S256'],
				token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
				service_documentation: `https://www.${site.domain}`,
				// MCP endpoint for tool calls
				mcp_endpoint: `${serverUrl}/mcp`,
			}, {
				headers: {
					'Content-Type': 'application/json',
					'Cache-Control': 'public, max-age=3600',
				},
			});
		}

		// Authorization endpoint
		if (url.pathname === '/authorize') {
			try {
				// Parse OAuth request using the provider
				const oauthReqInfo = await oauthEnv.OAUTH_PROVIDER.parseAuthRequest(request);

				// Validate PKCE is present (required by MCP spec)
				if (!oauthReqInfo.codeChallenge || oauthReqInfo.codeChallengeMethod !== 'S256') {
					const redirectUri = new URL(oauthReqInfo.redirectUri);
					redirectUri.searchParams.set('error', 'invalid_request');
					redirectUri.searchParams.set('error_description', 'PKCE with S256 is required');
					if (oauthReqInfo.state) {
						redirectUri.searchParams.set('state', oauthReqInfo.state);
					}
					return Response.redirect(redirectUri.toString(), 302);
				}

				// Read the auth_token cookie
				const cookies = request.headers.get('Cookie') || '';
				const authToken = parseCookie(cookies, 'auth_token');

				// If no cookie, redirect to VK Media login
				if (!authToken) {
					const loginRedirect = new URL(VK_LOGIN_URL);
					loginRedirect.searchParams.set('redirect', request.url);
					return Response.redirect(loginRedirect.toString(), 302);
				}

				// Complete the authorization - store the auth token and site in props
				// The OAuthProvider will encrypt these props into the access token
				const { redirectTo } = await oauthEnv.OAUTH_PROVIDER.completeAuthorization({
					request: oauthReqInfo,
					userId: 'vkmedia-user', // We don't have user ID, just the token
					metadata: { service: site.name, domain: site.domain },
					scope: ['articles:search'],
					props: {
						authToken: authToken,
						clientId: oauthReqInfo.clientId,
						resource: serverUrl,
						siteDomain: site.domain,
					} satisfies ExtendedAuthContext,
				});

				return Response.redirect(redirectTo, 302);
			} catch (error) {
				// Return OAuth error response
				const redirectUri = url.searchParams.get('redirect_uri');
				const state = url.searchParams.get('state');
				if (redirectUri) {
					const errorUrl = new URL(redirectUri);
					errorUrl.searchParams.set('error', 'invalid_request');
					errorUrl.searchParams.set('error_description', error instanceof Error ? error.message : 'Authorization failed');
					if (state) {
						errorUrl.searchParams.set('state', state);
					}
					return Response.redirect(errorUrl.toString(), 302);
				}
				return Response.json({ error: 'invalid_request', error_description: 'Authorization failed' }, { status: 400 });
			}
		}

		// Root path - redirect to metadata or show info
		if (url.pathname === '/') {
			return Response.json({
				name: `${site.name} MCP Server`,
				mcp_endpoint: `${serverUrl}/mcp`,
				oauth_metadata: `${serverUrl}/.well-known/oauth-authorization-server`,
			});
		}

		// Default: return 404
		return new Response('Not Found', { status: 404 });
	},
};

// Create the MCP handler using McpAgent.serve()
const mcpHandler = VKMcpAgent.serve('/mcp', {
	binding: 'MCP_OBJECT',
});

/**
 * Main OAuth Provider export
 */
export default new OAuthProvider({
	apiRoute: '/mcp',
	apiHandler: mcpHandler,
	defaultHandler: authHandler,
	authorizeEndpoint: '/authorize',
	tokenEndpoint: '/token',
	clientRegistrationEndpoint: '/register',
	scopesSupported: ['articles:search'],
	// 7 days token TTL
	refreshTokenTTL: 7 * 24 * 60 * 60,
});
