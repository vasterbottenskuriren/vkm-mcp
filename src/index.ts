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

import { McpAgent } from 'agents/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VKSearchResponse, SanitizedArticle } from './types';

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

// Props passed to MCP agent after authentication
interface MCPProps extends Record<string, unknown> {
	authToken: string;
	siteDomain: string;
	email?: string;
}

/**
 * MCP Agent for newspaper article search
 */
export class VKMcpAgent extends McpAgent<Env, unknown, MCPProps> {
	server = new McpServer({
		name: 'VK Media Article Search',
		version: '1.0.0',
	});

	// Store auth context from request headers
	private authToken?: string;
	private siteDomain?: string;

	/**
	 * Override fetch to extract auth context from custom headers
	 */
	async fetch(request: Request): Promise<Response> {
		// Extract auth context from custom headers
		const authToken = request.headers.get('X-VK-Auth-Token');
		const siteDomain = request.headers.get('X-VK-Site-Domain');

		if (authToken) {
			this.authToken = authToken;
		}
		if (siteDomain) {
			this.siteDomain = siteDomain;
		}

		// Call parent fetch to handle MCP protocol
		return super.fetch(request);
	}

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
					// Get the auth token and site from instance or props
					const authToken = this.authToken || this.props?.authToken;
					const siteDomain = this.siteDomain || this.props?.siteDomain || 'vk.se';
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
 * CORS headers for all responses
 */
const corsHeaders = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
	'Access-Control-Expose-Headers': 'mcp-protocol-version',
	'Access-Control-Max-Age': '86400'
};

/**
 * Handle dynamic client registration (RFC 7591)
 */
async function handleClientRegistration(request: Request, env: Env, site: SiteConfig): Promise<Response> {
	console.log('=== MCP CLIENT REGISTRATION START ===');
	const body = await request.json().catch(() => ({})) as {
		redirect_uris?: string[];
		client_name?: string;
	};
	console.log('Registration request body:', JSON.stringify(body));

	const clientId = crypto.randomUUID();
	const clientSecret = crypto.randomUUID();
	console.log('Generated client_id:', clientId);

	// Default redirect URIs for MCP clients
	const defaultRedirectUris = [
		// Local development
		'http://127.0.0.1:6274/oauth/callback',
		'http://localhost:6274/oauth/callback',
		// Claude.ai
		'https://claude.ai/oauth/callback',
		'https://claude.ai/api/mcp/auth_callback',
	];

	const client = {
		client_id: clientId,
		client_secret: clientSecret,
		redirect_uris: body.redirect_uris || defaultRedirectUris,
		client_name: body.client_name || `${site.name} MCP Client`,
		grant_types: ['authorization_code', 'refresh_token'],
		response_types: ['code'],
		scope: 'articles:search'
	};

	// Store client in KV with TTL of 7 days
	await env.OAUTH_KV.put(`mcp_client:${clientId}`, JSON.stringify(client), { expirationTtl: 7 * 24 * 60 * 60 });

	console.log(`Registered MCP client: ${clientId}`);
	console.log('=== MCP CLIENT REGISTRATION END ===');

	return new Response(JSON.stringify({
		client_id: clientId,
		client_secret: clientSecret,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		grant_types: client.grant_types,
		response_types: client.response_types,
		scope: client.scope,
		redirect_uris: client.redirect_uris
	}), {
		headers: {
			'Content-Type': 'application/json',
			...corsHeaders
		}
	});
}

/**
 * Handle OAuth authorization
 */
async function handleAuthorization(request: Request, env: Env, site: SiteConfig, serverUrl: string): Promise<Response> {
	console.log('=== MCP AUTHORIZE START ===');
	const url = new URL(request.url);
	const clientId = url.searchParams.get('client_id');
	const redirectUri = url.searchParams.get('redirect_uri');
	const scope = url.searchParams.get('scope');
	const state = url.searchParams.get('state');
	const codeChallenge = url.searchParams.get('code_challenge');
	const codeChallengeMethod = url.searchParams.get('code_challenge_method');

	console.log('Authorize params:', { clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod });

	if (!clientId) {
		return new Response(JSON.stringify({
			error: 'invalid_request',
			error_description: 'Missing client_id'
		}), {
			status: 400,
			headers: { 'Content-Type': 'application/json', ...corsHeaders }
		});
	}

	// Get client from KV storage or accept known Claude.ai client
	let clientData = await env.OAUTH_KV.get(`mcp_client:${clientId}`);

	if (!clientData) {
		// Accept claude.ai's predetermined client ID or any claude.ai redirect
		if (redirectUri && redirectUri.includes('claude.ai')) {
			console.log(`Accepting claude.ai client: ${clientId}`);

			const claudeClient = {
				client_id: clientId,
				client_secret: 'claude-ai-predetermined',
				redirect_uris: [
					'https://claude.ai/api/mcp/auth_callback',
					redirectUri
				],
				client_name: 'Claude.ai',
				grant_types: ['authorization_code'],
				response_types: ['code'],
				scope: 'articles:search'
			};

			await env.OAUTH_KV.put(`mcp_client:${clientId}`, JSON.stringify(claudeClient), { expirationTtl: 7 * 24 * 60 * 60 });
			clientData = JSON.stringify(claudeClient);
		} else {
			return new Response(JSON.stringify({
				error: 'invalid_client',
				error_description: `Client not found: ${clientId}`
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}
	}

	const client = JSON.parse(clientData);
	const actualRedirectUri = redirectUri || client.redirect_uris[0];

	// Check if user has VK Media auth_token cookie
	const cookies = request.headers.get('Cookie') || '';
	const authToken = parseCookie(cookies, 'auth_token');

	if (!authToken) {
		// Redirect to VK Media login with return_to parameter
		const loginUrl = new URL(VK_LOGIN_URL);
		loginUrl.searchParams.set('redirect', request.url);
		console.log('No auth_token cookie, redirecting to VK login:', loginUrl.toString());
		return Response.redirect(loginUrl.toString());
	}

	console.log('Found auth_token cookie, generating authorization code');

	// Generate authorization code
	const code = crypto.randomUUID();
	const tokenData = {
		clientId,
		redirectUri: actualRedirectUri,
		scope,
		codeChallenge,
		codeChallengeMethod,
		authToken, // Store the VK auth token
		siteDomain: site.domain,
		expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
	};

	// Store authorization code in KV with 10 minute TTL
	await env.OAUTH_KV.put(`mcp_code:${code}`, JSON.stringify(tokenData), { expirationTtl: 600 });

	// Redirect back to client with code
	const params = new URLSearchParams({ code });
	if (state) params.append('state', state);

	console.log('Redirecting back with authorization code');
	console.log('=== MCP AUTHORIZE END ===');

	return Response.redirect(`${actualRedirectUri}?${params.toString()}`);
}

/**
 * Handle token exchange
 */
async function handleTokenExchange(request: Request, env: Env): Promise<Response> {
	console.log('=== MCP TOKEN START ===');

	// Handle both JSON and form data
	let body: {
		grant_type?: string;
		code?: string;
		client_id?: string;
		client_secret?: string;
		code_verifier?: string;
		refresh_token?: string;
	};
	const contentType = request.headers.get('content-type') || '';

	if (contentType.includes('application/x-www-form-urlencoded')) {
		const formData = await request.formData();
		body = Object.fromEntries(formData.entries()) as typeof body;
		console.log('Token request (form data):', JSON.stringify(body));
	} else {
		body = await request.json().catch(() => ({})) as typeof body;
		console.log('Token request (JSON):', JSON.stringify(body));
	}

	const grantType = body.grant_type;

	if (!grantType) {
		console.error('Missing grant_type in token request');
		return new Response(JSON.stringify({
			error: 'invalid_request',
			error_description: 'Missing grant_type parameter'
		}), {
			status: 400,
			headers: { 'Content-Type': 'application/json', ...corsHeaders }
		});
	}

	if (grantType === 'authorization_code') {
		const code = body.code;
		const clientId = body.client_id;
		const codeVerifier = body.code_verifier;

		console.log('Token exchange attempt:', { code: code?.substring(0, 8) + '...', clientId, hasVerifier: !!codeVerifier });

		if (!code) {
			console.error('Missing authorization code');
			return new Response(JSON.stringify({
				error: 'invalid_request',
				error_description: 'Missing authorization code'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		// Get authorization code from KV
		const codeData = await env.OAUTH_KV.get(`mcp_code:${code}`);
		if (!codeData) {
			console.error('Authorization code not found in KV:', code);
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Authorization code not found or expired'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		const tokenData = JSON.parse(codeData);
		if (tokenData.expiresAt < Date.now()) {
			await env.OAUTH_KV.delete(`mcp_code:${code}`);
			console.error('Authorization code expired');
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Authorization code expired'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		// Validate client_id if provided
		if (clientId && tokenData.clientId !== clientId) {
			console.error('Client ID mismatch:', { expected: tokenData.clientId, received: clientId });
			return new Response(JSON.stringify({
				error: 'invalid_client',
				error_description: 'Client ID mismatch'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		// Handle PKCE verification
		if (tokenData.codeChallenge && tokenData.codeChallengeMethod === 'S256') {
			if (!codeVerifier) {
				return new Response(JSON.stringify({
					error: 'invalid_request',
					error_description: 'Code verifier required for PKCE'
				}), {
					status: 400,
					headers: { 'Content-Type': 'application/json', ...corsHeaders }
				});
			}

			// Verify PKCE challenge
			const encoder = new TextEncoder();
			const data = encoder.encode(codeVerifier);
			const hashBuffer = await crypto.subtle.digest('SHA-256', data);
			const hashArray = new Uint8Array(hashBuffer);
			const challenge = btoa(String.fromCharCode(...hashArray))
				.replace(/\+/g, '-')
				.replace(/\//g, '_')
				.replace(/=/g, '');

			if (challenge !== tokenData.codeChallenge) {
				return new Response(JSON.stringify({
					error: 'invalid_grant',
					error_description: 'Invalid code verifier'
				}), {
					status: 400,
					headers: { 'Content-Type': 'application/json', ...corsHeaders }
				});
			}
		}

		// Delete used authorization code
		await env.OAUTH_KV.delete(`mcp_code:${code}`);

		// Generate access token and refresh token
		const accessToken = crypto.randomUUID();
		const refreshToken = crypto.randomUUID();

		const accessTokenData = {
			type: 'access_token',
			clientId,
			authToken: tokenData.authToken, // Store VK auth token
			siteDomain: tokenData.siteDomain,
			scope: tokenData.scope,
			refreshToken,
			expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
		};

		const refreshTokenData = {
			type: 'refresh_token',
			clientId,
			authToken: tokenData.authToken,
			siteDomain: tokenData.siteDomain,
			scope: tokenData.scope,
			expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
		};

		// Store tokens in KV
		await env.OAUTH_KV.put(`mcp_token:${accessToken}`, JSON.stringify(accessTokenData), { expirationTtl: 3600 });
		await env.OAUTH_KV.put(`mcp_refresh:${refreshToken}`, JSON.stringify(refreshTokenData), { expirationTtl: 7 * 24 * 60 * 60 });

		console.log('Generated access token and refresh token');
		console.log('=== MCP TOKEN END ===');

		return new Response(JSON.stringify({
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			refresh_token: refreshToken,
			scope: tokenData.scope
		}), {
			headers: {
				'Content-Type': 'application/json',
				...corsHeaders
			}
		});
	}

	// Handle refresh_token grant
	if (grantType === 'refresh_token') {
		const refreshToken = body.refresh_token;
		const clientId = body.client_id;

		if (!refreshToken) {
			return new Response(JSON.stringify({
				error: 'invalid_request',
				error_description: 'Missing refresh_token'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		// Get refresh token from KV
		const refreshData = await env.OAUTH_KV.get(`mcp_refresh:${refreshToken}`);
		if (!refreshData) {
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Refresh token not found or expired'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		const refreshTokenData = JSON.parse(refreshData);
		if (refreshTokenData.expiresAt < Date.now()) {
			await env.OAUTH_KV.delete(`mcp_refresh:${refreshToken}`);
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Refresh token expired'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		if (clientId && refreshTokenData.clientId !== clientId) {
			return new Response(JSON.stringify({
				error: 'invalid_client',
				error_description: 'Client ID mismatch'
			}), {
				status: 400,
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		// Generate new access token
		const newAccessToken = crypto.randomUUID();
		const newAccessTokenData = {
			type: 'access_token',
			clientId: refreshTokenData.clientId,
			authToken: refreshTokenData.authToken,
			siteDomain: refreshTokenData.siteDomain,
			scope: refreshTokenData.scope,
			refreshToken,
			expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
		};

		await env.OAUTH_KV.put(`mcp_token:${newAccessToken}`, JSON.stringify(newAccessTokenData), { expirationTtl: 3600 });

		console.log('Refreshed access token');

		return new Response(JSON.stringify({
			access_token: newAccessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			scope: refreshTokenData.scope
		}), {
			headers: {
				'Content-Type': 'application/json',
				...corsHeaders
			}
		});
	}

	return new Response(JSON.stringify({
		error: 'unsupported_grant_type'
	}), {
		status: 400,
		headers: { 'Content-Type': 'application/json', ...corsHeaders }
	});
}

/**
 * MCP authentication middleware - validates Bearer token and returns props
 */
async function requireMCPAuth(request: Request, env: Env): Promise<MCPProps | Response> {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return new Response(JSON.stringify({
			error: 'unauthorized',
			error_description: 'Missing or invalid Authorization header'
		}), {
			status: 401,
			headers: { 'Content-Type': 'application/json', ...corsHeaders }
		});
	}

	const token = authHeader.substring(7);

	// Get token from KV
	const tokenDataStr = await env.OAUTH_KV.get(`mcp_token:${token}`);
	if (!tokenDataStr) {
		return new Response(JSON.stringify({
			error: 'invalid_token',
			error_description: 'Token not found or expired'
		}), {
			status: 401,
			headers: { 'Content-Type': 'application/json', ...corsHeaders }
		});
	}

	const tokenData = JSON.parse(tokenDataStr);
	if (tokenData.expiresAt < Date.now()) {
		await env.OAUTH_KV.delete(`mcp_token:${token}`);
		return new Response(JSON.stringify({
			error: 'token_expired',
			error_description: 'Access token has expired'
		}), {
			status: 401,
			headers: { 'Content-Type': 'application/json', ...corsHeaders }
		});
	}

	return {
		authToken: tokenData.authToken,
		siteDomain: tokenData.siteDomain
	};
}

/**
 * Main worker export - handles all routing
 */
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const site = getSiteFromHost(url.hostname);
		const serverUrl = getServerUrl(site);

		// Handle CORS preflight
		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
		}

		// Root endpoint - server info (required for MCP discovery)
		if (url.pathname === '/' && request.method === 'GET') {
			return new Response(JSON.stringify({
				name: `${site.name} MCP Server`,
				version: '1.0.0',
				description: `Search ${site.name} newspaper articles`,
				authentication: {
					type: 'oauth2.1',
					discovery: `${serverUrl}/.well-known/oauth-authorization-server`
				},
				capabilities: {
					tools: ['search_articles'],
					oauth: true,
					refresh_tokens: true
				}
			}), {
				headers: {
					'Content-Type': 'application/json',
					...corsHeaders
				}
			});
		}

		// OAuth Protected Resource Metadata (RFC 9728)
		if (url.pathname === '/.well-known/oauth-protected-resource') {
			return new Response(JSON.stringify({
				resource: serverUrl,
				authorization_servers: [serverUrl],
				scopes_supported: ['articles:search'],
			}), {
				headers: {
					'Content-Type': 'application/json',
					'Cache-Control': 'public, max-age=3600',
					...corsHeaders
				}
			});
		}

		// OAuth 2.1 Authorization Server Metadata (RFC 8414)
		if (url.pathname === '/.well-known/oauth-authorization-server') {
			return new Response(JSON.stringify({
				issuer: serverUrl,
				authorization_endpoint: `${serverUrl}/authorize`,
				token_endpoint: `${serverUrl}/token`,
				registration_endpoint: `${serverUrl}/register`,
				scopes_supported: ['articles:search'],
				response_types_supported: ['code'],
				grant_types_supported: ['authorization_code', 'refresh_token'],
				code_challenge_methods_supported: ['S256'],
				token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
				service_documentation: `https://www.${site.domain}`,
			}), {
				headers: {
					'Content-Type': 'application/json',
					'Cache-Control': 'public, max-age=3600',
					...corsHeaders
				}
			});
		}

		// Dynamic client registration (RFC 7591)
		if (url.pathname === '/register' && request.method === 'POST') {
			return handleClientRegistration(request, env, site);
		}

		// OAuth authorization endpoint
		if (url.pathname === '/authorize') {
			return handleAuthorization(request, env, site, serverUrl);
		}

		// OAuth token endpoint
		if (url.pathname === '/token' && request.method === 'POST') {
			return handleTokenExchange(request, env);
		}

		// Health check
		if (url.pathname === '/health') {
			return new Response(JSON.stringify({
				status: 'healthy',
				timestamp: new Date().toISOString(),
				service: `${site.name} MCP Server`
			}), {
				headers: {
					'Content-Type': 'application/json',
					...corsHeaders
				}
			});
		}

		// SSE endpoint - requires authentication (for Claude Code)
		if (url.pathname === '/sse' || url.pathname === '/sse/message') {
			const authResult = await requireMCPAuth(request, env);
			if (authResult instanceof Response) {
				return authResult;
			}

			// Create a new request with auth context in custom headers
			const headers = new Headers(request.headers);
			headers.set('X-VK-Auth-Token', authResult.authToken);
			headers.set('X-VK-Site-Domain', authResult.siteDomain);

			const modifiedRequest = new Request(request.url, {
				method: request.method,
				headers,
				body: request.body,
				duplex: 'half',
			} as RequestInit);

			// Pass to SSE handler
			const response = await VKMcpAgent.serveSSE('/sse').fetch(modifiedRequest, env, ctx);

			// Add CORS headers to SSE response
			const responseHeaders = new Headers(response.headers);
			Object.entries(corsHeaders).forEach(([key, value]) => {
				responseHeaders.set(key, value);
			});
			return new Response(response.body, {
				status: response.status,
				headers: responseHeaders
			});
		}

		// MCP endpoint - requires authentication (streamable HTTP)
		if (url.pathname === '/mcp') {
			const authResult = await requireMCPAuth(request, env);
			if (authResult instanceof Response) {
				return authResult;
			}

			// Create a new request with auth context in custom headers
			const headers = new Headers(request.headers);
			headers.set('X-VK-Auth-Token', authResult.authToken);
			headers.set('X-VK-Site-Domain', authResult.siteDomain);

			const modifiedRequest = new Request(request.url, {
				method: request.method,
				headers,
				body: request.body,
				// Preserve duplex for streaming
				duplex: 'half',
			} as RequestInit);

			// Pass modified request to MCP handler
			const response = await VKMcpAgent.serve('/mcp').fetch(modifiedRequest, env, ctx);

			// Add CORS headers to MCP response
			const responseHeaders = new Headers(response.headers);
			Object.entries(corsHeaders).forEach(([key, value]) => {
				responseHeaders.set(key, value);
			});
			return new Response(response.body, {
				status: response.status,
				headers: responseHeaders
			});
		}

		// 404 for everything else
		return new Response('Not Found', {
			status: 404,
			headers: corsHeaders
		});
	}
};
