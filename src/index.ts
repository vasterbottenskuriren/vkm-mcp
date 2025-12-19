/**
 * VK Media MCP Server
 *
 * A simple MCP server for searching newspaper articles across VK Media properties.
 * Uses raw MCP protocol handling - no Durable Objects required.
 */

import type { VKSearchResponse, SanitizedArticle } from './types';

// Supported newspaper sites
interface SiteConfig {
	name: string;
	domain: string;
	searchApiBase: string;
	apiPathPrefix: string;
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

const DEFAULT_SITE = SITES['vk.se'];
const VK_LOGIN_URL = 'https://konto.vkmedia.se/login';

function getSiteFromHost(hostname: string): SiteConfig {
	for (const [siteDomain, config] of Object.entries(SITES)) {
		if (hostname.endsWith(siteDomain) || hostname.includes(siteDomain)) {
			return config;
		}
	}
	return DEFAULT_SITE;
}

function getServerUrl(site: SiteConfig): string {
	return `https://mcp.content.${site.domain}`;
}

function getSearchApiUrl(site: SiteConfig): string {
	return `${site.searchApiBase}/${site.apiPathPrefix}/rest/articles/search`;
}

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

const corsHeaders = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
	'Access-Control-Expose-Headers': 'mcp-protocol-version',
	'Access-Control-Max-Age': '86400'
};

// =============================================================================
// MCP Protocol Handling (No Durable Objects)
// =============================================================================

const MCP_VERSION = '2024-11-05';

// Tool definition for search_articles
const TOOLS = [
	{
		name: 'search_articles',
		description: 'Search newspaper articles by keyword',
		inputSchema: {
			type: 'object',
			properties: {
				search: {
					type: 'string',
					description: 'Search query for articles'
				},
				limit: {
					type: 'number',
					description: 'Number of results to return (1-50)',
					default: 15
				},
				page: {
					type: 'number',
					description: 'Page number for pagination',
					default: 0
				}
			},
			required: ['search']
		}
	}
];

// Handle search_articles tool call
async function handleSearchArticles(
	args: { search: string; limit?: number; page?: number },
	authToken: string,
	site: SiteConfig
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
	try {
		const { search, limit = 15, page = 0 } = args;

		const apiUrl = new URL(getSearchApiUrl(site));
		apiUrl.searchParams.set('search', search);
		apiUrl.searchParams.set('limit', String(Math.min(Math.max(limit, 1), 50)));
		apiUrl.searchParams.set('page', String(Math.max(page, 0)));

		const response = await fetch(apiUrl.toString(), {
			headers: {
				'Cookie': `auth_token=${authToken}`,
				'Content-Type': 'application/json',
			},
		});

		if (!response.ok) {
			return {
				content: [{ type: 'text', text: `Unable to access ${site.name} at this time` }],
				isError: true,
			};
		}

		const data = await response.json() as VKSearchResponse;

		const articles: SanitizedArticle[] = data.result.hits.map(article => ({
			headline: article.headline,
			preamble: article.preamble,
			section: article.section?.name || 'Unknown',
			authors: article.authors?.map(a => a.name) || [],
			publishDate: article.publishDate,
		}));

		return {
			content: [{
				type: 'text',
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
			content: [{ type: 'text', text: 'Unable to access the newspaper at this time' }],
			isError: true,
		};
	}
}

// Handle MCP JSON-RPC request
async function handleMcpRequest(
	body: any,
	authToken: string,
	site: SiteConfig
): Promise<any> {
	const { method, params, id } = body;

	// Handle different MCP methods
	switch (method) {
		case 'initialize':
			return {
				jsonrpc: '2.0',
				id,
				result: {
					protocolVersion: MCP_VERSION,
					capabilities: {
						tools: {}
					},
					serverInfo: {
						name: `${site.name} MCP Server`,
						version: '1.0.0'
					}
				}
			};

		case 'notifications/initialized':
			// Client acknowledgment - no response needed for notifications
			return null;

		case 'tools/list':
			return {
				jsonrpc: '2.0',
				id,
				result: {
					tools: TOOLS
				}
			};

		case 'tools/call':
			const toolName = params?.name;
			const toolArgs = params?.arguments || {};

			if (toolName === 'search_articles') {
				const result = await handleSearchArticles(toolArgs, authToken, site);
				return {
					jsonrpc: '2.0',
					id,
					result
				};
			}

			return {
				jsonrpc: '2.0',
				id,
				error: {
					code: -32601,
					message: `Unknown tool: ${toolName}`
				}
			};

		case 'ping':
			return {
				jsonrpc: '2.0',
				id,
				result: {}
			};

		default:
			return {
				jsonrpc: '2.0',
				id,
				error: {
					code: -32601,
					message: `Method not found: ${method}`
				}
			};
	}
}

// =============================================================================
// OAuth Handling
// =============================================================================

async function handleClientRegistration(request: Request, env: Env, site: SiteConfig): Promise<Response> {
	const body = await request.json().catch(() => ({})) as {
		redirect_uris?: string[];
		client_name?: string;
	};

	const clientId = crypto.randomUUID();
	const clientSecret = crypto.randomUUID();

	const defaultRedirectUris = [
		'http://127.0.0.1:6274/oauth/callback',
		'http://localhost:6274/oauth/callback',
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

	await env.OAUTH_KV.put(`mcp_client:${clientId}`, JSON.stringify(client), { expirationTtl: 7 * 24 * 60 * 60 });

	return new Response(JSON.stringify({
		client_id: clientId,
		client_secret: clientSecret,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		grant_types: client.grant_types,
		response_types: client.response_types,
		scope: client.scope,
		redirect_uris: client.redirect_uris
	}), {
		headers: { 'Content-Type': 'application/json', ...corsHeaders }
	});
}

async function handleAuthorization(request: Request, env: Env, site: SiteConfig, serverUrl: string): Promise<Response> {
	const url = new URL(request.url);
	const clientId = url.searchParams.get('client_id');
	const redirectUri = url.searchParams.get('redirect_uri');
	const scope = url.searchParams.get('scope');
	const state = url.searchParams.get('state');
	const codeChallenge = url.searchParams.get('code_challenge');
	const codeChallengeMethod = url.searchParams.get('code_challenge_method');

	if (!clientId) {
		return new Response(JSON.stringify({
			error: 'invalid_request',
			error_description: 'Missing client_id'
		}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	let clientData = await env.OAUTH_KV.get(`mcp_client:${clientId}`);

	if (!clientData) {
		if (redirectUri && redirectUri.includes('claude.ai')) {
			const claudeClient = {
				client_id: clientId,
				client_secret: 'claude-ai-predetermined',
				redirect_uris: ['https://claude.ai/api/mcp/auth_callback', redirectUri],
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
			}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}
	}

	const client = JSON.parse(clientData);
	const actualRedirectUri = redirectUri || client.redirect_uris[0];

	const cookies = request.headers.get('Cookie') || '';
	const authToken = parseCookie(cookies, 'auth_token');

	if (!authToken) {
		const loginUrl = new URL(VK_LOGIN_URL);
		loginUrl.searchParams.set('redirect', request.url);
		return Response.redirect(loginUrl.toString());
	}

	const code = crypto.randomUUID();
	const tokenData = {
		clientId,
		redirectUri: actualRedirectUri,
		scope,
		codeChallenge,
		codeChallengeMethod,
		authToken,
		siteDomain: site.domain,
		expiresAt: Date.now() + 10 * 60 * 1000
	};

	await env.OAUTH_KV.put(`mcp_code:${code}`, JSON.stringify(tokenData), { expirationTtl: 600 });

	const params = new URLSearchParams({ code });
	if (state) params.append('state', state);

	return Response.redirect(`${actualRedirectUri}?${params.toString()}`);
}

async function handleTokenExchange(request: Request, env: Env): Promise<Response> {
	let body: any;
	const contentType = request.headers.get('content-type') || '';

	if (contentType.includes('application/x-www-form-urlencoded')) {
		const formData = await request.formData();
		body = Object.fromEntries(formData.entries());
	} else {
		body = await request.json().catch(() => ({}));
	}

	const { grant_type, code, client_id, code_verifier, refresh_token } = body;

	if (!grant_type) {
		return new Response(JSON.stringify({
			error: 'invalid_request',
			error_description: 'Missing grant_type'
		}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	if (grant_type === 'authorization_code') {
		if (!code) {
			return new Response(JSON.stringify({
				error: 'invalid_request',
				error_description: 'Missing code'
			}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		const codeData = await env.OAUTH_KV.get(`mcp_code:${code}`);
		if (!codeData) {
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Code not found or expired'
			}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		const tokenData = JSON.parse(codeData);

		if (tokenData.expiresAt < Date.now()) {
			await env.OAUTH_KV.delete(`mcp_code:${code}`);
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Code expired'
			}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		// PKCE verification
		if (tokenData.codeChallenge && tokenData.codeChallengeMethod === 'S256') {
			if (!code_verifier) {
				return new Response(JSON.stringify({
					error: 'invalid_request',
					error_description: 'Code verifier required'
				}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
			}

			const encoder = new TextEncoder();
			const data = encoder.encode(code_verifier);
			const hashBuffer = await crypto.subtle.digest('SHA-256', data);
			const hashArray = new Uint8Array(hashBuffer);
			const challenge = btoa(String.fromCharCode(...hashArray))
				.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

			if (challenge !== tokenData.codeChallenge) {
				return new Response(JSON.stringify({
					error: 'invalid_grant',
					error_description: 'Invalid code verifier'
				}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
			}
		}

		await env.OAUTH_KV.delete(`mcp_code:${code}`);

		const accessToken = crypto.randomUUID();
		const newRefreshToken = crypto.randomUUID();

		await env.OAUTH_KV.put(`mcp_token:${accessToken}`, JSON.stringify({
			authToken: tokenData.authToken,
			siteDomain: tokenData.siteDomain,
			scope: tokenData.scope,
			expiresAt: Date.now() + 60 * 60 * 1000
		}), { expirationTtl: 3600 });

		await env.OAUTH_KV.put(`mcp_refresh:${newRefreshToken}`, JSON.stringify({
			authToken: tokenData.authToken,
			siteDomain: tokenData.siteDomain,
			scope: tokenData.scope,
			expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
		}), { expirationTtl: 7 * 24 * 60 * 60 });

		return new Response(JSON.stringify({
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			refresh_token: newRefreshToken,
			scope: tokenData.scope
		}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	if (grant_type === 'refresh_token') {
		if (!refresh_token) {
			return new Response(JSON.stringify({
				error: 'invalid_request',
				error_description: 'Missing refresh_token'
			}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		const refreshData = await env.OAUTH_KV.get(`mcp_refresh:${refresh_token}`);
		if (!refreshData) {
			return new Response(JSON.stringify({
				error: 'invalid_grant',
				error_description: 'Refresh token not found'
			}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		const data = JSON.parse(refreshData);
		const newAccessToken = crypto.randomUUID();

		await env.OAUTH_KV.put(`mcp_token:${newAccessToken}`, JSON.stringify({
			authToken: data.authToken,
			siteDomain: data.siteDomain,
			scope: data.scope,
			expiresAt: Date.now() + 60 * 60 * 1000
		}), { expirationTtl: 3600 });

		return new Response(JSON.stringify({
			access_token: newAccessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			scope: data.scope
		}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	return new Response(JSON.stringify({
		error: 'unsupported_grant_type'
	}), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
}

async function validateToken(request: Request, env: Env): Promise<{ authToken: string; siteDomain: string } | Response> {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader?.startsWith('Bearer ')) {
		return new Response(JSON.stringify({
			error: 'unauthorized',
			error_description: 'Missing Authorization header'
		}), { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	const token = authHeader.substring(7);
	const tokenData = await env.OAUTH_KV.get(`mcp_token:${token}`);

	if (!tokenData) {
		return new Response(JSON.stringify({
			error: 'invalid_token',
			error_description: 'Token not found or expired'
		}), { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	const data = JSON.parse(tokenData);
	if (data.expiresAt < Date.now()) {
		await env.OAUTH_KV.delete(`mcp_token:${token}`);
		return new Response(JSON.stringify({
			error: 'token_expired'
		}), { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	return { authToken: data.authToken, siteDomain: data.siteDomain };
}

// =============================================================================
// Main Worker
// =============================================================================

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const site = getSiteFromHost(url.hostname);
		const serverUrl = getServerUrl(site);

		// CORS preflight
		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
		}

		// Root - server info
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
			}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		// OAuth metadata
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
			}), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', ...corsHeaders } });
		}

		// OAuth endpoints
		if (url.pathname === '/register' && request.method === 'POST') {
			return handleClientRegistration(request, env, site);
		}

		if (url.pathname === '/authorize') {
			return handleAuthorization(request, env, site, serverUrl);
		}

		if (url.pathname === '/token' && request.method === 'POST') {
			return handleTokenExchange(request, env);
		}

		// MCP endpoint - handles JSON-RPC directly
		if (url.pathname === '/mcp' && request.method === 'POST') {
			const authResult = await validateToken(request, env);
			if (authResult instanceof Response) {
				return authResult;
			}

			const body = await request.json().catch(() => null);
			if (!body) {
				return new Response(JSON.stringify({
					jsonrpc: '2.0',
					error: { code: -32700, message: 'Parse error' }
				}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
			}

			const mcpSite = SITES[authResult.siteDomain] || site;
			const response = await handleMcpRequest(body, authResult.authToken, mcpSite);

			if (response === null) {
				// Notification - no response
				return new Response(null, { status: 204, headers: corsHeaders });
			}

			return new Response(JSON.stringify(response), {
				headers: { 'Content-Type': 'application/json', ...corsHeaders }
			});
		}

		// Health check
		if (url.pathname === '/health') {
			return new Response(JSON.stringify({
				status: 'healthy',
				timestamp: new Date().toISOString()
			}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		return new Response('Not Found', { status: 404, headers: corsHeaders });
	}
};
