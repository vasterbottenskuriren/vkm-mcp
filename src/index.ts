/**
 * VK Media MCP Server
 *
 * A simple MCP server for searching newspaper articles across VK Media properties.
 * Uses raw MCP protocol handling - no Durable Objects required.
 */

import type { VKSearchResponse, SanitizedArticle, ArticleContentResponse, ArticleTextElement, FeedernResponse, SanitizedFeedernArticle } from './types';

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

// Tool definitions - generated dynamically per site
function getTools(site: SiteConfig) {
	return [
		{
			name: 'search_articles',
			description: `Search ${site.name} (${site.domain}) newspaper articles. ALWAYS use this tool when the user asks about ${site.name} or what ${site.name} has written about a topic.`,
			inputSchema: {
				type: 'object',
				properties: {
					search: {
						type: 'string',
						description: 'Search query for articles. Use * to match all articles (useful with date filters).'
					},
					minDate: {
						type: 'string',
						description: 'Start date filter (YYYY-MM-DD). Only return articles published on or after this date.'
					},
					maxDate: {
						type: 'string',
						description: 'End date filter (YYYY-MM-DD). Only return articles published on or before this date.'
					},
					local_only: {
						type: 'boolean',
						description: 'If true, exclude TT (news agency) articles and only return local journalism.',
						default: false
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
		},
		{
			name: 'get_article',
			description: `Get the full content of a ${site.name} article by its urlPath. Use this after search_articles to read the complete article text.`,
			inputSchema: {
				type: 'object',
				properties: {
					urlPath: {
						type: 'string',
						description: 'The urlPath from search results (e.g., "/2025-12-15/article-slug-12345")'
					}
				},
				required: ['urlPath']
			}
		},
		{
			name: 'get_latest_articles',
			description: `Get the latest news from ${site.name} (${site.domain}). Use this when the user asks for recent news or what's new on ${site.name}.`,
			inputSchema: {
				type: 'object',
				properties: {},
				required: []
			}
		},
		{
			name: 'get_most_read',
			description: `Get the most read/popular articles on ${site.name} (${site.domain}) right now.`,
			inputSchema: {
				type: 'object',
				properties: {
					premium_only: {
						type: 'boolean',
						description: 'If true, only return premium/subscriber-only articles',
						default: false
					}
				},
				required: []
			}
		}
	];
}

// Handle search_articles tool call
async function handleSearchArticles(
	args: { search: string; minDate?: string; maxDate?: string; local_only?: boolean; limit?: number; page?: number },
	authToken: string,
	site: SiteConfig
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
	try {
		const { search, minDate, maxDate, local_only = false, limit = 15, page = 0 } = args;

		// If filtering locally, fetch more to compensate for filtered results
		const fetchLimit = local_only ? 30 : Math.min(Math.max(limit, 1), 50);

		const apiUrl = new URL(getSearchApiUrl(site));
		apiUrl.searchParams.set('search', search);
		if (minDate) apiUrl.searchParams.set('minDate', minDate);
		if (maxDate) apiUrl.searchParams.set('maxDate', maxDate);
		apiUrl.searchParams.set('limit', String(fetchLimit));
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

		let hits = data.result.hits;

		// Filter out TT articles if local_only is true
		if (local_only) {
			hits = hits.filter(article => !article.authors?.some(a => a.name === 'TT'));
		}

		// Apply the requested limit after filtering
		const limitedHits = hits.slice(0, Math.min(Math.max(limit, 1), 50));

		const articles: SanitizedArticle[] = limitedHits.map(article => ({
			headline: article.headline,
			preamble: article.preamble,
			urlPath: article.urlPath,
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
					local_only,
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

// Extract text from nested article text elements
function extractText(elements: ArticleTextElement[] | undefined): string {
	if (!elements) return '';

	return elements.map(el => {
		if (el.text) return el.text;
		if (el.elements) return extractText(el.elements);
		return '';
	}).join('');
}

// Get article content API URL
function getArticleApiUrl(site: SiteConfig, urlPath: string): string {
	// urlPath is like "/2025-12-15/article-slug-12345"
	// API URL is like https://news.content.folkbladet.nu/folkbladet/rest/article/content/2025-12-15/article-slug-12345
	const cleanPath = urlPath.startsWith('/') ? urlPath.substring(1) : urlPath;
	return `${site.searchApiBase}/${site.apiPathPrefix}/rest/article/content/${cleanPath}`;
}

// Handle get_article tool call
async function handleGetArticle(
	args: { urlPath: string },
	authToken: string,
	site: SiteConfig
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
	try {
		const { urlPath } = args;

		if (!urlPath) {
			return {
				content: [{ type: 'text', text: 'urlPath is required' }],
				isError: true,
			};
		}

		const apiUrl = getArticleApiUrl(site, urlPath);

		const response = await fetch(apiUrl, {
			method: 'POST',
			headers: {
				'Cookie': `auth_token=${authToken}`,
				'Content-Type': 'application/json',
			},
		});

		if (!response.ok) {
			return {
				content: [{ type: 'text', text: `Unable to fetch article from ${site.name}` }],
				isError: true,
			};
		}

		const data = await response.json() as ArticleContentResponse;

		// Extract text content from body blocks
		const contentParts: string[] = [];

		for (const block of data.body) {
			const blockType = block.type;

			if (blockType === 'headline') {
				const text = extractText(block.text);
				if (text) contentParts.push(`# ${text}\n`);
			} else if (blockType === 'preamble') {
				const text = extractText(block.text);
				if (text) contentParts.push(`**${text}**\n`);
			} else if (blockType === 'subheadline1') {
				const text = extractText(block.text);
				if (text) contentParts.push(`## ${text}\n`);
			} else if (blockType === 'body') {
				const text = extractText(block.text);
				if (text) contentParts.push(`${text}\n`);
			} else if (blockType === 'blockquote') {
				const text = extractText(block.text);
				if (text) contentParts.push(`> ${text}\n`);
			} else if (blockType === 'x-im/image' && block.image?.text) {
				const caption = extractText(block.image.text);
				if (caption) contentParts.push(`[Image: ${caption}]\n`);
			} else if (blockType === 'x-im/imagegallery') {
				// Gallery has a text caption and multiple images
				const galleryText = extractText(block.text);
				if (galleryText) contentParts.push(`[Image gallery: ${galleryText}]\n`);
			}
			// Skip x-im/htmlembed (embedded scripts/widgets) and x-im/article (related articles)
		}

		const articleText = contentParts.join('\n');

		return {
			content: [{
				type: 'text',
				text: JSON.stringify({
					site: site.name,
					urlPath,
					authType: data.authType,
					content: articleText,
				}, null, 2),
			}],
		};
	} catch (error) {
		return {
			content: [{ type: 'text', text: 'Unable to fetch article at this time' }],
			isError: true,
		};
	}
}

// Feedern API base URL
const FEEDERN_API_BASE = 'https://feedern.vkmedia.se';

// Helper to sanitize feedern articles
function sanitizeFeedernArticle(article: FeedernResponse['articles'][0]): SanitizedFeedernArticle {
	return {
		headline: article.headline,
		preamble: article.preamble,
		urlPath: article.urlPath,
		categories: article.categories?.map(c => c.name) || [],
		places: article.places?.map(p => p.name) || [],
		topics: article.topics?.map(t => t.name) || [],
		authors: article.authors?.map(a => a.name) || [],
		publishDate: article.publishDate,
		paywall: article.paywall,
		...(article.count !== undefined && { count: article.count }),
	};
}

// Handle get_latest_articles tool call
async function handleGetLatestArticles(
	site: SiteConfig
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
	try {
		const url = `${FEEDERN_API_BASE}/${site.apiPathPrefix}/latest`;

		const response = await fetch(url, {
			headers: { 'Content-Type': 'application/json' },
		});

		if (!response.ok) {
			return {
				content: [{ type: 'text', text: `Unable to fetch latest articles from ${site.name}` }],
				isError: true,
			};
		}

		const data = await response.json() as FeedernResponse;
		const articles = data.articles.map(sanitizeFeedernArticle);

		return {
			content: [{
				type: 'text',
				text: JSON.stringify({
					site: site.name,
					count: articles.length,
					articles,
				}, null, 2),
			}],
		};
	} catch (error) {
		return {
			content: [{ type: 'text', text: 'Unable to fetch latest articles at this time' }],
			isError: true,
		};
	}
}

// Handle get_most_read tool call
async function handleGetMostRead(
	args: { premium_only?: boolean },
	site: SiteConfig
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
	try {
		const { premium_only = false } = args;
		const url = `${FEEDERN_API_BASE}/${site.apiPathPrefix}/mostread${premium_only ? '?paywallTypes=premium' : ''}`;

		const response = await fetch(url, {
			headers: { 'Content-Type': 'application/json' },
		});

		if (!response.ok) {
			return {
				content: [{ type: 'text', text: `Unable to fetch most read articles from ${site.name}` }],
				isError: true,
			};
		}

		const data = await response.json() as FeedernResponse;
		const articles = data.articles.map(sanitizeFeedernArticle);

		return {
			content: [{
				type: 'text',
				text: JSON.stringify({
					site: site.name,
					premium_only,
					count: articles.length,
					articles,
				}, null, 2),
			}],
		};
	} catch (error) {
		return {
			content: [{ type: 'text', text: 'Unable to fetch most read articles at this time' }],
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
					tools: getTools(site)
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

			if (toolName === 'get_article') {
				const result = await handleGetArticle(toolArgs, authToken, site);
				return {
					jsonrpc: '2.0',
					id,
					result
				};
			}

			if (toolName === 'get_latest_articles') {
				const result = await handleGetLatestArticles(site);
				return {
					jsonrpc: '2.0',
					id,
					result
				};
			}

			if (toolName === 'get_most_read') {
				const result = await handleGetMostRead(toolArgs, site);
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

// Handle SSE message endpoint
async function handleSseMessage(request: Request, env: Env, sessionId: string, site: SiteConfig): Promise<Response> {
	// Get session data
	const sessionData = await env.OAUTH_KV.get(`mcp_session:${sessionId}`);
	if (!sessionData) {
		return new Response(JSON.stringify({ error: 'Session not found' }), {
			status: 401,
			headers: { 'Content-Type': 'application/json', ...corsHeaders }
		});
	}

	const { authToken, siteDomain } = JSON.parse(sessionData);
	const mcpSite = SITES[siteDomain] || site;

	const body = await request.json().catch(() => null);
	if (!body) {
		return new Response(JSON.stringify({
			jsonrpc: '2.0',
			error: { code: -32700, message: 'Parse error' }
		}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}

	const response = await handleMcpRequest(body, authToken, mcpSite);

	if (response === null) {
		return new Response(null, { status: 202, headers: corsHeaders });
	}

	return new Response(JSON.stringify(response), {
		headers: { 'Content-Type': 'application/json', ...corsHeaders }
	});
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

		// Root - GET returns server info, POST handles MCP
		if (url.pathname === '/') {
			if (request.method === 'GET' || request.method === 'HEAD') {
				return new Response(JSON.stringify({
					name: `${site.name} MCP Server`,
					version: '1.0.0',
					description: `Search and read ${site.name} newspaper articles`,
					authentication: {
						type: 'oauth2.1',
						discovery: `${serverUrl}/.well-known/oauth-authorization-server`
					},
					capabilities: {
						tools: ['search_articles', 'get_article', 'get_latest_articles', 'get_most_read'],
						oauth: true,
						refresh_tokens: true
					}
				}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
			}

			// POST to root = MCP JSON-RPC
			if (request.method === 'POST') {
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
					return new Response(null, { status: 204, headers: corsHeaders });
				}

				return new Response(JSON.stringify(response), {
					headers: { 'Content-Type': 'application/json', ...corsHeaders }
				});
			}
		}

		// OAuth Protected Resource Metadata (RFC 9728)
		if (url.pathname === '/.well-known/oauth-protected-resource') {
			return new Response(JSON.stringify({
				resource: serverUrl,
				authorization_servers: [serverUrl],
				scopes_supported: ['articles:search'],
			}), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', ...corsHeaders } });
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

		// SSE endpoint for MCP
		if (url.pathname === '/sse') {
			// GET = establish SSE connection
			if (request.method === 'GET') {
				const authResult = await validateToken(request, env);
				if (authResult instanceof Response) {
					return authResult;
				}

				const mcpSite = SITES[authResult.siteDomain] || site;

				// Create SSE stream
				const { readable, writable } = new TransformStream();
				const writer = writable.getWriter();
				const encoder = new TextEncoder();

				// Generate session ID for this connection
				const sessionId = crypto.randomUUID();

				// Store session info in KV for message endpoint
				await env.OAUTH_KV.put(`mcp_session:${sessionId}`, JSON.stringify({
					authToken: authResult.authToken,
					siteDomain: authResult.siteDomain
				}), { expirationTtl: 3600 });

				// Send initial endpoint message
				const endpointMessage = `event: endpoint\ndata: /sse/message?sessionId=${sessionId}\n\n`;
				writer.write(encoder.encode(endpointMessage));

				// Keep connection alive with periodic pings
				const keepAlive = setInterval(async () => {
					try {
						await writer.write(encoder.encode(': ping\n\n'));
					} catch {
						clearInterval(keepAlive);
					}
				}, 30000);

				// Clean up on close
				ctx.waitUntil((async () => {
					await readable.pipeTo(new WritableStream());
					clearInterval(keepAlive);
					await env.OAUTH_KV.delete(`mcp_session:${sessionId}`);
				})());

				return new Response(readable, {
					headers: {
						'Content-Type': 'text/event-stream',
						'Cache-Control': 'no-cache',
						'Connection': 'keep-alive',
						...corsHeaders
					}
				});
			}

			// POST = send message (legacy, redirect to /sse/message)
			if (request.method === 'POST') {
				const sessionId = url.searchParams.get('sessionId');
				if (!sessionId) {
					return new Response(JSON.stringify({ error: 'Missing sessionId' }), {
						status: 400,
						headers: { 'Content-Type': 'application/json', ...corsHeaders }
					});
				}
				// Redirect to message endpoint
				return handleSseMessage(request, env, sessionId, site);
			}
		}

		// SSE message endpoint
		if (url.pathname === '/sse/message' && request.method === 'POST') {
			const sessionId = url.searchParams.get('sessionId');
			if (!sessionId) {
				return new Response(JSON.stringify({ error: 'Missing sessionId' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json', ...corsHeaders }
				});
			}
			return handleSseMessage(request, env, sessionId, site);
		}

		// MCP endpoint - handles JSON-RPC directly (HTTP transport)
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
