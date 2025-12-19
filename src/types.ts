/**
 * Type definitions for VK MCP Server
 */

// Auth context passed to MCP tools after OAuth
// Must extend Record<string, unknown> for McpAgent compatibility
export interface AuthContext extends Record<string, unknown> {
	authToken: string; // The auth_token from cookie
	clientId: string;
	resource: string;
	siteDomain?: string; // The newspaper domain (e.g., vk.se, folkbladet.nu)
}

// VK API article response structure
export interface VKArticle {
	headline: string;
	preamble: string;
	section: {
		name: string;
		uuid: string;
	};
	authors: Array<{
		name: string;
		contactInfo?: {
			email?: string;
			phone?: string;
		};
	}>;
	publishDate: string;
}

export interface VKSearchResponse {
	result: {
		includedHits: number;
		totalHits: number;
		hits: VKArticle[];
	};
}

// Sanitized article for Claude (only safe fields)
export interface SanitizedArticle {
	headline: string;
	preamble: string;
	section: string;
	authors: string[];
	publishDate: string;
}
