/**
 * Type definitions for VK MCP Server
 */

// VK API article response structure (search results)
export interface VKArticle {
	headline: string;
	preamble: string;
	urlPath: string;
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

// Article content API response
export interface ArticleContentResponse {
	body: ArticleBodyBlock[];
	authType: string;
}

export interface ArticleBodyBlock {
	id: string;
	type: string;
	text?: ArticleTextElement[];
	image?: {
		uri: string;
		text?: ArticleTextElement[];
	};
}

export interface ArticleTextElement {
	type: string;
	text?: string;
	elements?: ArticleTextElement[];
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
	urlPath: string;
	section: string;
	authors: string[];
	publishDate: string;
}
