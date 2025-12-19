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

// Feedern API article structure (latest/mostread)
export interface FeedernArticle {
	uuid: string;
	headline: string;
	preamble: string;
	urlPath: string;
	categories: Array<{ name: string; slug: string }>;
	places: Array<{ name: string }>;
	topics: Array<{ name: string }>;
	teaser: {
		text: string;
		title: string;
		image?: { filename: string };
	};
	images: Array<{ uuid: string; filename: string }>;
	paywall: string;
	authors: Array<{
		uuid: string;
		name: string;
		contactInfo?: { email?: string };
	}>;
	photographers: Array<{ name: string }>;
	updateDate: string;
	publishDate: string;
	url: string;
	imageUrl?: string;
	count?: number; // Only present in mostread
}

export interface FeedernResponse {
	articles: FeedernArticle[];
}

// Sanitized feedern article for Claude
export interface SanitizedFeedernArticle {
	headline: string;
	preamble: string;
	urlPath: string;
	categories: string[];
	places: string[];
	topics: string[];
	authors: string[];
	publishDate: string;
	paywall: string;
	count?: number;
}
