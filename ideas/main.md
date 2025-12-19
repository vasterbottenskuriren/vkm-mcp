Yes! Absolutely! That's a clever approach. You can map the MCP access token to the original VK JWT cookie value. Here's how:

## Store the Mapping: Access Token → VK JWT

```typescript
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { McpAgent } from '@cloudflare/agents';

const VKAuthHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    if (url.pathname === '/oauth/authorize') {
      // User's browser hits here - read the vk.se cookie
      const cookies = request.headers.get('Cookie') || '';
      const vkJWT = cookies.split(';')
        .find(c => c.trim().startsWith('auth_token='))
        ?.split('=')[1];
      
      if (!vkJWT) {
        return Response.redirect(
          `https://vk.se/login?redirect=${encodeURIComponent(url.toString())}`,
          302
        );
      }
      
      // Validate the VK JWT
      const isValid = await validateVKJWT(vkJWT, env);
      if (!isValid) {
        return new Response('Invalid token', { status: 401 });
      }
      
      // Generate authorization code
      const authCode = crypto.randomUUID();
      
      // Store VK JWT temporarily linked to auth code
      await env.OAUTH_KV.put(`auth_code:${authCode}`, vkJWT, {
        expirationTtl: 600 // 10 minutes for auth code
      });
      
      // Redirect back to Claude
      const redirectUri = url.searchParams.get('redirect_uri');
      const state = url.searchParams.get('state');
      
      return Response.redirect(
        `${redirectUri}?code=${authCode}&state=${state}`,
        302
      );
    }
    
    if (url.pathname === '/oauth/token') {
      // Claude exchanges auth code for access token
      const body = await request.formData();
      const authCode = body.get('code');
      
      // Retrieve the VK JWT
      const vkJWT = await env.OAUTH_KV.get(`auth_code:${authCode}`);
      if (!vkJWT) {
        return new Response('Invalid auth code', { status: 400 });
      }
      
      // Generate MCP access token
      const mcpAccessToken = crypto.randomUUID();
      
      // 🔑 KEY PART: Map access token to VK JWT
      await env.OAUTH_KV.put(`access_token:${mcpAccessToken}`, vkJWT, {
        expirationTtl: 3600 // 1 hour - match your JWT expiry
      });
      
      // Clean up auth code
      await env.OAUTH_KV.delete(`auth_code:${authCode}`);
      
      return Response.json({
        access_token: mcpAccessToken,
        token_type: 'Bearer',
        expires_in: 3600
      });
    }
  }
};

class VKSearchMCP extends McpAgent<Env> {
  async init() {
    this.server.tool(
      'vk_search',
      'Search VK content',
      { query: { type: 'string' } },
      async ({ query }) => {
        // Get the MCP access token from auth context
        const mcpAccessToken = this.props.accessToken;
        
        // 🔑 Look up the VK JWT using the access token
        const vkJWT = await this.env.OAUTH_KV.get(`access_token:${mcpAccessToken}`);
        
        if (!vkJWT) {
          return {
            content: [{ 
              type: 'text', 
              text: 'Session expired - please reconnect' 
            }]
          };
        }
        
        // Use the VK JWT to call your search API
        const response = await fetch('https://api.vk.se/search', {
          headers: {
            'Authorization': `Bearer ${vkJWT}`,
            'Content-Type': 'application/json'
          },
          method: 'POST',
          body: JSON.stringify({ query })
        });
        
        const results = await response.json();
        
        return {
          content: [{ 
            type: 'text', 
            text: JSON.stringify(results, null, 2)
          }]
        };
      }
    );
  }
}

export default new OAuthProvider({
  apiRoute: '/mcp',
  apiHandler: VKSearchMCP.Router,
  defaultHandler: VKAuthHandler,
  authorizeEndpoint: '/oauth/authorize',
  tokenEndpoint: '/oauth/token',
  clientRegistrationEndpoint: '/oauth/register',
});
```

## The Flow

1. **OAuth authorize**: User's browser → read `auth_token` cookie → store `auth_code:xyz → JWT`
2. **OAuth token exchange**: Claude → exchange auth code → create MCP access token → store `access_token:abc → JWT`
3. **MCP tool calls**: Claude sends MCP access token → look up `access_token:abc` → get VK JWT → call VK API

## Benefits

- ✅ VK JWT never leaves your Worker (secure)
- ✅ MCP access token acts as a session key
- ✅ You control token expiry independently
- ✅ Same domain cookies work during OAuth flow
- ✅ Can invalidate sessions by deleting the KV mapping

## Important: Token Refresh

If VK JWTs expire frequently, you might need to handle refresh. You could:
1. Store JWT expiry alongside the token in KV
2. Check if expired before using
3. Redirect user to re-authenticate if needed

Does this solve your use case?