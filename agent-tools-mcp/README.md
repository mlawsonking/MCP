# agent-tools-mcp (Engine #2 — the agent-native wrapper)

An MCP server that exposes our live web-utility tools to any AI agent (Claude Desktop, Cursor,
Claude Code, etc.). This is what plugs the tools into the MCP ecosystem (97M SDK downloads/mo).

## Tools
- **`read_url`** — fetch a page and return its main content as clean Markdown (for RAG / reading).
- **`unfurl_url`** — fetch a URL's structured metadata (title, description, image, favicon, …).

Both call the live, deterministic endpoints (no LLM, no keys needed for the free tier):
- `https://url-to-markdown-three.vercel.app/api/read`
- `https://url-metadata-three.vercel.app/api/meta`

## Install (local)
```
npm install
node index.mjs        # runs as an MCP stdio server
node test/client.mjs  # end-to-end self-test (lists + calls both tools)
```

## Add to an MCP client
Claude Desktop / Cursor / Claude Code config (`mcpServers`):
```json
{
  "mcpServers": {
    "agent-tools": {
      "command": "node",
      "args": ["D:/Random exploration of income/engine2/agent-tools-mcp/index.mjs"]
    }
  }
}
```
Override the endpoints with env vars `READ_API_URL` / `META_API_URL` if you self-host them.

## Monetization path (next, account-gated)
1. **Publish to npm** + submit to MCP registries (MCPize, glama, smithery) → discovery.
2. **Apify Actor** wrappers of the same endpoints → pay-per-result (80% payout).
3. **RapidAPI** listing of the HTTP endpoints → free + paid tiers (marketplace billing).
4. **x402 paywall** on the endpoints → agents pay per call in USDC, no signup.
