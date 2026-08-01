# LangChain and LangGraph (JavaScript)

Install LangChain's MCP adapter, then create a client for the local stdio server:

```bash
npm install @langchain/mcp-adapters
```

```js
import { MultiServerMCPClient } from "@langchain/mcp-adapters";

const client = new MultiServerMCPClient({
  mcpServers: {
    agentGuards: {
      transport: "stdio",
      command: "npx",
      args: ["-y", "agent-guards"],
    },
  },
});

const guardTools = await client.getTools();
```

Pass `guardTools` to the LangChain agent or LangGraph node that should be allowed to call them. Call
`await client.close()` when your process shuts down.

## What you get

- Normal LangChain tools generated from the 31 MCP tool declarations.
- Local deterministic scans for payloads, code, email, and package names.
- Optional network tools for current reputation and public-list data.
- Add `"--offline"` to `args` when the graph must make no network-backed checks.
- Merely binding tools does not enforce their use; put calls in the graph path for a real gate.

The scanners are regex, list, and structural checks. They are useful before a model acts, but they
are not a classifier or a sandbox.
