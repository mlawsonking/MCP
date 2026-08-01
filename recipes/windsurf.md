# Windsurf

Open Windsurf's MCP configuration, or edit `~/.codeium/windsurf/mcp_config.json`, and add:

```json
{
  "mcpServers": {
    "agent-guards": {
      "command": "npx",
      "args": ["-y", "agent-guards"]
    }
  }
}
```

Refresh the MCP server list and confirm that `agent-guards` starts without an error.

## What you get

- 31 tools from all six guard suites through one stdio process.
- Local payload scanning by default for the deterministic engines.
- Optional live lookups for data that cannot be current offline.
- Add `--offline` to expose only tools that do not need the network.
- MCP makes tools available to Cascade; it does not force a check before every risky action.

No API key is required. Node 18 or newer and an `npx` executable on Windsurf's PATH are required.
