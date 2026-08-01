# Cursor

Create `.cursor/mcp.json` in the project, or use Cursor's user-level MCP configuration, and add:

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

Restart or refresh MCP servers in Cursor, then ask the agent to list the `agent-guards` tools.

## What you get

- Package checks before you choose to install a dependency.
- Local scans for secrets, risky code patterns, and known injection phrasing.
- Email pre-flight checks before an agent acts on a message.
- Optional live reputation lookups, clearly named in each tool description.
- MCP tools are available to the model, but Cursor does not call them automatically on every edit.

For ambient interception on every install, edit, and web fetch, the separate plugin in this repo is
for Claude Code's hook API. Cursor receives MCP tools, not those Claude-specific hooks.
