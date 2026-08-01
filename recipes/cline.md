# Cline

Open Cline's MCP Servers view, choose the configuration option, and add this server to the
`mcpServers` object Cline shows you:

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

Enable the server and confirm that Cline lists its tools before relying on it in a task.

## What you get

- One server instead of six separate guard configurations.
- Local secret, code, email-content, and injection-pattern scans.
- Network-backed package, domain, sanctions, and web checks when requested.
- `"args": ["-y", "agent-guards", "--offline"]` keeps the server fully local.
- Cline decides when to call MCP tools; this configuration is not an automatic policy gate.

The scanners match known rules and structural signals. They do not understand intent, and a new
attack phrased outside those rules can pass.
