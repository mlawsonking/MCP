# Any MCP host

Add this server to any host that accepts standard MCP stdio configuration:

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

## What you get

- 31 tools covering packages, untrusted content, email, code, payments, and web reads.
- Secret, code, injection-pattern, and obfuscation checks run locally.
- Current OSV, DNS, RDAP, OFAC, scam-list, and web checks use the network.
- Add `"--offline"` to `args` to expose local tools only.
- Deterministic rules are explainable, but novel phrasing and unknown secret formats get through.

The config field around `mcpServers` varies by host. The `command` and `args` object is the portable
part. Do not put this stdio server behind an HTTP URL; the package speaks MCP over stdin/stdout.
