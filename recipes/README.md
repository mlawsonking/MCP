# Integration recipes

These recipes all start the same published `agent-guards` stdio server. The server exposes 31 tools
from the six guard suites. Local scanners keep payloads on the machine. Tools that need current
reputation or network data say which service they call, and `--offline` removes those tools.

- [Any MCP host](mcp.md)
- [Cursor](cursor.md)
- [Cline](cline.md)
- [Windsurf](windsurf.md)
- [LangChain and LangGraph](langchain-langgraph.md)

Node 18 or newer is required. Run `npx -y agent-guards --list` first if you want to inspect the tool
names and network requirements before connecting a host.
