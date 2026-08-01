// Fresh-install funnel check. The package is deliberately launched through npx, rather than from
// this checkout, so this catches missing files, broken bin declarations, and bad published MCP
// sessions. Give it an npm package spec and, when the binary name differs, the executable name.
//
//   node test/stranger-client.mjs agent-guards
//   node test/stranger-client.mjs @mlawsonking/code-guard-mcp code-guard-mcp

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const spec = process.argv[2];
const executable = process.argv[3] || String(spec || '').replace(/^@[^/]+\//, '');
if (!spec) {
  process.stderr.write('usage: node test/stranger-client.mjs <npm-package> [executable]\n');
  process.exit(2);
}

const transport = new StdioClientTransport({
  command: 'npx',
  args: ['-y', '--package', spec, executable],
  stderr: 'pipe',
  env: process.env,
});
const client = new Client({ name: 'agent-guards-stranger-walk', version: '1.0.0' }, { capabilities: {} });

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  if (!tools.length) throw new Error('the server returned no tools');

  let check = 'tool list';
  if (tools.some((tool) => tool.name === 'scan_secrets')) {
    const response = await client.callTool({ name: 'scan_secrets', arguments: { text: 'api_key = "walk-fixture-value"' } });
    const parsed = JSON.parse(response.content[0].text);
    if (!parsed.found || String(parsed.redacted).includes('walk-fixture-value')) {
      throw new Error('scan_secrets did not find and redact the fixture');
    }
    check = 'scan_secrets found and redacted the fixture';
  }
  process.stdout.write(`${spec}: ${tools.length} tools; ${check}\n`);
} finally {
  await client.close();
}
