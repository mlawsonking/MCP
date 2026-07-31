// End-to-end check of a generated facade: spawn it as a real MCP stdio server, talk to it with the
// real SDK client, and confirm a tool call comes back in the shape callers already parse.
//
// One facade is enough to prove the generated entry point works, because all six are generated from
// the same template and differ only in which product's tools they select. The per-product tool
// contract is asserted separately in facades.mjs, which needs no install.
//
// Run from the repo root after installing that facade's dependencies:
//   npm install --prefix agent-firewall-mcp && node agent-guards/test/facade-client.mjs

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const require = createRequire(import.meta.url);
const { ck, section, done } = require('./_harness.cjs');

const here = path.dirname(fileURLToPath(import.meta.url));
const facadeDir = path.resolve(here, '..', '..', 'agent-firewall-mcp');
const entry = path.join(facadeDir, 'index.mjs');
const pkg = require(path.join(facadeDir, 'package.json'));

section('agent-firewall-mcp over a real stdio session');

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entry],
  cwd: facadeDir,
  stderr: 'pipe',
});
const client = new Client({ name: 'facade-test', version: '1.0.0' }, { capabilities: {} });
await client.connect(transport);

const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
ck('the session connects and lists tools', tools.length > 0, `${tools.length} tools`);
ck('the published five tools are all there',
  ['check_ip', 'check_password', 'check_url', 'scan_content', 'scan_secrets'].every((n) => names.includes(n)),
  names.join());
ck('no extra tools leaked in from other products', names.length === 5, names.join());

// The server version used to be hardcoded to 1.0.0 while package.json said 1.1.0.
const info = client.getServerVersion();
ck('the server advertises the package version', info && info.version === pkg.version, `advertised=${info && info.version} package=${pkg.version}`);

// Descriptions are what an agent reads to decide whether to call a tool.
const secretsTool = tools.find((t) => t.name === 'scan_secrets');
ck('a local tool says so in its description', /fully locally/i.test(secretsTool.description || ''), (secretsTool.description || '').slice(-80));
const ipTool = tools.find((t) => t.name === 'check_ip');
ck('a cloud tool names its network dependency', /Network: needs/.test(ipTool.description || ''), (ipTool.description || '').slice(-90));

section('a tool call returns the shape callers already parse');
{
  const res = await client.callTool({ name: 'scan_secrets', arguments: { text: 'api_key = "hunter2sekrit"' } });
  ck('response is a single text block', Array.isArray(res.content) && res.content.length === 1 && res.content[0].type === 'text');
  let parsed;
  try { parsed = JSON.parse(res.content[0].text); } catch { parsed = null; }
  ck('the text block is JSON', !!parsed, String(res.content[0].text).slice(0, 80));
  if (parsed) {
    for (const field of ['ok', 'length', 'found', 'secrets', 'pii', 'verdict', 'findings', 'redacted', 'rules_version', 'ms']) {
      ck(`field "${field}" is present`, Object.prototype.hasOwnProperty.call(parsed, field), Object.keys(parsed).join());
    }
    ck('the secret value is not in the redacted output', !String(parsed.redacted).includes('hunter2sekrit'), parsed.redacted);
  }
}

section('a failing call reports an error rather than a verdict');
{
  const res = await client.callTool({ name: 'scan_secrets', arguments: { text: '' } });
  ck('empty input is an error, not an all-clear', res.isError === true, JSON.stringify(res).slice(0, 120));
}

await client.close();
done('agent-guards facade client');
