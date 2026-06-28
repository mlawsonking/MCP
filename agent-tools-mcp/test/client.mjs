// Spawns the MCP server over stdio, lists tools, and calls all of them (hitting live endpoints).
// This is the Engine #2 end-to-end audit. Run: node test/client.mjs
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({ command: 'node', args: ['index.mjs'] });
const client = new Client({ name: 'audit-client', version: '1.0.0' });
await client.connect(transport);

const { tools } = await client.listTools();
console.log('TOOLS (' + tools.length + '):', tools.map((t) => t.name).join(', '));

let pass = 0, fail = 0;
const text = (r) => (r.content && r.content[0] && r.content[0].text) || '';
async function probe(name, args, ok) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const good = !r.isError && ok(text(r));
    good ? pass++ : fail++;
    console.log(`${good ? 'PASS' : 'FAIL'}  ${name}  :: ${text(r).replace(/\s+/g, ' ').slice(0, 90)}`);
  } catch (e) { fail++; console.log(`FAIL  ${name} (threw) ${e.message}`); }
}

await probe('read_url', { url: 'https://example.com' }, (t) => /Example Domain/.test(t));
await probe('unfurl_url', { url: 'https://github.com' }, (t) => /"title"/.test(t) && /GitHub/.test(t));
await probe('validate_email', { email: 'test@gmail.com' }, (t) => /"deliverable": true/.test(t));
await probe('extract_web', { url: 'https://example.com', selectors: { h1: 'h1', links: 'a[]@href' } }, (t) => /Example Domain/.test(t));
await probe('get_feed', { url: 'https://news.ycombinator.com/rss', limit: 3 }, (t) => /"items"/.test(t));
await probe('dns_lookup', { domain: 'google.com' }, (t) => /"has_mx": true/.test(t));
await probe('domain_info', { domain: 'google.com' }, (t) => /"age_days"/.test(t));
await probe('ssl_check', { host: 'github.com' }, (t) => /"days_remaining"/.test(t) && /"trusted": true/.test(t));
await probe('http_inspect', { url: 'github.com' }, (t) => /"status": 200/.test(t));
await probe('structured_data', { url: 'https://github.com' }, (t) => /"opengraph"|"schema_types"/.test(t));

await client.close();
console.log(`\n${pass} passed, ${fail} failed across ${tools.length} live tools`);
process.exit(fail === 0 ? 0 : 1);
