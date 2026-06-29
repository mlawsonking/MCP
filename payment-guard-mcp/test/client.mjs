// Spawns payment-guard-mcp over stdio, lists tools, exercises each. Run: node test/client.mjs
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({ command: process.execPath, args: ['index.mjs'] });
const client = new Client({ name: 'test', version: '1.0.0' });
let pass = 0, fail = 0;
const ck = (n, c, info) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${info ? '  :: ' + info : ''}`); };
const text = (r) => (r.content && r.content[0] && r.content[0].text) || '';
const json = (r) => { try { return JSON.parse(text(r).replace(/^[^{[]*/, '')); } catch { return {}; } };

await client.connect(transport);
const tools = (await client.listTools()).tools;
ck('lists 4 tools', tools.length === 4, tools.map((t) => t.name).join(', '));

let r = await client.callTool({ name: 'screen_address', arguments: { address: 'vitalik.eth', chain: 'eth' } });
let j = json(r); ck('screen_address ENS → resolves + verdict', j.ok && j.resolved_from === 'vitalik.eth' && !!j.verdict, `verdict=${j.verdict}`);

r = await client.callTool({ name: 'screen_payment', arguments: { url: 'http://coinbase.com.x402-pay.tk/checkout' } });
j = json(r); ck('screen_payment lookalike → flagged', j.ok && j.verdict !== 'safe', `verdict=${j.verdict}`);

r = await client.callTool({ name: 'check_sanctioned', arguments: { address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' } });
j = json(r); ck('check_sanctioned clean → clear', j.ok && j.verdict === 'clear', `list=${j.list_size}`);

r = await client.callTool({ name: 'resolve_name', arguments: { name: 'vitalik.eth' } });
j = json(r); ck('resolve_name vitalik.eth', j.ok && j.resolved === true && !!j.address, `addr=${(j.address || '').slice(0, 12)}`);

console.log(`\n${pass} passed, ${fail} failed`);
await client.close();
process.exit(fail === 0 ? 0 : 1);
