// Spawns package-guard-mcp over stdio, lists tools, and exercises each. Run: node test/client.mjs
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
ck('lists 5 tools', tools.length === 5, tools.map((t) => t.name).join(', '));

let r = await client.callTool({ name: 'verify_package', arguments: { name: 'express' } });
let j = json(r); ck('verify_package express → safe', j.exists === true && !!j.verdict, `verdict=${j.verdict}`);

r = await client.callTool({ name: 'verify_package', arguments: { name: 'reqeusts-fake-pkg-9z9z9z' } });
j = json(r); ck('verify_package hallucinated → danger', j.exists === false && j.verdict === 'danger', `hallucination=${j.likely_hallucination}`);

r = await client.callTool({ name: 'check_vulns', arguments: { name: 'lodash', version: '4.17.11' } });
j = json(r); ck('check_vulns lodash@4.17.11', j.ok && j.count > 0, `count=${j.count}`);

r = await client.callTool({ name: 'package_info', arguments: { name: 'flask', ecosystem: 'pypi' } });
j = json(r); ck('package_info flask (pypi)', j.ok && j.exists === true, `latest=${j.latest}`);

r = await client.callTool({ name: 'audit_deps', arguments: { packages: ['react', 'lodash', 'not-real-pkg-7q7q'] } });
j = json(r); ck('audit_deps batch', j.ok && j.total === 3 && j.summary.missing >= 1, `danger=${j.summary?.danger} missing=${j.summary?.missing}`);

r = await client.callTool({ name: 'typosquat_scan', arguments: { name: 'lodash' } });
j = json(r); ck('typosquat_scan lodash', j.ok && typeof j.registered === 'number', `registered=${j.registered}`);

console.log(`\n${pass} passed, ${fail} failed`);
await client.close();
process.exit(fail === 0 ? 0 : 1);
