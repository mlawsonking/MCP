#!/usr/bin/env node
// The unified local MCP server: every tool from all six guards in one process, no configuration.
//
// Nothing is written to stdout except MCP protocol traffic. stdout IS the transport on a stdio
// server, so every human-readable line here goes to stderr. A stray console.log breaks the session
// in a way that looks like a client bug.

import { createRequire } from 'module';
import { serveStdio } from '../mcp/server.mjs';

const require = createRequire(import.meta.url);
const registry = require('../tools/index.js');
const pkg = require('../package.json');

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const valueOf = (flag) => {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null;
};

if (has('--help') || has('-h')) {
  process.stderr.write(`agent-guards ${pkg.version} — local security tools for AI agents, over MCP stdio.

  npx agent-guards                    every tool, cloud intel enabled
  npx agent-guards --offline          local engines only; cloud tools report what they cannot check
  npx agent-guards --only <product>   one product's tools
                                      (agent-firewall, code-guard, package-guard,
                                       payment-guard, email-guard, agent-tools)
  npx agent-guards --disable a,b      turn off named tools
  npx agent-guards --list             list the tools and exit

Local tools work with no network and send nothing off the machine. Cloud tools are marked in their
descriptions and name the service they call. In --offline mode a cloud tool reports that it could not
check rather than returning a verdict, because "could not check" is not "nothing found".
`);
  process.exit(0);
}

const offline = has('--offline');
const only = valueOf('--only');
const disabled = new Set((valueOf('--disable') || '').split(',').map((s) => s.trim()).filter(Boolean));

let tools;
try {
  tools = only ? registry.toolsFor(only) : registry.ALL;
} catch (e) {
  process.stderr.write(`${e.message}\nProducts: ${Object.keys(registry.PRODUCTS).join(', ')}\n`);
  process.exit(1);
}

const isLocal = (t) => !t.needs || !t.needs.length;
// A tool with `cloudWhen` does most of its work locally and only reaches the network to enrich the
// result, so offline it still answers and lists what it skipped. Calling that "cloud" would tell
// someone offline they have less than they do.
const isMostlyLocal = (t) => !isLocal(t) && !!t.cloudWhen;

if (has('--list')) {
  const rows = tools.map((t) => {
    const kind = isLocal(t) ? 'local' : isMostlyLocal(t) ? `mostly local (network for: ${t.needs.join(', ')})` : `cloud (${t.needs.join(', ')})`;
    return `  ${t.name.padEnd(20)} ${String(t.product).padEnd(15)} ${kind}`;
  });
  const local = tools.filter(isLocal).length;
  const mostly = tools.filter(isMostlyLocal).length;
  process.stderr.write(
    `${tools.length} tools — ${local} fully local, ${mostly} mostly local, ${tools.length - local - mostly} need the network\n` +
    `Offline, the first ${local + mostly} still answer; the rest report that they could not check.\n\n${rows.join('\n')}\n`
  );
  process.exit(0);
}

const ctx = { offline, disabled };
const registered = await serveStdio({
  tools,
  name: only || 'agent-guards',
  version: pkg.version,
  ctx,
});

const localCount = tools.filter(isLocal).length + tools.filter(isMostlyLocal).length;
process.stderr.write(
  `agent-guards ${pkg.version} running — ${registered.length} tools` +
  `${offline ? ` (OFFLINE: ${localCount} still answer, the rest report that they could not check)` : `, ${localCount} run locally and ${tools.length - localCount} use cloud intel`}` +
  `${disabled.size ? `, ${disabled.size} disabled` : ''}\n`
);
