#!/usr/bin/env node
// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: scripts/sync-shared.js (facadeEntry) + agent-guards/tools/
// Regenerate: node scripts/sync-shared.js
//
// web-tools-mcp — the agent-tools tools, running locally.
//
// Every tool this exposes is defined once in the core registry and shared with the unified server,
// so the tool names, schemas and response shapes here cannot drift from it. Tools that need the
// network say so in their own descriptions; --offline makes them report what they could not check
// instead of returning a verdict.
import { createRequire } from 'module';
import { serveStdio } from './core/mcp/server.mjs';

const require = createRequire(import.meta.url);
const registry = require('./core/tools/index.js');
const pkg = require('./package.json');

const argv = process.argv.slice(2);
const offline = argv.includes('--offline');
const disableArg = argv.indexOf('--disable');
const disabled = new Set(
  disableArg !== -1 && argv[disableArg + 1] && !argv[disableArg + 1].startsWith('--')
    ? argv[disableArg + 1].split(',').map((s) => s.trim()).filter(Boolean)
    : []
);

const tools = registry.toolsFor('agent-tools');
const registered = await serveStdio({
  tools,
  name: 'agent-tools',
  version: pkg.version,
  ctx: { offline, disabled },
});

// stdout is the MCP transport. Anything human-readable goes to stderr or it corrupts the session.
process.stderr.write(`web-tools-mcp ${pkg.version} running (${registered.length} tools)${offline ? ' [offline]' : ''}.\n`);
