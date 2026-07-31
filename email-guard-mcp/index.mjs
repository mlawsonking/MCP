#!/usr/bin/env node
// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: scripts/sync-shared.js (facadeEntry) + agent-guards/tools/
// Regenerate: node scripts/sync-shared.js
//
// email-guard-mcp — the email-guard tools, running locally.
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

const tools = registry.toolsFor('email-guard');
const registered = await serveStdio({
  tools,
  name: 'email-guard',
  version: pkg.version,
  ctx: { offline, disabled },
});

// stdout is the MCP transport. Anything human-readable goes to stderr or it corrupts the session.
const rulesets = require('./core/lib/rulesets.js');
process.stderr.write(`email-guard-mcp ${pkg.version} running (${registered.length} tools)${offline ? ' [offline]' : ''}, rules ${rulesets.provenance()}.\n`);

// Rule updates. About once a day this asks the feed whether a newer ruleset exists, carrying the
// surface tag "facade" and the rules version already installed and nothing else. It runs after the
// transport is connected and is never awaited, so a slow feed cannot delay a tool call. Turn it off
// with --offline, AGENT_GUARDS_NO_FEED=1, or {"feed": false} in ~/.agent-guards/config.json.
// https://github.com/mlawsonking/MCP/blob/main/rules/README.md
if (!offline) {
  require('./core/lib/feed.js').update({ surface: 'facade' })
    .then((r) => {
      if (r.action === 'applied') process.stderr.write(`rules updated to ${r.version}\n`);
      else if (r.action === 'refused') process.stderr.write(`rules update refused: ${r.reason}\n`);
    })
    .catch(() => { /* the rules already loaded stay in place */ });
}
