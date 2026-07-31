// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/index.js
// Regenerate: node scripts/sync-shared.js
// The tool registry: every tool the six products expose, in one list.
//
// This is the single definition of each tool's name, schema, description and behaviour. The unified
// MCP server registers all of them; each `-mcp` facade package registers the subset for its product.
// One definition means a facade cannot drift from the unified server, which is the whole point of
// the facades being thin.

const firewall = require('./firewall');
const code = require('./code');
const packages = require('./packages');
const payments = require('./payments');
const email = require('./email');
const web = require('./web');

const ALL = [].concat(firewall, code, packages, payments, email, web);

// Product key -> the npm package name of the facade that exposes it. Used by the facades and by the
// tests that check every tool still belongs to exactly one product.
const PRODUCTS = {
  'agent-firewall': 'agent-firewall-mcp',
  'code-guard': '@mlawsonking/code-guard-mcp',
  'package-guard': 'package-guard-mcp',
  'payment-guard': 'payment-guard-mcp',
  'email-guard': 'email-guard-mcp',
  'agent-tools': 'web-tools-mcp',
};

function toolsFor(product) {
  const list = ALL.filter((t) => t.product === product);
  if (!list.length) throw new Error(`No tools registered for product "${product}"`);
  return list;
}

function byName(name) {
  return ALL.find((t) => t.name === name);
}

// A tool is "local" when it needs nothing external. Those are the ones that still work offline.
function localTools() {
  return ALL.filter((t) => !t.needs || t.needs.length === 0);
}

function cloudTools() {
  return ALL.filter((t) => t.needs && t.needs.length > 0);
}

module.exports = { ALL, PRODUCTS, toolsFor, byName, localTools, cloudTools };
