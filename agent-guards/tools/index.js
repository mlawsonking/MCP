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

const { RULES_VERSION } = require('../lib/version');

const ALL = [].concat(firewall, code, packages, payments, email, web);

// Run a tool and guarantee the metadata every verdict is supposed to carry.
//
// Handlers that already set `rules_version` keep theirs (the code scanner ships its own version,
// which moves on a different schedule from the shared ruleset). This only fills the gap, so that
// "every verdict names the rules that produced it" is true by construction rather than by each
// handler remembering. List-based checks keep their own coverage object on top: which rules ran and
// how much of the world the list covers are two different questions, and a caller needs both.
async function runTool(tool, args, ctx) {
  const out = await tool.run(args || {}, ctx || { offline: false, disabled: new Set() });
  if (out && typeof out === 'object' && out.verdict !== undefined && out.rules_version === undefined) {
    out.rules_version = RULES_VERSION;
  }
  return out;
}

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

module.exports = { ALL, PRODUCTS, toolsFor, byName, localTools, cloudTools, runTool };
