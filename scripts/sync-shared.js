#!/usr/bin/env node
// Keeps every product folder's copy of shared code in sync with its single source.
//
// Why copies at all: each product folder is its own Vercel project, deployed with `vercel --prod`
// from inside that folder. Vercel only bundles files under the project root, so a require() that
// reaches up into ../agent-guards would work locally and fail in production. The copies are
// committed so deploys keep working; the sources are the only files anyone edits.
//
// Three kinds of copy, one source each:
//
//   core   agent-guards/{lib,engines}/*.js  ->  <product>/lib/core/...
//          The detection engines. THE source of truth for detection behaviour.
//   lib    shared/lib/{common,safety}.js    ->  <product>/lib/...
//          The API-facing surface over the core: HTTP plumbing, beacon, and the export names the
//          handlers in api/ already import.
//   shim   generated one-liners             ->  e.g. code-guard/lib/codescan.js
//          Product-specific modules whose bodies moved into the core. Re-export everything so no
//          caller had to change.
//
//   node scripts/sync-shared.js           rewrite every copy from its source
//   node scripts/sync-shared.js --check   fail if any copy has drifted (CI runs this)

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CORE = path.join(ROOT, 'agent-guards');

// Every product folder gets the whole core. It is a few dozen KB, and a uniform rule means adding an
// engine never needs a change here.
const PRODUCTS = ['package-guard', 'agent-firewall', 'payment-guard', 'email-guard', 'code-guard', 'agent-tools-api'];

// source file -> the product folders that need a copy of it
const TARGETS = {
  'common.js': PRODUCTS,
  'safety.js': ['agent-firewall', 'payment-guard', 'email-guard', 'code-guard'],
};

// The six MCP packages. Each vendors the core and registers only its own product's tools, so a
// facade cannot drift from the unified server: there is one definition of every tool.
//
// They vendor rather than depend on the core for the same reason the API folders do — an npm
// dependency would have to be published first, and the package name is still the owner's call.
const FACADES = {
  'package-guard-mcp': { product: 'package-guard', npm: 'package-guard-mcp' },
  'agent-firewall-mcp': { product: 'agent-firewall', npm: 'agent-firewall-mcp' },
  'payment-guard-mcp': { product: 'payment-guard', npm: 'payment-guard-mcp' },
  'email-guard-mcp': { product: 'email-guard', npm: 'email-guard-mcp' },
  'code-guard-mcp': { product: 'code-guard', npm: '@mlawsonking/code-guard-mcp' },
  'agent-tools-mcp': { product: 'agent-tools', npm: 'web-tools-mcp' },
};

// destination file -> the core module it re-exports
const SHIMS = {
  'code-guard/lib/codescan.js': './core/engines/code',
  'package-guard/lib/pkg.js': './core/engines/packages',
  'email-guard/lib/email.js': './core/engines/email',
  'payment-guard/lib/risk.js': './core/engines/payments',
  'payment-guard/lib/ens.js': './core/engines/ens',
};

function banner(source) {
  return [
    '// GENERATED FILE - do not edit here. Your change will be overwritten.',
    `// Source of truth: ${source}`,
    '// Regenerate: node scripts/sync-shared.js',
    '',
  ].join('\n');
}

// Core files as posix-style relative paths. The API folders need the engines; the MCP facades also
// need the tool declarations and the MCP layer.
function coreFiles(dirs) {
  const out = [];
  for (const dir of dirs) {
    const abs = path.join(CORE, dir);
    if (!fs.existsSync(abs)) continue;
    for (const f of fs.readdirSync(abs).sort()) {
      if (f.endsWith('.js') || f.endsWith('.mjs')) out.push(`${dir}/${f}`);
    }
  }
  return out;
}

// A facade package declares "type": "module", which would otherwise make every vendored .js file
// ESM and break the CommonJS core. The nearest package.json wins, so this marker keeps core/ as
// CommonJS inside an ESM package. The .mjs files under core/mcp stay ESM regardless of it.
const CJS_MARKER = '{\n  "type": "commonjs"\n}\n';

function facadeEntry(folder, { product, npm }) {
  return `#!/usr/bin/env node
// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: scripts/sync-shared.js (facadeEntry) + agent-guards/tools/
// Regenerate: node scripts/sync-shared.js
//
// ${npm} — the ${product} tools, running locally.
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

const tools = registry.toolsFor('${product}');
const registered = await serveStdio({
  tools,
  name: '${product}',
  version: pkg.version,
  ctx: { offline, disabled },
});

// stdout is the MCP transport. Anything human-readable goes to stderr or it corrupts the session.
process.stderr.write(\`${npm} \${pkg.version} running (\${registered.length} tools)\${offline ? ' [offline]' : ''}.\\n\`);
`;
}

function shimBody(target, mod) {
  return banner(`agent-guards/${mod.replace('./core/', '')}.js`) +
    `// The implementation moved into the core. This file only keeps the import path stable for\n` +
    `// everything under api/ that already requires it.\n` +
    `module.exports = require('${mod}');\n`;
}

const check = process.argv.includes('--check');
const drifted = [];
let written = 0;

function place(destAbs, want, label) {
  const current = fs.existsSync(destAbs) ? fs.readFileSync(destAbs, 'utf8') : null;
  if (current === want) return;
  if (check) { drifted.push(label); return; }
  fs.mkdirSync(path.dirname(destAbs), { recursive: true });
  fs.writeFileSync(destAbs, want);
  written++;
  console.log(`wrote ${label}`);
}

// 1. the core, into the API folders (engines only) and the MCP facades (engines + tools + mcp)
const API_CORE = coreFiles(['lib', 'engines']);
const FACADE_CORE = coreFiles(['lib', 'engines', 'tools', 'mcp']);
if (!API_CORE.length) {
  console.error('No core files found under agent-guards/lib or agent-guards/engines.');
  process.exit(1);
}
const read = (rel) => banner(`agent-guards/${rel}`) + fs.readFileSync(path.join(CORE, rel), 'utf8');

for (const rel of API_CORE) {
  const want = read(rel);
  for (const product of PRODUCTS) {
    place(path.join(ROOT, product, 'lib', 'core', rel), want, path.posix.join(product, 'lib/core', rel));
  }
}
for (const rel of FACADE_CORE) {
  const want = read(rel);
  for (const folder of Object.keys(FACADES)) {
    place(path.join(ROOT, folder, 'core', rel), want, path.posix.join(folder, 'core', rel));
  }
}
for (const folder of Object.keys(FACADES)) {
  place(path.join(ROOT, folder, 'core', 'package.json'), CJS_MARKER, path.posix.join(folder, 'core/package.json'));
  place(path.join(ROOT, folder, 'index.mjs'), facadeEntry(folder, FACADES[folder]), path.posix.join(folder, 'index.mjs'));
}

// 2. the API-facing shared libs
for (const [name, folders] of Object.entries(TARGETS)) {
  const want = banner(`shared/lib/${name}`) + fs.readFileSync(path.join(ROOT, 'shared', 'lib', name), 'utf8');
  for (const folder of folders) {
    place(path.join(ROOT, folder, 'lib', name), want, path.posix.join(folder, 'lib', name));
  }
}

// 3. the product-specific shims
for (const [target, mod] of Object.entries(SHIMS)) {
  place(path.join(ROOT, target), shimBody(target, mod), target);
}

if (check) {
  if (drifted.length) {
    console.error('Generated copies have drifted from their source:\n' + drifted.map((f) => '  ' + f).join('\n'));
    console.error('\nEdit the source (agent-guards/ or shared/lib/) and run: node scripts/sync-shared.js');
    process.exit(1);
  }
  const facadeCount = Object.keys(FACADES).length;
  const total = API_CORE.length * PRODUCTS.length + FACADE_CORE.length * facadeCount + facadeCount * 2 +
    Object.values(TARGETS).flat().length + Object.keys(SHIMS).length;
  console.log(
    `generated copies in sync (${total} files checked: ${API_CORE.length} core x ${PRODUCTS.length} APIs, ` +
    `${FACADE_CORE.length} core + entry + marker x ${facadeCount} facades, ` +
    `${Object.values(TARGETS).flat().length} lib, ${Object.keys(SHIMS).length} shims)`
  );
} else {
  console.log(written ? `synced ${written} file(s)` : 'already in sync');
}
