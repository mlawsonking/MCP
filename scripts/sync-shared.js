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

// The Claude Code plugin. It vendors the core for the same reason the facades do, and for one more:
// a plugin is installed by cloning a marketplace repo, and ${CLAUDE_PLUGIN_ROOT} is only promised to
// be the plugin's own directory. A hook that reached up into ../agent-guards would work in this
// checkout and break on someone else's machine, which is the Vercel bundling mistake wearing a
// different hat. It also needs data/ — the popular-package lists the offline name check compares
// against — which nothing else copies.
const PLUGIN = 'agent-guards-plugin';
const PLUGIN_CORE_DIRS = ['lib', 'engines', 'tools', 'cli'];
const PLUGIN_DATA_DIRS = ['data'];

// A plain CommonJS entry point, so it works both as `node .../bin/guard` and as a bare `guard` from
// the Bash tool's PATH, which is where a plugin's bin/ ends up. It cannot be the core's own
// bin/guard.mjs: an extensionless file is CommonJS to Node no matter what it contains, and that file
// is an ES module.
function pluginBin(version) {
  return `#!/usr/bin/env node
// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: scripts/sync-shared.js (pluginBin) + agent-guards/cli/
// Regenerate: node scripts/sync-shared.js
//
// guard ${version} — the same CLI as the agent-guards package, bundled with the plugin so it needs
// no install. This file has no extension on purpose: a plugin's bin/ is added to the Bash tool's
// PATH, and a bare \`guard\` has to be runnable there.
//
// The surface tag is set here rather than in the CLI so a rules pull made through the plugin is
// counted as a plugin install. The hooks themselves never pull: they are the intercept path and are
// not allowed to touch the network at all, which agent-guards/test/no-network.cjs enforces.
if (!process.env.AGENT_GUARDS_SURFACE) process.env.AGENT_GUARDS_SURFACE = 'plugin';
require('../core/cli/index.js')
  .main(process.argv.slice(2))
  .then((code) => { process.exitCode = code; })
  .catch((e) => { process.stderr.write('guard: ' + ((e && e.stack) || e) + '\\n'); process.exitCode = 2; });
`;
}

function pluginBinCmd() {
  return '@echo off\r\nrem GENERATED FILE - do not edit here. Regenerate: node scripts/sync-shared.js\r\n'
    + 'node "%~dp0guard" %*\r\n';
}

// The rules feed manifest, written by scripts/sign-rules-bundle.js, vendored into the one product
// that serves the feed.
const FEED_MANIFEST_SRC = 'rules/manifest.json';
const FEED_MANIFEST_DEST = 'agent-firewall/rules/manifest.json';

// The GitHub Action is its OWN repository, cloned inside this one and gitignored here. It vendors
// the core too, so a PR scan runs the same rules as everything else without depending on our Vercel
// apps being up. Because it is not part of this repo, a clean CI runner does not have the folder at
// all, so this target is optional: present, it is kept in sync and drift-checked; absent, that is
// reported rather than passing quietly.
const OPTIONAL_TARGETS = [
  { dir: 'code-guard-action', subdir: 'core', dirs: ['lib', 'engines'], data: ['data'] },
];

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
function coreFiles(dirs, exts = ['.js', '.mjs']) {
  const out = [];
  for (const dir of dirs) {
    const abs = path.join(CORE, dir);
    if (!fs.existsSync(abs)) continue;
    for (const f of fs.readdirSync(abs).sort()) {
      if (exts.some((e) => f.endsWith(e))) out.push(`${dir}/${f}`);
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
const rulesets = require('./core/lib/rulesets.js');
process.stderr.write(\`${npm} \${pkg.version} running (\${registered.length} tools)\${offline ? ' [offline]' : ''}, rules \${rulesets.provenance()}.\\n\`);

// Rule updates. About once a day this asks the feed whether a newer ruleset exists, carrying the
// surface tag "facade" and the rules version already installed and nothing else. It runs after the
// transport is connected and is never awaited, so a slow feed cannot delay a tool call. Turn it off
// with --offline, AGENT_GUARDS_NO_FEED=1, or {"feed": false} in ~/.agent-guards/config.json.
// https://github.com/mlawsonking/MCP/blob/main/rules/README.md
if (!offline) {
  require('./core/lib/feed.js').update({ surface: 'facade' })
    .then((r) => {
      if (r.action === 'applied') process.stderr.write(\`rules updated to \${r.version}\\n\`);
      else if (r.action === 'refused') process.stderr.write(\`rules update refused: \${r.reason}\\n\`);
    })
    .catch(() => { /* the rules already loaded stay in place */ });
}
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

// 1b. the plugin's vendored core. Data files are copied byte for byte: they are JSON, so a comment
// banner would make them unparseable, and the provenance they need is already inside them.
const PLUGIN_CORE = coreFiles(PLUGIN_CORE_DIRS);
const PLUGIN_DATA = coreFiles(PLUGIN_DATA_DIRS, ['.json']);
const pluginVersion = JSON.parse(fs.readFileSync(path.join(CORE, 'package.json'), 'utf8')).version;

for (const rel of PLUGIN_CORE) {
  place(path.join(ROOT, PLUGIN, 'core', rel), read(rel), path.posix.join(PLUGIN, 'core', rel));
}
for (const rel of PLUGIN_DATA) {
  place(path.join(ROOT, PLUGIN, 'core', rel), fs.readFileSync(path.join(CORE, rel), 'utf8'), path.posix.join(PLUGIN, 'core', rel));
}
place(
  path.join(ROOT, PLUGIN, 'core', 'package.json'),
  `{\n  "type": "commonjs",\n  "version": "${pluginVersion}"\n}\n`,
  path.posix.join(PLUGIN, 'core/package.json')
);
place(path.join(ROOT, PLUGIN, 'bin', 'guard'), pluginBin(pluginVersion), path.posix.join(PLUGIN, 'bin/guard'));
place(path.join(ROOT, PLUGIN, 'bin', 'guard.cmd'), pluginBinCmd(), path.posix.join(PLUGIN, 'bin/guard.cmd'));

// 1c. optional targets that live in another repository
const skippedOptional = [];
let optionalCount = 0;
for (const t of OPTIONAL_TARGETS) {
  if (!fs.existsSync(path.join(ROOT, t.dir))) { skippedOptional.push(t.dir); continue; }
  for (const rel of coreFiles(t.dirs)) {
    place(path.join(ROOT, t.dir, t.subdir, rel), read(rel), path.posix.join(t.dir, t.subdir, rel));
    optionalCount++;
  }
  for (const rel of coreFiles(t.data || [], ['.json'])) {
    place(path.join(ROOT, t.dir, t.subdir, rel), fs.readFileSync(path.join(CORE, rel), 'utf8'), path.posix.join(t.dir, t.subdir, rel));
    optionalCount++;
  }
  place(path.join(ROOT, t.dir, t.subdir, 'package.json'), CJS_MARKER, path.posix.join(t.dir, t.subdir, 'package.json'));
  optionalCount++;
}

// 1d. the rules feed manifest, vendored into the product that serves it.
//
// agent-firewall/api/rules/latest.js revalidates against the copy on GitHub's raw CDN and only
// falls back to this one when that is unreachable. Vercel will not bundle anything above the
// project root, so the file has to exist inside the folder rather than be required from rules/.
// Copied byte for byte: a banner would make the JSON unparseable.
let feedManifestCount = 0;
if (fs.existsSync(path.join(ROOT, FEED_MANIFEST_SRC))) {
  place(
    path.join(ROOT, FEED_MANIFEST_DEST),
    fs.readFileSync(path.join(ROOT, FEED_MANIFEST_SRC), 'utf8'),
    FEED_MANIFEST_DEST
  );
  feedManifestCount = 1;
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
  const pluginFiles = PLUGIN_CORE.length + PLUGIN_DATA.length + 3; // + marker + the two bin shims
  const total = API_CORE.length * PRODUCTS.length + FACADE_CORE.length * facadeCount + facadeCount * 2 +
    Object.values(TARGETS).flat().length + Object.keys(SHIMS).length + pluginFiles + feedManifestCount;
  console.log(
    `generated copies in sync (${total} files checked: ${API_CORE.length} core x ${PRODUCTS.length} APIs, ` +
    `${FACADE_CORE.length} core + entry + marker x ${facadeCount} facades, ` +
    `${pluginFiles} plugin, ${Object.values(TARGETS).flat().length} lib, ${Object.keys(SHIMS).length} shims)`
  );
  if (optionalCount) console.log(`plus ${optionalCount} file(s) in optional targets present in this checkout`);
  if (skippedOptional.length) {
    console.log(`not checked, not present in this checkout: ${skippedOptional.join(', ')} (its own repository, gitignored here)`);
  }
} else {
  console.log(written ? `synced ${written} file(s)` : 'already in sync');
}
