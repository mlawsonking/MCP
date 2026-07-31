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

// Every .js file under agent-guards/lib and agent-guards/engines, as posix-style relative paths.
function coreFiles() {
  const out = [];
  for (const dir of ['lib', 'engines']) {
    const abs = path.join(CORE, dir);
    if (!fs.existsSync(abs)) continue;
    for (const f of fs.readdirSync(abs).sort()) {
      if (f.endsWith('.js')) out.push(`${dir}/${f}`);
    }
  }
  return out;
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

// 1. the core
const CORE_FILES = coreFiles();
if (!CORE_FILES.length) {
  console.error('No core files found under agent-guards/lib or agent-guards/engines.');
  process.exit(1);
}
for (const rel of CORE_FILES) {
  const want = banner(`agent-guards/${rel}`) + fs.readFileSync(path.join(CORE, rel), 'utf8');
  for (const product of PRODUCTS) {
    place(path.join(ROOT, product, 'lib', 'core', rel), want, path.posix.join(product, 'lib/core', rel));
  }
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
  const total = CORE_FILES.length * PRODUCTS.length + Object.values(TARGETS).flat().length + Object.keys(SHIMS).length;
  console.log(`generated copies in sync (${total} files checked: ${CORE_FILES.length} core x ${PRODUCTS.length} products, ${Object.values(TARGETS).flat().length} lib, ${Object.keys(SHIMS).length} shims)`);
} else {
  console.log(written ? `synced ${written} file(s)` : 'already in sync');
}
