#!/usr/bin/env node
// Keeps the per-product copies of the shared libs in sync with shared/lib/.
//
// Why copies at all: each product folder is its own Vercel project, deployed with `vercel --prod`
// from inside that folder. Vercel only bundles files under the project root, so a require() that
// reaches up into ../shared would work locally and fail in production. The copies are committed so
// deploys keep working; shared/lib/ is the only file anyone edits.
//
//   node scripts/sync-shared.js           rewrite every copy from the source
//   node scripts/sync-shared.js --check    fail if any copy has drifted (CI runs this)

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// source file -> the product folders that need a copy of it
const TARGETS = {
  'common.js': ['package-guard', 'agent-firewall', 'payment-guard', 'email-guard', 'code-guard', 'agent-tools-api'],
  'safety.js': ['agent-firewall', 'payment-guard', 'email-guard', 'code-guard'],
};

function banner(name) {
  return [
    '// GENERATED FILE - do not edit here. Your change will be overwritten.',
    `// Source of truth: shared/lib/${name}`,
    '// Regenerate: node scripts/sync-shared.js',
    '',
  ].join('\n');
}

function expected(name) {
  return banner(name) + fs.readFileSync(path.join(ROOT, 'shared', 'lib', name), 'utf8');
}

const check = process.argv.includes('--check');
const drifted = [];
let written = 0;

for (const [name, folders] of Object.entries(TARGETS)) {
  const want = expected(name);
  for (const folder of folders) {
    const dest = path.join(ROOT, folder, 'lib', name);
    const current = fs.existsSync(dest) ? fs.readFileSync(dest, 'utf8') : null;
    if (current === want) continue;
    if (check) { drifted.push(path.posix.join(folder, 'lib', name)); continue; }
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, want);
    written++;
    console.log(`wrote ${folder}/lib/${name}`);
  }
}

if (check) {
  if (drifted.length) {
    console.error('Shared libs have drifted from shared/lib/:\n' + drifted.map((f) => '  ' + f).join('\n'));
    console.error('\nEdit shared/lib/ and run: node scripts/sync-shared.js');
    process.exit(1);
  }
  console.log(`shared libs in sync (${Object.values(TARGETS).flat().length} copies checked)`);
} else {
  console.log(written ? `synced ${written} file(s)` : 'already in sync');
}
