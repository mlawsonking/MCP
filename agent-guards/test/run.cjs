#!/usr/bin/env node
// Runs every core suite in its own process and fails if any of them fail.
//
// Separate processes on purpose: several engines cache list loads at module scope, and a suite that
// inherited a warm cache from an earlier suite would be testing the cache rather than the code.

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// Offline suites only. Anything that touches a third-party endpoint goes in a suite that is run by
// hand, for the reason written into CI: a suite that goes red at random teaches everyone to ignore red.
const SUITES = ['net.cjs', 'engines.cjs', 'mcp.mjs', 'facades.mjs'];

let failed = 0;
for (const suite of SUITES) {
  const file = path.join(__dirname, suite);
  if (!fs.existsSync(file)) continue;
  console.log(`\n=== ${suite} ===`);
  const r = spawnSync(process.execPath, [file], { stdio: 'inherit' });
  if (r.status !== 0) failed++;
}

if (failed) {
  console.log(`\n${failed} suite(s) failed`);
  process.exit(1);
}
console.log('\nall core suites passed');
