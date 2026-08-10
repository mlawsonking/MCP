#!/usr/bin/env node
// An installed plugin is cached per version at
// ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/. If the plugin's code changes but its
// version does not, `claude plugin update` answers "already at the latest version" and keeps serving
// the old copy, so the change reaches nobody who already installed. That happened with the shell rule
// fix: committed, pushed, present in the marketplace clone, and still not running on the machine that
// reported the bug.
//
// This records a hash of everything the plugin ships alongside the version it belongs to. Change the
// plugin without bumping the version and this fails. It reads no git history, so it behaves the same
// on a shallow CI checkout as it does locally.
//
//   node scripts/check-plugin-version.js            verify (CI)
//   node scripts/check-plugin-version.js --update    re-record after a bump
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const PLUGIN_DIR = path.join(ROOT, 'agent-guards-plugin');
const PLUGIN_MANIFEST = path.join(PLUGIN_DIR, '.claude-plugin', 'plugin.json');
const MARKETPLACE = path.join(ROOT, '.claude-plugin', 'marketplace.json');
const LOCK = path.join(PLUGIN_DIR, '.claude-plugin', 'content.lock.json');
const SKIP_DIRS = new Set(['node_modules', '.git']);
const LOCK_NAME = path.basename(LOCK);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name), out);
      continue;
    }
    if (entry.name === LOCK_NAME) continue;
    out.push(path.join(dir, entry.name));
  }
  return out;
}

// Line endings differ between a Windows checkout and a Linux runner, and that is not a content
// change. Normalize before hashing or this fails for the wrong reason.
function hashPlugin() {
  const h = crypto.createHash('sha256');
  for (const file of walk(PLUGIN_DIR)) {
    const rel = path.relative(PLUGIN_DIR, file).split(path.sep).join('/');
    h.update(rel);
    h.update('\0');
    h.update(fs.readFileSync(file).toString('utf8').replace(/\r\n/g, '\n'));
    h.update('\0');
  }
  return h.digest('hex');
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function marketplaceEntryVersion(name) {
  const m = readJson(MARKETPLACE);
  const list = Array.isArray(m.plugins) ? m.plugins : [];
  const entry = list.find((p) => p && p.name === name);
  return entry ? entry.version : undefined;
}

function main() {
  const update = process.argv.includes('--update');
  const manifest = readJson(PLUGIN_MANIFEST);
  const version = manifest.version;
  const fail = [];

  if (!version) fail.push(`${path.relative(ROOT, PLUGIN_MANIFEST)} has no version.`);

  // The marketplace entry is what a client reads when it decides whether an update exists. A bump in
  // one file and not the other is the same silent no-op as no bump at all.
  const listed = marketplaceEntryVersion(manifest.name);
  if (listed === undefined) {
    fail.push(`marketplace.json has no entry named "${manifest.name}".`);
  } else if (listed !== version) {
    fail.push(`plugin.json says ${version} but marketplace.json says ${listed}. Bump both.`);
  }

  const hash = hashPlugin();
  const lock = fs.existsSync(LOCK) ? readJson(LOCK) : null;

  if (update) {
    if (lock && lock.hash !== hash && lock.version === version) {
      console.error(`agent-guards-plugin changed but the version is still ${version}. Bump it in`);
      console.error('plugin.json and marketplace.json, then run this again.');
      process.exit(1);
    }
    fs.writeFileSync(LOCK, `${JSON.stringify({ version, hash }, null, 2)}\n`);
    console.log(`recorded agent-guards-plugin ${version} ${hash.slice(0, 12)}`);
    return;
  }

  if (!lock) {
    fail.push(`${path.relative(ROOT, LOCK)} is missing. Run: node scripts/check-plugin-version.js --update`);
  } else if (lock.hash !== hash && lock.version === version) {
    fail.push(
      `agent-guards-plugin changed but the version is still ${version}, so an installed plugin will\n` +
      '  never pick it up: the cache is keyed by version and update reports "already at the latest\n' +
      '  version". Bump plugin.json and marketplace.json, then run:\n' +
      '    node scripts/check-plugin-version.js --update'
    );
  } else if (lock.hash !== hash) {
    fail.push(
      `agent-guards-plugin changed and the version is now ${version}, but the lock still records\n` +
      `  ${lock.version}. Run: node scripts/check-plugin-version.js --update`
    );
  }

  if (fail.length) {
    console.error('plugin version check failed:');
    for (const f of fail) console.error(`- ${f}`);
    process.exit(1);
  }
  console.log(`ok   agent-guards-plugin ${version} matches its recorded contents`);
}

main();
