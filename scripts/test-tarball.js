#!/usr/bin/env node
// Pack the core exactly as npm would publish it, install that tarball into an empty directory, and
// run real checks through the installed copy.
//
// This exists because published 0.3.0 shipped without `data/`: the `files` allowlist in package.json
// did not include it, so every install answered `verdict: safe` for `crossenv`, a real npm typosquat.
// Every test in the repo passed, because the repo has the file. A source-tree test cannot see what
// npm leaves out, so the only honest check is to install the artifact and use it.
//
//   node scripts/test-tarball.js
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PKG = path.join(ROOT, 'agent-guards');
let failures = 0;
let checks = 0;

function ck(label, pass, detail) {
  checks += 1;
  if (pass) { console.log(`  ok   ${label}`); return; }
  failures += 1;
  console.log(`  FAIL ${label}${detail ? `\n       ${String(detail).slice(0, 300)}` : ''}`);
}

// npm needs a shell on Windows (it is a .cmd); node must NOT have one, or a path containing a space
// such as "C:\Program Files\nodejs\node.exe" is split at the space by cmd.
function run(cmd, args, cwd) {
  const isNpm = /npm(\.cmd)?$/i.test(cmd);
  return execFileSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: isNpm && process.platform === 'win32',
  });
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-tarball-'));
console.log(`\nagent-guards published-artifact check (${tmp})\n`);

try {
  // 1. Pack exactly what npm publish would send.
  const packed = JSON.parse(run('npm', ['pack', '--json', '--pack-destination', tmp], PKG));
  const tarball = path.join(tmp, packed[0].filename);
  const shipped = new Set(packed[0].files.map((f) => f.path.replace(/\\/g, '/')));

  // 2. The files the engines require at runtime have to be in the artifact. Named individually so a
  //    failure says which one, rather than "something is missing".
  for (const needed of [
    'data/popular-npm.json',
    'data/popular-pypi.json',
    'engines/pkgname.js',
    'engines/shellcmd.js',
    'cli/index.js',
    'bin/guard.mjs',
    'bin/agent-guards.mjs',
  ]) {
    ck(`the artifact contains ${needed}`, shipped.has(needed), `not in the ${shipped.size}-file tarball`);
  }

  // 3. Install the artifact into an empty project, the way a stranger would.
  const proj = path.join(tmp, 'proj');
  fs.mkdirSync(proj);
  fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify({ name: 'tarball-check', version: '1.0.0', private: true }) + '\n');
  run('npm', ['install', tarball, '--no-audit', '--no-fund', '--loglevel', 'error'], proj);

  // 4. Use it. `crossenv` is the canonical npm typosquat: a real package that shipped malware under
  //    a name one separator away from `cross-env`. If the installed copy calls this safe, the guard
  //    is worse than nothing, because it answers a security question with a wrong reassurance.
  const probe = path.join(proj, 'probe.js');
  fs.writeFileSync(probe, `
    const { inspect } = require('agent-guards/engines/pkgname.js');
    const out = {};
    for (const [name, eco] of [['crossenv', 'npm'], ['reqests', 'pypi'], ['express', 'npm']]) {
      const r = inspect(name, eco);
      out[name] = { verdict: r.verdict, findings: (r.findings || []).map((f) => f.id), listSize: r.list_size };
    }
    process.stdout.write(JSON.stringify(out));
  `);
  const res = JSON.parse(run(process.execPath, [probe], proj));

  ck('the installed copy loaded its comparison list', res.crossenv.listSize > 0, `list_size ${res.crossenv.listSize}`);
  ck('crossenv is not called safe by the installed copy', res.crossenv.verdict !== 'safe', `verdict ${res.crossenv.verdict}`);
  ck('crossenv is flagged as a squat', res.crossenv.verdict === 'danger' || res.crossenv.verdict === 'caution', `verdict ${res.crossenv.verdict}`);
  ck('a pypi typosquat is flagged', res.reqests.verdict !== 'safe', `verdict ${res.reqests.verdict}`);
  ck('a real popular package stays quiet', res.express.verdict === 'safe', `verdict ${res.express.verdict}`);

  // 5. The declared executables have to exist and run from the artifact.
  const pkgJson = JSON.parse(fs.readFileSync(path.join(proj, 'node_modules', 'agent-guards', 'package.json'), 'utf8'));
  for (const [bin, rel] of Object.entries(pkgJson.bin || {})) {
    ck(`the ${bin} executable is present`, fs.existsSync(path.join(proj, 'node_modules', 'agent-guards', rel)), rel);
  }
  // `guard` with no arguments prints its usage and exits non-zero on purpose, so the output is what
  // matters here, not the code.
  let help = '';
  try { help = run(process.execPath, [path.join(proj, 'node_modules', 'agent-guards', pkgJson.bin.guard)], proj); }
  catch (err) { help = String(err.stdout || '') + String(err.stderr || ''); }
  ck('guard runs from the installed artifact', /usage|scan|package/i.test(help), help.slice(0, 120));

  // 6. The fail-closed direction: with the list removed, the answer must not be a clean name.
  const noData = path.join(proj, 'node_modules', 'agent-guards', 'data');
  const parked = path.join(tmp, 'data-parked');
  fs.renameSync(noData, parked);
  const degraded = JSON.parse(run(process.execPath, [probe], proj));
  ck('a name check without its list never says safe', degraded.crossenv.verdict !== 'safe', `verdict ${degraded.crossenv.verdict}`);
  ck('a name check without its list says unknown', degraded.crossenv.verdict === 'unknown', `verdict ${degraded.crossenv.verdict}`);
  fs.renameSync(parked, noData);
} catch (err) {
  failures += 1;
  console.log(`  FAIL harness error: ${err.message}`);
  if (err.stdout) console.log(String(err.stdout).slice(0, 400));
  if (err.stderr) console.log(String(err.stderr).slice(0, 400));
} finally {
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* the OS can have it */ }
}

console.log(`\npublished artifact: ${checks - failures} passed, ${failures} failed\n`);
process.exit(failures ? 1 : 0);
