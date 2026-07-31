#!/usr/bin/env node
// Builds the bundled popular-package name lists that the offline typosquat check compares against.
//
//   node scripts/build-popular-packages.js
//
// Writes agent-guards/data/popular-npm.json and popular-pypi.json. Both are committed, so this
// script is only run when the lists need refreshing. It needs the network; nothing at runtime does.
//
// Why a list at all: the hook path cannot call a registry, so "is this name one edit away from
// something enormously popular" is the only typosquat signal available locally.
//
// Why the list has to be COMPLETE for the range it claims, not just large: a name that is missing
// is wrong in two directions at once. A squat aimed at it is not caught, and the real package
// itself gets reported as a squat of whatever else it happens to sit near. An earlier version of
// this script measured each name individually against api.npmjs.org and silently dropped the third
// that got rate-limited, which put a hole exactly there. So the ranking is taken whole, and a
// sample is re-measured to check the ranking is what it says it is.
//
// Where the data comes from:
//   npm   the download ranking published by npm-high-impact (github.com/wooorm/npm-high-impact),
//         taken in order. A random sample is then re-measured against api.npmjs.org, npm's own
//         endpoint, and the sample's numbers are written into the file so the claim can be checked.
//   PyPI  hugovk.dev/top-pypi-packages, generated from PyPI's own download table. Names are stored
//         in PEP 503 form (runs of - _ . collapsed to a single -, lowercased), which is how pip
//         compares them: store them raw and `discord.py` reads as a squat of `discord-py`, which is
//         the same project.

const fs = require('fs');
const path = require('path');

const OUT_DIR = path.join(__dirname, '..', 'agent-guards', 'data');

const NPM_SOURCE = 'https://cdn.jsdelivr.net/npm/npm-high-impact/lib/top-download.js';
const NPM_TAKE = 3000;
const NPM_SAMPLE = 60;

const PYPI_SOURCE = 'https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json';
const PYPI_TAKE = 3000;

async function getText(url) {
  const r = await fetch(url, { headers: { 'User-Agent': 'agent-guards-build/1.0 (+https://github.com/mlawsonking/MCP)' } });
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return r.text();
}

async function getJson(url) {
  return JSON.parse(await getText(url));
}

// The source is an ES module exporting a single-quoted array literal. Parsing it as text avoids
// importing a remote module into this process.
function parseNameArray(src) {
  const body = src.slice(src.indexOf('[') + 1, src.lastIndexOf(']'));
  return body.split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
}

// Re-measure a spread-out sample: not the top N, which would prove nothing about the bottom of the
// list, but every (size/sample)th name, so the last one checked is the last one included.
async function verifySample(names, size) {
  const step = Math.max(1, Math.floor(names.length / size));
  const picks = [];
  for (let i = 0; i < names.length && picks.length < size; i += step) picks.push(names[i]);

  const measured = [];
  const failed = [];
  for (const n of picks) {
    let ok = false;
    for (let attempt = 0; attempt < 4 && !ok; attempt++) {
      try {
        const j = await getJson(`https://api.npmjs.org/downloads/point/last-week/${n}`);
        if (j && typeof j.downloads === 'number') { measured.push({ name: n, weekly: j.downloads }); ok = true; }
        else ok = true; // answered, just not with a number
      } catch {
        await new Promise((r) => setTimeout(r, 750 * (attempt + 1)));
      }
    }
    if (!ok) failed.push(n);
    process.stderr.write(`\r  sampled ${measured.length + failed.length}/${picks.length}`);
  }
  process.stderr.write('\n');
  return { measured, failed, picks: picks.length };
}

function write(file, payload) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const dest = path.join(OUT_DIR, file);
  fs.writeFileSync(dest, JSON.stringify(payload, null, 0) + '\n');
  const kb = (fs.statSync(dest).size / 1024).toFixed(1);
  console.log(`wrote agent-guards/data/${file} — ${payload.names.length} names, ${kb} KB`);
}

async function main() {
  const today = new Date().toISOString().slice(0, 10);

  console.log('npm: fetching the download ranking');
  const ranked = parseNameArray(await getText(NPM_SOURCE));
  const npmNames = ranked.slice(0, NPM_TAKE);
  console.log(`npm: took the top ${npmNames.length} of ${ranked.length}; re-measuring a sample of ${NPM_SAMPLE}`);
  const sample = await verifySample(npmNames, NPM_SAMPLE);
  const weeklies = sample.measured.map((m) => m.weekly).sort((a, b) => a - b);

  write('popular-npm.json', {
    ecosystem: 'npm',
    generated: today,
    source: `${NPM_SOURCE} — the npm download ranking published by npm-high-impact (github.com/wooorm/npm-high-impact)`,
    selection: `the first ${npmNames.length} names of that ranking, in order, with nothing dropped`,
    ranking_length: ranked.length,
    // The sample exists so the selection above is a checkable claim rather than a citation.
    verification: {
      method: `${sample.picks} names spread evenly across the list, re-measured at api.npmjs.org/downloads/point/last-week on ${today}`,
      measured: sample.measured.length,
      unreachable: sample.failed.length,
      lowest_weekly_in_sample: weeklies.length ? weeklies[0] : null,
      median_weekly_in_sample: weeklies.length ? weeklies[Math.floor(weeklies.length / 2)] : null,
    },
    limits: 'A snapshot. A package that became popular after the date above is not here, so a squat aimed at it is not caught by the local name check, and the package itself may be reported as resembling something else.',
    names: npmNames,
  });

  console.log('pypi: fetching the download table');
  const pypi = await getJson(PYPI_SOURCE);
  const rows = (pypi.rows || []).slice(0, PYPI_TAKE);
  const seen = new Set();
  const pypiNames = [];
  for (const r of rows) {
    if (!r || !r.project) continue;
    const norm = String(r.project).replace(/[-_.]+/g, '-').toLowerCase();
    if (seen.has(norm)) continue;
    seen.add(norm);
    pypiNames.push(norm);
  }

  write('popular-pypi.json', {
    ecosystem: 'pypi',
    generated: today,
    source: `${PYPI_SOURCE} — built from PyPI's own download table (dataset last_update ${pypi.last_update || 'unknown'}, via ${pypi.source || 'unknown'})`,
    selection: `the first ${rows.length} projects of that table, in order, normalised to PEP 503 form and deduplicated`,
    ranking_length: (pypi.rows || []).length,
    verification: {
      method: 'none: pypi.org publishes no per-package downloads API to re-measure against, so the counts are the linked dataset\'s and are not independently checked here',
      lowest_downloads_in_selection: rows.length ? rows[rows.length - 1].download_count : null,
    },
    limits: 'A snapshot. A project that became popular after the date above is not here, so a squat aimed at it is not caught by the local name check, and the project itself may be reported as resembling something else.',
    names: pypiNames,
  });
}

main().catch((e) => { console.error(e); process.exit(1); });
