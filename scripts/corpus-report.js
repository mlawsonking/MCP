#!/usr/bin/env node
// Run every corpus case and report the measured rate per category.
//
// This is the answer to "how good is it?" that does not require trusting anyone. Each case declares
// what this engine does TODAY — catch, miss, or stay quiet — and this prints the tally. A case whose
// behaviour changed is a regression and exits non-zero, which is what makes it a CI gate rather than
// a brochure.
//
//   node scripts/corpus-report.js            human-readable table
//   node scripts/corpus-report.js --json     machine-readable, for the Action
//   node scripts/corpus-report.js --markdown the block pasted into CORPUS.md
'use strict';

const path = require('path');

const CORE = path.join(__dirname, '..', 'agent-guards');
const { CASES } = require(path.join(CORE, 'corpus', 'index.js'));
const injection = require(path.join(CORE, 'engines', 'injection.js'));
const secrets = require(path.join(CORE, 'engines', 'secrets.js'));
const shellcmd = require(path.join(CORE, 'engines', 'shellcmd.js'));
const email = require(path.join(CORE, 'engines', 'email.js'));
const pkgname = require(path.join(CORE, 'engines', 'pkgname.js'));

// Did the engine say something about this input? Not "is it safe" — whether a rule fired at all.
function detected(testCase) {
  switch (testCase.engine) {
    case 'injection':
      return injection.scan(testCase.input).findings.length > 0;
    case 'email': {
      const parsed = email.parseEmail(testCase.input);
      return injection.scan(parsed.combined).findings.length > 0;
    }
    case 'shell':
      return shellcmd.parse(testCase.input).risky.length > 0;
    case 'secrets':
      return secrets.scan(testCase.input).findings.length > 0;
    case 'pkgname': {
      const r = pkgname.inspect(testCase.input, testCase.ecosystem || 'npm');
      return (r.findings || []).length > 0;
    }
    default:
      throw new Error(`unknown engine: ${testCase.engine}`);
  }
}

const results = CASES.map((c) => {
  let fired = false;
  let error = null;
  try { fired = detected(c); } catch (err) { error = err.message; }
  const wanted = c.expect === 'catch' ? true : false;
  const regressed = error !== null || fired !== wanted;
  return { ...c, fired, error, regressed };
});

const categories = [...new Set(CASES.map((c) => c.category))];
const summary = categories.map((cat) => {
  const inCat = results.filter((r) => r.category === cat);
  const attacks = inCat.filter((r) => r.expect === 'catch' || r.expect === 'miss');
  const caught = attacks.filter((r) => r.expect === 'catch').length;
  const quiet = inCat.filter((r) => r.expect === 'quiet');
  const falsePositives = quiet.filter((r) => r.fired).length;
  return {
    category: cat,
    attacks: attacks.length,
    caught,
    missed: attacks.length - caught,
    rate: attacks.length ? Math.round((caught / attacks.length) * 100) : null,
    benign: quiet.length,
    falsePositives,
  };
});

const regressions = results.filter((r) => r.regressed);
const totalAttacks = summary.reduce((a, s) => a + s.attacks, 0);
const totalCaught = summary.reduce((a, s) => a + s.caught, 0);
const totalBenign = summary.reduce((a, s) => a + s.benign, 0);
const totalFp = summary.reduce((a, s) => a + s.falsePositives, 0);

if (process.argv.includes('--json')) {
  process.stdout.write(JSON.stringify({
    cases: CASES.length, totalAttacks, totalCaught, totalBenign, totalFp,
    overallRate: totalAttacks ? Math.round((totalCaught / totalAttacks) * 100) : null,
    categories: summary,
    regressions: regressions.map((r) => ({ id: r.id, expect: r.expect, fired: r.fired, error: r.error })),
  }, null, 2) + '\n');
  process.exit(regressions.length ? 1 : 0);
}

const rows = summary.map((s) => `| ${s.category} | ${s.caught}/${s.attacks} | ${s.rate}% | ${s.falsePositives}/${s.benign} |`);
const table = [
  '| category | caught | rate | false positives |',
  '| --- | --- | --- | --- |',
  ...rows,
  `| **all** | **${totalCaught}/${totalAttacks}** | **${Math.round((totalCaught / totalAttacks) * 100)}%** | **${totalFp}/${totalBenign}** |`,
].join('\n');

if (process.argv.includes('--markdown')) {
  const misses = results.filter((r) => r.expect === 'miss');
  process.stdout.write(`${table}\n\n### What it does not catch\n\n${misses.map((m) => `- \`${m.id}\` (${m.category}): ${String(m.input).replace(/\s+/g, ' ').slice(0, 90)}`).join('\n')}\n`);
  process.exit(regressions.length ? 1 : 0);
}

console.log(`\nadversarial corpus: ${CASES.length} cases\n`);
console.log(table);
if (regressions.length) {
  console.log('\nREGRESSIONS (a case no longer behaves the way the corpus records):');
  for (const r of regressions) {
    console.log(`  ${r.id}: expected ${r.expect}, ${r.error ? `threw ${r.error}` : `engine ${r.fired ? 'fired' : 'was silent'}`}`);
  }
}
console.log(`\n${regressions.length ? `${regressions.length} regression(s)` : 'no regressions'}\n`);
process.exit(regressions.length ? 1 : 0);
