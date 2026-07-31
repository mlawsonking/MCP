// Minimal test harness, same shape as the per-product suites so the output reads the same
// everywhere. No dependencies: CI runs these on a clean runner with nothing installed.

let pass = 0;
let fail = 0;
const failures = [];

function ck(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? `  (${detail})` : ''}`);
  }
  return !!cond;
}

function section(title) {
  console.log(`\n${title}`);
}

function done(suite) {
  console.log(`\n${suite}: ${pass} passed, ${fail} failed`);
  if (fail) {
    console.log('failed: ' + failures.join(', '));
    process.exit(1);
  }
}

module.exports = { ck, section, done };
