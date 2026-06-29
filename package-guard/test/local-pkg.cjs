// Local end-to-end tests for the Package Guard cluster (real OSV/npm/PyPI). Run: node test/local-pkg.cjs
const verify = require('../api/verify-package.js');
const vulns = require('../api/check-vulns.js');
const info = require('../api/package-info.js');
const typo = require('../api/typosquat-scan.js');
const audit = require('../api/audit-deps.js');

function mockRes() { return { statusCode: 200, body: '', setHeader() {}, end(b) { this.body = b || ''; } }; }
async function call(h, query, body) { const res = mockRes(); await h({ method: body ? 'POST' : 'GET', query: query || {}, body }, res); return { code: res.statusCode, json: JSON.parse(res.body) }; }
let pass = 0, fail = 0;
const ck = (n, c, info) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${info ? '  :: ' + info : ''}`); };

(async () => {
  let r = await call(verify, { name: 'react' });
  ck('verify react (real, safe-ish)', r.json.ok && r.json.exists === true && !!r.json.verdict, `verdict=${r.json.verdict} dl=${r.json.weekly_downloads}`);

  r = await call(verify, { name: 'reqeusts-fake-pkg-9z9z9z9z' });
  ck('verify hallucinated → danger', r.json.ok && r.json.exists === false && r.json.verdict === 'danger' && r.json.likely_hallucination === true, `suggestions=${(r.json.suggestions || []).length}`);

  r = await call(verify, { name: 'lodash', version: '4.17.11' });
  ck('verify lodash@4.17.11 has vulns', r.json.ok && r.json.vulnerabilities.count > 0, `vulns=${r.json.vulnerabilities.count} verdict=${r.json.verdict}`);

  r = await call(vulns, { name: 'lodash', version: '4.17.11' });
  ck('check-vulns lodash@4.17.11', r.json.ok && r.json.count > 0, `count=${r.json.count}`);

  r = await call(info, { name: 'express' });
  ck('package-info express', r.json.ok && r.json.exists === true && !!r.json.latest, `latest=${r.json.latest} license=${r.json.license}`);

  r = await call(typo, { name: 'lodash' });
  ck('typosquat-scan lodash', r.json.ok && typeof r.json.registered === 'number', `registered=${r.json.registered}/${r.json.variants_checked} suspicious=${r.json.suspicious}`);

  r = await call(audit, { packages: 'react,lodash,this-pkg-not-real-7q7q7q' });
  ck('audit-deps batch', r.json.ok && r.json.total === 3 && r.json.summary.missing >= 1, `danger=${r.json.summary.danger} missing=${r.json.summary.missing} vuln=${r.json.summary.vulnerable}`);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
