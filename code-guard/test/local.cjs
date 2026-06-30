// Local tests for Code Guard handlers (mock req/res). Run: node test/local.cjs
const scanCode = require('../api/scan-code.js');
const scanDiff = require('../api/scan-diff.js');
const rules = require('../api/rules.js');

let pass = 0, fail = 0;
const ok = (n, c, d) => { (c ? pass++ : fail++); console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${d ? '  :: ' + d : ''}`); };
const mockRes = () => ({ statusCode: 200, body: '', setHeader() {}, end(b) { this.body = b || ''; } });
async function call(h, body = {}, query = {}) { const res = mockRes(); await h({ method: 'POST', body, query, headers: {} }, res); return { code: res.statusCode, json: JSON.parse(res.body || '{}') }; }

const PY_VULN = [
  'import os, pickle, requests',
  'API_KEY = "sk-ant-abcdef1234567890abcdefghij1234567890"',
  'def run(cmd, data, url):',
  '    os.system("echo " + cmd)',
  '    obj = pickle.loads(data)',
  '    r = requests.get(url, verify=False)',
  '    return obj',
].join('\n');

const JS_VULN = [
  'const x = eval(userInput);',
  'el.innerHTML = data;',
  'const id = Math.random();',
  'db.query("SELECT * FROM users WHERE id = " + id);',
].join('\n');

const CLEAN = 'def add(a, b):\n    return a + b\n';

const DIFF = ['@@ -1,3 +1,4 @@', ' def f():', '-    return 1', '+    return eval(x)', '+    y = 2'].join('\n');

(async () => {
  let r = await call(scanCode, { code: PY_VULN, language: 'python' });
  ok('python vuln -> block', r.json.verdict === 'block', `verdict=${r.json.verdict} total=${r.json.total} cats=${r.json.categories}`);
  ok('python -> detects os.system', r.json.findings.some(f => f.id === 'py-os-system'), '');
  ok('python -> detects pickle', r.json.findings.some(f => f.id === 'py-pickle'), '');
  ok('python -> detects verify=False', r.json.findings.some(f => f.id === 'py-verify-false'), '');
  ok('python -> detects hardcoded secret', r.json.findings.some(f => f.category === 'hardcoded-secret'), r.json.findings.filter(f => f.category === 'hardcoded-secret').map(f => f.id).join(','));
  ok('python -> line numbers present', r.json.findings.every(f => f.line >= 1), '');

  r = await call(scanCode, { code: JS_VULN, language: 'javascript' });
  ok('js vuln -> block', r.json.verdict === 'block', `verdict=${r.json.verdict} cats=${r.json.categories}`);
  ok('js -> detects eval', r.json.findings.some(f => f.id === 'js-eval'), '');
  ok('js -> detects SQL concat', r.json.findings.some(f => f.id === 'sql-concat'), '');

  r = await call(scanCode, { code: CLEAN, language: 'python' });
  ok('clean code -> pass', r.json.verdict === 'pass', `verdict=${r.json.verdict} total=${r.json.total}`);

  r = await call(scanCode, {}, {});
  ok('no code -> 400', r.code === 400, `code=${r.code}`);

  r = await call(scanDiff, { diff: DIFF, language: 'python' });
  ok('diff added eval -> block', r.json.verdict === 'block', `verdict=${r.json.verdict} added=${r.json.addedLines}`);
  ok('diff -> eval on added line ~2', r.json.findings.some(f => f.id === 'py-eval-exec'), `line=${(r.json.findings.find(f => f.id === 'py-eval-exec') || {}).line}`);

  r = await call(rules, {}, {});
  ok('rules catalog -> returns rules', r.json.ok && r.json.total > 20, `total=${r.json.total} cats=${r.json.categories.length}`);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
