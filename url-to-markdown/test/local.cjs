// Local end-to-end test of the handler (does real fetches). Run: node test/local.cjs
const handler = require('../api/read.js');

function mockRes() {
  return { statusCode: 200, headers: {}, body: '', setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b || ''; } };
}
async function call(url, format) {
  const res = mockRes();
  await handler({ method: 'GET', query: { url, format } }, res);
  return res;
}

(async () => {
  const cases = [
    ['https://example.com', 'json', 200],
    ['https://en.wikipedia.org/wiki/Model_Context_Protocol', 'json', 200],
    ['ftp://example.com', 'json', 400],
    ['http://127.0.0.1/', 'json', 400],
    ['not a url', 'json', 400],
  ];
  let pass = 0, fail = 0;
  for (const [url, fmt, want] of cases) {
    try {
      const res = await call(url, fmt);
      const ok = res.statusCode === want;
      ok ? pass++ : fail++;
      let p; try { p = JSON.parse(res.body); } catch { p = res.body; }
      console.log(`${ok ? 'PASS' : 'FAIL'}  [${res.statusCode} want ${want}]  ${url}`);
      if (p && p.ok) console.log(`      “${p.title}” — ${p.words} words, ${p.ms}ms :: ${(p.markdown || '').slice(0, 120).replace(/\s+/g, ' ')}`);
      else console.log(`      ${typeof p === 'string' ? p.slice(0, 120) : (p && p.error) || ''}`);
    } catch (e) { fail++; console.log('FAIL (threw)', url, e.message); }
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
