// Local end-to-end test (real fetches). Run: node test/local.cjs
const handler = require('../api/meta.js');
function mockRes() { return { statusCode: 200, headers: {}, body: '', setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b || ''; } }; }
async function call(url) { const res = mockRes(); await handler({ method: 'GET', query: { url } }, res); return res; }

(async () => {
  const cases = [
    ['https://github.com', 200],
    ['https://en.wikipedia.org/wiki/Model_Context_Protocol', 200],
    ['http://127.0.0.1/', 400],
    ['ftp://example.com', 400],
    ['nope', 400],
  ];
  let pass = 0, fail = 0;
  for (const [url, want] of cases) {
    try {
      const res = await call(url);
      const ok = res.statusCode === want; ok ? pass++ : fail++;
      const p = JSON.parse(res.body);
      console.log(`${ok ? 'PASS' : 'FAIL'} [${res.statusCode} want ${want}] ${url}`);
      if (p.ok) console.log(`     title="${p.title}" | site="${p.siteName || ''}" | img=${p.image ? 'y' : 'n'} | favicon=${p.favicon ? 'y' : 'n'} | ${p.ms}ms`);
      else console.log(`     ${p.error}`);
    } catch (e) { fail++; console.log('FAIL (threw)', url, e.message); }
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
