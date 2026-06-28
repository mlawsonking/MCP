// Quick test for the consolidated read + meta endpoints. Run: node test/local-read.cjs
const read = require('../api/read.js');
const meta = require('../api/meta.js');
function mockRes() { return { statusCode: 200, body: '', setHeader() {}, end(b) { this.body = b || ''; } }; }
async function call(h, query) { const res = mockRes(); await h({ method: 'GET', query }, res); return res; }

(async () => {
  let pass = 0, fail = 0;
  let r = await call(read, { url: 'https://en.wikipedia.org/wiki/Model_Context_Protocol' });
  let j = JSON.parse(r.body);
  (j.ok && j.words > 100) ? pass++ : fail++;
  console.log(`read: ${r.statusCode} ok=${j.ok} "${j.title}" ${j.words} words`);
  r = await call(meta, { url: 'https://github.com' });
  j = JSON.parse(r.body);
  (j.ok && j.title && j.image) ? pass++ : fail++;
  console.log(`meta: ${r.statusCode} ok=${j.ok} "${j.title}" site=${j.siteName} img=${!!j.image}`);
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
