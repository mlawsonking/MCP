// Local end-to-end tests (real DNS + fetches). Run: node test/local.cjs
const email = require('../api/validate-email.js');
const extract = require('../api/extract.js');
const feed = require('../api/feed.js');

function mockRes() { return { statusCode: 200, headers: {}, body: '', setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b || ''; } }; }
async function call(handler, query) { const res = mockRes(); await handler({ method: 'GET', query }, res); return { code: res.statusCode, json: JSON.parse(res.body) }; }

let pass = 0, fail = 0;
function check(name, cond, info) { cond ? pass++ : fail++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${info ? '  :: ' + info : ''}`); }

(async () => {
  // validate-email
  let r = await call(email, { email: 'test@gmail.com' });
  check('email gmail deliverable+free', r.json.ok && r.json.deliverable && r.json.free_provider && r.json.has_mx, `mx=${r.json.has_mx} score=${r.json.score}`);
  r = await call(email, { email: 'foo@mailinator.com' });
  check('email disposable flagged', r.json.disposable === true, `deliverable=${r.json.deliverable}`);
  r = await call(email, { email: 'admin@gmail.com' });
  check('email role flagged', r.json.role_account === true, '');
  r = await call(email, { email: 'not-an-email' });
  check('email invalid syntax', r.json.valid_syntax === false && r.json.deliverable === false, '');

  // extract
  r = await call(extract, { url: 'https://example.com', selectors: JSON.stringify({ h1: 'h1', firstLink: 'a@href', paras: 'p[]' }) });
  check('extract example.com', r.json.ok && r.json.data.h1 === 'Example Domain' && /^https?:/.test(r.json.data.firstLink || ''), `h1="${r.json.data.h1}" link=${r.json.data.firstLink}`);

  // feed
  r = await call(feed, { url: 'https://news.ycombinator.com/rss', limit: '5' });
  check('feed HN parses items', r.json.ok && Array.isArray(r.json.items) && r.json.items.length > 0 && r.json.items[0].title, `count=${r.json.count} first="${(r.json.items[0] || {}).title}"`);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
