// Local end-to-end tests for the Website Intelligence cluster (real network). Run: node test/local-intel.cjs
const dns = require('../api/dns.js');
const domain = require('../api/domain.js');
const ssl = require('../api/ssl.js');
const http = require('../api/http.js');
const structured = require('../api/structured.js');

function mockRes() { return { statusCode: 200, body: '', setHeader() {}, end(b) { this.body = b || ''; } }; }
async function call(h, query) { const res = mockRes(); await h({ method: 'GET', query }, res); return { code: res.statusCode, json: JSON.parse(res.body) }; }
let pass = 0, fail = 0;
const check = (n, c, info) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${info ? '  :: ' + info : ''}`); };

(async () => {
  let r = await call(dns, { domain: 'google.com' });
  check('dns google.com', r.json.ok && r.json.records.A && r.json.email_auth.has_mx && r.json.email_auth.spf, `A=${(r.json.records.A || []).length} mx=${r.json.email_auth.has_mx} spf=${r.json.email_auth.spf} dmarc=${r.json.email_auth.dmarc}`);

  r = await call(domain, { name: 'google.com' });
  check('domain RDAP google.com', r.json.ok && r.json.age_days > 1000, `age_days=${r.json.age_days} registrar="${r.json.registrar}" reg=${r.json.registration}`);

  r = await call(ssl, { host: 'google.com' });
  check('ssl google.com', r.json.ok && r.json.days_remaining > 0 && r.json.trusted, `issuer="${r.json.issuer}" days=${r.json.days_remaining} trusted=${r.json.trusted}`);

  r = await call(http, { url: 'github.com' });
  check('http github.com', r.json.ok && r.json.status === 200, `final=${r.json.final_url} status=${r.json.status} hsts=${r.json.security.hsts} redirects=${r.json.redirects}`);

  r = await call(structured, { url: 'https://github.com' });
  check('structured github.com', r.json.ok && (r.json.counts.opengraph > 0 || r.json.counts.jsonld > 0), `og=${r.json.counts.opengraph} jsonld=${r.json.counts.jsonld} types=[${r.json.schema_types}]`);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
