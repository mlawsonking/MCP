// Live end-to-end tests for Payment Guard (real OFAC + scam lists + public RPC + ENS). Run: node test/local.cjs
const screenAddress = require('../api/screen-address.js');
const screenPayment = require('../api/screen-payment.js');
const checkSanctioned = require('../api/check-sanctioned.js');
const resolveName = require('../api/resolve-name.js');
const { ofacSanctionedSet, scamList } = require('../lib/risk.js');

function mockRes() { return { statusCode: 200, body: '', setHeader() {}, end(b) { this.body = b || ''; } }; }
async function call(h, query) { const res = mockRes(); await h({ method: 'GET', query }, res); return { code: res.statusCode, json: JSON.parse(res.body) }; }
let pass = 0, fail = 0;
const ck = (n, c, info) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${info ? '  :: ' + info : ''}`); };
const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

(async () => {
  const ofac = await ofacSanctionedSet(); const scam = await scamList();
  console.log(`(loaded ${ofac ? ofac.size : '?'} OFAC + ${scam ? scam.size : '?'} scam addresses)\n`);

  // screen-address: real sanctioned address → block
  const sanc = ofac && ofac.size ? [...ofac][0] : null;
  let r = await call(screenAddress, { address: sanc, chain: 'eth' });
  ck('screen-address: OFAC address → block', r.json.verdict === 'block' && r.json.sanctioned === true, `flags=${r.json.flags}`);

  // screen-address: a real scam-listed address → block
  const scamAddr = scam && scam.size ? [...scam.keys()][0] : null;
  r = await call(screenAddress, { address: scamAddr, chain: 'eth' });
  ck('screen-address: scam address → block', r.json.verdict === 'block' && r.json.scam && r.json.scam.listed === true, `note=${r.json.scam && (r.json.scam.note || '').slice(0, 30)}`);

  // screen-address: ENS name → resolves + screens
  r = await call(screenAddress, { address: 'vitalik.eth', chain: 'eth' });
  ck('screen-address: ENS name resolves + screens', r.json.ok && r.json.resolved_from === 'vitalik.eth' && r.json.address.toLowerCase() === VITALIK.toLowerCase(), `verdict=${r.json.verdict} addr=${(r.json.address || '').slice(0, 12)}`);

  // resolve-name: ENS forward resolution
  r = await call(resolveName, { name: 'vitalik.eth' });
  ck('resolve-name: vitalik.eth', r.json.ok && r.json.resolved === true && r.json.address.toLowerCase() === VITALIK.toLowerCase(), `verdict=${r.json.verdict}`);

  // check-sanctioned: clean address → clear; sanctioned → block
  r = await call(checkSanctioned, { address: VITALIK });
  ck('check-sanctioned: clean → clear', r.json.ok && r.json.verdict === 'clear', `sanctioned=${r.json.sanctioned}`);
  r = await call(checkSanctioned, { address: sanc });
  ck('check-sanctioned: sanctioned → block', r.json.ok && r.json.verdict === 'block', `list_size=${r.json.list_size}`);

  // screen-payment: brand lookalike URL → caution/block
  r = await call(screenPayment, { url: 'http://coinbase.com.x402-pay.tk/checkout' });
  ck('screen-payment: lookalike → flagged', r.json.ok && (r.json.verdict === 'block' || r.json.verdict === 'caution'), `verdict=${r.json.verdict} flags=${(r.json.flags || []).map(f => f.id)}`);

  // screen-payment: normal https domain → safe-ish
  r = await call(screenPayment, { url: 'https://stripe.com' });
  ck('screen-payment: legit domain → safe', r.json.ok && r.json.verdict === 'safe', `verdict=${r.json.verdict} age=${r.json.domain_age_days}`);

  // invalid input → 400
  r = await call(screenAddress, { address: 'garbage', chain: 'eth' });
  ck('screen-address: garbage → 400', r.code === 400, r.json.error);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
