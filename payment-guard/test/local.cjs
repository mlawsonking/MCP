// Live end-to-end tests for Payment Guard (real OFAC + scam lists + public RPC + ENS). Run: node test/local.cjs
const screenAddress = require('../api/screen-address.js');
const screenPayment = require('../api/screen-payment.js');
const checkSanctioned = require('../api/check-sanctioned.js');
const resolveName = require('../api/resolve-name.js');
const { ofacSanctions, ofacSanctionedSet, scamList, OFAC_EVM_LISTS } = require('../lib/risk.js');

function mockRes() { return { statusCode: 200, body: '', setHeader() {}, end(b) { this.body = b || ''; } }; }
async function call(h, query) { const res = mockRes(); await h({ method: 'GET', query }, res); return { code: res.statusCode, json: JSON.parse(res.body) }; }
let pass = 0, fail = 0;
const ck = (n, c, info) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${info ? '  :: ' + info : ''}`); };
const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const OFAC_BASE = 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_';

// Addresses on the OFAC SDN list that do NOT appear in the ETH list. Before the multi-list fix these
// four came back verdict:"clear" / "Not on the OFAC sanctioned-address list." from production.
const OFAC_FIXTURES = [
  '0x175d44451403edf28469df03a9280c1197adb92c',
  '0x38735f03b30fbc022ddd06abed01f0ca823c6a94',
  '0xfac583c0cf07ea434052c49115a4682172ab6b4f',
  '0xfec8a60023265364d066a1212fde3930f6ae8da7',
];

async function fetchList(name) {
  const r = await fetch(`${OFAC_BASE}${name}.txt`);
  if (!r.ok) return null;
  return (await r.text()).split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter((l) => /^0x[0-9a-f]{40}$/.test(l));
}

(async () => {
  // ---- Degraded-mode test FIRST, while the module cache is still cold. ----
  // The failure we fear: the sanctions list fails to load and we tell the caller the address is safe.
  const realFetch = globalThis.fetch;
  globalThis.fetch = (url, opts) =>
    String(url).includes('ofac-sanctioned') ? Promise.reject(new Error('simulated OFAC outage')) : realFetch(url, opts);
  let r = await call(screenAddress, { address: VITALIK, chain: 'eth' });
  ck('screen-address: OFAC list unavailable → never "safe"',
    r.json.verdict !== 'safe' && r.json.sanctioned === null && (r.json.flags || []).includes('sanctions-check-unavailable'),
    `verdict=${r.json.verdict} sanctioned=${r.json.sanctioned}`);
  ck('screen-address: outage never claims the address is unsanctioned',
    !(r.json.reasons || []).some((x) => /not on the ofac/i.test(x)),
    `reasons=${JSON.stringify(r.json.reasons)}`);
  globalThis.fetch = realFetch;

  const { set: ofac, lists: loaded } = await ofacSanctions();
  const scam = await scamList();
  console.log(`(loaded ${ofac ? ofac.size : '?'} OFAC across [${(loaded || []).join(',')}] + ${scam ? scam.size : '?'} scam addresses)\n`);

  // ---- Coverage regression: we must ingest every EVM-format OFAC list, not just ETH. ----
  ck('ofac: every EVM list ingested', OFAC_EVM_LISTS.every((n) => (loaded || []).includes(n)),
    `loaded=${(loaded || []).join(',')} expected=${OFAC_EVM_LISTS.join(',')}`);

  const perList = {};
  for (const n of OFAC_EVM_LISTS) perList[n] = await fetchList(n);
  const expected = new Set(Object.values(perList).filter(Boolean).flat());
  ck('ofac: loaded set equals the union of all EVM lists',
    ofac && ofac.size === expected.size && [...expected].every((a) => ofac.has(a)),
    `ours=${ofac ? ofac.size : '?'} expected=${expected.size}`);

  const ethOnly = new Set(perList.ETH || []);
  const beyondEth = [...expected].filter((a) => !ethOnly.has(a));
  ck('ofac: covers addresses the ETH list alone would miss', beyondEth.length > 0,
    `${beyondEth.length} beyond ETH (if this hits 0, OFAC delisted them — update OFAC_FIXTURES deliberately)`);

  const liveFixtures = OFAC_FIXTURES.filter((a) => expected.has(a));
  ck('ofac: known non-ETH fixtures still listed upstream', liveFixtures.length > 0,
    `${liveFixtures.length}/${OFAC_FIXTURES.length} still on the SDN list`);
  for (const addr of liveFixtures) {
    const f = await call(checkSanctioned, { address: addr });
    ck(`check-sanctioned: non-ETH-list address ${addr.slice(0, 10)} → block`,
      f.json.sanctioned === true && f.json.verdict === 'block', `verdict=${f.json.verdict}`);
  }

  // ---- Coverage must be stated in the response, not just the docs. ----
  const cov = await call(checkSanctioned, { address: VITALIK });
  ck('check-sanctioned: states its coverage',
    !!cov.json.coverage && cov.json.coverage.address_format === 'evm' &&
    Array.isArray(cov.json.coverage.not_checked) && cov.json.coverage.not_checked.includes('BTC'),
    `coverage=${cov.json.coverage ? 'present' : 'MISSING'}`);
  const covScreen = await call(screenAddress, { address: VITALIK, chain: 'base' });
  ck('screen-address: states its sanctions coverage', !!covScreen.json.sanctions_coverage,
    `coverage=${covScreen.json.sanctions_coverage ? 'present' : 'MISSING'}`);

  // screen-address: real sanctioned address → block
  const sanc = ofac && ofac.size ? [...ofac][0] : null;
  r = await call(screenAddress, { address: sanc, chain: 'eth' });
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
