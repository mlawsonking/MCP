// resolve-name — ENS name -> address, and a fast sanctions/scam screen of the result.
// GET /api/resolve-name?name=vitalik.eth
const { sendJson, handleOptions, track } = require('../lib/common.js');
const { ensResolve, looksLikeEns } = require('../lib/ens.js');
const { ofacSanctions, ofacCoverage, scamList } = require('../lib/risk.js');
const { requirePayment } = require('../lib/x402.js');

// What ENS resolution here actually is, attached to every response so the caller does not have to
// infer it: mainnet registry, one addr() call, and no name-shape analysis of any kind.
const ENS_COVERAGE = {
  method: 'namehash -> ENS registry resolver(node) -> addr(bytes32) on Ethereum mainnet',
  screens: 'the resolved address, against the OFAC EVM sanctions lists and the scam/abuse blocklists',
  homoglyph_detection: false,
  ensip15_normalization: false,
  offchain_resolution: false,
  note: 'Lookalike and homoglyph names are not detected. Offchain and L2 names (Basenames, .cb.id, gasless subnames) need ENSIP-10/CCIP-Read, which is not implemented, so they report resolved:false here even though a wallet resolves them.',
};

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  if (await requirePayment(req, res, { resource: '/api/resolve-name' })) return;
  const started = Date.now();
  const name = String((req.query && (req.query.name || req.query.ens)) || '').trim();
  if (!looksLikeEns(name)) return sendJson(res, 400, { ok: false, error: 'Provide an ENS name (e.g. name.eth)' });
  track(req, 'guard_call', { product: 'payment-guard', endpoint: 'resolve-name' });

  const address = await ensResolve(name);
  if (!address) return sendJson(res, 200, { ok: true, name, resolved: false, address: null, verdict: 'caution', note: 'Did not resolve via the mainnet ENS registry (namehash -> resolver -> addr()). Offchain and L2 names (Basenames, .cb.id, gasless subnames) are not supported here, so a wallet may still resolve this name. There is no address to screen, so nothing was checked.', ens_coverage: ENS_COVERAGE, ms: Date.now() - started });

  const [ofacRes, scam] = await Promise.all([ofacSanctions(), scamList()]);
  const ofac = ofacRes.set;
  const sanctioned = ofac ? ofac.has(address.toLowerCase()) : null;
  const scamNote = scam ? scam.get(address.toLowerCase()) : undefined;
  const flagged = !!sanctioned || !!scamNote;
  // A sanctions list we could not load is an unanswered question, not a clean result.
  const unscreened = sanctioned === null;
  return sendJson(res, 200, {
    ok: true, name, resolved: true, address, sanctioned, scam: scamNote ? { listed: true, note: scamNote } : { listed: false },
    verdict: flagged ? 'block' : unscreened ? 'caution' : 'safe',
    note: flagged
      ? 'Resolved address is sanctioned/scam — do NOT pay.'
      : unscreened
        ? 'Resolved, but the OFAC sanctions list could not be loaded, so the address was NOT screened against it. Treat as unscreened, not clean.'
        : 'Resolved cleanly, and the resolved address is not on the lists. The name itself was not checked for lookalike characters. For full risk (on-chain freshness, etc.) call /api/screen-address with this address.',
    sanctions_coverage: ofacCoverage(ofacRes.lists),
    ens_coverage: ENS_COVERAGE,
    ms: Date.now() - started,
  });
};
