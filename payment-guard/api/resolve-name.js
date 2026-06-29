// resolve-name — ENS name -> address, and a fast sanctions/scam screen of the result.
// GET /api/resolve-name?name=vitalik.eth
const { sendJson, handleOptions } = require('../lib/common.js');
const { ensResolve, looksLikeEns } = require('../lib/ens.js');
const { ofacSanctionedSet, scamList } = require('../lib/risk.js');
const { requirePayment } = require('../lib/x402.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  if (await requirePayment(req, res, { resource: '/api/resolve-name' })) return;
  const started = Date.now();
  const name = String((req.query && (req.query.name || req.query.ens)) || '').trim();
  if (!looksLikeEns(name)) return sendJson(res, 400, { ok: false, error: 'Provide an ENS name (e.g. name.eth)' });

  const address = await ensResolve(name);
  if (!address) return sendJson(res, 200, { ok: true, name, resolved: false, address: null, verdict: 'caution', note: 'Name does not resolve to an address — do not pay a name that doesn\'t resolve.', ms: Date.now() - started });

  const [ofac, scam] = await Promise.all([ofacSanctionedSet(), scamList()]);
  const sanctioned = ofac ? ofac.has(address.toLowerCase()) : null;
  const scamNote = scam ? scam.get(address.toLowerCase()) : undefined;
  const flagged = !!sanctioned || !!scamNote;
  return sendJson(res, 200, {
    ok: true, name, resolved: true, address, sanctioned, scam: scamNote ? { listed: true, note: scamNote } : { listed: false },
    verdict: flagged ? 'block' : 'safe',
    note: flagged ? 'Resolved address is sanctioned/scam — do NOT pay.' : 'Resolved cleanly. For full risk (on-chain freshness, etc.) call /api/screen-address with this address.',
    ms: Date.now() - started,
  });
};
