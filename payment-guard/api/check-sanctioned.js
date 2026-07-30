// check-sanctioned — fast OFAC sanctions primitive: is this address (or ENS name) sanctioned? No on-chain.
// GET /api/check-sanctioned?address=0x...  (or ?address=name.eth)
const { sendJson, handleOptions } = require('../lib/common.js');
const { isEvmAddress, ofacSanctions, ofacCoverage } = require('../lib/risk.js');
const { ensResolve, looksLikeEns } = require('../lib/ens.js');
const { requirePayment } = require('../lib/x402.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  if (await requirePayment(req, res, { resource: '/api/check-sanctioned' })) return;
  const started = Date.now();
  const input = String((req.query && (req.query.address || req.query.addr)) || '').trim();
  let address = input, resolved_from;
  if (!isEvmAddress(address)) {
    if (looksLikeEns(input)) { const r = await ensResolve(input); if (r) { address = r; resolved_from = input; } else return sendJson(res, 400, { ok: false, error: `"${input}" did not resolve via the mainnet ENS registry (namehash -> resolver -> addr()). Offchain and L2 names (Basenames, .cb.id, gasless subnames) are not supported here, so a wallet may still resolve it. Pass the address directly to screen it.` }); }
    else return sendJson(res, 400, { ok: false, error: 'Provide an EVM address (0x + 40 hex) or ENS name' });
  }
  const { set: ofac, lists } = await ofacSanctions();
  const sanctioned = ofac ? ofac.has(address.toLowerCase()) : null;
  return sendJson(res, 200, {
    ok: true, address, resolved_from, sanctioned,
    source: 'OFAC SDN (sanctioned digital-currency addresses)', list_size: ofac ? ofac.size : undefined,
    verdict: sanctioned ? 'block' : sanctioned === false ? 'clear' : 'unknown',
    note: sanctioned
      ? 'On the OFAC sanctions list — transacting may be illegal.'
      : sanctioned === false
        ? 'Not on the OFAC EVM sanctioned-address lists. See coverage for what that does and does not cover.'
        : 'OFAC list temporarily unavailable.',
    coverage: ofacCoverage(lists),
    ms: Date.now() - started,
  });
};
