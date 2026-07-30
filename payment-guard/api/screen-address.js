// screen-address — the pre-send guard for AI agents that move money.
// GET /api/screen-address?address=0x...&chain=eth|base|polygon|arbitrum|optimism
// Checks: OFAC-sanctioned? on a scam/abuse blocklist? on-chain risk (brand-new/unused, contract) → verdict.
const { sendJson, handleOptions, track, upgradeInfo } = require('../lib/common.js');
const { CHAINS, isEvmAddress, ofacSanctions, ofacCoverage, OFAC_EVM_LISTS, scamList, onchain } = require('../lib/risk.js');
const { ensResolve, looksLikeEns } = require('../lib/ens.js');
const { requirePayment } = require('../lib/x402.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  track(req, 'guard_call', { product: 'payment-guard', endpoint: 'screen-address' });
  if (await requirePayment(req, res, { resource: '/api/screen-address' })) return;
  const started = Date.now();
  const q = req.query || {};
  const input = String(q.address || q.addr || '').trim();
  const chain = String(q.chain || 'eth').toLowerCase();
  if (!CHAINS[chain]) return sendJson(res, 400, { ok: false, error: 'Unsupported chain. Use eth, base, polygon, arbitrum, or optimism.' });

  let address = input;
  let resolved_from;
  if (!isEvmAddress(address)) {
    if (looksLikeEns(input)) {
      const r = await ensResolve(input);
      if (!r) return sendJson(res, 200, { ok: true, input, resolved: false, verdict: 'caution', reasons: [`Could not resolve ENS name "${input}" to an address — do not pay a name that doesn't resolve.`], ms: Date.now() - started });
      address = r; resolved_from = input;
    } else {
      return sendJson(res, 400, { ok: false, error: 'Provide a valid EVM address (0x + 40 hex) or an ENS name (e.g. name.eth)' });
    }
  }

  const low = address.toLowerCase();
  const [ofacRes, scam] = await Promise.all([ofacSanctions(), scamList()]);
  const ofac = ofacRes.set;
  const sanctioned = ofac ? ofac.has(low) : null;
  const scamNote = scam ? scam.get(low) : undefined;

  let onc = null;
  try { onc = await onchain(chain, address); } catch {}

  const flags = [];
  const reasons = [];
  let verdict = 'safe';

  if (sanctioned) {
    verdict = 'block'; flags.push('ofac-sanctioned');
    reasons.push('Address is on the OFAC sanctions list — sending funds to it may be illegal. Do NOT pay.');
  }
  if (scamNote) {
    verdict = 'block'; flags.push('known-scam');
    reasons.push(`Address is on a known scam/abuse blocklist: ${String(scamNote).slice(0, 140)}.`);
  }
  if (verdict !== 'block' && onc) {
    if (!onc.isContract && onc.txCount === 0 && !onc.hasBalance) {
      verdict = 'caution'; flags.push('brand-new-unused');
      reasons.push('Brand-new / unused address (no outgoing transactions, no balance) — common for scam drop addresses. Verify the recipient out-of-band before sending.');
    } else if (onc.isContract) {
      flags.push('contract');
      reasons.push('Recipient is a smart contract — confirm it is the intended one (e.g., a known payment processor), not a lookalike.');
    }
  }
  // A check that did not run is an unanswered question, never a clean result. Each of these
  // downgrades 'safe' and names the check that was skipped.
  if (sanctioned === null) {
    if (verdict === 'safe') verdict = 'caution';
    flags.push('sanctions-check-unavailable');
    reasons.push('The OFAC sanctions list could not be loaded, so this address was NOT screened against it. Treat this as unscreened, not as clean.');
  } else if (ofacRes.lists.length < OFAC_EVM_LISTS.length) {
    // The union is built from whichever lists answered, so a partial load silently narrows coverage.
    const missing = OFAC_EVM_LISTS.filter((l) => !ofacRes.lists.includes(l));
    if (verdict === 'safe') verdict = 'caution';
    flags.push('sanctions-partial');
    reasons.push(`Only part of the OFAC data loaded. The ${missing.join(', ')} list(s) failed, so an address sanctioned only under those was not matched.`);
  }
  if (scam === null) {
    if (verdict === 'safe') verdict = 'caution';
    flags.push('scam-check-unavailable');
    reasons.push('The scam/abuse blocklists could not be loaded, so this address was NOT screened against them.');
  }
  if (verdict === 'safe') {
    const ran = ['not on the OFAC EVM sanctions lists', 'not on the scam lists'];
    if (onc && onc.txCount > 0) ran.push('has on-chain history');
    reasons.push(`${ran.join(', ')}.`.replace(/^n/, 'N'));
  }

  return sendJson(res, 200, {
    ok: true, address, resolved_from, chain, verdict,
    sanctioned, scam: scamNote ? { listed: true, note: scamNote } : { listed: scam === null ? null : false, checked: scam !== null },
    sanctions_coverage: ofacCoverage(ofacRes.lists),
    onchain: onc || undefined, flags, reasons, upgrade: upgradeInfo(req, 'payment-guard'), ms: Date.now() - started,
  });
};
