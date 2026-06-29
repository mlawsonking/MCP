// screen-address — the pre-send guard for AI agents that move money.
// GET /api/screen-address?address=0x...&chain=eth|base|polygon|arbitrum|optimism
// Checks: OFAC-sanctioned? on a scam/abuse blocklist? on-chain risk (brand-new/unused, contract) → verdict.
const { sendJson, handleOptions } = require('../lib/common.js');
const { CHAINS, isEvmAddress, ofacSanctionedSet, scamList, onchain } = require('../lib/risk.js');
const { ensResolve, looksLikeEns } = require('../lib/ens.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
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
  const [ofac, scam] = await Promise.all([ofacSanctionedSet(), scamList()]);
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
  if (sanctioned === null && !scamNote) reasons.push('Note: sanctions/scam list temporarily unavailable; verdict is based on on-chain signals only.');
  if (verdict === 'safe') reasons.push(`Not sanctioned, not on scam lists${onc ? ', and has on-chain history' : ''}.`);

  return sendJson(res, 200, {
    ok: true, address, resolved_from, chain, verdict,
    sanctioned, scam: scamNote ? { listed: true, note: scamNote } : { listed: false },
    onchain: onc || undefined, flags, reasons, ms: Date.now() - started,
  });
};
