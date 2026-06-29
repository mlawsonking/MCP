// screen-token — is this token contract a honeypot / rug / high-tax / scam? Before an agent buys/approves.
// GET /api/screen-token?address=0x<token>&chain=eth|base|polygon|arbitrum|optimism
const { sendJson, handleOptions } = require('../lib/common.js');
const { isEvmAddress, CHAINS, scamList, honeypotCheck, onchain } = require('../lib/risk.js');
const { requirePayment } = require('../lib/x402.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  if (await requirePayment(req, res, { resource: '/api/screen-token' })) return;
  const started = Date.now();
  const q = req.query || {};
  const address = String(q.address || q.token || '').trim();
  const chain = String(q.chain || 'eth').toLowerCase();
  if (!isEvmAddress(address)) return sendJson(res, 400, { ok: false, error: 'Invalid token contract address (0x + 40 hex)' });
  if (!CHAINS[chain]) return sendJson(res, 400, { ok: false, error: 'Unsupported chain. Use eth, base, polygon, arbitrum, or optimism.' });

  const low = address.toLowerCase();
  const [scam, hp, onc] = await Promise.all([scamList(), honeypotCheck(chain, address), onchain(chain, address).catch(() => null)]);
  const scamNote = scam ? scam.get(low) : undefined;

  const flags = [], reasons = [];
  let verdict = 'safe';
  let token, taxes, honeypot;

  if (onc && !onc.isContract) { verdict = 'caution'; flags.push('not-a-contract'); reasons.push('Address is not a contract — not a token (or self-destructed). Verify you have the right token address.'); }
  if (scamNote) { verdict = 'block'; flags.push('scam-listed'); reasons.push(`On a scam/abuse blocklist: ${String(scamNote).slice(0, 120)}.`); }

  if (hp) {
    honeypot = !!(hp.honeypotResult && hp.honeypotResult.isHoneypot);
    const sim = hp.simulationResult || {};
    taxes = { buy: sim.buyTax, sell: sim.sellTax, transfer: sim.transferTax };
    token = hp.token ? { name: hp.token.name, symbol: hp.token.symbol } : undefined;
    if (honeypot) {
      verdict = 'block'; flags.push('honeypot');
      reasons.push(`HONEYPOT: simulation shows you cannot sell after buying${hp.honeypotResult.honeypotReason ? ` (${hp.honeypotResult.honeypotReason})` : ''}. Do NOT buy.`);
    } else {
      if (typeof sim.sellTax === 'number' && sim.sellTax >= 50) { verdict = 'block'; flags.push('extreme-sell-tax'); reasons.push(`Extreme sell tax (${sim.sellTax}%) — effectively un-sellable.`); }
      else if (typeof sim.sellTax === 'number' && sim.sellTax >= 10) { if (verdict === 'safe') verdict = 'caution'; flags.push('high-sell-tax'); reasons.push(`High sell tax (${sim.sellTax}%).`); }
      const risk = hp.summary && hp.summary.risk;
      if (risk === 'high' && verdict === 'safe') { verdict = 'caution'; flags.push('high-risk-summary'); }
      if (Array.isArray(hp.flags) && hp.flags.length) { for (const f of hp.flags.slice(0, 3)) reasons.push(`Flag: ${(f && (f.description || f.flag)) || f}`); if (verdict === 'safe') verdict = 'caution'; }
    }
  } else {
    reasons.push('Honeypot simulation unavailable for this chain/token — verdict based on scam-list + on-chain only.');
  }
  if (verdict === 'safe') reasons.push('Not a honeypot, not scam-listed, taxes normal.');

  return sendJson(res, 200, { ok: true, address, chain, verdict, token, honeypot, taxes, scam: scamNote ? { listed: true, note: scamNote } : { listed: false }, flags, reasons, ms: Date.now() - started });
};
