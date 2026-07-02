// x402 payment gate — DORMANT until configured. Lets AI agents pay per call in USDC over HTTP 402.
// Config comes from payment-guard/x402.config.json (edit that file) OR env vars (X402_ENABLED/X402_PAY_TO).
// SAFETY: activates ONLY when enabled AND payTo is a valid EVM address (0x + 40 hex). A Bitcoin address
// (1.../3.../bc1...) or anything non-EVM is REFUSED → the gate stays off and the API stays free. So a
// wrong paste can never break or mis-bill the live endpoints.
//
// Protocol (x402 v1): no `X-PAYMENT` header -> 402 with `accepts` requirements. Header present -> verify
// (and settle) via a facilitator -> proceed. Facilitator does the on-chain work (fee-free on Base).
// Reference: https://docs.cdp.coinbase.com/x402 · facilitator https://x402.org/facilitator

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // USDC on Base (6 decimals)
const isEvm = (a) => /^0x[0-9a-fA-F]{40}$/.test(a || '');

let fileConfig = {};
try { fileConfig = require('../x402.config.json'); } catch {}

function config() {
  const enabled = fileConfig.enabled === true || process.env.X402_ENABLED === '1';
  const payTo = fileConfig.payTo || process.env.X402_PAY_TO || '';
  const price = fileConfig.price || process.env.X402_PRICE || '$0.001';
  const network = fileConfig.network || process.env.X402_NETWORK || 'base';
  return { enabled, payTo, price, network, validAddr: isEvm(payTo), active: enabled && isEvm(payTo) };
}

function priceToAtomic(price) {
  const n = Number(String(price).replace(/[^0-9.]/g, '')) || 0;
  return String(Math.round(n * 1e6)); // 6-decimal USDC atomic units
}

async function facilitator(path, body) {
  const base = process.env.X402_FACILITATOR_URL || fileConfig.facilitatorUrl || 'https://x402.org/facilitator';
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ctrl.signal });
    return { ok: r.ok, json: await r.json().catch(() => null) };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  finally { clearTimeout(t); }
}

// true = handled here (caller should `return`). false = proceed (gate off, invalid addr, or payment verified).
async function requirePayment(req, res, { resource = '/' } = {}) {
  const cfg = config();
  if (cfg.enabled && !cfg.validAddr) { try { console.error(`[x402] enabled but payTo is not a valid EVM address ("${cfg.payTo}") — gate stays OFF. Use a 0x… Base address.`); } catch {} }
  if (!cfg.active) return false; // dormant or misconfigured → free

  // RapidAPI bypass: RapidAPI is the payment layer for its proxied traffic — never double-charge it.
  const proxySecret = req.headers && req.headers['x-rapidapi-proxy-secret'];
  if (proxySecret) {
    const expected = process.env.RAPIDAPI_SECRET || fileConfig.rapidApiSecret;
    if (!expected || proxySecret === expected) return false; // RapidAPI handles billing → proceed free
  }

  const requirements = {
    scheme: 'exact', network: cfg.network, maxAmountRequired: priceToAtomic(cfg.price),
    resource, description: 'Payment required for this endpoint', mimeType: 'application/json',
    payTo: cfg.payTo, maxTimeoutSeconds: 60, asset: USDC_BASE, extra: { name: 'USD Coin', version: '2' },
  };
  const send402 = (errMsg) => { res.statusCode = 402; res.setHeader('Content-Type', 'application/json'); res.setHeader('Access-Control-Allow-Origin', '*'); res.end(JSON.stringify({ x402Version: 1, error: errMsg, accepts: [requirements] })); };

  const header = req.headers && (req.headers['x-payment'] || req.headers['X-PAYMENT']);
  if (!header) { send402('X-PAYMENT header is required'); return true; }

  let payload;
  try { payload = JSON.parse(Buffer.from(String(header), 'base64').toString('utf8')); } catch { send402('Invalid X-PAYMENT header (expected base64 JSON)'); return true; }

  const v = await facilitator('/verify', { x402Version: 1, paymentPayload: payload, paymentRequirements: requirements });
  if (!v.ok || !v.json || v.json.isValid === false) { send402(`Payment verification failed${v.json && v.json.invalidReason ? `: ${v.json.invalidReason}` : ''}`); return true; }

  const s = await facilitator('/settle', { x402Version: 1, paymentPayload: payload, paymentRequirements: requirements });
  if (s.ok && s.json) { try { res.setHeader('X-PAYMENT-RESPONSE', Buffer.from(JSON.stringify(s.json)).toString('base64')); } catch {} }
  return false; // paid → proceed to the handler
}

module.exports = { requirePayment, config };
