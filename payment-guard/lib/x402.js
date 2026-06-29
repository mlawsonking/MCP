// x402 payment gate — DORMANT by default. Lets AI agents pay per call in USDC over HTTP 402.
// Activates ONLY when X402_ENABLED=1 AND X402_PAY_TO=<your Base wallet> are set as env vars.
// While disabled (the default on Vercel), requirePayment() is a guaranteed no-op → free API unchanged.
//
// Protocol (x402 v1): no `X-PAYMENT` header -> 402 with `accepts` requirements. Header present ->
// verify (and settle) via a facilitator -> proceed. Facilitator does the on-chain work (fee-free on Base).
// Reference: https://docs.cdp.coinbase.com/x402 · facilitator https://x402.org/facilitator

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // USDC on Base (6 decimals)

function priceToAtomic(price) {
  // "$0.001" -> "1000" (6-decimal USDC atomic units)
  const n = Number(String(price).replace(/[^0-9.]/g, '')) || 0;
  return String(Math.round(n * 1e6));
}

async function facilitator(path, body) {
  const base = process.env.X402_FACILITATOR_URL || 'https://x402.org/facilitator';
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ctrl.signal });
    return { ok: r.ok, json: await r.json().catch(() => null) };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  finally { clearTimeout(t); }
}

// Returns true if the request was handled here (payment required/invalid) → caller should `return`.
// Returns false if the request may proceed (gate disabled, or payment verified).
async function requirePayment(req, res, { price = process.env.X402_PRICE || '$0.001', resource = '/', network = 'base' } = {}) {
  if (process.env.X402_ENABLED !== '1' || !process.env.X402_PAY_TO) return false; // dormant → free
  const payTo = process.env.X402_PAY_TO;
  const requirements = {
    scheme: 'exact', network, maxAmountRequired: priceToAtomic(price),
    resource, description: 'Payment required for this endpoint', mimeType: 'application/json',
    payTo, maxTimeoutSeconds: 60, asset: USDC_BASE, extra: { name: 'USD Coin', version: '2' },
  };
  const send402 = (errMsg) => { res.statusCode = 402; res.setHeader('Content-Type', 'application/json'); res.setHeader('Access-Control-Allow-Origin', '*'); res.end(JSON.stringify({ x402Version: 1, error: errMsg, accepts: [requirements] })); };

  const header = req.headers && (req.headers['x-payment'] || req.headers['X-PAYMENT']);
  if (!header) { send402('X-PAYMENT header is required'); return true; }

  let payload;
  try { payload = JSON.parse(Buffer.from(String(header), 'base64').toString('utf8')); } catch { send402('Invalid X-PAYMENT header (expected base64 JSON)'); return true; }

  const v = await facilitator('/verify', { x402Version: 1, paymentPayload: payload, paymentRequirements: requirements });
  if (!v.ok || !v.json || v.json.isValid === false) { send402(`Payment verification failed${v.json && v.json.invalidReason ? `: ${v.json.invalidReason}` : ''}`); return true; }

  // Settle (best-effort) so funds actually move; expose the receipt header.
  const s = await facilitator('/settle', { x402Version: 1, paymentPayload: payload, paymentRequirements: requirements });
  if (s.ok && s.json) { try { res.setHeader('X-PAYMENT-RESPONSE', Buffer.from(JSON.stringify(s.json)).toString('base64')); } catch {} }
  return false; // paid → proceed to the handler
}

module.exports = { requirePayment };
