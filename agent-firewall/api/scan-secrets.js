// scan-secrets — detect leaked API keys/tokens/private-keys + PII in text, and return a redacted copy.
// POST { "text": "..." }  |  GET ?text=...
const { sendJson, handleOptions } = require('../lib/common.js');
const { scanSecrets } = require('../lib/safety.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const body = req.body || {};
  const text = body.text || (req.query && req.query.text) || '';
  if (!text) return sendJson(res, 400, { ok: false, error: 'Provide text (POST {text} or ?text=).' });
  const r = scanSecrets(text);
  return sendJson(res, 200, { ok: true, length: String(text).length, ...r, ms: Date.now() - started });
};
