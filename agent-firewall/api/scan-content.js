// scan-content — detect prompt-injection / jailbreak / obfuscation in untrusted text (or a fetched URL).
// POST { "text": "..." }  |  GET ?text=...  |  GET/POST with ?url= (fetches then scans)
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');
const { scanInjection } = require('../lib/safety.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const body = req.body || {};
  let text = body.text || (req.query && req.query.text) || '';
  const url = body.url || (req.query && req.query.url);
  let source = 'text';
  if (!text && url) {
    const f = await safeFetch(String(url), {});
    if (!f.ok) return sendJson(res, 502, { ok: false, error: 'Failed to fetch url', detail: f.error });
    text = f.text || ''; source = 'url';
  }
  if (!text) return sendJson(res, 400, { ok: false, error: 'Provide text (POST {text} or ?text=) or a url to fetch.' });
  const r = scanInjection(text);
  return sendJson(res, 200, { ok: true, source, length: String(text).length, ...r, ms: Date.now() - started });
};
