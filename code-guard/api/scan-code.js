// scan-code — security-scan a code snippet the agent just wrote, BEFORE it commits/runs it.
// Detects the high-frequency vuln classes in AI-generated code (injection, SSRF, hardcoded secrets, weak crypto,
// unsafe deserialization, TLS-off, XSS) → findings (rule, severity, line, fix) + verdict. Deterministic, no LLM.
// POST { "code": "...", "language": "python|javascript|..." }  (language optional — auto-detected)
const { sendJson, handleOptions } = require('../lib/common.js');
const { scanCode } = require('../lib/codescan.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const body = req.body || {};
  const code = body.code || (req.query && req.query.code) || '';
  const lang = body.language || body.lang || (req.query && (req.query.language || req.query.lang)) || '';
  if (!code || !String(code).trim()) return sendJson(res, 400, { ok: false, error: 'Provide code: POST {"code":"...","language":"python"} (language optional).' });
  const r = scanCode(code, lang);
  const advice = r.verdict === 'block'
    ? 'Do NOT commit/run as-is — fix the critical/high findings first.'
    : r.verdict === 'review' ? 'Review the findings before committing.' : 'No high-signal issues found (fast first-line scan — not a full audit).';
  return sendJson(res, 200, { ok: true, ...r, advice, ms: Date.now() - started });
};
