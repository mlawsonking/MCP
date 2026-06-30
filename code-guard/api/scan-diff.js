// scan-diff — scan only the ADDED lines of a unified diff (the agent's just-written change), with the
// correct new-file line numbers. Use in a coding agent's commit loop. Deterministic, no LLM.
// POST { "diff": "<unified diff>", "language": "python|javascript|..." }
const { sendJson, handleOptions } = require('../lib/common.js');
const { scanDiff } = require('../lib/codescan.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const body = req.body || {};
  const diff = body.diff || (req.query && req.query.diff) || '';
  const lang = body.language || body.lang || (req.query && (req.query.language || req.query.lang)) || '';
  if (!diff || !String(diff).trim()) return sendJson(res, 400, { ok: false, error: 'Provide a unified diff: POST {"diff":"@@ ... +newcode"}.' });
  const r = scanDiff(diff, lang);
  const advice = r.verdict === 'block'
    ? 'Do NOT commit this change as-is — it introduces critical/high issues.'
    : r.verdict === 'review' ? 'Review the flagged added lines before committing.' : 'No high-signal issues in the added lines (first-line scan).';
  return sendJson(res, 200, { ok: true, ...r, advice, ms: Date.now() - started });
};
