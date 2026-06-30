// rules — the deterministic rule catalog Code Guard checks (transparency + so agents/users know coverage).
const { sendJson, handleOptions } = require('../lib/common.js');
const { listRules } = require('../lib/codescan.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const rules = listRules();
  const byCategory = {};
  rules.forEach((r) => { (byCategory[r.category] = byCategory[r.category] || []).push(r.id); });
  return sendJson(res, 200, { ok: true, total: rules.length, categories: Object.keys(byCategory).sort(), rules });
};
