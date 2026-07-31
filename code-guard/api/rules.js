// rules — the deterministic rule catalog Code Guard checks (transparency + so agents/users know coverage).
const { sendJson, handleOptions, track } = require('../lib/common.js');
const { listRules, CODE_RULES_VERSION, CODE_RULESET_INFO } = require('../lib/codescan.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const rules = listRules();
  const byCategory = {};
  rules.forEach((r) => { (byCategory[r.category] = byCategory[r.category] || []).push(r.id); });
  track(req, 'guard_call', { product: 'code-guard', endpoint: 'rules' });
  return sendJson(res, 200, {
    ok: true, total: rules.length, categories: Object.keys(byCategory).sort(), rules,
    rules_version: CODE_RULES_VERSION,
    // total counts catalog entries; code_rules counts the actual patterns. hardcoded-* is one entry
    // standing in for 25 patterns in the shared ruleset: 22 credential, 3 personal-data (email, SSN, card).
    code_rules: CODE_RULESET_INFO.rules,
    note: 'These are regex rules, not a compiler. A clean result means none of them matched, not that the code is safe.',
  });
};
