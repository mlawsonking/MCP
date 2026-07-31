// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/code.js
// Regenerate: node scripts/sync-shared.js
// Code Guard tools. All three are fully local — no network in any detection path here.

const code = require('../engines/code');
const secrets = require('../engines/secrets');

module.exports = [
  {
    name: 'scan_code',
    product: 'code-guard',
    description:
      'Scan a code snippet for the vulnerability classes that show up most in generated code: injection, SSRF, ' +
      'hardcoded secrets, weak crypto, unsafe deserialization, disabled TLS, XSS. Regex rules matched line by line — ' +
      'no parser, no data flow, no taint tracking. JS/TS and Python only. Fully local.',
    needs: [],
    input: {
      code: { type: 'string', description: 'The source to scan.' },
      language: { type: 'string', optional: true, description: 'python, javascript, typescript. Auto-detected if omitted.' },
    },
    async run(args) {
      const t0 = Date.now();
      const src = String(args.code || '');
      if (!src.trim()) return { ok: false, error: 'Provide code: {"code":"...","language":"python"} (language optional).' };
      const r = code.scanCode(src, args.language || args.lang || '');
      const advice = r.verdict === 'block'
        ? 'Do NOT commit/run as-is — fix the critical/high findings first.'
        : r.verdict === 'review' ? 'Review the findings before committing.' : 'No high-signal issues found (fast first-line scan — not a full audit).';
      return { ok: true, ...r, advice, ms: Date.now() - t0 };
    },
  },

  {
    name: 'scan_diff',
    product: 'code-guard',
    description:
      'Scan only the added lines of a unified diff, reporting findings against the new file line numbers. ' +
      'Use this on a patch before committing so untouched code does not drown the result. Fully local.',
    needs: [],
    input: {
      diff: { type: 'string', description: 'A unified diff.' },
      language: { type: 'string', optional: true, description: 'python, javascript, typescript. Auto-detected if omitted.' },
    },
    async run(args) {
      const t0 = Date.now();
      const d = String(args.diff || '');
      if (!d.trim()) return { ok: false, error: 'Provide diff: {"diff":"<unified diff>"}' };
      const r = code.scanDiff(d, args.language || args.lang || '');
      const advice = r.verdict === 'block'
        ? 'Do NOT commit/run as-is — fix the critical/high findings first.'
        : r.verdict === 'review' ? 'Review the findings before committing.' : 'No high-signal issues found (fast first-line scan — not a full audit).';
      return { ok: true, ...r, advice, ms: Date.now() - t0 };
    },
  },

  {
    name: 'list_rules',
    product: 'code-guard',
    description:
      'List the rule catalog so you can see the coverage and the gaps: rule id, category, severity, language. ' +
      'The grouped hardcoded-* entry stands in for the secret and PII ruleset. Fully local.',
    needs: [],
    input: {},
    async run() {
      const rules = code.listRules();
      const byCategory = {};
      rules.forEach((r) => { (byCategory[r.category] = byCategory[r.category] || []).push(r.id); });
      return {
        ok: true,
        total: rules.length,
        categories: Object.keys(byCategory).sort(),
        rules,
        rules_version: code.CODE_RULES_VERSION,
        // total counts catalog entries; code_rules counts the actual patterns. The grouped
        // hardcoded-* entry stands in for the secret ruleset, whose size is read from the engine
        // rather than written down here, so it cannot go stale.
        code_rules: code.CODE_RULESET_INFO.rules,
        secret_patterns: secrets.INFO.secrets.rules,
        pii_patterns: secrets.INFO.pii.rules,
        note: 'These are regex rules, not a compiler. A clean result means none of them matched, not that the code is safe.',
      };
    },
  },
];
