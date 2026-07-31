// Prompt-injection and obfuscation scanning. Fully local, no network, no model.
//
// What this catches: known instruction-override, jailbreak, prompt-leak, exfiltration and
// tool-poisoning phrasings, plus the Unicode tricks used to hide them from a human reviewer
// (zero-width characters, bidi overrides, the Unicode tag block, hidden CSS, HTML comments).
//
// What this does not catch: novel phrasings, paraphrase, and anything a determined attacker writes
// after reading these rules. It is a deterministic known-pattern scanner, not a classifier. Say that
// wherever the output is shown.

const { RULES_VERSION } = require('../lib/version');
const rulesets = require('../lib/rulesets');

// Each rule: weight contributes to a 0..100 risk score. Curated; defense-in-depth, not a guarantee.
const INJECTION_RULES = [
  { id: 'ignore-previous', cat: 'instruction-override', w: 35, re: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|above|earlier|preceding|the\s+system)\b[^.\n]{0,20}\b(instruction|prompt|message|rule|context|direction)/i },
  { id: 'new-instructions', cat: 'instruction-override', w: 25, re: /\b(here are|follow|obey)\b[^.\n]{0,30}\b(new|the\s+real|updated|true)\b[^.\n]{0,20}\binstruction/i },
  { id: 'role-override', cat: 'role-manipulation', w: 30, re: /\b(you\s+are\s+now|from\s+now\s+on|act\s+as|pretend\s+to\s+be|roleplay\s+as|behave\s+like)\b/i },
  { id: 'dan-jailbreak', cat: 'jailbreak', w: 40, re: /\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak|unfiltered|without\s+(any\s+)?restrictions|no\s+longer\s+bound)\b/i },
  { id: 'system-prompt-exfil', cat: 'prompt-leak', w: 35, re: /\b(reveal|show|print|repeat|output|tell\s+me|what\s+(is|are))\b[^.\n]{0,30}\b(your\s+)?(system\s+prompt|initial\s+instruction|the\s+above|your\s+(instruction|rule|directive|prompt))/i },
  { id: 'exfil-action', cat: 'data-exfiltration', w: 35, re: /\b(send|post|exfiltrate|upload|leak|transmit|forward)\b[^.\n]{0,40}(https?:\/\/|to\s+the\s+(following|url|server|endpoint)|api\s+key|credential|secret|token)/i },
  { id: 'tool-poison', cat: 'tool-poisoning', w: 30, re: /\b(call|invoke|use|run|execute)\b[^.\n]{0,30}\b(tool|function|command|shell|os\.system|subprocess|eval)\b/i },
  { id: 'secret-ask', cat: 'credential-phishing', w: 20, re: /\b(give|provide|share|reveal|what\s+is)\b[^.\n]{0,25}\b(api\s*key|password|secret|access\s*token|private\s*key|credential)/i },
  { id: 'imperative-override', cat: 'instruction-override', w: 12, re: /\b(do\s+not\s+(tell|inform|warn|mention)|without\s+(telling|informing|notifying)|do\s+not\s+(refuse|decline))\b/i },
  { id: 'fake-system-tag', cat: 'prompt-injection', w: 28, re: /(<\|?(system|im_start|im_end)\|?>|\[\/?(INST|SYS|SYSTEM)\]|###\s*(system|instruction)\s*:)/i },
  { id: 'urgency-coercion', cat: 'social-engineering', w: 8, re: /\b(this\s+is\s+(urgent|critical)|you\s+must\s+(immediately|now)|or\s+(you|the\s+user)\s+will\s+be)\b/i },
];

const ZERO_WIDTH = /[​-‍⁠﻿]/g;         // zero-width / joiners / BOM
const BIDI = /[‪-‮⁦-⁩]/g;              // bidi overrides (Trojan Source)
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;               // unicode "tag" block (invisible smuggling)
const HIDDEN_HTML = /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*#?(fff(fff)?|white)\b|opacity\s*:\s*0)/i;
const HTML_COMMENT_INSTR = /<!--[^>]*\b(ignore|instruction|system|assistant|you\s+are)\b/i;

// The five obfuscation signals scan() can emit, in the order it checks them. Listed here so the
// published rule count is derived from one place rather than counted by hand in a doc.
const OBFUSCATION_SIGNAL_IDS = ['zero-width-chars', 'bidi-override', 'unicode-tag-smuggling', 'hidden-html', 'html-comment-instruction'];

// The rules the feed has applied, or the ones compiled in above. The obfuscation signals below are
// not fed: they are Unicode properties rather than patterns, so there is nothing for a feed to
// update and pretending otherwise would overstate what an update changes.
function activeRules() { return rulesets.rules('injection') || INJECTION_RULES; }

function scan(text) {
  const t = String(text || '');
  const findings = [];
  let score = 0;
  for (const r of activeRules()) {
    const m = t.match(r.re);
    if (m) { score += r.w; findings.push({ id: r.id, category: r.cat, weight: r.w, match: m[0].slice(0, 120) }); }
  }

  const zw = (t.match(ZERO_WIDTH) || []).length;
  if (zw) { const w = Math.min(30, 10 + zw); score += w; findings.push({ id: 'zero-width-chars', category: 'obfuscation', weight: w, match: `${zw} hidden char(s)` }); }
  const bidi = (t.match(BIDI) || []).length;
  if (bidi) { score += 30; findings.push({ id: 'bidi-override', category: 'obfuscation', weight: 30, match: `${bidi} bidi control char(s)` }); }
  const tags = (t.match(TAG_CHARS) || []).length;
  if (tags) { score += 35; findings.push({ id: 'unicode-tag-smuggling', category: 'obfuscation', weight: 35, match: `${tags} invisible tag char(s)` }); }
  if (HIDDEN_HTML.test(t)) { score += 20; findings.push({ id: 'hidden-html', category: 'obfuscation', weight: 20, match: 'hidden-CSS content' }); }
  if (HTML_COMMENT_INSTR.test(t)) { score += 20; findings.push({ id: 'html-comment-instruction', category: 'obfuscation', weight: 20, match: 'instruction in HTML comment' }); }

  score = Math.min(100, score);
  const risk = score >= 60 ? 'critical' : score >= 35 ? 'high' : score >= 15 ? 'medium' : findings.length ? 'low' : 'none';
  const verdict = score >= 35 ? 'block' : score >= 15 ? 'review' : 'allow';
  return {
    risk,
    score,
    verdict,
    findings,
    categories: [...new Set(findings.map((f) => f.category))],
    rules_version: rulesets.version(RULES_VERSION),
    rules_provenance: rulesets.provenance(),
  };
}

// Strip the invisible characters so a caller can show a human what the text actually says. This is
// for display, not for making dangerous text safe.
function deobfuscate(text) {
  return String(text || '').replace(ZERO_WIDTH, '').replace(BIDI, '').replace(TAG_CHARS, '');
}

const INFO = {
  version: RULES_VERSION,
  rules: INJECTION_RULES.length,
  obfuscation_signals: OBFUSCATION_SIGNAL_IDS.length,
  ids: INJECTION_RULES.map((r) => r.id),
  limits: 'Deterministic known-pattern and Unicode-obfuscation matching. Not a classifier: novel phrasing and paraphrase are not covered.',
};

module.exports = { scan, deobfuscate, INJECTION_RULES, OBFUSCATION_SIGNAL_IDS, INFO, RULES_VERSION };
