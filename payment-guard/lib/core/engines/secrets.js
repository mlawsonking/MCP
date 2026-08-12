// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/engines/secrets.js
// Regenerate: node scripts/sync-shared.js
// Secret and PII detection, with redaction. Fully local, no network.
//
// `vg` is the capture group holding the SECRET ITSELF, which is not always group 1. Getting this
// wrong is not a cosmetic bug: the original code used `m[1] || m[0]`, so `api_key = "hunter2"`
// redacted the words "api_key" and left the value in the output, and a PEM block redacted the
// literal "RSA " while every line of the key body survived. The field named `redacted` was handing
// back secrets. Every rule below declares its value group explicitly; if you add a rule, add a test
// that asserts the secret VALUE is absent from `redacted`, not that the marker is present.

const { RULES_VERSION } = require('../lib/version');
const rulesets = require('../lib/rulesets');

const SECRET_RULES = [
  { id: 'aws-access-key', type: 'AWS Access Key ID', re: /\b((AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b/g, severity: 'critical', vg: 1 },
  { id: 'github-pat', type: 'GitHub Token', re: /\b((ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b/g, severity: 'critical', vg: 1 },
  // The lookahead is not cosmetic. Without it this rule also matched `sk-ant-…`, so an Anthropic key
  // came back as two findings, one of them naming the wrong vendor, and the redacted copy labelled
  // it an OpenAI key. A tool that misidentifies the credential it just found sends someone to rotate
  // the wrong thing.
  { id: 'openai', type: 'OpenAI API Key', re: /\b(sk-(?!ant-)(proj-)?[A-Za-z0-9_-]{20,})\b/g, severity: 'critical', vg: 1 },
  { id: 'anthropic', type: 'Anthropic API Key', re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g, severity: 'critical', vg: 1 },
  { id: 'google-api', type: 'Google API Key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, severity: 'high', vg: 1 },
  { id: 'slack', type: 'Slack Token', re: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g, severity: 'critical', vg: 1 },
  { id: 'stripe', type: 'Stripe Secret Key', re: /\b((sk|rk)_live_[0-9A-Za-z]{24,})\b/g, severity: 'critical', vg: 1 },
  { id: 'twilio', type: 'Twilio Key', re: /\b(SK[0-9a-fA-F]{32})\b/g, severity: 'high', vg: 1 },
  { id: 'npm', type: 'npm Token', re: /\b(npm_[0-9A-Za-z]{36})\b/g, severity: 'critical', vg: 1 },
  { id: 'jwt', type: 'JWT', re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g, severity: 'medium', vg: 1 },
  // Match the whole armoured block, not just the BEGIN line, so the key body is what gets removed.
  { id: 'private-key', type: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: 'critical', vg: 0 },

  // --- Azure ---
  // The storage account key is the whole keys-to-the-kingdom credential for a storage account, and
  // it is nearly always pasted inside a connection string rather than on its own.
  { id: 'azure-storage-key', type: 'Azure Storage Account Key', re: /AccountKey\s*=\s*([A-Za-z0-9+/=]{40,})/g, severity: 'critical', vg: 1 },
  { id: 'azure-sas-token', type: 'Azure SAS Token', re: /[?&]sig=([A-Za-z0-9%+/=_-]{40,})/g, severity: 'high', vg: 1 },
  // Azure AD (Entra) client secrets carry a distinctive `<3 chars>8Q~` / `7Q~` shape. Anchored with
  // lookaround rather than \b because the value may start with a non-word character.
  { id: 'azure-ad-secret', type: 'Azure AD Client Secret', re: /(?<![\w~.-])([A-Za-z0-9~._-]{3}[78]Q~[A-Za-z0-9~._-]{31,34})(?![\w~.-])/g, severity: 'critical', vg: 1 },

  // --- Google Cloud ---
  // A service-account JSON leaks through two things: the PEM body (caught by private-key above) and
  // the key id, which identifies the key even after the body is stripped.
  { id: 'gcp-sa-key-id', type: 'GCP Service Account Key ID', re: /"private_key_id"\s*:\s*"([0-9a-f]{40})"/g, severity: 'high', vg: 1 },
  { id: 'gcp-oauth-refresh', type: 'Google OAuth Refresh Token', re: /\b(1\/\/[0-9A-Za-z_-]{20,})/g, severity: 'high', vg: 1 },

  // --- Connection strings ---
  // The password inside a database or broker URI. Redacts only the password so the host and user
  // stay readable, which is usually what makes the finding actionable.
  { id: 'db-connection-uri', type: 'Database Connection String Password', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|ftp):\/\/[^:@\s/]+:([^@\s/]{3,})@/gi, severity: 'critical', vg: 1 },
  // ADO.NET / ODBC / JDBC style: Password=...; or Pwd=...;
  { id: 'connection-string-password', type: 'Connection String Password', re: /\b(?:password|pwd)\s*=\s*([^;'"\s]{6,})/gi, severity: 'medium', vg: 1 },

  // --- Other high-signal vendor formats ---
  { id: 'sendgrid', type: 'SendGrid API Key', re: /\b(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64})\b/g, severity: 'critical', vg: 1 },
  { id: 'gitlab-pat', type: 'GitLab Token', re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g, severity: 'critical', vg: 1 },
  { id: 'huggingface', type: 'Hugging Face Token', re: /\b(hf_[A-Za-z0-9]{30,})\b/g, severity: 'critical', vg: 1 },

  { id: 'generic-secret', type: 'Generic Secret Assignment', re: /\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]/gi, severity: 'medium', vg: 2 },
];

// Addresses that are reserved by RFC and cannot resolve to a real mailbox.
const RESERVED_DOMAIN = /@(?:[A-Za-z0-9.-]*\.)?(?:test|example|invalid|localhost)$|@(?:[A-Za-z0-9.-]*\.)?example\.(?:com|net|org)$/i;

const PII_RULES = [
  { id: 'email', type: 'Email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, severity: 'low', vg: 0 },
  { id: 'ssn', type: 'US SSN', re: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'high', vg: 0 },
  { id: 'credit-card', type: 'Credit Card', re: /\b(?:\d[ -]?){13,16}\b/g, severity: 'high', luhn: true, vg: 0 },
];

function luhn(num) {
  const s = String(num).replace(/\D/g, '');
  if (s.length < 13 || s.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = s.length - 1; i >= 0; i--) { let d = +s[i]; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; }
  return sum % 10 === 0;
}

function maskSecret(s) {
  s = String(s);
  if (s.length <= 6) return s[0] + '****';
  return s.slice(0, 3) + '*'.repeat(Math.min(12, s.length - 5)) + s.slice(-2);
}

function scan(text) {
  const t = String(text || '');
  const findings = [];
  // Collect the exact span of each secret, then splice them out back-to-front. The original code did
  // a document-wide split/join on the matched text, which replaced every other occurrence of that
  // string too (redacting "RSA " turned both the BEGIN and END lines into rubble).
  const spans = [];
  const apply = (rules, kind) => {
    for (const r of rules) {
      const vg = r.vg || 0;
      r.re.lastIndex = 0;
      let m;
      while ((m = r.re.exec(t)) !== null) {
        const val = m[vg];
        // A rule whose value group did not participate cannot be redacted safely; skip rather than
        // report a finding we would leave in the output.
        if (val === undefined) { if (!r.re.global) break; continue; }
        if (r.luhn && !luhn(val)) { if (!r.re.global) break; continue; }
        // RFC 2606 and 6761 set aside .test, .example, .invalid and .localhost (and example.com/net/org)
        // precisely so documentation and tests have addresses that can never belong to anyone. Calling
        // those personal data is noise, and noise is what gets a scanner switched off. This engine's
        // own test fixtures tripped it.
        if (r.id === 'email' && RESERVED_DOMAIN.test(val)) { if (!r.re.global) break; continue; }
        const start = vg === 0 ? m.index : m.index + m[0].indexOf(val);
        spans.push({ start, end: start + val.length, type: r.type });
        findings.push({ id: r.id, kind, type: r.type, severity: r.severity, preview: maskSecret(val), index: start });
        if (!r.re.global) break;
        // A zero-length match would spin forever.
        if (m[0] === '') r.re.lastIndex++;
      }
    }
  };
  apply(rulesets.rules('secrets') || SECRET_RULES, 'secret');
  apply(rulesets.rules('pii') || PII_RULES, 'pii');

  // Splice spans out back-to-front so earlier offsets stay valid. Overlaps (a vendor key that is also
  // the value of a generic assignment) collapse into the widest span so nothing is left behind.
  let redacted = t;
  const merged = spans
    .sort((a, b) => a.start - b.start || b.end - a.end)
    .reduce((acc, s) => {
      const last = acc[acc.length - 1];
      if (last && s.start < last.end) { last.end = Math.max(last.end, s.end); return acc; }
      acc.push({ ...s });
      return acc;
    }, []);
  for (let i = merged.length - 1; i >= 0; i--) {
    const s = merged[i];
    redacted = redacted.slice(0, s.start) + `[REDACTED:${s.type}]` + redacted.slice(s.end);
  }

  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const worst = findings.reduce((a, f) => Math.max(a, order[f.severity] || 0), 0);
  const verdict = worst >= 3 ? 'block' : worst >= 1 ? 'review' : 'allow';
  return {
    found: findings.length,
    secrets: findings.filter((f) => f.kind === 'secret').length,
    pii: findings.filter((f) => f.kind === 'pii').length,
    verdict,
    findings,
    redacted,
    rules_version: rulesets.version(RULES_VERSION),
    rules_provenance: rulesets.provenance(),
  };
}

const INFO = {
  version: RULES_VERSION,
  secrets: { rules: SECRET_RULES.length, ids: SECRET_RULES.map((r) => r.id) },
  pii: { rules: PII_RULES.length, ids: PII_RULES.map((r) => r.id) },
  limits: 'Pattern matching against known credential formats. A secret in an unknown format, or split across lines, is not detected.',
};

module.exports = { scan, luhn, maskSecret, SECRET_RULES, PII_RULES, INFO, RULES_VERSION };
