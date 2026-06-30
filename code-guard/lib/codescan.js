// Code Guard — deterministic SAST ruleset for AI-generated code. No LLM. Heuristic/regex, fast first-line.
// Positioning: catches the high-frequency vuln classes in AI-written code (injection, SSRF, hardcoded secrets,
// weak crypto, unsafe deserialization, TLS-off, XSS) IN THE AGENT'S LOOP — not a full audit replacement.
// Reuses scanSecrets (agent-firewall engine) for hardcoded credentials.
const { scanSecrets } = require('./safety.js');

// sev: critical|high|medium|low · lang: 'any'|'js'(js/ts)|'py'
const RULES = [
  // code execution / command injection
  { id: 'js-eval', cat: 'code-injection', sev: 'high', lang: 'js', re: /\beval\s*\(/, msg: 'eval() can execute arbitrary code.', fix: 'Avoid eval; use JSON.parse for data.' },
  { id: 'js-new-function', cat: 'code-injection', sev: 'high', lang: 'js', re: /\bnew\s+Function\s*\(/, msg: 'new Function() executes arbitrary code from strings.', fix: 'Avoid dynamic code generation.' },
  { id: 'js-cmd-concat', cat: 'command-injection', sev: 'critical', lang: 'js', re: /\b(exec|execSync)\s*\(\s*(?:[`'"][^`'"]*\$\{|[^)]*\+)/, msg: 'Shell command built from interpolation/concatenation → command injection.', fix: 'Use execFile/spawn with an args array; never build shell strings from input.' },
  { id: 'js-vm', cat: 'code-injection', sev: 'high', lang: 'js', re: /\bvm\.(runIn\w+|compileFunction)\s*\(/, msg: 'vm module runs untrusted code in-process.', fix: 'Do not run untrusted code in-process.' },
  { id: 'py-eval-exec', cat: 'code-injection', sev: 'high', lang: 'py', re: /\b(eval|exec)\s*\(/, msg: 'eval()/exec() executes arbitrary code.', fix: 'Use ast.literal_eval for data; avoid dynamic execution.' },
  { id: 'py-os-system', cat: 'command-injection', sev: 'critical', lang: 'py', re: /\bos\.(system|popen)\s*\(/, msg: 'os.system/os.popen run shell commands → command injection.', fix: 'Use subprocess.run([...], shell=False).' },
  { id: 'py-subprocess-shell', cat: 'command-injection', sev: 'critical', lang: 'py', re: /\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True/, msg: 'subprocess with shell=True → command injection.', fix: 'Pass an args list and shell=False.' },
  // SQL injection
  { id: 'sql-concat', cat: 'sql-injection', sev: 'high', lang: 'any', re: /\b(execute|query)\s*\(\s*[`'"][^`'"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^`'"]*(?:[`'"]\s*[+%]|\$\{)/i, msg: 'SQL string built by concatenation/interpolation → SQL injection.', fix: 'Use parameterized queries / prepared statements.' },
  { id: 'py-sql-fstring', cat: 'sql-injection', sev: 'high', lang: 'py', re: /\.execute\s*\(\s*f["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b/i, msg: 'SQL built with an f-string → SQL injection.', fix: 'Use cursor.execute(sql, params) with placeholders.' },
  // insecure deserialization
  { id: 'py-pickle', cat: 'insecure-deserialization', sev: 'critical', lang: 'py', re: /\b(pickle|cPickle|_pickle|marshal)\.(loads?|load)\s*\(/, msg: 'Deserializing pickle/marshal can execute arbitrary code.', fix: 'Never unpickle untrusted data; use JSON.' },
  { id: 'py-yaml-load', cat: 'insecure-deserialization', sev: 'high', lang: 'py', re: /\byaml\.load\s*\((?![^)]*(Safe|safe_))/, msg: 'yaml.load without SafeLoader can execute code.', fix: 'Use yaml.safe_load().' },
  { id: 'node-deserialize', cat: 'insecure-deserialization', sev: 'high', lang: 'js', re: /\bnode-serialize|\bunserialize\s*\(/, msg: 'Unsafe deserialization can execute code.', fix: 'Use JSON.parse on untrusted data.' },
  // weak crypto / randomness  (context-dependent → lower severity to cut noise)
  { id: 'weak-hash', cat: 'weak-crypto', sev: 'medium', lang: 'any', re: /\b(md5|sha1)\s*\(|['"]md5['"]|['"]sha1['"]|createHash\s*\(\s*['"](md5|sha1)/i, msg: 'MD5/SHA1 are broken for security use.', fix: 'SHA-256+ for integrity; bcrypt/scrypt/argon2 for passwords.' },
  { id: 'js-math-random', cat: 'weak-crypto', sev: 'low', lang: 'js', re: /\bMath\.random\s*\(\)/, msg: 'Math.random() is not cryptographically secure (if used for tokens/IDs).', fix: 'Use crypto.randomBytes / crypto.getRandomValues.' },
  { id: 'py-random', cat: 'weak-crypto', sev: 'low', lang: 'py', re: /\brandom\.(random|randint|choice|randrange|getrandbits)\s*\(/, msg: 'random module is not cryptographically secure (if used for secrets).', fix: 'Use the secrets module.' },
  { id: 'crypto-ecb', cat: 'weak-crypto', sev: 'high', lang: 'any', re: /\bECB\b|MODE_ECB/, msg: 'ECB mode leaks plaintext patterns.', fix: 'Use AES-GCM with a random nonce.' },
  { id: 'weak-cipher', cat: 'weak-crypto', sev: 'high', lang: 'any', re: /\b(DES|3DES|RC4|MD4)\b/, msg: 'Weak/legacy cipher.', fix: 'Use AES-256-GCM.' },
  // TLS verification disabled
  { id: 'py-verify-false', cat: 'tls', sev: 'high', lang: 'py', re: /\bverify\s*=\s*False\b/, msg: 'TLS certificate verification disabled (verify=False).', fix: 'Remove verify=False; fix the cert chain.' },
  { id: 'js-reject-unauth', cat: 'tls', sev: 'high', lang: 'js', re: /rejectUnauthorized\s*:\s*false/, msg: 'TLS verification disabled (rejectUnauthorized:false).', fix: 'Do not disable cert validation.' },
  { id: 'node-tls-env', cat: 'tls', sev: 'high', lang: 'any', re: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/, msg: 'Disables all TLS verification process-wide.', fix: 'Never set NODE_TLS_REJECT_UNAUTHORIZED=0.' },
  { id: 'py-unverified-ssl', cat: 'tls', sev: 'high', lang: 'py', re: /_create_unverified_context|ssl\.CERT_NONE/, msg: 'TLS verification disabled.', fix: 'Use the default verified context.' },
  // XSS / template injection
  { id: 'js-innerhtml', cat: 'xss', sev: 'medium', lang: 'js', re: /\.(innerHTML|outerHTML)\s*=\s*(?!['"`]\s*['"`]\s*;?\s*$)/, msg: 'Assigning dynamic data to innerHTML → XSS.', fix: 'Use textContent or sanitize (DOMPurify).' },
  { id: 'js-dangerously', cat: 'xss', sev: 'medium', lang: 'js', re: /dangerouslySetInnerHTML/, msg: 'dangerouslySetInnerHTML can introduce XSS.', fix: 'Sanitize HTML (DOMPurify) before rendering.' },
  { id: 'js-doc-write', cat: 'xss', sev: 'medium', lang: 'js', re: /document\.write\s*\(/, msg: 'document.write with dynamic data → XSS.', fix: 'Build DOM nodes safely.' },
  { id: 'py-ssti', cat: 'ssti', sev: 'high', lang: 'py', re: /render_template_string\s*\(/, msg: 'render_template_string with user input → server-side template injection.', fix: 'Render fixed templates with context variables.' },
  { id: 'py-mark-safe', cat: 'xss', sev: 'medium', lang: 'py', re: /\b(mark_safe|Markup)\s*\(/, msg: 'Bypassing auto-escaping → XSS.', fix: 'Let the engine escape; sanitize untrusted HTML.' },
  // SSRF (heuristic — non-literal outbound URL)
  { id: 'ssrf-js', cat: 'ssrf', sev: 'medium', lang: 'js', re: /\b(fetch|axios|request|got)\s*\(\s*(?:`[^`]*\$\{|req\.|request\.|[a-zA-Z_$][\w$]*\s*[,)])/, msg: 'Outbound request to a non-constant/user-influenced URL → possible SSRF.', fix: 'Allowlist destinations; block internal/metadata IPs (169.254.169.254, localhost, RFC1918).' },
  { id: 'ssrf-py', cat: 'ssrf', sev: 'medium', lang: 'py', re: /\b(requests\.\w+|urlopen|httpx\.\w+)\s*\(\s*(?!["'])[a-zA-Z_]/, msg: 'Outbound request to a non-literal URL → possible SSRF.', fix: 'Allowlist destinations; block internal/metadata IPs.' },
  // misc
  { id: 'flask-debug', cat: 'misconfiguration', sev: 'medium', lang: 'py', re: /\.run\s*\([^)]*debug\s*=\s*True/, msg: 'Flask debug=True exposes the Werkzeug debugger (RCE) in production.', fix: 'debug=False in production.' },
  { id: 'jwt-noverify', cat: 'auth', sev: 'high', lang: 'any', re: /verify_signature\s*:\s*false|algorithms\s*=\s*\[\s*['"]none['"]|['"]alg['"]\s*:\s*['"]none['"]/i, msg: 'JWT signature verification disabled / alg=none.', fix: 'Verify signatures with a fixed algorithm allowlist.' },
  { id: 'py-assert-auth', cat: 'logic', sev: 'low', lang: 'py', re: /\bassert\b[^\n=]*\b(auth|admin|permission|is_authenticated|is_admin|token|password)\b/i, msg: 'assert used for a security check — stripped with python -O.', fix: 'Use explicit if/raise.' },
];

function normalizeLang(hint, src) {
  const h = String(hint || '').toLowerCase();
  if (/\b(js|javascript|jsx|ts|typescript|tsx|node)\b/.test(h)) return 'js';
  if (/\b(py|python)\b/.test(h)) return 'py';
  if (/\bdef\s+\w+\s*\(|^\s*import\s+\w|:\s*$/m.test(src) && !/\b(function|const|let|=>)\b/.test(src)) return 'py';
  if (/\b(function|const|let|=>|require\(|import .* from)\b/.test(src)) return 'js';
  return 'unknown';
}

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

function applyRules(lines, lang, lineOffset) {
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]; const line = raw.lineText !== undefined ? raw.lineText : raw;
    const lineNo = raw.lineNo !== undefined ? raw.lineNo : i + 1 + (lineOffset || 0);
    if (!String(line).trim()) continue;
    for (const r of RULES) {
      if (r.lang !== 'any' && lang !== 'unknown' && r.lang !== lang) continue;
      r.re.lastIndex = 0;
      if (r.re.test(line)) findings.push({ id: r.id, category: r.cat, severity: r.sev, line: lineNo, code: String(line).trim().slice(0, 160), message: r.msg, remediation: r.fix });
    }
  }
  return findings;
}

function secretFindings(src, lineOf) {
  const out = [];
  const sec = scanSecrets(src);
  sec.findings.forEach((f) => {
    out.push({ id: 'hardcoded-' + f.id, category: 'hardcoded-secret', severity: f.severity, line: lineOf(f.index), code: `(${f.type}: ${f.preview})`, message: `Hardcoded ${f.type} in source.`, remediation: 'Move to env vars / a secrets manager and ROTATE this credential.' });
  });
  return out;
}

function summarize(findings, lang) {
  findings.sort((a, b) => (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || (a.line - b.line));
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const verdict = (counts.critical || counts.high) ? 'block' : counts.medium ? 'review' : counts.low ? 'review' : 'pass';
  const categories = [...new Set(findings.map((f) => f.category))];
  return { lang, verdict, total: findings.length, counts, categories, findings };
}

function scanCode(code, langHint) {
  const src = String(code || '');
  const lang = normalizeLang(langHint, src);
  const findings = applyRules(src.split(/\r?\n/), lang);
  const lineOf = (idx) => src.slice(0, idx).split(/\r?\n/).length;
  return summarize(findings.concat(secretFindings(src, lineOf)), lang);
}

// scanDiff — scan only ADDED lines of a unified diff (the agent's just-written change).
function scanDiff(diff, langHint) {
  const text = String(diff || '');
  const lines = text.split(/\r?\n/);
  const added = []; let newLine = 0; const addedSrcParts = [];
  for (const l of lines) {
    const hunk = l.match(/^@@\s*-\d+(?:,\d+)?\s+\+(\d+)/);
    if (hunk) { newLine = parseInt(hunk[1], 10); continue; }
    if (l.startsWith('+++') || l.startsWith('---')) continue;
    if (l.startsWith('+')) { added.push({ lineText: l.slice(1), lineNo: newLine }); addedSrcParts.push(l.slice(1)); newLine++; }
    else if (l.startsWith('-')) { /* removed: don't advance new-file line */ }
    else { newLine++; }
  }
  const lang = normalizeLang(langHint, addedSrcParts.join('\n'));
  const findings = applyRules(added, lang);
  // secrets within added lines
  const addedSrc = addedSrcParts.join('\n');
  const offsets = []; let pos = 0; added.forEach((a) => { offsets.push({ start: pos, lineNo: a.lineNo }); pos += a.lineText.length + 1; });
  const lineOf = (idx) => { let ln = added.length ? added[added.length - 1].lineNo : 1; for (const o of offsets) { if (idx >= o.start) ln = o.lineNo; } return ln; };
  return { ...summarize(findings.concat(secretFindings(addedSrc, lineOf)), lang), addedLines: added.length };
}

function listRules() {
  return RULES.map((r) => ({ id: r.id, category: r.cat, severity: r.sev, lang: r.lang, message: r.msg }))
    .concat([{ id: 'hardcoded-*', category: 'hardcoded-secret', severity: 'critical/high', lang: 'any', message: 'Hardcoded API keys, tokens, private keys, and generic secrets.' }]);
}

module.exports = { scanCode, scanDiff, listRules, RULES };
