#!/usr/bin/env node
// Sign rules/bundle.json and write the manifest the feed endpoint serves.
//
// The signature is detached and covers the bundle's exact bytes. It is what makes the transport
// untrusted: it does not matter whether a client got the bundle from a Vercel function, from
// GitHub's raw CDN, or off a USB stick, because the only thing that decides whether it is applied
// is whether it verifies against the public key compiled into the package.
//
// The manifest is not signed and does not need to be. Everything in it that matters is checked
// against the bundle after download — the SHA-256, the signature, and the version, which a client
// takes from inside the signed document rather than from the manifest's claim. A tampered manifest
// can waste a client's bandwidth and nothing else.
//
// The key comes from the RULES_SIGNING_KEY environment variable (a GitHub Actions secret) or, for a
// local run, from rules/feed-private-key.pem, which is gitignored. Neither is ever printed.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const OUT_DIR = path.join(ROOT, 'rules');
const BUNDLE = path.join(OUT_DIR, 'bundle.json');
const SIDECAR = path.join(OUT_DIR, 'packages.tsv');
const SIG = path.join(OUT_DIR, 'bundle.json.sig');
const MANIFEST = path.join(OUT_DIR, 'manifest.json');
const LOCAL_KEY = path.join(OUT_DIR, 'feed-private-key.pem');

// Where the bundle actually lives once it is pushed. GitHub's raw CDN serves it the moment the
// pipeline commits, which is what makes the whole thing owner-free: no deploy stands between a new
// bundle and the clients that pull it.
const BUNDLE_URL = process.env.RULES_BUNDLE_URL || 'https://raw.githubusercontent.com/mlawsonking/MCP/main/rules/bundle.json';

const die = (m) => { console.error(`sign failed: ${m}`); process.exit(1); };

function loadKey() {
  const env = process.env.RULES_SIGNING_KEY;
  if (env && env.trim()) {
    try { return crypto.createPrivateKey(env.replace(/\\n/g, '\n')); }
    catch (e) { die(`RULES_SIGNING_KEY is set but will not load as a private key: ${e.message}`); }
  }
  if (fs.existsSync(LOCAL_KEY)) {
    try { return crypto.createPrivateKey(fs.readFileSync(LOCAL_KEY, 'utf8')); }
    catch (e) { die(`${LOCAL_KEY} will not load as a private key: ${e.message}`); }
  }
  die('no signing key. Set RULES_SIGNING_KEY, or run scripts/gen-feed-key.js for a local one.');
}

if (!fs.existsSync(BUNDLE)) die(`${BUNDLE} does not exist. Run scripts/build-rules-bundle.js first.`);

const key = loadKey();
if (key.asymmetricKeyType !== 'ed25519') die(`the signing key is ${key.asymmetricKeyType}, expected ed25519`);

const bytes = fs.readFileSync(BUNDLE);
const signature = crypto.sign(null, bytes, key).toString('base64');

// Verify what we just produced, with the public half derived from the private one. A signing step
// that never checks its own output is how an unverifiable bundle ships.
const pub = crypto.createPublicKey(key);
if (!crypto.verify(null, bytes, pub, Buffer.from(signature, 'base64'))) die('the signature does not verify against its own key');

const spki = pub.export({ type: 'spki', format: 'der' }).toString('base64');
const trusted = require(path.join(ROOT, 'agent-guards/lib/feed')).TRUSTED_KEYS;
if (!trusted.includes(spki)) {
  die(`this key's public half is not in TRUSTED_KEYS in agent-guards/lib/feed.js, so no client would accept the bundle.\n  got: ${spki}`);
}

const doc = JSON.parse(bytes.toString('utf8'));
const sidecarBytes = fs.existsSync(SIDECAR) ? fs.readFileSync(SIDECAR) : null;

const manifest = {
  schema: doc.schema,
  version: doc.version,
  generated: doc.generated,
  bytes: bytes.length,
  sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  url: BUNDLE_URL,
  signature,
  notes: doc.notes,
  counts: {
    injection: doc.rulesets.injection.length,
    secrets: doc.rulesets.secrets.length,
    pii: doc.rulesets.pii.length,
    code: doc.rulesets.code.length,
    ofac_addresses: Object.keys(doc.lists.ofac_evm.entries).length,
    scam_addresses: Object.keys(doc.lists.scam_addresses.entries).length,
    malicious_packages: doc.lists.malicious_packages.npm_count + doc.lists.malicious_packages.pypi_count,
  },
  // Repeated from the bundle so a human curling the endpoint can see which lists are stale without
  // downloading megabytes. The copy a client acts on is the one inside the signed bundle.
  sources: doc.sources,
};
if (sidecarBytes) {
  const sha = crypto.createHash('sha256').update(sidecarBytes).digest('hex');
  if (sha !== doc.lists.malicious_packages.sha256) {
    die('rules/packages.tsv does not match the hash in rules/bundle.json — rebuild before signing');
  }
  manifest.packages = { file: doc.lists.malicious_packages.file, bytes: sidecarBytes.length, sha256: sha };
}

fs.writeFileSync(SIG, signature + '\n');
fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 1) + '\n');

console.log(`signed ${path.relative(ROOT, BUNDLE)} (${bytes.length} bytes)`);
console.log(`wrote  ${path.relative(ROOT, SIG)}`);
console.log(`wrote  ${path.relative(ROOT, MANIFEST)} for version ${doc.version}`);
