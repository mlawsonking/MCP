#!/usr/bin/env node
// Verify a freshly built bundle by installing it, through the real feed client, exactly the way a
// stranger's machine would.
//
// The build already runs the schema validator over its own output. This goes further and is the
// step that actually decides whether the bundle ships: it serves rules/ to the real client over a
// stubbed transport and checks the signature, the hash chain to the package list, the schema, the
// ReDoS gate, the version rules and the sidecar all behave. Then it deliberately breaks things and
// checks the client refuses.
//
// The reason this exists rather than trusting the build: a bundle that no client will apply is
// indistinguishable, from the publisher's side, from one that every client applies. The failure is
// silent and it is discovered days later as "the rules stopped updating".

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const RULES = path.join(ROOT, 'rules');

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guards-verify-'));
process.env.AGENT_GUARDS_HOME = HOME;
delete process.env.AGENT_GUARDS_NO_FEED;
delete process.env.AGENT_GUARDS_FEED_URL;

const feed = require(path.join(ROOT, 'agent-guards/lib/feed'));
const mal = require(path.join(ROOT, 'agent-guards/lib/malicious-packages'));

let failures = 0;
function ck(name, cond, detail) {
  if (cond) { console.log(`  ok   ${name}`); return true; }
  failures++;
  console.log(`  FAIL ${name}${detail ? `  (${detail})` : ''}`);
  return false;
}

for (const f of ['bundle.json', 'bundle.json.sig', 'manifest.json', 'packages.tsv']) {
  if (!fs.existsSync(path.join(RULES, f))) {
    console.error(`rules/${f} is missing. Run scripts/build-rules-bundle.js then scripts/sign-rules-bundle.js.`);
    process.exit(1);
  }
}

const manifest = fs.readFileSync(path.join(RULES, 'manifest.json'), 'utf8');
const bundle = fs.readFileSync(path.join(RULES, 'bundle.json'), 'utf8');
const tsv = fs.readFileSync(path.join(RULES, 'packages.tsv'), 'utf8');

// The transport a real client would use, with the files on disk standing in for the network.
const serve = (over = {}) => async (url) => {
  if (url.includes('/api/rules/latest')) return { ok: true, text: over.manifest !== undefined ? over.manifest : manifest, etag: '"verify"' };
  if (url.endsWith('packages.tsv')) return { ok: true, text: over.tsv !== undefined ? over.tsv : tsv };
  return { ok: true, text: over.bundle !== undefined ? over.bundle : bundle };
};

(async () => {
  console.log('verifying rules/ through the real feed client\n');

  const r = await feed.update({ surface: 'cli', force: true, fetchImpl: serve() });
  ck('the bundle applies', r.action === 'applied', r.reason);
  if (!ck('it verified against a key compiled into the package', r.action === 'applied')) {
    console.log('\n  The signature did not verify against agent-guards/lib/feed.js TRUSTED_KEYS.');
    console.log('  Either the bundle was signed with the wrong key, or the public half was never shipped.');
  }
  const doc = JSON.parse(bundle);
  ck('the version the client recorded is the one in the bundle', feed.cachedVersion() === doc.version, `${feed.cachedVersion()} vs ${doc.version}`);
  ck('the package list came down and matched its pinned hash', r.packages && r.packages.action === 'updated', JSON.stringify(r.packages));
  ck('the cached bundle re-validates when read back', !!feed.loadCached());

  // The lists are only worth anything if a lookup against them works.
  const b = feed.loadCached();
  ck('the sanctions list is not empty', b.lists.ofac_evm.count > 0, String(b.lists.ofac_evm.count));
  ck('the scam list is not empty', b.lists.scam_addresses.count > 0, String(b.lists.scam_addresses.count));
  ck('a package with pinned malicious versions reads as malicious at that version',
    mal.check('npm', 'axios', '1.14.1') && mal.check('npm', 'axios', '1.14.1').verdict === 'malicious');
  // The case the whole format exists for. If this ever flips to "malicious", every `npm install
  // axios` in the world starts getting told it is installing malware.
  const clean = mal.check('npm', 'axios', '99.99.99');
  ck('and NOT malicious at a version the advisory does not name', clean && clean.verdict !== 'malicious', JSON.stringify(clean));

  const stale = doc.sources.filter((s) => !s.ok);
  if (stale.length) {
    console.log(`\n  ${stale.length} source(s) are stale and the bundle says so:`);
    for (const s of stale) console.log(`    ${s.id}: ${s.note}`);
  }

  console.log('\nand the refusals:');

  // A bundle whose bytes changed after signing.
  const tampered = bundle.replace('"schema": 1', '"schema":  1');
  const t = await feed.update({ surface: 'cli', force: true, allowRollback: true, fetchImpl: serve({ bundle: tampered }) });
  ck('a tampered bundle is refused', !t.ok, t.reason);
  ck('and the good version is still installed', feed.cachedVersion() === doc.version);

  // A signature made by someone else.
  const other = crypto.generateKeyPairSync('ed25519');
  const forged = JSON.parse(manifest);
  forged.signature = crypto.sign(null, Buffer.from(bundle, 'utf8'), other.privateKey).toString('base64');
  const f2 = await feed.update({ surface: 'cli', force: true, allowRollback: true, fetchImpl: serve({ manifest: JSON.stringify(forged) }) });
  ck('a bundle signed by an untrusted key is refused', !f2.ok && /signature did not verify/.test(f2.reason), f2.reason);

  // A package list that does not match the hash the signed bundle pins.
  fs.rmSync(path.join(feed.rulesDir(), 'packages.tsv'), { force: true });
  const s2 = await feed.update({ surface: 'cli', force: true, allowRollback: true, fetchImpl: serve({ tsv: tsv + 'npm\tsneaked-in\t*\tMAL-x\n' }) });
  ck('a package list that does not match its pinned hash is refused', !s2.ok && /SHA-256/.test(s2.reason), s2.reason);

  fs.rmSync(HOME, { recursive: true, force: true });
  console.log(failures ? `\n${failures} check(s) failed. This bundle must not ship.` : '\nall checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
