// The rules feed's failure matrix.
//
// This suite existed before the pipeline that publishes bundles did, because the interesting
// question about a feed is not "does a good bundle apply" but "what does a client do when the feed
// is missing, malformed, tampered with, stale, rolled back, oversized, hostile, or expensive". Each
// of those is a case below, and each one asserts the same two things: the client refuses, and the
// rules it already had are still there afterwards.
//
// The suite signs its own bundles with a keypair it generates at startup and passes in through
// `opts.keys`. It therefore needs no access to the real signing key, which is the point: the real
// private key lives in a GitHub Actions secret and nothing on a developer's machine or a CI runner
// should be able to produce a bundle this client would trust.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// Point the whole library at a scratch home before anything reads it.
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guards-feed-'));
process.env.AGENT_GUARDS_HOME = HOME;
delete process.env.AGENT_GUARDS_NO_FEED;
delete process.env.AGENT_GUARDS_FEED_URL;

const { ck, section, done } = require('./_harness.cjs');
const feed = require('../lib/feed');
const schema = require('../lib/rules-schema');
const redos = require('../lib/redos');
const mal = require('../lib/malicious-packages');
const rulesets = require('../lib/rulesets');
const injection = require('../engines/injection');
const secrets = require('../engines/secrets');
const { INJECTION_RULES } = require('../engines/injection');
const { SECRET_RULES, PII_RULES } = require('../engines/secrets');
const { RULES: CODE_RULES } = require('../engines/code');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const TEST_KEYS = [publicKey.export({ type: 'spki', format: 'der' }).toString('base64')];

// The malicious-package sidecar: sorted by ecosystem then name, byte order, which is what the
// binary search in lib/malicious-packages.js assumes. `*` means every version of that package.
const SIDECAR = [
  'npm\taxios\t0.30.4,1.14.1\tMAL-2026-2307',
  'npm\tevil-all-versions\t*\tMAL-2025-0001',
  'pypi\tevil-pkg\t1.0.0\tMAL-2025-0002',
].join('\n') + '\n';
const SIDECAR_SHA = crypto.createHash('sha256').update(Buffer.from(SIDECAR, 'utf8')).digest('hex');

// ---------------------------------------------------------------------------------------------
// bundle + transport fixtures
// ---------------------------------------------------------------------------------------------

function bundleDoc(over = {}) {
  const doc = {
    schema: 1,
    // Newer than what installGood() puts on disk, because a client only downloads a bundle when
    // the feed is actually ahead of it. A fixture that offered the same version would short-circuit
    // and quietly stop testing whatever the case was about.
    version: '2026.08.02',
    generated: '2026-08-02T04:00:00Z',
    notes: 'test bundle',
    rulesets: {
      injection: [{ id: 'ignore-previous', category: 'instruction-override', weight: 35, pattern: 'ignore all previous instructions', flags: 'i' }],
      secrets: [{ id: 'aws-access-key', type: 'AWS Access Key ID', pattern: '\\b((AKIA)[0-9A-Z]{16})\\b', flags: 'g', severity: 'critical', value_group: 1 }],
      pii: [{ id: 'ssn', type: 'US SSN', pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b', flags: 'g', severity: 'high', value_group: 0 }],
      code: [{ id: 'js-eval', category: 'code-injection', severity: 'high', language: 'js', pattern: '\\beval\\s*\\(', flags: '', message: 'eval() can execute arbitrary code.', fix: 'Avoid eval.' }],
    },
    lists: {
      ofac_evm: { source: 'test', fetched: '2026-08-01', entries: { '0x8589427373d6d84e98730d7795d8f6f8731fda16': 'OFAC SDN' } },
      scam_addresses: { source: 'test', fetched: '2026-08-01', entries: { '0x0000000000000000000000000000000000000bad': 'test scam' } },
      malicious_packages: {
        source: 'test', fetched: '2026-08-01', file: 'packages.tsv',
        sha256: SIDECAR_SHA, bytes: Buffer.byteLength(SIDECAR, 'utf8'),
        npm_count: 2, pypi_count: 1, versioned_count: 2,
      },
    },
    sources: [{ id: 'ofac', ok: true, url: 'https://example.invalid/ofac', fetched: '2026-08-01', age_days: 0, note: '' }],
  };
  return { ...doc, ...over };
}

function sign(text) {
  return crypto.sign(null, Buffer.from(text, 'utf8'), privateKey).toString('base64');
}

// A feed that serves whatever the test hands it, and counts what was asked for so a test can
// assert that something was NOT fetched.
function serve({ bundleText, manifest: manifestOver = {}, manifestText, manifestFail, bundleFail, truncated, sidecarText, sidecarFail }) {
  const text = bundleText === undefined ? JSON.stringify(bundleDoc()) : bundleText;
  const manifest = {
    schema: 1,
    version: (() => { try { return JSON.parse(text).version; } catch { return '2026.08.01'; } })(),
    generated: '2026-08-01T04:00:00Z',
    bytes: Buffer.byteLength(text, 'utf8'),
    sha256: crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex'),
    url: 'https://raw.githubusercontent.com/mlawsonking/MCP/main/rules/bundle.json',
    signature: sign(text),
    ...manifestOver,
  };
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push(url);
    if (url.includes('/api/rules/latest')) {
      if (manifestFail) return { ok: false, error: manifestFail };
      return { ok: true, status: 200, text: manifestText !== undefined ? manifestText : JSON.stringify(manifest), etag: '"abc"' };
    }
    if (url.endsWith('packages.tsv')) {
      if (sidecarFail) return { ok: false, error: sidecarFail };
      return { ok: true, status: 200, text: sidecarText !== undefined ? sidecarText : SIDECAR };
    }
    if (bundleFail) return { ok: false, error: bundleFail };
    return { ok: true, status: 200, text, truncated: !!truncated };
  };
  return { fetchImpl, calls, manifest, text };
}

// Every call forces past the TTL and uses the test keys; a test that wants to exercise the TTL
// says so explicitly.
const run = (harness, over = {}) => feed.update({ surface: 'cli', force: false, keys: TEST_KEYS, fetchImpl: harness.fetchImpl, ...over });

function reset() {
  fs.rmSync(feed.rulesDir(), { recursive: true, force: true });
}

// Put a known-good bundle on disk so the "keeps working on its last good rules" assertions have
// something to be about. Returns its version.
async function installGood(version = '2026.08.01') {
  reset();
  const h = serve({ bundleText: JSON.stringify(bundleDoc({ version })) });
  const r = await run(h, { force: true });
  if (r.action !== 'applied') throw new Error(`fixture install failed: ${r.reason}`);
  return version;
}

const cachedText = () => { try { return fs.readFileSync(feed.bundlePath(), 'utf8'); } catch { return null; } };

// ---------------------------------------------------------------------------------------------

(async () => {
  section('a good bundle applies');
  {
    reset();
    const h = serve({});
    const r = await run(h, { force: true });
    ck('a valid signed bundle is applied', r.ok && r.action === 'applied', r.reason);
    ck('the applied version is recorded', feed.cachedVersion() === '2026.08.02', String(feed.cachedVersion()));
    ck('the bundle is on disk', !!cachedText());
    ck('the cached bundle re-validates when loaded back', !!feed.loadCached());
    ck('the bundle pins the package list by hash', feed.loadCached().lists.malicious_packages.sha256 === SIDECAR_SHA);
    ck('the package list was downloaded', r.packages && r.packages.action === 'updated', JSON.stringify(r.packages));
    ck('the package list is on disk', fs.existsSync(path.join(feed.rulesDir(), 'packages.tsv')));
  }

  section('the applied rules are the rules that run');
  {
    // The whole point of a feed, and the thing that is easy to build and never actually connect.
    // A bundle carrying a rule that does not exist in the package has to change what scan() finds,
    // and the verdict has to say where the rules came from.
    reset();
    rulesets.reload();
    const before = injection.scan('the moon is made of tuesday');
    ck('with no bundle, a scan reports bundled provenance', before.rules_provenance === 'bundled', before.rules_provenance);
    ck('with no bundle, the version is the one compiled in', before.rules_version === injection.RULES_VERSION, before.rules_version);
    ck('and the invented phrase matches nothing', before.findings.length === 0);

    const doc = bundleDoc({ version: '2026.08.04' });
    doc.rulesets.injection.push({ id: 'moon-tuesday', category: 'test-only', weight: 40, pattern: 'the moon is made of tuesday', flags: 'i' });
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('the bundle applies', r.action === 'applied', r.reason);

    const after = injection.scan('the moon is made of tuesday');
    ck('a rule that only exists in the feed now matches', after.findings.some((f) => f.id === 'moon-tuesday'), JSON.stringify(after.findings));
    ck('the verdict names the feed as the source', after.rules_provenance === 'feed@2026.08.04', after.rules_provenance);
    ck('and rules_version is the feed version', after.rules_version === '2026.08.04', after.rules_version);

    // The secret engine too, since redaction is where getting this wrong costs the most. The key is
    // assembled at runtime rather than written out: GitHub's push protection is right to refuse a
    // credential-shaped literal in a commit, and this repo has learned that the hard way.
    const awsKey = 'AKIA' + 'IOSFODNN7' + 'EXAMPLE';
    const sec = secrets.scan(awsKey);
    ck('the secret engine runs the fed rules', sec.findings.some((f) => f.id === 'aws-access-key'), JSON.stringify(sec.findings));
    ck('the secret engine reports feed provenance', sec.rules_provenance === 'feed@2026.08.04', sec.rules_provenance);
    ck('the redacted copy still does not contain the secret', !sec.redacted.includes(awsKey), sec.redacted);

    const status = rulesets.status();
    ck('the status object reports the feed and its counts', status.source === 'feed' && status.counts.injection === 2, JSON.stringify(status.counts));
    ck('the status object lists no stale sources for a clean bundle', status.stale_sources.length === 0);

    // And back again: with the bundle gone, the compiled-in rules take over with no fuss.
    reset();
    rulesets.reload();
    const back = injection.scan('the moon is made of tuesday');
    ck('removing the bundle falls back to the compiled-in rules', back.findings.length === 0 && back.rules_provenance === 'bundled', back.rules_provenance);
  }

  section('the malicious-package list');
  {
    await installGood();
    const file = path.join(feed.rulesDir(), 'packages.tsv');
    // The case that decides the whole format. Measured against the 3,000 most-installed npm
    // packages, 42 appear on the malicious list because they were briefly compromised. If a name
    // match alone were a block, `npm install axios` would be reported as installing malware.
    const pinnedBad = mal.check('npm', 'axios', '1.14.1', file);
    const pinnedGood = mal.check('npm', 'axios', '1.7.9', file);
    const unpinned = mal.check('npm', 'axios', null, file);
    ck('a compromised version of a legitimate package is malicious', pinnedBad.verdict === 'malicious', JSON.stringify(pinnedBad));
    ck('a clean version of the same package is NOT malicious', pinnedGood.verdict === 'caution', JSON.stringify(pinnedGood));
    ck('and the caution says which versions are the bad ones', /0\.30\.4, 1\.14\.1/.test(pinnedGood.note), pinnedGood.note);
    ck('no version given is a caution, not a block', unpinned.verdict === 'caution', JSON.stringify(unpinned));
    ck('a wholly malicious package is malicious at any version',
      mal.check('npm', 'evil-all-versions', '9.9.9', file).verdict === 'malicious');
    ck('the ecosystem is part of the key', mal.check('pypi', 'evil-all-versions', '1.0.0', file).verdict === 'clear');
    ck('a package on neither list is clear', mal.check('npm', 'express', '4.18.2', file).verdict === 'clear');
    ck('the last line of the file is findable', mal.check('pypi', 'evil-pkg', '1.0.0', file).verdict === 'malicious');
    ck('the first line of the file is findable', mal.check('npm', 'axios', '0.30.4', file).verdict === 'malicious');
    ck('a missing list reports "not checked" rather than "clear"',
      mal.check('npm', 'axios', '1.14.1', path.join(feed.rulesDir(), 'nope.tsv')) === null);
  }
  {
    // A sidecar whose bytes do not match the hash in the signed bundle is tampering, not a flaky
    // network, and it stops the update. The local copy has to go first or the client correctly
    // notices it already has the right file and never downloads anything.
    await installGood();
    fs.rmSync(path.join(feed.rulesDir(), 'packages.tsv'), { force: true });
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.03' })), sidecarText: SIDECAR + 'npm\tsneaked-in\t*\tMAL-x\n' });
    const r = await run(h, { force: true });
    ck('a package list that does not match its pinned hash is refused',
      !r.ok && /does not match the SHA-256 the signed bundle pins/.test(r.reason), r.reason);
    ck('the rules version did not move after a tampered package list', feed.cachedVersion() === '2026.08.01');
  }
  {
    // A sidecar that will not download is a bad day, not an attack. The rules still apply.
    await installGood();
    fs.rmSync(path.join(feed.rulesDir(), 'packages.tsv'), { force: true });
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.03' })), sidecarFail: 'timed out' });
    const r = await run(h, { force: true });
    ck('rules still apply when the package list will not download', r.ok && r.action === 'applied', r.reason);
    ck('and the skipped download is reported rather than hidden',
      r.packages && r.packages.action === 'skipped' && /could not download/.test(r.packages.reason), JSON.stringify(r.packages));
  }
  {
    // Second update, same list: it should not be downloaded again.
    reset();
    const h1 = serve({});
    await run(h1, { force: true });
    const h2 = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.07' })) });
    const r = await run(h2, { force: true });
    ck('an unchanged package list is not downloaded twice', r.packages.action === 'unchanged', JSON.stringify(r.packages));
    ck('and nothing asked for it', h2.calls.every((u) => !u.endsWith('packages.tsv')), h2.calls.join(' '));
  }
  {
    await installGood();
    const doc = bundleDoc({ version: '2026.08.03' });
    doc.lists.malicious_packages.file = '../../../etc/passwd';
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('a sidecar name that is a path is refused', !r.ok && /is not a plain file name/.test(r.reason), r.reason);
  }
  {
    // The manifest is not signed, so nothing it says may end up recorded as fact. Here it claims a
    // version the bundle does not carry; the bundle is valid and applies, and what gets written
    // down has to be the bundle's version. Without this assertion the client could be talked into
    // believing it is newer than it is, and then refuse every genuine update as a rollback.
    reset();
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.02' })), manifest: { version: '2026.09.09' } });
    const r = await run(h, { force: true });
    ck('a bundle applies even when the manifest overstates the version', r.action === 'applied', r.reason);
    ck('the version recorded comes from the signed bundle, not the manifest', feed.cachedVersion() === '2026.08.02', String(feed.cachedVersion()));
    ck('the result reports the bundle version too', r.version === '2026.08.02', String(r.version));
  }

  section('missing: the feed is not there');
  {
    const version = await installGood();
    const h = serve({ manifestFail: 'Fetch failed or timed out' });
    const r = await run(h, { force: true });
    ck('an unreachable feed reports a failure', !r.ok && r.action === 'failed', r.reason);
    ck('the failure names the feed rather than blaming the rules', /could not reach the feed/.test(r.reason), r.reason);
    ck('the last good version is still installed', feed.cachedVersion() === version);
    ck('the last good bundle is still on disk', !!cachedText());
  }
  {
    // The manifest arrives and offers something newer, but the bundle download dies.
    await installGood();
    const h = serve({ bundleFail: 'Fetch failed or timed out' });
    const r = await run(h, { force: true });
    ck('a bundle that will not download is a failure, not an application', !r.ok && r.action === 'failed', r.reason);
    ck('the last good version survives a dead bundle download', feed.cachedVersion() === '2026.08.01');
  }

  section('malformed');
  {
    await installGood();
    const h = serve({ manifestText: 'this is not json' });
    const r = await run(h, { force: true });
    ck('a manifest that is not JSON is refused', !r.ok, r.reason);
    ck('the last good rules survive a malformed manifest', feed.cachedVersion() === '2026.08.01');
  }
  {
    await installGood();
    const h = serve({ bundleText: '{"schema":1,"version":', manifest: { version: '2026.08.02' } });
    const r = await run(h, { force: true });
    ck('a bundle that is not JSON is refused', !r.ok && r.action === 'refused', r.reason);
    ck('the last good version survives a truncated bundle', feed.cachedVersion() === '2026.08.01');
  }
  {
    await installGood();
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ schema: 99, version: '2026.08.02' })) });
    const r = await run(h, { force: true });
    ck('a bundle in a schema this client does not know is refused', !r.ok, r.reason);
    ck('the refusal says which schema it understands', /schema is 99/.test(r.reason), r.reason);
  }
  {
    await installGood();
    const doc = bundleDoc({ version: '2026.08.02' });
    doc.rulesets.injection = [];
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('a bundle that empties a ruleset is refused (a feed may not switch a detector off)',
      !r.ok && /may not switch a detector off/.test(r.reason), r.reason);
  }
  {
    await installGood();
    const doc = bundleDoc({ version: '2026.08.02' });
    doc.rulesets.secrets[0].value_group = 7;
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('a secret rule whose value group does not exist is refused', !r.ok && /value_group/.test(r.reason), r.reason);
  }
  {
    await installGood();
    const doc = bundleDoc({ version: '2026.08.02' });
    doc.lists.scam_addresses.entries = JSON.parse('{"__proto__":{"polluted":true}}');
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('a list keyed with __proto__ is refused', !r.ok && /__proto__/.test(r.reason), r.reason);
    ck('nothing was polluted', ({}).polluted === undefined);
  }

  section('tampered');
  {
    const version = await installGood();
    const good = JSON.stringify(bundleDoc({ version: '2026.08.02' }));
    // Same length, one character different: the signature is over bytes, so this is the realistic
    // attack shape rather than a truncation.
    const h = serve({ bundleText: good });
    h.fetchImpl = (url) => (url.includes('/api/rules/latest')
      ? Promise.resolve({ ok: true, text: JSON.stringify(h.manifest) })
      : Promise.resolve({ ok: true, text: good.replace('"critical"', '"criticaL"') }));
    const r = await run(h, { force: true });
    ck('a bundle whose bytes changed fails the hash', !r.ok && /SHA-256/.test(r.reason), r.reason);
    ck('the tampered bundle was not written', feed.cachedVersion() === version);
  }
  {
    await installGood();
    const text = JSON.stringify(bundleDoc({ version: '2026.08.02' }));
    const h = serve({ bundleText: text, manifest: { signature: sign('a different document entirely') } });
    const r = await run(h, { force: true });
    ck('a bundle with a signature over something else is refused', !r.ok && /signature did not verify/.test(r.reason), r.reason);
  }
  {
    await installGood();
    const other = crypto.generateKeyPairSync('ed25519');
    const text = JSON.stringify(bundleDoc({ version: '2026.08.02' }));
    const h = serve({ bundleText: text, manifest: { signature: crypto.sign(null, Buffer.from(text, 'utf8'), other.privateKey).toString('base64') } });
    const r = await run(h, { force: true });
    ck('a bundle signed by a key we do not trust is refused', !r.ok && /signature did not verify/.test(r.reason), r.reason);
    ck('the last good version is untouched after a forged bundle', feed.cachedVersion() === '2026.08.01');
  }
  {
    const text = JSON.stringify(bundleDoc());
    ck('a signature of the wrong length is refused without being handed to the verifier',
      feed.verifySignature(Buffer.from(text), Buffer.alloc(32).toString('base64'), TEST_KEYS) === false);
    ck('a valid signature verifies', feed.verifySignature(Buffer.from(text), sign(text), TEST_KEYS) === true);
    ck('every key compiled into this package imports as an Ed25519 public key',
      feed.TRUSTED_KEYS.every((k) => {
        try { return crypto.createPublicKey({ key: Buffer.from(k, 'base64'), format: 'der', type: 'spki' }).asymmetricKeyType === 'ed25519'; }
        catch { return false; }
      }));
  }

  section('rolled back');
  {
    await installGood('2026.08.05');
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.01' })) });
    const r = await run(h, { force: false });
    ck('an older version is not applied', !r.ok || r.action !== 'applied', r.reason);
    ck('the installed version is still the newer one', feed.cachedVersion() === '2026.08.05');
  }
  {
    await installGood('2026.08.05');
    // The manifest lies about the version to get past the cheap short-circuit; the bundle inside is
    // the old one. The decision has to be made on the signed document, not the manifest's claim.
    const old = JSON.stringify(bundleDoc({ version: '2026.08.01' }));
    const h = serve({ bundleText: old, manifest: { version: '2099.01.01' } });
    const r = await run(h, { force: true });
    ck('a manifest that lies about the version does not get an old bundle installed',
      !r.ok && r.action === 'refused' && /never rolled back/.test(r.reason), r.reason);
    ck('the installed version is still the newer one after a lying manifest', feed.cachedVersion() === '2026.08.05');
  }
  {
    await installGood('2026.08.05');
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.05' })) });
    const r = await run(h, { force: true });
    ck('the same version is reported as up to date, not reapplied', r.ok && r.action === 'up-to-date', r.reason);
  }
  {
    // `guard update` forces a pull past the TTL. It must NOT be able to downgrade: that is a
    // separate switch, and conflating the two was a real bug this assertion now pins.
    await installGood('2026.08.05');
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.01' })) });
    const r = await run(h, { force: true });
    ck('forcing a pull does not by itself allow a downgrade', r.action !== 'applied', r.reason);
    ck('the newer version survives a forced pull of an older one', feed.cachedVersion() === '2026.08.05');
  }
  {
    await installGood('2026.08.05');
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.01' })) });
    const r = await run(h, { force: true, allowRollback: true });
    ck('allowRollback does install an older version (the documented escape hatch)', r.ok && r.action === 'applied', r.reason);
    ck('and the older version is what is now recorded', feed.cachedVersion() === '2026.08.01');
  }

  section('oversized');
  {
    await installGood();
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.02' })), manifest: { bytes: schema.LIMITS.bundle_bytes + 1 } });
    const r = await run(h, { force: true });
    ck('a manifest offering a bundle over the size limit is refused before it is downloaded',
      !r.ok && /over the .* limit/.test(r.reason), r.reason);
    ck('the oversized bundle was never fetched', h.calls.every((u) => u.includes('/api/rules/latest')), h.calls.join(' '));
  }
  {
    await installGood();
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.02' })), truncated: true });
    const r = await run(h, { force: true });
    ck('a bundle that hit the byte cap mid-download is refused', !r.ok && /larger than/.test(r.reason), r.reason);
  }
  {
    const big = 'x'.repeat(schema.LIMITS.bundle_bytes + 10);
    const v = schema.validate(big);
    ck('the validator refuses oversized text outright', !v.ok && /over the/.test(v.errors[0]), v.errors[0]);
  }

  section('hostile: where the manifest points');
  {
    await installGood();
    const h = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.02' })), manifest: { url: 'https://evil.example.com/bundle.json' } });
    const r = await run(h, { force: true });
    ck('a bundle URL on a host we do not fetch rules from is refused',
      !r.ok && r.action === 'refused' && /not a host this client will fetch rules from/.test(r.reason), r.reason);
    ck('the hostile host was never contacted', h.calls.every((u) => !u.includes('evil.example.com')), h.calls.join(' '));
  }
  {
    await installGood();
    const h = serve({ manifest: { url: 'http://raw.githubusercontent.com/x' } });
    const r = await run(h, { force: true });
    ck('a plain-http bundle URL is refused', !r.ok && /https bundle URL/.test(r.reason), r.reason);
  }
  {
    await installGood();
    const h = serve({ manifest: { url: 'file:///etc/passwd' } });
    const r = await run(h, { force: true });
    ck('a non-http scheme is refused', !r.ok && r.action === 'refused', r.reason);
  }

  section('expensive: a pattern that would hang the client');
  {
    await installGood();
    const doc = bundleDoc({ version: '2026.08.02' });
    // Passes the static lint (no nested quantifier) and is catastrophic anyway. The bounded
    // execution gate is what has to catch this one.
    doc.rulesets.injection.push({ id: 'slow', category: 'test', weight: 10, pattern: '^(a|a)+$', flags: '' });
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('a catastrophically backtracking pattern is refused', !r.ok && /ReDoS/.test(r.reason), r.reason);
    ck('the refusal names the offending rule', /injection:slow/.test(r.reason), r.reason);
    ck('the last good rules are still installed after a hostile pattern', feed.cachedVersion() === '2026.08.01');
  }
  {
    await installGood();
    const doc = bundleDoc({ version: '2026.08.02' });
    doc.rulesets.code.push({ id: 'nested', category: 'test', severity: 'low', language: 'any', pattern: '(x+)+y', flags: '', message: 'm' });
    const h = serve({ bundleText: JSON.stringify(doc) });
    const r = await run(h, { force: true });
    ck('a nested unbounded quantifier is refused by the static lint', !r.ok && /nested unbounded quantifier/.test(r.reason), r.reason);
  }

  section('the ReDoS gate itself');
  {
    // validate() is synchronous and is what loads the cached bundle off disk on every start, where
    // there is no room to spawn a worker. So the cheap static lint has to reject a catastrophic
    // pattern on its own, without the bounded-execution gate behind it.
    const doc = bundleDoc();
    doc.rulesets.code.push({ id: 'nested', category: 'test', severity: 'low', language: 'any', pattern: '(x+)+y', flags: '', message: 'm' });
    const v = schema.validate(JSON.stringify(doc));
    ck('the synchronous validator alone rejects a nested unbounded quantifier',
      !v.ok && v.errors.some((e) => /nested unbounded quantifier/.test(e)), (v.errors || []).join('; '));
    ck('and it accepts the same bundle without that rule', schema.validate(JSON.stringify(bundleDoc())).ok);
  }
  {
    ck('the lint flags (a+)+', redos.lint('^(a+)+$').ok === false);
    ck('the lint flags ([a-z]*)+', redos.lint('([a-z]*)+').ok === false);
    ck('the lint allows a bounded group like (all\\s+)?', redos.lint('(all\\s+)?instruction').ok === true);
    ck('the lint allows a plain alternation under a star', redos.lint('^(a|b)*$').ok === true);
    ck('the lint refuses an unbalanced pattern', redos.lint('(abc').ok === false);
    const shipped = [
      ...INJECTION_RULES.map((r) => ({ id: `injection:${r.id}`, source: r.re.source, flags: r.re.flags })),
      ...SECRET_RULES.map((r) => ({ id: `secrets:${r.id}`, source: r.re.source, flags: r.re.flags })),
      ...PII_RULES.map((r) => ({ id: `pii:${r.id}`, source: r.re.source, flags: r.re.flags })),
      ...CODE_RULES.map((r) => ({ id: `code:${r.id}`, source: r.re.source, flags: r.re.flags })),
    ];
    const gate = await redos.checkPatterns(shipped);
    ck(`all ${shipped.length} patterns this package ships pass its own ReDoS gate`, gate.ok,
      gate.failures.map((f) => `${f.id}: ${f.reason}`).join('; '));
    const bad = await redos.checkPatterns([{ id: 'known-bad', source: '^(a+)+$', flags: '' }]);
    ck('the gate rejects a known-catastrophic pattern', !bad.ok && bad.failures[0].id === 'known-bad');
  }

  section('turning it off');
  {
    reset();
    const h = serve({});
    const r = await run(h, { force: true, offline: true });
    ck('--offline skips the pull', !r.ok && r.action === 'skipped' && /offline/.test(r.reason), r.reason);
    ck('nothing was fetched in offline mode', h.calls.length === 0);
  }
  {
    reset();
    process.env.AGENT_GUARDS_NO_FEED = '1';
    const h = serve({});
    const r = await run(h, { force: true });
    delete process.env.AGENT_GUARDS_NO_FEED;
    ck('AGENT_GUARDS_NO_FEED skips the pull', r.action === 'skipped' && /AGENT_GUARDS_NO_FEED/.test(r.reason), r.reason);
    ck('nothing was fetched with the environment variable set', h.calls.length === 0);
  }
  {
    reset();
    process.env.AGENT_GUARDS_NO_FEED = '0';
    const h = serve({});
    const r = await run(h, { force: true });
    delete process.env.AGENT_GUARDS_NO_FEED;
    ck('AGENT_GUARDS_NO_FEED=0 means off, not on', r.action === 'applied', r.reason);
  }
  {
    reset();
    fs.mkdirSync(HOME, { recursive: true });
    fs.writeFileSync(path.join(HOME, 'config.json'), JSON.stringify({ feed: false }));
    const h = serve({});
    const r = await run(h, { force: true });
    fs.rmSync(path.join(HOME, 'config.json'), { force: true });
    ck('feed:false in config.json skips the pull', r.action === 'skipped' && /config\.json/.test(r.reason), r.reason);
  }

  section('what the pull carries, and how often');
  {
    reset();
    const h = serve({});
    await run(h, { force: true, surface: 'plugin' });
    const asked = h.calls.find((u) => u.includes('/api/rules/latest'));
    ck('the pull carries the surface tag', /surface=plugin/.test(asked), asked);
    ck('the pull carries the version already installed', /have=none/.test(asked), asked);
    ck('the pull carries nothing else', new URL(asked).searchParams.size === 2, asked);
    const h2 = serve({ bundleText: JSON.stringify(bundleDoc({ version: '2026.08.09' })) });
    await run(h2, { force: true, surface: 'mcp' });
    const asked2 = h2.calls.find((u) => u.includes('/api/rules/latest'));
    ck('a later pull reports the version it now has', /have=2026\.08\.02/.test(asked2), asked2);
  }
  {
    reset();
    const h = serve({});
    const first = await run(h, { force: true });
    const second = await run(h, { force: false });
    ck('the first pull applies', first.action === 'applied', first.reason);
    ck('a second pull inside the TTL does not go out again', second.action === 'skipped' && /recently/.test(second.reason), second.reason);
    // Three from the first pull: manifest, bundle, package list. The second pull adds nothing.
    ck('and it did not touch the network', h.calls.length === 3, h.calls.join(' '));
    const later = await run(h, { force: false, now: Date.now() + 31 * 3600 * 1000 });
    ck('a pull after the TTL does go out again', later.action !== 'skipped', later.reason);
  }
  {
    const st = { last_attempt: new Date(Date.now() - 25 * 3600 * 1000).toISOString() };
    const due = feed.dueForPull(st, Date.now());
    const notDue = feed.dueForPull({ last_attempt: new Date().toISOString() }, Date.now());
    ck('the TTL has jitter on top of a day, so 25 hours may or may not be due', typeof due === 'boolean');
    ck('a pull one second ago is never due', notDue === false);
  }

  section('the local cache is not trusted either');
  {
    await installGood();
    fs.writeFileSync(feed.bundlePath(), '{"schema":1,"version":"2026.09.09"');
    ck('a corrupted cache file loads as no rules rather than throwing', feed.loadCached() === null);
  }

  done('feed');
})().catch((e) => { console.error(e); process.exit(1); });
