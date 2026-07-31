# The rules feed

This directory is the rules that agent-guards runs. A scheduled job rebuilds it from its upstream
sources, signs it, and commits it here. Installed copies pull it about once a day and apply it if it
verifies.

You can read every rule in `bundle.json`. That is deliberate. If a check flags your code you should
be able to find the exact pattern that did it without asking me.

## What is here

| File | What it is |
|---|---|
| `bundle.json` | The rules and the small intel lists. 266 KB. |
| `bundle.json.sig` | A detached Ed25519 signature over `bundle.json`'s exact bytes, base64. |
| `manifest.json` | The 1.7 KB pointer a client fetches first: version, size, hash, signature, and where the bundle is. |
| `packages.tsv` | The known-malicious package list. 9.5 MB, too big to sit inside the JSON. |
| `CHANGELOG.md` | What changed in each version, written by the build. |

The current bundle is `2026.07.31`: 11 injection rules, 22 secret patterns, 3 PII patterns, 31 code
rules, 100 sanctioned addresses, 3,182 scam addresses, and 228,339 malicious packages.

Versions are dates. `2026.07.31`, and `2026.07.31.1` if a second one goes out the same day. A client
will not install a version older than or equal to the one it already has unless you pass
`--allow-rollback`.

## Rules are data, never code

The bundle carries pattern source strings. Nothing in it is ever `eval`'d, `require`'d, or turned
into a function. The only thing a client does with a pattern is `new RegExp(source, flags)`, and only
after the pattern has passed a ReDoS check.

That check matters more than it looks. A regex delivered over a feed runs on every client's hot path
against text the client did not choose, so a pattern that backtracks catastrophically is a denial of
service that needs no exploit beyond publishing it. JavaScript has no regex timeout, so the only way
to bound one is to run it somewhere you can kill. Both the publisher and the client run every pattern
in a worker thread against pump strings built from the pattern's own alphabet, and terminate it if it
runs past its budget. Measured before it was relied on: `worker.terminate()` interrupts a regex
already spinning inside V8 in about 4 milliseconds.

The client runs that check itself rather than trusting that I ran it. The bundle is remote input.

## Verifying a bundle yourself

The public key is in `agent-guards/lib/feed.js` as `TRUSTED_KEYS`. It is the SPKI form, base64:

```
MCowBQYDK2VwAyEA/9neavSj1zSMlyMVmrV8OOWPIP8B0JqMRAiGES2r0BU=
```

To check the signature with nothing but Node:

```bash
node -e "const c=require('crypto'),f=require('fs');const k=c.createPublicKey({key:Buffer.from('MCowBQYDK2VwAyEA/9neavSj1zSMlyMVmrV8OOWPIP8B0JqMRAiGES2r0BU=','base64'),format:'der',type:'spki'});console.log(c.verify(null,f.readFileSync('bundle.json'),k,Buffer.from(f.readFileSync('bundle.json.sig','utf8').trim(),'base64')))"
```

That prints `true` for a bundle I published and `false` for anything else, including one byte of
whitespace changed.

The private key lives in a GitHub Actions secret and nowhere else. It is not on my machine and it is
not in this repository. If it ever leaks, the fix is a new key added to the front of `TRUSTED_KEYS`
in a release, and the old one removed in a later one so nobody is stranded mid-upgrade.

## What a client checks, in order

1. Fetch `manifest.json`. It names the bundle URL, size, SHA-256 and signature.
2. Refuse a bundle URL that is not HTTPS on a known host. The manifest is not signed, so without
   this a tampered one could point a client at any URL it liked.
3. Refuse a bundle bigger than 12 MB, before downloading it.
4. Check the SHA-256 of what arrived against the manifest.
5. Verify the Ed25519 signature.
6. Validate against the schema: field by field, bounded lengths, no key named `__proto__`, and a
   refusal if any ruleset arrived empty. A feed is not allowed to switch a detector off.
7. Run every pattern through the ReDoS gate.
8. Compare versions. The version used is the one **inside the signed bundle**, never the manifest's
   claim, so a lying manifest cannot talk a client into thinking it is newer than it is.
9. Download `packages.tsv` if its SHA-256 changed. That hash is inside the signed bundle, so one
   signature covers both files.

A failure at any step leaves the client on the rules it already had, and says so. It does not fall
back to nothing, and it does not stop guarding because an update failed.

## The package list

`packages.tsv` is every non-withdrawn `MAL-` advisory OSV publishes for npm and PyPI, one package per
line, sorted, tab separated:

```
npm	axios	0.30.4,1.14.1	MAL-2026-2307
npm	cxp-jquery	*	MAL-2021-1
pypi	evil-pkg	1.0.0	MAL-2025-0002
```

`*` means every version of that package is malicious. A version list means only those versions are.

That distinction is the reason this is not a list of names. OSV's npm export is 213 MB and its PyPI
export is 31 MB; what the build drops is every advisory body, not any package. But 42 of the 3,000
most-installed npm packages appear on this list, including `debug`, `chalk`, `axios` and `ansi-styles`
from the September 2025 npm worm, because they were compromised at specific versions and then fixed.
A names-only list would report `npm install debug` as installing malware. So:

- exact version on the list: malicious.
- name on the list, your version is not: caution, and the output names the versions that are.
- no version given: caution, same.

Withdrawn advisories are excluded. An advisory the maintainers retracted is not evidence of anything
and publishing it would be accusing a package of something its own advisory took back.

Nothing is loaded to search this file. It is sorted, and lookups binary-search it on disk, which is
four or five reads and no parse. That is why it is a separate file: parsing 9.5 MB before every
`npm install` would cost more than the check is worth.

## Stale sources

Every source the build touched is listed in `sources`, with `ok: false` and an age in days if it
could not be refreshed. When that happens the previous contents are carried forward and every
surface says the list is stale.

I care about this one more than the rest. A sanctions list served quietly as fresh when it is a week
old is the worst thing this project could ship, because it produces a confident "not sanctioned" from
a check that did not really run. If a source is stale you will see it in `guard update --status`, in
the feed endpoint's `stale_sources`, and in the commit message.

## What a pull sends

Two things: which surface asked (`cli`, `plugin`, `mcp` or `facade`) and the rules version you
already have.

```
GET /api/rules/latest?surface=cli&have=2026.07.31
```

No machine id, no user id, no file names, nothing you scanned. I count those pulls to know whether
anyone is still using this, and that is all they are for.

To stop it entirely, any one of:

```bash
export AGENT_GUARDS_NO_FEED=1
```

`--offline` on any command, or `{"feed": false}` in `~/.agent-guards/config.json`. Point it somewhere
else with `AGENT_GUARDS_FEED_URL`.

With updates off, everything still works. The rules compiled into the package are the floor, and they
are the same rules that were current when you installed it.

## What is not in the feed

The Unicode obfuscation signals, the package-name heuristics, and the popular-package lists ship with
the package and do not update over the feed. The first are properties of Unicode rather than
patterns, and the other two are algorithms with data attached rather than data. Saying an update
refreshed them would overstate what it did.

## Building it yourself

```bash
node scripts/build-rules-bundle.js
node scripts/sign-rules-bundle.js
node scripts/verify-rules-bundle.js
```

The build downloads about 245 MB from OSV and refuses to write anything if a pattern fails the ReDoS
gate or the result fails the client's own validator. The verify step installs what was built through
the real client, then tampers with it and checks the client refuses.
