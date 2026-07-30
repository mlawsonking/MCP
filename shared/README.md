# shared/lib

The source of truth for the helper modules every product uses.

- `common.js` — `sendJson`, `handleOptions`, `safeFetch` (the SSRF guard), the `track` usage beacon,
  `upgradeInfo`. Copied into 6 products.
- `safety.js` — the injection ruleset, secret and PII rules, `analyzeUrl`, domain age. Copied into 4.

## Edit here, then run the sync

```bash
node scripts/sync-shared.js
```

Every `<product>/lib/common.js` and `<product>/lib/safety.js` is a generated copy with a banner saying
so. Editing one of those directly gets your change overwritten.

CI runs `node scripts/sync-shared.js --check`, which fails the build if any copy has drifted.

## Why copies instead of a require or a package

Each product folder is its own Vercel project, deployed with `vercel --prod` from inside that folder.
Vercel only bundles files under the project root, so `require('../../shared/lib/common.js')` would work
on a laptop and break in production. Committing generated copies keeps deploys working while leaving
exactly one file to edit.

The alternative, publishing these to npm, would mean a publish (owner OTP) for every one-line change to
a regex. Not worth it at this size.
