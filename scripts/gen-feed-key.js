#!/usr/bin/env node
// Generate the Ed25519 keypair the rules feed is signed with.
//
// Run once. It prints the PUBLIC key, which belongs in agent-guards/lib/feed.js as a trusted key,
// and writes the PRIVATE key to rules/feed-private-key.pem, which is gitignored. The private key is
// never printed: the terminal it would land in has scrollback, and PSReadLine keeps history.
//
// The owner then puts the private key into the repository's Actions secret and deletes the file:
//
//   gh secret set RULES_SIGNING_KEY < rules/feed-private-key.pem
//   Remove-Item rules/feed-private-key.pem
//
// Refuses to overwrite an existing key file, because doing so would strand every client that
// trusts the old public key.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUT = path.join(__dirname, '..', 'rules', 'feed-private-key.pem');

if (fs.existsSync(OUT)) {
  console.error(`${OUT} already exists. Delete it deliberately if you really mean to rotate the key.`);
  process.exit(1);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });

const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

console.log(`private key written to ${OUT} (gitignored, mode 600)`);
console.log('');
console.log('public key, for the TRUSTED_KEYS list in agent-guards/lib/feed.js:');
console.log('');
console.log(`  '${spki}',`);
console.log('');
console.log('Next: put the private key in the Actions secret and delete the local copy.');
console.log('  gh secret set RULES_SIGNING_KEY < rules/feed-private-key.pem');
console.log('  Remove-Item rules/feed-private-key.pem');
