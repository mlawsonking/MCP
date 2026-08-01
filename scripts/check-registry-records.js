#!/usr/bin/env node
// Validates the seven server.json registry records BEFORE a publish, not during one.
//
// Why this exists: publishing to the MCP registry needs the owner to paste a fresh GitHub PAT, and
// the token expires in about an hour, so a publish run is a scarce, manual, interactive thing. Every
// precondition that can be checked locally should be, or a whole session gets burned discovering one
// of them. This has already happened: a 1.1.0 publish run failed on `description` being 112
// characters against a 100-character limit, which was sitting in the repo the whole time.
//
// Checked here, all of which have bitten at least once:
//   - description length (registry rejects over 100 with a 422)
//   - the three version fields moving in lockstep (package.json, server.json, packages[0].version)
//   - repository.subfolder present (its absence collapsed the facade entries into one on Glama)
//   - packages[0].identifier matching the real npm name (three of these differ from the folder name)
//
//   node scripts/check-registry-records.js

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const MAX_DESCRIPTION = 100;

// folder -> where its server.json lives. web-tools' record is at the repo root, not in its folder,
// which is a trap every publish run has to remember.
const RECORDS = [
  { folder: 'agent-guards', record: 'agent-guards/server.json' },
  { folder: 'package-guard-mcp', record: 'package-guard-mcp/server.json' },
  { folder: 'agent-firewall-mcp', record: 'agent-firewall-mcp/server.json' },
  { folder: 'payment-guard-mcp', record: 'payment-guard-mcp/server.json' },
  { folder: 'email-guard-mcp', record: 'email-guard-mcp/server.json' },
  { folder: 'code-guard-mcp', record: 'code-guard-mcp/server.json' },
  { folder: 'agent-tools-mcp', record: 'server.json' },
];

const problems = [];
const read = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));

for (const { folder, record } of RECORDS) {
  const pkg = read(path.posix.join(folder, 'package.json'));
  const srv = read(record);
  const where = `${record}`;

  const desc = srv.description || '';
  if (desc.length > MAX_DESCRIPTION) {
    problems.push(`${where}: description is ${desc.length} chars, limit is ${MAX_DESCRIPTION}. The registry rejects this with a 422.`);
  }

  const nested = srv.packages && srv.packages[0];
  if (!nested) {
    problems.push(`${where}: no packages[0] entry`);
  } else {
    if (nested.version !== srv.version || srv.version !== pkg.version) {
      problems.push(`${where}: versions out of lockstep - package.json ${pkg.version}, server.json ${srv.version}, packages[0] ${nested.version}`);
    }
    if (nested.identifier !== pkg.name) {
      problems.push(`${where}: packages[0].identifier is "${nested.identifier}" but the npm name is "${pkg.name}"`);
    }
  }

  if (!srv.repository || !srv.repository.subfolder) {
    problems.push(`${where}: repository.subfolder is missing. Without it the registry cannot tell the six apart in a monorepo.`);
  }
  if (pkg.mcpName && srv.name !== pkg.mcpName) {
    problems.push(`${where}: server.json name "${srv.name}" does not match package.json mcpName "${pkg.mcpName}"`);
  }
}

if (problems.length) {
  console.error('Registry records are not ready to publish:\n' + problems.map((p) => '  ' + p).join('\n'));
  process.exit(1);
}
console.log(`registry records ready to publish (${RECORDS.length} checked: description length, version lockstep, subfolder, npm identifier)`);
