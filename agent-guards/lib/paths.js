// Where agent-guards keeps its local state.
//
// One directory, in the user's home, holding two things: the ledger of what was checked and a cache
// of verdicts that were expensive to get. Nothing here is ever uploaded and nothing here is read by
// anything but this machine.
//
// AGENT_GUARDS_HOME overrides the location. The tests set it so a test run never touches the real
// ledger, and it gives anyone who wants their state somewhere else a way to say so.

const os = require('os');
const path = require('path');
const fs = require('fs');

function home() {
  const override = process.env.AGENT_GUARDS_HOME;
  if (override && String(override).trim()) return path.resolve(String(override).trim());
  return path.join(os.homedir(), '.agent-guards');
}

function ledgerPath() { return path.join(home(), 'ledger.jsonl'); }
function cachePath() { return path.join(home(), 'cache', 'packages.json'); }

// Create the directory on demand. Returns false rather than throwing: a guard that cannot write its
// ledger still has to run the check.
function ensureDir(dir) {
  try { fs.mkdirSync(dir, { recursive: true }); return true; }
  catch { return false; }
}

module.exports = { home, ledgerPath, cachePath, ensureDir };
