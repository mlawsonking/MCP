// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/engines/ens.js
// Regenerate: node scripts/sync-shared.js
// ENS name resolution (Ethereum mainnet) — name -> address. Correct keccak256 via js-sha3.
//
// keccak256 is not the SHA3-256 in node:crypto: Ethereum kept the original Keccak padding, so the
// built-in gives a different digest and every namehash would be wrong. js-sha3 is loaded lazily so a
// missing or broken install degrades into an honest "could not check" instead of crashing the caller
// or, worse, resolving to nothing and being read as "this name is not registered".
const { rpc, isEvmAddress } = require('./payments');

const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

let _keccak;
function keccak() {
  if (_keccak === undefined) {
    try { _keccak = require('js-sha3').keccak256; } catch { _keccak = null; }
  }
  return _keccak;
}

function namehash(name) {
  const k = keccak();
  if (!k) throw new Error('js-sha3 is not installed, so ENS names cannot be hashed');
  let node = '00'.repeat(32);
  if (name) {
    const labels = String(name).toLowerCase().trim().split('.');
    for (let i = labels.length - 1; i >= 0; i--) {
      const labelHash = k(labels[i]);                       // hex of utf8 label
      node = k(Buffer.from(node + labelHash, 'hex'));       // keccak of concatenated 64 bytes
    }
  }
  return node; // 64 hex chars, no 0x
}

const looksLikeEns = (s) => typeof s === 'string' && /\.[a-z0-9-]+$/i.test(s) && !isEvmAddress(s);

// The detailed form distinguishes the three outcomes a caller needs to tell apart:
//   { ok: true,  address }            resolved
//   { ok: true,  address: null }      looked it up, the name has no address
//   { ok: false, error }              could not look it up — NOT the same as "no address"
// A caller that treats the third case as the second says "this name is unregistered" when it means
// "the RPC was down", which is the fail-open class this project keeps hunting.
async function ensResolveDetailed(name) {
  if (!looksLikeEns(name)) return { ok: true, address: null, note: 'not an ENS-shaped name' };
  if (!keccak()) return { ok: false, address: null, error: 'js-sha3 unavailable, cannot compute namehash' };
  try {
    const node = namehash(name);
    const resolverRet = await rpc('eth', 'eth_call', [{ to: ENS_REGISTRY, data: '0x0178b8bf' + node }, 'latest']);
    if (resolverRet === null || resolverRet === undefined) return { ok: false, address: null, error: 'ENS registry call failed' };
    if (resolverRet === '0x') return { ok: true, address: null, note: 'no resolver set' };
    const resolver = '0x' + resolverRet.slice(-40);
    if (/^0x0+$/.test(resolver)) return { ok: true, address: null, note: 'no resolver set' };
    const addrRet = await rpc('eth', 'eth_call', [{ to: resolver, data: '0x3b3b57de' + node }, 'latest']);
    if (addrRet === null || addrRet === undefined) return { ok: false, address: null, error: 'ENS resolver call failed' };
    if (addrRet === '0x') return { ok: true, address: null, note: 'resolver returned no address' };
    const address = '0x' + addrRet.slice(-40);
    if (!isEvmAddress(address) || /^0x0+$/.test(address)) return { ok: true, address: null, note: 'resolver returned the zero address' };
    return { ok: true, address };
  } catch (e) {
    return { ok: false, address: null, error: String((e && e.message) || e) };
  }
}

// Kept exactly as it was: returns the address or null. Existing callers depend on this signature.
async function ensResolve(name) {
  const r = await ensResolveDetailed(name);
  return r.address || null;
}

module.exports = { namehash, ensResolve, ensResolveDetailed, looksLikeEns };
