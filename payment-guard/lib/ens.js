// ENS name resolution (Ethereum mainnet) — name -> address. Correct keccak256 via js-sha3.
const { keccak256 } = require('js-sha3');
const { rpc, isEvmAddress } = require('./risk.js');

const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

function namehash(name) {
  let node = '00'.repeat(32);
  if (name) {
    const labels = String(name).toLowerCase().trim().split('.');
    for (let i = labels.length - 1; i >= 0; i--) {
      const labelHash = keccak256(labels[i]);                       // hex of utf8 label
      node = keccak256(Buffer.from(node + labelHash, 'hex'));       // keccak of concatenated 64 bytes
    }
  }
  return node; // 64 hex chars, no 0x
}

const looksLikeEns = (s) => typeof s === 'string' && /\.[a-z0-9-]+$/i.test(s) && !isEvmAddress(s);

async function ensResolve(name) {
  if (!looksLikeEns(name)) return null;
  try {
    const node = namehash(name);
    const resolverRet = await rpc('eth', 'eth_call', [{ to: ENS_REGISTRY, data: '0x0178b8bf' + node }, 'latest']);
    if (!resolverRet || resolverRet === '0x') return null;
    const resolver = '0x' + resolverRet.slice(-40);
    if (/^0x0+$/.test(resolver)) return null;
    const addrRet = await rpc('eth', 'eth_call', [{ to: resolver, data: '0x3b3b57de' + node }, 'latest']);
    if (!addrRet || addrRet === '0x') return null;
    const address = '0x' + addrRet.slice(-40);
    if (!isEvmAddress(address) || /^0x0+$/.test(address)) return null;
    return address;
  } catch { return null; }
}

module.exports = { namehash, ensResolve, looksLikeEns };
