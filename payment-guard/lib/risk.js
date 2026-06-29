// Payment Guard risk helpers — OFAC sanctioned addresses + scam lists + on-chain reads. All free, $0.
// EVM-first (ETH/Base/Polygon/Arbitrum/Optimism — where x402/USDC lives). No LLM, no paid data.

const CHAINS = {
  eth: { name: 'Ethereum', rpc: ['https://ethereum-rpc.publicnode.com', 'https://eth.llamarpc.com', 'https://1rpc.io/eth'] },
  base: { name: 'Base', rpc: ['https://base-rpc.publicnode.com', 'https://mainnet.base.org'] },
  polygon: { name: 'Polygon', rpc: ['https://polygon-bor-rpc.publicnode.com', 'https://polygon-rpc.com'] },
  arbitrum: { name: 'Arbitrum', rpc: ['https://arbitrum-one-rpc.publicnode.com', 'https://arb1.arbitrum.io/rpc'] },
  optimism: { name: 'Optimism', rpc: ['https://optimism-rpc.publicnode.com', 'https://mainnet.optimism.io'] },
};
const isEvmAddress = (a) => typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a);

async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal, headers: { 'User-Agent': 'payment-guard/1.0', ...(opts.headers || {}) } }); }
  finally { clearTimeout(t); }
}

// ---- OFAC-sanctioned crypto addresses (public-domain SDN data; community mirror, auto-updated) ----
let _ofac = { set: null, at: 0 };
async function ofacSanctionedSet() {
  if (_ofac.set && Date.now() - _ofac.at < 6 * 3600_000) return _ofac.set;
  try {
    const r = await fetchWithTimeout('https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt');
    if (!r.ok) return _ofac.set;
    const txt = await r.text();
    const set = new Set(txt.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter((l) => /^0x[0-9a-f]{40}$/.test(l)));
    if (set.size) { _ofac = { set, at: Date.now() }; }
    return _ofac.set;
  } catch { return _ofac.set; }
}

// ---- Scam / abuse address blocklist (multi-source: ethereum-lists darklist + ScamSniffer) ----
let _scam = { map: null, at: 0 };
async function scamList() {
  if (_scam.map && Date.now() - _scam.at < 6 * 3600_000) return _scam.map;
  const map = new Map();
  // Source 1: MyEtherWallet/ethereum-lists darklist (address + comment)
  try {
    const r = await fetchWithTimeout('https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json');
    if (r.ok) { const arr = await r.json(); for (const e of arr) if (e && e.address) map.set(String(e.address).toLowerCase(), e.comment || 'ethereum-lists darklist'); }
  } catch {}
  // Source 2: ScamSniffer blacklist (array of addresses)
  try {
    const r = await fetchWithTimeout('https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json');
    if (r.ok) { const arr = await r.json(); for (const a of arr) { const k = String(a).toLowerCase(); if (/^0x[0-9a-f]{40}$/.test(k) && !map.has(k)) map.set(k, 'ScamSniffer blacklist'); } }
  } catch {}
  if (map.size) { _scam = { map, at: Date.now() }; return map; }
  return _scam.map; // keep last good cache if both fetches failed
}

// ---- On-chain reads via free public RPC ----
async function rpc(chain, method, params) {
  const c = CHAINS[chain];
  if (!c) return null;
  for (const url of c.rpc) {
    try {
      const r = await fetchWithTimeout(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }, 7000);
      if (!r.ok) continue;
      const j = await r.json();
      if (j && j.result !== undefined) return j.result;
    } catch {}
  }
  return null;
}

async function onchain(chain, address) {
  const [code, nonceHex, balHex] = await Promise.all([
    rpc(chain, 'eth_getCode', [address, 'latest']),
    rpc(chain, 'eth_getTransactionCount', [address, 'latest']),
    rpc(chain, 'eth_getBalance', [address, 'latest']),
  ]);
  if (code === null && nonceHex === null && balHex === null) return null; // RPC unavailable
  const isContract = !!code && code !== '0x' && code !== '0x0';
  const txCount = nonceHex ? parseInt(nonceHex, 16) : 0;
  let balanceWei = 0n;
  try { balanceWei = balHex ? BigInt(balHex) : 0n; } catch {}
  return { isContract, txCount, hasBalance: balanceWei > 0n, balanceEth: Number(balanceWei) / 1e18 };
}

module.exports = { CHAINS, isEvmAddress, fetchWithTimeout, ofacSanctionedSet, scamList, rpc, onchain };
