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
// OFAC tags SDN crypto addresses by CURRENCY, not by chain. We ingest every upstream list that
// publishes EVM-format addresses (0x + 40 hex) and union them, because an address on the SDN list
// is sanctioned whichever EVM chain you send on. Checking only the ETH list missed 4 sanctioned
// addresses that appear under ARB/BSC/USDC/USDT — see test/local.cjs OFAC_FIXTURES.
// Lists in non-EVM formats (BTC, TRX, SOL, XMR, ZEC, LTC, ...) are deliberately not ingested:
// this API only accepts EVM addresses, so they could never match.
const OFAC_LIST_BASE = 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_';
const OFAC_EVM_LISTS = ['ETH', 'ARB', 'BSC', 'ETC', 'USDC', 'USDT'];
const OFAC_NOT_CHECKED = ['BTC', 'XBT', 'TRX', 'SOL', 'XMR', 'ZEC', 'LTC', 'DASH', 'XRP', 'BCH', 'BSV', 'BTG', 'XVG'];

// What the sanctions check actually covers. Attached to every response that reports on it, so the
// caller never has to guess what "not sanctioned" was measured against.
function ofacCoverage(loadedLists) {
  return {
    list: 'OFAC SDN sanctioned digital-currency addresses',
    source: 'https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses',
    address_format: 'evm',
    lists_ingested: OFAC_EVM_LISTS,
    lists_loaded: loadedLists || [],
    chains: 'Every EVM chain. OFAC lists addresses by currency, not by chain, so one EVM address list applies to eth, base, polygon, arbitrum and optimism alike.',
    not_checked: OFAC_NOT_CHECKED,
    note: 'Only EVM (0x) addresses are checked. Bitcoin, Tron, Solana, Monero and other non-EVM sanctioned addresses are on the SDN list but this API cannot accept them. A "not sanctioned" result means the address is absent from the EVM lists above, nothing more.',
  };
}

// A complete load is good for 6 hours. A partial one is cached far more briefly: the union is built
// from whichever lists answered, so caching a partial result for 6 hours would turn one transient
// fetch failure into six hours of quietly narrowed sanctions coverage.
const OFAC_TTL_MS = 6 * 3600_000;
const OFAC_PARTIAL_TTL_MS = 5 * 60_000;

let _ofac = { set: null, at: 0, lists: [] };
async function ofacSanctions() {
  const ttl = _ofac.lists.length === OFAC_EVM_LISTS.length ? OFAC_TTL_MS : OFAC_PARTIAL_TTL_MS;
  if (_ofac.set && Date.now() - _ofac.at < ttl) return _ofac;
  const results = await Promise.all(OFAC_EVM_LISTS.map(async (name) => {
    try {
      const r = await fetchWithTimeout(`${OFAC_LIST_BASE}${name}.txt`);
      if (!r.ok) return null;
      const txt = await r.text();
      // Non-EVM entries live in some of these files (USDT carries Tron addresses); the regex drops them.
      const addrs = txt.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter((l) => /^0x[0-9a-f]{40}$/.test(l));
      return { name, addrs };
    } catch { return null; }
  }));
  const ok = results.filter(Boolean);
  if (!ok.length) return _ofac; // total failure: keep the last good cache (may be empty)
  const set = new Set();
  for (const l of ok) for (const a of l.addrs) set.add(a);
  if (set.size) _ofac = { set, at: Date.now(), lists: ok.map((l) => l.name) };
  return _ofac;
}

// Kept for callers that only need membership.
async function ofacSanctionedSet() { return (await ofacSanctions()).set; }

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

// ---- Token honeypot / tax / risk (honeypot.is — free, no key; simulates a buy+sell) ----
// honeypot.is answers for Ethereum and Base. It returns 400 "Invalid chain" for Polygon, Arbitrum and
// Optimism, so the honeypot and tax fields can never be populated there. Callers are told rather than
// left to infer it from a missing key.
const CHAIN_ID = { eth: 1, base: 8453, polygon: 137, arbitrum: 42161, optimism: 10 };
const HONEYPOT_CHAINS = ['eth', 'base'];
async function honeypotCheck(chain, address) {
  const id = CHAIN_ID[chain];
  if (!id) return null;
  try {
    const r = await fetchWithTimeout(`https://api.honeypot.is/v2/IsHoneypot?address=${address}&chainID=${id}`, {}, 9000);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// Test seam: the list caches are module state, so a suite that simulates an outage has to be able to
// clear them or it just re-reads whatever a previous test warmed up.
function _resetCachesForTests() { _ofac = { set: null, at: 0, lists: [] }; _scam = { map: null, at: 0 }; }

module.exports = { CHAINS, CHAIN_ID, HONEYPOT_CHAINS, isEvmAddress, fetchWithTimeout, ofacSanctions, ofacSanctionedSet, ofacCoverage, OFAC_EVM_LISTS, scamList, rpc, onchain, honeypotCheck, _resetCachesForTests };
