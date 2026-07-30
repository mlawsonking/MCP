#!/usr/bin/env node
// payment-guard-mcp — MCP server: the pre-send risk check for AI agents that move money.
// Tools call the live Payment Guard API (OFAC + scam lists + on-chain + ENS). Deterministic, no LLM.
//   screen_address   -> the guard: address/ENS -> sanctioned? scam? on-chain risk -> verdict
//   screen_payment   -> vet an x402/payment URL or merchant domain
//   check_sanctioned -> fast OFAC sanctions check
//   resolve_name     -> ENS name -> address, screened

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API = process.env.PAYMENT_GUARD_API || 'https://payment-guard.vercel.app';
const ok = (text) => ({ content: [{ type: 'text', text }] });
const err = (msg) => ({ content: [{ type: 'text', text: `Error: ${msg}` }], isError: true });
async function get(path, params) {
  const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== ''))).toString();
  const r = await fetch(`${API}${path}?${qs}`, { headers: { Accept: 'application/json' } });
  return r.json();
}
const CHAIN = z.enum(['eth', 'base', 'polygon', 'arbitrum', 'optimism']).optional().describe('EVM chain (default eth).');
const server = new McpServer({ name: 'payment-guard', version: '1.0.0' });

server.tool(
  'screen_address',
  'THE PRE-SEND GUARD. Before an agent sends funds to a crypto address (x402/transfer), call this. Accepts an EVM address OR an ENS name. Returns a verdict (safe/caution/block): whether the address is OFAC-sanctioned (do not pay), on a scam/abuse blocklist, or suspicious on-chain (brand-new/unused — common for scam drop addresses — or a contract). Use on every payment recipient. Sanctions matching covers every EVM-format OFAC SDN list and applies to all EVM chains; non-EVM sanctioned addresses are not checked. If the sanctions list cannot be loaded the verdict is downgraded to caution with a sanctions-check-unavailable flag rather than reported as safe. Read sanctions_coverage in the response for exactly what was checked.',
  { address: z.string().describe('EVM address (0x + 40 hex) or ENS name (e.g. name.eth).'), chain: CHAIN },
  async ({ address, chain }) => { try { const j = await get('/api/screen-address', { address, chain }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'screen failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'screen_payment',
  'Vet an x402/payment endpoint or merchant URL before paying it: punycode host, URL shorteners, abuse-prone TLDs, raw-IP host, credentials in the URL, very-new domain (RDAP), and the final URL after redirects (the intermediate hops are not analysed). The lookalike rule is a substring match on 14 known brand names, flagged when the brand is not the registrable domain, so paypal.com.secure-pay.xyz is caught; there is no edit distance or homoglyph mapping, so an ASCII typo like paypa1.com is not caught by that rule. Returns a verdict: safe / caution / block.',
  { url: z.string().describe('The x402/payment endpoint or merchant URL.') },
  async ({ url }) => { try { const j = await get('/api/screen-payment', { url }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'screen failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'check_sanctioned',
  'Fast OFAC sanctions check for a crypto address or ENS name (no on-chain lookup). Matches against the union of every EVM-format OFAC SDN list (ETH, ARB, BSC, ETC, USDC, USDT), which applies to all EVM chains because OFAC lists addresses by currency rather than by chain. Only EVM (0x) addresses are accepted, so Bitcoin, Tron, Solana and Monero sanctioned addresses are NOT checked. A false result means the address is absent from those EVM lists and nothing more; read the coverage object in the response. If the list cannot be loaded, sanctioned is null and verdict is "unknown" — treat that as unscreened, not as clean.',
  { address: z.string().describe('EVM address or ENS name.') },
  async ({ address }) => { try { const j = await get('/api/check-sanctioned', { address }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'check failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'resolve_name',
  'Resolve an ENS name to an address and screen that address against the OFAC EVM sanctions lists and the scam/abuse blocklists. Catches names that do not resolve. It does NOT detect lookalike or homoglyph names: there is no confusable check and no ENSIP-15 normalization, so a spoofed name that resolves to a clean address comes back clean. Resolution is namehash -> mainnet ENS registry resolver -> a direct addr() call, with no ENSIP-10/CCIP-Read, so offchain and L2 names (Basenames, .cb.id, gasless subnames) report resolved:false here even though a wallet resolves them. Read ens_coverage in the response.',
  { name: z.string().describe('ENS name, e.g. vitalik.eth.') },
  async ({ name }) => { try { const j = await get('/api/resolve-name', { name }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'resolve failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'screen_token',
  'Before an agent buys, swaps, or approves a token, check if the token contract is a HONEYPOT (you can buy but not sell), has an extreme sell tax, or is on a scam blocklist. The buy+sell simulation comes from api.honeypot.is, which supports Ethereum and Base only: it returns 400 "Invalid chain" for polygon, arbitrum and optimism, so the honeypot and tax fields are not populated there and the response says so via honeypot_checked and honeypot_coverage. When no simulation ran the verdict is never safe — it is caution, or block if the scam blocklist already hit, with a honeypot-check-unavailable flag. Returns token name/symbol, buy/sell/transfer taxes where available, and a verdict: safe / caution / block.',
  { address: z.string().describe('Token contract address (0x + 40 hex).'), chain: CHAIN },
  async ({ address, chain }) => { try { const j = await get('/api/screen-token', { address, chain }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'screen failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('payment-guard-mcp running (5 tools).');
