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
  'THE PRE-SEND GUARD. Before an agent sends funds to a crypto address (x402/transfer), call this. Accepts an EVM address OR an ENS name. Returns a verdict (safe/caution/block): whether the address is OFAC-sanctioned (do not pay), on a scam/abuse blocklist, or suspicious on-chain (brand-new/unused — common for scam drop addresses — or a contract). Use on every payment recipient.',
  { address: z.string().describe('EVM address (0x + 40 hex) or ENS name (e.g. name.eth).'), chain: CHAIN },
  async ({ address, chain }) => { try { const j = await get('/api/screen-address', { address, chain }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'screen failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'screen_payment',
  'Vet an x402/payment endpoint or merchant URL before paying it: punycode/homograph, brand lookalikes, URL shorteners, abuse-prone TLDs, raw-IP host, very-new domain (RDAP), and the redirect chain. Returns a verdict: safe / caution / block.',
  { url: z.string().describe('The x402/payment endpoint or merchant URL.') },
  async ({ url }) => { try { const j = await get('/api/screen-payment', { url }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'screen failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'check_sanctioned',
  'Fast OFAC sanctions check for a crypto address or ENS name (no on-chain lookup). Returns whether it is on the OFAC SDN sanctioned-digital-currency list. Use as a quick compliance gate.',
  { address: z.string().describe('EVM address or ENS name.') },
  async ({ address }) => { try { const j = await get('/api/check-sanctioned', { address }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'check failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'resolve_name',
  'Resolve an ENS name to an address and screen it. Catches names that do not resolve (do not pay them) and surfaces if the resolved address is sanctioned/scam — useful to defend against ENS lookalike/spoof attacks before paying a human-readable name.',
  { name: z.string().describe('ENS name, e.g. vitalik.eth.') },
  async ({ name }) => { try { const j = await get('/api/resolve-name', { name }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'resolve failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

server.tool(
  'screen_token',
  'Before an agent buys, swaps, or approves a token, check if the token contract is a HONEYPOT (you can buy but not sell), a rug (extreme/high sell tax), or on a scam blocklist. Runs an on-chain buy+sell simulation. Returns token name/symbol, buy/sell/transfer taxes, and a verdict: safe / caution / block.',
  { address: z.string().describe('Token contract address (0x + 40 hex).'), chain: CHAIN },
  async ({ address, chain }) => { try { const j = await get('/api/screen-token', { address, chain }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'screen failed'); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('payment-guard-mcp running (5 tools).');
