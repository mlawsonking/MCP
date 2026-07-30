# Payment Guard

**The pre-send risk check for AI agents that move money.** Before your agent sends funds — over x402,
crypto, or to a payment URL — it should ask one question: *is this recipient safe to pay?*

Agents are starting to move real money on their own, over x402 endpoints and crypto rails. The obvious
way that goes wrong is paying a sanctioned or scam address by mistake, and on-chain that is irreversible.

Deterministic, no LLM. Free data: the OFAC SDN sanctioned-address lists, the ethereum-lists and
ScamSniffer blocklists, on-chain reads over public RPC, and ENS. On-chain checks run on Ethereum,
Base, Polygon, Arbitrum and Optimism.

### What the sanctions check actually covers

OFAC publishes sanctioned addresses by currency, not by chain. I ingest every upstream list that is in
EVM (`0x`) format — ETH, ARB, BSC, ETC, USDC, USDT — and match against the union of all of them, so one
result applies to every EVM chain.

Bitcoin, Tron, Solana, Monero and the other non-EVM sanctioned addresses are **not** checked. This API
only accepts EVM addresses, so it could never match them. A `sanctioned: false` means the address is
absent from the EVM lists above and nothing more. Every response carries a `coverage` object that says
this in machine-readable form.

Earlier versions of this API read only the ETH list. That missed 4 addresses that OFAC publishes under
ARB, BSC, USDC and USDT, and returned `verdict: "clear"` for them. The test suite now pins those four.

### What the ENS check actually covers

`lib/ens.js` does one thing: namehash the name, call `resolver(node)` on the mainnet ENS registry, then
call `addr(bytes32)` on that resolver. Whatever address comes back gets screened against the sanctions
and scam lists. That is the whole check.

It does not detect lookalike or homoglyph names. There is no confusable check and no ENSIP-15
normalization, so a name with a Cyrillic character in it is just another name to me — I resolve it and
screen whatever address it points to.

Mainnet registry and a direct `addr()` call only. There is no ENSIP-10 wildcard resolution and no
CCIP-Read, so offchain and L2 names — Basenames, `.cb.id`, gasless subnames — come back as not
resolving here even though a wallet resolves them. Read "did not resolve" as "not via the mainnet
registry with a direct `addr()` call", not as "does not exist".

### What the honeypot check actually covers

The buy+sell simulation is api.honeypot.is. It answers for Ethereum and Base, and returns
400 `Invalid chain` for Polygon, Arbitrum and Optimism, so the `honeypot` and `taxes` fields are not
populated on those three. When no simulation ran the verdict is never `safe`: you get `caution` (or
`block`, if the scam blocklist already hit), a `honeypot-check-unavailable` flag, and a
`honeypot_coverage` object naming the chains it supports.
honeypot.is also has no result for tokens with no liquidity pool, which is the population most likely
to be a rug.

### What the URL check actually covers

The lookalike rule matches 14 brand names (paypal, coinbase, metamask, chase and the rest of the list in
`lib/safety.js`) as a substring of the host, and flags them when the brand is not the registrable
domain. `paypal.com.secure-pay.xyz` is caught. There is no edit distance and no homoglyph mapping, so
`paypa1.com` is not caught by that rule — a punycode host trips a separate `punycode` flag, but a
plain ASCII typo does not. On redirects I compare the final URL only, not each hop.

## Tools (HTTP + MCP)

| Endpoint | What it does |
|---|---|
| `GET /api/screen-address` | **The guard.** Address (or ENS name) → OFAC-sanctioned? on a scam/abuse blocklist? on-chain risk (brand-new/unused, contract)? → `verdict` (safe/caution/block) + reasons |
| `GET /api/screen-payment` | Vet an x402/payment endpoint or merchant URL (punycode host, a known brand name outside the registrable domain, shorteners, abuse-prone TLD, new domain, the final URL after redirects) → verdict |
| `GET /api/check-sanctioned` | Fast OFAC sanctions check for an address/ENS name (no on-chain). Returns a `coverage` object stating which lists were consulted |
| `GET /api/resolve-name` | Resolve an ENS name → address, then screen that address against the sanctions and scam lists. Catches names that do not resolve |
| `GET /api/screen-token` | Honeypot / sell-tax / blocklist check on a token contract before a buy or approve. The buy+sell simulation comes from api.honeypot.is, Ethereum and Base only |

## Examples
```bash
# Screen a recipient before sending (works with an address or an ENS name)
curl "https://payment-guard.vercel.app/api/screen-address?address=vitalik.eth&chain=eth"
# Vet an x402 payment endpoint / merchant URL
curl "https://payment-guard.vercel.app/api/screen-payment?url=https://pay.example.com/x402"
# Compliance primitive
curl "https://payment-guard.vercel.app/api/check-sanctioned?address=0x..."
```

## Use it from an agent (MCP)
```jsonc
{ "mcpServers": { "payment-guard": { "command": "npx", "args": ["-y", "payment-guard-mcp"] } } }
```

Completes the AI-agent safety suite: **Package Guard** (supply chain) · **Agent Firewall** (input/output)
· **Payment Guard** (money). Part of the [Agent Tools](https://github.com/mlawsonking/MCP) family. MIT.
