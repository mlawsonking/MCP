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

## Tools (HTTP + MCP)

| Endpoint | What it does |
|---|---|
| `GET /api/screen-address` | **The guard.** Address (or ENS name) → OFAC-sanctioned? on a scam/abuse blocklist? on-chain risk (brand-new/unused, contract)? → `verdict` (safe/caution/block) + reasons |
| `GET /api/screen-payment` | Vet an x402/payment endpoint or merchant URL (punycode, lookalikes, shorteners, new domain, redirects) → verdict |
| `GET /api/check-sanctioned` | Fast OFAC sanctions check for an address/ENS name (no on-chain). Returns a `coverage` object stating which lists were consulted |
| `GET /api/resolve-name` | Resolve an ENS name → address and screen it (catch non-resolving names + spoofs before paying) |
| `GET /api/screen-token` | Honeypot/rug/tax risk for a token contract before a buy/approve (on-chain buy+sell simulation) |

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
