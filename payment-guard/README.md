# Payment Guard

**The pre-send risk check for AI agents that move money.** Before your agent sends funds — over x402,
crypto, or to a payment URL — it should ask one question: *is this recipient safe to pay?*

In 2026 agents are already moving real money (x402: $600M+ moved, ~500k AI wallets, now a Linux
Foundation standard backed by Visa/Stripe/Anthropic/Coinbase). The #1 named risk is *the agent
interacting with a sanctioned or tainted address unknowingly.* Payment Guard catches it in one call.

Deterministic, no LLM. Free data: **OFAC** sanctioned addresses + **ethereum-lists + ScamSniffer**
blocklists + on-chain reads via **public RPC** + **ENS**. EVM: Ethereum, Base, Polygon, Arbitrum, Optimism.

## Tools (HTTP + MCP)

| Endpoint | What it does |
|---|---|
| `GET /api/screen-address` | **The guard.** Address (or ENS name) → OFAC-sanctioned? on a scam/abuse blocklist? on-chain risk (brand-new/unused, contract)? → `verdict` (safe/caution/block) + reasons |
| `GET /api/screen-payment` | Vet an x402/payment endpoint or merchant URL (punycode, lookalikes, shorteners, new domain, redirects) → verdict |
| `GET /api/check-sanctioned` | Fast OFAC sanctions check for an address/ENS name (no on-chain) |
| `GET /api/resolve-name` | Resolve an ENS name → address and screen it (catch non-resolving names + spoofs before paying) |

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
