# payment-guard-mcp

**The pre-send risk check for AI agents that move money, as an MCP server.**

Before your agent sends funds — x402, crypto, or a payment URL — have it call `screen_address`. In 2026
agents are already moving real money (x402: $600M+, ~500k AI wallets, a Linux Foundation standard backed
by Visa/Stripe/Anthropic/Coinbase), and the #1 risk is paying a sanctioned or tainted address unknowingly.

```jsonc
{ "mcpServers": { "payment-guard": { "command": "npx", "args": ["-y", "payment-guard-mcp"] } } }
```

## Tools
- **`screen_address`** — the guard. EVM address or ENS name → OFAC-sanctioned? on a scam/abuse blocklist? on-chain risk (brand-new/unused, contract)? → `verdict` (safe/caution/block).
- **`screen_payment`** — vet an x402/payment endpoint or merchant URL (lookalikes, new domain, redirects).
- **`check_sanctioned`** — fast OFAC sanctions check for an address / ENS name.
- **`resolve_name`** — resolve an ENS name → address and screen it (catch non-resolving names + spoofs).

Chains: Ethereum, Base, Polygon, Arbitrum, Optimism. Deterministic, free, no LLM. Data: OFAC SDN,
ethereum-lists + ScamSniffer blocklists, public RPC, ENS. Backed by `https://payment-guard.vercel.app`
(override with `PAYMENT_GUARD_API`).

Completes the AI-agent safety suite: **Package Guard · Agent Firewall · Payment Guard**.
Part of the [Agent Tools](https://github.com/mlawsonking/MCP) family. MIT.
