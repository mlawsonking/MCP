# payment-guard-mcp

An MCP server that checks who your agent is about to pay, before it sends anything. Give it a crypto address, an ENS name, or a payment URL and it returns a verdict. Deterministic, no LLM, free.

Agents are starting to move real money on their own, over crypto rails, x402 endpoints, and payment links. The obvious way that goes wrong is paying a sanctioned or scam address by mistake, which is usually irreversible. `screen_address` is the check to run first.

## Install

```json
{ "mcpServers": { "payment-guard": { "command": "npx", "args": ["-y", "payment-guard-mcp"] } } }
```

## Tools

- `screen_address`: the main guard. Takes an EVM address or ENS name and checks OFAC sanctions, scam and abuse blocklists, and on-chain signals (brand-new and unused addresses, contracts). Returns safe, caution, or block.
- `screen_payment`: vet an x402 or merchant payment URL for lookalikes, freshly registered domains, and suspicious redirects.
- `check_sanctioned`: a quick OFAC-only check for an address or ENS name.
- `resolve_name`: resolve an ENS name to its address and screen it, which catches names that don't resolve and spoofed lookalikes.
- `screen_token`: before buying, swapping, or approving a token, check the contract for honeypot behavior (you can buy but not sell), extreme sell taxes, and blocklist hits.

Chains: Ethereum, Base, Polygon, Arbitrum, Optimism. Data comes from the OFAC SDN list, community scam lists (ethereum-lists, ScamSniffer), public RPC nodes, and ENS. It calls https://payment-guard.vercel.app (set `PAYMENT_GUARD_API` to override). One of six agent guards in this repo. MIT.
