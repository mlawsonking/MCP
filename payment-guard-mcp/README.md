# payment-guard-mcp

An MCP server that checks who your agent is about to pay, before it sends anything. Give it a crypto address, an ENS name, or a payment URL and it returns a verdict. Deterministic, no LLM, free.

Agents are starting to move real money on their own, over crypto rails, x402 endpoints, and payment links. The obvious way that goes wrong is paying a sanctioned or scam address by mistake, which is usually irreversible. `screen_address` is the check to run first.

## Install

```json
{ "mcpServers": { "payment-guard": { "command": "npx", "args": ["-y", "payment-guard-mcp"] } } }
```

## Tools

- `screen_address`: the main guard. Takes an EVM address or ENS name and checks OFAC sanctions, scam and abuse blocklists, and on-chain signals (brand-new and unused addresses, contracts). Returns safe, caution, or block.
- `screen_payment`: vet an x402 or merchant payment URL for a punycode host, a known brand name sitting outside the registrable domain, shorteners, abuse-prone TLDs, freshly registered domains, and the final URL after redirects.
- `check_sanctioned`: a quick OFAC-only check for an address or ENS name.
- `resolve_name`: resolve an ENS name to its address and screen that address. It catches names that don't resolve. It does not detect spoofed lookalike names.
- `screen_token`: before buying, swapping, or approving a token, check the contract for honeypot behavior (you can buy but not sell), extreme sell taxes, and blocklist hits.

On-chain checks run on Ethereum, Base, Polygon, Arbitrum and Optimism. Data comes from the OFAC SDN list, community scam lists (ethereum-lists, ScamSniffer), public RPC nodes, and ENS.

ENS coverage: resolution is namehash, then `resolver(node)` on the mainnet ENS registry, then a direct `addr(bytes32)` call. The address that comes back is screened against the sanctions and scam lists. There is no confusable check and no ENSIP-15 normalization, so lookalike and homoglyph names are not detected. There is no ENSIP-10 wildcard resolution and no CCIP-Read, so offchain and L2 names — Basenames, `.cb.id`, gasless subnames — report as not resolving here even though a wallet resolves them.

Honeypot coverage: the buy+sell simulation is api.honeypot.is, Ethereum and Base only. It returns 400 `Invalid chain` for Polygon, Arbitrum and Optimism, so the honeypot and tax fields are not populated there. The response says which chains it covers, and when no simulation ran the verdict is never `safe` — it is `caution`, or `block` if the scam blocklist already hit.

URL coverage: the lookalike rule is a substring match on 14 brand names, flagged when the brand is not the registrable domain. `paypal.com.secure-pay.xyz` is caught; `paypa1.com` is not, because there is no edit distance or homoglyph mapping. Only the final URL after redirects is compared, not each hop.

Sanctions coverage, stated plainly: OFAC publishes sanctioned addresses by currency, not by chain, so this checks the union of every EVM-format list (ETH, ARB, BSC, ETC, USDC, USDT) and that result applies to any EVM chain. Bitcoin, Tron, Solana, Monero and other non-EVM sanctioned addresses are not checked, because only EVM addresses are accepted. Every response carries a coverage object saying so. If the list cannot be loaded the result is `unknown`, never `clear`.


## Rule updates

About once a day this server asks the rules feed whether there is a newer ruleset, and applies it if
there is. The request carries two things: which surface asked, which here is `facade`, and the rules
version already installed. No machine id, no user id, no file names, nothing you scanned.

Bundles are signed with Ed25519 and verified against a public key compiled into this package, so it
does not matter which mirror served one. A bundle that fails its signature, its schema, or its ReDoS
check is discarded and the rules you already had stay in place. `--offline` turns updates off, as
does `AGENT_GUARDS_NO_FEED=1` or `{"feed": false}` in `~/.agent-guards/config.json`. The bundle
format and how to verify one yourself: https://github.com/mlawsonking/MCP/blob/main/rules/README.md

It calls https://payment-guard.vercel.app (set `PAYMENT_GUARD_API` to override). One of six agent guards in this repo. MIT.
