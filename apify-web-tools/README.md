# Web Tools — Apify Actor

One Actor wrapping all 10 [Agent Tools](https://github.com/mlawsonking/MCP) web utilities. Pick a
`tool` per run; the Actor calls the live API and pushes the JSON result to the dataset (one item per
run → **pay-per-result** monetization).

## Input
```json
{ "tool": "read", "url": "https://example.com" }
{ "tool": "validate-email", "email": "someone@example.com" }
{ "tool": "extract", "url": "https://news.ycombinator.com", "selectors": { "titles": ".titleline a[]" } }
{ "tool": "dns", "domain": "github.com" }
{ "tool": "ssl", "host": "github.com" }
```
Tools: `read, meta, validate-email, extract, feed, dns, domain, ssl, http, structured`.

## Publish (after creating a free Apify account)
```
npm i -g apify-cli
apify login
apify push        # from this folder → builds & deploys the Actor
```
Then in the Apify Console, set **Monetization → Pay per result** and a price per item, and publish to
the Store. (Apify pays the maker 80%.)
