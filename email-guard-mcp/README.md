# email-guard-mcp

An MCP server for email safety. It checks inbound mail before your agent acts on it, and outbound mail before your agent sends it. Deterministic, no LLM, free.

Once an agent can read and send email, the inbox turns into an attack surface. An incoming message can try to hijack the agent with instructions buried in the body, which people have started calling AI agent phishing. On the way out, an agent can leak a secret or send something that gets its sending domain flagged as spam.

## Install

```json
{ "mcpServers": { "email-guard": { "command": "npx", "args": ["-y", "email-guard-mcp"] } } }
```

## Tools

- `scan_inbound`: run this before acting on a message. It matches known injection and hijack patterns (including zero-width, bidi, and hidden-HTML tricks), compares sender headers (SPF, DKIM, or DMARC results as reported by the receiving server, reply-to and return-path mismatches, and a 24-name brand list matched against the display name), looks the sender domain up in DNS and RDAP (disposable, or registered in the last 30 days), and scores links. It returns a verdict plus fixed-shape metadata, so the agent works from that instead of the raw, possibly poisoned, text.
- `scan_outbound`: run this before sending. It runs 22 secret patterns (AWS, GitHub, OpenAI, Anthropic, Google, Slack, Stripe, Twilio, npm, JWT, PEM private-key blocks, Azure storage keys and SAS tokens, GCP service-account key ids, database and ODBC connection-string passwords, SendGrid, GitLab, Hugging Face, and quoted `api_key`/`secret`/`password`/`token` assignments) and 3 PII patterns (email address, US SSN, Luhn-valid card number) over the subject, body and HTML, and returns a redacted copy. It also flags deliverability problems that hurt your sender reputation, and dead recipients (disposable domains, or no MX records, which guarantees a bounce).
- `check_domain_auth`: SPF, DMARC, MX, domain age, and disposable status for a domain or address. Returns weak or enforced.

## What these do not do

The injection side is pattern matching, not a classifier. A phrasing nobody wrote a rule for gets through.

The brand list is a substring test on the display name. `"PayPal Security" <svc@paypal-secure.tk>` is not flagged, because the domain contains "paypal". Any brand off the list is not flagged either.

The leak scan knows 15 shapes and nothing else. A DigitalOcean or SendGrid key, a bare bearer token, and an unquoted `password=supersecret123` all pass clean. The email-address rule is noisy in the other direction: any address in the body puts the message at review, so read `leak.findings` before you treat a review as a leak.

The structured output from `scan_inbound` has a fixed shape, but nothing in it is sanitised. `subject`, `sender.display`, `sender.from`, `sender.replyTo`, `sender.domain`, `links[].url`, `links[].host`, `injection.findings[].match`, and the note strings in `sender.spoofFlags` and `reasons` are all copied out of the email. The verdict, the scores, the rule ids and the advice string are the only parts written here. The rest is still the attacker's text. Treat it as data.

Data comes from DNS (SPF, DMARC, MX), RDAP for domain age, disposable-domain lists, and injection and secret rulesets.


## Rule updates

About once a day this server asks the rules feed whether there is a newer ruleset, and applies it if
there is. The request carries two things: which surface asked, which here is `facade`, and the rules
version already installed. No machine id, no user id, no file names, nothing you scanned.

Bundles are signed with Ed25519 and verified against a public key compiled into this package, so it
does not matter which mirror served one. A bundle that fails its signature, its schema, or its ReDoS
check is discarded and the rules you already had stay in place. `--offline` turns updates off, as
does `AGENT_GUARDS_NO_FEED=1` or `{"feed": false}` in `~/.agent-guards/config.json`. The bundle
format and how to verify one yourself: https://github.com/mlawsonking/MCP/blob/main/rules/README.md

On email authentication, plainly: SPF, DKIM and DMARC results are read out of the `Authentication-Results` header that the receiving mail server wrote. Nothing here verifies a DKIM signature, and DKIM DNS records are never looked up, because the selector cannot be derived from a domain name alone. That means the value is only as trustworthy as whoever wrote the header. For mail your own server received it is a good signal; in a raw `.eml` from an untrusted source an attacker can simply type `dkim=pass`. Every response carries a note saying which case applies. Same input always gives the same output. It calls https://email-guard-api.vercel.app (set `EMAIL_GUARD_API` to override). One of six agent guards in this repo. MIT.
