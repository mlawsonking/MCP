// Machine-readable pricing. GET /api/pricing
//
// There is no paid tier. There was one: PRO/ULTRA/MEGA plans sold 50k, 500k and 3M requests a month
// while this endpoint gives 120 requests a minute to anyone with no key, which is roughly 5.18M a
// month. The $150 plan bought less than free. Rather than raise the prices, the plans are gone: the
// engines are the product, they run locally, and the hosted endpoint is a convenience mirror.
const { sendJson, handleOptions, track } = require('../lib/common.js');

const PRICING = {
  "ok": true,
  "product": "Email Guard",
  "description": "Inbound phishing/injection and outbound leak checks for agent email.",
  "cost": "free",
  "free": {
    "direct": {
      "url": "https://email-guard-api.vercel.app",
      "auth": "none",
      "rate_limit": "120 requests/min per IP",
      "notes": "Free public endpoint. No key, no signup. Shared and rate-limited, with no uptime guarantee."
    },
    "rapidapi_basic": {
      "price": "$0/mo",
      "quota": "1,000 requests/mo",
      "url": "https://rapidapi.com/mlawsonking/api/email-guard",
      "notes": "A keyed mirror of the same endpoint for callers who want marketplace billing plumbing. It buys nothing the direct endpoint does not already give away."
    }
  },
  "paid_plans": [],
  "if_you_need_more": {
    "answer": "Run it locally. Same engines, no rate limit, no network, nothing leaves your machine.",
    "install": "npx -y agent-guards",
    "why": "This endpoint is a shared free mirror. The local package is the complete product, not a trial of it."
  },
  "no_sla": "This is a free endpoint on a free hosting tier. There is no SLA, no support commitment and no guarantee it stays up. Anything you depend on should run the local package.",
  "mcp_install": {
    "command": "npx",
    "args": ["-y","email-guard-mcp"]
  },
  "source": "https://github.com/mlawsonking/MCP",
  "license": "MIT"
};

module.exports = (req, res) => {
  if (handleOptions(req, res)) return;
  // The landing page fires one request here with ?pv=1 when it loads. Counting it on an
  // endpoint that already exists beats adding a sixth copy of a new one, and pricing itself is
  // not worth measuring. Anything else asking for pricing is not a page view and is not counted.
  if (/[?&]pv=1(&|$)/.test(String(req.url || ''))) track(req, 'page_view', { product: "email-guard", page: 'landing' });
  sendJson(res, 200, PRICING);
};
