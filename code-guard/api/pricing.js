// Machine-readable pricing. GET /api/pricing
const { sendJson, handleOptions } = require('../lib/common.js');

const PRICING = {
  "ok": true,
  "product": "Code Guard",
  "description": "Security scan for AI-generated code before it ships.",
  "free": {
    "direct": {
      "url": "https://code-guard-api.vercel.app",
      "auth": "none",
      "rate_limit": "120 requests/min per IP",
      "notes": "Free public endpoint. No key, no signup."
    },
    "rapidapi_basic": {
      "price": "$0/mo",
      "quota": "1,000 requests/mo",
      "url": "https://rapidapi.com/mlawsonking/api/code-guard"
    }
  },
  "paid_plans": [
    {
      "plan": "PRO",
      "price": "$10/mo",
      "quota": "50,000 requests/mo"
    },
    {
      "plan": "ULTRA",
      "price": "$40/mo",
      "quota": "500,000 requests/mo"
    },
    {
      "plan": "MEGA",
      "price": "$150/mo",
      "quota": "3,000,000 requests/mo"
    }
  ],
  "signup": "https://rapidapi.com/mlawsonking/api/code-guard",
  "mcp_install": {
    "command": "npx",
    "args": [
      "-y",
      "@mlawsonking/code-guard-mcp"
    ]
  },
  "source": "https://github.com/mlawsonking/MCP",
  "license": "MIT"
};

module.exports = (req, res) => {
  if (handleOptions(req, res)) return;
  sendJson(res, 200, PRICING);
};
