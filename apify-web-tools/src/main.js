// Apify Actor: Web Tools — one Actor wrapping all 10 deterministic web utilities.
// Reads { tool, ...params }, calls the live agent-tools API, pushes the JSON result to the
// dataset (one item = one result → pay-per-result monetization on Apify).
import { Actor } from 'apify';

const BASE = process.env.TOOLS_API || 'https://agent-tools-api.vercel.app/api';
const enc = encodeURIComponent;

await Actor.init();
const input = (await Actor.getInput()) || {};
const { tool, url, email, domain, host, name, selectors, limit, format } = input;

const routes = {
  read: () => `/read?url=${enc(url)}${format ? `&format=${enc(format)}` : ''}`,
  meta: () => `/meta?url=${enc(url)}`,
  'validate-email': () => `/validate-email?email=${enc(email)}`,
  extract: () => `/extract?url=${enc(url)}&selectors=${enc(JSON.stringify(selectors || {}))}`,
  feed: () => `/feed?url=${enc(url)}${limit ? `&limit=${limit}` : ''}`,
  dns: () => `/dns?domain=${enc(domain)}`,
  domain: () => `/domain?name=${enc(domain || name)}`,
  ssl: () => `/ssl?host=${enc(host || domain)}`,
  http: () => `/http?url=${enc(url)}`,
  structured: () => `/structured?url=${enc(url)}`,
};

if (!tool || !routes[tool]) {
  await Actor.fail(`Unknown or missing "tool". Use one of: ${Object.keys(routes).join(', ')}`);
}

const endpoint = BASE + routes[tool]();
let result;
try {
  const r = await fetch(endpoint, { headers: { Accept: 'application/json' } });
  result = await r.json();
} catch (e) {
  result = { ok: false, error: 'request failed', detail: String((e && e.message) || e) };
}

await Actor.pushData({ tool, ...result });
await Actor.exit();
