#!/usr/bin/env node
// agent-tools-mcp — an MCP server that exposes web utility tools to AI agents.
// Tools:
//   read_url   -> fetch a page and return its main content as clean Markdown (for RAG)
//   unfurl_url -> fetch a page's structured metadata (title, description, image, favicon, ...)
// Each just calls the live Vercel endpoints, so the agent gets a reliable, deterministic result.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const TOOLS_API = process.env.TOOLS_API_URL || 'https://agent-tools-api.vercel.app';
const READ_API = process.env.READ_API_URL || `${TOOLS_API}/api/read`;
const META_API = process.env.META_API_URL || `${TOOLS_API}/api/meta`;

async function getJson(base, url) {
  const r = await fetch(`${base}?url=${encodeURIComponent(url)}`, { headers: { Accept: 'application/json' } });
  return r.json();
}
const ok = (text) => ({ content: [{ type: 'text', text }] });
const err = (msg) => ({ content: [{ type: 'text', text: `Error: ${msg}` }], isError: true });

const server = new McpServer({ name: 'agent-tools', version: '1.0.0' });

server.tool(
  'read_url',
  'Fetch a web page and return its main readable content as clean Markdown. Use this to read an article, doc, or page for analysis or RAG. Strips nav/ads/boilerplate.',
  { url: z.string().describe('The http(s) URL of the page to read.') },
  async ({ url }) => {
    try {
      const j = await getJson(READ_API, url);
      if (!j.ok) return err(j.error || 'failed to read URL');
      const head = `# ${j.title || 'Untitled'}\nSource: ${j.url} (${j.words} words)\n\n`;
      return ok(head + (j.markdown || ''));
    } catch (e) { return err(String((e && e.message) || e)); }
  }
);

server.tool(
  'unfurl_url',
  'Fetch a URL\'s structured metadata: title, description, preview image, site name, favicon, canonical URL, language. Use this for link previews or to quickly understand what a URL is without reading the whole page.',
  { url: z.string().describe('The http(s) URL to unfurl.') },
  async ({ url }) => {
    try {
      const j = await getJson(META_API, url);
      if (!j.ok) return err(j.error || 'failed to fetch metadata');
      return ok(JSON.stringify(j, null, 2));
    } catch (e) { return err(String((e && e.message) || e)); }
  }
);

server.tool(
  'validate_email',
  'Validate an email address: syntax, live MX/A DNS check, and disposable/role/free-provider detection. Returns deliverability and a 0-1 quality score. (MX-level, no SMTP probe.)',
  { email: z.string().describe('The email address to validate.') },
  async ({ email }) => {
    try {
      const r = await fetch(`${TOOLS_API}/api/validate-email?email=${encodeURIComponent(email)}`);
      const j = await r.json();
      return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error || 'validation failed');
    } catch (e) { return err(String((e && e.message) || e)); }
  }
);

server.tool(
  'extract_web',
  'Scrape structured data from a web page using CSS selectors. Pass selectors as {key: "css"}. Suffix a selector with @attr for an attribute, or [] for all matches (e.g. "a.item[]@href"). Returns {key: value|array}.',
  { url: z.string().describe('Page URL to scrape.'), selectors: z.record(z.string()).describe('Map of output key -> CSS selector.') },
  async ({ url, selectors }) => {
    try {
      const r = await fetch(`${TOOLS_API}/api/extract?url=${encodeURIComponent(url)}&selectors=${encodeURIComponent(JSON.stringify(selectors))}`);
      const j = await r.json();
      return j.ok ? ok(JSON.stringify(j.data, null, 2)) : err(j.error || 'extraction failed');
    } catch (e) { return err(String((e && e.message) || e)); }
  }
);

server.tool(
  'get_feed',
  'Fetch an RSS or Atom feed and return its items as clean JSON (title, link, date, snippet). Use to check a site/blog/podcast for recent posts.',
  { url: z.string().describe('Feed URL.'), limit: z.number().optional().describe('Max items (default 25).') },
  async ({ url, limit }) => {
    try {
      const r = await fetch(`${TOOLS_API}/api/feed?url=${encodeURIComponent(url)}&limit=${limit || 25}`);
      const j = await r.json();
      return j.ok ? ok(JSON.stringify({ title: j.title, count: j.count, items: j.items }, null, 2)) : err(j.error || 'feed parse failed');
    } catch (e) { return err(String((e && e.message) || e)); }
  }
);

async function toolsGet(path, params) {
  const qs = new URLSearchParams(params).toString();
  const r = await fetch(`${TOOLS_API}${path}?${qs}`);
  return r.json();
}

server.tool(
  'dns_lookup',
  'Look up DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) plus email-auth (SPF/DMARC) detection. Use for deliverability, security, or reconnaissance.',
  { domain: z.string().describe('Domain name.'), type: z.string().optional().describe('Record type or "all" (default).') },
  async ({ domain, type }) => { try { const j = await toolsGet('/api/dns', { domain, type: type || 'all' }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error); } catch (e) { return err(String((e && e.message) || e)); } }
);
server.tool(
  'domain_info',
  'Get a domain\'s registration info via RDAP: creation/expiry dates, domain AGE in days, registrar, status, nameservers. Domain age is a strong trust/fraud signal.',
  { domain: z.string().describe('Domain name.') },
  async ({ domain }) => { try { const j = await toolsGet('/api/domain', { name: domain }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error); } catch (e) { return err(String((e && e.message) || e)); } }
);
server.tool(
  'ssl_check',
  'Inspect a host\'s SSL/TLS certificate: issuer, subject, validity window, DAYS REMAINING until expiry, SANs, protocol, trust. Use for cert monitoring.',
  { host: z.string().describe('Hostname (e.g. example.com).') },
  async ({ host }) => { try { const j = await toolsGet('/api/ssl', { host }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error); } catch (e) { return err(String((e && e.message) || e)); } }
);
server.tool(
  'http_inspect',
  'Inspect an HTTP(S) URL: final status, full redirect chain, response headers, and a security-header report (HSTS, CSP, X-Frame-Options, etc.).',
  { url: z.string().describe('URL to inspect.') },
  async ({ url }) => { try { const j = await toolsGet('/api/http', { url }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error); } catch (e) { return err(String((e && e.message) || e)); } }
);
server.tool(
  'structured_data',
  'Extract a page\'s machine-readable structured data: JSON-LD (schema.org), OpenGraph, and Twitter cards. Use to quickly understand what an entity/page is.',
  { url: z.string().describe('Page URL.') },
  async ({ url }) => { try { const j = await toolsGet('/api/structured', { url }); return j.ok ? ok(JSON.stringify(j, null, 2)) : err(j.error); } catch (e) { return err(String((e && e.message) || e)); } }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error('agent-tools-mcp running (10 tools).');
