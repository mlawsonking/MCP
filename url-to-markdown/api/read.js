// URL -> clean Markdown reader.
// GET /api/read?url=https://example.com[&format=json|markdown]
// Returns the main readable content of a web page as clean Markdown.
// Built for AI agents (RAG) and developers. Deterministic, no LLM, no external paid services.

const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');
const TurndownService = require('turndown');
const dns = require('dns').promises;
const net = require('net');

const FETCH_TIMEOUT_MS = 7000;
const MAX_BYTES = 5 * 1024 * 1024; // 5 MB cap.
const UA = 'url-to-markdown-bot/1.0 (+https://github.com/; reader API for AI agents)';

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
    return false;
  }
  const lc = ip.toLowerCase();
  return lc === '::1' || lc === '::' || lc.startsWith('fe80') || lc.startsWith('fc') || lc.startsWith('fd');
}

function send(res, code, obj, asMarkdown) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (asMarkdown) {
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.statusCode = code;
    res.end(typeof obj === 'string' ? obj : JSON.stringify(obj));
  } else {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.statusCode = code;
    res.end(JSON.stringify(obj));
  }
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.statusCode = 204;
    res.end();
    return;
  }

  const started = Date.now();
  const q = req.query || {};
  let target = q.url || (req.body && req.body.url) || '';
  const format = String(q.format || 'json').toLowerCase();
  const wantMd = format === 'markdown' || format === 'md';

  if (!target) return send(res, 400, { ok: false, error: 'Missing required ?url= parameter' }, false);

  let u;
  try { u = new URL(target); } catch { return send(res, 400, { ok: false, error: 'Invalid URL' }, false); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return send(res, 400, { ok: false, error: 'Only http and https URLs are supported' }, false);
  }

  // SSRF guard: resolve the host and refuse private/loopback addresses.
  try {
    const { address } = await dns.lookup(u.hostname);
    if (isPrivateIp(address)) return send(res, 400, { ok: false, error: 'Refusing to fetch a private/loopback address' }, false);
  } catch {
    return send(res, 400, { ok: false, error: 'Could not resolve host' }, false);
  }

  // Fetch with timeout, UA, and a size cap.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  let html, finalUrl, status;
  try {
    const r = await fetch(u.href, {
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml,text/plain' },
    });
    finalUrl = r.url;
    status = r.status;
    const ct = r.headers.get('content-type') || '';
    if (!r.ok) return send(res, 502, { ok: false, error: `Upstream returned HTTP ${status}`, url: finalUrl }, false);
    if (!/text\/html|application\/xhtml|text\/plain/i.test(ct)) {
      return send(res, 415, { ok: false, error: `Unsupported content-type: ${ct || 'unknown'}`, url: finalUrl }, false);
    }
    // Read with a byte cap.
    const reader = r.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_BYTES) { try { await reader.cancel(); } catch {} break; }
      chunks.push(value);
    }
    html = Buffer.concat(chunks).toString('utf-8');
  } catch (e) {
    return send(res, 504, { ok: false, error: 'Fetch failed or timed out', detail: String((e && e.message) || e) }, false);
  } finally {
    clearTimeout(timer);
  }

  // Extract main content and convert to Markdown.
  let title = '', byline = '', excerpt = '', markdown = '';
  try {
    const dom = new JSDOM(html, { url: finalUrl });
    const td = new TurndownService({ headingStyle: 'atx', codeBlockStyle: 'fenced', bulletListMarker: '-' });
    let article = null;
    try { article = new Readability(dom.window.document).parse(); } catch {}
    if (article && article.content) {
      title = article.title || dom.window.document.title || '';
      byline = article.byline || '';
      excerpt = article.excerpt || '';
      markdown = td.turndown(article.content);
    } else {
      title = dom.window.document.title || '';
      const body = dom.window.document.body;
      markdown = td.turndown(body ? body.innerHTML : html);
    }
    markdown = markdown.replace(/\n{3,}/g, '\n\n').trim();
  } catch (e) {
    return send(res, 500, { ok: false, error: 'Failed to parse content', detail: String((e && e.message) || e) }, false);
  }

  if (wantMd) return send(res, 200, markdown, true);

  return send(res, 200, {
    ok: true,
    url: finalUrl,
    title,
    byline: byline || undefined,
    excerpt: excerpt || undefined,
    words: markdown ? markdown.split(/\s+/).filter(Boolean).length : 0,
    chars: markdown.length,
    ms: Date.now() - started,
    markdown,
  }, false);
};
