// URL -> structured metadata (link unfurl).
// GET /api/meta?url=https://example.com
// Returns title, description, image, site name, favicon, canonical, etc. — the data every
// app needs to render a link preview, and every agent needs to summarize a link.
// Deterministic, no LLM, no external paid services.

const cheerio = require('cheerio');
const dns = require('dns').promises;
const net = require('net');

const FETCH_TIMEOUT_MS = 7000;
const MAX_BYTES = 3 * 1024 * 1024;
const UA = 'url-metadata-bot/1.0 (+https://github.com/; metadata API for AI agents)';

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    return false;
  }
  const lc = ip.toLowerCase();
  return lc === '::1' || lc === '::' || lc.startsWith('fe80') || lc.startsWith('fc') || lc.startsWith('fd');
}

function sendJson(res, code, obj) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.statusCode = code;
  res.end(JSON.stringify(obj));
}

function abs(href, base) {
  if (!href) return '';
  try { return new URL(href, base).href; } catch { return ''; }
}

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.statusCode = 204; res.end(); return;
  }

  const started = Date.now();
  const q = req.query || {};
  const target = q.url || (req.body && req.body.url) || '';
  if (!target) return sendJson(res, 400, { ok: false, error: 'Missing required ?url= parameter' });

  let u;
  try { u = new URL(target); } catch { return sendJson(res, 400, { ok: false, error: 'Invalid URL' }); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return sendJson(res, 400, { ok: false, error: 'Only http and https URLs are supported' });
  }
  try {
    const { address } = await dns.lookup(u.hostname);
    if (isPrivateIp(address)) return sendJson(res, 400, { ok: false, error: 'Refusing to fetch a private/loopback address' });
  } catch { return sendJson(res, 400, { ok: false, error: 'Could not resolve host' }); }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  let html = '', finalUrl = u.href;
  try {
    const r = await fetch(u.href, { redirect: 'follow', signal: ctrl.signal, headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml' } });
    finalUrl = r.url;
    const ct = r.headers.get('content-type') || '';
    if (!r.ok) return sendJson(res, 502, { ok: false, error: `Upstream returned HTTP ${r.status}`, url: finalUrl });
    if (!/text\/html|application\/xhtml/i.test(ct)) return sendJson(res, 415, { ok: false, error: `Unsupported content-type: ${ct || 'unknown'}`, url: finalUrl });
    const reader = r.body.getReader();
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_BYTES) { try { await reader.cancel(); } catch {} break; }
      chunks.push(value);
    }
    html = Buffer.concat(chunks).toString('utf-8');
  } catch (e) {
    return sendJson(res, 504, { ok: false, error: 'Fetch failed or timed out', detail: String((e && e.message) || e) });
  } finally { clearTimeout(timer); }

  try {
    const $ = cheerio.load(html);
    const m = (names) => {
      for (const n of names) {
        const c = $(`meta[property="${n}"]`).attr('content') || $(`meta[name="${n}"]`).attr('content');
        if (c && c.trim()) return c.trim();
      }
      return '';
    };
    const title = ($('title').first().text() || '').trim() || m(['og:title', 'twitter:title']);
    const description = m(['description', 'og:description', 'twitter:description']);
    const image = abs(m(['og:image', 'og:image:url', 'twitter:image', 'twitter:image:src']), finalUrl);
    const siteName = m(['og:site_name', 'application-name']);
    const type = m(['og:type']);
    const themeColor = m(['theme-color']);
    const author = m(['author', 'article:author']);
    const canonical = abs($('link[rel="canonical"]').attr('href'), finalUrl);
    const lang = ($('html').attr('lang') || '').trim();

    // Favicon: prefer declared icons, else origin /favicon.ico.
    let favicon = '';
    $('link[rel]').each((_, el) => {
      const rel = ($(el).attr('rel') || '').toLowerCase();
      if (!favicon && /(^|\s)(icon|shortcut icon|apple-touch-icon)(\s|$)/.test(rel)) {
        favicon = abs($(el).attr('href'), finalUrl);
      }
    });
    if (!favicon) { try { favicon = new URL('/favicon.ico', finalUrl).href; } catch {} }

    return sendJson(res, 200, {
      ok: true, url: finalUrl, title, description: description || undefined, image: image || undefined,
      siteName: siteName || undefined, type: type || undefined, author: author || undefined,
      themeColor: themeColor || undefined, canonical: canonical || undefined, favicon: favicon || undefined,
      lang: lang || undefined, ms: Date.now() - started,
    });
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Failed to parse metadata', detail: String((e && e.message) || e) });
  }
};
