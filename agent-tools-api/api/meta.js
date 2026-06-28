// URL -> structured metadata (link unfurl).
// GET /api/meta?url=https://example.com
const cheerio = require('cheerio');
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');

function abs(href, base) { if (!href) return ''; try { return new URL(href, base).href; } catch { return ''; } }

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const target = q.url || (req.body && req.body.url);
  if (!target) return sendJson(res, 400, { ok: false, error: 'Missing required ?url= parameter' });

  const f = await safeFetch(target, { accept: 'text/html,application/xhtml+xml' });
  if (!f.ok) return sendJson(res, f.code || 502, { ok: false, error: f.error, detail: f.detail });

  try {
    const $ = cheerio.load(f.text);
    const m = (names) => { for (const n of names) { const c = $(`meta[property="${n}"]`).attr('content') || $(`meta[name="${n}"]`).attr('content'); if (c && c.trim()) return c.trim(); } return ''; };
    const title = ($('title').first().text() || '').trim() || m(['og:title', 'twitter:title']);
    const description = m(['description', 'og:description', 'twitter:description']);
    const image = abs(m(['og:image', 'og:image:url', 'twitter:image', 'twitter:image:src']), f.finalUrl);
    const siteName = m(['og:site_name', 'application-name']);
    const type = m(['og:type']);
    const themeColor = m(['theme-color']);
    const author = m(['author', 'article:author']);
    const canonical = abs($('link[rel="canonical"]').attr('href'), f.finalUrl);
    const lang = ($('html').attr('lang') || '').trim();
    let favicon = '';
    $('link[rel]').each((_, el) => { const rel = ($(el).attr('rel') || '').toLowerCase(); if (!favicon && /(^|\s)(icon|shortcut icon|apple-touch-icon)(\s|$)/.test(rel)) favicon = abs($(el).attr('href'), f.finalUrl); });
    if (!favicon) { try { favicon = new URL('/favicon.ico', f.finalUrl).href; } catch {} }

    return sendJson(res, 200, {
      ok: true, url: f.finalUrl, title, description: description || undefined, image: image || undefined,
      siteName: siteName || undefined, type: type || undefined, author: author || undefined,
      themeColor: themeColor || undefined, canonical: canonical || undefined, favicon: favicon || undefined,
      lang: lang || undefined, ms: Date.now() - started,
    });
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Failed to parse metadata', detail: String((e && e.message) || e) });
  }
};
