// URL -> clean Markdown reader (Readability + Turndown).
// GET /api/read?url=https://example.com[&format=json|markdown]
const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');
const TurndownService = require('turndown');
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const target = q.url || (req.body && req.body.url);
  const format = String(q.format || 'json').toLowerCase();
  const wantMd = format === 'markdown' || format === 'md';
  if (!target) return sendJson(res, 400, { ok: false, error: 'Missing required ?url= parameter' });

  const f = await safeFetch(target, { accept: 'text/html,application/xhtml+xml', maxBytes: 5 * 1024 * 1024 });
  if (!f.ok) return sendJson(res, f.code || 502, { ok: false, error: f.error, detail: f.detail });
  if (!/text\/html|application\/xhtml/i.test(f.contentType || '')) {
    return sendJson(res, 415, { ok: false, error: `Unsupported content-type: ${f.contentType || 'unknown'}`, url: f.finalUrl });
  }

  let title = '', byline = '', excerpt = '', markdown = '';
  try {
    const dom = new JSDOM(f.text, { url: f.finalUrl });
    const td = new TurndownService({ headingStyle: 'atx', codeBlockStyle: 'fenced', bulletListMarker: '-' });
    let article = null;
    try { article = new Readability(dom.window.document).parse(); } catch {}
    if (article && article.content) {
      title = article.title || dom.window.document.title || '';
      byline = article.byline || ''; excerpt = article.excerpt || '';
      markdown = td.turndown(article.content);
    } else {
      title = dom.window.document.title || '';
      const b = dom.window.document.body;
      markdown = td.turndown(b ? b.innerHTML : f.text);
    }
    markdown = markdown.replace(/\n{3,}/g, '\n\n').trim();
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Failed to parse content', detail: String((e && e.message) || e) });
  }

  if (wantMd) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.statusCode = 200; res.end(markdown); return;
  }
  return sendJson(res, 200, {
    ok: true, url: f.finalUrl, title, byline: byline || undefined, excerpt: excerpt || undefined,
    words: markdown ? markdown.split(/\s+/).filter(Boolean).length : 0, chars: markdown.length,
    ms: Date.now() - started, markdown,
  });
};
