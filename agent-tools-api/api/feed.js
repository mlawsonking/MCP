// RSS/Atom feed -> clean JSON.
// GET /api/feed?url=https://news.ycombinator.com/rss&limit=25
// Deterministic, no LLM. Handy for agents/automations that watch sites for new content.

const Parser = require('rss-parser');
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');

const parser = new Parser({ timeout: 8000 });

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const url = q.url || (req.body && req.body.url);
  const limit = Math.min(100, Math.max(1, parseInt(q.limit || '25', 10) || 25));
  if (!url) return sendJson(res, 400, { ok: false, error: 'Missing required ?url= parameter' });

  const f = await safeFetch(url, { accept: 'application/rss+xml,application/atom+xml,application/xml,text/xml,*/*' });
  if (!f.ok) return sendJson(res, f.code || 502, { ok: false, error: f.error, detail: f.detail });

  let feed;
  try { feed = await parser.parseString(f.text); }
  catch (e) { return sendJson(res, 422, { ok: false, error: 'Not a valid RSS/Atom feed', detail: String((e && e.message) || e) }); }

  const items = (feed.items || []).slice(0, limit).map((it) => ({
    title: it.title || undefined,
    link: it.link || undefined,
    isoDate: it.isoDate || it.pubDate || undefined,
    author: it.creator || it.author || undefined,
    categories: it.categories && it.categories.length ? it.categories.slice(0, 10) : undefined,
    contentSnippet: it.contentSnippet ? it.contentSnippet.replace(/\s+/g, ' ').trim().slice(0, 500) : undefined,
  }));

  return sendJson(res, 200, {
    ok: true, url: f.finalUrl, title: feed.title || undefined, description: feed.description || undefined,
    link: feed.link || undefined, count: items.length, items, ms: Date.now() - started,
  });
};
