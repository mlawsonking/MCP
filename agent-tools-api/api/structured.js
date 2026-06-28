// Structured-data extractor: JSON-LD (schema.org), OpenGraph, and Twitter cards from a page.
// GET /api/structured?url=https://example.com
// Higher-value than basic metadata: returns the machine-readable schema a page declares.
// Deterministic, cheerio-based, $0.

const cheerio = require('cheerio');
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const url = q.url || (req.body && req.body.url);
  if (!url) return sendJson(res, 400, { ok: false, error: 'Missing required ?url= parameter' });

  const f = await safeFetch(url, { accept: 'text/html,application/xhtml+xml' });
  if (!f.ok) return sendJson(res, f.code || 502, { ok: false, error: f.error, detail: f.detail });

  try {
    const $ = cheerio.load(f.text);
    const jsonld = [];
    $('script[type="application/ld+json"]').each((_, el) => {
      const raw = $(el).contents().text();
      try { jsonld.push(JSON.parse(raw)); } catch {}
    });

    const og = {};
    $('meta[property^="og:"]').each((_, el) => { const p = ($(el).attr('property') || '').slice(3); const c = $(el).attr('content'); if (p && c && og[p] === undefined) og[p] = c; });
    const twitter = {};
    $('meta[name^="twitter:"]').each((_, el) => { const p = ($(el).attr('name') || '').slice(8); const c = $(el).attr('content'); if (p && c && twitter[p] === undefined) twitter[p] = c; });

    const types = [];
    const collect = (o) => {
      if (!o) return;
      if (Array.isArray(o)) return o.forEach(collect);
      if (typeof o === 'object') {
        if (o['@type']) [].concat(o['@type']).forEach((t) => typeof t === 'string' && types.push(t));
        if (o['@graph']) collect(o['@graph']);
      }
    };
    jsonld.forEach(collect);

    return sendJson(res, 200, {
      ok: true, url: f.finalUrl,
      schema_types: [...new Set(types)],
      jsonld: jsonld.length ? jsonld : undefined,
      opengraph: Object.keys(og).length ? og : undefined,
      twitter: Object.keys(twitter).length ? twitter : undefined,
      counts: { jsonld: jsonld.length, opengraph: Object.keys(og).length, twitter: Object.keys(twitter).length },
      ms: Date.now() - started,
    });
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Failed to parse structured data', detail: String((e && e.message) || e) });
  }
};
