// Web extract: fetch a page and pull structured data with CSS selectors.
// GET  /api/extract?url=...&selectors={"title":"h1","prices":".price[]","links":"a.item@href[]"}
// POST { "url": "...", "selectors": { ... } }
// Selector syntax: "css"  -> first match text;  "css@attr" -> attribute;  "css[]" -> all matches (array).
// href/src attributes are resolved to absolute URLs. Deterministic, cheerio-based, no LLM.

const cheerio = require('cheerio');
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const body = req.body || {};
  const url = q.url || body.url;
  let selectors = q.selectors || body.selectors;
  if (!url) return sendJson(res, 400, { ok: false, error: 'Missing required url parameter' });
  if (selectors == null) return sendJson(res, 400, { ok: false, error: 'Missing selectors. JSON object {key:"css"}; suffix @attr for an attribute, [] for all matches.' });
  if (typeof selectors === 'string') { try { selectors = JSON.parse(selectors); } catch { return sendJson(res, 400, { ok: false, error: 'selectors must be valid JSON' }); } }
  if (typeof selectors !== 'object' || Array.isArray(selectors)) return sendJson(res, 400, { ok: false, error: 'selectors must be a JSON object of {key: "css selector"}' });
  const keys = Object.keys(selectors);
  if (keys.length === 0 || keys.length > 50) return sendJson(res, 400, { ok: false, error: 'Provide 1-50 selectors' });

  const f = await safeFetch(url, { accept: 'text/html,application/xhtml+xml' });
  if (!f.ok) return sendJson(res, f.code || 502, { ok: false, error: f.error, detail: f.detail });

  const data = {};
  try {
    const $ = cheerio.load(f.text);
    for (const key of keys) {
      let sel = String(selectors[key]);
      let attr = null, all = false;
      const atIdx = sel.lastIndexOf('@');
      if (atIdx > 0) { attr = sel.slice(atIdx + 1).trim(); sel = sel.slice(0, atIdx); }
      sel = sel.trim();
      if (sel.endsWith('[]')) { all = true; sel = sel.slice(0, -2).trim(); }
      const getVal = (el) => {
        const e = $(el);
        let v = attr ? (e.attr(attr) || '') : e.text();
        v = (v || '').replace(/\s+/g, ' ').trim();
        if (attr && /^(href|src|data-src|poster)$/i.test(attr) && v) { try { v = new URL(v, f.finalUrl).href; } catch {} }
        return v;
      };
      let els;
      try { els = $(sel); } catch { data[key] = all ? [] : null; continue; }
      if (all) data[key] = els.map((_, el) => getVal(el)).get().filter(Boolean);
      else data[key] = els.length ? getVal(els.first()) : null;
    }
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: 'Extraction failed', detail: String((e && e.message) || e) });
  }
  return sendJson(res, 200, { ok: true, url: f.finalUrl, data, ms: Date.now() - started });
};
