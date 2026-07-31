// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/web.js
// Regenerate: node scripts/sync-shared.js
// Agent Web Tools. Ten tools that fetch, parse and inspect things on the open web.
//
// Response shapes match what the hosted API returns today, field for field, because web-tools-mcp is
// a facade over this and anyone already parsing its output must keep working. Fields may be added,
// never renamed or removed. The only field dropped is `upgrade`, which was a hosted-API sales note
// and means nothing on a local install.
//
// Optional parsers. Five of these need a real HTML or feed parser (cheerio, jsdom,
// @mozilla/readability, turndown, rss-parser) and the core depends on none of them. They are loaded
// on first use inside the handler, and a missing one is reported by name with the install command.
// That matters more than it sounds: the alternative failure is `{ ok: true, data: {} }`, which reads
// as "the page has nothing on it" when what actually happened is "nothing was ever parsed". Same bug
// class as a lookup that fails and gets reported as "not sanctioned".
//
// Every tool here is a network tool, so all ten report unavailable in offline mode. Every fetch of a
// user-supplied URL goes through safeFetch, including the header inspector, which used to carry its
// own hand-rolled SSRF check. One guard, one place to fix it.

const dns = require('dns').promises;
const tls = require('tls');
const { isIP } = require('net');

const { safeFetch, isPrivateIp, defaultTransport } = require('../lib/net');
const { unavailable } = require('./_schema');
const email = require('../engines/email');

// ---------------------------------------------------------------------------
// Optional dependencies

// Loaded once and remembered, so a missing package costs one failed require rather than one per
// call. `error` is kept only when the require failed for a reason other than the package simply not
// being there, because "not installed" and "installed but broken" need different fixes.
const _optional = new Map();
function optional(name) {
  if (!_optional.has(name)) {
    try {
      _optional.set(name, { mod: require(name), error: null });
    } catch (e) {
      const absent = e && e.code === 'MODULE_NOT_FOUND' && String(e.message).includes(`'${name}'`);
      _optional.set(name, { mod: null, error: absent ? null : String((e && e.message) || e) });
    }
  }
  return _optional.get(name);
}

function load(names) {
  const mods = {};
  const missing = [];
  const errors = [];
  for (const n of names) {
    const r = optional(n);
    if (r.mod) mods[n] = r.mod;
    else {
      missing.push(n);
      if (r.error) errors.push(`${n}: ${r.error}`);
    }
  }
  return { mods, missing, errors };
}

// What a tool returns when it cannot parse because the parser is not there. Deliberately shaped like
// unavailable() from _schema.js: ok:false, verdict unknown, checked false. An agent must not be able
// to mistake this for "I looked and found nothing".
function missingPackages(tool, wanted, missing, errors) {
  const one = missing.length === 1;
  const state = errors && errors.length
    ? 'which could not be loaded'
    : one ? 'which is not installed' : 'which are not installed';
  const out = {
    ok: false,
    tool,
    verdict: 'unknown',
    checked: false,
    error: `${tool} needs the optional ${one ? 'package' : 'packages'} ${missing.join(', ')}, ${state}`,
    needs_packages: wanted,
    missing_packages: missing,
    advice: `Install ${one ? 'it' : 'them'} with "npm install ${missing.join(' ')}" and call ${tool} again. Nothing was parsed, so this is an unknown result, not a page with no content.`,
  };
  if (errors && errors.length) out.detail = errors.join('; ');
  return out;
}

// ---------------------------------------------------------------------------
// Shared helpers

// dns_lookup, domain_info and ssl_check all take "a host" in whatever shape it arrives: a bare
// domain, a full URL, a host:port. Reduce it the way the hosted endpoints did, and refuse anything
// that is a private or loopback target in disguise. ssl_check connects, so this is a real guard for
// it; for the other two it stops the tools being used to map an internal network.
function hostArg(raw) {
  let h = String(raw || '').trim().toLowerCase();
  if (!h) return { error: 'missing' };
  try { if (h.includes('://')) h = new URL(h).hostname; } catch {}
  h = h.replace(/^\[|\]$/g, '');
  // An IP literal never reaches the domain-shaped test below, so judge it here. Public literals were
  // rejected as invalid by the hosted endpoints too; private ones get their own answer.
  if (isIP(h)) return isPrivateIp(h) ? { error: 'private' } : { error: 'invalid' };
  h = h.replace(/\/.*$/, '').replace(/:.*$/, '');
  if (isIP(h)) return isPrivateIp(h) ? { error: 'private' } : { error: 'invalid' };
  if (h === 'localhost' || h.endsWith('.localhost')) return { error: 'private' };
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(h)) return { error: 'invalid' };
  return { host: h };
}

function abs(href, base) {
  if (!href) return '';
  try { return new URL(href, base).href; } catch { return ''; }
}

// Node's http headers keep repeated fields (set-cookie) as an array. The hosted endpoint went
// through fetch(), whose Headers view joins repeats into one string, so join them here and keep
// `headers` a flat string map.
function flatHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) out[k] = Array.isArray(v) ? v.join(', ') : String(v);
  return out;
}

const str = (v) => String(v === undefined || v === null ? '' : v).trim();

module.exports = [
  {
    name: 'read_url',
    product: 'agent-tools',
    description:
      'Fetch a web page and return its main readable content as Markdown, with navigation, ads and boilerplate ' +
      'stripped. HTML only: any other content type is refused rather than guessed at. No JavaScript is executed, ' +
      'so a page that builds its text in the browser comes back with little or nothing, and the response says so.',
    needs: ['the target website'],
    needsPackages: ['jsdom', 'turndown', '@mozilla/readability'],
    input: { url: { type: 'string', description: 'The http(s) URL of the page to read. Fetching is SSRF-guarded.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const target = str(args.url);
      if (!target) return { ok: false, error: 'Provide url' };
      if (ctx.offline) return unavailable('read_url', ['the target website'], 'offline mode: the page has to be fetched');

      // jsdom and turndown are required. Readability is not: without it we still return the page,
      // as the whole body rather than the article, and the response records that it degraded.
      const { mods, missing, errors } = load(['jsdom', 'turndown', '@mozilla/readability']);
      const hard = missing.filter((m) => m !== '@mozilla/readability');
      if (hard.length) return missingPackages('read_url', ['jsdom', 'turndown', '@mozilla/readability'], hard, errors);

      const f = await safeFetch(target, { accept: 'text/html,application/xhtml+xml', maxBytes: 5 * 1024 * 1024 });
      if (!f.ok) return { ok: false, error: f.error, detail: f.detail };
      if (!/text\/html|application\/xhtml/i.test(f.contentType || '')) {
        return { ok: false, error: `Unsupported content-type: ${f.contentType || 'unknown'}`, url: f.finalUrl };
      }

      const { JSDOM } = mods.jsdom;
      const TurndownService = mods.turndown;
      const Readability = mods['@mozilla/readability'] && mods['@mozilla/readability'].Readability;

      let title = '', byline = '', excerpt = '', markdown = '';
      try {
        const dom = new JSDOM(f.text, { url: f.finalUrl });
        const td = new TurndownService({ headingStyle: 'atx', codeBlockStyle: 'fenced', bulletListMarker: '-' });
        let article = null;
        if (Readability) { try { article = new Readability(dom.window.document).parse(); } catch {} }
        if (article && article.content) {
          title = article.title || dom.window.document.title || '';
          byline = article.byline || '';
          excerpt = article.excerpt || '';
          markdown = td.turndown(article.content);
        } else {
          title = dom.window.document.title || '';
          const b = dom.window.document.body;
          markdown = td.turndown(b ? b.innerHTML : f.text);
        }
        markdown = markdown.replace(/\n{3,}/g, '\n\n').trim();
      } catch (e) {
        return { ok: false, error: 'Failed to parse content', detail: String((e && e.message) || e) };
      }

      const words = markdown ? markdown.split(/\s+/).filter(Boolean).length : 0;
      const out = {
        ok: true, url: f.finalUrl, title,
        byline: byline || undefined, excerpt: excerpt || undefined,
        words, chars: markdown.length,
        ms: Date.now() - t0, markdown,
      };
      if (!Readability) {
        out.checks_skipped = [{ id: 'readability', reason: '@mozilla/readability is not installed, so this is the whole page rather than the main article' }];
      }
      // An empty article is a result an agent will read as "this page is blank". Say which of the
      // likely reasons it is instead.
      if (!words) out.note = 'No readable text was extracted. The page probably renders its content with JavaScript, which is not executed here, or it is behind a paywall or bot check.';
      return out;
    },
  },

  {
    name: 'unfurl_url',
    product: 'agent-tools',
    description:
      'Read a URL\'s declared metadata for a link preview: title, description, preview image, site name, favicon, ' +
      'canonical URL, language. This is what the page says about itself in its own meta tags, not a verified fact ' +
      'about it. Cheaper than read_url when you only need to know what a link is.',
    needs: ['the target website'],
    needsPackages: ['cheerio'],
    input: { url: { type: 'string', description: 'The http(s) URL to unfurl. Fetching is SSRF-guarded.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const target = str(args.url);
      if (!target) return { ok: false, error: 'Provide url' };
      if (ctx.offline) return unavailable('unfurl_url', ['the target website'], 'offline mode: the page has to be fetched');
      const { mods, missing, errors } = load(['cheerio']);
      if (missing.length) return missingPackages('unfurl_url', ['cheerio'], missing, errors);

      const f = await safeFetch(target, { accept: 'text/html,application/xhtml+xml' });
      if (!f.ok) return { ok: false, error: f.error, detail: f.detail };

      try {
        const $ = mods.cheerio.load(f.text);
        const m = (names) => {
          for (const n of names) {
            const c = $(`meta[property="${n}"]`).attr('content') || $(`meta[name="${n}"]`).attr('content');
            if (c && c.trim()) return c.trim();
          }
          return '';
        };
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
        $('link[rel]').each((_, el) => {
          const rel = ($(el).attr('rel') || '').toLowerCase();
          if (!favicon && /(^|\s)(icon|shortcut icon|apple-touch-icon)(\s|$)/.test(rel)) favicon = abs($(el).attr('href'), f.finalUrl);
        });
        // The /favicon.ico guess is a convention, not something we fetched and confirmed exists.
        if (!favicon) { try { favicon = new URL('/favicon.ico', f.finalUrl).href; } catch {} }

        return {
          ok: true, url: f.finalUrl, title,
          description: description || undefined, image: image || undefined,
          siteName: siteName || undefined, type: type || undefined, author: author || undefined,
          themeColor: themeColor || undefined, canonical: canonical || undefined, favicon: favicon || undefined,
          lang: lang || undefined, ms: Date.now() - t0,
        };
      } catch (e) {
        return { ok: false, error: 'Failed to parse metadata', detail: String((e && e.message) || e) };
      }
    },
  },

  {
    name: 'validate_email',
    product: 'agent-tools',
    description:
      'Validate an email address: syntax, a live MX or A lookup on the domain, and disposable, role and free-provider ' +
      'flags. Returns a deliverability call and a 0 to 1 quality score. There is no SMTP probe, so this says the ' +
      'domain can receive mail, never that the specific mailbox exists. The disposable list is fetched and falls back ' +
      'to a small built-in set when it cannot be reached, so a false "not disposable" is possible.',
    needs: ['DNS (MX/A)', 'disposable-email-domains list'],
    input: { email: { type: 'string', description: 'The email address to validate.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const addr = str(args.email);
      if (!addr) return { ok: false, error: 'Provide email' };
      if (ctx.offline) return unavailable('validate_email', ['DNS (MX/A)', 'the disposable-domains list'], 'offline mode: syntax alone is not a deliverability answer');

      const SYNTAX = /^[^\s@"]+(\.[^\s@"]+)*@[^\s@.]+(\.[^\s@.]+)+$/;
      const ROLE = new Set(['admin', 'administrator', 'info', 'support', 'sales', 'contact', 'billing', 'help', 'helpdesk', 'postmaster', 'webmaster', 'hostmaster', 'abuse', 'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'marketing', 'team', 'office', 'hello', 'enquiries', 'inquiries', 'careers', 'jobs', 'hr', 'press', 'media', 'security', 'privacy', 'legal', 'accounts', 'accounting', 'finance', 'service', 'services', 'newsletter', 'notifications', 'notification', 'root']);
      const FREE = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'zoho.com', 'yandex.com', 'mail.com', 'mail.ru', 'fastmail.com', 'hey.com', 'tutanota.com', 'tuta.io']);

      const validSyntax = addr.length <= 254 && SYNTAX.test(addr);
      const at = addr.lastIndexOf('@');
      const local = at >= 0 ? addr.slice(0, at) : '';
      const domain = at >= 0 ? addr.slice(at + 1).toLowerCase() : '';

      let hasMx = false, hasA = false, mx = [];
      const skipped = [];
      if (validSyntax && domain) {
        try {
          const recs = await dns.resolveMx(domain);
          if (recs && recs.length) { hasMx = true; mx = recs.sort((a, b) => a.priority - b.priority).slice(0, 5).map((r) => r.exchange); }
        } catch (e) {
          // ENODATA/ENOTFOUND mean the query ran and there is no MX. Anything else means the query
          // did not run, and "no MX" would be an answer we did not earn.
          const code = (e && e.code) || 'ERROR';
          if (code !== 'ENODATA' && code !== 'ENOTFOUND') skipped.push({ id: 'mx', reason: code });
        }
        if (!hasMx) {
          try {
            const a = await dns.resolve4(domain).catch(() => dns.resolve6(domain));
            if (a && a.length) hasA = true;
          } catch (e) {
            const code = (e && e.code) || 'ERROR';
            if (code !== 'ENODATA' && code !== 'ENOTFOUND') skipped.push({ id: 'a', reason: code });
          }
        }
      }
      // Both DNS halves failing for a reason other than "no such record" means we know nothing about
      // this domain, and a 0.2 score would read as a verdict.
      if (skipped.length >= 2) return unavailable('validate_email', ['DNS (MX/A)'], `DNS lookups failed: ${skipped.map((s) => `${s.id} ${s.reason}`).join(', ')}`);

      const acceptsMail = hasMx || hasA;
      const isDisposable = domain ? await email.isDisposable(domain) : false;
      const isRole = local ? ROLE.has(local.toLowerCase()) : false;
      const isFree = domain ? FREE.has(domain) : false;
      const deliverable = validSyntax && acceptsMail && !isDisposable;
      const score = !validSyntax ? 0 : !acceptsMail ? 0.2 : isDisposable ? 0.25 : isRole ? 0.7 : isFree ? 0.85 : 0.95;

      const out = {
        ok: true, email: addr, valid_syntax: validSyntax, local: local || undefined, domain: domain || undefined,
        has_mx: hasMx, accepts_mail: acceptsMail, mx_records: mx.length ? mx : undefined,
        disposable: isDisposable, role_account: isRole, free_provider: isFree,
        deliverable, score, ms: Date.now() - t0,
      };
      if (skipped.length) out.checks_skipped = skipped;
      return out;
    },
  },

  {
    name: 'extract_web',
    product: 'agent-tools',
    description:
      'Pull specific values out of a web page with CSS selectors. Pass selectors as {key: "css"}. Suffix a selector ' +
      'with @attr for an attribute and with [] for every match, so "a.item[]@href" returns an array of links. ' +
      'href, src, data-src and poster values are resolved to absolute URLs. Static HTML only: nothing is executed, ' +
      'and a selector that matches nothing returns null or an empty array rather than an error.',
    needs: ['the target website'],
    needsPackages: ['cheerio'],
    input: {
      url: { type: 'string', description: 'Page URL to scrape. Fetching is SSRF-guarded.' },
      selectors: { type: 'record', description: 'Map of output key to CSS selector.' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const target = str(args.url);
      let selectors = args.selectors;
      if (!target) return { ok: false, error: 'Provide url' };
      if (selectors == null) return { ok: false, error: 'Provide selectors: a JSON object {key:"css"}; suffix @attr for an attribute, [] for all matches.' };
      if (typeof selectors === 'string') { try { selectors = JSON.parse(selectors); } catch { return { ok: false, error: 'selectors must be valid JSON' }; } }
      if (typeof selectors !== 'object' || Array.isArray(selectors)) return { ok: false, error: 'selectors must be a JSON object of {key: "css selector"}' };
      const keys = Object.keys(selectors);
      if (keys.length === 0 || keys.length > 50) return { ok: false, error: 'Provide 1-50 selectors' };
      if (ctx.offline) return unavailable('extract_web', ['the target website'], 'offline mode: the page has to be fetched');
      const { mods, missing, errors } = load(['cheerio']);
      if (missing.length) return missingPackages('extract_web', ['cheerio'], missing, errors);

      const f = await safeFetch(target, { accept: 'text/html,application/xhtml+xml' });
      if (!f.ok) return { ok: false, error: f.error, detail: f.detail };

      const data = {};
      try {
        const $ = mods.cheerio.load(f.text);
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
          // A selector cheerio cannot parse is that one key's problem, not the whole call's.
          try { els = $(sel); } catch { data[key] = all ? [] : null; continue; }
          if (all) data[key] = els.map((_, el) => getVal(el)).get().filter(Boolean);
          else data[key] = els.length ? getVal(els.first()) : null;
        }
      } catch (e) {
        return { ok: false, error: 'Extraction failed', detail: String((e && e.message) || e) };
      }
      return { ok: true, url: f.finalUrl, data, ms: Date.now() - t0 };
    },
  },

  {
    name: 'get_feed',
    product: 'agent-tools',
    description:
      'Fetch an RSS or Atom feed and return its items as JSON: title, link, date, author, categories, snippet. ' +
      'Whatever the feed publishes is what you get, including its idea of dates and ordering. A page that is not a ' +
      'feed is reported as such rather than parsed into an empty list.',
    needs: ['the feed URL'],
    needsPackages: ['rss-parser'],
    input: {
      url: { type: 'string', description: 'Feed URL. Fetching is SSRF-guarded.' },
      limit: { type: 'number', optional: true, description: 'Max items, 1 to 100 (default 25).' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const target = str(args.url);
      if (!target) return { ok: false, error: 'Provide url' };
      const limit = Math.min(100, Math.max(1, parseInt(args.limit, 10) || 25));
      if (ctx.offline) return unavailable('get_feed', ['the feed URL'], 'offline mode: the feed has to be fetched');
      const { mods, missing, errors } = load(['rss-parser']);
      if (missing.length) return missingPackages('get_feed', ['rss-parser'], missing, errors);

      const f = await safeFetch(target, { accept: 'application/rss+xml,application/atom+xml,application/xml,text/xml,*/*' });
      if (!f.ok) return { ok: false, error: f.error, detail: f.detail };

      let feed;
      try {
        // The feed is fetched by safeFetch and handed over as text. rss-parser never does its own
        // request here, so its redirect and timeout handling never runs and cannot skip the guard.
        const parser = new mods['rss-parser']();
        feed = await parser.parseString(f.text);
      } catch (e) {
        return { ok: false, error: 'Not a valid RSS/Atom feed', detail: String((e && e.message) || e) };
      }

      const items = (feed.items || []).slice(0, limit).map((it) => ({
        title: it.title || undefined,
        link: it.link || undefined,
        isoDate: it.isoDate || it.pubDate || undefined,
        author: it.creator || it.author || undefined,
        categories: it.categories && it.categories.length ? it.categories.slice(0, 10) : undefined,
        contentSnippet: it.contentSnippet ? it.contentSnippet.replace(/\s+/g, ' ').trim().slice(0, 500) : undefined,
      }));

      return {
        ok: true, url: f.finalUrl, title: feed.title || undefined, description: feed.description || undefined,
        link: feed.link || undefined, count: items.length, items, ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'dns_lookup',
    product: 'agent-tools',
    description:
      'Look up DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV) and report whether SPF and ' +
      'DMARC are published. Uses this machine\'s resolver, so the answers are whatever it returns, cache and all. ' +
      'A record type whose query failed is listed in checks_skipped rather than reported as absent.',
    needs: ['DNS'],
    input: {
      domain: { type: 'string', description: 'Domain name.' },
      type: { type: 'string', optional: true, description: 'Record type or "all" (default).' },
    },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV'];
      const h = hostArg(args.domain);
      if (h.error === 'missing') return { ok: false, error: 'Provide domain' };
      if (h.error === 'private') return { ok: false, error: 'Refusing to look up a private/loopback address' };
      if (h.error) return { ok: false, error: 'Invalid domain' };
      const domain = h.host;
      const type = String(args.type || 'all').toUpperCase();
      if (type !== 'ALL' && !TYPES.includes(type)) return { ok: false, error: `Unsupported type. Use: ${TYPES.join(', ')} or all` };
      if (ctx.offline) return unavailable('dns_lookup', ['DNS'], 'offline mode: every answer here comes from a resolver');

      const want = type === 'ALL' ? ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] : [type];
      const records = {};
      const skipped = [];
      await Promise.all(want.map(async (t) => {
        try {
          let r;
          if (t === 'A') r = await dns.resolve4(domain);
          else if (t === 'AAAA') r = await dns.resolve6(domain);
          else if (t === 'MX') r = (await dns.resolveMx(domain)).sort((a, b) => a.priority - b.priority);
          else if (t === 'TXT') r = (await dns.resolveTxt(domain)).map((a) => a.join(''));
          else r = await dns.resolve(domain, t);
          // SOA answers with an object, not an array. The hosted endpoint tested `r.length` on
          // everything, so SOA was advertised and then silently dropped from every response.
          if (Array.isArray(r) ? r.length > 0 : !!r) records[t] = r;
        } catch (e) {
          // ENODATA and ENOTFOUND are real answers: the query ran, there is nothing of that type.
          // SERVFAIL, timeouts and refusals are not answers, and must not read as "no record".
          const code = (e && e.code) || 'ERROR';
          if (code !== 'ENODATA' && code !== 'ENOTFOUND') skipped.push({ id: t, reason: code });
        }
      }));

      if (skipped.length === want.length) {
        return unavailable('dns_lookup', ['DNS'], `every query failed: ${skipped.map((s) => `${s.id} ${s.reason}`).join(', ')}`);
      }

      const txt = records.TXT || [];
      const spf = txt.find((t) => /^v=spf1/i.test(t)) || null;
      let dmarc = null;
      try {
        const d = await dns.resolveTxt('_dmarc.' + domain);
        dmarc = d.map((a) => a.join('')).find((t) => /^v=DMARC1/i.test(t)) || null;
      } catch (e) {
        const code = (e && e.code) || 'ERROR';
        if (code !== 'ENODATA' && code !== 'ENOTFOUND') skipped.push({ id: 'DMARC', reason: code });
      }
      // email_auth reads SPF out of TXT and has_mx out of MX. If either query did not run, whether
      // because it failed or because a single type was asked for, the false in that field means "not
      // checked" and has to say so.
      if (skipped.some((s) => s.id === 'TXT')) skipped.push({ id: 'SPF', reason: 'the TXT lookup failed, so no SPF record could be read' });
      else if (!want.includes('TXT')) skipped.push({ id: 'SPF', reason: `only ${type} records were requested, so SPF was not read` });
      if (!want.includes('MX')) skipped.push({ id: 'has_mx', reason: `only ${type} records were requested, so MX was not read` });

      const out = {
        ok: true, domain, records,
        email_auth: {
          has_mx: !!records.MX,
          spf: !!spf, spf_record: spf || undefined,
          dmarc: !!dmarc, dmarc_record: dmarc || undefined,
        },
        ms: Date.now() - t0,
      };
      if (skipped.length) out.checks_skipped = skipped;
      return out;
    },
  },

  {
    name: 'domain_info',
    product: 'agent-tools',
    description:
      'Registration facts for a domain from RDAP, the JSON successor to WHOIS: creation and expiry dates, age in ' +
      'days, registrar, status, nameservers. Age is the useful signal, since a domain registered days ago is a ' +
      'common fraud marker. Coverage depends on the registry: some ccTLDs publish little or nothing through RDAP.',
    needs: ['rdap.org'],
    input: { domain: { type: 'string', description: 'Domain name.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const h = hostArg(args.domain);
      if (h.error === 'missing') return { ok: false, error: 'Provide domain' };
      if (h.error === 'private') return { ok: false, error: 'Refusing to look up a private/loopback address' };
      if (h.error) return { ok: false, error: 'Invalid domain' };
      const name = h.host;
      if (ctx.offline) return unavailable('domain_info', ['rdap.org'], 'offline mode: registration data is entirely remote');

      // rdap.org is a redirector: it answers with a 30x to the registry that actually holds the
      // record. safeFetch re-checks every one of those hops, which a plain fetch would not.
      const r = await safeFetch(`https://rdap.org/domain/${encodeURIComponent(name)}`, {
        accept: 'application/rdap+json, application/json',
        timeoutMs: 8000,
      });
      if (!r.ok) {
        if (r.status === 404) return { ok: false, error: 'Domain not found or not registered', domain: name };
        if (typeof r.status === 'number') return { ok: false, error: `RDAP returned HTTP ${r.status}`, domain: name };
        return { ok: false, error: 'RDAP lookup failed or timed out', detail: r.detail || r.error, domain: name };
      }

      let d;
      try { d = JSON.parse(r.text); } catch (e) { return { ok: false, error: 'RDAP returned something that is not JSON', detail: String((e && e.message) || e), domain: name }; }

      const ev = d.events || [];
      const evDate = (a) => { const e = ev.find((x) => x.eventAction === a); return e ? e.eventDate : undefined; };
      const registration = evDate('registration');
      const expiration = evDate('expiration');
      const lastChanged = evDate('last changed');
      const ageDays = registration ? Math.floor((Date.now() - new Date(registration)) / 86400000) : undefined;
      const expiresInDays = expiration ? Math.floor((new Date(expiration) - Date.now()) / 86400000) : undefined;

      let registrar;
      const reg = (d.entities || []).find((e) => (e.roles || []).includes('registrar'));
      if (reg && Array.isArray(reg.vcardArray) && reg.vcardArray[1]) {
        const fn = reg.vcardArray[1].find((x) => x[0] === 'fn');
        if (fn) registrar = fn[3];
      }

      const out = {
        ok: true, domain: (d.ldhName || name).toLowerCase(), status: d.status || undefined,
        registration: registration || undefined, expiration: expiration || undefined, last_changed: lastChanged || undefined,
        age_days: ageDays, expires_in_days: expiresInDays, registrar: registrar || undefined,
        nameservers: (d.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
        ms: Date.now() - t0,
      };
      // An undefined age is "the registry did not publish a creation date", not "brand new" and not
      // "old". Callers scoring on age need to be able to tell those apart.
      if (ageDays === undefined) out.checks_skipped = [{ id: 'domain-age', reason: 'this registry published no registration date' }];
      return out;
    },
  },

  {
    name: 'ssl_check',
    product: 'agent-tools',
    description:
      'Open a TLS connection to a host on port 443 and report its certificate: issuer, subject, validity window, ' +
      'days remaining, SANs, protocol, and whether it validates against the system trust store. Port 443 only, and ' +
      'this reads one certificate rather than grading the configuration the way a full TLS scanner would.',
    needs: ['the target host on port 443'],
    input: { host: { type: 'string', description: 'Hostname, for example example.com.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const h = hostArg(args.host);
      if (h.error === 'missing') return { ok: false, error: 'Provide host' };
      if (h.error === 'private') return { ok: false, error: 'Refusing to connect to a private/loopback address' };
      if (h.error) return { ok: false, error: 'Invalid host' };
      const host = h.host;
      if (ctx.offline) return unavailable('ssl_check', ['the target host on port 443'], 'offline mode: the certificate has to be read off a live connection');

      // Resolve first and refuse if anything the name points at is private, then connect to that one
      // address with the hostname still presented for SNI and certificate validation. Same reasoning
      // as lib/net.js: resolving twice is what lets a hostile resolver answer differently the second
      // time, so we pin the address we checked.
      let addresses;
      try {
        addresses = (await dns.lookup(host, { all: true })).map((a) => a.address);
      } catch (e) {
        return { ok: false, error: 'TLS connection failed', detail: `could not resolve host: ${String((e && e.code) || (e && e.message) || e)}`, host };
      }
      const bad = addresses.find((a) => isPrivateIp(a));
      if (bad) return { ok: false, error: 'Refusing to connect to a private/loopback address', detail: `${host} resolves to ${bad}`, host };
      const ip = addresses[0];

      const result = await new Promise((resolve) => {
        let settled = false;
        const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
        // rejectUnauthorized stays false on purpose: an expired or self-signed certificate is a
        // result to report, not a connection to refuse. `trusted` carries the verdict.
        const socket = tls.connect({ host: ip, servername: host, port: 443, timeout: 8000, rejectUnauthorized: false }, () => {
          try {
            const cert = socket.getPeerCertificate(false);
            finish({ cert, proto: socket.getProtocol(), authorized: socket.authorized });
          } catch (e) {
            finish({ error: String((e && e.message) || e) });
          } finally { try { socket.end(); } catch {} }
        });
        socket.on('error', (e) => finish({ error: String((e && e.message) || e) }));
        socket.on('timeout', () => { finish({ error: 'connection timed out' }); try { socket.destroy(); } catch {} });
      });

      if (result.error) return { ok: false, error: 'TLS connection failed', detail: result.error, host };
      const c = result.cert || {};
      const validTo = c.valid_to ? new Date(c.valid_to) : null;
      const daysRemaining = validTo ? Math.floor((validTo - Date.now()) / 86400000) : undefined;
      const sans = c.subjectaltname ? c.subjectaltname.split(',').map((s) => s.replace(/^\s*DNS:/, '').trim()) : undefined;

      return {
        ok: true, host, protocol: result.proto || undefined, trusted: !!result.authorized,
        issuer: c.issuer ? (c.issuer.O || c.issuer.CN) : undefined,
        subject: c.subject ? c.subject.CN : undefined,
        valid_from: c.valid_from || undefined, valid_to: c.valid_to || undefined,
        days_remaining: daysRemaining, expired: daysRemaining !== undefined ? daysRemaining < 0 : undefined,
        sans, serial: c.serialNumber || undefined,
        connected_ip: ip, ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'http_inspect',
    product: 'agent-tools',
    description:
      'Request a URL and report the final status, the full redirect chain, every response header, and which security ' +
      'headers are present (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). ' +
      'Presence is all this checks: a CSP that allows everything still counts as present. A 404 or a 500 is a result, ' +
      'not an error. GET only, and redirects stop at 5 hops.',
    needs: ['the target URL'],
    input: { url: { type: 'string', description: 'URL to inspect. A missing scheme is treated as https. Fetching is SSRF-guarded.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      let target = str(args.url);
      if (!target) return { ok: false, error: 'Provide url' };
      // A bare host means https, as it did on the hosted endpoint. A scheme we cannot inspect is
      // refused here: the hosted version prepended https to it and then failed to resolve
      // "https://ftp://host", so its protocol check never actually ran.
      const scheme = target.match(/^([a-z][a-z0-9+.-]*):\/\//i);
      if (scheme && !/^https?$/i.test(scheme[1])) return { ok: false, error: 'Only http/https URLs are supported' };
      if (!scheme) target = 'https://' + target;
      if (ctx.offline) return unavailable('http_inspect', ['the target URL'], 'offline mode: headers only exist on a live response');

      // This tool used to walk redirects itself with its own dns.lookup guard, which meant two SSRF
      // implementations to keep correct and only one of them getting the fixes. safeFetch owns the
      // walk now; the transport seam is how the per-hop status and the headers get back out, so the
      // guard is still the single one in lib/net.js.
      const seen = [];
      const transport = async (u, ip, opts) => {
        const res = await defaultTransport(u, ip, opts);
        seen.push({ url: u.href, status: res.status, headers: flatHeaders(res.headers), ip: res.connectedIp || ip });
        return res;
      };
      const r = await safeFetch(target, { transport, accept: '*/*' });

      const chain = seen.map((hop, i) => {
        const entry = { url: hop.url };
        if (typeof hop.status === 'number') entry.status = hop.status;
        // Every non-final hop in the trail is a redirect, and the hop after it is where it went.
        if (seen[i + 1]) entry.location = seen[i + 1].url;
        return entry;
      });

      // safeFetch reports a non-2xx final response as a failure. For an inspector it is the answer,
      // and `status` is set only on that branch, so it is what tells the two cases apart.
      const answered = seen.filter((hop) => typeof hop.status === 'number');
      if (!r.ok && typeof r.status !== 'number') {
        const out = { ok: false, error: r.error, chain };
        if (r.detail) out.detail = r.detail;
        return out;
      }
      if (!answered.length) return { ok: false, error: 'Request failed or timed out', detail: 'no response was received', chain };

      const last = answered[answered.length - 1];
      const headers = last.headers;
      const security = {
        hsts: !!headers['strict-transport-security'],
        csp: !!headers['content-security-policy'],
        x_frame_options: headers['x-frame-options'] || undefined,
        x_content_type_options: headers['x-content-type-options'] || undefined,
        referrer_policy: headers['referrer-policy'] || undefined,
        permissions_policy: headers['permissions-policy'] || undefined,
      };

      return {
        ok: true, url: target, final_url: last.url, status: last.status,
        redirects: Math.max(0, chain.length - 1), chain,
        server: headers['server'] || undefined, content_type: headers['content-type'] || undefined,
        security, headers, connected_ip: last.ip, ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'structured_data',
    product: 'agent-tools',
    description:
      'Pull a page\'s machine-readable structured data: JSON-LD (schema.org), OpenGraph and Twitter card tags, plus ' +
      'the schema.org types declared. This is the page describing itself, so treat prices, ratings and availability ' +
      'as claims. JSON-LD that does not parse is skipped rather than repaired.',
    needs: ['the target website'],
    needsPackages: ['cheerio'],
    input: { url: { type: 'string', description: 'Page URL. Fetching is SSRF-guarded.' } },
    async run(args, ctx = {}) {
      const t0 = Date.now();
      const target = str(args.url);
      if (!target) return { ok: false, error: 'Provide url' };
      if (ctx.offline) return unavailable('structured_data', ['the target website'], 'offline mode: the page has to be fetched');
      const { mods, missing, errors } = load(['cheerio']);
      if (missing.length) return missingPackages('structured_data', ['cheerio'], missing, errors);

      const f = await safeFetch(target, { accept: 'text/html,application/xhtml+xml' });
      if (!f.ok) return { ok: false, error: f.error, detail: f.detail };

      try {
        const $ = mods.cheerio.load(f.text);
        const jsonld = [];
        let unparsable = 0;
        $('script[type="application/ld+json"]').each((_, el) => {
          const raw = $(el).contents().text();
          try { jsonld.push(JSON.parse(raw)); } catch { unparsable++; }
        });

        const og = {};
        $('meta[property^="og:"]').each((_, el) => {
          const p = ($(el).attr('property') || '').slice(3);
          const c = $(el).attr('content');
          if (p && c && og[p] === undefined) og[p] = c;
        });
        const twitter = {};
        $('meta[name^="twitter:"]').each((_, el) => {
          const p = ($(el).attr('name') || '').slice(8);
          const c = $(el).attr('content');
          if (p && c && twitter[p] === undefined) twitter[p] = c;
        });

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

        const out = {
          ok: true, url: f.finalUrl,
          schema_types: [...new Set(types)],
          jsonld: jsonld.length ? jsonld : undefined,
          opengraph: Object.keys(og).length ? og : undefined,
          twitter: Object.keys(twitter).length ? twitter : undefined,
          counts: { jsonld: jsonld.length, opengraph: Object.keys(og).length, twitter: Object.keys(twitter).length },
          ms: Date.now() - t0,
        };
        // A block of broken JSON-LD is not the same as a page with no JSON-LD.
        if (unparsable) out.checks_skipped = [{ id: 'jsonld', reason: `${unparsable} ld+json block${unparsable === 1 ? '' : 's'} did not parse as JSON` }];
        return out;
      } catch (e) {
        return { ok: false, error: 'Failed to parse structured data', detail: String((e && e.message) || e) };
      }
    },
  },
];
