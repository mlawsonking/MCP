// SSRF-safe fetching.
//
// The threat this file exists to stop is a URL we were handed pointing at something only our server
// can reach: 127.0.0.1, 169.254.169.254 (cloud instance metadata, i.e. credentials), a 10.x admin
// panel. Three separate ways to get there have bitten this code, and all three are closed here:
//
//   1. Check the first hostname, then let fetch follow redirects. A public host that 302s to
//      127.0.0.1 was fetched with the guard none the wiser. Fixed in Phase 0: hops are followed by
//      hand and every one is re-validated.
//   2. Resolve the hostname to check it, then hand the *hostname* to the fetch, which resolves it a
//      second time. An attacker who controls the DNS answers returns a public address to the check
//      and a private one to the fetch (DNS rebinding). Fixed here: we resolve once and connect to
//      that exact address, so there is no second lookup to poison.
//   3. Connection pooling. Node's default agent keys its socket pool on host and port, and the pool
//      key does not include a custom `lookup`. A pooled keep-alive socket from an earlier request is
//      therefore reused for a target we just pinned somewhere else, and the pin never runs. Measured
//      directly: with the default agent a second request to the same hostname pinned to a different
//      IP reported zero lookup calls and came back from the original socket. Every request here sets
//      `agent: false` for that reason. Do not "optimize" it back to a shared keep-alive agent.
//
// Both the resolver and the transport are injectable so the guard can be tested with hostile answers
// instead of hoping a real attacker shows up. A check that cannot be made to fail is not a check.

const dnsPromises = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');

const MAX_REDIRECTS = 5;
const DEFAULT_TIMEOUT_MS = 7000;
const DEFAULT_MAX_BYTES = 3 * 1024 * 1024;
const DEFAULT_UA = 'agent-guards/1.0 (+https://github.com/mlawsonking/MCP)';
const DEFAULT_ACCEPT = 'text/html,application/xhtml+xml,application/xml,application/rss+xml,text/plain';

// Ranges that must never be reachable through a user-supplied URL. Beyond the obvious private
// blocks this covers link-local (cloud metadata lives at 169.254.169.254), carrier NAT, and the
// documentation/benchmark/multicast/reserved space, none of which a legitimate target uses and all
// of which are useful to an attacker probing an internal network.
function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const p = String(ip).split('.').map(Number);
    if (p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // malformed: refuse
    if (p[0] === 0) return true;                                   // 0.0.0.0/8 "this network"
    if (p[0] === 10) return true;                                  // 10/8 private
    if (p[0] === 127) return true;                                 // loopback
    if (p[0] === 169 && p[1] === 254) return true;                 // link-local + cloud metadata
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;     // 172.16/12 private
    if (p[0] === 192 && p[1] === 168) return true;                 // 192.168/16 private
    if (p[0] === 192 && p[1] === 0 && p[2] === 0) return true;     // IETF protocol assignments
    if (p[0] === 192 && p[1] === 0 && p[2] === 2) return true;     // TEST-NET-1
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true;  // benchmarking
    if (p[0] === 198 && p[1] === 51 && p[2] === 100) return true;  // TEST-NET-2
    if (p[0] === 203 && p[1] === 0 && p[2] === 113) return true;   // TEST-NET-3
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;    // carrier-grade NAT
    if (p[0] >= 224) return true;                                  // multicast + reserved + broadcast
    return false;
  }
  // IPv6 is matched on the expanded numeric form, never on the string. `::ffff:127.0.0.1` and
  // `::ffff:7f00:1` are the same address, and `new URL()` hands back the second one — a check
  // written against the dotted spelling passes loopback straight through. That gap was live in this
  // file until the mapped-loopback test caught it.
  const groups = expandIpv6(ip);
  if (!groups) return true; // unparseable: refuse rather than guess

  const leadingZero = (n) => groups.slice(0, n).every((g) => g === 0);
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) both carry a v4 address in the
  // last 32 bits. Judge them by the v4 rules, which is where the interesting ranges live.
  if (leadingZero(5) && (groups[5] === 0xffff || groups[5] === 0)) {
    const isUnspecifiedOrLoopback = groups[5] === 0 && groups[6] === 0 && groups[7] <= 1;
    if (!isUnspecifiedOrLoopback) {
      const v4 = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join('.');
      return isPrivateIp(v4);
    }
  }
  if (groups.every((g) => g === 0)) return true;                    // :: unspecified
  if (leadingZero(7) && groups[7] === 1) return true;               // ::1 loopback
  if ((groups[0] & 0xfe00) === 0xfc00) return true;                 // fc00::/7 unique local
  if ((groups[0] & 0xffc0) === 0xfe80) return true;                 // fe80::/10 link-local
  if ((groups[0] & 0xff00) === 0xff00) return true;                 // ff00::/8 multicast
  if (groups[0] === 0x0064 && groups[1] === 0xff9b) return true;    // 64:ff9b::/96 NAT64 to v4
  return false;
}

// Expand any IPv6 spelling into its eight 16-bit groups. Returns null if it is not a valid IPv6
// address, which callers treat as "refuse".
function expandIpv6(input) {
  let s = String(input).toLowerCase().replace(/^\[|\]$/g, '');
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  if (net.isIPv6(s) !== true && net.isIP(s) !== 6) return null;

  // Rewrite a trailing dotted quad into two hex groups so the rest is uniform.
  const dotted = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) {
    const q = dotted[1].split('.').map(Number);
    if (q.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    const hex = [((q[0] << 8) | q[1]).toString(16), ((q[2] << 8) | q[3]).toString(16)].join(':');
    s = s.slice(0, s.length - dotted[1].length) + hex;
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':').filter((x) => x !== '') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter((x) => x !== '') : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...new Array(fill).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => parseInt(g, 16));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

// The resolver seam. Returns every address a hostname resolves to; we check all of them, because a
// hostname that answers with one public and one private address would otherwise be a coin flip.
async function defaultResolve(hostname) {
  const recs = await dnsPromises.lookup(hostname, { all: true });
  return recs.map((r) => r.address);
}

// The transport seam. Connects to `pinnedIp` and nothing else, while still presenting the original
// hostname for TLS SNI, certificate validation and the Host header.
function defaultTransport(url, pinnedIp, opts) {
  const { method = 'GET', headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES } = opts || {};
  const mod = url.protocol === 'https:' ? https : http;
  return new Promise((resolve) => {
    let connectedIp;
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };

    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: (url.pathname || '/') + (url.search || ''),
        method,
        headers,
        // Never pool. See the note at the top of this file: a reused socket skips the pin entirely.
        agent: false,
        // Force the connection to the address we already validated. Node calls this instead of DNS,
        // so there is no second resolution for an attacker to answer differently.
        lookup: (hostname, o, cb) => {
          const family = pinnedIp.includes(':') ? 6 : 4;
          if (o && o.all) return cb(null, [{ address: pinnedIp, family }]);
          return cb(null, pinnedIp, family);
        },
      },
      (res) => {
        const chunks = [];
        let total = 0;
        let truncated = false;
        res.on('data', (c) => {
          total += c.length;
          if (total > maxBytes) { truncated = true; res.destroy(); return; }
          chunks.push(c);
        });
        res.on('end', () => done({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString('utf-8'),
          truncated,
          connectedIp,
        }));
        res.on('error', () => done({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString('utf-8'),
          truncated,
          connectedIp,
        }));
      }
    );

    req.on('socket', (s) => s.on('connect', () => { connectedIp = s.remoteAddress; }));
    req.on('error', (e) => done({ error: String((e && e.message) || e), connectedIp }));
    req.setTimeout(timeoutMs, () => req.destroy(new Error('timed out')));
    req.end();
  });
}

// Validate one hop: resolve the hostname, refuse if anything it points at is private, and return the
// address we will connect to.
async function checkHop(url, resolve, hop) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: hop === 0 ? 'Only http and https URLs are supported' : 'Refusing to follow a redirect to a non-http(s) URL' };
  }
  // A literal IP in the URL never goes near the resolver.
  const literal = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(literal)) {
    if (isPrivateIp(literal)) {
      return { error: hop === 0 ? 'Refusing to fetch a private/loopback address' : 'Refusing to follow a redirect to a private/loopback address' };
    }
    return { pinned: literal, addresses: [literal] };
  }

  let addresses;
  try {
    addresses = await resolve(url.hostname);
  } catch {
    return { error: 'Could not resolve host' };
  }
  if (!Array.isArray(addresses)) addresses = addresses ? [addresses] : [];
  addresses = addresses.map((a) => (a && a.address ? a.address : a)).filter(Boolean);
  if (!addresses.length) return { error: 'Could not resolve host' };

  // If ANY answer is private, refuse the whole hostname. Picking the public one out of a mixed
  // answer would be a race we do not need to run.
  const bad = addresses.find((a) => isPrivateIp(a));
  if (bad) {
    return { error: hop === 0 ? 'Refusing to fetch a private/loopback address' : 'Refusing to follow a redirect to a private/loopback address', address: bad };
  }
  return { pinned: addresses[0], addresses };
}

// Fetch a URL with every hop validated and pinned.
//
// Returns { ok, code?, error?, text?, finalUrl?, contentType?, status?, detail? } — the shape callers
// already depend on — plus additive fields: connected_ip, hops, resolved_addresses.
async function safeFetch(target, opts = {}) {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = DEFAULT_MAX_BYTES,
    accept = DEFAULT_ACCEPT,
    ua = DEFAULT_UA,
    maxRedirects = MAX_REDIRECTS,
    resolve = defaultResolve,
    transport = defaultTransport,
    // Extra request headers. Added for the rules feed's conditional pulls (If-None-Match); they are
    // merged after the defaults so a caller cannot rewrite the pinned Host header by accident.
    headers: extraHeaders = null,
  } = opts;

  let current;
  try { current = new URL(target); } catch { return { ok: false, code: 400, error: 'Invalid URL' }; }

  const deadline = Date.now() + timeoutMs;
  const trail = [];

  for (let hop = 0; ; hop++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return { ok: false, code: 504, error: 'Fetch failed or timed out', detail: 'timeout budget exhausted', finalUrl: current.href, hops: trail };

    const checked = await checkHop(current, resolve, hop);
    if (checked.error) {
      return { ok: false, code: 400, error: checked.error, finalUrl: current.href, hops: trail };
    }
    trail.push({ url: current.href, ip: checked.pinned });

    const res = await transport(current, checked.pinned, {
      method: 'GET',
      headers: { ...(extraHeaders || {}), 'User-Agent': ua, Accept: accept, Host: current.host },
      timeoutMs: Math.max(1, remaining),
      maxBytes,
    });

    if (res && res.error) {
      return { ok: false, code: 504, error: 'Fetch failed or timed out', detail: res.error, finalUrl: current.href, hops: trail };
    }

    const status = res.status;
    const headers = res.headers || {};
    const headerOf = (n) => (typeof headers.get === 'function' ? headers.get(n) : headers[n] || headers[n.toLowerCase()]);

    if ([301, 302, 303, 307, 308].includes(status)) {
      const loc = headerOf('location');
      if (loc) {
        if (hop >= maxRedirects) {
          return { ok: false, code: 502, error: `More than ${maxRedirects} redirects`, finalUrl: current.href, hops: trail };
        }
        let next;
        try { next = new URL(loc, current); } catch {
          return { ok: false, code: 502, error: 'Redirect to an invalid URL', finalUrl: current.href, hops: trail };
        }
        current = next;
        continue;
      }
      // A redirect status with no Location is just a response; fall through and treat it as one.
    }

    const contentType = headerOf('content-type') || '';
    // 304 is a successful conditional request, not an upstream failure. A caller that sent
    // If-None-Match gets told nothing changed rather than being handed an error for a working
    // cache. It carries no body by definition, so there is nothing else to return.
    if (status === 304) {
      return { ok: true, notModified: true, status, text: '', finalUrl: current.href, contentType, etag: headerOf('etag') || null, hops: trail };
    }
    if (typeof status === 'number' && (status < 200 || status >= 300)) {
      return { ok: false, code: 502, error: `Upstream returned HTTP ${status}`, status, finalUrl: current.href, hops: trail };
    }
    return {
      ok: true,
      status,
      text: res.text || '',
      finalUrl: current.href,
      contentType,
      etag: headerOf('etag') || null,
      connected_ip: res.connectedIp || checked.pinned,
      hops: trail,
      truncated: !!res.truncated,
    };
  }
}

module.exports = { isPrivateIp, safeFetch, defaultResolve, defaultTransport, MAX_REDIRECTS };
