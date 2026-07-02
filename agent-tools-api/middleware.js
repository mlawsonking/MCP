// Per-IP rate limit for the free public endpoints. In-memory per edge isolate:
// resets on cold start, which is fine — the job is stopping abusive bursts from
// exhausting the free tier, not precise accounting. RapidAPI traffic is exempt
// (the marketplace enforces its own plan quotas).
const WINDOW_MS = 60000;
const LIMIT = 120; // requests per IP per minute — generous for a real agent loop
const buckets = new Map();

export const config = { matcher: '/api/:path*' };

export default function middleware(req) {
  if (req.method === 'OPTIONS') return;
  const h = req.headers;
  if (h.get('x-rapidapi-proxy-secret')) return;
  const ip = (h.get('x-forwarded-for') || 'unknown').split(',')[0].trim();
  const now = Date.now();
  let b = buckets.get(ip);
  if (!b || now - b.start >= WINDOW_MS) { b = { start: now, n: 0 }; buckets.set(ip, b); }
  b.n++;
  if (buckets.size > 10000) buckets.clear();
  if (b.n > LIMIT) {
    const retry = Math.max(1, Math.ceil((b.start + WINDOW_MS - now) / 1000));
    return new Response(
      JSON.stringify({ ok: false, error: 'Rate limit: ' + LIMIT + ' requests/min per IP on the free endpoint. For higher volume see /api/pricing.', retry_after_seconds: retry }),
      { status: 429, headers: { 'content-type': 'application/json', 'retry-after': String(retry), 'access-control-allow-origin': '*' } }
    );
  }
}
