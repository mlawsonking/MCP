// Edge middleware: optional RapidAPI-only enforcement (the monetization switch).
//
// Default = OFF → all /api/* endpoints stay open (free tier + the MCP/agent channel work).
// To make RapidAPI the *only* paid way in (Model B), set these in Vercel → Project → Settings → Env:
//   ENFORCE_RAPIDAPI = 1
//   RAPIDAPI_SECRET   = <the X-RapidAPI-Proxy-Secret from your RapidAPI API's Security tab>
// Then requests without the matching secret header are rejected. Flip it back by unsetting ENFORCE_RAPIDAPI.

export const config = { matcher: '/api/:path*' };

export default function middleware(req) {
  if (process.env.ENFORCE_RAPIDAPI !== '1') return; // open by default — pass through

  const secret = process.env.RAPIDAPI_SECRET || '';
  const provided = req.headers.get('x-rapidapi-proxy-secret') || '';
  if (secret && provided === secret) return; // genuine RapidAPI traffic — allow

  return new Response(
    JSON.stringify({ ok: false, error: 'This API is served through RapidAPI. Subscribe on the RapidAPI Hub to get a key.' }),
    { status: 403, headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' } }
  );
}
