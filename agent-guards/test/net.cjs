// SSRF guard tests.
//
// The point of this suite is that each check CAN fail. The resolver and the transport are injected,
// so the hostile DNS answer an attacker would need is simply handed to the code under test. Where a
// test asserts something did not happen (a loopback server was never contacted, a socket was never
// reused), it asserts the absence directly rather than the presence of a reassuring string.

const http = require('http');
const { ck, section, done } = require('./_harness.cjs');
const { safeFetch, isPrivateIp, defaultTransport } = require('../lib/net');

const PUBLIC_IP = '93.184.216.34';

// A resolver that answers differently each time it is called: the classic DNS-rebinding setup.
function rebindingResolver(first, then) {
  const calls = [];
  const fn = async (host) => {
    calls.push(host);
    return calls.length === 1 ? [first] : [then];
  };
  fn.calls = calls;
  return fn;
}

// A transport that records what it was asked to connect to and replies with a canned response.
function recordingTransport(reply) {
  const seen = [];
  const fn = async (url, pinnedIp) => {
    seen.push({ url: url.href, pinnedIp });
    const r = typeof reply === 'function' ? reply(url, pinnedIp, seen.length) : reply;
    return r || { status: 200, headers: { 'content-type': 'text/plain' }, text: 'ok' };
  };
  fn.seen = seen;
  return fn;
}

(async () => {
  section('isPrivateIp');
  ck('loopback', isPrivateIp('127.0.0.1'));
  ck('cloud metadata 169.254.169.254', isPrivateIp('169.254.169.254'));
  ck('rfc1918 10/8', isPrivateIp('10.0.0.5'));
  ck('carrier NAT 100.64/10', isPrivateIp('100.64.1.1'));
  ck('::ffff: mapped loopback (dotted spelling)', isPrivateIp('::ffff:127.0.0.1'));
  // new URL() rewrites the dotted spelling into this one, so it is the form that actually arrives.
  ck('::ffff: mapped loopback (hex spelling)', isPrivateIp('::ffff:7f00:1'));
  ck('::ffff: mapped rfc1918 (hex spelling)', isPrivateIp('::ffff:a00:1'));
  ck('::ffff: mapped public address is still public', !isPrivateIp('::ffff:5db8:d822'), '93.184.216.34 mapped');
  ck('::1', isPrivateIp('::1'));
  ck('unparseable address is refused', isPrivateIp('not-an-ip'));
  ck('NAT64 prefix', isPrivateIp('64:ff9b::7f00:1'));
  ck('multicast 224/4', isPrivateIp('239.1.1.1'));
  ck('a real public address is not private', !isPrivateIp(PUBLIC_IP), PUBLIC_IP);
  ck('8.8.8.8 is not private', !isPrivateIp('8.8.8.8'));

  section('DNS rebinding (the TOCTOU this suite exists for)');
  {
    // The attacker answers "public" to the safety check and "loopback" to the connection.
    const resolve = rebindingResolver(PUBLIC_IP, '127.0.0.1');
    const transport = recordingTransport({ status: 200, headers: { 'content-type': 'text/plain' }, text: 'body' });
    const r = await safeFetch('http://rebind.example/x', { resolve, transport });

    ck('fetch succeeds against the address that was validated', r.ok === true, `error=${r.error}`);
    // If anything resolves a second time, the second answer is the attacker's. One call per hop.
    ck('hostname is resolved exactly once', resolve.calls.length === 1, `calls=${resolve.calls.length}`);
    ck('the connection is pinned to the validated address', transport.seen.length === 1 && transport.seen[0].pinnedIp === PUBLIC_IP, `pinned=${transport.seen.map((s) => s.pinnedIp).join()}`);
    // Assert the absence: the loopback address the attacker wanted us on never reached the transport.
    ck('the rebound loopback address never reaches the transport', !transport.seen.some((s) => s.pinnedIp === '127.0.0.1'), JSON.stringify(transport.seen));
  }

  section('private address refusal');
  {
    const t = recordingTransport();
    const r = await safeFetch('http://evil.example/x', { resolve: async () => ['127.0.0.1'], transport: t });
    ck('hostname resolving to loopback is refused', r.ok === false && /private\/loopback/i.test(r.error || ''), `error=${r.error}`);
    ck('nothing was fetched at all', t.seen.length === 0, JSON.stringify(t.seen));
  }
  {
    const r = await safeFetch('http://metadata.example/x', { resolve: async () => ['169.254.169.254'], transport: recordingTransport() });
    ck('hostname resolving to cloud metadata is refused', r.ok === false && /private\/loopback/i.test(r.error || ''), `error=${r.error}`);
  }
  {
    // A mixed answer is a coin flip we refuse to toss.
    const t = recordingTransport();
    const r = await safeFetch('http://mixed.example/x', { resolve: async () => [PUBLIC_IP, '10.0.0.1'], transport: t });
    ck('a mixed public+private answer is refused outright', r.ok === false && t.seen.length === 0, `error=${r.error} seen=${t.seen.length}`);
  }
  ck('literal loopback URL is refused', (await safeFetch('http://127.0.0.1/x', { transport: recordingTransport() })).ok === false);
  ck('literal ::ffff: mapped loopback is refused', (await safeFetch('http://[::ffff:127.0.0.1]/x', { transport: recordingTransport() })).ok === false);
  ck('non-http scheme is refused', (await safeFetch('file:///etc/passwd', { transport: recordingTransport() })).ok === false);

  section('redirect hops are each re-validated');
  {
    const t = recordingTransport((url) =>
      url.href.includes('/start')
        ? { status: 302, headers: { location: 'http://127.0.0.1:9/secret' }, text: '' }
        : { status: 200, headers: {}, text: 'should never get here' }
    );
    const r = await safeFetch('http://public.example/start', { resolve: async () => [PUBLIC_IP], transport: t });
    ck('302 to loopback is blocked', r.ok === false && /redirect to a private/i.test(r.error || ''), `error=${r.error}`);
    ck('the loopback hop was never requested', !t.seen.some((s) => s.url.includes('127.0.0.1')), JSON.stringify(t.seen));
  }
  {
    const t = recordingTransport((url) =>
      url.href.includes('/start')
        ? { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' }, text: '' }
        : { status: 200, headers: {}, text: 'creds' }
    );
    const r = await safeFetch('http://public.example/start', { resolve: async () => [PUBLIC_IP], transport: t });
    ck('302 to cloud metadata is blocked', r.ok === false && /redirect to a private/i.test(r.error || ''), `error=${r.error}`);
    ck('the metadata hop was never requested', !t.seen.some((s) => s.url.includes('169.254')), JSON.stringify(t.seen));
  }
  {
    // Each hop must be resolved and checked on its own, not just the first.
    const hosts = [];
    const resolve = async (h) => { hosts.push(h); return h === 'hop3.example' ? ['10.1.2.3'] : [PUBLIC_IP]; };
    const t = recordingTransport((url) => {
      if (url.href.includes('hop1')) return { status: 302, headers: { location: 'http://hop2.example/' }, text: '' };
      if (url.href.includes('hop2')) return { status: 302, headers: { location: 'http://hop3.example/' }, text: '' };
      return { status: 200, headers: {}, text: 'internal' };
    });
    const r = await safeFetch('http://hop1.example/', { resolve, transport: t });
    ck('a private address three hops in is still caught', r.ok === false && /redirect to a private/i.test(r.error || ''), `error=${r.error}`);
    ck('every hop was resolved separately', hosts.join() === 'hop1.example,hop2.example,hop3.example', hosts.join());
  }
  {
    const t = recordingTransport((url, ip, n) => ({ status: 302, headers: { location: `http://public.example/${n}` }, text: '' }));
    const r = await safeFetch('http://public.example/0', { resolve: async () => [PUBLIC_IP], transport: t });
    ck('a redirect loop stops at the cap', r.ok === false && /More than \d+ redirects/.test(r.error || ''), `error=${r.error}`);
  }

  section('the real transport connects where it was told, not where DNS points');
  {
    // Bound on loopback, addressed as example.com. If the pin is honoured the request lands here;
    // if the transport ever resolves the hostname itself it goes to the real example.com instead.
    const seen = [];
    let connections = 0;
    const server = http.createServer((req, res) => { seen.push(req.headers.host); res.end('local'); });
    server.on('connection', () => { connections++; });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;

    const url = new URL(`http://example.com:${port}/probe`);
    const res = await defaultTransport(url, '127.0.0.1', { headers: { Host: url.host }, timeoutMs: 4000 });
    ck('request reached the pinned address', res.status === 200 && res.text === 'local', `status=${res.status} err=${res.error}`);
    ck('the original hostname is still sent as Host', seen[0] === `example.com:${port}`, seen.join());

    // Pooling is what let a reused socket skip the pin. Two requests must mean two connections.
    await defaultTransport(url, '127.0.0.1', { headers: { Host: url.host }, timeoutMs: 4000 });
    ck('sockets are never pooled between requests', connections === 2, `connections=${connections} (1 means a socket was reused and the pin was skipped)`);

    await new Promise((r) => server.close(r));
  }

  done('agent-guards net');
})();
