// A preload that takes the network away.
//
// Loaded with `node -r` in front of a hook, it replaces every way out of the process with something
// that throws. If a hook still produces its answer under this, the answer was reached without the
// network — which is the one property the hooks are not allowed to lose, and the sort of claim that
// rots the moment someone adds an "enrich this a bit" call. A comment saying "no network here"
// cannot fail. This can.

const net = require('net');
const http = require('http');
const https = require('https');
const dns = require('dns');
const tls = require('tls');

const BOOM = 'agent-guards test: the network was used inside a path that must not use it';
const explode = () => { throw new Error(BOOM); };

globalThis.fetch = explode;
net.Socket.prototype.connect = explode;
net.connect = explode;
net.createConnection = explode;
tls.connect = explode;
http.request = explode;
http.get = explode;
https.request = explode;
https.get = explode;
dns.lookup = explode;
dns.resolve = explode;
dns.resolve4 = explode;
if (dns.promises) { dns.promises.lookup = explode; dns.promises.resolve = explode; }
