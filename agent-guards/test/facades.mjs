// Facade compatibility.
//
// The six `-mcp` packages are published and installed. Whatever else changes underneath, an existing
// user's install command must keep producing the same tool names taking the same arguments. This
// suite freezes that contract.
//
// The expected lists below were read out of the 1.0.x `index.mjs` files before they were replaced,
// not from any document. If a tool name here has to change, it is a breaking release and the
// registry, npm and every README have to move together.

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { ck, section, done } = require('./_harness.cjs');
const registry = require('../tools/index.js');

// product -> the exact tool names published in 1.0.x
const CONTRACT = {
  'package-guard': ['verify_package', 'check_vulns', 'package_info', 'audit_deps', 'typosquat_scan'],
  'agent-firewall': ['scan_content', 'scan_secrets', 'check_url', 'check_ip', 'check_password'],
  'payment-guard': ['screen_address', 'screen_payment', 'check_sanctioned', 'resolve_name', 'screen_token'],
  'email-guard': ['scan_inbound', 'scan_outbound', 'check_domain_auth'],
  'code-guard': ['scan_code', 'scan_diff', 'list_rules'],
  'agent-tools': ['read_url', 'unfurl_url', 'validate_email', 'extract_web', 'get_feed', 'dns_lookup', 'domain_info', 'ssl_check', 'http_inspect', 'structured_data'],
};

// tool -> the argument names it accepted in 1.0.x, and which were required.
const ARGS = {
  verify_package: { all: ['name', 'ecosystem', 'version'], required: ['name'] },
  check_vulns: { all: ['name', 'ecosystem', 'version'], required: ['name'] },
  package_info: { all: ['name', 'ecosystem'], required: ['name'] },
  audit_deps: { all: ['packages', 'packageJson', 'requirements', 'ecosystem'], required: [] },
  typosquat_scan: { all: ['name', 'ecosystem'], required: ['name'] },
  scan_content: { all: ['text', 'url'], required: [] },
  scan_secrets: { all: ['text'], required: ['text'] },
  check_url: { all: ['url'], required: ['url'] },
  check_ip: { all: ['ip'], required: ['ip'] },
  check_password: { all: ['password'], required: ['password'] },
  screen_address: { all: ['address', 'chain'], required: ['address'] },
  screen_payment: { all: ['url'], required: ['url'] },
  check_sanctioned: { all: ['address'], required: ['address'] },
  resolve_name: { all: ['name'], required: ['name'] },
  screen_token: { all: ['address', 'chain'], required: ['address'] },
  scan_inbound: { all: ['email', 'from', 'subject', 'body', 'html'], required: [] },
  scan_outbound: { all: ['from', 'to', 'subject', 'body', 'html', 'email'], required: [] },
  check_domain_auth: { all: ['domain'], required: ['domain'] },
  scan_code: { all: ['code', 'language'], required: ['code'] },
  scan_diff: { all: ['diff', 'language'], required: ['diff'] },
  list_rules: { all: [], required: [] },
  read_url: { all: ['url'], required: ['url'] },
  unfurl_url: { all: ['url'], required: ['url'] },
  validate_email: { all: ['email'], required: ['email'] },
  extract_web: { all: ['url', 'selectors'], required: ['url', 'selectors'] },
  get_feed: { all: ['url', 'limit'], required: ['url'] },
  dns_lookup: { all: ['domain', 'type'], required: ['domain'] },
  domain_info: { all: ['domain'], required: ['domain'] },
  ssl_check: { all: ['host'], required: ['host'] },
  http_inspect: { all: ['url'], required: ['url'] },
  structured_data: { all: ['url'], required: ['url'] },
};

section('every product still exposes exactly the tools it published');
for (const [product, expected] of Object.entries(CONTRACT)) {
  const actual = registry.toolsFor(product).map((t) => t.name);
  const missing = expected.filter((n) => !actual.includes(n));
  const added = actual.filter((n) => !expected.includes(n));
  ck(`${product}: no published tool went missing`, missing.length === 0, `missing: ${missing.join()}`);
  // Adding a tool is allowed; it just has to be deliberate, so it is reported rather than asserted away.
  if (added.length) console.log(`       note: ${product} adds ${added.join()}`);
  ck(`${product}: tool count is ${expected.length} or more`, actual.length >= expected.length, `${actual.length}`);
}

section('argument names and required-ness are unchanged');
for (const [name, spec] of Object.entries(ARGS)) {
  const tool = registry.byName(name);
  if (!tool) { ck(`${name}: exists`, false, 'tool not found in the registry'); continue; }
  const props = Object.keys(tool.input || {});
  const missing = spec.all.filter((a) => !props.includes(a));
  ck(`${name}: accepts every published argument`, missing.length === 0, `missing: ${missing.join()}`);

  const requiredNow = props.filter((p) => !tool.input[p].optional);
  // A previously optional argument becoming required breaks callers that omitted it.
  const newlyRequired = requiredNow.filter((p) => !spec.required.includes(p));
  ck(`${name}: nothing became newly required`, newlyRequired.length === 0, `now required: ${newlyRequired.join()}`);
  const noLongerRequired = spec.required.filter((p) => !requiredNow.includes(p));
  if (noLongerRequired.length) console.log(`       note: ${name} relaxed ${noLongerRequired.join()} to optional (safe)`);
}

section('totals');
ck('31 published tools are all present', Object.values(CONTRACT).flat().every((n) => !!registry.byName(n)));
ck('every registry tool belongs to a known product', registry.ALL.every((t) => Object.keys(CONTRACT).includes(t.product)), [...new Set(registry.ALL.map((t) => t.product))].join());

done('agent-guards facades');
