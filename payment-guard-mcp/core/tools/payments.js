// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/payments.js
// Regenerate: node scripts/sync-shared.js
// Payment Guard tools. Five tools, and every one of them is cloud: the sanctions and scam lists are
// fetched, the on-chain reads and ENS resolution go through public RPC, and the honeypot simulation
// is a remote service. Nothing here works offline except the structural half of screen_payment.
//
// Response shapes match what the hosted API returns today, field for field, because payment-guard-mcp
// is a facade over this and anyone already parsing its output must keep working. Fields may be added,
// never renamed or removed. The x402 payment gate is deliberately absent: that is hosted-API billing,
// not a check.
//
// This product is where the project's worst bug class lived. Four responses once reported a positive
// safety claim from a lookup that had failed: "Not sanctioned" when the OFAC fetch died, "not a
// honeypot" for chains honeypot.is refuses to answer for, "no known vulnerabilities", and `safe` off a
// null sanctions result. Every handler below therefore treats an absent lookup as an open question:
// the check that did not run is named in `flags` and `reasons`, and the verdict is never a pass. If
// you are editing this file, that is the invariant to keep.

const {
  CHAINS, HONEYPOT_CHAINS, isEvmAddress,
  ofacSanctions, ofacCoverage, OFAC_EVM_LISTS,
  scamList, onchain, honeypotCheck,
} = require('../engines/payments');
const { ensResolveDetailed, looksLikeEns } = require('../engines/ens');
const url = require('../engines/url');
const { safeFetch } = require('../lib/net');
const { unavailable } = require('./_schema');

// The enum is read off the engine so the tool schema and the RPC table cannot drift apart. Today it
// is exactly ['eth', 'base', 'polygon', 'arbitrum', 'optimism'], which is what payment-guard-mcp
// declares.
const CHAIN_INPUT = {
  type: 'string',
  optional: true,
  enum: Object.keys(CHAINS),
  description: 'EVM chain (default eth).',
};
const BAD_CHAIN = { ok: false, error: 'Unsupported chain. Use eth, base, polygon, arbitrum, or optimism.' };

// The three services behind these tools, named the same way in every `needs` list and every
// unavailable() call so a caller reading two responses sees the same words for the same thing.
const OFAC = 'OFAC sanctioned-address lists';
const SCAM = 'ethereum-lists + ScamSniffer blocklists';
const RPC = 'public EVM RPC';

// ENS resolution, with the three outcomes kept apart:
//   { address }        resolved
//   { none: true }     looked it up, this name has no address
//   { failed: reason } could not look it up, which is NOT the same as "no address"
// Collapsing the third into the second is how "the RPC was down" gets reported as "that name is not
// registered", so ensResolveDetailed is used here rather than ensResolve.
async function resolveEns(name) {
  const r = await ensResolveDetailed(name);
  if (r.address) return { address: r.address };
  if (r.ok === false) return { failed: r.error || 'the ENS lookup failed' };
  return { none: true, note: r.note };
}

// What ENS resolution here actually is, attached to every resolve_name response so the caller does not
// have to infer it: mainnet registry, one addr() call, and no name-shape analysis of any kind.
const ENS_COVERAGE = {
  method: 'namehash -> ENS registry resolver(node) -> addr(bytes32) on Ethereum mainnet',
  screens: 'the resolved address, against the OFAC EVM sanctions lists and the scam/abuse blocklists',
  homoglyph_detection: false,
  ensip15_normalization: false,
  offchain_resolution: false,
  note: 'Lookalike and homoglyph names are not detected. Offchain and L2 names (Basenames, .cb.id, gasless subnames) need ENSIP-10/CCIP-Read, which is not implemented, so they report resolved:false here even though a wallet resolves them.',
};

module.exports = [
  {
    name: 'screen_address',
    product: 'payment-guard',
    description:
      'The pre-send check for an agent about to send funds to a crypto address. Takes an EVM address or an ENS name ' +
      'and returns safe, caution or block from three inputs: the OFAC EVM sanctions lists, the ethereum-lists and ' +
      'ScamSniffer scam blocklists, and an on-chain read (brand-new and unused address, which is the shape of a scam ' +
      'drop address, or a contract). Sanctions coverage is EVM-format address lists only, so Bitcoin, Tron, Solana and ' +
      'Monero sanctioned addresses are not checked; it applies to every EVM chain, because OFAC lists addresses by ' +
      'currency rather than by chain. If a list fails to load the verdict is downgraded to caution and a flag names the ' +
      'check that did not run, rather than reporting safe. Read sanctions_coverage in the response.',
    needs: [OFAC, SCAM, RPC],
    input: {
      address: { type: 'string', description: 'EVM address (0x + 40 hex) or ENS name (e.g. name.eth).' },
      chain: CHAIN_INPUT,
    },
    async run(args, ctx) {
      const t0 = Date.now();
      const input = String(args.address || args.addr || '').trim();
      const chain = String(args.chain || 'eth').toLowerCase();
      if (!CHAINS[chain]) return BAD_CHAIN;
      // Input validation is local, so it runs before the offline gate: a malformed address is a
      // malformed address whether or not there is a network.
      if (!isEvmAddress(input) && !looksLikeEns(input)) {
        return { ok: false, error: 'Provide a valid EVM address (0x + 40 hex) or an ENS name (e.g. name.eth)' };
      }
      if (ctx.offline) return unavailable('screen_address', [OFAC, SCAM, RPC], 'offline mode: every check here is a fetched list or an on-chain read');

      let address = input;
      let resolved_from;
      if (!isEvmAddress(address)) {
        const r = await resolveEns(input);
        if (!r.address) {
          return {
            ok: true, input, resolved: false, verdict: 'caution',
            reasons: [r.failed
              ? `The ENS lookup for "${input}" failed (${r.failed}), so no address was resolved and nothing was screened. That is a lookup failure, not evidence that the name is unregistered.`
              : `"${input}" did not resolve via the mainnet ENS registry (namehash -> resolver -> addr()). Offchain and L2 names (Basenames, .cb.id, gasless subnames) are not supported here, so a wallet may still resolve it. Either way there is no address, so nothing was screened.`],
            resolve_error: r.failed,
            ms: Date.now() - t0,
          };
        }
        address = r.address; resolved_from = input;
      }

      const low = address.toLowerCase();
      const [ofacRes, scam] = await Promise.all([ofacSanctions(), scamList()]);
      const ofac = ofacRes.set;
      const sanctioned = ofac ? ofac.has(low) : null;
      const scamNote = scam ? scam.get(low) : undefined;

      let onc = null;
      try { onc = await onchain(chain, address); } catch {}

      const flags = [];
      const reasons = [];
      let verdict = 'safe';

      if (sanctioned) {
        verdict = 'block'; flags.push('ofac-sanctioned');
        reasons.push('Address is on the OFAC sanctions list — sending funds to it may be illegal. Do NOT pay.');
      }
      if (scamNote) {
        verdict = 'block'; flags.push('known-scam');
        reasons.push(`Address is on a known scam/abuse blocklist: ${String(scamNote).slice(0, 140)}.`);
      }
      if (verdict !== 'block' && onc) {
        if (!onc.isContract && onc.txCount === 0 && !onc.hasBalance) {
          verdict = 'caution'; flags.push('brand-new-unused');
          reasons.push('Brand-new / unused address (no outgoing transactions, no balance) — common for scam drop addresses. Verify the recipient out-of-band before sending.');
        } else if (onc.isContract) {
          flags.push('contract');
          reasons.push('Recipient is a smart contract — confirm it is the intended one (e.g., a known payment processor), not a lookalike.');
        }
      }
      // A check that did not run is an unanswered question, never a clean result. Each of these
      // downgrades 'safe' and names the check that was skipped.
      if (sanctioned === null) {
        if (verdict === 'safe') verdict = 'caution';
        flags.push('sanctions-check-unavailable');
        reasons.push('The OFAC sanctions list could not be loaded, so this address was NOT screened against it. Treat this as unscreened, not as clean.');
      } else if (ofacRes.lists.length < OFAC_EVM_LISTS.length) {
        // The union is built from whichever lists answered, so a partial load silently narrows coverage.
        const missing = OFAC_EVM_LISTS.filter((l) => !ofacRes.lists.includes(l));
        if (verdict === 'safe') verdict = 'caution';
        flags.push('sanctions-partial');
        reasons.push(`Only part of the OFAC data loaded. The ${missing.join(', ')} list(s) failed, so an address sanctioned only under those was not matched.`);
      }
      if (scam === null) {
        if (verdict === 'safe') verdict = 'caution';
        flags.push('scam-check-unavailable');
        reasons.push('The scam/abuse blocklists could not be loaded, so this address was NOT screened against them.');
      }
      // The RPC being down does not narrow a list, so it does not move the verdict, but the
      // brand-new-and-unused test is the reason this tool catches drop addresses and the caller has to
      // know it did not run.
      if (!onc) {
        flags.push('onchain-check-unavailable');
        reasons.push(`The public ${chain} RPC did not answer, so the on-chain checks (brand-new/unused address, contract or wallet) did not run.`);
      }
      if (verdict === 'safe') {
        const ran = ['not on the OFAC EVM sanctions lists', 'not on the scam lists'];
        if (onc && onc.txCount > 0) ran.push('has on-chain history');
        reasons.push(`${ran.join(', ')}.`.replace(/^n/, 'N'));
      }

      return {
        ok: true, address, resolved_from, chain, verdict,
        sanctioned,
        scam: scamNote
          ? { listed: true, note: scamNote, checked: true }
          : { listed: scam === null ? null : false, checked: scam !== null },
        sanctions_coverage: ofacCoverage(ofacRes.lists),
        onchain: onc || undefined,
        onchain_checked: !!onc,
        flags, reasons, ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'screen_payment',
    product: 'payment-guard',
    description:
      'Check an x402 endpoint or merchant URL before paying it. The structural half is local: punycode host, raw-IP ' +
      'host, credentials in the URL, abuse-prone TLD, known shorteners, excessive subdomains, nonstandard port, and a ' +
      'substring match against 14 brand names flagged when the brand is not the registrable domain, so ' +
      'paypal.com.secure-pay.xyz is caught. There is no edit distance and no homoglyph mapping, so an ASCII typo like ' +
      'paypa1.com is not caught by that rule. Domain age needs RDAP and the destination after redirects needs a fetch; ' +
      'the intermediate hops are not analysed. Offline it still returns the structural verdict and reports those two ' +
      'network checks as skipped. Returns safe, caution or block.',
    needs: ['rdap.org', 'the URL being screened (redirect follow)'],
    input: { url: { type: 'string', description: 'The x402/payment endpoint or merchant URL.' } },
    async run(args, ctx) {
      const t0 = Date.now();
      const target = String(args.url || args.endpoint || '').trim();
      if (!target) return { ok: false, error: 'Provide url (an x402/payment endpoint or merchant URL)' };

      const a = url.analyze(target);
      if (!a.valid) {
        return {
          ok: true, url: target, valid: false, verdict: 'block', score: 100, flags: a.flags,
          reasons: ['URL is malformed — do not send a payment to it.'],
          rules_version: a.rules_version, ms: Date.now() - t0,
        };
      }

      let score = a.score;
      const flags = [...a.flags];
      const skipped = [];

      // Domain age. Offline this is simply not available, and an RDAP miss is not "the domain is old".
      let age;
      if (ctx.offline) {
        skipped.push({ id: 'domain-age', reason: 'offline mode' });
      } else {
        age = await url.getDomainAgeDays(a.host);
        if (age === undefined) skipped.push({ id: 'domain-age', reason: 'RDAP lookup returned nothing' });
      }
      if (typeof age === 'number') {
        if (age < 30) { score += 25; flags.push({ id: 'very-new-domain', severity: 'high', note: `domain registered ${age}d ago` }); }
        else if (age < 180) { score += 12; flags.push({ id: 'new-domain', severity: 'medium', note: `domain registered ${age}d ago` }); }
      }

      // Where the URL actually lands. `new URL(x).href` normalizes (a missing path becomes "/"), so
      // the comparison is against the normalized form; comparing against the raw string reported a
      // redirect for every input that was not already canonical.
      let normalized = target;
      try { normalized = new URL(target).href; } catch {}
      let redirected = false;
      let finalUrl;
      if (ctx.offline) {
        skipped.push({ id: 'redirect-follow', reason: 'offline mode' });
      } else {
        try {
          const f = await safeFetch(target, {});
          // Use finalUrl regardless of f.ok. safeFetch reports it on the non-2xx path too, and an x402
          // endpoint answers 402 by definition, so gating on f.ok disabled the redirect check on
          // exactly the endpoints this product is named after.
          if (f.finalUrl && f.finalUrl !== target && f.finalUrl !== normalized) {
            finalUrl = f.finalUrl; redirected = true;
            const fa = url.analyze(f.finalUrl);
            if (fa.valid && fa.host !== a.host) { score += fa.score; for (const fl of fa.flags) flags.push({ ...fl, note: `${fl.note || fl.id} (after redirect)` }); }
          }
          // What does matter is whether an HTTP response came back at all. A DNS failure, a refused
          // fetch or a redirect loop means the chain was never followed to the end, and reporting
          // redirected:false there would be a claim about a request that never completed.
          if (f.ok !== true && typeof f.status !== 'number') {
            skipped.push({ id: 'redirect-follow', reason: f.error || 'the URL could not be fetched' });
          }
        } catch (e) {
          skipped.push({ id: 'redirect-follow', reason: String((e && e.message) || e) });
        }
      }

      score = Math.min(100, score);
      const verdict = score >= 50 ? 'block' : score >= 25 ? 'caution' : 'safe';
      // The verdict stands on the structural half, which is the same offline as online. What changes
      // is how much was measured, and that is carried by checks_skipped and by the "Not checked"
      // entries in reasons rather than by quietly nudging the verdict.
      const reasons = flags.length ? flags.map((f) => f.note || f.id) : ['No structural red flags; domain looks ordinary. Still verify the recipient is who you expect.'];
      // `reasons` is what an agent reads. A skipped check belongs in it, not only in a side field.
      for (const s of skipped) reasons.push(`Not checked: ${s.id} (${s.reason}).`);

      const out = {
        ok: true, url: target, valid: true, host: a.host,
        domain_age_days: age, redirected, final_url: finalUrl,
        score, verdict, flags, reasons,
        rules_version: a.rules_version, ms: Date.now() - t0,
      };
      if (skipped.length) out.checks_skipped = skipped;
      return out;
    },
  },

  {
    name: 'check_sanctioned',
    product: 'payment-guard',
    description:
      'Fast OFAC sanctions check for a crypto address or ENS name, with no on-chain lookup and no scam lists. Matches ' +
      'against the union of every EVM-format OFAC SDN list (ETH, ARB, BSC, ETC, USDC, USDT), which applies to all EVM ' +
      'chains because OFAC lists addresses by currency rather than by chain. Only EVM (0x) addresses are covered: the ' +
      'Bitcoin, Tron, Solana, Monero and other non-EVM sanctioned addresses are on the SDN list and are not checked ' +
      'here. sanctioned:false means the address is absent from those EVM lists and nothing more. If the lists cannot be ' +
      'loaded, sanctioned is null and the verdict is "unknown"; if only some of them load, the verdict is "unknown" too, ' +
      'because absence from a partial corpus is not a clear result. Read coverage in the response.',
    needs: [OFAC, `${RPC} (only when an ENS name is passed)`],
    input: { address: { type: 'string', description: 'EVM address or ENS name.' } },
    async run(args, ctx) {
      const t0 = Date.now();
      const input = String(args.address || args.addr || '').trim();
      if (!isEvmAddress(input) && !looksLikeEns(input)) {
        return { ok: false, error: 'Provide an EVM address (0x + 40 hex) or ENS name' };
      }
      if (ctx.offline) return unavailable('check_sanctioned', [OFAC], 'offline mode: the OFAC lists are fetched, not bundled');

      let address = input;
      let resolved_from;
      if (!isEvmAddress(address)) {
        const r = await resolveEns(input);
        if (r.address) { address = r.address; resolved_from = input; }
        else if (r.failed) return { ok: false, error: `The ENS lookup for "${input}" failed (${r.failed}). That is a lookup failure, not evidence that the name is unregistered, and nothing was screened.` };
        else return { ok: false, error: `"${input}" did not resolve via the mainnet ENS registry (namehash -> resolver -> addr()). Offchain and L2 names (Basenames, .cb.id, gasless subnames) are not supported here, so a wallet may still resolve it. Pass the address directly to screen it.` };
      }

      const { set: ofac, lists } = await ofacSanctions();
      const sanctioned = ofac ? ofac.has(address.toLowerCase()) : null;
      // A partial load narrows the corpus without narrowing the answer, so "absent" stops meaning
      // "clear" — same reasoning as the sanctions-partial flag on screen_address.
      const missing = OFAC_EVM_LISTS.filter((l) => !(lists || []).includes(l));
      const partial = sanctioned !== null && missing.length > 0;
      return {
        ok: true, address, resolved_from, sanctioned,
        source: 'OFAC SDN (sanctioned digital-currency addresses)', list_size: ofac ? ofac.size : undefined,
        verdict: sanctioned ? 'block' : sanctioned === false && !partial ? 'clear' : 'unknown',
        note: sanctioned
          ? 'On the OFAC sanctions list — transacting may be illegal.'
          : sanctioned === false
            ? (partial
              ? `Absent from the OFAC lists that loaded, but the ${missing.join(', ')} list(s) failed, so an address sanctioned only under those was not matched. Treat this as partially screened, not as clear.`
              : 'Not on the OFAC EVM sanctioned-address lists. See coverage for what that does and does not cover.')
            : 'OFAC list temporarily unavailable.',
        coverage: ofacCoverage(lists),
        lists_missing: missing,
        ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'resolve_name',
    product: 'payment-guard',
    description:
      'Resolve an ENS name to an address and screen that address against the OFAC EVM sanctions lists and the ' +
      'scam/abuse blocklists. Resolution is namehash, then the mainnet ENS registry resolver, then a direct addr() ' +
      'call. There is no ENSIP-10/CCIP-Read, so offchain and L2 names (Basenames, .cb.id, gasless subnames) report ' +
      'resolved:false here even though a wallet resolves them. It does NOT detect lookalike or homoglyph names: no ' +
      'confusable check and no ENSIP-15 normalization, so a spoofed name that resolves to a clean address comes back ' +
      'clean. A failed registry call is reported as a failed lookup, never as an unregistered name. Read ens_coverage ' +
      'in the response.',
    needs: [`${RPC} (ENS registry)`, OFAC, SCAM],
    input: { name: { type: 'string', description: 'ENS name, e.g. vitalik.eth.' } },
    async run(args, ctx) {
      const t0 = Date.now();
      const name = String(args.name || args.ens || '').trim();
      if (!looksLikeEns(name)) return { ok: false, error: 'Provide an ENS name (e.g. name.eth)' };
      if (ctx.offline) return unavailable('resolve_name', [`${RPC} (ENS registry)`, OFAC, SCAM], 'offline mode: ENS resolution is an on-chain call and the screening lists are fetched');

      const r = await resolveEns(name);
      // The registry call failing is not "this name has no address". resolved is null here, distinct
      // from the false below, and the verdict is unknown rather than caution: nothing was measured.
      if (r.failed) {
        return {
          ...unavailable('resolve_name', [`${RPC} (ENS registry)`], `ENS lookup failed: ${r.failed}`),
          name, resolved: null, address: null, ens_coverage: ENS_COVERAGE, ms: Date.now() - t0,
        };
      }
      if (!r.address) {
        return {
          ok: true, name, resolved: false, address: null, verdict: 'caution',
          note: 'Did not resolve via the mainnet ENS registry (namehash -> resolver -> addr()). Offchain and L2 names (Basenames, .cb.id, gasless subnames) are not supported here, so a wallet may still resolve this name. There is no address to screen, so nothing was checked.',
          ens_coverage: ENS_COVERAGE, ms: Date.now() - t0,
        };
      }

      const address = r.address;
      const [ofacRes, scam] = await Promise.all([ofacSanctions(), scamList()]);
      const ofac = ofacRes.set;
      const sanctioned = ofac ? ofac.has(address.toLowerCase()) : null;
      const scamNote = scam ? scam.get(address.toLowerCase()) : undefined;
      const flagged = !!sanctioned || !!scamNote;
      // A list we could not load is an unanswered question, not a clean result. Both lists count: the
      // address is only "screened" if both of them actually answered.
      const sanctionsDown = sanctioned === null;
      const scamDown = scam === null;
      const unscreened = sanctionsDown || scamDown;
      return {
        ok: true, name, resolved: true, address, sanctioned,
        scam: scamNote
          ? { listed: true, note: scamNote, checked: true }
          : { listed: scamDown ? null : false, checked: !scamDown },
        verdict: flagged ? 'block' : unscreened ? 'caution' : 'safe',
        note: flagged
          ? 'Resolved address is sanctioned/scam — do NOT pay.'
          : sanctionsDown
            ? 'Resolved, but the OFAC sanctions list could not be loaded, so the address was NOT screened against it. Treat as unscreened, not clean.'
            : scamDown
              ? 'Resolved, and not on the OFAC EVM sanctions lists, but the scam/abuse blocklists could not be loaded, so the address was NOT screened against them. Treat as partially screened, not clean.'
              : 'Resolved cleanly, and the resolved address is not on the lists. The name itself was not checked for lookalike characters. For full risk (on-chain freshness, etc.) call screen_address with this address.',
        sanctions_coverage: ofacCoverage(ofacRes.lists),
        ens_coverage: ENS_COVERAGE,
        ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'screen_token',
    product: 'payment-guard',
    description:
      'Check a token contract before an agent buys, swaps or approves it: is it a HONEYPOT (you can buy but not sell), ' +
      'does it have an extreme sell tax, is it on a scam/abuse blocklist. The buy+sell simulation comes from ' +
      'api.honeypot.is, which supports Ethereum and Base only and answers 400 "Invalid chain" for polygon, arbitrum and ' +
      'optimism, so the honeypot and tax fields cannot be populated there. It also has no result for tokens with no ' +
      'liquidity pool, which is exactly the population most likely to be a rug. When no simulation ran the verdict is ' +
      'never safe: it is caution, or block if the blocklist already hit, with a honeypot-check-unavailable flag, and ' +
      'honeypot_checked plus honeypot_coverage say what happened. Returns token name/symbol, buy/sell/transfer taxes ' +
      'where available, and a verdict of safe, caution or block.',
    needs: ['honeypot.is', SCAM, RPC],
    input: {
      address: { type: 'string', description: 'Token contract address (0x + 40 hex).' },
      chain: CHAIN_INPUT,
    },
    async run(args, ctx) {
      const t0 = Date.now();
      const address = String(args.address || args.token || '').trim();
      const chain = String(args.chain || 'eth').toLowerCase();
      if (!isEvmAddress(address)) return { ok: false, error: 'Invalid token contract address (0x + 40 hex)' };
      if (!CHAINS[chain]) return BAD_CHAIN;
      if (ctx.offline) return unavailable('screen_token', ['honeypot.is', SCAM, RPC], 'offline mode: the sell simulation and the blocklists are both remote');

      const low = address.toLowerCase();
      const [scam, hp, onc] = await Promise.all([scamList(), honeypotCheck(chain, address), onchain(chain, address).catch(() => null)]);
      const scamNote = scam ? scam.get(low) : undefined;

      const flags = [], reasons = [];
      let verdict = 'safe';
      let token, taxes, honeypot;

      if (onc && !onc.isContract) { verdict = 'caution'; flags.push('not-a-contract'); reasons.push('Address is not a contract — not a token (or self-destructed). Verify you have the right token address.'); }
      if (scamNote) { verdict = 'block'; flags.push('scam-listed'); reasons.push(`On a scam/abuse blocklist: ${String(scamNote).slice(0, 120)}.`); }

      if (hp) {
        honeypot = !!(hp.honeypotResult && hp.honeypotResult.isHoneypot);
        const sim = hp.simulationResult || {};
        taxes = { buy: sim.buyTax, sell: sim.sellTax, transfer: sim.transferTax };
        token = hp.token ? { name: hp.token.name, symbol: hp.token.symbol } : undefined;
        if (honeypot) {
          verdict = 'block'; flags.push('honeypot');
          reasons.push(`HONEYPOT: simulation shows you cannot sell after buying${hp.honeypotResult.honeypotReason ? ` (${hp.honeypotResult.honeypotReason})` : ''}. Do NOT buy.`);
        } else {
          if (typeof sim.sellTax === 'number' && sim.sellTax >= 50) { verdict = 'block'; flags.push('extreme-sell-tax'); reasons.push(`Extreme sell tax (${sim.sellTax}%) — effectively un-sellable.`); }
          else if (typeof sim.sellTax === 'number' && sim.sellTax >= 10) { if (verdict === 'safe') verdict = 'caution'; flags.push('high-sell-tax'); reasons.push(`High sell tax (${sim.sellTax}%).`); }
          const risk = hp.summary && hp.summary.risk;
          if (risk === 'high' && verdict === 'safe') { verdict = 'caution'; flags.push('high-risk-summary'); }
          if (Array.isArray(hp.flags) && hp.flags.length) { for (const f of hp.flags.slice(0, 3)) reasons.push(`Flag: ${(f && (f.description || f.flag)) || f}`); if (verdict === 'safe') verdict = 'caution'; }
        }
      } else {
        // The simulation is the whole point of this endpoint. If it did not run we know nothing about
        // whether the token is sellable, so we must not return 'safe'. honeypot.is supports Ethereum and
        // Base only, and returns 404 for tokens with no liquidity pool, which is exactly the population
        // most likely to be a rug.
        if (verdict === 'safe') verdict = 'caution';
        honeypot = null;
        flags.push('honeypot-check-unavailable');
        reasons.push(`No honeypot simulation ran for this token on ${chain}. ${HONEYPOT_CHAINS.includes(chain) ? 'honeypot.is had no result for it, which is common for tokens with no liquidity pool.' : `honeypot.is supports ${HONEYPOT_CHAINS.join(' and ')} only.`} Treat the sell-side risk as unknown, not as clear.`);
      }
      // Same rule as the honeypot simulation: a blocklist that did not load has not cleared anything.
      if (scam === null) {
        if (verdict === 'safe') verdict = 'caution';
        flags.push('scam-check-unavailable');
        reasons.push('The scam/abuse blocklists could not be loaded, so this token was NOT screened against them.');
      }
      if (!onc) {
        flags.push('onchain-check-unavailable');
        reasons.push(`The public ${chain} RPC did not answer, so it was not confirmed that this address is a contract at all.`);
      }
      if (verdict === 'safe' && hp) reasons.push('Not a honeypot, not scam-listed, taxes normal.');

      return {
        ok: true, address, chain, verdict, token, honeypot, taxes,
        scam: scamNote
          ? { listed: true, note: scamNote, checked: true }
          : { listed: scam === null ? null : false, checked: scam !== null },
        honeypot_checked: !!hp,
        honeypot_coverage: {
          source: 'api.honeypot.is',
          chains_supported: HONEYPOT_CHAINS,
          chain_supported: HONEYPOT_CHAINS.includes(chain),
          checked: !!hp,
        },
        onchain_checked: !!onc,
        flags, reasons, ms: Date.now() - t0,
      };
    },
  },
];
