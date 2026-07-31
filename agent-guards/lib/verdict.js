// Verdict metadata, standardized.
//
// Two rules learned the hard way, now enforced here rather than remembered per engine:
//
// 1. Every verdict says which ruleset produced it (`rules_version`).
// 2. A check that did not run is never reported as a pass. Four endpoints once said "not sanctioned",
//    "no known vulnerabilities", "not a honeypot" and "safe" when the lookup behind each had failed
//    or was never attempted. A positive safety claim from an absent answer is the worst bug this
//    codebase can ship, so the machinery for admitting it lives in one place.
//
// An engine builds a Checks object, records each check as it runs or fails, and stamps its result.
// The stamp downgrades the verdict if anything was skipped and lists what was missed.

const { RULES_VERSION } = require('./version');

const ORDER = { allow: 0, clear: 0, ok: 0, caution: 1, review: 1, warn: 1, block: 2, danger: 2 };

// A verdict may only ever move toward caution, never away from it.
function worst(a, b) {
  if (!a) return b;
  if (!b) return a;
  return (ORDER[b] ?? 0) > (ORDER[a] ?? 0) ? b : a;
}

class Checks {
  constructor() {
    this.entries = [];
  }

  // The check ran and produced an answer we trust.
  ran(id, detail) {
    this.entries.push({ id, ran: true, ...(detail ? { detail } : {}) });
    return this;
  }

  // The check did not run, or ran and failed. `reason` is shown to the caller verbatim, so write it
  // for a human reading a verdict at 2am: say what was skipped and what that means they don't know.
  skipped(id, reason) {
    this.entries.push({ id, ran: false, reason: String(reason || 'no reason given') });
    return this;
  }

  get skippedIds() {
    return this.entries.filter((e) => !e.ran).map((e) => e.id);
  }

  get allRan() {
    return this.entries.every((e) => e.ran);
  }
}

// Stamp a result with its metadata. Returns a new object; does not mutate the input.
//
//   stamp(result, { checks, coverage })
//
// - `rules_version` is added unless the caller passed an explicit one.
// - `checks` becomes `checks_run` / `checks_skipped` in the output, and any skipped check forces the
//   verdict to at least `review` and sets `complete: false`.
// - `coverage` is passed through untouched for list-based checks (sanctions lists, blocklists), which
//   need to say how much of the world they actually cover on top of which rules they ran.
function stamp(result, opts = {}) {
  const { checks, coverage, rulesVersion } = opts;
  const out = { ...result };

  out.rules_version = rulesVersion || result.rules_version || RULES_VERSION;

  if (checks instanceof Checks) {
    out.checks_run = checks.entries.filter((e) => e.ran).map((e) => e.id);
    const skipped = checks.entries.filter((e) => !e.ran);
    out.complete = skipped.length === 0;
    if (skipped.length) {
      out.checks_skipped = skipped.map((e) => ({ id: e.id, reason: e.reason }));
      // The verdict cannot be a clean pass when part of the answer is missing.
      if (out.verdict !== undefined) out.verdict = worst(out.verdict, 'review');
    }
  }

  if (coverage !== undefined) out.coverage = coverage;
  return out;
}

// Build the sentence a caller shows a user. It never asserts safety for a check that did not run:
// `clean` is only used when every check ran, otherwise the skipped ones are named.
function summarize(checks, clean, prefix = 'Checked') {
  if (!(checks instanceof Checks)) return clean;
  if (checks.allRan) return clean;
  const missed = checks.entries.filter((e) => !e.ran);
  const names = missed.map((e) => `${e.id} (${e.reason})`).join('; ');
  return `${prefix} what it could, but ${missed.length} check${missed.length === 1 ? '' : 's'} did not run: ${names}. Treat this as unknown, not as clear.`;
}

module.exports = { Checks, stamp, summarize, worst };
