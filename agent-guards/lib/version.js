// Version strings for the core. Every verdict the core produces carries `rules_version` so a caller
// can pin a verdict to the ruleset that produced it. Bump RULES_VERSION whenever a rule is added or
// removed, or an existing pattern, weight or severity changes, and add the entry to
// RULES-CHANGELOG.md at the repo root.
//
// The format is the release date. A second release on the same date gets a `.N` suffix rather than
// tomorrow's date, so the string never claims a day the rules did not ship on.
const RULES_VERSION = '2026.07.30.1';

// The code scanner ships its own rules and versions them separately, because it lives in a different
// place in the pipeline and moves on its own schedule.
const CODE_RULES_VERSION = '2026.07.30';

// The name and command rules that run in the hook path (engines/pkgname.js, engines/shellcmd.js).
// Separate for the same reason as the code scanner, and for one more: nothing hosted exposes these,
// so they can move without a deploy. Stamping them with RULES_VERSION would have meant either
// bumping a shared version that did not change, or shipping new rules under an old version. Both
// leave a caller unable to tell which ruleset produced a verdict, which is the whole point of the
// field.
const NAME_RULES_VERSION = '2026.07.31';

module.exports = { RULES_VERSION, CODE_RULES_VERSION, NAME_RULES_VERSION };
