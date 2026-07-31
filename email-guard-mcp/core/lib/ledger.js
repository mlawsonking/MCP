// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/lib/ledger.js
// Regenerate: node scripts/sync-shared.js
// The local ledger: one line of JSON per check, appended to ~/.agent-guards/ledger.jsonl.
//
// This file is the only record that the guards did anything. It exists so a week of quiet protection
// is visible instead of invisible, and so anyone can audit what was recorded by opening it in a text
// editor. It is never uploaded and there is no code anywhere in this repo that sends it anywhere.
//
// What goes in a record, and nothing else:
//   ts       ISO timestamp
//   event    what happened (install_check, edit_scan, fetch_scan, cli_scan, ...)
//   engine   which engine answered
//   verdict  danger | caution | safe | unknown
//   action   what the guard actually DID: blocked | warned | reported | none
//   subject  a SHORT non-sensitive label: a package name, a file's basename, a hostname
//   rules    the rule IDs that fired
//   source   hook | cli | skill
//
// `action` is separate from `verdict` on purpose. Most of these checks are advisory: a secret found
// by the PostToolUse hook is a `danger` verdict that stopped nothing, because the write had already
// happened. Counting those as "blocked" in the weekly summary would be this project claiming credit
// for work it did not do, which is the same sin as a check that did not run reporting a pass.
//
// What must never go in: file contents, diff text, secret values, email bodies, fetched page text,
// full paths, or anything else that would make this file worth stealing. `record()` enforces that by
// building the line field by field rather than spreading a caller's object into it, and by truncating
// the subject. If you add a field, add it here and ask what it would leak.

const fs = require('fs');
const { ledgerPath, ensureDir } = require('./paths');
const path = require('path');

const SUBJECT_MAX = 120;
const RULES_MAX = 12;

// A single write() at the end of a file opened with 'a' lands as one unit on both POSIX and Windows,
// so a hook and the CLI appending at the same moment interleave whole lines rather than fragments.
// That only holds while a line stays small, which is the other reason the fields above are capped.
function append(line) {
  const file = ledgerPath();
  if (!ensureDir(path.dirname(file))) return false;
  try {
    fs.appendFileSync(file, line + '\n');
    return true;
  } catch {
    return false; // an unwritable ledger must never break the check it was recording
  }
}

function clean(s, max) {
  return String(s == null ? '' : s).replace(/[\r\n\t]+/g, ' ').trim().slice(0, max);
}

function record(entry = {}) {
  const line = {
    ts: new Date().toISOString(),
    event: clean(entry.event || 'check', 40),
    engine: clean(entry.engine || '', 40),
    verdict: clean(entry.verdict || 'unknown', 20),
    action: clean(entry.action || 'none', 20),
    subject: clean(entry.subject || '', SUBJECT_MAX),
    source: clean(entry.source || 'cli', 20),
  };
  if (Array.isArray(entry.rules) && entry.rules.length) {
    line.rules = entry.rules.slice(0, RULES_MAX).map((r) => clean(r, 60));
  }
  if (typeof entry.findings === 'number') line.findings = entry.findings;
  if (typeof entry.ms === 'number') line.ms = Math.round(entry.ms);
  // Set when a check ran but could not complete, so `guard stats` can tell "nothing found" apart
  // from "nothing was looked at".
  // Skipped reasons are prose, not identifiers, and they are the part someone reads when they want
  // to know why a check came back empty. Cut them at 60 like a rule ID and they arrive as half a
  // sentence, which reads as a bug rather than as an explanation.
  if (Array.isArray(entry.skipped) && entry.skipped.length) {
    line.skipped = entry.skipped.slice(0, RULES_MAX).map((r) => clean(r, 160));
  }
  return append(JSON.stringify(line));
}

// Read the ledger back. A truncated final line (the process died mid-append) is skipped rather than
// throwing, because a stats command that crashes on a damaged ledger is worse than one that reports
// on the lines it could read.
function read({ since } = {}) {
  const file = ledgerPath();
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch { return { entries: [], unreadable: 0, exists: false, path: file }; }

  const entries = [];
  let unreadable = 0;
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const e = JSON.parse(line);
      if (since && e.ts && e.ts < since) continue;
      entries.push(e);
    } catch { unreadable++; }
  }
  return { entries, unreadable, exists: true, path: file };
}

const ORDER = { danger: 3, block: 3, caution: 2, review: 2, warn: 2, unknown: 1, safe: 0, clear: 0, allow: 0, ok: 0 };

// The numbers `guard stats` prints. Kept here rather than in the CLI so the plugin's skill and the
// CLI cannot disagree about what a week looked like.
function summarize(entries) {
  const byVerdict = {};
  const byEvent = {};
  const byRule = {};
  const caught = [];
  let skippedChecks = 0;

  for (const e of entries) {
    const v = e.verdict || 'unknown';
    byVerdict[v] = (byVerdict[v] || 0) + 1;
    byEvent[e.event || 'check'] = (byEvent[e.event || 'check'] || 0) + 1;
    for (const r of e.rules || []) byRule[r] = (byRule[r] || 0) + 1;
    if (e.skipped && e.skipped.length) skippedChecks++;
    if ((ORDER[v] || 0) >= 2) caught.push(e);
  }

  return {
    checks: entries.length,
    verdicts: byVerdict,
    events: byEvent,
    rules: Object.entries(byRule).sort((a, b) => b[1] - a[1]),
    caught: caught.sort((a, b) => (ORDER[b.verdict] || 0) - (ORDER[a.verdict] || 0)),
    // Counted from what the guard did, not from how bad the finding was.
    blocked: caught.filter((e) => e.action === 'blocked').length,
    reported: caught.filter((e) => e.action !== 'blocked').length,
    incomplete: skippedChecks,
    first: entries.length ? entries[0].ts : null,
    last: entries.length ? entries[entries.length - 1].ts : null,
  };
}

module.exports = { record, read, summarize, ledgerPath, SUBJECT_MAX };
