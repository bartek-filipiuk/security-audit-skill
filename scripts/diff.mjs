#!/usr/bin/env node
// Audit diff (roadmap R12): what changed since the previous audit of the same project.
//   node diff.mjs [--dir .security-audit] [--json]
// The previous run is the newest finished run in <dir>/history/ (prepass --new-run and --since archive
// every run there whole, findings with their remediation blocks included, so no extra snapshot is kept).
// Only verified findings take part; rejected and raw ones are not findings. A finding counts as fixed
// when its remediation.status is fixed (Phase 6 or --verify-fixes), otherwise as present.
// Classes:
//   new        present now, absent from the previous run (and not fixed in an older one)
//   fixed      present in the previous run, now absent from a full audit, or now marked fixed
//   regressed  present now, but marked fixed in the previous run, or present in an older run and gone
//              from the previous full run
//   unchanged  present in both runs; severity changes are listed separately
//   not_rechecked  present in the previous run, absent now, but this run was partial (--scope)
// Matching, in order, each finding used once: same category + same file + line ranges within 3 lines
// (nearest first); same category + same file + same normalized title; same category + same normalized
// title (the file moved). Title comparison ignores case, punctuation, numbers and file:line tokens, and
// accepts a token overlap (Jaccard) of at least 0.6.
// Read-only: report-md.mjs and report-html.mjs call diffAudit() and render the "Since last audit" section.
// The history is read by this script only; agents still never read history/.

import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit, titleOf } from "./audit-state.mjs";
import { findingLocation, where } from "./export.mjs";

export const LINE_WINDOW = 3;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const json = (p) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } };

// Finished runs in history/, newest first. A run without report.md did not finish and is skipped.
export function historyRuns(dir) {
  const h = join(dir, "history");
  if (!existsSync(h)) return [];
  return readdirSync(h, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(h, e.name, "report.md")))
    .map((e) => e.name)
    .sort((a, b) => (runKey(a) < runKey(b) ? 1 : runKey(a) > runKey(b) ? -1 : 0))
    .map((name) => runInfo(join(h, name), name));
}

// Run names are report.md times ("2026-10-09T10-00-00"), with "-2", "-3"... on a collision: pad the
// suffix so "-10" sorts after "-9".
const runKey = (name) => (name.length > 19 ? `${name.slice(0, 19)}~${name.slice(20).padStart(4, "0")}` : name);

function runInfo(path, name) {
  const summary = json(join(path, "tools", "summary.json"));
  return { name, path, commit: summary?.commit ?? "", scope: summary?.scope?.label ?? null, findings: snapshot(path) };
}

// The compact view of one run that the diff works on.
export function snapshot(dir) {
  return loadAudit(dir).findings
    .filter((f) => f.data && (f.data.status === "verified" || f.data.status === "fixed"))
    .map((f) => {
      const fm = f.data;
      const rem = typeof fm.remediation === "object" && fm.remediation ? fm.remediation : {};
      const loc = findingLocation(f.body);
      return {
        id: fm.id ?? f.stem,
        category: fm.category,
        severity: String(fm.severity ?? "").toUpperCase(),
        title: titleOf(fm, f.body) || f.stem,
        file: loc?.file ?? "",
        start: loc?.start ?? null,
        end: loc?.end ?? null,
        where: where(loc),
        fixed: fm.status === "fixed" || rem.status === "fixed",
      };
    });
}

export function normTitle(t) {
  return String(t ?? "").toLowerCase()
    .replace(/`[^`]*`/g, " ")
    .replace(/[\w./()[\]@-]+\.\w+(:\d+(\s*[-–]\s*\d+)?)?/g, " ")
    .replace(/[^a-z]+/g, " ")
    .trim();
}

export function sameTitle(a, b) {
  const x = normTitle(a), y = normTitle(b);
  if (!x || !y) return false;
  if (x === y) return true;
  const A = new Set(x.split(" ")), B = new Set(y.split(" "));
  const inter = [...A].filter((w) => B.has(w)).length;
  return inter / (A.size + B.size - inter) >= 0.6;
}

// Distance between two line ranges (0 when they overlap); null when they cannot be compared.
function lineGap(a, b) {
  if (a.start == null || b.start == null) return a.start == null && b.start == null ? 0 : null;
  if (a.end >= b.start && b.end >= a.start) return 0;
  return a.end < b.start ? b.start - a.end : a.start - b.end;
}

// Pairs current with previous findings. Returns [[cur, prev]] plus the unmatched of both sides.
export function matchFindings(current, previous) {
  const cur = new Set(current), prev = new Set(previous);
  const pairs = [];
  const take = (rank) => {
    const cands = [];
    for (const c of cur) for (const p of prev) {
      if (c.category !== p.category) continue;
      const r = rank(c, p);
      if (r != null) cands.push([r, c, p]);
    }
    cands.sort((a, b) => a[0] - b[0]);
    for (const [, c, p] of cands) {
      if (!cur.has(c) || !prev.has(p)) continue;
      pairs.push([c, p]);
      cur.delete(c);
      prev.delete(p);
    }
  };
  take((c, p) => {
    if (!c.file || c.file !== p.file) return null;
    const gap = lineGap(c, p);
    return gap != null && gap <= LINE_WINDOW ? gap * 2 + (sameTitle(c.title, p.title) ? 0 : 1) : null;
  });
  take((c, p) => (c.file && c.file === p.file && sameTitle(c.title, p.title) ? 0 : null));
  take((c, p) => (sameTitle(c.title, p.title) ? 0 : null));
  return { pairs, newOnes: [...cur], gone: [...prev] };
}

// The diff itself. Pure: current = snapshot of this run, runs = historyRuns() (newest first).
export function classify(current, runs, { partial = false } = {}) {
  const [prev, ...older] = runs;
  const out = { new: [], fixed: [], regressed: [], unchanged: [], severity_changed: [], not_rechecked: [], still_fixed: 0 };
  const { pairs, newOnes, gone } = matchFindings(current, prev.findings);
  for (const [c, p] of pairs) {
    if (c.fixed && p.fixed) { out.still_fixed++; continue; }
    if (c.fixed) { out.fixed.push({ ...p, now: c, how: "marked fixed" }); continue; }
    if (p.fixed) out.regressed.push({ ...c, was: p, how: `marked fixed in run ${prev.name}` });
    else out.unchanged.push({ ...c, was: p });
    if (c.severity !== p.severity) out.severity_changed.push({ ...c, from: p.severity, to: c.severity });
  }
  // A finding that disappeared before the previous run and is back now is a regression. Only when the
  // previous run was a full audit: a partial one may simply not have looked there.
  let rest = newOnes.filter((c) => !c.fixed);
  if (!prev.scope) {
    for (const run of older) {
      if (!rest.length) break;
      const m = matchFindings(rest, run.findings);
      for (const [c, p] of m.pairs) out.regressed.push({ ...c, was: p, how: p.fixed ? `marked fixed in run ${run.name}` : `last reported in run ${run.name}, gone from run ${prev.name}` });
      rest = m.newOnes;
    }
  }
  out.new = [...rest, ...newOnes.filter((c) => c.fixed)];
  for (const p of gone) {
    if (p.fixed) out.still_fixed++;
    else if (partial) out.not_rechecked.push(p);
    else out.fixed.push({ ...p, how: "no longer reported" });
  }
  const bySev = (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id);
  for (const k of ["new", "fixed", "regressed", "unchanged", "severity_changed", "not_rechecked"]) out[k].sort(bySev);
  return out;
}

// null on the first audit (no finished run in history/).
export function diffAudit(dir) {
  const runs = historyRuns(dir);
  if (!runs.length) return null;
  const summary = json(join(dir, "tools", "summary.json"));
  const partial = Boolean(summary?.scope);
  return { previous: { run: runs[0].name, commit: runs[0].commit, scope: runs[0].scope }, partial, ...classify(snapshot(dir), runs, { partial }) };
}

export function diffHeadline(d) {
  const parts = [`${d.new.length} new`, `${d.fixed.length} fixed`, `${d.regressed.length} regressed`, `${d.unchanged.length} unchanged`];
  if (d.severity_changed.length) parts.push(`${d.severity_changed.length} severity ${d.severity_changed.length === 1 ? "change" : "changes"}`);
  if (d.not_rechecked.length) parts.push(`${d.not_rechecked.length} not re-checked`);
  return parts.join(", ");
}

export function diffIntro(d) {
  const p = d.previous;
  const notes = [];
  if (d.partial) notes.push("This audit was partial: previous findings outside its scope are listed as not re-checked, not as fixed.");
  if (p.scope) notes.push(`The previous audit was partial (scope "${p.scope}"), so some new findings may lie outside what it looked at.`);
  return `Compared with the previous audit (run ${p.run}${p.commit ? `, commit ${p.commit}` : ""}): ${diffHeadline(d)}.${notes.length ? ` ${notes.join(" ")}` : ""}`;
}

const line = (f) => `${f.id} (${f.severity}, ${f.category}): ${f.title}${f.where ? ` (${f.where})` : ""}`;

export function renderDiffMd(d) {
  if (!d) return "";
  const cell = (s) => String(s).replace(/\n/g, " ");
  const L = ["## Since Last Audit", "", diffIntro(d), ""];
  const list = (head, items, fmt) => {
    if (!items.length) return;
    L.push(`**${head}**`, "", ...items.map((f) => `- ${cell(fmt(f))}`), "");
  };
  list("New", d.new, (f) => `${line(f)}${f.fixed ? " (already fixed)" : ""}`);
  list("Regressed", d.regressed, (f) => `${line(f)}; was ${f.was.id}, ${f.how}`);
  list("Fixed", d.fixed, (f) => `${line(f)}; ${f.how}${f.now ? ` as ${f.now.id}` : ""}`);
  list("Severity changed", d.severity_changed, (f) => `${f.id}: ${f.from} → ${f.to}, ${f.title}`);
  list("Not re-checked (outside this audit's scope)", d.not_rechecked, line);
  if (d.unchanged.length) L.push(`**Unchanged**: ${d.unchanged.map((f) => f.id).join(", ")}.`, "");
  return L.join("\n");
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const dir = resolve(args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : ".security-audit");
  const d = diffAudit(dir);
  if (args.includes("--json")) console.log(JSON.stringify(d, null, 2));
  else console.log(d ? renderDiffMd(d) : "diff: no previous finished audit in history/, nothing to compare (first run).");
}
