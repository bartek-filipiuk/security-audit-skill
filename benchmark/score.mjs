#!/usr/bin/env node
// Scores one benchmark run against answer-key.json and appends a line to results.jsonl.
//   node benchmark/score.mjs <run-dir> [--label "what changed"] [--tool security-audit|claude-security] [--app <name>] [--no-save]
// <run-dir> is what setup.mjs printed: it holds meta.json and app/.security-audit/. The answer key is the
// one of the app named by --app, else by meta.json `bench_app`, else Ledgerly's (see apps.mjs).
//
// Matching is exact: by file and line, never by keywords (roadmap R03).
// - A finding has one primary location: the first `**File**:` line of its Evidence section (else the
//   first `path:line` it cites). A range (`:15-28`) counts as its start..end. Other files a finding
//   cites (callers, chain links) are context and never match.
// - A key entry lists locations: file plus the inclusive line range of the vulnerable statement or of
//   the code a fix changes. The file must be equal to the finding's path or a path suffix of it
//   (`app/src/x.ts` matches `src/x.ts`; a bare `x.ts` matches nothing).
// - Window: the finding's line may sit up to `key.window` lines (default 2) outside the range, which
//   absorbs citing the first line of the enclosing statement or function.
// - Nearest wins: a finding matches only the entries at the smallest distance (0 = inside the range),
//   across seeded bugs, decoys and known extras, so neighbouring ranges in one file stay apart.
// - `advisory: true` entries (vulnerable dependency versions) match only findings in category
//   `dependency`, and dependency findings match only advisory entries. Findings without a category
//   (other tools) may match either.
// - A finding without a line, or outside every window, matches nothing and is listed for review.

import { appendFileSync, existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit, titleOf } from "../scripts/audit-state.mjs";
import { benchApp } from "./apps.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_WINDOW = 2;

const PATH = String.raw`[\w.()[\]@-]+(?:\/[\w.()[\]@-]+)*`;
const LOC = new RegExp(String.raw`(${PATH}|\.env(?![.\w]))(?::(\d+)(?:\s*[-\u2013]\s*(\d+))?)?`, "g");

const normalize = (p) => p.replace(/^\((?![^/]*\))/, "").replace(/^\.\//, "").replace(/^app\//, "");

// The first path in `text` that looks like a source file, with its line or line range when given.
export function parseLocation(text) {
  for (const m of text.matchAll(LOC)) {
    const file = m[1];
    if (file !== ".env" && !/\.(?:[cm]?[jt]sx?|json|ya?ml|md|example|env|sql|rules|toml|php|twig|module|inc|install|theme|py|html?|txt|cfg|ini)$|^\.env/.test(file.split("/").pop())) continue;
    const start = m[2] ? Number(m[2]) : null;
    const end = m[3] ? Math.max(Number(m[3]), start) : start;
    return { file: normalize(file), start, end };
  }
  return null;
}

// Primary location of a finding file: the Evidence `**File**:` line, else the first cited path:line.
export function primaryLocation(text) {
  const fileLine = text.match(/\*\*File\*\*:?\s*(.+)/);
  if (fileLine) {
    const loc = parseLocation(fileLine[1]);
    if (loc) return loc;
  }
  const body = text.replace(/^---\r?\n[\s\S]*?\r?\n---/, "");
  for (const m of body.matchAll(LOC)) {
    if (!m[2]) continue;
    const loc = parseLocation(m[0]);
    if (loc) return loc;
  }
  return parseLocation(body);
}

// Cited paths lose a leading `app/` (the run directory); a key file under Laravel's own `app/` is compared
// with and without it, so `app/Http/X.php` and `app/app/Http/X.php` both match it.
const samePath = (cited, file) => [...new Set([file, normalize(file)])].some((f) => cited === f || cited.endsWith("/" + f));

// Distance in lines between a finding location and a key location; Infinity when the file differs
// or the finding has no line.
export function distance(loc, keyLoc) {
  if (!loc || loc.start == null || !samePath(loc.file, keyLoc.file)) return Infinity;
  const [a, b] = keyLoc.lines;
  if (loc.end < a) return a - loc.end;
  if (loc.start > b) return loc.start - b;
  return 0;
}

const compatible = (finding, entry) => finding.category == null || (finding.category === "dependency") === Boolean(entry.advisory);

// Entries a finding matches: the nearest within the window, ties all count.
export function matchFinding(finding, entries, window = DEFAULT_WINDOW) {
  let best = Infinity;
  let hits = [];
  for (const e of entries) {
    if (!compatible(finding, e)) continue;
    const d = Math.min(...e.locations.map((l) => distance(finding.loc, l)));
    if (d > window) continue;
    if (d < best) { best = d; hits = [e]; } else if (d === best) hits.push(e);
  }
  return { entries: hits, distance: hits.length ? best : null };
}

export function score(findings, key) {
  const window = key.window ?? DEFAULT_WINDOW;
  const kinds = [
    ...key.seeded.map((e) => ({ ...e, kind: "seeded" })),
    ...key.decoys.map((e) => ({ ...e, kind: "decoy" })),
    ...(key.known_extras ?? []).map((e, i) => ({ id: `X${i + 1}`, ...e, kind: "extra" })),
  ];
  const fs = findings.map((f) => {
    const loc = f.loc ?? primaryLocation(f.text);
    const finding = {
      id: f.data?.id ?? f.stem,
      status: f.data?.status === "fixed" ? "verified" : f.data?.status,
      severity: f.data?.severity,
      category: f.data?.category ?? null,
      proof: f.data?.proof,
      carried: Boolean(f.data?.carried_from),
      title: titleOf(f.data ?? {}, f.body),
      loc,
    };
    const m = matchFinding(finding, kinds, window);
    return { ...finding, match: m.entries.length ? "exact" : "none", entries: m.entries, distance: m.distance };
  });
  const verified = fs.filter((f) => f.status === "verified");
  const rejected = fs.filter((f) => f.status === "rejected");
  const hits = (list, id) => list.filter((f) => f.entries.some((e) => e.id === id));

  const seeded = key.seeded.map((e) => {
    const hit = hits(verified, e.id);
    const dropped = hits(rejected, e.id);
    return {
      id: e.id, class: e.class, detect: e.detect,
      result: hit.length ? "found" : dropped.length ? "dropped_by_verifier" : "missed",
      match: hit.length || dropped.length ? "exact" : "none",
      by: (hit.length ? hit : dropped).map((f) => f.id),
      proof: hit.map((f) => f.proof).filter(Boolean),
      carried: hit.length > 0 && hit.every((f) => f.carried),
    };
  });
  const claimed = new Set(seeded.flatMap((s) => (s.result === "found" ? s.by : [])));
  const decoyFp = verified
    .filter((f) => !claimed.has(f.id))
    .flatMap((f) => f.entries.filter((e) => e.kind === "decoy").map((e) => ({ decoy: e.id, finding: f.id, title: f.title })));
  const fpIds = new Set(decoyFp.map((d) => d.finding));
  const extras = verified.filter((f) => !claimed.has(f.id) && !fpIds.has(f.id) && f.entries.some((e) => e.kind === "extra"));
  const extraIds = new Set(extras.map((f) => f.id));
  const unmatched = verified.filter((f) => !claimed.has(f.id) && !fpIds.has(f.id) && !extraIds.has(f.id));
  const found = seeded.filter((s) => s.result === "found").length;
  const where = (l) => (l ? `${l.file}${l.start != null ? `:${l.start}${l.end !== l.start ? `-${l.end}` : ""}` : " (no line)"}` : "(no location)");

  return {
    recall: +(found / seeded.length).toFixed(3),
    found,
    carried: seeded.filter((s) => s.carried).length,
    dropped_by_verifier: seeded.filter((s) => s.result === "dropped_by_verifier").length,
    missed: seeded.filter((s) => s.result === "missed").length,
    decoy_fp: decoyFp.length,
    verified_total: verified.length,
    rejected_total: rejected.length,
    raw_left: fs.filter((f) => f.status === "raw").length,
    matching: "exact",
    loose_matches: 0,
    window,
    seeded, decoyFp,
    extras: extras.map((f) => f.id),
    unmatched: unmatched.map((f) => ({ id: f.id, severity: f.severity, title: f.title, location: where(f.loc) })),
    matches: fs.filter((f) => f.status !== "raw").map((f) => ({ finding: f.id, status: f.status, location: where(f.loc), match: f.match, entries: f.entries.map((e) => e.id), distance: f.distance })),
  };
}

// The Claude Security plugin (Anthropic) writes app/CLAUDE-SECURITY-<timestamp>/CLAUDE-SECURITY-RESULTS.jsonl.
// Its findings are verified before they are written, so each line counts as a verified finding. The
// schema is not documented field by field: the location comes from the first of the usual file and
// line fields that is present, else from the first `path:line` in the JSON line.
export function loadClaudeSecurity(appDir) {
  const dirs = readdirSync(appDir).filter((n) => n.startsWith("CLAUDE-SECURITY-")).sort();
  if (!dirs.length) return null;
  const dir = join(appDir, dirs[dirs.length - 1]);
  const jsonl = join(dir, "CLAUDE-SECURITY-RESULTS.jsonl");
  if (!existsSync(jsonl)) return null;
  const rows = readFileSync(jsonl, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  const findings = rows.map((o, i) => {
    const pick = (...keys) => keys.map((k) => o[k]).find((v) => typeof v === "string" && v.trim());
    const title = pick("title", "name", "summary") ?? String(pick("description") ?? "").slice(0, 120);
    const id = String(pick("id", "finding_id") ?? `F${i + 1}`);
    const text = JSON.stringify(o);
    return { stem: id, data: { id, status: "verified", severity: String(pick("severity") ?? "").toUpperCase(), title }, body: `## Title\n${title}\n`, text, loc: claudeSecurityLocation(o) ?? primaryLocation(text) };
  });
  return { dir, findings, report: join(dir, "CLAUDE-SECURITY-RESULTS.md") };
}

export function claudeSecurityLocation(o) {
  const src = [o, o.location, o.loc, o.source].find((x) => x && typeof x === "object" && ["file", "file_path", "path", "filename"].some((k) => typeof x[k] === "string"));
  if (!src) return null;
  const file = ["file", "file_path", "path", "filename"].map((k) => src[k]).find((v) => typeof v === "string");
  const num = (...keys) => keys.map((k) => Number(src[k] ?? o[k])).find((n) => Number.isInteger(n) && n > 0);
  const fromPath = parseLocation(file);
  const start = num("line", "start_line", "line_number", "startLine") ?? fromPath?.start ?? null;
  const end = num("end_line", "endLine") ?? (start === fromPath?.start ? fromPath?.end : start) ?? start;
  return { file: fromPath?.file ?? file, start, end: start == null ? null : Math.max(end, start) };
}

// realpath on both sides: the skill is usually run through a symlink (~/.claude/skills/...).
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const runDir = resolve(args.find((a) => !a.startsWith("--") && !["--label", "--tool", "--app"].includes(args[args.indexOf(a) - 1])) ?? ".");
  const label = args.indexOf("--label") >= 0 ? args[args.indexOf("--label") + 1] : "";
  const auditDir = join(runDir, "app", ".security-audit");
  const tool = args.includes("--tool") ? args[args.indexOf("--tool") + 1] : "security-audit";
  let findings, report;
  if (tool === "claude-security") {
    const cs = loadClaudeSecurity(join(runDir, "app"));
    if (!cs) { console.error(`No CLAUDE-SECURITY-*/CLAUDE-SECURITY-RESULTS.jsonl in ${join(runDir, "app")}.`); process.exit(1); }
    ({ findings, report } = cs);
  } else {
    if (!existsSync(join(auditDir, "findings"))) {
      console.error(`No findings in ${auditDir}. Run the audit first (see setup.mjs output).`);
      process.exit(1);
    }
    findings = loadAudit(auditDir).findings;
    report = join(auditDir, "report.md");
  }
  const meta = existsSync(join(runDir, "meta.json")) ? JSON.parse(readFileSync(join(runDir, "meta.json"), "utf8")) : {};
  const bench = benchApp(args.includes("--app") ? args[args.indexOf("--app") + 1] : meta.bench_app);
  const key = JSON.parse(readFileSync(bench.key, "utf8"));
  const r = score(findings, key);

  const minutes = meta.started_at && existsSync(report)
    ? +((statSync(report).mtimeMs - Date.parse(meta.started_at)) / 60000).toFixed(1)
    : null;

  console.log(`App ${bench.name}`);
  console.log(`Recall ${r.found}/${r.seeded.length} (${Math.round(r.recall * 100)}%)${r.carried ? ` (${r.carried} carried over from a previous run)` : ""} · dropped by verifier ${r.dropped_by_verifier} · missed ${r.missed} · decoy false positives ${r.decoy_fp} · duration ${minutes ?? "?"} min`);
  console.log(`Matching: exact by file and line (window ±${r.window}), loose matches ${r.loose_matches}`);
  console.log("");
  for (const s of r.seeded) console.log(`  ${s.id} ${s.result.padEnd(19)} ${s.match.padEnd(5)} ${s.by.join(", ").padEnd(24)} ${s.proof.join(",").padEnd(8)} ${s.carried ? "carried " : ""}${s.class}`);
  if (r.decoyFp.length) {
    console.log("\nDecoy false positives:");
    for (const d of r.decoyFp) console.log(`  ${d.decoy} <- ${d.finding}: ${d.title}`);
  }
  if (r.extras.length) console.log(`\nKnown extras (valid, not scored): ${r.extras.join(", ")}`);
  if (r.unmatched.length) {
    console.log("\nVerified but unmatched (review by hand: a real extra issue, a key gap, or a false positive):");
    for (const u of r.unmatched) console.log(`  ${u.id} [${u.severity}] ${u.location}: ${u.title}`);
  }
  if (r.raw_left) console.log(`\nWARNING: ${r.raw_left} findings still raw.`);

  if (!args.includes("--no-save")) {
    const { seeded, decoyFp, matches, ...summary } = r;
    appendFileSync(
      join(here, "results.jsonl"),
      JSON.stringify({ date: new Date().toISOString(), app: bench.name, tool, label, skill_sha: meta.skill_sha, skill_dirty: meta.skill_dirty, minutes, ...summary, per_bug: Object.fromEntries(seeded.map((s) => [s.id, s.result])) }) + "\n",
    );
    console.log(`\nSaved to ${join(here, "results.jsonl")}`);
  }
}
