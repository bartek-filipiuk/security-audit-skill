#!/usr/bin/env node
// Scores one benchmark run against answer-key.json and appends a line to results.jsonl.
//   node benchmark/score.mjs <run-dir> [--label "what changed"] [--tool security-audit|claude-security] [--no-save]
// <run-dir> is what setup.mjs printed: it holds meta.json and app/.security-audit/.
// Matching: a finding counts for a key entry when it cites one of the entry's files (path suffix)
// and its text contains one of the entry's keywords. ponytail: keyword matching, not semantic
// judgment; read the "unmatched" list by hand after each run.

import { appendFileSync, existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit, titleOf } from "../scripts/audit-state.mjs";

const here = dirname(fileURLToPath(import.meta.url));

export function citedPaths(text) {
  const out = new Set();
  for (const m of text.matchAll(/([\w.()[\]@-]+(?:\/[\w.()[\]@-]+)*\.(?:[cm]?[jt]sx?|json|ya?ml|md|example))(?::\d+)?/g)) {
    out.add(m[1].replace(/^\.\//, "").replace(/^app\//, ""));
  }
  if (/(^|[\s`'"(/])\.env(?![.\w])/.test(text)) out.add(".env");
  return out;
}

const cites = (finding, files) => files.some((f) => [...finding.paths].some((p) => p === f || p.endsWith("/" + f) || f.endsWith("/" + p)));
const mentions = (finding, keywords) => keywords.some((k) => finding.lower.includes(k.toLowerCase()));
const matches = (finding, entry) => cites(finding, entry.files) && mentions(finding, entry.keywords);

export function score(findings, key) {
  const fs = findings.map((f) => ({
    id: f.data?.id ?? f.stem,
    status: f.data?.status === "fixed" ? "verified" : f.data?.status,
    severity: f.data?.severity,
    proof: f.data?.proof,
    title: titleOf(f.data ?? {}, f.body),
    paths: citedPaths(f.text),
    lower: f.text.toLowerCase(),
  }));
  const verified = fs.filter((f) => f.status === "verified");
  const rejected = fs.filter((f) => f.status === "rejected");

  const seeded = key.seeded.map((e) => {
    const hit = verified.filter((f) => matches(f, e));
    const dropped = rejected.filter((f) => matches(f, e));
    return {
      id: e.id, class: e.class, detect: e.detect,
      result: hit.length ? "found" : dropped.length ? "dropped_by_verifier" : "missed",
      by: (hit.length ? hit : dropped).map((f) => f.id),
      proof: hit.map((f) => f.proof).filter(Boolean),
    };
  });
  const claimed = new Set(seeded.flatMap((s) => (s.result === "found" ? s.by : [])));
  const decoyFp = key.decoys.flatMap((d) => verified.filter((f) => !claimed.has(f.id) && matches(f, d)).map((f) => ({ decoy: d.id, finding: f.id, title: f.title })));
  const fpIds = new Set(decoyFp.map((d) => d.finding));
  const extras = verified.filter((f) => !claimed.has(f.id) && !fpIds.has(f.id) && key.known_extras.some((x) => matches(f, x)));
  const extraIds = new Set(extras.map((f) => f.id));
  const unmatched = verified.filter((f) => !claimed.has(f.id) && !fpIds.has(f.id) && !extraIds.has(f.id));
  const found = seeded.filter((s) => s.result === "found").length;

  return {
    recall: +(found / seeded.length).toFixed(3),
    found,
    dropped_by_verifier: seeded.filter((s) => s.result === "dropped_by_verifier").length,
    missed: seeded.filter((s) => s.result === "missed").length,
    decoy_fp: decoyFp.length,
    verified_total: verified.length,
    rejected_total: rejected.length,
    raw_left: fs.filter((f) => f.status === "raw").length,
    seeded, decoyFp,
    extras: extras.map((f) => f.id),
    unmatched: unmatched.map((f) => ({ id: f.id, severity: f.severity, title: f.title })),
  };
}

// The Claude Security plugin (Anthropic) writes app/CLAUDE-SECURITY-<timestamp>/CLAUDE-SECURITY-RESULTS.jsonl.
// Its findings are verified before they are written, so each line counts as a verified finding. The
// schema is not documented field by field, so the whole JSON line is the text the matcher reads.
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
    return { stem: id, data: { id, status: "verified", severity: String(pick("severity") ?? "").toUpperCase(), title }, body: `## Title\n${title}\n`, text };
  });
  return { dir, findings, report: join(dir, "CLAUDE-SECURITY-RESULTS.md") };
}

// realpath on both sides: the skill is usually run through a symlink (~/.claude/skills/...).
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const runDir = resolve(args.find((a) => !a.startsWith("--") && !["--label", "--tool"].includes(args[args.indexOf(a) - 1])) ?? ".");
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
  const key = JSON.parse(readFileSync(join(here, "answer-key.json"), "utf8"));
  const meta = existsSync(join(runDir, "meta.json")) ? JSON.parse(readFileSync(join(runDir, "meta.json"), "utf8")) : {};
  const r = score(findings, key);

  const minutes = meta.started_at && existsSync(report)
    ? +((statSync(report).mtimeMs - Date.parse(meta.started_at)) / 60000).toFixed(1)
    : null;

  console.log(`Recall ${r.found}/${r.seeded.length} (${Math.round(r.recall * 100)}%) · dropped by verifier ${r.dropped_by_verifier} · missed ${r.missed} · decoy false positives ${r.decoy_fp} · duration ${minutes ?? "?"} min`);
  console.log("");
  for (const s of r.seeded) console.log(`  ${s.id} ${s.result.padEnd(19)} ${s.by.join(", ").padEnd(24)} ${s.proof.join(",").padEnd(8)} ${s.class}`);
  if (r.decoyFp.length) {
    console.log("\nDecoy false positives:");
    for (const d of r.decoyFp) console.log(`  ${d.decoy} <- ${d.finding}: ${d.title}`);
  }
  if (r.extras.length) console.log(`\nKnown extras (valid, not scored): ${r.extras.join(", ")}`);
  if (r.unmatched.length) {
    console.log("\nVerified but unmatched (review by hand: a real extra issue, a key gap, or a false positive):");
    for (const u of r.unmatched) console.log(`  ${u.id} [${u.severity}] ${u.title}`);
  }
  if (r.raw_left) console.log(`\nWARNING: ${r.raw_left} findings still raw.`);

  if (!args.includes("--no-save")) {
    const { seeded, decoyFp, ...summary } = r;
    appendFileSync(
      join(here, "results.jsonl"),
      JSON.stringify({ date: new Date().toISOString(), tool, label, skill_sha: meta.skill_sha, skill_dirty: meta.skill_dirty, minutes, ...summary, per_bug: Object.fromEntries(seeded.map((s) => [s.id, s.result])) }) + "\n",
    );
    console.log(`\nSaved to ${join(here, "results.jsonl")}`);
  }
}
