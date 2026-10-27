#!/usr/bin/env node
// The coverage ledger records which entry points and bug classes were checked, so "not found" can be
// told apart from "not looked at". Each writer keeps its own file, coverage/<auditor>.json (parallel
// auditors never share one); this script validates them against references/coverage-ledger.schema.json
// and renders the report's Coverage and Not Assessed sections from them.
//   node coverage.mjs [--dir .security-audit] [--write] [--summary]
// --write: merge every ledger file into coverage.json; refuses while there are validation errors.
// --summary: counts per status and the classes nobody recorded.
// Exit code 1 when validation fails.

import { existsSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAudit } from "./audit-state.mjs";

export const SCHEMA = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "references", "coverage-ledger.schema.json"), "utf8"));
const ENTRY = SCHEMA.$defs.entry;
export const CLASSES = ENTRY.properties.class.enum;
export const STATUSES = ENTRY.properties.status.enum;
// The twelve audit classes every full audit must account for (checklist 2.1-2.12, in that order).
export const AUDIT_CLASSES = CLASSES.filter((c) => c !== "test-gap" && c !== "all");
const SECTION = Object.fromEntries(AUDIT_CLASSES.map((c, i) => [c, `2.${i + 1}`]));
const classLabel = (c) => (SECTION[c] ? `${c} (§${SECTION[c]})` : c);
const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const norm = (p) => String(p ?? "").replace(/^\.\//, "");

// A JSON Schema subset, exactly the keywords the ledger schema uses: $ref (local), type, const, enum,
// pattern, minLength, minItems, required, properties, additionalProperties: false, items, allOf, if/then.
export function checkSchema(value, schema, path = "ledger", root = schema, errors = []) {
  if (schema.$ref) return checkSchema(value, schema.$ref.slice(2).split("/").reduce((s, k) => s[k], root), path, root, errors);
  const type = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
  const why = schema.description ? ` (${schema.description})` : "";
  if (schema.type && schema.type !== type) { errors.push(`${path}: expected ${schema.type}, got ${type}`); return errors; }
  if ("const" in schema && value !== schema.const) errors.push(`${path}: must be ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: ${JSON.stringify(value)} is not one of: ${schema.enum.join(", ")}`);
  if (type === "string") {
    if (schema.minLength && value.length < schema.minLength) errors.push(`${path}: must not be empty`);
    else if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) errors.push(`${path}: ${JSON.stringify(value)} is invalid${why}`);
  }
  if (type === "array") {
    if (schema.minItems && value.length < schema.minItems) errors.push(`${path}: needs at least ${schema.minItems} item(s)${why}`);
    if (schema.items) value.forEach((v, i) => checkSchema(v, schema.items, `${path}[${i}]`, root, errors));
  }
  if (type === "object") {
    for (const k of schema.required ?? []) if (!(k in value)) errors.push(`${path}: missing required field "${k}"`);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) checkSchema(v, schema.properties[k], `${path}.${k}`, root, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: unknown field "${k}"`);
    }
  }
  for (const sub of schema.allOf ?? []) {
    if (sub.if && checkSchema(value, sub.if, path, root, []).length === 0 && sub.then) {
      const cond = Object.entries(sub.if.properties ?? {}).map(([k, s]) => `${k} is ${"const" in s ? JSON.stringify(s.const) : s.enum.map((x) => JSON.stringify(x)).join(" or ")}`).join(", ");
      for (const e of checkSchema(value, sub.then, path, root, [])) errors.push(`${e} (required when ${cond})`);
    } else if (!sub.if) checkSchema(value, sub, path, root, errors);
  }
  return errors;
}

// Schema plus the checks a schema cannot express. `ids`: finding and non-issue ids of the audit, so
// evidence that names a finding must name one that exists.
export function validateLedger(doc, { ids } = {}) {
  const errors = checkSchema(doc, SCHEMA);
  if (errors.length || !Array.isArray(doc?.entries)) return errors;
  doc.entries.forEach((e, i) => {
    if (e.class === "all" && e.status === "checked") errors.push(`ledger.entries[${i}]: class "all" is only for gaps (not_assessed or not_applicable); record a checked row per class`);
    for (const ev of e.evidence ?? []) {
      if (ids && /^(non-)?[a-z][a-z-]*-\d{3}$/.test(ev) && !ids.has(ev)) errors.push(`ledger.entries[${i}].evidence: "${ev}" names no finding or non-issue file of this audit`);
    }
  });
  return errors;
}

// Every ledger file under coverage/, with its parse errors. coverage.json (the merged copy) is not read.
export function loadLedgers(dir) {
  const d = join(dir, "coverage");
  if (!existsSync(d)) return [];
  return readdirSync(d).filter((f) => f.endsWith(".json")).sort().map((f) => {
    try {
      return { file: `coverage/${f}`, doc: JSON.parse(readFileSync(join(d, f), "utf8")), errors: [] };
    } catch (e) {
      return { file: `coverage/${f}`, doc: null, errors: [`not valid JSON: ${e.message}`] };
    }
  });
}

export function validateAudit(dir) {
  const { findings, nonIssues } = loadAudit(dir);
  const ids = new Set([...findings, ...nonIssues].map((x) => x.stem));
  const ledgers = loadLedgers(dir);
  const errors = [];
  for (const l of ledgers) {
    const errs = l.doc ? validateLedger(l.doc, { ids }) : l.errors;
    errs.forEach((e) => errors.push(`${l.file}: ${e}`));
  }
  return { ledgers, errors };
}

export const mergeLedgers = (ledgers) => ({
  schema_version: "1.0",
  generated_at: new Date().toISOString(),
  entries: ledgers.flatMap((l) => (Array.isArray(l.doc?.entries) ? l.doc.entries : [])),
});

// Rows of the old-style not-assessed.md (pre-pass tool rows, the --scope line, rows carried by --since).
function legacyRows(dir) {
  const p = join(dir, "not-assessed.md");
  if (!existsSync(p)) return null;
  return readFileSync(p, "utf8").split("\n")
    .filter((l) => /^\|/.test(l) && !/^\|\s*-/.test(l) && !/^\|\s*category\s*\|/i.test(l))
    .map((l) => l.split("|").slice(1, -1).map((c) => c.trim()))
    .map(([cls, check, ...why]) => ({ class: cls, target: "", check, why: why.filter(Boolean).join(" · "), by: "not-assessed.md" }));
}

const readJson = (dir, p) => {
  try { return existsSync(join(dir, p)) ? JSON.parse(readFileSync(join(dir, p), "utf8")) : null; } catch { return null; }
};

// Everything the report needs, derived from the ledger. Rows a validation error would make unreliable
// are still shown: a broken ledger must never shrink the Not Assessed list.
export function coverageModel(dir) {
  const ledgers = loadLedgers(dir);
  const entries = ledgers.flatMap((l) => (Array.isArray(l.doc?.entries) ? l.doc.entries : []))
    .filter((e) => e && typeof e === "object");
  const recorded = ledgers.length > 0;
  const eps = readJson(dir, "tools/entry-points.json");
  const summary = readJson(dir, "tools/summary.json");

  const byClass = Object.fromEntries([...AUDIT_CLASSES, ...CLASSES.filter((c) => !AUDIT_CLASSES.includes(c))].map((c) => [c, []]));
  for (const e of entries) (byClass[e.class] ??= []).push(e);

  const gaps = [];
  for (const e of entries.filter((x) => x.status === "not_assessed")) {
    gaps.push({ class: e.class, target: e.target === "*" ? "" : norm(e.target) + (e.handler ? ` (${e.handler})` : ""), check: e.check ?? "", why: e.reason ?? "(no reason given)", by: e.auditor ?? "?" });
  }
  if (!recorded) {
    gaps.push({ class: "all", target: "", check: "coverage ledger", why: "no coverage ledger was recorded, so which entry points and classes were checked is unknown", by: "coverage.mjs" });
  } else {
    for (const c of AUDIT_CLASSES) {
      if (!byClass[c].length) gaps.push({ class: c, target: "", check: "whole class", why: "no auditor recorded this class: not looked at", by: "coverage.mjs" });
    }
  }
  let uncovered = null;
  if (recorded && Array.isArray(eps)) {
    const seen = new Set(entries.map((e) => norm(e.target)));
    uncovered = eps.filter((ep) => !seen.has(norm(ep.file)));
    if (uncovered.length) {
      const names = uncovered.slice(0, 20).map((ep) => `${norm(ep.file)}:${ep.line} ${ep.kind} ${ep.route || ep.name}`.trim());
      gaps.push({ class: "all", target: `${uncovered.length} entry point(s)`, check: "entry points with no coverage row", why: `no auditor recorded checking them: ${names.join("; ")}${uncovered.length > 20 ? `; and ${uncovered.length - 20} more (tools/entry-points.json)` : ""}`, by: "coverage.mjs" });
    }
  }
  for (const [label, block] of [["Dependencies", summary?.deps], ["Secrets", summary?.secrets]]) {
    if (block && /NOT RUN|FAILED/.test(block.status)) gaps.push({ class: label === "Dependencies" ? "dependency" : "exposure", target: "", check: `${label} scan`, why: block.status, by: "prepass" });
  }
  const legacy = legacyRows(dir);
  for (const r of legacy ?? []) gaps.push(r);
  const seenRow = new Set();
  const dedup = gaps.filter((g) => { const k = `${g.class}|${g.target}|${g.check}|${g.why}`; return !seenRow.has(k) && seenRow.add(k); });

  return { recorded, ledgers: ledgers.map((l) => l.file), entries, byClass, entryPoints: Array.isArray(eps) ? eps.length : null, uncovered, gaps: dedup, legacy: legacy !== null, toolGaps: Boolean(summary) };
}

// The report's Not Assessed rows. null only when nothing about coverage was recorded at all (an audit
// that predates both the ledger and not-assessed.md), so report-html can say "unknown, not empty".
export function notAssessedRows(dir) {
  const m = coverageModel(dir);
  const toolRows = m.gaps.some((g) => g.by === "prepass");
  if (!m.recorded && !m.legacy && !toolRows) return null;
  return m.gaps;
}

export function renderCoverageMd(dir) {
  const m = coverageModel(dir);
  const L = ["## Coverage", ""];
  if (!m.recorded) {
    L.push("No coverage ledger was recorded (`coverage/*.json`), so this report cannot tell \"not found\" from \"not looked at\". Treat every class without a finding or a non-issue as not assessed.", "");
  } else {
    const auditors = new Set(m.entries.map((e) => e.auditor));
    const carried = m.entries.filter((e) => e.carried_from).length;
    L.push(`From the coverage ledger: ${m.entries.length} rows by ${auditors.size} writer(s) in ${m.ledgers.join(", ")}${carried ? `, ${carried} carried over from the previous audit` : ""}. A class with no row was not looked at; it is listed under Not Assessed.`, "");
    L.push("| Class | Checked (targets) | Not applicable | Not assessed | Recorded by |", "|---|---|---|---|---|");
    for (const [c, rows] of Object.entries(m.byClass)) {
      if (!rows.length && !AUDIT_CLASSES.includes(c)) continue;
      const n = (s) => rows.filter((e) => e.status === s).length;
      const targets = new Set(rows.filter((e) => e.status === "checked").map((e) => norm(e.target))).size;
      L.push(`| ${classLabel(c)} | ${rows.length ? `${n("checked")} (${targets})` : "not looked at"} | ${n("not_applicable")} | ${n("not_assessed")} | ${cell([...new Set(rows.map((e) => e.auditor))].join(", ")) || "–"} |`);
    }
    L.push("");
    if (m.entryPoints === null) L.push("Entry points: the pre-pass list (`tools/entry-points.json`) is missing, so entry-point coverage was not computed.");
    else L.push(`Entry points: ${m.entryPoints - m.uncovered.length} of ${m.entryPoints} from the pre-pass have a coverage row${m.uncovered.length ? `; ${m.uncovered.length} have none and are listed under Not Assessed` : ""}.`);
    const na = m.entries.filter((e) => e.status === "not_applicable");
    if (na.length) {
      L.push("", "Not applicable:", "");
      for (const e of na) L.push(`- ${classLabel(e.class)} · ${e.target === "*" ? "whole project" : `\`${norm(e.target)}\``}${e.handler ? ` (${e.handler})` : ""}: ${e.reason} (${e.auditor})`);
    }
    L.push("");
  }
  L.push("## Not Assessed (coverage gaps)", "", "Nobody checked these. They are unknown, not safe.", "");
  if (!m.gaps.length) L.push("No coverage gaps recorded.", "");
  else {
    L.push("| Class | Target | Check | Why not assessed | Recorded by |", "|---|---|---|---|---|");
    for (const g of m.gaps) L.push(`| ${cell(g.class)} | ${cell(g.target) || "–"} | ${cell(g.check) || "–"} | ${cell(g.why)} | ${cell(g.by)} |`);
    L.push("");
  }
  return L.join("\n");
}

export function summarizeCoverage(dir) {
  const m = coverageModel(dir);
  if (!m.recorded) return "coverage: no ledger recorded (coverage/*.json)";
  const by = (s) => m.entries.filter((e) => e.status === s).length;
  const missing = AUDIT_CLASSES.filter((c) => !m.byClass[c].length);
  return [
    `coverage: ${m.entries.length} rows · checked ${by("checked")} · not_applicable ${by("not_applicable")} · not_assessed ${by("not_assessed")}`,
    `classes not recorded: ${missing.length ? missing.join(", ") : "none"}`,
    m.entryPoints === null ? "entry points: tools/entry-points.json missing" : `entry points without a row: ${m.uncovered.length} of ${m.entryPoints}`,
  ].join("\n");
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const dir = resolve(args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : ".security-audit");
  const { ledgers, errors } = validateAudit(dir);
  console.log(`coverage: ${ledgers.length} ledger file(s) in ${join(dir, "coverage")}`);
  if (errors.length) {
    console.log(`${errors.length} problem(s):`);
    for (const e of errors) console.log(`  - ${e}`);
  }
  if (args.includes("--summary")) console.log(summarizeCoverage(dir));
  if (args.includes("--write")) {
    if (errors.length) console.log("coverage.json NOT written: fix the problems above first.");
    else {
      const doc = mergeLedgers(ledgers);
      writeFileSync(join(dir, "coverage.json"), JSON.stringify(doc, null, 2) + "\n");
      console.log(`coverage.json written: ${doc.entries.length} rows`);
    }
  }
  process.exit(errors.length ? 1 : 0);
}
