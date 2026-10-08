#!/usr/bin/env node
// Exports the findings in remediation.json for other tools (roadmap R11). Reads only local files, makes no
// network call and needs no token: the user uploads or imports the file.
//   node export.mjs --format sarif|linear|jira [--dir .security-audit] [--out <file>|-] [--all]
// sarif  → SARIF 2.1.0 for GitHub code scanning (github/codeql-action/upload-sarif), one rule per finding.
// linear → CSV for Linear's CSV import: Title, Description, Priority, Labels.
// jira   → CSV for Jira's CSV import: Summary, Description, Issue Type, Priority, Labels.
// remediation.json names the findings and their state; the file, line, impact and fix come from each
// finding's file in findings/ (Evidence `**File**:` line, `## Impact`, `## Recommendation`).
// By default findings that are fixed or wont_fix are left out; --all exports every verified finding.
// The output names unfixed weaknesses with file and line: keep it in the gitignored directory and import
// it only into a private repository or tracker.

import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFrontmatter, section, titleOf } from "./audit-state.mjs";

export const TOOL = { name: "security-audit", version: "1.1.0", informationUri: "https://github.com/bartek-filipiuk/security-audit-skill" };
export const FORMATS = ["sarif", "linear", "jira"];
const SKIPPED = ["fixed", "wont_fix"];

const LEVEL = { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note" };
// GitHub code scanning reads `security-severity` (0.0-10.0) to show Critical/High/Medium/Low.
const SECURITY_SEVERITY = { CRITICAL: "9.5", HIGH: "8.0", MEDIUM: "5.5", LOW: "3.0" };
const LINEAR_PRIORITY = { CRITICAL: "Urgent", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
const JIRA_PRIORITY = { CRITICAL: "Highest", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };

// The finding's primary location: the first path in the Evidence `**File**:` line, else the first
// `path:line` in the text. A file without a line (a secret in git history) keeps `start: null`.
export function findingLocation(body) {
  const fileLine = body.match(/\*\*File\*\*:?\s*(.+)/)?.[1];
  if (fileLine) {
    const token = fileLine.match(/`([^`]+)`/)?.[1] ?? fileLine.trim().split(/\s+/)[0];
    const m = token.match(/^([^\s:,]+)(?::(\d+)(?:\s*[-–]\s*(\d+))?)?/);
    if (m) return loc(m[1], m[2], m[3]);
  }
  const m = body.match(/([\w.()[\]@-]+(?:\/[\w.()[\]@-]+)*\.\w+):(\d+)(?:\s*[-–]\s*(\d+))?/);
  return m ? loc(m[1], m[2], m[3]) : null;
}

function loc(file, a, b) {
  const start = a ? Number(a) : null;
  const end = b ? Math.max(Number(b), start) : start;
  return { file: file.replace(/^\.\//, ""), start, end };
}

export const where = (l) => (l ? `${l.file}${l.start != null ? `:${l.start}${l.end !== l.start ? `-${l.end}` : ""}` : ""}` : "");

// remediation.json entries joined with their finding files. Missing finding files are reported, not fatal.
export function loadExport(dir, { all = false } = {}) {
  const path = join(dir, "remediation.json");
  if (!existsSync(path)) throw new Error(`No ${path}. Run the audit first (Phase 5.5 writes it).`);
  const rem = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(rem.findings)) throw new Error(`${path} has no findings array.`);
  const warnings = [];
  const items = rem.findings
    .filter((f) => all || !SKIPPED.includes(f.remediation_status))
    .map((f) => {
      const file = join(dir, "findings", `${f.id}.md`);
      let body = "";
      if (existsSync(file)) body = parseFrontmatter(readFileSync(file, "utf8")).body;
      else warnings.push(`${f.id}: no findings/${f.id}.md, exported without location, impact or fix`);
      const location = body ? findingLocation(body) : null;
      if (body && !location) warnings.push(`${f.id}: no file cited in its Evidence`);
      return {
        id: f.id,
        category: f.category,
        severity: String(f.severity ?? "").toUpperCase(),
        title: f.title || titleOf({}, body) || f.id,
        proof: f.proof ?? "",
        status: f.remediation_status ?? "open",
        verification: f.verification ?? "",
        regression_test: f.regression_test ?? "",
        location,
        impact: (body && section(body, "Impact")) || "",
        fix: (body && section(body, "Recommendation")) || "",
      };
    });
  return { meta: rem, items, warnings };
}

export function toSarif({ meta, items }) {
  const rules = items.map((f) => ({
    id: f.id,
    name: f.category,
    shortDescription: { text: f.title },
    fullDescription: { text: f.impact || f.title },
    defaultConfiguration: { level: LEVEL[f.severity] ?? "warning" },
    help: { text: f.fix ? `Fix: ${f.fix}` : "See the finding in .security-audit/findings/.", markdown: f.fix ? `**Fix**\n\n${f.fix}` : "See the finding in `.security-audit/findings/`." },
    properties: { tags: ["security", f.category].filter(Boolean), "security-severity": SECURITY_SEVERITY[f.severity] ?? "5.5", precision: f.proof === "test" ? "very-high" : "high" },
  }));
  const results = items.map((f, i) => {
    const r = {
      ruleId: f.id,
      ruleIndex: i,
      level: LEVEL[f.severity] ?? "warning",
      message: { text: f.impact ? `${f.title}. ${f.impact}` : f.title },
      properties: { severity: f.severity, category: f.category, proof: f.proof, remediation_status: f.status },
    };
    if (f.location) {
      const physicalLocation = { artifactLocation: { uri: f.location.file, uriBaseId: "%SRCROOT%" } };
      if (f.location.start != null) physicalLocation.region = { startLine: f.location.start, endLine: f.location.end };
      r.locations = [{ physicalLocation }];
    }
    return r;
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { ...TOOL, semanticVersion: TOOL.version, rules } },
      originalUriBaseIds: { "%SRCROOT%": { description: { text: "The audited project's root directory." } } },
      results,
      properties: { audited_commit: meta.audited_commit ?? "", audit_date: meta.audit_date ?? "", source: meta.source ?? "" },
    }],
  };
}

// RFC 4180 cell; a leading = + - @ tab or CR is prefixed with ' so a spreadsheet never runs it as a formula.
export const csvCell = (v) => {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
};
const csv = (header, rows) => [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";

export function description(f, meta) {
  const parts = [
    `Finding ${f.id} (${f.severity}, ${f.category}, proof: ${f.proof || "n/a"}, status: ${f.status})`,
    `Location: ${where(f.location) || "not cited"}`,
  ];
  if (f.impact) parts.push(`Impact:\n${f.impact}`);
  parts.push(`Fix:\n${f.fix || "See the finding file."}`);
  if (f.regression_test) parts.push(`Regression test: ${f.regression_test}`);
  if (f.verification) parts.push(`Verification: ${f.verification}`);
  parts.push(`From security-audit${meta.audited_commit ? ` at commit ${meta.audited_commit}` : ""}${meta.audit_date ? `, ${meta.audit_date}` : ""}: .security-audit/findings/${f.id}.md`);
  return parts.join("\n\n");
}

const summary = (f) => `[${f.severity}] ${f.title}${f.location ? ` (${where(f.location)})` : ""}`;

export function toLinearCsv({ meta, items }) {
  return csv(["Title", "Description", "Priority", "Labels"],
    items.map((f) => [summary(f), description(f, meta), LINEAR_PRIORITY[f.severity] ?? "Medium", ["security", f.category].filter(Boolean).join(", ")]));
}

// Jira takes several labels as repeated Labels columns; labels cannot contain spaces.
export function toJiraCsv({ meta, items }) {
  return csv(["Summary", "Description", "Issue Type", "Priority", "Labels", "Labels"],
    items.map((f) => [summary(f), description(f, meta), "Bug", JIRA_PRIORITY[f.severity] ?? "Medium", "security", String(f.category ?? "").replace(/\s+/g, "-")]));
}

export function render(format, data) {
  if (format === "sarif") return JSON.stringify(toSarif(data), null, 2) + "\n";
  if (format === "linear") return toLinearCsv(data);
  if (format === "jira") return toJiraCsv(data);
  throw new Error(`--format must be one of: ${FORMATS.join(", ")}`);
}

export const defaultOut = (dir, format) => join(dir, "export", format === "sarif" ? "security-audit.sarif" : `${format}.csv`);

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name, def) => (args.includes(name) ? args[args.indexOf(name) + 1] : def);
  const format = opt("--format");
  if (!FORMATS.includes(format)) {
    console.error(`Usage: node export.mjs --format ${FORMATS.join("|")} [--dir .security-audit] [--out <file>|-] [--all]`);
    process.exit(2);
  }
  const dir = resolve(opt("--dir", ".security-audit"));
  let data;
  try { data = loadExport(dir, { all: args.includes("--all") }); } catch (e) { console.error(e.message); process.exit(1); }
  const text = render(format, data);
  const out = opt("--out", defaultOut(dir, format));
  for (const w of data.warnings) console.error(`warning: ${w}`);
  if (out === "-") process.stdout.write(text);
  else {
    mkdirSync(dirname(resolve(out)), { recursive: true });
    writeFileSync(out, text);
    console.log(`${data.items.length} findings → ${out}${format === "sarif" ? "" : ` (import it in ${format === "linear" ? "Linear" : "Jira"}: CSV import)`}. It names unfixed weaknesses: keep it private.`);
  }
}
