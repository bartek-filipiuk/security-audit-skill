#!/usr/bin/env node
// Writes one brief per Phase 2 auditor: only its checklist sections plus the stack patterns for the
// languages the project actually contains. The coordinator passes the brief's path instead of pasting
// the checklist into every prompt, which keeps the coordinator's context small on big projects.
//   node briefs.mjs [--dir .security-audit] [--brief name=2.1,2.3 ...]
// Without --brief it writes the default five: auth, injection, infra, concurrency, upload.
// Stack profiles found in the repo (Supabase, Firebase, Laravel, Symfony, Drupal, Django, FastAPI, Flask) add
// their checklist section to the brief that owns 2.1 and their pattern sections to every brief.

import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { detectStack, FRAMEWORK_PROFILES, languagesOf, PROFILES, projectFiles } from "./stack.mjs";

const REF = join(dirname(fileURLToPath(import.meta.url)), "..", "references");
export const DEFAULT_BRIEFS = {
  auth: ["2.1", "2.3", "2.10", "2.11"],
  injection: ["2.2", "2.4"],
  infra: ["2.5", "2.7", "2.8", "2.12"],
  concurrency: ["2.9"],
  upload: ["2.6"],
};

// First-column labels in stack-patterns.md, per language family.
const LANG_ROWS = {
  js: /^(JS\/TS|JS|React|Vue|Angular|EJS|Handlebars|Next\.js.*|tRPC|Hono|Better-Auth|AI SDK.*|AI tools|pg-boss.*|Stripe.*|Drizzle)$/,
  php: /^(PHP.*|Drupal.*|PHP\/Twig)$/,
  python: /^(Python.*|Django)$/,
  go: /^Go( templates)?$/,
  ruby: /^(Ruby|Rails)$/,
  java: /^(Java.*)$/,
};
const GENERIC = /^(All|All languages|General|Detection|Config|Method inconsistency|Unprotected mutations)$/;
// Languages and framework profiles both come from stack.mjs, the one stack detector.
export function detectLanguages(root) {
  const files = projectFiles(root);
  const found = languagesOf(files);
  // Pattern rows are per language family: TypeScript counts as js, and only families with rows are listed.
  const langs = Object.keys(LANG_ROWS).filter((l) => found.includes(l) || (l === "js" && found.includes("ts")));
  return [...langs, ...detectStack(root, { files }).framework_profiles];
}

// Checklist sections `## Stack profile: <Name>` for the profiles present.
export function profileSections(langs) {
  const ck = readFileSync(join(REF, "audit-checklist.md"), "utf8");
  return [...ck.matchAll(/^## Stack profile: (\w+)[\s\S]*?(?=^## |(?![\s\S]))/gm)]
    .filter((m) => langs.includes(m[1].toLowerCase()))
    .map((m) => m[0].trim());
}

function checklistSections(numbers) {
  const ck = readFileSync(join(REF, "audit-checklist.md"), "utf8");
  return numbers.map((n) => {
    const m = ck.match(new RegExp(`^## ${n.replace(".", "\\.")} [\\s\\S]*?(?=^## |(?![\\s\\S]))`, "m"));
    return m ? m[0].trim() : `(checklist section ${n} not found)`;
  });
}

export function patternsFor(langs) {
  const sp = readFileSync(join(REF, "stack-patterns.md"), "utf8");
  const isLang = (label) => Object.values(LANG_ROWS).some((re) => re.test(label));
  // Language rows only for languages present; generic rows and plain regex rows always.
  const rowOk = (label) => GENERIC.test(label) || langs.some((l) => LANG_ROWS[l]?.test(label)) || !isLang(label);
  const out = [];
  for (const part of sp.split(/^## /m).slice(1)) {
    const [title, ...rest] = part.split("\n");
    if (/PHP/.test(title) && !langs.includes("php")) continue;
    if (/JS\/TS|JS frameworks/.test(title) && !langs.includes("js")) continue;
    const profile = Object.keys(FRAMEWORK_PROFILES).find((p) => title.trim().toLowerCase() === p);
    if (profile && !langs.includes(profile)) continue;
    const rows = rest.filter((l) => l.startsWith("|"));
    if (rows.length < 3) continue;
    const first = (r) => r.split("|")[1]?.trim() ?? "";
    const keep = rows.slice(2).filter((r) => rowOk(first(r)));
    if (keep.length) out.push(`## ${title}\n${rows[0]}\n${rows[1]}\n${keep.join("\n")}`);
  }
  return out.join("\n\n");
}

// A profile forced with --stack adds its language's patterns even when no tracked file has that extension.
export function forcedLanguage(dir) {
  try {
    const s = JSON.parse(readFileSync(join(dir, "tools", "summary.json"), "utf8")).stack;
    return s?.forced ? (PROFILES[s.forced]?.lang ?? null) : null;
  } catch {
    return null;
  }
}

export function writeBriefs(dir, briefs = DEFAULT_BRIEFS, langs = [...new Set([...detectLanguages(resolve(dir, "..")), forcedLanguage(dir)].filter(Boolean))]) {
  mkdirSync(join(dir, "briefs"), { recursive: true });
  const patterns = patternsFor(langs);
  const profiles = profileSections(langs);
  const owner = Object.keys(briefs).find((n) => briefs[n].includes("2.1")) ?? Object.keys(briefs)[0];
  const written = {};
  for (const [name, numbers] of Object.entries(briefs)) {
    const sections = [...checklistSections(numbers), ...(name === owner ? profiles : [])];
    const body = `# Brief: ${name} auditor\n\nLanguages detected: ${langs.join(", ") || "none"}.\n\n## Your checklist\n\n${sections.join("\n\n")}\n\n# Stack patterns\n\n${patterns}\n`;
    writeFileSync(join(dir, "briefs", `${name}.md`), body);
    written[name] = body.length;
  }
  return written;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const dir = resolve(args.indexOf("--dir") >= 0 ? args[args.indexOf("--dir") + 1] : ".security-audit");
  const custom = args.flatMap((a, i) => (args[i - 1] === "--brief" ? [a] : []));
  const briefs = custom.length ? Object.fromEntries(custom.map((c) => { const [n, s] = c.split("="); return [n, s.split(",")]; })) : DEFAULT_BRIEFS;
  const sizes = writeBriefs(dir, briefs);
  console.log(`briefs: ${Object.entries(sizes).map(([n, b]) => `${n} (${Math.round(b / 1000)}k chars)`).join(", ")} -> ${join(dir, "briefs")}`);
}
