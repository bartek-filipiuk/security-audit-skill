#!/usr/bin/env node
// Writes one brief per Phase 2 auditor: only its checklist sections plus the stack patterns for the
// languages the project actually contains. The coordinator passes the brief's path instead of pasting
// the checklist into every prompt, which keeps the coordinator's context small on big projects.
//   node briefs.mjs [--dir .security-audit] [--brief name=2.1,2.3 ...]
// Without --brief it writes the default five: auth, injection, infra, concurrency, upload.
// Stack profiles found in the repo (Supabase, Firebase, Laravel, Symfony, Drupal, Django, FastAPI, Flask) add
// their checklist section to the brief that owns 2.1 and their pattern sections to every brief.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
const EXT = { js: /\.(?:[cm]?[jt]sx?)$/, php: /\.(php|module|inc|theme|install)$/, python: /\.py$/, go: /\.go$/, ruby: /\.rb$/, java: /\.(java|kt)$/ };
// Stack profiles: detected from their files, or from a package in package.json, composer.json,
// requirements*.txt, pyproject.toml or Pipfile.
const PROFILE_FILES = {
  supabase: /(^|\/)supabase\/(?:migrations\/[^/]+\.sql|functions\/.+|config\.toml)$/,
  firebase: /(^|\/)(?:firestore\.rules|storage\.rules|database\.rules\.json|firebase\.json)$/,
  laravel: /(^|\/)(?:artisan|routes\/(?:web|api)\.php|app\/Http\/Kernel\.php|[\w/-]+\.blade\.php)$/,
  symfony: /(^|\/)(?:symfony\.lock|config\/bundles\.php|config\/packages\/[\w.-]+\.ya?ml)$/,
  drupal: /(^|\/)[\w-]+\.(?:info|routing)\.yml$/,
  django: /(^|\/)(?:manage\.py|urls\.py)$/,
};
const PROFILE_SDK = {
  supabase: /"@supabase\/(?:supabase-js|ssr)"/,
  firebase: /"firebase(?:-admin|-functions)?"\s*:/,
  laravel: /"laravel\/framework"\s*:/,
  symfony: /"symfony\/(?:framework-bundle|http-kernel)"\s*:/,
  drupal: /"drupal\/core(?:-recommended)?"\s*:/,
  // Python requirement lines (`Django==5.2`, `"fastapi>=0.115"`); flask-login and djangorestframework do not count.
  django: /(?:^|["'])\s*django\s*(?:\[[^\]]*\]\s*)?(?:[=<>~!;"',]|$)/im,
  fastapi: /(?:^|["'])\s*fastapi\s*(?:\[[^\]]*\]\s*)?(?:[=<>~!;"',]|$)/im,
  flask: /(?:^|["'])\s*flask\s*(?:\[[^\]]*\]\s*)?(?:[=<>~!;"',]|$)/im,
};
const PROFILES = [...new Set([...Object.keys(PROFILE_FILES), ...Object.keys(PROFILE_SDK)])];

export function detectLanguages(root) {
  const r = spawnSync("git", ["-C", root, "ls-files"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const files = r.status === 0 ? r.stdout.split("\n") : [];
  const own = files.filter((f) => f && !/node_modules|vendor\//.test(f));
  const manifests = own.filter((f) => /(^|\/)(?:(?:package|composer)\.json|requirements[\w.-]*\.txt|pyproject\.toml|Pipfile)$/.test(f)).map((f) => {
    try { return existsSync(join(root, f)) ? readFileSync(join(root, f), "utf8") : ""; } catch { return ""; }
  });
  const langs = Object.keys(EXT).filter((l) => own.some((f) => EXT[l].test(f)));
  const profiles = PROFILES.filter((p) => own.some((f) => PROFILE_FILES[p]?.test(f)) || manifests.some((m) => PROFILE_SDK[p]?.test(m)));
  return [...langs, ...profiles];
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
    const profile = PROFILES.find((p) => title.trim().toLowerCase() === p);
    if (profile && !langs.includes(profile)) continue;
    const rows = rest.filter((l) => l.startsWith("|"));
    if (rows.length < 3) continue;
    const first = (r) => r.split("|")[1]?.trim() ?? "";
    const keep = rows.slice(2).filter((r) => rowOk(first(r)));
    if (keep.length) out.push(`## ${title}\n${rows[0]}\n${rows[1]}\n${keep.join("\n")}`);
  }
  return out.join("\n\n");
}

export function writeBriefs(dir, briefs = DEFAULT_BRIEFS, langs = detectLanguages(resolve(dir, ".."))) {
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
