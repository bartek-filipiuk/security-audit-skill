#!/usr/bin/env node
// Builds the Codex CLI skill from this repository: a SKILL.md with Codex frontmatter, the Codex adaptation
// notes (preamble.md) and the canonical SKILL.md body, plus agents/, references/, scripts/, the guard hook and
// agents/openai.yaml. The Claude Code skill and the OpenCode variant are read, never changed.
// The output never goes into the repository: it holds exactly one SKILL.md (the Claude Code skill), and a second
// one would be picked up by Claude Code or OpenCode. Use install.mjs to put the skill where Codex finds it.
//   node codex/build.mjs [--out DIR]      (default: $TMPDIR/security-audit-codex-<pid>)
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
export const MARKER = ".codex-port";

// Text the preamble relies on. If a canonical file stops containing one, preamble.md is out of date: the build
// fails instead of shipping a wrong mapping.
const ANCHORS = {
  "SKILL.md": [
    "`$ARGUMENTS`", "`$SKILL_DIR`", "## Portability (agents other than Claude Code)", "## Agent Model Selection",
    "agents/recon-scanner.md", "agents/category-auditor.md", "agents/deep-dive-verifier.md",
    "agents/test-quality-auditor.md", "## Rules Block for Every Agent", "~/.claude/skills/audit-live",
    "safety classifier", "git check-ignore -q .security-audit/report.md", "### Phase 6", "### `--mutation`",
  ],
  "agents/recon-scanner.md": ["Use Glob to find files"],
  "agents/category-auditor.md": ["using Grep"],
};

// Physical path of `p`, or of its nearest existing ancestor plus the rest.
function physical(p) {
  const tail = [];
  while (!existsSync(p) && dirname(p) !== p) {
    tail.unshift(basename(p));
    p = dirname(p);
  }
  return join(realpathSync(p), ...tail);
}

// The canonical description, unfolded from `description: >-` (or a plain one-line value).
export function canonicalDescription(skill) {
  const fm = skill.match(/^---\n([\s\S]*?)\n---\n/)?.[1] ?? "";
  const folded = fm.match(/^description: >-?\n((?: {2,}.*\n?)+)/m);
  const plain = fm.match(/^description: (?!>)(.+)$/m);
  const text = folded ? folded[1].split("\n").map((l) => l.trim()).filter(Boolean).join(" ") : plain?.[1]?.trim();
  if (!text) throw new Error("SKILL.md has no description in its frontmatter");
  return text;
}

const stripFrontmatter = (text) => text.replace(/^---\n[\s\S]*?\n---\n/, "");

export function defaultOut() {
  return join(tmpdir(), `security-audit-codex-${process.pid}`);
}

// Returns the skill directory (<out>/security-audit).
export function build(out = defaultOut()) {
  out = resolve(out);
  const repoReal = realpathSync(repo);
  const outReal = physical(out);
  if (outReal === repoReal || outReal.startsWith(`${repoReal}/`) || repoReal.startsWith(`${outReal}/`)) {
    throw new Error(`refusing to build into ${out}: inside (or above) the repository, which must hold exactly one SKILL.md`);
  }
  const pkg = join(out, "security-audit");
  // Only a previous build of ours may be replaced.
  if (existsSync(out) && readdirSync(out).length && !existsSync(join(pkg, MARKER))) {
    throw new Error(`refusing to replace ${out}: not empty and not a previous Codex build`);
  }

  const skill = readFileSync(join(repo, "SKILL.md"), "utf8");
  for (const [file, anchors] of Object.entries(ANCHORS)) {
    const body = readFileSync(join(repo, file), "utf8");
    const missing = anchors.filter((a) => !body.includes(a));
    if (missing.length) throw new Error(`${file} no longer contains: ${missing.join(" | ")}. Update codex/preamble.md.`);
  }

  rmSync(out, { recursive: true, force: true });
  const skip = (p) => !/(^|\/)CLAUDE\.md$|\.test\.mjs$/.test(p); // local memory files and the repo's own tests
  for (const dir of ["agents", "references", "scripts"]) cpSync(join(repo, dir), join(pkg, dir), { recursive: true, filter: skip });

  const frontmatter = [
    "---",
    "name: security-audit",
    `description: ${JSON.stringify(canonicalDescription(skill))}`,
    "metadata:",
    '  short-description: "Evidence-based multi-agent security audit"',
    "---",
    "",
  ].join("\n");
  writeFileSync(join(pkg, "SKILL.md"), frontmatter + readFileSync(join(here, "preamble.md"), "utf8") + stripFrontmatter(skill));

  cpSync(join(here, "openai.yaml"), join(pkg, "agents", "openai.yaml"));
  mkdirSync(join(pkg, "hooks"), { recursive: true });
  cpSync(join(here, "guard.mjs"), join(pkg, "hooks", "guard.mjs"));
  // OpenCode's guard, unchanged: guard.mjs imports checkShell from it; its OpenCode default export stays unused.
  // .mjs, so Node loads it as an ES module without a package.json.
  cpSync(join(repo, "opencode", "plugin.js"), join(pkg, "hooks", "shell-check.mjs"));
  cpSync(join(here, "hooks.json"), join(pkg, "hooks", "hooks.json"));
  cpSync(join(repo, "LICENSE"), join(pkg, "LICENSE"));

  let version = "unknown";
  try {
    version = execFileSync("git", ["describe", "--tags", "--always", "--dirty"], { cwd: repo, encoding: "utf8" }).trim();
  } catch {}
  writeFileSync(join(pkg, "VERSION"), `${version}\n`);
  writeFileSync(join(pkg, MARKER), "Installed by security-audit codex/install.mjs. Removed by --uninstall.\n");
  return pkg;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const out = args.includes("--out") ? args[args.indexOf("--out") + 1] : defaultOut();
  try {
    const pkg = build(out);
    console.log(`Codex skill built: ${pkg}\nInstall with: node ${join(here, "install.mjs")} (builds again, into $CODEX_HOME/skills)`);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
