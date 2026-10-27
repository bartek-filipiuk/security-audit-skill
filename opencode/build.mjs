#!/usr/bin/env node
// Builds the self-contained OpenCode package from this repository: the sa-* agents (OpenCode frontmatter plus
// the shared prompts), the /security-audit command, the guard plugin, the installer and a copy of agents/,
// references/ and scripts/. The Claude Code skill (the repository root) is read, never changed.
//   node opencode/build.mjs [--out dist/opencode]
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");

// Permission blocks shared by the agent frontmatters; `{{name}}` on its own line expands at its indentation.
// Shell is deny-by-default: no cat/grep/find, because they would read .env past the `read` rule.
const BLOCKS = {
  base: [
    "read:",
    '  "*": allow',
    '  "*.env": deny',
    '  "*.env.*": deny',
    '  "*.env.example": allow',
    "webfetch: deny",
    "websearch: deny",
    "skill: deny",
    // The installed scripts and references live outside the project (~/.config/opencode/security-audit).
    "external_directory:",
    '  "*": deny',
    '  "{{SKILL_DIR}}/**": allow',
  ],
  shell: [
    '"*": deny',
    '"node {{SKILL_DIR}}/scripts/*": allow',
    '"cd *": allow', // the guard plugin refuses a cd that leaves the project
    '"pwd": allow',
    '"echo *": allow',
    '"ls": allow',
    '"ls *": allow',
    ...["rev-parse", "check-ignore", "ls-files", "log", "show", "diff", "blame", "status"].map((c) => `"git ${c} *": allow`),
    '"git status": allow',
  ],
  // The regression tests of Phase 3 and the test-quality run need the project's own runner.
  tests: [
    "npm test*", "npm run test*", "pnpm test*", "pnpm run test*", "pnpm vitest *", "pnpm exec vitest *",
    "npx vitest *", "npx jest *", "yarn test*", "bun test*", "node --test *", "pytest*", "python -m pytest*",
    "go test *", "cargo test*", "vendor/bin/phpunit*", "php artisan test*", "bundle exec rspec*",
  ].map((c) => `"${c}": allow`),
};

const BODIES = {
  "sa-coordinator": "SKILL.md",
  "sa-recon": "agents/recon-scanner.md",
  "sa-auditor": "agents/category-auditor.md",
  "sa-verifier": "agents/deep-dive-verifier.md",
  "sa-test-quality": "agents/test-quality-auditor.md",
};

// SKILL.md text that the coordinator's adaptation notes rely on. If SKILL.md stops containing one, the notes in
// opencode/agents/sa-coordinator.md are out of date: the build fails instead of shipping a wrong mapping.
const ANCHORS = [
  "`$ARGUMENTS`", "`$SKILL_DIR`", "agents/recon-scanner.md", "agents/category-auditor.md",
  "agents/deep-dive-verifier.md", "agents/test-quality-auditor.md", "## Agent Model Selection",
  "~/.claude/skills/audit-live", "safety classifier", "git check-ignore -q .security-audit/report.md",
  "### Phase 6", "### `--mutation`",
];

export function expandBlocks(text) {
  return text.replace(/^( *)\{\{(\w+)\}\}\n/gm, (line, indent, name) => {
    if (!BLOCKS[name]) throw new Error(`unknown block {{${name}}}`);
    return BLOCKS[name].map((l) => `${indent}${l}\n`).join("");
  });
}

const stripFrontmatter = (text) => text.replace(/^---\n[\s\S]*?\n---\n/, "");

export function build(out) {
  const skill = readFileSync(join(repo, "SKILL.md"), "utf8");
  const missing = ANCHORS.filter((a) => !skill.includes(a));
  if (missing.length) throw new Error(`SKILL.md no longer contains: ${missing.join(" | ")}. Update opencode/agents/sa-coordinator.md.`);

  rmSync(out, { recursive: true, force: true });
  const skip = (p) => !/(^|\/)CLAUDE\.md$|\.test\.mjs$/.test(p); // local memory files and the repo's own tests
  for (const dir of ["agents", "references", "scripts"]) {
    cpSync(join(repo, dir), join(out, "security-audit", dir), { recursive: true, filter: skip });
  }
  cpSync(join(repo, "LICENSE"), join(out, "LICENSE"));

  mkdirSync(join(out, "agents"), { recursive: true });
  for (const file of readdirSync(join(here, "agents"))) {
    const name = file.replace(/\.md$/, "");
    if (!BODIES[name]) throw new Error(`no prompt mapped for ${file}`);
    const body = stripFrontmatter(readFileSync(join(repo, BODIES[name]), "utf8"));
    writeFileSync(join(out, "agents", file), expandBlocks(readFileSync(join(here, "agents", file), "utf8")) + body);
  }
  cpSync(join(here, "command.md"), join(out, "commands", "security-audit.md"));
  // Not named SKILL.md: this repository is itself the Claude Code skill directory, and OpenCode scans it.
  cpSync(join(here, "redirect-skill.md"), join(out, "redirect-skill.md"));
  cpSync(join(here, "plugin.js"), join(out, "plugins", "security-audit-guard.js"));
  cpSync(join(here, "install.mjs"), join(out, "install.mjs"));
  cpSync(join(here, "README.md"), join(out, "README.md"));

  let version = "unknown";
  try {
    version = execFileSync("git", ["describe", "--tags", "--always", "--dirty"], { cwd: repo, encoding: "utf8" }).trim();
  } catch {}
  writeFileSync(join(out, "VERSION"), `${version}\n`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const out = resolve(args.includes("--out") ? args[args.indexOf("--out") + 1] : join(repo, "dist", "opencode"));
  build(out);
  console.log(`OpenCode package: ${out}\nInstall: node ${join(out, "install.mjs")} --auditor-model <provider/model> --verifier-model <provider/model>`);
}
