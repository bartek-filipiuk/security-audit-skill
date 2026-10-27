#!/usr/bin/env node
// Creates a fresh, hint-free copy of a benchmark app outside the skill repo, with a git history.
//   node benchmark/setup.mjs [--app ledgerly|supabase-notes|php-tickets|py-clinic] [--dest DIR]
// Default app: ledgerly (benchmark/app); others live in benchmark/<name>/app (see apps.mjs).
// Default DIR: $TMPDIR/<app>-bench-<timestamp>. The audit runs in DIR/app; meta.json and the
// answer key stay outside it. Ledgerly gets a seeded two-commit history: the leaked key is generated
// here at runtime so the skill repo never contains a string that secret scanners or push protection
// would flag. Other apps get one commit.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { benchApp } from "./apps.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const destArg = args.indexOf("--dest") >= 0 ? args[args.indexOf("--dest") + 1] : null;
const bench = benchApp(args.indexOf("--app") >= 0 ? args[args.indexOf("--app") + 1] : undefined);
const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
const runDir = resolve(destArg ?? join(tmpdir(), `${bench.name}-bench-${stamp}`));
const app = join(runDir, "app");

mkdirSync(runDir, { recursive: true });
cpSync(bench.app, app, { recursive: true });

const base62 = (n) => {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return [...randomBytes(n)].map((b) => abc[b % 62]).join("");
};
const dev = bench.name === "ledgerly" ? "Ledgerly Dev" : "App Dev";
const git = (argv, date) =>
  execFileSync("git", ["-c", `user.name=${dev}`, "-c", `user.email=dev@${bench.name}.invalid`, "-c", "commit.gpgsign=false", ...argv], {
    cwd: app,
    stdio: "pipe",
    env: { ...process.env, ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}) },
  });

if (bench.name === "ledgerly") {
  // Commit 1: the project as it was before .gitignore existed, including a real-looking .env.
  rmSync(join(app, ".gitignore"));
  writeFileSync(
    join(app, ".env"),
    [
      "APP_URL=http://localhost:3000",
      `DATABASE_URL=postgres://ledgerly:${base62(20)}@db.internal:5432/ledgerly`,
      `BETTER_AUTH_SECRET=${base62(40)}`,
      `STRIPE_SECRET_KEY=sk_live_${"51"}${base62(30)}`,
      "",
    ].join("\n"),
  );
  git(["init", "-q", "-b", "main"]);
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "feat: ledgerly mvp"], "2026-05-04T10:12:00+02:00");

  // Commit 2: stop tracking .env (the key stays in history).
  cpSync(join(here, "app", ".gitignore"), join(app, ".gitignore"));
  git(["rm", "-q", "--cached", ".env"]);
  rmSync(join(app, ".env"));
  git(["add", ".gitignore"]);
  git(["commit", "-q", "-m", "chore: stop tracking .env"], "2026-05-05T09:40:00+02:00");
} else {
  git(["init", "-q", "-b", "main"]);
  git(["add", "-A"]);
  git(["commit", "-q", "-m", "feat: initial version"], "2026-05-12T10:00:00+02:00");
}

let skillSha = "";
let skillDirty = false;
try {
  skillSha = execFileSync("git", ["-C", here, "rev-parse", "--short", "HEAD"], { encoding: "utf8" }).trim();
  skillDirty = execFileSync("git", ["-C", here, "status", "--porcelain"], { encoding: "utf8" }).trim().length > 0;
} catch {}

writeFileSync(
  join(runDir, "meta.json"),
  JSON.stringify({ started_at: new Date().toISOString(), skill_sha: skillSha, skill_dirty: skillDirty, app, bench_app: bench.name }, null, 2) + "\n",
);

console.log(`Benchmark run ready: ${runDir}

1. Audit it in a fresh Claude Code session:
     cd ${app} && claude
     > /security-audit
2. When the report is written, score it:
     node ${join(here, "score.mjs")} ${runDir} --label "<what changed>"`);
