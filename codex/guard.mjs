#!/usr/bin/env node
// Codex hook for the security-audit skill. One script for three events, configured in ~/.codex/hooks.json by
// install.mjs:
//   UserPromptSubmit  a prompt that invokes `$security-audit` marks the session as an audit session;
//   PreToolUse        in a marked session, refuse shell commands and patches that break the rules block;
//   SessionEnd        remove the mark.
// Sessions without the mark are never touched (exit 0 at once). Deny = exit 2 with the reason on stderr.
// The shell semantics are OpenCode's guard, unchanged: the build copies opencode/plugin.js next to this file as
// shell-check.mjs. This stops accidents, not a hostile model: code run by the test runner can still read anything
// the sandbox can read.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkShell, shellWords } from "./shell-check.mjs";

const SKILL_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const STATE_DIR = "{{STATE_DIR}}"; // filled by install.mjs: $CODEX_HOME/security-audit
const INVOKED = /\$security-audit\b/;

const marker = (session) => join(STATE_DIR, "active", String(session).replace(/[^\w.-]/g, "_"));

// Read-only git subcommands. Everything else (commit, push, checkout, stash, fetch, ...) changes the repository,
// its working tree or talks to a remote.
const GIT_READ = new Set([
  "rev-parse", "check-ignore", "ls-files", "log", "show", "diff", "blame", "status",
  "rev-list", "ls-tree", "merge-base", "grep", "describe",
]);
const NETWORK = new Set(["curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "docker", "podman"]);
const INSTALL = { npm: ["install", "i", "ci", "add", "update"], pnpm: ["install", "i", "add", "update", "fetch"], yarn: ["install", "add", "upgrade"],
  bun: ["install", "i", "add"], pip: ["install", "download"], pip3: ["install", "download"], uv: ["pip", "add", "sync"],
  gem: ["install"], bundle: ["install", "update"], composer: ["install", "require", "update"], go: ["get", "install", "mod"],
  cargo: ["install", "add", "fetch"], poetry: ["install", "add", "update"] };
// Commands whose file arguments are written: every path among them must be inside .security-audit/.
const WRITERS = new Set(["rm", "rmdir", "mv", "touch", "mkdir", "tee", "ln", "chmod", "chown", "truncate", "unlink", "shred"]);
// Words that only precede the real command.
const PREFIX = new Set(["sudo", "env", "command", "builtin", "exec", "nohup", "time", "nice", "xargs", "then", "do", "else", "elif", "if", "while", "until", "!", "{"]);

const text = (word) => word.map((ch) => ch.c).join("");

// Lexical plus symlink-aware: the nearest existing ancestor is resolved, the rest is appended.
function physical(path) {
  let head = path;
  const tail = [];
  while (!existsSync(head) && dirname(head) !== head) {
    tail.unshift(basename(head));
    head = dirname(head);
  }
  try {
    head = realpathSync(head);
  } catch {}
  return join(head, ...tail);
}
const inside = (dir, p) => p === dir || p.startsWith(`${dir}/`);

function inAuditDir(root, path) {
  const rootReal = physical(resolve(root));
  return inside(join(rootReal, ".security-audit"), physical(resolve(rootReal, path)));
}

// `.env`, `src/.env.local`, `--file=.env`, `HEAD:.env`; not `.env.example`, not an exclusion (`--exclude=.env*`).
const isEnvFile = (word) => {
  if (/^--exclude/.test(word)) return false;
  const name = basename(word.slice(Math.max(word.lastIndexOf("="), word.lastIndexOf(":")) + 1));
  return /^\.env/.test(name) && name !== ".env.example";
};
// A recursive grep, or rg told to read hidden or ignored files, would read .env files unless they are excluded.
const excludesEnv = (args) => args.some((x) => /^(--exclude(-dir)?=|!).*\.env/.test(x)) || args.some((x, i) => ["-g", "--glob", "--exclude"].includes(args[i - 1]) && /^!?\.env/.test(x));

// The commands of a shell line as arrays of word strings (redirection targets dropped, checkShell handles them).
function commands(command) {
  const out = [];
  let cur = [];
  const items = shellWords(command);
  for (let k = 0; k < items.length; k++) {
    const item = items[k];
    if (Array.isArray(item)) cur.push(text(item));
    else if (item === ";") {
      if (cur.length) out.push(cur);
      cur = [];
    } else k++; // ">" or ">&": skip its target
  }
  if (cur.length) out.push(cur);
  return out;
}

// Blocklist on top of checkShell: Codex has no deny-by-default shell, so the model reads code through it.
export function checkPolicy(command, root, depth = 0) {
  for (let words of commands(command)) {
    for (const w of words) if (isEnvFile(w)) return `.env files may not be read (${w})`;
    for (;;) {
      if (PREFIX.has(words[0]) || /^\w+=/.test(words[0] ?? "")) words = words.slice(1);
      else if (words[0] === "timeout") {
        words = words.slice(1);
        while (/^-/.test(words[0] ?? "")) words = words.slice(1);
        words = words.slice(1); // the duration
      } else break;
    }
    while (words.length && /^-/.test(words[0])) words = words.slice(1); // options of a prefix (env -i, xargs -0)
    if (!words.length) continue;
    const name = basename(words[0]);
    const args = words.slice(1);
    if (["bash", "sh", "zsh", "dash"].includes(name) && args.includes("-c") && depth < 3) {
      const inner = args[args.indexOf("-c") + 1];
      const why = inner && (checkShell(inner, root) ?? checkPolicy(inner, root, depth + 1));
      if (why) return why;
      continue;
    }
    if (name === "git") {
      let a = 0;
      while (a < args.length && args[a].startsWith("-")) a += ["-C", "-c", "--git-dir", "--work-tree"].includes(args[a]) ? 2 : 1;
      const sub = args[a];
      if (sub === "remote" && (args[a + 1] === undefined || ["-v", "get-url", "show"].includes(args[a + 1]))) continue;
      if (sub === "branch" && args.slice(a + 1).every((x) => ["--show-current", "-a", "-r", "-v", "--list"].includes(x))) continue;
      if (!GIT_READ.has(sub)) return `git ${sub ?? ""} is not a read-only git command`.trim();
      continue;
    }
    if (NETWORK.has(name)) return `${name}: no network tools in an audit (network is off in the sandbox)`;
    if (INSTALL[name] && INSTALL[name].includes(args.find((x) => !x.startsWith("-")))) return `${name} ${args[0]}: no package installs in an audit`;
    if (/^python[\d.]*$/.test(name) && args[0] === "-m" && args[1] === "pip" && args.includes("install")) return "pip install: no package installs in an audit";
    if (name === "grep" && args.some((x) => /^-[a-zA-Z]*[rR]/.test(x) || x === "--recursive") && !excludesEnv(args)) {
      return "grep -r would read .env files: use rg (skips hidden files) or add --exclude='.env*'";
    }
    if (name === "rg" && args.some((x) => /^-[a-zA-Z]*u/.test(x) || ["--hidden", "--no-ignore", "-."].includes(x)) && !excludesEnv(args)) {
      return "rg with hidden or ignored files would read .env files: add -g '!.env*'";
    }
    if (name === "find") {
      const exec = args.findIndex((x) => ["-exec", "-execdir", "-ok", "-okdir"].includes(x));
      if (args.includes("-delete")) return "find -delete removes files";
      if (exec >= 0) {
        const runs = basename(args[exec + 1] ?? "");
        const inPlace = ["sed", "perl"].includes(runs) && args.slice(exec + 2).some((x) => /^-[a-zA-Z]*i/.test(x));
        if (WRITERS.has(runs) || inPlace || runs === "cp") return `find -exec ${runs} writes files`;
      }
    }
    const paths = args.filter((x) => !x.startsWith("-"));
    if (WRITERS.has(name)) {
      for (const p of paths) if (!inAuditDir(root, p)) return `${name} writes outside .security-audit/ (${p})`;
    }
    if (name === "cp" || name === "install") {
      const target = paths.at(-1);
      if (target && !inAuditDir(root, target)) return `${name} writes outside .security-audit/ (${target})`;
    }
    if ((name === "sed" || name === "perl") && args.some((x) => /^-[a-zA-Z]*i/.test(x) || x.startsWith("--in-place"))) {
      const files = paths.slice(name === "sed" && !args.some((x) => x === "-e" || x === "-f") ? 1 : 0);
      for (const p of files) if (!inAuditDir(root, p)) return `${name} -i edits outside .security-audit/ (${p})`;
    }
  }
  return null;
}

// apply_patch: `*** Add File: p`, `*** Update File: p`, `*** Delete File: p`, `*** Move to: p`. Only
// `.security-audit/**` and the project's `.gitignore` may change. A patch without a readable path is refused.
export function patchPaths(patch) {
  return [...String(patch).matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): *(.+?) *$/gm)].map((m) => m[1]);
}

export function checkPatch(patch, root) {
  const paths = patchPaths(patch);
  if (!paths.length) return "patch names no file the guard can check";
  const rootReal = physical(resolve(root));
  for (const p of paths) {
    const target = physical(resolve(rootReal, p));
    if (target === join(rootReal, ".gitignore") || inside(join(rootReal, ".security-audit"), target)) continue;
    return `edits outside .security-audit/ (${p})`;
  }
  return null;
}

// SKILL.md: audit-state.mjs --final must exit 0 before the report is assembled (same gate as the OpenCode plugin).
function reportGate(root) {
  try {
    execFileSync(process.execPath, [join(SKILL_DIR, "scripts", "audit-state.mjs"), "--final", "--dir", resolve(root, ".security-audit")], { stdio: "pipe" });
    return null;
  } catch (e) {
    return `audit-state.mjs --final fails, fix the finding files first:\n${String(e.stdout || e.message).slice(-1500)}`;
  }
}

// Field shapes are tolerant: the docs give `tool_input.command` for Bash and apply_patch; a string array
// (`["bash", "-lc", "..."]`), `cmd`, `patch` or `input` are accepted as well.
function commandOf(input) {
  if (typeof input === "string") return input;
  const c = input?.command ?? input?.cmd ?? input?.patch ?? input?.input;
  if (Array.isArray(c)) {
    if (c.length >= 3 && /(^|\/)(ba|z|da)?sh$/.test(c[0]) && /^-l?c$/.test(c[1])) return String(c[2]);
    return c.map(String).join(" ");
  }
  return typeof c === "string" ? c : null;
}

export function preToolUse(event) {
  const root = event.cwd;
  if (!root || !isAbsolute(root)) return "no absolute cwd in the hook input";
  const input = event.tool_input;
  const command = commandOf(input);
  if (command === null) return null; // a tool without a command or patch (not one this guard covers)
  const workdir = input?.workdir ?? input?.cwd;
  if (typeof workdir === "string" && !inside(physical(resolve(root)), physical(resolve(root, workdir)))) {
    return `workdir leaves the project (${workdir})`;
  }
  const tool = String(event.tool_name ?? "");
  const words = shellWords(command);
  const first = Array.isArray(words[0]) ? text(words[0]) : "";
  if (/^(apply_patch|Edit|Write)$/.test(tool) || (/^\*\*\* Begin Patch/m.test(command) && /^(apply_patch|applypatch)$/.test(first))) {
    return checkPatch(command, root);
  }
  const problem = checkShell(command, root) ?? checkPolicy(command, root);
  if (problem) return problem;
  return /report-(md|html)\.mjs/.test(command) ? reportGate(root) : null;
}

export function handle(event) {
  const session = event.session_id;
  if (!session) return { code: 0 };
  switch (event.hook_event_name) {
    case "UserPromptSubmit": {
      if (!INVOKED.test(String(event.prompt ?? ""))) return { code: 0 };
      mkdirSync(join(STATE_DIR, "active"), { recursive: true });
      writeFileSync(marker(session), `${event.cwd ?? ""}\n`);
      const additionalContext = "security-audit guard active for this session: edits only in .security-audit/, read-only git, no network.";
      return { code: 0, stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext } }) };
    }
    case "SessionEnd":
      rmSync(marker(session), { force: true });
      return { code: 0 };
    case "PreToolUse": {
      if (!existsSync(marker(session))) return { code: 0 };
      const problem = preToolUse(event);
      return problem ? { code: 2, stderr: `security-audit guard: ${problem}` } : { code: 0 };
    }
    default:
      return { code: 0 };
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  let event;
  try {
    event = JSON.parse(readFileSync(0, "utf8"));
  } catch {
    process.exit(0); // not a hook event: nothing to guard
  }
  let result;
  try {
    result = handle(event);
  } catch (e) {
    // Fail closed inside an audit session, stay out of the way elsewhere.
    const active = event?.session_id && existsSync(marker(event.session_id));
    result = active && event.hook_event_name === "PreToolUse" ? { code: 2, stderr: `security-audit guard error: ${e.message}` } : { code: 0 };
  }
  if (result.stdout) process.stdout.write(`${result.stdout}\n`);
  if (result.stderr) process.stderr.write(`${result.stderr}\n`);
  process.exit(result.code);
}
