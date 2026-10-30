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
import { homedir } from "node:os";
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

// rg/grep glob arguments that only exclude: `-g '!**/.env*'`, `--glob=!.env*`, `--iglob '!x/.env'`.
const GLOB_FLAGS = ["-g", "--glob", "--iglob"];
const negatedGlob = (words, i) =>
  (words[i].startsWith("!") && GLOB_FLAGS.includes(words[i - 1])) || /^(--i?glob=|-g)!/.test(words[i]);

// ---- Pre-processing before checkShell (codex only; the OpenCode guard is unchanged) ----
// A few safe shell shapes that checkShell refuses as a whole are rewritten into an equivalent command it can check:
//   `>> .gitignore` (append to the project's own .gitignore, not through a symlink) -> `>> /dev/null`;
//   `$(simple command)` used only as an argument of `[`/`test`, the inner command checked on its own;
//   leading `PATH=/usr/bin`-style assignments from a fixed safe set -> dropped;
//   `{a,b}` brace lists whose every expansion stays in .security-audit/ -> expanded;
//   `for v in <literal words>; do …; done` -> the body once per value, `$v` replaced by the value.
// Anything that does not match exactly is left as it was, so checkShell refuses it as before.

// shellWords with source positions. Every result is compared with shellWords itself before it is trusted.
function lex(command) {
  const out = [];
  let word = null;
  const begin = (i) => (word ??= { chars: [], start: i, end: i });
  const push = (c, i, q = false, x = false) => {
    begin(i);
    word.chars.push({ c, q, x, i });
    word.end = Math.max(word.end, i + 1);
  };
  const end = () => {
    if (word) out.push(word);
    word = null;
  };
  const expands = (i) => /[\w{(@*#?!$-]/.test(command[i + 1] ?? "");
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "\\") {
      if (command[i + 1] === "\n") i++;
      else if (i + 1 < command.length) {
        begin(i);
        i++;
        push(command[i], i, true);
      }
    } else if (c === "'") {
      begin(i);
      for (i++; i < command.length && command[i] !== "'"; i++) push(command[i], i, true);
      word.end = Math.min(i + 1, command.length);
    } else if (c === '"') {
      begin(i);
      for (i++; i < command.length && command[i] !== '"'; i++) {
        if (command[i] === "\\" && '$`"\\'.includes(command[i + 1])) {
          i++;
          push(command[i], i, true);
        } else push(command[i], i, true, command[i] === "`" || (command[i] === "$" && expands(i)));
      }
      word.end = Math.min(i + 1, command.length);
    } else if (c === "$" && command[i + 1] === "'") {
      push("$", i, false, true);
      for (i += 2; i < command.length && command[i] !== "'"; i++) {
        if (command[i] === "\\") i++;
        push(command[i], i, true);
      }
      word.end = Math.min(i + 1, command.length);
    } else if (c === "`" || (c === "$" && expands(i))) {
      push(c, i, false, true);
    } else if (c === "#" && !word) {
      while (i + 1 < command.length && command[i + 1] !== "\n") i++;
    } else if (/\s/.test(c) && c !== "\n") {
      end();
    } else if (/[;&|()\n]/.test(c)) {
      end();
      out.push({ op: ";", start: i, end: i + 1 });
    } else if (c === "<") {
      end();
    } else if (c === ">") {
      end();
      const start = i;
      if (command[i + 1] === ">" || command[i + 1] === "|") i++;
      if (command[i + 1] === "&") i++;
      out.push({ op: command[i] === "&" ? ">&" : ">", start, end: i + 1, raw: command.slice(start, i + 1) });
    } else push(c, i);
  }
  end();
  const plain = out.map((it) => (it.op ? it.op : it.chars.map(({ c, q, x }) => ({ c, q, x }))));
  return JSON.stringify(plain) === JSON.stringify(shellWords(command)) ? out : null;
}

const wtext = (word) => word.chars.map((ch) => ch.c).join("");
const START_KW = new Set(["if", "then", "do", "else", "elif", "while", "until", "!", "{", "time"]);
const LOOP_KW = new Set(["for", "while", "until", "select", "case", "function"]);
const PLACEHOLDER = "__sa_subst__";

// Applies non-overlapping {start, end, text} edits.
function applyEdits(command, edits) {
  let out = command;
  for (const e of [...edits].sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

// One `for NAME in w1 w2 …; do BODY; done` with literal words, unrolled to `{ BODY[w1]\nBODY[w2]\n}`. Null when
// there is no such loop or it is not one this can unroll (then the command is checked as it is and refused).
function unrollFor(command) {
  const items = lex(command);
  if (!items) return null;
  for (let k = 0, start = true; k < items.length; k++) {
    const it = items[k];
    if (it.op) {
      if (it.op === ";") start = true;
      else k++;
      continue;
    }
    const w = wtext(it);
    if (start && w === "for" && it.chars.every((ch) => !ch.q)) return unrollAt(command, items, k);
    start = start && START_KW.has(w);
  }
  return null;
}

function unrollAt(command, items, k) {
  const isWord = (i, w) => items[i] && !items[i].op && (w === undefined || wtext(items[i]) === w);
  const sep = (i) => items[i]?.op === ";" && /[;\n]/.test(command[items[i].start]);
  if (!isWord(k + 1) || !/^[A-Za-z_]\w*$/.test(wtext(items[k + 1])) || items[k + 1].chars.some((ch) => ch.q)) return null;
  const name = wtext(items[k + 1]);
  if (!isWord(k + 2, "in")) return null;
  let i = k + 3;
  const values = [];
  for (; isWord(i); i++) {
    const v = items[i];
    if (v.chars.some((ch) => ch.x || (!ch.q && /[*?[\]{}~]/.test(ch.c)))) return null; // not a literal word
    values.push(wtext(v));
  }
  if (!values.length || values.length > 200 || !sep(i)) return null;
  while (sep(i)) i++;
  if (!isWord(i, "do")) return null;
  const doItem = items[i];
  let done = -1;
  for (let j = i + 1, start = true; j < items.length; j++) {
    const it = items[j];
    if (it.op) {
      if (it.op === ";") start = true;
      else j++;
      continue;
    }
    const w = wtext(it);
    if (start && (LOOP_KW.has(w) || w === "do")) return null; // nested loops: not unrolled
    if (start && w === "done") {
      done = j;
      break;
    }
    start = start && START_KW.has(w);
  }
  if (done < 0) return null;
  const body = command.slice(doItem.end, items[done].start);
  const bodyItems = lex(body);
  if (!bodyItems) return null;
  // `$NAME` / `${NAME}` expansions in the body.
  const refs = [];
  for (const it of bodyItems) {
    if (it.op) continue;
    for (const ch of it.chars) {
      if (ch.c !== "$" || !ch.x) continue;
      const m = body.slice(ch.i + 1).match(new RegExp(`^(?:${name}(?!\\w)|\\{${name}\\})`));
      if (m) refs.push({ start: ch.i, end: ch.i + 1 + m[0].length, quoted: ch.q });
    }
  }
  const bodies = [];
  for (const v of values) {
    const edits = [];
    for (const r of refs) {
      if (r.quoted) edits.push({ ...r, text: v.replace(/[\\$`"]/g, "\\$&") });
      else if (/^[\w./@%+,:=-]+$/.test(v)) edits.push({ ...r, text: v }); // unquoted: no splitting or globbing
      else return null;
    }
    bodies.push(applyEdits(body, edits));
  }
  return `${command.slice(0, items[k].start)}{ ${bodies.join("\n")}\n}${command.slice(items[done].end)}`;
}

const SAFE_ENV = new Set(["PATH", "PYTHONDONTWRITEBYTECODE", "NODE_OPTIONS", "CI", "NO_COLOR", "FORCE_COLOR", "TZ", "LANG", "LC_ALL"]);
const NODE_BIN = new RegExp(`^${join(homedir(), ".nvm", "versions", "node").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/v[\\d.]+/bin$`);
function safeAssignment(word) {
  if (word.chars.some((ch) => ch.x)) return false;
  const eq = word.chars.findIndex((ch) => ch.c === "=");
  if (eq <= 0 || word.chars.slice(0, eq + 1).some((ch) => ch.q)) return false;
  const t = wtext(word);
  const name = t.slice(0, eq);
  const value = t.slice(eq + 1);
  if (!SAFE_ENV.has(name)) return false;
  if (name === "PATH") return value.split(":").every((d) => ["/usr/bin", "/bin", "/usr/local/bin"].includes(d) || NODE_BIN.test(d));
  if (name === "NODE_OPTIONS") return !value.split(/\s+/).some((o) => /^(-r|--require|--import|--loader|--experimental-loader|--env-file|--inspect)/.test(o));
  return /^[\w.,:+-]*(\/[\w+-]+)?$/.test(value); // 1, en_US.UTF-8, Europe/Warsaw
}

// `{a,b}` in one word, every expansion a file or glob directly under a directory inside .security-audit/.
function braceExpansion(command, word, root) {
  if (word.chars.some((ch) => ch.x)) return null;
  const open = word.chars.filter((ch) => !ch.q && ch.c === "{");
  const close = word.chars.filter((ch) => !ch.q && ch.c === "}");
  if (open.length !== 1 || close.length !== 1 || open[0].i > close[0].i) return null;
  const o = word.chars.indexOf(open[0]);
  const c = word.chars.indexOf(close[0]);
  const commas = [];
  for (let j = o + 1; j < c; j++) if (!word.chars[j].q && word.chars[j].c === ",") commas.push(j);
  if (!commas.length) return null;
  const cuts = [o, ...commas, c];
  const prefix = word.chars.slice(0, o);
  const suffix = word.chars.slice(c + 1);
  const pre = wtext({ chars: prefix });
  const dir = pre.slice(0, pre.lastIndexOf("/") + 1);
  if (!dir || !inAuditDir(root, dir) || prefix.some((ch) => !ch.q && /[*?[~]/.test(ch.c))) return null;
  const out = [];
  for (let n = 0; n + 1 < cuts.length; n++) {
    const alt = word.chars.slice(cuts[n] + 1, cuts[n + 1]);
    const chars = [...prefix, ...alt, ...suffix];
    const t = wtext({ chars });
    const last = t.slice(dir.length);
    if (last.includes("/") || ["", ".", ".."].includes(last)) return null;
    if (!chars.some((ch) => !ch.q && /[*?[]/.test(ch.c)) && !inAuditDir(root, t)) return null;
    const raw = (from, to) => command.slice(from, to);
    out.push(raw(word.start, open[0].i) + raw(word.chars[cuts[n]].i + 1, word.chars[cuts[n + 1]].i) + raw(close[0].i + 1, word.end));
  }
  return out.join(" ");
}

// Words of `command` (after rewriting) holding the substitution placeholder must be arguments of `[`/`[[`/`test`.
function placeholdersInTests(command) {
  const items = shellWords(command);
  let words = [];
  const ok = () => {
    if (!words.some((w) => w.includes(PLACEHOLDER))) return true;
    const rest = words.slice(words.findIndex((w) => !START_KW.has(w)));
    return ["[", "[[", "test"].includes(rest[0]) && !rest[0].includes(PLACEHOLDER);
  };
  for (let k = 0; k < items.length; k++) {
    const it = items[k];
    if (Array.isArray(it)) words.push(text(it));
    else if (it === ";") {
      if (!ok()) return false;
      words = [];
    } else if (Array.isArray(items[++k]) && text(items[k]).includes(PLACEHOLDER)) return false; // redirection target
  }
  return ok();
}

// The command checkShell and checkPolicy see, or a problem found in an inner `$(…)`.
function rewrite(command, root, depth) {
  let cmd = command;
  for (let n = 0; n < 10; n++) {
    const next = unrollFor(cmd);
    if (next === null) break;
    cmd = next;
  }
  const items = lex(cmd);
  if (!items) return { command };
  const rootReal = physical(resolve(root));
  const gitignore = join(rootReal, ".gitignore");
  const base = [];
  const substs = [];
  for (let k = 0, start = true; k < items.length; k++) {
    const it = items[k];
    if (it.op) {
      if (it.op === ";") {
        start = true;
        continue;
      }
      const target = items[k + 1];
      if (it.raw === ">>" && target && !target.op && !target.chars.some((ch) => ch.x || (!ch.q && /[*?[{}~]/.test(ch.c)))) {
        const p = resolve(rootReal, wtext(target));
        if (p === gitignore && physical(p) === gitignore) base.push({ start: target.start, end: target.end, text: "/dev/null" });
      }
      k++;
      continue;
    }
    const w = wtext(it);
    if (start && /^[A-Za-z_]\w*=/.test(w)) {
      if (safeAssignment(it)) base.push({ start: it.start, end: it.end, text: "" });
      else if (w.startsWith("NODE_OPTIONS=")) return { command, problem: `NODE_OPTIONS may not load code (${w})` };
    } else {
      start = start && START_KW.has(w);
      const expanded = braceExpansion(cmd, it, root);
      if (expanded !== null) base.push({ start: it.start, end: it.end, text: expanded });
    }
    for (const ch of it.chars) {
      if (ch.c !== "$" || !ch.x || cmd[ch.i + 1] !== "(") continue;
      const close = cmd.indexOf(")", ch.i + 2);
      const inner = close > 0 ? cmd.slice(ch.i + 2, close) : "";
      if (/^[^()$`'"\\\n;&|<>]+$/.test(inner) && !cmd.includes(PLACEHOLDER)) substs.push({ start: ch.i, end: close + 1, text: PLACEHOLDER, inner });
    }
  }
  const outside = (e) => !substs.some((s) => e.start < s.end && s.start < e.end);
  const plain = applyEdits(cmd, base);
  if (!substs.length || depth >= 3) return { command: plain };
  const withSubst = applyEdits(cmd, [...base.filter(outside), ...substs]);
  if (!placeholdersInTests(withSubst)) return { command: plain };
  for (const s of substs) {
    const why = checkCommand(s.inner, root, depth + 1);
    if (why) return { command: withSubst, problem: `in $(${s.inner}): ${why}` };
  }
  return { command: withSubst };
}

// The whole shell check: the rewrites above, then OpenCode's checkShell, then the blocklist.
export function checkCommand(command, root, depth = 0) {
  const { command: cmd, problem } = rewrite(command, root, depth);
  return problem ?? checkShell(cmd, root) ?? checkPolicy(cmd, root, depth);
}

// Blocklist on top of checkShell: Codex has no deny-by-default shell, so the model reads code through it.
export function checkPolicy(command, root, depth = 0) {
  for (let words of commands(command)) {
    for (let i = 0; i < words.length; i++) if (isEnvFile(words[i]) && !negatedGlob(words, i)) return `.env files may not be read (${words[i]})`;
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
      const why = inner && checkCommand(inner, root, depth + 1);
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
  const problem = checkCommand(command, root);
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
      const additionalContext = "security-audit guard active for this session: edits only in .security-audit/ (plus adding lines to the project's .gitignore), read-only git, no network.";
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
