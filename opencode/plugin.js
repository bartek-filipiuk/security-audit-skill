// OpenCode plugin (v2 API, beta) for the sa-* audit agents. Their permissions already allow only the skill's
// scripts, read-only git and test runners; this closes what permissions cannot see: shell redirection and
// `git --output` writing outside .security-audit/, a cd out of the project, shell arguments that read outside
// the project, and a report rendered over findings that do not validate.
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const SKILL_DIR = "{{SKILL_DIR}}";

// Words as bash would pass them: quotes and backslashes removed, each character tagged `q` when it was quoted
// or escaped (no glob, no tilde) and `x` when it starts an expansion ($VAR, ${..}, $(..), `..`, $'..'), whose
// value the guard cannot know. Strings mark structure: ";" a new command (; & | ( ) newline), ">" a file
// redirection, ">&" a descriptor duplication. Not a full parser: heredoc bodies are read as words (stricter).
export function shellWords(command) {
  const out = [];
  let word = null;
  const push = (c, q = false, x = false) => (word ??= []).push({ c, q, x });
  const end = () => {
    if (word) out.push(word);
    word = null;
  };
  const expands = (i) => /[\w{(@*#?!$-]/.test(command[i + 1] ?? "");
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "\\") {
      if (command[i + 1] === "\n") i++;
      else if (i + 1 < command.length) push(command[++i], true);
    } else if (c === "'") {
      word ??= [];
      for (i++; i < command.length && command[i] !== "'"; i++) push(command[i], true);
    } else if (c === '"') {
      word ??= [];
      for (i++; i < command.length && command[i] !== '"'; i++) {
        if (command[i] === "\\" && '$`"\\'.includes(command[i + 1])) push(command[++i], true);
        else push(command[i], true, command[i] === "`" || (command[i] === "$" && expands(i)));
      }
    } else if (c === "$" && command[i + 1] === "'") {
      push("$", false, true); // $'\057etc' decodes escapes: never resolvable here
      for (i += 2; i < command.length && command[i] !== "'"; i++) push(command[i] === "\\" ? command[++i] : command[i], true);
    } else if (c === "`" || (c === "$" && expands(i))) {
      push(c, false, true);
    } else if (c === "#" && !word) {
      while (i + 1 < command.length && command[i + 1] !== "\n") i++;
    } else if (/\s/.test(c) && c !== "\n") {
      end();
    } else if (/[;&|()\n]/.test(c)) {
      end();
      out.push(";");
    } else if (c === "<") {
      end();
    } else if (c === ">") {
      end();
      if (command[i + 1] === ">" || command[i + 1] === "|") i++;
      if (command[i + 1] === "&") i++;
      out.push(command[i] === "&" ? ">&" : ">");
    } else push(c);
  }
  end();
  return out;
}

const text = (word) => word.map((ch) => ch.c).join("");

// Physical path, as the kernel opens it: every existing symlink on the way is followed, so `..` after a link
// climbs from its target. Components that do not exist resolve lexically. A dangling or looping link is null.
function physical(base, path) {
  let cur = path.startsWith("/") ? "/" : base;
  for (const part of path.split("/")) {
    if (part === "" || part === ".") continue;
    cur = part === ".." ? dirname(cur) : join(cur, part);
    let link = false;
    try {
      link = lstatSync(cur).isSymbolicLink();
    } catch {}
    if (link) {
      try {
        cur = realpathSync(cur);
      } catch {
        return null;
      }
    }
  }
  return cur;
}

const within = (dir, p) => p !== null && (p === dir || p.startsWith(dir === "/" ? "/" : `${dir}/`));

// Why a word may reach outside `dirs` (resolved against `base`), or null. Fails closed on what it cannot resolve.
// `read` is an argument: it may be `--dir=/x` and may be a regex; a redirection or cd target is neither.
function outsideWord(word, base, dirs, read = false) {
  if (word.some((ch) => ch.x)) return "variable or substitution";
  const eq = word.findIndex((ch) => ch.c === "=" || ch.c === "/");
  if (read && eq > 0 && word[eq].c === "=") word = word.slice(eq + 1); // --dir=/x, KEY=/x
  if (!word.length) return null;
  const raw = text(word);
  const path = raw.replace(/\/+/g, "/"); // //work == /work
  if (path === "/dev/null") return null;
  const bare = (re) => word.some((ch) => !ch.q && re.test(ch.c));
  if (word[0].c === "~" && !word[0].q) return "home directory";
  if (bare(/[{}]/) && !["{", "}", "{}"].includes(raw)) return "brace expansion"; // {/x,/y}, {..,a}
  const glob = word.findIndex((ch) => !ch.q && /[*?[]/.test(ch.c));
  if (glob >= 0) {
    // A glob stays inside when its fixed directory does and nothing after it can be `..` (`.*` matches it).
    const lead = text(word.slice(0, glob));
    const dir = lead.slice(0, lead.lastIndexOf("/") + 1);
    if (raw.slice(dir.length).split("/").some((part) => part.startsWith("."))) return "glob";
    return dirs.some((d) => within(d, physical(base, dir || "."))) ? null : "glob";
  }
  // `/\ncarried_from:/`, `'/api/'`, `/^id:/` are regexes in a script, git or grep argument. Read as one only when
  // nothing by that name exists: a quoted word with a regex character or a trailing slash, or a bare `/` not
  // followed by a name. ponytail: `git log -S '/etc/'` is refused because /etc exists; rephrase the regex.
  if (read && path.startsWith("/") && path.length > 1 && !existsSync(path)) {
    if (word.every((ch) => ch.q) && (/[\\^$()|+?*[\]{}]/.test(path) || path.endsWith("/"))) return null;
    if (!/[\w.~@+-]/.test(path[1])) return null;
  }
  return dirs.some((d) => within(d, physical(base, path))) ? null : "path";
}

// ponytail: relative targets resolve against the project root, so a redirect after `cd .security-audit` is
// refused even though it is safe; the agent then uses an absolute path. Exact cwd tracking is not worth a
// shell parser.
export function checkShell(command, root) {
  const rootReal = physical("/", resolve(root));
  const skillReal = physical("/", resolve(SKILL_DIR));
  const auditDir = join(rootReal, ".security-audit");
  const items = shellWords(command);
  for (let k = 0; k < items.length; k++) {
    if (!(items[k] === ">" || items[k] === ">&") || !Array.isArray(items[k + 1])) continue;
    const target = items[k + 1];
    if (text(target) === "/dev/null" || (items[k] === ">&" && /^(\d+-?|-)$/.test(text(target)))) continue; // >&2, >&-
    if (outsideWord(target, rootReal, [auditDir])) return `redirection writes outside .security-audit/ (${text(target)})`;
  }
  // Every cd target (also `pushd`) must stay in the project: no home, no `cd -`, no variable, no glob.
  for (let k = 0, start = true; k < items.length; k++) {
    const item = items[k];
    if (!Array.isArray(item)) {
      start = item === ";" ? true : start;
      if (item !== ";") k++; // a redirection target is not a command
      continue;
    }
    const name = text(item);
    const wasStart = start;
    start = start && ["if", "then", "do", "else", "elif", "while", "until", "!", "{", "time", "command", "builtin"].includes(name);
    if (!wasStart || (name !== "cd" && name !== "pushd")) continue;
    let a = k + 1;
    while (Array.isArray(items[a]) && /^-[LPe@]+$/.test(text(items[a]))) a++;
    const target = Array.isArray(items[a]) ? items[a] : null;
    if (!target || text(target) === "-" || outsideWord(target, rootReal, [rootReal])) {
      return `cd leaves the project (${target ? text(target) : "~"})`;
    }
  }
  if (/\bgit\b[^;&|]*\s--output(=|\s)/.test(command)) return "git --output writes a file";
  // Reads outside the project: `external_directory` holds the file tools, not shell arguments (`ls ..`,
  // `git diff --no-index /x /dev/null`, a skill script with `--dir /elsewhere`). A path argument must stay in the
  // project or the skill directory, so an audit never sees another project, another run or its answer key.
  // Every word counts, normalized as bash reads it (`//x`, `\/x`, `""/x`, `.\./x` are paths too) and resolved
  // through symlinks; variables, `$'..'`, braces and globs that could leave are refused, not guessed.
  // This stops accidents, not a hostile model: the test runner still runs code that can read anything.
  for (const item of items) {
    if (!Array.isArray(item)) continue;
    const why = outsideWord(item, rootReal, [rootReal, skillReal], true);
    if (why) return `path outside the project (${text(item)}${why === "path" ? "" : `: ${why}`})`;
  }
  return null;
}

// SKILL.md: audit-state.mjs --final must exit 0 before the report is assembled.
function reportGate(root) {
  try {
    execFileSync("node", [`${SKILL_DIR}/scripts/audit-state.mjs`, "--final", "--dir", resolve(root, ".security-audit")], {
      stdio: "pipe",
    });
    return null;
  } catch (e) {
    return `audit-state.mjs --final fails, fix the finding files first:\n${String(e.stdout || e.message).slice(-1500)}`;
  }
}

export default {
  id: "security-audit-guard",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", (event) => {
      if (!String(event.agent).startsWith("sa-") || event.tool !== "shell") return;
      const command = String(event.input?.command ?? "");
      const root = ctx.location.directory;
      const problem = checkShell(command, root) ?? (/report-(md|html)\.mjs/.test(command) ? reportGate(root) : null);
      if (problem) throw new Error(`security-audit guard: ${problem}`);
    });
  },
};
