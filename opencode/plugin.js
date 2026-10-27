// OpenCode plugin (v2 API, beta) for the sa-* audit agents. Their permissions already allow only the skill's
// scripts, read-only git and test runners; this closes what permissions cannot see: shell redirection and
// `git --output` writing outside .security-audit/, a cd out of the project, shell arguments that read outside
// the project, and a report rendered over findings that do not validate.
import { execFileSync } from "node:child_process";
import { isAbsolute, relative, resolve } from "node:path";

const SKILL_DIR = "{{SKILL_DIR}}";

// Files written by `>`, `>>`, `>|`, `2>`, `&>`; `>&1` duplicates a descriptor and writes no file.
export function redirectTargets(command) {
  return [...command.matchAll(/(?:\d|&)?>(?:>|\|)?(?!&)\s*("[^"]*"|'[^']*'|[^\s;&|<>]+)/g)].map((m) =>
    m[1].replace(/^["']|["']$/g, ""),
  );
}

// ponytail: relative targets resolve against the project root, so a redirect after `cd .security-audit` is
// refused even though it is safe; the agent then uses an absolute path. Exact cwd tracking is not worth a
// shell parser.
export function checkShell(command, root) {
  const auditDir = resolve(root, ".security-audit");
  for (const target of redirectTargets(command)) {
    if (target === "/dev/null") continue;
    const rel = relative(auditDir, resolve(root, target));
    if (rel.startsWith("..") || isAbsolute(rel)) return `redirection writes outside .security-audit/ (${target})`;
  }
  for (const [, target = "~"] of command.matchAll(/(?:^|[;&|]\s*)cd(?:\s+("[^"]*"|'[^']*'|[^\s;&|]+))?(?![^\s;&|])/g)) {
    const path = target.replace(/^["']|["']$/g, "");
    const rel = /^[~$-]/.test(path) ? ".." : relative(root, resolve(root, path)); // home, variables, `cd -`
    if (rel.startsWith("..") || isAbsolute(rel)) return `cd leaves the project (${target})`;
  }
  if (/\bgit\b[^;&|]*\s--output(=|\s)/.test(command)) return "git --output writes a file";
  // Reads outside the project: `external_directory` holds the file tools, not shell arguments (`ls ..`,
  // `git diff --no-index /x /dev/null`, a skill script with `--dir /elsewhere`). A path argument must stay in the
  // project or the skill directory, so an audit never sees another project, another run or its answer key.
  for (const token of command.split(/[\s;&|<>()]+/)) {
    const path = token.replace(/^[^=]*=(?=[/~.$])/, "").replace(/^["']|["']$/g, "");
    if (!/^(\/|~|\$\{?HOME|\.\.(\/|$))|\/\.\.(\/|$)/.test(path) || path === "/dev/null") continue;
    const abs = /^[~$]/.test(path) ? null : resolve(root, path);
    const inside = (dir) => abs !== null && !relative(dir, abs).startsWith("..") && !isAbsolute(relative(dir, abs));
    if (!inside(root) && !inside(SKILL_DIR)) return `path outside the project (${path})`;
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
