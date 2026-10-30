import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "./build.mjs";
import guard, { checkShell } from "./plugin.js";

const root = "/work/app";

test("guard: redirection only into .security-audit/", () => {
  assert.equal(checkShell("node x.mjs > .security-audit/tools/a.json", root), null);
  assert.equal(checkShell("node x.mjs >> /work/app/.security-audit/a.md 2>&1", root), null);
  assert.equal(checkShell("pnpm vitest run 2> /dev/null", root), null);
  assert.match(checkShell("echo x > out.txt", root), /outside/);
  assert.match(checkShell("echo x >| ../out.txt", root), /outside/);
  assert.match(checkShell("node a.mjs &> '/work/app/src/a.ts'", root), /outside/);
  assert.match(checkShell("echo x > .security-audit/../src/a.ts", root), /outside/);
  assert.match(checkShell("echo x > /elsewhere/.security-audit/a", root), /outside/);
  assert.match(checkShell("git diff --output=patch.diff", root), /git --output/);
  assert.equal(checkShell("cd /work/app && cd .security-audit && node x.mjs", root), null);
  assert.match(checkShell("cd /tmp && node x.mjs", root), /cd leaves/);
  assert.match(checkShell("pwd; cd ..", root), /cd leaves/);
  assert.match(checkShell("cd && echo x > .security-audit/a", root), /cd leaves/);
  assert.match(checkShell("cd ~/x; ls", root), /cd leaves/);
  assert.match(checkShell("cd $HOME", root), /cd leaves/);
  assert.equal(checkShell("node a.mjs --cdx 1", root), null);
});

test("guard: shell arguments may not read outside the project", () => {
  assert.match(checkShell("ls /work", root), /outside the project/);
  assert.match(checkShell("ls ..", root), /outside the project/);
  assert.match(checkShell("git diff --no-index /work/other/answer-key.json /dev/null", root), /outside the project/);
  assert.match(checkShell("node x.mjs --dir=/work/other/.security-audit", root), /outside the project/);
  assert.match(checkShell("git -C ../other log", root), /outside the project/);
  assert.match(checkShell("ls ~/runs", root), /outside the project/);
  assert.match(checkShell("ls src/../../x", root), /outside the project/);
  assert.equal(checkShell("ls /work/app/src && git diff HEAD~1 -- src/a.ts 2>/dev/null", root), null);
  assert.equal(checkShell("cd /work/app && node x.mjs --dir /work/app/.security-audit 2>&1", root), null);
  assert.equal(checkShell("git log --format=%H -n 3 && git show HEAD:src/a.ts", root), null);
  assert.equal(checkShell("node x.mjs --pattern '/\\ncarried_from:/' --re /^id:/", root), null); // regexes, not paths
});

test("guard: paths are read as bash reads them, unresolvable ones are refused", () => {
  const refused = [
    "ls //work/other", "git -C //x log", "node x.mjs --dir //work/other", "cat //etc/passwd", // doubled slashes
    "ls /*/x", "ls {/work/other,/tmp}/x", "ls .*", "ls src/*/../../x", "ls {..,src}", // globs and braces
    "ls $'/work/other/x'", "ls \\/work/other", 'ls ""/work/other', 'ls ".."/other', "ls .\\./other/x", // quoting
    "ls $OLDPWD/x", "ls $TMPDIR/x", "ls ${XDG_CONFIG_HOME}/x", "ls $PWD/..", 'ls "$HOME"', "ls `pwd`/..", // variables
    "ls $(dirname $PWD)", "node x.mjs --dir=$OLDPWD", "node x.mjs --dir=~/x",
  ];
  for (const command of refused) assert.match(checkShell(command, root) ?? "", /outside the project/, command);
  for (const command of ["cd //work/other", "cd $OLDPWD", "cd -", "cd /work/app/../other", '"cd" /tmp', "if true; then cd /x; fi"]) {
    assert.match(checkShell(command, root) ?? "", /cd leaves/, command);
  }
  for (const command of ["echo x > .security-audit/$X", "echo x > '/tmp/(a)'", "echo x > ~/a", "echo x >& out.txt"]) {
    assert.match(checkShell(command, root) ?? "", /redirection writes outside/, command);
  }
  const allowed = [
    "git log -S '/api/'", "node x.mjs --pattern '/x/'", "grep -E '/v1/(users|orgs)' src/a.ts", 'grep -rn "/api/v2/" src',
    "ls src/*.ts && ls //work/app/src", "ls /work/app/src/*.ts", "ls '/work/app/src'", "git log --oneline HEAD..main",
    "cd //work/app/src && ls", "node x.mjs 2>&1 | head -5 # a comment with /etc/passwd",
  ];
  for (const command of allowed) assert.equal(checkShell(command, root), null, command);
});

test("guard: symlinks are followed, inside the project and to it", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sa-guard-")));
  const app = join(dir, "app");
  mkdirSync(join(app, "src"), { recursive: true });
  mkdirSync(join(dir, "other"));
  writeFileSync(join(dir, "other", "answer-key.json"), "{}");
  symlinkSync(join(dir, "other"), join(app, "out")); // a link in the project that points out of it
  symlinkSync(join(app, "src"), join(app, "lib")); // a link that stays inside
  symlinkSync(join(dir, "missing"), join(app, "dangling"));
  symlinkSync(app, join(dir, "applink")); // the project itself opened through a link
  for (const r of [app, join(dir, "applink")]) {
    for (const command of ["ls out", "cat out/answer-key.json", "ls src/../out/", "ls dangling", "ls lib/../../other"]) {
      assert.match(checkShell(command, r) ?? "", /outside the project/, `${r}: ${command}`);
    }
    assert.match(checkShell("cd out", r) ?? "", /cd leaves/);
    assert.match(checkShell("echo x > .security-audit/../out/a", r) ?? "", /redirection writes outside/);
    for (const command of ["ls src lib/", `ls ${app}/src ${dir}/applink/lib`, "cd lib && ls", "ls src/*"]) {
      assert.equal(checkShell(command, r), null, `${r}: ${command}`);
    }
  }
  rmSync(dir, { recursive: true, force: true });
});

test("guard: only sa-* agents, only the shell tool", async () => {
  let hook;
  await guard.setup({ location: { directory: root }, tool: { hook: async (name, fn) => (hook = fn) } });
  const run = (agent, tool, command) => () => hook({ agent, tool, input: { command } });
  assert.throws(run("sa-auditor", "shell", "echo x > src/a.ts"), /security-audit guard/);
  assert.doesNotThrow(run("build", "shell", "echo x > src/a.ts"));
  assert.doesNotThrow(run("sa-auditor", "read", "echo x > src/a.ts"));
});

test("build + install: self-contained package, no placeholders left", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sa-opencode-"));
  build(join(dir, "pkg"));
  assert.ok(!existsSync(join(dir, "pkg", "security-audit", "scripts", "selftest.test.mjs")));
  const { install, denyClaudeSkill } = await import(join(dir, "pkg", "install.mjs"));

  const config = join(dir, "config");
  install({ configDir: config, auditorModel: "deepseek/deepseek-flash", verifierModel: "anthropic/claude-fable-5-1" });
  for (const sub of ["agents", "commands", "plugins", "skills/security-audit-opencode"]) {
    for (const f of readdirSync(join(config, sub)).filter((f) => !f.endsWith("/"))) {
      const p = join(config, sub, f);
      if (f.includes(".")) assert.doesNotMatch(readFileSync(p, "utf8"), /\{\{/, p);
    }
  }
  const coordinator = readFileSync(join(config, "agents", "sa-coordinator.md"), "utf8");
  assert.match(coordinator, /## Hard Rules/); // the SKILL.md body is there
  assert.ok(coordinator.includes(`node ${join(config, "security-audit")}/scripts/*": allow`));
  assert.ok(coordinator.includes(`"${join(config, "security-audit")}/**": allow`)); // reads outside the project
  assert.doesNotMatch(coordinator, /^model:/m);
  assert.match(readFileSync(join(config, "agents", "sa-verifier.md"), "utf8"), /^mode: subagent\nmodel: anthropic\/claude-fable-5-1$/m);
  assert.match(readFileSync(join(config, "agents", "sa-recon.md"), "utf8"), /^model: deepseek\/deepseek-flash$/m);
  assert.ok(existsSync(join(config, "security-audit", "scripts", "prepass.mjs")));
  assert.throws(() => install({ configDir: config, auditorModel: "x\nmode: primary" }), /provider\/model/);
  writeFileSync(join(config, "security-audit", "SKILL.md"), "");
  assert.throws(() => install({ configDir: config }), /Claude Code skill/);

  // The deny merges into an existing config and keeps what is there.
  writeFileSync(join(config, "opencode.json"), JSON.stringify({ model: "a/b", permission: { skill: "ask" } }));
  denyClaudeSkill(config);
  const merged = JSON.parse(readFileSync(join(config, "opencode.json"), "utf8"));
  assert.equal(merged.model, "a/b");
  assert.deepEqual(merged.permission.skill, { "*": "ask", "security-audit": "deny" });
  writeFileSync(join(config, "opencode.json"), "{ // comment\n}");
  assert.match(denyClaudeSkill(config), /not plain JSON/);
});

// The repository is the Claude Code skill directory (~/.claude/skills/security-audit), and OpenCode scans
// ~/.claude/skills too: any second SKILL.md in it, dist/ included, would leak into one tool or the other.
test("the skill directory holds exactly one SKILL.md", () => {
  const repo = fileURLToPath(new URL("..", import.meta.url));
  const found = readdirSync(repo, { recursive: true })
    .filter((p) => !/(^|\/)(\.git|node_modules)(\/|$)/.test(p))
    .filter((p) => p === "SKILL.md" || p.endsWith("/SKILL.md"));
  assert.deepEqual(found, ["SKILL.md"]);
});
