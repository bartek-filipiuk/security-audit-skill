#!/usr/bin/env node
// Installs the security-audit skill for the OpenAI Codex CLI. Run it from the repository checkout.
//   node codex/install.mjs [--auditor-model <slug>] [--codex-home DIR]
//   node codex/install.mjs --uninstall [--codex-home DIR]
// Builds the skill into $CODEX_HOME/skills/security-audit (default ~/.codex), and merges the guard's four hook
// handlers into $CODEX_HOME/hooks.json (previous file kept as hooks.json.bak). config.toml is never edited: what
// belongs there is printed.
// --auditor-model: recon, category auditors and test quality are spawned with this model; verifiers and COMBINE
//   inherit the session model. Without it every agent inherits the session model.
import { cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MARKER, build } from "./build.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const MODEL = /^[\w.-]+$/; // goes into SKILL.md text: a plain model slug only
const EVENTS = ["UserPromptSubmit", "PreToolUse", "SessionEnd"];

export const paths = (codexHome) => ({
  skillDir: join(codexHome, "skills", "security-audit"),
  stateDir: join(codexHome, "security-audit"),
  hooksFile: join(codexHome, "hooks.json"),
  guard: join(codexHome, "skills", "security-audit", "hooks", "guard.mjs"),
});

function modelNote(auditorModel) {
  if (!auditorModel) return "Every sub-agent inherits your model: do not set `model` in `spawn_agent`.";
  return `Spawn recon, the category auditors and the test-quality auditor with \`model: "${auditorModel}"\`; the Phase 3 verifier shards and COMBINE inherit your model. If \`spawn_agent\` has no \`model\` parameter, every sub-agent inherits your model.`;
}

// Our handler groups, from the installed hooks/hooks.json (command already filled in).
const ourHooks = (skillDir) => JSON.parse(readFileSync(join(skillDir, "hooks", "hooks.json"), "utf8")).hooks;

const isOurs = (guard) => (handler) => typeof handler?.command === "string" && handler.command.includes(guard);

// Drops our handlers (matched by the guard path) from a hooks object; empty groups and events go too.
function withoutOurs(hooks, guard) {
  const out = {};
  for (const [event, groups] of Object.entries(hooks ?? {})) {
    if (!Array.isArray(groups)) {
      out[event] = groups;
      continue;
    }
    const kept = groups
      .map((g) => (Array.isArray(g?.hooks) ? { ...g, hooks: g.hooks.filter((h) => !isOurs(guard)(h)) } : g))
      .filter((g) => !Array.isArray(g?.hooks) || g.hooks.length);
    if (kept.length) out[event] = kept;
  }
  return out;
}

function tomlFor(hooks) {
  const lines = [];
  for (const [event, groups] of Object.entries(hooks)) {
    for (const g of groups) {
      lines.push(`[[hooks.${event}]]`);
      if (g.matcher) lines.push(`matcher = ${JSON.stringify(g.matcher)}`);
      for (const h of g.hooks) {
        lines.push(`[[hooks.${event}.hooks]]`, `type = "command"`, `command = ${JSON.stringify(h.command)}`, `timeout = ${h.timeout}`);
      }
    }
  }
  return lines.join("\n");
}

const inlineHooks = (codexHome) => {
  const toml = join(codexHome, "config.toml");
  return existsSync(toml) && /^\s*\[\[?\s*hooks[.\]\s]/m.test(readFileSync(toml, "utf8"));
};

// Merges our handlers into hooks.json. Never edits config.toml; if hooks live inline there, prints the TOML.
export function mergeHooks(codexHome, ours, guard) {
  const { hooksFile } = paths(codexHome);
  if (inlineHooks(codexHome)) {
    return `config.toml has inline [hooks], not edited and hooks.json not written. Add by hand to config.toml:\n${tomlFor(ours)}`;
  }
  let config = {};
  let backup = false;
  if (existsSync(hooksFile)) {
    const raw = readFileSync(hooksFile, "utf8");
    try {
      config = JSON.parse(raw);
    } catch {
      return `${hooksFile} is not plain JSON, not edited. Add by hand:\n${JSON.stringify({ hooks: ours }, null, 2)}`;
    }
    writeFileSync(`${hooksFile}.bak`, raw);
    backup = true;
  }
  const hooks = withoutOurs(config.hooks, guard);
  for (const [event, groups] of Object.entries(ours)) hooks[event] = [...(hooks[event] ?? []), ...groups];
  writeFileSync(hooksFile, `${JSON.stringify({ ...config, hooks }, null, 2)}\n`);
  return `${hooksFile}: guard hooks for ${EVENTS.join(", ")} added${backup ? `, previous file in ${hooksFile}.bak` : ""}`;
}

export function unmergeHooks(codexHome, guard) {
  const { hooksFile } = paths(codexHome);
  if (!existsSync(hooksFile)) return inlineHooks(codexHome) ? "config.toml has inline [hooks]: remove the security-audit guard entries by hand" : "no hooks.json";
  const raw = readFileSync(hooksFile, "utf8");
  let config;
  try {
    config = JSON.parse(raw);
  } catch {
    return `${hooksFile} is not plain JSON, not edited: remove the entries that run ${guard} by hand`;
  }
  writeFileSync(`${hooksFile}.bak`, raw);
  writeFileSync(hooksFile, `${JSON.stringify({ ...config, hooks: withoutOurs(config.hooks, guard) }, null, 2)}\n`);
  return `${hooksFile}: guard hooks removed, previous file in ${hooksFile}.bak`;
}

export function install({ codexHome, auditorModel, nodePath = process.execPath }) {
  if (auditorModel !== undefined && !MODEL.test(auditorModel)) throw new Error(`not a model slug: ${auditorModel}`);
  const { skillDir, stateDir, guard } = paths(codexHome);
  if (existsSync(skillDir) && !existsSync(join(skillDir, MARKER))) {
    throw new Error(`${skillDir} exists and was not installed by this port, refusing to replace it`);
  }
  const command = `"${nodePath}" "${guard}"`;
  const tmp = mkdtempSync(join(tmpdir(), "sa-codex-build-"));
  try {
    const pkg = build(join(tmp, "out"));
    const fill = (file, values) => {
      let text = readFileSync(join(pkg, file), "utf8");
      for (const [k, v] of Object.entries(values)) text = text.replaceAll(`{{${k}}}`, v);
      writeFileSync(join(pkg, file), text);
    };
    fill("SKILL.md", { SKILL_DIR: skillDir, MODEL_NOTE: modelNote(auditorModel) });
    fill("hooks/shell-check.mjs", { SKILL_DIR: skillDir });
    fill("hooks/guard.mjs", { STATE_DIR: stateDir });
    fill("hooks/hooks.json", { GUARD_COMMAND: JSON.stringify(command).slice(1, -1) });
    rmSync(skillDir, { recursive: true, force: true }); // ours (marker checked above): drops files removed since
    cpSync(pkg, skillDir, { recursive: true });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  const hooksNote = mergeHooks(codexHome, ourHooks(skillDir), guard);
  return { skillDir, hooksNote };
}

export function uninstall({ codexHome }) {
  const { skillDir, stateDir, guard } = paths(codexHome);
  if (existsSync(skillDir) && !existsSync(join(skillDir, MARKER))) {
    throw new Error(`${skillDir} was not installed by this port, refusing to remove it`);
  }
  const hooksNote = unmergeHooks(codexHome, guard);
  rmSync(skillDir, { recursive: true, force: true });
  rmSync(stateDir, { recursive: true, force: true });
  return { skillDir, hooksNote };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const codexHome = resolve(opt("--codex-home") ?? process.env.CODEX_HOME ?? join(homedir(), ".codex"));
  try {
    if (args.includes("--uninstall")) {
      const { skillDir, hooksNote } = uninstall({ codexHome });
      console.log(`Removed ${skillDir}\n  ${hooksNote}\nRestart Codex.`);
    } else {
      const auditorModel = opt("--auditor-model");
      const { skillDir, hooksNote } = install({ codexHome, auditorModel });
      console.log(`Installed security-audit ${readFileSync(join(skillDir, "VERSION"), "utf8").trim()} into ${skillDir}
  agents: ${auditorModel ? `recon, auditors and test quality on ${auditorModel}, verifiers on the session model` : "all on the session model"}
  ${hooksNote}
Next:
  1. Restart Codex, then trust the guard hooks once: run \`codex\`, type /hooks, trust the security-audit entries.
     Untrusted hooks are skipped silently, so the guard is off until you do. \`codex exec\` can pass
     --dangerously-bypass-hook-trust instead.
  2. Run in workspace-write: \`codex --sandbox workspace-write\`, or headless
     \`codex exec --sandbox workspace-write -a never '$security-audit --scope top20'\`.
     Start with \`$security-audit\`: only then is the session guarded.
Optional, by hand in ${join(codexHome, "config.toml")} (this installer never edits it):
  [agents]
  max_concurrent_threads_per_session = 6     # 5 auditors at once instead of 3
  [sandbox_workspace_write]
  network_access = true                      # lets osv-scanner and docker scanners run; off by default`);
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
