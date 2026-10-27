#!/usr/bin/env node
// Installs the security-audit package into OpenCode's config directory. Run it from the built package.
//   node install.mjs [--auditor-model provider/model] [--verifier-model provider/model] [--config-dir DIR]
// --auditor-model: recon, category auditors and test quality (cost over quality).
// --verifier-model: Phase 3 verifiers and COMBINE, the judgment phase. Use the strongest model you have,
//   ideally from another vendor than the auditors, so detection and verification do not share blind spots.
// Unset models inherit the model of the session that runs /security-audit.
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// Values go into YAML frontmatter: accept only a plain provider/model id.
const MODEL_ID = /^[\w.-]+\/[\w.:#/-]+$/;

export function install({ configDir, auditorModel, verifierModel }) {
  for (const m of [auditorModel, verifierModel]) {
    if (m && !MODEL_ID.test(m)) throw new Error(`not a provider/model id: ${m}`);
  }
  const skillDir = join(configDir, "security-audit");
  const fill = (text) => text.replaceAll("{{SKILL_DIR}}", skillDir);
  const models = { "sa-recon": auditorModel, "sa-auditor": auditorModel, "sa-test-quality": auditorModel, "sa-verifier": verifierModel };

  // The package has no SKILL.md; one there means a Claude Code skill (e.g. --config-dir ~/.claude/skills).
  if (existsSync(join(skillDir, "SKILL.md"))) throw new Error(`${skillDir} holds a Claude Code skill, refusing to replace it`);
  rmSync(skillDir, { recursive: true, force: true }); // our own directory: removes files dropped since the last install
  cpSync(join(here, "security-audit"), skillDir, { recursive: true });

  mkdirSync(join(configDir, "agents"), { recursive: true });
  for (const file of readdirSync(join(here, "agents"))) {
    let text = fill(readFileSync(join(here, "agents", file), "utf8"));
    const model = models[file.replace(/\.md$/, "")];
    if (model) text = text.replace(/^mode: subagent$/m, `$&\nmodel: ${model}`);
    writeFileSync(join(configDir, "agents", file), text);
  }
  cpSync(join(here, "commands"), join(configDir, "commands"), { recursive: true });
  cpSync(join(here, "redirect-skill.md"), join(configDir, "skills", "security-audit-opencode", "SKILL.md"));
  mkdirSync(join(configDir, "plugins"), { recursive: true });
  writeFileSync(join(configDir, "plugins", "security-audit-guard.js"), fill(readFileSync(join(here, "plugins", "security-audit-guard.js"), "utf8")));

  return { skillDir, configNote: denyClaudeSkill(configDir) };
}

// OpenCode also loads skills from ~/.claude/skills. The Claude Code variant of this skill dispatches with
// Claude-only instructions, so OpenCode must not load it.
export function denyClaudeSkill(configDir) {
  const manual = 'Add to your OpenCode config by hand: "permission": { "skill": { "security-audit": "deny" } }';
  if (existsSync(join(configDir, "opencode.jsonc"))) return `opencode.jsonc found, not edited. ${manual}`;
  const path = join(configDir, "opencode.json");
  let config = {};
  const existed = existsSync(path);
  if (existed) {
    const raw = readFileSync(path, "utf8");
    try {
      config = JSON.parse(raw);
    } catch {
      return `opencode.json is not plain JSON, not edited. ${manual}`;
    }
    writeFileSync(`${path}.bak`, raw);
  }
  if (typeof config.permission === "string") config.permission = { "*": config.permission };
  config.permission ??= {};
  const skill = config.permission.skill;
  config.permission.skill = typeof skill === "object" && skill ? skill : skill ? { "*": skill } : {};
  config.permission.skill["security-audit"] = "deny";
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
  return `${path}: skill "security-audit" (the Claude Code variant) denied${existed ? `, previous file in ${path}.bak` : ""}`;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const configDir = resolve(opt("--config-dir") ?? join(homedir(), ".config", "opencode"));
  const auditorModel = opt("--auditor-model");
  const verifierModel = opt("--verifier-model");
  const { skillDir, configNote } = install({ configDir, auditorModel, verifierModel });
  console.log(`Installed security-audit ${readFileSync(join(here, "VERSION"), "utf8").trim()} into ${configDir}
  scripts and references: ${skillDir}
  auditors: ${auditorModel ?? "session model"}, verifier: ${verifierModel ?? "session model"}
  ${configNote}
In a project, in OpenCode: /security-audit (or --scope top20 for a cheap first run).`);
}
