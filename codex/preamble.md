# Codex adaptation (read this first)

You run the security-audit pipeline below inside the OpenAI Codex CLI. The pipeline was written for Claude Code.
Where it differs, these mappings apply. They replace the pipeline's "Portability" section.

- **Sub-agents are requested.** This skill explicitly asks you to spawn sub-agents for Phases 1–4 in Parallel
  Mode: recon, the category auditors, the Phase 3 verifier shards and COMBINE, and the test-quality auditor.
  Standard and Triage Mode stay in this context, as the pipeline says.
- **Arguments.** Codex does not expand `$ARGUMENTS`. Take the flags (`--scope`, `--since`, `--stack`, `--brief`,
  `--info`, `--verify-fixes`) from the user's message that invoked `$security-audit`.
- **`$SKILL_DIR` is `{{SKILL_DIR}}`.** Write every script call with that absolute path, e.g.
  `node {{SKILL_DIR}}/scripts/prepass.mjs --new-run`. The `references/` and `agents/` files named below are
  under that directory.
- **Dispatch.** "Dispatch an agent with the prompt from `agents/<file>.md`" means one `spawn_agent` call with
  `fork_turns: "none"` and a prompt made of: the Rules Block for Every Agent (below), the line
  `Read and follow {{SKILL_DIR}}/agents/<file>.md`, and the inputs the pipeline lists (paths, domain, number
  range, mode), never file contents. "All agents run in parallel" means several `spawn_agent` calls, then
  `wait_agent` (prefer long waits). Codex runs at most 4 agents at once including you, so start at most three
  sub-agents at a time and start the next one when one finishes.
- **Models.** Ignore every model name in the pipeline, including the Agent Model Selection table.
  {{MODEL_NOTE}}
- **Tools named in the prompts.** Grep is `rg -n`, Glob is `rg --files` (with `-g '<glob>'`), Read is
  `sed -n '1,200p' <file>`. Run them through the shell. `rg` skips hidden and ignored files; list dot
  directories such as `.github/` explicitly.
- **Long commands.** Run `prepass.mjs` once, in the foreground, with the longest timeout or yield time the shell
  tool allows. Never start it twice. If the call returns while the command is still running, keep polling that
  same session, or check with `ls .security-audit/prepass.md` until the file exists, then continue.
- **Sandbox and network.** Run inside the workspace-write sandbox. Never request escalation
  (`sandbox_permissions: "require_escalated"`) for anything in this audit, network included. When a pre-pass
  scanner cannot run (no network, no docker), its `NOT RUN` line goes into `not-assessed.md` as the pipeline says.
- **The rules block is enforced** when the run was started with `$security-audit`: a hook refuses edits outside
  `.security-audit/` (and `.gitignore`), shell redirection outside `.security-audit/`, a `cd` out of the
  project, paths outside the project and `{{SKILL_DIR}}`, `.env` files, git commands that change anything,
  network tools and package installs, and rendering the report while `audit-state.mjs --final` fails. A refused
  call is the rules block working: change the method instead of retrying the same call, and record a check you
  cannot do in `not-assessed.md`.
- **Phase 0 `.gitignore` step.** Run `git check-ignore -q .security-audit/report.md`. If it fails, add the line
  `.security-audit/` to `.gitignore` with `apply_patch` (create the file if it is missing). Then run
  `git ls-files --error-unmatch .security-audit` for the tracked warning.
- **Claude Code only.** Skip the audit-live paragraph and the safety-classifier remark.
- **Phase 6 (fixing source) does not run here**, because the guard refuses source edits. `--verify-fixes` works,
  since it edits only finding files. When the user asks for fixes, tell them to apply them in a normal Codex
  session following `{{SKILL_DIR}}/references/remediation.md`, then run `$security-audit --verify-fixes`.
- **`--mutation` does not run here**, because it needs a copy of the repository outside the project. Add the
  line `| tests | mutation testing | not supported in the Codex variant |` to `not-assessed.md`.

---

