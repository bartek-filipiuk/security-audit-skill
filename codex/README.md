# security-audit for the OpenAI Codex CLI

The Codex variant of the security-audit skill: the same pipeline, prompts, checklist and scripts as the Claude
Code skill, installed as a Codex skill with a guard hook. It does not need the Claude Code or OpenCode variant
and does not touch them. Built and tested against codex-cli 0.155.1.

Requirements: Codex CLI with hooks (stable since 0.15x), Node 20+, git, `rg` (ripgrep). For dependency and secret
scanning, `osv-scanner` and `gitleaks` on `PATH`; see Network below.

## Install

From a checkout of the repository:

```bash
node codex/install.mjs                                # every agent on the session model
node codex/install.mjs --auditor-model <model-slug>   # recon, auditors, test quality on a cheaper model
```

The installer builds the skill straight into `$CODEX_HOME/skills/security-audit/` (default `~/.codex`; for a test,
`--codex-home DIR`) and merges four guard handlers into `$CODEX_HOME/hooks.json` (previous file kept as
`hooks.json.bak`, other hooks kept). It never edits `config.toml`: if your hooks live inline there as `[hooks]`
tables, it prints the TOML to add instead. Nothing is written into the repository: it holds the Claude Code
`SKILL.md`, and a second one would leak into Claude Code or OpenCode. `node codex/build.mjs [--out DIR]` builds the
same package into a temporary directory to look at; it refuses an `--out` inside the repository.

Then:

1. Restart Codex.
2. Trust the hooks once: run `codex`, type `/hooks`, trust the security-audit entries. Codex skips untrusted or
   changed hooks **silently**, so until you do this the guard is off. A guarded session shows the line
   "security-audit guard active for this session" in its context. `codex exec` can pass
   `--dangerously-bypass-hook-trust` for one run instead. Reinstalling changes the hook hash: trust again.
3. Optional, by hand in `config.toml`:
   - `[agents]` `max_concurrent_threads_per_session = 6`: Codex runs 4 agents at once including the coordinator,
     so the default runs three auditors at a time.
   - `[sandbox_workspace_write]` `network_access = true`: see Network.

`--auditor-model` takes a plain slug (`[\w.-]+`, e.g. from `codex debug models`). The verifier shards and COMBINE
always run on the session model: start the session with the strongest model you have. A model counts as supported
only after it scores on the Ledgerly benchmark like the Claude variant. If your Codex build does not expose a
`model` parameter on `spawn_agent`, every agent inherits the session model regardless.

Uninstall: `node codex/install.mjs --uninstall` removes the skill directory (only if it carries the port's
`.codex-port` marker), exactly the guard's entries in `hooks.json` (backup in `hooks.json.bak`) and the session
marks in `$CODEX_HOME/security-audit/`.

## Use

In a project, inside the workspace-write sandbox:

```
codex --sandbox workspace-write
$security-audit                      # whole project
$security-audit --scope top20        # the 20 riskiest places, a cheap first run
$security-audit --since last         # re-audit only what changed since the last audit
$security-audit --verify-fixes       # recompute what is fixed, change nothing
```

Headless: `codex exec --sandbox workspace-write -c approval_policy='"never"' '$security-audit --scope top20'` (add `--json` for the
event stream, `-o FILE` for the last message). The default `codex exec` sandbox is read-only, which cannot write
`.security-audit/`. The report is `.security-audit/report.html`.

**Start with `$security-audit`.** Only a prompt that contains `$security-audit` marks the session as an audit
session and turns the guard on. Codex may also pick the skill by itself for "audit this project" (implicit
invocation stays enabled); such a run follows the same prompts but is **not guarded**.

## What is enforced

Two layers. The sandbox (workspace-write): writes only in the project, `/tmp` and `$TMPDIR`; `.git/` read-only;
no network; sub-agents inherit it. Reads are not restricted by the sandbox.

The guard hook (`hooks/guard.mjs`, PreToolUse on `Bash` and `apply_patch`), in a marked session only:

- the OpenCode guard's shell rules, imported unchanged (`opencode/plugin.js`, copied at build time as
  `hooks/shell-check.mjs`): redirection and `git --output` only into `.security-audit/`; no `cd`/`pushd` out of the
  project; no shell argument that reads outside the project or the skill directory (resolved as bash and the
  kernel would, through symlinks; variables, `$(..)`, `~`, braces and escaping globs refused); no report while
  `audit-state.mjs --final` fails;
- on top, because Codex has no deny-by-default shell: no word naming a `.env` file (`.env.example` allowed);
  `grep -r` and `rg --hidden/-u/--no-ignore` only with `.env*` excluded; git only read-only subcommands; no
  `curl`, `wget`, `ssh`, `docker` and other network tools, no package installs; `rm`, `mv`, `cp`, `tee`, `touch`,
  `mkdir`, `sed -i` and similar only into `.security-audit/`; `find -delete` and `find -exec <writer>` refused;
  `bash -c '…'` is checked inside;
- `apply_patch` may add, update, delete or move only files under `.security-audit/` and the project's
  `.gitignore`; a patch without a readable file header is refused;
- a shell `workdir` outside the project is refused.

The limits: the hook sees the command line, not what it starts. Test code run by the project's runner, and the
scanners started by `prepass.mjs`, can read anything the sandbox can read. A hostile model can get around word-level
checks (`python3 -c …`). The guard stops accidents, not adversaries. `workspace-check.mjs` lists any file changed
outside `.security-audit/` at the end of the run.

## Network

Network is off in workspace-write, so `osv-scanner` (advisory database), semgrep and trivy rule downloads and
docker image pulls fail: the pre-pass reports them as NOT RUN and `not-assessed.md` lists them. `gitleaks` runs
offline. This is the default on purpose. To let them run, set by hand in `config.toml`:

```toml
[sandbox_workspace_write]
network_access = true
```

That opens the network to everything the audit runs, test code included. The installer never sets it.

## Differences from the Claude Code variant

- No Phase 6 (fixing): the guard refuses source edits. Fix in a normal session, then `$security-audit --verify-fixes`.
- No `--mutation`: it needs a copy of the repository outside the project.
- No audit-live panel.
- Fewer scanners without network (above).

## Verified and assumed (codex-cli 0.155.1)

Verified on this version:

- the installed skill is discovered from `$CODEX_HOME/skills` and listed with the canonical description
  (`codex debug prompt-input` with a temporary `HOME` and `CODEX_HOME`); `$security-audit --scope top20` reaches
  the model as literal text;
- the hook input fields (`session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`, `prompt`) and the
  output shape for `additionalContext`, from the JSON schemas embedded in the binary;
- `hooks` and `multi_agent` are stable features, enabled by default (`codex features list`);
- 4 concurrency slots including the root agent, model overrides only with `fork_turns` `"none"`, and Codex spawns
  sub-agents only when a skill asks for them explicitly (the multi-agent instructions in `prompt-input`).

From the official hooks documentation, not run here: shell commands match as `Bash` and `apply_patch` as
`apply_patch`; both put their text in `tool_input.command`; exit 2 with the reason on stderr denies the call;
hooks of sub-agents report the parent session id (so the session mark covers them); `SessionEnd` does not run for
sub-agents and also fires after 30 idle minutes.

Assumed, to check in the first real run:

- PreToolUse fires for tool calls made by sub-agents (the docs do not say). If not, only the coordinator is
  guarded: run Parallel Mode sequentially when you need enforcement.
- The `apply_patch` text uses the `*** Add File:` / `*** Update File:` / `*** Delete File:` / `*** Move to:`
  headers. The parser also accepts `cmd`, `patch` or `input` fields and an array command (`["bash", "-lc", …]`);
  a patch it cannot read is refused, not let through.
- Whether the shell tool's input carries a `workdir`; if it does, the guard checks it.
- The handler command `"<node>" "<guard>"` is run through a shell. The installer writes the absolute path of the
  node binary that ran it; after a Node upgrade (nvm) run the installer again.
- Whether the docker socket is reachable from inside the sandbox (a container would bypass it). The guard refuses
  `docker` typed by the model; it cannot see the docker calls `prepass.mjs` makes.

## Smoke run (costs plan quota or API credit)

```bash
node benchmark/setup.mjs --app py-clinic --dest "$HOME/runs/codex-pyc"
cd "$HOME/runs/codex-pyc/app"
codex exec --sandbox workspace-write -c approval_policy='"never"' --dangerously-bypass-hook-trust \
  --json -o ../last-message.md '$security-audit' > ../events.jsonl
cd - && node benchmark/score.mjs "$HOME/runs/codex-pyc" --label "codex 0.155 py-clinic smoke" \
  --results "$HOME/runs/codex-results.jsonl"
```

Check in `events.jsonl`: the skill's `SKILL.md` was read, the scripts ran without escalation requests, the
osv/semgrep rows say NOT RUN, any guard refusals, and `workspace-check.mjs` found nothing outside
`.security-audit/`. Then trust the hooks in the TUI and repeat without `--dangerously-bypass-hook-trust`.
