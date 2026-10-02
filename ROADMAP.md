# Roadmap

No dates. Order follows what buyers ask for.

## Today

The skill is most precise on Next.js App Router, tRPC, Hono, Drizzle, Better-Auth, AI SDK and plain
Node. On that stack the pre-pass finds entry points by framework convention and ranks hotspots.
Python, PHP, Go, Ruby and Java are audited with general rules: the audit works, with fewer
stack-specific checks and a weaker hotspot ranking.

## Next: stack profiles

- **Stack detection in the pre-pass.** The report states which profile was applied and what the
  profile does not cover, instead of leaving that implicit.
- **`--stack <name>`** to force a profile when detection is wrong or the repository mixes stacks.
- **Profiles**, each with entry-point detection, hotspot signals and checklist patterns:
  - PHP: Laravel, Symfony, Drupal
  - Python: Django, FastAPI, Flask
  - Go
  - Rust

A profile ships when it has a benchmark of its own: seeded bugs and decoys in that stack, scored the
same way as Ledgerly.

## Also planned

- More checks where the skill is thin today: CSRF, CI/CD pipelines, Docker.
- A second benchmark app that stays unpublished, for measuring changes to the skill.
- `audit-live`: phase timing and a per-auditor view.
