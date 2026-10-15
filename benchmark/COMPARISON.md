# security-audit vs the Claude Security plugin on Ledgerly

> These numbers are from before R08 (2026-10-06) and count 16 seeded bugs and 8 decoys. R08 added four seeded
> bugs (B17 CSRF, B18 CI workflow, B19 Dockerfile, B20 install script) and three decoys (D09 to D11), so recall
> on that key is out of 20 and runs from before R08 are not comparable without re-running. R21 added three more
> (B21 LLM output to HTML, B22 unscoped agent tool, B23 LLM cost) and two decoys (D12, D13): out of 23. R23 added B24 (anonymous paid SMS) and D14: out of 24 now.

One run each, 2026-10-03, Claude Code, Opus 5.5 at effort xhigh, auto mode, a fresh `setup.mjs` copy without
`node_modules` (the app's lockfile integrity hashes do not match the registry, so install fails for both).
Scored with `benchmark/score.mjs`, usage counted with `benchmark/usage.mjs` at the same prices for both.

| | security-audit 1.1.0 (default full audit) | Claude Security plugin 0.12.0 (`medium`, its default) |
|---|---|---|
| Seeded bugs found | 16 of 16 | 15 of 16 by hand (scorer: 14; see notes) |
| Missed | none | B14: vulnerable `next` version reachable through image config |
| Decoys reported as bugs | 0 of 8 | 0 of 8 by hand (scorer: 1; see notes) |
| Real issues outside the key | open redirect after login; removed members keep org access | the same two |
| Wall clock | 32 min (interactive session, built a test harness) | 12.7 min (headless) |
| Tokens / API-price cost | 23.81M (96% cache reads) / 11.71 USD | 10.97M (85% cache reads) / 12.72 USD |
| Proof for serious findings | 16 regression tests that fail today | code and git-history reading only, confidence per finding |
| Also produced | verified-safe list (23, each with the control's file:line), not-assessed list (7), test-quality review, dependency advisories, secret scan, HTML report | Markdown, JSONL, SARIF with CWE, revision stamp, coverage statement |

Session ids: skill `0fbf7b3a-d4b3-424b-9bb1-de69e3af47ee` (counted until 10:43Z), plugin
`f4fb079f-7df4-4b00-ba1b-c60f8efffb0c`. Plugin output: `~/ledgerly-cs/app/CLAUDE-SECURITY-20261003-195902/`.

## Notes on the hand scoring

- **B15, secret in git history.** The plugin found it (F5, F19, F20, confirmed 3 of 3 by its panel), but its
  report renderer refused them because `.env` no longer exists in the tree, so they are missing from the
  JSONL and SARIF and appear only in the Markdown report. The scorer reads the JSONL, hence 14.
- **D07, download route.** The plugin's F4 says the download route presigns any `s3Key` the uploader chose.
  The route itself is correctly org-scoped (the decoy), but the key comes from seeded bug B11, so F4 is a
  real consequence of B11, not a false positive.
- **B14** needs a dependency advisory scan. The plugin's documentation says it does not replace dependency
  scanners; the skill runs osv-scanner in the pre-pass.

## What this does and does not show

- One run per tool. The benchmark README asks for two before trusting a difference of one or two bugs.
- The skill was developed with Ledgerly as its test set; the plugin never saw it. On detection alone the
  free plugin is level with the skill here, and it is faster.
- The skill's remaining edge on this app: dependency advisories, regression tests as proof, the
  verified-safe and not-assessed lists, and the test-quality review.
