# Real-advisory benchmarks (R30)

The other benchmark apps are written for this skill, with planted bugs. These are public open-source
modules pinned to a release from before a published security fix, scored on whether the skill finds what
the advisory describes. The code is never copied into this repo: `fetch.mjs` downloads the release, checks
the sha256 pinned in the module's `manifest.json` and prepares a run directory outside the repo. Only the
manifest and the answer keys live here.

## miniorange_saml (Drupal: SAML SSO - Service Provider)

| Release | Role | Key |
|---|---|---|
| 3.1.3 (2026-02-25) | target: vulnerable to every advisory below | `answer-key-3.1.3.json`, 11 scored advisories, 3 known extras |
| 3.2.0 (2026-09-09) | control: the release that fixes all of them | `answer-key-3.2.0.json`, no seeded bugs, 10 decoys on the fixed code |

Scored on 3.1.3, one key entry per drupal.org advisory (ids `SA-2026-NNN`):

| Advisory | CVE | drupal.org risk | Class |
|---|---|---|---|
| [SA-CONTRIB-2026-031](https://www.drupal.org/sa-contrib-2026-031) | CVE-2026-5343 | Critical 19/25 | SAML signature checks report a failure but do not stop the login (authentication bypass); fixed in 3.1.4 |
| [SA-CONTRIB-2026-141](https://www.drupal.org/sa-contrib-2026-141) | CVE-2026-87943 | Critical 18/25 | routes with `_access: 'TRUE'` reach admin functionality and write configuration |
| [SA-CONTRIB-2026-143](https://www.drupal.org/sa-contrib-2026-143) | CVE-2026-87945 | Critical 16/25 | RelayState used as the post-login redirect (open redirect) |
| [SA-CONTRIB-2026-142](https://www.drupal.org/sa-contrib-2026-142) | CVE-2026-87944 | Critical 15/25 | TLS certificate verification disabled on outbound HTTPS |
| [SA-CONTRIB-2026-144](https://www.drupal.org/sa-contrib-2026-144) | CVE-2026-87946 | Critical 15/25 | non-constant-time HMAC comparison, predictable request IDs |
| [SA-CONTRIB-2026-145](https://www.drupal.org/sa-contrib-2026-145) | CVE-2026-87947 | Mod. critical 14/25 | signature algorithm chosen by the SAML response |
| [SA-CONTRIB-2026-148](https://www.drupal.org/sa-contrib-2026-148) | CVE-2026-87950 | Mod. critical 13/25 | vendor API credentials embedded in the source |
| [SA-CONTRIB-2026-147](https://www.drupal.org/sa-contrib-2026-147) | CVE-2026-87949 | Mod. critical 12/25 | SAML attributes echoed into HTML (XSS) |
| [SA-CONTRIB-2026-149](https://www.drupal.org/sa-contrib-2026-149) | CVE-2026-87951 | Mod. critical 12/25 | vendor account password stored in configuration |
| [SA-CONTRIB-2026-151](https://www.drupal.org/sa-contrib-2026-151) | CVE-2026-87953 | Mod. critical 11/25 | IdP metadata URL fetched without checks (SSRF, admin only) |
| [SA-CONTRIB-2026-150](https://www.drupal.org/sa-contrib-2026-150) | CVE-2026-87952 | Mod. critical 10/25 | no replay protection for SAML responses |

Not scored: [SA-CONTRIB-2026-146](https://www.drupal.org/sa-contrib-2026-146) (XSS in generated HTML) has
no single fixed location (the fix swaps `Xss::filter` for `Html::escape` across files), so its main spots are
a known extra, together with XML parser hardening and a fail-open timestamp check that came with the fixes
without an advisory of their own. Line ranges come from the fix diffs (git.drupalcode.org compare API,
3.1.3→3.1.4 and 3.1.4→3.2.0) and were checked against the extracted trees.

## Run

    node benchmark/real/fetch.mjs miniorange_saml 3.1.3            # prints the run directory
    cd <run>/app && CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "/security-audit" \
      --permission-mode auto --output-format json
    node benchmark/score.mjs <run> --label "R30 miniorange_saml 3.1.3"   # key from meta.json
    node benchmark/usage.mjs <session id>

The same for `3.2.0` gives the control: recall is `0/0`, and `decoy false positives` counts verified
findings that still report a fixed advisory. Options: `--dest DIR` for the run directory, `--tarball FILE`
(or `REAL_TARBALL=FILE`) to use a local copy of the release instead of downloading it (the sha256 is still
checked), and `--check` to validate the key against the fetched tree (real files, ranges inside them and not
blank, no overlaps, and the vendor key's value nowhere in `benchmark/real/`). `score.mjs --key <path>` scores
any run against a key file directly.

The run directory holds `meta.json` (with the key's path) and the downloaded tarball; the audit sees only
`<run>/app`, a single git commit of the release. Never copy a key into `app/`.

## Caveats

- Training data. These advisories, the fix commits and the releases are public. SA-CONTRIB-2026-031 (April
  2026) may well be in a model's training data; the 3.2.0 batch was published on 2026-09-09. Check the
  cutoff of the model you run before reading anything into a hit. Finding an already-published bug is a
  floor for what the skill does on unknown code, not a ceiling, and not proof it would have found it first.
- Nondeterminism. LLM runs vary. Run the target at least twice and report each run and the union; do not
  trust a change of one or two advisories from a single run.
- One module, one advisory family, mostly SAML response handling. It says nothing about other stacks.
- The prompt is `/security-audit` and nothing else: the skill is not told about the advisories.
- Hygiene: the fetched module contains the vendor's embedded key (SA-CONTRIB-2026-148). Findings may
  quote it, so publish only the scorer output and `usage.mjs` numbers, never finding bodies, and keep
  `.security-audit/` local.

## Results

| Date | Release | Run | Skill sha | Model | Recall | Decoy FP | Unmatched | Tokens / cost / time |
|---|---|---|---|---|---|---|---|---|
| | 3.1.3 | A | | | not run yet | | | |
| | 3.2.0 | control | | | not run yet | | | |
| | 3.1.3 | B (repeat) | | | not run yet | | | |
