# Real-advisory benchmarks (R30, R31)

The other benchmark apps are written for this skill, with planted bugs. These are public open-source
modules pinned to a release from before a published security fix, scored on whether the skill finds what
the advisory describes. The code is never copied into this repo: `fetch.mjs` downloads the release, checks
the sha256 pinned in the module's `manifest.json` and prepares a run directory outside the repo. Only the
manifest and the answer keys live here.

## Layout

One directory per module, holding `manifest.json` and one `answer-key-<version>.json` per pinned release:

    benchmark/real/
      fetch.mjs
      miniorange_saml/                    R30, module id `miniorange_saml` (kept at its original path)
      drupal/rest_api_authentication/     R31 week 1, id `drupal/rest_api_authentication`
      wordpress/flamingo/                 id `wordpress/flamingo`
      npm/fast-jwt/                       id `npm/fast-jwt`
      go/goshs/                           id `go/goshs`

New modules go under `<ecosystem>/<package>/` with `ecosystem` one of `drupal`, `wordpress`, `npm`, `pypi`,
`rubygems`, `go`; the package directory is lower case, without `@` or `/` (`npm/fastify-static` for
`@fastify/static`). Each version entry in the manifest has `url` (a registry URL that is byte-stable: drupal.org
tarballs, WordPress plugin zips, npm tarballs, PyPI sdists, `.gem` files, Go proxy zips; never GitHub
`archive/refs/tags` tarballs), `sha256` (measured, full), `released`, `key`, and when needed `archive`
(`tar.gz` by default, `zip`, `gem`) and `root` (the module root inside the archive, e.g.
`goshs.de/goshs/v2@v2.1.4` for a Go proxy zip; otherwise the single top directory is used, and for a gem
the archive root). `secret_constants` lists PHP constants whose value must never land in this directory.

`fetch.mjs` refuses an archive with an absolute entry, a `..` segment, a symlink, a hard link or a special
file (tar.gz, zip and the gem's inner `data.tar.gz` alike, checked before extraction and again on the
extracted tree). It removes agent instruction files the release ships (`.claude/`, `CLAUDE.md`,
`CLAUDE.local.md`, `.mcp.json`) from `app/` and lists them in `meta.json`: they would steer the audit, and
project settings can run hooks on the operator's machine.

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

## Week 1 of R31 (2026-10-20)

Four modules from four ecosystems, all with advisories published after June 2026. Each target has its
fixed release as the control (no seeded entries, the fixed code as decoys). Line ranges come from the fix
commits or a diff of the two releases and were checked with `fetch.mjs --check` against both extracted trees.

| Module id | Target / control | Size | Scored on the target |
|---|---|---|---|
| `drupal/rest_api_authentication` | 3.1.0 / 3.2.0 | PHP 5.1k lines | [SA-CONTRIB-2026-182](https://www.drupal.org/sa-contrib-2026-182) (CVE-2026-96385, Mod. critical 13/25): the authentication provider recognises API requests by substrings of the raw URI, so some REST requests skip the configured API authentication |
| `wordpress/flamingo` | 2.6.2 / 2.6.3 | PHP 3.6k lines | [CVE-2026-12853](https://www.cve.org/CVERecord?id=CVE-2026-12853) (CVSS 5.4): post types and taxonomies registered without capabilities, so contributors read contact tags and channel data through core APIs |
| `npm/fast-jwt` | 6.2.4 / 6.3.1 | JS 1.5k lines | [GHSA-5hjw-83fp-phq9](https://github.com/advisories/GHSA-5hjw-83fp-phq9) (array payload skips claim validators), [GHSA-g3jj-5cmm-3hxx](https://github.com/advisories/GHSA-g3jj-5cmm-3hxx) (public JWK text accepted as an HMAC secret), [GHSA-8wpc-h4q6-8fxv](https://github.com/advisories/GHSA-8wpc-h4q6-8fxv) (empty key with an algorithm list accepts unsigned tokens); all High |
| `go/goshs` | v2.1.4 / v2.1.5 | Go 18.2k lines | eight repository advisories fixed in v2.1.5: [GHSA-6m5c-fv2q-jrj2](https://github.com/goshs-labs/goshs/security/advisories/GHSA-6m5c-fv2q-jrj2) (auth exemption too wide, Critical), [GHSA-966r-mw4j-rv64](https://github.com/goshs-labs/goshs/security/advisories/GHSA-966r-mw4j-rv64) (overwrites under no-delete, Critical), [GHSA-6wwv-mx7w-35jx](https://github.com/goshs-labs/goshs/security/advisories/GHSA-6wwv-mx7w-35jx) (FTP mode flags), [GHSA-rc9g-fmpg-c6pp](https://github.com/goshs-labs/goshs/security/advisories/GHSA-rc9g-fmpg-c6pp) (WebDAV POST read), [GHSA-wg2q-39h6-66x9](https://github.com/advisories/GHSA-wg2q-39h6-66x9) (CVE-2026-66063, upload name traversal), [GHSA-964w-f6gj-5236](https://github.com/advisories/GHSA-964w-f6gj-5236) (CVE-2026-66064, block-list bypass), [GHSA-4wh5-87mw-whxf](https://github.com/goshs-labs/goshs/security/advisories/GHSA-4wh5-87mw-whxf) (SFTP no-delete), [GHSA-mqvv-v9g7-4h3j](https://github.com/goshs-labs/goshs/security/advisories/GHSA-mqvv-v9g7-4h3j) (share links skip the ACL) |

Notes per module:
- `rest_api_authentication` ships a fallback vendor API key as a PHP constant (no advisory). It is a known
  extra in both keys and a `secret_constants` entry, so `--check` fails if its value ever appears here.
- `flamingo` zips are built by WordPress.org from the SVN tag and can change if the tag is re-committed:
  a sha256 mismatch means diff and re-pin, never skip the check.
- `goshs` is fetched under its canonical module path `goshs.de/goshs/v2` (the zips' go.sum hashes match
  sum.golang.org). The release ships `.claude/rules/*.md`, which `fetch.mjs` removes. Many advisories
  published after v2.1.5 (August to October 2026) still affect both releases and are not keyed yet, so
  unmatched findings on either are expected and some are real.

## Run

    node benchmark/real/fetch.mjs miniorange_saml 3.1.3            # prints the run directory
    cd <run>/app && CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "/security-audit" \
      --permission-mode auto --output-format json
    node benchmark/score.mjs <run> --label "R30 miniorange_saml 3.1.3"   # key from meta.json
    node benchmark/usage.mjs <session id>

The other modules take their id: `node benchmark/real/fetch.mjs drupal/rest_api_authentication 3.1.0`,
`wordpress/flamingo 2.6.2`, `npm/fast-jwt 6.2.4`, `go/goshs v2.1.4` (Go versions keep the `v`), and the
control releases `3.2.0`, `2.6.3`, `6.3.1`, `v2.1.5`. Label score runs `R31 <id> <version> <run>`.

The control release gives a recall of `0/0`, and `decoy false positives` counts verified findings that
still report a fixed advisory. Options: `--dest DIR` for the run directory, `--tarball FILE`
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
- Coverage. miniorange_saml is one advisory family, mostly SAML response handling; the R31 batches add
  other stacks a few modules at a time. A handful of modules per ecosystem says little about that ecosystem.
- The prompt is `/security-audit` and nothing else: the skill is not told about the advisories.
- Hygiene: the fetched modules can contain embedded vendor keys (miniorange_saml SA-CONTRIB-2026-148,
  rest_api_authentication's fallback key). Findings may quote them, so publish only the scorer output and
  `usage.mjs` numbers, never finding bodies, and keep `.security-audit/` local.

## Findings outside the key

Every verified finding that matches no key entry on a vulnerable release, and every verified finding on a
control release, is unmatched, not "new":

- It is never published: no README text, no issue, no PR, no blog post, no chat message outside the owner's
  private channel. The results table shows only the count ("Unmatched: N, under review").
- `.security-audit/` and the run directories stay local and out of git; finding bodies may hold secrets or
  working requests.
- The owner verifies it locally, by hand, against the fix diff and the latest release. A key mistake is fixed
  in the key. Anything still present in the latest release is reported privately, by the owner only (never by
  an agent, never by mail automation), through the project's own channel: the drupal.org security team for
  Drupal, the plugin's security contact or the Wordfence or Patchstack intake for WordPress, GitHub private
  vulnerability reporting or the project's `SECURITY.md` for npm, PyPI, RubyGems and Go. Coordinated
  disclosure, 90 days by default.
- A key gets a new seeded entry for it only after the maintainer publishes an advisory, and the README then
  cites that advisory id and nothing more.
- Runs read extracted source only, offline: no requests to the maintainers' infrastructure. The prompt stays
  `/security-audit` with no advisory hints.

## Results

| Date | Release | Run | Skill sha | Model | Recall | Decoy FP | Unmatched | Tokens / cost / time |
|---|---|---|---|---|---|---|---|---|
| 2026-10-19 | 3.1.3 | A | 7f956ef | Opus 5.5 | 4/11 (SA-2026-031 CRITICAL found as the top finding; 143, 142; 147 as a secondary location of a found XSS); 141 and 148 found and dropped by the verifier | 0 | 1 | 3.25M / 2.37 USD / 6 min |
| 2026-10-19 | 3.2.0 | control | 7f956ef | Opus 5.5 | 0/0 (control) | 1 (the SA-151 fix flagged for a redirect / DNS-rebinding bypass, admin-only; read as a residual issue rather than a false positive) | 7, under review | 4.28M / 3.15 USD / 8 min |
| | 3.1.3 | B (repeat) | | | not run yet | | | |
| | `drupal/rest_api_authentication` 3.1.0 (and 3.2.0 control) | A, B | | | not run yet | | | |
| | `wordpress/flamingo` 2.6.2 (and 2.6.3 control) | A, B | | | not run yet | | | |
| | `npm/fast-jwt` 6.2.4 (and 6.3.1 control) | A, B | | | not run yet | | | |
| | `go/goshs` v2.1.4 (and v2.1.5 control) | A, B | | | not run yet | | | |

Notes:
- The prompt was `/security-audit` and nothing else; the skill was not told about the advisories.
- Run A: no CRITICAL or HIGH false positive. First scored 3/11 with 2 unmatched, when the scorer matched only the
  primary location of a finding: the systematic XSS finding lists SA-2026-147's lines as a secondary location.
  Re-scored 2026-10-20 with secondary-location matching (`benchmark/README.md`, Rules): 4/11, as counted by hand.
- Run A missed SA-2026-145 (signature algorithm taken from the response), 150 (replay), 151 (SSRF), 144
  (non-constant-time compare, predictable IDs) and 149 (password in configuration).
- Run B: the fixed signature, redirect, access, TLS and replay code was assessed as fixed. Its unmatched
  findings are being reviewed by hand and are not described here until that review, and any report it leads to,
  is done.
