```
Security Audit Skill — Coverage Summary

12 security categories + 8 stack profiles, 203 checklist items, 40 pattern sections
OWASP Top 10 2021: 10/10 | OWASP API Security Top 10 2023: 10/10
Stack patterns: JS/TS (Next.js App Router, tRPC, Hono, Drizzle, Better-Auth, AI SDK tools), Python, PHP, Go, Ruby, Java;
  GitHub Actions, Dockerfile and compose, Terraform/Kubernetes/CloudFormation, package manifests and lockfiles;
  LLM and agent features (AI SDK, openai, @anthropic-ai/sdk, LangChain/LangGraph, MCP);
  resource exhaustion and spend (SMS, e-mail and AI providers, limiters, pagination, upload limits, queues, regex);
  Supabase (RLS, storage, SECURITY DEFINER, Edge Functions, service-role keys), Firebase (rules, Cloud Functions, Admin SDK),
  Laravel (routes and middleware, Eloquent scope, mass assignment, *Raw SQL, Blade, CSRF exceptions, uploads),
  Symfony (#[Route], IsGranted/access_control, voters, Doctrine DQL, Twig |raw), Drupal (routing.yml access, database API, Markup, CSRF tokens),
  Django (urls.py/DRF routes and permissions, user-owned querysets, raw SQL, |safe, csrf_exempt, settings), FastAPI (Depends auth, response_model,
  text() SQL, BackgroundTasks SSRF, CORS), Flask (login_required/before_request, render_template_string, send_file, secret_key, debug)
Pre-pass (deterministic, seconds): hotspot ranking, entry points by framework convention, Drizzle tenant-scope scan,
  Supabase/Firebase policy scan, PHP routes (Laravel, Symfony, Drupal) ranked by their controller method,
  Python routes (Django, FastAPI, Flask) ranked by their view, with a user-owned model scan,
  dependency advisories (osv-scanner, composer audit and pip-audit fallbacks), secrets across git history (gitleaks, redacted);
  rule scanners semgrep, zizmor, hadolint, trivy (native or pinned docker image) and bandit (native) as candidates;
  Psalm taint analysis reported NOT RUN (it would execute the project's autoloader)

Categories:
 1. Authentication & Authorization — session IDs, JWT, BOLA, BFLA, account lockout, CSRF (origin checks, SameSite, OAuth state),
    LLM tool and agent authorization (tenant scope inside tools, approval for destructive tools)
 2. Input Validation & Injection — SQLi, XSS, SSTI, NoSQL, LDAP, prototype pollution, open redirect, host header, second-order, GraphQL,
    LLM output to HTML/SQL/shell/URL sinks, secrets in model context
 3. Rate Limiting & Abuse Prevention — including LLM cost and token limits, resource exhaustion and spend
    (paid SMS/e-mail/AI calls anonymous callers can drive, unbounded queries, uploads, queues, expensive work, regex)
 4. Data Exposure — stack traces, over-exposed API fields, secrets in logs
 5. Security Headers & Transport — CORS, CSP (trusted domain abuse), HSTS
 6. File Upload — MIME, null byte, magic bytes, size config
 7. Dependency, Supply Chain & Build Pipeline — CVEs, install scripts, lockfile integrity, CI/CD workflows
    (pull_request_target, expression injection, unpinned actions, secrets in logs), containers and IaC
 8. Cryptography — broken algorithms, JWT alg:none/confusion, insecure RNG, TOTP plaintext
 9. Concurrency & Race Conditions — TOCTOU, double-submit, WebSocket
10. Documentation vs Reality
11. Business Logic — mass assignment, negative values, payment bypass, soft-delete, IDOR
12. Logging & Monitoring

Benchmark (OWASP Juice Shop v19.2.1, public, likely in model training data):
  68 verified findings (12C / 29H / 25M / 2L)
  61/66 code-level challenges = 92.4% coverage
  45 non-issues documented | FN rate: 7.6%

Modes: Standard (<20 endpoints) | Triage (20-50) | Parallel (>50) | partial: --scope auth|payments|...|<path>|topN
Stack: detected from manifests and framework files; dedicated profile for JS/TS (Node), PHP (Laravel, Symfony, Drupal)
  and Python (Django, FastAPI, Flask), general checklist for Go, Rust, Ruby, JVM, .NET (the report says which);
  --stack <name> forces a profile
Report: report.md + report.html (to fix / verified safe / not assessed)
Private benchmark: benchmark/ (Ledgerly, own stack, 24 seeded bugs + 14 decoys; supabase-notes, 10 + 12; php-tickets, 13 + 14; py-clinic, 18 + 18), see benchmark/README.md
Models: sonnet for the mechanical phases (1, 2, 4); Phase 3 verifier inherits the session model
Proof labels: HIGH/CRITICAL are marked test (a regression test fails today) or static (code reading)
Coverage ledger: every auditor records per entry point and class checked / not applicable / not assessed
  (schema-validated); the report's Coverage and Not Assessed sections come from it, so "not found" ≠ "not looked at"
```
