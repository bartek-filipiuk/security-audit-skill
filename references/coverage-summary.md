```
Security Audit Skill — Coverage Summary

12 security categories, 124 checklist items, 31 pattern sections
OWASP Top 10 2021: 10/10 | OWASP API Security Top 10 2023: 10/10
Stack patterns: JS/TS (Next.js App Router, tRPC, Hono, Drizzle, Better-Auth, AI SDK tools), Python, PHP, Go, Ruby, Java;
  GitHub Actions, Dockerfile and compose, Terraform/Kubernetes/CloudFormation, package manifests and lockfiles;
  LLM and agent features (AI SDK, openai, @anthropic-ai/sdk, LangChain/LangGraph, MCP)
Pre-pass (deterministic, seconds): hotspot ranking, entry points by framework convention, Drizzle tenant-scope scan,
  dependency advisories (osv-scanner), secrets across git history (gitleaks, redacted)

Categories:
 1. Authentication & Authorization — session IDs, JWT, BOLA, BFLA, account lockout, CSRF (origin checks, SameSite, OAuth state),
    LLM tool and agent authorization (tenant scope inside tools, approval for destructive tools)
 2. Input Validation & Injection — SQLi, XSS, SSTI, NoSQL, LDAP, prototype pollution, open redirect, host header, second-order, GraphQL,
    LLM output to HTML/SQL/shell/URL sinks, secrets in model context
 3. Rate Limiting & Abuse Prevention — including LLM cost and token limits
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
Report: report.md + report.html (to fix / verified safe / not assessed)
Private benchmark: benchmark/ (Ledgerly, own stack, 23 seeded bugs + 13 decoys), see benchmark/README.md
Models: sonnet for the mechanical phases (1, 2, 4); Phase 3 verifier inherits the session model
Proof labels: HIGH/CRITICAL are marked test (a regression test fails today) or static (code reading)
```
