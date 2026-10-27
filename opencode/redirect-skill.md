---
name: security-audit-opencode
description: Use when asked to audit or review the security of a codebase, find vulnerabilities, or check auth, payments or webhooks for security issues.
---
Do not run a security audit yourself. The audit runs in its own agent with enforced permissions. Tell the user
to type `/security-audit` (whole project), `/security-audit --scope top20` (the riskiest places) or
`/security-audit --info` (what it covers), and stop.
