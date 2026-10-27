---
description: Security audit, Phase 1. Maps the exposed surface, the authorization map, dependencies, tests and security claims into .security-audit/recon.md. Dispatched by sa-coordinator.
mode: subagent
hidden: true
permission:
  {{base}}
  edit:
    "*": deny
    ".security-audit/**": allow
  bash:
    {{shell}}
  task: deny
---
