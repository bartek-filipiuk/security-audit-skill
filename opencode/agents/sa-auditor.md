---
description: Security audit, Phase 2. Audits one category group and writes raw findings and non-issues into .security-audit/. Dispatched by sa-coordinator.
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
