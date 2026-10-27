---
description: Security audit, Phase 4. Assesses whether the project's tests catch the verified findings and writes .security-audit/test-quality.md. Dispatched by sa-coordinator.
mode: subagent
hidden: true
permission:
  {{base}}
  edit:
    "*": deny
    ".security-audit/**": allow
  bash:
    {{shell}}
    {{tests}}
  task: deny
---
