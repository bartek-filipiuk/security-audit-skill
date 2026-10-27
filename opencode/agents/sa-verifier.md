---
description: Security audit, Phase 3. Verifies raw findings (single, shard or COMBINE mode), writes regression tests under .security-audit/tests/ and rejects false positives. Dispatched by sa-coordinator.
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
