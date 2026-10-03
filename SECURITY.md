# Security policy

This repository is a Claude Code skill: instructions, prompts and Node scripts that run on your machine
while you audit your own code. A weakness in it could, for example, make the audit write outside
`.security-audit/`, run something you did not expect, or leak a secret into a report.

Report such a problem privately to **bartek@devince.dev** with the steps to reproduce it. Please do not open
a public issue for it. You will get an answer within a few days, and the fix will credit you unless you
prefer otherwise.

Findings the skill reports about *your* code are not vulnerabilities in this project; open a normal issue if
you think the skill got one wrong.
