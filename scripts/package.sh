#!/bin/bash
# Builds the buyer ZIP: <out>/security-audit-<version>.zip with security-audit/ and devince-install.json at the root.
#   scripts/package.sh <out-dir>
set -e
R=$(cd "$(dirname "$0")/.." && pwd); OUT=$(cd "${1:-.}" && pwd)
V=$(python3 -c "import json;print(json.load(open('$R/devince-install.json'))['version'])")
grep -q "Wersja $V" "$R/INSTALACJA.md" || { echo "INSTALACJA.md does not say Wersja $V"; exit 1; }
W=$(mktemp -d); mkdir -p "$W/security-audit"
cd "$R" && git ls-files | grep -vE "(^|/)CLAUDE\.md$|^\.gitignore$|^benchmark/results\.jsonl$|^ROADMAP\.md$|^AGENTS\.md$|^HANDOFF\.md$|^marketing/|^scripts/package\.sh$|^devince-install\.json$|^audit-live/\.gitignore$" \
  | while read f; do mkdir -p "$W/security-audit/$(dirname "$f")"; cp "$f" "$W/security-audit/$f"; done
cp "$R/devince-install.json" "$W/"
cd "$W" && rm -f "$OUT/security-audit-$V.zip" && zip -qr "$OUT/security-audit-$V.zip" devince-install.json security-audit && rm -rf "$W"
unzip -p "$OUT/security-audit-$V.zip" | grep -qiE "intent-hub|/home/bartek|scratchpad" && { echo "private strings in the package"; exit 1; }
echo "$OUT/security-audit-$V.zip ($(unzip -l "$OUT/security-audit-$V.zip" | tail -1 | awk '{print $2}') files)"
