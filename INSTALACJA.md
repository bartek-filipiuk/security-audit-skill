# Security Audit — instalacja

Wersja 1.0.0

## Wymagania

- Claude Code (płatny plan albo klucz API)
- Node.js 20 lub nowszy
- Docker do skanu zależności i sekretów. Zamiast dockera możesz zainstalować `osv-scanner` i `gitleaks`.
  Bez nich audyt też działa, a raport wypisze te dwa sprawdzenia jako niezrobione.

## Instalacja

```bash
mkdir -p ~/.claude/skills
unzip security-audit-1.0.0.zip -d ~/.claude/skills/
# skill leży teraz w ~/.claude/skills/security-audit
```

Sprawdzenie, że skrypty działają (kilka sekund, bez tokenów):

```bash
cd ~/.claude/skills/security-audit && node --test scripts/
```

## Pierwszy audyt

W katalogu swojego projektu, w Claude Code:

```
/security-audit --scope top20
```

To szybki przebieg po 20 najbardziej ryzykownych miejscach. Pełny audyt: `/security-audit`.
Inne zakresy: `--scope auth`, `--scope payments`, `--scope src/api`. Po poprawkach: `/security-audit --verify-fixes`.

Raport: `.security-audit/report.html` w katalogu projektu. Katalog jest automatycznie dopisywany do `.gitignore`,
bo wskazuje niepoprawione słabości z plikiem i linią. Nie publikuj go.

## Podgląd postępu na żywo (opcjonalnie)

W paczce jest folder `audit-live`: mod do Claude Code, który podczas audytu pokazuje panel z fazą,
liczbą znalezisk i powiadomieniem o każdym nowym. Wymaga Claude Code 2.1.287 lub nowszego.

```bash
cp -r ~/.claude/skills/security-audit/audit-live ~/.claude/skills/
```

Panel otwiera się sam w szerokim terminalu (od 144 kolumn). W węższym wpisz `/audit-live`.
Mod tylko czyta pliki z `.security-audit/`. Cały kod to jeden plik: `audit-live/hooks/register.js`.
Skill działa tak samo bez niego.

## Aktualizacje

Gdy wychodzi nowa wersja, dostajesz mailem nowy link do pobrania. Rozpakuj paczkę w to samo miejsce.

## Discord

Pomoc w używaniu i rozmowy o wynikach: https://discord.gg/ctbj9SgT9N (serwer WrocDevs, kanał #security-audit-skill)

Zasada: nie wklejamy fragmentów raportów z niepoprawionymi słabościami ani sekretów.
