# Security Audit — instalacja

Wersja 1.1.0

## Wymagania

- Claude Code (płatny plan albo klucz API)
- Node.js 20 lub nowszy
- Docker do skanu zależności i sekretów. Zamiast dockera możesz zainstalować `osv-scanner` i `gitleaks`.
  Bez nich audyt też działa, a raport wypisze te dwa sprawdzenia jako niezrobione.

## Instalacja

Rozpakuj paczkę i przenieś folder `security-audit` do `~/.claude/skills`:

```bash
unzip security-audit-1.1.0.zip -d /tmp/secaudit
mkdir -p ~/.claude/skills
mv /tmp/secaudit/security-audit ~/.claude/skills/
```

Alternatywnie jedną komendą, z linkiem z maila (wymaga Node 20+):

```bash
npx devince-apps install <link do pobrania z maila>
```

Ta komenda pobiera paczkę, sprawdza archiwum i układa skill oraz mod w `~/.claude/skills`. Jej kod jest
publiczny: github.com/bartek-filipiuk/devince-apps-cli.

Sprawdzenie, że skrypty działają (kilka sekund, bez tokenów):

```bash
cd ~/.claude/skills/security-audit && node --test scripts/
```

## Pierwszy audyt

Przed audytem zainstaluj zależności projektu i upewnij się, że jego testy się uruchamiają
(na przykład `pnpm install && pnpm test`). Audyt pisze testy regresji w runnerze Twojego projektu;
bez zainstalowanych zależności nie uruchomi ich i każde znalezisko dostanie etykietę „static”.

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
