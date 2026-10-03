# Scenariusz: „Jak działa Security Audit” (film z komentarzem, 8–12 minut)

Cel: pokazać wynik, raport i etapy, tak żeby widz zrozumiał, czym to się różni od zwykłego promptu, i wiedział,
co dostaje za 147 zł. Mówisz do kamery albo pod nagranie ekranu, bez slajdów. Każda scena ma: co pokazać,
co powiedzieć (w punktach, własnymi słowami) i czego nie pokazywać.

## 0. Hak (0:00–0:30)

Pokaż: raport HTML z Ledgerly otwarty w przeglądarce, przewinięty do „Fix first”.
Powiedz:
- Ta aplikacja ma 16 celowo ukrytych błędów bezpieczeństwa. Skill znalazł wszystkie, nie dał się nabrać na żadną z 8 pułapek, i zajęło mu to 32 minuty.
- Pokażę, co dostajesz, jak to działa w środku i czego to nie robi.

## 1. Problem (0:30–1:30)

Pokaż: pusty terminal albo kamera.
Powiedz:
- Buduję w Claude Code i wdrażam na produkcję. „Claude, sprawdź bezpieczeństwo” daje listę, w której nie wiadomo, co jest prawdziwe, co ważne i czego model w ogóle nie sprawdził.
- Trzy rzeczy, których mi brakowało: dowód przy każdym znalezisku, odsiane fałszywe alarmy i uczciwa lista „nie sprawdzone”.

## 2. Uruchomienie (1:30–2:30)

Pokaż: `cd` do projektu, `claude`, wpisanie `/security-audit`. Panel „Audit” otwiera się sam.
Powiedz:
- Jedna komenda w katalogu projektu. Bez konfiguracji, bez konta w kolejnym serwisie.
- Panel po prawej to opcjonalny mod: faza, liczniki według wagi, dymek przy każdym nowym znalezisku.
- Zakres: cały projekt albo `--scope auth`, `--scope payments`, `--scope top20`.
Nie pokazuj: treści promptów agentów, plików w `~/.claude/skills`.

## 3. Pięć faz, na przyspieszonym nagraniu (2:30–5:00)

Pokaż: film „pełny przebieg” ze strony (5 min), zatrzymywany w czterech miejscach.
Powiedz przy każdym zatrzymaniu:
- **Wstępny skan** (pierwsze sekundy): lista miejsc dostępnych z zewnątrz i ranking ryzyka, zależności w publicznej bazie CVE, sekrety w całej historii gita. To skrypty, nie model, trwa dwie sekundy.
- **Mapa i audyt** (liczniki rosną): mapa uprawnień, potem audyt po 12 obszarach, od najbardziej ryzykownych miejsc. Tu powstają kandydaci, celowo z nadmiarem.
- **Weryfikacja** („2 background agents launched”): osobni weryfikatorzy czytają kod drugi raz, śledzą dane od wejścia do użycia, odrzucają fałszywe alarmy, łączą znaleziska w łańcuchy. Przy poważnych piszą test regresji w runnerze projektu, który dziś nie przechodzi. W tym przebiegu odpadło 6 kandydatów.
- **Raport** („Phase: Done”): ocena testów projektu, lista działań w kolejności, raport HTML.

## 4. Raport, powoli (5:00–8:00)

Pokaż: raport HTML, sekcja po sekcji.
Powiedz:
- Pasek werdyktu: ile do naprawy, ile bezpieczne, ile nie sprawdzone. Ramka „Partial audit”, gdy zakres był ograniczony.
- „Fix first”: trzy rzeczy na dziś, z plikiem i linią.
- Jedno znalezisko rozwinięte: „How to fix” na wierzchu, dowód z kodu, przepływ danych, skutek („kto może zrobić to, czego nie powinien”), stan testu regresji. Etykieta „Failing test” albo „Code reading only”.
- „Verified safe”: każdy wpis wskazuje zabezpieczenie w kodzie, z plikiem i linią. Brak znalezisk to nie „bezpiecznie”, dopóki nie ma dowodu.
- „Not assessed”: to, czego audyt nie mógł ocenić, na przykład ustawienia produkcji. To jest sekcja, której w zwykłym prompcie nie ma.
- Zależności i sekrety: osobne tabele z wynikiem skanerów.
Nie pokazuj: niczego z prawdziwego projektu klienta. Tylko Ledgerly.

## 5. Czego nie robi (8:00–9:00)

Pokaż: sekcja „Co sprawdza, a czego nie” na stronie.
Powiedz:
- Nie zastępuje pentestu: czyta kod i uruchamia testy lokalnie, nie dotyka produkcji.
- Nie symuluje ataków. Dowodem jest test regresji, nie demonstracja włamania.
- Nie zna Twojej produkcji: limity, proxy, zmienne środowiskowe wypisuje do sprawdzenia.
- Najlepiej działa na Next.js, tRPC, Hono, Drizzle, Better-Auth. Inne stacki na regułach ogólnych; profile dla PHP, Pythona, Go i Rusta są w planach.
- Modele mają własne mechanizmy bezpieczeństwa. Ten przebieg przeszedł w całości, ale nie gwarantuję, że każdy przejdzie.

## 6. Koszt i oferta (9:00–10:00)

Pokaż: sekcja „Czym różni się od zwykłego promptu” z kartą liczb, potem cennik.
Powiedz:
- Ten przebieg: 23,8 mln tokenów, 96% z cache, około 11,70 USD w cenach API, na Opus 5.5. Tokeny idą z Twojego konta.
- 147 zł, raz. W paczce skill, mod z panelem, aplikacja testowa z kluczem odpowiedzi, Discord, aktualizacje mailem. 14 dni na zwrot.
- Ten sam wynik powtórzysz u siebie: aplikacja testowa jest w paczce.

## 7. Zakończenie (10:00–10:30)

Pokaż: security-audit.dev.
Powiedz:
- Link w opisie. Jeśli masz pytania o swój stack, Discord.

## Rzeczy do przygotowania przed nagraniem

- Raport Ledgerly otwarty w przeglądarce bez paska zakładek (tryb pełnoekranowy, F11).
- Terminal co najmniej 144 kolumny, duża czcionka, czysty pulpit, powiadomienia wyłączone.
- Film „pełny przebieg” pobrany lokalnie, żeby zatrzymywać go bez ładowania.
- Strona otwarta w drugiej karcie.
