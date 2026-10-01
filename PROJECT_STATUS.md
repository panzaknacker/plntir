# Projektstatus

- Stand: in Entwicklung
- Umfang: Control Plane für Gerätesicherheit, verschlüsselte Archivbibliotheken und Integrationen
- Produktionssupport: keiner
- Quellbedingungen: keine Lizenz zur Weiterverwendung gewählt

## Lokale Prüfung: 21.09.2026

Arch Linux amd64, Go 1.26.8 und GCC 16.2.1. Die Prüfungen liefen in einer
temporären Quellkopie mit vorbereiteten Modulen, `GOPROXY=off`, `GOSUMDB=off`
und dem lokalen Compiler.
[Geprüfter Code und Build-Eingaben](docs/evidence/2026-09-21-inputs.sha256).

| Prüfung | Ergebnis |
| --- | --- |
| Archiv-Demo | Exakte Wiederherstellung und Ablehnung veränderten Ciphertexts bestanden. [Ausgabe](docs/evidence/2026-09-21-archive-demo.txt). |
| `make check` | Client-/Kern-Tests und vet, API-/Fleet-Verträge, Regression für benötigte Werkzeuge, statische Prüfungen, dscl, Integrität, verschlüsseltes Backup, Dashboard- und Paketprüfungen bestanden. [Ausgabe](docs/evidence/2026-09-21-local-check.txt). |
| `make archive-check mdm-check test-race` | Archivtests/vet, macOS-Cross-Builds, Fleet-Policy/Tests/vet sowie Race-Tests für Client, Kern und Archiv bestanden. [Ausgabe](docs/evidence/2026-09-21-archive-mdm-race.txt). |

Der erste Lauf übersprang ShellCheck; die abschließende Nachprüfung verwendete
Version 0.11.0 und bestand den vollständigen `make check` einschließlich
Shell-Prüfungen und 69 isolierter Fälle für Bereitschaftszustände.
[Abschließendes Protokoll](docs/evidence/2026-09-21-guard-state-check.txt),
[geprüfte Eingaben](docs/evidence/2026-09-21-guard-state-inputs.sha256).
Die separaten Node-Anwendungssuiten, Terraform-/Ansible-Providerprüfungen,
echtes Enrollment, Cloud-Rollout und Verhalten auf macOS-Geräten wurden nicht
getestet. GitHub Actions bleiben deaktiviert.

## Änderungen in diesem Review

ShellCheck deckte drei wirkungslose `! systemctl is-active`-Prüfungen auf: Bash
setzt `set -e` für einen negierten Befehl nicht durch. Eine erste Korrektur
stützte sich auf den Exitcode 3 von `is-active`; ein unabhängiges Review
stellte fest, dass dieser auch Übergangs- und Fehlerzustände abdeckt. Diese
Prüfung mit zwölf Fällen ist historisch und keine abschließende Abnahme.
Die Guards verlangen jetzt eine erfolgreiche `systemctl show`-Antwort mit genau
`LoadState=loaded` und `ActiveState=inactive`. Die
[Regression](tests/readiness-disabled-checks.py) prüft beide Reihenfolgen der
Eigenschaften und lehnt aktive, wechselnde, fehlgeschlagene, fehlende,
fehlerhafte und abfragefehlerhafte Fälle ab. Es wurden keine Deployments oder
Dienste verändert. Bekannte Fehlalarme des Linters bei jq/Callbacks haben lokale
Erklärungen; leere `CDPATH`-Zuweisungen sind explizit ausgeschrieben.

Die statischen und Paketprüfungen suchen `rg` jetzt über PATH und schlagen
ausdrücklich fehl, wenn es fehlt; die neue Regression prüft diesen Fehlerpfad.
Die CI nennt die bestehenden Abhängigkeiten `age` und `curl`. Der Archivtest
gibt zusätzlich Fortschritt aus, ohne seine Prüfungen zu ändern.

Zehn Verweise auf den Operator-Host verwenden jetzt die Dokumentationsadresse
`192.0.2.10`. Verifikationsschlüssel, Fingerprints und Vertrauensprüfungen sind
unverändert. [Verbleibende Veröffentlichungsprüfung](docs/PUBLICATION.md).

## Anonymisierung vom 29.09.2026

Vor der Veröffentlichung wurden die Projektdomain durch `plntir.example`, die
konkreten Mesh-Hostadressen durch andere Adressen im selben
Cloudflare-Mesh-Bereich `100.96.0.0/12`, die AWS-Konto-ID durch das
Beispielkonto `444455556666` und die Kennungen des Cloudflare-Organisations-CAs
durch Platzhalter ersetzt. Danach bestanden die Go-Tests von Kern, Client,
Archivagent und Fleet-Ingress mit Go 1.26.8 sowie die Python-Prüfungen für
Fleet-Ingress, OpenAPI-Vertrag, Web-Dashboard und Bereitschaftszustände. Die
Protokolle vom 21.09. beziehen sich auf den Stand vor dieser Ersetzung.

## Frühere Nachweise und offene Arbeit

Die Arbeitskopie vom 19. September bestand die lokalen
[Containerprüfungen](docs/evidence/2026-09-19-container-check.txt),
[Archivprüfungen](docs/evidence/2026-09-19-archive-check.txt) und
[MDM-/Race-Prüfungen](docs/evidence/2026-09-19-mdm-race-checks.txt).
Compose und ShellCheck wurden in dieser Umgebung übersprungen.

[DEVELOPMENT.md](DEVELOPMENT.md) hält die verbleibende Arbeit an
Produktionsidentität, Scanner, Recovery und Geräte-/Cloud-Integration fest.
`make platform-check` ist eine umfassendere Prüfstufe. Die privat genutzte
Installation ist eine andere oder neuere Variante;
[Projekthintergrund](docs/PORTFOLIO.md).

## Quellprüfung

Der saubere Quell-Export bestand die Prüfung lokaler Links und der
Dateihygiene. Gitleaks 8.30.1 meldete am 21. September keine Funde.
[Scanner-Ausgabe](docs/evidence/2026-09-21-source-scan.txt). Die Git-Historie
ist eine separate Prüfung; eine Prüfung des Betreiberkontexts bleibt nötig.
