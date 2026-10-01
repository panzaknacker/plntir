# Lokale Nachprüfung · 01.10.2026

Die [Archivdemo](evidence/2026-10-01-archive-demo.txt) bestand: byteidentische
Wiederherstellung und Ablehnung veränderten Ciphertexts.

`make mdm-check archive-check test-race` bestand: Fleet-Policy und Verträge,
Fleet-Go-Tests/vet, Archivtests/vet, beide macOS-Cross-Builds sowie Race-Tests
für Client, Kern und Archiv.
[Vollständiges Komponentenprotokoll](evidence/2026-10-01-components.txt).

Ein neuer vollständiger `make check` oder `make platform-check` lief nicht.
Der bestehende Vollprüfungscontainer startet wegen eines veralteten Boot-IDs
nicht; sein gemeinsamer Zustand wurde nicht verändert. Kein echtes Enrollment,
Cloud-Betrieb oder macOS-Gerät wurde geprüft.

## Anonyme Betreiberbeispiele

Vier persönliche macOS-Homepfade wurden danach einheitlich durch
`/Users/plntir-operator` ersetzt. Statische Prüfungen und die Web-Dashboard-
Datenprüfungen bestanden nach der Ersetzung. Docker-Compose-Validierung und
ShellCheck waren lokal nicht installiert und wurden ausdrücklich übersprungen.
[Statischer Lauf](evidence/2026-10-01-anonymous-static.txt).
Die Betreiberbeispiele müssen vor einem echten Betrieb an eigene lokale
Einstellungen angepasst werden. Go-Code und kryptographische Prüfungen sind unverändert.

## Umgebung und Quellstand

Fedora 44 x86_64, Kernel 7.2.5-200.fc44; Go 1.26.8, soweit verwendet,
und Python 3.14.7. Vorbereitete Werkzeuge und Modulcaches wurden wiederverwendet.
Go-Proxy und Prüfsummenabrufe waren deaktiviert. Daten und Schlüssel waren
synthetisch und temporär.

[Kontext](evidence/2026-10-01-context.json) ·
[Geprüfte Code-/Build-Eingaben](evidence/2026-10-01-inputs.sha256)

Lokale Checkout-/Werkzeugpfade und zufällige öffentliche Demo-Key-IDs wurden
normalisiert; Ergebnisse und Fehler blieben erhalten. Gitleaks 8.30.1 meldete
bei der Prüfung aller vorhandenen Git-Refs keine Geheimnisse. Nicht mitgelieferte
ursprüngliche Entwicklungshistorie und Produktionsreife sind davon nicht erfasst.

[Gehostete CI-Startfehler](HOSTED-CI.md) sind von diesen lokalen Ergebnissen getrennt.
