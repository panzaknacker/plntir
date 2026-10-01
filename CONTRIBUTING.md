# Beiträge

Mit [Komponentenstand](DEVELOPMENT.md) und [PROJECT_STATUS.md](PROJECT_STATUS.md) beginnen.
Änderungen fokussiert halten und Problem, Verhalten sowie betroffene
Vertrauensgrenzen erläutern.

## Lokale Prüfung

Go gemäß `core/go.mod`, C-Compiler, Bash, GNU Make, Python mit PyYAML, jq,
ripgrep, OpenSSH, age und curl vorbereiten. Backup-Prüfungen verlangen
`/usr/bin/age` und `/usr/bin/age-keygen`.

```sh
PYTHONDONTWRITEBYTECODE=1 GOFLAGS=-mod=readonly make check mdm-check archive-check test-race
```

`make platform-check` hat zusätzliche Anforderungen. Lokale Prüfungen
qualifizieren weder Enrollment noch Cloud-Betrieb oder macOS-Geräte.

Tatsächlich ausgeführte Befehle, Umgebung, Ergebnisse und übersprungene Checks
festhalten. Geänderte Go-Dateien mit `gofmt` formatieren. Verhaltensänderungen
brauchen gezielte Regressionen für Fehlerfälle und abgelehnte Eingaben.

## Anforderungen an Beiträge

Ausdrückliche Freigaben, geprüftes Vertrauen, Fehlerbehandlung und Recovery-Grenzen
erhalten. Ändert sich eine Fähigkeit oder ihre Abnahme, den Projektstatus anpassen.
Lokale, simulierte und echte Betriebsnachweise getrennt benennen.

Synthetische Fixtures verwenden. Keine Binaries, privaten Zustände, Zugangsdaten,
echten Inventare oder Fremdquellen ohne Lizenzhinweise committen.
Sensible Befunde über [SECURITY.md](SECURITY.md) melden.

## Quellbedingungen

Keine Wiederverwendungslizenz gewählt. Diese Anleitung erteilt keine neue
Lizenz und führt keine Beitragsvereinbarung ein. Drittanbieterhinweise erhalten.
