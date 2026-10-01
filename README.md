# plntir

Agentenaktivität nachvollziehen und Zusammenarbeit auf privaten Geräten
unterstützen. Dieser Quellstand enthält eine Go-Control-Plane, einen
Operator-Client, verschlüsselte Archivbibliotheken und TypeScript-/Preact-Oberflächen.

Das erste Ziel war, Dateien und Aktionen von Softwareagenten auf eigenen
Geräten zu verstehen. Mit Unterstützung kamen Kommunikation und Dateiaustausch
zwischen Geräten für gemeinsame Entwicklung hinzu.
[Hintergrund und Entscheidungen](docs/PORTFOLIO.md).

**In Entwicklung.** Der HTTP-Kern läuft im schreibgeschützten Shadow-Modus.
Identität, Geräte- und Cloud-Integration sind unvollständig.
[Komponentengrenzen](DEVELOPMENT.md).

## Archivdemo ausprobieren

Voraussetzungen: Linux, Bash, GNU coreutils und Go gemäß
[mac/archive-agent/go.mod](mac/archive-agent/go.mod).
Das festgelegte Go-Modul vor der Offline-Demo vorbereiten:

```sh
(cd mac/archive-agent && go mod download)
bash scripts/portfolio-demo.sh
```

Die Demo verschlüsselt eine synthetische Datei, stellt die ursprünglichen
Bytes exakt wieder her und prüft die Ablehnung veränderten Ciphertexts.
Sie verwendet temporäre Schlüssel und einen In-Memory-Objektspeicher.
Keine Betreiberkonfiguration, Geräteverbindung oder Cloud-Bereitstellung wird geladen.
[Ablauf und erwartete Ausgabe](docs/DEMO.md).

## Code-Einstiege

| Bereich | Code | Entscheidung |
| --- | --- | --- |
| Archiv-Restore | [Test](mac/archive-agent/archive/restore_test.go) · [Implementierung](mac/archive-agent/archive/restore.go) | Originalinhalt prüfen und veränderten Ciphertext ablehnen. |
| Freigaben | [SQLite-Tests](core/internal/store/sqlite/sharing_test.go) | Eine Dateiwiederherstellung darf widerrufenen Zugriff nicht wiederherstellen. |
| Dauerhafte Jobs | [Job-Tests](core/internal/store/sqlite/jobs_test.go) | Leases und Wiederholungen trennen Arbeit von der Lebensdauer eines Workers. |
| HTTP-Grenze | [Server](core/internal/httpapi/server.go) | Änderungen sperren, solange Identität und Betrieb unvollständig sind. |

Weitere Komponenten betreffen API-Verträge, Fleet-Ingress, signierte Pakete,
Terraform/Ansible und Cloud-Anbindungen. Topologiebeispiele sind keine Demo-Ziele.
[Vollständiger Komponentenstand](DEVELOPMENT.md).

## Lokale Prüfung

Die September-Protokolle erfassen Archivdemo, Kern-/Client-Prüfungen,
API-/Fleet-Verträge, Backup- und Paketprüfungen, Archiv-/MDM-Tests und Go-Race-Tests.
Die spätere Anonymisierung wurde durch die dokumentierten Go-/Python-Prüfungen
begleitet. [Ergebnisse und Umfang](PROJECT_STATUS.md).
[Aktuelle lokale Nachprüfung](docs/LOCAL-REVIEW-2026-10-01.md).

Go, C-Compiler, Bash, Python mit PyYAML, GNU Make, jq, ripgrep, OpenSSH,
age und curl vorbereiten. Backup-Prüfungen benötigen `/usr/bin/age` und
`/usr/bin/age-keygen`.

```sh
PYTHONDONTWRITEBYTECODE=1 GOFLAGS=-mod=readonly make check
PYTHONDONTWRITEBYTECODE=1 GOFLAGS=-mod=readonly make mdm-check archive-check test-race
```

`make platform-check` verlangt zusätzliche Node-, Terraform- und Ansible-Werkzeuge.
Lokale Tests belegen kein echtes Enrollment, keinen Cloud-Betrieb und kein
Verhalten auf macOS-Geräten.

## Vertrauen und Wiederherstellung

Fileshare-Inhalte werden vor dem Upload verschlüsselt. Autorisierte
Admin-Recovery- und Malware-Abläufe können Schlüssel entpacken; Inhalte sind
vor dem Recovery-Administrator nicht verborgen. Der Scanner kann noch kein
qualifiziertes Produktionsergebnis „sauber“ ausstellen. Cloud- und
Geräteänderungen bleiben standardmäßig gesperrt.

[Sicherheitsmodell](docs/plntir-security-model.md) ·
[Recovery](docs/plntir-recovery-and-continuity.md) ·
[Veröffentlichungsprüfung](docs/PUBLICATION.md)

Die [GitHub-Workflows](https://github.com/panzaknacker/plntir/actions) sind von
lokalen Ergebnissen getrennt. Der [CI-Startfehler](docs/HOSTED-CI.md) ist dokumentiert.

## Dokumentation und Quellbedingungen

[Demo](docs/DEMO.md) · [Projektstatus](PROJECT_STATUS.md) ·
[Entwicklung](DEVELOPMENT.md) · [Beiträge](CONTRIBUTING.md) ·
[Sicherheitsmeldungen](SECURITY.md)

Es wurde keine Projektlizenz zur Weiterverwendung gewählt. Bestehende
Drittanbieterhinweise bleiben gültig; Quellsichtbarkeit erteilt keine zusätzliche Lizenz.
