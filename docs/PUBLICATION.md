# Quellstand und Veröffentlichung

Dieser Quellstand verwendet neutrale Betreiberbeispiele.
Produktive Einstellungen bleiben außerhalb des Repositorys. Die Archivdemo
lädt diese Einstellungen nicht.

## Betreiberbeispiele

| Bereich | Vorgabe |
| --- | --- |
| Operator-Verbindungen | `192.0.2.10` als Dokumentationsadresse; eigene Hosts lokal festlegen. |
| Projektdomänen und Konto-IDs | Beispieldomänen und Beispielkonten; keine produktiven Endpunkte daraus ableiten. |
| macOS-Homeverzeichnis | `/Users/plntir-operator` als neutraler Beispielpfad in Konfiguration, Endpoint-Helfer, Retrieval-Export und Migration. |
| Verifikationsschlüssel | Öffentliche Vertrauensanker, keine privaten Schlüssel; vor eigenem Betrieb unabhängig zuordnen. |
| Backup-Empfänger | Betreiberbezogene Recovery-Einstellung vor eigenem Betrieb prüfen. |

Die vier macOS-Homepfade wurden am 01.10.2026 vereinheitlicht. Statische
Prüfungen und Web-Dashboard-Datenprüfungen bestanden danach. Compose und
ShellCheck waren lokal nicht installiert und wurden ausdrücklich übersprungen.
Go-Code, Signatur- und Archivfunktionen wurden dabei nicht geändert.

## Historie und Herkunft

Ältere private Commits enthalten noch persönliche Benutzerpfade. Dieser Stand
wurde deshalb aus dem geprüften Export mit neuer anonymer Historie aufgebaut.
Die bisherigen Entwürfe und ihre Historie bleiben im separaten privaten Archiv
erhalten. Die öffentliche Historie enthält diese älteren Commits nicht.

Quell-Commit-IDs in älteren Prüfprotokollen beziehen sich auf den privaten
Ausgangsstand. Die Dateien des anonymen Exports entsprechen dem gemergten
Quellstand; die beigefügten SHA-256-Manifeste dokumentieren die geprüften Eingaben.

Die ursprüngliche vollständige Entwicklungshistorie wurde nicht mitgeliefert.
Die private Installation verwendet eine andere oder neuere Variante; ihr genaues
Verhältnis zu diesem Snapshot ist noch offen.

Es wurde keine Projektlizenz zur Weiterverwendung gewählt. Bestehende
Drittanbieterhinweise bleiben erhalten.

[Aktuelle lokale Nachprüfung](LOCAL-REVIEW-2026-10-01.md) ·
[Projektstatus](../PROJECT_STATUS.md) · [Hintergrund](PORTFOLIO.md)
