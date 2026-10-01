# plntir

Go-Control-Plane und Operator-Client für Agentenaktivität auf privaten Geräten,
verschlüsselte Archive sowie TypeScript-/Preact-Oberflächen.

In Entwicklung. Der HTTP-Kern arbeitet im schreibgeschützten Shadow-Modus.
Fileshare zeigt den tatsächlichen Verfügbarkeitsstatus; Session, Dateiliste und
Transfers sind noch nicht angebunden. Geräte- und Cloud-Integration sind offen.
Die separate Client-Webkonsole ist ein eigener Dienst im privaten Mesh.

## Ausprobieren

Linux, Bash, GNU coreutils und Go gemäß [Archivmodul](mac/archive-agent/go.mod):

```sh
(cd mac/archive-agent && go mod download)
bash scripts/portfolio-demo.sh
```

Die Demo verschlüsselt synthetische Daten, stellt die Bytes wieder her und lehnt
veränderten Ciphertext ab. Sie benötigt keine Geräte oder Cloud-Ressourcen.

Für lokale Prüfungen Go, C-Compiler, Python mit PyYAML, jq, ripgrep, OpenSSH,
age, curl und GNU Make bereitstellen. Backup-Checks brauchen `/usr/bin/age`
und `/usr/bin/age-keygen`.

```sh
PYTHONDONTWRITEBYTECODE=1 GOFLAGS=-mod=readonly make check mdm-check archive-check test-race
(cd web && npm ci --ignore-scripts && npm run check && npm run build)
```

Die Frontends brauchen Node gemäß [package.json](web/package.json).
`make platform-check` verlangt außerdem Terraform- und Ansible-Werkzeuge.

## Code

[HTTP-Grenze](core/internal/httpapi/) · [Datenhaltung](core/internal/store/sqlite/) ·
[Archiv-Restore](mac/archive-agent/archive/) · [Client-Webkonsole](client/internal/webconsole/)

Lokale Tests belegen weder Enrollment noch Cloud-Betrieb oder macOS-Geräte.
GitHub Actions sind derzeit deaktiviert; die bisherigen Starts endeten vor einem Job.

## Sicherheit

Inhalte werden vor dem Upload verschlüsselt. Autorisierte Recovery- und
Malware-Abläufe können Schlüssel entpacken. Der Scanner kann noch kein
qualifiziertes Produktionsergebnis „sauber“ ausstellen. Betreiberzustand,
Schlüssel und echte Telemetrie gehören nicht in Git. Sensible Befunde über die
private Meldung im GitHub-Security-Tab teilen.

Keine Wiederverwendungslizenz gewählt. Bestehende Drittanbieterhinweise gelten.
