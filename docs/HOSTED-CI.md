# Gehostete CI

## Prüfversuch vom 01.10.2026 im privaten Ausgangsrepository

GitHub Actions waren vor der Durchsicht deaktiviert. Die vorhandenen Prüf- und
Secret-Scan-Workflows wurden kurz aktiviert und manuell gestartet:

- Prüfworkflow: privater Lauf `36853178219`.
- Secret-Scan: privater Lauf `36853190178`.

Beide endeten mit `startup_failure`, bevor ein Job angelegt wurde. Jobs-API und
Check-Run-Liste blieben leer; Runner-Logs oder Fehleranmerkungen waren nicht
verfügbar. Der genaue Startgrund wurde über die API nicht ausgegeben.
In diesen gehosteten Läufen wurden keine Tests ausgeführt.

Actionlint 1.7.12 akzeptierte beide Workflow-Dateien. Die festgelegte
Checkout-Aktion existiert. Diese Prüfungen diagnostizieren den Startfehler nicht.

Actions wurden auf den ursprünglichen deaktivierten Zustand zurückgestellt,
um weitere Fehlmeldungen bei Dokumentationsänderungen zu vermeiden. Die
fehlgeschlagenen Läufe bleiben im privaten Archiv erhalten. Das neu aufgebaute
öffentliche Repository hat eine eigene anonyme Historie; Actions bleiben dort
ebenfalls deaktiviert. Nach Klärung der Ursache die Workflows gezielt aktivieren
und beobachten. Lokale Ergebnisse sind getrennt dokumentiert.

[Projektstatus](../PROJECT_STATUS.md)
