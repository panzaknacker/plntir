# Fernwartung eines aktiv genutzten Macs

Dieses Runbook gilt, solange der verwaltete Mac normal genutzt wird und kein
lokales Wartungsfenster offen ist. Standard ist Beobachten, nicht Verändern.

## Erlaubte Hintergrundarbeit

- Den leichtgewichtigen minütlichen Gesundheitscheck weiterlaufen lassen.
- Sicherheitszustand und Telemetrie mit reduzierter CPU-Priorität ausführen.
- Verfügbare Apple-Softwareupdates abfragen, ohne sie zu installieren.
- macOS seine bereits konfigurierten automatischen Prüfungen, Downloads,
  Updates kritischer Daten und Richtlinien für Hintergrundinstallation
  ausführen lassen.
- Nur abgelaufene, von plntir erzeugte Abrufarchive entfernen, die exakt dem
  erzeugten Dateinamensformat entsprechen. Andere Dateien werden nie bereinigt.
- Den geplanten Bereitschafts-Timer für alle Benutzer deaktiviert lassen. Eine
  Quellmessung läuft erst, nachdem ein Betreiber ein Archiv auf Anforderung
  ausdrücklich freigegeben hat.

## Aktionen, die ein Wartungsfenster erfordern

Während der Mac genutzt wird, kein macOS-Update aus der Ferne installieren,
keinen Neustart anfordern, keine macOS-Datenschutzberechtigungen ändern, keine
Benutzerkonten verändern und keinen Rollback-Weg entfernen. Den lokalen
Betreiber nur einbeziehen, wenn die begrenzten SSH-Wege fehlschlagen oder macOS
eine Datenschutzentscheidung auf dem Bildschirm verlangt.

Updates rein lesend über den bestehenden Recovery-Weg auflisten:

```sh
./scripts/connect-plntir-recovery.sh /usr/sbin/softwareupdate --list
```

In einer gewöhnlichen Fernsitzung nie `--install`, `--all` oder `--restart`
anhängen. Zuerst ein ausdrückliches Wartungsfenster festhalten.

## Grenze für das Aufräumen

Der Abruf-Exporter darf seine eigenen erzeugten `.tar.gz`-Dateien nach 24
Stunden löschen. Er prüft den vollständigen erzeugten Dateinamen, verweigert
Symlinks und berührt keine Benutzerinhalte. Installer-Eingänge, Ergebnislogs,
Host-Backups, alte Hilfsprogramme und verschlüsselte Archive bleiben während
der Rollback-Beobachtungsphase erhalten und sind keine routinemäßigen
Aufräumziele.

Bevor alte Hilfsprogramme entfernt werden, mindestens einen Tag gesundes
Monitoring und einen erfolgreichen Zyklus aus Abruf, Übertragung, Prüfsumme und
Löschung abschließen. Aufräumen ersetzt nicht den Speicherplatz, den das
vollständige verschlüsselte Archiv aller Benutzer braucht.

## Ausgangszustand vom 30.08.2026

Der aktive Mac meldete kein verfügbares Apple-Softwareupdate. Automatische
Update-Prüfung, Download, macOS-Installation, kritische Updates und Updates von
Konfigurationsdaten waren aktiviert. Die vorhandenen sichtbaren plntir-Staging-
und Ergebnisverzeichnisse belegten etwa 64 KiB und wurden behalten, weil die
Migrations-Beobachtungsphase weniger als einen Tag alt war. Der ältere Zustand
des Control-Nodes belegte etwa 19 MiB und wurde ebenfalls als Rollback-Daten
behalten.
