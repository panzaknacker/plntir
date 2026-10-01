# Plntir-macOS-Archivagent: inaktiver Qualifikations-Build

Dieses Verzeichnis enthält den lokalen, standardmäßig deaktivierten Datenpfad
für Archive. Es ist kein LaunchDaemon, ist nicht über MDM registriert und hat
den aktiven Mac nicht verändert. `make archive-check` führt die Linux-Tests aus
und baut die Bibliothek per Cross-Build für macOS auf Apple Silicon und Intel.

## Durchgesetzte Invarianten

- Die Traversierung beginnt an einer bereinigten absoluten Wurzel und öffnet
  jede Komponente mit `openat(2)` plus `O_NOFOLLOW`. Ersetzte Verzeichnisse,
  Änderungen an der Quelle und ausgetauschte Symlinks führen zu einem Fehler,
  statt den Backup-Umfang stillschweigend zu ändern. Die Traversierung
  überschreitet keine Mount-Grenzen.
- `.Trash`, Benutzer-Caches, bekannte temporäre Verzeichnisbäume,
  nicht-reguläre Spezialdateien und `.icloud`-Platzhalter werden als Ausschlüsse
  erfasst. Symlinks werden als Metadaten archiviert und nie verfolgt. Eine
  native iCloud-Qualifikationsprobe kann eingebunden werden; die
  Suffix-Erkennung ist nur der konservative Standard.
- Produktions-Chunks sind knapp unter 64 MiB groß. Jeder Chunk verwendet
  AES-256-GCM mit einem geleasten Nonce-Zähler und binärer, längenbegrenzter AAD
  mit Geräte-, Archiv-, Arbeits- und opaker Objektidentität. Inode, Größe, Modus
  und mtime in Nanosekunden der Quelle müssen vor und nach dem Lesen
  übereinstimmen.
- Ein lokal erzeugter DEK wird unabhängig voneinander von AWS KMS und einem
  öffentlichen RSA-Schlüssel für Offline-Recovery verpackt. Ein neuer Snapshot
  kann keinen älteren DEK wiederverwenden. Wiederverwendete Ciphertext-Objekte
  tragen ihre ursprüngliche AAD- und Key-Envelope-Identität im verschlüsselten
  Snapshot-Manifest.
- Der unveränderliche Plan und der veränderliche Fortsetzungszustand verlangen
  prozesseigene private Verzeichnisse und reguläre Dateien mit `0600`.
  Unbekannte JSON-Felder, Symlinks, lockere Berechtigungen, geänderte Digests,
  doppelte Objekt-IDs und wiederverwendete Nonces führen zu einem
  fail-closed-Abbruch. Weder ein roher DEK noch eine vorsignierte URL wird
  serialisiert.
- Vor jeder Anfrage nach einer Berechtigung werden ein ausstehendes Objekt und
  seine verbrauchte Nonce atomar gespeichert und per fsync gesichert. Eine
  Wiederholung fordert eine neue Berechtigung an, rekonstruiert aber dieselbe
  Objekt-ID und byteidentischen Ciphertext. Berechtigungen müssen innerhalb von
  fünf Minuten ablaufen und PUT, Content-Length, SHA-256-Prüfsumme, Objekt-ID,
  Work-ID und Content-Type binden. Weiterleitungen werden nie verfolgt.
- Die lokale Policy verweigert getaktete, Hotspot- und Netzwerke mit
  unbekannten Kosten, Akku unter 20 Prozent ohne Netzteil, weniger als 15 GiB
  freien Speicher, ernsten/kritischen oder unbekannten thermischen Zustand,
  Last über 90 Prozent für fünf Minuten, veraltete Proben und wiederholte
  Netzwerkfehler. Bei 50/80/100 Prozent des S3-Budgets warnt sie, blockiert neue
  Geräte und löst einen harten Alarm aus, während bestehende Backups
  weiterlaufen.
- Der Offline-Restore-Test rekonstruiert eine Datei aus mehreren Objekten nur
  mit Snapshot-Manifest, Ciphertext-Objekten und dem privaten RSA-Schlüssel. Er
  prüft Hash, Größe, Nonce, AAD, GCM-Tag und Schlüssel-Fingerprint jedes
  Objekts ohne KMS- oder Netzwerkaufruf.

## Verbleibende Aktivierungsschritte

Dieses Paket beansprucht bewusst nicht, ein Produktionsbackup zu sein. Vor einer
Installation brauchen folgende Punkte noch eine eigene Implementierung oder
Live-Qualifikation und die unmittelbare Freigabe durch den Betreiber:

1. Eine signierte macOS-native Policy-/iCloud-Probe und ein Profil für vollen
   Festplattenzugriff.
2. APFS-konsistente Behandlung sich laufend ändernder Datenbanken oder ein
   ausdrücklicher Qualifikationskorpus für Wiederholung und Neuplanung pro
   Datei.
3. Die mTLS-Control-Plane-Implementierung, die DEKs verpackt, echte an
   Prüfsummen gebundene S3-URLs liefert, das verschlüsselte Snapshot-Manifest
   veröffentlicht und die Aufbewahrungsrichtlinie (30 Tage/letzter bekannter
   guter Stand) anwendet.
4. Lasttests mit direktem Stream für das erste Backup von etwa 365 GB,
   Fortsetzung nach Neustart und Netzwerkverlust, S3-Budgetalarme und ein
   echter Offline-Schlüssel in KeePass/auf einem YubiKey. Test-RSA-Schlüssel
   sind kurzlebig und keine Produktionsgeheimnisse.
5. Ein signiertes Release, launchd-Paketierung, ein Pilot auf einem frischen
   Gerät und eine eigene Freigabe vor jeder Profiländerung oder jedem Neustart
   auf dem Produktions-Mac.

Bis diese Schritte bestanden sind, diesen Code nur über seine lokalen Tests
verwenden.
