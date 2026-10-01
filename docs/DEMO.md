# Lokales Archivbeispiel

Das Beispiel verschlüsselt eine synthetische Datei, stellt sie mit einem
temporären Offline-Schlüssel wieder her und vergleicht die Bytes. Danach ändert
es ein Byte des Ciphertexts und prüft, dass der Restore das Archiv ablehnt.

## Voraussetzungen

Linux, Bash, grep, GNU coreutils und Go gemäß `mac/archive-agent/go.mod`.
Die festgelegte Abhängigkeit `golang.org/x/sys` muss im Modul-Cache liegen.
Bei Bedarf separat vorbereiten:

```sh
(cd mac/archive-agent && go mod download)
```

Die Vorbereitung der Abhängigkeiten kann das Netzwerk nutzen. Die Demo selbst
setzt `GOPROXY=off`, `GOSUMDB=off` und `GOTOOLCHAIN=local`; fehlende
Abhängigkeiten führen zu einem Fehler statt zu einem Download.

## Ausführen

Aus der Repository-Wurzel:

```sh
bash scripts/portfolio-demo.sh
```

Der Runner gibt die Compilerversion und einen Quell-Fingerprint aus und führt
dann [`TestFullFileRestoreUsesOnlyOfflinePrivateKey`](../mac/archive-agent/archive/restore_test.go) aus.

| Schritt | Was läuft |
| --- | --- |
| Planen | `BuildPlan` teilt eine erzeugte 55-Byte-Datei in sieben kleine Test-Chunks. |
| Verschlüsseln | `WrapArchiveDEK`, `SealChunk` und `EncodeCipherChunk` erzeugen Envelopes und authentifizierte Chunks. |
| Manifest | `MaterializeSnapshot` setzt den Snapshot zusammen; Objekte liegen in einer Go-Map. |
| Wiederherstellen | `RestoreFileOffline` stellt mit einem temporären RSA-Schlüssel die ursprünglichen Bytes wieder her. |
| Manipulation ablehnen | Ein geändertes Ciphertext-Byte muss den Restore scheitern lassen. |

KMS-Wrapper und Objektspeicher sind Test-Doubles. Es werden kein
Betreiberprofil, keine SSH-Verbindung, kein Gerät und kein Cloud-Deployment
geladen.

## Ausgabe und Aufräumen

Der Test muss eine erfolgreiche exakte Wiederherstellung, abgelehnte
Manipulation und einen bestandenen Go-Test melden. Compilerfehler, fehlende
Werkzeuge und fehlgeschlagene Prüfungen liefern einen Exitcode ungleich null.

Temporäre Daten und Schlüssel werden beim Beenden entfernt. Ein übergebener
`GOCACHE` bleibt erhalten; andernfalls ist der Build-Cache temporär. Der
vorbereitete Modul-Cache bleibt unberührt.

## Prüfnachweis

Die [Ausgabe vom 19. September](evidence/2026-09-19-archive-demo.txt) hält den
ursprünglichen Lauf fest. Der Fingerprint des Runners umfasst ihn selbst, die
Moduldateien des Archivs und `archive/*.go`; Codeänderungen erfordern einen
neuen Lauf. Die aktuellen Prüfungen stehen in
[PROJECT_STATUS.md](../PROJECT_STATUS.md).

## Weiterlesen

- [Archivbibliothek](../mac/archive-agent/README.md)
- [Restore](../mac/archive-agent/archive/restore.go) und [Kryptografie](../mac/archive-agent/archive/crypto.go)
- [Projekthintergrund](PORTFOLIO.md)
- [Stand der übrigen Komponenten](../DEVELOPMENT.md)
