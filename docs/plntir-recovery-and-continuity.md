# Plntir-Recovery und Kontinuität

dieses runbook trennt quellhistorie, endpunkt-recovery und verschlüsselte
snapshots der control plane. es legt nie einen privaten schlüssel, eine
passphrase, ein R2-token oder entschlüsselte benutzerinhalte in git ab.

## Vertrauensanker

- signaturidentität für releases: plntir-release
- SSH-signatur-namespace: plntir-endpoint-recovery
- fingerprint des release-schlüssels:
  `SHA256:iuiyzojuhRUsQnTqiTdALHweb70aok45Gz1M559L1vs`
- empfänger der backup-verschlüsselung:
  `age10pnwza9png8l34cc5z37vwrlp6nu54wuccmq7qw88de5flct5eqql5nl0q`

die privaten dateien werden unter `secrets/` ignoriert:

- `plntir_release_signing_ed25519`
- `plntir_control_plane_backup.agekey`

beide in einen offline-tresor des betreibers kopieren, bevor man sich auf die
automatische recovery verlässt. der private signaturschlüssel gehört nie auf den
mac oder den control-node. die age-identität gehört nie auf den control-node;
dieser host erhält nur den öffentlichen empfänger.

## Git-Historie und sofortiger Spiegel auf einem zweiten Host

der arbeitsbaum enthält keinen versionierten privaten schlüssel und kein
laufzeit-secret. das git-remote `control-node` ist ein bare-spiegel nur über SSH
unter:

    admin@192.0.2.10:/var/lib/plntir/git/plntir-control-plane.git

nach dem commit einer geprüften revision diese mit dem wrapper für strikte
hostkey- und identitätsprüfung pushen:

    ./scripts/push-plntir-git-offhost.sh

der wrapper verweigert eine unerwartete remote-URL und verweigert den push,
solange versionierte änderungen nicht committet sind. dieser spiegel schützt die
quellhistorie, falls die betreiber-workstation verloren geht. er ersetzt nicht
den R2-snapshot, weil git-spiegel und laufende dienste dieselbe fehlerdomäne
des control-nodes teilen.

## Signiertes Endpunkt-Recovery-Kit

das paket mit den bestehenden endpunktschlüsseln und dem eigenen
signaturschlüssel bauen:

    ./scripts/build-plntir-platform-update.sh \
      generated/Plntir-Endpoint-Recovery \
      MANAGED_USER \
      bootstrapadmin \
      100.101.0.5 \
      secrets/plntir_endpoint_monitor_ed25519.pub \
      secrets/plntir_endpoint_response_ed25519.pub \
      secrets/plntir_endpoint_archive_ed25519.pub \
      secrets/plntir_recovery_ed25519.pub \
      secrets/plntir_release_signing_ed25519

die ausgabe enthält das archiv, eine SHA-256-begleitdatei, eine abgetrennte
SSH-signatur, eine allowed-signers-datei und den root-runner. der runner prüft
prüfsumme und signatur vor dem entpacken. ein geprüftes archiv und seine
signatur werden unter `/Library/Application Support/plntir/recovery/packages/`
aufbewahrt.

der plattform-installer installiert außerdem `com.plntir.endpoint-integrity` im
reinen alarmmodus. es läuft beim start und alle fünf minuten mit niedriger CPU-
und E/A-priorität. es vergleicht hashes, eigentümer, gruppen und modi für die
begrenzte menge an plntir-dateien. es schreibt:

- `/Library/Application Support/plntir/integrity/status.env`
- `/Library/Application Support/plntir/integrity/drift.tsv`

es repariert keine dateien, ändert keine macOS-einstellungen, lädt keinen code
herunter und startet den mac nicht neu. der bestehende health-collector gibt nur
den zustand und die anzahl der abweichungen an die betriebskonsole weiter.

## Verschlüsselte Snapshots des Control-Nodes

der snapshot enthält plntir-binaries, konfiguration, monitoring-zustand,
SSH-konfiguration und hostkeys, exakte sudo-regeln, systemd-zustand, den
bare-git-spiegel, WARP-zustand, falls vorhanden, und administrative
SSH-zugangsdaten des control-nodes. abgerufene archive von mac-benutzern und
allgemeine inhalte von home-verzeichnissen schließt er bewusst aus. der gesamte
snapshot wird verschlüsselt, bevor er geschrieben wird.

jeder snapshot wird direkt aus tar in age gestreamt; es wird kein
klartextarchiv geschrieben. R2-uploads verwenden eindeutige objektnamen,
`If-None-Match: *`, eine sofortige prüfung durch erneuten download mit
prüfsumme und das präfix:

    snapshots/control-node/YYYY/MM/

R2 im cloudflare-konto aktivieren, den privaten bucket
`plntir-control-plane-backups` anlegen und ein object-read-&-write-token nur für
diesen bucket erstellen. die beispielkonfiguration in eine nur für root lesbare
datei kopieren und jeden platzhalter ersetzen:

    sudo install -o root -g root -m 0600 \
      config/backup/plntir-control-plane-backup.env.example \
      /root/plntir-control-plane-backup.env

hochgeladene objekte 90 tage lang mit einem R2-bucket-lock auf dem präfix
`snapshots/` schützen. bucket-locks verhindern während der aufbewahrung sowohl
löschen als auch überschreiben:

    npx wrangler r2 bucket lock add plntir-control-plane-backups \
      --name plntir-90-day-snapshots \
      --prefix snapshots/ \
      --retention-days 90

das age-paket von debian installieren, dann den ersten upload einrichten und
prüfen:

    sudo ./scripts/provision-plntir-offhost-backup.sh \
      /path/to/plntir \
      /root/plntir-control-plane-backup.env \
      /path/to/plntir/config/backup/plntir-control-plane-backup-recipient.txt

der tägliche timer wird erst aktiviert, nachdem der erste verschlüsselte upload
erneut heruntergeladen und sein SHA-256 geprüft wurde.

## Wiederherstellungstest

ein `.tar.gz.age`-objekt herunterladen und auf einem betreiberrechner mit der
offline-age-identität prüfen:

    ./scripts/verify-plntir-control-plane-backup.sh \
      plntir-control-plane-HOST-TIMESTAMP.tar.gz.age \
      secrets/plntir_control_plane_backup.agekey

diese prüfung entschlüsselt in ein privates temporäres verzeichnis, lehnt
absolute pfade und pfade mit übergeordneten verzeichnissen ab, prüft die
nötigen recovery-inhalte und entfernt den temporären klartext beim beenden. das
entpacken auf einem laufenden host bleibt ein separater, ausdrücklicher
recovery-vorgang.

## Freigabeschritte für den Rollout

1. eine quellrevision ohne secrets committen und auf den spiegel des
   control-nodes pushen.
2. das signierte recovery-kit und seinen negativen manipulationstest prüfen.
3. einen verschlüsselten externen snapshot erstellen und seine
   wiederherstellung testen.
4. das signierte kit unter `/Users/Shared/.plntir/inbox/platform-update`
   bereitstellen.
5. während eines lokalen administratorfensters den einzelnen befehl aus
   `RUN_ME.txt` ausführen.
6. das integritätsmonitoring mindestens 48 stunden im reinen alarmmodus lassen.
7. automatische reparatur erst aktivieren, wenn abweichungsrichtlinie und
   rollback-test gesondert freigegeben sind.
