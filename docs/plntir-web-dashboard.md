# Plntir-Web-Dashboard im privaten Mesh

die plntir-webkonsole ist ein HTTPS-dienst, der an die exakte
cloudflare-mesh-IP des control-nodes gebunden ist. er hat keinen öffentlichen
DNS-eintrag, lauscht auf keiner öffentlichen oder wildcard-adresse, und die
host-firewall akzeptiert TCP/8443 nur auf dem interface `CloudflareWARP`.

die konsole trennt bewusst drei bereiche:

1. **routine-monitoring** zeigt die bestehende gesundheitshistorie,
   strukturierten status, posture-erfassungen, laufzeittelemetrie, timer,
   speicher und ereignisse.
2. **einsicht in private daten** ist standardmäßig gesperrt. die erneute
   eingabe des separaten dashboard-passworts öffnet eine in-memory-sitzung für
   höchstens zehn minuten. dateilisten, proben, safari-verlauf, archivlisten und
   downloads erfordern diesen bereich. browser und server verwerfen die private
   ansicht, wenn sie abläuft.
3. **aktionen** verwenden nur den root-eigenen dispatcher `plntir-web-action`.
   es gibt keine shell, kein befehlsfeld und keinen beliebigen sudo-endpunkt.
   erlaubt sind verzeichnisauflistung, begrenzte textvorschau, größenprobe,
   ausgewählter export, ein schreibgeschützter snapshot des safari-verlaufs und
   eine sofortige aktualisierung der bestehenden collectoren. der dienst darf
   netlink nur nutzen, damit die statuserfassung die WARP-adresse und nftables
   prüfen kann; er erhält keine ambient capabilities.

das mac-administratorpasswort wird von diesem webdienst absichtlich nicht
akzeptiert. es an einen ständig laufenden server zu senden, würde die
bestehende recovery-grenze schwächen und ist für die festen operationen mit dem
reaktionsschlüssel unnötig. das dashboard-passwort ist ein separates
step-up-zugangsmerkmal und wird nie in die datenbank, logs, den browserspeicher
oder die befehlszeile geschrieben. echte notfallarbeit als root läuft weiterhin
über die kurzlebige SSH-recovery-sitzung auf betreiberseite.

schlüsselbund-secrets gehören nicht zum datei-explorer. voller
festplattenzugriff entsperrt weder den anmelde- noch den iCloud-schlüsselbund
des benutzers, und plntir umgeht keine lokale macOS-abfrage `Allow Once`.

## Das Deployment-Bundle bauen

aus der repository-wurzel:

```sh
make check
make plntir-web
./scripts/build-plntir-web-bundle.sh /tmp/plntir-web-bundle
```

auf dem betreiber-host ein eigenes dashboard-zugangsmerkmal und ein privates
TLS-kit erzeugen. keine der beiden ausgaben gehört in git:

```sh
./scripts/generate-plntir-web-auth.sh /tmp/plntir-web-auth.json operator
./scripts/generate-plntir-web-tls.sh /tmp/plntir-web-tls 100.101.0.5
```

`plntir-web-ca.key` im verschlüsselten betreiber-tresor aufbewahren. nur das
bundle, das auth-JSON, das CA-zertifikat, das serverzertifikat und den privaten
serverschlüssel in ein nur für root zugängliches staging-verzeichnis auf dem
control-node kopieren.

## Auf dem Control-Node installieren

aus einer authentifizierten administratorsitzung auf dem control-node
ausführen:

```sh
sudo ./scripts/install-plntir-web-dashboard.sh \
  /root/staging/plntir-web-bundle \
  100.101.0.5 \
  /root/staging/plntir-web-ca.crt \
  /root/staging/plntir-web-server.crt \
  /root/staging/plntir-web-server.key \
  /root/staging/plntir-web-auth.json

sudo ./scripts/verify-plntir-web-dashboard.sh
```

`plntir-web-ca.crt` nur auf autorisierten betreibergeräten importieren und dann
öffnen:

```text
https://100.101.0.5:8443/
```

für diese IP-basierte version ist keine DNS-änderung nötig. cloudflare mesh
erlaubt einem registrierten client, einen dienst direkt auf einem mesh-node über
dessen mesh-IP zu erreichen. ein späterer privater hostname kann ohne
öffentliches DNS ergänzt werden, muss dann aber sowohl im TLS-zertifikat als
auch in `allowed_hosts` stehen.

für zusätzliche absicherung eine private cloudflare-access-anwendung mit
default-deny für die exakte mesh-IP und TCP/8443 anlegen, beschränkt auf den
betreiber und den geforderten gerätezustand. die lokale anmeldung bleibt auch
bei aktiviertem access erforderlich.

aktuelle cloudflare-referenzen:

- <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/self-hosted-private-app/>

## Datenzugriff auf Anforderung

- das öffnen des dashboards scannt `/Users` nicht.
- das entsperren kopiert keine inhalte automatisch. die dateiansicht listet
  jeweils nur eine verzeichnisebene auf, begrenzt auf 2.000 einträge.
- das öffnen einer regulären datei liefert höchstens 512 KiB für eine
  UTF-8-textvorschau im browser. binärdateien zeigen nur eine kurze
  hexadezimale signatur und bleiben für einen ausdrücklich ausgewählten export
  verfügbar. symlinks lassen sich weder anzeigen noch prüfen noch exportieren.
- eine größenprobe durchläuft nur den ausdrücklich gewählten pfad.
- ein ausgewählter export erzeugt pro gewähltem pfad ein geprüftes archiv,
  überträgt es zum control-node, prüft seinen SHA-256-digest und löscht die
  vorübergehende kopie auf dem mac.
- die safari-einsicht nutzt die backup-API von SQLite, um einen konsistenten,
  temporären, schreibgeschützten snapshot zu erzeugen, liefert nur den gewählten
  zeitraum und entfernt den temporären snapshot, bevor der befehl endet.
- exportjobs laufen nacheinander mit reduzierter CPU-priorität und begrenzen
  jede übertragung vom mac zum control-node auf 25 mbit/s. vor der übertragung
  hält der control-node den größeren wert aus 10 % der dateisystemkapazität oder
  10 GiB als freien speicher zurück.
- das dashboard meldet wartende, laufende, abgeschlossene, fehlgeschlagene und
  abgebrochene jobs, ohne die navigation zu blockieren. archiv-downloads werden
  direkt zum browser gestreamt, statt im webprozess gepuffert zu werden.
- audit-einträge enthalten aktionsmetadaten und gewählte pfade, nie passwörter
  oder safari-URLs.

den bereich für private daten unmittelbar nach einem vorgang sperren.
abgeschlossene archive bleiben auf dem control-node geschützt und erfordern für
auflistung oder download ein neues entsperren des privaten bereichs.

## Rollback

der installer legt kopien des zustands vor der änderung unter
`/var/backups/plntir/<UTC timestamp>-web-dashboard` ab. um die erreichbarkeit
zu beenden, ohne nachweise zu entfernen:

```sh
sudo systemctl disable --now plntir-web.service
```

der dienst hat keine öffentliche route. das entfernen der einzelnen
WARP-only-regel für TCP/8443 aus `/etc/nftables.conf` und ein neuladen von
nftables schließt auch den netzwerkweg. bei einer notabschaltung keine
monitoring-daten oder audit-einträge entfernen.
