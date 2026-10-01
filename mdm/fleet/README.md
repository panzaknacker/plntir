# Fleet-MDM-Grenze für plntir v1

Dies ist ein Blueprint für ein Shadow-Deployment von `plntir-mdm-01`. Er
erstellt keine AWS-Instanz, veröffentlicht kein DNS, installiert keinen Tunnel,
lädt kein APNs-Material hoch und registriert kein Gerät. Der bestehende
Watch-Node und der Produktions-Mac werden nicht berührt.

Fleet ist auf `fleet-v4.89.2` gepinnt. Das geprüfte Upstream-Quellarchiv hat
den SHA-256
`1fb267b8a0b997b201bc833e13794d773c3dd75b5117101345219b63e1ff27e9`;
der Fleet-Container hat außerdem einen unveränderlichen Image-Digest in
`compose.yaml`. Eine Änderung eines dieser Werte erfordert eine neue, aus dem
Quellcode abgeleitete Routenprüfung, ein Datenbank-Backup, einen Migrationstest
und einen Rollback-Test.

## Netzwerkgrenze

Es gibt einen einzigen Hostnamen für Geräte: `mdm.plntir.example`. Weder
`fleet.plntir.example` noch `ops.plntir.example` wird in v1 verwendet.

Der Verkehr folgt diesem Weg:

```text
Apple MDM / fleetd
        |
Cloudflare edge (no interactive Access challenge)
        |
two outbound-only Tunnel connectors on edge and relay
        |
plntir-mdm-01 private IPv4:1338
        |
Plntir exact host/path/method proxy
        |
Fleet:8080
```

Die eingehenden AWS-Firewalls bleiben leer. Bevor Port 1338 an die private
Adresse des MDM-Nodes gebunden wird, muss `nftables` auf dem Host ihn nur von
den exakten privaten Adressen von `plntir-edge-01` und `plntir-relay-01`
zulassen. Die Beispielumgebung bindet ihn an `127.0.0.1`, sodass ein bloßer
Start von Compose nichts für einen anderen Host veröffentlicht.

Die rohe Fleet-Oberfläche ist ein separater Listener auf Port 1337. Ihr sicherer
Standard ist ebenfalls Loopback. Sie ist nie Ursprung eines Cloudflare-Tunnels.
Für ein freigegebenes Fenster zur Ersteinrichtung oder Recovery darf sie erst
an die private MDM-Adresse gebunden werden, wenn `nftables` diesen Port
ausschließlich vom per SSM verwalteten Relay zulässt; der Betreiber nutzt dann
AWS-FIDO und SSM-Portweiterleitung. Routineverwaltung gehört in typisierte
plntir-Aktionen, nicht in die rohe Fleet-Oberfläche.

## Exakter öffentlicher Vertrag

`public-routes-v4.89.2.json` ist die maßgebliche Quelle. Jeder Eintrag hält den
exakten Pfad, die HTTP-Methode, den Zweck und die geprüften Zeilen im
Fleet-Quellcode fest. Er enthält 15 Pfade und 17 Kombinationen aus Pfad und
Methode:

| Gruppe | Exakte Pfade |
| --- | --- |
| Apple-Enrollment/Check-in | `/mdm/apple/scep`, `/mdm/apple/mdm` |
| Per MDM ausgeliefertes fleetd | `/api/mdm/apple/installer` |
| Osquery-Kern | `/api/v1/osquery/enroll`, `/api/v1/osquery/config`, `/api/v1/osquery/distributed/read`, `/api/v1/osquery/distributed/write`, `/api/v1/osquery/log` |
| Orbit-Kern/Skripte | `/api/fleet/orbit/enroll`, `/api/fleet/orbit/ping`, `/api/fleet/orbit/config`, `/api/fleet/orbit/device_token`, `/api/fleet/orbit/device_mapping`, `/api/fleet/orbit/scripts/request`, `/api/fleet/orbit/scripts/result` |

`ingress_policy.py` prüft die Versionsbindung und erzeugt
`cloudflared.example.yml`. Jede Tunnelregel ist ein verankerter exakter
regulärer Ausdruck, und die letzten beiden Regeln liefern 404. Cloudflared
vergleicht Pfade, bietet aber nicht die Methodengrenze dieses Deployments; daher
prüft der kleine Go-Proxy zusätzlich den exakten Host und die Methode. Er lehnt
prozentkodierte Pfade, Punktsegmente, doppelte Schrägstriche, Präfix-/Suffix-Tricks,
unbekannte Hosts und alle nicht deklarierten Methoden ab, bevor Fleet die Anfrage
erhält. Query-Strings bleiben verfügbar, weil SCEP- und Installer-Aufrufe opake
Parameter brauchen; weder der Proxy noch seine Tests protokollieren sie.

Fleet selbst bleibt hinter dieser Routing-Schicht die Instanz für
Authentifizierung: SCEP-Challenge, Enrollment-/Orbit-Secrets, Node-Keys,
Installer-Token und Apple-Enrollment-Zertifikat bleiben Pflicht. Der Proxy
ersetzt diese Prüfungen nicht.

Die Grenztests ausführen:

```sh
make mdm-check
```

Die Suite prüft jede positive Route, repräsentative negative Routen, falsche
Methoden, Host-Verwechslung, kodierte Pfade, Abweichungen der erzeugten
Tunnelkonfiguration, Fehler bei verändertem Manifest und die Eigenschaft des
Proxys, keine Secrets aus Query-Strings zu protokollieren.

## In v1 absichtlich deaktiviert

Folgendes bleibt hinter der privaten Oberfläche oder ist gar nicht verfügbar:

- Fleet-Administrator-APIs und interaktive Seiten;
- ABM/ADE, kontobasiertes Enrollment, Service Discovery und OTA-Enrollment;
- Fleet Desktop und Geräteseiten für Endbenutzer;
- Softwareinstallation und Setup Experience;
- Von Fleet verwaltete Hinterlegung von FileVault-/Festplattenschlüsseln;
- File Carving und Auslieferung von YARA-Regeln.

Der osquery-Launcher von Fleet übergibt Carve-Endpunkt-Flags auch dann, wenn
kein Carve angefordert wird. Plntir stellt diese Endpunkte bewusst nicht bereit;
ein versuchtes File Carving schlägt daher fail-closed fehl. Die Aktivierung
einer deaktivierten Gruppe erfordert eine neue Feature-Sperre und ein
aktualisiertes exaktes Manifest, keine Wildcard-Route.

Das manuelle Enrollment-Profil wird über den privaten Administratorkanal
heruntergeladen, nicht über eine öffentliche Enrollment-URL. In Fleet 4.89.2
enthält dieses Profil die oben genannten SCEP- und MDM-Pfade. Nach dem
Enrollment wird die tokengebundene Installer-Route benötigt, damit Fleet-MDM
fleetd installieren kann.

## Begrenzter Compose-Stack

Der Stack enthält MySQL, Redis, Fleet, einen einmaligen Job zur Vorbereitung der
Datenbank, einen einmaligen Volume-Initialisierer und den plntir-Ingress-Proxy.
MySQL und Redis haben keine Host-Ports. Die Speichergrenzen zur Laufzeit
betragen 768 MiB für MySQL, 128 MiB für Redis, 640 MiB für Fleet und 64 MiB für
den Proxy; PID-Grenzen sind ebenfalls gesetzt. Der Proxy ist ein
schreibgeschütztes `scratch`-Image ohne root, bei dem alle Capabilities entfernt
sind. Sein Go-Build-Image ist auf den geprüften Manifest-Digest für linux/AMD64
gepinnt, und sein Docker-Build führt Unit-Tests aus, bevor das Binary entsteht.

Die Beispielumgebung an einen nur für root zugänglichen Ort kopieren und beide
Bind-Adressen für privates Staging auf Loopback lassen:

```sh
sudo install -d -m 0700 /etc/plntir/fleet
sudo install -m 0600 mdm/fleet/fleet.env.example /etc/plntir/fleet/fleet.env
docker compose --env-file /etc/plntir/fleet/fleet.env \
  -f mdm/fleet/compose.yaml config --quiet
docker compose --env-file /etc/plntir/fleet/fleet.env \
  -f mdm/fleet/compose.yaml build --pull ingress
```

Ohne die unmittelbare Deployment-Freigabe, die der v1-Plan verlangt, weder `up`
ausführen noch eine Bind-Adresse ändern oder den Tunnel veröffentlichen.

## Freigabeschritte

Bevor das erste Wegwerf-iPhone diesen Stack erreicht, muss all dies bestanden
sein:

1. Aktuelle Kostenprüfungen für AWS, Cloudflare und VMs bleiben innerhalb der
   freigegebenen Budgets.
2. Die Entscheidung zur vorübergehenden Standard-Firewall von Lightsail ist
   ausdrücklich getroffen.
3. Die privaten Adressen von `plntir-mdm-01`, Edge und Relay stehen fest, und
   die Host-Firewall wurde über IPv4 und IPv6 negativ gescannt.
4. Beide Tunnel-Connectoren validieren die erzeugte Routendatei; der Ausfall
   eines Connectors unterbricht den Geräteverkehr nicht.
5. MySQL- und APNs-Backups sind verschlüsselt und auf Wiederherstellung
   getestet.
6. Ein eigenes Apple-Konto besitzt das APNs-Zertifikat, und Ablaufwarnungen
   nach 60/30/14/7 Tagen sind aktiv.
7. Fleet-Setup und der Download des manuellen Profils funktionieren über den
   privaten Admin-Weg; keine öffentliche Route außerhalb der Maschinenrouten
   antwortet.
8. Abläufe für SCEP, MDM, Installer, Orbit, osquery und begrenzte Testskripte
   bestehen auf einem frischen Testgerät, einschließlich Tests mit fehlender,
   ungültiger und wiederholter Identität.

Der Produktions-Mac wird erst registriert, nachdem der Pilot mit dem
Wegwerf-iPhone bestanden ist und der Benutzer die nächste ausdrückliche Freigabe
erteilt. Kein bestehendes Gerät wird für die Registrierung gelöscht, und die
Fernlöschung bleibt `unverified`, bis nachgewiesen ist, dass die tatsächliche
Enrollment-Art sie unterstützt.
