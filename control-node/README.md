# Deployment des plntir-Control-Nodes

Plntir bietet richtliniengesteuerte, datenschutzfreundliche Aufsicht über
KI-Agenten-Workflows. Es kombiniert Endpunkt- und Netzwerkkontrollen, um die
Angriffsfläche für Prompt Injection, Malware, Datenabfluss und neue Bedrohungen
zu verringern.

Dieses Verzeichnis ist die versionierte Quelle für Monitoring-Skripte und
systemd-Units, die für den Debian-basierten plntir-Control-Node bereitgestellt
werden.

Der sichere Dashboard-Weg verwendet ein eigenes Systemkonto 'macobserver'. SSH
zwingt jeden Schlüssel dieses Kontos durch 'plntir-observer-dispatch'; der
einzige akzeptierte Befehl ist `status-v2`. Der Observer kann den
Monitoring-Zustand über die Gruppe 'plntircontrol' lesen und hat zwei exakte,
rein lesende sudo-Berechtigungen:

- Die nftables-Input-Chain der Control Plane auflisten;
- Die letzten zwölf Journal-Einträge von 'plntir-endpoint-health' lesen.

Er kann keine Shell erhalten, kein TTY zuweisen und keine SSH-Weiterleitungen
anlegen.

Die optionale HTTPS-Betriebskonsole bindet nur an die exakte
Cloudflare-Mesh-IP des Control-Nodes und verwendet ein separates Dienstkonto
sowie einen festen Aktions-Dispatcher. Bauen, installieren und prüfen nach dem
[Runbook für das private Web-Dashboard](../docs/plntir-web-dashboard.md).

## Schrittweise Migration

Einen separaten Observer-Schlüssel im verschlüsselten Betreiber-Tresor erzeugen,
dann das Repository-Bundle und den öffentlichen Schlüssel auf den
plntir-Control-Node kopieren. Aus einer bestehenden Notfallsitzung ausführen:

    sudo ./scripts/provision-plntir-control-node.sh \
      /tmp/plntir \
      /tmp/plntir_observer_ed25519.pub

Ein optionales drittes Argument beschränkt den Schlüssel auf ein Quell-CIDR.
Diese Beschränkung erst setzen, wenn die WARP-Adresse des Betreibers stabil ist.

Lokal auf dem plntir-Control-Node prüfen:

    sudo ./scripts/verify-plntir-control-node.sh

Danach 'config/plntir-console.observer.example.json' von der
Betreiber-Workstation aus testen. Das alte Dashboard-Profil und den öffentlichen
SSH-Recovery-Weg behalten, bis sowohl Mesh-SSH als auch ein unabhängiger
Recovery-Weg über den Provider bestanden haben.

Der Provisioner schreibt Kopien des Zustands vor der Änderung nach
'/var/backups/plntir/<UTC timestamp>/'. Er entfernt den bestehenden
'admin'-Zugang nicht und schließt keine Firewall-Regel.

Die Installation dieses Bundles stellt den zweiten SSH-Hop vom
plntir-Control-Node zum Mac nicht um. Ohne `/etc/plntir/managed-endpoint.conf`
verwenden die Jobs das alte Konto und den alten Schlüssel.

## Den zweiten SSH-Hop umstellen

Nachdem eine authentifizierte Mac-Administratorsitzung die beiden erzwungenen
Schlüssel installiert und geprüft hat, deren private Hälften aus dem
verschlüsselten Tresor in ein nur für root zugängliches temporäres Verzeichnis
auf dem plntir-Control-Node kopieren. Aktivieren mit:

    sudo ./scripts/activate-plntir-endpoint-agent.sh \
      macagent \
      /Users/MANAGED_USER \
      100.101.0.2 \
      /root/staging/plntir_endpoint_monitor_ed25519 \
      /root/staging/plntir_endpoint_response_ed25519 \
      /root/staging/plntir_endpoint_known_hosts

Der Aktivator testet `health-v1`, `posture-v1` und `response-status-v1`, bevor
er die Transportkonfiguration schreibt. Danach führt er beide Collectoren aus
und stellt die vorherige Konfiguration wieder her, wenn eines der Ergebnisse
fehlschlägt. Private Schlüssel werden als 'admin:admin' mit Modus 0600
installiert; kein privater Schlüssel gehört in dieses Repository.

Nach der Aktivierung den Verifier erneut ausführen und eine begrenzte
Abrufprobe testen:

    sudo ./scripts/verify-plntir-control-node.sh
    sudo -u admin /opt/plntir/bin/plntir-endpoint-retrieve \
      --probe /Users/MANAGED_USER/TEST_PATH

Den alten Mac-Schlüssel und das alte Konto mindestens ein vollständiges
Monitoring-Intervall und einen erfolgreichen Zyklus aus Export, Übertragung,
Prüfsumme und Löschung lang behalten.
