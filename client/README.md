# Plntirctl-Terminal-Dashboard

Plntir bietet richtliniengesteuerte, datenschutzfreundliche Aufsicht über
KI-Agenten-Workflows. Es kombiniert Endpunkt- und Netzwerkkontrollen, um die
Angriffsfläche für Prompt Injection, Malware, Datenabfluss und neue Bedrohungen
zu verringern.

`plntirctl` ist ein lokales, schreibgeschütztes Terminal-Dashboard für die
plntir-Control-Plane für sichere Agenten. Es läuft auf der
Betreiber-Workstation und führt über die bestehende SSH-Verbindung zum
plntir-Control-Node einen festgelegten Status-Collector aus.

Es installiert keinen Daemon, öffnet keinen Port und ändert keine Konfiguration,
weder auf dem plntir-Control-Node noch auf dem verwalteten Mac. Die Timer des
Control-Nodes laufen unabhängig weiter, wenn das Dashboard geschlossen ist.

## Bauen und prüfen

Aus dem Verzeichnis `plntir`:

```sh
make check
make plntirctl
./bin/plntirctl doctor
```

Das Binary verwendet `config/plntir-console.json`. Diese Datei enthält nur
Verbindungsmetadaten und Pfade, niemals private Schlüssel. Relative Pfade zu
Schlüsseln und `known_hosts` werden relativ zur Konfigurationsdatei aufgelöst.

## Verwendung

Das fortlaufend aktualisierte Dashboard starten:

```sh
./bin/plntirctl dashboard
```

Einen offline befindlichen Mac während des Transports als erwartet markieren:

```sh
./bin/plntirctl dashboard --offline-reason Transport
```

Einen einzelnen lesbaren oder JSON-Snapshot abrufen:

```sh
./bin/plntirctl status
./bin/plntirctl status --json
```

Ein schmaleres, gestapeltes Layout verwenden:

```sh
./bin/plntirctl dashboard --width 90
```

Das Dashboard mit `Ctrl+C` beenden.

## Öffentliche und Mesh-Verbindungsprofile

Die mitgelieferten öffentlichen bzw. alten Verbindungsprofile verwenden
`192.0.2.10`, eine Dokumentationsadresse nach RFC 5737, statt des echten
Bootstrap-Hosts eines Betreibers. Sie sind Beispiele, kein funktionierendes
Verbindungsprofil. Vor der Verwendung des Operator-Clients ein separates lokales
Profil mit dem vorgesehenen Host und seinem unabhängig geprüften Hostkey
einrichten. Sobald die Betreiber-Workstation im Cloudflare-Mesh registriert
und der Hostkey des Control-Nodes für seine Mesh-Adresse gepinnt ist, lässt sich
das vorhandene Referenz-Mesh-Profil so auswählen:

```sh
./bin/plntirctl dashboard --host 100.101.0.5
```

Die öffentliche Lightsail-SSH-Regel erst schließen, nachdem dieser Weg und ein
separater Notfallzugang beide getestet wurden.

## Sicherheitseigenschaften

- Die OpenSSH-Hostkey-Prüfung ist strikt; `accept-new` wird nie verwendet.
- Passwort- und Keyboard-Interactive-Authentifizierung sind deaktiviert.
- Agent-Forwarding, lokale Befehle, TTY-Zuweisung und jegliches SSH-Forwarding
  sind deaktiviert.
- Der private Schlüssel muss Modus `0600` oder strenger haben.
- Entfernter Statustext wird vor der Anzeige von Terminal- und
  Bidi-Steuerzeichen bereinigt.
- Die Collector-Ausgabe ist auf 1 MiB begrenzt, und jede Abfrage hat ein festes
  Timeout.
- Das festgelegte entfernte Skript nutzt nur Leseoperationen. Seine einzige
  `sudo`-Operation ist `nft list chain`, um zu melden, ob öffentliches SSH noch
  erreichbar ist.

Das bevorzugte Profil authentifiziert sich als Dienstkonto `macobserver` ohne
Shell und erlaubt nur `status-v2`. Das alte Administratorprofil bleibt
ausschließlich als vorübergehender Migrations- und Recovery-Weg verfügbar.
