# Plntir-v1-Host-Härtung

Dieses Ansible-Verzeichnis ist nur für die fünf neuen Ubuntu-24.04-Nodes
bestimmt. Sein Standardinventar enthält null Hosts, beide Freigabeschalter für
Check und Apply stehen auf false, und der aktive Watch-ARN ist ein
ausdrücklich verbotenes Ziel. Es gibt keinen Apply-Wrapper. Nichts davon wurde
gegen AWS ausgeführt.

Die Baseline bietet:

- Serielle Ausführung, jeweils ein Node, gebunden an exakten Hostnamen,
  Betriebssystem, Architektur, Rolle, AWS-Ressourcen-ARN, Hash des signierten
  Releases und eine frische Freigabereferenz;
- SSH ohne root mit Public-Key-Authentifizierung, optionalen kurzlebigen
  Zertifikaten einer Ed25519-User-CA, ohne Passwort-/Root-Login und ohne
  Weiterleitungen;
- Dauerhafte, begrenzte Journale, Audit-Regeln, unterdrückte Core-Dumps,
  Timer für Sicherheitsupdates ohne automatischen Neustart, AppArmor und
  konservative sysctl-Werte;
- Eine Tabelle `inet plntir_filter` mit Default-Drop für Input- und
  Forward-Chains, exakten Quelladressen für jeden Dienst und dem nötigen
  IPv6-Steuerverkehr;
- Docker-Härtung nur auf dem MDM-Node, darunter deaktivierte Kommunikation
  zwischen Containern auf der Standard-Bridge, begrenzte Logs, kein
  Userland-Proxy und standardmäßig no-new-privileges.

Die Firewall verwendet nie `flush ruleset`; Docker und andere Komponenten
behalten ihre eigenen Tabellen. Von Docker veröffentlichte MDM-Ports sind
sowohl im Input- als auch im Pre-Docker-Forward-Hook abgedeckt, einschließlich
des ursprünglich veröffentlichten Ports nach DNAT. Port 1337 akzeptiert nur die
Relay-Quelle und Port 1338 nur die beiden Tunnel-Connector-Quellen. Der
Wazuh-Agent-Enrollment-Port 1515 wird von der Baseline nicht geöffnet.

Das MDM-Compose-Projekt vergibt drei feste Namen für Linux-Bridges. Die beiden
Netzwerke mit `internal: true` dürfen nur innerhalb ihrer eigenen Bridge
weiterleiten. Die Egress-Bridge von Fleet darf nur an das exakte physische
Interface weiterleiten, das im Host-Inventar angegeben ist; sie kann keine der
internen Bridges erreichen. Unbekannte Docker-Bridges und die Standard-Bridge
erhalten keine pauschale Forward-Ausnahme. `REPLACE_MDM_PRIMARY_INTERFACE`
schon vor einem Lauf im Check-Modus durch den beobachteten Interface-Namen
ersetzen.

Die ausgehende Policy bleibt auf den allgemeinen Nodes auf accept, weil
Paketspiegel, APNs, Cloudflare Tunnel, AWS-APIs und Endpunkte für signierte
Updates dynamische Adressen haben. Das wird nicht als Egress-Allowlist
bezeichnet. Beim SIEM ist es anders: Seine Output-Policy ist Default-Drop und
erlaubt nur TCP 3128 (HTTPS-CONNECT-Proxy), TCP 2525 (unabhängiges SMTP-Relay)
und UDP 123 (Zeit) zu genau einer privaten Relay-IPv4-Adresse.

Die Rolle `wazuh_isolated` ist vorhanden, aber unabhängig von der allgemeinen
Host-Baseline deaktiviert. Sie prüft ein kanonisches, Ed25519-signiertes
Manifest zweimal, bindet Installer, Offline-Paketbündel und erzeugte
Installationsdateien an ihre exakten Hashes, installiert Wazuh 4.14.7 nur mit
`--offline-installation` und prüft alle vier lokalen Dienste sowie die
Output-Firewall des SIEM. Sie kann erst laufen, wenn eigene Freigaben für
Release, Budget, Roles Anywhere, E-Mail/SMS, geschlossenes Enrollment,
signierte Integritätslaufzeit und Alert-Ingest vorliegen.

Der Ingest-Nachweis ist bewusst ausdrücklich. Die aktuelle Wazuh-Dokumentation
beschreibt einen Forwarder auf demselben Host, der
`/var/ossec/logs/alerts/alerts.json` liest, während offene 4.14.x-Berichte
lange Alerts, korrelierte Alerts und das Verhalten bei Rotation und Neustart in
`integratord` betreffen. Die Qualifikation muss diese Fälle mit den exakt
gepinnten Paketen durchspielen; ein ungetesteter eigener Hook wird von dieser
Rolle nicht installiert.

Die Offline-Validierung braucht nur Python, PyYAML und Jinja2:

```sh
./infra/ansible/validate.sh
```

Wenn Ansible oder nftables lokal verfügbar sind, ergänzt der Validator deren
Syntaxprüfungen. Das mitgelieferte Inventar bleibt leer. Nach freigegebener
Erstellung der Compute-Ressourcen `inventory/hosts.example.yml` in die von Git
ignorierte `inventory/hosts.yml` kopieren, jeden Platzhalter durch exakte
private Adressen und ARNs ersetzen und über einen separaten Kanal ein
kurzlebiges SSH-Zertifikat oder einen SSM-Weg beschaffen.

Selbst der Check-Modus ist gesperrt, weil er sich mit echten Maschinen
verbindet und deren Zustand erfasst. Ein künftiger freigegebener Aufruf hat
diese Form; das ist Dokumentation, keine Erlaubnis zur Ausführung:

```sh
ANSIBLE_CONFIG=infra/ansible/ansible.cfg \
ansible-playbook -i infra/ansible/inventory/hosts.yml \
  --check --diff infra/ansible/site.yml \
  -e plntir_check_mode_authorized=true \
  -e plntir_immediate_approval_reference=approved-YYYYMMDDTHHMMSSZ-ticket \
  -e plntir_release_id=sha256:REPLACE
```

Ein Apply ändert den ersten Schalter auf `plntir_deployment_authorized=true` und
lässt `--check` weg; es braucht eine neue unmittelbare Freigabereferenz. Der
Bootstrap-Zugang `ubuntu` bleibt in `AllowUsers`, bis Cloudflare-Zertifikats-SSH,
SSM-Recovery, Hostkey-Pins und Rollback jeweils getestet sind. Seine Entfernung
gehört zur separaten Produktionsfreigabe, nie zu diesem Baseline-Lauf.
