# Roadmap der plntir-Control-Plane

Stand vom 29.08.2026. Die derzeit laufenden Hosts verwenden noch die
bisherigen installierten Dienstnamen; die plntir-Migration ist lokal
vorbereitet und muss vor der Umstellung eine Prüfung mit Rollback-Möglichkeit
bestehen.

| Priorität | Befund | Aktueller Schutz | Nächster Schritt |
| --- | --- | --- | --- |
| P1 | Kein MDM | SIP, Gatekeeper, Firewall, Stealth-Modus, eingeschränktes SSH und ein Recovery-Administrator auf Anforderung | Gesondert entscheiden, ob Inventar und Policy-Verteilung den Einsatz der plntir-Geräteverwaltung rechtfertigen |
| P0 | Dem plntir-Control-Node fehlt Kapazität für ein vollständiges Archiv aller Benutzer | Die Bereitschaftsprüfung blockiert vor der Übertragung; kein Teilarchiv wird akzeptiert | Mindestens 281 GiB nutzbaren Spielraum ergänzen, bevorzugt ein größeres verschlüsseltes Archiv-Volume, dann die Planung wiederholen |
| P0 | Pfade und Dienste unter dem Namen plntir sind noch nicht live | Bestehender SSH- und Monitoring-Stack bleibt in Betrieb; ein Backup vor der Änderung existiert | Beide Migrationspakete testen, zuerst den Control-Node, dann den Mac migrieren und die Kompatibilität bis zum Ende der Beobachtungsphase erhalten |
| P1 | GUI-Support ist noch nicht auf Anforderung verfügbar | Bildschirmfreigabe lauscht nicht; SSH-Recovery funktioniert | Nach dem MDM-Enrollment `EnableRemoteDesktop` nur für freigegebene Zeitfenster nutzen und danach immer `DisableRemoteDesktop` senden |
| P1 | Das Betreiberkonto des Control-Nodes hat aus dem früheren Deployment noch weitreichendes unbeaufsichtigtes sudo | Eingeschränkter Observer-Schlüssel, Host-Firewall, fail2ban und Recovery über den Provider bleiben verfügbar | Routineaufgaben durch exakte Aliase ersetzen und das weitreichende Konto nur als zeitlich begrenzte Recovery behalten, bis MDM erprobt ist |
| P1 | Neustart und Paketwartung des Control-Nodes stehen noch aus | Automatische Updates und Zeitsynchronisation funktionieren | Backup anlegen, Provider-Konsole prüfen, patchen und in einem eigenen Zeitfenster neu starten |
| P2 | Noch keine richtliniengestützte Werkzeuggrenze für KI-Agenten | Bestehende Dispatcher verweigern beliebige entfernte Befehle und die Routine-Telemetrie schließt Prompt-Inhalte aus | Allowlists für signierte Werkzeuge, Freigabeschritte, DLP-/Egress-Policy und datenschutzfreundliche Workflow-Events ergänzen, sobald das MDM-Inventar stabil ist |
| P2 | Keine Alarmzustellung außerhalb des Hosts und kein auf Wiederherstellung getestetes Telemetrie-Backup | Lokales Journal plus verschlüsselter Archivablauf | Authentifizierte Alarmierung und verschlüsseltes externes Backup ergänzen, sobald Ziele und Aufbewahrung freigegeben sind |

## Vor der plntir-Migration geprüft

- `bootstrapadmin` ist ein Administrator mit aktiviertem Secure Token; sein
  Passwort liegt nur im Betreiber-Tresor und wird nie auf den Control-Node
  kopiert.
- `macagent` ist ein Standardkonto mit begrenzten Dispatchern für Monitoring,
  Reaktion und Export aller Benutzer.
- Die Exportbereitschaft erkennt alle drei aktuellen Home-Verzeichnisse. Die
  Quelle umfasst etwa 340 GiB, und das aktuelle Ziel wird vor der Übertragung
  blockiert, weil es nur etwa 143 GiB frei hat.
- Dem Organisations-CA von Cloudflare wird für die SSL-Policy vertraut, und
  eine echte HTTPS-Anfrage wurde mit dem Gateway-CA der Organisation als
  Aussteller beobachtet.
- Die Bildschirmfreigabe ist weder dauerhaft aktiv noch von außen erreichbar.

## In diesem Repository vorbereitet

- Plntir-Betriebskonsole (`plntirctl`) mit Status-Schema v2 und
  vorübergehender Lesekompatibilität für Schema v1;
- Plntir-Dienste auf dem Control-Node für Monitoring, Sicherheit,
  Archivbereitschaft und Observer;
- Plntir-Endpunkt-Agent-Helfer mit getrennten Monitoring- und
  Reaktionsschlüsseln;
- Exakte sudo-Aliase für root-eigene Collectoren statt beliebigem entferntem
  sudo;
- Atomare Umschaltung des Transports, Backups, Prüfung und Rollback;
- Blueprint für die plntir-Geräteverwaltung für `fleet.plntir.example` und
  `mdm.plntir.example` mit gepinnten Container-Images und schmalem öffentlichem
  Ingress;
- Ein ausdrückliches Sicherheits- und Datenschutzmodell für KI-Workflows.

## Reihenfolge der Umstellung

1. Statische Prüfungen und Pakettests lokal abschließen.
2. Neue Zugangsdaten-Aliase kopieren, ohne die derzeit funktionierenden Dateien
   zu löschen.
3. Den plntir-Control-Node migrieren und sowohl den neuen Observer-Weg als auch
   den bestehenden Recovery-Weg prüfen.
4. Das Mac-Paket in `/Users/Shared` bereitstellen, seinen einzigen Root-Runner
   ausführen und Anzeigenamen der Konten, SSH-Grenzen, Helfer und
   Rollback-Daten prüfen.
5. Mindestens ein vollständiges Gesundheits- und Sicherheitsintervall sowie eine
   begrenzte Abrufprobe durchführen; die alte Kompatibilität während der
   Beobachtungsphase erhalten.
6. Fleet deployen, APNs-Material erzeugen, die endgültige Apple-Server-URL
   setzen und die eine unvermeidbare lokale Freigabe des MDM-Profils
   durchführen.
7. GUI-Befehle auf Anforderung und Sicherheitsrichtlinien schrittweise
   ergänzen.

Keinen funktionierenden Recovery-Weg entfernen und die
Fleet-Administratoroberfläche nicht im Zuge der Umbenennung öffentlich machen.
Richtlinien zur Festplattenverschlüsselung liegen außerhalb dieser Roadmap.
