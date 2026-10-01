# Plntir-Sicherheitsmodell

Plntir bietet richtliniengesteuerte, datenschutzfreundliche Aufsicht über
KI-Agenten-Workflows. Es kombiniert Endpunkt- und Netzwerkkontrollen, um die
Angriffsfläche für Prompt Injection, Malware, Datenabfluss und neue Bedrohungen
zu verringern.

*Sichere Agenten-Workflows. Datenschutzfreundliche Aufsicht. Belastbare
Endpunkt- und Netzwerkkontrolle.*

## Grenzen der Aussagen

Plntir ist ein mehrschichtiges System zur Risikominderung und Reaktion. Es
behauptet nicht, einen Endpunkt immun gegen Prompt Injection, Malware oder
unbekannte Schwachstellen zu machen. Kein Endpunkt- oder Netzwerkprodukt kann
das garantieren. Das Design begrenzt stattdessen Berechtigungen, schränkt
Werkzeugausführung und ausgehenden Verkehr ein, zeichnet einen überprüfbaren
Sicherheitszustand auf, erkennt verdächtige Änderungen und erhält
Recovery-Wege.

Marketing- und Betreiberoberflächen dürfen eine Kontrolle erst als aktiv
beschreiben, wenn die zugehörige Host- und Ende-zu-Ende-Prüfung grün ist.
Geplante Kontrollen müssen als geplant gekennzeichnet bleiben.

## Aktive Kontrollen vor MDM

- Der plntir-Control-Node ist von nicht vertrauenswürdigen Workloads getrennt
  und bietet keinen allgemeinen Befehlsausführer für Agenten an.
- SSH-Identitäten sind gepinnt und Rollen getrennt. Monitoring- und
  Reaktionsschlüssel sind auf feste Dispatcher beschränkt; exakte sudo-Aliase
  ersetzen pauschalen unbeaufsichtigten Root-Zugriff.
- Gesundheit und Sicherheitszustand des Endpunkts werden ohne routinemäßige
  Prompt- oder Dokumentinhalte erfasst. Terminal-Steuerzeichen und
  Bidi-Zeichen werden bereinigt, bevor entfernte Daten die Betreiberkonsole
  erreichen.
- Das sichere plntir-Archiv deckt den festen Bereich `/Users` nur ab, wenn es
  ausdrücklich gestartet wird. Es prüft zuerst Lesbarkeit und Zielkapazität,
  komprimiert, verschlüsselt und hasht dann und protokolliert die Übertragung.
- Der Organisations-CA von Cloudflare wird auf dem verwalteten Mac nur dort für
  TLS-Inspektion vertraut, wo die Gateway-Policy greift. Das verbessert die
  Netzwerksichtbarkeit, macht inspizierte Inhalte aber nicht an sich sicher.
- Interaktiver grafischer Zugriff ist nicht dauerhaft offen. Das Zieldesign
  aktiviert ihn über MDM für ein freigegebenes Supportfenster und deaktiviert
  ihn nach der Sitzung.

## Geplante MDM- und KI-Workflow-Kontrollen

| Bedrohung | Geplante plntir-Kontrolle | Wichtige Einschränkung |
| --- | --- | --- |
| Prompt Injection und unsichere Werkzeuganweisungen | Werkzeug-Allowlists, Agentenidentitäten mit minimalen Rechten, Freigabeschritte für folgenreiche Aktionen und Policy-Events rund um Tool-Aufrufe | Inhaltsklassifikation kann neuartige oder verschleierte Angriffe übersehen; bei irreversiblen Aktionen bleibt menschliche Freigabe nötig |
| Malware und schädliche Downloads | Gateway-Inspektion, Reputations-Policy, Regeln für signierte/notarisierte Software, Endpunkt-Telemetrie, Scans, Quarantäne und schnelle Netzwerkisolierung | TLS-Inspektion und Signaturen erkennen nicht jede unbekannte Nutzlast |
| Datenabfluss | Ziel-Allowlists, DLP-Regeln, begrenzter Dateizugriff, ausdrückliche Archivabläufe und geschwärzte/pseudonyme Betriebstelemetrie | Vollständige Recovery-Archive enthalten absichtlich Benutzerdateien und brauchen daher strikte Verschlüsselung und Zugriffskontrolle |
| Zero-Day- und neue Bedrohungen | Schnelles Inventar, Patch-Policy, Konfigurations-Baselines, Verhaltensalarme, Fernisolierung und dokumentierte Recovery | Ein Zero-Day kann ausgeführt werden, bevor eine Signatur oder Policy existiert |
| Kompromittierte Automatisierung | Getrennte Monitoring-/Reaktions-Zugangsdaten, signierte Deployment-Artefakte, Befehlsgrenzen, Audit-Logs und Rotation von Zugangsdaten | Langlebige Zugangsdaten brauchen weiterhin Rotation und Incident Response |

Die erste MDM-Policy-Gruppe wird Inventar, signierte Konfigurationsprofile,
PPPC-Freigaben für die endgültige Helper-Identität, Remote Desktop nach Bedarf,
den Stand der Betriebssystem-Updates und begrenzte Skriptausführung einrichten.
Santa oder eine gleichwertige Ebene für Ausführungsrichtlinien kommt erst hinzu,
nachdem ihre Regeln und ihr Rollback-Weg an einem Pilotgerät getestet wurden.

## Regeln für Datenschutz und Anonymisierung

- Keine Prompt-Inhalte, Zwischenablage, Nachrichtentexte, Browserinhalte oder
  Benutzerdokumente als routinemäßige Monitoring-Daten erfassen.
- Stabile pseudonyme Geräte- und Workflow-Kennungen gegenüber Personennamen
  bevorzugen. Die Zuordnung der Identitäten im zugriffsgeschützten
  Verwaltungssystem halten, nicht in allgemeinen Logs.
- Nur die Felder erfassen, die nötig sind, um einen Policy-Zustand
  nachzuweisen, ein Ereignis zu untersuchen oder eine ausdrücklich genehmigte
  Recovery auszuführen.
- Für Telemetrie und Archive Aufbewahrungsgrenzen und authentifizierte
  Löschung anwenden.
- Pseudonymisierte Daten nie als anonym bezeichnen, wenn ein autorisierter
  Betreiber sie einem Gerät oder Benutzer zuordnen kann.

## Administrative Identitäten

Technische Kurznamen bleiben stabil, damit macOS-Secure-Token, Berechtigungen,
SSH-Einschränkungen und Automatisierung nicht brechen:

- `bootstrapadmin`: Anzeigename **plntir recovery administrator**
- `macagent`: Anzeigename **plntir endpoint agent**
- `macobserver`: Anzeigename **plntir observer service**

Passwörter und private Schlüssel bleiben im verschlüsselten Betreiber-Tresor.
Plntir legt das Passwort des Recovery-Administrators weder im Quellcode noch in
Deployment-Paketen, entfernten Befehlen oder auf dem Control-Node ab.
