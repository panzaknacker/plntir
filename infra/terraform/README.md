# Plntir-Terraform-Roots

AWS und Cloudflare verwenden getrennte Roots und getrennte State-Objekte, um die
Kopplung von Zugangsdaten und Schadensradius zu verringern. Beide Roots stehen
standardmäßig auf `cloud_mutations_authorized = false`; ein gewöhnlicher Plan
enthält daher nur Review-Ausgaben und keine Cloud-Ressourcen.

Der AWS-Root steht außerdem standardmäßig auf `compute_strategy = "unselected"`.
Das ist eine harte Architektursperre: Neue Lightsail-OS-Instanzen erhalten kurz
die vom Provider vorgegebenen öffentlichen SSH-/HTTP-Regeln, während EC2 mit
einer leeren Security Group starten kann, aber ein anderes Kostenmodell hat.
Keine Compute-Ressource wird deklariert, bevor diese Wahl und ihr
aktualisierter Preisbericht freigegeben sind.

`compute_stack_enabled` bleibt standardmäßig false. Der Lightsail-Zweig erstellt
aus einem unmittelbar aktualisierten Katalog nur Kern, MDM, Edge und SIEM plus
das EC2-arm64-Relay. Weil der AWS-Provider eine leere Menge öffentlicher
Lightsail-Ports oder ein Peering zwischen Lightsail und Default-VPC nicht
abbilden kann, verwenden zwei gesperrte Abschlussschritte nach der Erstellung
die kurzlebige AWS-CLI-Sitzung. Der erste prüft alle vier exakten Namen gegen
den geschützten Watch-ARN und schließt jeden gefundenen offenen Port sofort nach
den Lightsail-Create-Aufrufen, ohne auf das Relay zu warten. Der zweite prüft,
dass die gewählte VPC die Default-VPC des Kontos ist, und richtet das Peering
erst ein, wenn das Relay existiert. Ein Fehler lässt das Apply fehlschlagen und
die Nodes unqualifiziert; das Skript öffnet nie einen Port.

Der alternative EC2-Zweig erstellt alle fünf Nodes in einer eigenen
Dual-Stack-VPC. Jede Instanz startet mit einer Security Group, deren
Ingress-Liste von Anfang an leer ist. Edge und Relay liegen in getrennten Zonen,
Root-gp3-Volumes sind verschlüsselt, IMDSv2 ist Pflicht, nur das Relay erhält
das SSM-Instanzprofil, und jeder Node verwendet einen eigenen, separat
übermittelten Ed25519-Key-Pair-Namen.

Diese Topologie ist absichtlich durch eine zweite Architektursperre blockiert.
Anders als die öffentliche Lightsail-Firewall lehnt eine leere EC2-Security-Group
auch private Verbindungen von Edge zu Kern, Relay zu SIEM und Agent zu SIEM ab.
Der vorgesehene SSM-Recovery-Weg über das Relay kann daher nicht allein dadurch
funktionieren, dass Lightsail durch EC2 ersetzt wird. Die Aktivierung dieses
Zweigs verlangt sowohl `ec2_zero_ingress_architecture_approved = true` als auch
den SHA-256 eines signierten Qualifikationsberichts für ein überarbeitetes
Design aus ausgehendem Transport pro Node, Bootstrap, Connector-Ausfall und
AWS-Recovery. Dieses Repository enthält noch kein solches Release und keinen
solchen Bericht; Dummy-Werte gibt es nur in Offline-Terraform-Tests. Die Wahl von
EC2 in einem echten Plan ohne diese Werte schlägt fail-closed fehl.

Die festen EC2-Größen sind Mindestentsprechungen, kein Versprechen, dass ihr
aktualisierter Preis in das Lightsail-Budget passt. Beide Zweige verlangen
SHA-256 und Zeitstempel eines geprüften Preis-/Katalogberichts, eine gewählte
Schätzung von höchstens 150 USD, einen signierten Release-Digest, den exakten
ARN der Permissions Boundary der Root-Bootstrap-Service-Rolle und eine frische
Markierung der unmittelbaren Freigabe. Der Preiszeitstempel wird beim Apply
erneut geprüft und läuft nach vier Stunden ab; ein späterer Bautag braucht daher
einen neuen Bericht, statt eine alte Schätzung wiederzuverwenden.

Die Wazuh-Integritätsebene ist ein dritter, unabhängig deaktivierter AWS-Stack.
Er installiert weder Wazuh noch erstellt er die SIEM-VM. Nachdem Wazuh
ausdrücklich als letzte VM-Stufe freigegeben ist, erstellt er einen eigenen
rotierenden KMS-Schlüssel, einen privaten versionierten S3-Bucket mit genau 90
Tagen Object-Lock-Aufbewahrung im Modus COMPLIANCE, ein verschlüsseltes
SNS-Topic und eine separate Roles-Anywhere-CA/-Profil/-Rolle für
`plntir-siem-01`. Die Laufzeitrolle darf nur unterhalb von `objects/` anhängen,
ihre unvollständigen Multipart-Uploads verwalten, an dieses eine Topic
veröffentlichen und KMS über genau diese S3-/SNS-Dienste nutzen. Sie hat keine
Berechtigung zum Lesen oder Löschen von Objekten, zur Bucket-Verwaltung oder
allgemeine AWS-Rechte.

Die Aktivierung verlangt die signierte Offline-Release-Bestätigung für Wazuh
4.14.7, den Hash ihres Bundles, eine signierte Qualifikation für
SIEM-Isolation und -Recovery, eine unmittelbar geprüfte VM-Gesamtsumme strikt
unter 150 USD, die Permissions Boundary der Service-Rolle, eine öffentliche
Roles-Anywhere-CA für das SIEM, den globalen Änderungsschalter und eine frische
Freigabemarkierung. Die eingecheckten Standardwerte erstellen nichts. Endpunkte
für E-Mail- und SMS-Abonnements bleiben bewusst außerhalb von Terraform, weil sie
in den gemeinsamen State gelangen würden und eine Bestätigung brauchen. Bis beide
Wege separat angelegt sind und unabhängig voneinander eine Testnachricht
zustellen, bleibt `wazuh_alert_routes_qualified` false und die Ausgabe darf
nicht als betriebliche Alarmierung gelten. Der tägliche Cloudflare-Hash-Anker
gehört ebenso zum signierten SIEM-Laufzeit-Release, nicht zu diesem AWS-Root.

Der Cloudflare-Root hat für diesen täglichen Anker einen separaten,
standardmäßig ausgeschalteten Speicherschalter. Er erstellt weder
Fileshare-Speicher noch eine Worker-Route, sondern einen eigenen R2-Bucket,
dessen Präfix `anchors/` für genau 180 Tage gesperrt ist, und verlangt den
Digest des qualifizierten Worker-Releases. Der eingecheckte Worker verlangt
zusätzlich von Cloudflare geprüftes mTLS, einen exakten SHA-256-Pin des
Leaf-Zertifikats und eine Ed25519-Signatur und schreibt dann mit
`If-None-Match: *` unter dem UTC-Datum als Schlüssel. Route, CA-Upload,
Zertifikatsweiterleitung und Worker-Deployment bleiben eine unmittelbare
Produktionsfreigabe; `wazuh_anchor_edge_qualified` muss false bleiben, bis die
vollständige externe Qualifikation für Schreiben, Lesen und Wiederholen
bestanden ist.

Nur mit einer Backend-Datei außerhalb von Git initialisieren:

```sh
terraform -chdir=infra/terraform/aws init -backend-config=/secure/aws-backend.hcl
terraform -chdir=infra/terraform/cloudflare init -backend-config=/secure/cloudflare-backend.hcl
```

Die Cloudflare-Authentifizierung muss aus einem kurzlebigen Umgebungswert
`CLOUDFLARE_API_TOKEN` kommen. Tunnel-Zugangsdaten werden separat abgerufen und
versiegelt; keine Datenquelle und keine Ausgabe für Tunnel-Tokens ist erlaubt.
Es gibt bewusst kein Apply-Skript. Jede Plan-Aktualisierung, jedes Apply,
Destroy und Import, jede State-Operation und jede Aktion der
Produktionsfreigabe ist ein eigener unmittelbarer Freigabeschritt.

Der Cloudflare-Access-Root hat zwei weitere Prüfungen zum Zeitpunkt der
Freigabe. Bevor `access_stack_enabled` etwas erstellen kann, muss geprüft sein,
dass die WARP-Enrollment-Policy nur freigegebene Enrollment-Methoden zulässt,
alle Bootstrap-Enrollment-Tokens bereits widerrufen sind und die unabhängige
Berechtigung für MFA per Hardwareschlüssel bestätigt ist. Terraform verwaltet
weder Access-Service-Tokens noch WARP-Enrollment-Secrets, weil deren erzeugte
Zugangsdaten in den State gelangen würden. Die verwalteten Posture-Checks für
WARP und Gateway sind beide Pflicht: WARP allein passt auch auf den
Consumer-Client, während Gateway den Client an die plntir-Zero-Trust-Organisation
bindet. Fileshare-Registrierung und Bindung von Plattform-Passkeys bleiben
separate Prüfungen der Kernanwendung.
