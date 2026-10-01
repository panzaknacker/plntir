# Wazuh-Integritätsprotokoll (inaktive Shadow-Komponente)

Dieses Paket implementiert das unabhängig testbare Protokoll zwischen dem
künftigen `plntir-siem-01`, AWS, dem Kern und Cloudflare. Es ist reiner
Bibliothekscode: Mit den eingecheckten Standardwerten wird kein Dienst
installiert, keine Wazuh-Konfiguration bearbeitet und kein Netzwerkendpunkt
aktiviert.

Für jeden angenommenen Wazuh-JSON-Alert behält das Paket das vollständige
Rohdokument nur innerhalb eines kanonischen SHA-256-Hash-Chain-Eintrags. Das
lokale Journal schreibt Eintrag und Zustand mit fsync/atomarer Veröffentlichung,
lehnt doppelte JSON-Schlüssel und Symlinks ab und hält Archiv-, SNS- und
Kern-Zustellung unabhängig voneinander fest. Ein Ausfall des Kerns stoppt daher
weder die S3-Object-Lock-Archivierung noch kritische SNS-Alerts. Das
unvermeidbare Absturzfenster zwischen einer externen SNS-Annahme und ihrer
lokalen Quittung bedeutet, dass Alerts mindestens einmal zugestellt werden;
jede Nachricht trägt den stabilen Event-Hash.

Der AWS-Adapter akzeptiert nur die exakte Bindung an Konto, Bucket, KMS und
Topic in Frankfurt, kurzlebige `ProcessProvider`-Sitzungen und einen
ausdrücklich angegebenen privaten Relay-IPv4-Proxy auf Port 3128. Statische,
Umgebungs-, Container- und IMDS-Zugangsdatenquellen werden abgelehnt. S3-Puts
sind bedingt, per Prüfsumme bestätigt, an den kanonischen Eintrag gebunden und
KMS-verschlüsselt. SNS erhält nur Event-Hash, Zeit, numerische Regel- und
Agentenkennungen, Level und Schweregrad, aber niemals den Roh-Alert.

Der Kern nimmt eine separate, signierte Gesundheitsprojektion genau unter
`/internal/v1/wazuh/health` an. Der Handler verlangt eine bereits geprüfte
mTLS-Kette plus den exakten SHA-256-Fingerprint des Leaf-Zertifikats,
kanonisches JSON, eine Ed25519-Signatur, ein begrenztes Replay-Fenster, eine
lückenlose Sequenz und eine neue Deduplizierungs-ID. SQLite speichert nur die
letzte bereinigte Projektion und ihr generisches Envelope-Ledger. Dieser
Handler ist nicht am öffentlichen Listener des Kerns eingebunden.

Der tägliche Cloudflare-Anker wird vor der Übertragung dauerhaft vorbereitet,
sodass eine verlorene HTTP-Antwort zu einer byteidentischen Wiederholung führt.
Der Worker akzeptiert pro UTC-Datum einen per Cloudflare-mTLS geprüften und
Ed25519-signierten Wert und schreibt ihn bedingt in ein separates, für 180 Tage
gesperrtes R2-Präfix.

Bevor daraus ein signierter Laufzeitdienst werden kann, muss die gepinnte
Alert-Quelle Wazuh 4.14.7 einen Qualifikationskorpus bestehen, der mindestens
Folgendes abdeckt:

- Level-16-, korrelierte, lange (bis zur lokalen Grenze von einem MiB),
  Unicode-, fehlerhafte und Alerts mit doppelten Schlüsseln;
- Neustart von Manager/Integrator, Inode-Ersetzung, tägliche Rotation,
  vorübergehender Netzwerkverlust und eine verlorene HTTP-Antwort;
- Ausfälle von Kern und Cloudflare, während S3/SNS weiterlaufen, danach
  geordnetes Replay;
- Exakter Egress nur über das Relay, Roles-Anywhere-Erneuerung,
  SNS-Zustellung per E-Mail/SMS, S3-Aufbewahrung sowie Offline-Restore und
  Kettenprüfung.

Relevante Upstream-Referenzen sind die
[Wazuh-Dokumentation zum Alert-Management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html),
die [Hinweise zum Server-Forwarder](https://documentation.wazuh.com/current/integrations-guide/index.html)
und der derzeit offene
[4.14.x-integratord-Bericht](https://github.com/wazuh/wazuh/issues/35834).
Bis die signierte Laufzeit und dieser Qualifikationsbericht vorliegen, verlangt
die Ansible-Rolle leere Platzhalterwerte und bleibt fail-closed.
