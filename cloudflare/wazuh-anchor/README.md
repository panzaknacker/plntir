# Täglicher Wazuh-Hash-Anker (Shadow-Build)

Dieser isolierte Worker nimmt pro UTC-Tag genau einen kanonischen,
Ed25519-signierten Hash-Chain-Anker von `plntir-siem-01` an. Cloudflare muss
zuerst das Client-Zertifikat prüfen, und der Worker pinnt zusätzlich dessen
SHA-256-Fingerprint. Das Datum selbst ist der unveränderliche R2-Schlüssel; ein
bedingtes Put mit `If-None-Match: *` macht byteidentische Wiederholungen
idempotent und lehnt einen widersprüchlichen zweiten Anker ab. Die
Deduplizierungsidentität muss Datum und Sequenz exakt binden. Anfragen,
Lesezugriffe, Auflistungen, Löschungen, unsignierte Bodys, veraltete Bodys,
unbekannte Felder und nicht-kanonisches JSON werden nicht angeboten.

Die eingecheckte `wrangler.jsonc` enthält Platzhalter, hat keine Route,
deaktiviert `workers.dev` und Vorschau-URLs und hat kein Deploy-Skript. Ein
Produktionsrelease braucht weiterhin einen separaten, gesperrten R2-Bucket,
hochgeladene mTLS-CA-/Hostname-Einstellungen, den signierten öffentlichen
SIEM-Schlüssel, den exakten Fingerprint des Leaf-Zertifikats, den Relay-Pfad,
einen Nachweis der Aufbewahrung und ein unmittelbar freigegebenes
Wrangler-Deployment. Bis diese Qualifikation abgeschlossen ist, ist dies
getesteter Protokollcode, keine externe Recovery-Kopie.

Die Tests ohne Provider ausführen:

```sh
npm run check
```
