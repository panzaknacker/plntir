# TLS-Inspektion über Cloudflare Gateway auf dem Mac

dies ist ein zweiteiliger freigabeschritt. der mac muss dem
organisationsspezifischen gateway-CA vertrauen, und cloudflare gateway muss die
HTTPS-inspektion für den verkehr des geräts aktiviert haben. die installation
eines öffentlichen cloudflare-web-CAs ersetzt den organisations-CA nicht.

## Aktuelles Mac-Zertifikat

der cloudflare-one-client hat auf diesem mac folgendes zertifikat installiert:

- common name: `Gateway CA - Cloudflare Managed G1 <ORGANISATIONS-ID>`
- SHA-256: `<SHA256-DES-ORGANISATIONS-CA>`
- quelle: `/Library/Application Support/Cloudflare/installed_certs/<ZERTIFIKATS-ID>.pem`

das lokale paket pinnt alle drei werte und beschränkt die ausdrückliche
vertrauenseinstellung auf die SSL-/TLS-policy. aus der physischen
administratorsitzung ausführen:

```sh
sudo /Users/Shared/.plntir/inbox/cloudflare-ca-trust/run.sh
```

die ergebnisse werden nach
`/Users/Shared/.plntir/results/cloudflare-ca-trust/status.json` und
`install.log` geschrieben. ein erfolgreicher status mit `trusted_for_tls: true`
belegt, dass die mac-seite bereit ist. `tls_inspection_observed: false` bedeutet,
dass die cloudflare-policy-seite noch ausgeschaltet ist, nicht auf dieses gerät
angewendet wird oder durch eine do-not-inspect-regel ausgenommen ist.

## Freigabeschritt für die Cloudflare-Policy

in zero trust zunächst für einen kleinen testbereich **traffic policies >
traffic settings > proxy and inspection > inspect HTTPS requests with TLS
decryption** aktivieren. bestätigen, dass der aussteller des echten
leaf-zertifikats der gateway-CA der organisation ist und normales HTTPS weiter
funktioniert, bevor der bereich erweitert wird.

do-not-inspect-regeln für anwendungen mit zertifikats-pinning, dienste mit
gegenseitigem TLS, apple-verwaltungs-/push-verkehr und die endgültigen
fleet-MDM-endpunkte anlegen. TLS-inspektion darf keine voraussetzung für
MDM-check-in, SCEP, APNs oder einen recovery-weg werden.

später sollte MDM denselben organisations-CA ausrollen und ihm vertrauen, damit
die einstellung reproduzierbar ist. kein anderes root-zertifikat für das
MDM-profil erzeugen.
