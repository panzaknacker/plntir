# Plntir-Scanner (Shadow-Build)

dieses paket ist im eingecheckten zustand bewusst nicht deploybar. die
wrangler-datei enthält platzhalter für kontoschlüssel, zertifikats-IDs und
broker-URLs. produktionswerte werden erst bei der produktionsfreigabe eingesetzt
und nie committet. `RESULT_SIGNING_KEY_PKCS8` ist ein wrangler-secret mit einem
privaten Ed25519-PKCS8-schlüssel; es fehlt absichtlich in `wrangler.jsonc` und
im state.

der R2-consumer prüft die signierten metadaten des unveränderlichen objekts,
erstellt dann einen idempotent benannten workflow und bestätigt die
queue-nachricht. der workflow streamt den ciphertext in einen eigenen container
ohne netzwerk. er holt über eine mTLS-bindung eine schlüsselumverpackung für
genau einen job vom AWS-KMS-broker und liefert ein Ed25519-signiertes,
jobgebundenes ergebnis über einen separaten mTLS-ergebnis-broker zurück.

der queue-handler wartet nie auf den scan. das ist für 500-GB-medien nötig:
queue-aufrufe haben ein zeitlimit von 15 minuten, während jeder workflow-schritt
für die dauer seiner ein-/ausgabe aktiv bleiben darf.

es gibt kein `deploy`-paketskript. das deployment und das anlegen der
R2-event-regel sind produktionsänderungen und erfordern die unmittelbare
freigabe.
