# KMS-Scan-Broker

Dieser Lambda-Handler akzeptiert nur die API-Gateway-v2-Route `POST /v1/rewrap`.
API Gateway muss eine regionale Custom Domain mit mTLS-Truststore verwenden und
der einzige Principal sein, der die Funktion aufrufen darf. Der Handler pinnt
zusätzlich den SHA-256 des Leaf-Client-Zertifikats, die API-ID und die Domain.

Er prüft die Ed25519-Signatur des Kerns über die unveränderlichen
R2-Objektmetadaten, bevor er KMS aufruft. Der ursprüngliche Datei-DEK muss mit
genau diesem Verschlüsselungskontext erzeugt worden sein:

```text
plntir-purpose=file-dek
plntir-file-version-id=<opaque fver id>
plntir-object-key=<opaque R2 object key>
```

Der entschlüsselte 32-Byte-DEK wird sofort mit HKDF-SHA-256 und AES-256-GCM
für den einmaligen X25519-Public-Key des Scanner-Containers neu verpackt. Er
erscheint nie in einem Log oder einer Antwort. Die eingecheckte Konfiguration
enthält keine deploybaren Werte; Zertifikatsausstellung, API Gateway,
KMS-Policy, Lambda-Rolle und alle Umgebungswerte bleiben Sperren bis zur
Produktionsfreigabe.
