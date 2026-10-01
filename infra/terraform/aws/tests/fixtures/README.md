# Terraform-Mock-Fixtures

`mock-public-ca.crt` ist ein kurzlebiges, selbstsigniertes **öffentliches**
Zertifikat, das nur vom lokalen Mock-Provider von Terraform verwendet wird. Sein
privater Schlüssel wurde nach der Erstellung des Zertifikats vernichtet. Die
Fixture ist kein Vertrauensanker für Deployments und darf nie von einer
Apply-Konfiguration referenziert werden.
