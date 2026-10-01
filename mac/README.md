# Deployment auf dem verwalteten Mac

plntir bietet richtliniengesteuerte, datenschutzfreundliche aufsicht über
KI-agenten-workflows. es kombiniert endpunkt- und netzwerkkontrollen, um die
angriffsfläche für prompt injection, malware, datenabfluss und neue bedrohungen
zu verringern.

die dateien in diesem verzeichnis spiegeln die derzeit eingesetzten helfer für
posture, telemetrie und export und ergänzen den vorbereiteten ersatz mit
minimalen rechten.

das zieldesign verwendet ein eigenes standardkonto, normalerweise 'macagent',
und zwei verschiedene SSH-schlüssel:

- monitoring-schlüssel: nur 'health-v1', 'posture-v1' und 'telemetry-v1';
- reaktionsschlüssel: status plus begrenzte export-, übertragungs- und
  löschvorgänge.

beide schlüssel sind auf die mesh-adresse des plntir-control-nodes beschränkt
und haben je schlüssel erzwungene befehle. der agent ist kein administrator.
exakte sudo-regeln erlauben nur die root-eigenen helfer; eine shell oder ein
allgemeiner befehlsausführer ist nicht erlaubt.

## Voraussetzungen für eine authentifizierte Administratorsitzung

1. ein standard-agentenkonto mit einem zufälligen, im tresor verwalteten
   passwort anlegen.
2. getrennte Ed25519-schlüsselpaare für monitoring und reaktion erzeugen.
   private schlüssel bleiben auf dem plntir-control-node; nur die öffentlichen
   schlüssel zum mac bringen.
3. eine authentifizierte administratorsitzung lokal oder über den
   plntir-recovery-SSH-weg offen halten.
4. den aktuellen schlüssel des plntir-control-nodes funktionsfähig lassen, bis
   die neuen schlüssel die entfernten tests bestehen.

aus der lokalen administratorsitzung installieren:

    sudo ./scripts/provision-plntir-endpoint.sh \
      /path/to/plntir \
      macagent \
      MANAGED_USER \
      LEGACY_SSH_USER \
      100.101.0.5 \
      /path/to/monitor.pub \
      /path/to/response.pub

dann ausführen:

    sudo ./scripts/verify-plntir-endpoint.sh \
      macagent MANAGED_USER LEGACY_SSH_USER

die vorbereitete SSH-policy schränkt das agentenkonto ein, behält aber bewusst
das bestehende SSH-konto als rollback-weg. alle neuen befehle vom
plntir-control-node aus testen, bevor die lokale sitzung geschlossen wird. der
provisioner sichert ersetzte dateien unter `/var/backups/plntir/<UTC timestamp>/`.

richtlinien zur festplattenverschlüsselung liegen außerhalb dieses
deployments. das herabstufen des menschlichen kontos oder das entfernen des
recovery-zugangs ist eine eigene änderung mit höherem risiko und darf nicht mit
einem update des endpunkt-agenten gebündelt werden.
