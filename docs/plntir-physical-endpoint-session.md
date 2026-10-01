# Authentifizierte Mac-Administratorsitzung

Dieses Runbook setzt das plntir-Sicherheitsmodell um: stabile technische
Kontonamen, eingeschränkte Befehle, datenschutzfreundliches Monitoring und ein
geprüfter Rollback, bevor ein alter Weg außer Betrieb genommen wird.

## Lokales Update mit einem Befehl

Ein Deployment-Archiv mit getrennten öffentlichen Monitoring- und
Reaktionsschlüsseln für den plntir-Control-Node bauen und die erzeugten Dateien
auf dem Mac nach `/Users/Shared/.plntir/inbox/platform-update` kopieren. Aus
einer authentifizierten lokalen Administratorsitzung oder einer
plntir-Recovery-SSH-Administratorsitzung ausführen:

    sudo /Users/Shared/.plntir/inbox/platform-update/run.sh

Der Root-Runner prüft Eigentümer und Rechte des Staging-Verzeichnisses, kopiert
das Archiv in ein nur für root zugängliches temporäres Verzeichnis, prüft seinen
gepinnten SHA-256 und führt erst dann den lokalen Installer aus.

Der kombinierte lokale Installer legt das versteckte Standardkonto `macagent`
an, falls es fehlt, installiert eingeschränkten Zugang für Monitoring,
Reaktion, Archiv und Recovery, behält den bestehenden SSH-Weg für einen
Rollback und schreibt den Gesamtfortschritt nach:

- `/Users/Shared/.plntir/results/platform-update/status.json`
- `/Users/Shared/.plntir/results/platform-update/install.log`

MDM-Enrollment, Festplattenverschlüsselung und macOS-Datenschutzfreigaben
gehören nicht zu diesem Update. Den plntir-Control-Node erst auf den
Dispatch-Transport umstellen, wenn der Status `success` ist und beide neuen
Schlüssel die Ende-zu-Ende-Tests bestehen.

Während der gesamten Änderung eine authentifizierte Administratorsitzung offen
halten. Am Mac muss außerdem der erwartete Benutzer an der Konsole angemeldet
sein; das ist eine Vorabprüfung, nicht der Ort, an dem die SSH-Passwortabfrage
erscheint. Ziel ist, den begrenzten Agenten-Transport zu installieren, nicht
alle Rollback-Wege auf einmal zu entfernen.

## Mitbringen, bevor der Mac ankommt

- Ein geprüftes Backup und seine Recovery-Zugangsdaten;
- Das Control-Plane-Bundle auf vertrauenswürdigen Wechselmedien;
- Zwei neue öffentliche Ed25519-Schlüssel: Monitoring und Reaktion;
- Das bestehende lokale Administratorpasswort aus dem verschlüsselten Tresor;
- Den endgültigen MDM-Hostnamen und das manuelle Enrollment-Profil, aber nur,
  wenn Fleet-Server, APNs-Zertifikat und Recovery-Ablauf ihre Tests bereits
  bestehen.

Private SSH-Schlüssel bleiben auf dem plntir-Control-Node oder im
verschlüsselten Tresor. Erzeugte `.mobileconfig`-Dateien sind sensibel und
gehören nicht in dieses Repository.

## Erster Besuch: sichere Änderungen

1. Strom und ein zuverlässiges Netzwerk anschließen. Die rein lesende Erfassung
   ausführen und die Ausgabe mit dem Änderungsprotokoll speichern:

       sudo ./scripts/plntir-endpoint-preflight.sh

2. Das obige Update mit einem Befehl ausführen. Es legt das versteckte
   Standardkonto `macagent` mit einem zufälligen Passwort an, bestätigt, dass es
   weder Administratorrechte noch einen Secure Token hat, installiert beide
   Forced-Command-Schlüssel und führt den lokalen Verifier aus. Prüfen, dass
   `results/status.json` `success` meldet.

3. Auf dem plntir-Control-Node 'activate-plntir-endpoint-agent.sh' ausführen.
   Danach ein Gesundheitsintervall, ein Sicherheitsintervall, eine Abrufprobe
   und einen kleinen Ende-zu-Ende-Export prüfen. Prüfsumme des Archivs und das
   Aufräumen auf der Gegenseite bestätigen.

4. Den lokalen Verifier erneut ausführen. Den alten Schlüssel und das alte
   SSH-Konto belassen, falls eine neue Prüfung nicht grün ist.

## Optionaler MDM-Schritt

Das manuelle MDM-Enrollment ist ein eigener Kontrollpunkt. Das Fleet-Profil erst
installieren, wenn die öffentlichen MDM-/SCEP-Endpunkte ohne interaktive
Web-Anmeldung funktionieren, Tests zur Ablehnung von Client-Zertifikaten
bestehen und Fleet-Backups existieren. Aktuelle MDM- und fleetd-Check-ins auf
dem Server bestätigen.

Richtlinien zur Festplattenverschlüsselung liegen außerhalb dieses Runbooks.
Die Einführung von MDM darf sie oder eine macOS-Datenschutzberechtigung nicht
stillschweigend ändern.

## Alten Zugang erst nach der Beobachtungsphase entfernen

Nach mindestens einem vollen Tag gesunden Monitorings und einem erfolgreichen
Recovery-Test nur die passende alte Schlüsselzeile des Control-Nodes aus dem
alten Konto sichern und entfernen. Dieses Konto aus `com.apple.access_ssh`
entfernen und seine alte sudo-Regel löschen. Das Konto selbst als physischen
Notfall-Administrator behalten.

Den täglichen menschlichen Benutzer herabzustufen, Secure Tokens zu ändern oder
die Volume-Owner-Recovery zu ändern ist ein eigener Vorgang mit höherem Risiko
und darf nicht mit diesem Update gebündelt werden.

Auf dem plntir-Control-Node öffentliches SSH behalten, bis die
Betreiber-Workstation eine getestete WARP-Route hat und der Weg über
Provider-Konsole/Recovery funktioniert. Danach die öffentliche Regel in einem
eigenen Änderungsfenster schließen.
