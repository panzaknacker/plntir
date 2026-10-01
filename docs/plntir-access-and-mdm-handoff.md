# Zugangs-Upgrade und Übergabe an MDM

diese phase richtet kontrollierten zugang vor MDM ein, ohne eines der
SSH-konten zu einem uneingeschränkten, unbeaufsichtigten administrator zu
machen.

## Zugangsrollen

| rolle | ort der zugangsdaten | mac-konto | erlaubte aktion |
| --- | --- | --- | --- |
| recovery auf anforderung | lokaler tresor des betreibers | `bootstrapadmin` | interaktives SSH über den plntir-control-node; `sudo` verlangt weiterhin das bootstrap-admin-passwort |
| monitoring und reaktion | plntir-control-node | `macagent` | bestehende erzwungene status- und reaktionsbefehle aus der allowlist |
| export aller benutzer | plntir-control-node | `macagent` | genau `all-users-plan-v1` und `all-users-stream-v1`; der root-helfer verwendet immer den festen bereich `/Users` |
| archiventschlüsselung | nur lokaler tresor des betreibers | keines | heruntergeladene `.tar.zst.gpg`-archive entschlüsseln und prüfen |

das bootstrap-admin-passwort wird weder in dieses repository noch auf den
plntir-control-node noch in einen SSH-befehl kopiert. es gibt bewusst keine
regel `NOPASSWD: ALL`. der separate archivschlüssel kann keine shell öffnen und
keinen beliebigen pfad wählen.

## Ein authentifizierter Administratorbefehl

das vorbereitete upgrade lässt sich lokal oder über die authentifizierte
recovery-SSH-sitzung installieren mit:

```sh
sudo /Users/Shared/.plntir/inbox/access-upgrade/run.sh
```

der installer prüft sein eingebettetes manifest, installiert den
eingeschränkten helfer, die autorisierten schlüssel und die exakte sudo-regel,
testet die befehlsgrenze und schreibt sein ergebnis unter
`/Users/Shared/.plntir/results/access-upgrade/`. er behält außerdem ein
rollback-backup der ersetzten dateien.

voller festplattenzugriff ist eine datenschutzberechtigung von macOS. bevor
MDM/PPPC installiert ist, kann der root-export-helfer
`full_disk_access_required` melden; das ist eine erwartete, ausdrückliche
sperre und erzeugt nie wissentlich ein unvollständiges archiv. plntir erteilt
diese berechtigung nicht und bearbeitet TCC nicht. siehe
[runbook für privaten zugang auf anforderung](plntir-on-demand-private-access.md).

## Export- und Speicherverhalten

ein export deckt immer den festen baum `/Users` ab, einschließlich des
home-verzeichnisses jedes lokalen benutzers. es gibt keine konfigurierte
obergrenze für die archivgröße. vor dem streaming misst der plntir-control-node
die scheinbare größe der quelle und verlangt:

```text
source bytes + 20% transfer headroom + max(10 GiB, 10% of Plntir Control Node filesystem)
```

der plntir-control-node reserviert den sicherheitsabstand für die dauer der
übertragung mit `fallocate`. reicht der platz nicht, wird der status zu
`insufficient_control_node_storage`, und das dashboard warnt, bevor der export
beginnt.

die daten werden vom mac als `tar` gestreamt, mit zstd komprimiert und mit GPG
verschlüsselt, bevor sie in den speicher des plntir-control-nodes geschrieben
werden. auf dem plntir-control-node ist nur der öffentliche
verschlüsselungsschlüssel installiert. der private GPG-schlüssel und seine
passphrase bleiben im lokalen tresor des betreibers.

nachdem beide hälften aktiviert sind, verwenden:

```sh
./scripts/plntir-secure-archive-status.sh
./scripts/start-plntir-secure-archive.sh
./scripts/fetch-latest-plntir-secure-archive.sh
```

der abrufbefehl prüft manifest, prüfsumme, verfügbaren lokalen speicher und
entschlüsselung, bevor er die heruntergeladene datei akzeptiert.

## Übergabe an MDM

dieses zugangs-upgrade gibt absichtlich nicht vor, MDM zu sein. MDM ist apples
kanal für die geräteverwaltung: der mac registriert sich bei einem
verwaltungsserver, erhält signierte konfigurationsprofile und befehle über APNs
und meldet den gerätezustand. für dieses projekt ist die nächste phase:

1. den separaten shadow-node `plntir-mdm-01` aufbauen, ohne den aktiven
   watch-node oder den mac zu verändern.
2. nur die im quellcode geprüften fleet-maschinenpfade unter `mdm.plntir.example`
   über die beiden rein ausgehenden tunnel-connectoren und den exakten
   host-/pfad-/methoden-proxy auf dem node veröffentlichen.
3. APNs, SCEP und client-zertifikats-authentifizierung durchgängig
   konfigurieren und prüfen; keine interaktive access-anmeldung vor den
   geräteverkehr setzen.
4. ein frisches iPhone als pilot einsetzen und seine tatsächlichen
   verwaltungsfunktionen bestätigen.
5. nach einer eigenen freigabe den mac registrieren und ein PPPC-profil
   installieren, das der endgültigen, stabilen, signierten
   export-/helfer-identität vollen festplattenzugriff gewährt; danach die
   bereitschaftsprüfung für alle benutzer wiederholen.
6. einschränkungen, inventar, osquery- und santa-richtlinien schrittweise
   ergänzen und dabei das physische bootstrap-konto als dokumentierten
   recovery-weg erhalten.

ein modernes macOS-device-enrollment führt zu supervision, ist aber kein
automated device enrollment und verlangt weiterhin die lokale freigabe des
verwaltungsprofils. fleet free liefert die erste phase für MDM und
skriptsteuerung. richtlinien zur festplattenverschlüsselung liegen außerhalb
dieser übergabe.

die private fleet-basis ist auf `plntir-mdm-01` vorbereitet; sowohl die rohe
oberfläche als auch der geräte-proxy sind an loopback gebunden. die oberfläche
ist nie ursprung eines tunnels. während eines freigegebenen bootstrap- oder
recovery-fensters darf `nftables` auf dem host port 1337 auf der privaten
adresse ausschließlich für `plntir-relay-01` öffnen; eine aktive
AWS-FIDO-eigentümersitzung öffnet dann eine reine SSM-portweiterleitung:

```sh
export PLNTIR_RELAY_INSTANCE_ID=i-REPLACE
export PLNTIR_MDM_PRIVATE_IP=REPLACE_PRIVATE_IPV4
./scripts/connect-plntir-device-management.sh
```

das maßgebliche routenmanifest für v4.89.2 und die negativen tests liegen unter
`mdm/fleet/`; `make mdm-check` prüft sie. öffentliche routen für SCEP, apple
MDM, installer, orbit und osquery kommen erst hinzu, wenn administratorkonto,
verschlüsseltes datenbank-backup, beide tunnel-connectoren, DNS,
host-firewall-scans und der nachweis zu APNs-eigentum und -erneuerung bereit
sind. der produktions-mac bleibt hinter seinem eigenen ausdrücklichen
pilot-schritt.
