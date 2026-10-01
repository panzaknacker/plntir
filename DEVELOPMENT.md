# Komponentenstand

plntir ist in entwicklung. lokale tests belegen bestimmte eigenschaften der
implementierung; produktionsintegrationen brauchen weiterhin eine eigene
qualifikation.

| komponente | aktuelle implementierung | verbleibende qualifikation |
| --- | --- | --- |
| client und go-kern | lokaler observer, API-verträge, persistenz und job-logik | durchgängige identität, betrieb und recovery in einer wegwerf-umgebung |
| fleet-ingress | gepinnte policy für maschinenpfade und lokale proxy-tests | echtes enrollment, zertifikate und qualifikation von upgrades |
| macOS-archivagent | bibliothek mit tests für traversal, verschlüsselung, fortsetzen und restore | verhalten des macOS-dateisystems und ein vom betreiber freigegebener installationsablauf |
| scanner | fail-closed-grundgerüst der pipeline | echte erkennungs-engines und qualifikationskorpus; kein produktionsergebnis „sauber“ |
| fileshare- und admin-apps | lokale anwendungen und domänenlogik | vollständige integration von authentifizierung, speicher und recovery |
| telemetrie-analyzer | lokales asynchrones modell | quellenabhängige erfassungsabdeckung, einwilligung und qualifikation der aufbewahrung |
| wazuh-integritätsebene | inaktive journal-, zustell- und anchor-komponenten | unabhängige senke, qualifikation für neustart und ausfall |
| cloud-infrastruktur | standardmäßig gesperrte vorlagen und lokale validierungssperren | mandantenkonfiguration, provider-validierung und ausdrücklich freigegebener rollout |

die domains in der vorhandenen konfiguration beschreiben eine
referenztopologie. sie sind keine gehostete demo und keine endpunkte zum
abtasten. standortspezifisches inventar, enrollment-profile, kontokennungen und
zugangsdaten muss der betreiber außerhalb des quellstands bereitstellen.

## Prüfgrenzen

der GitHub-workflow `Local verification` führt `make check`, `make mdm-check`,
`make archive-check` und `make test-race` unter linux aus. die archivprüfung
kompiliert zusätzlich für macOS; cross-kompilierung ist kein test auf einem
echten gerät.

`make platform-check` bleibt die umfassendere, separat eingerichtete prüfstufe.
sie benötigt die dokumentierten abhängigkeiten für node, terraform, ansible und
die komponenten. ein bestandener lokaler workflow bedeutet nicht, dass diese
gesamte matrix bestanden hat.

unvollständige funktionen müssen einen ausdrücklichen nicht-unterstützt- oder
fehlerzustand liefern oder deaktiviert bleiben. diese tabelle aktualisieren,
wenn sich implementierung oder gemessene nachweise ändern. historische
designdokumente von getestetem verhalten unterscheidbar halten.

## Quellbedingungen

dieser snapshot hat keine lizenz zur weiterverwendung des projekts. eine
open-source-lizenz wurde nicht gewählt. vorhandene hinweise von drittanbietern
behalten ihre eigenen bedingungen.
