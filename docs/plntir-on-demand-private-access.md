# Zugriff auf private Daten nur auf Anforderung

plntir hält keine weitreichende administrator- oder sitzung für private daten
offen. die normalen gesundheits-, sicherheits- und integritätsjobs durchlaufen
keine home-verzeichnisse und erfassen keine inhalte aus safari, mail,
schlüsselbund oder dokumenten.

die standard-betriebsrichtlinie ist:

- der recovery-SSH-schlüssel öffnet eine sitzung nur, wenn ein betreiber
  `./scripts/connect-plntir-root.sh` ausführt;
- ein vorbereitetes signiertes update kann stattdessen
  `./scripts/connect-plntir-root.sh --apply-staged-update` verwenden; das führt
  nur den gepinnten update-befehl aus und schließt sich, ohne eine root-shell zu
  hinterlassen;
- beliebiger root-zugriff verlangt weiterhin das mac-administratorpasswort in
  diesem SSH-terminal und endet mit `Ctrl-D`;
- der geplante bereitschafts-timer für das archiv aller benutzer ist
  deaktiviert;
- ein vollständiges `/Users`-archiv startet nur über
  `./scripts/start-plntir-secure-archive.sh`, nachdem der betreiber die exakte
  bestätigungsphrase eingegeben hat;
- kein plntir-installer bearbeitet die TCC-datenbank von macOS oder erteilt eine
  datenschutzberechtigung.

das archiv aller benutzer ist ein fester, verschlüsselter recovery-vorgang. es
kann keinen beliebigen pfad wählen und keine shell öffnen. sein
bereitschaftsscan und stream laufen nur für den ausdrücklich freigegebenen
vorgang, und der einmalige dienst beendet sich danach.

## Safari und Mail

macOS schützt mail, safari und andere private anwendungsdaten mit vollem
festplattenzugriff. ein SSH-skript kann keine unterstützte einmalige freigabe
für vollen festplattenzugriff erzeugen. wenn eine bestimmte recovery-aufgabe
diese daten wirklich braucht, muss eine person am mac in den
systemeinstellungen vorübergehend vollen festplattenzugriff für entfernte
benutzer aktivieren, den begrenzten vorgang beobachten und ihn unmittelbar
danach wieder deaktivieren. plntir schaltet diese einstellung nicht automatisch
um.

## Schlüsselbund

der zugriff auf den schlüsselbund ist von administrator- und
festplattenzugriffsrechten getrennt. ein mac-administratorpasswort entsperrt
nicht automatisch den schlüsselbund eines anderen benutzers. macOS kann für ein
bestimmtes schlüsselbundobjekt und die anfragende anwendung `Allow Once`,
`Always Allow` oder `Deny` anbieten. der plntir-standard ist `Allow Once`, und
das nur, wenn der angemeldete benutzer die genaue recovery-aufgabe versteht und
freigibt. plntir führt keinen allgemeinen schlüsselbund-export durch und ändert
keine zugriffslisten von objekten.

richtlinien zur festplattenverschlüsselung liegen außerhalb des wartungsumfangs
dieser control plane und werden weder erfasst noch alarmiert.
