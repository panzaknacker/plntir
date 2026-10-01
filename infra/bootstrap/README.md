# AWS-Identitäts-Bootstrap

dieser stack ist die einzige vorlage, die mit der kurzlebigen root-anmeldung
angewendet werden soll. er erstellt `plntir-builder`, `PlntirBootstrapAdmin`,
`plntir-owner`, eine ruhende rolle `PlntirBreakGlass` und deren
EventBridge-/SNS-alarmweg. er erstellt kein anmeldeprofil, keinen
zugriffsschlüssel, keine VM, kein netzwerk und keinen datendienst.

derselbe nur mit root nutzbare stack erstellt eine dauerhaft beibehaltene
permissions boundary für plntir-laufzeitrollen. vom builder erstellte rollen
müssen genau diesen ARN referenzieren. die boundary enthält keine berechtigung
zur IAM-verwaltung oder zur übernahme von rollen, und der builder darf nur
`AmazonSSMManagedInstanceCore` anhängen; beliebige inline-policies können
`iam:PassRole` daher nicht in eine administrative laufzeit verwandeln.

`plntir-owner` trägt das principal-tag `plntir-breakglass=disabled`; die
trust-policy für break-glass lehnt ihn daher ab, obwohl der benutzer eine
berechtigung für `sts:AssumeRole` hat. die aktivierung verlangt eine separate,
mit root authentifizierte tag-änderung, eine einstündige rollensitzung und ein
getestetes alarm-abonnement.

der geschützte watch-ARN ist ein pflichtparameter; für die builder-rolle sind
alle änderungen an lebenszyklus, netzwerk und metadaten dieses ziels verboten.
eine snapshot-migration ist eine spätere, zeitlich begrenzte policy-änderung
nach einem eigenen freigabeschritt.

FIDO-passkeys/sicherheitsschlüssel lassen sich nicht über IAM-CLI/-API
registrieren. nach dem erstellen des stacks in der AWS-konsole für jeden
benutzer den konsolenzugang aktivieren und beide physischen schlüssel
registrieren. keines der anmeldepasswörter an skripte weitergeben oder in
terraform/CloudFormation speichern.

die validierung ist rein lesend:

```sh
./infra/bootstrap/validate.sh plntir-root-bootstrap
```

die offline-validierung fragt nie nach einer AWS-sitzung:

```sh
./infra/bootstrap/validate.sh --local-only
```

nach dem identitäts-stack ist `infra/state/aws-terraform-state.yaml` ein eigener
change-set-freigabeschritt für das verschlüsselte terraform-backend. er gehört
nicht zum nur mit root nutzbaren identitäts-stack und darf nicht vor der
FIDO-anmeldung des builders und einem geprüften CloudFormation-change-set
ausgeführt werden.

es gibt absichtlich kein apply-skript. das erstellen des stacks, das aktivieren
der konsolenanmeldung, das registrieren von FIDO-geräten, das anbinden von
alarmzielen und das löschen des builders bei der produktionsfreigabe erfordern
jeweils eine unmittelbare menschliche freigabe.
