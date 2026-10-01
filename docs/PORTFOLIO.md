# Warum plntir

Berichte aus Communities, denen ich folge, über kompromittierte Abhängigkeiten,
Prompt Injection und manipulierte Suchergebnisse haben mich dazu gebracht, einen
klareren Blick auf autonome Agenten auf meinen eigenen Geräten zu wollen. Das
erste Ziel war, ihre Daten und Aktivitäten an einem Ort zu sammeln, damit ich
nachvollziehen kann, was sie heruntergeladen, erzeugt und getan haben.

Mit Unterstützung wurde das Projekt um Kommunikation und Dateiaustausch zwischen
Agenten erweitert, die autonom auf verschiedenen Rechnern arbeiten. Dazu gehören
meine eigenen Geräte und die von Personen, die am selben Projekt mitarbeiten.

Rund 30 Freunde und Bekannte nutzen eine private Variante. Wie genau sie sich
zu diesem Quellstand verhält, ist noch nicht dokumentiert.

## Entscheidungen im Code

**Recovery prüft den Inhalt, nicht nur die Entschlüsselung.** Der Archivtest
stellt die ursprünglichen Bytes wieder her und prüft danach, dass beschädigter
Ciphertext abgelehnt wird.
[Restore-Test](../mac/archive-agent/archive/restore_test.go),
[Implementierung](../mac/archive-agent/archive/restore.go).

**Das Wiederherstellen einer Datei darf keinen widerrufenen Zugriff
wiederherstellen.** Die Freigabetests decken Zugriff durch Empfänger und
Fremde, Widerruf, Löschung und Wiederherstellung auf der SQLite-/Domänenebene ab.
[Freigabetests](../core/internal/store/sqlite/sharing_test.go).

**Jobs überstehen unterbrochene Worker.** Leases, Heartbeats und Wiederholungen
trennen dauerhafte Arbeit von der Lebensdauer eines Workers.
[Job-Tests](../core/internal/store/sqlite/jobs_test.go).

Der [HTTP-Kern](../core/internal/httpapi/server.go) lehnt Änderungen ab, solange
Identität und betriebliche Integration im Shadow-Modus bleiben.

## Ausprobieren

Der [Archiv-Demo](DEMO.md) folgen und danach die Restore-Implementierung
ansehen. Sie verwendet synthetische Eingaben, temporäre Schlüssel und lokale
Test-Doubles für Speicher und KMS.

Für das Gesamtsystem hält [DEVELOPMENT.md](../DEVELOPMENT.md) unfertige
Integrationen fest und [PROJECT_STATUS.md](../PROJECT_STATUS.md) die
tatsächlichen Tests. Betreiberspezifisches Material steht in
[PUBLICATION.md](PUBLICATION.md).
