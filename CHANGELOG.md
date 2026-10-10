# Changelog

Alle nennenswerten Änderungen an diesem Projekt.

## [0.43.0] – 2026-10-10

Eine Sicherheitslücke im Panel geschlossen und die Oberfläche nach einer Designkritik über alle
Ansichten aufgeräumt: Farben mit fester Aufgabe, Listen nach Dringlichkeit, Texte, die sagen, was
passiert ist und was jetzt zu tun ist.

### Sicherheit

**Der Fortschritt einer Reparatur oder eines Updates kommt als Text auf die Website-Seite.**
Die Zeilen des Protokolls nennen Plugin-Ordner und Versionsangaben von der Platte des Kunden.
Die Seite setzte sie bisher als HTML ein: Ein Plugin-Ordner mit einem Namen wie
`<img src=x onerror=…>` führte sein Skript in der Sitzung des Administrators aus, sobald
dieser eine Reparatur oder ein Update der Website startete. Protokollzeilen und Phasen
entstehen jetzt als Elemente mit `textContent`, wie es die Schritte schon taten.
`check_wiring.sh` prüft, dass die Seiten mit Fortschritt (`status.htm`,
`malwatch_site_show.htm`) `innerHTML` höchstens leeren.

### Geändert

**Farben mit Aufgabe.** Ein Knopf, der etwas startet (Reparatur, Updates, „scharf“), ist gelb wie
jede Hauptaktion des Panels. Was entfernt, sperrt oder beendet (Quarantäne, Löschen, Sperren, Notaus,
Teilen beenden), steht als Umriss in Pink; gefüllt pink ist nur noch der Knopf im
Bestätigungsdialog. Schweregrade tragen überall ihr Wort: „3 Lücken · mittel“ auf der Website-
und der Update-Seite, die Update-Seite färbt nach der schwersten Lücke. Die Fundliste zeigte jede
Stufe grau, weil sie die Farbe nach dem übersetzten Wort suchte; sie nimmt jetzt den gespeicherten Wert.

**Listen nach Dringlichkeit.** Die Fundliste öffnet mit dem Filter „offen“ und zeigt zuerst die
offenen, darin die schwersten und neuesten; eine Spalte, nach der du sortierst, geht davor, „alle“
im Filter bleibt gewählt. Die Prüfläufe stehen neueste zuerst und nennen ihre Funde in Worten
(„3 kritisch · 8 hoch“).

**Keine leeren Zeilen.** Die Vorlagen-Engine von ISPConfig zählt eine leere Liste als eine Zeile;
im Aktionsprotokoll einer Website stand deshalb eine Zeile „()“. Alle Listen gehen über
`malwatch_set_loop()`, `check_wiring.sh` prüft das (Prüfung 107).

**Titel und Wege.** Seitentitel nennen das Thema („Funde“, „Fund“, „Prüfläufe“,
„Scanner-Einstellungen“), die Website-Seite den Namen der Website; die Statusseite trägt ihren
Satz als Seitentitel. Abschnittstitel sind Überschriften. Jede Detailseite hat unter dem Titel
einen Rückweg („← Status“, „← matrix.dj“, „← Abwehr-Übersicht“). In der Leiste heißen die beiden
Einstellungen „Scanner-Einstellungen“ und „Abwehr-Einstellungen“.

**Texte.** Die Oberfläche spricht durchgehend mit „du“. „Freigeben“ hatte drei Bedeutungen und hat
jetzt drei Wörter: Ein Fund ist „harmlos“, eine fail2ban-Sperre wird „aufgehoben“, ein Dump wird
„geteilt“. Ein gescheiterter Quarantäneauftrag nennt Nummer, Zeitpunkt, Aktion, Grund und den
nächsten Schritt; ohne Protokoll den Rückgabewert. „Datei(en)“, „Element(en)“ und „davon 0
dringend“ sind ganze Sätze geworden, „aktuell 5.9.18“ heißt „neueste Version 5.9.18“. Die
Fußnote der Dumps nennt den geteilten Verweis als zweiten Weg zum Archiv.

**Einstellungen in Gruppen.** Scanner- und Abwehr-Einstellungen ordnen ihre Abschnitte in vier
Reiter (Scanner: Prüfung, Bei einem Fund, Benachrichtigung, System; Abwehr: Schutz, Sperren,
Anzeige und Aufbewahrung, System); darin klappen die Abschnitte auf. Gespeichert werden immer
alle Gruppen. Kommt die Seite mit einem Fehler zurück, öffnet sie den Reiter des genannten Feldes
und markiert ihn, sonst alle Gruppen; die Suche der Abwehr-Einstellungen findet in allen Gruppen.
Der gewählte Reiter bleibt in der Sitzung. Die Scanner-Einstellungen haben einen Speicherknopf
statt zweien.

**Fund-Seite:** Stufe und Zustand stehen getrennt; „Nächster offener Fund →“ führt zur nächsten
offenen Datei derselben Website, die schwerste zuerst.

**Website-Seite:** „Jetzt prüfen“ ist die eine Hauptaktion. **Website-Einstellungen:** Eine Stufe,
deren Aktion aus ist, tritt zurück; „Abbrechen“ führt zur Website.

**Quarantäne:** Lange Regelnamen und Domains brechen um, die Knöpfe einer Zeile ebenfalls; die
Tabelle passt in die Breite des Panels, „Zurückholen“ und „Herunterladen“ stehen nicht mehr hinter
einem Scrollbalken.

**Abwehr:** Die Knöpfe für angehakte Websites bleiben am unteren Rand sichtbar, während die Liste
scrollt. „sperren“ sagt im Tooltip, wo sich die Sperre aufheben lässt. Das Nachladen der Sperren
heißt „25 weitere zeigen (noch 131 nicht geladen)“.

**Barrierefreiheit:** Marken und Chips mindestens 11 px, Zeilenknöpfe mindestens 24 px hoch,
Text in Orange auf hellem Grund im Rückfall der Themes ohne Variablen dunkler (4,5:1).
Filterfelder und der Filterknopf haben einen Namen, „Ansehen“ nennt für Screenreader die Website.

### Hinzugefügt

**Einstellung „Dumps behalten (Tage)“** (`keep_dump_days`, Vorgabe 7, erlaubt 1 bis 90) unter
Scanner-Einstellungen. Die sieben Tage standen fest im Code des Servers. Gilt für Dumps, die ab
jetzt fertig werden; die Seite der Dumps nennt die eingestellte Frist.

## [0.42.0] – 2026-10-09

Fehlalarme verschwinden durch Erkennung: Der Scanner gleicht mehr mit den Herstellern ab, ordnet ein,
was eine Datei tatsächlich tun kann, und erkennt zwei weitere Arten von Herstellercode: Wrapper, die eine
Bibliothek aus eigenem Text schreibt, und die Tests von Bibliotheken. Gegen die 1.493 Einträge der Quarantäne
des ISPConfig-Hosts meldet 0.42.0 jede der 978 Dateien weiter hoch oder kritisch, die nach der Einzelprüfung
vom 30.09.2026 so gehören, und nichts neu; die übrigen 180 Meldungen von 0.40.0 waren Fehlalarme.

### Hinzugefügt

**Abgleich mit den Herstellern.** Themes von wordpress.org prüft der Scanner gegen das
veröffentlichte Archiv, so wie Kern und Plugins. Eine Datei mit Fund in einem Composer-Paket
vergleicht er mit dem Originalarchiv des Pakets; stimmt sie überein, entfällt der Fund.
`vendor/composer/installed.json` liefert dafür nur Paket und Stand, das Archiv nennt das
Paketregister (`--verify-packagist-url`, Vorgabe https://repo.packagist.org): Eine veränderte
`installed.json` kann so kein eigenes Archiv unterschieben. Eine abweichende Skriptdatei (JS, CSS, HTML) eines Plugins oder
Themes vergleicht er mit der Datei im SVN von wordpress.org: Ein eingefügter Block, der lädt
oder ausführt, bleibt ein Fund der Stufe „hoch“; eine durchgehend neu gebaute Datei gilt als
Werk des Herstellers. Eine Kopie einer geprüften Datei an anderem Ort, etwa neben einem
Bildoptimierer, gilt als geprüft; Regeln, die nach dem Ort urteilen, melden sie weiter.
Scanner: `--no-verify-composer`, `--no-verify-originals`, `--verify-hosts`,
`--verify-max-downloads`, `--verify-max-mb`, `--verify-timeout`, `--verify-retry-hours`.

**Datenbank bekannter Dateien, ausgeschaltet.** Eingeschaltet schlägt der Scanner Dateien mit
Fund, die kein anderer Abgleich bestätigt, per SHA-1-Summe in einer Datenbank wie CIRCL
hashlookup nach (`--hashlookup-url`). An den Dienst gehen ausschließlich Prüfsummen; ein
Eintrag zählt mit passender SHA-256-Summe, ein als schädlich markierter bestätigt nichts. Eine
Adresse mit Anmeldedaten lehnen Scanner und Einstellungsseite ab, weil sie auf der
Befehlszeile steht.

**Einstellungen unter Scanner > Einstellungen > Abgleich mit den Herstellern:** Endungen für
Abweichungen, erlaubte Skript-Hosts, Composer-Pakete und Originaldateien abgleichen,
Paketregister, Hosts für Archive, Abrufe je Prüfung (50), Größe je Abruf (50 MB), Wartezeit je Abruf
(60 Sekunden), neuer Versuch nach (24 Stunden), Datenbank bekannter Dateien fragen (aus) und
ihre Adresse.

**Regel `php.tool.file_manager_open` (kritisch, selbsttätige Quarantäne):** der quelloffene
PHP File Manager mit abgeschalteter Anmeldung (`"authorize":"0"`). Wer die Datei aufruft, kann
ohne Kennwort Dateien hochladen, ändern und ausführen. Am 30.09.2026 lagen sechs Kopien auf
einer Website, jede in einem Plugin-Ordner mit ausgedachtem Namen, hochgeladen über eine
gestohlene WordPress-Anmeldung; die Regeln bis dahin meldeten sie nur als „hoch“, und die
automatische Quarantäne ließ sie liegen.

**Funde verschwundener Dateien.** Stündlich prüft der Server bis zu 500 offene Funde darauf,
ob ihre Datei noch da ist, und schließt die Funde verschwundener Dateien. Das hält vor allem
Websites aktuell, die abgeschaltet sind und deshalb nicht mehr geprüft werden. Die Liste der
Funde kennzeichnet solche Websites mit „abgeschaltet“ oder „gelöscht“.

**Aufräumen einstellbar:** Minute der stündlichen Aufräumarbeiten (7), erledigte Aufträge
behalten (30 Tage), behobene Funde behalten (90 Tage), Funde je Stunde auf fehlende Dateien
prüfen (500, 0 schaltet ab).

**Testordner von Bibliotheken.** In einem Testordner einer Bibliothek zählen die
Hinweisregeln `php.exec.background`, `php.eval.variable` und `binary.elf` nicht: Tests
starten Testserver im Hintergrund, enthalten Beispieldateien mit `eval` und bringen die
Programme mit, die sie brauchen. Ein Testordner ist ein Ordner wie `test`, `tests`,
`test-suite`, `testsuite`, `fixtures` oder `__tests__` innerhalb einer Bibliothek unterhalb
von `vendor`, `vendors`, `node_modules` oder `bower_components`. Als Test gilt auch eine
Datei, die die Bibliothek in ihrer `.gitignore` als Datei eines Testordners führt, etwa der
Mock-Server Prism des SendGrid-SDK. Unterhalb eines Upload-Ordners gilt nichts als
Bibliothek; Signaturen, Webshell-Regeln und alle Funde ab „hoch“ gelten auch in
Testordnern. Scanner: `--test-dirs`, `--library-dirs`, `--test-rules`; eintragen lassen sich
Regeln bis zur Stufe „mittel“ ohne selbsttätige Quarantäne.

**Einstellungen unter Scanner > Einstellungen > Testordner von Bibliotheken:** Testordner,
Bibliotheksordner und Regeln, die in Testordnern nicht zählen. Die Seite lehnt eine Regel
ab, die der Regelkatalog als „hoch“, „kritisch“ oder mit selbsttätiger Quarantäne führt.

### Geändert

**Dateien ohne Wirkung gelten als harmlos:** nur Kommentare, ein `exit` am Anfang oder nur
feste Daten wie Übersetzungstabellen und Konfigurationsarrays, auch hinter einer
ABSPATH-Sperre. Das betrifft PHP im Upload-Ordner und fremde Dateien im Kern von WordPress.

**Regeln zu PHP-Konstrukten werten Treffer, die PHP ausführen kann:** im Code und in
Zeichenketten, die eine Datei an `eval` geben oder in eine Datei schreiben kann. Ein `eval(`
in einem Kommentar oder im HTML-Teil einer Datei zählt als Text; so meldete der Scanner
zuvor eine auskommentierte Zeile von RevSlider als kritisch. `include "http://"` zählt mit
einer Adresse dahinter; ein Hilfetext, der dazu auffordert, „http://“ einzutragen, zählt
nicht (Salient). Abruf und Ausführung gehören zu einer Aktion, wenn sie in derselben
Funktion stehen oder die eine die andere direkt aufruft; so meldete die Regel
`php.remote.fetch_eval_indirect` zuvor die XML-RPC-Bibliothek von SeedProd.

**Der PHP-Leser verliert den Faden seltener.** Ein eingesetzter Wert `{$name}` in einer
Zeichenkette endet an seiner eigenen Klammer; zuvor las der Scanner bis zur nächsten
geschweiften Klammer der Datei weiter und hielt den Code dazwischen für Text. `<?` öffnet PHP
auch ohne folgendes Leerzeichen, wie PHP es mit eingeschalteten Short-Tags tut; die
XML-Deklaration `<?xml` bleibt Text.

**Kodiertes wird dekodiert und eingeordnet.** Bilder, Zertifikate, Schlüssel, Archive,
Schriften und PDF in base64 sind Daten, ebenso alles hinter `__halt_compiler` in einem PHAR.
`document.write` mit `unescape` wird entschlüsselt; ein mailto-Link, Text oder ein Skript von
einem erlaubten Host ist harmlos. Listen und Suchmuster mit Namen bekannter Webshells, wie
Sicherheits-Plugins sie führen, gelten als Daten.

**Admin-Aktionen hinter Rechte- und Nonce-Prüfung** in WordPress meldet der Scanner als
„mittel“ mit einem Hinweis auf die Prüfung. Die automatische Maßnahme verschiebt Funde der
Stufen „hoch“ und „kritisch“.

**Die PHP-Version der Website zählt:** `preg_replace` mit `/e` bleibt ab PHP 7 still, weil
PHP es dort nicht mehr ausführt (`--php` oder `--php-version`).

**Abweichungen vom Hersteller** zählen bei Endungen, die PHP, der Webserver oder ein Browser
ausführt (`--modified-exts`); eine abweichende Readme oder Übersetzungsvorlage bleibt Sache
des Herstellers.

**Fehlermeldungen der Grenzen** auf der Einstellungsseite nennen das Feld, die erlaubten
Werte und den nächsten Schritt; „Abbruch nach Stunden“ und „Aufbewahrte Prüfläufe je
Website“ haben einen Hinweis.

**Selbst geschriebene Wrapper sind kein Fund.** `php.eval.variable` und
`php.remote.fetch_eval_indirect` lassen ein `eval` durch, das Code ausführt, den dieselbe
Funktion aus eigenem Text schreibt: Die Variable entsteht dort aus Zeichenketten, die eine
Funktions- oder Klassendefinition eröffnen, und aus nichts, was aus der Anfrage, einer
Datei, dem Netz, einem Decoder oder einem Aufruf über eine Variable stammt. So schreibt die
XML-RPC-Bibliothek phpxmlrpc ihre Wrapper, die SeedProd mitliefert. Ein `eval` auf einen
Parameter, auf der obersten Ebene einer Datei oder auf dekodierten Text bleibt ein Fund.

**Kopien geprüfter Dateien auch per SHA-256.** Seit 0.40.3 stehen Plugin-Dateien mit der
SHA-256 von wordpress.org in den Listen; eine Kopie solcher Dateien erkennt der Scanner an dieser
Summe, die übrigen weiter an der MD5.

### Behoben

**Zurückgeholte Einträge verlassen die Quarantäne.** Nach dem Wiederherstellen blieb der
Eintrag im Speicher der Quarantäne stehen, und das Panel führte die Datei weiter als
verschoben.

**Leere Listen erreichen den Scanner leer.** Eine absichtlich geleerte Liste, bei der leer
eine Wahl ist (erlaubte Skript-Hosts, Hosts für Archive, Regeln für Testordner), ersetzte
der Server durch die Vorgabe.

## [0.41.0] – 2026-10-09

### Hinzugefügt

**Die Quarantäne prüft den Platz am Ziel, bevor sie schreibt.** `add` misst das Archiv
und die Kopie, die zur Kontrolle entpackt wird, in der Ablage; `restore` die Dateien am
ursprünglichen Ort und mit `--force` die Zwischenkopie in der Ablage, wobei zählt, was
`--force` am Ziel entfernt; `export` das ZIP und die Zwischendatei seiner größten Datei.
Dazu kommt eine Reserve, die frei bleibt. Als frei zählt, was einem gewöhnlichen Benutzer
zur Verfügung steht, wie bei `dump`; zwei Ziele auf einem Dateisystem zählen zusammen.
Weil sich vor dem Packen nicht sagen lässt, wie gut sich Dateien packen lassen, rechnet
die Prüfung Archiv und ZIP so groß wie die Dateien selbst. Reicht der Platz nicht, bricht
der Schritt ab: Dateien und Einträge bleiben, wie sie sind, und die Meldung nennt den
freien Platz, den Bedarf samt Reserve und den nächsten Schritt. Das gilt für die
automatische Maßnahme des Addons, für die Aufträge der Seite Quarantäne, für `repair` und
für `upgrade` samt Rücknahme. Den Kern legt `repair` als einen Schritt ab: `wp-admin`,
`wp-includes` und die geänderten losen Dateien zählen zusammen, bevor einer davon seinen
Platz verlässt.

**`--quarantine-reserve`** für `quarantine`, `repair` und `upgrade`: der Platz in MiB,
der bei jedem Schreiben der Quarantäne frei bleibt. Vorgabe 256, erlaubt 0 bis 1048576;
ein Wert außerhalb wird mit Bereich und Vorgabe abgewiesen. Im Addon steht die Reserve
unter Security > Scanner > Einstellungen > Quarantäne; der Runner gibt sie an jeden
Auftrag der Quarantäne, an Wiederherstellungen und an Updates.

**`scan --email` liest das SMTP-Passwort aus `--smtp-pass-file` oder
`MALWATCH_SMTP_PASS`**, wie `send-mail`; die Datei geht vor. `--smtp-pass` bleibt für
bestehende Aufrufe und geht der Umgebung vor. Hilfe und README empfehlen Datei oder
Umgebung, weil die Befehlszeile für jeden Benutzer der Maschine lesbar ist. Beide
Schalter zusammen weist `scan` vor dem Lauf ab, ebenso eine Passwortdatei, die sich nicht
lesen lässt.

### Geändert

**`quarantine export` packt als Strom.** Jede Datei geht über eine Zwischendatei neben
dem ZIP: gepackt, mit CRC und Größen für den Kopf, dann mit ZipCrypto verschlüsselt ins
ZIP. Der Speicherbedarf bleibt gleich, wie groß eine Datei auch ist. Mehrere `--id`
landen direkt in einem ZIP, jede unter ihrer Kennung. Ein Eintrag, der fehlt oder
sich nicht lesen lässt, bleibt mit seiner Meldung draußen; ohne lesbaren Eintrag und nach
einem Fehler beim Schreiben bleibt kein ZIP zurück.

**`quarantine restore` liest das Archiv vor dem ersten Schreiben ganz.** Ein unlesbares
Archiv lässt das Ziel unangetastet, mit und ohne `--force`.

**Addon:** Die Meldung eines Elements einer Wiederherstellung wird nach Zeichen auf 255
gekürzt, wie bei Updates, sodass ein Umlaut an der Grenze ganz bleibt.

### Einspielen

Das Schema legt `malwatch_config.quarantine_reserve` mit der Vorgabe 256 an. Scanner und
Addon gehören zusammen: Das Addon gibt `--quarantine-reserve` an Aufträge der Quarantäne,
an Wiederherstellungen und an Updates, und diesen Schalter kennt erst der Scanner aus
demselben Stand; deshalb den Scanner zuerst einspielen. Hat das Arbeitsverzeichnis eines
Servers weniger als 256 MiB frei, lehnt die Quarantäne das Schreiben ab, bis Platz
geschaffen oder die Reserve gesenkt ist.

### Tests

- `internal/quarantine/space_test.go`: ohne Platz bleiben Datei und Ablage, wie sie sind,
  und die Meldung nennt Ablage, freien Platz, Reserve und den nächsten Schritt; dieselbe
  Datei wird mit einer Reserve abgelegt und mit einer anderen abgelehnt; `add` rechnet
  Archiv und Kontrollkopie; eine Ablage, die es noch nicht gibt, wird am nächsten
  vorhandenen Ordner gemessen; `CheckStore` zählt mehrere Quellen zusammen; `restore`
  ohne Platz im Webordner behält den Eintrag, mit `--force` braucht es die Zwischenkopie
  in der Ablage und rechnet, was es am Ziel entfernt; ein unlesbares Archiv wird vor dem
  Schreiben abgewiesen; `export` ohne Platz schreibt kein ZIP, packt eine Datei von 6 MiB
  als Strom, lässt keine Zwischendatei zurück und lässt unlesbare und unbekannte Einträge
  draußen; das Archiv bleibt unter seiner Schätzung; `CheckReserve` und `SizeText`.
- `internal/diskspace/diskspace_test.go`: Messung eines Ordners, ein Ordner und sein
  Unterordner auf einem Dateisystem, ein fehlender Pfad, belegter Platz einer Datei.
- `internal/repair/space_test.go`: mit Platz für `wp-admin` allein bleiben `wp-admin` und
  `wp-includes` beide liegen, mit Platz für beide läuft die Reparatur; ein Plugin ohne
  Platz in der Quarantäne bleibt samt geladenem Release unverändert.
- `internal/upgrade/space_test.go`: ein Update ohne Platz für den alten Stand lässt die
  Website unverändert, mit passender Reserve läuft es; eine Rücknahme ohne Platz meldet
  `rollback_failed` mit dem Grund, und der alte Stand bleibt in der Quarantäne.
- `cmd/malwatch/quarantine_space_test.go`: `add` ohne Platz, wie die automatische
  Maßnahme aufgerufen, lässt die Datei liegen, schreibt die Bestandsliste und meldet in
  einer Zeile unter 400 Bytes; `restore` und `export` ohne Platz; `quarantine`, `repair`
  und `upgrade` weisen eine Reserve außerhalb der Grenzen ab; die Hilfe nennt Vorgabe und
  Grenzen aus dem Code.
- `cmd/malwatch/scan_smtp_test.go`: `scan --email` meldet sich mit dem Passwort aus der
  Datei, aus der Umgebung und aus `--smtp-pass` an; beide Schalter zusammen und eine
  fehlende Passwortdatei brechen vor dem Lauf ab; ohne `--email` stört eine fehlende Datei
  nicht; die Hilfe nennt die Wege.
- `ispconfig/tests/quarantine_space_test.php` (CI-Schritt „Quarantine reserve“): Vorgabe
  und Grenzen gleich in Scanner, Panel und Server, Spalte, Feld, Seite und Texte; der
  Server gibt einen anderen Wert weiter und einen ungültigen als Vorgabe; Aufträge der
  Quarantäne (auch die automatische Maßnahme), Wiederherstellungen und Updates bekommen
  den Schalter, eine Prüfung keinen.

## [0.40.3] – 2026-10-05

### Geändert

**Plugin-Dateien werden über SHA-256 verglichen.** Wo wordpress.org für eine Plugin-Datei einen
SHA-256 veröffentlicht, vergleicht malwatch über ihn, wie `wp plugin verify-checksums`: beim
Abgleich der Herstellerdateien im Scan und bei der Prüfung eines geladenen Archivs in
`upgrade`. MD5 gilt für Listen, die nur MD5 tragen, etwa die des WordPress-Kerns. Gemeldet von
Semgrep (use-of-md5).

**`--smtp-tls=starttls`, die Vorgabe, verschickt eine Mail nur nach STARTTLS.** Bietet der
Server kein STARTTLS an, bricht der Versand mit einer Meldung ab, die die Wege nennt: STARTTLS
am Server, `--smtp-tls=tls` oder `--smtp-tls=none`. An einen Server auf derselben Maschine
(`localhost`, `127.0.0.1`, `::1`) geht die Mail auch ohne STARTTLS. Für `starttls` und `tls` ist
TLS 1.2 die Untergrenze. Das gilt für `malwatch scan --email` und `malwatch send-mail`.
Gemeldet von Semgrep (missing-ssl-minversion).

**Workflows:** `ci.yml` gibt dem Token jedes Jobs Leserechte auf das Repository. Jede Action in
`ci.yml` und `release.yml` ist auf den Commit ihres Release festgelegt, die Version steht als
Kommentar daneben; `tools/check-workflows.sh` prüft beides im Job `test`. Gemeldet von CodeQL
(actions/missing-workflow-permissions) und Semgrep (github-actions-mutable-action-tag).

### Hinzugefügt

**`--smtp-timeout`** für `scan` und `send-mail`: wie lange der Aufbau der Verbindung zum
SMTP-Server dauern darf, der TLS-Aufbau von `--smtp-tls=tls` eingeschlossen. Vorgabe 30s wie
bisher, erlaubt 1s bis 10m.

### Einspielen

Wer über `--smtp` einen Server auf einem anderen Rechner ohne STARTTLS anspricht, setzt
`--smtp-tls=none` oder schaltet STARTTLS am Server ein. Das Addon übergibt die Verschlüsselung,
die in ISPConfig unter System > Hauptkonfiguration > Mail eingestellt ist; mit dem Wert `tls`
dort gilt die Regel oben.

### Tests

- `internal/mail/mail_test.go`: ein SMTP-Server ohne STARTTLS unter dem Namen eines anderen
  Rechners bekommt keine Mail, und die Meldung nennt die Wege; derselbe Server als 127.0.0.1
  bekommt sie. Nach STARTTLS mit eigenem Zertifikat geht die Mail über TLS 1.2 oder neuer. Die
  TLS-Einstellungen tragen Untergrenze und Servernamen. Ein stummer Server lässt
  `--smtp-tls=tls` nach `Timeout` (im Test 300 ms) scheitern. `CheckTimeout` nimmt 1s bis 10m.
- `internal/knownfiles/sha256list_test.go`: eine Plugin-Liste mit MD5 und SHA-256 wird über
  SHA-256 gelesen, auch mit mehreren Builds einer Datei; eine Datei ohne SHA-256 behält MD5.
  `Matches` erkennt die Art einer Summe an ihrer Länge.
- `internal/upgrade/verify_test.go`: `VerifyTree` prüft eine Datei gegen ihren SHA-256.
- `cmd/malwatch/sendmail_test.go`: `--smtp-timeout` außerhalb von 1s bis 10m wird abgewiesen,
  in `scan` und `send-mail`; die Hilfe nennt Vorgabe und Grenzen aus dem Code.
- Job `test`, Schritt „Workflows“: `tools/check-workflows.sh` weist eine Action ohne Commit und
  einen Workflow ohne `permissions` ab.

## [0.40.2] – 2026-10-05

### Geändert

**proxycheck.io fragt nur, was die freien Listen offen lassen.** Die Wahl „proxycheck.io“
bei „VPN und Rechenzentrum“ heißt jetzt „X4BNet-Listen, dazu proxycheck.io für Adressen ohne
Merkmal“. Die X4BNet-Listen laufen dabei mit und schlagen jede Adresse nach. An den Dienst
geht nur eine Adresse, die keine freie Liste als Tor, VPN oder Rechenzentrum kennt; eine
wartende Adresse, die eine Liste später kennt, fällt aus der Warteschlange. Mit den Zahlen von
web.herkules sind das rund 500 von 3.565 Adressen. Eine gespeicherte Wahl von proxycheck.io
gilt ab dem Einspielen als die neue.

### Behoben

**Antworten von proxycheck.io bleiben beim Abgleich mit den Bereichsdateien erhalten.** Jede
neu geladene Tor-Liste schlug alle Adressen noch einmal nach und schrieb VPN und
Rechenzentrum aus den Dateien. Ohne X4BNet-Listen stand danach „nein“, und die Adresse galt
weiter als beantwortet; auf web.herkules traf das am 05.10.2026 alle 970 Antworten. Ein
Merkmal aus der Antwort bleibt jetzt stehen, ein Merkmal der Listen kommt dazu. Land,
Provider und Tor aus der Antwort bleiben, solange dafür keine lokale Quelle gewählt ist.
Wird der Dienst abgewählt, schlagen die Listen jede Adresse neu nach, und seine Merkmale
gehen mit.

### Einspielen

Danach einmal die Einstellungen der Abwehr speichern, damit der Auftrag „Herkunft der
Adressen“ die X4BNet-Listen lädt. Adressen, die proxycheck.io vor 0.40.2 beantwortet hat,
tragen seine Merkmale nicht mehr; neu gefragt werden sie, nachdem ihr Zustand zurückgesetzt
ist: `UPDATE malwatch_waf_ip SET external_state = 'none', external_at = NULL,
external_tries = 0 WHERE external_state = 'done'`. Danach kommen nur die ohne Merkmal der
Listen an die Reihe.

### Tests

`waf_class_probe.php` prüft den Ablauf mit beiden Stufen: welche Adressen gefragt werden,
dass eine Antwort einen neuen Abgleich übersteht, dass ein Merkmal der Listen dazukommt, dass
eine später bekannte Adresse die Schlange verlässt und dass beim Abwählen die Merkmale des
Dienstes gehen. `waf_proxycheck_test.php` prüft, wer welches Merkmal schreibt,
`waf_origin_sources_test.php` die Quellen der neuen Wahl, `waf_panel_test.php` ihre Zeilen.

## [0.40.1] – 2026-10-05

### Behoben

**Wiederherstellen aus der Quarantäne schreibt nur innerhalb des Webstamms.** Das gilt auch
für die selbsttätige Rücknahme eines Upgrades, das die Website stört. Jeder Schritt geht über
ein `os.Root` auf dem Zielordner, das einen Weg hinaus im Moment des Schreibens abweist;
Rechte, Zeiten und Besitzer setzt der Scanner über die geöffnete Datei. Einen Link legt er
über den geöffneten Elternordner an (`/proc/self/fd`, auf Linux immer vorhanden). Ein Link
kommt weiter so zurück, wie er in die Quarantäne kam, auch wenn er aus dem Webstamm zeigt.
Gemeldet von CodeQL (go/unsafe-unzip-symlink, go/zipslip).

**Entfernen beim Verschieben in die Quarantäne und vor `restore --force`** geht denselben
Weg und bleibt im Webstamm.

**Release-Workflow:** Der Tag erreicht den Schritt „Resolve version“ als Umgebungsvariable
und muss die Form v1.2.3 haben, ein Zusatz wie -rc.1 ist erlaubt. Gemeldet von Semgrep
(run-shell-injection).

**Reparatur, Overlay, Upgrade-Rücknahme und das Ablegen in die Quarantäne greifen über
`os.Root` zu, wie die Wiederherstellung.** `repair.Swap`, `SwapCore` und `Overlay`, die
Rücknahme eines Upgrades (`upgrade.rollBack`) und das Packen eines Baums in die Quarantäne
(`quarantine.writeArchive`) gehen jeden Schritt über ein `os.Root` auf dem Webstamm, das einen
Weg hinaus im Moment des Zugriffs abweist. Rechte und Besitzer setzt der Scanner über den
Dateideskriptor, das Löschen und das Lesen gehen über `os.Root`. Die gemeinsamen Helfer liegen
jetzt in `internal/rootio`, das auch die Wiederherstellung aus der Quarantäne nutzt. Ein Link,
der im Webstamm bleibt, wird weiter verfolgt; ein geteilter Upload-Ordner als Link bleibt
erhalten, wie er war.

### Tests

- `internal/quarantine/archive_test.go`: ein Archiv mit einem Link ins Leere und danach
  einer Datei unter demselben Namen, eines mit einem Link auf einen Ordner außerhalb und einer
  Datei darunter. Beide weist `readArchive` ab, außerhalb entsteht nichts, die Meldung nennt
  den Link. `removeAllIn` entfernt einen Link im Baum samt Ordner und lässt sein Ziel stehen;
  einen Namen hinter einem Link nach außen weist es ab.
- `internal/quarantine/archive_test.go`: `writeArchive` über einen Ordner, der zu einem Link
  aus dem Webstamm gewechselt ist, liest nichts von außen und meldet den Link.
- `internal/repair/rootsafe_test.go`: `Swap` legt einen bereitgestellten Baum über `os.Root`
  ab und weist einen Baum hinter einem Link aus dem Webstamm ab; `SwapCore` legt ein frisches
  Kernverzeichnis an; `Overlay` hält an einem Link, der aus dem Webstamm führt, und schreibt
  nichts dahinter.
- `internal/upgrade/rollback_root_test.go`: `removeAdded` entfernt das vom Release Angelegte
  über `os.Root` und lässt eine Datei hinter einem Link aus der Installation stehen.

## [0.40.0] – 2026-09-30

### Hinzugefügt

**HTML-Mail an den Betreiber.** Die Mail bei neuen Funden kommt als HTML mit der
Textfassung als Alternative: je Datei die Stufe mit ihrer Farbe, die Regeln, warum, was die
Datei tut, was zu tun ist und der Knopf „Im Panel ansehen“. Die Vorlage
`malwatch_notification_de.html` (und `_en`) wird mitgeliefert und ist neutral gehalten;
eine eigene unter `conf-custom/mail/` geht vor, so wie ISPConfig es bei seinen eigenen Mails
hält. Die Gestaltung steht ganz in der Vorlage: `{…}` für Werte, `{name_block}…{/name_block}`
für Teile, die nur bei Bedarf erscheinen, `{finding_block}…{/finding_block}` je Datei,
`{img:logo.png}` für ein Bild aus dem Ordner der Vorlage, das eingebettet mitkommt, und ein
Kommentar `malwatch-colors` für die Farben der Stufen. Jeder Wert wird maskiert; aus einem
Fund gelangt kein Markup in die Mail.

**`malwatch send-mail`.** Stellt eine fertig gebaute Mail zu, über einen SMTP-Server
(`--smtp`, `--smtp-user`, `--smtp-tls=none|starttls|tls`, `--smtp-insecure`) oder über
sendmail. Das Passwort kommt aus `--smtp-pass-file` oder der Umgebungsvariablen
`MALWATCH_SMTP_PASS`, nie von der Befehlszeile. Das Addon nutzt dafür denselben SMTP-Server
wie ISPConfig (System > Hauptkonfiguration > Mail), weil ISPConfigs eigener Mailer eine
Textfassung, eine HTML-Fassung und eingebettete Bilder nebeneinanderlegt und Mailprogramme
dann alles zeigen.

**Einstellungen unter Scanner > Einstellungen > Mail:** „Format der Mails“ (HTML mit
Textfassung oder nur Text), „Name des Absenders“ (Vorgabe malwatch) und „Zertifikat des
SMTP-Servers prüfen“ (Vorgabe an).

### Geändert

**`php.remote.fetch_eval_indirect` ohne selbsttätige Quarantäne:** Alte XML-RPC-Bibliotheken
holen per curl und führen danach eine Variable aus. Am 29.09.2026 hat die Regel so SeedProds
`infusionsoft/xmlrpc-2.0/lib/xmlrpc.inc` auf vier Websites selbst in die Quarantäne gelegt.
Sie meldet weiter mit „kritisch“; ob die Datei verschoben wird, entscheidet ein Mensch.

**Rückweg bei Fehlern:** Scheitert die HTML-Mail (Scanner fehlt, SMTP lehnt ab), geht
dieselbe Mail als Text über ISPConfig, und das Protokoll der Aktionen nennt den Grund. Fehlt
ein Bild, das die Vorlage einbetten will, steht das im Protokoll von ISPConfig.

**Datum und Zahlen** stehen in den Mails so, wie man sie liest: 29.09.2026, 18:20 und
38.619 (englisch 2026-09-29 18:20 und 38,619).

### Behoben

**Wiederherstellen, Löschen und Herunterladen in der Quarantäne:** Das Panel legt diese
Aufträge ohne Webordner an, weil sie mit den Kennungen der Einträge arbeiten. Der Runner
verlangte für jeden Auftrag einen vorhandenen Ordner und lehnte sie mit „Der zu prüfende Pfad
existiert nicht.“ ab; seit es die drei Knöpfe gibt (07.09.2026), erreichten sie den Scanner
nie. Jetzt brauchen nur Aufträge auf einer Website einen Ordner, und ihre Meldung nennt
Website, Ordner und den nächsten Schritt.

**Legende der Fundseite:** „Treffer einer Regel“ stand immer in Pink, der Farbe von
„kritisch“, auch wenn die Treffer im Code die Farbe ihrer Stufe trugen, etwa Bernstein bei
„mittel“. Die Legende nimmt jetzt die Farbe der schwersten Stufe auf der Seite. Weil Stufen
und Fähigkeiten sich die Töne teilen (mittel und „aufpassen“ sind beide Bernstein), hat ein
Treffer zusätzlich einen Rahmen, fette Schrift und einen breiteren Balken am Zeilenrand.

### Einspielen

Das Schema legt `mail_format`, `mail_from_name` und `mail_smtp_verify` in `malwatch_config`
an. Scanner und Addon gehören zusammen: Das Addon ruft ab 0.40.0 `malwatch send-mail` auf,
das erst der Scanner 0.40.0 kennt; mit einem älteren Scanner geht die Mail als Text raus.

### Tests

- `cmd/malwatch/sendmail_test.go`: Zustellung an einen SMTP-Server im Test, Anmeldung mit dem
  Passwort aus der Umgebung und aus einer Datei, CRLF und Punkt-Maskierung, abgelehnte
  Eingaben.
- `ispconfig/tests/mail_html_test.php` (neu, in der CI): Maskieren, Abschnitte, Farben aus der
  Vorlage und neutraler Rückfall, eingebettete Bilder, fehlende Bilder, keine Pfade aus dem
  Ordner hinaus, beide mitgelieferten Vorlagen ohne übrige Platzhalter, der MIME-Aufbau
  (related um alternative, CID, Quoted-Printable, keine Zeile über 998 Zeichen, kodierter
  Betreff), die Befehlszeile ohne Passwort, die Mail eines Laufs mit Obergrenze der Dateien.
- `check_wiring.sh` Prüfung 104: Schema, Vorgaben, Formular, Seite und Texte der
  Mail-Einstellungen, installierte Klassen und Vorlagen, dieselbe Umgebungsvariable in Scanner
  und Addon, kein Passwort auf der Befehlszeile, HTML-Weg und Rückweg, der CI-Schritt.
- `ispconfig/tests/finding_view_test.php`: Die Legende nimmt die Klasse der Seite, die Seite
  setzt sie aus der schwersten Stufe; Treffer jeder Stufe mit Rahmen, fetter Schrift und
  breitem Balken, Fähigkeiten ohne Rahmen mit schmalem Balken.
- `ispconfig/tests/render_pages.php`: rendert die Seite eines Funds, dessen Datei eine
  Ansicht hat, und verlangt dann Codezeilen.
- `internal/rules/catalog_test.go`: `php.remote.fetch_eval_indirect` trägt kein AutoSafe.
- `ispconfig/tests/quarantine_jobs_test.php` (neu, in der CI): Wiederherstellen, Löschen und
  Herunterladen starten ohne Webordner; Prüfung und Verschieben in die Quarantäne verlangen ihn
  weiter und nennen in der Meldung Website und Ordner.

## [0.39.0] – 2026-09-29

### Hinzugefügt

**Fundansicht.** Jede gemeldete Datei hat im Panel eine eigene Seite (Liste der Funde und
Seite der Website: „Ansehen“). Sie zeigt, warum die Datei gemeldet wurde, was sie tut und
ihren Code mit den auffälligen Stellen markiert, und daneben die Knöpfe „Kein Befund“,
„Wieder melden“ und „In Quarantäne verschieben“. Der Code ist Text einer Kundenseite und
erscheint immer maskiert; eine Markierung teilt nie ein Zeichen.

**Erklärungen je Regel.** Alle 71 Regeln des Katalogs und die vier Quellen außerhalb
(abweichende Herstellerdatei, fremde Datei im Herstellerordner, Signaturliste, ClamAV)
sagen in einfachen Worten, was sie gesehen haben, was das bedeutet und was zu tun ist.
`malwatch rules --json` liefert beides als `explain` und `advice`, die Quellen außerhalb
unter `extras`. Ein Test verlangt eine Erklärung für jede Regel und verbietet Erklärungen
zu Regeln, die es nicht mehr gibt.

**Was die Datei tut.** Für jede Datei mit Funden nennt der Scanner ihre Fähigkeiten laut
Quelltext, jeweils mit Zeilen: gefährlich (führt Shell-Befehle aus, führt Text als Code
aus, bindet Code von fremden Adressen ein, ändert die Crontab, startet Hintergrund-
prozesse), zum Aufpassen (entschlüsselt Text, versteckt Namen in Hex, lädt aus dem Netz,
nimmt Uploads an, schreibt Dateien, entpackt Archive, verschickt Mails, schaltet
Fehlermeldungen ab), Hinweis (liest Anfragedaten) und Schutz (läuft nur in WordPress oder
Joomla, verlangt eine Anmeldung, prüft Rechte, arbeitet mit einem Formular-Token). Eine
Fähigkeit allein ist nie ein Fund.

**Markierte Stellen im Bericht.** Ein Fund einer Regel trägt jede Stelle, an der ihr Muster
greift, dazu die erste Stelle jeder Zusatzbedingung (`marks`: Zeile, Spalte, Länge).
Treffer in der zusammengesetzten Sicht zeigen auf die Stelle in der Datei.

**Neue Schalter für `malwatch scan`:** `--view-lines` (ganze Datei bis so viele Zeilen,
sonst Ausschnitte; Vorgabe 400, 0 schaltet den Code ab), `--view-context` (Zeilen um jede
Stelle, 5), `--view-line-length` (Bytes je Zeile, 300; längere Zeilen behalten den Teil um
die Markierung), `--view-marks` (Stellen je Regel und Fähigkeit, 20) und `--view-budget`
(MiB Code je Bericht, 32; darüber behalten weitere Dateien ihre Fähigkeiten und verlieren
den Code). Werte außerhalb der Grenzen lehnt der Scanner mit dem Namen des Schalters ab.
Der Bericht führt die Ansichten unter `files`, je Inhalt einmal.

**Einstellungen im Panel.** Scanner > Einstellungen hat den Abschnitt „Fundansicht“ mit
denselben Werten, dazu „Ansicht behalten (Tage)“ (Vorgabe 30) und unter „Mail“ die
„Adresse des Panels“. Ein gespeicherter Wert außerhalb der Grenzen hält keine Prüfung auf:
Der Scanner bekommt dann die Vorgabe.

### Geändert

**Die Mail an den Betreiber** nennt je Datei die Stufe, die Regeln mit Titel, den Grund
(die Erklärung der schwersten Regel) und was die Datei tut, gekürzt auf 78 Zeichen je
Zeile. Mit eingetragener Adresse des Panels steht darunter „Ansehen“ mit einem Link, der
die Seite des Fundes öffnet, sobald das Panel angemeldet ist (Skript
`js/js.d/malwatch-finding-link.js`). Die Vorlagen kennen dafür `{panel_url}` und den
Abschnitt `{panel_block}`.

**Der Regelkatalog** wird zusätzlich eingelesen, sobald das Programm des Scanners neuer ist
als die gespeicherte Liste. Bis 0.38.0 dauerte das nach einem Update bis zu einen Tag.

### Einspielen

Das Schema legt `malwatch_file` an (eine Ansicht je Inhalt), dazu `malwatch_finding.marks`,
`malwatch_rule.explanation` und `.advice` sowie die Einstellungen `view_lines`,
`view_context`, `view_line_length`, `view_marks`, `view_budget`, `view_keep_days` und
`panel_url` in `malwatch_config`. Scanner und Addon gehören zusammen: Das Addon gibt ab
0.39.0 die Schalter `--view-*` mit, die erst der Scanner 0.39.0 kennt. Ansichten entstehen
bei der nächsten Prüfung einer Website; bis dahin sagt die Seite eines Fundes das.

### Tests

- `internal/traits`, `internal/fileview`, `internal/textpos`: Fähigkeiten eines alten
  Uploaders und einer Probe mit Shell-Aufruf, Methoden gleichen Namens, Reihenfolge und
  Grenzen; ganze Datei, Ausschnitte, Grenze der Zeilen, lange Zeilen um die Markierung,
  gleiche Länge in Bytes nach dem Ersetzen, Binärdateien; Zeilen und Stellen.
- `internal/rules/marks_test.go`, `explain_test.go`: Stellen je Treffer und Zusatzbedingung,
  die Grenze; eine Erklärung je Regel, keine verwaisten, Rat je Stufe, echte Umlaute.
- `internal/scanner/view_test.go`: Stellen, Fähigkeiten und Code im Bericht, das Budget,
  ohne Einstellungen kein Code.
- `cmd/malwatch`: Erklärungen im Katalog, die Hilfe nennt Vorgaben und Grenzen der Schalter
  aus dem Code, ein Wert außerhalb wird abgelehnt.
- `ispconfig/tests/finding_view_test.php` (neu, in der CI): Maskieren jeder Zeile,
  Markierungen, Überlappung, Mehrbyte-Zeichen, Zeilen der Ansicht, Einlesen von Stellen und
  Ansichten, gleiche Grenzen in Panel und Server, die Adresse des Panels, die Funde in der
  Mail samt Breite.
- `check_wiring.sh` Prüfung 103: Vorgaben und Grenzen in Scanner, Panel, Server und Schema,
  Felder, Hinweise und Texte, Runner, Hilfe, Installation und Links, Erklärungen im Katalog.

## [0.38.0] – 2026-09-28

### Hinzugefügt

**Regeln gegen Einnistung auf dem Server.** Anlass war das Schad-Plugin AzimutAV vom
28.09.2026 auf esport-mv.de: Es legte ein Startskript in `wp-content/uploads`, trug es in
die Crontab des Webbenutzers ein, lud damit ein Linux-Programm nach und startete es im
Hintergrund. malwatch 0.35.1 erkannte davon nichts. Neu:

| Regel | Stufe | Was sie meldet |
|---|---|---|
| `php.dropper.cron` | kritisch, eindeutig | PHP macht eine Datei ausführbar und trägt sie über einen Shell-Aufruf in die Crontab ein |
| `php.exec.crontab` | hoch | PHP ändert die Crontab über einen Shell-Aufruf |
| `php.exec.background` | mittel | PHP startet einen Prozess im Hintergrund |
| `shell.fetch_exec` | kritisch, eindeutig | ein Shell-Skript lädt ein Programm aus dem Netz, macht es ausführbar und startet es im Hintergrund |
| `shell.in_uploads` | hoch | ein Shell-Skript in einem Upload-Ordner |
| `binary.elf_in_uploads` | kritisch | ein Linux-Programm in einem Upload-Ordner |
| `binary.elf` | mittel | ein Linux-Programm anderswo im Webverzeichnis |

„Eindeutig“ heißt: Die automatische Aktion „Eindeutige Schädlinge entfernen“ verschiebt
solche Dateien nach einer geplanten Prüfung in die Quarantäne. Shell-Skripte erkennt der
Scanner an `.sh` und `.bash` oder an der ersten Zeile (`#!/bin/sh`, `#!/usr/bin/env bash`
und ähnliche), auch ohne Endung.

**Große Dateien.** Dateien über der Größengrenze (`--max-size`, Vorgabe 32 MiB) liest der
Scanner weiter nicht ganz, prüft aber ihren Anfang: Ein aufgeblähtes Programm fällt so
trotzdem auf.

**Upload-Ordner als Einstellung.** Die Liste der Upload-Ordner stand fest im Scanner. Sie
steht jetzt unter Scanner > Einstellungen („Ordner für hochgeladene Dateien“, bis zu 16
Namen mit je höchstens 30 Zeichen) und geht als `--upload-dirs` an den Scanner;
`php.in_uploads` nutzt dieselbe Liste. Ein gespeicherter Wert, den die Seite abweisen würde,
hält keine Prüfung auf: Es gelten seine brauchbaren Namen, sonst die Vorgabe.

**CI.** Der gebaute Scanner jedes Commits liegt sieben Tage als Artefakt
`malwatch-linux-amd64` bereit, für einen Lauf über echte Websites vor dem Tag.

### Einspielen

Das Schema legt `malwatch_config.upload_dirs` an. Scanner und Addon gehören zusammen: Das
Addon gibt ab 0.38.0 `--upload-dirs` mit, und das kennt erst der Scanner 0.38.0.

Den Regelkatalog liest der Cron-Job einmal am Tag in `malwatch_rule`; erst dann kennt das
Addon die Titel der neuen Regeln und welche davon eindeutig sind. Nach dem Einspielen
`<state_dir>/state/rules.json` löschen, dann liest er ihn im nächsten Lauf.

### Tests

- `internal/rules/persistence_test.go`: Treffer und Nicht-Treffer für jede neue Regel,
  andere Upload-Ordner, der Anfang großer Dateien, die Erkennung von Shell-Skripten. Die
  Beispiele sind aus Stücken zusammengesetzt und enthalten kein Webshell-Muster, weil der
  Virenschutz auf dem Arbeitsrechner solche Testdateien löscht.
- `internal/scanner/programs_test.go`, `internal/walk/large_test.go` und
  `cmd/malwatch/upload_dirs_test.go`: große Programme samt Freigabeliste, die Upload-Ordner
  bis in den Cache und auf der Kommandozeile.
- `ispconfig/tests/upload_dirs_test.php` (neu, in der CI): Vorgabe, Grenzen, das Muster der
  Seite, das Aufräumen der Eingabe und die Namen für den Scanner.
- `check_wiring.sh` Prüfung 102: dieselbe Vorgabe und dieselben Grenzen in Scanner, Panel
  und Server, Feld, Texte, Runner, und kein Upload-Muster mehr im Katalog.

## [0.37.0] – 2026-09-28

### Geändert

**Zeitplan in Tagen.** Die Einstellungen einer Website haben das Feld „Abstand der
Prüfungen (Tage)“: Alle so viele Tage prüft malwatch die Website von selbst, 0 schaltet den
Zeitplan aus, erlaubt sind 0 bis 365. Die festen Stufen von vorher gehen beim Einspielen
einmal in Tage über: täglich 1, wöchentlich 7, monatlich 30, aus 0. Ein kürzerer Abstand
zieht die nächste Prüfung vor, ein längerer gilt ab der nächsten. Wer andere Einstellungen
der Website speichert, lässt die geplante Prüfung, wo sie ist.

**Die Wache rechnet mit Tagen.** Einen neuen oder geänderten Abstand zählt sie ab dem
Zeitpunkt, an dem sie ihn zuerst sah; sie merkt ihn sich in `watch.json` unter `plans`.
Wer alle Websites auf einen kurzen Abstand stellt und die ersten Prüfungen darüber
verteilt, bekommt so keinen Alarm für Websites, die noch an die Reihe kommen. Eine Website,
die noch nie geprüft wurde, meldet sie, sobald Abstand und Spielraum vorbei sind („noch nie
geprüft“).

**Texte.** Aus den „nächtlichen Prüfungen“ auf Scanner > Einstellungen werden „geplante
Prüfungen“: Die Prüfungen verteilen sich über den ganzen Tag. Fehlt das Webverzeichnis
einer Website, nennt das Protokoll von ISPConfig Website und Verzeichnis und was zu tun ist.

### Behoben

**Die Vorgabe für neue Websites wirkt.** Bis 0.36.0 zeigte Scanner > Einstellungen eine
Vorgabe („wöchentlich“), die keine Website erreichte: Neue Websites bekamen ihre Zeile ohne
Zeitplan, auf web.herkules stand er bei 60 von 61 Websites auf „aus“. Das Feld heißt jetzt
„Abstand der Prüfungen für neue Websites (Tage)“ (Vorgabe 7). Jede aktive Website ohne
eigene Einstellungen bekommt innerhalb einer Minute eine Zeile mit diesem Abstand, ihre erste
Prüfung liegt zufällig innerhalb des Abstands. Bei 0 prüft malwatch Websites ohne eigene
Einstellungen nur auf Anstoß, wie bisher.

**Geplante Prüfungen zur geplanten Zeit.** Den Zeitpunkt der nächsten Prüfung schreibt jetzt
MySQL selbst (`FROM_UNIXTIME`). Bis 0.36.0 schrieb ihn PHP in der Zeitzone von ISPConfig;
auf web.herkules ist das `Etc/UTC`, MySQL vergleicht mit `NOW()` in Europe/Berlin, und jede
Prüfung wurde zwei Stunden zu früh fällig. Die Wache liest das Ende eines Scans in der
Zeitzone von ISPConfig und nennt es in der Uhrzeit des Servers; bisher stand in ihren
Meldungen eine um zwei Stunden verschobene Zeit.

### Einspielen

Das Schema legt `malwatch_site.scan_days` und `malwatch_config.default_scan_days` an und
füllt sie einmal aus `schedule` und `default_schedule`. Die alten Spalten bleiben für den
Rückweg zu 0.36 stehen. `waf/install.sh` braucht keinen neuen Lauf.

### Tests

- `panel_helpers_test.php`: die Planung beim Speichern (`malwatch_plan_next_run()`) mit
  2 Tagen und anderen Abständen, die Vorgabe `default_scan_days`.
- `scan_days_test.php` (neu, in der CI): die nächste Prüfung nach Tagen und die erste
  Prüfung einer neuen Website, zufällig innerhalb des Abstands.
- `waf_lib_test.php`: die Wache mit Tagen, der Beginn eines neuen Abstands, Websites ohne
  Prüfung, Zeiten aus einer anderen Zeitzone (`waf_time_in_zone()`).
- `tests/schedule_probe.php` (neu, als root auf dem Server): die Übertragung der Stufen, ein
  zweites Update, Zeilen für Websites ohne Einstellungen, die Planung nach Tagen gegen
  `NOW()`, das fehlende Webverzeichnis. `tests/watch_probe.php` rechnet mit Tagen und mit den
  Zeitzonen wie `waf-switch`; `tests/waf_class_probe.php` lädt den Helfer aus dem Prüfstand.
- `check_wiring.sh` Prüfung 101: Spalten, Felder mit Grenzen und Texten, Planung und Wache
  nach `scan_days`, kein Code mehr mit den alten Stufen.

## [0.36.0] – 2026-09-28

### Hinzugefügt

**Wache über den Scanner.** `waf-switch watch` läuft aus der Cron-Datei der Abwehr
alle fünf Minuten über `hc-run malwatch-wache`, neben dem Cron von ISPConfig. Sie meldet:

- eine Sperre, die ISPConfig länger als 15 Minuten als „läuft“ führt; läuft dabei kein
  `cron.php` von ISPConfig mehr, löst sie die Sperre,
- einen Cron-Job, der nicht mehr läuft, und einen Absturz,
- Aufträge, die länger als 180 Minuten warten,
- Websites, deren letzter Scan länger zurückliegt als ihr Zeitplan plus 12 Stunden.

Probleme stehen im Protokoll von ISPConfig, der Check in healthchecks wird rot, OpsKnight
bekommt über `hc-run` einen Vorfall, und die Admin-Adresse aus Scanner > Einstellungen
bekommt eine Mail: beim ersten Mal, nach 24 Stunden als Erinnerung und als Entwarnung.

**Selbstfreigabe nach einem Absturz.** Stirbt ein Lauf des Cron-Jobs an einem Fehler, den
kein Abfangen erreicht, etwa am Speicher, gibt er sich frei und startet nach zehn Minuten
neu. ISPConfig hielte ihn sonst 24 Stunden lang für laufend, und der Cron von ISPConfig
verlöre bei jedem Lauf die Jobs, die nach malwatch an der Reihe sind.

**Einstellungen** unter Abwehr > Einstellungen > Takt und Hintergrund: Abstand der Wache
(5 Minuten), Sperre hängt nach (15 Minuten), Pause nach einem Absturz (10 Minuten),
Aufträge warten höchstens (180 Minuten), Spielraum für Scans (12 Stunden), Erinnerung nach
(24 Stunden). Der Name des Checks steht bei den Orten (`MALWATCH_WAF_HC_WATCH_NAME`,
Vorgabe `malwatch-wache`).

### Einspielen

`waf/install.sh` erneut ausführen: Es legt `waf-switch` mit dem Befehl `watch` ab und
schreibt die Cron-Datei mit der dritten Zeile. Für healthchecks einen Check anlegen und
seine Ping-Adresse in `/etc/hc-run.d/malwatch-wache.url` schreiben.

### Tests

- `waf_lib_test.php`: die Regeln der Wache mit den Vorgaben und mit anderen Werten, die
  Mails und die Zeile der Cron-Datei; die Vorlage `fixtures/waf/cron-malwatch-waf` hat die
  dritte Zeile.
- `tests/watch_probe.php` und `tests/cron_guard_probe.php` laufen als root auf dem Server:
  die Wache gegen eine Wegwerf-Datenbank, und ein Lauf des Cron-Jobs, der am Speicher stirbt.
- `check_wiring.sh` Prüfung 85 kennt die sechs Zahlen, Prüfung 100 die Zeile der Wache, den
  Befehl `watch` und die Selbstfreigabe.

## [0.35.2] – 2026-09-28

### Behoben

**Der Cron-Job von malwatch läuft wieder und startet Scans.** Seit 0.32.0 las
`tick_is_fresh()` die Frist des Minutentakts aus den Einstellungen, ohne die
Bibliothek der Abwehr zu laden. Jeder Lauf des ISPConfig-Cron-Jobs endete
deshalb mit „Call to undefined function waf_settings()“, und ISPConfig ließ den
Job danach jeweils 24 Stunden als „läuft“ stehen. Auf web.herkules startete vom
26.09. um 13:21 Uhr bis zum Rollout dieser Version kein Scan und kein
Schwachstellenabgleich. Die Abwehr lief weiter, ihr Minutentakt hat eine eigene
Cron-Datei.

- `malwatch_waf` lädt seine Bibliotheken beim Anlegen. Fehlt eine, nennt
  `settings()` sie und bittet darum, das Paket erneut einzuspielen.
- Jeder Abschnitt des Cron-Jobs fängt auch PHP-Fehler (`Throwable`) ab, das
  Laden der Helfer eingeschlossen. Ein Fehler steht mit Art, Datei und Zeile im
  ISPConfig-Protokoll, die übrigen Abschnitte laufen weiter, und ISPConfig gibt
  den Job am Ende des Laufs frei.
- Die Meldungen dieser Abschnitte sind deutsch und sagen, wie es weitergeht.

### Tests

- `check_wiring.sh` Prüfung 98: Die Klasse der Abwehr lädt ihre Bibliothek beim
  Anlegen, und `settings()` prüft sie. Prüfung 99: Jeder Abschnitt des
  Cron-Jobs fängt `Throwable`, auch das Laden der Helfer.
- `tests/waf_fresh_probe.php` lädt die Klasse wie der Cron-Job in einem frischen
  PHP-Prozess. `tests/cron_section_probe.php` lässt den Cron-Job mit einem
  WAF-Teil laufen, der einen Error wirft, und prüft, dass Protokolleintrag und
  Aufräumarbeiten folgen. Beide laufen als root auf dem Server.

## [0.35.1] – 2026-09-27

### Behoben

**`waf/install.sh` läuft auch aus einem Ordner, dessen Skripte kein
Ausführrecht haben.** In 0.35.0 standen `install.sh`, `waf-switch`, `waf-guard`
und `waf-report` im Repository ohne Ausführrecht, und ein Ordner aus
`git archive` brach beim ersten Aufruf von `waf-switch` mit „Permission denied“
ab, bevor er etwas änderte. Die vier Skripte tragen jetzt das Ausführrecht, und
der Installer startet `waf-switch` seines Ordners notfalls über `php`.

## [0.35.0] – 2026-09-27

### Hinzugefügt

**Die Orte und Namen der Abwehr sind Einstellungen.** Jeder Pfad, den die Abwehr
auf dem Server anlegt oder liest, steht in den Einstellungen; Vorgabe ist der
bisherige Wert. Mit den Vorgaben schreibt der Installer jede Datei Byte für Byte
wie bisher.

- nginx: Regelverzeichnis, Einbindung der Regeln und der Sperrliste, Name des
  Dienstes.
- ModSecurity und CRS: Grundkonfiguration, Einstellungen und Regeln der CRS,
  Regelprüfung, Zwischenspeicher.
- Protokolle und Sicherungen: Audit-Log, Sperrprotokoll, Protokoll der Wache,
  Sicherungen, logrotate-Datei.
- Werkzeuge und Takt: Ordner der Werkzeuge, Cron-Datei, hc-run (leer: die Läufe
  starten direkt), die Namen der beiden Checks in Healthchecks und die
  Programmverzeichnisse.

Ein Ort ändert sich über den Installer, mit der Variablen und dem neuen Wert vor
dem Aufruf, etwa `MALWATCH_WAF_CONF_DIR=/pfad waf/install.sh`. Er legt den neuen
Ort an, prüft mit Regelprüfung, `nginx -t` und `nginx -T` und speichert erst
danach; scheitert ein Schritt, legt er jede Datei zurück, und die Einstellungen
behalten ihren Wert. `--check` zeigt vorher, was sich ändert. Vor einem neuen
Sperrprotokoll fragt er nach, weil dann jede Website mit Abwehr neu geschrieben
wird; ohne Terminal bestätigt `--yes`. `waf-switch paths` listet alle Orte mit
ihrer Variablen, und Security > Abwehr > Einstellungen zeigt sie unter „Stand auf
dem Server“.

**Neu im Panel.** Unter „Takt und Hintergrund“ die Minute der Wache (Vorgabe 5)
und die Minute des Stundenlaufs (Vorgabe 7). Unter „Technik“ die Gruppe
ModSecurity: Anfragekörper bis 12.800 KB, ohne Dateien bis 128 KB, größere
Anfragen „Anfang prüfen“ oder „Ablehnen“. `settings.conf` entsteht aus diesen
Werten; der Auftrag nach dem Speichern übernimmt sie mit Regelprüfung,
`nginx -t` und Reload und schreibt die Cron-Datei der Abwehr neu.

### Geändert

- Die Wache läuft aus der Cron-Datei der Abwehr; der Installer nimmt ihre Zeile
  aus der crontab von root.
- `waf-guard` und `waf-report` finden `waf-switch` neben sich und nehmen
  Protokoll und Audit-Log aus den Einstellungen.
- nginx, systemctl, logrotate, fail2ban-client und modsec-rules-check sucht die
  Abwehr in den Programmverzeichnissen; fehlt eines, nennt der Auftrag die
  durchsuchten Verzeichnisse.
- Fällt der eigene Takt aus, startet der Cron von ISPConfig den Stundenlauf der
  Abwehr zur Minute aus den Einstellungen.
- Der Installer erkennt das nginx-Modul an `nginx -T`.

## [0.34.0] – 2026-09-26

### Hinzugefügt

**Die technischen Werte der Abwehr sind Einstellungen.** Security > Abwehr >
Einstellungen hat den neuen Abschnitt „Technik“ mit 46 Einstellungen in fünf
Gruppen. Die Vorgaben sind die bisherigen Werte; das Verhalten ändert sich erst,
wenn jemand einen Wert ändert.

- Quellen der Herkunft: für jede der acht Quellen (DB-IP und MaxMind je Land und
  Provider, Tor, X4BNet VPN und Rechenzentren, Suchmaschinen) die Adressen, eine
  je Zeile, bei DB-IP mit `{month}` für den Monat, dazu die Mindestzahl an
  Einträgen und die Höchstgröße in MB. Dazu die zwei Schwellen der
  Plausibilitätsprüfung: höchstens 1 % unlesbare Zeilen, mindestens 50 % des
  bisherigen Stands.
- Downloads: Verbindungsaufbau 10 s, Download 120 s, 3 Weiterleitungen.
- proxycheck.io: Adresse des Dienstes, 100 Adressen je Anfrage, Antwort bis 2 MB,
  Verbindungsaufbau 5 s, Antwort 10 s, ein Fehlschlag wird nach 60 Minuten erneut
  gefragt, höchstens 3 Versuche.
- Arbeit im Hintergrund: 500 Adressen je Lauf nachschlagen, alte Treffer in 50
  Schritten zu je 1.000 löschen, Antwortdateien ohne Treffer nach 60 Minuten
  löschen, 20.000 Zeilen von `blocked.log` je Lauf, bis zu 50 Regelmeldungen je
  Treffer.
- Anzeige und Kommandozeile: 50 Pfade auf der Seite einer Website, Vorschau einer
  Ausnahme 300 ms nach der letzten Eingabe, `waf-switch jobs` zeigt 20 Aufträge,
  `waf-switch` wartet 2 Minuten über die Frist eines Auftrags hinaus und fragt im
  Abstand von „Aktualisierung laufender Aufträge“ nach.

Adressen müssen mit `https://` beginnen. Eine Quelle ohne Adresse und mehr als
eine Adresse für proxycheck.io nimmt das Formular nicht an, jeweils mit einer
Meldung, die Ursache und nächsten Schritt nennt. Adressfelder nutzen die volle
Breite und wachsen mit ihrem Inhalt.

### Behoben

**DB-IP greift beim Monatswechsel sauber auf den Vormonat zurück.** Bisher
rechnete der Code „jetzt minus 15 Tage“ und versuchte ab dem 16. eines Monats den
laufenden Monat zweimal. Der Rückfall ist jetzt immer der Kalender-Vormonat.

## [0.33.0] – 2026-09-26

### Hinzugefügt

**Vor dem Speichern zeigt ein Fenster, was sich ändert.** Auf Security > Abwehr >
Einstellungen und Security > Scanner > Einstellungen öffnet jeder Knopf, der die
Einstellungen speichert, das Fenster „Änderungen prüfen“. Es listet jede
geänderte Einstellung nach Abschnitt, mit bisherigem und neuem Wert: Zahlen mit
Einheit, Auswahlfelder und Automatik-Karten mit ihrer Beschriftung, Schalter als
an und aus, bei Listen die Einträge, die dazukommen (+) und wegfallen (−). Ein
entferntes eigenes Netz trägt den roten Hinweis „Schutz fällt weg“. Schlüssel
erscheinen nur als Maske, ein neuer mit seinen letzten vier Zeichen. „Speichern“
speichert, „Weiter bearbeiten“ führt zurück ins Formular. Ohne Änderung meldet
das Fenster „Nichts geändert“ und bietet „Trotzdem speichern“ an; auf der Seite
der Abwehr stößt das die Übernahme auf den Servern erneut an.

Das Fenster vergleicht mit dem gespeicherten Stand aus der Datenbank. Nach einem
abgelehnten Speichern zeigt es deshalb alle Änderungen, die noch offen sind,
auch die aus dem ersten Versuch.

## [0.32.0] – 2026-09-26

### Geändert

**Die Einstellungen der Abwehr sind neu geordnet.** Security > Abwehr >
Einstellungen hat elf Abschnitte zum Auf- und Zuklappen: Sperren, Angemeldete
Nutzer, Nie sperren, Verdächtige Herkunft, Herkunft der Adressen, fail2ban,
Scharf schalten, Anzeige, Aufbewahrung, Takt und Hintergrund, Stand auf dem
Server. Jeder Titel sagt in einer Zeile, wie der Abschnitt gerade eingestellt
ist, etwa „Automatik sperrt · ab 50 Punkten in 10 Minuten · 1 → 24 → 168
Stunden“. Die Suche oben filtert Felder und Abschnitte. Ein Wert, der von der
Vorgabe abweicht, trägt einen Punkt, nennt die Vorgabe und lässt sich mit
„Vorgabe übernehmen“ zurücksetzen; die Leiste unten zählt, was noch nicht
gespeichert ist. Einheiten stehen neben dem Feld, Schalter sind Knopfgruppen, und
jedes Zahlenfeld ist so breit wie sein größter erlaubter Wert. Meldet das
Speichern einen Fehler, sind alle Abschnitte offen.

**Angemeldete Zugriffe werden nur auf den Backend-Pfaden abgewertet.** Bis 0.31
galt der Anteil aus „Angemeldete Zugriffe zählen mit“ auf jedem Pfad außer
Anmeldung und XML-RPC. Jetzt gilt er auf den Pfaden der Liste „Abwerten auf diesen
Pfaden“ (Vorgabe `/wp-admin/`, `/wp-json/`); auf allen anderen Pfaden zählen auch
angemeldete Zugriffe voll. Eine leere Liste wertet wie bisher auf allen Pfaden ab.

### Hinzugefügt

**Werte, die bisher fest im Code standen, sind Einstellungen**, jede mit Vorgabe,
Grenzen, Hinweis und einer Meldung, die Ursache und nächsten Schritt nennt:

- Angemeldete Nutzer: „Immer voll zählen“ (Vorgabe `wp-login.php`, `xmlrpc.php`)
  und „Anmeldung erkennen an“ (Vorgabe `wordpress_logged_in_`), dazu die Pfade
  der Abwertung.
- Nie sperren: die eigenen Netze (Vorgabe `127.0.0.0/8`, `::1/128`,
  `10.50.0.0/24`). Eine leere Liste nimmt das Formular nicht an, damit keine
  Sperre den Server selbst oder den Proxy davor trifft.
- Anzeige: die Zeiträume der Übersicht (Vorgabe 1, 7, 30 und 90 Tage) und der
  Zeitraum beim Öffnen (Vorgabe 7), die Zeilen der Herkunftsauswahl auf der Seite
  Sperren (Vorgabe 25) und wie oft die Seiten der Abwehr laufende Aufträge
  nachfragen (Vorgabe 5 Sekunden).
- Takt und Hintergrund: wann der Minutentakt als ausgefallen gilt (Vorgabe 180
  Sekunden), wie oft ein Auftrag eine belegte Sperre erneut versucht (Vorgabe
  250 ms) und wie viele Treffer einer Adresse die Automatik liest, um die
  häufigste Regel zu nennen (Vorgabe 200).
- Scanner > Einstellungen: wie oft die Übersicht und die Seite einer Website den
  Fortschritt einer laufenden Prüfung abfragen (Vorgabe 2 Sekunden; die
  Übersicht fragte bisher alle 3 Sekunden).

Listen stehen ein Eintrag je Zeile. Ein Eintrag, der nicht passt, steht mit
Namen und Regel in der Meldung, und gespeichert wird erst die korrigierte Liste.

**Die eigene Schwelle einer Website nimmt ihre Grenzen aus „Punkte für eine
Sperre“.** Panel, Auftrag und Eingabefeld prüften 5 bis 10000 bisher je für sich.

Die Datenbank bekommt zwölf Spalten in `malwatch_config`; `schema.sql` legt sie
beim Update an, vorhandene Werte bleiben.

## [0.31.0] – 2026-09-24

### Hinzugefügt

**Drei Webshell-Familien werden am Inhalt erkannt.** Bei der Bereinigung zweier
Server lagen Schaddateien, die malwatch nur über ihren Ort im WordPress-Kern
fand oder gar nicht:

- `php.webshell.include_wrapper` (kritisch): rund 25 KB große Dateien, die sich
  mit kopierten Doc-Kommentaren von WordPress tarnen. Kern ist eine Funktion,
  die nur ihren Parameter einbindet, dazu ein verschlüsselter Block aus hohen
  Bytes. Außerhalb von `wp-admin` und `wp-includes`, etwa im Statistik-Ordner,
  blieben sie bisher ungemeldet. Die Hülle allein hat auch der Autoloader von
  Composer; gemeldet wird erst die Hülle zusammen mit dem Block.
- `php.backdoor.self_delete` (kritisch, ohne selbsttätige Quarantäne): ein
  kleines Upload-Skript mit Passwort per GET, das sich auf Zuruf selbst löscht.
  Gemeldet wird die Selbstlöschung auf Zuruf zusammen mit einem Schreibvorgang;
  ein Installer, der sich nach getaner Arbeit entfernt, bleibt still.
- `php.obfuscation.hex_function_names` (kritisch): eine Webshell, die ihre
  Funktionsnamen als Hex-Texte in einem Array führt (`'7068705f756e616d65'`
  steht für `php_uname`).

Über alle PHP-Dateien beider Server treffen die drei Regeln nur Schadcode.

### Behoben

**Ein getauschter WordPress-Kern gehört wieder der Website.** `repair` legt
`wp-admin` und `wp-includes` vor dem Tausch in die Quarantäne. Danach war kein
alter Ordner mehr da, von dem der neue Kern Besitzer und Rechte hätte übernehmen
können, und er behielt die Identität des entpackten Archivs: `root`. WordPress
konnte sich auf solchen Websites nicht mehr selbst aktualisieren. `repair` liest
Besitzer, Gruppe und Rechte jetzt vor dem Ablegen und gibt sie dem neuen Kern
zurück, wie bei Plugins und Themes. Websites, die mit einer früheren Version
repariert wurden, lassen sich im Webstamm so richten:
`find wp-admin wp-includes -user root -exec chown -h <benutzer>:<gruppe> {} +`.

**`htaccess.cgi_handler` meldet die Härtung `Options -ExecCGI` nicht mehr.**
Gravity Forms und LimeSurvey schalten CGI in ihren Upload-Ordnern mit dieser
Zeile ab. Gemeldet wird jetzt nur `ExecCGI` ohne Minus.

**`php.eval.hexname` meldet den Lizenzschlüssel von MailWizz nicht mehr.**
MailWizz schreibt seinen Optionsschlüssel `system.license.purchase_code` in Hex,
und die Regel sah darin das Wort `system`. `eval` und `system` zählen jetzt nur
als ganzer Name.

## [0.30.2] – 2026-09-24

### Behoben

**Die Regel für Nachlader über Temp-Dateien meldet keine gewöhnlichen Bibliotheken
mehr.** `php.dropper.temp_include` (seit 0.29.0) verlangte nur, dass `tempnam`,
das Einbinden einer Variablen und ein Dekodierer irgendwo in derselben Datei
vorkommen. Große Bibliotheken haben alle drei an verschiedenen Stellen: PHPMailer 5
signiert über Temp-Dateien, bindet eine Sprachdatei ein und dekodiert base64 für
MIME. Auf einem Server meldete die Regel so 22 Dateien aus PHPMailer, HTMLPurifier,
fpdf, elFinder, dompdf, timthumb und dem Contao Manager als kritisch, und weil die
Regel zum selbsttätigen Verschieben freigegeben ist, hätte eine automatische
Maßnahme diese Bibliotheken in die Quarantäne gelegt. Die Regel verlangt jetzt,
dass Anlegen, Schreiben und Einbinden dicht aufeinander folgen, mit höchstens zwei
Anweisungen dazwischen, wie im echten Nachlader. Die 22 Dateien bleiben still,
der Nachlader aus dem Befall, für den die Regel gebaut wurde, wird weiter erkannt.

## [0.30.1] – 2026-09-24

### Behoben

**Die amd64-Binary startet auf älteren Linux-Systemen.** Bis einschließlich
0.30.0 war die veröffentlichte Binary für amd64 gegen die glibc des Bauservers
gelinkt und startete auf Systemen mit älterer glibc nicht, etwa unter Ubuntu
20.04 („``version `GLIBC_2.34' not found``“). Die Release-Binaries sind jetzt
statisch gelinkt (`CGO_ENABLED=0`) und laufen auf jedem Linux. `make dist`
prüft jede Binary und bricht den Bau ab, sobald eine dynamisch gelinkt ist.

## [0.30.0] – 2026-09-23

### Hinzugefügt

**Eigenständige Datei-Manager werden gemeldet.** Auf einer übernommenen Website
lag neben einem Spam-Mailer ein Tiny File Manager: eine einzelne PHP-Datei, mit
der sich alles hochladen, ändern und löschen lässt, was der Webnutzer darf. Der
Scanner meldete den Mailer, den Datei-Manager nicht, denn Tiny File Manager ist
ehrliche Open-Source-Software, die viele mit Absicht installieren. Die neue
Regel `php.tool.file_manager` meldet ihn als „mittel": ein Hinweis zum
Nachsehen, nie ein Grund für eine selbsttätige Quarantäne. Erkannt wird das
Werkzeug an seinen eigenen Konstanten, nicht am Titel, den ein Angreifer als
Erstes umbenennt. Eine Signaturliste, die nur den Namen nennt, löst nichts aus.

**Das Sperr-`.htaccess` von Angreifern wird erkannt.** Zwei Befälle hinterließen
dieselbe Art Datei, einer davon in 182 Verzeichnissen einer Website: PHP wird in
jeder Schreibweise der Endung verboten (`php`, `PHp`, `pHP` …, dazu `suspected`),
danach wird eine kurze Liste eigener Einstiege wieder freigegeben. Das sperrt
andere Angreifer und jedes Aufräumskript aus. Die Regel `htaccess.php_lockdown`
(hoch) verlangt beides: die ausgeschriebenen Schreibvarianten und eine Freigabe.
Eine Härtungsregel für einen Upload-Ordner, die PHP sperrt und nichts freigibt,
bleibt unbehelligt. Unter nginx wirkt eine solche Datei nicht; sie ist trotzdem
eine Spur des Angreifers, und unter Apache legt sie die Website lahm.

Gemessen auf zwei Servern mit zusammen 2,8 Millionen Dateien: Jeder Treffer der
beiden Regeln stammt von einem Angreifer, frisches WordPress und Joomla bleiben
ohne Fund.

## [0.29.1] – 2026-09-23

### Behoben

**GoAccess-Statistikberichte werden als Berichte erkannt und übersprungen.** Ein
GoAccess-Bericht listet die angefragten Adressen einer Website auf, darunter die
Pfade, die Angreifer abklopfen — mitsamt ihren base64-kodierten Nutzlasten. Der
Scanner überspringt Statistikseiten von AWStats, Webalizer und GoAccess, doch der
GoAccess-Kennsatz steht erst tief in der Datei, weit hinter dem Prüffenster von
acht Kilobyte; solche Berichte wurden dadurch geprüft und schlugen mit Regeln wie
„kodierter Aufruf einer Ausführungsfunktion" an. GoAccess bettet im Kopf jeder
Seite ein festes Favicon ein; dessen Palette steht weit vorn und dient jetzt als
früher Marker. Das Prüffenster bleibt klein, sodass nur ein Marker im Kopf zählt
— ein spät in eine Schaddatei geschriebenes Marker-Wort bleibt wirkungslos.

## [0.29.0] – 2026-09-23

### Hinzugefügt

**Jede Datei wird geprüft, der Inhalt entscheidet statt der Endung.** Der Scanner
las bisher nur bekannte Endungen. Ein Lader, der seinen Rumpf als `.css` oder
`.orig` ablegt und von anderer Stelle einbindet, blieb dadurch ungelesen. Jetzt
liest der Scanner jede Datei und entscheidet aus den ersten Bytes, ob sie PHP
oder ein Bild ist. PHP unter fremdem Namen und Code hinter einem Bildkopf werden
so erkannt, ganz gleich wie die Datei heißt. Die Endung entscheidet weiter dort,
wo der Webserver nach ihr geht: „PHP im Upload-Verzeichnis" bleibt eine Frage des
Namens. Auf frischem WordPress und Joomla erzeugt das keinen einzigen Fehlalarm.

**`wp-admin` und `wp-includes` gelten als vollständige Ordner.** WordPress legt
in diese beiden Verzeichnisse nichts von der Website. Eine ausführbare Datei, die
die Herstellerliste dort nicht kennt, ist auf einem anderen Weg hineingekommen
und wird als fremd gemeldet — der Weg, auf dem eine untergeschobene
`wp-admin/wp-admin.php` auffällt. Die Wurzel bleibt teilweise bekannt, dort
liegen Konfiguration und `wp-content`.

**Fünf neue Regeln und ein erweiterter Kampagnenmarker** gegen einen
ALFA-Webshell-Befall:

- `php.webshell.column_cipher` (kritisch): der Lader, der seinen Rumpf per
  Spaltentransposition zusammensetzt und ausführt. Vorher nur „mittel".
- `php.dropper.temp_include` (kritisch): schreibt dekodierten Code in eine
  Temp-Datei und bindet sie ein.
- `htaccess.cgi_handler` (hoch): macht eine fremde Endung über CGI ausführbar.
- `htaccess.disable_security` (hoch): schaltet mod_security ab.
- `malware.alfa_toolkit` (kritisch): Dateien im Verzeichnis
  `ALFA_DATA`/`alfacgiapi` oder mit der Endung `.alfa`.
- `php.webshell.known` erkennt zusätzlich die Marker `1nv1s1bl3` und
  „Sole Sad & Invisible".

## [0.28.3] – 2026-09-23

### Behoben

**Treffer aus angemeldeten Sitzungen zählen zu einem Zehntel.** Am 23.09.2026
sperrte die Automatik den Redakteur einer Kundenwebsite aus: Der Seitenbaukasten
löste beim Speichern Regeln des CRS aus, 60 Punkte aus 13 Treffern bei einer
Schwelle von 50, alle aus seiner angemeldeten Sitzung. Die Automatik zählt die
Punkte aus angemeldeten WordPress-Sitzungen jetzt getrennt und wertet sie mit
„Angemeldete Zugriffe zählen mit (Prozent)" unter Abwehr > Einstellungen, Vorgabe
10, erlaubt 0 bis 100. Anmeldung und XML-RPC zählen immer voll, dort laufen die
Rateangriffe. Der Grund einer Sperre nennt den rohen Punktestand, sobald abgewertet
wurde, etwa „angemeldete Zugriffe abgewertet (roh 1.235)".

Die Anmeldung erkennt malwatch am Cookie `wordpress_logged_in_*`, und das lässt sich
fälschen. Eine Adresse, die es bei jeder Anfrage mitschickt, braucht bei 10 Prozent
die zehnfache Punktzahl; bei 0 wird sie nur noch bei Angriffen auf Anmeldung oder
XML-RPC gesperrt.

Auf web.herkules lief die Abwertung seit dem 23.09.2026, 11:04 als direkter Eingriff;
mit 0.28.3 steht sie im Paket, und der Anteil ist einstellbar. Die Klassenprobe
prüft sie an der Datenbank: Redakteur frei, dieselben Punkte auf der Anmeldung als
Vorschlag, ein gefälschtes Cookie auf wenigen Anfragen abgewertet und trotzdem
vorgeschlagen.

## [0.28.2] – 2026-09-22

### Behoben

**„Weitere laden" hielt die Reihenfolge nicht immer.** Vorschläge mit gleichen Punkten
aus einem Cron-Lauf, Sperren, die „Alle Sperren aufheben" gemeinsam beendet hat, und
dieselbe Adresse in zwei Jails von fail2ban lagen in der Sortierung gleichauf. Bei
Gleichstand darf die Datenbank die Reihenfolge je nach Zeilenzahl anders wählen; nach
„Weitere laden" konnten oben andere Zeilen stehen als vorher. Jede Liste sortiert jetzt
zuletzt nach der Adresse, fail2ban danach nach der Jail.

**Der Minutentakt las die Minute zu spät.** Ob der Stundenteil fällig ist, prüfte
`waf-switch tick` erst nach Warten und Lauf. Reichte beides über die volle Minute, lief
der Stundenteil doppelt oder fiel für eine Stunde aus. Die Minute gilt jetzt ab dem
Start des Takts.

**Weitere Korrekturen**

- „Weitere laden" hat eine Zeitgrenze: „Zeitgrenze für „Weitere laden“ (Sekunden)"
  unter Abwehr > Einstellungen, Vorgabe 30, erlaubt 5 bis 300. Kommt die Antwort
  später, steht unter dem Knopf, woran es lag.
- Nach „Weitere laden" zeigt der Titel des Abschnitts die aktuelle Zahl.
- Der Browser merkt sich nur noch, wo ein Abschnitt von der Vorgabe abweicht. Eine
  spätere Änderung der Vorgabe erreicht damit alle, die den Abschnitt nie umgestellt
  haben.
- Unterüberschriften bleiben in jedem Theme kleiner und leichter als der Titel ihres
  Abschnitts.
- Der Hinweis zur „Wartezeit des Minutentakts" sagt, dass der Lauf ausfällt, wenn die
  Abwehr nach der Wartezeit noch belegt ist.
- `cron_hourly()` meldet einen abgefangenen Fehler als Fehler. Die Sperre der Abwehr
  versucht es nur so lange erneut, wie ein anderer sie hält, und endet bei jedem
  anderen Fehler sofort.
- Die Seite gibt beim Wechsel ihren Beobachter frei und hält so keine alten Inhalte im
  Speicher.
- Die Spalte `waf_ban_page_rows` hat auch nach einem Update den Standard 1000; der
  gespeicherte Wert bleibt.
- Die Kommentare im Code der letzten Änderungen sind englisch. `waf/README.md`
  beschreibt das Warten des Minutentakts und den Monitor des Wächters. Die Wartezeit
  wirkt mit dem `waf-switch` ab 0.28.1; nach einem Update deshalb auch `waf-switch`
  aus `waf/` nach `/usr/local/sbin/` kopieren.

## [0.28.1] – 2026-09-22

### Behoben

**Der Minutentakt der Abwehr fiel jede Stunde einmal aus.** Zur Minute 05 startet
der stündliche Wächter `waf-guard` in derselben Sekunde wie der Takt und hält für
sein `nginx -t` die Sperre der Abwehr. Der Takt wich bisher sofort aus, und der Lauf
dieser Minute fiel weg. Jetzt wartet er, bis die Sperre frei ist, höchstens so lange,
wie „Wartezeit des Minutentakts" unter Abwehr > Einstellungen sagt (Vorgabe 30
Sekunden, erlaubt 0 bis 50). Der stündliche Teil zur Minute 07 wartet ebenso. Der
Cron-Job von ISPConfig wartet weiterhin nie, weil er währenddessen alle anderen Jobs
von ISPConfig aufhält.

## [0.28.0] – 2026-09-22

### Neu

**„Sperren" klappt auf und zu.** Jeder Abschnitt der Seite ist ein aufklappbarer Block
mit der Zahl seiner Einträge im Titel, etwa „Vorschläge (156)". Offen beginnen
„Gesperrt" und „Sperren von fail2ban", die übrigen sind zu. Die Seite merkt sich im
Browser, was du auf- oder zugeklappt hast.

**Weitere laden.** Jede Liste zeigt zuerst 25 Zeilen. Der Knopf „Weitere 25 laden
(131 übrig)" holt die nächsten auf derselben Seite dazu und ersetzt dabei nur diese
eine Liste. Jeder Knopf der Seite schickt mit, wie lang die Listen gerade sind; nach
Sperren, Verwerfen oder Freigeben bleiben sie deshalb so lang. Scheitert das
Nachladen, steht unter dem Knopf, woran es lag und was zu tun ist.

**Länder ausgeschrieben.** Auf „Sperren" und auf der Seite einer Website steht der
Name des Landes, sein Code erscheint beim Überfahren. Die Auswahl der Herkunft zeigt
Name und Code nebeneinander, bei Anbietern Name und AS-Nummer. Der Grund einer Sperre
nennt das Land als „Land Frankreich (FR)", `waf-switch ban origin` ebenso. Die Namen
kommen aus der PHP-Erweiterung intl; fehlt sie, bleibt der Code.

### Geändert

**Zwei Einstellungen für die Länge der Listen.** „Zeilen je Schritt der Seite Sperren"
(neu, Vorgabe 25, erlaubt 5 bis 500) legt fest, wie viele Zeilen eine Liste zuerst
zeigt und wie viele jeder Klick dazuholt. „Höchstens Zeilen je Liste der Seite
Sperren" hieß bisher „Zeilen je Abschnitt" und ist jetzt die Grenze fürs Nachladen,
Vorgabe 1000. Wer noch die alte Vorgabe 200 eingestellt hatte, bekommt beim Update
einmal 1000.

## [0.27.1] – 2026-09-22

### Behoben

**Die Seite „Sperren" lud 17 Sekunden.** Die Auswahl der Länder und Anbieter
verknüpfte jeden Treffer einzeln mit der Herkunft seiner Adresse; weil kein Index der
Treffer mit der Adresse beginnt, las MariaDB dafür den ganzen Index einmal je
Adresse, knapp 8 Sekunden je Liste bei 66.000 Treffern. Jetzt werden die Treffer erst
je Adresse gezählt und danach verknüpft: 50 ms je Liste, mit demselben Ergebnis.

**Aufräumen der Herkunft.** Das stündliche Aufräumen fragte je Adresse nach ihren
Treffern und brauchte dafür knapp 5 Sekunden. Die Treffertabelle bekommt einen
Schlüssel über Server und Adresse (`server_client`).

## [0.27.0] – 2026-09-22

### Neu

**Eigener Minutentakt für die Abwehr.** ISPConfig führt alle seine Cron-Jobs
nacheinander unter einer Sperre aus. Solange einer lange läuft, startet kein anderer
— nachts baut AWStats die Statistik jeder Website und hielt die Abwehr damit eine
halbe Stunde an: kein Einlesen, keine Sperren, kein Ablauf, kein Blick auf fail2ban.
Jetzt startet `/etc/cron.d/malwatch-waf` jede Minute `waf-switch tick`, unabhängig von
ISPConfig; zur Minute 07 folgt der Stundenteil. Solange der Takt läuft, überlässt der
Cron-Job von malwatch ihm den Lauf; bleibt er drei Minuten aus, übernimmt der
Cron-Job wieder. `waf/install.sh` richtet die Datei ein, und `hc-run waf-tick` meldet
jeden Lauf an healthchecks.

## [0.26.0] – 2026-09-22

### Neu

**fail2ban im Panel.** Die Sperren von fail2ban stehen auf der Seite Security >
Abwehr > Sperren, mit Grund in Klartext („SSH: zu viele fehlgeschlagene
Anmeldungen (sshd)"), Beginn und der Zeit, die bleibt. Der Cron liest jede Minute
alle Jails; antwortet fail2ban nicht, sagt der Abschnitt das und zeigt den letzten
Stand. Jede Sperre lässt sich freigeben.

**Überall sperren.** Eine Adresse lässt sich an einer Zeile von fail2ban oder über
ein Eingabefeld überall sperren: im Web über malwatch und am Server über einen Jail
von fail2ban (Vorgabe `recidive`, auf web.herkules alle Ports für sieben Tage). Was
„überall" heißt, ist einstellbar — Web mit der üblichen Staffel und fail2ban, Web
ohne Ende und fail2ban, oder nur fail2ban —, und zwar global, je Jail für den Knopf
und je Regel der Abwehr für die Automatik: Eine markierte Regel schickt jede
automatische Sperre, die sie auslöst, auch zu fail2ban. Eigene Netze, die Adressen
des Servers und „Nie sperren" werden dabei abgewiesen.

Auf der Kommandozeile: `waf-switch ban everywhere <ip>` und `waf-switch ban f2b`.

## [0.25.4] – 2026-09-22

### Behoben

**Von Hand sperren sprang eine Stufe zu weit.** „jetzt sperren" an einem
Vorschlag und `waf-switch ban add` rechneten die Stufe noch auf die alte Art: Eine
Adresse, die nie gesperrt war, bekam 24 Stunden statt einer, eine zweite Sperre
sieben Tage statt 24 Stunden. Jetzt gilt dieselbe Regel wie für die Automatik —
die Stufe zählt Sperren, keine Vorschläge.

**Sperren endeten bis zu 59 Minuten zu spät.** Abgelaufene Sperren wurden nur zur
Minute 07 jeder Stunde beendet; eine Stundensperre konnte fast zwei Stunden
dauern, in nginx wie in der Liste für die Firewall. Das Beenden läuft jetzt jede
Minute, direkt vor dem Schreiben der Sperrdatei.

**`waf-switch ban list` zeigte Vorschläge als „dauerhaft".** Ein Vorschlag hat
kein Ende; die Spalte zeigt dort jetzt „-", und „dauerhaft" steht nur noch bei
Sperren ohne Ende.

## [0.25.3] – 2026-09-21

### Behoben

**Ein Vorschlag schützte seine Adresse vor jeder Sperre.** Hatte eine Adresse
einmal einen Vorschlag, bewertete die Automatik sie nie wieder, und Vorschläge
liefen nie ab. Auf web.herkules kamen 39 von 137 vorgeschlagenen Adressen mit
zusammen 15.266 Treffern zurück, ohne dass sich etwas tat; nach dem Umstellen auf
„sperren" oder mit „sofort sperren" wäre keine davon gesperrt worden.

Jetzt gilt:

- Darf gesperrt werden, wird aus einem Vorschlag eine Sperre. Die Stufe zählt
  Sperren: Eine Adresse, die nie gesperrt war, beginnt bei der ersten Stufe.
- Kommt eine Adresse im Vorschlagsmodus mit einer neuen Welle zurück, wird ihr
  Vorschlag mit den neuen Zahlen erneuert.
- Ein Vorschlag, um den sich niemand kümmert, fällt weg, wenn seine Adresse
  ruhig bleibt: neue Einstellung „Vorschläge aufbewahren (Tage)", Vorgabe 7.

**Die Seite „Sperren" lädt nicht mehr alles.** Jeder Abschnitt zeigt höchstens so
viele Zeilen, wie eingestellt ist (neue Einstellung, Vorgabe 200), die
Vorschläge mit den meisten Punkten zuerst; darunter steht, wie viele es insgesamt
sind.

**Zeilenumbrüche in Zeichenketten.** An 22 Stellen stand ein echter Zeilenumbruch
in einer Zeichenkette statt der Escape-Folge, darunter im Vergleich der
Sperrdatei aus 0.25.2. Mit Windows-Zeilenenden wäre dort der minütliche Reload
zurückgekommen. Alle Stellen sind umgestellt, und eine neue Prüfung in CI
verhindert, dass das wiederkommt.

## [0.25.2] – 2026-09-21

### Behoben

**nginx wurde jede Minute neu geladen.** Die Sperrdatei trägt in ihrer ersten
Zeile die Zeit, zu der sie geschrieben wurde. Der Vergleich nahm diese Zeile mit,
darum galt die Datei jede Minute als geändert: `nginx -t` mit allen Regeln und ein
Reload, rund um die Uhr, seit 0.23.0. Verglichen werden jetzt nur die Adressen;
nginx wird nur noch neu geladen, wenn eine Adresse dazukommt oder wegfällt.

**Drei Knöpfe ohne Wirkung.** Ihnen fehlte das Feld, in das sie ihren Wert
schreiben, und der Wert ging still verloren:

- „sperren" an den Regel-Karten und Einzeltreffern der Website-Seite schickte
  keine Adresse und endete mit „Das ist keine Adresse".
- „diese Website löst nie eine Sperre aus" setzte die Schwelle auf 0, ließ die
  Website aber auslösen — das Gegenteil.
- „Auswahl übernehmen" für Länder und Anbieter speicherte nie etwas.

Die Auswahl speichert jetzt Länder und Anbieter mit einem Knopf zusammen, so geht
kein Häkchen in der anderen Tabelle verloren. Eine neue Prüfung verlangt für
jeden Knopf, dass sein Feld in derselben Vorlage steht.

**Weitere Korrekturen**

- Der Grund einer Sperre nennt die echten Punkte und sagt dazu, wie sie wegen
  der Herkunft gewertet wurden, etwa „30 Punkte …, Herkunft: Land FR, Punkte mit
  200 % gewertet".
- Ist die Sperrliste voll, wird aus einer neuen Sperre ein Vorschlag. Bisher
  brach der Durchgang ab, und die übrigen Adressen gingen verloren.
- Die Adresse der Liste für die Firewall entsteht auch, wenn das Panel auf einem
  eigenen Port läuft, etwa 8080. Lässt sich aus dem Namen keine Adresse bilden,
  sagt die Seite das, statt einen fehlenden Schlüssel zu behaupten.
- Die Auswahl der Herkunft zeigt den Zeitraum, für den es Treffer gibt
  (`waf_detail_days`), statt eines längeren, den keine Zahl abdeckt.
- Eine Auswahl, die länger als 255 Zeichen ist, wird mit Begründung abgewiesen;
  bisher meldete der Auftrag Erfolg, obwohl nichts gespeichert wurde.
- `waf-switch ban origin on|off` läuft als Auftrag und steht damit in der Liste
  der Aufträge.
- Die Serverklasse lädt je Minute nur die Herkunft der Adressen im Zeitfenster.

## [0.25.1] – 2026-09-18

### Behoben

**Meldungen von `waf-switch ban`.** Die Kommandozeile antwortete mit einem festen
Satz, auch wenn der Auftrag abgewiesen wurde: `ban add` auf eine Adresse unter
„Nie sperren" meldete „Sperre eingetragen", obwohl nichts gesperrt wurde. Jetzt
steht dort die Meldung des Auftrags, und der Rückgabewert stimmt.

## [0.25.0] – 2026-09-18

### Neu

**Die Herkunft senkt die Schwelle.** Für Adressen aus ausgewählten Ländern, von
ausgewählten Anbietern oder aus Rechenzentren, VPN und Tor gilt eine eigene,
niedrigere Schwelle, und ihre Punkte zählen um einen einstellbaren Anteil mehr.
Ein eigener Schalter sperrt solche Adressen sofort, während die Automatik sonst
nur vorschlägt. Alles beginnt ausgeschaltet.

Länder und Anbieter werden auf der Seite Security > Abwehr > Sperren aus den
echten Treffern angekreuzt — mit Trefferzahl und Zahl der Adressen daneben, also
ohne Kürzelraten. Der Grund einer Sperre nennt das Merkmal mit, etwa „Herkunft:
Anbieter Google LLC". Der Wille des Betreibers geht vor: Eine Website, die keine
Sperre auslöst, bleibt frei, und die Ausnahmeliste wirkt wie bisher.

Rückweg ohne Panel: `waf-switch ban origin off`.

## [0.24.1] – 2026-09-18

### Behoben

**Klassenprobe.** Die neue Prüfung der Liste für die Firewall sah im ersten
Arbeitsbereich der Probe nach, während die Klasse seit dem Abschnitt zur
Herkunft in einem zweiten schreibt.

## [0.24.0] – 2026-09-18

### Neu

**Sperrliste für die Firewall.** Die gesperrten Adressen stehen unter einer
eigenen Adresse bereit, eine Adresse je Zeile. Die OPNsense holt sie als Alias
vom Typ „URL Table (IPs)" und sperrt damit an der Kante, bevor die Anfragen den
Webserver erreichen. Die Adresse trägt einen Schlüssel aus 32 Zeichen; ohne ihn
antwortet die Stelle mit 404. Auf der Seite Security > Abwehr > Sperren stehen
die Adresse, die Zahl der Einträge und ein Knopf für einen neuen Schlüssel; auf
der Kommandozeile zeigt `waf-switch ban url` dasselbe.

Der Schlüssel entsteht von selbst, sobald die Automatik auf „vorschlagen" oder
„sperren" steht. Die Liste enthält Adressen, sonst nichts — keine Namen, keine
Zeiten, keine Gründe.

## [0.23.4] – 2026-09-18

### Behoben

**Klassenprobe.** Beim Schreiben der Website-Felder sah die Serverklasse für die
Einbindung der Sperrliste immer unter `/etc/nginx/conf.d` nach, auch wenn ein
anderer Ordner eingestellt war. Sie folgt jetzt der eingestellten Einbindung, und
eine neue Prüfung hält fest, dass das Feld mit vorhandener Einbindung auch das
zweite Zugriffslog schreibt.

## [0.23.3] – 2026-09-18

### Behoben

**Zahl der abgewehrten Versuche.** Gezählt wurden auch Antworten 403, die eine
Website selbst gegeben hatte, bevor die Sperre stand. Der Zähler nimmt jetzt nur
noch Zeilen, die nach dem Beginn der Sperre entstanden sind.

## [0.23.2] – 2026-09-18

### Behoben

**Regel im Grund einer Sperre.** Der Grund nannte „meist Regel Array" statt der
Regelnummer: Die Treffer speichern ihre Regeln als Objekte mit `id` und `msg`, die
Auswertung erwartete nackte Nummern. Sie versteht jetzt beides.

## [0.23.1] – 2026-09-18

### Behoben

**Dauer einer Sperre.** Das Ende einer Sperre wurde in UTC gerechnet, während die
Datenbank Serverzeit führt. In Mitteleuropa lag das Ende damit zwei Stunden vor dem
Beginn: Eine Sperre über eine Stunde war sofort abgelaufen. Ende, Zeitfenster,
Aufbewahrung und der erneute Versuch nach einem Fehler rechnen jetzt in derselben
Zone wie die Datenbank. Eine Prüfung mit fest eingestellter Zone hält das fest.

## [0.23.0] – 2026-09-18

### Neu

**Sperren.** Wer in kurzer Zeit zu viele Anomalie-Punkte sammelt, wird serverweit
mit 403 abgewiesen. Die neue Seite **Security > Abwehr > Sperren** zeigt, wer
gesperrt ist, warum, seit wann, bis wann und wie viele Versuche seither abgeprallt
sind. Die Automatik beginnt bei „aus“; „vorschlagen“ rechnet nur mit, „sperren“
handelt. Von Hand geht jederzeit — auch direkt an jeder Adresse in den Regel-Karten
und Einzeltreffern.

**Schwelle je Website.** Jede Website kann eine eigene Schwelle bekommen oder gar
keine Sperre auslösen; ohne eigenen Wert gilt der Wert des Servers (Vorgabe 50
Punkte in 10 Minuten).

**Staffel und Ausnahmen.** Die erste Sperre dauert eine Stunde, die zweite 24, ab
der dritten sieben Tage — alles einstellbar. Nie gesperrt werden die eigenen Netze,
die Adressen der Ausnahmeliste und die veröffentlichten Adressbereiche von Google
und Bing, die malwatch wie die übrigen Herkunftslisten lädt.

**Rückweg.** `waf-switch ban off` hebt alle Sperren auf und schaltet die Automatik
aus, auch ohne Panel. Lehnt nginx die erzeugte Datei ab, kommt der vorherige Stand
zurück und es wird nicht neu geladen.

## [0.22.0] – 2026-09-18

### Neu

**proxycheck.io als Quelle für VPN, Proxy und Rechenzentrum.** Unter **Security >
Abwehr > Einstellungen** steht bei „VPN und Rechenzentrum“ neben den X4BNet-Listen
jetzt proxycheck.io. Der Dienst beantwortet jede Adresse einzeln: Er nennt VPN,
Proxy, Rechenzentrum und den Namen des Anbieters, dazu Land und Netz, wenn keine
lokale Quelle dafür gewählt ist. Die Seite nimmt Schlüssel und Tageslimit entgegen
und sagt dazu, dass jede neue Adresse aus einem Treffer an den Dienst geht.

**Kontingent im Blick.** Der Abwehr-Cron schickt je Durchgang höchstens eine Anfrage
mit 100 Adressen und bleibt unter dem Tageslimit (Vorgabe 500, einstellbar von 1 bis
100000). Die Einstellungsseite zeigt „heute n von m Abfragen, k Adressen geprüft“.
Ist das Limit erreicht, warten die übrigen Adressen auf den nächsten Tag; eine
gescheiterte Anfrage wird nach einer Stunde erneut versucht, höchstens dreimal.

**Beim Abschalten geht alles mit.** Wird proxycheck.io abgewählt, löscht der nächste
Auftrag „Herkunft der Adressen“ die Merkmale des Dienstes aus den Adressen und seine
Zeile aus dem Stand der Quellen.

## [0.21.1] – 2026-09-17

### Behoben

**Namen der Quellen auf der Einstellungsseite.** Unter „Stand der gewählten Quellen“
standen die technischen Schlüssel (`dbip_country`) und die nackten Werte. Die Seite
liest ihr eigenes Wörterbuch, in dem die Texte der Abwehr-Seiten fehlten. Jetzt steht
dort „DB-IP Lite: Land — Stand 2026-09, 717.169 Bereiche, geladen am …“. Prüfung 69
in `check_wiring.sh` hält die beiden Wörterbücher künftig zusammen.

## [0.21.0] – 2026-09-17

### Neu

**Herkunft der Adressen.** Die Seiten der Abwehr zeigen zu jeder Adresse Land,
Provider und die Chips „Tor“, „VPN“ und „Rechenzentrum“. Die Angaben kommen aus
Listen, die der Server selbst herunterlädt: DB-IP Lite oder MaxMind GeoLite2 für
Land und Provider, die Liste des Tor-Projekts, die X4BNet-Listen für VPN-Netze und
Rechenzentren.

**Jede Quelle einzeln wählbar.** Unter **Security > Abwehr > Einstellungen** steht
der Abschnitt „Herkunft der Adressen“. Alles beginnt auf „aus“: Erst mit einer Wahl
lädt der Server eine Liste. Der Abschnitt nennt je Quelle den Stand, die Zahl der
Bereiche, den letzten Abruf und einen Fehler mit dem, was jetzt gilt. Für MaxMind
nimmt die Seite Konto-ID und Lizenzschlüssel entgegen; der Schlüssel erscheint
danach nur noch verdeckt.

**Auftrag „Herkunft der Adressen“.** Der stündliche Cron legt ihn an, sobald eine
Quelle fällig ist, und nach dem Speichern der Einstellungen sofort. Er lädt jede
fällige Liste, baut sie in eine Bereichsdatei um und tauscht sie erst nach der
Prüfung: Die Datei muss sich lesen lassen, genug Bereiche enthalten und darf nicht
auf die Hälfte des bisherigen Stands fallen. Sonst bleibt der bisherige Stand
aktiv, und die Einstellungsseite nennt den Grund.

### Geändert

**Adressen in der Datenbank.** Zu jeder Adresse eines gespeicherten Treffers hält
`malwatch_waf_ip` Land, Netz und die Merkmale. Die Zeile verschwindet mit dem
letzten Treffer der Adresse, also spätestens nach der eingestellten Aufbewahrung.
Die Listen selbst enthalten keine Besucheradressen, und der Server schickt keine
Adresse nach außen.

## [0.20.0] – 2026-09-17

### Neu

**Treffer verstehen.** Die Seite einer Website unter **Security > Abwehr** erklärt
jede Regel auf Deutsch: was sie erkennt, woran sie in den gespeicherten Anfragen
angeschlagen hat, etwa „Parameter „q“ enthält „union select““, und wie der Treffer
einzuordnen ist: Scanner, Angriffsversuch, Fehlalarm möglich, Protokollverstoß,
Auswertung oder Antwort der Website. Der Regelkatalog umfasst alle 170 Regeln der
Stufe 1 von CRS 3.3.5 auf Deutsch und Englisch; Regeln höherer Stufen zeigen den
Text ihrer Gruppe.

**Adressen je Regel.** Jede Regel-Karte nennt die Adressen, von denen ihre Treffer
kamen, mit Anzahl, und wie viele Treffer von angemeldeten Nutzern stammen. Ein Klick
auf eine Adresse zeigt nur deren gespeicherte Anfragen und springt dorthin; „Filter
aufheben“ zeigt wieder alle.

**Einstellung „Einzeltreffer für die Regel-Karten“.** So viele jüngste gespeicherte
Anfragen einer Website wertet die Seite für Adressen und Auslöser aus, Vorgabe 5000.

### Geändert

**Einzeltreffer.** Aufgeklappt nennt jede Regel ihren Auslöser in Worten und ihre
Einordnung, darunter klein den Rohtext aus dem Audit-Log. Anfragen angemeldeter
Nutzer tragen den Hinweis auf einen möglichen Fehlalarm. Die Adresse steht in einer
eigenen Spalte.

**Regeltitel.** Übersicht und Ausnahmeliste nehmen die Titel aus dem Katalog. Die
Gruppen 910, 912 und 922 haben einen Namen.

**Verständliche Meldungen.** Liegt ein Wert auf der Einstellungsseite der Abwehr
außerhalb der Grenzen, nennt die Meldung das Feld, die erlaubten Zahlen und den
nächsten Schritt. Ist die Angabe im Adressfilter keine IP-Adresse, zeigt die Seite
alle gespeicherten Anfragen, sagt das über der Liste und nennt den Weg zum Filtern.

**Datenbank.** `malwatch_waf_hit` bekommt den Index `site_ip` für den Adressfilter,
`malwatch_config` die Spalte `waf_card_hits`. Das Schema legt beides bei der
Installation und beim Update selbst an.

## [0.19.1] – 2026-09-17

### Geändert

**Menü in zwei Gruppen.** Das Modul Security trennt jetzt **Scanner** (Status, Funde,
Schwachstellen, Quarantäne, Dumps, Prüfläufe, Einstellungen) und **Abwehr**
(Übersicht, Ausnahmen, Einstellungen). Ausnahmen und Einstellungen der Abwehr stehen
damit direkt im Menü; bisher führten nur Links auf der Übersicht dorthin.

### Behoben

**`waf/install.sh` bei einer bestehenden WAF.** Die Sicherung legte
`/etc/logrotate.d/waf` unter demselben Namen ab wie die Kopie von `/etc/nginx/waf`;
`cp` brach ab, und das Skript endete, bevor es etwas umstellte. Die Datei heißt in
der Sicherung jetzt `logrotate-waf`.

## [0.19.0] – 2026-09-17

### Neu

**Abwehr.** Unter **Security > Abwehr** steht die WAF aller Websites auf einer
Seite. Der Kopf fasst zusammen, wie viele Websites mitschreiben und blockieren und
wie viele Anfragen im gewählten Zeitraum abgewiesen worden wären. Die Liste zeigt
je Website den Zustand, die Treffer mit ihrem Verlauf je Tag, „wäre abgewiesen“ und
die häufigste Regel. Gefiltert wird nach Zustand, WordPress und Treffern; die
Zeiträume reichen bis zur Aufbewahrung der Tageszahlen. Angehakte Websites wechseln
gemeinsam auf „mitschreiben“, „scharf“ oder „aus“.

**Website im Detail.** Die Seite einer Website zeigt den Verlauf, die Regeln im
Klartext mit ihren häufigsten Pfaden und die gespeicherten Anfragen mit Kopfzeilen
und Anfrageinhalt. Die Seitenantwort öffnet als Text in einem eigenen Fenster.
„scharf“ wird frei, sobald die Website lange genug mitschreibt; die Vorschau nennt
vorher, wie viele Anfragen der letzten Tage abgewiesen worden wären und wie viele
davon von angemeldeten Nutzern kamen.

**Ausnahmen per Knopf.** „Ausnahme …“ an einer Regel oder Anfrage füllt das
Formular der Seite: für die Website, einen Pfad, einen Parameter oder alle
Websites. Die Vorschau zählt, wie viele Treffer der letzten Tage die Ausnahme
verhindert hätte. Eigene Regeln und die Punktwertung nimmt das Formular nicht an.
Die Seite „Ausnahmen“ listet alle mit Zustand und Fehlergrund.

**Notaus und Seitenantwort.** „Notaus“ schaltet die Regeln auf allen Websites ab
und setzt scharfe Websites auf „mitschreiben“; ein rotes Band steht auf der Seite,
bis „Notaus beenden“ folgt. Der Knopf „Seitenantwort“ wechselt zwischen
vollständig und schlank.

**Einstellungen der Abwehr.** Die Aufbewahrung der Anfragen, der Tageszahlen und
des Audit-Logs, die Mindestdauer vor „scharf“, der Zeitraum der Vorschau, die
Zeilen je Durchgang und die Frist für den vhost stehen auf einer eigenen Seite.

### Geändert

**Aufträge im Cron.** Jeder Knopf legt einen Auftrag an. Der malwatch-Cron liest
jede Minute das Audit-Log ein und führt die Aufträge nacheinander aus, den Notaus
zuerst. Jede Dateiänderung läuft über eine Kopie, `modsec-rules-check` und
`nginx -t`, erst dann tauscht der Auftrag die Dateien und lädt nginx neu. Scheitert
eine Prüfung, bleibt der vorherige Stand, und der Auftrag nennt den Grund.

**WAF-Werkzeuge mit neuen Namen.** Auf dem Server heißen die Werkzeuge
`waf-switch`, `waf-guard` und `waf-report`, die Dateien unter `/etc/nginx/waf`
tragen englische Namen. `waf/install.sh` stellt einen bestehenden Server um und
entfernt die alten Namen nach dem erfolgreichen Reload.

**Deinstallieren** löscht auch die Tabellen der Dumps und der Datenbankliste.

### Behoben

**Überschriften sichtbar.** Die Abschnitte der Einstellungen, der Einstellungen einer
Website und der Seite einer Website tragen wieder sichtbare Überschriften; das
Stylesheet von ISPConfig hatte sie ausgeblendet. Die Sprungziele „Funde“ und
„Software“ auf der Seite einer Website funktionieren damit ebenfalls.

**Fehlermeldungen der Einstellungen.** Ein Wert außerhalb seines Bereichs, etwa bei
„Gleichzeitige Prüfungen“, zeigt seinen Grund jetzt über dem Formular.

**„Auf die bestehenden Funde anwenden“ speichert mit.** Felder, die im selben Zug
geändert wurden, werden gespeichert, und die Funde werden nach der Einstellung
behandelt, die vor dem Klick galt. Zuvor scheiterte das Speichern dabei an der
Prüfung des Formularschlüssels.

## [0.18.0] – 2026-09-15

### Neu

**Dumps öffentlich freigeben.** Jede fertige Zeile der Liste hat „Öffentlich
freigeben“. Dahinter wählst du, wie lange der Verweis gilt — solange der Dump
liegt, 24 Stunden oder ein einziger Abruf — und kannst ein Passwort setzen, das
das Panel vorschlägt. Es entsteht ein zweiter Verweis mit 40 Zeichen Zufall,
getrennt vom Weg durch das Panel; er steht in der Zeile zum Kopieren und
funktioniert ohne Anmeldung.

Mit Passwort fragt die Seite es vorher in einem schlichten Formular ab;
gespeichert wird nur dessen Hash. Jeder Abruf zählt mit Zeit und Adresse in der
Zeile mit, und „Freigabe aufheben“ macht den Verweis sofort ungültig. Der Dump
selbst und sein Weg über das Panel bleiben davon unberührt.

## [0.17.0] – 2026-09-15

### Neu

**Dumps.** Die neue Seite „Dumps“ packt eine Website in ein tar.gz und stellt
es zum Herunterladen bereit: das Webverzeichnis, die angehakten Datenbanken
und auf Wunsch die Protokolle. Die Auswahl zeigt je Datenbank Größe, Zahl der
Tabellen, die WordPress-Installation, zu der sie gehört, und den letzten
Schreibzugriff; beim Öffnen der Seite ist alles angehakt. Diese Angaben sammelt
der stündliche Lauf auf dem Server.

Ein Dump liegt sieben Tage, danach räumt derselbe Lauf ihn weg. Der Verweis
zum Herunterladen gilt so lange und lässt sich mehrfach benutzen. Vor dem
Packen vergleicht der Lauf die geschätzte Größe mit dem freien Platz und hält
an, wenn es eng wird. Scheitert eine Datenbank, endet der Lauf, und das halbe
Archiv wird gelöscht.

Der Scanner bekommt dafür den Befehl `malwatch dump`; das Panel reiht ihn über
die bestehende Warteschlange ein und zeigt den Fortschritt wie bei einer
Prüfung.

## [0.16.3] – 2026-09-14

### Geändert

**Die Rückfrage der Reparatur nennt, was angehakt ist.** „Reparatur starten“
zählt im Dialog nur die angehakten Arten mit ihrer Anzahl auf, etwa „Kern und
3 Plugins durch die Originale ersetzen?“. Im Kopf eines Ordners zählt der
Ordner, beim Knopf unten die ganze Seite. Der Satz zu Elementen ohne Original
steht nur dabei, wenn so ein Element angehakt ist.

## [0.16.2] – 2026-09-14

### Behoben

**Knöpfe mit Rückfrage öffnen den Dialog wieder.** „Reparatur starten“,
„Updates starten“, „In Quarantäne verschieben“, „Endgültig löschen“ und die
übrigen Knöpfe mit Rückfrage blieben im Panel seit 0.15.0 ohne Wirkung, ebenso
seit 0.16.1 der Hinweis bei Knöpfen ohne Häkchen. ISPConfig fragt nach dem Laden
einer Seite fortlaufend die offenen Änderungen ab und schreibt die Antwort in
jedes Element mit der Klasse `modal-body`, auch in den Dialog von malwatch. Der
Dialog verlor dadurch seinen Text, und das Öffnen brach ab. Sein Inhalt trägt
jetzt eine eigene Klasse.

## [0.16.1] – 2026-09-14

### Behoben

**Knöpfe ohne Häkchen sagen, was fehlt.** Probelauf und Start auf den Seiten
„Updates“ und „Reparatur“ sowie die Sammelaktionen der Quarantäne waren
gesperrt, solange nichts angehakt war, und ein Klick darauf blieb ohne
Rückmeldung. Die Knöpfe sehen jetzt normal aus. Ohne Häkchen öffnet ein Klick
den Dialog mit „Bitte zuerst Elemente anhaken“ und dem Weg zum Anhaken, im Kopf
eines Ordners zusammen mit dessen Pfad. Mit Häkchen geht es weiter wie bisher.

## [0.16.0] – 2026-09-14

### Neu

**Kurze Versionsliste mit Nachladen.** Das Auswahlfeld der Seite „Updates“
zeigt die neueste passende Version, die kleinste, die alle Lücken schließt, und
die neueste Version jeder der fünf neuesten Hauptversionen: beim Kern je x.y,
bei Plugins und Themes je erster Stelle. „Weitere Versionen laden …“ am Ende
holt die übrigen Versionen für dieses eine Feld. Auf einer Website mit 515
Feldern trug die Seite zuvor gut 25.000 Einträge und jetzt gut 2.000; das Panel
ist entsprechend schneller bereit, und das erste Öffnen eines Felds folgt
spürbar schneller.

**Knöpfe in der Schwachstellen-Liste.** Jede Website hat in ihrer Zeile die
Knöpfe „Updates“, „Lücken“ und, bei offenen Funden, „Malware-Funde“ mit deren
Zahl. „Lücken“ und „Malware-Funde“ öffnen die Seite der Website direkt beim
Abschnitt „Software“ oder „Funde“.

## [0.15.0] – 2026-09-14

### Neu

**Rückfragen als Dialog im Panel.** Löschen, Zurückholen, Reparieren,
Aktualisieren, eine Website wieder einschalten und „Auf die bestehenden Funde
anwenden“ fragen in einem Dialog im Stil des Panels nach. Er nennt die Aktion
und bei einer einzelnen Datei ihren Pfad. Bei Aktionen, die Dateien bewegen,
ist der Bestätigen-Knopf rot; der Fokus liegt zuerst auf „Abbrechen“, Esc
schließt. Knöpfe, die eine Auswahl brauchen, bleiben ausgegraut, bis etwas
angehakt ist.

**Quarantäne je Website.** Über der Liste steht eine Übersicht mit Einträgen,
Größe auf der Platte und jüngstem Eintrag je Website, die meisten Einträge
zuerst. Ein Klick zeigt nur die Einträge dieser Website, mit Blättern und allen
Aktionen. Der Hinweis auf der Seite einer Website führt direkt dorthin.

**Updates und Reparatur je Ordner.** Beide Seiten gliedern nach
WordPress-Installation. Jeder Ordner hat Probelauf und Start für seine
angehakten Elemente, dazu „Alle auswählen“ und „Auswahl umkehren“ für den
Ordner und für die ganze Seite. Beide Seiten starten ohne Häkchen; der Verweis
„Aktualisieren“ einer Softwarezeile hakt weiter sein Element an.

**Jede veröffentlichte Version wählbar.** Die Seite „Updates“ listet jede
stabile Version über der installierten, die neueste zuerst. „Neueste passende“
bleibt vorgewählt, „kleinste, die alle Lücken schließt“ ist markiert. Der
Scanner holt die Liste bei wordpress.org und liefert sie mit dem nächsten
Abgleich einer Website. Ob eine ältere Version zu PHP und WordPress der Website
passt, prüft der Lauf nach dem Holen.

**`repair --only` mit Ordner.** `--only=plugin:akismet@blog` repariert das
Plugin allein in der Installation im Ordner `blog` unter `--path`,
`--only=core@.` den Kern in `--path` selbst.

### Behoben

**Ein Häkchen der Reparaturseite traf jeden Ordner.** Die Seite übergab
`--only=plugin:akismet`, und der Lauf reparierte das Plugin in jeder
Installation der Website, die es enthielt. Jetzt nennt jeder Wert seinen
Ordner.

**Pfade mit Apostroph in den Knöpfen einer Fundzeile.** Die Knöpfe setzten den
Pfad in ein Skript im `onclick`-Attribut, und ein Apostroph im Dateinamen
konnte dort beim Klick eigenen Code ausführen. Die Werte stehen jetzt als Text
in Attributen.

## [0.14.3] – 2026-09-14

### Geändert

**Die Seite „Updates“ startet ohne Auswahl.** Bisher waren alle Zeilen mit
Lücken angehakt, auf einer großen Website Hunderte Elemente. Ausgewählt wird
jetzt von Hand; der Verweis „Aktualisieren“ einer Softwarezeile hakt sein
Element an.

**Eine nicht ladbare Prüfsummenliste lehnt nur ihr Element ab.** Ein Netzfehler
oder eine kaputte Antwort von wordpress.org hielt bisher den ganzen Lauf an.
Jetzt wird dieses Element mit Grund abgelehnt, die übrigen laufen weiter. Eine
Prüfsumme, die nicht passt, beendet den Lauf weiterhin.

## [0.14.2] – 2026-09-14

### Behoben

**Prüfsummenlisten mit mehreren Werten je Datei.** wordpress.org nennt für eine
Plugin-Datei, die sich zwischen zwei Builds derselben Version geändert hat,
mehrere gültige MD5-Werte. malwatch las davon nur einen und verwarf die ganze
Liste: Ein Update brach in der Prüfung ab, und der Scan verglich die Dateien
dieses Plugins mit keiner Liste. Jetzt gilt eine Datei als Original, wenn sie
einem der genannten Werte entspricht, wie bei WP-CLI.

## [0.14.1] – 2026-09-14

### Behoben

**Die Nachprüfung nach einem Update bewertet den neuen Code.** PHP führt nach
dem Tausch die übersetzten alten Dateien weiter aus, bis OPcache sie neu liest.
Die Nachprüfung kam früher und bewertete deshalb den alten Stand: Ein Update,
das die Website lahmlegt, galt als gelungen, und der alte Stand kam nicht
zurück. `malwatch upgrade` wartet jetzt nach dem Tausch und nach dem
Zurückholen die mit `--settle` genannte Zeit, beim Tausch noch im
Wartungsmodus. Das Addon übergibt dafür `opcache.revalidate_freq` aus der
PHP-FPM-Konfiguration der Website plus eine Sekunde und lehnt ein Update ab,
wenn OPcache in diesem Pool keine Zeitstempel prüft.

## [0.14.0] – 2026-09-14

### Neu

**WordPress-Updates aus dem Panel.** Die Seite „Updates“ einer Website bietet
für den WordPress-Kern und für Plugins und Themes mit neuerer Version bei
wordpress.org je zwei Zielversionen an: die neueste, deren Anforderungen an
WordPress- und PHP-Version die Website erfüllt, und die kleinste, die alle
bekannten Lücken schließt. Beim Kern ist die neueste die jüngste Version seines
Zweigs. Jede Angabe nennt, welche Lücken sie schließt.

**Der Befehl `malwatch upgrade`.** Er liest eine Plandatei, lädt die
Zielversionen, prüft Prüfsummen und Anforderungen, legt den alten Stand in die
Quarantäne und tauscht ihn, während WordPress den Wartungsmodus zeigt. Hebt ein
Kern-Update die Datenbank an, exportiert WP-CLI sie vorher als Benutzer der
Website und hebt sie danach an. Anschließend ruft malwatch Startseite und
Anmeldeseite ab; antwortet eine davon mit einem Serverfehler, ohne Antwort oder
mit leerer Seite, kommt der alte Stand zurück, die Datenbank eingeschlossen.

**Meldungen.** Zurückholen und Fehler gehen per Mail an den Betreiber und, wenn
für die Website „Kunde benachrichtigen“ eingeschaltet ist, an den Kunden. Die
Seite der Website zeigt den Fortschritt je Element und die letzten zehn Läufe.

**Scan und Abgleich** nennen die PHP-Version der Website (`--php`), je Software
die Anforderungen der neuesten Version und beim Kern die neueste Version des
Zweigs.

**Einstellungen:** Pfad zu WP-CLI.

## [0.13.2] – 2026-09-13

### Geändert

**Aufgeklappte Listen rücken ein.** In der Schwachstellen-Übersicht stehen die
Installationen einer Website eingerückt unter ihrem Namen, mit einer Linie
links. Auf der Seite einer Website rückt die Lückenliste unter „Lücken
anzeigen“ ein. So hebt sich, was ein Block aufklappt, von der Liste darum ab.

## [0.13.1] – 2026-09-13

### Geändert

**„Schwachstellen" gliedert nach Websites.** Je Website steht ein
aufklappbarer Block mit ihren angreifbaren Installationen, die schwerste
Einstufung zuerst, bis zu 40 je Website. Jede Zeile nennt die Zahl der Lücken,
die installierte Version und die Version, ab der alle behoben sind; die
aktuelle Version erscheint bei veralteter Software. Die einzelnen Lücken stehen
auf der Seite der Website. Mit ihnen wog die Übersicht auf dem Livesystem
1,7 MB bei 458 Installationen; gegliedert wiegt sie 156 KB bei inzwischen 592.

**Lücken auf der Seite einer Website.** Die Liste einer Installation klappt in
einer eigenen Zeile über die ganze Tabellenbreite auf; in der Produktspalte war
sie 332 Pixel schmal. Je Installation stehen die zehn schwersten Lücken, auf
der ganzen Seite bis zu 400. Weitere Installationen zeigen die Zahl ihrer
Lücken, und ein Hinweis unter der Tabelle nennt den Grund. Ein zweiter Hinweis
erscheint, wenn die Tabelle wegen ihrer Grenze von 300 Zeilen einen Teil der
Installationen auslässt. Die Seite einer Demo-Website mit 712 Installationen,
425 davon angreifbar, sank damit von 1,08 MB auf 352 KB.

## [0.13.0] – 2026-09-13

### Neu

**Bekannte Schwachstellen je installierter Version.** Zu jeder erkannten
Software schlägt der Scanner nach, welche Sicherheitslücken für genau diese
Version veröffentlicht sind: mit CVE-Nummer, Einstufung und der Version, die
sie behebt.

| Software | Quelle |
|---|---|
| WordPress, Plugins, Themes | WPVulnerability und wordpress.org, mit API-Schlüssel zusätzlich WPScan |
| Joomla | Joomla Security Centre, dazu OSV |
| Drupal, TYPO3, phpMyAdmin, Contao, Shopware, MediaWiki, Magento 2 | OSV |

Für Nextcloud, Matomo und Magento 1 gibt es keine tragfähige Quelle; ihre
Installationen tragen den Hinweis „Lücken nicht geprüft“. Die Meldungen zu
Shopware 6 und Magento 2 gelten nur für ihre eigene Hauptversion: dort steht oft
„ab Version 0“, und ein Shop mit Shopware 5 bekäme sonst den Rat, auf 6.4 zu
aktualisieren.

Viele Lücken stehen mehrfach in den Daten, oft zweimal in derselben Datenbank:
einmal mit CVE-Nummer, einmal so, wie ein zweiter Forscher sie gemeldet hat.
Einträge mit gemeinsamer Kennung oder derselben behebenden Version werden
zusammengelegt und erscheinen einmal.

OSV wird einmal am Tag als Gesamtarchiv geladen und auf dem Server
durchsucht. An WPVulnerability und WPScan gehen Name und Version der
jeweiligen Komponente. Antworten bleiben einen Tag gespeichert, die von WPScan
eine Woche, weil dessen kostenloser Tarif 25 Abfragen am Tag erlaubt. Ist das
Kontingent aufgebraucht, pausiert WPScan, und die gespeicherten Antworten
gelten weiter. Bleibt eine Quelle dreimal hintereinander stumm, fragt der Lauf
sie nicht weiter und greift auf ältere gespeicherte Antworten zurück. Der
Bericht nennt beides.

**Menüpunkt „Schwachstellen".** Die Seite listet alle Installationen mit
bekannten Lücken über alle Websites, die schwerste Einstufung zuerst. Jede
Zeile klappt ihre Lücken mit Verweis auf den Eintrag auf. Die Seite einer
Website zeigt dieselbe Liste unter ihrer Software, die Statusseite eine Zeile
mit dem Weg dorthin. Eine Website mit bekannten Lücken und ohne offenen Fund
bekommt den Zustand „bekannte Lücken". Nennt eine Lücke keine behebende
Version, heißt es „2 von 3 behoben ab 5.9.2“. Fragt ein Lauf keine Datenbank,
bleibt die Liste des letzten Abgleichs stehen, solange die Version gleich ist,
und trägt den Hinweis „letzter Abgleich unvollständig“.

**Täglicher Abgleich.** Ab 4 Uhr gleicht das Addon einmal am Tag jede aktive
Website ab. Der Abgleich führt allein die Softwarestufe des Scanners aus:
Software erkennen, Versionen und Lücken nachschlagen. Bis zu drei Abgleiche
laufen gleichzeitig, zusätzlich zu den eingestellten gleichzeitigen Prüfungen.
„Alle Websites jetzt abgleichen" reiht die Runde sofort ein. Startet jemand
für eine Website eine Prüfung, während ihr Abgleich noch wartet, übernimmt die
Prüfung; sie gleicht ohnehin mit ab.

**WPScan-Schlüssel unter Einstellungen.** Der Runner legt ihn als Datei mit
Rechten 0600 ab und übergibt dem Scanner den Dateinamen. Als Argument stünde er
für jeden Benutzer des Servers lesbar in `/proc`. Die Einstellungsseite zeigt
einen gespeicherten Schlüssel nur als Hinweis; ein leeres Feld behält ihn, ein
Häkchen entfernt ihn.

**Scanner.** `--no-vuln-scan` schaltet den Abgleich ab; den WPScan-Schlüssel
liefern `--wpscan-token-file` oder `MALWATCH_WPSCAN_TOKEN`. Der JSON-Bericht
trägt je Software `vulnerabilities`, `update_to` und
`vulnerabilities_checked`. Rückgabecode 2 gilt auch für Software mit
bekannten Lücken, und `--email` verschickt den Bericht auch dann, wenn er nur
bekannte Lücken enthält.

### Nachgemessen

Über alle 36 WordPress-Websites des Servers: 709 Komponenten, davon 251 mit
bekannten Lücken, zusammen 1.601 Einträge. Keine gemeldete Korrekturversion lag
unter der installierten Version, und keine Komponente in ihrer neuesten Version
stand mit einer Lücke da. Dazu je eine Drupal-, Joomla- und TYPO3-Installation
zum Gegenlesen. Vier Stellen haben die ersten Messungen korrigiert:

1. **Slider Revolution 6.7.20** stand mit einer Upload-Lücke da, die erst mit
   7.0.0 kam. Die Datenbank führt sie als „< 7.0.11", ihr eigener Titel sagt
   „7.0.0 - 7.0.10". Solche Angaben grenzen den Bereich jetzt nach unten ein,
   sofern sie zum strukturierten Bereich passen und genau einen Abschnitt
   nennen. Von acht Einträgen für diese Installation blieben vier.
2. **Joomla:** Der Feed schreibt hinter „Versions:" ein geschütztes
   Leerzeichen. Die Feldsuche übersah es, und keine einzige Meldung wurde
   gelesen. Jetzt passen 22 Meldungen auf eine Installation mit 5.4.5.
3. **„Bisher ohne Korrektur" bei einer behobenen Lücke:** Ein Eintrag „bis
   einschließlich 1.16.3" trug zusätzlich die Markierung „unbehoben", auf einer
   Website mit 1.15.29, während 1.20.2 aktuell ist. Die obere Grenze gilt jetzt
   vor der Markierung; angezeigt wird „betroffen bis 1.16.3".
4. **Titel beim WordPress-Kern:** Einträge trugen die Versionsnummer als Titel.
   Er kommt jetzt aus der Beschreibung der Lücke.

## [0.12.3] – 2026-09-09

### Geändert

**Die Stufe steht nicht mehr zweimal in derselben Zeile.** Sie hatte ihren Platz
in der ersten Spalte und wurde darunter an jeder Regelzeile wiederholt — bei
einer Datei mit drei Treffern also viermal dasselbe Wort.

Wiederholt wird sie jetzt nur noch, wenn sie etwas hinzufügt: hat eine Datei
Treffer **verschiedener** Stufen, zeigt die Spalte die schwerste, und erst das
Etikett an der Regel sagt, welche Regel welche gefunden hat.

Nachgezählt an zwei Websites: auf der einen 92 Regelzeilen, davon jetzt **null**
mit Etikett — dort ist jede Datei in sich einheitlich. Auf der anderen 500
Regelzeilen, davon **163** mit Etikett: das sind die Dateien, in denen
tatsächlich zwei Stufen zusammenkommen. 337 überflüssige Etiketten weg, die
aussagekräftigen geblieben.

## [0.12.2] – 2026-09-09

### Behoben

**Die Tabellenüberschriften fielen ineinander, die Schaltflächen wurden zu
Strichen — die eigentliche Ursache stand nicht in unserem Blatt.** ISPConfig
setzt in `ispconfig.css`:

```css
.table { table-layout: fixed; }
```

Bei `table-layout: fixed` kommen die Spaltenbreiten ausschließlich aus den
Angaben der ersten Zeile. `width:1%` heißt dann wörtlich *ein Prozent* — bei
1082 Pixeln Tabellenbreite also elf Pixel — statt „so schmal wie der Inhalt".
Der Inhalt wird gar nicht erst gemessen und läuft aus der Zelle heraus. So
wurde aus „Stufe" und „Datei" in der Überschrift „SDatei", und die beiden
Schaltflächen jeder Fundzeile standen als farbige Striche am Rand.

ISPConfig hält dafür `.table-auto` bereit; für die drei Seiten dieses Bereichs
gilt es jetzt durchgehend.

Warum es drei Anläufe gebraucht hat: geprüft wurde bis dahin gegen einen
Nachbau der Vorlage. Der zeigt den Fehler nie, weil er die Stylesheets des
Panels nicht lädt — und genau dort stand die Zeile. Jetzt wird die echte Seite
gerendert und mit `bootstrap.min.css`, `ispconfig.css`, `responsive.min.css`
und `cicada.css` zusammen gemessen. Darin ließ sich der Screenshot des
Auftraggebers auf den Pixel nachstellen: Stufe 11, Datei 1050, Datum 11,
Schaltflächen 11.

Danach, an derselben Seite:

| Inhaltsbreite | Stufe | Datei | Zuerst gesehen | Aktionen | scrollt |
|---|---|---|---|---|---|
| 1084 | 53 | 727 | 117 | 185 | nein |
| 900 | 53 | 543 | 117 | 185 | nein |
| 760 | 53 | 403 | 117 | 185 | nein |

Nebenbei behoben: der Block mit den Regeltreffern hatte keine Breitengrenze und
zog die Dateispalte auf 1050 Pixel. Er ist jetzt wie der Dateiname auf 60
Zeichen gedeckelt.

## [0.12.1] – 2026-09-09

### Behoben

**Die Softwaretabelle schob die Seite zur Seite.** Diesmal an der echten Seite
gemessen statt an einer Nachbildung: die Detailseite von demoberei.ch, gerendert
mit ihren echten Daten, in eine 1000 Pixel breite Inhaltsspalte gestellt — so
breit ist sie im Panel neben der Navigation bei einem 1285 Pixel breiten
Fenster.

Die Tabelle war **1084 Pixel** breit. Die Ursache stand in einer einzigen
Klasse: die Spalte „Produkt" trug `mw-tight`, also `width:1%` mit
`white-space:nowrap`. Das heißt nicht „schmal", sondern „so breit wie der
Inhalt, und der darf nicht umbrechen" — bei einem Namen wie
`Ultimate_VC_Addons / ultimate-vc-addons` waren das 448 Pixel für eine Spalte,
die aussieht, als solle sie schmal sein. Ein Plugin-Name ist kein schmales Feld;
die Klasse ist weg, der Name darf umbrechen.

Nachgemessen an derselben Seite: alle fünf Tabellen passen bei 1000 und bei 1200
Pixeln, keine muss seitlich scrollen, die Seite selbst scrollt nicht, und beide
Schaltflächen jeder Fundzeile stehen in voller Breite da statt als farbige
Striche am Rand.

Unterhalb von etwa 900 Pixeln bleibt die Fundtabelle bei 905 Pixeln stehen —
Stufe, Dateiname, Datum und die zwei Schaltflächen brauchen so viel. Dort
scrollt dann der Tabellenrahmen, nicht die Seite. Das ist der Unterschied, um
den es die ganze Zeit ging.

## [0.12.0] – 2026-09-08

### Hinzugefügt

**„Gehört das hier hin?" statt „sieht das schlecht aus?"** — `vendor.foreign_file`.

Für jedes erkannte Plugin lädt der Scanner ohnehin die Prüfsummenliste von
wordpress.org; daran erkennt er bisher geänderte Herstellerdateien. Was er
nicht ansah: Dateien, die **in** einem Plugin-Verzeichnis liegen und die der
Hersteller überhaupt nicht ausliefert. Ein Plugin-Verzeichnis enthält das
Plugin — was sonst noch darin steht, ist auf einem anderen Weg hineingekommen.

Das ist die eine Prüfung, bei der Verschleierung nicht hilft. Sie sieht den Ort
an, nicht den Inhalt: eine perfekt getarnte Hintertür in
`wp-content/plugins/akismet/` fällt auf, weil Akismet sie nicht ausliefert, und
nicht, weil sie verdächtig aussieht.

Der Kern ist ausdrücklich ausgenommen. Seine Prüfsummenliste beschreibt den
Kern, nicht das Verzeichnis: `wp-config.php`, die Uploads und jedes Plugin
stehen nicht darin, und sie alle als fremd zu melden hieße, die ganze Website
zu melden.

### Gemessen

Acht Websites, rund 105.000 Dateien, 95 Plugin-Installationen: **eine einzige
fremde Datei** — und die war eine erzeugte CSS-Datei, die Formidable Forms sich
selbst in sein Verzeichnis legt.

Daraus folgte die Einschränkung, mit der die Prüfung jetzt läuft: gemeldet wird
nur, was der Server ausführen kann. Ein Stylesheet ist kein Einstieg, eine
PHP-Datei, die der Hersteller nicht ausliefert, ist einer. Mit dieser
Einschränkung: null Funde auf allen acht Websites.

Gegenprobe, damit „null" nicht heißt „prüft nichts": eine untergeschobene
`.php` in einer Kopie von Akismet wird als einziger Fund gemeldet, die über
hundert echten Plugin-Dateien daneben schweigen. Eine daneben abgelegte `.css`
wird nicht gemeldet.

### Bekannte Grenzen

Themes bleiben außen vor — wordpress.org veröffentlicht für sie keine
Prüfsummen (`theme-checksums` antwortet mit 404), das Archiv müsste geladen und
selbst ausgewertet werden. Bezahlte Plugins veröffentlicht ohnehin niemand;
dort greift die Prüfung nicht, was schon bisher so war.

Wie `core.modified` steht auch diese Prüfung nicht im Regelkatalog und kann
deshalb nie Teil einer automatischen Maßnahme werden. Das ist richtig so — beide
gehören vor die Augen eines Menschen —, aber die Zahlen neben den
Einstellungen zählen sie nicht mit.

## [0.11.0] – 2026-09-08

### Hinzugefügt

**Fünf neue Prüfungen**, 49 werden 54. Jede schließt eine Lücke, die eine
Gegenprobe an sechs Laborproben offengelegt hat — von den sechs klassischen
Formen erkannte der Scanner vorher zwei, und beide nur als „mittel".

- `php.eval.create_function` — `create_function` mit entschlüsseltem oder aus
  der Anfrage stammendem Rumpf. Bis PHP 7 der Ersatz für `eval`, wenn `eval`
  gesperrt war, und deshalb in jedem älteren Befall. Der Aufruf allein ist
  keiner: WordPress hat ihn jahrelang für Widgets benutzt.
- `php.webshell.auth_pass` — die Kennwortzeile der WSO-Familie. Geprüft wird
  die ganze Zuweisung, nicht das Wort, damit ein Text über Webshells nicht als
  einer gilt.
- `php.cloaking.search_bot` — zeigt Suchmaschinen etwas anderes als Besuchern.
  Eine Art von Befall, für die es bisher gar keine Regel gab: der Code ist
  unauffällig, auffällig ist die Unterscheidung. Nur „hoch" und nicht
  selbsttätig — es gibt ehrliche Gründe, einen Bot anders zu behandeln.
- `php.stealth.touch_mtime` — setzt den Zeitstempel einer abgelegten Datei auf
  den einer Nachbardatei, damit sie in der Verzeichnisliste nicht auffällt.
- `php.remote.fetch_eval_indirect` — lädt aus dem Netz in eine Variable und
  führt diese danach aus. Die vorhandene Regel verlangte beides ineinander und
  sah die zweischrittige Form nicht; übrig blieb `php.eval.variable` mit
  „mittel", für Code, der sich seine Anweisungen aus dem Netz holt, zwei
  Stufen zu wenig.

### Gemessen

Fehlalarme: **null**. Frisches WordPress und Joomla (13.770 Dateien) melden
vorher wie nachher nichts. Auf drei Websites mit echtem Befall bleibt die Zahl
der Funde exakt gleich — gameday-film.de 648, hecht-tiefbau.de 98,
torrios.de 16 — bei zusammen rund 51.000 Dateien.

Neue Treffer auf diesen Websites: **ebenfalls null.** Was dort liegt, sehen die
bisherigen Regeln bereits. Die neuen Prüfungen decken bekannte Angriffsformen
ab, die auf diesem Server gerade nicht vorkommen; als nachgewiesene
Verbesserung der Erkennung ist das nicht zu verkaufen.

### Wieder entfernt

Eine sechste Regel auf `ignore_user_abort(true)` plus `set_time_limit(0)` plus
Codeausführung — der Dauerläufer, den niemand bestellt hat — ist an der ersten
echten Website, die sie zu sehen bekam, danebengegriffen: das Sicherungs-Plugin
`iwp-client` tut genau diese drei Dinge, und zwar zu Recht. Es läuft lange,
überlebt den Abbruch des Aufrufers und ruft `mysqldump` über `passthru` auf.
Jedes Sicherungs- und Verwaltungs-Plugin sieht so aus.

Enger fassen ließe sie sich nur, indem man verlangt, dass das Ausgeführte von
außen kommt — und das melden `php.eval.request` und
`php.remote.fetch_eval_indirect` schon. Es blieb kein Bereich übrig, in dem sie
etwas beiträgt, also ist sie draußen. Der Grund steht als Kommentar an ihrer
Stelle im Katalog, damit sie niemand ein zweites Mal schreibt.

## [0.10.4] – 2026-09-08

### Behoben

**Auch auf dem Monitor rutschte die zweite Schaltfläche aus der Tabelle.** 0.10.3
hat die schmale Darstellung geradegezogen, die breite aber nur für ein wirklich
breites Fenster. In der Inhaltsspalte des Panels — bei 800 bis 900 Pixeln — war
die Fundtabelle 87 Pixel breiter als ihr Rahmen: die Schaltflächen standen in
einer Reihe und durften nicht schrumpfen, also schob sich „In Quarantäne
verschieben" nach rechts hinaus und war als roter Strich am Rand zu sehen.

Zwei Reihen dürfen jetzt umbrechen, wenn es eng wird: die Schaltflächen einer
Zeile und die Trefferzeile aus Regel, Stelle und Auszug. Beide behalten ihre
volle Breite und rücken untereinander, statt aus dem Bild zu wandern. Gemessen
bei 800, 900 und 1200 Pixeln: aus 87 Pixeln Überhang wurden 3, 8 und 0.

## [0.10.3] – 2026-09-08

### Behoben

**Auf dem Telefon fielen die Tabellenüberschriften ineinander und die
Schaltflächen standen außerhalb des Bildes.** Aus „Stufe" und „Datei" wurde in
der Kopfzeile „SDatei", aus drei Überschriften ein ineinandergeschobenes Wort,
Pfade waren mitten im Verzeichnis abgeschnitten, und die ganze Seite ließ sich
seitlich wegschieben, statt in den Rahmen zu passen.

Die Ursache war eine Annahme: die dichte Darstellung, die eine Tabelle auf einem
Monitor lesbar macht — `width:1%` und `white-space:nowrap` auf den schmalen
Spalten, ein Pfad auf 46 Zeichen gekürzt — setzt Platz voraus. Auf 375 Pixeln
gibt es ihn nicht. Solche Spalten schrumpfen dort auf wenige Pixel, und weil
`nowrap` den Text nicht umbrechen lässt, läuft er aus der Zelle heraus über die
Nachbarn.

Die schmale Fassung ist jetzt die Grundeinstellung, weil sie nichts voraussetzt:
Pfade brechen um und werden nicht gekürzt, Spalten nehmen sich, was sie brauchen,
die Schaltflächen einer Zeile stehen untereinander statt nebeneinander. Alles
Enge kommt erst ab Tabletbreite dazu. Zusätzlich schiebt der Tabellenrahmen im
Notfall die Tabelle seitlich statt die ganze Seite.

Ein auf 46 Zeichen gekürzter Pfad hatte auf dem Telefon noch einen zweiten
Haken: der volle Pfad hing als Tooltip daran, und Darüberfahren gibt es dort
nicht.

Die Spalte „Zuerst gesehen" der Fundliste entfällt unterhalb von 768 Pixeln.
Stufe, Datei und die beiden Schaltflächen füllen die Breite eines Telefons
bereits aus; das Datum ist die Angabe, die man am ehesten entbehrt, und es steht
auch in der Fundliste.

## [0.10.2] – 2026-09-08

Eine Prüfung des gesamten Zweigs, die vor allem die Korrekturen der vorigen Prüfung
angesehen hat. Zwei davon griffen nur dort, wo hingesehen worden war.

### Behoben

**Die Symlink-Abwehr deckte nur eine von zwei Schreibschleifen.** Die Schleife, die die
losen Kerndateien schreibt, gab es zweimal. Im Modus „Darüberschreiben" — also genau dem
Modus, der den alten Baum stehen lässt und damit auch das, was jemand hineingelegt hat —
kam eine `index.php`, die auf `wp-config.php` zeigt, durch die Grenzprüfung, und die
Herstellerdatei landete als root in der `wp-config.php`. Ohne Kopie, weil Verknüpfungen
beim Ablegen absichtlich übersprungen werden. Es gibt jetzt genau eine solche Schleife.

**Die Reparatur prüfte das geladene Original zu spät.** „Enthält es dieses Verzeichnis?"
stand je Verzeichnis unmittelbar vor dessen Auslagerung: fehlte dem Download das zweite,
war das erste längst in der Quarantäne und von der Website weg. Die Website stand ohne
`wp-admin` da, und der Lauf meldete einen Fehler. Jetzt wird alles geprüft, bevor
irgendetwas angefasst wird. Eine Reihenfolge ist keine Prüfung.

**Ein gescheiterter Kernlauf verschwieg, was er schon abgelegt hatte.** Die Kennungen
gingen auf dem Fehlerweg verloren, der ausgelagerte Baum lag im Speicher, und weder
Bericht noch Panel nannten ihn. Vorhanden, aber unauffindbar ist schlimmer als verloren.

**`validRel` prüfte nichts.** Die Schleife suchte `..` in einem Pfad, aus dem `path.Clean`
sie längst herausgerechnet hatte — drei Fassungen lang eine Prüfung, die keine war. Der
zugehörige Test war grün, weil die Datei nicht existierte, nicht weil der Pfad abgelehnt
wurde; er legt sie jetzt vorher an.

**Die Liste entschied am Namen, was ein Eintrag ist.** Eine Änderung am Format der Kennung
hätte jeden vorhandenen Eintrag lautlos aus der Liste genommen — und das Panel löscht, was
die Liste nicht nennt. Ein Verzeichnis mit einer `meta.json` ist ein Eintrag, wie immer es
heißt; die Namen der übersprungenen stehen jetzt in der Liste und im Protokoll.

**Eine leere Liste löscht keinen Index mehr.** Zeigte die Einstellung auf einen
vorhandenen, aber falschen Speicher, war die Antwort „keine Einträge" — und der Abgleich
räumte den ganzen Index ab. Solange die Datenbank für diesen Server Zeilen hat, löscht
eine leere Antwort nichts.

**Die Minutenschritte des Crons bremsen jetzt auch nach einem Fehlschlag.** Scheiterte
einer, lief er jede Minute erneut.

**„Zusammenstellung speichern" speicherte die Einstellungen mit** — und schaltete dabei die
automatische Maßnahme still ab. Wer eine Regelauswahl unter einem Namen sichert, erwartet
genau das und nichts weiter.

**Ein Apostroph in einem Bestätigungstext zerlegte die Schaltfläche.** Die Texte gehen in
ein `onclick`-Attribut; sie werden jetzt dafür aufbereitet, und Prüfung 41 hält jeden
weiteren daran fest.

### Geändert

Prüfung 40 sieht jetzt auch einzeilige Argumentlisten und Aufrufe, die als Zeichenkette
zusammengesetzt werden — die erste Fassung hätte den Fehler, für den sie geschrieben
wurde, in dieser Form nicht gefangen. Beide neuen Prüfungen sind mit absichtlich
eingebauten Fehlern zum Auslösen gebracht worden, vier verschiedene für Prüfung 40.

## [0.10.1] – 2026-09-08

### Behoben

**„In Quarantäne verschieben" ging jedes Mal schief.** Der Auftrag rief den Scanner ohne
seinen Befehl auf — `malwatch add …` statt `malwatch quarantine add …`. Der Scanner kennt
kein `add`, antwortete mit seiner eigenen Hilfe und Rückgabecode 3, und im Panel stand
„Die Quarantäne hat keinen Bericht hinterlassen" mit dieser Hilfe als Ausgabe.

Die Verdrahtungsprüfung 37 vergleicht die Schalter und sah nichts: ein fehlender Schalter
fällt auf, ein fehlendes erstes Wort nicht. Prüfung 40 nimmt jetzt jede Argumentliste des
Runners und besteht darauf, dass ihr erstes Element ein Befehl ist, den `usage.go` kennt.

**Eine Datei, die schon weg war, zählte als Fehlschlag.** Nach einer Reparatur ist das der
Normalfall: sie ersetzt ganze Verzeichnisse, und die Funde darin sind mit dem Verzeichnis
verschwunden. Vierzig verschobene Dateien und eine bereits gelöschte meldeten zusammen
einen gescheiterten Auftrag. Jetzt heißt das „bereits verschwunden" und ist kein Fehler —
das Ziel, dass die Datei nicht mehr auf der Website liegt, ist ja erreicht.

**Die Größe blieb „noch unbekannt".** Was eine Reparatur ablegt, kennt nur seine Kennung;
Größe, Dateizahl und Art stehen in der Liste des Speichers, die bisher erst der nächste
Quarantäneauftrag erzeugte. Dreizehn Zeilen sagten deshalb „noch unbekannt" und der
belegte Platz stand auf null — die Auskunft, für die man die Seite aufschlägt. Der Cron
holt die Liste jetzt, sobald eine Zeile ohne Größe dasteht.

**Der Regelkatalog kam eine Stunde zu spät.** `refresh_rules` und das Aufräumen des Spools
standen hinter der Sperre, die die Tabellenläufe der Aufräumarbeiten auf Minute 7 der
Stunde begrenzt. Beide bringen ihre eigene Bremse mit; die Sperre hat sie nur verzögert.
Nach einer frischen Installation zeigte die Einstellungsseite deswegen bis zu eine Stunde
lang „0 Prüfungen" neben jeder automatischen Maßnahme.

### Geändert

**Die Tabellen sind halb so hoch und lesen sich in einem Durchgang.** Ein Pfad stand über
drei Zeilen, die Art des Eintrags als eigene Zeile darüber, und die Schaltflächen der
letzten Spalte waren zu farbigen Strichen am Rand zusammengequetscht — ein Flex-Container
schrumpft seine Kinder unter ihre Inhaltsbreite, wenn die Spalte schmal ist. Jetzt: enge
Polsterung, Pfad einzeilig mit dem vollen Pfad als Tooltip, die Art als kleines Etikett
daneben, Zahlen rechtsbündig und tabellarisch, Schaltflächen in einer Reihe ohne
Schrumpfen. Betrifft alle sechs Tabellen der neuen Seiten und der Detailseite.

**Die Schriftfarben stimmen jetzt auf beiden Themes.** Gedämpfter Text stand als
`var(--cic-text-dim, #8b9298)` im Blatt — der Rückfallwert ist der des dunklen Themes, und
auf dem hellen Standardtheme, das keine `--cic-*` setzt, ergab das Hellgrau auf Weiß.
Gedämpfter Text läuft jetzt über `opacity` und erbt damit die Farbe des Themes, Linien und
Flächen über durchscheinendes Grau; Schaltflächen bekommen von der Erweiterung überhaupt
keine Farbe mehr, weil das Theme sie richtig setzt und jede eigene Angabe es auf dem
anderen kaputt macht.

Dabei aufgefallen und mit behoben: das Fundzeichen für „kritisch" stand auf der
Statusseite rot auf rot, und eine Variable `--cic-ok-mid` gibt es nicht, die Regel lief
also immer in ihren Rückfall.

## [0.10.0] – 2026-09-07

### Hinzugefügt

**Die Quarantäne.** Alles, was das Addon von einer Website entfernt, liegt jetzt an einer
Stelle, die man ansehen kann: einzelne Funde, ganze Verzeichnisse, die eine Reparatur
ersetzt hat, und was eine automatische Maßnahme nachts weggenommen hat. Jeder Eintrag
nennt Pfad, Website, Grund, Zeitpunkt, Herkunft und Größe. Von dort geht es zurück auf die
Website, als Datei zum eigenen Rechner oder endgültig weg — und nur das Letzte ist
unwiderruflich.

Vorher schrieb „Entfernen" eine Kopie in ein Verzeichnis, das niemand ansieht, und löschte
die Datei. Auf dem Testsystem hatten sich dort 1,1 GB angesammelt, aus denen kein Mensch
je wieder etwas herausgeholt hat, weil nichts sagte, was darin liegt.

**Herunterladen gibt ein passwortgeschütztes ZIP, Passwort `infected`.** Das ist die
Übereinkunft, mit der Sicherheitsleute Proben verschicken: jeder Entpacker versteht sie,
und kein Virenscanner sieht hinein, also kommt die Datei heil am Arbeitsplatz an, statt
unterwegs eingesammelt zu werden. Vertraulichkeit ist das nicht und soll es nicht sein —
es hält die Probe davon ab, aus Versehen zu laufen.

**Die Reparatur ist eine Entscheidung geworden statt zweier Knöpfe.** Eine eigene Seite
fragt, wie ersetzt werden soll, was mit Elementen geschieht, für die es keine
Herstellerdatei gibt, und welche Elemente überhaupt angefasst werden. Daneben steht, was
mit jedem einzelnen passieren wird.

- *Vollständig ersetzen*: der bisherige Inhalt wandert in die Quarantäne, dann kommt das
  Original an seine Stelle. Untergeschobene Dateien sind damit aus dem Webverzeichnis
  heraus, auch die, die keine Prüfung gefunden hat.
- *Darüberschreiben, nichts verschieben*: der Inhalt wandert ebenfalls in die Quarantäne,
  bleibt aber liegen, und die Herstellerdateien werden darübergelegt. Angepasste Vorlagen
  überleben — eine untergeschobene Datei allerdings auch.

**Automatische Maßnahme nach den nächtlichen Prüfungen.** Vier Möglichkeiten: nichts
anfassen, nur die Funde ohne Ermessensspielraum, alles Kritische, oder eine selbst
zusammengestellte Auswahl von Prüfungen, die sich unter einem Namen speichern lässt. Neben
jeder Möglichkeit steht, wie viele Prüfungen sie umfasst und wie viele Funddateien sie
gerade beträfe — eine Zahl aus den eigenen Daten, nicht aus dem Werbetext.

Die Maßnahme greift nur bei Funden, die neu hinzukommen. Was schon in der Liste steht, hat
der Bediener gesehen und stehen gelassen; das nachträglich nachts wegzunehmen wäre eine
Entscheidung über seinen Kopf hinweg. Für die bestehenden Funde gibt es einen eigenen
Knopf, der vorher die Zahl nennt.

**Neue Befehle.** `malwatch quarantine list|restore|delete|export` bedient den Speicher von
der Kommandozeile, `malwatch rules --json` gibt den Regelkatalog aus, damit die Oberfläche
Prüfungen beim Namen nennen kann statt bei ihrer Kennung.

### Geändert

**Eine Reparatur löscht kein Element mehr, nur weil der Hersteller die Version nicht
veröffentlicht.** Bezahlte Plugins und selbst gebaute Themes gibt es nirgends zum
Herunterladen; bisher verschwanden sie, und die Website verlor eine Funktion, weil eine
Datei nicht öffentlich ist. Die Vorgabe ist jetzt, das Element stehen zu lassen und zu
melden. Wer es doch weghaben will, wählt „in die Quarantäne" — `os.RemoveAll` ohne vorher
angelegte Kopie gibt es an keiner Stelle mehr.

**Beide Reparaturmodi sichern, bevor sie etwas anfassen.** „Nichts geht verloren" steht so
in der Oberfläche und stimmt jetzt ohne Fußnote.

**Ein Sammel-Download ist ein ZIP, kein Auftrag je Eintrag.** Pro Server läuft immer nur ein
Auftrag; zwanzig ausgewählte Einträge wären neunzehn Absagen und ein Download gewesen.

### Behoben

**Der Fortschrittsbalken zählte auf jedem Livesystem null Dateien.** `/var/lib/malwatch`
gehört root und ist `0750`, die Oberfläche läuft als Benutzer `ispconfig` — sie konnte die
Fortschrittsdatei also nie lesen:

```
$ sudo -u ispconfig cat /var/lib/malwatch/runs/job-100.progress
cat: … Permission denied
```

Damit kam von der ganzen Zählerarbeit aus 0.9.0 — `--expect`, Nenner, Prozentzahl —
nichts im Browser an; sichtbar waren nur die Phasen, die die Vorlage selbst setzt. Der
Installer gibt `runs` und `spool` jetzt die Gruppe der Oberfläche und das Setgid-Bit, damit
neu geschriebene Dateien sie erben, und zieht vorhandene Dateien nach. Der Runner legt
fehlende Verzeichnisse genauso an, falls ein Auftrag vor dem Update eintrifft.

**Die Deinstallation ließ zwei Tabellen stehen.** `malwatch_repair` und
`malwatch_repair_element` fehlten in `uninstall-schema.sql`, seit es sie gibt.

**Die vierte Reparaturphase hieß „Sichern".** Sie legt den alten Baum in die Quarantäne;
der Name stammte noch aus der Zeit, als sie ein `.tar.gz` schrieb, das niemand wiederfand.

## [0.9.2] – 2026-09-07

### Geändert

**Schaltflächen und Fortschritt stehen jetzt oben.** Beide lagen zwischen der
Tabelle des letzten Laufs und der Fundliste und gingen dort unter. Die Aktionen
stehen nun direkt unter der Überschrift, der Fortschritt darunter — beides das
Erste, was man sieht.

**Der Fortschritt zeigt die Phasen des Laufs, der wirklich läuft.** Ein Scan hat
keine Reparaturphasen; „Erkennen · Holen · Prüfen · Sichern · Tauschen" während
einer Prüfung anzuzeigen ließ sie aussehen wie eine Reparatur, die bei „Erkennen"
hängt. Ein Scan zeigt jetzt „Dateien werden geprüft" mit Zähler und Prozentzahl,
eine Reparatur ihre fünf Phasen mit der aktuellen hervorgehoben.

**Der Balken bewegt sich auch bei einem Scan.** Er rechnete seine Breite nur aus
`elements_done/elements_total` — Werte, die es nur bei einer Reparatur gibt — und
fiel sonst auf feste fünf Prozent zurück. Jetzt nimmt er bei einem Scan
`files_done/files_total`, gedeckelt bei 99 Prozent bis zur Fertigmeldung.

Farben durchgehend aus den Theme-Variablen mit Rückfallwert, Radius 3px, das
Laufprotokoll scrollt in eigenem Rahmen statt die Seite zu strecken. Die
Phasennamen liegen in den Sprachdateien statt fest im Code.

## [0.9.1] – 2026-09-07

### Behoben

**Der Knopf „Ansehen" auf der Statusseite führte bei jeder Website ins Leere.**
Er hängte `?domain_id=` an, `malwatch_site_show.php` liest aber `$_REQUEST['id']`
— es kam also 0 an, und die Seite antwortete „Ungültige Website." Die Fundliste
machte es von jeher richtig; die neue Statusseite nicht. Keine der 33
Verdrahtungsprüfungen sah es, weil beide Namen für sich betrachtet plausibel
aussehen. Prüfung 34 hält jetzt fest, dass ein Verweis den Parameternamen
benutzt, den die Zielseite liest.

## [0.9.0] – 2026-09-07

### Neu

**Ein eigener Bereich „Security" in der oberen Leiste.** Bisher hing das Addon als
Navigationsgruppe in der Seitenleiste des fremden Sites-Moduls. Der Installer trägt
das Modul jetzt selbst in `sys_user.modules` der Administratoren ein, der
Deinstaller nimmt es wieder heraus; alle Seiten liegen unter `security/`.

**Eine Statusseite, die eine Frage beantwortet.** Nicht 61 Zeilen mit Spalten,
sondern ein Satz — „Drei Websites brauchen Ihre Aufmerksamkeit." — und darunter
nur diese drei, die dringendste oben. Die unauffälligen stehen als ruhige Zeile
darunter und sind kein Standardinhalt.

**Ein Fortschrittsbalken, der sich bewegt.** Der Scan meldete bisher einen Zähler
ohne Nenner, weshalb die Anzeige auf feste fünf Prozent zurückfiel und ein Lauf
minutenlang aussah wie ein Absturz. Der Scanner nimmt jetzt `--expect` entgegen,
der Runner reicht die Dateizahl des letzten Laufs derselben Website durch, und die
Anzeige deckelt bei 99 Prozent, bis der Lauf fertig meldet.

### Behoben

**Die Oberfläche reißt den Bediener nicht mehr aus jeder Seite zurück.** Die alte
Übersicht lud sich bei laufender Prüfung alle fünf Sekunden komplett neu. Ihr
Abbruch hing an `DOMNodeRemoved` — einem Mutation Event, das Chrome seit Version
127 abgeschaltet hat. Der Timer überlebte deshalb jede Navigation und holte den
Bediener aus den Einstellungen und aus jedem einzelnen Fund zurück in die Liste.

Ersetzt durch punktuelles Umschreiben einzelner Zellen aus einem JSON-Endpunkt,
abgebrochen über `MutationObserver` und zusätzlich über `document.contains` in
jedem Durchlauf — damit auch ein vergessener Timer nur noch ins Leere schreiben
kann. Dieselbe Korrektur auf der Detailseite, wo derselbe Fehler stand.

**Der Erwartungswert zählt jetzt dasselbe wie der Zähler.** `files_scanned` zählt
nur Dateien, die den Zwischenspeicher verfehlen; ein warmer Lauf über 193.888
Dateien hätte die ganze Zeit auf 0 Prozent gestanden. Beide Seiten rechnen jetzt
mit den angesehenen Dateien.

**Der Installer legt die Verzeichnisse an, in die er kopiert.** ISPConfigs
`enable_files()` erzeugt keine Elternverzeichnisse und prüft den Rückgabewert von
`copy()` nicht — jede Kopie wäre still fehlgeschlagen, und der Installer hätte
trotzdem Erfolg gemeldet.

**Die Sprachdatei erreicht die neuen Seiten.** `load_language_file()` bindet die
Datei im eigenen Geltungsbereich ein; `$wb` kam beim Aufrufer nie an, und die
Statusseite hätte ohne einen einzigen Text gerendert.

### Geändert

Elf neue Verdrahtungsprüfungen halten fest, was in dieser Runde schiefging: keine
`DOMNodeRemoved`-Benutzung, kein Neuladen im Takt, Zustandswerte gegen das Schema
statt gegen eine wiederholte Liste, jedes Kopierziel mit erzeugtem Verzeichnis,
und keine Seite, die `$wb` liest, ohne die Sprachdatei einzubinden.

## [0.8.2] – 2026-09-07

### Neu

Zwei Verschleierungsfamilien, die den Funktionsnamen auf Wegen verstecken, für
die der Katalog keine Antwort hatte.

**`php.obfuscation.xor_literal`** – das Wort `chr` schreiben, ohne es zu
schreiben:

```php
$gdigop = 'gdigop' ^ "\x04\x0c\x1b";        // 'chr'
$name   = "a"."r"."r".$gdigop(97)."\171";   // array_map
```

PHPs `^` verknüpft zwei Zeichenketten byteweise bis zur kürzeren, also lässt
sich jedes Wort aus einer Attrappe und einer Maske bauen. Verräterisch ist die
Maske: um auf druckbaren Buchstaben zu landen, muss sie Bytes unterhalb des
Leerzeichens tragen. Tabulator, Zeilenumbruch und Wagenrücklauf sind
ausgenommen — ohne diese Ausnahme meldete die Regel 58 Dateien eines frischen
WordPress und 213 einer Installation mit 193.888 Dateien.

**`php.obfuscation.substr_of_nothing`** – `substr("", 0)` ist der Leerstring,
umständlich geschrieben. Er steht am Kopf eines Dekodierers, der Namen aus einem
verwürfelten Alphabet liest. Die Tabelle selbst ist kein Muster, und der
doppelte Index, der sie liest, steht in 723 Dateien einer ehrlichen
Installation. Dieser Tick nicht.

### Gemessen

Beide vor dem Bauen gegen ein frisches WordPress, ein frisches Joomla, drei
Kundensites und 193.888 Dateien einer vierten: null. Auf der befallenen Site 6
und 7, und der siebte liegt in einem Plugin-Verzeichnis, abgelegt acht Tage
nachdem der Ordner drumherum geschrieben wurde.

Gemeldete Dateien dort: 392 auf 403. Saubere Mengen unverändert.

## [0.8.1] – 2026-09-07

### Behoben

Ein Review nahm 0.8.0 auseinander und fand dreimal denselben Fehler: eine Regel,
deren Begründung ein Merkmal nannte, das das Muster nicht verlangte.

**`php.include.decoy_guard`** meldete gewöhnliches PHP als kritisch —
`if (!isset($lang)) { $lang = 'de'; } else { require_once "lang/$lang.php"; }`
ist eine normale Redewendung. Was sie vom Loader trennt, ist das stummschaltende
`@`. Einzeln nachgezählt: 43 von 43 Loadern haben es, die ehrlichen Formen
verstummen.

**`php.obfuscation.name_in_variable`** verlangte einen Großbuchstaben. WordPress
und Joomla sind snake_case-Welten, ein Korpus aus ihnen kann über camelCase
nichts sagen — und `$strLen = 'mb_strlen'` ist Jetpacks eigene Redewendung mit
genau einem. Jetzt sind zwei nötig.

**`php.obfuscation.chr_arithmetic`** und **`php.obfuscation.chr_chain`** hatten
keine Namensgrenze, sodass `mb_chr(187-73)` als verschleierter Buchstabe galt.

### Geändert

Zwei Tests prüften nichts, beides durch Mutation belegt: der Schutz gegen
`mb_chr` liess sich vollständig löschen, ohne dass die Suite rot wurde. Er wird
jetzt direkt geprüft. Dazu ein Fuzzer für den Indexvertrag — ein Eintrag je
Byte, jeder im Bereich, nie rückwärts, nie länger als die Eingabe; 34,7
Millionen Eingaben ohne Bruch.

Der Vertrag von `joinConcatenated` ist neu beschrieben. Er versprach, nie etwas
einzufügen, ersetzt aber Läufe durch erzeugte Bytes — ein Kommentar wird zum
Leerzeichen, `"\x5f"` und `chr(95)` zum Unterstrich. Beschrieben sind jetzt die
vier Eigenschaften, die wirklich tragen.

Die Erkennung bleibt unverändert: 756 Funde auf 392 Dateien.

## [0.8.0] – 2026-09-07

### Neu

Eine Site trug 272 Hintertüren durch `wp-includes`, `wp-admin`, Plugins und
Themes, und der Scanner meldete keine einzige. Sie verstecken den
Funktionsnamen alle gleich:

```php
$v = 's'."\164"."\x72".chr(95)."\162"."\x6f".chr(116)."\61"."\x33";
```

Das ist `str_rot13`. Zwei Dinge hinderten die zweite Ansicht daran, es zu
lesen: sie verklebte zwei Literale nur bei gleichem Anführungszeichen, obwohl
PHP das egal ist, und `chr(95)` ist ein Aufruf statt eines Literals, sodass der
Unterstrich nie ankam.

**Kettenleser.** Die zweite Ansicht läuft jetzt eine Verkettung ab — Literale
beider Anführungsarten und `chr()`-Aufrufe mit Zahl oder Rechnung als Argument.
Punkte und innere Anführungszeichen fallen weg, die äußeren bleiben. `chr($i)`
bleibt unangetastet: das hat erst zur Laufzeit eine Antwort.

**`php.obfuscation.chr_arithmetic`** – `chr(187-73)` ist der Buchstabe `r`, und
es gibt genau einen Grund, ihn so zu schreiben. Gemessen vor der Schwelle: ein
frisches WordPress und Joomla halten 7.605 PHP-Dateien, 110 davon rufen `chr`
auf, keine schreibt das Argument als Summe.

**`php.obfuscation.name_in_variable`** – gewöhnliche Funktionsnamen in
Variablen geparkt, damit keine Regel sie je sieht. Die Variable muss einen
Großbuchstaben tragen: ehrlicher Code benennt sie nach der Funktion und
schreibt sie klein (`$strlen = 'mb_strlen'` in Jetpack), der Verschleierer
nimmt, was sein Erzeuger ausgeworfen hat.

**`php.include.decoy_guard`** – eine Einbindung hinter einer Abfrage, die nie
falsch sein kann:

```php
if (!isset($rog)) { rtrim($rog); } else { @include_once($rog); }
```

`isset` auf eine gerade zugewiesene Variable ist immer wahr, `rtrim` im
leeren Kontext tut nichts. Der Zweig ist Kulisse. 43 solcher Loader zogen PHP
aus versteckten `.css`-Dateien.

### Gemessen

Auf der befallenen Site steigen die gemeldeten Dateien von 73 auf 392. Zum
Vergleich: ein anderer Scanner mit 334 eigenen Definitionen meldet dort 390.
Fehlalarme bleiben bei null — frisches WordPress, frisches Joomla, drei
Kundensites und eine Installation mit 193.888 PHP-Dateien melden genau das,
was sie vorher meldeten.

## [0.7.0] – 2026-09-06

### Neu

Ein Rundumschlag über alle 33 Websites mit Funden, gesucht über Signale, die der
Scanner nicht kennt: versteckte `.php`-Dateien, PHP in `.well-known`, PHP in
`uploads`. Von 898 Verdachtskandidaten blieben 415 unerkannt, und die zerfielen
in 32 verschiedene Inhalte — fast alles leere WordPress-Schutzdateien,
macOS-Metadaten und Werkzeugkonfigurationen. Zwei waren es nicht:

- **`php.disguised_as_image`** — eine ausführbare Endung hinter einem Bildnamen.
  Auf einer Website lag `Group-36-1-300x49.php` zwischen den echten
  Vorschaubildern des Medienarchivs und trug deren Namensschema exakt. Am Inhalt
  war nichts zu erkennen: der Name und die Endung sind der Fund, denn die Endung
  ist es, die den Webserver dazu bringt, die Datei auszuführen. `svg` ist
  bewusst ausgenommen — Symfonys Fehlerseite bringt `symfony-ghost.svg.php` mit,
  eine Vorlage, die eines zeichnet.
- **`php.in_uploads` erweitert.** Eine Datei dort braucht keinen PHP-Code, um ein
  Problem zu sein. Die gefundene enthielt nichts als ein Upload-Formular in
  reinem HTML — die sichtbare Hälfte einer Hintertür, eine angehängte Zeile von
  der ganzen entfernt.

### Behoben

Sieben Punkte aus einer Durchsicht des Regelstands, fünf davon Fehlalarme auf
ehrlichem Code. Jeder wurde vor der Änderung nachgestellt:

- `php.include.assembled_path` meldete `require_once $paths['base'] . $paths['file']`.
  Mindestens ein Index muss jetzt **gerechnet** sein — `$T[9+1]` ist die
  Handschrift des Laders, zwei schlichte Indizes sind die eines Pfadbauers.
- `php.tool.leaf_mailer` meldete jedes `$leaf['version']`. `$leaf` ist ein
  gewöhnlicher Name in Baum-, Menü- und Taxonomie-Code; die beiden
  Werkzeugnamen decken beide Varianten allein ab.
- `php.webshell.hardcoded_gate` meldete ein kleines Anmeldetor mit fest
  eingetragenem Hash. Die Datei muss den erschlichenen Zugang auch **nutzen**
  können.
- `php.obfuscation.split_open_tag` meldete eine Datei, die PHP erzeugt und
  irgendwo auch `curl_exec` ruft. Der Lader **sucht** zusätzlich nach dem Tag in
  dem, was er geholt hat; ein Erzeuger sucht nach nichts.
- `php.stream.archive_url` meldete eine Archivadresse in einem Kommentar. Sie
  muss in einer Zeichenkette stehen.
- `php.in_image` und `php.in_uploads` fragten die zusammengesetzte Sicht, ob
  eine Datei einen PHP-Tag trägt. Diese Sicht schweißt einen zusammen, und ein
  zusammengeschweißter Tag wird nicht ausgeführt. Beide sind `RawOnly`.
- `php.obfuscation.goto_spaghetti` ließ sich mit einem fehlenden Leerzeichen
  hinter der Sprungmarke umgehen.

**Heredocs und Nowdocs werden übersprungen.** Ob der Zusammensetzer einen
überlebte, hing bisher daran, ob sein Rumpf eine gerade Anzahl
Anführungszeichen enthielt; bei gerader wurde der Rumpf als Quelltext
verschweißt. Eine README in einem Heredoc konnte damit den Namen erzeugen, nach
dem die Regeln suchen.

### Entfernt

- `php.webshell.session_filehash_gate`. Ein Sitzungsschlüssel aus dem Hash der
  eigenen Datei ist auch das, was Sitzungsbibliotheken tun: die Regel feuerte
  auf CMS Made Simple, auf ein Sitzungsmodul und auf den Contao-Manager. Sie
  trug messbar **null** zur Erkennung bei — was sie fing, fängt
  `php.tool.leaf_mailer` beim Namen.

### Geändert

- `Rule` kennt `AlsoRequires`, eine zweite unterstützende Bedingung. Manche
  Formen brauchen drei Aussagen über eine Datei, und zwei davon lassen sich
  nicht in ein Muster schreiben.
- Die zweite Sicht wird erst bei Bedarf gebaut, nicht vorab, und ihr Index ist
  `int32`. Ein 2-MB-Archiv, auf das keine Regel zutrifft, zahlte vorher eine
  Kopie und eine 12,8-MB-Landkarte — je Arbeiter.

Erkennung unverändert: 215 von 217 Dateien aus dem Befallszeitraum, null
Fehlalarme auf frischem WordPress und vier Websites im Betrieb.

## [0.6.0] – 2026-09-05

### Neu

- **Sieben weitere Verschleierungen.** Von allem, was während des Befalls auf der
  betroffenen Website geschrieben wurde, findet der Scanner jetzt **215 von 217**
  statt 184. Die zwei verbliebenen sind eine AWStats-Seite und eine
  503-Wartungsseite, die die Bereinigung angefasst hat.

  - `php.obfuscation.goto_spaghetti` — Sprung und Sprungmarke in derselben
    Zeile. Nicht die Zahl der Sprünge: `goto` ist selten, aber nicht unbenutzt —
    der HTML-Parser von WordPress springt damit, AWS-SDK und Guzzle ebenso.
  - `php.obfuscation.split_open_tag` — `'<' . '?' . 'php'`, zusammen mit einem
    Netzabruf. Allein genügt es nicht: TCPDF erzeugt PHP-Font-Dateien und
    vermeidet den Tag im eigenen Quelltext aus demselben mechanischen Grund.
  - `php.include.assembled_path` — `require_once $T[9+1].$T[43+2]`, ein
    Dateiname zeichenweise aus einem selbstgebauten Array.
  - `php.upload.traversal` — `'../' . $_FILES[…]['name']`, wenn Verschieben und
    Ziel zwei Zeilen auseinanderstehen.

- Die zweite Sicht lässt **Kommentare zu einem Leerzeichen zusammenfallen**. Ein
  Schadprogramm hatte sie zwischen jedes Token geschoben:
  `@require_once /*-x-*/ $T /*-y-*/ [9+1]`. Nur Kommentare mitten im Ausdruck
  lösen einen zweiten Durchgang aus, sonst würde jede Datei mit Lizenzkopf den
  Lauf verdoppeln.

### Behoben

- `php.webshell.session_filehash_gate` meldete **CMS Made Simple**. Es mischt
  `md5(__FILE__)` in einen Login-Fingerabdruck und liest `$_SESSION` unter einem
  festen Namen. Die Regel verlangt jetzt, dass der Dateihash der Sitzungsschlüssel
  selbst ist.

### Gemessen

| | vorher | nachher |
|---|---|---|
| 217 Dateien aus dem Befallszeitraum | 184 | **215** |
| frisches WordPress und Joomla | 0 | 0 |
| vier Kundenseiten in Betrieb | 34 | 34 |
| Laufzeit einer Website mit 7.350 Dateien | 71,2 s | 73,6 s |

Und eine Korrektur an der eigenen Messlatte: fünf der 149 „bekannten
Schaddateien" sind gewöhnliche WordPress-Dateien — `IDNAEncoder.php`,
`Restriction.php`, `woocommerce.php` haben zufällig elfstellige Namen. Deshalb
misst die zweite Zahl über den Zeitraum statt über die Namensform.

## [0.5.0] – 2026-09-05

### Neu

- **Vier weitere Verschleierungen erkannt.** Ein zweiter Blick auf denselben
  Befall, diesmal nicht über die Namensform der abgelegten Dateien, sondern über
  den Zeitraum: von allem, was während des Befalls geschrieben wurde, findet der
  Scanner jetzt 200 von 217 statt 184.

  - `php.stream.archive_url` — ein Lader holt seinen Rumpf aus einem Archiv:
    `zip://…zip#…tmp`, mal über `require`, mal über `file_get_contents`. Nur bei
    fest verdrahteter Adresse, denn Roundcube kopiert legitim mit
    `copy("zip://$path#$entry", …)`.
  - `php.include.stream_wrapper` — `require "zip://…"`, `data://`, `php://input`.
    `phar://` bleibt bewusst draußen: ein Phar-Stub tut genau das, und Guzzle
    bringt einen mit.
  - `php.tool.leaf_mailer` — Leaf PHP Mailer in seinen Varianten, die untereinander
    keine Form teilen und deshalb beim Namen genannt werden.
  - Die zweite Sicht löst jetzt **Hex- und Oktal-Escapes** mit auf: `"\x5f\107\x45\x54"`
    ist `_GET`. Und sie überspringt **Kommentare zwischen den Teilen** einer
    Verkettung: `"ra"/*-X8KKH~;-*/."nge"` ergibt `range`.

  - `php.webshell.hardcoded_gate` — eine Kennwortabfrage, deren Vergleichshash
    im Quelltext derselben Datei steht. Eine Shell trägt ihren Schlüssel bei
    sich, ein Plugin schlägt seinen nach.

### Gemessen

Anlass war ein zweiter, gründlicherer Blick auf denselben Befall — über den
Zeitraum statt über die Namensform:

| | vorher | nachher |
|---|---|---|
| 149 bekannte Schaddateien | 144 | 144 |
| 217 Dateien aus dem Befallszeitraum | 184 | **200** |
| frisches WordPress und Joomla | 0 | 0 |
| vier Kundenseiten in Betrieb | 34 | 34 |
| eine Website mit 193.885 PHP-Dateien | 516 | **516** |

Drei Regeln sind während dieser Messung wieder verschwunden, und das ist der
Zweck des Fehlalarm-Korpus:

- `${$var}` als Aufruf ist gewöhnliches PHP; Doctrine, Mailster und BackupBuddy
  benutzen es.
- Eine Adresse in ein Archiv hinein ist für sich harmlos — Roundcube kopiert mit
  `copy("zip://$path#$entry", …)` aus einem hochgeladenen Archiv. Die Regel
  greift nur noch bei fest verdrahteter Adresse.
- Die Türsteher-Regel aufzuweichen, statt eine zweite daneben zu stellen, meldete
  **NinjaFirewall** als Webshell. Ein Sicherheits-Plugin fälschlich als Schadcode
  auszuweisen ist der teuerste Fehlalarm überhaupt; die alte Regel ist deshalb
  unverändert geblieben.

## [0.4.0] – 2026-09-05

### Neu

- **Bessere Erkennung.** An einem echten Befall gemessen: von 149 abgelegten
  Schaddateien fand der Scanner 28, jetzt findet er 144. Frisches WordPress und
  vier Websites im Betrieb melden unverändert dasselbe wie vorher.

  Die Nutzlasten setzten ihre Funktionsnamen aus Bruchstücken zusammen —
  `'base'.'64'.'_dec'.'ode'` —, sodass jede Regel, die `base64_decode`
  ausschreibt, ins Leere lief. Die Maschine liest jede Datei jetzt ein zweites
  Mal mit zusammengesetzten Zeichenketten; damit bekommt der ganze Katalog auf
  einmal seine Sicht zurück. Drei neue Regeln decken den Rest ab:
  `php.eval.variable_call`, `php.silence.preamble` und
  `php.webshell.session_filehash_gate` — Letzteres für Werkzeuge wie Leafmailer,
  die gar nicht verschleiert sind und deshalb durch jedes Raster fielen.

  `tools/detection-score.sh` macht die Messung wiederholbar, `docs/erkennung-messen.md`
  beschreibt sie.

- **Wiederherstellen aus der Oberfläche.** Knopf auf der Website-Seite, mit
  Rückfrage, dazu ein Probelauf. Die Website wird für die Dauer abgeschaltet und
  kommt nur bei sauberem Rückgabecode zurück; danach läuft automatisch eine
  Prüfung, die zeigt, was übrig ist.

- **Einzelne Funde löschen.** Je Fundzeile ein Knopf, dazu „Alle Funde löschen",
  beide mit Rückfrage. Gelöscht wird über die Warteschlange und nur, was als Fund
  dieser Website in der Datenbank steht; das Binary prüft die Pfadgrenze ein
  zweites Mal. Jede Datei wird vorher gesichert. Neuer Befehl `malwatch quarantine`.

- **Fortschritt sichtbar.** Die Website-Seite zeigt Phasen, Element, Datei und
  ein mitlaufendes Protokoll, solange ein Auftrag läuft, und holt sich danach
  selbst zurück. Die Übersicht meldet laufende Aufträge und lädt nach.

### Behoben

- **Prüfungen verschwanden spurlos.** Eine Website bekommt ihre Einstellungszeile
  erst, wenn jemand ihre Einstellungen speichert. Beim Eintragen des Ergebnisses
  stieg das Einlesen ohne diese Zeile kommentarlos aus — 66 gelaufene Prüfungen,
  60-mal „ungeprüft" in der Übersicht. Die Zeile wird jetzt angelegt.
- **Der Knopf „Freigeben" heißt „Kein Befund".** Er ändert nur den Zustand und
  rührt die Datei nicht an; neben einem Schadcode-Fund las sich das alte Wort wie
  Durchwinken.
- **Die Übersicht war unbenutzbar hoch.** Die beiden Knöpfe je Zeile stapelten
  sich, weil ISPConfigs `.buttons`-Hülle für einen Formularfuß gedacht ist, nicht
  für eine Tabellenzelle: rund 34 statt 100 Pixel je Zeile, zwei Spalten weniger,
  und der Zustand färbt die linke Zeilenkante.

### Geändert

- `malwatch_job` kennt `job_kind`; neue Tabellen `malwatch_repair` und
  `malwatch_repair_element`. Schemaänderungen prüfen sich in `information_schema`
  selbst, damit sie auch bestehende Installationen erreichen.

## [0.3.1] – 2026-09-05

### Behoben

- Der Probelauf berichtete im Perfekt: „ersetzt core 5.9.10 (0 Dateien)" für
  etwas, das gerade nicht ersetzt wurde. Ausgerechnet dieser Bericht wird
  gelesen, bevor jemand den Lauf startet, der tatsächlich löscht. `--dry-run`
  schreibt jetzt „würde ersetzen" und „WÜRDE LÖSCHEN" und nennt keine
  Dateizahl, die es noch nicht gibt.

## [0.3.0] – 2026-09-05

### Neu

- **`malwatch repair`** setzt eine WordPress-Installation auf den
  Auslieferungszustand zurück: Kern, sämtliche Plugins und sämtliche Themes
  werden versionsgenau durch die Originale ersetzt, der alte Ordner vorher
  vollständig entfernt. Damit verschwindet auch, was keine Regel getroffen hat —
  eine abgelegte Datei überlebt nur, solange ihr Verzeichnis überlebt. Was ein
  Lauf danach noch meldet, ist per Definition nicht Teil der Software.

  Erst wird alles geholt und geprüft, dann gesichert, dann getauscht. Bis zum
  Tauschen ist keine Datei der Website angefasst: ein abgebrochener Download
  kostet einen Lauf, keine Website. Gesichert wird alles, was angefasst wird,
  als `tar.gz` unter `--backup-dir`.

  Unangetastet bleiben `wp-config.php`, `wp-content/uploads`, alles in
  `wp-content`, was kein Plugin- oder Theme-Ordner ist, und jede fremde Datei im
  Webstamm. Das Letzte ist Absicht: genau diese Reste soll der anschließende
  Lauf zeigen. `wp-content/mu-plugins` wird ausgewiesen, nicht gelöscht.

  Findet sich für ein Element kein Original — ein gekauftes Plugin, ein
  zurückgezogenes Release —, wird der Ordner trotzdem entfernt, mit Name und
  Version im Protokoll und mit Sicherung. Ein 404 der Herstellerquelle ist eine
  Tatsache über das Element; jeder andere Fehlschlag beendet den Lauf, solange
  die Website unberührt ist.

  `--dry-run` spielt alles bis vor den ersten Schreibvorgang durch.

- **Laufender Fortschritt** über `--progress=DATEI`: Phase, Element, Datei,
  Zähler und ein mitlaufendes Protokoll als JSON, geschrieben-dann-umbenannt,
  damit ein Leser nie ein halbes Dokument sieht. Der Scan schreibt dieselbe
  Datei — bisher meldete er „eingeplant" und dann minutenlang nichts.

### Geändert

- Der Scanner schreibt erstmals, und zwar ausschließlich unterhalb von `--path`
  und `--backup-dir`. Ein Pfad, der nach Auflösung aller Symlinks außerhalb
  liegt, führt zum Abbruch statt zum Überspringen — ein Überspringen würde eine
  Manipulation stillschweigend hinnehmen.
- Ein neuer CI-Job legt vier Webshells in echtes WordPress 6.6.2, zwei innerhalb
  von Herstellerverzeichnissen und zwei außerhalb, und verlangt danach: die
  innerhalb sind weg, die außerhalb sind genau das, was der Scan meldet.

### Bekannte Grenzen

- Themes werden nicht gegen Prüfsummen verifiziert — wordpress.org veröffentlicht
  für sie keine. Der Bericht sagt das.
- Der Abgleich der entpackten Archive gegen die Prüfsummenlisten ist noch nicht
  verdrahtet; geholt und entpackt wird, verglichen noch nicht.
- Nur WordPress. Für Joomla, TYPO3 und die übrigen gibt es keine verlässliche
  Quelle für versionsgenaue Archive; sie werden im Bericht benannt.
- Die Bedienung über die ISPConfig-Oberfläche folgt als Teil 2.

## [0.2.10] – 2026-09-05

### Behoben

- Beim Entfernen der Erweiterung blieben alle sieben Tabellen in der Datenbank
  zurück. `run_uninstall_sql()` im Kern trägt denselben Fehler wie sein
  Gegenstück beim Installieren, und `uninstall_extension()` löscht das
  Erweiterungsverzeichnis unmittelbar nach dem Haken — mitsamt der SQL-Datei,
  mit der man hinterher hätte aufräumen können. Der Haken löscht die Tabellen
  jetzt selbst, im letzten Moment, in dem die Datei noch existiert. Scheitert
  das, druckt er die `DROP`-Anweisungen aus, statt sie mit dem Verzeichnis
  verschwinden zu lassen.

### Geändert

- Das Entfernen über die Kommandozeile braucht **root**: das Verwaltungskonto
  steht in `mysql_clientdb.conf`, die nur root lesen darf. Über **System >
  Extensions** im Panel bleiben die Tabellen stehen — dort ist weder das Konto
  noch das Arbeitsverzeichnis erreichbar. Die README sagt das jetzt.
- Der Ladeweg für SQL-Dateien liegt in `install/sql_loader.php`, den sich
  Installation und Entfernen teilen: Verwaltungskonto über eine
  0600-Defaults-Datei, damit das Passwort nie in `ps` auftaucht.
- Das Entfernungs-Schema heißt `install/uninstall-schema.sql`, aus demselben
  Grund wie `schema.sql` in 0.2.8. `manual_install.php` räumt eine
  liegengebliebene `uninstall.sql` mit ab, zwei Prüfungen im Bauablauf halten
  beide alten Namen fern.

## [0.2.9] – 2026-09-05

### Behoben

- Die Umbenennung aus 0.2.8 wirkte nur bei Neuinstallationen. Ein Update
  entpackt das Paket über das vorhandene Verzeichnis, und `unzip` entfernt
  nichts: die alte `install/install.sql` blieb daneben liegen, und der Kern
  fand sie weiter. `manual_install.php` löscht sie jetzt, nachdem das Schema
  aus `schema.sql` gelesen wurde.

## [0.2.8] – 2026-09-05

### Behoben

- Die Installation druckte mitten im Lauf einen SQL-Syntaxfehler und meldete
  danach trotzdem Erfolg. Der Fehler kam aus dem Kern:
  `extension_installer::load_install_sql()` baut seinen Aufruf aus
  `$conf['mysql'][…]`, und diese Schlüssel gibt es nur, solange ISPConfig
  selbst eingerichtet wird. Auf einem laufenden System bleiben sie leer, der
  Aufruf trägt kein Passwort, `mysql` fragt danach, liest die Antwort aus der
  umgeleiteten SQL-Datei und scheitert am Rest. Das Schema heißt deshalb jetzt
  `install/schema.sql`; unter einem Namen, den der Kern nicht sucht, bleibt der
  Aufruf still. Geladen wird es weiterhin von `manual_install.php`, mit dem
  Verwaltungskonto über eine 0600-Datei, damit das Passwort nicht in `ps`
  auftaucht. Eine Prüfung im Bauablauf verhindert die Rückkehr des Namens.

### Entfernt

- Der Aufruf von `load_install_sql()` im `update()`-Haken. Er konnte nie etwas
  laden: das ISPConfig-Konto darf auf `dbispconfig` nur lesen und schreiben,
  keine Tabellen anlegen.

## [0.2.7] – 2026-09-05

### Behoben

- „Jetzt prüfen“, „Alle prüfen“, „Freigeben“ und „Wieder einschalten“ endeten
  in „CSRF-Versuch blockiert“. Das Panel umschließt den ganzen Inhaltsbereich
  bereits mit einem Formular namens `pageForm`; die eigenen Vorlagen haben
  darin ein zweites gleichen Namens geöffnet. Ein Eingabefeld gehört immer zum
  nächstgelegenen Formular-Vorfahren, gesucht und abgeschickt wird aber das
  erste im Dokument — also das äußere. Damit ging die Anfrage zwar raus, aber
  ohne Token und ohne Aktion. Die Vorlagen öffnen jetzt kein eigenes Formular
  mehr, so wie es der Kern in seinen Listenvorlagen auch hält, und das Token
  reist unter den Namen, die `form.tpl.htm` rendert. Der Bauablauf prüft
  beides.
- Der Fehlalarm „weicht von der Auslieferung ab“ auf `wp-config-sample.php`.
  wordpress.org veröffentlicht für diesen Pfad in jeder Sprache nur die
  englische Prüfsumme, während die lokalisierten Archive eine übersetzte Datei
  ausliefern. Auf einer deutschen Installation konnte der Eintrag deshalb nie
  passen. Die Datei bleibt aus dem Kernvergleich heraus; WordPress lädt sie
  ohnehin nicht, und Signaturen und Heuristik lesen sie weiter wie jede andere.

## [0.2.6] – 2026-09-04

### Behoben

- 49 Fehlalarme „weicht von der Auslieferung ab" auf einer einzigen Website.
  Die Prüfsummenliste von WordPress enthält die mitgelieferten Themes, die
  eigenständig aktualisiert werden. Unterhalb von wp-content wird nicht mehr
  verglichen, genau wie es auch wp-cli hält.
- Eine deutsche WordPress-Installation wurde gegen die englischen Prüfsummen
  gehalten. Die Sprachausgabe wird jetzt aus der Installation gelesen.

## [0.2.5] – 2026-09-04

### Behoben

- Die Knöpfe „Jetzt prüfen", „Alle prüfen", „Freigeben" und „Wieder
  einschalten" lösten nichts aus. Das Panel schickt Formulare nur über seine
  eigenen Datenattribute ab; ein gewöhnlicher Absendeknopf erzeugt darin gar
  keine Anfrage. Der Bauablauf prüft das jetzt.

## [0.2.4] – 2026-09-04

### Geändert

- Ein Wiederholungslauf meldete „0 Dateien", weil unveränderte Dateien aus
  dem Zwischenspeicher kommen. Jetzt steht die Gesamtzahl da, dahinter wie
  viele davon neu geprüft und wie viele unverändert waren.

## [0.2.3] – 2026-09-04

### Behoben

- Das Rendertestwerkzeug meldete zwei Seiten fälschlich als fehlerhaft: die
  Seite selbst überschrieb die Schleifenvariable.

## [0.2.2] – 2026-09-04

### Behoben

- Das Prüfwerkzeug tests/render_pages.php lag nicht im Erweiterungspaket und
  war auf dem Server damit nicht vorhanden.

## [0.2.1] – 2026-09-04

### Behoben

- Die Einstellungsseite einer Website ohne gespeicherte Einstellungen zeigte
  ein leeres Formular und rendete es doppelt.
- Beim ersten Speichern blieben Website-Bezug, Server und Gruppe leer, weil
  das Formular nur seine eigenen Felder schreibt. Damit fand der Zeitplan die
  Website nie, und die zweite Website liess sich gar nicht speichern.
- Eine fremde Kennung in der Adresse führte auf der Einstellungsseite zu
  einer Rechtemeldung.

### Neu

- `tests/render_pages.php` rendert alle Seiten gegen eine laufende
  ISPConfig-Installation. Alle drei Fehler oben waren syntaktisch fehlerfrei
  und nur beim Rendern zu sehen.

## [0.2.0] – 2026-09-04

### Geändert

- Funde werden je Datei gruppiert statt je Regel. Eine befallene Datei löst
  oft mehrere Regeln aus und stand bisher mehrfach in der Liste.
- Pfade werden relativ zum geprüften Verzeichnis gezeigt, der Dateiname
  hervorgehoben, der Ordner gedämpft. Der vollständige Pfad steht als
  Tooltip an der Zeile. Lange Pfade brechen um statt aus der Spalte zu
  laufen.
- Über der Fundliste steht, wie viele Dateien betroffen sind.
- Freigeben und Wiederöffnen gelten für die ganze Datei.

## [0.1.3] – 2026-09-04

### Behoben

- Statistikseiten von AWStats, Webalizer und GoAccess werden nicht mehr
  geprüft. Ihre 404-Auswertung listet die Pfade auf, nach denen Angreifer
  suchen, darunter die Namen bekannter Webshells. Auf einer einzigen Website
  erzeugte das 15 Fehlalarme.
- Ein Prüflauf gilt erst als beendet, wenn der Scanner seinen Rückgabecode
  hinterlegt hat. Vorher entschied das Verschwinden der Prozesskennung, was
  davon abhängt, ob sich setsid abspaltet.

## [0.1.2] – 2026-09-04

### Behoben

- Die Installation brach mit einem Fatal ab: die Erweiterung benutzte die
  Konstante LOGLEVEL_INFO, die ISPConfig nicht kennt.
- Die beiden Formularseiten hinterlegten die Formulardefinition nicht, so dass
  sie beim Öffnen abgebrochen wären.

### Neu

- Zwei Prüfskripte im Bauablauf: eines gegen unbekannte Konstanten, eines
  gegen fehlende Formular-, Vorlagen- und Sprachdateien. Beide finden Fehler,
  die eine Syntaxprüfung nicht sehen kann.

## [0.1.1] – 2026-09-04

### Behoben

- Das Extension-Paket wurde beim Release nicht gebaut, weil das Bauskript nicht
  ausführbar eingecheckt war.

## [0.1.0] – 2026-09-04

Erste Fassung.

### Scanner

- Signaturstufe mit den frei verfügbaren Hashes und Bytemustern aus Linux
  Malware Detect, geladen über `malwatch update`.
- Heuristik mit 33 Regeln für PHP, JavaScript, HTML und `.htaccess`.
- Abgleich gegen die offiziellen Prüfsummen von WordPress-Kern und -Plugins.
  Unveränderte Herstellerdateien erzeugen keinen Fehlalarm, veränderte einen
  eigenen Befund.
- Erkennung veralteter Installationen von WordPress samt Plugins und Themes,
  Joomla, Drupal, TYPO3, Contao, Nextcloud, phpMyAdmin, Matomo, MediaWiki,
  Shopware und Magento.
- ClamAV als optionale Zusatzstufe.
- Bericht als Text oder JSON, Versand per sendmail oder SMTP, Rückgabecode
  nach Schwere.
- Zwischenspeicher für bereits geprüfte Dateien. Er verfällt, sobald sich
  Regeln oder Signaturen ändern.
- Freigabeliste über Prüfsummen statt über Pfade.

### ISPConfig-Addon

- Addon nach der Extension-Struktur von ISPConfig 3.3, ohne Änderung an
  Kerndateien.
- Bereich im Modul Websites: Übersicht aller Websites, Detailseite je Website
  mit Funden, erkannter Software, Verlauf und Aktionsprotokoll, Fundliste über
  alle Websites, Verlauf der Prüfläufe, Einstellungen.
- Prüfung von Hand je Website oder für alle auf einmal.
- Zeitplan je Website: täglich, wöchentlich, monatlich.
- Aktionen je Website mit eigener Mindeststufe: Betreiber benachrichtigen,
  Kunde benachrichtigen, Website abschalten. Nur neue Funde lösen aus,
  veraltete Software schaltet nie ab, und ein sauberer Lauf hebt eine Sperre
  nicht von selbst auf.
- Deutsch und Englisch.
