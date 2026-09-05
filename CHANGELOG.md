# Changelog

Alle nennenswerten Änderungen an diesem Projekt.

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
