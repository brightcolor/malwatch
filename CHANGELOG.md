# Changelog

Alle nennenswerten Änderungen an diesem Projekt.

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
