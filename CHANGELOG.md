# Changelog

Alle nennenswerten Änderungen an diesem Projekt.

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
