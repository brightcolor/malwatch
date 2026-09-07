# Security-Bereich im Panel — Entwurf

**Stand:** 7. September 2026
**Entwurf zur Ansicht:** https://claude.ai/code/artifact/48b9f42c-4de1-4ebc-9cb5-429244691f94

## Zweck

Das Addon soll von jemandem bedienbar sein, der morgens wissen will, ob etwas
brennt, und der weder Regelbezeichner noch PHP liest. Heute ist es das nicht:
es sitzt in der Seitenleiste eines fremden Moduls, es reißt den Bediener bei
laufendem Scan alle fünf Sekunden aus jeder Seite heraus, sein
Fortschrittsbalken steht still, und seine Ergebnisliste zeigt als Spalte
`php.obfuscation.chr_arithmetic`.

Dieser Entwurf beschreibt einen eigenen Bereich **Security** in der oberen
Leiste, seine vier Seiten, und die Quarantäne als handelnde Maßnahme —
wahlweise automatisch bei den nächtlichen Läufen.

## Was heute kaputt ist, und warum

Drei der vier Beschwerden haben eine benennbare Ursache. Sie sind hier
festgehalten, damit die Umsetzung sie behebt statt sie zu umgehen.

**Das Zurückspringen.** `interface/templates/malwatch_site_list.htm` ruft bei
laufendem Job alle fünf Sekunden `ISPConfig.loadContent()` auf. Der Abbruch
hängt an `DOMNodeRemoved` — einem Mutation Event, das Chrome seit Version 127
abgeschaltet hat. Der Timer wird also nie gelöscht und zieht den Bediener aus
jeder anderen Seite in die Liste zurück.

**Der stehende Fortschrittsbalken.** `cmd/malwatch/scan.go:141` meldet
`pw.File("", int(n), 0)` — einen Zähler ohne Nenner. Die Zeichenroutine in
`malwatch_site_show.htm` rechnet die Breite aus `elements_done / elements_total`,
beides null, und fällt auf feste 5 % zurück. Zusätzlich zeigt sie die fünf
Phasennamen der *Reparatur*, auch wenn ein Scan läuft.

**Die unverständlichen Ergebnisse.** `report.Finding` trägt nur `Rule`, also die
Kennung. Die verständlichen Beschreibungen stehen im Go-Katalog und erreichen
die Datenbank nie. Die Oberfläche kann deshalb nichts anderes zeigen als den
Bezeichner.

Die vierte Beschwerde — der Ort im Menü — ist eine bewusste Entscheidung von
damals, dokumentiert in `interface/malwatch.menu.php`: ein eigenes Modul hätte
in `sys_user.modules` geschrieben werden müssen. Genau das wird jetzt gemacht.

## Modul statt Seitenleiste

Ein eigenes Modul `security` nach dem Muster des bereits laufenden
`wpinstaller`, das auf demselben Server denselben Weg geht.

    interface/web/security/lib/module.conf.php
        $module['name']      = 'security';
        $module['title']     = 'Security';
        $module['startpage'] = 'security/status.php';
        $module['order']     = '40';
        $module['icon']      = 'icon icon-monitor';

Der Installer trägt `security` in `sys_user.modules` **jedes Benutzers mit
`typ = 'admin'`** ein, der es noch nicht hat; der Deinstaller entfernt es
wieder. Beides idempotent, damit ein zweiter Lauf nichts doppelt schreibt.

Sichtbar ist der Bereich ausschließlich für Administratoren. Reseller und
Endkunden bekommen ihn nicht, und die Seiten brauchen deshalb keine
Mandantentrennung. Jede Seite prüft trotzdem `$app->auth->is_admin()` und
antwortet sonst mit einer leeren Seite — die Modulzugehörigkeit allein ist
keine Rechteprüfung.

`interface/malwatch.menu.php` und sein Eintrag in `install/file.list` entfallen.
Die vorhandenen Seiten ziehen von `sites/` nach `security/` um; alte Links auf
`sites/malwatch_*.php` werden nicht umgeleitet, weil sie nur in der entfernten
Menüdatei standen.

## Die vier Seiten

### Status

Beantwortet eine Frage, statt Daten auszubreiten. Die Überschrift ist ein Satz:
*„Drei Websites brauchen Ihre Aufmerksamkeit."* Darunter stehen **nur** diese
Websites, die dringendste zuerst, je als Zeile mit Klartextzusammenfassung und
zwei Schaltflächen.

Die Sortierung: Websites mit kritischen Funden, dann laufende Prüfungen, dann
Websites mit hohen Funden, dann der Rest. Eine Website, die gerade geprüft wird,
zeigt ihren Fortschrittsbalken direkt in ihrer Zeile.

Die unauffälligen Websites stehen als eine ruhige Zeile darunter — *„58 weitere
Websites sind unauffällig"* — mit einem Link, der sie aufklappt. Sie sind kein
Standardinhalt.

Die Zahl neben „Status" in der Seitenleiste ist die **Anzahl der Websites, die
etwas brauchen**, nicht die Anzahl der Funde. Drei, nicht 403.

### Website im Detail

Kein eigener Punkt in der Seitenleiste — eine einzelne Website ist kein Bereich.
Erreichbar über „Ansehen" auf der Statusseite, mit „← Status" zurück; in der
Leiste bleibt „Status" markiert.

Funde sind nach **Handlung** gruppiert, nicht nach Technik:

| Gruppe | Was hineingehört | Erklärender Satz unter der Überschrift |
|---|---|---|
| Sofort entfernen | Funde, deren Regel im Katalog `Certain: true` trägt | „Diese Dateien gehören zu keinem Plugin und keinem Theme … nichts hängt an ihnen." |
| Ansehen und entscheiden | alles Übrige mit Stufe `critical` oder `high` | „Manche davon gehören zu einem Plugin und dürfen bleiben — deshalb fasst hier niemand automatisch etwas an." |
| Nur zur Kenntnis | Stufe `medium` und `low` | „Sie können nichts mehr anrichten, sollten aber irgendwann verschwinden." |

Jeder Fund beginnt mit einem Satz in Klartext. Die Regelkennung, der Auszug aus
der Datei, Größe und Änderungsdatum liegen hinter einem zugeklappten
**„Woran erkannt?"**.

### Quarantäne

Zeigt, was herausgenommen wurde: Datei, Website, Grund im Klartext, Zeitpunkt,
und ob automatisch oder von Hand. Je Zeile ein **„Zurückholen"**.

Auf der Seite steht ausdrücklich, dass nichts gelöscht wird und wo die Dateien
liegen. Wer eine Automatik einschaltet, muss wissen, wohin sie greift.

### Prüfläufe

Wann, welcher Umfang, wie lange, wie viele Dateien, was dabei herauskam.
Unverändert in der Sache, nur in der Sprache angeglichen.

### Einstellungen

Die Frage lautet: **„Was soll bei den nächtlichen Prüfungen automatisch
passieren?"** Vier Antworten, siehe unten.

## Sprache

Verbindlich für alle Beschriftungen, Meldungen und E-Mails:

- Keine Regelbezeichner in der Oberfläche. `php.include.decoy_guard` heißt
  „Einbindung hinter einer Schein-Abfrage" und steht nur unter „Woran erkannt?".
- Keine Wörter aus dem Bau: kein *Preset*, keine *Freigabeliste*, kein
  *Datensatz*, kein *Job*.
- Schaltflächen sagen, was geschieht: **In Quarantäne**, **Zurückholen**,
  **Unbedenklich**, **Alles entfernen**. Nicht *Freigeben* — das hat schon
  einmal niemand verstanden.
- Zahlen mit deutscher Tausendertrennung, Datumsangaben ausgeschrieben
  („6. September"), Uhrzeiten mit „Uhr“.
- Eine Meldung nennt die Folge, nicht den Vorgang: „51 Dateien liegen in
  Quarantäne", nicht „Quarantäne-Tabelle enthält 51 Einträge".

## Farben und Form

Jede Farbe kommt aus den Theme-Variablen des Panels, mit Rückfallwert:

    color: var(--cic-text, #bac3ca);
    border-left: 3px solid var(--cic-bad, #d13f22);

Verwendet werden ausschließlich die vorhandenen Namen: `--cic-page`,
`--cic-surface`, `--cic-head`, `--cic-raised`, `--cic-hover`, `--cic-sunken`,
`--cic-line`, `--cic-line-soft`, `--cic-line-loud`, `--cic-text`,
`--cic-text-loud`, `--cic-text-dim`, `--cic-accent`, `--cic-accent-text`,
`--cic-accent-deep`, `--cic-on-accent`, `--cic-ok`, `--cic-ok-text`,
`--cic-warn`, `--cic-warn-lift`, `--cic-bad`, `--cic-bad-text`,
`--cic-bad-deep`, `--cic-move`.

Zwei Dinge sind dabei zu beachten:

- **`--cic-accent` und `--cic-warn` sind fast dieselbe Farbe** (`#dd630d` gegen
  `#de7313`). Für den Warnzustand wird deshalb `--cic-warn-lift` benutzt, der
  hellere Ton; der Akzent bleibt den Schaltflächen. Zustand und Bedienbarkeit
  müssen auf einen Blick unterscheidbar sein.
- **Nicht alle Bediener sitzen auf cicada.** Auf diesem Server sind auch
  `default` und `ispc-clean` in Gebrauch, die diese Variablen nicht kennen.
  Deshalb sitzen die Seiten auf den Bootstrap-Klassen des Panels auf
  (`.panel`, `.table`, `.btn`, `.progress`, `.label`), und die Variablen legen
  nur nach, was das Theme anbietet. Eine Seite darf nie eine eigene Farbinsel
  sein.

Der Radius im Theme ist durchgehend **3px**. Keine abgerundeten Kacheln.

## Fortschritt

**Im Go-Teil.** `malwatch scan` lernt `--expect=N`: die erwartete Anzahl
Dateien. Ist sie gesetzt, meldet der Fortschritt `files_done` **und**
`files_total`, sonst wie bisher nur den Zähler.

**Im Runner.** `malwatch_runner.inc.php` liest vor dem Start die
`files_scanned` des jüngsten abgeschlossenen Laufs derselben Website aus
`malwatch_scan` und reicht sie als `--expect` durch. Gibt es keinen, entfällt
der Schalter.

**In der Oberfläche.** Mit Nenner ein echter Balken mit Prozentzahl und
Restschätzung; ohne Nenner ein laufender Zähler ohne Prozent — „71.240 Dateien
geprüft" — und ein Balken im unbestimmten Zustand. Der Balken erscheint auf der
Statusseite in der Zeile der Website und auf deren Detailseite.

Der Erwartungswert ist eine Schätzung und kann danebenliegen: eine Website
wächst zwischen zwei Läufen. Die Anzeige wird deshalb bei **99 % gedeckelt**,
solange der Job läuft, und springt erst auf 100 %, wenn er `done` meldet. Ein
Balken, der bei 140 % steht, ist schlimmer als einer ohne Prozentzahl.

Die Phasennamen richten sich nach der Art des Jobs: ein Scan zeigt keine
Reparaturphasen.

## Kein Neuladen mehr

`ISPConfig.loadContent()` im Takt entfällt ersatzlos. Stattdessen fragt ein
JSON-Endpunkt `security/progress.php` den Stand ab und die Seite schreibt nur
die betroffenen Zellen um: Balken, Zähler, Zustandsschild.

Der Abbruch hängt an einem `MutationObserver` auf `#pageContent`, nicht an
`DOMNodeRemoved`. Zusätzlich prüft jeder Durchlauf `document.contains(el)` und
bricht ab, wenn das Element fort ist. Selbst ein übrig gebliebener Timer kann
dann nur noch ins Leere schreiben und niemanden mehr aus seiner Seite reißen.

Der Takt ist 3 Sekunden, solange ein Job läuft, und hört auf, sobald der Stand
`done` oder `failed` meldet.

## Verständliche Funde

Der Regelkatalog in Go bekommt zu jeder Regel drei Felder:

    // Explain sagt in zwei Sätzen, was gefunden wurde - für jemanden, der
    // weder PHP noch den Regelbezeichner liest.
    Explain string
    // Action sagt, was zu tun ist, und warum das gefahrlos ist.
    Action  string
    // Certain trägt nur, wessen Fund nichts zu entscheiden lässt: gemessen
    // gegen ein frisches WordPress, ein frisches Joomla, drei Kundensites und
    // 193.888 Dateien einer vierten ohne einen einzigen Fehlalarm. Es steuert
    // die Gruppe "Sofort entfernen" und erzeugt die mitgelieferte
    // Zusammenstellung gleichen Namens.
    Certain bool

`Certain` ist bewusst eine Eigenschaft der Regel und nicht die
Zusammenstellung aus der Datenbank. Wer seine Automatik ändert, soll damit
nicht unbemerkt umsortieren, wie die Funde auf der Seite gruppiert sind.

Ein neuer Befehl `malwatch rules --json` gibt den Katalog aus: Kennung, Stufe,
Kurzbeschreibung, `Explain`, `Action`, `Certain`. Das Ergebnis wird als
`interface/web/security/lib/rules.inc.php` abgelegt — einmal beim Installieren
und danach bei jedem nächtlichen Lauf, bevor der erste Scan startet.

Damit ist Go die einzige Quelle. Kommt eine Regel hinzu, braucht die Oberfläche
keine Datenbankwanderung — die Datei wird beim nächsten Lauf neu geschrieben.
Fehlt zu einer Kennung ein Eintrag, zeigt die Oberfläche die Kurzbeschreibung
aus der Datenbank und darunter die Kennung; sie bleibt also lesbar, auch wenn
Binär und Addon einmal auseinanderlaufen.

Alle 48 vorhandenen Regeln bekommen `Explain` und `Action` geschrieben. Das ist
Fließarbeit, aber es ist der eigentliche Inhalt dieses Umbaus.

## Quarantäne

### Datenbank

    CREATE TABLE malwatch_quarantine (
      quarantine_id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
      sys_userid      INT UNSIGNED NOT NULL DEFAULT 0,
      sys_groupid     INT UNSIGNED NOT NULL DEFAULT 0,
      sys_perm_user   VARCHAR(5) NOT NULL DEFAULT 'riud',
      sys_perm_group  VARCHAR(5) NOT NULL DEFAULT 'riud',
      sys_perm_other  VARCHAR(5) NOT NULL DEFAULT '',
      server_id       INT UNSIGNED NOT NULL DEFAULT 0,
      parent_domain_id INT UNSIGNED NOT NULL DEFAULT 0,
      domain          VARCHAR(255) NOT NULL DEFAULT '',
      file_path       VARCHAR(1024) NOT NULL DEFAULT '',
      file_sha256     VARCHAR(64) NOT NULL DEFAULT '',
      file_size       BIGINT UNSIGNED NOT NULL DEFAULT 0,
      rule_id         VARCHAR(128) NOT NULL DEFAULT '',
      severity        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'high',
      stored_path     VARCHAR(1024) NOT NULL DEFAULT '',
      moved_by        ENUM('auto','operator') NOT NULL DEFAULT 'operator',
      moved_at        DATETIME DEFAULT NULL,
      restored_at     DATETIME DEFAULT NULL,
      PRIMARY KEY (quarantine_id),
      KEY parent_domain_id (parent_domain_id),
      KEY moved_at (moved_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

`stored_path` ist der Ort unter `/var/lib/malwatch/quarantine/`. `restored_at`
gesetzt heißt zurückgeholt; die Zeile bleibt als Protokoll stehen.

### Ablauf

Verschieben nutzt den vorhandenen Befehl `malwatch quarantine --path
--backup-dir --file=…`, der vor dem Verschieben sichert. Die Oberfläche stellt
einen Job in `malwatch_job`, der Runner führt ihn aus, der Ingest schreibt die
Zeilen.

Zurückholen braucht einen neuen Befehl `malwatch restore --backup-dir
--file=<stored_path> --to=<file_path>`. Er legt die Datei an ihren
ursprünglichen Ort zurück, mit Eigentümer, Gruppe und Rechten aus der Sicherung,
und verweigert die Arbeit, wenn dort inzwischen etwas anderes liegt.

Die Prüfung aus `internal/repair/safety.go` — `InsideRoot` mit vollständiger
Symlink-Auflösung — gilt für beide Richtungen. Ein Pfad, der den Webstamm
verlässt, wird abgelehnt, nicht übersprungen.

## Automatik mit benannten Zusammenstellungen

### Datenbank

    CREATE TABLE malwatch_ruleset (
      ruleset_id   INT UNSIGNED NOT NULL AUTO_INCREMENT,
      name         VARCHAR(128) NOT NULL DEFAULT '',
      rules        TEXT NOT NULL,          -- eine Regelkennung je Zeile
      is_builtin   ENUM('y','n') NOT NULL DEFAULT 'n',
      PRIMARY KEY (ruleset_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

`malwatch_config` bekommt `auto_quarantine_ruleset_id INT UNSIGNED NOT NULL
DEFAULT 0`. Null heißt: nichts anfassen.

### Mitgeliefert

Drei Zusammenstellungen mit `is_builtin = 'y'`. Sie sind änderbar; wer sie
ändert, bekommt eine Kopie mit `is_builtin = 'n'`, damit ein Update das
Original zurückschreiben kann, ohne die eigene Auswahl zu zerstören.

1. **Nichts anfassen** — leer, Voreinstellung.
2. **Eindeutige Schädlinge entfernen** — die Regeln, die gegen ein frisches
   WordPress, ein frisches Joomla, drei Kundensites und 193.888 Dateien einer
   vierten null Funde erzeugt haben: `php.eval.request`, `php.eval.encoded`,
   `php.eval.hexname`, `php.eval.variable_call`, `php.callback.request`,
   `php.dynamic.request_call`, `php.preg_replace.eval`, `php.webshell.known`,
   `php.include.decoy_guard`, `php.obfuscation.chr_arithmetic`,
   `php.obfuscation.name_in_variable`, `php.obfuscation.xor_literal`,
   `php.obfuscation.substr_of_nothing`.
3. **Alles Kritische entfernen** — jede Regel mit Stufe `critical`, beim
   Schreiben der Datei aus dem Katalog erzeugt.

### Eigene

Die Einstellungsseite zeigt alle 48 Regeln mit ihrer verständlichen
Bezeichnung, ihrer Stufe und der Anzahl offener Funde, jede mit einem
Kästchen. Ein Namensfeld und „Speichern" legen die Zusammenstellung an. Sie
erscheint danach als vierte Wahlmöglichkeit mit ihrem Namen daneben.

### Der nächtliche Lauf

Nach jedem geplanten Scan verschiebt der Runner die Funde, deren `rule_id` in
der gewählten Zusammenstellung steht, und deren `finding_state` `open` ist.
Nicht verschoben wird, was ein Bediener als „Unbedenklich" markiert hat.

Danach geht eine E-Mail an `admin_mail` mit der Liste: Website, Datei, Grund im
Klartext, und der Hinweis, wie man zurückholt. Wurde nichts verschoben, geht
keine E-Mail.

Ein Fehler beim Verschieben einer Datei bricht den Lauf nicht ab; er wird
protokolliert und die Datei bleibt liegen.

## Reihenfolge der Auslieferung

Drei Stufen, jede für sich nützlich und einzeln auslieferbar.

**Stufe 1 — Bedienbarkeit.** Modul `security`, Umzug der Seiten, Statusseite,
Wegfall des Neuladens, Fortschritt mit Nenner (`--expect`, Runner, Anzeige).
Danach lässt sich das Addon benutzen, während ein Scan läuft.

**Stufe 2 — Verständlichkeit.** `Explain` und `Action` für alle 48 Regeln,
`malwatch rules --json`, die erzeugte `rules.inc.php`, die neue Detailseite mit
den drei Handlungsgruppen.

**Stufe 3 — Handeln.** Quarantäne-Tabelle, Seite, `malwatch restore`,
Mehrfachauswahl in den Funden, Zusammenstellungen und die nächtliche Automatik.

## Prüfen

- **`tests/check_wiring.sh`** wächst um: `module.conf.php` vorhanden und
  syntaktisch gültig; kein `DOMNodeRemoved` mehr im Baum; kein
  `loadContent` in einem Timer; jede Regel im Katalog hat `Explain` und
  `Action`; jede in einer mitgelieferten Zusammenstellung genannte Kennung
  existiert im Katalog.
- **Go:** `--expect` verändert den Fortschritt und sonst nichts — gleiche
  Funde mit und ohne. `malwatch restore` legt Eigentümer, Gruppe und Rechte
  wieder her und verweigert einen belegten Zielpfad. `malwatch rules --json`
  gibt alle Regeln aus.
- **Am lebenden Objekt:** Modul erscheint für den Admin und für sonst
  niemanden; ein laufender Scan lässt sich verlassen, ohne zurückgezogen zu
  werden; der Balken bewegt sich; eine Datei lässt sich verschieben und
  zurückholen, und die Website läuft danach wieder.
- **Deinstallation** entfernt `security` aus `sys_user.modules` und lässt die
  Quarantäne stehen — dort liegen Dateien, die noch gebraucht werden könnten.

## Ausdrücklich nicht Teil davon

- Reseller- und Kundenzugang. Der Bereich ist für Administratoren.
- Automatisches Löschen. Quarantäne verschiebt, sie löscht nie.
- Die Reparatur (`malwatch repair`) bleibt, wie sie ist; sie bekommt nur die
  neue Fortschrittsanzeige mit.
- Die drei offenen Betriebsthemen aus dieser Woche — offen liegende
  Datenbankabzüge, wirkungslose `.htaccess`, die Funde auf torrios.de — sind
  Aufgaben am Server, nicht an dieser Oberfläche.
