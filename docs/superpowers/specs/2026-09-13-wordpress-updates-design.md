# malwatch — WordPress-Updates aus dem Panel

Stand: 13.09.2026

## Zweck

Die Schwachstellen-Übersicht nennt je Installation die bekannten Lücken und die
Version, die sie schließt. Mit dieser Stufe spielt der Betreiber das Update
direkt aus dem Panel ein: für den WordPress-Kern und für Plugins und Themes, die
wordpress.org führt.

Ein Update geht den Weg der Reparatur: Archiv holen, prüfen, den alten Stand in
die Quarantäne legen, tauschen. Neu sind vier Teile:

1. die Zielversion, wählbar je Element
2. die Prüfung der Anforderungen an WordPress- und PHP-Version
3. Export und Anhebung der Datenbank über WP-CLI, wenn ein Kern-Update sie
   verlangt
4. die Nachprüfung der Website mit automatischem Zurückholen und Meldung

## Entscheidungen

| Frage | Entscheidung |
|---|---|
| Umfang | WordPress-Kern, Plugins und Themes mit Archiv bei wordpress.org |
| Zielversion | wählbar je Element: „neueste passende" vorausgewählt, daneben „kleinste, die alle Lücken schließt" |
| Ausführung | Dateien über den Reparaturweg, WP-CLI als Benutzer der Website allein für die Datenbank |
| Fehlerfall | automatisch zurückholen und melden |
| Meldung | an den Betreiber bei Zurückholen oder Fehler, an den Kunden zusätzlich bei eingeschaltetem „Kunde benachrichtigen" |

## Teil 1 — der Befehl

```
malwatch update --path=/var/www/clients/client3/web12/web \
                --plan=/var/lib/malwatch/state/runs/job-41.plan.json \
                --run-as=web12:client3 \
                --php=/usr/bin/php8.2 \
                --wp-cli=/usr/local/bin/wp \
                --connect=127.0.0.1 \
                --quarantine-dir=/var/lib/malwatch/state/quarantine \
                --domain=beispiel.de \
                --progress=/var/lib/malwatch/state/runs/job-41.progress \
                --json --out=/var/lib/malwatch/state/runs/job-41.json
```

| Schalter | Bedeutung |
|---|---|
| `--path` | Webstamm der Website. Liegt eine Installation aus dem Plan außerhalb, bricht der Lauf ab |
| `--plan` | JSON-Datei mit Installationen, Adressen und Elementen samt Zielversion |
| `--run-as` | Benutzer und Gruppe der Website. WP-CLI läuft unter ihnen; `root` und UID 0 werden abgewiesen |
| `--php` | PHP-Binary der Website |
| `--wp-cli` | Pfad zu WP-CLI. Fehlt die Datei, lehnt der Lauf jedes Kern-Update ab, das die Datenbank anheben müsste |
| `--connect` | Ziel der Nachprüfung als `host` oder `host:port`: die IP des Vhosts, bei `*` 127.0.0.1 |
| `--quarantine-dir`, `--domain`, `--progress`, `--json`, `--out`, `--dry-run` | wie bei `repair` |

Der Plan:

```json
{ "schema": 1,
  "installs": [
    { "path": "/var/www/clients/client3/web12/web",
      "url": "https://beispiel.de/",
      "elements": [
        { "kind": "core", "version": "6.4.5" },
        { "kind": "plugin", "slug": "elementor", "version": "3.25.1" } ] },
    { "path": "/var/www/clients/client3/web12/web/blog",
      "url": "https://beispiel.de/blog/",
      "elements": [
        { "kind": "plugin", "slug": "akismet", "version": "5.3.1" } ] } ] }
```

Eine Website trägt oft mehrere Installationen, jede mit eigener Adresse; eine
Datei hält das übersichtlich. Der Runner schreibt sie mit Rechten 0600 neben die
Fortschrittsdatei.

### Die Phasen

| | Phase | Was passiert | Website berührt |
|---|---|---|---|
| 1 | Erkennen | Plan lesen und prüfen, installierte Versionen lesen, PHP-Version abfragen | nein |
| 2 | Holen | Archive aller Zielversionen in das Bereitstellungsverzeichnis | nein |
| 3 | Prüfen | Prüfsummen, Anforderungen, Ausgangsstand der Seiten | nein |
| 4 | Aktualisieren | je Element: sichern, tauschen, Datenbank, nachprüfen, bei Bedarf zurückholen | **ja** |

Der Schnitt liegt wie bei der Reparatur vor der Phase, die schreibt. Ein
abgebrochener Download, ein Serverfehler oder eine falsche Prüfsumme beenden den
Lauf, und die Website bleibt, wie sie war. Antwortet wordpress.org auf eine
Zielversion mit 404, ist sie unveröffentlicht: das Element wird abgelehnt, die
übrigen laufen weiter.

`--dry-run` hält nach Phase 3 an. Der Bericht nennt dann je Element, ob es
aktualisiert würde, und den Ausgangsstand der Seiten.

### Reihenfolge

Je Installation zuerst der Kern, dann Plugins, dann Themes, innerhalb einer Art
nach Slug. Phase 3 prüft die Anforderungen eines Plugins gegen die Kern-Version,
die nach dem geplanten Kern-Update gilt. Wird das Kern-Update in Phase 4
abgelehnt oder zurückgeholt, prüft Phase 4 jedes folgende Element erneut gegen
die tatsächlich installierte Version.

### Anforderungen

| Element | Quelle im Archiv | Geprüft gegen |
|---|---|---|
| Kern | `wp-includes/version.php`: `$required_php_version` | PHP-Version der Website |
| Plugin | Kopf der Hauptdatei: `Requires at least`, `Requires PHP`; fehlt ein Wert dort, `readme.txt` | WordPress-Version der Installation, PHP-Version der Website |
| Theme | `style.css`: `Requires at least`, `Requires PHP` | wie beim Plugin |

Die PHP-Version liefert `<php> -r 'echo PHP_VERSION;'`; dabei läuft kein Code der
Website. Abgelehnt wird ein Element außerdem, wenn

- die Zielversion gleich oder niedriger ist als die installierte,
- die Installation eine `.maintenance` trägt, die jünger als zehn Minuten ist:
  dann aktualisiert WordPress gerade selbst,
- `wp-config.php` Multisite einschaltet.

Abgelehnt heißt: Grund im Bericht, Website unberührt, der Lauf geht mit dem
nächsten Element weiter.

### Aktualisieren, je Element

1. **Datenbank sichern.** Allein beim Kern und nur, wenn sich `$wp_db_version`
   zwischen alter und neuer `version.php` unterscheidet: `wp db export -` unter
   `--run-as` mit `--php`. malwatch schreibt die Ausgabe mit Rechten 0600 als
   eigenen Eintrag in die Quarantäne. Scheitert der Export, wird das Element
   abgelehnt, bevor sich eine Datei ändert.
2. **Wartungsmodus.** `.maintenance` mit `<?php $upgrading = <Zeitstempel>; ?>`
   im Stamm der Installation. WordPress antwortet währenddessen mit 503.
3. **Sichern und tauschen.** Der alte Ordner kommt als Eintrag in die Quarantäne
   wie bei `repair --mode=replace`, beim Kern `wp-admin`, `wp-includes` und die
   geänderten Dateien im Stammverzeichnis. Der neue Baum übernimmt Eigentümer,
   Gruppe und Modus des alten (`repair.Swap`, `repair.SwapCore`).
4. **Datenbank anheben.** Nach Schritt 1: `wp core update-db --skip-plugins
   --skip-themes` unter `--run-as` mit `--php`. WP-CLI lädt dabei die mu-plugins
   der Installation mit.
5. **Wartungsmodus aus.** `.maintenance` wird entfernt, auf jedem Weg aus diesem
   Element heraus, auch bei Fehler und Zurückholen.
6. **Nachprüfen.** Scheitert die Nachprüfung, holt malwatch zurück.

### Nachprüfung

Geprüft werden die Startseite (`url`) und die Anmeldeseite (`url` +
`wp-login.php`). malwatch verbindet sich mit `--connect`, auf Port 443 oder 80
je nach Adresse, und schickt den Namen der Website als Host und SNI. Das
Zertifikat bleibt ungeprüft: bewertet wird allein die Antwort der Website.
Weiterleitungen folgt die Prüfung bis zu fünfmal, solange sie auf denselben
Namen oder dessen `www`-Variante zeigen; eine Weiterleitung anderswohin zählt
als Antwort. Jede Anfrage hat 20 Sekunden.

Den Ausgangsstand nimmt Phase 3 auf. Nach jedem aktualisierten Element gilt das
Ergebnis seiner Nachprüfung als neuer Ausgangsstand.

Eine Seite gilt als kaputt, wenn sie im Ausgangsstand mit einem Status unter 500
antwortete und jetzt

- mit 500 oder höher antwortet,
- in den 20 Sekunden ohne Antwort bleibt oder
- mit 200 und leerem Inhalt antwortet, wo vorher Inhalt kam.

WordPress sendet seine Seite „kritischer Fehler" mit Status 500; ein
unterdrückter PHP-Fehler zeigt sich als leere Seite. Antwortete eine Seite schon
im Ausgangsstand mit 500 oder höher, bleibt ihre Nachprüfung ohne Aussage. Der
Bericht vermerkt das, und über das Zurückholen entscheidet die andere Seite.

### Zurückholen

1. Der neue Baum wird entfernt, die Quarantäne-Einträge des Elements kommen an
   ihren Ort zurück (`quarantine.Restore` mit `force`).
2. Gibt es einen Datenbank-Export: `wp db import -` unter `--run-as` mit dem
   Export.
3. Beide Seiten werden erneut geprüft.

Antworten sie wie im Ausgangsstand, heißt der Ausgang `rolled_back`, mit dem
Grund aus der Nachprüfung. Bleibt die Website kaputt, heißt er
`rollback_failed`: Der Lauf hält an, die übrigen Elemente tragen `skipped`, und
die Meldung sagt, dass die Website Hilfe braucht.

Was ein Besucher zwischen dem Ende des Wartungsmodus und dem Import in die
Datenbank schreibt, geht beim Import verloren. Der Import geschieht allein bei
einer kaputten Website.

### Ausgänge je Element

| Ausgang | Bedeutung |
|---|---|
| `updated` | aktualisiert und nachgeprüft |
| `refused` | abgelehnt vor dem ersten Schreibvorgang, Grund im Bericht |
| `rolled_back` | Nachprüfung gescheitert, alter Stand zurück und nachgeprüft |
| `failed` | Fehler beim Tauschen oder in der Datenbank, alter Stand zurück und nachgeprüft |
| `rollback_failed` | alter Stand zurück, die Website bleibt kaputt; der Lauf hält an |
| `skipped` | nach `rollback_failed` oder einem Fehler des Laufs unbegonnen |

Rückgabecode 0, wenn jedes Element `updated` trägt oder der Probelauf nichts
einzuwenden hat. 2, wenn ein Element `refused`, `rolled_back` oder `failed`
trägt. 1 bei `rollback_failed` oder einem Fehler des Laufs.

### Bericht

`report.Update` nach dem Muster von `report.Repair`: `schema`,
`malwatch_version`, `started_at`, `finished_at`, `root`, `dry_run`,
`php_version`, `installs`, `log`, `errors`. Je Element `kind`, `slug`, `path`,
`from`, `to`, `outcome`, `message`, `quarantine_ids`, `db_export_id` und
`checks` mit dem Status vorher und nachher je Seite.

### Fortschritt

Dieselbe Datei wie bei Scan und Reparatur: `kind: "update"`, `phase_total: 4`,
`element` mit `kind`, `slug`, `from` und `to`, dazu ein Zustand je Element:
wartet, holt, geprüft, abgelehnt, getauscht, Datenbank, nachgeprüft,
zurückgeholt.

### Die Grenze

Wie bei der Reparatur schreibt malwatch allein unterhalb von `--path`,
`--quarantine-dir` und dem Bereitstellungsverzeichnis. Ein Pfad, der nach
Auflösung aller Symlinks außerhalb liegt, beendet den Lauf. Dazu:

- WP-CLI läuft unter `--run-as`, nie als root.
- Der Datenbank-Export liegt allein in der Quarantäne, mit Rechten 0600.
- Slugs und Versionen aus dem Plan durchlaufen dieselbe Prüfung wie Werte von
  der Platte (`vendorfiles.safe`).

## Teil 2 — Angaben für die Zielversionen

Damit das Panel die neueste passende Version anbieten kann, trägt der Bericht
jedes Scans und Abgleichs mehr:

| Feld | Quelle |
|---|---|
| `Software.latest_requires_wp` | `requires` aus der Plugin- oder Theme-API von wordpress.org |
| `Software.latest_requires_php` | `requires_php` aus derselben Antwort; beim Kern `php_version` der Versionsabfrage |
| `Software.latest_in_branch` | beim Kern die höchste Version des installierten Zweigs aus `stable-check` |
| `php_version` | Ausgabe von `--php`, das der Runner künftig jedem Scan und Abgleich mitgibt |

Das Addon speichert die drei Software-Felder in gleichnamigen Spalten von
`malwatch_software` und die PHP-Version in `malwatch_site.php_version`.

## Teil 3 — das Addon

### Seite „Updates"

`malwatch_update_start.php?id=<domain_id>`, gebaut wie
`malwatch_repair_start.php`. `&software_id=<id>` wählt ein Element vor.

- Je WordPress-Installation ein Block, Installationen mit Lücken zuerst,
  höchstens 50 Blöcke; darunter ein Hinweis mit der Zahl der übrigen.
- Je Element mit neuerer Version bei wordpress.org eine Zeile: Auswahlkästchen,
  installierte Version, Auswahl der Zielversion, Hinweis.
- Elemente mit bekannten Lücken sind vorausgewählt. Veraltete Elemente ohne
  bekannte Lücken stehen darunter und sind abgewählt.
- Elemente, die wordpress.org nicht führt (`version_unknown = 'y'`), stehen
  ausgegraut mit „nur von Hand: nicht bei wordpress.org".
- Unten „Probelauf" und „Updates starten". Die Rückfrage vor dem Start nennt die
  Zahl der Elemente, die Quarantäne, den Wartungsmodus und das automatische
  Zurückholen.

Zielversionen je Zeile:

| Angebot | Plugin, Theme | Kern |
|---|---|---|
| neueste passende | `latest_version`, wenn die Website `latest_requires_wp` und `latest_requires_php` erfüllt | `latest_in_branch` |
| kleinste, die alle Lücken schließt | `vuln_fixed_in` | `vuln_fixed_in` |

- Fallen beide auf dieselbe Version, steht eine.
- Erfüllt die Website die Anforderungen der neuesten Version nicht, nennt die
  Zeile den Grund („3.25.1 braucht PHP 8.1, die Website läuft mit 7.4"), und die
  kleinste Version ist vorausgewählt. Deren Anforderungen prüft der Scanner in
  Phase 3.
- Jede Angabe sagt, ob sie alle bekannten Lücken schließt, gerechnet aus
  `vuln_fixed_in` und `vuln_nofix`: „schließt alle 7 Lücken", „schließt 5 von 7,
  für 2 gibt es keine Korrektur", „behoben erst ab 6.5.2".

Beim Einreihen rechnet die Seite die Angebote neu und nimmt allein Versionen
an, die sie selbst angeboten hat.

### Wege zur Seite

- Seite der Website: Knopf „Updates" über der Software-Tabelle und
  „Aktualisieren" in jeder Zeile mit Update bei wordpress.org
- Schwachstellen-Übersicht: Verweis „Updates" je Website neben dem Weg zur Seite
  der Website

### Auftrag

- `malwatch_job.job_kind` bekommt `update`. `options` trägt Software-IDs mit
  Zielversion und `dry_run`; Pfade kommen allein aus der Datenbank.
- Für eine Website läuft ein Auftrag zur selben Zeit, wie bei allen Arten. Ein
  wartender Abgleich weicht dem Update, wie er einem Scan weicht.
- Der Runner löst die Software-IDs zu Installationen auf, schreibt die
  Plandatei und setzt:
  - `--run-as` aus `web_domain.system_user` und `web_domain.system_group`
  - `--php` aus `server_php.php_fastcgi_binary`, mit `php-cgi` zu `php`
    umgeschrieben, bei `server_php_id = 0` `/usr/bin/php`. Fehlt die Datei,
    endet der Auftrag mit Fehler, bevor der Scanner startet
  - `--wp-cli` aus der neuen Einstellung `wp_cli_path`, Vorgabe
    `/usr/local/bin/wp`
  - `--connect` aus `web_domain.ip_address`, bei `*` oder leer `127.0.0.1`
  - je Installation die Adresse: `https://` bei `ssl = 'y'`, sonst `http://`,
    dann Domain und Pfad der Installation relativ zum Webstamm

### Einlesen

`malwatch_ingest::ingest_update`:

1. `malwatch_update` (ein Lauf) und `malwatch_update_element` (je Element) nach
   dem Muster der Reparatur-Tabellen, mit `from_version`, `to_version`,
   `outcome`, `message` und `quarantine_ids`.
2. Für `updated`: `malwatch_software.installed_version` auf die Zielversion.
3. Den Quarantäne-Index abgleichen wie nach einer Reparatur.
4. Einen Abgleich für die Website einreihen, damit Lücken und Zustand stimmen.
5. Meldungen auslösen.

### Meldung

Trägt ein Element `rolled_back`, `failed` oder `rollback_failed`, oder endet der
Lauf mit Fehler:

- Mail an `admin_email` aus den Einstellungen
- Mail an die Kundenadresse, wenn für die Website `notify_client = 'y'` gilt
- je Mail ein Eintrag in `malwatch_action_log` wie bei Funden

Die Mail nennt Website, Installation, Element, Versionen, Ausgang und Grund. Bei
`rollback_failed` steht oben, dass die Website Hilfe braucht. Vorlage
`malwatch_update_notification` in Deutsch und Englisch, nach dem Muster von
`malwatch_notification`.

### Seite der Website

- Der Fortschritt eines laufenden Updates erscheint wie bei der Reparatur, mit
  den vier Phasen und einer Zeile je Element.
- Ein Abschnitt „Updates" zeigt die letzten zehn Läufe: Zeitpunkt, Probelauf
  oder echter Lauf, je Element Versionen und Ausgang.

### Schema

Selbstprüfende Änderungen wie bisher:

- `malwatch_job.job_kind` um `update`
- `malwatch_software` um `latest_requires_wp`, `latest_requires_php`,
  `latest_in_branch`
- `malwatch_site` um `php_version`
- `malwatch_config` um `wp_cli_path`
- neue Tabellen `malwatch_update` und `malwatch_update_element`

## Was diese Stufe ausklammert

- Updates ohne Klick, etwa nachts nach dem Abgleich
- Joomla, Drupal, TYPO3 und die übrigen CMS
- WordPress-Multisite: der Befehl lehnt eine solche Installation ab
- Datenbank-Anpassungen einzelner Plugins wie WooCommerce: die startet das
  Plugin selbst oder zeigt einen Hinweis im Dashboard
- Sprachpakete: die holt WordPress über seine automatischen
  Übersetzungs-Updates
- die MySQL-Anforderung des Kerns
- Zurückholen per Klick aus dem Verlauf: das geht über die Quarantäne, wie nach
  einer Reparatur
- mehrere Server

## Prüfung

Scanner:

| | Was geprüft wird |
|---|---|
| 1 | Die Seite antwortet vorher mit 200, nachher mit 500: das Element wird zurückgeholt, der Baum ist byteweise wie vorher, der Bericht nennt den Grund |
| 2 | Ein Archiv mit `Requires PHP: 8.1` gegen PHP 7.4 und eines mit `Requires at least: 6.6` gegen WordPress 6.4: beide `refused`, die Website byteweise unverändert |
| 3 | Ein manipuliertes Archiv vom vorgetäuschten Herstellerserver: Abbruch vor Phase 4 |
| 4 | Ein WP-CLI-Stub zeichnet Benutzer, PHP-Binary und Befehle auf: `db export` und `update-db` laufen allein bei geändertem `$wp_db_version`, beim Zurückholen `db import` mit dem Export |
| 5 | `.maintenance` ist nach jedem Ausgang entfernt, auch nach Fehler und Zurückholen; eine frische `.maintenance` vor dem Lauf führt zu `refused` |
| 6 | Eine Zielversion gleich oder unter der installierten, ein unsicherer Slug und ein Pfad außerhalb von `--path` werden abgewiesen |
| 7 | `--run-as=root` wird abgewiesen |
| 8 | Nach `rollback_failed` hält der Lauf an, die übrigen Elemente tragen `skipped`, Rückgabecode 1 |
| 9 | Eine Leseschleife parallel zum Lauf sieht in der Fortschrittsdatei nie ungültiges JSON |

Addon:

| | Was geprüft wird |
|---|---|
| 1 | `render_pages.php` rendert `malwatch_update_start.php` und die erweiterte Seite der Website |
| 2 | Die Seite nimmt allein Versionen an, die sie angeboten hat |
| 3 | Der Runner schreibt die Plandatei mit Rechten 0600 und leitet `--php` aus `server_php` ab |
| 4 | Ein eingelesener Bericht setzt die Versionen, reiht den Abgleich ein und verschickt bei `rolled_back` Mails an den Betreiber und, bei `notify_client = 'y'`, an den Kunden |

Abnahmetest in CI:

> Die CI startet MySQL, installiert WordPress aus einem älteren Zweig mit
> WP-CLI, aktiviert ein älteres Plugin und liefert die Website über `php -S`
> aus. Dann `malwatch update` für den Kern im Zweig und für das Plugin.
>
> Erwartung: Alle Dateien stimmen mit den Prüfsummen der Zielversionen, beide
> Seiten antworten mit 200.
>
> Zweiter Durchgang: Ein vorgetäuschter Herstellerserver liefert ein
> Plugin-Update, dessen Hauptdatei einen fatalen Fehler wirft. Erwartung:
> `rolled_back`, und beide Seiten antworten wieder mit 200.

## Auslieferung

Wie gehabt baut ein Tag Binaries, Addon-Paket und `SHA256SUMS`. Auf dem Server
folgt zuerst ein Probelauf gegen eine Test-Website, dann ein echtes Update auf
einer Demo-Website; danach steht die Funktion allen Websites offen.

## Nachtrag zum Umsetzungsplan (14.09.2026)

Beim Planen haben sich sieben Punkte geklärt, beim Abnahmetest und bei den
ersten Läufen im Panel drei weitere. Sie gelten vor dem Text oben:

1. Der Befehl heißt `malwatch upgrade`; `malwatch update` lädt seit jeher die
   Signaturen. Die Kennungen im Addon folgen: `job_kind = 'upgrade'`,
   `malwatch_upgrade`, `malwatch_upgrade_element`,
   `malwatch_upgrade_start.php`, `ingest_upgrade`,
   `malwatch_upgrade_notification`. Die Beschriftung im Panel bleibt „Updates“.
2. Rückgabecode 3 gilt für `rollback_failed` und jeden Fehler des Laufs, wie
   bei den übrigen Befehlen.
3. Der Bericht führt die Elemente als flache Liste `elements`; jedes nennt
   seine Installation in `install`.
4. Die Fortschrittsdatei trägt je Element einen Schritt mit `from`, `to` und
   `state`.
5. `repair` prüft bisher keine Prüfsummen; das Upgrade prüft sie über
   `knownfiles`. Ein Plugin, für das wordpress.org keine Liste veröffentlicht,
   läuft wie ein Theme weiter und trägt den Vermerk `unverified`.
6. Der Datenbank-Export liegt als Quarantäne-Eintrag in dem Verzeichnis, das
   allein root betreten darf; das Archiv trägt die Rechte der Quarantäne.
7. Quarantäne-Einträge eines Upgrades tragen den Ursprung `upgrade`.
8. Nach dem Tausch und nach dem Zurückholen wartet der Lauf die Zeit aus
   `--settle`, bevor er die Seiten abruft; beim Tausch läuft die Wartezeit noch
   im Wartungsmodus. PHP führt mit OPcache die übersetzten alten Dateien weiter
   aus, bis `opcache.revalidate_freq` seit der letzten Prüfung einer Datei
   vergangen ist. Das Addon übergibt diesen Wert aus der PHP-FPM-Konfiguration
   der Website plus eine Sekunde und lehnt ein Update ab, wenn der Pool keine
   Zeitstempel prüft. Gefunden hat das der CI-Abnahmetest zu 0.14.0; behoben in
   0.14.1.
9. Eine Prüfsummenliste von wordpress.org kann für eine Plugin-Datei mehrere
   MD5-Werte nennen, wenn sich die Datei zwischen zwei Builds derselben Version
   geändert hat. Die Datei gilt als Original, wenn sie einem davon entspricht,
   wie bei WP-CLI (0.14.2).
10. Die Seite „Updates“ startet ohne angehakte Zeile; allein `&software_id=`
    hakt sein Element an. Eine Prüfsummenliste, die sich nicht laden lässt,
    lehnt ihr Element ab, und die übrigen laufen weiter. Eine Prüfsumme, die
    nicht passt, beendet den Lauf weiterhin (0.14.3). Beides gilt vor dem Text
    zu Phase 3 und zur Seite oben.
