# malwatch — Abwehr: Treffer erklären und Herkunft der Adressen

Stand: 17.09.2026, abgestimmt mit Mathias in vier Abschnitten. Baut auf
`docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md` (malwatch 0.19.0) auf.

- **Teil A „Treffer verstehen"**: IP-Adressen an den Regeln, deutsche Erklärungen zu
  jeder Regel, der konkrete Auslöser eines Treffers.
- **Teil B „Herkunft der Adressen"**: Land, Provider, Tor, VPN und Rechenzentrum zu jeder
  Adresse, aus Quellen, die jeder Betreiber nach Schutzbedarf und Datenschutz wählt.

Teil A geht vor Teil B live. Die Menügruppe „Abwehr" (Übersicht, Ausnahmen,
Einstellungen) kam bereits mit 0.19.1.

## 1. Zweck

Wer die Seite einer Website öffnet, soll ohne Vorwissen verstehen:

- welche Adresse eine Regel ausgelöst hat
- was die Regel erkennt, was im konkreten Treffer angeschlagen hat und wie ernst das ist
- woher eine Adresse kommt: Land, Provider, Tor, VPN, Rechenzentrum

Harte Vorgabe bleibt: **Der Webserver darf niemals ausfallen.** Nichts in dieser Spec
fasst nginx an.

## 2. Entscheidungen

| Frage | Entscheidung |
|---|---|
| IP-Anzeige | in den Regel-Karten (Adressen der Einzeltreffer) und als eigene Spalte der Einzeltreffer |
| „Woran erkannt?" | Erklärung, Auslöser und Einordnung auf Deutsch; die englische CRS-Meldung bleibt klein darunter |
| Umfang des Katalogs | die 166 Regeln, die CRS 3.3.5 bei Stufe 1 ausführt (164 mit dem Tag `paranoia-level/1`, dazu 920181 und 921200), und die Auswertungsregeln 949110, 959100, 980130, 980140; übrige Regeln über ihre Gruppe |
| Katalogformat | gewöhnliche ISPConfig-Sprachdatei, damit der Spracheditor sie lesen und bearbeiten kann |
| Obergrenze der Regel-Karten | Einstellung `waf_card_hits`, Vorgabe 5000 jüngste Einzeltreffer je Website |
| Adressfilter | Index `site_ip` (`parent_domain_id`, `client_ip`, `seen_at`) auf `malwatch_waf_hit`; nach einem Knopf bleibt der Filter erhalten |
| Reihenfolge in Teil B | erst die lokalen Listen als 0.21.0, proxycheck.io danach als eigenes Release |
| Format der Bereichsdateien | eigene Datei je Quelle: sortierte Bereiche mit 16-Byte-Adressen und einer Wertetabelle, binär durchsucht |
| Quellen der Herkunft | je Merkmal einstellbar, jeweils mit „aus" |
| Externe Dienste | proxycheck.io als erster; weitere später |
| Voreinstellung | alles aus; die Seiten weisen darauf hin. Auf web.herkules werden beim Einspielen DB-IP, Tor-Liste und X4BNet eingeschaltet |
| Zeiträume und Grenzen | Einstellungen mit Vorgabe |
| Namen | Bezeichner, Dateien, Schlüssel und Kommentare englisch; Oberfläche und Specs deutsch |
| Reihenfolge | Teil A, dann Teil B, je eigenes Release |

## 3. Ausgangslage

- `malwatch_waf_hit.client_ip` enthält die Besucheradresse; auf web.herkules sind alle
  gespeicherten Adressen öffentliche IPv4-Adressen. Einzeltreffer bleiben
  `waf_detail_days` (Vorgabe 7).
- `malwatch_waf_day` enthält Tageszahlen je Regel und Pfad, **ohne Adressen**, für
  `waf_stats_days` (Vorgabe 90). Die Regel-Karten entstehen daraus.
- Die Spalte `rules` eines Treffers ist JSON, je Regel `id`, `msg`, `data` und `param`,
  zum Beispiel
  `{"id":"941100","msg":"XSS Attack Detected via libinjection","data":"Matched Data: XSS data found within ARGS:q: <script>alert(1)</script>","param":"q"}`.
- Die Überschrift einer Regel ist heute der deutsche Name ihrer Gruppe
  (`waf_panel_rule_title()`, Schlüssel `group_9xx_txt`); „Woran erkannt?" zeigt die
  englische CRS-Meldung.
- CRS 3.3.5 auf web.herkules: 165 Regeln tragen `paranoia-level/1`, 51 Stufe 2, 19 Stufe 3,
  7 Stufe 4. Die WAF läuft auf Stufe 1.
- Einstellungen stehen als Spalten in `malwatch_config` (Zeile `config_id = 1`), neue
  Spalten kommen über bedingte `ALTER TABLE` in `install/schema.sql`. Vorgaben und Grenzen
  stehen in `malwatch_waf_lib.inc.php`.
- Der malwatch-Cron läuft als root jede Minute (`malwatch_waf::cron_minute()`) und
  stündlich (`cron_hourly()`); WAF-Aufträge laufen über `malwatch_job` mit
  `job_kind = 'waf'`.
- Das Panel liest nur die Datenbank (Spec 0.19.0, Abschnitt 12).
- malwatch-Code läuft ab PHP 7.0. web.herkules hat PHP 8.3 mit `curl`, `zip`, `zlib`,
  `json`, `intl`; `unzip` und `gunzip` sind vorhanden. Dateien im MaxMind-DB-Format
  (`.mmdb`) liegen keine vor, und PHP hat keine Erweiterung dafür.
- Alle Quellen aus Abschnitt 8 sind vom Server aus erreichbar (geprüft am 17.09.2026).

## 4. Teil A: Regelkatalog

### Dateien

- `ispconfig/interface/lang/de_malwatch_waf_rules.lng` und
  `ispconfig/interface/lang/en_malwatch_waf_rules.lng`, installiert neben den übrigen
  Sprachdateien der Abwehr, im Format jeder ISPConfig-Sprachdatei:

```php
$wb['rule_930130_title'] = 'Zugriff auf geschützte Datei';
$wb['rule_930130_what'] = 'Die Anfrage wollte eine Datei lesen, die nie öffentlich sein sollte, etwa .env, .git oder eine Zugangsdatei. Solche Dateien enthalten oft Zugangsdaten.';
$wb['rule_930130_class'] = 'scanner';
$wb['rule_920440_trigger'] = 'Dateiendung „%s“';
$wb['group_942_what'] = 'Ein Wert enthält SQL-Bausteine, die eine Datenbankabfrage verändern sollen.';
$wb['group_942_class'] = 'false_positive_prone';
```

- `title`: höchstens 48 Zeichen. `what`: ein bis zwei Sätze. `class`: eine der Klassen
  unten. `note`: optionaler Zusatzsatz zur Einordnung. `trigger`: optionale Vorlage mit
  genau einem `%s` für Regeln, deren `data` nur einen Wert enthält.
- `group_<ggg>_what` und `group_<ggg>_class` erklären die Regeln einer Gruppe, die der
  Katalog selbst nicht führt.
- Beide Dateien sind vollständig; die englische darf kürzer formulieren.
- `ispconfig/tests/fixtures/crs-3.3.5-pl1-rule-ids.txt` listet die 170 Regel-IDs,
  gezogen aus `/usr/share/modsecurity-crs/rules/*.conf` auf web.herkules.

### Einordnung

| Klasse | Oberfläche | Text |
|---|---|---|
| `scanner` | Scanner | Typisch für automatische Scanner. Antwortet die Website mit 404 oder 403, wurde nichts geliefert. |
| `attack` | Angriffsversuch | Ein gezielter Versuch; ein Fehlalarm ist unwahrscheinlich. Eine Ausnahme nur nach genauer Prüfung. |
| `false_positive_prone` | Fehlalarm möglich | Schlägt auch bei echten Eingaben an, etwa HTML aus einem Editor, Suchbegriffe oder Passwörter. Eine Ausnahme für den Parameter oder Pfad ist sinnvoll, wenn die Treffer von echten Nutzern stammen. |
| `protocol` | Protokollverstoß | Die Anfrage hält sich nicht an HTTP; meist Bots oder alte Programme. |
| `scoring` | Auswertung | Die Punkte aller Regeln einer Anfrage liegen über der Grenze. Im scharfen Modus weist allein diese Regel ab. |
| `response` | Antwort der Website | Die Antwort der Website enthält Fehlermeldungen, Quelltext oder interne Angaben. Das weist auf ein Problem der Website hin. Diese Regeln greifen nur, wenn die WAF Seitenantworten prüft. |

- Kam ein Treffer von einem angemeldeten Nutzer, folgt der Satz „Die Anfrage kam von
  einem angemeldeten Nutzer; das spricht für einen Fehlalarm."
- In der Regel-Karte heißt der Satz „n von m Treffern kamen von angemeldeten Nutzern."

### Überschrift

`waf_panel_rule_title()` nimmt zuerst `title` aus dem Katalog, dann den Namen der Gruppe,
dann die CRS-Meldung, dann „Regel <ID>".

### Auslöser

`data` hat die Form `Matched Data: <Stück> found within <Stelle>: <Wert>`. Eine neue
Funktion zerlegt das in Stück, Stelle und Wert; eine zweite übersetzt die Stelle:

| Stelle | Oberfläche |
|---|---|
| `ARGS:<n>`, `ARGS_GET:<n>`, `ARGS_POST:<n>` | Parameter „n" |
| `ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES` | Name eines Parameters |
| `REQUEST_FILENAME`, `REQUEST_BASENAME` | Dateiname der Anfrage |
| `REQUEST_URI`, `REQUEST_URI_RAW` | Adresse der Anfrage |
| `REQUEST_LINE` | Anfragezeile |
| `QUERY_STRING` | Parameterteil der Adresse |
| `REQUEST_HEADERS:<n>` | Kopfzeile „n" |
| `REQUEST_HEADERS_NAMES` | Name einer Kopfzeile |
| `REQUEST_COOKIES:<n>` | Cookie „n" |
| `REQUEST_COOKIES_NAMES` | Name eines Cookies |
| `REQUEST_BODY` | Anfrageinhalt |
| `XML:<pfad>` | XML-Inhalt |
| `FILES`, `FILES_NAMES` | Name einer hochgeladenen Datei |
| `REQUEST_METHOD` | Methode |
| `REQUEST_PROTOCOL` | Protokoll |
| andere | unverändert |

Satz: „<Stelle> enthält „<Stück>"". Fehlt das Stück: „<Stelle>: <Wert>". Ohne `data`:
kein Auslöser. Stück und Wert werden auf 120 Zeichen gekürzt und maskiert ausgegeben. Werte
von `Cookie` und `Authorization` sind schon beim Einlesen entfernt.

## 5. Teil A: Anzeige

### Regel-Karte (`malwatch_waf_show.php`)

- Kopfzeile wie bisher: Titel, ID, Treffer, letzter Treffer, „Ausnahme …".
- Häufigste Pfade wie bisher.
- **Adressen aus den gespeicherten Anfragen (n Tage)**, n = `waf_detail_days`: bis zu
  fünf Adressen mit Anzahl, aus den jüngsten `waf_card_hits` Einzeltreffern der Website,
  deren `rules` die Regel enthalten; darunter „und n weitere". Erreicht die Seite die
  Obergrenze, heißt die Überschrift „Adressen aus den neuesten n gespeicherten Anfragen".
  Enthält keiner dieser Einzeltreffer die Regel: „Keine dieser Anfragen enthält die
  Regel." Darunter steht, wie viele dieser Treffer von angemeldeten Nutzern kamen.
- Ein Klick auf eine Adresse lädt die Seite mit `&ip=<adresse>` und springt zu den
  Einzeltreffern; sie zeigen dann nur diese Adresse, mit einem Hinweis und „Filter
  aufheben". Der Parameter wird mit `FILTER_VALIDATE_IP` geprüft und kommt nach einem
  Knopf als verstecktes Feld zurück. Der Index `site_ip` trägt Liste und Zählung.
- Ist die Angabe keine IP-Adresse, bleibt die Liste ungefiltert. Über den
  Einzeltreffern nennt eine Meldung die Angabe, sagt, dass die Liste deshalb alle
  gespeicherten Anfragen zeigt, und verweist zum Filtern auf die Adressen in den
  Regel-Karten und Anfragen.
- **Woran erkannt?** (aufklappbar): „Was erkannt wurde", die bis zu drei häufigsten
  Auslöser der Einzeltreffer mit Anzahl, die Einordnung, klein die CRS-Meldung.

### Einzeltreffer

- Zugeklappt: Zeit, **IP** in eigener Spalte, Anfrage, Regeln, Punkte, Chips.
- Aufgeklappt oben: Antwortcode und der Verweis „Nur Anfragen dieser Adresse"; bei
  angemeldeten Nutzern der Satz aus Abschnitt 4.
- Aufgeklappt je Regel: „Titel (ID)" mit der Einordnung als Chip, „Ausgelöst durch: …",
  die Einordnung in einem Satz, bei Bedarf der Zusatzsatz, klein der Rohtext aus `data`.

### Sprache

Neue Schlüssel in `de_malwatch_waf.lng` und `en_malwatch_waf.lng`; alle Texte der Seite
kommen aus den Sprachdateien.

## 6. Teil B: Einstellungen

Neue Spalten in `malwatch_config`:

Release 0.21.0 bringt die lokalen Quellen. Die Spalten `waf_origin_proxycheck_key`
und `waf_origin_proxycheck_daily` und der Wert `proxycheck` in `waf_origin_net`
kommen mit dem Release für proxycheck.io.
Umgesetzt mit 0.22.0 (Plan `docs/superpowers/plans/2026-09-18-malwatch-abwehr-herkunft-proxycheck.md`).

| Spalte | Typ, Vorgabe | Grenzen |
|---|---|---|
| `waf_origin_geo` | enum `off`, `dbip`, `maxmind`; `off` | |
| `waf_origin_maxmind_account` | varchar(32); leer | Ziffern |
| `waf_origin_maxmind_key` | varchar(128); leer | Buchstaben, Ziffern, `_` |
| `waf_origin_tor` | enum `off`, `torproject`; `off` | |
| `waf_origin_net` | enum `off`, `x4b`, `proxycheck`; `off` | |
| `waf_origin_proxycheck_key` | varchar(128); leer | Buchstaben, Ziffern, `-` |
| `waf_origin_proxycheck_daily` | int; 500 | 1 bis 100000 |
| `waf_origin_tor_hours` | int; 1 | 1 bis 168 |
| `waf_origin_list_hours` | int; 24 | 1 bis 720 |
| `waf_origin_db_hours` | int; 24 | 1 bis 720 |

Die Einstellungsseite der Abwehr bekommt den Abschnitt **Herkunft der Adressen**:

- „Land und Provider": aus, DB-IP Lite, MaxMind GeoLite2. Bei MaxMind erscheinen
  Konto-ID und Lizenzschlüssel.
- „Tor": aus, offizielle Tor-Liste.
- „VPN und Rechenzentrum": aus, X4BNet-Listen, proxycheck.io. Bei proxycheck.io
  erscheinen Schlüssel und Tageslimit.
- Hinweis bei lokalen Quellen: „Die Liste wird heruntergeladen, Adressen bleiben auf dem
  Server."
- Hinweis bei proxycheck.io: „Jede neue Adresse aus einem Treffer geht an proxycheck.io.
  Prüfe die Datenschutzbedingungen des Dienstes, bevor du ihn einschaltest."
- Schlüsselfelder zeigen einen gespeicherten Wert als `••••` plus die letzten vier
  Zeichen; ein leeres Feld beim Speichern behält den gespeicherten Wert, „Schlüssel
  löschen" entfernt ihn.
- Aktualisierung: Tor-Liste alle `waf_origin_tor_hours` Stunden, X4BNet-Listen alle
  `waf_origin_list_hours` Stunden, DB-IP und MaxMind werden alle `waf_origin_db_hours`
  Stunden geprüft und nur bei neuem Stand geladen.
- Pflichtfelder: MaxMind braucht Konto-ID und Schlüssel, proxycheck.io einen Schlüssel;
  sonst meldet die Seite den Fehler am Feld und speichert nicht.

## 7. Teil B: Stand der Quellen

Tabelle `malwatch_waf_origin_source`, eine Zeile je Quelle und Server:

| Spalte | Inhalt |
|---|---|
| `server_id`, `source` | Schlüssel; `source` ist `dbip_country`, `dbip_asn`, `maxmind_country`, `maxmind_asn`, `tor`, `x4b_vpn`, `x4b_datacenter`, `proxycheck` |
| `version` | Stand der Quelle, etwa `2026-09` bei DB-IP |
| `checked_at`, `fetched_at` | letzte Prüfung, letzter erfolgreicher Abruf |
| `entries` | Zahl der Bereiche oder Adressen |
| `error`, `error_at` | letzter Fehler als Text, ohne Schlüssel |
| `day`, `queries` | nur proxycheck.io: Tag und Zahl der Abfragen an diesem Tag |

Die Einstellungsseite zeigt die Zeilen der gewählten Quellen: Stand, Einträge, letzter
Abruf, Fehler mit „es gilt der Stand von …", bei proxycheck.io „heute n von m
Abfragen". Die Übersicht zeigt eine Zeile „Herkunft: …" mit denselben Angaben in Kurzform
oder „Herkunft der Adressen ist aus" mit Link zu den Einstellungen.

## 8. Teil B: Quellen und Laden

| Quelle | Adresse | Form | Lizenz, Pflicht |
|---|---|---|---|
| DB-IP Lite Land | `https://download.db-ip.com/free/dbip-country-lite-<JJJJ-MM>.csv.gz` | CSV: Start, Ende, Land | CC BY 4.0, Link „IP Geolocation by DB-IP" |
| DB-IP Lite ASN | `https://download.db-ip.com/free/dbip-asn-lite-<JJJJ-MM>.csv.gz` | CSV: Start, Ende, ASN, Organisation | CC BY 4.0, derselbe Link |
| MaxMind GeoLite2 Land | `https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip` | ZIP mit CSV, Anmeldung mit Konto-ID und Schlüssel | MaxMind-Lizenz, Hinweis „enthält GeoLite2-Daten von MaxMind" |
| MaxMind GeoLite2 ASN | `https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip` | ZIP mit CSV | wie oben |
| Tor | `https://check.torproject.org/torbulkexitlist` | eine IPv4-Adresse je Zeile | frei |
| X4BNet VPN | `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt` und `ipv6.txt` | CIDR je Zeile | MIT |
| X4BNet Rechenzentren | `…/output/datacenter/ipv4.txt` und `ipv6.txt` | CIDR je Zeile | MIT |

### Ablauf

- `cron_hourly()` legt einen WAF-Auftrag `origin_update` an, sobald eine gewählte Quelle
  fällig ist und keiner offen ist. Er erscheint in der Auftragsliste der Abwehr mit
  Ergebnis. Nach dem Speichern der Einstellungen legt die Seite den Auftrag sofort an.
- Der Auftrag lädt jede fällige Quelle mit `curl` (TLS geprüft, Verbindung 10 s, Abruf
  120 s, Kennung `malwatch/<version>`), in eine temporäre Datei unter
  `/var/lib/malwatch/waf/origin/tmp/`.
- DB-IP: zuerst der laufende Monat, bei 404 der Vormonat. Ist `version` schon aktuell,
  bleibt es bei der Prüfung.
- Grenzen je Download: DB-IP und MaxMind 80 MB, Listen 20 MB.

### Gemeinsames Format

- Jede Quelle wird in eine Bereichsdatei `/var/lib/malwatch/waf/origin/<source>.bin`
  übersetzt: sortierte, überschneidungsfreie Bereiche mit Start- und Endadresse (16 Byte,
  IPv4 als `::ffff:a.b.c.d`) und einem Verweis auf einen Wert, am Ende die Wertetabelle.
- Eine Nachschlage-Funktion sucht binär in der Datei; sie läuft ab PHP 7.0 ohne
  Erweiterungen.
- Der Umbau liest zeilenweise; X4BNet- und Tor-Listen werden im Speicher sortiert und
  zusammengelegt.

### Prüfung vor dem Tausch

- Die Datei entpackt sich fehlerfrei.
- Mindestens 99 % der Datenzeilen sind lesbar; Leer- und Kommentarzeilen zählen nicht.
- Mindestzahl: DB-IP und MaxMind je 100 000 Bereiche, Tor 100 Adressen, X4BNet je 1 000
  Bereiche; außerdem mindestens die Hälfte des bisherigen Stands.
- Erst dann ersetzt `rename()` die bisherige Datei. Sonst bleibt sie, und `error` nennt den
  Grund.

## 9. Teil B: Nachschlagen

Tabelle `malwatch_waf_ip`, eine Zeile je Adresse und Server:

| Spalte | Inhalt |
|---|---|
| `server_id`, `ip` | Schlüssel |
| `country` | ISO-Kürzel oder leer |
| `asn`, `as_org` | Nummer und Name des Netzes |
| `is_tor`, `is_vpn`, `is_hosting`, `is_proxy` | `y` oder `n` |
| `vpn_operator` | Anbietername, nur von proxycheck.io |
| `local_at` | Zeitpunkt der lokalen Prüfung |
| `external_state` | `none`, `pending`, `done`, `failed`, `limit` |
| `external_at` | Zeitpunkt der externen Prüfung |
| `external_tries` | Zahl der gescheiterten externen Prüfungen |

Die Felder `external_state`, `external_at`, `external_tries`, `is_proxy` und
`vpn_operator` entstehen schon mit 0.21.0 und bleiben leer, bis proxycheck.io dazu
kommt.

- Beim Einlesen legt `ingest` für jede neue Adresse eine Zeile an und prüft sie gegen die
  lokalen Bereichsdateien. Bringt ein neuer Treffer eine bekannte Adresse, wird ihre Zeile
  neu geprüft, sofern eine gewählte lokale Quelle seit `local_at` neu geladen wurde.
- Ist proxycheck.io gewählt, steht eine neue Zeile auf `pending`. Ein eigener Schritt in
  `cron_minute()` schickt nach dem Einlesen höchstens eine Anfrage mit bis zu 100 Adressen
  (`POST https://proxycheck.io/v3/?key=…`, Feld `ips`), nie über das Tageslimit hinaus, mit
  5 s Verbindungs- und 10 s Abrufgrenze.
- Übernommen werden `detections.vpn`, `detections.tor`, `detections.hosting`,
  `detections.proxy`, `network.asn`, `network.provider` (sonst `network.organisation`),
  `location.country_code` und `operator.name`. Die Werte von proxycheck.io ersetzen die
  lokalen Werte für VPN, Rechenzentrum und Proxy; Land und Provider kommen nur dann von
  proxycheck.io, wenn „Land und Provider" auf „aus" steht.
- Tageslimit erreicht: `limit`, am nächsten Tag wieder `pending`. Fehler: `failed`,
  `external_tries` plus eins, nach einer Stunde wieder `pending`, solange
  `external_tries` unter 3 liegt.
- Das Panel verbindet `malwatch_waf_hit.client_ip` mit `malwatch_waf_ip.ip`.

## 10. Teil B: Anzeige

- An jeder Adresse (Einzeltreffer, Regel-Karte): Land als Kürzel mit Landesnamen im
  `title` (über `intl`, sonst nur das Kürzel), Provider als „AS3320 Deutsche Telekom AG"
  (gekürzt auf 40 Zeichen, voll im `title`), Chips „Tor", „VPN" (mit Anbieter, wenn
  bekannt), „Rechenzentrum", „Proxy".
- Offene externe Prüfung: „wird geprüft". Limit erreicht: „nicht geprüft, Tageslimit".
- Namensnennung unter den Einzeltreffern und den Regel-Karten, solange die Quelle gewählt
  ist: „IP-Daten: DB-IP" mit Link auf `https://db-ip.com`, bei MaxMind „Enthält
  GeoLite2-Daten von MaxMind" mit Link auf `https://www.maxmind.com`.
- Sind alle drei Merkmale aus, zeigen Übersicht und Website-Seite „Herkunft der
  Adressen ist aus" mit Link zu den Einstellungen.

## 11. Aufräumen und Datenschutz

- `cron_hourly()` löscht nach dem Aufräumen der Einzeltreffer jede Zeile in
  `malwatch_waf_ip`, zu der kein Treffer mehr gehört. Herkunftsdaten bleiben damit
  höchstens so lange wie der letzte Treffer der Adresse.
- Wird eine Quelle abgeschaltet, löscht der nächste `origin_update` ihre Dateien und
  leert ihre Felder in `malwatch_waf_ip`; ihre Zeile in `malwatch_waf_origin_source`
  entfällt.
- Schlüssel stehen nie in Auftragsprotokollen, Fehlertexten oder Cron-Ausgaben; im HTML
  stehen höchstens ihre letzten vier Zeichen.
- Auftragsprotokolle nennen Quellen und Zahlen, keine Adressen.
- Lokale Quellen senden keine Besucheradressen. proxycheck.io bekommt nur Adressen aus
  Treffern und nur, wenn der Betreiber es gewählt hat.
- Nur Administratoren sehen die Seiten, wie bisher.

## 12. Fehlerfälle

| Fall | Verhalten |
|---|---|
| Abruf scheitert oder Datei unplausibel | alter Stand bleibt aktiv, `error` gesetzt, nächster Versuch zum nächsten Termin |
| Noch nie geladen | Adressen ohne Herkunft, Stand „noch nicht geladen" |
| `zip` fehlt bei MaxMind | Fehler „PHP-Erweiterung zip fehlt", sonst wie oben |
| MaxMind lehnt die Anmeldung ab | Fehler „Konto-ID oder Lizenzschlüssel abgelehnt" |
| proxycheck.io antwortet mit Fehler oder `denied` | Adressen `failed`, Fehlertext ohne Schlüssel |
| Platte voll beim Umbau | temporäre Datei gelöscht, alter Stand bleibt |
| Bereichsdatei beschädigt | Nachschlagen liefert leer, `error` nennt die Datei, der nächste Auftrag lädt neu |

## 13. Prüfung

- PHP-Tests in `ispconfig/tests/`:
  - Katalog (`waf_rules_catalog_test.php`): jede ID aus der Fixture hat einen deutschen
    und einen englischen Eintrag mit Titel, Erklärung und Klasse, `class` gültig und in
    beiden Sprachen gleich, `title` höchstens 48 Zeichen, jede Vorlage mit genau einem
    `%s`; jede Gruppe hat Erklärung und Klasse.
  - Auslöser: Zerlegen von `data` in Stück, Stelle und Wert, Übersetzen jeder Stelle aus
    Abschnitt 4, Kürzen und Maskieren.
  - Bereichsdatei: Schreiben und Suchen für IPv4 und IPv6, Grenzen der Bereiche,
    überlappende CIDR-Listen, leere und beschädigte Datei.
  - Einlesen der Quellen: DB-IP-CSV, MaxMind-CSV mit Standorttabelle, Tor-Liste,
    X4BNet-Liste, jeweils mit kaputten Zeilen; Plausibilitätsgrenzen.
  - proxycheck.io: Abbilden einer v3-Antwort aus einer Beispieldatei, `denied`, fehlende
    Felder.
  - Anzeige: Chips, Kürzungen, Namensnennung nur bei gewählter Quelle.
- `check_wiring.sh`: Voreinstellung `off` für alle drei Merkmale; die Hinweistexte
  stehen in beiden Sprachdateien; keine Schlüsselspalte in einem Protokoll- oder
  Fehlertext; die Seiten prüfen `&ip=` mit `FILTER_VALIDATE_IP`.
- `render_pages.php`: Website-Seite mit und ohne Herkunftsdaten, mit IP-Filter.
- Klickprobe im Nachbau: Einstellungsseite mit Quellenwahl, Schlüsselfeldern, Fehlern.
- Server: Probeabruf aller lokalen Quellen in ein Probeverzeichnis unter `/root`, mit
  Messung von Laufzeit und Speicher, bevor ein Auftrag live läuft.

## 14. Einführung

1. Teil A: Plan, Umsetzung, Release, Einspielen auf web.herkules mit Freigabe,
   Serverprotokoll.
2. Teil B: Plan, Umsetzung, Release, Probeabruf auf dem Server, Einspielen mit Freigabe.
3. Auf web.herkules: DB-IP Lite, Tor-Liste und X4BNet einschalten, ersten
   `origin_update` beobachten, Anzeige mit Mathias prüfen.
4. proxycheck.io nur auf Wunsch von Mathias, mit seinem Schlüssel.

## 15. Nicht enthalten

- weitere externe Dienste (ipinfo, AbuseIPDB und andere)
- Stadt, Region, Karten
- Sperren von Adressen (Teil 2 „Sperren" der Abwehr)
- Herkunft in den Tageszahlen

## 16. Risiken

| Risiko | Umgang |
|---|---|
| Quellen ändern Adresse, Format oder Lizenz | Plausibilitätsprüfung, Fehler sichtbar, alter Stand bleibt |
| X4BNet kennt nicht jedes VPN | Oberfläche sagt „VPN" nur bei Treffer in der Liste; Rechenzentrum fängt viele weitere |
| „VPN" oder „Rechenzentrum" trifft auch echte Firmennetze | Chips sind Hinweise; Sperren gibt es in diesem Teil keine |
| proxycheck.io ändert die v3-Antwort | Abbildung über benannte Felder, fehlende Felder bleiben leer, Beispieldatei im Test |
| Umbau großer Listen braucht Speicher | zeilenweises Lesen, Messung beim Probeabruf |
| Katalogtexte veralten mit CRS 4 | Fixture je CRS-Version; ein neuer Regelsatz braucht neue Einträge |
