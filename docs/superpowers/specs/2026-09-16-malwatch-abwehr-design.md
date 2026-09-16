# malwatch — Abwehr: WAF je Website schalten und auswerten

Stand: 16.09.2026. Teil 1 von 2, abgestimmt mit Mathias in vier Abschnitten.
Teil 2 „Sperren" (Angreifer-Adressen, URL-Tabelle für die OPNsense, fail2ban)
bekommt eine eigene Spec.

Grundlage ist die WAF aus
`docs/superpowers/specs/2026-09-16-waf-web-herkules-design.md`: ModSecurity als
nginx-Modul mit CRS 3.3.5, Stufe 0 und Stufe 1 laufen auf web.herkules.

## 1. Zweck

Die WAF wird im Panel bedient und ausgewertet:

- je Website schalten: aus, mitschreiben, scharf
- Treffer über alle Websites sehen, mit Verlauf, Regeln und Pfaden
- jede Website im Detail, bis zur einzelnen Anfrage
- Ausnahmen per Knopf anlegen und entfernen
- Notaus und den Schalter für die Seitenantwort im Audit-Log bedienen

Harte Vorgabe bleibt: **Der Webserver darf niemals ausfallen.**

## 2. Entscheidungen

| Frage | Entscheidung |
|---|---|
| Umfang | Schalten, Auswertung, Ausnahmen per Knopf, Notaus, Seitenantwort |
| Aufbewahrung | Tageszahlen ohne Adressen 90 Tage, Einzeltreffer 7 Tage, beides einstellbar |
| „Scharf" im Panel | mit Vorschau, Zeitraum und Mindestdauer einstellbar, ohne Daten ausgegraut |
| Weg | der malwatch-Cron liest als root ein und führt Aufträge aus |
| Zeiträume und Schwellen | immer Einstellungen mit Vorgabe |
| Aufteilung | Teil 1 Abwehr, Teil 2 Sperren |
| Namen | Variablen, Funktionen, Dateien, Schlüssel und Kommentare englisch; Oberfläche und Specs deutsch |
| Sichtbarkeit | nur Administratoren, wie der ganze Security-Bereich |

## 3. Ausgangslage

- Regeln laden einmal global über `/etc/nginx/conf.d/waf.conf` und
  `/etc/nginx/waf/main.conf`, 925 Regeln.
- Eine Website schaltet sich über einen markierten Block im Feld
  `web_domain.nginx_directives` ein. ISPConfig übernimmt den Block in den vhost und
  wirft dabei Kommentarzeilen heraus; im vhost zählt deshalb allein
  `modsecurity on;`.
- Audit-Log `/var/log/waf/audit.log`, JSON, `root:adm` 0600. 110 CRS-Regeln setzen
  `ctl:auditLogParts=+E` und schreiben die ganze Seitenantwort mit.
- Nur 11 von 63 vhosts haben einen eigenen 443-Block. Für die übrigen endet TLS auf der
  OPNsense, nginx bekommt Port 80.
- Anfragen des Servers an sich selbst kommen über die OPNsense mit 10.50.0.11 zurück
  und sind per Regel 10001 von der Prüfung ausgenommen. Proben kommen deshalb immer von
  außen.
- Die WordPress-Ausnahmen des Regelwerks nehmen `/wp-login.php` aus.
- Die ersten Werkzeuge tragen deutsche Namen (`waf-schalter`, `waf-wache`,
  `waf-bericht`, `einstellungen.conf` …). Teil 1 benennt sie um (Abschnitt 9).

## 4. Namen

### Zustände

| Code | Oberfläche | Block im Feld „nginx-Direktiven" |
|---|---|---|
| `off` | aus | kein Block |
| `detect` | mitschreiben | `modsecurity on;` |
| `enforce` | scharf | `modsecurity on;` und `modsecurity_rules 'SecRuleEngine On';` |

### Markierung

```
# WAF-BEGIN (detect) - managed by waf-switch
modsecurity on;
# WAF-END
```

Die alte Markierung `# WAF-Anfang (mitschreiben|scharf) …` / `# WAF-Ende` wird
weiter erkannt; `mitschreiben` gilt als `detect`, `scharf` als `enforce`.

### Umbenennung

| bisher | neu |
|---|---|
| `waf-schalter` | `waf-switch` |
| `waf-schalter setze`, `zurueck`, `notaus`, `antwortrumpf` | `waf-switch set`, `restore`, `emergency`, `response-body` |
| Werte `aus`, `mitschreiben`, `scharf` auf der Kommandozeile | `off`, `detect`, `enforce` |
| `waf-wache` | `waf-guard` |
| `waf-bericht` | `waf-report` |
| `einstellungen.conf` | `settings.conf` |
| `crs-zusatz.conf` | `crs-extra.conf` |
| `ausnahmen-vorher.conf` | `exclusions-before.conf` |
| `ausnahmen-nachher.conf` | `exclusions-after.conf` |
| `zustand.conf` | `state.conf` |
| `antwortrumpf.conf`, `voll`/`schlank` | `response-body.conf`, `full`/`lean` |
| neu | `exclusions-panel-before.conf`, `exclusions-panel-after.conf` |
| `/var/backups/waf-schalter` | `/var/backups/waf-switch` |
| `/var/log/waf/wache.log` | `/var/log/waf/guard.log` |
| hc-run-Name `waf-wache` | `waf-guard` |
| `waf_block_setzen`, `waf_block_entfernen`, `waf_block_zustand`, `waf_vhost_zustand`, `waf_zustand_gueltig` | `waf_block_set`, `waf_block_remove`, `waf_block_state`, `waf_vhost_state`, `waf_state_valid` |
| `waf_antwortrumpf_text`, `waf_antwortrumpf_modus`, `waf_antwortrumpf_gueltig` | `waf_response_body_text`, `waf_response_body_mode`, `waf_response_body_valid` |
| `waf_audit_zeile`, `waf_audit_auswerten` | `waf_audit_parse_line`, `waf_audit_summarize` |

## 5. Datenmodell

Alle neuen Tabellen tragen wie die übrigen die sechs `sys_`-Spalten und `server_id`.

### `malwatch_waf_hit` (neu) — Einzeltreffer

| Spalte | Typ | Inhalt |
|---|---|---|
| `hit_id` | int, Schlüssel | |
| `parent_domain_id`, `domain` | | Website |
| `unique_id` | varchar(64), eindeutig | Kennung der Transaktion aus dem Audit-Log |
| `seen_at` | datetime | Zeitpunkt |
| `client_ip` | varchar(45) | Besucheradresse |
| `method` | varchar(10) | |
| `uri` | varchar(2048) | mit Query, auf 2048 Zeichen gekürzt |
| `path` | varchar(1024) | ohne Query |
| `status` | smallint | Antwortcode |
| `anomaly_score` | smallint | Punktzahl aus 949110, sonst 0 |
| `would_block` | enum('n','y') | Regel 949110 dabei |
| `logged_in` | enum('n','y') | Cookie mit dem Namen `wordpress_logged_in_…` vorhanden |
| `rules` | text | JSON: Regel-ID, Meldung, Fundstelle, Parameter |
| `request_headers` | text | JSON; Werte von `Cookie` und `Authorization` durch `[entfernt]` ersetzt, Namen bleiben |
| `request_body` | mediumtext, NULL | nur wenn das Audit-Log ihn enthält |
| `response_file` | varchar(255) | relativer Pfad der gepackten Seitenantwort, leer ohne |
| `response_bytes` | int | Größe der Seitenantwort |

Schlüssel: `unique_id`, `(parent_domain_id, seen_at)`, `seen_at`.
Aufbewahrung: `waf_detail_days`.

### `malwatch_waf_site_day` (neu) — Tageszahlen je Website

`day` date, `parent_domain_id`, `domain`, `hits` (Transaktionen mit Treffer),
`would_block` (Transaktionen mit 949110), `logged_in_hits`. Eindeutig auf
`(day, parent_domain_id)`. **Keine Adressen.** Aufbewahrung: `waf_stats_days`.

### `malwatch_waf_day` (neu) — Tageszahlen je Website, Regel und Pfad

`day`, `parent_domain_id`, `domain`, `rule_id` varchar(16), `path` varchar(1024),
`path_hash` char(40) (sha1 des Pfads), `hits`, `would_block_hits` (Treffer dieser
Regel in Transaktionen mit 949110). Eindeutig auf
`(day, parent_domain_id, rule_id, path_hash)`. **Keine Adressen.** Aufbewahrung:
`waf_stats_days`.

### `malwatch_waf_exception` (neu) — Ausnahmen

| Spalte | Inhalt |
|---|---|
| `exception_id` | Schlüssel; die Regel-ID in der Datei ist `10200 + exception_id` |
| `scope` | enum('site','site_path','site_param','all','all_path') |
| `parent_domain_id`, `domain` | 0 und leer bei `all` und `all_path` |
| `rule_id` | varchar(16) |
| `path` | varchar(1024), bei `site_path`, `all_path`, wahlweise bei `site_param` |
| `param` | varchar(128), bei `site_param` |
| `note` | varchar(255), steht nur in der Datenbank |
| `exception_state` | enum('pending','active','error','removing') |
| `error_reason` | varchar(255) |
| `job_id` | letzter Auftrag |
| `created_by`, `created_at`, `activated_at` | |

### `malwatch_site` (erweitert)

`waf_state` enum('off','detect','enforce') Vorgabe `off`, `waf_state_since`
datetime NULL, `waf_job_id` int, `waf_pending_state` varchar(16). Eine Website ohne
Zeile bekommt beim ersten Schalten eine. Quelle der Wahrheit bleibt das Feld
„nginx-Direktiven"; `waf_state` hält den zuletzt bestätigten Stand für die Listen.

### `malwatch_job` und `malwatch_action_log` (erweitert)

`job_kind` wächst um `waf`, `action_type` um `waf`. Beides über die
selbstprüfenden Zusätze in `schema.sql`, wie bei `dump`.

### `malwatch_config` (erweitert) — Einstellungen und Lesestand

| Spalte | Vorgabe | Bedeutung |
|---|---|---|
| `waf_detail_days` | 7 | Einzeltreffer aufbewahren |
| `waf_stats_days` | 90 | Tageszahlen aufbewahren |
| `waf_log_keep_days` | 7 | Stände des Audit-Logs in logrotate |
| `waf_preview_days` | 7 | Zeitraum der Vorschau vor „scharf" |
| `waf_min_detect_days` | 7 | Mindestdauer „mitschreiben" vor „scharf" |
| `waf_response_body` | `full` | Seitenantwort im Audit-Log (`full`, `lean`) |
| `waf_ingest_max_lines` | 5000 | Zeilen je Einleselauf |
| `waf_job_deadline_minutes` | 5 | Frist für einen Zustandswechsel |
| `waf_audit_log` | `/var/log/waf/audit.log` | |
| `waf_conf_dir` | `/etc/nginx/waf` | |
| `waf_emergency` | `n` | Notaus aktiv |
| `waf_emergency_since` | NULL | |
| `waf_log_inode`, `waf_log_offset` | 0 | Lesestand |

## 6. Einlesen

`malwatch_waf::ingest()` läuft in jedem Cron-Durchgang vor dem Start neuer Aufträge.

1. `stat` des Audit-Logs. Weicht die Inode vom gespeicherten Wert ab oder ist die Datei
   kürzer als der Lesestand, beginnt das Lesen bei 0. Das deckt `copytruncate` und neue
   Dateien ab.
2. Höchstens `waf_ingest_max_lines` Zeilen ab dem Lesestand. Unvollständige letzte
   Zeilen bleiben für den nächsten Lauf stehen.
3. Je Zeile `waf_audit_parse_line()`: Transaktion, Host, Pfad, Regeln, 949110,
   Cookie-Namen. Unlesbare Zeilen werden gezählt und übersprungen.
4. Website über den Host: `web_domain.domain` des vhosts, dieselbe Domain mit `www.`
   und alle Einträge der Typen `alias`, `subdomain`, `vhostalias`, `vhostsubdomain` mit
   ihrem `parent_domain_id`. Unbekannte Hosts werden gezählt und in die Cron-Meldung
   geschrieben.
5. `INSERT IGNORE` in `malwatch_waf_hit` über `unique_id`; nur neu angelegte Treffer
   erhöhen die Tageszahlen (`INSERT … ON DUPLICATE KEY UPDATE`).
6. Enthält die Zeile eine Seitenantwort, landet sie gepackt unter
   `<state_dir>/waf/responses/<unique_id>.html.gz`. Verzeichnis 02750
   `root:<panelgruppe>`, Datei 0640.
7. Lesestand und Inode speichern.

## 7. Aufräumen

Im stündlichen Teil von `housekeeping`:

- Treffer älter als `waf_detail_days` samt Antwortdatei löschen
- Zeilen der beiden Tagestabellen älter als `waf_stats_days` löschen
- Antwortdateien ohne Treffer löschen
- Arbeitsverzeichnisse von Aufträgen ohne laufenden Auftrag löschen

## 8. Seiten

### Menü

„Abwehr" steht im Security-Modul hinter „Schwachstellen". Alle Seiten prüfen
`$app->auth->is_admin()` und antworten sonst leer. Formulare und Knöpfe nutzen
`csrf_token_get` und `csrf_token_check('POST')` wie die übrigen Seiten. Laufende
Aufträge zeigen ihren Fortschritt ohne Neuladen über das vorhandene
Fortschrittsmuster.

### Übersicht — `malwatch_waf_list.php`

- Kopf als Satz, etwa „2 Websites schreiben mit, keine blockiert. Heute 14 Treffer,
  3 davon wären abgewiesen worden."
- Rotes Band „Notaus aktiv seit …" mit „Notaus beenden", solange `waf_emergency = y`.
- Oben rechts: „Notaus" (rot, mit Rückfrage) und der Umschalter für die Seitenantwort
  („vollständig" / „schlank").
- Zeitraum: heute, 7, 30, 90 Tage, begrenzt durch `waf_stats_days`.
- Filter: Zustand, WordPress, nur mit Treffern.
- Liste aller Websites mit `web_domain.type = 'vhost'` und `active = 'y'` auf diesem
  Server: Zustand als Kennzeichnung (aus, mitschreiben, scharf,
  „wird umgesetzt"), seit, Treffer im Zeitraum mit kleinem Verlauf je Tag, davon „wäre
  abgewiesen", häufigste Regel, Knöpfe „Ansehen" und „Zustand ändern".
- Mehrfachauswahl mit „Zustand ändern" für alle markierten Websites.
- Link „Ausnahmen (n)".

### Website im Detail — `malwatch_waf_show.php?id=<domain_id>`

- Schalter aus, mitschreiben, scharf.
- „Scharf" öffnet die Vorschau: Anzahl der Transaktionen mit 949110 in den letzten
  `waf_preview_days` Tagen, davon von angemeldeten Nutzern, beteiligte Regeln aus
  `malwatch_waf_day.would_block_hits`. Der Knopf bleibt grau, solange die Website
  kürzer als `waf_min_detect_days` mitschreibt, und nennt das Datum, ab dem er frei wird.
- Verlauf: Treffer je Tag, getrennt nach „wäre abgewiesen" und übrigen.
- Regeln: Klartext-Überschrift, Treffer, häufigste Pfade, letzter Treffer, Knopf
  „Ausnahme …". Die englische CRS-Meldung liegt unter „Woran erkannt?".
- Pfade: Pfad, Treffer, Regeln.
- Einzeltreffer aus `waf_detail_days`: Zeit, Adresse, Methode und Adresse der Anfrage,
  Regeln, Punktzahl, „angemeldet". Aufklappbar: Kopfzeilen, Anfrageinhalt, Knopf
  „Seitenantwort ansehen" bei vorhandener Datei.
- Ausnahmen dieser Website mit Zustand, Notiz und „Entfernen".

### Dialog „Ausnahme"

- Geltungsbereich: „diese Website" (`site`), „nur dieser Pfad" (`site_path`), „nur
  dieser Parameter" (`site_param`, Pfad wahlweise), „alle Websites" (`all`, mit Pfad
  `all_path`).
- Regel, Pfad und Parameter aus dem Treffer vorbelegt und änderbar, dazu eine Notiz.
- Vorschau aus `malwatch_waf_day`: „Diese Ausnahme hätte 18 von 21 Treffern der letzten
  7 Tage verhindert." Zeitraum: `waf_preview_days`.
- „Anlegen" legt die Zeile mit `pending` an und reiht einen Auftrag ein.

### Ausnahmen gesamt — `malwatch_waf_exception_list.php`

Alle Ausnahmen mit Geltungsbereich, Website, Regel, Pfad oder Parameter, Notiz, Zustand,
Fehler, Anlage durch und am. Filter nach Zustand und Website, Knopf „Entfernen".

### Seitenantwort ansehen — `malwatch_waf_response.php?hit=<hit_id>`

Liefert die entpackte Antwort als `text/plain; charset=utf-8` mit
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'` und
`Content-Disposition: inline`. Die Antwort stammt aus Anfragen von Angreifern und wird
deshalb nie als HTML im Panel dargestellt.

### Aktionen — `malwatch_waf_action.php`

Ein POST-Endpunkt für alle Knöpfe. Prüft Adminrechte und CSRF, prüft die Eingaben,
legt Zeilen an und reiht Aufträge über `datalogInsert('malwatch_job', …)` ein. Antwort
als JSON für die Seiten.

### Einstellungen — `malwatch_waf_config_edit.php`

Eine eigene Seite mit eigener Formulardefinition
`form/malwatch_waf_config.tform.php` auf derselben Zeile von `malwatch_config`,
erreichbar über „Einstellungen" auf der Übersicht. Die bestehende
Einstellungsseite bleibt unverändert, sie trägt bereits eigene Abläufe beim
Speichern. Felder: die Einstellungen aus Abschnitt 5 ohne Lesestand und Notaus.
Speichern reiht einen Auftrag `apply_settings` ein.

### Klartext für Regeln

Überschriften nach Regelgruppe aus den Sprachdateien, etwa 941 „Skript-Einschleusung
(XSS)", 942 „SQL-Einschleusung", 930 „Zugriff auf Dateien und Pfade", 932
„Befehlsausführung", 933 „PHP-Angriff", 913 „Scanner", 920 „Verstoß gegen das
Protokoll", 949 „Punktgrenze überschritten". Ohne Eintrag gilt die CRS-Meldung.

## 9. Aufträge

### Aktionen

`malwatch_job` mit `job_kind = 'waf'`, `options` als JSON:

| `action` | Felder |
|---|---|
| `set_state` | `domain_ids`, `state` |
| `exception_add` | `exception_id` |
| `exception_remove` | `exception_id` |
| `emergency` | `on` (bool), `hard` (bool) |
| `response_body` | `mode` (`full`, `lean`) |
| `apply_settings` | — |
| `migrate_markers` | — |

### Reihenfolge

`malwatch_waf::run_jobs()` im Cron nimmt einen `waf`-Auftrag nur, wenn kein anderer
läuft. `emergency` kommt vor allen übrigen. Jede Aktion schreibt eine Zeile in
`malwatch_action_log` mit Person, Aktion und Ergebnis.

### `set_state`

1. Feld `nginx_directives` je Website nach
   `/var/backups/waf-switch/<Zeitstempel>/<domain>.txt` sichern.
2. `waf_block_set()` anwenden und über `datalogUpdate('web_domain', …)` schreiben.
   `waf_pending_state` setzen, Auftrag bleibt `running`.
3. Folgende Durchgänge lesen den vhost mit `waf_vhost_state()`. Stimmt der Zustand,
   folgt `nginx -t`; bei Erfolg `waf_state`, `waf_state_since` setzen und den Auftrag
   abschließen.
4. Nach `waf_job_deadline_minutes` ohne bestätigten Zustand oder bei fehlgeschlagenem
   `nginx -t`: Zuerst das Feld mit dem Text vergleichen, den der Auftrag geschrieben
   hat. Stimmt es überein, gesicherten Inhalt zurückschreiben. Hat inzwischen jemand
   das Feld geändert, bleibt es stehen, und der Auftrag meldet „Feld wurde zwischenzeitlich
   geändert, keine Rücknahme". In beiden Fällen endet der Auftrag mit `error` und Grund.
5. `enforce` prüft vor Schritt 1 je Website auf dem Server: aktueller Zustand `detect`
   seit mindestens `waf_min_detect_days` und `waf_emergency = n`. Websites, die das nicht
   erfüllen, werden übersprungen und im Ergebnis des Auftrags mit Grund genannt; die
   übrigen Websites des Auftrags laufen weiter.

### Ausnahmen erzeugen

`waf_exception_rules()` baut aus allen Zeilen mit `pending` oder `active` zwei Texte.

`exclusions-panel-before.conf` (vor dem Regelwerk eingebunden):

```
# site
SecRule REQUEST_HEADERS:Host "@rx ^(?:example\.de|www\.example\.de)(?::\d+)?$" \
    "id:10201,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveById=942100"

# site_path
SecRule REQUEST_HEADERS:Host "@rx ^(?:example\.de|www\.example\.de)(?::\d+)?$" \
    "id:10202,phase:1,pass,nolog,t:none,t:lowercase,chain"
    SecRule REQUEST_FILENAME "@beginsWith /wp-admin/admin-ajax.php" \
        "t:none,ctl:ruleRemoveById=942100"

# site_param
SecRule REQUEST_HEADERS:Host "@rx ^(?:example\.de|www\.example\.de)(?::\d+)?$" \
    "id:10203,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveTargetById=942100;ARGS:filter"

# all_path
SecRule REQUEST_FILENAME "@beginsWith /xmlrpc.php" \
    "id:10204,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=941100"
```

`site_param` mit Pfad bekommt die Kette wie `site_path`.

`exclusions-panel-after.conf` (nach dem Regelwerk eingebunden):

```
# all, exception 5
SecRuleRemoveById 941160
```

Die Hosts einer Website stammen aus derselben Zuordnung wie beim Einlesen, klein
geschrieben und mit `preg_quote` maskiert. Eingaben werden vor dem Anlegen im Panel und
erneut im Auftrag geprüft:

| Feld | Muster |
|---|---|
| `rule_id` | `^[0-9]{3,7}$` |
| `path` | `^/[A-Za-z0-9._~/%+-]{0,1023}$` |
| `param` | `^[A-Za-z0-9_.\[\]-]{1,128}$` |

Die Notiz gelangt nie in eine Regeldatei.

### Jede Dateiänderung

1. Arbeitsverzeichnis `<state_dir>/waf/staging/<job_id>/` mit einer Kopie von
   `waf_conf_dir` anlegen und die geänderten Dateien dort schreiben.
2. Eine `main.conf` im Arbeitsverzeichnis, deren Includes auf die Kopie zeigen,
   mit `modsec-rules-check` prüfen.
3. Die bisherigen Dateien sichern und die neuen per `rename` austauschen.
4. `nginx -t`. Bei Erfolg `systemctl reload nginx`, danach `systemctl is-active nginx`.
5. Scheitert Schritt 2 oder 4: gesicherte Dateien zurück, **kein** Reload, Auftrag
   `error` mit Grund im Klartext, betroffene Ausnahmen auf `error`.
6. Nach jedem Erfolg wird der Inhalt von `waf_conf_dir` nach
   `<state_dir>/waf/last-good/` kopiert.

Alle verwalteten Dateien legt `waf/install.sh` an. Ein Auftrag tauscht nur
vorhandene Dateien aus; so bleibt beim Zurücknehmen immer eine gültige
Konfiguration stehen.

### Notaus

- `on`: `state.conf` mit `SecRuleEngine Off` über den Ablauf oben, Reload, danach je
  Website mit `enforce` ein `set_state` auf `detect`. `waf_emergency = y`.
- `hard`: für den Fall, dass das Modul fehlt. `/etc/nginx/conf.d/waf.conf` wird nach
  `waf.conf.off` umbenannt, alle Websites bekommen `off`. Die Prüfung mit `nginx -t`
  entfällt dabei je Website und läuft einmal am Ende des Auftrags, gefolgt vom
  Reload. Wieder eingeschaltet wird über `waf/install.sh`.
- `off`: `state.conf` leeren, Reload, `waf_emergency = n`.

### Seitenantwort

`response-body.conf` mit `waf_response_body_text(mode)` über den Ablauf oben;
`waf_response_body` in `malwatch_config` nachführen. Die Regel im Modus `lean`
trägt die ID 10199 und liegt damit unter dem Bereich der Ausnahmen.

### Einstellungen übernehmen

`/etc/logrotate.d/waf` mit `rotate <waf_log_keep_days>` neu schreiben und mit
`logrotate -d` prüfen. Die übrigen Einstellungen wirken ohne Dateiänderung.

### Markierungen umschreiben

`migrate_markers` sucht Felder mit der alten Markierung und schreibt sie mit dem Ablauf
von `set_state` auf die neue um, Zustand unverändert.

## 10. Werkzeuge auf dem Server

- `waf-switch` ruft `malwatch_waf` auf. `status`, `set`, `probe`, `emergency on|off
  [--hard]`, `restore <ordner>`, `response-body full|lean|status`. Notaus und
  Seitenantwort laufen sofort, ohne auf den Cron zu warten.
- `waf-guard` stündlich über `hc-run waf-guard`: `nginx -t`. Meldet der Test eine
  unbekannte Direktive `modsecurity`, folgt Notaus `--hard`. Nennt er eine Datei unter
  `waf_conf_dir`, stellt der Wächter `last-good` wieder her, prüft erneut und lädt neu.
  Außerdem verarbeitet er hängende Aufträge wie der Cron, damit deren Frist auch ohne
  Cron greift.
- `waf-report` gibt die Tabelle aus `waf_audit_summarize()` aus.

### Umstellung von den alten Namen

`waf/install.sh` erledigt sie in dieser Reihenfolge und darf mehrfach laufen:

1. Neue Dateien unter den neuen Namen neben die alten legen, dazu `main.conf.new` mit den
   neuen Includes.
2. `modsec-rules-check` auf `main.conf.new`, dann `main.conf.new` nach `main.conf`,
   `nginx -t`, Reload. Bei Fehler die alte `main.conf` zurück.
3. Erst nach Erfolg die Dateien mit alten Namen entfernen.
4. Werkzeuge unter den neuen Namen einspielen, alte entfernen.
5. Cron-Zeile `waf-wache` durch `waf-guard` ersetzen.
6. `waf-switch` reiht `migrate_markers` ein.

## 11. Gemeinsamer Code

- `ispconfig/interface/lib/malwatch_waf_lib.inc.php`: reine Funktionen für Block,
  vhost-Zustand, Seitenantwort, Audit-Zeile, Zusammenfassung, Ausnahmeregeln und
  Eingabeprüfung. Getestet in `ispconfig/tests/waf_lib_test.php`.
- `ispconfig/server/lib/classes/malwatch_waf.inc.php`: Einlesen, Aufräumen, Aufträge,
  Dateiänderungen. Bindet die reinen Funktionen über
  `/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php` ein;
  dort legt `install/file.list` die Datei ab, wie `malwatch_lib.inc.php`.
- `waf/lib/` entfällt; `waf-switch` und `waf-report` binden dieselbe Datei ein.

## 12. Sicherheit und Datenschutz

- Nur Administratoren; jede Seite prüft das selbst.
- Einzeltreffer enthalten Adressen und Anfrageinhalte und bleiben
  `waf_detail_days`; Tageszahlen enthalten keine Adressen.
- Werte von `Cookie` und `Authorization` werden vor dem Speichern entfernt.
- Seitenantworten werden nur als Text ausgeliefert.
- Regeldateien entstehen ausschließlich aus geprüften Feldern.
- Das Audit-Log bleibt `root:adm` 0600; das Panel liest nur die Datenbank und die
  Antwortdateien.

## 13. Prüfung

### Am Rechner

`ispconfig/tests/waf_lib_test.php`:

1. Block setzen, entfernen, Zustand lesen, alte Markierung erkennen.
2. vhost-Zustand bei Kommentaren, `modsecurity off;` und leerem Text.
3. Audit-Zeile: Host mit und ohne Port, Pfad ohne Query, Regeln, 949110, Cookie-Namen,
   entfernte Werte von `Cookie` und `Authorization`, kaputte Zeilen.
4. Ausnahmeregeln für alle fünf Geltungsbereiche, stabile IDs, maskierte Hosts,
   abgewiesene Eingaben mit Anführungszeichen, Zeilenumbrüchen und Steuerzeichen.
5. Lesestand bei neuer Inode und gekürzter Datei.
6. Stichtage und Vorschau aus den Einstellungen.

Dazu `check_wiring.sh` und `render_pages.php` gegen die echten Panel-Stylesheets.

### Am Server

Je Schritt mit Freigabe von Mathias, Proben von außen:

1. bright-color.de per Panel auf `off` und zurück auf `detect`; Fristüberschreitung mit
   verkürzter Frist in den Einstellungen.
2. Probe erscheint im nächsten Durchgang auf der Seite; Probe mit Cookie-Namen
   `wordpress_logged_in_test` gilt als angemeldet.
3. Ausnahme aus einem Treffer (`site_path`) anlegen; dieselbe Probe erzeugt auf dem Pfad
   keinen Treffer dieser Regel mehr, auf einem anderen Pfad weiterhin. Eine Ausnahme mit
   ungültiger Regel-ID wird abgewiesen, ohne Reload.
4. Notaus an und aus, Seitenantwort in beide Richtungen.
5. Umstellung: `nginx -T` zeigt nur die neuen Dateien, `crontab -l` nur `waf-guard`,
   `waf-guard` läuft durch.

Nach jedem Schritt: nginx aktiv, drei Websites von außen erreichbar, 5xx-Anteil
unverändert, keine abgestürzten Worker, Speicher innerhalb der Grenzen der WAF-Spec.

## 14. Einführung

1. malwatch 0.19.0: Version, CHANGELOG, README.
2. Schema über die selbstprüfenden Zusätze, neue Dateien in `install/file.list`,
   Menüpunkt in `module.conf.php`.
3. Ausliefern wie gewohnt, jede Kopie mit `cmp` gegenprüfen, Seiten mit den Proben von
   bright-color.de ansehen.
4. `waf/install.sh` mit der Umstellung aus Abschnitt 10.
5. Danach die Stufen 2 und 3 der WAF-Einführung über die neue Seite.
6. Jeder Schritt am Server bekommt einen Eintrag im Serverprotokoll.

Rückweg: vorherige malwatch-Version einspielen; die WAF behält die zuletzt gültige
Einbindung, die Zustände der Websites bleiben.

## 15. Nicht in Teil 1

- Angreifer-Adressen, Sperrliste, URL-Tabelle für die OPNsense, fail2ban-Sperren
  (Teil 2)
- Mails bei Blockaden
- Sicht für Kunden und Reseller
- eigene Pakete mit Engine 3.0.16 und CRS 4.25 LTS

## 16. Risiken

1. **Menge:** Mit `full` wiegt ein Treffer rund 125 KB. Die Antwortdateien liegen
   gepackt, die Tabelle bleibt klein; `waf_detail_days` begrenzt beides.
2. **Einleselast:** Bei vielen Treffern begrenzt `waf_ingest_max_lines` die Arbeit je
   Durchgang; der Rückstand zeigt sich im Lesestand.
3. **Unbekannte Hosts:** Anfragen an Namen ohne Eintrag in `web_domain` erscheinen nur als
   Zahl in der Cron-Meldung.
4. **Laufzeitausnahmen in Engine 3:** Das Verhalten von `ctl:ruleRemoveById` und
   `ctl:ruleRemoveTargetById` wird am Server mit Proben belegt, bevor Ausnahmen für
   Kundenseiten angelegt werden.
5. **Gleichzeitige Arbeit an Websites:** Speichert ein Admin das Feld „nginx-Direktiven"
   während eines Auftrags, gewinnt die jüngere Änderung; der Auftrag erkennt den
   abweichenden Stand und meldet ihn.
