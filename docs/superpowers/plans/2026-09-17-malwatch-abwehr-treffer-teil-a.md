# malwatch — Abwehr: Treffer verstehen (Teil A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die Website-Seite der Abwehr zeigt zu jeder Regel die auslösenden Adressen, erklärt jede Regel auf Deutsch mit Auslöser und Einordnung und hebt die Adresse in den Einzeltreffern hervor.

**Architecture:** Ein Regelkatalog als gewöhnliche ISPConfig-Sprachdatei je Sprache liefert Titel, Erklärung, Klasse und bei Bedarf eine Vorlage für den Auslöser. Reine Funktionen in `malwatch_waf_panel.inc.php` lesen den Katalog, zerlegen die `data` eines Treffers und fassen die jüngsten Einzeltreffer je Regel zusammen. Die Seiten reichen den Katalog durch. Die Datenbank bekommt eine Einstellungsspalte und einen Index für den Adressfilter.

**Tech Stack:** PHP ab 7.0 im ISPConfig-Panel (vlibTemplate, tform), MariaDB, POSIX-sh für `check_wiring.sh`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`, Teil A (Abschnitte 1 bis 5). Teil B „Herkunft der Adressen" bekommt einen eigenen Plan.

## Global Constraints

- PHP-Code läuft ab PHP 7.0; keine neuen PHP-Erweiterungen, keine neuen Pakete.
- Variablen, Funktionen, Dateinamen, Schlüssel und Code-Kommentare englisch; Oberfläche, Plan und Spec deutsch.
- Zeiträume, Grenzen und Mengen sind Einstellungen mit Vorgabe, nie feste Werte im Code.
- Keine echten Kundendaten in Repo, Tests oder Changelog; Beispieladressen aus 192.0.2.0/24, 198.51.100.0/24 und 203.0.113.0/24.
- Konkurrenzprodukte werden nie genannt. Vor jedem Commit: `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` bleibt leer.
- Alle Seiten nur für Administratoren; jede Ausgabe läuft durch `$app->functions->htmlentities()`.
- Der Webserver darf niemals ausfallen. Teil A ändert nichts an nginx und an den Regeldateien.
- Serverschritte nur nach Freigabe von Mathias, jeder mit Eintrag im Serverprotokoll `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md` (frisch lesen, gezielt einfügen, neueste zuerst).
- Agenten nur mit Freigabe von Mathias.
- Commits mit ausdrücklichen Pfaden und dem Trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`; gearbeitet wird im Repo `C:\Users\brigh\Claude Workingdir\malwatch` auf dem Zweig `waf-herkules`.
- Unter Windows: PHP braucht `C:/…`-Pfade; das Bash-Werkzeug macht aus `\\n` in Befehlstexten einen Zeilenumbruch, Backslashes in Hilfsskripten deshalb über `chr(92)`.
- `sh ispconfig/tests/check_wiring.sh` läuft lange; im Hintergrund starten.

## Präzisierungen gegenüber der Spec

Task A3 übernimmt die Punkte 1 bis 6 in die Spec (Abschnitte 2, 4, 5 und 13), Task A9 die Punkte 7 und 8 (Abschnitte 2 und 5).

1. **Katalogformat:** Der Katalog ist eine gewöhnliche ISPConfig-Sprachdatei mit Schlüsseln `rule_<id>_title`, `rule_<id>_what`, `rule_<id>_class`, `rule_<id>_note` und `rule_<id>_trigger`. Der Spracheditor von ISPConfig kann sie so lesen und bearbeiten; ein eigenes Array `$waf_rules` könnte er beim Speichern zerstören.
2. **Sechste Klasse:** `response` („Antwort der Website") für die Regeln 950 bis 954. Sie prüfen die Seitenantwort und weisen eher auf ein Problem der Website hin.
3. **Umfang:** 170 Einträge. 164 Regeln tragen `paranoia-level/1`; 920181 und 921200 stehen im Abschnitt der Stufe 1 ohne diesen Tag; dazu die Auswertungsregeln 949110, 959100, 980130 und 980140.
4. **Auslöser ohne Stelle:** Für Regeln, deren `data` nur einen Wert enthält (etwa 920440 mit `.bak`), trägt der Katalog eine Vorlage `trigger` wie `Dateiendung „%s“`.
5. **Obergrenze der Regel-Karten:** Einstellung `waf_card_hits` (Vorgabe 5000, 100 bis 100000). So viele jüngste Einzeltreffer einer Website liest die Seite für Adressen und Auslöser. Ein Scanner erzeugt auf einer Website leicht Hunderttausende Einzeltreffer in sieben Tagen.
6. **Gruppen:** Die Gruppen 910, 912 und 922 bekommen einen Namen. Jede Gruppe bekommt im Katalog eine Erklärung und eine Klasse für Regeln außerhalb des Katalogs (Stufe 2 bis 4).
7. **Index für den Adressfilter:** `site_ip` (`parent_domain_id`, `client_ip`, `seen_at`) auf `malwatch_waf_hit`. Liste und Zählung einer Adresse lesen damit nur deren Zeilen. Der Filter kommt nach einem Knopf als verstecktes Feld `ip` zurück, wie `days`. Eine Angabe, die keine IP-Adresse ist, lässt die Liste ungefiltert und bekommt eine Meldung mit dem Weg zum Filtern (Vorgabe „Verständliche Fehlermeldungen“ vom 17.09.2026). Nach derselben Vorgabe nennen die Bereichsmeldungen der Einstellungsseite Feld, Grenzen und nächsten Schritt (Task A1).
8. **Adresse im Einzeltreffer:** Die zugeklappte Zeile bleibt reiner Schalter zum Aufklappen. Aufgeklappt führt „Nur Anfragen dieser Adresse“ zum Filter, und jede Regel trägt ihre Einordnung zusätzlich als Chip.

## Dateien

| Datei | Aufgabe |
|---|---|
| `ispconfig/interface/lib/malwatch_waf_panel.inc.php` | neue reine Funktionen: `waf_panel_rule_catalog()`, `waf_panel_rule_catalog_file()`, `waf_panel_rule_classes()`, `waf_panel_rule_info()`, `waf_panel_trigger_parts()`, `waf_panel_target_label()`, `waf_panel_trigger_text()`, `waf_panel_ranked()`, `waf_panel_rule_hits()`, `waf_panel_ip_filter()`; `waf_panel_rule_title()`, `waf_panel_rules()`, `waf_panel_hit()`, `waf_panel_enforce()` bekommen `$catalog` als optionalen letzten Parameter |
| `ispconfig/interface/lang/de_malwatch_waf_rules.lng`, `en_malwatch_waf_rules.lng` | neu: Regelkatalog und Gruppentexte |
| `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` | Klassen, Stellen, Sätze, Beschriftungen der Karten und Treffer, Gruppennamen 910, 912, 922 |
| `ispconfig/interface/malwatch_waf_show.php` | Katalog laden, Karten mit Adressen, Auslösern und Einordnung, Adressfilter, Treffer mit Auslöser und Einordnung |
| `ispconfig/interface/templates/malwatch_waf_show.htm` | Markup und Stil der Karten und Treffer |
| `ispconfig/interface/malwatch_waf_list.php`, `malwatch_waf_exception_list.php` | Titel aus dem Katalog |
| `ispconfig/install/schema.sql` | Spalte `waf_card_hits` (A1), Index `site_ip` (A8) |
| `ispconfig/interface/lib/malwatch_waf_lib.inc.php`, `ispconfig/interface/form/malwatch_waf_config.tform.php`, `ispconfig/interface/templates/malwatch_waf_config_edit.htm`, `ispconfig/interface/lang/de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng` | Einstellung `waf_card_hits` |
| `ispconfig/install/file.list` | die beiden Katalogdateien |
| `ispconfig/tests/fixtures/crs-3.3.5-pl1-rule-ids.txt` | neu: die 170 Regel-IDs |
| `ispconfig/tests/waf_rules_catalog_test.php` | neu: Vollständigkeit und Form des Katalogs |
| `ispconfig/tests/waf_panel_test.php` | Tests der neuen Funktionen |
| `ispconfig/tests/check_wiring.sh` | Prüfungen 64 bis 66 und Spalte in Prüfung 51 |
| `ispconfig/tests/render_pages.php` | Website-Seite mit Adressfilter |
| `.superpowers/abwehr/harness/fake_db.php`, `build_all.sh` (nur auf diesem Rechner, git-ignoriert) | Beispieldaten und Renderläufe für die Website-Seite |
| `.github/workflows/ci.yml` | Katalogtest in der CI |
| `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md` | Präzisierungen |
| `CHANGELOG.md`, `README.md`, `ispconfig/README.md`, `internal/version/version.go`, `ispconfig/version` | Release 0.20.0 |

---

### Task A1: Einstellung für die Obergrenze der Regel-Karten

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_lib.inc.php` (`waf_settings_defaults()`, `waf_settings_limits()`)
- Modify: `ispconfig/install/schema.sql` (neuer bedingter `ALTER TABLE` nach dem Block der Abwehr-Einstellungen)
- Modify: `ispconfig/interface/form/malwatch_waf_config.tform.php` (Feld nach `waf_job_deadline_minutes`)
- Modify: `ispconfig/interface/templates/malwatch_waf_config_edit.htm` (Abschnitt „Anzeige" vor „Cron")
- Modify: `ispconfig/interface/lang/de_malwatch_waf_config.lng`, `ispconfig/interface/lang/en_malwatch_waf_config.lng`
- Modify: `ispconfig/tests/check_wiring.sh` (Prüfung 51)
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_settings($row)` aus `malwatch_waf_lib.inc.php`
- Produces: `waf_settings(...)['waf_card_hits']` (int, 100 bis 100000, Vorgabe 5000); Task A7 liest den Wert

- [ ] **Step 1: Test schreiben**

In `ispconfig/tests/waf_panel_test.php` direkt vor der Zeile `// --- summary -----------------------------------------------------------------` einfügen:

```php
// --- A1: how many hits the rule cards read -------------------------------------

$card = waf_settings(array());
expect_same('card hits default', isset($card['waf_card_hits']) ? $card['waf_card_hits'] : null, 5000);
$card = waf_settings(array('waf_card_hits' => '99'));
expect_same('card hits floor', isset($card['waf_card_hits']) ? $card['waf_card_hits'] : null, 100);
$card = waf_settings(array('waf_card_hits' => '250000'));
expect_same('card hits ceiling', isset($card['waf_card_hits']) ? $card['waf_card_hits'] : null, 100000);

// A range message names the limits of its field and what to do next.
foreach (waf_settings_limits() as $key => $limit) {
	$errmsg = isset($config_tab['fields'][$key]['validators'][0]['errmsg']) ? $config_tab['fields'][$key]['validators'][0]['errmsg'] : '';
	$de = isset($config_words['de'][$errmsg]) ? $config_words['de'][$errmsg] : '';
	$en = isset($config_words['en'][$errmsg]) ? $config_words['en'][$errmsg] : '';
	expect_same("range message of $key", array(
		strpos($de, $limit[0] . ' bis ' . $limit[1]) !== false, strpos($de, 'erneut speichern') !== false,
		strpos($en, $limit[0] . ' to ' . $limit[1]) !== false, strpos($en, 'save again') !== false,
	), array(true, true, true, true));
}
```

Die Schleife setzt die Regel „Verständliche Fehlermeldungen“ um: Jede Bereichsmeldung nennt Feld, Grenzen und den nächsten Schritt.

In `ispconfig/tests/check_wiring.sh`, Prüfung 51, die Spaltenliste um `waf_card_hits` ergänzen:

```sh
for col in waf_detail_days waf_stats_days waf_log_keep_days waf_preview_days waf_min_detect_days \
	waf_response_body waf_ingest_max_lines waf_job_deadline_minutes waf_audit_log waf_conf_dir \
	waf_emergency waf_emergency_since waf_card_hits; do
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `10 Fehler`, Exit-Code 1: `FAIL card hits default: NULL, erwartet 5000`, `FAIL card hits floor`, `FAIL card hits ceiling` und `FAIL range message of …` für die sieben bisherigen Felder (Grenzen stimmen, der nächste Schritt fehlt).

- [ ] **Step 3: Vorgabe und Grenze**

In `ispconfig/interface/lib/malwatch_waf_lib.inc.php`, `waf_settings_defaults()`, nach `'waf_emergency_since' => null,` einfügen:

```php
		'waf_card_hits' => 5000,
```

In `waf_settings_limits()` nach `'waf_job_deadline_minutes' => array(2, 120),` einfügen:

```php
		'waf_card_hits' => array(100, 100000),
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `14 Fehler`: `settings form edits the numbers only`, die Prüfungen `settings form type of waf_card_hits`, `… range of …`, `… default of …`, `… message of …`, `… label of …` und `range message of …` für alle acht Felder. Die drei Prüfungen `card hits …` bestehen.

- [ ] **Step 5: Formular, Vorlage, Texte, Schema**

In `ispconfig/interface/form/malwatch_waf_config.tform.php` das Feld `waf_job_deadline_minutes` so abschließen und das neue Feld anhängen (die Reihenfolge der Felder muss der von `waf_settings_limits()` entsprechen):

```php
		'waf_job_deadline_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '2:120',
					'errmsg' => 'waf_job_deadline_minutes_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_card_hits' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '100:100000',
					'errmsg' => 'waf_card_hits_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		)
	)
);
```

In `ispconfig/interface/templates/malwatch_waf_config_edit.htm` vor `<p class="mw-wafcfg-head">{tmpl_var name='cron_head_txt'}</p>` einfügen:

```html
<p class="mw-wafcfg-head">{tmpl_var name='display_head_txt'}</p>

<div class="form-group">
	<label for="waf_card_hits" class="col-sm-3 control-label">{tmpl_var name='waf_card_hits_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="100" max="100000" step="1" name="waf_card_hits" id="waf_card_hits" value="{tmpl_var name='waf_card_hits'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_card_hits_hint_txt'}</span>
	</div>
</div>

```

In `ispconfig/interface/lang/de_malwatch_waf_config.lng` vor `$wb['cron_head_txt'] = 'Cron';` einfügen:

```php
$wb['display_head_txt'] = 'Anzeige';
$wb['waf_card_hits_txt'] = 'Einzeltreffer für die Regel-Karten';
$wb['waf_card_hits_hint_txt'] = 'So viele jüngste Einzeltreffer einer Website liest die Seite, um je Regel Adressen und Auslöser zu zeigen. Ein höherer Wert zeigt mehr Adressen und verlängert den Seitenaufbau.';

```

und die sieben Zeilen von `$wb['waf_detail_days_error_range']` bis `$wb['waf_job_deadline_minutes_error_range']` am Dateiende ersetzen durch:

```php
$wb['waf_detail_days_error_range'] = 'Einzelne Anfragen (Tage): Erlaubt sind ganze Zahlen von 1 bis 3650. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_stats_days_error_range'] = 'Tageszahlen (Tage): Erlaubt sind ganze Zahlen von 1 bis 3650. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_log_keep_days_error_range'] = 'Audit-Log (Tage): Erlaubt sind ganze Zahlen von 1 bis 365. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_preview_days_error_range'] = 'Vorschau (Tage): Erlaubt sind ganze Zahlen von 1 bis 365. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_min_detect_days_error_range'] = 'Mitschreiben vor „scharf“ (Tage): Erlaubt sind ganze Zahlen von 0 bis 365. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ingest_max_lines_error_range'] = 'Zeilen je Durchgang: Erlaubt sind ganze Zahlen von 100 bis 100000. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_job_deadline_minutes_error_range'] = 'Frist für den vhost (Minuten): Erlaubt sind ganze Zahlen von 2 bis 120. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_card_hits_error_range'] = 'Einzeltreffer für die Regel-Karten: Erlaubt sind ganze Zahlen von 100 bis 100000. Bitte den Wert anpassen und erneut speichern.';
```

In `ispconfig/interface/lang/en_malwatch_waf_config.lng` an denselben Stellen:

```php
$wb['display_head_txt'] = 'Display';
$wb['waf_card_hits_txt'] = 'Single hits for the rule cards';
$wb['waf_card_hits_hint_txt'] = 'The page reads this many of the latest single hits of a website to show addresses and triggers per rule. A higher value shows more addresses and makes the page slower to build.';

```

```php
$wb['waf_detail_days_error_range'] = 'Single requests (days): whole numbers from 1 to 3650 are allowed. Please adjust the value and save again.';
$wb['waf_stats_days_error_range'] = 'Day figures (days): whole numbers from 1 to 3650 are allowed. Please adjust the value and save again.';
$wb['waf_log_keep_days_error_range'] = 'Audit log (days): whole numbers from 1 to 365 are allowed. Please adjust the value and save again.';
$wb['waf_preview_days_error_range'] = 'Preview (days): whole numbers from 1 to 365 are allowed. Please adjust the value and save again.';
$wb['waf_min_detect_days_error_range'] = 'Detect before "enforce" (days): whole numbers from 0 to 365 are allowed. Please adjust the value and save again.';
$wb['waf_ingest_max_lines_error_range'] = 'Lines per pass: whole numbers from 100 to 100000 are allowed. Please adjust the value and save again.';
$wb['waf_job_deadline_minutes_error_range'] = 'Deadline for the vhost (minutes): whole numbers from 2 to 120 are allowed. Please adjust the value and save again.';
$wb['waf_card_hits_error_range'] = 'Single hits for the rule cards: whole numbers from 100 to 100000 are allowed. Please adjust the value and save again.';
```

In `ispconfig/install/schema.sql` vor der Zeile `-- waf carries the jobs of the page Abwehr. The malwatch cron works on them` einfügen:

```sql
-- How many of the latest hits of a website the rule cards read; default as in waf_settings_defaults().
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_card_hits` int(11) unsigned NOT NULL DEFAULT ''5000''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_card_hits');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

```

- [ ] **Step 6: Tests laufen lassen**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_lib_test.php`
Expected: `waf_panel: alle Prüfungen bestanden` und `waf_lib: alle Prüfungen bestanden`.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 7: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/install/schema.sql ispconfig/interface/form/malwatch_waf_config.tform.php ispconfig/interface/templates/malwatch_waf_config_edit.htm ispconfig/interface/lang/de_malwatch_waf_config.lng ispconfig/interface/lang/en_malwatch_waf_config.lng ispconfig/tests/check_wiring.sh ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): setting for how many hits the rule cards read" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A2: Auslöser eines Treffers in Worten

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (neue Funktionen nach `waf_panel_rule_title()`)
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `ispconfig/interface/lang/en_malwatch_waf.lng` (Block am Dateiende)
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_panel_text($wb, $key, $fallback)`, `waf_cut($text, $bytes)`
- Produces:
  - `waf_panel_trigger_parts($data)` → `array('form' => 'matched'|'assign'|'header'|'plain'|'none', 'piece' => string, 'target' => string, 'value' => string)`
  - `waf_panel_target_label($wb, $target)` → string
  - `waf_panel_trigger_text($wb, $data, $pattern)` → string, `''` ohne Auslöser; `$pattern` ist die Vorlage `rule_<id>_trigger` aus dem Katalog oder `''`

- [ ] **Step 1: Test schreiben**

In `ispconfig/tests/waf_panel_test.php` vor dem Block `// --- A1: how many hits the rule cards read` einfügen:

```php
// --- A2: triggers --------------------------------------------------------------

expect_same('trigger parts matched', waf_panel_trigger_parts('Matched Data: <script> found within ARGS:q: <script>alert(1)</script>'),
	array('form' => 'matched', 'piece' => '<script>', 'target' => 'ARGS:q', 'value' => '<script>alert(1)</script>'));
expect_same('trigger parts with a colon in the value', waf_panel_trigger_parts('Matched Data: $((41*271)) found within ARGS:0: {then: $1:__proto__:then}'),
	array('form' => 'matched', 'piece' => '$((41*271))', 'target' => 'ARGS:0', 'value' => '{then: $1:__proto__:then}'));
expect_same('trigger parts without value', waf_panel_trigger_parts('Matched Data: zip://x found within ARGS:file'),
	array('form' => 'matched', 'piece' => 'zip://x', 'target' => 'ARGS:file', 'value' => ''));
expect_same('trigger parts of a form part', waf_panel_trigger_parts('Matched Data: utf-7 found within Content-Type multipart form'),
	array('form' => 'matched', 'piece' => 'utf-7', 'target' => 'Content-Type multipart form', 'value' => ''));
expect_same('trigger parts assignment', waf_panel_trigger_parts('ARGS_NAMES:aaaa=aaaa'),
	array('form' => 'assign', 'piece' => '', 'target' => 'ARGS_NAMES:aaaa', 'value' => 'aaaa'));
expect_same('trigger parts header', waf_panel_trigger_parts('Restricted header detected: /accept-charset/'),
	array('form' => 'header', 'piece' => '', 'target' => '', 'value' => 'accept-charset'));
expect_same('trigger parts plain', waf_panel_trigger_parts('.bak'),
	array('form' => 'plain', 'piece' => '', 'target' => '', 'value' => '.bak'));
expect_same('trigger parts plain with prefix', waf_panel_trigger_parts('Matched Data: utf-7'),
	array('form' => 'plain', 'piece' => '', 'target' => '', 'value' => 'utf-7'));
expect_same('trigger parts empty', waf_panel_trigger_parts('  '),
	array('form' => 'none', 'piece' => '', 'target' => '', 'value' => ''));

expect_same('target parameter', waf_panel_target_label($wb, 'ARGS:q'), 'Parameter „q“');
expect_same('target post parameter', waf_panel_target_label($wb, 'ARGS_POST:json.content'), 'Parameter „json.content“');
expect_same('target parameter names', waf_panel_target_label($wb, 'ARGS_NAMES:aaaa'), 'Name eines Parameters');
expect_same('target file name', waf_panel_target_label($wb, 'REQUEST_FILENAME'), 'Dateiname der Anfrage');
expect_same('target base name', waf_panel_target_label($wb, 'REQUEST_BASENAME'), 'Dateiname der Anfrage');
expect_same('target address', waf_panel_target_label($wb, 'REQUEST_URI_RAW'), 'Adresse der Anfrage');
expect_same('target request line', waf_panel_target_label($wb, 'REQUEST_LINE'), 'Anfragezeile');
expect_same('target query', waf_panel_target_label($wb, 'QUERY_STRING'), 'Parameterteil der Adresse');
expect_same('target header', waf_panel_target_label($wb, 'REQUEST_HEADERS:User-Agent'), 'Kopfzeile „User-Agent“');
expect_same('target header names', waf_panel_target_label($wb, 'REQUEST_HEADERS_NAMES:x-foo'), 'Name einer Kopfzeile');
expect_same('target cookie', waf_panel_target_label($wb, 'REQUEST_COOKIES:sid'), 'Cookie „sid“');
expect_same('target cookie names', waf_panel_target_label($wb, 'REQUEST_COOKIES_NAMES:sid'), 'Name eines Cookies');
expect_same('target body', waf_panel_target_label($wb, 'REQUEST_BODY'), 'Anfrageinhalt');
expect_same('target xml', waf_panel_target_label($wb, 'XML:/*'), 'XML-Inhalt');
expect_same('target files', waf_panel_target_label($wb, 'FILES:upload'), 'Name einer hochgeladenen Datei');
expect_same('target files names', waf_panel_target_label($wb, 'FILES_NAMES'), 'Name einer hochgeladenen Datei');
expect_same('target method', waf_panel_target_label($wb, 'REQUEST_METHOD'), 'Methode');
expect_same('target protocol', waf_panel_target_label($wb, 'REQUEST_PROTOCOL'), 'Protokoll');
expect_same('target unknown', waf_panel_target_label($wb, 'TX:extension'), 'TX:extension');
expect_same('target parameter without a name', waf_panel_target_label($wb, 'ARGS'), 'ARGS');

expect_same('trigger text contains', waf_panel_trigger_text($wb, 'Matched Data: .env found within REQUEST_FILENAME: /.env', ''),
	'Dateiname der Anfrage enthält „.env“');
expect_same('trigger text with a fixed piece', waf_panel_trigger_text($wb, 'Matched Data: XSS data found within ARGS:q: <script>alert(1)</script>', ''),
	'Parameter „q“: <script>alert(1)</script>');
expect_same('trigger text assignment', waf_panel_trigger_text($wb, 'REQUEST_HEADERS:Content-Length=abc', ''),
	'Kopfzeile „Content-Length“: abc');
expect_same('trigger text header', waf_panel_trigger_text($wb, 'Restricted header detected: /proxy/', ''), 'Kopfzeile „proxy“');
expect_same('trigger text with pattern', waf_panel_trigger_text($wb, '.bak', 'Dateiendung „%s“'), 'Dateiendung „.bak“');
expect_same('trigger text without pattern', waf_panel_trigger_text($wb, '.bak', ''), 'Gefunden: „.bak“');
expect_same('trigger text with a broken pattern', waf_panel_trigger_text($wb, 'x', 'Wert %d und %s'), 'Gefunden: „x“');
expect_same('trigger text empty', waf_panel_trigger_text($wb, '', 'Dateiendung „%s“'), '');
expect_same('trigger text keeps percent signs', waf_panel_trigger_text($wb, 'Matched Data: %s%n found within ARGS:x: %s%n', ''),
	'Parameter „x“ enthält „%s%n“');
expect_same('trigger text cuts the piece',
	strlen(waf_panel_trigger_text($wb, 'Matched Data: ' . str_repeat('a', 200) . ' found within ARGS:x', '')),
	strlen('Parameter „x“ enthält „“') + 120);
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit `PHP Fatal error:  Uncaught Error: Call to undefined function waf_panel_trigger_parts()`.

- [ ] **Step 3: Funktionen schreiben**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` direkt nach der Funktion `waf_panel_rule_title()` einfügen:

```php
/**
 * The parts of a rule's data in an audit entry. CRS writes most rules as
 * "Matched Data: <piece> found within <target>: <value>"; some write
 * "<target>=<value>", 920450 writes "Restricted header detected: /<name>/",
 * and the rest only a value. form is matched, assign, header, plain or none.
 */
function waf_panel_trigger_parts($data)
{
	$data = trim((string) $data);
	$parts = array('form' => 'none', 'piece' => '', 'target' => '', 'value' => '');
	if ($data === '') {
		return $parts;
	}
	if (preg_match('/^Matched Data: (.*?) found within (.+?)(?:: (.*))?$/s', $data, $m)) {
		$parts['form'] = 'matched';
		$parts['piece'] = $m[1];
		$parts['target'] = $m[2];
		$parts['value'] = isset($m[3]) ? $m[3] : '';
		return $parts;
	}
	if (preg_match('/^([A-Z_]+(?::[^=]*)?)=(.*)$/s', $data, $m)) {
		$parts['form'] = 'assign';
		$parts['target'] = $m[1];
		$parts['value'] = $m[2];
		return $parts;
	}
	if (preg_match('#^Restricted header detected: /?(.*?)/?$#s', $data, $m)) {
		$parts['form'] = 'header';
		$parts['value'] = $m[1];
		return $parts;
	}
	$parts['form'] = 'plain';
	$parts['value'] = preg_replace('/^Matched Data: /', '', $data);
	return $parts;
}

/** A variable of ModSecurity in words; one the page does not know stays as it is. */
function waf_panel_target_label($wb, $target)
{
	$target = (string) $target;
	$pos = strpos($target, ':');
	$base = $pos === false ? $target : substr($target, 0, $pos);
	$name = $pos === false ? '' : substr($target, $pos + 1);
	$named = array(
		'ARGS' => 'target_param_txt', 'ARGS_GET' => 'target_param_txt', 'ARGS_POST' => 'target_param_txt',
		'REQUEST_HEADERS' => 'target_header_txt', 'REQUEST_COOKIES' => 'target_cookie_txt',
	);
	$plain = array(
		'ARGS_NAMES' => 'target_param_names_txt', 'ARGS_GET_NAMES' => 'target_param_names_txt',
		'ARGS_POST_NAMES' => 'target_param_names_txt',
		'REQUEST_FILENAME' => 'target_filename_txt', 'REQUEST_BASENAME' => 'target_filename_txt',
		'REQUEST_URI' => 'target_uri_txt', 'REQUEST_URI_RAW' => 'target_uri_txt',
		'REQUEST_LINE' => 'target_request_line_txt', 'QUERY_STRING' => 'target_query_txt',
		'REQUEST_HEADERS_NAMES' => 'target_header_names_txt', 'REQUEST_COOKIES_NAMES' => 'target_cookie_names_txt',
		'REQUEST_BODY' => 'target_body_txt', 'XML' => 'target_xml_txt',
		'FILES' => 'target_files_txt', 'FILES_NAMES' => 'target_files_txt',
		'REQUEST_METHOD' => 'target_method_txt', 'REQUEST_PROTOCOL' => 'target_protocol_txt',
	);
	if (isset($named[$base]) && $name !== '') {
		return sprintf(waf_panel_text($wb, $named[$base], '%s'), $name);
	}
	if (isset($plain[$base])) {
		return waf_panel_text($wb, $plain[$base], $target);
	}
	return $target;
}

/**
 * The trigger of one rule in a hit as a sentence, '' when the data names
 * none. $pattern comes from the catalog (rule_<id>_trigger) and words data
 * that carries a value only; it must hold exactly one %s.
 */
function waf_panel_trigger_text($wb, $data, $pattern)
{
	$parts = waf_panel_trigger_parts($data);
	$piece = waf_cut($parts['piece'], 120);
	$value = waf_cut($parts['value'], 120);
	// Pieces CRS writes as fixed words say nothing; the value does.
	if (in_array($piece, array('XSS data', 'Suspicious payload', 'Suspicious JS global variable'), true)) {
		$piece = '';
	}
	if ($parts['form'] === 'matched' || $parts['form'] === 'assign') {
		$target = waf_panel_target_label($wb, $parts['target']);
		if ($piece !== '') {
			return sprintf(waf_panel_text($wb, 'trigger_contains_txt', '%1$s: %2$s'), $target, $piece);
		}
		return $value !== '' ? sprintf(waf_panel_text($wb, 'trigger_value_txt', '%1$s: %2$s'), $target, $value) : $target;
	}
	if ($parts['form'] === 'header') {
		return sprintf(waf_panel_text($wb, 'target_header_txt', '%s'), $value);
	}
	if ($parts['form'] === 'plain') {
		$pattern = (string) $pattern;
		if (!preg_match('/^[^%]*%s[^%]*$/', $pattern)) {
			$pattern = waf_panel_text($wb, 'trigger_found_txt', '%s');
		}
		return sprintf($pattern, $value);
	}
	return '';
}
```

Am Ende von `ispconfig/interface/lang/de_malwatch_waf.lng` anhängen:

```php

// Where a rule matched, and the sentences around it.
$wb['target_param_txt'] = 'Parameter „%s“';
$wb['target_param_names_txt'] = 'Name eines Parameters';
$wb['target_filename_txt'] = 'Dateiname der Anfrage';
$wb['target_uri_txt'] = 'Adresse der Anfrage';
$wb['target_request_line_txt'] = 'Anfragezeile';
$wb['target_query_txt'] = 'Parameterteil der Adresse';
$wb['target_header_txt'] = 'Kopfzeile „%s“';
$wb['target_header_names_txt'] = 'Name einer Kopfzeile';
$wb['target_cookie_txt'] = 'Cookie „%s“';
$wb['target_cookie_names_txt'] = 'Name eines Cookies';
$wb['target_body_txt'] = 'Anfrageinhalt';
$wb['target_xml_txt'] = 'XML-Inhalt';
$wb['target_files_txt'] = 'Name einer hochgeladenen Datei';
$wb['target_method_txt'] = 'Methode';
$wb['target_protocol_txt'] = 'Protokoll';
$wb['trigger_contains_txt'] = '%1$s enthält „%2$s“';
$wb['trigger_value_txt'] = '%1$s: %2$s';
$wb['trigger_found_txt'] = 'Gefunden: „%s“';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf.lng` anhängen:

```php

// Where a rule matched, and the sentences around it.
$wb['target_param_txt'] = 'Parameter "%s"';
$wb['target_param_names_txt'] = 'Name of a parameter';
$wb['target_filename_txt'] = 'File name of the request';
$wb['target_uri_txt'] = 'Address of the request';
$wb['target_request_line_txt'] = 'Request line';
$wb['target_query_txt'] = 'Query string';
$wb['target_header_txt'] = 'Header "%s"';
$wb['target_header_names_txt'] = 'Name of a header';
$wb['target_cookie_txt'] = 'Cookie "%s"';
$wb['target_cookie_names_txt'] = 'Name of a cookie';
$wb['target_body_txt'] = 'Request body';
$wb['target_xml_txt'] = 'XML body';
$wb['target_files_txt'] = 'Name of an uploaded file';
$wb['target_method_txt'] = 'Method';
$wb['target_protocol_txt'] = 'Protocol';
$wb['trigger_contains_txt'] = '%1$s contains "%2$s"';
$wb['trigger_value_txt'] = '%1$s: %2$s';
$wb['trigger_found_txt'] = 'Found: "%s"';
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_panel_test.php && php -l ispconfig/interface/lib/malwatch_waf_panel.inc.php`
Expected: `waf_panel: alle Prüfungen bestanden` und `No syntax errors detected`.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the trigger of a hit in words" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A3: Regelkatalog, Grundgerüst und Gruppen 910 bis 922

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (`waf_panel_rule_title()` erweitern, neue Funktionen davor)
- Create: `ispconfig/interface/lang/de_malwatch_waf_rules.lng`, `ispconfig/interface/lang/en_malwatch_waf_rules.lng`
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `ispconfig/interface/lang/en_malwatch_waf.lng` (Gruppennamen, Klassen)
- Create: `ispconfig/tests/fixtures/crs-3.3.5-pl1-rule-ids.txt`
- Create: `ispconfig/tests/waf_rules_catalog_test.php`
- Modify: `ispconfig/tests/waf_panel_test.php`
- Modify: `ispconfig/install/file.list`, `.github/workflows/ci.yml`
- Modify: `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`

**Interfaces:**
- Consumes: `waf_panel_text()`, die Gruppennamen `group_9xx_txt`
- Produces:
  - `waf_panel_rule_classes()` → `array('scanner', 'attack', 'false_positive_prone', 'protocol', 'scoring', 'response')`
  - `waf_panel_rule_catalog_file($dir, $language)` → Pfad der Katalogdatei, Englisch als Rückfall
  - `waf_panel_rule_catalog($file)` → `array('rules' => array(<id> => array('title','what','class','note','trigger' soweit vorhanden)), 'groups' => array(<ggg> => array('what','class')))`. PHP macht aus den IDs Ganzzahl-Schlüssel; Zugriffe mit der ID als Zeichenkette funktionieren trotzdem.
  - `waf_panel_rule_info($wb, $catalog, $rule_id, $message)` → `array('rule_id','title','what','class','class_label','class_text','note','trigger','crs')`
  - `waf_panel_rule_title($wb, $rule_id, $message, $catalog = array())`

- [ ] **Step 1: Tests schreiben**

In `ispconfig/tests/waf_panel_test.php` vor dem Block `// --- A2: triggers` einfügen:

```php
// --- A3: rule catalog ----------------------------------------------------------

expect_same('rule classes', waf_panel_rule_classes(),
	array('scanner', 'attack', 'false_positive_prone', 'protocol', 'scoring', 'response'));

$catalog = array(
	'rules' => array('930130' => array('title' => 'Zugriff auf geschützte Datei', 'what' => 'Liest .env.', 'class' => 'scanner',
		'note' => 'Hinweis.', 'trigger' => '')),
	'groups' => array(
		'942' => array('what' => 'SQL-Bausteine.', 'class' => 'false_positive_prone'),
		'941' => array('what' => 'Skripte.', 'class' => 'kaputt'),
	),
);
$info = waf_panel_rule_info($wb, $catalog, '930130', 'Restricted File Access Attempt');
expect_same('rule info from the catalog',
	array($info['rule_id'], $info['title'], $info['what'], $info['class'], $info['class_label'], $info['note'], $info['crs']),
	array('930130', 'Zugriff auf geschützte Datei', 'Liest .env.', 'scanner', 'Scanner', 'Hinweis.', 'Restricted File Access Attempt'));
expect_same('rule info class text', $info['class_text'],
	'Typisch für automatische Scanner. Antwortet die Website mit 404 oder 403, wurde nichts geliefert.');
$info = waf_panel_rule_info($wb, $catalog, '942999', 'Some SQL rule');
expect_same('rule info from the group', array($info['title'], $info['what'], $info['class'], $info['class_label'], $info['trigger']),
	array('SQL-Einschleusung', 'SQL-Bausteine.', 'false_positive_prone', 'Fehlalarm möglich', ''));
$info = waf_panel_rule_info($wb, $catalog, '941999', 'XSS rule');
expect_same('rule info with a wrong class', array($info['class'], $info['class_label'], $info['class_text']), array('', '', ''));
$info = waf_panel_rule_info($wb, array(), '10010', 'own rule');
expect_same('rule info without a catalog', array($info['title'], $info['what'], $info['class']), array('own rule', '', ''));
expect_same('rule title from the catalog', waf_panel_rule_title($wb, '930130', 'x', $catalog), 'Zugriff auf geschützte Datei');
expect_same('group titles 910 912 922', array(
	waf_panel_rule_title($wb, '910999', ''), waf_panel_rule_title($wb, '912999', ''), waf_panel_rule_title($wb, '922999', ''),
), array('Bekannte Angreiferadresse', 'Überlastungsangriff', 'Mehrteiliges Formular'));

$rules_file = tempnam(sys_get_temp_dir(), 'mwrules');
file_put_contents($rules_file, "<?php\n\$wb['rule_930130_title'] = 'T';\n\$wb['rule_930130_class'] = 'scanner';\n"
	. "\$wb['group_942_what'] = 'W';\n\$wb['other_txt'] = 'x';\n\$wb['rule_12_title'] = 'kurz';\n");
$read = waf_panel_rule_catalog($rules_file);
expect_same('rule catalog from a file', array($read['rules']['930130'], $read['groups']['942'], count($read['rules'])),
	array(array('title' => 'T', 'class' => 'scanner'), array('what' => 'W'), 1));
unlink($rules_file);
expect_same('rule catalog of a missing file', waf_panel_rule_catalog(__DIR__ . '/no-such-file.lng'),
	array('rules' => array(), 'groups' => array()));

$rules_dir = sys_get_temp_dir() . '/mwrules' . getmypid();
@mkdir($rules_dir);
touch($rules_dir . '/en_malwatch_waf_rules.lng');
touch($rules_dir . '/de_malwatch_waf_rules.lng');
expect_same('rule catalog file of a language', waf_panel_rule_catalog_file($rules_dir, 'de'), $rules_dir . '/de_malwatch_waf_rules.lng');
expect_same('rule catalog file falls back to English', waf_panel_rule_catalog_file($rules_dir, 'fr'), $rules_dir . '/en_malwatch_waf_rules.lng');
expect_same('rule catalog file with a strange language', waf_panel_rule_catalog_file($rules_dir . '/', '../x'), $rules_dir . '/en_malwatch_waf_rules.lng');
unlink($rules_dir . '/en_malwatch_waf_rules.lng');
unlink($rules_dir . '/de_malwatch_waf_rules.lng');
rmdir($rules_dir);
```

`ispconfig/tests/fixtures/crs-3.3.5-pl1-rule-ids.txt` anlegen, eine ID je Zeile:

```text
# Rules of CRS 3.3.5 that run at paranoia level 1, as installed on
# web.herkules on 2026-09-17: the 164 rules tagged paranoia-level/1, 920181
# and 921200 (in the level 1 part without that tag), and the scoring rules
# 949110, 959100, 980130 and 980140.
910000
910100
910150
910160
910170
910180
911100
912120
912170
913100
913110
913120
920100
920120
920160
920170
920171
920180
920181
920190
920210
920220
920240
920250
920260
920270
920280
920290
920310
920311
920330
920340
920350
920360
920370
920380
920390
920400
920410
920420
920430
920440
920450
920470
920480
920500
920530
920600
920620
921110
921120
921130
921140
921150
921160
921190
921200
921421
922100
922110
922120
930100
930110
930120
930130
931100
931110
931120
932100
932105
932110
932115
932120
932130
932140
932150
932160
932170
932171
932180
933100
933110
933120
933130
933140
933150
933160
933170
933180
933200
933210
934100
941100
941110
941120
941130
941140
941160
941170
941180
941190
941200
941210
941220
941230
941240
941250
941260
941270
941280
941290
941300
941310
941350
941360
941370
942100
942140
942160
942170
942190
942220
942230
942240
942250
942270
942280
942290
942320
942350
942360
942500
943100
943110
943120
944100
944110
944120
944130
949110
950130
950140
951110
951120
951130
951140
951150
951160
951170
951180
951190
951200
951210
951220
951230
951240
951250
951260
952100
952110
953100
953110
953120
954100
954110
954120
954130
959100
980130
980140
```

`ispconfig/tests/waf_rules_catalog_test.php` anlegen:

```php
<?php
/**
 * Checks the rule catalog of the Abwehr pages: the rules CRS 3.3.5 runs at
 * paranoia level 1 (tests/fixtures/crs-3.3.5-pl1-rule-ids.txt) have a German
 * and an English entry, every group has its texts, and both files agree.
 *
 *   php ispconfig/tests/waf_rules_catalog_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_panel.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

function catalog_words($lang)
{
	$wb = array();
	$file = __DIR__ . '/../interface/lang/' . $lang . '_malwatch_waf_rules.lng';
	if (is_file($file)) {
		include $file;
	}
	return $wb;
}

$ids = array();
foreach (file(__DIR__ . '/fixtures/crs-3.3.5-pl1-rule-ids.txt') as $line) {
	$line = trim($line);
	if ($line !== '' && $line[0] !== '#') {
		$ids[] = $line;
	}
}
expect_same('fixture size', count($ids), 170);

// The groups the catalog covers so far; the following tasks add theirs.
$covered = array('910', '911', '912', '913', '920', '921', '922');
$all_groups = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934',
	'941', '942', '943', '944', '949', '950', '951', '952', '953', '954', '959', '980');

$words = array('de' => catalog_words('de'), 'en' => catalog_words('en'));
expect_same('same keys in both languages', array(
	array_values(array_diff(array_keys($words['de']), array_keys($words['en']))),
	array_values(array_diff(array_keys($words['en']), array_keys($words['de']))),
), array(array(), array()));

$catalogs = array();
foreach (array('de', 'en') as $lang) {
	$catalogs[$lang] = waf_panel_rule_catalog(__DIR__ . '/../interface/lang/' . $lang . '_malwatch_waf_rules.lng');
	foreach (array_keys($words[$lang]) as $key) {
		expect_same("$lang key $key has a known form",
			preg_match('/^(rule_\d{3,7}_(title|what|class|note|trigger)|group_\d{3}_(what|class))$/', (string) $key), 1);
	}
	foreach (array_keys($catalogs[$lang]['rules']) as $id) {
		expect_same("$lang rule $id is in the fixture", in_array((string) $id, $ids, true), true);
	}
}

foreach ($ids as $id) {
	if (!in_array(substr($id, 0, 3), $covered, true)) {
		continue;
	}
	foreach (array('de', 'en') as $lang) {
		$entry = isset($catalogs[$lang]['rules'][$id]) ? $catalogs[$lang]['rules'][$id] : array();
		$title = isset($entry['title']) ? $entry['title'] : '';
		expect_same("$lang $id title", $title !== '' && preg_match_all('/./u', $title) <= 48, true);
		expect_same("$lang $id what", isset($entry['what']) && trim($entry['what']) !== '', true);
		expect_same("$lang $id class", isset($entry['class']) && in_array($entry['class'], waf_panel_rule_classes(), true), true);
		if (isset($entry['trigger'])) {
			expect_same("$lang $id trigger holds one %s", preg_match('/^[^%]*%s[^%]*$/', $entry['trigger']), 1);
		}
	}
	expect_same("$id same class in both languages",
		isset($catalogs['de']['rules'][$id]['class'], $catalogs['en']['rules'][$id]['class'])
			&& $catalogs['de']['rules'][$id]['class'] === $catalogs['en']['rules'][$id]['class'], true);
	expect_same("$id same optional fields in both languages",
		array_keys(isset($catalogs['de']['rules'][$id]) ? $catalogs['de']['rules'][$id] : array()),
		array_keys(isset($catalogs['en']['rules'][$id]) ? $catalogs['en']['rules'][$id] : array()));
}

foreach ($all_groups as $group) {
	foreach (array('de', 'en') as $lang) {
		$entry = isset($catalogs[$lang]['groups'][$group]) ? $catalogs[$lang]['groups'][$group] : array();
		expect_same("$lang group $group what", isset($entry['what']) && trim($entry['what']) !== '', true);
		expect_same("$lang group $group class", isset($entry['class']) && in_array($entry['class'], waf_panel_rule_classes(), true), true);
	}
	expect_same("group $group same class in both languages",
		isset($catalogs['de']['groups'][$group]['class'], $catalogs['en']['groups'][$group]['class'])
			&& $catalogs['de']['groups'][$group]['class'] === $catalogs['en']['groups'][$group]['class'], true);
}

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_rules_catalog: alle Prüfungen bestanden\n";
```

- [ ] **Step 2: Tests laufen lassen, sie müssen scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit `Call to undefined function waf_panel_rule_classes()`.

Run: `php ispconfig/tests/waf_rules_catalog_test.php`
Expected: Abbruch mit `Call to undefined function waf_panel_rule_catalog()`.

- [ ] **Step 3: Funktionen schreiben**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` die Funktion `waf_panel_rule_title()` samt Kommentar ersetzen durch:

```php
/**
 * The heading of a rule: its title in the catalog, else its CRS group in
 * words, else the CRS message, else its number.
 */
function waf_panel_rule_title($wb, $rule_id, $message, $catalog = array())
{
	$rule_id = (string) $rule_id;
	if (isset($catalog['rules'][$rule_id]['title']) && (string) $catalog['rules'][$rule_id]['title'] !== '') {
		return (string) $catalog['rules'][$rule_id]['title'];
	}
	if (preg_match('/^(9\d\d)\d{3}$/', $rule_id, $m) && isset($wb['group_' . $m[1] . '_txt'])) {
		return (string) $wb['group_' . $m[1] . '_txt'];
	}
	if (trim((string) $message) !== '') {
		return (string) $message;
	}
	return sprintf(waf_panel_text($wb, 'rule_fallback_txt', '%s'), $rule_id);
}

/** The classes a rule of the catalog may carry. */
function waf_panel_rule_classes()
{
	return array('scanner', 'attack', 'false_positive_prone', 'protocol', 'scoring', 'response');
}

/** The catalog file for $language in $dir; the English one when that language has none. */
function waf_panel_rule_catalog_file($dir, $language)
{
	$dir = rtrim((string) $dir, '/');
	$language = preg_match('/^[a-z]{2}$/', (string) $language) ? (string) $language : 'en';
	$file = $dir . '/' . $language . '_malwatch_waf_rules.lng';
	return is_file($file) ? $file : $dir . '/en_malwatch_waf_rules.lng';
}

/**
 * The rule catalog in a language file: rules keyed by id with title, what,
 * class, note and trigger as far as the file has them, groups keyed by their
 * three digits with what and class. Other lines of the file are left out.
 */
function waf_panel_rule_catalog($file)
{
	$wb = array();
	if (is_file((string) $file)) {
		include (string) $file;
	}
	$catalog = array('rules' => array(), 'groups' => array());
	foreach ($wb as $key => $value) {
		if (preg_match('/^rule_(\d{3,7})_(title|what|class|note|trigger)$/', (string) $key, $m)) {
			$catalog['rules'][$m[1]][$m[2]] = (string) $value;
		} elseif (preg_match('/^group_(\d{3})_(what|class)$/', (string) $key, $m)) {
			$catalog['groups'][$m[1]][$m[2]] = (string) $value;
		}
	}
	return $catalog;
}

/**
 * What the pages say about one rule: its catalog entry, else the texts of its
 * CRS group. crs is the English message of the rule set.
 */
function waf_panel_rule_info($wb, $catalog, $rule_id, $message)
{
	$rule_id = (string) $rule_id;
	$entry = isset($catalog['rules'][$rule_id]) ? $catalog['rules'][$rule_id] : array();
	$group = array();
	if (preg_match('/^(9\d\d)\d{3}$/', $rule_id, $m) && isset($catalog['groups'][$m[1]])) {
		$group = $catalog['groups'][$m[1]];
	}
	$class = isset($entry['class']) ? (string) $entry['class'] : (isset($group['class']) ? (string) $group['class'] : '');
	if (!in_array($class, waf_panel_rule_classes(), true)) {
		$class = '';
	}
	return array(
		'rule_id' => $rule_id,
		'title' => waf_panel_rule_title($wb, $rule_id, $message, $catalog),
		'what' => isset($entry['what']) ? (string) $entry['what'] : (isset($group['what']) ? (string) $group['what'] : ''),
		'class' => $class,
		'class_label' => $class === '' ? '' : waf_panel_text($wb, 'class_' . $class . '_txt', $class),
		'class_text' => $class === '' ? '' : waf_panel_text($wb, 'class_' . $class . '_text_txt', ''),
		'note' => isset($entry['note']) ? (string) $entry['note'] : '',
		'trigger' => isset($entry['trigger']) ? (string) $entry['trigger'] : '',
		'crs' => trim((string) $message),
	);
}
```

In `ispconfig/interface/lang/de_malwatch_waf.lng` die Gruppennamen ergänzen: vor `$wb['group_911_txt']` die Zeile für 910, nach `group_911_txt` die für 912, nach `group_921_txt` die für 922:

```php
$wb['group_910_txt'] = 'Bekannte Angreiferadresse';
```

```php
$wb['group_912_txt'] = 'Überlastungsangriff';
```

```php
$wb['group_922_txt'] = 'Mehrteiliges Formular';
```

In `ispconfig/interface/lang/en_malwatch_waf.lng` an denselben Stellen:

```php
$wb['group_910_txt'] = 'Known attacker address';
```

```php
$wb['group_912_txt'] = 'Denial of service';
```

```php
$wb['group_922_txt'] = 'Multipart form';
```

Am Ende von `ispconfig/interface/lang/de_malwatch_waf.lng` anhängen:

```php

// The classes of the rule catalog: a label and the sentence of the class.
$wb['class_scanner_txt'] = 'Scanner';
$wb['class_scanner_text_txt'] = 'Typisch für automatische Scanner. Antwortet die Website mit 404 oder 403, wurde nichts geliefert.';
$wb['class_attack_txt'] = 'Angriffsversuch';
$wb['class_attack_text_txt'] = 'Ein gezielter Versuch; ein Fehlalarm ist unwahrscheinlich. Eine Ausnahme nur nach genauer Prüfung.';
$wb['class_false_positive_prone_txt'] = 'Fehlalarm möglich';
$wb['class_false_positive_prone_text_txt'] = 'Schlägt auch bei echten Eingaben an, etwa HTML aus einem Editor, Suchbegriffe oder Passwörter. Eine Ausnahme für den Parameter oder Pfad ist sinnvoll, wenn die Treffer von echten Nutzern stammen.';
$wb['class_protocol_txt'] = 'Protokollverstoß';
$wb['class_protocol_text_txt'] = 'Die Anfrage hält sich nicht an HTTP; meist Bots oder alte Programme.';
$wb['class_scoring_txt'] = 'Auswertung';
$wb['class_scoring_text_txt'] = 'Die Punkte aller Regeln einer Anfrage liegen über der Grenze. Im scharfen Modus weist allein diese Regel ab.';
$wb['class_response_txt'] = 'Antwort der Website';
$wb['class_response_text_txt'] = 'Die Antwort der Website enthält Fehlermeldungen, Quelltext oder interne Angaben. Das weist auf ein Problem der Website hin. Diese Regeln greifen nur, wenn die WAF Seitenantworten prüft.';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf.lng` anhängen:

```php

// The classes of the rule catalog: a label and the sentence of the class.
$wb['class_scanner_txt'] = 'Scanner';
$wb['class_scanner_text_txt'] = 'Typical for automated scanners. If the website answered with 404 or 403, nothing was delivered.';
$wb['class_attack_txt'] = 'Attack attempt';
$wb['class_attack_text_txt'] = 'A targeted attempt; a false alarm is unlikely. Add an exception only after a close look.';
$wb['class_false_positive_prone_txt'] = 'False alarm possible';
$wb['class_false_positive_prone_text_txt'] = 'Also fires on genuine input, such as HTML from an editor, search terms or passwords. An exception for the parameter or path makes sense when the hits come from real users.';
$wb['class_protocol_txt'] = 'Protocol violation';
$wb['class_protocol_text_txt'] = 'The request breaks the rules of HTTP; mostly bots or old programs.';
$wb['class_scoring_txt'] = 'Scoring';
$wb['class_scoring_text_txt'] = 'The points of all rules for a request are above the limit. In enforce mode this rule alone rejects the request.';
$wb['class_response_txt'] = 'Website response';
$wb['class_response_text_txt'] = 'The response of the website contains error messages, source code or internal details. That points to a problem of the website. These rules only apply when the WAF inspects responses.';
```

- [ ] **Step 4: Katalogdateien anlegen**

`ispconfig/interface/lang/de_malwatch_waf_rules.lng` anlegen:

```php
<?php
// Rule catalog of the pages "Abwehr" (loaded by waf_panel_rule_catalog()).
// rule_<id>_title, _what and _class for every rule CRS 3.3.5 runs at
// paranoia level 1, _note and _trigger where needed; a trigger words data
// that carries a value only and holds exactly one %s. group_<ggg>_what and
// _class cover the rules of the higher levels. Classes: scanner, attack,
// false_positive_prone, protocol, scoring, response.

// --- groups -------------------------------------------------------------------
$wb['group_910_what'] = 'Die Adresse steht auf einer Sperrliste des Regelwerks.';
$wb['group_910_class'] = 'attack';
$wb['group_911_what'] = 'Die Anfrage nutzt eine HTTP-Methode, die das Regelwerk nicht zulässt.';
$wb['group_911_class'] = 'false_positive_prone';
$wb['group_912_what'] = 'Die Adresse schickt in kurzer Zeit sehr viele Anfragen.';
$wb['group_912_class'] = 'attack';
$wb['group_913_what'] = 'Die Anfrage stammt von einem bekannten Sicherheits- oder Angriffsscanner.';
$wb['group_913_class'] = 'scanner';
$wb['group_920_what'] = 'Die Anfrage hält sich nicht an die Regeln von HTTP.';
$wb['group_920_class'] = 'protocol';
$wb['group_921_what'] = 'Die Anfrage versucht, HTTP-Kopfzeilen oder weitere Anfragen einzuschleusen.';
$wb['group_921_class'] = 'attack';
$wb['group_922_what'] = 'Ein mehrteiliges Formular enthält unzulässige Angaben.';
$wb['group_922_class'] = 'protocol';
$wb['group_930_what'] = 'Die Anfrage versucht, Dateien außerhalb des Webordners oder geschützte Dateien zu lesen.';
$wb['group_930_class'] = 'attack';
$wb['group_931_what'] = 'Die Anfrage versucht, Code von einer fremden Adresse einzubinden.';
$wb['group_931_class'] = 'attack';
$wb['group_932_what'] = 'Ein Wert enthält Befehle, die auf dem Server laufen sollen.';
$wb['group_932_class'] = 'attack';
$wb['group_933_what'] = 'Ein Wert enthält PHP-Code, PHP-Funktionen oder PHP-Dateien.';
$wb['group_933_class'] = 'attack';
$wb['group_934_what'] = 'Ein Wert enthält Node.js-Code.';
$wb['group_934_class'] = 'attack';
$wb['group_941_what'] = 'Ein Wert enthält HTML oder JavaScript, das im Browser anderer Besucher laufen könnte.';
$wb['group_941_class'] = 'false_positive_prone';
$wb['group_942_what'] = 'Ein Wert enthält SQL-Bausteine, die eine Datenbankabfrage verändern sollen.';
$wb['group_942_class'] = 'false_positive_prone';
$wb['group_943_what'] = 'Die Anfrage versucht, eine Sitzungs-ID unterzuschieben.';
$wb['group_943_class'] = 'attack';
$wb['group_944_what'] = 'Ein Wert enthält Java-Klassen oder serialisierte Java-Objekte.';
$wb['group_944_class'] = 'attack';
$wb['group_949_what'] = 'Die Punkte aller Regeln einer Anfrage liegen über der Grenze.';
$wb['group_949_class'] = 'scoring';
$wb['group_950_what'] = 'Die Antwort der Website verrät interne Daten.';
$wb['group_950_class'] = 'response';
$wb['group_951_what'] = 'Die Antwort enthält eine Fehlermeldung einer Datenbank.';
$wb['group_951_class'] = 'response';
$wb['group_952_what'] = 'Die Antwort enthält Java-Fehler oder Java-Quelltext.';
$wb['group_952_class'] = 'response';
$wb['group_953_what'] = 'Die Antwort enthält PHP-Fehler oder PHP-Quelltext.';
$wb['group_953_class'] = 'response';
$wb['group_954_what'] = 'Die Antwort enthält interne Angaben eines IIS-Servers.';
$wb['group_954_class'] = 'response';
$wb['group_959_what'] = 'Die Punkte der Antwort liegen über der Grenze.';
$wb['group_959_class'] = 'scoring';
$wb['group_980_what'] = 'Zusammenfassung der Punkte am Ende einer Anfrage.';
$wb['group_980_class'] = 'scoring';

// --- 910 to 913: reputation, methods, load, scanners ----------------------------
$wb['rule_910000_title'] = 'Bekannte Angreiferadresse';
$wb['rule_910000_what'] = 'Die Adresse fiel schon früher durch Angriffe auf und steht deshalb auf der Sperrliste des Regelwerks.';
$wb['rule_910000_class'] = 'attack';
$wb['rule_910000_note'] = 'Die Regel wirkt nur, wenn die IP-Reputation des Regelwerks eingeschaltet ist.';
$wb['rule_910000_trigger'] = '%s';
$wb['rule_910100_title'] = 'Anfrage aus einem Land mit hohem Risiko';
$wb['rule_910100_what'] = 'Die Adresse gehört zu einem Land, das in der Konfiguration als riskant eingetragen ist.';
$wb['rule_910100_class'] = 'attack';
$wb['rule_910100_note'] = 'Die Regel wirkt nur, wenn eine Länderliste eingerichtet ist.';
$wb['rule_910100_trigger'] = 'Land „%s“';
$wb['rule_910150_title'] = 'Suchmaschinen-Adresse auf der Sperrliste';
$wb['rule_910150_what'] = 'Project Honey Pot führt die Adresse als missbräuchlich genutzte Suchmaschine.';
$wb['rule_910150_class'] = 'attack';
$wb['rule_910150_note'] = 'Die Regel wirkt nur mit einem Schlüssel für die HTTP-Blacklist von Project Honey Pot.';
$wb['rule_910160_title'] = 'Spam-Adresse auf der Sperrliste';
$wb['rule_910160_what'] = 'Project Honey Pot führt die Adresse als Absender von Spam.';
$wb['rule_910160_class'] = 'attack';
$wb['rule_910160_note'] = 'Die Regel wirkt nur mit einem Schlüssel für die HTTP-Blacklist von Project Honey Pot.';
$wb['rule_910170_title'] = 'Verdächtige Adresse auf der Sperrliste';
$wb['rule_910170_what'] = 'Project Honey Pot führt die Adresse als verdächtig.';
$wb['rule_910170_class'] = 'attack';
$wb['rule_910170_note'] = 'Die Regel wirkt nur mit einem Schlüssel für die HTTP-Blacklist von Project Honey Pot.';
$wb['rule_910180_title'] = 'Adressensammler auf der Sperrliste';
$wb['rule_910180_what'] = 'Project Honey Pot führt die Adresse als Sammler von E-Mail-Adressen.';
$wb['rule_910180_class'] = 'attack';
$wb['rule_910180_note'] = 'Die Regel wirkt nur mit einem Schlüssel für die HTTP-Blacklist von Project Honey Pot.';
$wb['rule_911100_title'] = 'Unerlaubte Methode';
$wb['rule_911100_what'] = 'Die Anfrage nutzt eine HTTP-Methode, die das Regelwerk nicht zulässt. Die Grundeinstellung erlaubt GET, HEAD, POST und OPTIONS.';
$wb['rule_911100_class'] = 'false_positive_prone';
$wb['rule_911100_note'] = 'Web-Schnittstellen wie die REST-API von WordPress nutzen auch PUT, PATCH und DELETE.';
$wb['rule_911100_trigger'] = 'Methode „%s“';
$wb['rule_912120_title'] = 'Überlastungsangriff erkannt';
$wb['rule_912120_what'] = 'Die Adresse hat in kurzer Zeit sehr viele Anfragen geschickt und ist deshalb vorübergehend gesperrt.';
$wb['rule_912120_class'] = 'attack';
$wb['rule_912120_note'] = 'Die Regel wirkt nur, wenn der Schutz vor Überlastung im Regelwerk eingerichtet ist.';
$wb['rule_912170_title'] = 'Wiederholte Anfragewellen';
$wb['rule_912170_what'] = 'Die Adresse hat mehrfach Wellen vieler Anfragen geschickt.';
$wb['rule_912170_class'] = 'attack';
$wb['rule_912170_note'] = 'Die Regel wirkt nur, wenn der Schutz vor Überlastung im Regelwerk eingerichtet ist.';
$wb['rule_913100_title'] = 'Scanner an der Programmkennung erkannt';
$wb['rule_913100_what'] = 'Die Kennung des Programms (User-Agent) gehört zu einem bekannten Sicherheits- oder Angriffsscanner wie Nikto oder sqlmap.';
$wb['rule_913100_class'] = 'scanner';
$wb['rule_913110_title'] = 'Scanner an einer Kopfzeile erkannt';
$wb['rule_913110_what'] = 'Eine Kopfzeile der Anfrage ist typisch für einen bekannten Sicherheitsscanner.';
$wb['rule_913110_class'] = 'scanner';
$wb['rule_913120_title'] = 'Scanner an Datei oder Parameter erkannt';
$wb['rule_913120_what'] = 'Dateiname oder Parameter der Anfrage sind typisch für einen bekannten Sicherheitsscanner.';
$wb['rule_913120_class'] = 'scanner';

// --- 920: protocol ----------------------------------------------------------------
$wb['rule_920100_title'] = 'Ungültige Anfragezeile';
$wb['rule_920100_what'] = 'Die erste Zeile der Anfrage mit Methode, Adresse und Protokoll ist fehlerhaft aufgebaut.';
$wb['rule_920100_class'] = 'protocol';
$wb['rule_920100_trigger'] = 'Anfragezeile „%s“';
$wb['rule_920120_title'] = 'Umgehungsversuch beim Datei-Upload';
$wb['rule_920120_what'] = 'Der Dateiname in einem Upload enthält Zeichen, mit denen Prüfungen umgangen werden sollen.';
$wb['rule_920120_class'] = 'attack';
$wb['rule_920120_trigger'] = 'Dateiname „%s“';
$wb['rule_920160_title'] = 'Content-Length ist keine Zahl';
$wb['rule_920160_what'] = 'Die Kopfzeile Content-Length gibt die Größe des Inhalts an und darf nur Ziffern enthalten.';
$wb['rule_920160_class'] = 'protocol';
$wb['rule_920160_trigger'] = 'Content-Length „%s“';
$wb['rule_920170_title'] = 'GET oder HEAD mit Inhalt';
$wb['rule_920170_what'] = 'Eine GET- oder HEAD-Anfrage bringt einen Inhalt mit. Normale Browser tun das praktisch nie.';
$wb['rule_920170_class'] = 'protocol';
$wb['rule_920170_trigger'] = 'Methode „%s“ mit Inhalt';
$wb['rule_920171_title'] = 'GET oder HEAD mit Transfer-Encoding';
$wb['rule_920171_what'] = 'Eine GET- oder HEAD-Anfrage kündigt einen stückweise gesendeten Inhalt an.';
$wb['rule_920171_class'] = 'protocol';
$wb['rule_920171_trigger'] = 'Methode „%s“ mit Transfer-Encoding';
$wb['rule_920180_title'] = 'POST ohne Längenangabe';
$wb['rule_920180_what'] = 'Eine POST-Anfrage nennt weder die Länge ihres Inhalts noch eine stückweise Übertragung.';
$wb['rule_920180_class'] = 'protocol';
$wb['rule_920180_trigger'] = 'Protokoll „%s“';
$wb['rule_920181_title'] = 'Content-Length und Transfer-Encoding zugleich';
$wb['rule_920181_what'] = 'Die Anfrage nennt beide Längenangaben gleichzeitig. Das ist ein bekanntes Muster für das Einschmuggeln von Anfragen (Request Smuggling).';
$wb['rule_920181_class'] = 'attack';
$wb['rule_920190_title'] = 'Ungültiger Byte-Bereich';
$wb['rule_920190_what'] = 'Die Kopfzeile Range fordert einen Bereich an, dessen Ende vor dem Anfang liegt.';
$wb['rule_920190_class'] = 'protocol';
$wb['rule_920190_trigger'] = 'Range „%s“';
$wb['rule_920210_title'] = 'Widersprüchliche Connection-Kopfzeile';
$wb['rule_920210_what'] = 'Die Kopfzeile Connection enthält widersprüchliche Angaben, etwa keep-alive und close zugleich.';
$wb['rule_920210_class'] = 'protocol';
$wb['rule_920210_trigger'] = 'Connection „%s“';
$wb['rule_920220_title'] = 'Fehlerhafte URL-Kodierung in der Adresse';
$wb['rule_920220_what'] = 'Die Adresse enthält ungültige Prozent-Kodierungen. Damit versuchen Angreifer, Filter zu umgehen.';
$wb['rule_920220_class'] = 'attack';
$wb['rule_920220_trigger'] = 'Adresse „%s“';
$wb['rule_920240_title'] = 'Fehlerhafte URL-Kodierung im Inhalt';
$wb['rule_920240_what'] = 'Ein als Formular gesendeter Inhalt enthält ungültige Prozent-Kodierungen.';
$wb['rule_920240_class'] = 'attack';
$wb['rule_920240_trigger'] = 'Wert „%s“';
$wb['rule_920250_title'] = 'Fehlerhafte UTF-8-Kodierung';
$wb['rule_920250_what'] = 'Die Anfrage enthält Zeichen, die als UTF-8 ungültig sind. Damit versuchen Angreifer, Filter zu umgehen.';
$wb['rule_920250_class'] = 'attack';
$wb['rule_920250_trigger'] = 'Wert „%s“';
$wb['rule_920260_title'] = 'Unicode-Zeichen voller Breite';
$wb['rule_920260_what'] = 'Die Anfrage nutzt Unicode-Zeichen voller Breite in der Form %uFFxx, mit denen Filter umgangen werden sollen.';
$wb['rule_920260_class'] = 'attack';
$wb['rule_920270_title'] = 'Nullzeichen in der Anfrage';
$wb['rule_920270_what'] = 'Die Anfrage enthält ein Nullzeichen. Das dient fast immer dazu, Dateinamen oder Prüfungen zu manipulieren.';
$wb['rule_920270_class'] = 'attack';
$wb['rule_920280_title'] = 'Host-Kopfzeile fehlt';
$wb['rule_920280_what'] = 'Die Anfrage nennt keine Website, für die sie bestimmt ist. Browser senden diese Angabe immer.';
$wb['rule_920280_class'] = 'protocol';
$wb['rule_920290_title'] = 'Leere Host-Kopfzeile';
$wb['rule_920290_what'] = 'Die Kopfzeile Host ist vorhanden und leer.';
$wb['rule_920290_class'] = 'protocol';
$wb['rule_920310_title'] = 'Leere Accept-Kopfzeile';
$wb['rule_920310_what'] = 'Die Kopfzeile Accept ist leer. Browser geben dort an, welche Inhalte sie verstehen.';
$wb['rule_920310_class'] = 'protocol';
$wb['rule_920311_title'] = 'Leere Accept-Kopfzeile';
$wb['rule_920311_what'] = 'Die Kopfzeile Accept ist leer; diese Fassung der Regel nimmt einzelne bekannte Programme aus.';
$wb['rule_920311_class'] = 'protocol';
$wb['rule_920330_title'] = 'Leere Programmkennung';
$wb['rule_920330_what'] = 'Die Kopfzeile User-Agent ist leer. Browser nennen dort immer ihren Namen.';
$wb['rule_920330_class'] = 'protocol';
$wb['rule_920340_title'] = 'Inhalt ohne Content-Type';
$wb['rule_920340_what'] = 'Die Anfrage bringt einen Inhalt mit und verschweigt, welcher Art er ist.';
$wb['rule_920340_class'] = 'protocol';
$wb['rule_920350_title'] = 'IP-Adresse als Host';
$wb['rule_920350_what'] = 'Die Anfrage nennt als Website eine IP-Adresse. Das ist typisch für Scanner, die ganze Adressbereiche absuchen.';
$wb['rule_920350_class'] = 'scanner';
$wb['rule_920350_trigger'] = 'Host „%s“';
$wb['rule_920360_title'] = 'Parametername zu lang';
$wb['rule_920360_what'] = 'Der Name eines Parameters ist länger, als das Regelwerk erlaubt.';
$wb['rule_920360_class'] = 'false_positive_prone';
$wb['rule_920370_title'] = 'Parameterwert zu lang';
$wb['rule_920370_what'] = 'Der Wert eines Parameters ist länger, als das Regelwerk erlaubt.';
$wb['rule_920370_class'] = 'false_positive_prone';
$wb['rule_920380_title'] = 'Zu viele Parameter';
$wb['rule_920380_what'] = 'Die Anfrage enthält mehr Parameter, als das Regelwerk erlaubt.';
$wb['rule_920380_class'] = 'false_positive_prone';
$wb['rule_920380_note'] = 'Große Formulare, etwa aus Seitenbaukästen, kommen auf viele Felder.';
$wb['rule_920390_title'] = 'Parameter insgesamt zu groß';
$wb['rule_920390_what'] = 'Alle Parameter zusammen sind größer, als das Regelwerk erlaubt.';
$wb['rule_920390_class'] = 'false_positive_prone';
$wb['rule_920400_title'] = 'Hochgeladene Datei zu groß';
$wb['rule_920400_what'] = 'Eine hochgeladene Datei ist größer, als das Regelwerk erlaubt.';
$wb['rule_920400_class'] = 'false_positive_prone';
$wb['rule_920410_title'] = 'Uploads insgesamt zu groß';
$wb['rule_920410_what'] = 'Alle hochgeladenen Dateien zusammen sind größer, als das Regelwerk erlaubt.';
$wb['rule_920410_class'] = 'false_positive_prone';
$wb['rule_920420_title'] = 'Inhaltstyp nicht erlaubt';
$wb['rule_920420_what'] = 'Der Inhalt hat einen Typ, den das Regelwerk nicht zulässt.';
$wb['rule_920420_class'] = 'false_positive_prone';
$wb['rule_920420_note'] = 'Schnittstellen mit eigenen Datenformaten lösen die Regel aus.';
$wb['rule_920420_trigger'] = 'Content-Type „%s“';
$wb['rule_920430_title'] = 'HTTP-Version nicht erlaubt';
$wb['rule_920430_what'] = 'Die Anfrage nutzt eine Protokollversion, die das Regelwerk nicht zulässt.';
$wb['rule_920430_class'] = 'protocol';
$wb['rule_920430_trigger'] = 'Protokoll „%s“';
$wb['rule_920440_title'] = 'Verbotene Dateiendung';
$wb['rule_920440_what'] = 'Die Adresse endet auf eine Dateiendung, die auf Websites nie öffentlich abrufbar sein sollte, etwa .sql, .bak, .conf oder .log.';
$wb['rule_920440_class'] = 'scanner';
$wb['rule_920440_trigger'] = 'Dateiendung „%s“';
$wb['rule_920450_title'] = 'Verbotene Kopfzeile';
$wb['rule_920450_what'] = 'Die Anfrage enthält eine Kopfzeile, die das Regelwerk sperrt, etwa Proxy oder Lock-Token.';
$wb['rule_920450_class'] = 'protocol';
$wb['rule_920470_title'] = 'Ungültige Content-Type-Kopfzeile';
$wb['rule_920470_what'] = 'Die Kopfzeile Content-Type ist fehlerhaft aufgebaut.';
$wb['rule_920470_class'] = 'protocol';
$wb['rule_920470_trigger'] = 'Content-Type „%s“';
$wb['rule_920480_title'] = 'Zeichensatz nicht erlaubt';
$wb['rule_920480_what'] = 'Der Inhalt nennt einen Zeichensatz, den das Regelwerk nicht zulässt. Erlaubt sind UTF-8, ISO-8859-1, ISO-8859-15 und Windows-1252.';
$wb['rule_920480_class'] = 'protocol';
$wb['rule_920480_trigger'] = 'Content-Type „%s“';
$wb['rule_920500_title'] = 'Zugriff auf Sicherungs- oder Arbeitsdatei';
$wb['rule_920500_what'] = 'Die Anfrage sucht eine Sicherungskopie oder Arbeitsdatei eines Editors, etwa index.php~ oder .env.swp. Solche Dateien enthalten oft Quelltext oder Zugangsdaten.';
$wb['rule_920500_class'] = 'scanner';
$wb['rule_920500_trigger'] = 'Dateiname endet auf „%s“';
$wb['rule_920530_title'] = 'Mehrere Zeichensätze';
$wb['rule_920530_what'] = 'Die Kopfzeile Content-Type nennt mehr als einen Zeichensatz.';
$wb['rule_920530_class'] = 'protocol';
$wb['rule_920530_trigger'] = 'Content-Type „%s“';
$wb['rule_920600_title'] = 'Ungültige Accept-Kopfzeile';
$wb['rule_920600_what'] = 'Die Kopfzeile Accept enthält eine Zeichensatz-Angabe, die dort unzulässig ist.';
$wb['rule_920600_class'] = 'protocol';
$wb['rule_920600_trigger'] = 'Accept „%s“';
$wb['rule_920620_title'] = 'Mehrere Content-Type-Kopfzeilen';
$wb['rule_920620_what'] = 'Die Anfrage enthält die Kopfzeile Content-Type mehrfach.';
$wb['rule_920620_class'] = 'protocol';
$wb['rule_920620_trigger'] = '%s Content-Type-Kopfzeilen';

// --- 921 and 922: attacks on the protocol, multipart forms ------------------------
$wb['rule_921110_title'] = 'Einschmuggeln einer Anfrage';
$wb['rule_921110_what'] = 'Ein Parameter oder der Inhalt enthält eine zweite HTTP-Anfrage (Request Smuggling).';
$wb['rule_921110_class'] = 'attack';
$wb['rule_921120_title'] = 'Aufspalten der Antwort';
$wb['rule_921120_what'] = 'Die Anfrage enthält Zeilenumbrüche mit Kopfzeilen, um die Antwort des Servers aufzuspalten (Response Splitting).';
$wb['rule_921120_class'] = 'attack';
$wb['rule_921130_title'] = 'Aufspalten der Antwort';
$wb['rule_921130_what'] = 'Die Anfrage enthält HTML- oder HTTP-Teile, mit denen die Antwort des Servers aufgespalten werden soll.';
$wb['rule_921130_class'] = 'attack';
$wb['rule_921140_title'] = 'Kopfzeilen-Einschleusung über Kopfzeilen';
$wb['rule_921140_what'] = 'Eine Kopfzeile enthält Zeilenumbrüche, mit denen weitere Kopfzeilen eingeschleust werden sollen.';
$wb['rule_921140_class'] = 'attack';
$wb['rule_921150_title'] = 'Zeilenumbruch in einem Parameternamen';
$wb['rule_921150_what'] = 'Der Name eines Parameters enthält einen Zeilenumbruch. Damit sollen Kopfzeilen eingeschleust werden.';
$wb['rule_921150_class'] = 'attack';
$wb['rule_921160_title'] = 'Kopfzeilen-Einschleusung über Parameter';
$wb['rule_921160_what'] = 'Ein Parameter enthält einen Zeilenumbruch und den Namen einer Kopfzeile.';
$wb['rule_921160_class'] = 'attack';
$wb['rule_921190_title'] = 'Zeilenumbruch im Dateinamen';
$wb['rule_921190_what'] = 'Der Dateiname der Anfrage enthält einen Zeilenumbruch.';
$wb['rule_921190_class'] = 'attack';
$wb['rule_921200_title'] = 'LDAP-Einschleusung';
$wb['rule_921200_what'] = 'Ein Wert enthält Zeichen und Klammern, die eine Verzeichnisabfrage (LDAP) verändern sollen.';
$wb['rule_921200_class'] = 'attack';
$wb['rule_921421_title'] = 'Gefährlicher Inhaltstyp';
$wb['rule_921421_what'] = 'Die Kopfzeile Content-Type trägt nach dem eigentlichen Typ weitere Angaben, mit denen Prüfungen umgangen werden sollen.';
$wb['rule_921421_class'] = 'attack';
$wb['rule_922100_title'] = 'Zeichensatz-Feld im Formular';
$wb['rule_922100_what'] = 'Ein mehrteiliges Formular legt über das Feld _charset_ einen Zeichensatz fest, den das Regelwerk nicht zulässt.';
$wb['rule_922100_class'] = 'protocol';
$wb['rule_922100_trigger'] = 'Zeichensatz „%s“';
$wb['rule_922110_title'] = 'Ungültiger Zeichensatz im Formularteil';
$wb['rule_922110_what'] = 'Ein Teil eines mehrteiligen Formulars nennt einen Zeichensatz, den das Regelwerk nicht zulässt.';
$wb['rule_922110_class'] = 'protocol';
$wb['rule_922120_title'] = 'Veraltete Kopfzeile im Formularteil';
$wb['rule_922120_what'] = 'Ein Teil eines mehrteiligen Formulars nutzt die seit 2015 veraltete Angabe Content-Transfer-Encoding.';
$wb['rule_922120_class'] = 'protocol';
$wb['rule_922120_trigger'] = 'Angabe „%s“';
```

`ispconfig/interface/lang/en_malwatch_waf_rules.lng` anlegen:

```php
<?php
// Rule catalog of the pages "Abwehr" (loaded by waf_panel_rule_catalog()).
// rule_<id>_title, _what and _class for every rule CRS 3.3.5 runs at
// paranoia level 1, _note and _trigger where needed; a trigger words data
// that carries a value only and holds exactly one %s. group_<ggg>_what and
// _class cover the rules of the higher levels. Classes: scanner, attack,
// false_positive_prone, protocol, scoring, response.

// --- groups -------------------------------------------------------------------
$wb['group_910_what'] = 'The address is on a block list of the rule set.';
$wb['group_910_class'] = 'attack';
$wb['group_911_what'] = 'The request uses an HTTP method the rule set does not allow.';
$wb['group_911_class'] = 'false_positive_prone';
$wb['group_912_what'] = 'The address sends a great many requests in a short time.';
$wb['group_912_class'] = 'attack';
$wb['group_913_what'] = 'The request comes from a known security or attack scanner.';
$wb['group_913_class'] = 'scanner';
$wb['group_920_what'] = 'The request breaks the rules of HTTP.';
$wb['group_920_class'] = 'protocol';
$wb['group_921_what'] = 'The request tries to inject HTTP headers or further requests.';
$wb['group_921_class'] = 'attack';
$wb['group_922_what'] = 'A multipart form contains values that are not allowed.';
$wb['group_922_class'] = 'protocol';
$wb['group_930_what'] = 'The request tries to read files outside the web folder or protected files.';
$wb['group_930_class'] = 'attack';
$wb['group_931_what'] = 'The request tries to include code from a foreign address.';
$wb['group_931_class'] = 'attack';
$wb['group_932_what'] = 'A value contains commands meant to run on the server.';
$wb['group_932_class'] = 'attack';
$wb['group_933_what'] = 'A value contains PHP code, PHP functions or PHP files.';
$wb['group_933_class'] = 'attack';
$wb['group_934_what'] = 'A value contains Node.js code.';
$wb['group_934_class'] = 'attack';
$wb['group_941_what'] = 'A value contains HTML or JavaScript that could run in the browser of other visitors.';
$wb['group_941_class'] = 'false_positive_prone';
$wb['group_942_what'] = 'A value contains SQL fragments meant to change a database query.';
$wb['group_942_class'] = 'false_positive_prone';
$wb['group_943_what'] = 'The request tries to plant a session ID.';
$wb['group_943_class'] = 'attack';
$wb['group_944_what'] = 'A value contains Java classes or serialized Java objects.';
$wb['group_944_class'] = 'attack';
$wb['group_949_what'] = 'The points of all rules for a request are above the limit.';
$wb['group_949_class'] = 'scoring';
$wb['group_950_what'] = 'The response of the website reveals internal data.';
$wb['group_950_class'] = 'response';
$wb['group_951_what'] = 'The response contains an error message of a database.';
$wb['group_951_class'] = 'response';
$wb['group_952_what'] = 'The response contains Java errors or Java source code.';
$wb['group_952_class'] = 'response';
$wb['group_953_what'] = 'The response contains PHP errors or PHP source code.';
$wb['group_953_class'] = 'response';
$wb['group_954_what'] = 'The response contains internal details of an IIS server.';
$wb['group_954_class'] = 'response';
$wb['group_959_what'] = 'The points of the response are above the limit.';
$wb['group_959_class'] = 'scoring';
$wb['group_980_what'] = 'Summary of the points at the end of a request.';
$wb['group_980_class'] = 'scoring';

// --- 910 to 913: reputation, methods, load, scanners ----------------------------
$wb['rule_910000_title'] = 'Known attacker address';
$wb['rule_910000_what'] = 'The address was caught attacking before and is on the block list of the rule set.';
$wb['rule_910000_class'] = 'attack';
$wb['rule_910000_note'] = 'Only active when the IP reputation of the rule set is enabled.';
$wb['rule_910000_trigger'] = '%s';
$wb['rule_910100_title'] = 'Request from a high-risk country';
$wb['rule_910100_what'] = 'The address belongs to a country the configuration lists as risky.';
$wb['rule_910100_class'] = 'attack';
$wb['rule_910100_note'] = 'Only active when a country list is configured.';
$wb['rule_910100_trigger'] = 'Country "%s"';
$wb['rule_910150_title'] = 'Search engine address on the block list';
$wb['rule_910150_what'] = 'Project Honey Pot lists the address as an abused search engine.';
$wb['rule_910150_class'] = 'attack';
$wb['rule_910150_note'] = 'Only active with a key for the HTTP blacklist of Project Honey Pot.';
$wb['rule_910160_title'] = 'Spam address on the block list';
$wb['rule_910160_what'] = 'Project Honey Pot lists the address as a spam sender.';
$wb['rule_910160_class'] = 'attack';
$wb['rule_910160_note'] = 'Only active with a key for the HTTP blacklist of Project Honey Pot.';
$wb['rule_910170_title'] = 'Suspicious address on the block list';
$wb['rule_910170_what'] = 'Project Honey Pot lists the address as suspicious.';
$wb['rule_910170_class'] = 'attack';
$wb['rule_910170_note'] = 'Only active with a key for the HTTP blacklist of Project Honey Pot.';
$wb['rule_910180_title'] = 'Address harvester on the block list';
$wb['rule_910180_what'] = 'Project Honey Pot lists the address as a harvester of e-mail addresses.';
$wb['rule_910180_class'] = 'attack';
$wb['rule_910180_note'] = 'Only active with a key for the HTTP blacklist of Project Honey Pot.';
$wb['rule_911100_title'] = 'Method not allowed';
$wb['rule_911100_what'] = 'The request uses an HTTP method the rule set does not allow. By default GET, HEAD, POST and OPTIONS are allowed.';
$wb['rule_911100_class'] = 'false_positive_prone';
$wb['rule_911100_note'] = 'Web interfaces such as the WordPress REST API also use PUT, PATCH and DELETE.';
$wb['rule_911100_trigger'] = 'Method "%s"';
$wb['rule_912120_title'] = 'Denial of service detected';
$wb['rule_912120_what'] = 'The address sent a great many requests in a short time and is blocked for a while.';
$wb['rule_912120_class'] = 'attack';
$wb['rule_912120_note'] = 'Only active when the denial-of-service protection of the rule set is configured.';
$wb['rule_912170_title'] = 'Repeated request bursts';
$wb['rule_912170_what'] = 'The address sent several bursts of many requests.';
$wb['rule_912170_class'] = 'attack';
$wb['rule_912170_note'] = 'Only active when the denial-of-service protection of the rule set is configured.';
$wb['rule_913100_title'] = 'Scanner recognised by its user agent';
$wb['rule_913100_what'] = 'The user agent belongs to a known security or attack scanner such as Nikto or sqlmap.';
$wb['rule_913100_class'] = 'scanner';
$wb['rule_913110_title'] = 'Scanner recognised by a header';
$wb['rule_913110_what'] = 'A header of the request is typical for a known security scanner.';
$wb['rule_913110_class'] = 'scanner';
$wb['rule_913120_title'] = 'Scanner recognised by file or parameter';
$wb['rule_913120_what'] = 'File name or parameters of the request are typical for a known security scanner.';
$wb['rule_913120_class'] = 'scanner';

// --- 920: protocol ----------------------------------------------------------------
$wb['rule_920100_title'] = 'Invalid request line';
$wb['rule_920100_what'] = 'The first line of the request with method, address and protocol is malformed.';
$wb['rule_920100_class'] = 'protocol';
$wb['rule_920100_trigger'] = 'Request line "%s"';
$wb['rule_920120_title'] = 'Upload bypass attempt';
$wb['rule_920120_what'] = 'The file name of an upload contains characters meant to slip past checks.';
$wb['rule_920120_class'] = 'attack';
$wb['rule_920120_trigger'] = 'File name "%s"';
$wb['rule_920160_title'] = 'Content-Length is no number';
$wb['rule_920160_what'] = 'The Content-Length header gives the size of the body and may hold digits only.';
$wb['rule_920160_class'] = 'protocol';
$wb['rule_920160_trigger'] = 'Content-Length "%s"';
$wb['rule_920170_title'] = 'GET or HEAD with a body';
$wb['rule_920170_what'] = 'A GET or HEAD request carries a body. Regular browsers practically never do that.';
$wb['rule_920170_class'] = 'protocol';
$wb['rule_920170_trigger'] = 'Method "%s" with a body';
$wb['rule_920171_title'] = 'GET or HEAD with Transfer-Encoding';
$wb['rule_920171_what'] = 'A GET or HEAD request announces a body sent in chunks.';
$wb['rule_920171_class'] = 'protocol';
$wb['rule_920171_trigger'] = 'Method "%s" with Transfer-Encoding';
$wb['rule_920180_title'] = 'POST without a length';
$wb['rule_920180_what'] = 'A POST request states neither the length of its body nor a chunked transfer.';
$wb['rule_920180_class'] = 'protocol';
$wb['rule_920180_trigger'] = 'Protocol "%s"';
$wb['rule_920181_title'] = 'Content-Length and Transfer-Encoding together';
$wb['rule_920181_what'] = 'The request states both length headers at once, a known pattern for request smuggling.';
$wb['rule_920181_class'] = 'attack';
$wb['rule_920190_title'] = 'Invalid byte range';
$wb['rule_920190_what'] = 'The Range header asks for a range that ends before it starts.';
$wb['rule_920190_class'] = 'protocol';
$wb['rule_920190_trigger'] = 'Range "%s"';
$wb['rule_920210_title'] = 'Conflicting Connection header';
$wb['rule_920210_what'] = 'The Connection header holds conflicting values, such as keep-alive and close together.';
$wb['rule_920210_class'] = 'protocol';
$wb['rule_920210_trigger'] = 'Connection "%s"';
$wb['rule_920220_title'] = 'Malformed URL encoding in the address';
$wb['rule_920220_what'] = 'The address contains invalid percent encodings, used to slip past filters.';
$wb['rule_920220_class'] = 'attack';
$wb['rule_920220_trigger'] = 'Address "%s"';
$wb['rule_920240_title'] = 'Malformed URL encoding in the body';
$wb['rule_920240_what'] = 'A form body contains invalid percent encodings.';
$wb['rule_920240_class'] = 'attack';
$wb['rule_920240_trigger'] = 'Value "%s"';
$wb['rule_920250_title'] = 'Malformed UTF-8 encoding';
$wb['rule_920250_what'] = 'The request contains characters that are invalid UTF-8, used to slip past filters.';
$wb['rule_920250_class'] = 'attack';
$wb['rule_920250_trigger'] = 'Value "%s"';
$wb['rule_920260_title'] = 'Full-width Unicode characters';
$wb['rule_920260_what'] = 'The request uses full-width Unicode characters of the form %uFFxx to slip past filters.';
$wb['rule_920260_class'] = 'attack';
$wb['rule_920270_title'] = 'Null character in the request';
$wb['rule_920270_what'] = 'The request contains a null character. It nearly always serves to manipulate file names or checks.';
$wb['rule_920270_class'] = 'attack';
$wb['rule_920280_title'] = 'Host header missing';
$wb['rule_920280_what'] = 'The request names no website it is meant for. Browsers always send this.';
$wb['rule_920280_class'] = 'protocol';
$wb['rule_920290_title'] = 'Empty Host header';
$wb['rule_920290_what'] = 'The Host header is present and empty.';
$wb['rule_920290_class'] = 'protocol';
$wb['rule_920310_title'] = 'Empty Accept header';
$wb['rule_920310_what'] = 'The Accept header is empty. Browsers list there which content they understand.';
$wb['rule_920310_class'] = 'protocol';
$wb['rule_920311_title'] = 'Empty Accept header';
$wb['rule_920311_what'] = 'The Accept header is empty; this version of the rule leaves out some known programs.';
$wb['rule_920311_class'] = 'protocol';
$wb['rule_920330_title'] = 'Empty user agent';
$wb['rule_920330_what'] = 'The User-Agent header is empty. Browsers always name themselves there.';
$wb['rule_920330_class'] = 'protocol';
$wb['rule_920340_title'] = 'Body without Content-Type';
$wb['rule_920340_what'] = 'The request carries a body and keeps its kind to itself.';
$wb['rule_920340_class'] = 'protocol';
$wb['rule_920350_title'] = 'IP address as host';
$wb['rule_920350_what'] = 'The request names an IP address as the website, typical for scanners sweeping address ranges.';
$wb['rule_920350_class'] = 'scanner';
$wb['rule_920350_trigger'] = 'Host "%s"';
$wb['rule_920360_title'] = 'Parameter name too long';
$wb['rule_920360_what'] = 'The name of a parameter is longer than the rule set allows.';
$wb['rule_920360_class'] = 'false_positive_prone';
$wb['rule_920370_title'] = 'Parameter value too long';
$wb['rule_920370_what'] = 'The value of a parameter is longer than the rule set allows.';
$wb['rule_920370_class'] = 'false_positive_prone';
$wb['rule_920380_title'] = 'Too many parameters';
$wb['rule_920380_what'] = 'The request has more parameters than the rule set allows.';
$wb['rule_920380_class'] = 'false_positive_prone';
$wb['rule_920380_note'] = 'Large forms, such as those of page builders, have many fields.';
$wb['rule_920390_title'] = 'Parameters too large in total';
$wb['rule_920390_what'] = 'All parameters together are larger than the rule set allows.';
$wb['rule_920390_class'] = 'false_positive_prone';
$wb['rule_920400_title'] = 'Uploaded file too large';
$wb['rule_920400_what'] = 'An uploaded file is larger than the rule set allows.';
$wb['rule_920400_class'] = 'false_positive_prone';
$wb['rule_920410_title'] = 'Uploads too large in total';
$wb['rule_920410_what'] = 'All uploaded files together are larger than the rule set allows.';
$wb['rule_920410_class'] = 'false_positive_prone';
$wb['rule_920420_title'] = 'Content type not allowed';
$wb['rule_920420_what'] = 'The body has a type the rule set does not allow.';
$wb['rule_920420_class'] = 'false_positive_prone';
$wb['rule_920420_note'] = 'Interfaces with their own data formats fire this rule.';
$wb['rule_920420_trigger'] = 'Content-Type "%s"';
$wb['rule_920430_title'] = 'HTTP version not allowed';
$wb['rule_920430_what'] = 'The request uses a protocol version the rule set does not allow.';
$wb['rule_920430_class'] = 'protocol';
$wb['rule_920430_trigger'] = 'Protocol "%s"';
$wb['rule_920440_title'] = 'Forbidden file extension';
$wb['rule_920440_what'] = 'The address ends in an extension that should never be public on a website, such as .sql, .bak, .conf or .log.';
$wb['rule_920440_class'] = 'scanner';
$wb['rule_920440_trigger'] = 'File extension "%s"';
$wb['rule_920450_title'] = 'Forbidden header';
$wb['rule_920450_what'] = 'The request contains a header the rule set blocks, such as Proxy or Lock-Token.';
$wb['rule_920450_class'] = 'protocol';
$wb['rule_920470_title'] = 'Invalid Content-Type header';
$wb['rule_920470_what'] = 'The Content-Type header is malformed.';
$wb['rule_920470_class'] = 'protocol';
$wb['rule_920470_trigger'] = 'Content-Type "%s"';
$wb['rule_920480_title'] = 'Charset not allowed';
$wb['rule_920480_what'] = 'The body names a character set the rule set does not allow. Allowed are UTF-8, ISO-8859-1, ISO-8859-15 and Windows-1252.';
$wb['rule_920480_class'] = 'protocol';
$wb['rule_920480_trigger'] = 'Content-Type "%s"';
$wb['rule_920500_title'] = 'Access to a backup or working file';
$wb['rule_920500_what'] = 'The request looks for a backup copy or an editor working file, such as index.php~ or .env.swp. Such files often hold source code or credentials.';
$wb['rule_920500_class'] = 'scanner';
$wb['rule_920500_trigger'] = 'File name ends in "%s"';
$wb['rule_920530_title'] = 'Several charsets';
$wb['rule_920530_what'] = 'The Content-Type header names more than one character set.';
$wb['rule_920530_class'] = 'protocol';
$wb['rule_920530_trigger'] = 'Content-Type "%s"';
$wb['rule_920600_title'] = 'Invalid Accept header';
$wb['rule_920600_what'] = 'The Accept header contains a charset parameter that is not allowed there.';
$wb['rule_920600_class'] = 'protocol';
$wb['rule_920600_trigger'] = 'Accept "%s"';
$wb['rule_920620_title'] = 'Several Content-Type headers';
$wb['rule_920620_what'] = 'The request contains the Content-Type header more than once.';
$wb['rule_920620_class'] = 'protocol';
$wb['rule_920620_trigger'] = '%s Content-Type headers';

// --- 921 and 922: attacks on the protocol, multipart forms ------------------------
$wb['rule_921110_title'] = 'Request smuggling';
$wb['rule_921110_what'] = 'A parameter or the body contains a second HTTP request.';
$wb['rule_921110_class'] = 'attack';
$wb['rule_921120_title'] = 'Response splitting';
$wb['rule_921120_what'] = 'The request contains line breaks with headers to split the response of the server.';
$wb['rule_921120_class'] = 'attack';
$wb['rule_921130_title'] = 'Response splitting';
$wb['rule_921130_what'] = 'The request contains HTML or HTTP parts meant to split the response of the server.';
$wb['rule_921130_class'] = 'attack';
$wb['rule_921140_title'] = 'Header injection through headers';
$wb['rule_921140_what'] = 'A header contains line breaks meant to inject further headers.';
$wb['rule_921140_class'] = 'attack';
$wb['rule_921150_title'] = 'Line break in a parameter name';
$wb['rule_921150_what'] = 'The name of a parameter contains a line break, meant to inject headers.';
$wb['rule_921150_class'] = 'attack';
$wb['rule_921160_title'] = 'Header injection through parameters';
$wb['rule_921160_what'] = 'A parameter contains a line break and the name of a header.';
$wb['rule_921160_class'] = 'attack';
$wb['rule_921190_title'] = 'Line break in the file name';
$wb['rule_921190_what'] = 'The file name of the request contains a line break.';
$wb['rule_921190_class'] = 'attack';
$wb['rule_921200_title'] = 'LDAP injection';
$wb['rule_921200_what'] = 'A value contains characters and brackets meant to change a directory (LDAP) query.';
$wb['rule_921200_class'] = 'attack';
$wb['rule_921421_title'] = 'Dangerous content type';
$wb['rule_921421_what'] = 'The Content-Type header carries further values after the actual type, meant to slip past checks.';
$wb['rule_921421_class'] = 'attack';
$wb['rule_922100_title'] = 'Charset field in a form';
$wb['rule_922100_what'] = 'A multipart form sets a character set through the _charset_ field that the rule set does not allow.';
$wb['rule_922100_class'] = 'protocol';
$wb['rule_922100_trigger'] = 'Charset "%s"';
$wb['rule_922110_title'] = 'Invalid charset in a form part';
$wb['rule_922110_what'] = 'A part of a multipart form names a character set the rule set does not allow.';
$wb['rule_922110_class'] = 'protocol';
$wb['rule_922120_title'] = 'Deprecated header in a form part';
$wb['rule_922120_what'] = 'A part of a multipart form uses Content-Transfer-Encoding, deprecated since 2015.';
$wb['rule_922120_class'] = 'protocol';
$wb['rule_922120_trigger'] = 'Value "%s"';
```

- [ ] **Step 5: Tests laufen lassen**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_rules_catalog_test.php`
Expected: `waf_panel: alle Prüfungen bestanden` und `waf_rules_catalog: alle Prüfungen bestanden`.

- [ ] **Step 6: Installation, CI und Spec**

In `ispconfig/install/file.list` nach der Zeile für `en_malwatch_waf.lng` einfügen:

```text
c:interface/lang/de_malwatch_waf_rules.lng:interface/web/security/lib/lang/de_malwatch_waf_rules.lng
c:interface/lang/en_malwatch_waf_rules.lng:interface/web/security/lib/lang/en_malwatch_waf_rules.lng
```

In `.github/workflows/ci.yml`, Job `php-syntax`, nach dem Schritt `WAF page actions` einfügen:

```yaml
      - name: WAF rule catalog
        run: php ispconfig/tests/waf_rules_catalog_test.php
```

In `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`:

Die Zeile in Abschnitt 2

```markdown
| Umfang des Katalogs | alle Regeln von CRS 3.3.5 mit dem Tag `paranoia-level/1`; übrige Regeln über ihre Gruppe |
```

ersetzen durch:

```markdown
| Umfang des Katalogs | die 166 Regeln, die CRS 3.3.5 bei Stufe 1 ausführt (164 mit dem Tag `paranoia-level/1`, dazu 920181 und 921200), und die Auswertungsregeln 949110, 959100, 980130, 980140; übrige Regeln über ihre Gruppe |
| Katalogformat | gewöhnliche ISPConfig-Sprachdatei, damit der Spracheditor sie lesen und bearbeiten kann |
| Obergrenze der Regel-Karten | Einstellung `waf_card_hits`, Vorgabe 5000 jüngste Einzeltreffer je Website |
```

Den Unterabschnitt `### Dateien` in Abschnitt 4 (bis vor `### Einordnung`) ersetzen durch:

````markdown
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

````

In der Tabelle unter `### Einordnung` nach der Zeile für `scoring` einfügen:

```markdown
| `response` | Antwort der Website | Die Antwort der Website enthält Fehlermeldungen, Quelltext oder interne Angaben. Das weist auf ein Problem der Website hin. Diese Regeln greifen nur, wenn die WAF Seitenantworten prüft. |
```

In Abschnitt 5 den Punkt

```markdown
- **Adressen (n Tage)**, n = `waf_detail_days`: bis zu fünf Adressen mit Anzahl, aus
  `malwatch_waf_hit` der Website, deren `rules` die Regel enthalten; darunter „und n
  weitere". Ohne Einzeltreffer: „Keine Einzeltreffer im Zeitraum".
```

ersetzen durch:

```markdown
- **Adressen aus den gespeicherten Anfragen (n Tage)**, n = `waf_detail_days`: bis zu
  fünf Adressen mit Anzahl, aus den jüngsten `waf_card_hits` Einzeltreffern der Website,
  deren `rules` die Regel enthalten; darunter „und n weitere". Erreicht die Seite die
  Obergrenze, heißt die Überschrift „Adressen aus den neuesten n gespeicherten Anfragen".
  Enthält keiner dieser Einzeltreffer die Regel: „Keine dieser Anfragen enthält die
  Regel." Darunter steht, wie viele dieser Treffer von angemeldeten Nutzern kamen.
```

In Abschnitt 13 den Punkt

```markdown
  - Katalog: jede ID aus der Fixture hat einen deutschen und einen englischen Eintrag mit
    allen Feldern, `class` gültig, `title` höchstens 48 Zeichen.
```

ersetzen durch:

```markdown
  - Katalog (`waf_rules_catalog_test.php`): jede ID aus der Fixture hat einen deutschen
    und einen englischen Eintrag mit Titel, Erklärung und Klasse, `class` gültig und in
    beiden Sprachen gleich, `title` höchstens 48 Zeichen, jede Vorlage mit genau einem
    `%s`; jede Gruppe hat Erklärung und Klasse.
```

- [ ] **Step 7: Prüfen und committen**

Run: `php -l ispconfig/interface/lib/malwatch_waf_panel.inc.php && php -l ispconfig/interface/lang/de_malwatch_waf_rules.lng && php -l ispconfig/interface/lang/en_malwatch_waf_rules.lng`
Expected: dreimal `No syntax errors detected`.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/lang/de_malwatch_waf_rules.lng ispconfig/interface/lang/en_malwatch_waf_rules.lng ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/tests/fixtures/crs-3.3.5-pl1-rule-ids.txt ispconfig/tests/waf_rules_catalog_test.php ispconfig/tests/waf_panel_test.php ispconfig/install/file.list .github/workflows/ci.yml docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): rule catalog with the groups 910 to 922" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A4: Regelkatalog, Gruppen 930 bis 934 und 944

**Files:**
- Modify: `ispconfig/interface/lang/de_malwatch_waf_rules.lng`, `ispconfig/interface/lang/en_malwatch_waf_rules.lng` (Block am Dateiende)
- Test: `ispconfig/tests/waf_rules_catalog_test.php`

**Interfaces:**
- Consumes: Katalogformat und Test aus Task A3
- Produces: Einträge für 35 Regeln (930100 bis 944130)

- [ ] **Step 1: Test erweitern**

In `ispconfig/tests/waf_rules_catalog_test.php` die Zeile

```php
$covered = array('910', '911', '912', '913', '920', '921', '922');
```

ersetzen durch:

```php
$covered = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934', '944');
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_rules_catalog_test.php`
Expected: FAIL, unter anderem `FAIL de 930100 title: false, erwartet true` und `FAIL 944130 same class in both languages`.

- [ ] **Step 3: Einträge anhängen**

Am Ende von `ispconfig/interface/lang/de_malwatch_waf_rules.lng` anhängen:

```php

// --- 930 to 934 and 944: files, inclusion, commands, PHP, Node.js, Java -----------
$wb['rule_930100_title'] = 'Verzeichniswechsel, kodiert';
$wb['rule_930100_what'] = 'Die Anfrage enthält ../ in kodierter Form, um aus dem Webordner in andere Verzeichnisse zu gelangen (Path Traversal).';
$wb['rule_930100_class'] = 'attack';
$wb['rule_930110_title'] = 'Verzeichniswechsel';
$wb['rule_930110_what'] = 'Die Anfrage enthält ../, um aus dem Webordner in andere Verzeichnisse zu gelangen (Path Traversal).';
$wb['rule_930110_class'] = 'attack';
$wb['rule_930120_title'] = 'Zugriff auf Systemdateien';
$wb['rule_930120_what'] = 'Ein Wert nennt eine Datei des Betriebssystems oder einer Anwendung, etwa /etc/passwd oder parameters.yml.';
$wb['rule_930120_class'] = 'attack';
$wb['rule_930130_title'] = 'Zugriff auf geschützte Datei';
$wb['rule_930130_what'] = 'Die Anfrage wollte eine Datei lesen, die nie öffentlich sein sollte, etwa .env, .git oder eine Zugangsdatei. Solche Dateien enthalten oft Zugangsdaten.';
$wb['rule_930130_class'] = 'scanner';
$wb['rule_931100_title'] = 'Nachladen über eine IP-Adresse';
$wb['rule_931100_what'] = 'Ein Parameter enthält eine Adresse mit IP-Nummer. So versuchen Angreifer, fremden Code einzubinden (Remote File Inclusion).';
$wb['rule_931100_class'] = 'attack';
$wb['rule_931110_title'] = 'Nachladen über einen typischen Parameter';
$wb['rule_931110_what'] = 'Ein Parameter, über den oft fremde Dateien eingebunden werden, enthält eine Adresse.';
$wb['rule_931110_class'] = 'attack';
$wb['rule_931120_title'] = 'Nachladen mit Fragezeichen am Ende';
$wb['rule_931120_what'] = 'Ein Parameter enthält eine Adresse, die mit ? endet. Damit wird eine angehängte Dateiendung abgeschnitten, um fremden Code einzubinden.';
$wb['rule_931120_class'] = 'attack';
$wb['rule_932100_title'] = 'Unix-Befehl eingeschleust';
$wb['rule_932100_what'] = 'Ein Wert enthält einen Unix-Befehl mit Trennzeichen wie ; oder |, der auf dem Server laufen soll.';
$wb['rule_932100_class'] = 'attack';
$wb['rule_932105_title'] = 'Unix-Befehl eingeschleust';
$wb['rule_932105_what'] = 'Ein Wert enthält nach einem Trennzeichen einen Unix-Befehl, der auf dem Server laufen soll.';
$wb['rule_932105_class'] = 'attack';
$wb['rule_932110_title'] = 'Windows-Befehl eingeschleust';
$wb['rule_932110_what'] = 'Ein Wert enthält einen Windows-Befehl mit Trennzeichen, der auf dem Server laufen soll.';
$wb['rule_932110_class'] = 'attack';
$wb['rule_932115_title'] = 'Windows-Befehl eingeschleust';
$wb['rule_932115_what'] = 'Ein Wert enthält nach einem Trennzeichen einen Windows-Befehl, der auf dem Server laufen soll.';
$wb['rule_932115_class'] = 'attack';
$wb['rule_932120_title'] = 'PowerShell-Befehl';
$wb['rule_932120_what'] = 'Ein Wert enthält einen Befehl der Windows PowerShell.';
$wb['rule_932120_class'] = 'attack';
$wb['rule_932130_title'] = 'Unix-Shell-Ausdruck';
$wb['rule_932130_what'] = 'Ein Wert enthält einen Shell-Ausdruck wie $(…) oder ${…}, der auf dem Server ausgewertet werden soll.';
$wb['rule_932130_class'] = 'attack';
$wb['rule_932140_title'] = 'Windows-Befehl FOR oder IF';
$wb['rule_932140_what'] = 'Ein Wert enthält einen FOR- oder IF-Befehl der Windows-Kommandozeile.';
$wb['rule_932140_class'] = 'attack';
$wb['rule_932150_title'] = 'Direkter Unix-Befehl';
$wb['rule_932150_what'] = 'Ein Wert beginnt mit einem Unix-Befehl, der direkt ausgeführt werden soll.';
$wb['rule_932150_class'] = 'attack';
$wb['rule_932160_title'] = 'Unix-Shell-Code';
$wb['rule_932160_what'] = 'Ein Wert enthält typischen Shell-Code, etwa einen Pfad wie /bin/bash.';
$wb['rule_932160_class'] = 'attack';
$wb['rule_932170_title'] = 'Shellshock über eine Kopfzeile';
$wb['rule_932170_what'] = 'Eine Kopfzeile oder die Anfragezeile enthält das Muster der Shellshock-Lücke von 2014.';
$wb['rule_932170_class'] = 'attack';
$wb['rule_932171_title'] = 'Shellshock über einen Parameter';
$wb['rule_932171_what'] = 'Ein Parameter oder ein Dateiname enthält das Muster der Shellshock-Lücke von 2014.';
$wb['rule_932171_class'] = 'attack';
$wb['rule_932180_title'] = 'Hochladen einer gesperrten Datei';
$wb['rule_932180_what'] = 'Ein Upload trägt den Namen einer Datei, die das Verhalten des Servers ändert, etwa .htaccess oder web.config.';
$wb['rule_932180_class'] = 'attack';
$wb['rule_933100_title'] = 'PHP-Code eingeschleust';
$wb['rule_933100_what'] = 'Ein Wert enthält ein PHP-Anfangszeichen wie <?php oder <?=. So soll Code auf den Server gelangen.';
$wb['rule_933100_class'] = 'attack';
$wb['rule_933110_title'] = 'PHP-Datei hochgeladen';
$wb['rule_933110_what'] = 'Ein Upload trägt den Namen einer PHP-Datei. Hochgeladene PHP-Dateien sind der klassische Weg zu einer Hintertür.';
$wb['rule_933110_class'] = 'attack';
$wb['rule_933120_title'] = 'PHP-Einstellung eingeschleust';
$wb['rule_933120_what'] = 'Ein Wert enthält eine PHP-Einstellung wie allow_url_include oder auto_prepend_file.';
$wb['rule_933120_class'] = 'attack';
$wb['rule_933130_title'] = 'PHP-Variablen';
$wb['rule_933130_what'] = 'Ein Wert nennt interne PHP-Variablen wie $_SERVER oder $GLOBALS.';
$wb['rule_933130_class'] = 'attack';
$wb['rule_933140_title'] = 'PHP-Datenstrom';
$wb['rule_933140_what'] = 'Ein Wert nennt einen PHP-Datenstrom wie php://input oder php://filter, über den Dateien gelesen oder Code eingeschleust werden.';
$wb['rule_933140_class'] = 'attack';
$wb['rule_933150_title'] = 'Riskante PHP-Funktion';
$wb['rule_933150_what'] = 'Ein Wert nennt eine riskante PHP-Funktion wie eval, system oder base64_decode.';
$wb['rule_933150_class'] = 'attack';
$wb['rule_933160_title'] = 'Aufruf einer riskanten PHP-Funktion';
$wb['rule_933160_what'] = 'Ein Wert enthält den Aufruf einer riskanten PHP-Funktion samt Klammern.';
$wb['rule_933160_class'] = 'attack';
$wb['rule_933170_title'] = 'Eingeschleustes PHP-Objekt';
$wb['rule_933170_what'] = 'Ein Wert enthält ein serialisiertes PHP-Objekt. Damit lassen sich in unsicheren Anwendungen Aktionen auslösen (Object Injection).';
$wb['rule_933170_class'] = 'attack';
$wb['rule_933180_title'] = 'Funktionsaufruf über eine Variable';
$wb['rule_933180_what'] = 'Ein Wert enthält einen PHP-Funktionsaufruf über eine Variable, etwa $f(…).';
$wb['rule_933180_class'] = 'attack';
$wb['rule_933200_title'] = 'PHP-Wrapper';
$wb['rule_933200_what'] = 'Ein Wert beginnt mit einem PHP-Wrapper wie zip://, phar:// oder expect://.';
$wb['rule_933200_class'] = 'attack';
$wb['rule_933210_title'] = 'Verschleierter PHP-Funktionsaufruf';
$wb['rule_933210_what'] = 'Ein Wert enthält einen verschleierten Funktionsaufruf, etwa über Zeichenketten oder Kommentare.';
$wb['rule_933210_class'] = 'attack';
$wb['rule_934100_title'] = 'Node.js-Code eingeschleust';
$wb['rule_934100_what'] = 'Ein Wert enthält Node.js-Code, etwa child_process oder eval, der auf dem Server laufen soll.';
$wb['rule_934100_class'] = 'attack';
$wb['rule_944100_title'] = 'Verdächtige Java-Klasse';
$wb['rule_944100_what'] = 'Ein Wert nennt eine Java-Klasse, über die Befehle laufen, etwa java.lang.Runtime.';
$wb['rule_944100_class'] = 'attack';
$wb['rule_944110_title'] = 'Java-Prozessstart';
$wb['rule_944110_what'] = 'Ein Wert enthält den Start eines Prozesses in Java (Lücke CVE-2017-9805 in Apache Struts).';
$wb['rule_944110_class'] = 'attack';
$wb['rule_944120_title'] = 'Java-Serialisierung';
$wb['rule_944120_what'] = 'Ein Wert enthält ein serialisiertes Java-Objekt mit gefährlichen Klassen (Lücke CVE-2015-4852).';
$wb['rule_944120_class'] = 'attack';
$wb['rule_944130_title'] = 'Verdächtige Java-Klasse aus der Liste';
$wb['rule_944130_what'] = 'Ein Wert nennt eine Java-Klasse aus der Liste bekannter Angriffsklassen.';
$wb['rule_944130_class'] = 'attack';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf_rules.lng` anhängen:

```php

// --- 930 to 934 and 944: files, inclusion, commands, PHP, Node.js, Java -----------
$wb['rule_930100_title'] = 'Directory traversal, encoded';
$wb['rule_930100_what'] = 'The request contains ../ in encoded form to leave the web folder for other directories (path traversal).';
$wb['rule_930100_class'] = 'attack';
$wb['rule_930110_title'] = 'Directory traversal';
$wb['rule_930110_what'] = 'The request contains ../ to leave the web folder for other directories (path traversal).';
$wb['rule_930110_class'] = 'attack';
$wb['rule_930120_title'] = 'Access to system files';
$wb['rule_930120_what'] = 'A value names a file of the operating system or of an application, such as /etc/passwd or parameters.yml.';
$wb['rule_930120_class'] = 'attack';
$wb['rule_930130_title'] = 'Access to a protected file';
$wb['rule_930130_what'] = 'The request tried to read a file that should never be public, such as .env, .git or a credentials file. Such files often hold credentials.';
$wb['rule_930130_class'] = 'scanner';
$wb['rule_931100_title'] = 'Inclusion through an IP address';
$wb['rule_931100_what'] = 'A parameter contains an address with an IP number, a way to include foreign code (remote file inclusion).';
$wb['rule_931100_class'] = 'attack';
$wb['rule_931110_title'] = 'Inclusion through a typical parameter';
$wb['rule_931110_what'] = 'A parameter often used to include foreign files contains an address.';
$wb['rule_931110_class'] = 'attack';
$wb['rule_931120_title'] = 'Inclusion with a trailing question mark';
$wb['rule_931120_what'] = 'A parameter contains an address ending in ?, which cuts off an appended file extension to include foreign code.';
$wb['rule_931120_class'] = 'attack';
$wb['rule_932100_title'] = 'Unix command injected';
$wb['rule_932100_what'] = 'A value contains a Unix command with a separator such as ; or | meant to run on the server.';
$wb['rule_932100_class'] = 'attack';
$wb['rule_932105_title'] = 'Unix command injected';
$wb['rule_932105_what'] = 'A value contains a Unix command after a separator, meant to run on the server.';
$wb['rule_932105_class'] = 'attack';
$wb['rule_932110_title'] = 'Windows command injected';
$wb['rule_932110_what'] = 'A value contains a Windows command with a separator, meant to run on the server.';
$wb['rule_932110_class'] = 'attack';
$wb['rule_932115_title'] = 'Windows command injected';
$wb['rule_932115_what'] = 'A value contains a Windows command after a separator, meant to run on the server.';
$wb['rule_932115_class'] = 'attack';
$wb['rule_932120_title'] = 'PowerShell command';
$wb['rule_932120_what'] = 'A value contains a Windows PowerShell command.';
$wb['rule_932120_class'] = 'attack';
$wb['rule_932130_title'] = 'Unix shell expression';
$wb['rule_932130_what'] = 'A value contains a shell expression such as $(…) or ${…} meant to be evaluated on the server.';
$wb['rule_932130_class'] = 'attack';
$wb['rule_932140_title'] = 'Windows FOR or IF command';
$wb['rule_932140_what'] = 'A value contains a FOR or IF command of the Windows command line.';
$wb['rule_932140_class'] = 'attack';
$wb['rule_932150_title'] = 'Direct Unix command';
$wb['rule_932150_what'] = 'A value starts with a Unix command meant to run directly.';
$wb['rule_932150_class'] = 'attack';
$wb['rule_932160_title'] = 'Unix shell code';
$wb['rule_932160_what'] = 'A value contains typical shell code, such as a path like /bin/bash.';
$wb['rule_932160_class'] = 'attack';
$wb['rule_932170_title'] = 'Shellshock through a header';
$wb['rule_932170_what'] = 'A header or the request line contains the pattern of the Shellshock flaw from 2014.';
$wb['rule_932170_class'] = 'attack';
$wb['rule_932171_title'] = 'Shellshock through a parameter';
$wb['rule_932171_what'] = 'A parameter or a file name contains the pattern of the Shellshock flaw from 2014.';
$wb['rule_932171_class'] = 'attack';
$wb['rule_932180_title'] = 'Upload of a blocked file';
$wb['rule_932180_what'] = 'An upload carries the name of a file that changes how the server behaves, such as .htaccess or web.config.';
$wb['rule_932180_class'] = 'attack';
$wb['rule_933100_title'] = 'PHP code injected';
$wb['rule_933100_what'] = 'A value contains a PHP open tag such as <?php or <?=, a way to bring code onto the server.';
$wb['rule_933100_class'] = 'attack';
$wb['rule_933110_title'] = 'PHP file uploaded';
$wb['rule_933110_what'] = 'An upload carries the name of a PHP file. Uploaded PHP files are the classic way to a backdoor.';
$wb['rule_933110_class'] = 'attack';
$wb['rule_933120_title'] = 'PHP setting injected';
$wb['rule_933120_what'] = 'A value contains a PHP setting such as allow_url_include or auto_prepend_file.';
$wb['rule_933120_class'] = 'attack';
$wb['rule_933130_title'] = 'PHP variables';
$wb['rule_933130_what'] = 'A value names internal PHP variables such as $_SERVER or $GLOBALS.';
$wb['rule_933130_class'] = 'attack';
$wb['rule_933140_title'] = 'PHP stream';
$wb['rule_933140_what'] = 'A value names a PHP stream such as php://input or php://filter, used to read files or inject code.';
$wb['rule_933140_class'] = 'attack';
$wb['rule_933150_title'] = 'High-risk PHP function';
$wb['rule_933150_what'] = 'A value names a high-risk PHP function such as eval, system or base64_decode.';
$wb['rule_933150_class'] = 'attack';
$wb['rule_933160_title'] = 'Call of a high-risk PHP function';
$wb['rule_933160_what'] = 'A value contains the call of a high-risk PHP function with brackets.';
$wb['rule_933160_class'] = 'attack';
$wb['rule_933170_title'] = 'Injected PHP object';
$wb['rule_933170_what'] = 'A value contains a serialized PHP object, which can trigger actions in unsafe applications (object injection).';
$wb['rule_933170_class'] = 'attack';
$wb['rule_933180_title'] = 'Function call through a variable';
$wb['rule_933180_what'] = 'A value contains a PHP function call through a variable, such as $f(…).';
$wb['rule_933180_class'] = 'attack';
$wb['rule_933200_title'] = 'PHP wrapper';
$wb['rule_933200_what'] = 'A value starts with a PHP wrapper such as zip://, phar:// or expect://.';
$wb['rule_933200_class'] = 'attack';
$wb['rule_933210_title'] = 'Obfuscated PHP function call';
$wb['rule_933210_what'] = 'A value contains an obfuscated function call, such as through strings or comments.';
$wb['rule_933210_class'] = 'attack';
$wb['rule_934100_title'] = 'Node.js code injected';
$wb['rule_934100_what'] = 'A value contains Node.js code, such as child_process or eval, meant to run on the server.';
$wb['rule_934100_class'] = 'attack';
$wb['rule_944100_title'] = 'Suspicious Java class';
$wb['rule_944100_what'] = 'A value names a Java class that runs commands, such as java.lang.Runtime.';
$wb['rule_944100_class'] = 'attack';
$wb['rule_944110_title'] = 'Java process start';
$wb['rule_944110_what'] = 'A value contains the start of a process in Java (flaw CVE-2017-9805 in Apache Struts).';
$wb['rule_944110_class'] = 'attack';
$wb['rule_944120_title'] = 'Java serialization';
$wb['rule_944120_what'] = 'A value contains a serialized Java object with dangerous classes (flaw CVE-2015-4852).';
$wb['rule_944120_class'] = 'attack';
$wb['rule_944130_title'] = 'Suspicious Java class from the list';
$wb['rule_944130_what'] = 'A value names a Java class from the list of known attack classes.';
$wb['rule_944130_class'] = 'attack';
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_rules_catalog_test.php && php -l ispconfig/interface/lang/de_malwatch_waf_rules.lng && php -l ispconfig/interface/lang/en_malwatch_waf_rules.lng`
Expected: `waf_rules_catalog: alle Prüfungen bestanden` und zweimal `No syntax errors detected`.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/lang/de_malwatch_waf_rules.lng ispconfig/interface/lang/en_malwatch_waf_rules.lng ispconfig/tests/waf_rules_catalog_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): rule catalog for files, inclusion, commands, PHP and Java" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A5: Regelkatalog, Gruppen 941 bis 943

**Files:**
- Modify: `ispconfig/interface/lang/de_malwatch_waf_rules.lng`, `ispconfig/interface/lang/en_malwatch_waf_rules.lng` (Block am Dateiende)
- Test: `ispconfig/tests/waf_rules_catalog_test.php`

**Interfaces:**
- Consumes: Katalogformat und Test aus Task A3
- Produces: Einträge für 43 Regeln (941100 bis 943120)

- [ ] **Step 1: Test erweitern**

In `ispconfig/tests/waf_rules_catalog_test.php` die Zeile

```php
$covered = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934', '944');
```

ersetzen durch:

```php
$covered = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934', '944',
	'941', '942', '943');
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_rules_catalog_test.php`
Expected: FAIL, unter anderem `FAIL de 941100 title: false, erwartet true`.

- [ ] **Step 3: Einträge anhängen**

Am Ende von `ispconfig/interface/lang/de_malwatch_waf_rules.lng` anhängen:

```php

// --- 941 to 943: scripts, SQL, sessions -----------------------------------------
$wb['rule_941100_title'] = 'Skript-Einschleusung (XSS)';
$wb['rule_941100_what'] = 'Ein Wert enthält HTML oder JavaScript, das im Browser anderer Besucher laufen könnte (Cross-Site-Scripting). Erkannt durch die Bibliothek libinjection.';
$wb['rule_941100_class'] = 'false_positive_prone';
$wb['rule_941110_title'] = 'Script-Tag';
$wb['rule_941110_what'] = 'Ein Wert enthält ein <script>-Tag.';
$wb['rule_941110_class'] = 'false_positive_prone';
$wb['rule_941120_title'] = 'JavaScript-Ereignis';
$wb['rule_941120_what'] = 'Ein Wert enthält ein HTML-Attribut, das bei einem Ereignis JavaScript ausführt, etwa onload oder onerror.';
$wb['rule_941120_class'] = 'false_positive_prone';
$wb['rule_941130_title'] = 'Gefährliches HTML-Attribut';
$wb['rule_941130_what'] = 'Ein Wert enthält ein HTML-Attribut, über das Code laufen kann, etwa xlink:href oder eine Stilangabe mit Ausdruck.';
$wb['rule_941130_class'] = 'false_positive_prone';
$wb['rule_941140_title'] = 'JavaScript-Adresse';
$wb['rule_941140_what'] = 'Ein Wert enthält eine Adresse, die mit javascript: oder vbscript: beginnt.';
$wb['rule_941140_class'] = 'attack';
$wb['rule_941160_title'] = 'HTML-Einschleusung';
$wb['rule_941160_what'] = 'Ein Wert enthält HTML-Tags, die Inhalte oder Skripte in eine Seite einschleusen können.';
$wb['rule_941160_class'] = 'false_positive_prone';
$wb['rule_941170_title'] = 'Attribut-Einschleusung';
$wb['rule_941170_what'] = 'Ein Wert enthält ein Attribut, das Code nachladen oder ausführen kann.';
$wb['rule_941170_class'] = 'false_positive_prone';
$wb['rule_941180_title'] = 'Gesperrte JavaScript-Begriffe';
$wb['rule_941180_what'] = 'Ein Wert enthält Begriffe wie document.cookie oder window.location, mit denen Skripte Daten abgreifen.';
$wb['rule_941180_class'] = 'false_positive_prone';
$wb['rule_941190_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941190_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941190_class'] = 'false_positive_prone';
$wb['rule_941200_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941200_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941200_class'] = 'false_positive_prone';
$wb['rule_941210_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941210_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941210_class'] = 'false_positive_prone';
$wb['rule_941220_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941220_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941220_class'] = 'false_positive_prone';
$wb['rule_941230_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941230_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941230_class'] = 'false_positive_prone';
$wb['rule_941240_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941240_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941240_class'] = 'false_positive_prone';
$wb['rule_941250_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941250_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941250_class'] = 'false_positive_prone';
$wb['rule_941260_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941260_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941260_class'] = 'false_positive_prone';
$wb['rule_941270_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941270_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941270_class'] = 'false_positive_prone';
$wb['rule_941280_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941280_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941280_class'] = 'false_positive_prone';
$wb['rule_941290_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941290_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941290_class'] = 'false_positive_prone';
$wb['rule_941300_title'] = 'XSS-Muster des Internet-Explorer-Filters';
$wb['rule_941300_what'] = 'Ein Wert enthält ein HTML-Muster, das der frühere XSS-Filter des Internet Explorers als Angriff einstufte, etwa Tags wie embed, object, meta oder base mit Adressen oder Stilangaben mit Ausdrücken.';
$wb['rule_941300_class'] = 'false_positive_prone';
$wb['rule_941310_title'] = 'Fehlerhaft kodiertes XSS';
$wb['rule_941310_what'] = 'Ein Wert enthält Zeichen in einer US-ASCII-Kodierung, mit der Skript-Tags versteckt werden. Umlaute in normalem Text lösen die Regel ebenfalls aus.';
$wb['rule_941310_class'] = 'false_positive_prone';
$wb['rule_941350_title'] = 'UTF-7-kodiertes XSS';
$wb['rule_941350_what'] = 'Ein Wert enthält in UTF-7 kodierte Skript-Zeichen, die ältere Browser ausführen.';
$wb['rule_941350_class'] = 'attack';
$wb['rule_941360_title'] = 'Verschleiertes JavaScript';
$wb['rule_941360_what'] = 'Ein Wert besteht aus JavaScript, das nur aus Klammern und Zeichen wie ![]+ gebaut ist (JSFuck, Hieroglyphy).';
$wb['rule_941360_class'] = 'attack';
$wb['rule_941370_title'] = 'Globale JavaScript-Variable';
$wb['rule_941370_what'] = 'Ein Wert greift auf globale JavaScript-Objekte wie window oder self zu, oft verschleiert.';
$wb['rule_941370_class'] = 'false_positive_prone';
$wb['rule_942100_title'] = 'SQL-Einschleusung';
$wb['rule_942100_what'] = 'Ein Wert enthält SQL-Bausteine, die eine Datenbankabfrage verändern sollen. Erkannt durch die Bibliothek libinjection.';
$wb['rule_942100_class'] = 'false_positive_prone';
$wb['rule_942100_note'] = 'Längere Texte mit Anführungszeichen, etwa aus einem Editor, lösen die Regel gelegentlich aus.';
$wb['rule_942140_title'] = 'Interne Datenbanknamen';
$wb['rule_942140_what'] = 'Ein Wert nennt interne Datenbanken wie information_schema oder mysql.user.';
$wb['rule_942140_class'] = 'attack';
$wb['rule_942160_title'] = 'Blinde SQL-Einschleusung mit Pause';
$wb['rule_942160_what'] = 'Ein Wert enthält sleep() oder benchmark(). Angreifer prüfen damit an der Antwortzeit, ob eine Einschleusung wirkt.';
$wb['rule_942160_class'] = 'attack';
$wb['rule_942170_title'] = 'SQL-Pause mit Bedingung';
$wb['rule_942170_what'] = 'Ein Wert enthält SELECT mit sleep() oder benchmark(), teils in einer Bedingung.';
$wb['rule_942170_class'] = 'attack';
$wb['rule_942190_title'] = 'Ausspähen der Datenbank';
$wb['rule_942190_what'] = 'Ein Wert enthält Befehle, mit denen Angreifer eine Datenbank ausspähen oder Befehle ausführen, etwa UNION SELECT oder exec master.';
$wb['rule_942190_class'] = 'attack';
$wb['rule_942220_title'] = 'Zahlen für einen Überlauf';
$wb['rule_942220_what'] = 'Ein Wert enthält Zahlen, die in Programmen einen Überlauf oder Absturz auslösen, etwa 4294967296 oder 2.2250738585072007e-308.';
$wb['rule_942220_class'] = 'false_positive_prone';
$wb['rule_942230_title'] = 'Bedingte SQL-Einschleusung';
$wb['rule_942230_what'] = 'Ein Wert enthält eine SQL-Bedingung wie CASE oder IF, mit der Abfragen gesteuert werden.';
$wb['rule_942230_class'] = 'attack';
$wb['rule_942240_title'] = 'Zeichensatzwechsel in SQL';
$wb['rule_942240_what'] = 'Ein Wert enthält einen Wechsel des Zeichensatzes für MySQL oder einen Überlastungsversuch für MSSQL.';
$wb['rule_942240_class'] = 'attack';
$wb['rule_942250_title'] = 'SQL-Befehle MATCH, MERGE, EXECUTE';
$wb['rule_942250_what'] = 'Ein Wert enthält MATCH AGAINST, MERGE oder EXECUTE IMMEDIATE.';
$wb['rule_942250_class'] = 'attack';
$wb['rule_942270_title'] = 'Einfache SQL-Einschleusung';
$wb['rule_942270_what'] = 'Ein Wert enthält ein klassisches Muster wie union select from.';
$wb['rule_942270_class'] = 'attack';
$wb['rule_942280_title'] = 'Datenbank anhalten oder abschalten';
$wb['rule_942280_what'] = 'Ein Wert enthält pg_sleep, waitfor delay oder einen Befehl zum Abschalten der Datenbank.';
$wb['rule_942280_class'] = 'attack';
$wb['rule_942290_title'] = 'MongoDB-Einschleusung';
$wb['rule_942290_what'] = 'Ein Wert enthält Operatoren der Datenbank MongoDB wie $ne oder $where.';
$wb['rule_942290_class'] = 'attack';
$wb['rule_942320_title'] = 'Gespeicherte SQL-Prozeduren';
$wb['rule_942320_what'] = 'Ein Wert ruft gespeicherte Prozeduren oder Funktionen von MySQL oder PostgreSQL auf.';
$wb['rule_942320_class'] = 'attack';
$wb['rule_942350_title'] = 'SQL-Funktionen und Strukturänderungen';
$wb['rule_942350_what'] = 'Ein Wert enthält benutzerdefinierte Funktionen oder Befehle, die Daten oder Tabellen ändern.';
$wb['rule_942350_class'] = 'attack';
$wb['rule_942360_title'] = 'Verkettete SQL-Einschleusung';
$wb['rule_942360_what'] = 'Ein Wert enthält verkettete SQL-Bausteine, etwa einen Wert gefolgt von UNION SELECT oder load_file.';
$wb['rule_942360_class'] = 'false_positive_prone';
$wb['rule_942500_title'] = 'Ausführbarer MySQL-Kommentar';
$wb['rule_942500_what'] = 'Ein Wert enthält einen ausführbaren MySQL-Kommentar der Form /*! … */.';
$wb['rule_942500_class'] = 'attack';
$wb['rule_943100_title'] = 'Cookie über HTML setzen';
$wb['rule_943100_what'] = 'Ein Wert enthält HTML oder JavaScript, das beim Besucher ein Cookie setzt. So sollen Sitzungen übernommen werden (Session Fixation).';
$wb['rule_943100_class'] = 'attack';
$wb['rule_943110_title'] = 'Sitzungs-ID von fremder Website';
$wb['rule_943110_what'] = 'Ein Parametername sieht wie eine Sitzungs-ID aus, und die Anfrage kommt von einer fremden Website.';
$wb['rule_943110_class'] = 'false_positive_prone';
$wb['rule_943120_title'] = 'Sitzungs-ID ohne Herkunft';
$wb['rule_943120_what'] = 'Ein Parametername sieht wie eine Sitzungs-ID aus, und die Anfrage nennt keine Herkunftsseite.';
$wb['rule_943120_class'] = 'false_positive_prone';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf_rules.lng` anhängen:

```php

// --- 941 to 943: scripts, SQL, sessions -----------------------------------------
$wb['rule_941100_title'] = 'Script injection (XSS)';
$wb['rule_941100_what'] = 'A value contains HTML or JavaScript that could run in the browser of other visitors (cross-site scripting). Detected by the libinjection library.';
$wb['rule_941100_class'] = 'false_positive_prone';
$wb['rule_941110_title'] = 'Script tag';
$wb['rule_941110_what'] = 'A value contains a <script> tag.';
$wb['rule_941110_class'] = 'false_positive_prone';
$wb['rule_941120_title'] = 'JavaScript event';
$wb['rule_941120_what'] = 'A value contains an HTML attribute that runs JavaScript on an event, such as onload or onerror.';
$wb['rule_941120_class'] = 'false_positive_prone';
$wb['rule_941130_title'] = 'Dangerous HTML attribute';
$wb['rule_941130_what'] = 'A value contains an HTML attribute that can run code, such as xlink:href or a style value with an expression.';
$wb['rule_941130_class'] = 'false_positive_prone';
$wb['rule_941140_title'] = 'JavaScript address';
$wb['rule_941140_what'] = 'A value contains an address starting with javascript: or vbscript:.';
$wb['rule_941140_class'] = 'attack';
$wb['rule_941160_title'] = 'HTML injection';
$wb['rule_941160_what'] = 'A value contains HTML tags that can inject content or scripts into a page.';
$wb['rule_941160_class'] = 'false_positive_prone';
$wb['rule_941170_title'] = 'Attribute injection';
$wb['rule_941170_what'] = 'A value contains an attribute that can load or run code.';
$wb['rule_941170_class'] = 'false_positive_prone';
$wb['rule_941180_title'] = 'Blocked JavaScript terms';
$wb['rule_941180_what'] = 'A value contains terms such as document.cookie or window.location that scripts use to grab data.';
$wb['rule_941180_class'] = 'false_positive_prone';
$wb['rule_941190_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941190_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941190_class'] = 'false_positive_prone';
$wb['rule_941200_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941200_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941200_class'] = 'false_positive_prone';
$wb['rule_941210_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941210_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941210_class'] = 'false_positive_prone';
$wb['rule_941220_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941220_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941220_class'] = 'false_positive_prone';
$wb['rule_941230_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941230_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941230_class'] = 'false_positive_prone';
$wb['rule_941240_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941240_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941240_class'] = 'false_positive_prone';
$wb['rule_941250_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941250_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941250_class'] = 'false_positive_prone';
$wb['rule_941260_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941260_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941260_class'] = 'false_positive_prone';
$wb['rule_941270_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941270_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941270_class'] = 'false_positive_prone';
$wb['rule_941280_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941280_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941280_class'] = 'false_positive_prone';
$wb['rule_941290_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941290_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941290_class'] = 'false_positive_prone';
$wb['rule_941300_title'] = 'XSS pattern of the Internet Explorer filter';
$wb['rule_941300_what'] = 'A value contains an HTML pattern the former XSS filter of Internet Explorer rated as an attack, such as tags like embed, object, meta or base with addresses, or style values with expressions.';
$wb['rule_941300_class'] = 'false_positive_prone';
$wb['rule_941310_title'] = 'Malformed encoded XSS';
$wb['rule_941310_what'] = 'A value contains characters in a US-ASCII encoding that hides script tags. Umlauts in plain text fire the rule as well.';
$wb['rule_941310_class'] = 'false_positive_prone';
$wb['rule_941350_title'] = 'UTF-7 encoded XSS';
$wb['rule_941350_what'] = 'A value contains script characters encoded in UTF-7, which older browsers run.';
$wb['rule_941350_class'] = 'attack';
$wb['rule_941360_title'] = 'Obfuscated JavaScript';
$wb['rule_941360_what'] = 'A value consists of JavaScript built only from brackets and characters such as ![]+ (JSFuck, Hieroglyphy).';
$wb['rule_941360_class'] = 'attack';
$wb['rule_941370_title'] = 'Global JavaScript variable';
$wb['rule_941370_what'] = 'A value reaches for global JavaScript objects such as window or self, often obfuscated.';
$wb['rule_941370_class'] = 'false_positive_prone';
$wb['rule_942100_title'] = 'SQL injection';
$wb['rule_942100_what'] = 'A value contains SQL fragments meant to change a database query. Detected by the libinjection library.';
$wb['rule_942100_class'] = 'false_positive_prone';
$wb['rule_942100_note'] = 'Longer texts with quotation marks, such as those from an editor, fire the rule now and then.';
$wb['rule_942140_title'] = 'Internal database names';
$wb['rule_942140_what'] = 'A value names internal databases such as information_schema or mysql.user.';
$wb['rule_942140_class'] = 'attack';
$wb['rule_942160_title'] = 'Blind SQL injection with a pause';
$wb['rule_942160_what'] = 'A value contains sleep() or benchmark(). Attackers use the response time to see whether an injection works.';
$wb['rule_942160_class'] = 'attack';
$wb['rule_942170_title'] = 'SQL pause with a condition';
$wb['rule_942170_what'] = 'A value contains SELECT with sleep() or benchmark(), partly inside a condition.';
$wb['rule_942170_class'] = 'attack';
$wb['rule_942190_title'] = 'Spying on the database';
$wb['rule_942190_what'] = 'A value contains commands attackers use to spy on a database or run commands, such as UNION SELECT or exec master.';
$wb['rule_942190_class'] = 'attack';
$wb['rule_942220_title'] = 'Numbers for an overflow';
$wb['rule_942220_what'] = 'A value contains numbers that make programs overflow or crash, such as 4294967296 or 2.2250738585072007e-308.';
$wb['rule_942220_class'] = 'false_positive_prone';
$wb['rule_942230_title'] = 'Conditional SQL injection';
$wb['rule_942230_what'] = 'A value contains an SQL condition such as CASE or IF that steers queries.';
$wb['rule_942230_class'] = 'attack';
$wb['rule_942240_title'] = 'Charset switch in SQL';
$wb['rule_942240_what'] = 'A value contains a character set switch for MySQL or an overload attempt for MSSQL.';
$wb['rule_942240_class'] = 'attack';
$wb['rule_942250_title'] = 'SQL commands MATCH, MERGE, EXECUTE';
$wb['rule_942250_what'] = 'A value contains MATCH AGAINST, MERGE or EXECUTE IMMEDIATE.';
$wb['rule_942250_class'] = 'attack';
$wb['rule_942270_title'] = 'Basic SQL injection';
$wb['rule_942270_what'] = 'A value contains a classic pattern such as union select from.';
$wb['rule_942270_class'] = 'attack';
$wb['rule_942280_title'] = 'Pausing or shutting down the database';
$wb['rule_942280_what'] = 'A value contains pg_sleep, waitfor delay or a command to shut down the database.';
$wb['rule_942280_class'] = 'attack';
$wb['rule_942290_title'] = 'MongoDB injection';
$wb['rule_942290_what'] = 'A value contains operators of the MongoDB database such as $ne or $where.';
$wb['rule_942290_class'] = 'attack';
$wb['rule_942320_title'] = 'Stored SQL procedures';
$wb['rule_942320_what'] = 'A value calls stored procedures or functions of MySQL or PostgreSQL.';
$wb['rule_942320_class'] = 'attack';
$wb['rule_942350_title'] = 'SQL functions and structure changes';
$wb['rule_942350_what'] = 'A value contains user-defined functions or commands that change data or tables.';
$wb['rule_942350_class'] = 'attack';
$wb['rule_942360_title'] = 'Concatenated SQL injection';
$wb['rule_942360_what'] = 'A value contains concatenated SQL fragments, such as a value followed by UNION SELECT or load_file.';
$wb['rule_942360_class'] = 'false_positive_prone';
$wb['rule_942500_title'] = 'Executable MySQL comment';
$wb['rule_942500_what'] = 'A value contains an executable MySQL comment of the form /*! … */.';
$wb['rule_942500_class'] = 'attack';
$wb['rule_943100_title'] = 'Setting a cookie through HTML';
$wb['rule_943100_what'] = 'A value contains HTML or JavaScript that sets a cookie in the visitor browser, meant to take over sessions (session fixation).';
$wb['rule_943100_class'] = 'attack';
$wb['rule_943110_title'] = 'Session ID from a foreign website';
$wb['rule_943110_what'] = 'A parameter name looks like a session ID, and the request comes from a foreign website.';
$wb['rule_943110_class'] = 'false_positive_prone';
$wb['rule_943120_title'] = 'Session ID without a referrer';
$wb['rule_943120_what'] = 'A parameter name looks like a session ID, and the request names no referring page.';
$wb['rule_943120_class'] = 'false_positive_prone';
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_rules_catalog_test.php && php -l ispconfig/interface/lang/de_malwatch_waf_rules.lng && php -l ispconfig/interface/lang/en_malwatch_waf_rules.lng`
Expected: `waf_rules_catalog: alle Prüfungen bestanden` und zweimal `No syntax errors detected`.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/lang/de_malwatch_waf_rules.lng ispconfig/interface/lang/en_malwatch_waf_rules.lng ispconfig/tests/waf_rules_catalog_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): rule catalog for scripts, SQL and sessions" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A6: Regelkatalog, Auswertung und Antwortregeln, Abschluss des Katalogs

**Files:**
- Modify: `ispconfig/interface/lang/de_malwatch_waf_rules.lng`, `ispconfig/interface/lang/en_malwatch_waf_rules.lng` (Block am Dateiende)
- Test: `ispconfig/tests/waf_rules_catalog_test.php`

**Interfaces:**
- Consumes: Katalogformat und Test aus Task A3
- Produces: Einträge für 31 Regeln (949110, 950130 bis 954130, 959100, 980130, 980140); der Katalog deckt damit alle 170 IDs der Fixture ab

- [ ] **Step 1: Test erweitern**

In `ispconfig/tests/waf_rules_catalog_test.php` die Zeilen

```php
$covered = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934', '944',
	'941', '942', '943');
```

ersetzen durch:

```php
$covered = array('910', '911', '912', '913', '920', '921', '922', '930', '931', '932', '933', '934', '944',
	'941', '942', '943', '949', '950', '951', '952', '953', '954', '959', '980');
```

und vor dem Block `// --- summary` einfügen:

```php
// Every group of the fixture is covered, so every id has its entries.
expect_same('covered groups match the fixture', array_values(array_diff(
	array_unique(array_map(function ($id) {
		return substr($id, 0, 3);
	}, $ids)),
	$covered
)), array());
expect_same('catalog size', array(count($catalogs['de']['rules']), count($catalogs['en']['rules'])), array(170, 170));
```

- [ ] **Step 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_rules_catalog_test.php`
Expected: FAIL, unter anderem `FAIL de 949110 title: false, erwartet true` und `FAIL catalog size:` mit je 139 statt 170 Einträgen.

- [ ] **Step 3: Einträge anhängen**

Am Ende von `ispconfig/interface/lang/de_malwatch_waf_rules.lng` anhängen:

```php

// --- 949 and 950 to 980: scoring and the response of the website -----------------
$wb['rule_949110_title'] = 'Punktgrenze überschritten';
$wb['rule_949110_what'] = 'Die Regeln haben für diese Anfrage zusammen mehr Punkte vergeben, als die Grenze erlaubt. Im scharfen Modus weist allein diese Regel die Anfrage ab.';
$wb['rule_949110_class'] = 'scoring';
$wb['rule_950130_title'] = 'Verzeichnisliste in der Antwort';
$wb['rule_950130_what'] = 'Die Antwort der Website zeigt den Inhalt eines Verzeichnisses.';
$wb['rule_950130_class'] = 'response';
$wb['rule_950140_title'] = 'CGI-Quelltext in der Antwort';
$wb['rule_950140_what'] = 'Die Antwort enthält Quelltext eines CGI-Skripts.';
$wb['rule_950140_class'] = 'response';
$wb['rule_951110_title'] = 'SQL-Fehler in der Antwort (Microsoft Access)';
$wb['rule_951110_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Microsoft Access. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951110_class'] = 'response';
$wb['rule_951120_title'] = 'SQL-Fehler in der Antwort (Oracle)';
$wb['rule_951120_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Oracle. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951120_class'] = 'response';
$wb['rule_951130_title'] = 'SQL-Fehler in der Antwort (DB2)';
$wb['rule_951130_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank DB2. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951130_class'] = 'response';
$wb['rule_951140_title'] = 'SQL-Fehler in der Antwort (EMC)';
$wb['rule_951140_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank EMC. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951140_class'] = 'response';
$wb['rule_951150_title'] = 'SQL-Fehler in der Antwort (Firebird)';
$wb['rule_951150_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Firebird. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951150_class'] = 'response';
$wb['rule_951160_title'] = 'SQL-Fehler in der Antwort (Frontbase)';
$wb['rule_951160_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Frontbase. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951160_class'] = 'response';
$wb['rule_951170_title'] = 'SQL-Fehler in der Antwort (HSQLDB)';
$wb['rule_951170_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank HSQLDB. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951170_class'] = 'response';
$wb['rule_951180_title'] = 'SQL-Fehler in der Antwort (Informix)';
$wb['rule_951180_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Informix. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951180_class'] = 'response';
$wb['rule_951190_title'] = 'SQL-Fehler in der Antwort (Ingres)';
$wb['rule_951190_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Ingres. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951190_class'] = 'response';
$wb['rule_951200_title'] = 'SQL-Fehler in der Antwort (InterBase)';
$wb['rule_951200_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank InterBase. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951200_class'] = 'response';
$wb['rule_951210_title'] = 'SQL-Fehler in der Antwort (MaxDB)';
$wb['rule_951210_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank MaxDB. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951210_class'] = 'response';
$wb['rule_951220_title'] = 'SQL-Fehler in der Antwort (MSSQL)';
$wb['rule_951220_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank MSSQL. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951220_class'] = 'response';
$wb['rule_951230_title'] = 'SQL-Fehler in der Antwort (MySQL)';
$wb['rule_951230_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank MySQL. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951230_class'] = 'response';
$wb['rule_951240_title'] = 'SQL-Fehler in der Antwort (PostgreSQL)';
$wb['rule_951240_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank PostgreSQL. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951240_class'] = 'response';
$wb['rule_951250_title'] = 'SQL-Fehler in der Antwort (SQLite)';
$wb['rule_951250_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank SQLite. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951250_class'] = 'response';
$wb['rule_951260_title'] = 'SQL-Fehler in der Antwort (Sybase)';
$wb['rule_951260_what'] = 'Die Antwort enthält eine Fehlermeldung der Datenbank Sybase. Sie verrät Angreifern Aufbau und Schwachstellen der Anwendung.';
$wb['rule_951260_class'] = 'response';
$wb['rule_952100_title'] = 'Java-Quelltext in der Antwort';
$wb['rule_952100_what'] = 'Die Antwort enthält Java-Quelltext.';
$wb['rule_952100_class'] = 'response';
$wb['rule_952110_title'] = 'Java-Fehler in der Antwort';
$wb['rule_952110_what'] = 'Die Antwort enthält eine Java-Fehlermeldung.';
$wb['rule_952110_class'] = 'response';
$wb['rule_953100_title'] = 'PHP-Fehler in der Antwort';
$wb['rule_953100_what'] = 'Die Antwort enthält eine PHP-Fehlermeldung mit Pfaden oder Details.';
$wb['rule_953100_class'] = 'response';
$wb['rule_953110_title'] = 'PHP-Quelltext in der Antwort';
$wb['rule_953110_what'] = 'Die Antwort enthält PHP-Quelltext.';
$wb['rule_953110_class'] = 'response';
$wb['rule_953120_title'] = 'PHP-Quelltext in der Antwort';
$wb['rule_953120_what'] = 'Die Antwort enthält PHP-Quelltext mit einem PHP-Anfangszeichen.';
$wb['rule_953120_class'] = 'response';
$wb['rule_954100_title'] = 'IIS-Installationspfad in der Antwort';
$wb['rule_954100_what'] = 'Die Antwort verrät den Installationsort eines IIS-Servers.';
$wb['rule_954100_class'] = 'response';
$wb['rule_954110_title'] = 'Verfügbarkeitsfehler in der Antwort';
$wb['rule_954110_what'] = 'Die Antwort enthält eine Fehlermeldung, dass die Anwendung nicht verfügbar ist.';
$wb['rule_954110_class'] = 'response';
$wb['rule_954120_title'] = 'IIS-Angaben in der Antwort';
$wb['rule_954120_what'] = 'Die Antwort enthält interne Angaben eines IIS-Servers.';
$wb['rule_954120_class'] = 'response';
$wb['rule_954130_title'] = 'IIS-Fehlerseite';
$wb['rule_954130_what'] = 'Die Antwort ist eine Fehlerseite eines IIS-Servers mit internen Angaben.';
$wb['rule_954130_class'] = 'response';
$wb['rule_959100_title'] = 'Punktgrenze der Antwort überschritten';
$wb['rule_959100_what'] = 'Die Regeln haben für die Antwort der Website zusammen mehr Punkte vergeben, als die Grenze erlaubt.';
$wb['rule_959100_class'] = 'scoring';
$wb['rule_980130_title'] = 'Punkte der Anfrage (Auswertung)';
$wb['rule_980130_what'] = 'Zusammenfassung am Ende: wie viele Punkte die Anfrage je Angriffsart bekommen hat.';
$wb['rule_980130_class'] = 'scoring';
$wb['rule_980140_title'] = 'Punkte der Antwort (Auswertung)';
$wb['rule_980140_what'] = 'Zusammenfassung am Ende: wie viele Punkte die Antwort bekommen hat.';
$wb['rule_980140_class'] = 'scoring';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf_rules.lng` anhängen:

```php

// --- 949 and 950 to 980: scoring and the response of the website -----------------
$wb['rule_949110_title'] = 'Score limit exceeded';
$wb['rule_949110_what'] = 'The rules gave this request more points in total than the limit allows. In enforce mode this rule alone rejects the request.';
$wb['rule_949110_class'] = 'scoring';
$wb['rule_950130_title'] = 'Directory listing in the response';
$wb['rule_950130_what'] = 'The response of the website shows the contents of a directory.';
$wb['rule_950130_class'] = 'response';
$wb['rule_950140_title'] = 'CGI source code in the response';
$wb['rule_950140_what'] = 'The response contains source code of a CGI script.';
$wb['rule_950140_class'] = 'response';
$wb['rule_951110_title'] = 'SQL error in the response (Microsoft Access)';
$wb['rule_951110_what'] = 'The response contains an error message of the Microsoft Access database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951110_class'] = 'response';
$wb['rule_951120_title'] = 'SQL error in the response (Oracle)';
$wb['rule_951120_what'] = 'The response contains an error message of the Oracle database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951120_class'] = 'response';
$wb['rule_951130_title'] = 'SQL error in the response (DB2)';
$wb['rule_951130_what'] = 'The response contains an error message of the DB2 database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951130_class'] = 'response';
$wb['rule_951140_title'] = 'SQL error in the response (EMC)';
$wb['rule_951140_what'] = 'The response contains an error message of the EMC database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951140_class'] = 'response';
$wb['rule_951150_title'] = 'SQL error in the response (Firebird)';
$wb['rule_951150_what'] = 'The response contains an error message of the Firebird database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951150_class'] = 'response';
$wb['rule_951160_title'] = 'SQL error in the response (Frontbase)';
$wb['rule_951160_what'] = 'The response contains an error message of the Frontbase database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951160_class'] = 'response';
$wb['rule_951170_title'] = 'SQL error in the response (HSQLDB)';
$wb['rule_951170_what'] = 'The response contains an error message of the HSQLDB database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951170_class'] = 'response';
$wb['rule_951180_title'] = 'SQL error in the response (Informix)';
$wb['rule_951180_what'] = 'The response contains an error message of the Informix database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951180_class'] = 'response';
$wb['rule_951190_title'] = 'SQL error in the response (Ingres)';
$wb['rule_951190_what'] = 'The response contains an error message of the Ingres database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951190_class'] = 'response';
$wb['rule_951200_title'] = 'SQL error in the response (InterBase)';
$wb['rule_951200_what'] = 'The response contains an error message of the InterBase database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951200_class'] = 'response';
$wb['rule_951210_title'] = 'SQL error in the response (MaxDB)';
$wb['rule_951210_what'] = 'The response contains an error message of the MaxDB database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951210_class'] = 'response';
$wb['rule_951220_title'] = 'SQL error in the response (MSSQL)';
$wb['rule_951220_what'] = 'The response contains an error message of the MSSQL database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951220_class'] = 'response';
$wb['rule_951230_title'] = 'SQL error in the response (MySQL)';
$wb['rule_951230_what'] = 'The response contains an error message of the MySQL database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951230_class'] = 'response';
$wb['rule_951240_title'] = 'SQL error in the response (PostgreSQL)';
$wb['rule_951240_what'] = 'The response contains an error message of the PostgreSQL database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951240_class'] = 'response';
$wb['rule_951250_title'] = 'SQL error in the response (SQLite)';
$wb['rule_951250_what'] = 'The response contains an error message of the SQLite database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951250_class'] = 'response';
$wb['rule_951260_title'] = 'SQL error in the response (Sybase)';
$wb['rule_951260_what'] = 'The response contains an error message of the Sybase database. It shows attackers the structure and weak spots of the application.';
$wb['rule_951260_class'] = 'response';
$wb['rule_952100_title'] = 'Java source code in the response';
$wb['rule_952100_what'] = 'The response contains Java source code.';
$wb['rule_952100_class'] = 'response';
$wb['rule_952110_title'] = 'Java error in the response';
$wb['rule_952110_what'] = 'The response contains a Java error message.';
$wb['rule_952110_class'] = 'response';
$wb['rule_953100_title'] = 'PHP error in the response';
$wb['rule_953100_what'] = 'The response contains a PHP error message with paths or details.';
$wb['rule_953100_class'] = 'response';
$wb['rule_953110_title'] = 'PHP source code in the response';
$wb['rule_953110_what'] = 'The response contains PHP source code.';
$wb['rule_953110_class'] = 'response';
$wb['rule_953120_title'] = 'PHP source code in the response';
$wb['rule_953120_what'] = 'The response contains PHP source code with a PHP open tag.';
$wb['rule_953120_class'] = 'response';
$wb['rule_954100_title'] = 'IIS install path in the response';
$wb['rule_954100_what'] = 'The response reveals where an IIS server is installed.';
$wb['rule_954100_class'] = 'response';
$wb['rule_954110_title'] = 'Availability error in the response';
$wb['rule_954110_what'] = 'The response contains an error message saying the application is unavailable.';
$wb['rule_954110_class'] = 'response';
$wb['rule_954120_title'] = 'IIS details in the response';
$wb['rule_954120_what'] = 'The response contains internal details of an IIS server.';
$wb['rule_954120_class'] = 'response';
$wb['rule_954130_title'] = 'IIS error page';
$wb['rule_954130_what'] = 'The response is an error page of an IIS server with internal details.';
$wb['rule_954130_class'] = 'response';
$wb['rule_959100_title'] = 'Response score limit exceeded';
$wb['rule_959100_what'] = 'The rules gave the response of the website more points in total than the limit allows.';
$wb['rule_959100_class'] = 'scoring';
$wb['rule_980130_title'] = 'Points of the request (summary)';
$wb['rule_980130_what'] = 'Summary at the end: how many points the request got per kind of attack.';
$wb['rule_980130_class'] = 'scoring';
$wb['rule_980140_title'] = 'Points of the response (summary)';
$wb['rule_980140_what'] = 'Summary at the end: how many points the response got.';
$wb['rule_980140_class'] = 'scoring';
```

- [ ] **Step 4: Test laufen lassen**

Run: `php ispconfig/tests/waf_rules_catalog_test.php && php ispconfig/tests/waf_panel_test.php`
Expected: `waf_rules_catalog: alle Prüfungen bestanden` und `waf_panel: alle Prüfungen bestanden`.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/lang/de_malwatch_waf_rules.lng ispconfig/interface/lang/en_malwatch_waf_rules.lng ispconfig/tests/waf_rules_catalog_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): rule catalog for scoring and responses, all 170 rules" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A7: Daten für Regel-Karten, Adressfilter und Katalog in den Hilfsfunktionen

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (`waf_panel_rules()`, `waf_panel_hit()`, `waf_panel_enforce()`; neue Funktionen nach `waf_panel_paths()`)
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_panel_rule_info()`, `waf_panel_rule_title()` (A3), `waf_panel_trigger_text()` (A2)
- Produces:
  - `waf_panel_ranked($counts)` → `array(array('key' => string, 'count' => int), …)`, höchste Zahl zuerst, bei Gleichstand nach Schlüssel
  - `waf_panel_rule_hits($wb, $catalog, $rows)` → `array(<rule_id> => array('hits' => int, 'logged_in' => int, 'addresses' => ranked, 'triggers' => ranked))`
  - `waf_panel_ip_filter($get)` → gültige IP-Adresse oder `''`
  - `waf_panel_ip_filter_rejected($get)` → die eingegebene Angabe (höchstens 64 Bytes), wenn sie keine gültige IP-Adresse ist, sonst `''`; Task A8 zeigt dazu eine Meldung
  - `waf_panel_rules($wb, $rows, $catalog = array())`, `waf_panel_enforce($wb, $site, $totals, $rule_rows, $settings, $now, $catalog = array())`
  - `waf_panel_hit($wb, $row, $catalog = array())`: jede Regel trägt zusätzlich `trigger`, `class` (Schlüssel aus `waf_panel_rule_classes()` oder `''`), `class_label`, `class_text`, `note`

- [ ] **Step 1: Tests schreiben**

In `ispconfig/tests/waf_panel_test.php` vor dem Block `// --- A3: rule catalog` einfügen:

```php
// --- A7: rule cards, address filter, catalog in the helpers ----------------------

expect_same('ranked', waf_panel_ranked(array('b' => 2, 'a' => 2, 'c' => 5)), array(
	array('key' => 'c', 'count' => 5), array('key' => 'a', 'count' => 2), array('key' => 'b', 'count' => 2),
));
expect_same('ranked turns numeric keys into strings', waf_panel_ranked(array('17' => 1)), array(array('key' => '17', 'count' => 1)));

$card_catalog = array('rules' => array('920440' => array('title' => 'Verbotene Dateiendung', 'trigger' => 'Dateiendung „%s“')),
	'groups' => array());
$card_rows = array(
	array('client_ip' => '192.0.2.7', 'logged_in' => 'n', 'rules' => '[{"id":"930130","msg":"Restricted File Access Attempt",'
		. '"data":"Matched Data: .env found within REQUEST_FILENAME: /.env","param":""},'
		. '{"id":"920440","msg":"URL file extension is restricted by policy","data":".bak","param":""}]'),
	array('client_ip' => '192.0.2.7', 'logged_in' => 'n', 'rules' => '[{"id":"930130","msg":"x",'
		. '"data":"Matched Data: .env found within REQUEST_FILENAME: /x/.env","param":""}]'),
	array('client_ip' => '198.51.100.3', 'logged_in' => 'y', 'rules' => '[{"id":"930130","msg":"x",'
		. '"data":"Matched Data: .git/config found within REQUEST_FILENAME: /.git/config","param":""}]'),
	array('client_ip' => '', 'logged_in' => 'n', 'rules' => 'kaputt'),
);
$card = waf_panel_rule_hits($wb, $card_catalog, $card_rows);
expect_same('card rules', array_map('strval', array_keys($card)), array('930130', '920440'));
expect_same('card figures', array($card['930130']['hits'], $card['930130']['logged_in']), array(3, 1));
expect_same('card addresses', $card['930130']['addresses'], array(
	array('key' => '192.0.2.7', 'count' => 2), array('key' => '198.51.100.3', 'count' => 1),
));
expect_same('card triggers', $card['930130']['triggers'], array(
	array('key' => 'Dateiname der Anfrage enthält „.env“', 'count' => 2),
	array('key' => 'Dateiname der Anfrage enthält „.git/config“', 'count' => 1),
));
expect_same('card trigger with the catalog pattern', $card['920440']['triggers'],
	array(array('key' => 'Dateiendung „.bak“', 'count' => 1)));
expect_same('card without rows', waf_panel_rule_hits($wb, $card_catalog, array()), array());

expect_same('ip filter v4', waf_panel_ip_filter(array('ip' => ' 192.0.2.7 ')), '192.0.2.7');
expect_same('ip filter v6', waf_panel_ip_filter(array('ip' => '2001:db8::1')), '2001:db8::1');
expect_same('ip filter rejects text', waf_panel_ip_filter(array('ip' => '192.0.2.7<script>')), '');
expect_same('ip filter without value', waf_panel_ip_filter(array()), '');
expect_same('ip filter rejects arrays', waf_panel_ip_filter(array('ip' => array('192.0.2.7'))), '');
expect_same('ip notice for text', waf_panel_ip_filter_rejected(array('ip' => ' kein-ip ')), 'kein-ip');
expect_same('ip notice for an address', waf_panel_ip_filter_rejected(array('ip' => '192.0.2.7')), '');
expect_same('ip notice without value', waf_panel_ip_filter_rejected(array('ip' => '  ')), '');
expect_same('ip notice for arrays', waf_panel_ip_filter_rejected(array('ip' => array('x'))), '');
expect_same('ip notice cuts long input', strlen(waf_panel_ip_filter_rejected(array('ip' => str_repeat('x', 300)))), 64);

$catalog_rules = waf_panel_rules($wb, $rule_day_rows,
	array('rules' => array('942100' => array('title' => 'SQL-Einschleusung (libinjection)')), 'groups' => array()));
expect_same('rules with catalog titles', array_column($catalog_rules, 'title'),
	array('SQL-Einschleusung (libinjection)', 'Skript-Einschleusung (XSS)', 'Regel 10010'));
$catalog_enforce = waf_panel_enforce($wb, $site, $totals, $enforce_rules, $settings, '2026-09-16 12:00:00',
	array('rules' => array('941100' => array('title' => 'XSS (libinjection)')), 'groups' => array()));
expect_same('enforce with catalog titles', array_column($catalog_enforce['rules'], 'title'),
	array('SQL-Einschleusung', 'XSS (libinjection)'));

$catalog_hit = waf_panel_hit($wb, $hit_row,
	array('rules' => array('942190' => array('title' => 'Ausspähen der Datenbank', 'class' => 'attack')), 'groups' => array()));
expect_same('hit rule with catalog', array($catalog_hit['rules'][1]['title'], $catalog_hit['rules'][1]['class'],
	$catalog_hit['rules'][1]['class_label'], $catalog_hit['rules'][1]['trigger'], $catalog_hit['rules'][1]['note']),
	array('Ausspähen der Datenbank', 'attack', 'Angriffsversuch', 'Gefunden: „x“', ''));
expect_same('hit score rule without trigger', array($catalog_hit['rules'][0]['title'], $catalog_hit['rules'][0]['trigger'],
	$catalog_hit['rules'][0]['class'], $catalog_hit['rules'][0]['class_label'], $catalog_hit['rules'][0]['class_text']),
	array('Punktgrenze überschritten', '', '', '', ''));
```

- [ ] **Step 2: Tests laufen lassen, sie müssen scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit `Call to undefined function waf_panel_ranked()`.

- [ ] **Step 3: Funktionen schreiben**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php`:

In `waf_panel_rules()` die Kopfzeile

```php
function waf_panel_rules($wb, $rows)
```

ersetzen durch

```php
function waf_panel_rules($wb, $rows, $catalog = array())
```

und in ihr die Zeile

```php
		$rule['title'] = waf_panel_rule_title($wb, $id, $rule['msg']);
```

ersetzen durch

```php
		$rule['title'] = waf_panel_rule_title($wb, $id, $rule['msg'], $catalog);
```

In `waf_panel_enforce()` die Kopfzeile

```php
function waf_panel_enforce($wb, $site, $totals, $rule_rows, $settings, $now)
```

ersetzen durch

```php
function waf_panel_enforce($wb, $site, $totals, $rule_rows, $settings, $now, $catalog = array())
```

und in ihr

```php
				'title' => waf_panel_rule_title($wb, $row['rule_id'], $row['rule_msg']),
```

ersetzen durch

```php
				'title' => waf_panel_rule_title($wb, $row['rule_id'], $row['rule_msg'], $catalog),
```

In `waf_panel_hit()` die Kopfzeile

```php
function waf_panel_hit($wb, $row)
```

ersetzen durch

```php
function waf_panel_hit($wb, $row, $catalog = array())
```

und die Zeilen

```php
		$list[] = array('rule_id' => $id, 'title' => waf_panel_rule_title($wb, $id, $msg), 'msg' => $msg,
			'data' => isset($rule['data']) ? (string) $rule['data'] : '', 'param' => $param);
```

ersetzen durch

```php
		$data = isset($rule['data']) ? (string) $rule['data'] : '';
		$info = waf_panel_rule_info($wb, $catalog, $id, $msg);
		$list[] = array('rule_id' => $id, 'title' => $info['title'], 'msg' => $msg, 'data' => $data, 'param' => $param,
			'trigger' => waf_panel_trigger_text($wb, $data, $info['trigger']),
			'class' => $info['class'], 'class_label' => $info['class_label'], 'class_text' => $info['class_text'],
			'note' => $info['note']);
```

Den Kommentar über `waf_panel_hit()` ergänzen, sodass er lautet:

```php
/**
 * One stored hit for the detail page. Each rule carries its title, the
 * trigger in words and its class from $catalog. prefill is what the
 * exception form starts with: the first rule an exception may name, its
 * parameter, the path.
 */
```

Direkt nach der Funktion `waf_panel_paths()` einfügen:

```php
/**
 * array(key => count) as a list of array('key' => ..., 'count' => ...), the
 * highest count first, equal counts by key.
 */
function waf_panel_ranked($counts)
{
	$list = array();
	foreach ($counts as $key => $count) {
		$list[] = array('key' => (string) $key, 'count' => (int) $count);
	}
	usort($list, function ($a, $b) {
		return $a['count'] !== $b['count'] ? $b['count'] - $a['count'] : strcmp($a['key'], $b['key']);
	});
	return $list;
}

/**
 * Addresses and triggers per rule from stored hits of one website. $rows come
 * from malwatch_waf_hit (client_ip, logged_in, rules). Each rule gets hits,
 * logged_in, and its addresses and triggers as waf_panel_ranked() lists.
 */
function waf_panel_rule_hits($wb, $catalog, $rows)
{
	$rules = array();
	foreach ($rows as $row) {
		$list = json_decode((string) $row['rules'], true);
		if (!is_array($list)) {
			continue;
		}
		$ip = (string) $row['client_ip'];
		$logged_in = (string) $row['logged_in'] === 'y';
		foreach ($list as $rule) {
			$id = isset($rule['id']) ? (string) $rule['id'] : '';
			if ($id === '') {
				continue;
			}
			if (!isset($rules[$id])) {
				$rules[$id] = array('hits' => 0, 'logged_in' => 0, 'addresses' => array(), 'triggers' => array());
			}
			$rules[$id]['hits']++;
			if ($logged_in) {
				$rules[$id]['logged_in']++;
			}
			if ($ip !== '') {
				$rules[$id]['addresses'][$ip] = (isset($rules[$id]['addresses'][$ip]) ? $rules[$id]['addresses'][$ip] : 0) + 1;
			}
			$pattern = isset($catalog['rules'][$id]['trigger']) ? (string) $catalog['rules'][$id]['trigger'] : '';
			$text = waf_panel_trigger_text($wb, isset($rule['data']) ? $rule['data'] : '', $pattern);
			if ($text !== '') {
				$rules[$id]['triggers'][$text] = (isset($rules[$id]['triggers'][$text]) ? $rules[$id]['triggers'][$text] : 0) + 1;
			}
		}
	}
	foreach ($rules as $id => $rule) {
		$rules[$id]['addresses'] = waf_panel_ranked($rule['addresses']);
		$rules[$id]['triggers'] = waf_panel_ranked($rule['triggers']);
	}
	return $rules;
}

/** The address filter of the website page: a valid IP address, else ''. */
function waf_panel_ip_filter($get)
{
	$ip = isset($get['ip']) && is_string($get['ip']) ? trim($get['ip']) : '';
	return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
}

/**
 * The address filter as typed when it is no valid IP address, cut to 64
 * bytes for the notice on the page; '' when the filter is empty or valid.
 */
function waf_panel_ip_filter_rejected($get)
{
	$ip = isset($get['ip']) && is_string($get['ip']) ? trim($get['ip']) : '';
	return $ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) === false ? waf_cut($ip, 64) : '';
}
```

- [ ] **Step 4: Tests laufen lassen**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php -l ispconfig/interface/lib/malwatch_waf_panel.inc.php`
Expected: `waf_panel: alle Prüfungen bestanden`, `waf_panel_post: alle Prüfungen bestanden`, `No syntax errors detected`.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/tests/waf_panel_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): addresses and triggers per rule, address filter" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A8: Website-Seite mit Adressen, Auslösern und Einordnung

**Files:**
- Modify: `ispconfig/interface/malwatch_waf_show.php` (ganze Datei)
- Modify: `ispconfig/interface/templates/malwatch_waf_show.htm`
- Modify: `ispconfig/interface/malwatch_waf_list.php`, `ispconfig/interface/malwatch_waf_exception_list.php` (Sprachblock, Aufruf von `waf_panel_rule_title()`)
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `ispconfig/interface/lang/en_malwatch_waf.lng` (Block am Dateiende)
- Modify: `ispconfig/install/schema.sql` (Index `site_ip` auf `malwatch_waf_hit`)
- Test: `ispconfig/tests/check_wiring.sh` (Prüfungen 64 bis 66), `ispconfig/tests/render_pages.php`, Nachbau unter `.superpowers/abwehr/harness/` (nur auf diesem Rechner, git-ignoriert)

**Interfaces:**
- Consumes: `waf_panel_rule_catalog()`, `waf_panel_rule_catalog_file()`, `waf_panel_rule_info()` (A3); `waf_panel_rule_hits()`, `waf_panel_ip_filter()`, `waf_panel_rules()`, `waf_panel_enforce()` und `waf_panel_hit()` mit `$catalog` (A7); `waf_panel_settings($app)['waf_card_hits']` (A1)
- Produces: `security/malwatch_waf_show.php?id=<n>&days=<n>&ip=<adresse>`; Index `site_ip` (`parent_domain_id`, `client_ip`, `seen_at`); die Sprachschlüssel aus Step 4; der Eintrag `malwatch_waf_show.php?ip=stored` in `render_pages.php`, den Task A10 auf dem Server nutzt

Die Regel-Karten lesen die jüngsten `waf_card_hits` gespeicherten Anfragen der Website, sortiert wie die Liste der Einzeltreffer (`seen_at`, dann `hit_id`); so trägt der vorhandene Index `site_seen`. Der Adressfilter liest über den neuen Index `site_ip`. Nach einem Knopf kommt der Filter als verstecktes Feld `ip` zurück, wie `days`. Eine Angabe, die keine IP-Adresse ist, lässt die Liste ungefiltert; die Seite sagt das über den Einzeltreffern und nennt den Weg zum Filtern (Vorgabe „Verständliche Fehlermeldungen“).

- [ ] **Step 1: Prüfungen schreiben**

In `ispconfig/tests/check_wiring.sh` vor dem Block `if [ "$status" -eq 0 ]; then` am Dateiende einfügen:

```sh
# 64. The address filter of the website page takes an address only through
#     waf_panel_ip_filter(), and that function lets FILTER_VALIDATE_IP decide.
#     The value ends up in links and in a query; a page that reads ip itself
#     skips the check.
if ! sed -n '/^function waf_panel_ip_filter(/,/^}/p' "$root/interface/lib/malwatch_waf_panel.inc.php" | grep -q 'FILTER_VALIDATE_IP'; then
	fail "waf_panel_ip_filter() does not check the address with FILTER_VALIDATE_IP"
fi
grep -q 'waf_panel_ip_filter(' "$root/interface/malwatch_waf_show.php" \
	|| fail "malwatch_waf_show.php takes the address filter without waf_panel_ip_filter()"
for page in "$root"/interface/*.php; do
	if grep -qE "\\\$_(GET|POST|REQUEST)\[['\"]ip['\"]\]" "$page"; then
		fail "$(basename "$page") reads the address filter itself; waf_panel_ip_filter() checks it"
	fi
done

# 65. The rule catalog reaches every rule title. A page of the Abwehr that
#     names rules loads the catalog next to its language file and hands it to
#     every helper that names one; without it the page shows the English
#     message of the rule set.
for page in "$root"/interface/malwatch_waf_*.php; do
	[ -f "$page" ] || continue
	calls=$(grep -E 'waf_panel_(rule_title|rules|hit|enforce)\(' "$page" || true)
	[ -n "$calls" ] || continue
	grep -qF "waf_panel_rule_catalog(waf_panel_rule_catalog_file('lib/lang', \$language))" "$page" \
		|| fail "$(basename "$page") names rules but does not load the rule catalog"
	if printf '%s\n' "$calls" | grep -qvF '$catalog'; then
		fail "$(basename "$page") names a rule without the catalog"
	fi
done
for lang in de en; do
	[ -f "$root/interface/lang/${lang}_malwatch_waf_rules.lng" ] \
		|| fail "interface/lang/${lang}_malwatch_waf_rules.lng is missing"
done

# 66. The address filter reads malwatch_waf_hit by website and address
#     through the index site_ip. CREATE TABLE brings it to new installs only,
#     the guarded ALTER TABLE to existing ones.
grep -qF 'KEY `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`)' "$root/install/schema.sql" \
	|| fail "schema.sql creates malwatch_waf_hit without the index site_ip"
grep -qF 'ADD INDEX `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`)' "$root/install/schema.sql" \
	|| fail "schema.sql does not add the index site_ip to existing installs"
```

In `ispconfig/tests/render_pages.php` nach der Zeile `'malwatch_waf_show.php?days=90',` einfügen:

```php
	// Abwehr: the website filtered by the address of its latest stored request.
	'malwatch_waf_show.php?ip=stored',
```

vor der Zeile `$_SESSION['s']['user'] = array(` einfügen:

```php
// The address of the latest stored request of the website, so the filter runs
// on rows that exist. Without stored requests the page stays unfiltered.
if (isset($mw_query['ip']) && $mw_query['ip'] === 'stored') {
	$latest = $app->db->queryOneRecord('SELECT client_ip FROM malwatch_waf_hit WHERE parent_domain_id = ? '
		. 'ORDER BY seen_at DESC, hit_id DESC LIMIT 1', $domain_id);
	$mw_query['ip'] = is_array($latest) ? (string) $latest['client_ip'] : '';
}
```

vor der Zeile `$why = '';` einfügen:

```php
// A page filtered by an address says so and opens at the stored requests.
$unfiltered = isset($mw_query['ip']) && $mw_query['ip'] !== ''
	&& (strpos($out, 'class="mw-ipfilter"') === false || strpos($out, "getElementById('mw-hits')") === false);
```

und die Zeilen

```php
} elseif ($unjumped) {
	$why = 'no section to open at for show=' . $mw_query['show'];
```

ersetzen durch

```php
} elseif ($unjumped) {
	$why = 'no section to open at for show=' . $mw_query['show'];
} elseif ($unfiltered) {
	$why = 'address filter without its note or jump';
```

- [ ] **Step 2: Prüfungen laufen lassen, sie müssen scheitern**

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: Ende mit Status 1 und genau diesen Zeilen:

- `FAIL: malwatch_waf_show.php takes the address filter without waf_panel_ip_filter()`
- `FAIL: malwatch_waf_exception_list.php names rules but does not load the rule catalog`
- `FAIL: malwatch_waf_exception_list.php names a rule without the catalog`
- `FAIL: malwatch_waf_list.php names rules but does not load the rule catalog`
- `FAIL: malwatch_waf_list.php names a rule without the catalog`
- `FAIL: malwatch_waf_show.php names rules but does not load the rule catalog`
- `FAIL: malwatch_waf_show.php names a rule without the catalog`
- `FAIL: schema.sql creates malwatch_waf_hit without the index site_ip`
- `FAIL: schema.sql does not add the index site_ip to existing installs`

Run: `php -l ispconfig/tests/render_pages.php`
Expected: `No syntax errors detected`. Die Datei selbst läuft nur auf einem Server mit ISPConfig (Task A10).

- [ ] **Step 3: Index anlegen**

In `ispconfig/install/schema.sql` im Block `CREATE TABLE IF NOT EXISTS \`malwatch_waf_hit\`` die Zeile

```sql
  KEY `site_seen` (`parent_domain_id`,`seen_at`),
```

ersetzen durch

```sql
  KEY `site_seen` (`parent_domain_id`,`seen_at`),
  KEY `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`),
```

und vor der Zeile `-- waf carries the jobs of the page Abwehr. The malwatch cron works on them` einfügen (nach dem Block aus Task A1):

```sql
-- The address filter of the website page reads the stored requests of one
-- address; the index reaches existing installs here.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_waf_hit` ADD INDEX `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`)',
  'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_waf_hit' AND INDEX_NAME = 'site_ip');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;
```

InnoDB legt den Index ohne Sperre der Tabelle an; die Tabelle hält nur die Anfragen der letzten `waf_detail_days` Tage.

- [ ] **Step 4: Sprachtexte**

Am Ende von `ispconfig/interface/lang/de_malwatch_waf.lng` anhängen:

```php

// The rule cards and stored requests of the website page.
$wb['addresses_head_txt'] = 'Adressen aus den gespeicherten Anfragen (%s Tage)';
$wb['addresses_capped_txt'] = 'Adressen aus den neuesten %s gespeicherten Anfragen';
$wb['addresses_more_txt'] = 'und %s weitere';
$wb['addresses_none_txt'] = 'Keine dieser Anfragen enthält die Regel.';
$wb['count_times_txt'] = '%s×';
$wb['logged_in_share_txt'] = '%1$s von %2$s Treffern kamen von angemeldeten Nutzern.';
$wb['logged_in_hint_txt'] = 'Die Anfrage kam von einem angemeldeten Nutzer; das spricht für einen Fehlalarm.';
$wb['what_label_txt'] = 'Was erkannt wurde:';
$wb['triggers_head_txt'] = 'Häufigste Auslöser:';
$wb['class_label_txt'] = 'Einordnung:';
$wb['trigger_label_txt'] = 'Ausgelöst durch:';
$wb['crs_label_txt'] = 'Meldung des Regelwerks: %s';
$wb['ip_filter_txt'] = 'Nur Anfragen von %s.';
$wb['ip_filter_clear_txt'] = 'Filter aufheben';
$wb['ip_filter_none_txt'] = 'Von dieser Adresse ist keine Anfrage gespeichert.';
$wb['ip_filter_invalid_txt'] = '„%s“ ist keine gültige IP-Adresse. Die Liste zeigt deshalb alle gespeicherten Anfragen; zum Filtern eine Adresse in einer Regel-Karte oder einer Anfrage anklicken.';
$wb['ip_only_txt'] = 'Nur Anfragen dieser Adresse';
```

Am Ende von `ispconfig/interface/lang/en_malwatch_waf.lng` anhängen:

```php

// The rule cards and stored requests of the website page.
$wb['addresses_head_txt'] = 'Addresses in the stored requests (%s days)';
$wb['addresses_capped_txt'] = 'Addresses in the latest %s stored requests';
$wb['addresses_more_txt'] = 'and %s more';
$wb['addresses_none_txt'] = 'None of these requests contains the rule.';
$wb['count_times_txt'] = '%s×';
$wb['logged_in_share_txt'] = '%1$s of %2$s hits came from logged-in users.';
$wb['logged_in_hint_txt'] = 'The request came from a logged-in user, which points to a false positive.';
$wb['what_label_txt'] = 'What was detected:';
$wb['triggers_head_txt'] = 'Most frequent triggers:';
$wb['class_label_txt'] = 'Assessment:';
$wb['trigger_label_txt'] = 'Triggered by:';
$wb['crs_label_txt'] = 'Message of the rule set: %s';
$wb['ip_filter_txt'] = 'Only requests from %s.';
$wb['ip_filter_clear_txt'] = 'Remove filter';
$wb['ip_filter_none_txt'] = 'No request from this address is stored.';
$wb['ip_filter_invalid_txt'] = '"%s" is not a valid IP address. The list therefore shows every stored request; to filter, click an address on a rule card or in a request.';
$wb['ip_only_txt'] = 'Only requests from this address';
```

- [ ] **Step 5: Website-Seite**

`ispconfig/interface/malwatch_waf_show.php` vollständig ersetzen durch:

```php
<?php

/**
 * Abwehr for one website: the state with its switch and the preview for
 * enforce, the history, the rules with their addresses and explanations,
 * the paths and stored requests of the period, the exceptions and the form
 * that adds one.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';
require_once 'lib/malwatch_waf_panel.inc.php';

$language = $app->functions->check_language($_SESSION['s']['language']);
$lng_file = 'lib/lang/' . $language . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;
$catalog = waf_panel_rule_catalog(waf_panel_rule_catalog_file('lib/lang', $language));

$domain_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);
// The address filter of the stored requests; after a button it comes back as
// a hidden field of the form.
$ip_filter = waf_panel_ip_filter(array_merge($_GET, $_POST));
$ip_rejected = waf_panel_ip_filter_rejected(array_merge($_GET, $_POST));
$ip_query = $ip_filter !== '' ? '&ip=' . rawurlencode($ip_filter) : '';

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_show.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('state_head_txt', 'btn_set_off_txt', 'btn_set_detect_txt',
	'btn_set_enforce_txt', 'confirm_set_off_txt', 'confirm_set_detect_txt', 'confirm_set_enforce_txt',
	'btn_exception_remove_txt', 'confirm_exception_remove_txt', 'btn_exception_add_txt',
	'confirm_exception_add_txt', 'preview_wait_txt')));
$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));
$csrf = $app->auth->csrf_token_get('malwatch_waf_show');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$site = $domain_id > 0 ? $app->db->queryOneRecord(
	'SELECT w.domain_id, w.domain, s.waf_state, s.waf_state_since, s.waf_pending_state FROM web_domain w '
	. "LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id WHERE w.domain_id = ? AND w.type = 'vhost'", $domain_id) : null;
$app->tpl->setVar('has_site', is_array($site) ? 1 : 0);
if (!is_array($site)) {
	$app->tpl_defaults();
	$app->tpl->pparse();
	exit;
}

$settings = waf_panel_settings($app);
$clock = waf_panel_clock($app);
$filters = waf_panel_filters(array_merge($_GET, $_POST), $settings['waf_stats_days']);
$days = $filters['days'];
$state = waf_state_valid((string) $site['waf_state']) ? (string) $site['waf_state'] : 'off';

$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('domain', $app->functions->htmlentities($site['domain']));
$app->tpl->setVar('days', $days);
$app->tpl->setVar('ip_value', $app->functions->htmlentities($ip_filter));
$app->tpl->setVar('state_class', $state);
$app->tpl->setVar('state_label', $app->functions->htmlentities(waf_panel_state_label($wb, $state)));
$app->tpl->setVar('state_line', $app->functions->htmlentities(sprintf($wb['state_current_txt'], waf_panel_state_label($wb, $state))
	. ($state !== 'off' && (string) $site['waf_state_since'] !== '' ? ', ' . sprintf($wb['since_txt'], malwatch_datetime($site['waf_state_since'])) : '')));
$app->tpl->setVar('is_off', $state === 'off' ? 1 : 0);
$app->tpl->setVar('is_detect', $state === 'detect' ? 1 : 0);
$app->tpl->setVar('is_enforce', $state === 'enforce' ? 1 : 0);

// Jobs that change this website, or every website, are followed like on the overview.
$pending = false;
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	if (in_array($domain_id, $job['sites'], true)) {
		$pending = true;
	}
	$first_job = $first_job === 0 ? $job['job_id'] : $first_job;
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setVar('is_pending', $pending || (string) $site['waf_pending_state'] !== '' ? 1 : 0);
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);
$app->tpl->setVar('self_href', $app->functions->htmlentities('security/malwatch_waf_show.php?id=' . $domain_id . '&days=' . $days . $ip_query));

// The preview for enforce.
$totals = $app->db->queryOneRecord(
	'SELECT COALESCE(SUM(would_block), 0) AS would_block, COALESCE(SUM(would_block_logged_in), 0) AS would_block_logged_in '
	. 'FROM malwatch_waf_site_day WHERE parent_domain_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)',
	$domain_id, $settings['waf_preview_days'] - 1);
$block_rules = waf_panel_rows($app->db->queryAllRecords(
	'SELECT rule_id, MAX(rule_msg) AS rule_msg, SUM(would_block_hits) AS would_block_hits FROM malwatch_waf_day '
	. 'WHERE parent_domain_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY rule_id',
	$domain_id, $settings['waf_preview_days'] - 1));
$enforce = waf_panel_enforce($wb, $site, $totals, $block_rules, $settings, $clock['now'], $catalog);
$app->tpl->setVar('enforce_allowed', $enforce['allowed'] ? 1 : 0);
$hint = $enforce['reason'] !== '' ? waf_panel_reason_label($wb, $enforce['reason']) : '';
if ($enforce['reason'] === 'too_early' && $enforce['free_from'] !== '') {
	$hint .= ' ' . sprintf($wb['free_from_txt'], malwatch_datetime($enforce['free_from']));
}
$app->tpl->setVar('enforce_hint', $app->functions->htmlentities($hint));
$app->tpl->setVar('preview_line', $app->functions->htmlentities($enforce['would_block'] > 0
	? sprintf($wb['preview_block_txt'], $enforce['days'], number_format($enforce['would_block'], 0, ',', '.'),
		number_format($enforce['logged_in'], 0, ',', '.'))
	: sprintf($wb['preview_block_none_txt'], $enforce['days'])));
$block_rows = array();
foreach (array_slice($enforce['rules'], 0, 8) as $rule) {
	$block_rows[] = array('rule_line' => $app->functions->htmlentities($rule['title'] . ' (' . $rule['rule_id'] . '): '
		. number_format($rule['hits'], 0, ',', '.')));
}
$app->tpl->setLoop('block_rules', $block_rows);
$app->tpl->setVar('has_block_rules', count($block_rows) > 0 ? 1 : 0);

// Period links and history.
$link = 'security/malwatch_waf_show.php?id=' . $domain_id . '&days=';
$periods = array();
foreach (waf_periods($settings['waf_stats_days']) as $period) {
	$periods[] = array(
		'label' => $app->functions->htmlentities($period === 1 ? $wb['period_today_txt'] : sprintf($wb['period_days_txt'], $period)),
		'href' => $app->functions->htmlentities($link . $period . $ip_query),
		'current' => $period === $days ? 1 : 0,
	);
}
$app->tpl->setLoop('periods', $periods);

$series = waf_panel_day_series(waf_panel_rows($app->db->queryAllRecords(
	'SELECT day, hits, would_block FROM malwatch_waf_site_day WHERE parent_domain_id = ? '
	. 'AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $domain_id, $days - 1)), $clock['today'], $days);
$max = 1;
foreach ($series as $day) {
	$max = max($max, $day['hits']);
}
$bars = array();
foreach ($series as $day) {
	$bars[] = array(
		'hit_pct' => (int) round($day['hits'] * 100 / $max),
		'block_pct' => $day['hits'] > 0 ? (int) round($day['would_block'] * 100 / $day['hits']) : 0,
		'bar_title' => $app->functions->htmlentities(sprintf($wb['history_bar_txt'], waf_panel_day_label($day['day']),
			number_format($day['hits'], 0, ',', '.'), number_format($day['would_block'], 0, ',', '.'))),
	);
}
$app->tpl->setLoop('bars', $bars);
$app->tpl->setVar('chart_max', number_format($max, 0, ',', '.'));
$app->tpl->setVar('chart_first', count($series) > 0 ? $app->functions->htmlentities(waf_panel_day_label($series[0]['day'])) : '');
$app->tpl->setVar('chart_last', count($series) > 1
	? $app->functions->htmlentities(waf_panel_day_label($series[count($series) - 1]['day'])) : '');

// Rules and paths of the period. The latest stored requests, up to
// waf_card_hits of them, give each rule its addresses and triggers.
$day_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT day, rule_id, rule_msg, path, hits, would_block_hits FROM malwatch_waf_day WHERE parent_domain_id = ? '
	. 'AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $domain_id, $days - 1));
$card_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT client_ip, logged_in, rules FROM malwatch_waf_hit WHERE parent_domain_id = ? '
	. 'ORDER BY seen_at DESC, hit_id DESC LIMIT ?', $domain_id, (int) $settings['waf_card_hits']));
$card_hits = waf_panel_rule_hits($wb, $catalog, $card_rows);
$app->tpl->setVar('rule_addresses_head', $app->functions->htmlentities(count($card_rows) >= $settings['waf_card_hits']
	? sprintf($wb['addresses_capped_txt'], number_format($settings['waf_card_hits'], 0, ',', '.'))
	: sprintf($wb['addresses_head_txt'], $settings['waf_detail_days'])));
$no_card = array('hits' => 0, 'logged_in' => 0, 'addresses' => array(), 'triggers' => array());
$rule_rows = array();
foreach (waf_panel_rules($wb, $day_rows, $catalog) as $rule) {
	$info = waf_panel_rule_info($wb, $catalog, $rule['rule_id'], $rule['msg']);
	$seen = isset($card_hits[$rule['rule_id']]) ? $card_hits[$rule['rule_id']] : $no_card;
	$paths = array();
	foreach ($rule['paths'] as $path) {
		$paths[] = array('path' => $app->functions->htmlentities($path['path']), 'path_hits' => number_format($path['hits'], 0, ',', '.'));
	}
	$addresses = array();
	foreach (array_slice($seen['addresses'], 0, 5) as $address) {
		$addresses[] = array(
			'address' => $app->functions->htmlentities($address['key']),
			'address_hits' => $app->functions->htmlentities(sprintf($wb['count_times_txt'], number_format($address['count'], 0, ',', '.'))),
			'address_href' => $app->functions->htmlentities($link . $days . '&ip=' . rawurlencode($address['key'])),
		);
	}
	$triggers = array();
	foreach (array_slice($seen['triggers'], 0, 3) as $trigger) {
		$triggers[] = array(
			'trigger' => $app->functions->htmlentities($trigger['key']),
			'trigger_hits' => $app->functions->htmlentities(sprintf($wb['count_times_txt'], number_format($trigger['count'], 0, ',', '.'))),
		);
	}
	$rule_rows[] = array(
		'rule_id' => $app->functions->htmlentities($rule['rule_id']),
		'rule_title' => $app->functions->htmlentities($info['title']),
		'rule_line' => $app->functions->htmlentities(sprintf($wb['rule_hits_txt'], number_format($rule['hits'], 0, ',', '.'),
			number_format($rule['would_block'], 0, ',', '.'))),
		'rule_last' => $app->functions->htmlentities(sprintf($wb['rule_last_txt'], waf_panel_day_label($rule['last_day']))),
		'rule_paths' => $paths,
		'more_paths' => $rule['path_count'] > count($paths)
			? $app->functions->htmlentities(sprintf($wb['rule_more_paths_txt'], $rule['path_count'] - count($paths))) : '',
		'can_except' => $rule['can_except'] ? 1 : 0,
		'first_path' => $app->functions->htmlentities(count($rule['paths']) === 1 ? $rule['paths'][0]['path'] : ''),
		'rule_addresses' => $addresses,
		'has_addresses' => count($addresses) > 0 ? 1 : 0,
		'more_addresses' => count($seen['addresses']) > 5
			? $app->functions->htmlentities(sprintf($wb['addresses_more_txt'], count($seen['addresses']) - 5)) : '',
		'rule_what' => $app->functions->htmlentities($info['what']),
		'rule_triggers' => $triggers,
		'has_triggers' => count($triggers) > 0 ? 1 : 0,
		'rule_class' => $app->functions->htmlentities($info['class_label']),
		'rule_class_key' => $app->functions->htmlentities($info['class']),
		'rule_class_text' => $app->functions->htmlentities($info['class_text']),
		'rule_note' => $app->functions->htmlentities($info['note']),
		'rule_logged_in' => $seen['logged_in'] > 0
			? $app->functions->htmlentities(sprintf($wb['logged_in_share_txt'], number_format($seen['logged_in'], 0, ',', '.'),
				number_format($seen['hits'], 0, ',', '.'))) : '',
		'rule_crs' => $info['crs'] !== '' ? $app->functions->htmlentities(sprintf($wb['crs_label_txt'], $info['crs'])) : '',
	);
}
$app->tpl->setLoop('rules', $rule_rows);
$app->tpl->setVar('has_rules', count($rule_rows) > 0 ? 1 : 0);

$path_rows = array();
foreach (array_slice(waf_panel_paths($day_rows), 0, 50) as $path) {
	$path_rows[] = array(
		'path' => $app->functions->htmlentities($path['path']),
		'path_hits' => number_format($path['hits'], 0, ',', '.'),
		'path_rules' => $app->functions->htmlentities(implode(', ', $path['rules'])),
	);
}
$app->tpl->setLoop('paths', $path_rows);
$app->tpl->setVar('has_paths', count($path_rows) > 0 ? 1 : 0);

// Stored requests, all of the website or those of one address.
if ($ip_filter !== '') {
	$stored = $app->db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_waf_hit WHERE parent_domain_id = ? AND client_ip = ?',
		$domain_id, $ip_filter);
	$stored_rows = $app->db->queryAllRecords('SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = ? AND client_ip = ? '
		. 'ORDER BY seen_at DESC, hit_id DESC LIMIT 100', $domain_id, $ip_filter);
} else {
	$stored = $app->db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_waf_hit WHERE parent_domain_id = ?', $domain_id);
	$stored_rows = $app->db->queryAllRecords('SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = ? '
		. 'ORDER BY seen_at DESC, hit_id DESC LIMIT 100', $domain_id);
}
$app->tpl->setVar('ip_filter', $ip_filter !== '' ? 1 : 0);
$app->tpl->setVar('ip_jump', $ip_filter !== '' || $ip_rejected !== '' ? 1 : 0);
$app->tpl->setVar('ip_rejected', $app->functions->htmlentities($ip_rejected !== ''
	? sprintf($wb['ip_filter_invalid_txt'], $ip_rejected) : ''));
$app->tpl->setVar('ip_filter_line', $app->functions->htmlentities(sprintf($wb['ip_filter_txt'], $ip_filter)));
$app->tpl->setVar('ip_filter_clear_href', $app->functions->htmlentities($link . $days));
$app->tpl->setVar('hits_none_line', $app->functions->htmlentities($ip_filter !== '' ? $wb['ip_filter_none_txt'] : $wb['hits_none_txt']));
$hit_rows = array();
foreach (waf_panel_rows($stored_rows) as $row) {
	$hit = waf_panel_hit($wb, $row, $catalog);
	$rules = array();
	foreach ($hit['rules'] as $rule) {
		$rules[] = array(
			'hit_rule' => $app->functions->htmlentities($rule['title'] . ' (' . $rule['rule_id'] . ')'),
			'hit_rule_class' => $app->functions->htmlentities($rule['class_label']),
			'hit_rule_class_key' => $app->functions->htmlentities($rule['class']),
			'hit_rule_trigger' => $app->functions->htmlentities($rule['trigger']),
			'hit_rule_class_text' => $app->functions->htmlentities($rule['class_text']),
			'hit_rule_note' => $app->functions->htmlentities($rule['note']),
			'hit_rule_data' => $app->functions->htmlentities(trim($rule['msg'] . ' ' . $rule['data'])),
		);
	}
	$headers = array();
	foreach ($hit['headers'] as $header) {
		$headers[] = array('header_name' => $app->functions->htmlentities($header['name']),
			'header_value' => $app->functions->htmlentities($header['value']));
	}
	$ids = array();
	foreach ($hit['rules'] as $rule) {
		$ids[] = $rule['rule_id'];
	}
	$hit_rows[] = array(
		'hit_id' => $hit['hit_id'],
		'hit_time' => $app->functions->htmlentities(malwatch_datetime($hit['seen_at'])),
		'hit_ip' => $app->functions->htmlentities($hit['client_ip']),
		'hit_has_ip' => $hit['client_ip'] !== '' ? 1 : 0,
		'hit_ip_href' => $app->functions->htmlentities($link . $days . '&ip=' . rawurlencode($hit['client_ip'])),
		'hit_request' => $app->functions->htmlentities($hit['method'] . ' ' . $hit['uri']),
		'hit_ids' => $app->functions->htmlentities(implode(', ', $ids)),
		'hit_score' => $app->functions->htmlentities(sprintf($wb['hit_score_txt'], $hit['score'])),
		'hit_status' => $app->functions->htmlentities(sprintf($wb['hit_status_txt'], $hit['status'])),
		'hit_block' => $hit['would_block'] ? 1 : 0,
		'hit_logged_in' => $hit['logged_in'] ? 1 : 0,
		'hit_rules' => $rules,
		'hit_headers' => $headers,
		'has_body' => $hit['has_body'] ? 1 : 0,
		'hit_body' => $app->functions->htmlentities($hit['body']),
		'has_response' => $hit['has_response'] ? 1 : 0,
		'response_size' => $app->functions->htmlentities(sprintf($wb['response_size_txt'], malwatch_bytes($hit['response_bytes']))),
		'can_except' => $hit['prefill']['rule_id'] !== '' ? 1 : 0,
		'prefill_rule' => $app->functions->htmlentities($hit['prefill']['rule_id']),
		'prefill_path' => $app->functions->htmlentities($hit['prefill']['path']),
		'prefill_param' => $app->functions->htmlentities($hit['prefill']['param']),
	);
}
$app->tpl->setLoop('hits', $hit_rows);
$app->tpl->setVar('has_hits', count($hit_rows) > 0 ? 1 : 0);
$app->tpl->setVar('hits_limit', $app->functions->htmlentities(sprintf($wb['hits_limit_txt'], count($hit_rows),
	number_format(is_array($stored) ? (int) $stored['n'] : 0, 0, ',', '.'), $settings['waf_detail_days'])));

// Exceptions of this website and those for every website.
$exception_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT * FROM malwatch_waf_exception WHERE parent_domain_id = ? OR scope IN ('all','all_path') ORDER BY exception_id",
	$domain_id)) as $row) {
	$exception = waf_panel_exception_row($wb, $row);
	$exception_rows[] = array(
		'exception_id' => $exception['exception_id'],
		'exc_rule' => $app->functions->htmlentities($exception['rule_id']),
		'exc_scope' => $app->functions->htmlentities($exception['scope_label']),
		'exc_target' => $app->functions->htmlentities($exception['target']),
		'exc_note' => $app->functions->htmlentities($exception['note']),
		'exc_state' => $app->functions->htmlentities($exception['state_label']),
		'exc_failed' => $exception['state'] === 'error' ? 1 : 0,
		'exc_error' => $app->functions->htmlentities($exception['error']),
		'exc_created' => $app->functions->htmlentities($exception['created_by'] . ', ' . malwatch_datetime($exception['created_at'])),
		'can_remove' => $exception['can_remove'] ? 1 : 0,
	);
}
$app->tpl->setLoop('exceptions', $exception_rows);
$app->tpl->setVar('has_exceptions', count($exception_rows) > 0 ? 1 : 0);

$scopes = array();
foreach (waf_exception_scopes() as $scope) {
	$scopes[] = array('scope' => $scope, 'scope_label' => $app->functions->htmlentities(waf_panel_scope_label($wb, $scope)),
		'checked' => $scope === 'site_path' ? 1 : 0);
}
$app->tpl->setLoop('scopes', $scopes);

$app->tpl_defaults();
$app->tpl->pparse();
```

Gegenüber 0.19.0: Katalog neben der Sprachdatei, Adressfilter in Abfragen und Verweisen, Regel-Karten mit Adressen, Auslösern, Einordnung und Anteil angemeldeter Nutzer, Einzeltreffer mit Auslöser, Einordnung und Verweis auf die Adresse. `rule_msg` und `hit_rule_param` entfallen; die Meldung des Regelwerks steht in `rule_crs`, der Parameter im Auslöser.

- [ ] **Step 6: Übersicht und Ausnahmeliste**

In `ispconfig/interface/malwatch_waf_list.php` und in `ispconfig/interface/malwatch_waf_exception_list.php` jeweils den Block

```php
$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;
```

ersetzen durch

```php
$language = $app->functions->check_language($_SESSION['s']['language']);
$lng_file = 'lib/lang/' . $language . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;
$catalog = waf_panel_rule_catalog(waf_panel_rule_catalog_file('lib/lang', $language));
```

In `ispconfig/interface/malwatch_waf_list.php` die Zeile

```php
			: $app->functions->htmlentities(waf_panel_rule_title($wb, $row['top_rule'], $row['top_rule_msg'])),
```

ersetzen durch

```php
			: $app->functions->htmlentities(waf_panel_rule_title($wb, $row['top_rule'], $row['top_rule_msg'], $catalog)),
```

In `ispconfig/interface/malwatch_waf_exception_list.php` die Zeile

```php
		'exc_rule_title' => $app->functions->htmlentities(waf_panel_rule_title($wb, $exception['rule_id'], '')),
```

ersetzen durch

```php
		'exc_rule_title' => $app->functions->htmlentities(waf_panel_rule_title($wb, $exception['rule_id'], '', $catalog)),
```

- [ ] **Step 7: Vorlage**

In `ispconfig/interface/templates/malwatch_waf_show.htm` acht Stellen ersetzen.

Stil, die Zeile

```css
#mw-wafsite .mw-rulebtn{margin-left:auto}
```

ersetzen durch

```css
#mw-wafsite .mw-rulebtn{margin-left:auto}
#mw-wafsite .mw-rule ul{margin:2px 0 0;padding-left:18px}
#mw-wafsite .mw-rulecols{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,32ch),1fr));gap:6px 24px;margin:6px 0 4px}
#mw-wafsite .mw-addresses a{color:inherit;text-decoration:underline dotted;text-underline-offset:2px}
#mw-wafsite .mw-addresses a:hover,#mw-wafsite .mw-addresses a:focus-visible{color:var(--cic-accent-text,#dd630d)}
#mw-wafsite details.mw-why > summary{cursor:pointer;display:inline-block;font-size:12.5px;opacity:.85}
#mw-wafsite details.mw-why > summary:focus-visible{outline:2px solid var(--cic-accent,#dd630d);outline-offset:2px}
#mw-wafsite .mw-whybody{display:flex;flex-direction:column;gap:6px;margin:6px 0 2px;padding:6px 12px;max-width:95ch;font-size:13px;
	border-left:2px solid var(--cic-line-soft,rgba(128,128,128,.35))}
#mw-wafsite .mw-whybody ul{margin:2px 0 0}
#mw-wafsite .mw-whyhead{font-weight:600;margin-right:4px}
#mw-wafsite .mw-chip.mw-cls-attack{border-color:var(--cic-bad-deep,#b13116);color:var(--cic-bad-text,#d13f22)}
#mw-wafsite .mw-chip.mw-cls-false_positive_prone{border-style:dashed}
#mw-wafsite .mw-hitip{min-width:15ch}
#mw-wafsite .mw-hitrules{list-style:none;margin:4px 0 0;padding:0;display:flex;flex-direction:column;gap:8px}
#mw-wafsite .mw-hitrules > li{padding-left:10px;border-left:2px solid var(--cic-line-soft,rgba(128,128,128,.35))}
#mw-wafsite .mw-ipfilter,#mw-wafsite .mw-ipnotice{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;margin:0 0 8px;padding:8px 12px;font-size:13px;
	border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));border-left:3px solid var(--cic-accent,#dd630d);border-radius:3px}
#mw-wafsite .mw-ipnotice{border-left-color:var(--cic-bad-deep,#b13116)}
#mw-wafsite #mw-hits{scroll-margin-top:80px}
```

Verstecktes Feld, die Zeile

```html
<input type="hidden" name="days" value="{tmpl_var name='days'}" />
```

ersetzen durch

```html
<input type="hidden" name="days" value="{tmpl_var name='days'}" />
<input type="hidden" name="ip" value="{tmpl_var name='ip_value'}" />
```

Regel-Karte, die Zeilen

```html
		<div class="mw-dim">{tmpl_var name='rule_paths_txt'}</div>
		<ul>
			<tmpl_loop name="rule_paths"><li><span class="mw-mono">{tmpl_var name='path'}</span> <span class="mw-dim">{tmpl_var name='path_hits'}</span></li></tmpl_loop>
		</ul>
		<tmpl_if name="more_paths"><div class="mw-dim">{tmpl_var name='more_paths'}</div></tmpl_if>
		<details><summary class="mw-dim">{tmpl_var name='rule_why_txt'}</summary><div class="mw-mono">{tmpl_var name='rule_msg'}</div></details>
```

ersetzen durch

```html
		<div class="mw-rulecols">
			<div>
				<div class="mw-dim">{tmpl_var name='rule_paths_txt'}</div>
				<ul>
					<tmpl_loop name="rule_paths"><li><span class="mw-mono">{tmpl_var name='path'}</span> <span class="mw-dim">{tmpl_var name='path_hits'}</span></li></tmpl_loop>
				</ul>
				<tmpl_if name="more_paths"><div class="mw-dim">{tmpl_var name='more_paths'}</div></tmpl_if>
			</div>
			<div>
				<div class="mw-dim">{tmpl_var name='rule_addresses_head'}</div>
				<tmpl_if name="has_addresses">
				<ul class="mw-addresses">
					<tmpl_loop name="rule_addresses"><li><a class="mw-mono" href="#" data-load-content="{tmpl_var name='address_href'}">{tmpl_var name='address'}</a> <span class="mw-dim">{tmpl_var name='address_hits'}</span></li></tmpl_loop>
				</ul>
				<tmpl_if name="more_addresses"><div class="mw-dim">{tmpl_var name='more_addresses'}</div></tmpl_if>
				<tmpl_else>
				<div class="mw-dim">{tmpl_var name='addresses_none_txt'}</div>
				</tmpl_if>
				<tmpl_if name="rule_logged_in"><div>{tmpl_var name='rule_logged_in'}</div></tmpl_if>
			</div>
		</div>
		<details class="mw-why">
			<summary>{tmpl_var name='rule_why_txt'}</summary>
			<div class="mw-whybody">
				<tmpl_if name="rule_what"><div><span class="mw-whyhead">{tmpl_var name='what_label_txt'}</span> {tmpl_var name='rule_what'}</div></tmpl_if>
				<tmpl_if name="has_triggers">
				<div><span class="mw-whyhead">{tmpl_var name='triggers_head_txt'}</span>
					<ul><tmpl_loop name="rule_triggers"><li>{tmpl_var name='trigger'} <span class="mw-dim">{tmpl_var name='trigger_hits'}</span></li></tmpl_loop></ul>
				</div>
				</tmpl_if>
				<tmpl_if name="rule_class"><div><span class="mw-whyhead">{tmpl_var name='class_label_txt'}</span> <span class="mw-chip mw-cls-{tmpl_var name='rule_class_key'}">{tmpl_var name='rule_class'}</span> {tmpl_var name='rule_class_text'}</div></tmpl_if>
				<tmpl_if name="rule_note"><div>{tmpl_var name='rule_note'}</div></tmpl_if>
				<tmpl_if name="rule_crs"><div class="mw-dim">{tmpl_var name='rule_crs'}</div></tmpl_if>
			</div>
		</details>
```

Kopf der Einzeltreffer, die Zeile

```html
<p class="mw-sec">{tmpl_var name='hits_head_txt'}</p>
```

ersetzen durch

```html
<p class="mw-sec" id="mw-hits">{tmpl_var name='hits_head_txt'}</p>
<tmpl_if name="ip_rejected">
<p class="mw-ipnotice">{tmpl_var name='ip_rejected'}</p>
</tmpl_if>
<tmpl_if name="ip_filter">
<p class="mw-ipfilter"><span>{tmpl_var name='ip_filter_line'}</span> <a href="#" data-load-content="{tmpl_var name='ip_filter_clear_href'}">{tmpl_var name='ip_filter_clear_txt'}</a></p>
</tmpl_if>
```

Adressspalte im zugeklappten Treffer, die Zeile

```html
		<span class="mw-mono">{tmpl_var name='hit_ip'}</span>
```

ersetzen durch

```html
		<span class="mw-mono mw-hitip">{tmpl_var name='hit_ip'}</span>
```

Aufgeklappter Treffer, die Zeilen

```html
		<div class="mw-dim">{tmpl_var name='hit_status'}</div>
		<div>
			<strong>{tmpl_var name='hit_rules_txt'}</strong>
			<ul><tmpl_loop name="hit_rules"><li>{tmpl_var name='hit_rule'}<tmpl_if name="hit_rule_param"> · <span class="mw-mono">{tmpl_var name='hit_rule_param'}</span></tmpl_if>
				<span class="mw-dim mw-mono">{tmpl_var name='hit_rule_data'}</span></li></tmpl_loop></ul>
		</div>
```

ersetzen durch

```html
		<div class="mw-switch">
			<span class="mw-dim">{tmpl_var name='hit_status'}</span>
			<tmpl_if name="hit_has_ip"><a href="#" data-load-content="{tmpl_var name='hit_ip_href'}">{tmpl_var name='ip_only_txt'}</a></tmpl_if>
		</div>
		<tmpl_if name="hit_logged_in"><div>{tmpl_var name='logged_in_hint_txt'}</div></tmpl_if>
		<div>
			<strong>{tmpl_var name='hit_rules_txt'}</strong>
			<ul class="mw-hitrules"><tmpl_loop name="hit_rules"><li>
				<div>{tmpl_var name='hit_rule'}<tmpl_if name="hit_rule_class"> <span class="mw-chip mw-cls-{tmpl_var name='hit_rule_class_key'}">{tmpl_var name='hit_rule_class'}</span></tmpl_if></div>
				<tmpl_if name="hit_rule_trigger"><div><span class="mw-whyhead">{tmpl_var name='trigger_label_txt'}</span> {tmpl_var name='hit_rule_trigger'}</div></tmpl_if>
				<tmpl_if name="hit_rule_class_text"><div class="mw-dim">{tmpl_var name='hit_rule_class_text'}</div></tmpl_if>
				<tmpl_if name="hit_rule_note"><div class="mw-dim">{tmpl_var name='hit_rule_note'}</div></tmpl_if>
				<tmpl_if name="hit_rule_data"><div class="mw-dim mw-mono">{tmpl_var name='hit_rule_data'}</div></tmpl_if>
			</li></tmpl_loop></ul>
		</div>
```

Leere Liste, die Zeile

```html
<p class="mw-sub">{tmpl_var name='hits_none_txt'}</p>
```

ersetzen durch

```html
<p class="mw-sub">{tmpl_var name='hits_none_line'}</p>
```

Sprung zu den Einzeltreffern, die Zeile

```html
<p class="mw-sec">{tmpl_var name='exceptions_head_txt'}</p>
```

ersetzen durch

```html
<tmpl_if name="ip_jump">
<!--
	Opened with an address filter: the page comes into view at the stored requests.
	The panel scrolls to the top of every page it loads (ispconfig.js); that
	scroll stops first.
-->
<script>
(function () {
	var target = document.getElementById('mw-hits');
	if (!target) { return; }
	if (window.jQuery) { window.jQuery('html, body').stop(true); }
	target.scrollIntoView();
})();
</script>
</tmpl_if>

<p class="mw-sec">{tmpl_var name='exceptions_head_txt'}</p>
```

- [ ] **Step 8: Prüfungen laufen lassen**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php ispconfig/tests/waf_rules_catalog_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`, `waf_panel_post: alle Prüfungen bestanden`, `waf_rules_catalog: alle Prüfungen bestanden`.

Run: `for f in ispconfig/interface/malwatch_waf_show.php ispconfig/interface/malwatch_waf_list.php ispconfig/interface/malwatch_waf_exception_list.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng; do php -l "$f"; done`
Expected: fünfmal `No syntax errors detected`.

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Step 9: Seiten im Nachbau rendern**

Der Nachbau setzt die Seiten mit der echten Vorlagenklasse von ISPConfig und Beispieldaten zusammen; `build_all.sh` bricht bei jeder PHP-Warnung ab. Die Beispieldaten enthalten eine gespeicherte Anfrage von `198.51.100.7` mit den Regeln 942190 und 949110 und HTML in Adresse, Kopfzeilen, Inhalt und `data`. Für die Regel-Karten kommen sieben Anfragen mit Regel 942100 dazu.

In `.superpowers/abwehr/harness/fake_db.php`, Methode `queryAllRecords()`, die Zeilen

```php
		if (strpos($sql, 'FROM malwatch_waf_hit') !== false) {
			return array(
				array('hit_id' => '5', 'seen_at' => '2026-09-16 11:09:19', 'client_ip' => '198.51.100.7', 'method' => 'POST',
```

ersetzen durch

```php
		// The rule cards: seven stored requests with rule 942100 from six addresses.
		if (strpos($sql, 'SELECT client_ip, logged_in, rules FROM malwatch_waf_hit') !== false) {
			$rows = array();
			foreach (array('192.0.2.10', '192.0.2.11', '192.0.2.12', '192.0.2.13', '192.0.2.14', '2001:db8::7') as $i => $ip) {
				$rows[] = array('client_ip' => $ip, 'logged_in' => $i === 0 ? 'y' : 'n',
					'rules' => '[{"id":"942100","msg":"SQL Injection Attack Detected via libinjection",'
						. '"data":"Matched Data: s&sos found within ARGS:q: <b>x</b>","param":"q"}]');
			}
			$rows[] = $rows[0];
			return $rows;
		}
		if (strpos($sql, 'FROM malwatch_waf_hit') !== false) {
			return array(
				array('hit_id' => '5', 'seen_at' => '2026-09-16 11:09:19', 'client_ip' => '198.51.100.7', 'method' => 'POST',
```

In `.superpowers/abwehr/harness/build_all.sh` die Zeile

```sh
render 'malwatch_waf_show.php?id=11' out_show.html
```

ersetzen durch

```sh
render 'malwatch_waf_show.php?id=11' out_show.html
render 'malwatch_waf_show.php?id=11&ip=198.51.100.7' out_show_ip.html
render 'malwatch_waf_show.php?id=11&ip=kein-ip' out_show_badip.html
```

Dann rendern und nachsehen:

```bash
bash .superpowers/abwehr/harness/build_all.sh .
cd .superpowers/abwehr/harness
grep -c 'class="mw-ipfilter"' out_show.html out_show_ip.html out_show_badip.html
grep -c 'class="mw-ipnotice">&bdquo;kein-ip&ldquo; ist keine g&uuml;ltige IP-Adresse' out_show.html out_show_ip.html out_show_badip.html
grep -o 'data-load-content="security/malwatch_waf_show.php?id=11&amp;days=7&amp;ip=[^"]*"' out_show.html | sort | uniq -c
grep -o '[0-9]* von [0-9]* Treffern kamen von angemeldeten Nutzern\.\|und [0-9]* weitere\|Parameter &bdquo;q&ldquo; enth&auml;lt &bdquo;s&amp;sos&ldquo; <span class="mw-dim">[0-9]*&times;\|Ausgelöst durch:' out_show.html | sort | uniq -c
grep -cE '<b>x</b>|<script>alert|<img src=x>|<svg onload' out_show.html out_show_ip.html
cd ../../..
```

Expected:

- `build_all.sh` endet mit `Seiten gerendert; Klickseiten unter web/click_*.html, Protokoll web/clicks.log`, ohne `FEHLER`.
- Hinweis zum Filter: `out_show.html:0`, `out_show_ip.html:1`, `out_show_badip.html:0`.
- Meldung zur ungültigen Angabe: `out_show.html:0`, `out_show_ip.html:0`, `out_show_badip.html:1`; die Liste bleibt dort ungefiltert.
- Sechs Verweise mit je `1`: `ip=192.0.2.10` bis `ip=192.0.2.14` aus der Regel-Karte 942100 und `ip=198.51.100.7` aus dem Einzeltreffer. `2001:db8::7` steckt in „und 1 weitere“.
- Je einmal `2 von 7 Treffern kamen von angemeldeten Nutzern.`, `Ausgelöst durch:`, `Parameter &bdquo;q&ldquo; enth&auml;lt &bdquo;s&amp;sos&ldquo; <span class="mw-dim">7&times;` und `und 1 weitere`.
- Keine unmaskierten Beispielwerte: `out_show.html:0`, `out_show_ip.html:0`.

Die Seite im Browser prüfen: Vorschau-Server `waf-preview` aus `.claude/launch.json` starten und `click_show.html` öffnen. Eine Regel-Karte zeigt links die Pfade, rechts die Adressen; „Woran erkannt?“ klappt Erklärung, Auslöser, Einordnung und Meldung auf; ein Klick auf eine Adresse lädt die Seite mit dem Hinweis „Nur Anfragen von …“ und springt zu den Einzeltreffern.

- [ ] **Step 10: Commit**

```bash
git add ispconfig/interface/malwatch_waf_show.php ispconfig/interface/templates/malwatch_waf_show.htm ispconfig/interface/malwatch_waf_list.php ispconfig/interface/malwatch_waf_exception_list.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/install/schema.sql ispconfig/tests/check_wiring.sh ispconfig/tests/render_pages.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): addresses, triggers and classes on the website page" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task A9: Version 0.20.0, Changelog und Dokumentation

**Files:**
- Modify: `internal/version/version.go`, `ispconfig/version`
- Modify: `CHANGELOG.md` (neuer Abschnitt oben)
- Modify: `README.md` (Abschnitt „Abwehr“), `ispconfig/README.md` (Abschnitt „Abwehr“)
- Modify: `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md` (Präzisierungen 7 und 8)

**Interfaces:**
- Consumes: den Stand nach A1 bis A8
- Produces: malwatch 0.20.0 auf dem Zweig `waf-herkules`, vollständig geprüft und committet. Push nach `main`, Tag und Release folgen erst in Task A10 nach Freigabe von Mathias.

- [ ] **Step 1: Version**

In `internal/version/version.go` die Zeile

```go
var Version = "0.19.1"
```

ersetzen durch

```go
var Version = "0.20.0"
```

`ispconfig/version` enthält danach genau die Zeile `0.20.0`:

```bash
printf '0.20.0\n' > ispconfig/version
```

- [ ] **Step 2: Changelog**

In `CHANGELOG.md` direkt nach der Zeile `Alle nennenswerten Änderungen an diesem Projekt.` und ihrer Leerzeile einfügen:

```markdown
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

```

- [ ] **Step 3: README und Spec**

In `README.md` die Zeilen

```markdown
ihr Audit-Log aus: Treffer je Website und Tag, Regeln im Klartext, einzelne Anfragen
und die Vorschau, was „scharf“ abgewiesen hätte. Ausnahmen entstehen per Knopf aus
```

ersetzen durch

```markdown
ihr Audit-Log aus: Treffer je Website und Tag, Regeln mit Erklärung, Auslöser,
Einordnung und den Adressen ihrer Treffer, einzelne Anfragen und die Vorschau, was
„scharf“ abgewiesen hätte. Ausnahmen entstehen per Knopf aus
```

In `ispconfig/README.md` die Zeilen

```markdown
- **Website:** Schalter mit Vorschau für „scharf“, Verlauf, Regeln, Pfade, einzelne
  Anfragen, ihre Ausnahmen und das Formular „Ausnahme anlegen“.
```

ersetzen durch

```markdown
- **Website:** Schalter mit Vorschau für „scharf“, Verlauf, Regeln mit Erklärung,
  Auslösern, Einordnung und Adressen, Pfade, einzelne Anfragen (ein Klick auf eine
  Adresse filtert sie), ihre Ausnahmen und das Formular „Ausnahme anlegen“.
```

die Zeilen

```markdown
- **Einstellungen:** Aufbewahrung, Mindestdauer vor „scharf“, Zeitraum der Vorschau,
  Zeilen je Durchgang, Frist für den vhost.
```

ersetzen durch

```markdown
- **Einstellungen:** Aufbewahrung, Mindestdauer vor „scharf“, Zeitraum der Vorschau,
  Zahl der Einzeltreffer für die Regel-Karten, Zeilen je Durchgang, Frist für den
  vhost.
```

und nach dem Absatz, der mit `Einzelne Anfragen enthalten Besucheradressen` beginnt und mit `öffnen im Panel ausschließlich als Text.` endet, einfügen:

```markdown

Die Erklärungen der Regeln stehen in `interface/lang/de_malwatch_waf_rules.lng` und
`en_malwatch_waf_rules.lng`, im Format der Sprachdateien von ISPConfig: je Regel
`rule_<id>_title`, `rule_<id>_what` und `rule_<id>_class`, bei Bedarf
`rule_<id>_note` und `rule_<id>_trigger`, je Gruppe `group_<nnn>_what` und
`group_<nnn>_class`. `tests/waf_rules_catalog_test.php` prüft den Katalog gegen die
Regelliste `tests/fixtures/crs-3.3.5-pl1-rule-ids.txt`; ein neuer Regelsatz braucht
eine neue Liste und die passenden Einträge.
```

In `docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md`, Abschnitt 2, nach der Zeile, die mit `| Obergrenze der Regel-Karten |` beginnt (aus Task A3), einfügen:

```markdown
| Adressfilter | Index `site_ip` (`parent_domain_id`, `client_ip`, `seen_at`) auf `malwatch_waf_hit`; nach einem Knopf bleibt der Filter erhalten |
```

In Abschnitt 5 den Punkt

```markdown
- Ein Klick auf eine Adresse lädt die Seite mit `&ip=<adresse>`; die Einzeltreffer zeigen
  dann nur diese Adresse, mit einem Hinweis und „Filter aufheben". Der Parameter wird mit
  `FILTER_VALIDATE_IP` geprüft.
```

ersetzen durch:

```markdown
- Ein Klick auf eine Adresse lädt die Seite mit `&ip=<adresse>` und springt zu den
  Einzeltreffern; sie zeigen dann nur diese Adresse, mit einem Hinweis und „Filter
  aufheben". Der Parameter wird mit `FILTER_VALIDATE_IP` geprüft und kommt nach einem
  Knopf als verstecktes Feld zurück. Der Index `site_ip` trägt Liste und Zählung.
- Ist die Angabe keine IP-Adresse, bleibt die Liste ungefiltert. Über den
  Einzeltreffern nennt eine Meldung die Angabe, sagt, dass die Liste deshalb alle
  gespeicherten Anfragen zeigt, und verweist zum Filtern auf die Adressen in den
  Regel-Karten und Anfragen.
```

und den Punkt

```markdown
- Aufgeklappt je Regel: „Titel (ID)", „Ausgelöst durch: …", die Einordnung in einem
  Satz, klein der Rohtext aus `data`.
```

ersetzen durch:

```markdown
- Aufgeklappt oben: Antwortcode und der Verweis „Nur Anfragen dieser Adresse"; bei
  angemeldeten Nutzern der Satz aus Abschnitt 4.
- Aufgeklappt je Regel: „Titel (ID)" mit der Einordnung als Chip, „Ausgelöst durch: …",
  die Einordnung in einem Satz, bei Bedarf der Zusatzsatz, klein der Rohtext aus `data`.
```

- [ ] **Step 4: Alle Prüfungen**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go test ./... && go build ./... && echo "Go: ok"
find ispconfig -name '*.php' -print0 | xargs -0 -n1 php -l | grep -v '^No syntax errors' ; echo "Syntax geprüft"
sh ispconfig/tests/check_constants.sh
for t in upgrade_helpers_test upgrade_offers_test panel_helpers_test waf_lib_test waf_panel_test waf_panel_post_test waf_rules_catalog_test; do php "ispconfig/tests/$t.php" | tail -n 1; done
php -l waf/waf-switch && php -l waf/waf-report && bash -n waf/waf-guard && bash -n waf/install.sh && echo "Werkzeuge: ok"
MALWATCH_WAF_LIB=ispconfig/interface/lib/malwatch_waf_lib.inc.php php waf/waf-report ispconfig/tests/waf_audit_sample.log > /dev/null && echo "waf-report: ok"
cat ispconfig/version; grep -n 'var Version' internal/version/version.go
```

Expected:
- `Go: ok` unter Linux. Unter Windows scheitern zwei Go-Tests, die Teil A nicht berührt: `TestExitCodeFollowsTheThreshold` (schon vor Teil A) und `TestThePlantedFileInAReplacedPluginIsGone`, weil Windows Defender die präparierte Testdatei blockt. Dann `gofmt`, `go vet` und `go build` einzeln prüfen; maßgeblich ist die CI unter Linux in Task A10, Block 2.
- nach `find` nur `Syntax geprüft`
- `Constants OK: LOGLEVEL_DEBUG LOGLEVEL_ERROR LOGLEVEL_WARN`
- `upgrade helpers OK`, `upgrade offers OK`, `panel helpers OK`, dann `waf_lib`, `waf_panel`, `waf_panel_post` und `waf_rules_catalog` je mit `: alle Prüfungen bestanden`
- zweimal `No syntax errors detected in waf/…`, dann `Werkzeuge: ok` und `waf-report: ok`
- `0.20.0` und `5:var Version = "0.20.0"`

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Zum Schluss den Nachbau noch einmal bauen: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`.

- [ ] **Step 5: Commit**

```bash
git add internal/version/version.go ispconfig/version CHANGELOG.md README.md ispconfig/README.md docs/superpowers/specs/2026-09-17-malwatch-abwehr-treffer-herkunft-design.md
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "release: 0.20.0, rules explained with addresses and triggers" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
git status --short
```

Expected: `grep` gibt nichts aus, der Commit gelingt, `git status --short` zeigt keine Datei aus `ispconfig/`, `internal/`, `waf/` oder `docs/`.

---

### Task A10: Einführung auf web.herkules

malwatch 0.20.0 kommt in vier Blöcken auf den Server, jeder mit eigener Freigabe von Mathias und mit Eintrag im Serverprotokoll:

1. Probe auf einer Staging-Kopie, dazu Spalte und Index in `dbispconfig`
2. Veröffentlichen: `main`, CI, Tag `v0.20.0`, Release
3. malwatch 0.20.0 einspielen
4. Sichtprüfung im Panel, in Mathias' angemeldetem Chrome

Claude meldet sich nie im Panel an und tippt keine Zugangsdaten. Im Chrome arbeitet Claude in einem eigenen Tab, drückt keinen Knopf, der etwas ändert, und schließt den Tab am Ende.

**Files:**
- Serverprotokoll: `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md` (vor jedem Eintrag frisch lesen, gezielt einfügen, neueste Einträge oben)
- Hilfen am Rechner (nicht im Repo): `.superpowers/abwehr/measure.sh`

**Interfaces:**
- Consumes: den Commit aus Task A9 auf `waf-herkules`
- Produces: malwatch 0.20.0 auf web.herkules, geprüft und protokolliert

#### Messen

Vor dem ersten und nach jedem ändernden Schritt:

```bash
ssh ispconfig 'bash -s' < .superpowers/abwehr/measure.sh
for site in bright-color.de "$ZWEITE" "$DRITTE"; do curl -s -o /dev/null -w "%{http_code} %{time_total}s $site\n" "https://$site/"; done
```

`ZWEITE` und `DRITTE` sind die beiden Kundenwebsites aus den Messtabellen der letzten Einträge im Serverprotokoll; ihre Namen stehen nur dort.

**Abbruch**, sobald eines davon eintritt: `nginx -t` scheitert, nginx ist nicht aktiv, weniger als 2 GB verfügbar, Load (5 Minuten) dauerhaft über 6, eine Website antwortet anders als zu Beginn oder doppelt so langsam, die 5xx-Zahl steigt sprunghaft ohne erkennbaren Scanner, ein neuer Eintrag „exited on signal“. Dann: Werte festhalten, Mathias Bescheid geben, erst nach Klärung weiter. Teil A fasst nginx nicht an; ein Abbruch betrifft deshalb vor allem die Datenbank und PHP-FPM des Panels.

#### Block 1: Staging-Kopie, Spalte und Index

- [ ] **Step 1: Freigabe einholen**

Mathias bekommt vorgelegt: „A10, Block 1: Ich kopiere den Stand nach `/root/mw-0200-src` und `/root/mw-0200-stage`, prüfe die Syntax unter PHP 7.0 und 8.3 und lasse die Tests laufen. Dann sichere ich die Struktur von `malwatch_waf_hit` und `malwatch_config` und lade das Schema: Es legt die Spalte `waf_card_hits` (Vorgabe 5000) und den Index `site_ip` auf `malwatch_waf_hit` an. InnoDB baut den Index ohne Sperre, das laufende malwatch 0.19.1 arbeitet unverändert weiter. Danach rendere ich die neuen Seiten der Staging-Kopie gegen die echte Datenbank, messe Laufzeit und Speicher der Website-Seite und prüfe mit EXPLAIN, welche Indizes die Abfragen nehmen. Zum Schluss lösche ich die Kopie; die gerenderten Seiten mit Besucheradressen bleiben dabei auf dem Server und verschwinden mit ihr. nginx und die Websites bleiben unberührt.“ Weiter erst nach seinem Ja.

- [ ] **Step 2: Ausgangslage**

Beide Messungen, dazu:

```bash
ssh ispconfig "mysql -N dbispconfig -e \"SELECT COUNT(*) FROM malwatch_waf_hit; SELECT ROUND(DATA_LENGTH / 1048576), ROUND(INDEX_LENGTH / 1048576) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_waf_hit'; SELECT domain, COUNT(*) FROM malwatch_waf_hit GROUP BY domain\""
```

Expected: die Zahl der gespeicherten Anfragen, Daten- und Indexgröße in MB, die Anfragen je Website. Die Werte kommen ins Protokoll.

- [ ] **Step 3: Staging-Kopie, Syntax und Tests**

```bash
git archive --format=tar HEAD ispconfig waf | ssh ispconfig 'rm -rf /root/mw-0200-src /root/mw-0200-stage && mkdir -p /root/mw-0200-src /root/mw-0200-stage/interface/web && tar -x -C /root/mw-0200-src'
ssh ispconfig 'bash -s' <<'EOF'
set -eu
src=/root/mw-0200-src/ispconfig
stage=/root/mw-0200-stage
ln -s /usr/local/ispconfig/interface/lib "$stage/interface/lib"
cd "$src"
while IFS=: read -r action source target; do
	[ "$action" = c ] || continue
	case "$target" in
		interface/*) mkdir -p "$stage/$(dirname "$target")"; cp "$source" "$stage/$target" ;;
	esac
done < install/file.list
for php in php7.0 php; do
	find . \( -name '*.php' -o -name '*.lng' \) -print0 | xargs -0 -n1 "$php" -l | grep -v '^No syntax errors' || true
done
php tests/waf_lib_test.php
php tests/waf_panel_test.php
php tests/waf_panel_post_test.php
php tests/waf_rules_catalog_test.php
EOF
```

Expected: keine Zeile aus den Syntaxprüfungen, viermal „alle Prüfungen bestanden“.

- [ ] **Step 4: Spalte und Index**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
install -d -m 700 /var/backups/malwatch
mysqldump --no-data dbispconfig malwatch_waf_hit malwatch_config > "/var/backups/malwatch/schema-vor-0.20.0-$(date +%Y%m%d-%H%M%S).sql"
date "+%H:%M:%S Schema laden"
mysql dbispconfig < /root/mw-0200-src/ispconfig/install/schema.sql
date "+%H:%M:%S Schema geladen"
mysql -N dbispconfig -e "SELECT COLUMN_NAME, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_card_hits'"
mysql -N dbispconfig -e "SELECT INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_waf_hit' AND INDEX_NAME = 'site_ip' ORDER BY SEQ_IN_INDEX"
ls -l /var/backups/malwatch | tail -n 3
EOF
```

Expected:
- zwei Uhrzeiten, dazwischen das Laden des Schemas
- `waf_card_hits	5000`
- `site_ip	1	parent_domain_id`, `site_ip	2	client_ip`, `site_ip	3	seen_at`
- die Sicherungsdatei

Danach beide Messungen.

- [ ] **Step 5: Seiten der Staging-Kopie rendern und messen**

```bash
ssh ispconfig 'cat > /root/mw-0200-src/dump_page.php' <<'EOF'
<?php
// Renders one staged page as the admin, like the child of render_pages.php,
// and reports its run time and peak memory on stderr:
//   MW_SECURITY_DIR=<dir> php dump_page.php <domain_id> <page?query>
$started = microtime(true);
register_shutdown_function(function () use ($started) {
	fwrite(STDERR, sprintf("Laufzeit %.2f s, Speicher %.1f MB\n", microtime(true) - $started, memory_get_peak_usage(true) / 1048576));
});
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
$dir = getenv('MW_SECURITY_DIR');
chdir($dir);
require '/usr/local/ispconfig/interface/lib/config.inc.php';
require '/usr/local/ispconfig/interface/lib/app.inc.php';
$domain_id = (int) $argv[1];
list($file, $qs) = array_pad(explode('?', $argv[2], 2), 2, '');
parse_str($qs, $query);
$_SESSION['s']['user'] = array('userid' => 1, 'typ' => 'admin', 'active' => 1, 'default_group' => 1,
	'groups' => '1', 'modules' => 'dashboard,security,admin', 'language' => 'de', 'startmodule' => 'security', 'theme' => 'default');
$_SESSION['s']['module'] = array('name' => 'security');
$_SESSION['s']['language'] = 'de';
$_SESSION['s']['theme'] = 'default';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_FILENAME'] = $dir . '/' . $file;
$_SERVER['SCRIPT_NAME'] = '/security/' . $file;
$_SERVER['REQUEST_URI'] = '/security/' . $argv[2];
$_GET = $_REQUEST = array_merge(array('id' => $domain_id, 'domain_id' => $domain_id), $query);
$_POST = array();
include $file;
EOF
ssh ispconfig 'bash -s' <<'EOF'
set -eu
export MW_SECURITY_DIR=/root/mw-0200-stage/interface/web/security
d=/root/mw-0200-src
id=$(mysql -N dbispconfig -e "SELECT domain_id FROM web_domain WHERE domain = 'bright-color.de' AND type = 'vhost'")
ip=$(mysql -N dbispconfig -e "SELECT client_ip FROM malwatch_waf_hit WHERE parent_domain_id = $id ORDER BY seen_at DESC, hit_id DESC LIMIT 1")
# render_pages.php needs a website with a WordPress release list for malwatch_upgrade_versions.php.
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
cd "$d/ispconfig"
nice -n 15 php tests/render_pages.php "$rid" 2>&1 | tail -n 34
nice -n 15 php tests/render_pages.php "$id" 'malwatch_waf_show.php?ip=stored'
nice -n 15 php "$d/dump_page.php" "$id" "malwatch_waf_show.php" > "$d/show.html"
nice -n 15 php "$d/dump_page.php" "$id" "malwatch_waf_show.php?days=90" > "$d/show90.html"
nice -n 15 php "$d/dump_page.php" "$id" "malwatch_waf_show.php?ip=$ip" > "$d/show_ip.html"
nice -n 15 php "$d/dump_page.php" "$id" "malwatch_waf_list.php" > "$d/list.html"
nice -n 15 php "$d/dump_page.php" "$id" "malwatch_waf_exception_list.php" > "$d/exc.html"
echo "Regel-Karten: $(grep -c 'class="mw-rule"' "$d/show.html"), mit Adressen: $(grep -c 'class="mw-addresses"' "$d/show.html")"
echo "Auslöser in Einzeltreffern: $(grep -c 'Ausgelöst durch:' "$d/show.html")"
echo "Filterhinweis: ungefiltert $(grep -c 'class="mw-ipfilter"' "$d/show.html"), gefiltert $(grep -c 'class="mw-ipfilter"' "$d/show_ip.html")"
echo "Regeln ohne Titel: $(grep -o 'class="mw-ruletitle">Regel [0-9]*' "$d/show90.html" | sed 's/.*Regel //' | sort -u | tr '\n' ' ')"
echo "Seiten mit PHP-Meldungen: $(grep -l -E 'Warning|Notice|Fatal error' "$d"/*.html | wc -l)"
for q in \
	"SELECT client_ip, logged_in, rules FROM malwatch_waf_hit WHERE parent_domain_id = $id ORDER BY seen_at DESC, hit_id DESC LIMIT 5000" \
	"SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = $id ORDER BY seen_at DESC, hit_id DESC LIMIT 100" \
	"SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = $id AND client_ip = '$ip' ORDER BY seen_at DESC, hit_id DESC LIMIT 100" \
	"SELECT COUNT(*) FROM malwatch_waf_hit WHERE parent_domain_id = $id AND client_ip = '$ip'"; do
	echo "--- ${q%% FROM*}"
	mysql dbispconfig -e "EXPLAIN $q\G" | grep -E '^ *(key|rows|Extra):'
done
EOF
```

Expected:
- jede Zeile von `render_pages.php` mit `ok`, darunter `malwatch_waf_show.php?ip=stored`; am Ende `All pages render.`
- die Einzelzeile für bright-color.de: `malwatch_waf_show.php?ip=stored … ok`
- fünf Zeilen `Laufzeit …, Speicher …`; die Website-Seite braucht unter 2 s und unter 64 MB
- `Regel-Karten: n, mit Adressen: m` mit `m` größer 0; `Auslöser in Einzeltreffern:` größer 0
- `Filterhinweis: ungefiltert 0, gefiltert 1`
- `Regeln ohne Titel:` leer oder nur eigene Regeln (10000 bis 10999); jede CRS-Regel trägt einen Titel aus dem Katalog oder den Namen ihrer Gruppe
- `Seiten mit PHP-Meldungen: 0`
- EXPLAIN, je Abfrage nach ihrer `---`-Zeile: die ersten beiden mit `key: site_seen` und ohne `Using filesort`, die dritte mit `key: site_ip` und ohne `Using filesort`, die vierte mit `key: site_ip` und `Using index`

Weicht ein Wert ab: Befund ins Protokoll, Mathias Bescheid geben, Block 2 erst nach Klärung.

- [ ] **Step 6: Aufräumen**

```bash
ssh ispconfig 'rm -rf /root/mw-0200-src /root/mw-0200-stage; ls -d /root/mw-0200-src /root/mw-0200-stage 2>&1 | tail -n 2; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: zweimal `No such file or directory`, die Uhrzeit fürs Protokoll. Dann beide Messungen.

- [ ] **Step 7: Protokoll**

Das Serverprotokoll frisch lesen und den Eintrag gezielt nach seiner Beginnzeit einsortieren. Keine Besucheradressen ins Protokoll.

```markdown
## <Datum>, <Beginn>–<Ende> CEST · malwatch 0.20.0: Probe der Website-Seite, Spalte und Index

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code, Sitzung <Kennung>, im Auftrag von Mathias (Freigabe im Chat: „<Wortlaut>“) |
| Betroffen | `dbispconfig`: Spalte `malwatch_config.waf_card_hits`, Index `site_ip` auf `malwatch_waf_hit`; Staging-Kopie unter `/root`, wieder entfernt |
| Auftrag | Task A10, Block 1 des Plans `docs/superpowers/plans/2026-09-17-malwatch-abwehr-treffer-teil-a.md` im malwatch-Repo, Zweig `waf-herkules` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Die Website-Seite von 0.20.0 liest die neue Einstellung und filtert gespeicherte Anfragen nach Adresse. Vor dem Einspielen muss sie gegen die echte Datenbank rendern, und die Abfragen müssen ihre Indizes treffen.

### Ablauf

| Uhrzeit | Schritt |
|---|---|
| <Uhrzeit> | Ausgangslage: <n> gespeicherte Anfragen, <x> MB Daten, <y> MB Index |
| <Uhrzeit> | Staging-Kopie; Syntax unter PHP 7.0 und 8.3, vier Tests: <Ergebnis> |
| <Uhrzeit> | Sicherung `/var/backups/malwatch/schema-vor-0.20.0-<Zeitstempel>.sql`; `schema.sql` geladen von <Beginn> bis <Ende>; Spalte und Index vorhanden |
| <Uhrzeit> | `render_pages.php` gegen die Staging-Kopie: <Ergebnis>; Website-Seite <Laufzeit>, <Speicher>; <n> Regel-Karten, <m> mit Adressen |
| <Uhrzeit> | EXPLAIN: <Indizes je Abfrage> |
| <Uhrzeit> | Staging-Kopie gelöscht |

### Prüfung

<Messtabelle wie in den letzten Einträgen: Load, verfügbar, Swap, nginx, Worker-Abstürze, 5xx heute, drei Websites>

### Rückweg

0.19.1 nutzt Spalte und Index nicht. Bei Bedarf: `ALTER TABLE malwatch_waf_hit DROP INDEX site_ip; ALTER TABLE malwatch_config DROP COLUMN waf_card_hits;` Die Struktur von vorher liegt in der Sicherungsdatei.
```

#### Block 2: Veröffentlichen

- [ ] **Step 8: Freigabe einholen**

Mathias bekommt vorgelegt: „A10, Block 2: Ich bringe den Zweig `waf-herkules` per Fast-Forward nach `main`, schiebe `main`, warte auf die CI und setze danach den Tag `v0.20.0`. Der Release-Lauf baut `malwatch.pkg` und die Binärdateien.“ Weiter erst nach seinem Ja.

- [ ] **Step 9: main, CI, Tag, Release**

```bash
git fetch origin
git merge-base --is-ancestor origin/main waf-herkules && echo "Fast-Forward möglich"
git checkout main
git merge --ff-only waf-herkules
git push origin main
sha=$(git rev-parse HEAD)
gh run watch "$(gh run list --commit "$sha" --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: `Fast-Forward möglich`, der Push gelingt, der CI-Lauf dieses Commits endet grün, darunter der Schritt „WAF rule catalog“. Liefert `gh run list` noch keinen Lauf, einige Sekunden später wiederholen. Scheitert die CI, bleibt der Tag aus: Fehler auf `waf-herkules` beheben, committen, Step 9 von vorn.

```bash
git tag v0.20.0
git push origin v0.20.0
gh run watch "$(gh run list --commit "$sha" --workflow release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh release view v0.20.0 --json assets --jq '.assets[].name'
git checkout waf-herkules
```

Expected: der Release-Lauf endet grün; die Liste nennt `malwatch-linux-amd64`, `malwatch-linux-arm64`, `malwatch.pkg` und `SHA256SUMS`.

#### Block 3: malwatch 0.20.0 einspielen

- [ ] **Step 10: Freigabe einholen**

Mathias bekommt vorgelegt: „A10, Block 3: Ich spiele malwatch 0.20.0 ein: Scanner über `install.sh`, Paket nach Prüfsumme, `manual_install.php`, dann `cmp` jeder Kopie und `render_pages.php` live. Das Schema ist seit Block 1 auf dem neuen Stand. nginx und die WAF-Dateien bleiben unverändert.“ Weiter erst nach seinem Ja.

- [ ] **Step 11: Einspielen**

Zuerst beide Messungen, dann:

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
rm -rf /root/mw-0200-deploy && mkdir -p /root/mw-0200-deploy && cd /root/mw-0200-deploy
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.20.0/malwatch.pkg
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.20.0/SHA256SUMS
grep " malwatch.pkg$" SHA256SUMS | sha256sum -c -
curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh 2>&1 | grep -i installed
cd /usr/local/ispconfig/extensions && mkdir -p malwatch && cd malwatch && unzip -oq /root/mw-0200-deploy/malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php 2>&1 | grep -E "installed|loaded|Error|error|failed" | head -n 8
echo "Addon $(cat /usr/local/ispconfig/extensions/malwatch/version), Scanner $(/usr/local/bin/malwatch version | head -n 1)"
E=/usr/local/ispconfig/extensions/malwatch; n=0; total=0
while IFS=: read -r a s t; do [ "$a" = c ] || continue; total=$((total+1)); cmp -s "$E/$s" "/usr/local/ispconfig/$t" || { echo "abweichend: $t"; n=$((n+1)); }; done < "$E/install/file.list"
echo "Kopien geprüft: $total, abweichend: $n"
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
id=$(mysql -N dbispconfig -e "SELECT domain_id FROM web_domain WHERE domain = 'bright-color.de' AND type = 'vhost'")
nice -n 15 php "$E/tests/render_pages.php" "$rid" 2>&1 | tail -n 34
nice -n 15 php "$E/tests/render_pages.php" "$id" 'malwatch_waf_show.php?ip=stored'
rm -rf /root/mw-0200-deploy
date "+%d.%m.%Y, %H:%M:%S %Z"
EOF
```

Expected:
- `malwatch.pkg: OK`
- Addon `0.20.0`, Scanner meldet `v0.20.0`
- `Kopien geprüft: 91, abweichend: 0`
- jede Seite `ok`, `All pages render.`, dazu die Einzelzeile für bright-color.de mit `ok`

Weicht eine Kopie ab, holt `enable_files` sie nach, und der `cmp`-Block läuft erneut. Danach beide Messungen.

- [ ] **Step 12: Protokoll**

Frisch lesen, gezielt einfügen:

```markdown
## <Datum>, <Beginn>–<Ende> CEST · malwatch 0.20.0 eingespielt: Regeln erklärt, Adressen je Regel

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code, Sitzung <Kennung>, im Auftrag von Mathias (Freigaben im Chat: „<Wortlaut Block 2>“, „<Wortlaut Block 3>“) |
| Betroffen | ISPConfig-Erweiterung malwatch, `/usr/local/bin/malwatch` |
| Auftrag | Task A10, Blöcke 2 und 3 des Plans `docs/superpowers/plans/2026-09-17-malwatch-abwehr-treffer-teil-a.md` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Mathias wollte bei den Treffern die Adresse sehen und verstehen, woran eine Regel erkannt hat, auf Deutsch.

### Ablauf

| Uhrzeit | Schritt |
|---|---|
| vorher | Release v0.20.0 aus Commit `<kurz>` (Zweig `waf-herkules`, per Fast-Forward nach `main`); CI und Release-Lauf grün |
| <Uhrzeit> | Messung vorher |
| <Uhrzeit> | Paket geladen, Prüfsumme, Scanner, `manual_install.php`: <Ergebnis> |
| <Uhrzeit> | Addon <Version>, Scanner <Version>; `cmp` aller <n> Kopien: <n> abweichend |
| <Uhrzeit> | `render_pages.php` live: <Ergebnis>; Arbeitsverzeichnis gelöscht |

### Prüfung

<Messtabelle vorher und nachher>. `nginx -t` erfolgreich und nginx aktiv, vorher wie nachher; das Einspielen fasst nginx nicht an.

### Rückweg

Paket 0.19.1 (`releases/download/v0.19.1/malwatch.pkg`) nach Prüfsumme entpacken und `manual_install.php` laufen lassen; den Scanner mit `install.sh` auf die gewünschte Version bringen. Spalte und Index dürfen bleiben. Nicht erprobt.
```

#### Block 4: Sichtprüfung im Panel

- [ ] **Step 13: Freigabe einholen**

Mathias bekommt vorgelegt: „A10, Block 4: Ich öffne in deinem Chrome einen eigenen Tab mit dem Panel, in dem du angemeldet bist, gehe zu Security > Abwehr > Übersicht und öffne bright-color.de. Dort klappe ich bei einer Regel „Woran erkannt?“ auf, klicke eine Adresse, danach „Filter aufheben“, und sehe mir unter Abwehr > Einstellungen das neue Feld an, ohne zu speichern. Ich drücke keinen Knopf, der etwas ändert, und schließe den Tab danach. Die Bildschirmfotos zeigen Besucheradressen und bleiben hier im Chat.“ Weiter erst nach seinem Ja.

- [ ] **Step 14: Ansehen**

Werkzeuge von Claude in Chrome in einem Aufruf laden: `ToolSearch` mit `select:mcp__claude-in-chrome__tabs_context_mcp,mcp__claude-in-chrome__tabs_create_mcp,mcp__claude-in-chrome__navigate,mcp__claude-in-chrome__computer,mcp__claude-in-chrome__read_page,mcp__claude-in-chrome__find,mcp__claude-in-chrome__tabs_close_mcp`.

| Ablauf | Erwartet |
|---|---|
| eigenen Tab öffnen, Panel-Adresse aus dem Steckbrief des Serverprotokolls laden | Panel angemeldet; sonst abbrechen und Mathias fragen |
| Modul Security, Abwehr > Übersicht, bright-color.de „Ansehen“ | Website-Seite mit Regel-Karten; rechts „Adressen aus den gespeicherten Anfragen (7 Tage)“ mit Adressen und Anzahl |
| bei der ersten Regel „Woran erkannt?“ aufklappen | „Was erkannt wurde:“, „Häufigste Auslöser:“, „Einordnung:“ mit Chip, „Meldung des Regelwerks: …“ |
| eine Adresse der ersten Regel anklicken | Seite lädt neu, springt zu „Einzelne Anfragen“, Hinweis „Nur Anfragen von …“, nur Anfragen dieser Adresse |
| einen Einzeltreffer aufklappen | je Regel Titel mit Chip, „Ausgelöst durch: …“, Satz zur Einordnung, Rohtext klein |
| „Filter aufheben“ | Hinweis weg, wieder alle Anfragen |
| Abwehr > Einstellungen | Abschnitt „Anzeige“ mit „Einzeltreffer für die Regel-Karten“ und dem Wert 5000; nicht speichern |
| Tab schließen | — |

Bildschirmfotos der aufgeklappten Regel und des gefilterten Stands gehen an Mathias. Weicht etwas ab: Befund festhalten, Fehler auf `waf-herkules` beheben, als 0.20.1 mit neuen Freigaben ab Block 2.

- [ ] **Step 15: Protokoll ergänzen**

Frisch lesen und im Eintrag aus Step 12 eine Zeile in „Ablauf“ ergänzen: `| <Uhrzeit> | Sichtprüfung im Panel (Chrome von Mathias, eigener Tab): <Ergebnis> |`. Danach den Steckbrief prüfen: Die Zeile „malwatch“ braucht keine Änderung; die Zeile „WAF“ bleibt.

- [ ] **Step 16: Erinnerung aktualisieren**

In `C:\Users\brigh\.claude\projects\C--Users-brigh-AppData-Roaming-Claude-scratch-workspaces-62ecfad1-73cd-42be-ad3c-298657c741c7-0ce217ac-54ef-4123-a805-ad035d5f9d1a-scratch-2026-09-04-5eea4e\memory\waf-web-herkules.md` festhalten: 0.20.0 live seit <Datum, Uhrzeit>, Regelkatalog mit 170 Regeln, Adressfilter mit Index `site_ip`, Einstellung `waf_card_hits`; Teil B (Herkunft der Adressen) folgt mit eigenem Plan. Die Zeile in `MEMORY.md` passend kürzen.

---

## Abschluss von Teil A

Teil A ist fertig, wenn:

- A1 bis A9 committet sind und `sh ispconfig/tests/check_wiring.sh` `Wiring OK` meldet,
- v0.20.0 veröffentlicht ist und die CI grün war,
- web.herkules 0.20.0 zeigt, `render_pages.php` live alles rendert und die Sichtprüfung bestanden ist,
- das Serverprotokoll die Blöcke 1 bis 4 enthält.

Danach, jeweils mit eigener Freigabe: der Plan für Teil B „Herkunft der Adressen“ (Abschnitte 6 bis 12 der Spec).
