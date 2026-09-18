# Sperren, Stufe 1 (Release 0.23.0) — Umsetzungsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Ziel:** Aus Treffern werden Sperren: malwatch erkennt Angreifer an den Punkten im Zeitfenster, schlägt sie vor oder sperrt sie, und nginx weist sie serverweit mit 403 ab.

**Aufbau:** Die Entscheidung („wer, warum, wie lange") steckt in reinen Funktionen ohne Datenbank in einer eigenen Bibliothek `malwatch_waf_ban.inc.php`. Die Serverklasse ruft sie im Minutentakt auf, schreibt daraus `/etc/nginx/waf/blocked.conf` und lädt nginx neu — höchstens einmal je Durchgang und nur bei Änderung. Das Panel zeigt Sperren, Vorschläge und Ausnahmen und legt für jeden Knopf einen Auftrag an. Die Schwelle gilt je Website, die Sperre serverweit.

**Technik:** PHP ab 7.0, ISPConfig 3.3.1p1, vlibTemplate und tform im Panel, nginx mit `deny` im `http`-Kontext, MariaDB. Tests sind `expect_same()`-Skripte in `ispconfig/tests`, dazu `check_wiring.sh`, `render_pages.php` (nur auf dem Server) und `waf_class_probe.php` (nur auf dem Server, gegen eine Wegwerf-Datenbank).

**Spec:** `docs/superpowers/specs/2026-09-18-malwatch-sperren-design.md`, Stufe 1. Die Abschnitte 12 (fail2ban) und 13 (OPNsense) gehören zu späteren Releases und bleiben hier außen vor.

## Feste Vorgaben

- Bezeichner, Dateinamen, Konfigurationsschlüssel und Code-Kommentare auf Englisch. Texte für Menschen auf Deutsch mit echten Umlauten, dazu die englische Fassung in `en_*.lng`.
- PHP ab 7.0: keine typisierten Eigenschaften, kein `??`, kein `str_contains()`, `array()` statt `[]`.
- Jede Meldung nennt Ursache und nächsten Schritt.
- Der Webserver darf nicht ausfallen: Änderungen an nginx laufen über `nginx -t` und Reload, nie über einen Neustart. Scheitert die Prüfung, kommt die alte Datei zurück und es wird nicht neu geladen.
- Zeiträume und Grenzen sind einstellbar: Schwelle, Fenster, die drei Dauern, Obergrenze und Aufbewahrung stehen in den Einstellungen; die Schwelle zusätzlich je Website.
- Keine echten Kundendaten im Repository. Beispiele nutzen `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` und `2001:db8::/32`.
- Vor jedem Commit bleibt `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` ohne Ausgabe.
- Commit-Nachrichten enden auf `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. Geschoben, getaggt und eingespielt wird nur auf Ansage von Mathias.
- Jede Arbeit am Server kommt ins Protokoll `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`, frisch gelesen und gezielt eingefügt.
- Die Einführung beginnt im Vorschlagsmodus; auf „sperren" wird erst nach Beobachtung umgeschaltet.

## Ausgangslage: was 0.22.0 mitbringt

| Stelle | Stand |
|---|---|
| Treffer | `malwatch_waf_hit` mit `client_ip`, `parent_domain_id`, `seen_at`, `anomaly_score`, `rules`, `would_block`, `logged_in`; Index `site_seen` und `site_ip` |
| Herkunft | `malwatch_waf_ip` je Adresse (Land, Provider, Tor, VPN, Rechenzentrum, Proxy), gefüllt vom Cron |
| Bereichsdateien | `waf_origin_*` in `malwatch_waf_origin.inc.php`: Schreiber, Leser, binäre Suche, `waf_origin_cidr()` liefert zu `203.0.113.0/24` die 16-Byte-Grenzen |
| Quellen | `waf_origin_sources()` mit sieben Einträgen, `origin_update` lädt sie, `waf_origin_readers()` öffnet sie |
| Websites | `malwatch_site` mit `waf_state` (`off`, `detect`, `enforce`), `waf_state_since`, `waf_job_id`, `waf_pending_state` |
| Aufträge | `job_kind = 'waf'`, `start_job()` mit acht Fällen, `waf_panel_queue($app, $server_id, $action, $fields)` legt sie an |
| nginx | `/etc/nginx/conf.d/waf.conf` bindet `/etc/nginx/waf/main.conf` ein; `run_command('nginx_test')` und `run_command('nginx_reload')` in der Serverklasse; `waf-guard` stellt stündlich den letzten guten Stand her |
| Logs | `/var/log/waf/audit.log`, gelesen über Inode und Versatz in `/var/lib/malwatch/waf/reader.json`, gedreht von `/etc/logrotate.d/waf` |
| Werkzeuge | `waf-switch` (PHP-CLI mit Unterbefehlen), `waf-guard`, `waf-report` |
| Prüfungen | `check_wiring.sh` mit 72 Prüfungen, sieben Testreihen, `waf_class_probe.php`, `render_pages.php` |

## Dateien

| Datei | Aufgabe | Änderung |
|---|---|---|
| `ispconfig/install/schema.sql` | Schema | Tabellen `malwatch_waf_ban` und `malwatch_waf_allow`, neun Spalten in `malwatch_config`, zwei in `malwatch_site` |
| `ispconfig/interface/lib/malwatch_waf_ban.inc.php` | Entscheidung ohne Datenbank | **neu**: Schwelle je Website, Stufe und Dauer, Grund, Ausnahmen, Inhalt der `deny`-Datei, Lesen einer Logzeile |
| `ispconfig/interface/lib/malwatch_waf_lib.inc.php` | Einstellungen | neun Werte mit Vorgaben, Grenzen und Prüfung, dazu `waf_ban_modes()` |
| `ispconfig/interface/lib/malwatch_waf_origin.inc.php` | Quellen | Quelle `searchbots` mit Leser für die JSON-Listen von Google und Bing; `waf_origin_facts()` überspringt sie |
| `ispconfig/interface/lib/malwatch_waf_panel.inc.php` | Anzeige | Zeilen der Sperrliste, Vorschläge, Ausnahmen; Texte für Zustand und Dauer |
| `ispconfig/server/lib/classes/malwatch_waf.inc.php` | Cron und Aufträge | `ban_scan()`, `ban_apply()`, `ban_expire()`, `ban_count()`, sechs neue Auftragsfälle |
| `ispconfig/interface/malwatch_waf_ban_list.php` | Seite | **neu**: Sperren, Vorschläge, Ausnahmen |
| `ispconfig/interface/templates/malwatch_waf_ban_list.htm` | Vorlage | **neu** |
| `ispconfig/interface/malwatch_waf_show.php` und Vorlage | Website-Seite | Knopf „sperren" je Adresse, Schwelle der Website im Kasten „Zustand" |
| `ispconfig/interface/form/malwatch_waf_config.tform.php` und Vorlage | Einstellungen | neun Felder |
| `ispconfig/interface/lang/de\|en_malwatch_waf*.lng` | Texte | Seite, Knöpfe, Gründe, Fehlermeldungen |
| `ispconfig/interface/nav.php` bzw. Menüdatei | Menü | Punkt „Sperren" unter Abwehr |
| `waf/install.sh`, `waf/conf/waf-blocked.conf`, `waf/conf/logrotate-waf` | Installation | `deny`-Einbindung, Logformat, leere Sperrdatei, zweites Log |
| `waf/waf-switch` | Werkzeug | `block status\|off\|propose\|on\|list\|add\|lift\|allow` |
| `ispconfig/install/file.list` | Kopien | neue Bibliothek, Seite, Vorlage |
| `ispconfig/tests/waf_ban_test.php` | Test | **neu**: die reinen Funktionen |
| `ispconfig/tests/fixtures/bots/googlebot.json`, `bingbot.json` | Beispiele | **neu** |
| `ispconfig/tests/waf_class_probe.php` | Probe | Abschnitt D: Erkennen, Sperren, Anwenden, Ablaufen, Zählen |
| `ispconfig/tests/check_wiring.sh` | Verdrahtung | Prüfungen 73 bis 76 |
| `ispconfig/tests/render_pages.php` | Seiten | die neue Seite in drei Zuständen |
| `.github/workflows/ci.yml` | CI | Schritt „WAF ban" |
| `CHANGELOG.md`, `README.md`, `ispconfig/README.md`, `ispconfig/version`, `internal/version/version.go` | Release | 0.23.0 |

---
### Task D1: Schema, Einstellungen und Formular

Die Werte, an denen alles hängt: Modus, Schwelle, Fenster, drei Dauern, Obergrenze, Aufbewahrung, Suchmaschinen. Dazu die zwei Tabellen und die zwei Spalten je Website.

**Wichtig:** `waf_panel_test.php` leitet seine Erwartungen an das Formular aus `waf_settings_limits()` und den Auswahlfeldern ab. Einstellungen und Formularfelder gehören deshalb in **einen** Lauf, und die Reihenfolge in `waf_settings_limits()` muss der Reihenfolge der Felder im Formular entsprechen.

**Files:**
- Modify: `ispconfig/install/schema.sql`
- Modify: `ispconfig/interface/lib/malwatch_waf_lib.inc.php`
- Modify: `ispconfig/interface/form/malwatch_waf_config.tform.php`
- Modify: `ispconfig/interface/templates/malwatch_waf_config_edit.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_waf_config.lng`, `en_malwatch_waf_config.lng`
- Test: `ispconfig/tests/waf_lib_test.php`

**Interfaces:**
- Consumes: `waf_settings($row)`, `waf_settings_defaults()`, `waf_settings_limits()` aus 0.22.0
- Produces:
  - `waf_ban_modes()` → `array('off', 'propose', 'block')`
  - `$settings['waf_ban_mode']`, `['waf_ban_score']`, `['waf_ban_window_minutes']`, `['waf_ban_hours_first']`, `['waf_ban_hours_second']`, `['waf_ban_hours_third']`, `['waf_ban_max']`, `['waf_ban_keep_days']`, `['waf_ban_bots']`
  - Tabellen `malwatch_waf_ban`, `malwatch_waf_allow`; Spalten `malwatch_site.waf_ban_score`, `.waf_ban_trigger`

- [x] **Step 1: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_lib_test.php` ans Ende des Abschnitts zur Herkunft anfügen:

```php
// --- Sperren ------------------------------------------------------------------

expect_same('the three modes', waf_ban_modes(), array('off', 'propose', 'block'));
$block = waf_settings(array());
expect_same('blocking is off by default', $block['waf_ban_mode'], 'off');
expect_same('the defaults of the numbers', array($block['waf_ban_score'], $block['waf_ban_window_minutes'],
	$block['waf_ban_hours_first'], $block['waf_ban_hours_second'], $block['waf_ban_hours_third'],
	$block['waf_ban_max'], $block['waf_ban_keep_days']), array(50, 10, 1, 24, 168, 5000, 30));
expect_same('search engines are spared by default', $block['waf_ban_bots'], 'on');
$block = waf_settings(array('waf_ban_mode' => 'propose', 'waf_ban_score' => '80',
	'waf_ban_window_minutes' => '5', 'waf_ban_max' => '99', 'waf_ban_keep_days' => '400',
	'waf_ban_bots' => 'off'));
expect_same('a chosen mode is kept', $block['waf_ban_mode'], 'propose');
expect_same('numbers inside their limits', array($block['waf_ban_score'], $block['waf_ban_window_minutes'],
	$block['waf_ban_max'], $block['waf_ban_keep_days']), array(80, 5, 100, 365));
expect_same('search engines can be switched off', $block['waf_ban_bots'], 'off');
expect_same('an unknown mode falls back',
	waf_settings(array('waf_ban_mode' => 'vielleicht'))['waf_ban_mode'], 'off');
```

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_ban_modes()`

- [x] **Step 3: Die Einstellungen schreiben**

In `ispconfig/interface/lib/malwatch_waf_lib.inc.php` hinter `waf_origin_choices()`:

```php
/** The three states of the automatic blocking. */
function waf_ban_modes()
{
	return array('off', 'propose', 'block');
}
```

In `waf_settings_defaults()` hinter `'waf_origin_proxycheck_daily' => 500,`:

```php
		'waf_ban_mode' => 'off',
		'waf_ban_score' => 50,
		'waf_ban_window_minutes' => 10,
		'waf_ban_hours_first' => 1,
		'waf_ban_hours_second' => 24,
		'waf_ban_hours_third' => 168,
		'waf_ban_max' => 5000,
		'waf_ban_keep_days' => 30,
		'waf_ban_bots' => 'on',
```

In `waf_settings_limits()` hinter `'waf_origin_proxycheck_daily' => array(1, 100000),` — die Reihenfolge entspricht den Feldern im Formular:

```php
		'waf_ban_score' => array(5, 10000),
		'waf_ban_window_minutes' => array(1, 1440),
		'waf_ban_hours_first' => array(1, 8760),
		'waf_ban_hours_second' => array(1, 8760),
		'waf_ban_hours_third' => array(1, 8760),
		'waf_ban_max' => array(100, 100000),
		'waf_ban_keep_days' => array(1, 365),
```

In `waf_settings()` hinter der Prüfung des proxycheck-Schlüssels:

```php
	if (!in_array($settings['waf_ban_mode'], waf_ban_modes(), true)) {
		$settings['waf_ban_mode'] = $defaults['waf_ban_mode'];
	}
	$settings['waf_ban_bots'] = $settings['waf_ban_bots'] === 'off' ? 'off' : 'on';
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [x] **Step 5: Das Formular ergänzen**

In `ispconfig/interface/form/malwatch_waf_config.tform.php` hinter dem Feld `waf_origin_proxycheck_daily`:

```php
		'waf_ban_mode' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'off',
			'value' => array(
				'off' => 'ban_mode_off_txt',
				'propose' => 'ban_mode_propose_txt',
				'block' => 'ban_mode_ban_txt'
			)
		),
		'waf_ban_score' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '50',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '5:10000', 'errmsg' => 'waf_ban_score_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '5'
		),
		'waf_ban_window_minutes' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '10',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:1440', 'errmsg' => 'waf_ban_window_minutes_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_hours_first' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '1',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:8760', 'errmsg' => 'waf_ban_hours_first_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_hours_second' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '24',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:8760', 'errmsg' => 'waf_ban_hours_second_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_hours_third' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '168',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:8760', 'errmsg' => 'waf_ban_hours_third_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_ban_max' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '100:100000', 'errmsg' => 'waf_ban_max_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
		'waf_ban_keep_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '30',
			'validators' => array(
				array('type' => 'RANGE', 'range' => '1:365', 'errmsg' => 'waf_ban_keep_days_error_range')
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_ban_bots' => array(
			'datatype' => 'VARCHAR',
			'formtype' => 'SELECT',
			'default' => 'on',
			'value' => array(
				'on' => 'ban_bots_on_txt',
				'off' => 'ban_bots_off_txt'
			)
		),
```

- [x] **Step 6: Die Vorlage ergänzen**

In `ispconfig/interface/templates/malwatch_waf_config_edit.htm` vor dem Abschnitt „Cron" einfügen:

```html
<p class="mw-wafcfg-head">{tmpl_var name='ban_head_txt'}</p>
<p class="mw-wafcfg-note">{tmpl_var name='ban_intro_txt'}</p>

<div class="form-group">
	<label for="waf_ban_mode" class="col-sm-3 control-label">{tmpl_var name='waf_ban_mode_txt'}</label>
	<div class="col-sm-9">
		<select name="waf_ban_mode" id="waf_ban_mode" class="form-control">{tmpl_var name='waf_ban_mode'}</select>
		<span class="help-block">{tmpl_var name='waf_ban_mode_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_score" class="col-sm-3 control-label">{tmpl_var name='waf_ban_score_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="5" max="10000" step="1" name="waf_ban_score" id="waf_ban_score" value="{tmpl_var name='waf_ban_score'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_score_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_window_minutes" class="col-sm-3 control-label">{tmpl_var name='waf_ban_window_minutes_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="1440" step="1" name="waf_ban_window_minutes" id="waf_ban_window_minutes" value="{tmpl_var name='waf_ban_window_minutes'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_window_minutes_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_hours_first" class="col-sm-3 control-label">{tmpl_var name='waf_ban_hours_first_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="8760" step="1" name="waf_ban_hours_first" id="waf_ban_hours_first" value="{tmpl_var name='waf_ban_hours_first'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_hours_first_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_hours_second" class="col-sm-3 control-label">{tmpl_var name='waf_ban_hours_second_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="8760" step="1" name="waf_ban_hours_second" id="waf_ban_hours_second" value="{tmpl_var name='waf_ban_hours_second'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_hours_second_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_hours_third" class="col-sm-3 control-label">{tmpl_var name='waf_ban_hours_third_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="8760" step="1" name="waf_ban_hours_third" id="waf_ban_hours_third" value="{tmpl_var name='waf_ban_hours_third'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_hours_third_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_max" class="col-sm-3 control-label">{tmpl_var name='waf_ban_max_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="100" max="100000" step="1" name="waf_ban_max" id="waf_ban_max" value="{tmpl_var name='waf_ban_max'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_max_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_keep_days" class="col-sm-3 control-label">{tmpl_var name='waf_ban_keep_days_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="365" step="1" name="waf_ban_keep_days" id="waf_ban_keep_days" value="{tmpl_var name='waf_ban_keep_days'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ban_keep_days_hint_txt'}</span>
	</div>
</div>

<div class="form-group">
	<label for="waf_ban_bots" class="col-sm-3 control-label">{tmpl_var name='waf_ban_bots_txt'}</label>
	<div class="col-sm-9">
		<select name="waf_ban_bots" id="waf_ban_bots" class="form-control">{tmpl_var name='waf_ban_bots'}</select>
		<span class="help-block">{tmpl_var name='waf_ban_bots_hint_txt'}</span>
	</div>
</div>
```

Der Stilname `mw-wafcfg-head` steht bereits im Stilblock derselben Datei und wird für die Überschriften der Abschnitte genutzt; falls dort ein anderer Name steht, wird der genommen — maßgeblich ist der Block, den die Datei selbst mitbringt.

- [x] **Step 7: Die Texte ergänzen**

In `ispconfig/interface/lang/de_malwatch_waf_config.lng` ans Ende:

```php
$wb['ban_head_txt'] = 'Sperren';
$wb['ban_intro_txt'] = 'Wer in kurzer Zeit zu viele Punkte sammelt, wird serverweit mit 403 abgewiesen. Die Vorgabe ist „aus“: „vorschlagen“ rechnet nur mit, „sperren“ handelt.';
$wb['waf_ban_mode_txt'] = 'Automatik';
$wb['waf_ban_mode_hint_txt'] = 'Im Zustand „vorschlagen“ zeigt die Seite „Sperren“, wen malwatch gesperrt hätte. Der Knopf zum Sperren von Hand wirkt in jedem Zustand.';
$wb['ban_mode_off_txt'] = 'aus';
$wb['ban_mode_propose_txt'] = 'vorschlagen';
$wb['ban_mode_ban_txt'] = 'sperren';
$wb['waf_ban_score_txt'] = 'Punkte für eine Sperre';
$wb['waf_ban_score_hint_txt'] = 'So viele Anomalie-Punkte muss eine Adresse im Zeitfenster sammeln. Ein einzelner Treffer bringt meist 5 Punkte. Websites können einen eigenen Wert haben.';
$wb['waf_ban_window_minutes_txt'] = 'Zeitfenster (Minuten)';
$wb['waf_ban_window_minutes_hint_txt'] = 'Über diesen Zeitraum werden die Punkte einer Adresse zusammengezählt.';
$wb['waf_ban_hours_first_txt'] = 'Erste Sperre (Stunden)';
$wb['waf_ban_hours_first_hint_txt'] = 'So lange bleibt eine Adresse beim ersten Mal gesperrt.';
$wb['waf_ban_hours_second_txt'] = 'Zweite Sperre (Stunden)';
$wb['waf_ban_hours_second_hint_txt'] = 'So lange bleibt eine Adresse gesperrt, die innerhalb der Aufbewahrung schon einmal gesperrt war.';
$wb['waf_ban_hours_third_txt'] = 'Ab der dritten Sperre (Stunden)';
$wb['waf_ban_hours_third_hint_txt'] = 'So lange bleibt eine Adresse gesperrt, die es wieder und wieder versucht.';
$wb['waf_ban_max_txt'] = 'Höchstzahl gesperrter Adressen';
$wb['waf_ban_max_hint_txt'] = 'So viele Zeilen stehen höchstens in der Sperrdatei von nginx. Ist die Zahl erreicht, kommt keine neue Sperre dazu und die Seite sagt es.';
$wb['waf_ban_keep_days_txt'] = 'Sperren aufbewahren (Tage)';
$wb['waf_ban_keep_days_hint_txt'] = 'So lange bleiben abgelaufene und aufgehobene Sperren sichtbar; danach räumt der Cron sie weg. Der Wert bestimmt auch, wie lange eine Wiederholung als Wiederholung zählt.';
$wb['waf_ban_bots_txt'] = 'Suchmaschinen';
$wb['waf_ban_bots_hint_txt'] = 'Die veröffentlichten Adressbereiche von Google und Bing werden geladen und nie gesperrt.';
$wb['ban_bots_on_txt'] = 'verschonen';
$wb['ban_bots_off_txt'] = 'wie alle anderen';
$wb['waf_ban_score_error_range'] = 'Punkte für eine Sperre: Erlaubt sind ganze Zahlen von 5 bis 10000. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ban_window_minutes_error_range'] = 'Zeitfenster (Minuten): Erlaubt sind ganze Zahlen von 1 bis 1440. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ban_hours_first_error_range'] = 'Erste Sperre (Stunden): Erlaubt sind ganze Zahlen von 1 bis 8760. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ban_hours_second_error_range'] = 'Zweite Sperre (Stunden): Erlaubt sind ganze Zahlen von 1 bis 8760. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ban_hours_third_error_range'] = 'Ab der dritten Sperre (Stunden): Erlaubt sind ganze Zahlen von 1 bis 8760. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ban_max_error_range'] = 'Höchstzahl gesperrter Adressen: Erlaubt sind ganze Zahlen von 100 bis 100000. Bitte den Wert anpassen und erneut speichern.';
$wb['waf_ban_keep_days_error_range'] = 'Sperren aufbewahren (Tage): Erlaubt sind ganze Zahlen von 1 bis 365. Bitte den Wert anpassen und erneut speichern.';
```

In `ispconfig/interface/lang/en_malwatch_waf_config.lng` dieselben Schlüssel auf Englisch, Satz für Satz — etwa `$wb['ban_head_txt'] = 'Blocking';`, `$wb['ban_mode_propose_txt'] = 'propose';`, `$wb['waf_ban_score_error_range'] = 'Points for a block: whole numbers from 5 to 10000 are allowed. Please adjust the value and save again.';`

- [x] **Step 8: Das Schema ergänzen**

In `ispconfig/install/schema.sql` hinter dem Block, der die proxycheck-Spalten anlegt:

```sql
-- Sperren kommen mit 0.23.0: die Werte der Automatik.
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_config` ADD COLUMN `waf_ban_mode` enum(''off'',''propose'',''block'') NOT NULL DEFAULT ''off'', ADD COLUMN `waf_ban_score` int(11) unsigned NOT NULL DEFAULT ''50'', ADD COLUMN `waf_ban_window_minutes` int(11) unsigned NOT NULL DEFAULT ''10'', ADD COLUMN `waf_ban_hours_first` int(11) unsigned NOT NULL DEFAULT ''1'', ADD COLUMN `waf_ban_hours_second` int(11) unsigned NOT NULL DEFAULT ''24'', ADD COLUMN `waf_ban_hours_third` int(11) unsigned NOT NULL DEFAULT ''168'', ADD COLUMN `waf_ban_max` int(11) unsigned NOT NULL DEFAULT ''5000'', ADD COLUMN `waf_ban_keep_days` int(11) unsigned NOT NULL DEFAULT ''30'', ADD COLUMN `waf_ban_bots` enum(''off'',''on'') NOT NULL DEFAULT ''on''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME = 'waf_ban_mode');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Die Schwelle je Website; 0 heißt „wie der Server".
SET @mw := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_site` ADD COLUMN `waf_ban_score` int(11) unsigned NOT NULL DEFAULT ''0'', ADD COLUMN `waf_ban_trigger` enum(''y'',''n'') NOT NULL DEFAULT ''y''',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_site' AND COLUMN_NAME = 'waf_ban_score');
PREPARE stmt FROM @mw; EXECUTE stmt; DEALLOCATE PREPARE stmt;

--
-- One row per server and address: why it is blocked, since when, until when and
-- how many attempts were turned away since. cleanup() removes a row once its
-- end lies further back than waf_ban_keep_days.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_ban` (
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `ip` varchar(45) NOT NULL DEFAULT '',
  `state` enum('proposed','active','expired','lifted','dismissed') NOT NULL DEFAULT 'proposed',
  -- `rule` holds the rule that appeared most; the page turns it into words.
  `reason` varchar(255) NOT NULL DEFAULT '',
  `rule` varchar(16) NOT NULL DEFAULT '',
  `score` int(11) unsigned NOT NULL DEFAULT '0',
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  `level` tinyint(3) unsigned NOT NULL DEFAULT '1',
  `source` enum('auto','manual','fail2ban') NOT NULL DEFAULT 'auto',
  `created_at` datetime DEFAULT NULL,
  `blocked_at` datetime DEFAULT NULL,
  `until` datetime DEFAULT NULL,
  `lifted_at` datetime DEFAULT NULL,
  `lifted_by` varchar(64) NOT NULL DEFAULT '',
  `denied` int(11) unsigned NOT NULL DEFAULT '0',
  `denied_at` datetime DEFAULT NULL,
  PRIMARY KEY (`server_id`,`ip`),
  KEY `state_until` (`server_id`,`state`,`until`)
) DEFAULT CHARSET=utf8mb4 ;

--
-- Addresses and ranges that are never blocked. The fixed networks of the server
-- are in the code, not here.
--
CREATE TABLE IF NOT EXISTS `malwatch_waf_allow` (
  `allow_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `cidr` varchar(64) NOT NULL DEFAULT '',
  `note` varchar(255) NOT NULL DEFAULT '',
  `created_at` datetime DEFAULT NULL,
  `created_by` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`allow_id`),
  UNIQUE KEY `server_cidr` (`server_id`,`cidr`)
) DEFAULT CHARSET=utf8mb4 ;
```

In `ispconfig/install/uninstall-schema.sql` hinter den anderen `DROP TABLE`-Zeilen:

```sql
DROP TABLE IF EXISTS `malwatch_waf_ban`;
DROP TABLE IF EXISTS `malwatch_waf_allow`;
```

- [x] **Step 9: Die Kulisse der Vorschau nachziehen**

In `.superpowers/abwehr/harness/fake_db.php` (außerhalb des Repositorys) die Konfigurationszeile um die neun Werte ergänzen, sonst rendert die Einstellungsseite ohne sie:

```php
				'waf_ban_mode' => 'off', 'waf_ban_score' => '50', 'waf_ban_window_minutes' => '10',
				'waf_ban_hours_first' => '1', 'waf_ban_hours_second' => '24', 'waf_ban_hours_third' => '168',
				'waf_ban_max' => '5000', 'waf_ban_keep_days' => '30', 'waf_ban_bots' => 'on',
```

- [x] **Step 10: Prüfen**

Run: `php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php`
Expected: dreimal `alle Prüfungen bestanden`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`

Run: `grep -c 'Punkte für eine Sperre\|Zeitfenster (Minuten)\|Höchstzahl gesperrter Adressen' .superpowers/abwehr/harness/out_cfg.html`
Expected: mindestens `3`

- [x] **Step 11: Commit**

```bash
git add ispconfig/install ispconfig/interface ispconfig/tests/waf_lib_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): settings and tables for blocking attacker addresses" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D2: Die Entscheidung — wer, warum, wie lange

Eine eigene Bibliothek für alles, was ohne Datenbank auskommt. Sie beantwortet drei Fragen: Welche Schwelle gilt für diese Website? Wer hat sie überschritten? Wie lange und mit welcher Begründung wird gesperrt?

**Files:**
- Create: `ispconfig/interface/lib/malwatch_waf_ban.inc.php`
- Create: `ispconfig/tests/waf_ban_test.php`
- Modify: `ispconfig/install/file.list`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `waf_origin_bytes($ip)`, `waf_origin_cut($text, $bytes)` aus `malwatch_waf_origin.inc.php`; die Einstellungen aus Task D1
- Produces:
  - `waf_ban_site_score($settings, $site)` → int; `0` heißt „diese Website löst nie eine Sperre aus"
  - `waf_ban_decide($groups, $settings, $sites)` → Liste von `array('ip', 'domain', 'score', 'hits', 'rule', 'limit')`, je Adresse die Website mit den meisten Punkten
  - `waf_ban_level($earlier)` → 1, 2 oder 3
  - `waf_ban_hours($level, $settings)` → int
  - `waf_ban_until($level, $settings, $now)` → `'Y-m-d H:i:s'`
  - `waf_ban_reason($pick, $minutes, $rule_label)` → deutscher Satz, höchstens 255 Bytes

- [x] **Step 1: Den scheiternden Test schreiben**

`ispconfig/tests/waf_ban_test.php`:

```php
<?php
/**
 * Checks who is blocked, for how long and with which reason.
 *
 *   php ispconfig/tests/waf_ban_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_ban.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . PHP_EOL);
	}
}

$settings = array('waf_ban_score' => 50, 'waf_ban_window_minutes' => 10, 'waf_ban_hours_first' => 1,
	'waf_ban_hours_second' => 24, 'waf_ban_hours_third' => 168, 'waf_ban_max' => 5000,
	'waf_ban_keep_days' => 30);
$sites = array(
	11 => array('parent_domain_id' => '11', 'domain' => 'beispiel.test', 'waf_ban_score' => '0', 'waf_ban_trigger' => 'y'),
	12 => array('parent_domain_id' => '12', 'domain' => 'zweite.test', 'waf_ban_score' => '20', 'waf_ban_trigger' => 'y'),
	13 => array('parent_domain_id' => '13', 'domain' => 'dritte.test', 'waf_ban_score' => '0', 'waf_ban_trigger' => 'n'),
);

// --- The threshold of a website -----------------------------------------------

expect_same('a website without a value of its own takes the server value',
	waf_ban_site_score($settings, $sites[11]), 50);
expect_same('a website with its own value', waf_ban_site_score($settings, $sites[12]), 20);
expect_same('a website that never triggers', waf_ban_site_score($settings, $sites[13]), 0);
expect_same('an unknown website takes the server value', waf_ban_site_score($settings, null), 50);

// --- Who crossed it -----------------------------------------------------------

$groups = array(
	array('client_ip' => '192.0.2.10', 'parent_domain_id' => '11', 'score' => '62', 'hits' => '14', 'rule' => '930130'),
	array('client_ip' => '192.0.2.10', 'parent_domain_id' => '12', 'score' => '25', 'hits' => '5', 'rule' => '941100'),
	array('client_ip' => '198.51.100.7', 'parent_domain_id' => '11', 'score' => '30', 'hits' => '6', 'rule' => '920440'),
	array('client_ip' => '198.51.100.9', 'parent_domain_id' => '12', 'score' => '30', 'hits' => '6', 'rule' => '920440'),
	array('client_ip' => '203.0.113.5', 'parent_domain_id' => '13', 'score' => '900', 'hits' => '90', 'rule' => '930130'),
);
$picked = waf_ban_decide($groups, $settings, $sites);
expect_same('two addresses crossed a threshold', array_column($picked, 'ip'),
	array('192.0.2.10', '198.51.100.9'));
expect_same('the website with the most points is named',
	array($picked[0]['domain'], $picked[0]['score'], $picked[0]['hits'], $picked[0]['limit']),
	array('beispiel.test', 62, 14, 50));
expect_same('a website with its own lower value counts too',
	array($picked[1]['domain'], $picked[1]['score'], $picked[1]['limit']), array('zweite.test', 30, 20));
expect_same('nothing crossed, nothing picked', waf_ban_decide(array(
	array('client_ip' => '198.51.100.7', 'parent_domain_id' => '11', 'score' => '5', 'hits' => '1', 'rule' => '')),
	$settings, $sites), array());

// --- How long -----------------------------------------------------------------

expect_same('the first block', waf_ban_level(0), 1);
expect_same('the second block', waf_ban_level(1), 2);
expect_same('the third and every later one', array(waf_ban_level(2), waf_ban_level(9)), array(3, 3));
expect_same('the hours of every level', array(waf_ban_hours(1, $settings), waf_ban_hours(2, $settings),
	waf_ban_hours(3, $settings)), array(1, 24, 168));
expect_same('the end of a first block', waf_ban_until(1, $settings, '2026-09-18 10:00:00'), '2026-09-18 11:00:00');
expect_same('the end of a third block', waf_ban_until(3, $settings, '2026-09-18 10:00:00'), '2026-09-25 10:00:00');

// --- Why ----------------------------------------------------------------------

expect_same('the reason in one sentence',
	waf_ban_reason($picked[0], 10, 'Zugriff auf geschützte Datei (930130)'),
	'62 Punkte aus 14 Treffern in 10 Minuten auf beispiel.test, meist Zugriff auf geschützte Datei (930130).');
expect_same('a reason without a rule in words',
	waf_ban_reason(array('ip' => '192.0.2.10', 'domain' => 'beispiel.test', 'score' => 1200, 'hits' => 240,
		'rule' => '', 'limit' => 50), 10, ''),
	'1.200 Punkte aus 240 Treffern in 10 Minuten auf beispiel.test.');

// --- summary -----------------------------------------------------------------

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_ban: alle Prüfungen bestanden' . PHP_EOL;
```

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `PHP Warning: require(...malwatch_waf_ban.inc.php): Failed to open stream`

- [x] **Step 3: Die Bibliothek schreiben**

`ispconfig/interface/lib/malwatch_waf_ban.inc.php`:

```php
<?php
/**
 * Blocking attacker addresses: who crosses a threshold, for how long and with
 * which reason. Everything here works without a database and without a network,
 * so tests/waf_ban_test.php can check it on its own. The texts are German,
 * like the notes of the jobs.
 */
require_once __DIR__ . '/malwatch_waf_origin.inc.php';

/**
 * The points a website needs before an address is blocked: its own value, the
 * value of the server, or 0 when the website never triggers a block.
 */
function waf_ban_site_score($settings, $site)
{
	$trigger = is_array($site) && isset($site['waf_ban_trigger']) ? (string) $site['waf_ban_trigger'] : 'y';
	if ($trigger !== 'y') {
		return 0;
	}
	$own = is_array($site) && isset($site['waf_ban_score']) ? (int) $site['waf_ban_score'] : 0;
	return $own > 0 ? $own : (int) $settings['waf_ban_score'];
}

/**
 * The addresses that crossed the threshold of at least one website. $groups are
 * the sums of the window with client_ip, parent_domain_id, score, hits and the
 * rule that appeared most; $sites holds the websites by parent_domain_id. One
 * entry per address, naming the website with the most points.
 */
function waf_ban_decide($groups, $settings, $sites)
{
	$picked = array();
	foreach ($groups as $row) {
		$id = (int) $row['parent_domain_id'];
		$site = isset($sites[$id]) ? $sites[$id] : null;
		$limit = waf_ban_site_score($settings, $site);
		$score = (int) $row['score'];
		if ($limit <= 0 || $score < $limit) {
			continue;
		}
		$ip = (string) $row['client_ip'];
		if (isset($picked[$ip]) && $picked[$ip]['score'] >= $score) {
			continue;
		}
		$picked[$ip] = array(
			'ip' => $ip,
			'domain' => is_array($site) && isset($site['domain']) ? (string) $site['domain'] : '',
			'score' => $score,
			'hits' => (int) $row['hits'],
			'rule' => isset($row['rule']) ? (string) $row['rule'] : '',
			'limit' => $limit,
		);
	}
	return array_values($picked);
}

/** The level of a block: 1 the first time, 2 the second, 3 from then on. */
function waf_ban_level($earlier)
{
	$earlier = (int) $earlier;
	if ($earlier < 1) {
		return 1;
	}
	return $earlier === 1 ? 2 : 3;
}

/** The hours a block of that level lasts. */
function waf_ban_hours($level, $settings)
{
	if ((int) $level >= 3) {
		return (int) $settings['waf_ban_hours_third'];
	}
	return (int) $level === 2 ? (int) $settings['waf_ban_hours_second'] : (int) $settings['waf_ban_hours_first'];
}

/** When a block of that level ends, counted from $now. */
function waf_ban_until($level, $settings, $now)
{
	return gmdate('Y-m-d H:i:s', strtotime((string) $now) + waf_ban_hours($level, $settings) * 3600);
}

/**
 * The reason of a block as one sentence: points, hits, window, website and the
 * rule that appeared most, in words.
 */
function waf_ban_reason($pick, $minutes, $rule_label)
{
	$reason = number_format((int) $pick['score'], 0, ',', '.') . ' Punkte aus ' . (int) $pick['hits']
		. ' Treffern in ' . (int) $minutes . ' Minuten';
	if ((string) $pick['domain'] !== '') {
		$reason .= ' auf ' . $pick['domain'];
	}
	if ((string) $rule_label !== '') {
		$reason .= ', meist ' . $rule_label;
	}
	return waf_origin_cut($reason . '.', 255);
}
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `waf_ban: alle Prüfungen bestanden`

- [x] **Step 5: Die Bibliothek wird mitkopiert**

In `ispconfig/install/file.list` hinter der Zeile für `malwatch_waf_origin.inc.php` dieselbe Form mit `malwatch_waf_ban.inc.php` einfügen — die Datei gehört in `interface/web/security/lib/`, wie ihre Nachbarn.

Run: `grep -c 'malwatch_waf_ban.inc.php' ispconfig/install/file.list`
Expected: `1`

- [x] **Step 6: Die CI kennt den neuen Test**

In `.github/workflows/ci.yml` hinter dem Schritt „WAF proxycheck":

```yaml
      - name: WAF ban
        run: php ispconfig/tests/waf_ban_test.php
```

- [x] **Step 7: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_ban.inc.php ispconfig/tests/waf_ban_test.php ispconfig/install/file.list .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): decide who is blocked, for how long and why" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D3: Was nie gesperrt wird

Drei Schutzschichten vor jeder Sperre: die eigenen Netze, die Ausnahmeliste des Betreibers und die veröffentlichten Adressbereiche der Suchmaschinen. Letztere kommen über die Maschinerie der Herkunft — eine weitere Quelle, dieselbe Bereichsdatei, dieselbe binäre Suche.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_ban.inc.php`
- Modify: `ispconfig/interface/lib/malwatch_waf_origin.inc.php`
- Create: `ispconfig/tests/fixtures/bots/googlebot.json`, `ispconfig/tests/fixtures/bots/bingbot.json`
- Test: `ispconfig/tests/waf_ban_test.php`, `ispconfig/tests/waf_origin_sources_test.php`

**Interfaces:**
- Consumes: `waf_origin_cidr($cidr)` → `array(erste, letzte)` 16-Byte-Adresse oder `null`; `waf_origin_read_list($files, $out)`; `waf_origin_find($reader, $ip)` → Wert oder `''`
- Produces:
  - `waf_ban_fixed_allow()` → `array('127.0.0.0/8', '::1/128', '10.50.0.0/24')`
  - `waf_ban_allow_match($cidrs, $ip)` → bool
  - `waf_ban_allowed($ip, $cidrs, $reader)` → bool; `$reader` ist der geöffnete Leser von `searchbots` oder `null`
  - `waf_origin_read_bots($in, $out)` → wie die anderen Leser `array('ranges', 'values', 'lines', 'bad', 'skipped')` oder `null`
  - Quelle `searchbots` in `waf_origin_sources()`

- [x] **Step 1: Die Beispieldateien anlegen**

`ispconfig/tests/fixtures/bots/googlebot.json`:

```json
{
	"creationTime": "2026-09-01T00:00:00.000000",
	"prefixes": [
		{"ipv4Prefix": "192.0.2.0/24"},
		{"ipv6Prefix": "2001:db8:1::/48"},
		{"ipv4Prefix": "198.51.100.64/26"}
	]
}
```

`ispconfig/tests/fixtures/bots/bingbot.json`:

```json
{
	"creationTime": "2026-09-01T00:00:00.000000",
	"prefixes": [
		{"ipv4Prefix": "203.0.113.0/25"},
		{"ipv6Prefix": "2001:db8:2::/48"}
	]
}
```

- [x] **Step 2: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_ban_test.php` vor dem Abschnitt „summary" anfügen:

```php
// --- What is never blocked ----------------------------------------------------

expect_same('the fixed networks', waf_ban_fixed_allow(), array('127.0.0.0/8', '::1/128', '10.50.0.0/24'));
expect_same('the proxy is protected', waf_ban_allow_match(waf_ban_fixed_allow(), '10.50.0.1'), true);
expect_same('localhost is protected', waf_ban_allow_match(waf_ban_fixed_allow(), '127.0.0.1'), true);
expect_same('a visitor is not', waf_ban_allow_match(waf_ban_fixed_allow(), '192.0.2.10'), false);
expect_same('an address of the list', waf_ban_allow_match(array('203.0.113.0/24', '198.51.100.7'), '203.0.113.99'), true);
expect_same('a single address of the list', waf_ban_allow_match(array('198.51.100.7'), '198.51.100.7'), true);
expect_same('the neighbour of a single address',
	waf_ban_allow_match(array('198.51.100.7'), '198.51.100.8'), false);
expect_same('IPv6 in a range', waf_ban_allow_match(array('2001:db8::/32'), '2001:db8:1::5'), true);
expect_same('IPv6 outside a range', waf_ban_allow_match(array('2001:db8::/32'), '2001:db9::5'), false);
expect_same('what is no address is never allowed', waf_ban_allow_match(array('0.0.0.0/0'), 'kein-ip'), false);
expect_same('an entry that is no range is skipped',
	waf_ban_allow_match(array('unsinn', '203.0.113.0/24'), '203.0.113.9'), true);
expect_same('the three layers together, without a reader',
	array(waf_ban_allowed('10.50.0.1', array(), null), waf_ban_allowed('203.0.113.9', array('203.0.113.0/24'), null),
		waf_ban_allowed('192.0.2.10', array('203.0.113.0/24'), null)), array(true, true, false));
```

In `ispconfig/tests/waf_origin_sources_test.php` vor dem Abschnitt „summary" anfügen:

```php
// --- The ranges of the search engines -----------------------------------------

expect_same('search engines are a source of their own',
	isset(waf_origin_sources()['searchbots']), true);
expect_same('the search engines are chosen with their own setting',
	waf_origin_chosen(array('waf_ban_bots' => 'on')), array('searchbots'));
expect_same('two addresses for the search engines', count(waf_origin_urls('searchbots', '')), 2);
$bots = __DIR__ . '/fixtures/bots';
$out = $dir . '/searchbots.bin';
$counts = waf_origin_read_bots(array($bots . '/googlebot.json', $bots . '/bingbot.json'), $out);
expect_same('every prefix became a range', array($counts['ranges'], $counts['bad']), array(5, 0));
$reader = waf_origin_open($out);
expect_same('an address of Google', waf_origin_find($reader, '192.0.2.77'), 'y');
expect_same('an address of Bing', waf_origin_find($reader, '203.0.113.5'), 'y');
expect_same('an address of Bing outside its range', waf_origin_find($reader, '203.0.113.200'), '');
expect_same('an IPv6 address of a search engine', waf_origin_find($reader, '2001:db8:1::9'), 'y');
expect_same('an address of nobody', waf_origin_find($reader, '198.51.100.9'), '');
waf_origin_close($reader);
expect_same('a file that is no JSON gives nothing',
	waf_origin_read_bots(array($bots . '/gibt-es-nicht.json'), $dir . '/leer.bin'), null);
```

- [x] **Step 3: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_ban_fixed_allow()`

- [x] **Step 4: Die Ausnahmen schreiben**

Ans Ende von `ispconfig/interface/lib/malwatch_waf_ban.inc.php`:

```php

/**
 * The networks that are never blocked, whatever the settings say: localhost and
 * the network of the proxy in front of the server. Without them the server
 * could lock itself out.
 */
function waf_ban_fixed_allow()
{
	return array('127.0.0.0/8', '::1/128', '10.50.0.0/24');
}

/** true when the address lies in one of the given addresses or ranges. */
function waf_ban_allow_match($cidrs, $ip)
{
	$bytes = waf_origin_bytes($ip);
	if ($bytes === '') {
		return false;
	}
	foreach ($cidrs as $cidr) {
		$range = waf_origin_cidr($cidr);
		if ($range === null) {
			continue;
		}
		if (strcmp($bytes, $range[0]) >= 0 && strcmp($bytes, $range[1]) <= 0) {
			return true;
		}
	}
	return false;
}

/**
 * The three layers before a block: the fixed networks, the list of the operator
 * (which carries the addresses of the server itself) and the ranges of the
 * search engines. $reader is the open reader of the source searchbots or null.
 */
function waf_ban_allowed($ip, $cidrs, $reader)
{
	if (waf_ban_allow_match(waf_ban_fixed_allow(), $ip)) {
		return true;
	}
	if (waf_ban_allow_match($cidrs, $ip)) {
		return true;
	}
	return $reader !== null && waf_origin_find($reader, $ip) !== '';
}
```

- [x] **Step 5: Die Quelle der Suchmaschinen schreiben**

In `ispconfig/interface/lib/malwatch_waf_origin.inc.php` in `waf_origin_sources()` hinter `x4b_datacenter` einfügen:

```php
		'searchbots' => array('setting' => 'waf_ban_bots', 'value' => 'on', 'kind' => 'bots',
			'min' => 10, 'bytes' => 8 * 1024 * 1024, 'hours' => 'waf_origin_list_hours'),
```

In `waf_origin_urls()` den Zweig für die neue Quelle ergänzen — die beiden Listen stehen fest:

```php
		case 'searchbots':
			return array(
				'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
				'https://www.bing.com/toolbox/bingbot.json',
			);
```

Hinter `waf_origin_read_list()`:

```php
/**
 * The published ranges of the search engines. Google and Bing answer with JSON
 * whose entries carry ipv4Prefix or ipv6Prefix; the prefixes go through the
 * reader of the plain lists, so sorting and merging stay in one place.
 */
function waf_origin_read_bots($in, $out)
{
	$files = is_array($in) ? $in : array($in);
	$plain = $out . '.list';
	$handle = @fopen($plain, 'wb');
	if ($handle === false) {
		return null;
	}
	$bad = 0;
	$found = 0;
	foreach ($files as $file) {
		$data = json_decode((string) @file_get_contents($file), true);
		if (!is_array($data) || !isset($data['prefixes']) || !is_array($data['prefixes'])) {
			$bad++;
			continue;
		}
		foreach ($data['prefixes'] as $entry) {
			$cidr = '';
			if (is_array($entry)) {
				if (isset($entry['ipv4Prefix'])) {
					$cidr = (string) $entry['ipv4Prefix'];
				} elseif (isset($entry['ipv6Prefix'])) {
					$cidr = (string) $entry['ipv6Prefix'];
				}
			}
			if ($cidr === '') {
				$bad++;
				continue;
			}
			fwrite($handle, $cidr . "\n");
			$found++;
		}
	}
	fclose($handle);
	if ($found === 0) {
		@unlink($plain);
		return null;
	}
	$counts = waf_origin_read_list(array($plain), $out);
	@unlink($plain);
	if (is_array($counts)) {
		$counts['bad'] += $bad;
	}
	return $counts;
}
```

In `waf_origin_facts()` als erste Zeile der Schleife einfügen — die Suchmaschinen sagen nichts über die Herkunft einer Adresse, sie schützen nur:

```php
		if ($name === 'searchbots') {
			continue;
		}
```

- [x] **Step 6: Der Cron kennt den neuen Leser**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php` in `origin_read()` vor der abschließenden Zeile `return waf_origin_read_list($files, $fresh);`:

```php
			case 'searchbots':
				return waf_origin_read_bots($files, $fresh);
```

- [x] **Step 7: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_ban_test.php && php ispconfig/tests/waf_origin_sources_test.php && php ispconfig/tests/waf_origin_test.php && php ispconfig/tests/waf_proxycheck_test.php`
Expected: viermal `alle Prüfungen bestanden`

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php`
Expected: `No syntax errors detected`

- [x] **Step 8: Commit**

```bash
git add ispconfig/interface/lib ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): never block the own networks, the allow list or a search engine" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D4: Die Datei für nginx und das Zählen

Zwei kleine, aber heikle Stücke: der Inhalt von `/etc/nginx/waf/blocked.conf` — eine kaputte Zeile darin legt nginx lahm — und das Lesen einer Zeile aus `/var/log/waf/blocked.log`.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_ban.inc.php`
- Test: `ispconfig/tests/waf_ban_test.php`

**Interfaces:**
- Consumes: `waf_origin_bytes($ip)` aus `malwatch_waf_origin.inc.php`
- Produces:
  - `waf_ban_file($ips, $now, $max)` → Inhalt der Datei, endet auf `\n`
  - `waf_ban_log_line($line)` → `array('ip' => '…')` oder `null`

- [x] **Step 1: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_ban_test.php` vor dem Abschnitt „summary" anfügen:

```php
// --- The file for nginx -------------------------------------------------------

$file = waf_ban_file(array('192.0.2.10', '2001:db8::5'), '2026-09-18 10:00:00', 5000);
expect_same('the file says where it comes from', substr($file, 0, 21), '# von malwatch erzeugt');
expect_same('one line per address', substr_count($file, 'deny '), 2);
expect_same('a line ends with a semicolon', strpos($file, 'deny 192.0.2.10;') !== false, true);
expect_same('IPv6 belongs in there too', strpos($file, 'deny 2001:db8::5;') !== false, true);
expect_same('the file ends with a newline', substr($file, -1), "\n");
expect_same('what is no address never reaches nginx',
	substr_count(waf_ban_file(array('kein-ip', '"; server {', '192.0.2.10'), '2026-09-18 10:00:00', 5000), 'deny '), 1);
expect_same('the limit holds',
	substr_count(waf_ban_file(array('192.0.2.10', '192.0.2.11', '192.0.2.12'), '2026-09-18 10:00:00', 2), 'deny '), 2);
expect_same('an empty list gives a file without a single deny',
	substr_count(waf_ban_file(array(), '2026-09-18 10:00:00', 5000), 'deny '), 0);

// --- The log of the turned away requests --------------------------------------

expect_same('a line of a turned away request',
	waf_ban_log_line('2026-09-18T10:00:01+02:00 192.0.2.10 403 beispiel.test "GET /wp-login.php HTTP/1.1"'),
	array('ip' => '192.0.2.10'));
expect_same('another answer does not count',
	waf_ban_log_line('2026-09-18T10:00:01+02:00 192.0.2.10 200 beispiel.test "GET / HTTP/1.1"'), null);
expect_same('a line without an address', waf_ban_log_line('2026-09-18T10:00:01+02:00 kein-ip 403 x "GET / HTTP/1.1"'), null);
expect_same('an empty line', waf_ban_log_line(''), null);
expect_same('a fragment', waf_ban_log_line('2026-09-18T10:00:01+02:00 192.0.2.10'), null);
```

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_ban_file()`

- [x] **Step 3: Die beiden Funktionen schreiben**

Ans Ende von `ispconfig/interface/lib/malwatch_waf_ban.inc.php`:

```php

/**
 * The content of /etc/nginx/waf/blocked.conf. Only what inet_pton accepts
 * reaches the file, so nothing can smuggle a directive into the configuration
 * of nginx. At most $max lines, in the order they are handed over.
 */
function waf_ban_file($ips, $now, $max)
{
	$lines = array('# von malwatch erzeugt am ' . (string) $now . '. Änderungen hier werden überschrieben.');
	$max = (int) $max;
	$count = 0;
	foreach ($ips as $ip) {
		if ($count >= $max) {
			break;
		}
		$ip = trim((string) $ip);
		if (waf_origin_bytes($ip) === '') {
			continue;
		}
		$lines[] = 'deny ' . $ip . ';';
		$count++;
	}
	return implode("\n", $lines) . "\n";
}

/**
 * One line of /var/log/waf/blocked.log, written in the format mw_block:
 * time, address, status, host, request. Only an answer 403 from a real address
 * counts; everything else is none of our business.
 */
function waf_ban_log_line($line)
{
	$parts = explode(' ', trim((string) $line));
	if (count($parts) < 3) {
		return null;
	}
	if ((int) $parts[2] !== 403 || waf_origin_bytes($parts[1]) === '') {
		return null;
	}
	return array('ip' => (string) $parts[1]);
}
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `waf_ban: alle Prüfungen bestanden`

- [x] **Step 5: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_ban.inc.php ispconfig/tests/waf_ban_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the deny file of nginx and the log of turned away requests" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D5: Der Motor im Cron

Erkennen, schreiben, neu laden, ablaufen, zählen. Die Klasse braucht eine Datenbank und läuft nur auf dem Server; der Test dafür ist `waf_class_probe.php`, geschrieben in Task D6 und ausgeführt in Task D10, Block 1. Lokal prüfen `php -l`, die Testreihen und `check_wiring.sh`.

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_waf_ban.inc.php` (`waf_ban_top_rule()`)
- Modify: `ispconfig/server/lib/classes/malwatch_waf.inc.php`
- Test: `ispconfig/tests/waf_ban_test.php`

**Interfaces:**
- Consumes: `waf_ban_decide()`, `waf_ban_level()`, `waf_ban_until()`, `waf_ban_reason()`, `waf_ban_allowed()`, `waf_ban_file()`, `waf_ban_log_line()` aus D2 bis D4; `run_command('nginx_test'|'nginx_reload')`, `ensure_dirs()`, `rows()`, `now()`, `settings()` aus der Klasse
- Produces:
  - `waf_ban_top_rule($rows)` → Regel-ID als Zeichenkette oder `''`
  - `malwatch_waf::ban_scan()` → Zahl der neuen Sperren oder Vorschläge
  - `malwatch_waf::ban_apply()` → `array(geändert, Fehlertext)`
  - `malwatch_waf::ban_expire()` → Zahl der abgelaufenen Sperren
  - `malwatch_waf::ban_count()` → Zahl der gezählten Zeilen

- [x] **Step 1: Die scheiternde Prüfung für die häufigste Regel schreiben**

In `ispconfig/tests/waf_ban_test.php` hinter dem Abschnitt „Why" anfügen:

```php
// --- The rule that appeared most ----------------------------------------------

$hits = array(
	array('rules' => '["930130","949110"]'),
	array('rules' => '["930130","949110"]'),
	array('rules' => '["941100","949110"]'),
	array('rules' => 'kein json'),
);
expect_same('the rule that appeared most, without the scoring rules', waf_ban_top_rule($hits), '930130');
expect_same('only scoring rules means no rule',
	waf_ban_top_rule(array(array('rules' => '["949110","980130"]'))), '');
expect_same('no hits, no rule', waf_ban_top_rule(array()), '');
```

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_ban_top_rule()`

- [x] **Step 3: Die Funktion schreiben**

Ans Ende von `ispconfig/interface/lib/malwatch_waf_ban.inc.php`:

```php

/**
 * The rule that appeared most in the hits of the window. The four scoring rules
 * of the CRS stand in almost every hit and say nothing about the attack, so
 * they are left out.
 */
function waf_ban_top_rule($rows)
{
	$scoring = array('949110', '959100', '980130', '980140');
	$count = array();
	foreach ($rows as $row) {
		$ids = json_decode(isset($row['rules']) ? (string) $row['rules'] : '', true);
		if (!is_array($ids)) {
			continue;
		}
		foreach ($ids as $id) {
			$id = trim((string) $id);
			if ($id === '' || in_array($id, $scoring, true)) {
				continue;
			}
			$count[$id] = isset($count[$id]) ? $count[$id] + 1 : 1;
		}
	}
	arsort($count);
	foreach ($count as $id => $seen) {
		return (string) $id;
	}
	return '';
}
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_ban_test.php`
Expected: `waf_ban: alle Prüfungen bestanden`

- [x] **Step 5: Die Bibliothek in der Klasse laden**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php` hinter `const LIB_ORIGIN`:

```php
	/** The library that decides who is blocked; installed next to the panel. */
	const LIB_BAN = '/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_ban.inc.php';
```

Dazu bei den Eigenschaften, neben `$fetcher` und `$poster`:

```php
	/** The log nginx writes the turned away requests into; a probe points it elsewhere. */
	public $ban_log = '/var/log/waf/blocked.log';
```

In `ready()` wird sie wie die anderen geladen — dieselbe Zeile wie für `LIB_ORIGIN`, mit `LIB_BAN`.

- [x] **Step 6: Das Erkennen schreiben**

Hinter `origin_external_state()` in derselben Datei:

```php
	/**
	 * Looks at the window and writes down every address that crossed the
	 * threshold of a website: as a proposal in the mode propose, as a block in
	 * the mode block. Returns how many rows were written.
	 */
	public function ban_scan()
	{
		global $app, $conf;

		$settings = $this->settings();
		$mode = (string) $settings['waf_ban_mode'];
		if ($mode !== 'propose' && $mode !== 'block') {
			return 0;
		}
		$now = $this->now();
		$minutes = (int) $settings['waf_ban_window_minutes'];
		$since = gmdate('Y-m-d H:i:s', strtotime($now) - $minutes * 60);
		$groups = $this->rows($app->dbmaster->queryAllRecords(
			'SELECT client_ip, parent_domain_id, SUM(anomaly_score) AS score, COUNT(*) AS hits '
			. "FROM malwatch_waf_hit WHERE server_id = ? AND seen_at >= ? AND client_ip != '' "
			. 'GROUP BY client_ip, parent_domain_id', $conf['server_id'], $since));
		if (count($groups) === 0) {
			return 0;
		}
		$sites = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT parent_domain_id, domain, waf_ban_score, waf_ban_trigger FROM malwatch_site WHERE server_id = ?',
			$conf['server_id'])) as $row) {
			$sites[(int) $row['parent_domain_id']] = $row;
		}
		$picked = waf_ban_decide($groups, $settings, $sites);
		if (count($picked) === 0) {
			return 0;
		}
		$known = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT ip, state, level, created_at, lifted_at FROM malwatch_waf_ban WHERE server_id = ?',
			$conf['server_id'])) as $row) {
			$known[(string) $row['ip']] = $row;
		}
		$allow = $this->ban_allow_list();
		$readers = waf_origin_readers($this->ensure_dirs() . '/origin',
			(string) $settings['waf_ban_bots'] === 'on' ? array('searchbots') : array());
		$reader = isset($readers['searchbots']) ? $readers['searchbots'] : null;
		$active = (int) $this->db_value("SELECT COUNT(*) AS value FROM malwatch_waf_ban WHERE server_id = "
			. (int) $conf['server_id'] . " AND state = 'active'");
		$written = 0;
		foreach ($picked as $pick) {
			$ip = $pick['ip'];
			if (isset($known[$ip]) && $this->ban_keeps_quiet($known[$ip], $since)) {
				continue;
			}
			if (waf_ban_allowed($ip, $allow, $reader)) {
				continue;
			}
			if ($mode === 'block' && $active >= (int) $settings['waf_ban_max']) {
				$app->log('malwatch: die Sperrliste ist voll (' . (int) $settings['waf_ban_max']
					. ' Adressen); ' . $ip . ' wurde nicht gesperrt.', LOGLEVEL_WARN);
				break;
			}
			$top = waf_ban_top_rule($this->rows($app->dbmaster->queryAllRecords(
				'SELECT rules FROM malwatch_waf_hit WHERE server_id = ? AND client_ip = ? AND seen_at >= ? LIMIT 200',
				$conf['server_id'], $ip, $since)));
			$level = waf_ban_level(isset($known[$ip]) ? (int) $known[$ip]['level'] : 0);
			$state = $mode === 'block' ? 'active' : 'proposed';
			$app->dbmaster->query('INSERT INTO malwatch_waf_ban (server_id, ip, state, reason, rule, score, hits, '
				. "level, source, created_at, blocked_at, until, lifted_at, lifted_by, denied, denied_at) "
				. "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'auto', ?, ?, ?, NULL, '', 0, NULL) "
				. 'ON DUPLICATE KEY UPDATE state = VALUES(state), reason = VALUES(reason), rule = VALUES(rule), '
				. 'score = VALUES(score), hits = VALUES(hits), level = VALUES(level), source = VALUES(source), '
				. 'created_at = VALUES(created_at), blocked_at = VALUES(blocked_at), until = VALUES(until), '
				. "lifted_at = NULL, lifted_by = '', denied = 0, denied_at = NULL",
				$conf['server_id'], $ip, $state,
				waf_ban_reason($pick, $minutes, $top === '' ? '' : 'Regel ' . $top), $top,
				$pick['score'], $pick['hits'], $level, $now,
				$state === 'active' ? $now : null,
				$state === 'active' ? waf_ban_until($level, $settings, $now) : null);
			if ($state === 'active') {
				$active++;
			}
			$written++;
		}
		waf_origin_readers_close($readers);
		return $written;
	}

	/**
	 * true when an address is left alone: it carries a running block or a waiting
	 * proposal, or its proposal was dismissed or its block lifted inside the
	 * window — then the decision of the operator counts, not the counter.
	 */
	private function ban_keeps_quiet($row, $since)
	{
		$state = (string) $row['state'];
		if ($state === 'proposed' || $state === 'active') {
			return true;
		}
		if ($state === 'dismissed') {
			return (string) $row['created_at'] >= (string) $since;
		}
		return $state === 'lifted' && (string) $row['lifted_at'] >= (string) $since;
	}

	/**
	 * The addresses and ranges that are never blocked: the list of the operator
	 * plus every address the server itself carries.
	 */
	private function ban_allow_list()
	{
		global $app, $conf;

		$list = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT cidr FROM malwatch_waf_allow WHERE server_id = ?', $conf['server_id'])) as $row) {
			$list[] = (string) $row['cidr'];
		}
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			'SELECT ip_address FROM server_ip WHERE server_id = ?', $conf['server_id'])) as $row) {
			$list[] = (string) $row['ip_address'];
		}
		return $list;
	}
```

- [x] **Step 7: Das Anwenden schreiben**

Direkt dahinter:

```php
	/**
	 * Writes the deny file of nginx from the active blocks and reloads nginx when
	 * its content changed. Returns array(changed, error); the error text names
	 * what happened and what holds now. A configuration nginx refuses never
	 * reaches the running server: the old file comes back and nothing is
	 * reloaded.
	 */
	public function ban_apply()
	{
		global $app, $conf;

		$settings = $this->settings();
		$file = rtrim((string) $settings['waf_conf_dir'], '/') . '/blocked.conf';
		$max = (int) $settings['waf_ban_max'];
		$ips = array();
		foreach ($this->rows($app->dbmaster->queryAllRecords(
			"SELECT ip FROM malwatch_waf_ban WHERE server_id = ? AND state = 'active' "
			. "AND source IN ('auto','manual') ORDER BY ip LIMIT ?", $conf['server_id'], $max)) as $row) {
			$ips[] = (string) $row['ip'];
		}
		$want = waf_ban_file($ips, $this->now(), $max);
		$have = is_file($file) ? (string) @file_get_contents($file) : '';
		if ($have === $want) {
			return array(false, '');
		}
		if (@file_put_contents($file, $want) === false) {
			return array(false, 'Die Sperrdatei ' . $file . ' ließ sich nicht schreiben. Bitte Platz und Rechte '
				. 'unter dem Regelverzeichnis prüfen; es gilt weiter der vorherige Stand.');
		}
		@chmod($file, 0644);
		$test = $this->run_command('nginx_test', '');
		if ((int) $test[0] !== 0) {
			if ($have === '') {
				@file_put_contents($file, "# von malwatch erzeugt, leer\n");
			} else {
				@file_put_contents($file, $have);
			}
			return array(false, 'nginx hat die Sperrdatei abgelehnt: '
				. waf_cut(preg_replace('/\s+/', ' ', (string) $test[1]), 200)
				. ' Der vorherige Stand gilt weiter, es wurde nicht neu geladen.');
		}
		$reload = $this->run_command('nginx_reload', '');
		if ((int) $reload[0] !== 0) {
			return array(false, 'nginx ließ sich nicht neu laden: '
				. waf_cut(preg_replace('/\s+/', ' ', (string) $reload[1]), 200)
				. ' Die Sperren stehen in der Datei und wirken nach dem nächsten Reload.');
		}
		@copy($file, $this->ensure_dirs() . '/last-good/blocked.conf');
		return array(true, '');
	}
```

- [x] **Step 8: Ablaufen und Zählen schreiben**

Direkt dahinter:

```php
	/**
	 * Sets the blocks whose end has passed to expired and removes rows that are
	 * older than the keeping time. Returns how many blocks ended.
	 */
	public function ban_expire()
	{
		global $app, $conf;

		$settings = $this->settings();
		$now = $this->now();
		$app->dbmaster->query("UPDATE malwatch_waf_ban SET state = 'expired' WHERE server_id = ? "
			. "AND state = 'active' AND until IS NOT NULL AND until <= ?", $conf['server_id'], $now);
		$ended = (int) $app->dbmaster->affectedRows();
		$keep = gmdate('Y-m-d H:i:s', strtotime($now) - (int) $settings['waf_ban_keep_days'] * 86400);
		$app->dbmaster->query("DELETE FROM malwatch_waf_ban WHERE server_id = ? "
			. "AND state IN ('expired','lifted','dismissed') AND COALESCE(lifted_at, until, created_at) < ?",
			$conf['server_id'], $keep);
		return $ended;
	}

	/**
	 * Counts the requests nginx turned away since the last pass. The log holds
	 * one line per answer 403; only addresses that are blocked are counted, the
	 * rest belongs to the websites themselves.
	 */
	public function ban_count()
	{
		global $app, $conf;

		$file = $this->ban_log;
		if (!is_file($file)) {
			return 0;
		}
		$state = $this->ban_reader_state();
		$inode = (int) @fileinode($file);
		$size = (int) @filesize($file);
		$offset = ($inode !== $state['inode'] || $size < $state['offset']) ? 0 : $state['offset'];
		$handle = @fopen($file, 'rb');
		if ($handle === false) {
			return 0;
		}
		if ($offset > 0) {
			fseek($handle, $offset);
		}
		$seen = array();
		$lines = 0;
		while (($line = fgets($handle)) !== false && $lines < 20000) {
			$lines++;
			$one = waf_ban_log_line($line);
			if ($one === null) {
				continue;
			}
			$seen[$one['ip']] = isset($seen[$one['ip']]) ? $seen[$one['ip']] + 1 : 1;
		}
		$offset = ftell($handle);
		fclose($handle);
		$this->save_ban_reader_state($inode, $offset);
		$now = $this->now();
		foreach ($seen as $ip => $count) {
			$app->dbmaster->query('UPDATE malwatch_waf_ban SET denied = denied + ?, denied_at = ? '
				. "WHERE server_id = ? AND ip = ? AND state = 'active'", (int) $count, $now, $conf['server_id'], $ip);
		}
		return count($seen);
	}

	/** Where the reader of the block log stopped last time. */
	private function ban_reader_state()
	{
		$doc = json_decode((string) @file_get_contents($this->ensure_dirs() . '/blocked-reader.json'), true);
		return array(
			'inode' => is_array($doc) && isset($doc['inode']) ? (int) $doc['inode'] : 0,
			'offset' => is_array($doc) && isset($doc['offset']) ? (int) $doc['offset'] : 0,
		);
	}

	private function save_ban_reader_state($inode, $offset)
	{
		waf_write_atomic($this->ensure_dirs() . '/blocked-reader.json',
			json_encode(array('inode' => (int) $inode, 'offset' => (int) $offset)) . "\n");
	}
```

- [x] **Step 9: An den Cron anschließen**

In `cron_minute()` hinter `$this->origin_external();`:

```php
			$this->ban_scan();
			$this->ban_count();
			$this->ban_apply();
```

In `cron_hourly()` hinter `$this->cleanup();`:

```php
			$this->ban_expire();
```

`ban_apply()` steht bewusst als letztes: Erst entstehen Sperren, dann wird gezählt, dann schreibt ein einziger Lauf die Datei und lädt nginx höchstens einmal je Minute neu. `ban_expire()` im Stundenlauf beendet abgelaufene Sperren; die Datei zieht der nächste Minutenlauf nach.

- [x] **Step 10: Syntax und Prüfreihen**

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php && php -l ispconfig/interface/lib/malwatch_waf_ban.inc.php`
Expected: zweimal `No syntax errors detected`

Run: `php ispconfig/tests/waf_ban_test.php && php ispconfig/tests/waf_lib_test.php && php ispconfig/tests/waf_panel_test.php`
Expected: dreimal `alle Prüfungen bestanden`

- [x] **Step 11: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_ban.inc.php ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests/waf_ban_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): find, block, expire and count in the cron" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D6: Die Knöpfe — Aufträge für Sperren und Ausnahmen

Jeder Klick im Panel wird ein Auftrag, den der Cron ausführt: Automatik umschalten, von Hand sperren, aufheben, verwerfen, Ausnahme anlegen und löschen, Schwelle einer Website setzen. Am Ende jedes Auftrags steht dieselbe Anwendung der Datei wie im Minutentakt.

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_waf.inc.php`
- Modify: `ispconfig/tests/waf_class_probe.php`

**Interfaces:**
- Consumes: `ban_apply()`, `ban_allow_list()`, `waf_ban_allowed()`, `waf_ban_level()`, `waf_ban_until()`, `waf_ban_modes()`, `waf_origin_bytes()`, `waf_origin_cidr()`
- Produces: die Auftragsfälle `ban_mode`, `ban_add`, `ban_lift`, `ban_dismiss`, `ban_allow_add`, `ban_allow_remove`, `ban_site`; alle nehmen ihre Werte aus `options`

- [x] **Step 1: Die Fälle in `start_job()` eintragen**

In `ispconfig/server/lib/classes/malwatch_waf.inc.php` in `start_job()` hinter `case 'origin_update':`:

```php
			case 'ban_mode':
			case 'ban_add':
			case 'ban_lift':
			case 'ban_extend':
			case 'ban_dismiss':
			case 'ban_allow_add':
			case 'ban_allow_remove':
			case 'ban_site':
				return $this->run_block($job, $options);
```

- [x] **Step 2: Die Aufträge schreiben**

Hinter `ban_count()`:

```php
	/**
	 * Every button of the page „Sperren" lands here. Each case says in one
	 * sentence what happened; the file of nginx is written once at the end, so a
	 * click takes effect at once.
	 */
	private function run_block($job, $options)
	{
		global $app, $conf;

		$now = $this->now();
		$user = $this->job_user($job);
		$settings = $this->settings();
		$ip = isset($options['ip']) ? trim((string) $options['ip']) : '';
		$note = '';
		switch ($this->job_action($job)) {
			case 'ban_mode':
				$mode = isset($options['mode']) ? (string) $options['mode'] : '';
				if (!in_array($mode, waf_ban_modes(), true)) {
					return $this->finish($job, false, 'Unbekannter Zustand für die Automatik. Erlaubt sind aus, '
						. 'vorschlagen und sperren.');
				}
				$app->dbmaster->query('UPDATE malwatch_config SET waf_ban_mode = ? WHERE config_id = 1', $mode);
				$note = 'Automatik steht auf ' . $mode . '.';
				break;

			case 'ban_add':
				if (waf_origin_bytes($ip) === '') {
					return $this->finish($job, false, 'Das ist keine Adresse. Bitte eine IPv4- oder IPv6-Adresse '
						. 'angeben, etwa 192.0.2.10.');
				}
				if (waf_ban_allowed($ip, $this->ban_allow_list(), null)) {
					return $this->finish($job, false, 'Diese Adresse steht unter „Nie sperren" oder gehört zum '
						. 'Server selbst. Erst den Eintrag dort entfernen, dann sperren.');
				}
				$row = $app->dbmaster->queryOneRecord(
					'SELECT level FROM malwatch_waf_ban WHERE server_id = ? AND ip = ?', $conf['server_id'], $ip);
				$level = waf_ban_level(is_array($row) ? (int) $row['level'] : 0);
				$permanent = isset($options['permanent']) && (string) $options['permanent'] === 'y';
				$until = $permanent ? null : waf_ban_until($level, $settings, $now);
				$app->dbmaster->query('INSERT INTO malwatch_waf_ban (server_id, ip, state, reason, rule, score, '
					. "hits, level, source, created_at, blocked_at, until, lifted_at, lifted_by, denied, denied_at) "
					. "VALUES (?, ?, 'active', ?, '', 0, 0, ?, 'manual', ?, ?, ?, NULL, '', 0, NULL) "
					. 'ON DUPLICATE KEY UPDATE state = VALUES(state), reason = VALUES(reason), level = VALUES(level), '
					. 'source = VALUES(source), blocked_at = VALUES(blocked_at), until = VALUES(until), '
					. "lifted_at = NULL, lifted_by = '', denied = 0, denied_at = NULL",
					$conf['server_id'], $ip, 'Von Hand gesperrt von ' . $user . '.', $level, $now, $now, $until);
				$note = 'Adresse gesperrt, ' . ($permanent ? 'dauerhaft' : 'bis ' . $until) . '.';
				break;

			case 'ban_lift':
				if ($ip === 'all') {
					$app->dbmaster->query("UPDATE malwatch_waf_ban SET state = 'lifted', lifted_at = ?, "
						. "lifted_by = ? WHERE server_id = ? AND state IN ('active','proposed')",
						$now, $user, $conf['server_id']);
					$note = (int) $app->dbmaster->affectedRows() . ' Sperren und Vorschläge aufgehoben.';
					break;
				}
				$app->dbmaster->query("UPDATE malwatch_waf_ban SET state = 'lifted', lifted_at = ?, lifted_by = ? "
					. "WHERE server_id = ? AND ip = ? AND state IN ('active','proposed')",
					$now, $user, $conf['server_id'], $ip);
				if ((int) $app->dbmaster->affectedRows() === 0) {
					return $this->finish($job, false, 'Für diese Adresse gab es keine laufende Sperre. '
						. 'Vielleicht ist sie schon abgelaufen.');
				}
				$note = 'Sperre aufgehoben.';
				break;

			case 'ban_extend':
				$row = $app->dbmaster->queryOneRecord("SELECT level FROM malwatch_waf_ban WHERE server_id = ? "
					. "AND ip = ? AND state = 'active'", $conf['server_id'], $ip);
				if (!is_array($row)) {
					return $this->finish($job, false, 'Für diese Adresse läuft keine Sperre, die sich verlängern ließe.');
				}
				$level = waf_ban_level((int) $row['level']);
				$until = waf_ban_until($level, $settings, $now);
				$app->dbmaster->query('UPDATE malwatch_waf_ban SET level = ?, until = ? WHERE server_id = ? AND ip = ?',
					$level, $until, $conf['server_id'], $ip);
				$note = 'Sperre verlängert bis ' . $until . '.';
				break;

			case 'ban_dismiss':
				$app->dbmaster->query("UPDATE malwatch_waf_ban SET state = 'dismissed', created_at = ? "
					. "WHERE server_id = ? AND ip = ? AND state = 'proposed'", $now, $conf['server_id'], $ip);
				if ((int) $app->dbmaster->affectedRows() === 0) {
					return $this->finish($job, false, 'Für diese Adresse gab es keinen offenen Vorschlag.');
				}
				$note = 'Vorschlag verworfen; im laufenden Zeitfenster kommt er nicht wieder.';
				break;

			case 'ban_allow_add':
				$cidr = isset($options['cidr']) ? trim((string) $options['cidr']) : '';
				if (waf_origin_cidr($cidr) === null) {
					return $this->finish($job, false, 'Das ist keine Adresse und kein Bereich. Erlaubt sind '
						. 'Angaben wie 203.0.113.7 oder 203.0.113.0/24.');
				}
				$app->dbmaster->query('INSERT INTO malwatch_waf_allow (server_id, cidr, note, created_at, created_by) '
					. 'VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE note = VALUES(note)',
					$conf['server_id'], $cidr, waf_cut(isset($options['note']) ? (string) $options['note'] : '', 255),
					$now, $user);
				// A block that the new exception covers ends at once.
				$lifted = 0;
				foreach ($this->rows($app->dbmaster->queryAllRecords(
					"SELECT ip FROM malwatch_waf_ban WHERE server_id = ? AND state IN ('active','proposed')",
					$conf['server_id'])) as $row) {
					if (!waf_ban_allow_match(array($cidr), (string) $row['ip'])) {
						continue;
					}
					$app->dbmaster->query("UPDATE malwatch_waf_ban SET state = 'lifted', lifted_at = ?, "
						. 'lifted_by = ? WHERE server_id = ? AND ip = ?', $now, $user, $conf['server_id'], $row['ip']);
					$lifted++;
				}
				$note = 'Ausnahme eingetragen' . ($lifted > 0 ? ', ' . $lifted . ' Sperre(n) dazu aufgehoben' : '') . '.';
				break;

			case 'ban_allow_remove':
				$app->dbmaster->query('DELETE FROM malwatch_waf_allow WHERE server_id = ? AND allow_id = ?',
					$conf['server_id'], (int) (isset($options['allow_id']) ? $options['allow_id'] : 0));
				if ((int) $app->dbmaster->affectedRows() === 0) {
					return $this->finish($job, false, 'Diesen Eintrag gibt es nicht mehr.');
				}
				$note = 'Ausnahme gelöscht.';
				break;

			case 'ban_site':
				$domain_id = (int) (isset($options['domain_id']) ? $options['domain_id'] : 0);
				$score = (int) (isset($options['score']) ? $options['score'] : 0);
				$trigger = isset($options['trigger']) && (string) $options['trigger'] === 'n' ? 'n' : 'y';
				if ($score !== 0 && ($score < 5 || $score > 10000)) {
					return $this->finish($job, false, 'Eigene Schwelle: Erlaubt sind 0 (wie der Server) oder ganze '
						. 'Zahlen von 5 bis 10000.');
				}
				$app->dbmaster->query('UPDATE malwatch_site SET waf_ban_score = ?, waf_ban_trigger = ? '
					. 'WHERE server_id = ? AND parent_domain_id = ?', $score, $trigger, $conf['server_id'], $domain_id);
				if ((int) $app->dbmaster->affectedRows() === 0) {
					return $this->finish($job, false, 'Diese Website kennt malwatch nicht.');
				}
				$note = $trigger === 'n' ? 'Diese Website löst keine Sperre mehr aus.'
					: ($score === 0 ? 'Diese Website nimmt wieder die Schwelle des Servers.'
						: 'Eigene Schwelle: ' . $score . ' Punkte.');
				break;
		}
		$applied = $this->ban_apply();
		if ($applied[1] !== '') {
			return $this->finish($job, false, $note . ' ' . $applied[1]);
		}
		return $this->finish($job, true, $note);
	}
```

- [x] **Step 3: Die Probe schreiben**

In `ispconfig/tests/waf_class_probe.php` hinter dem Abschnitt „C5: proxycheck.io" anfügen:

```php
// --- D: Sperren ---------------------------------------------------------------

$waf->ban_log = $tmp . '/blocked.log';
$db->query('DELETE FROM malwatch_waf_ban');
$db->query('DELETE FROM malwatch_waf_allow');
$db->query("UPDATE malwatch_config SET waf_ban_mode = 'block', waf_ban_score = 50, "
	. 'waf_ban_window_minutes = 10, waf_ban_max = 3 WHERE config_id = 1');
$db->query("UPDATE malwatch_site SET waf_ban_score = 0, waf_ban_trigger = 'y'");
$db->query("DELETE FROM malwatch_waf_hit");
// Zwei Angreifer und ein Besucher mit einem einzelnen Fehlalarm.
foreach (array(array('192.0.2.50', 12, 5, '["930130"]'), array('198.51.100.50', 2, 5, '["941100"]'),
	array('10.50.0.1', 20, 5, '["930130"]')) as $one) {
	for ($i = 0; $i < $one[1]; $i++) {
		$db->query("INSERT INTO malwatch_waf_hit (server_id, parent_domain_id, domain, unique_id, seen_at, client_ip, "
			. "method, uri, path, status, anomaly_score, would_block, logged_in, rules, request_headers) "
			. "VALUES (?, 11, 'beispiel.test', ?, NOW(), ?, 'GET', '/x', '/x', 404, ?, 'y', 'n', ?, '{}')",
			$server, 'probe-block-' . $one[0] . '-' . $i, $one[0], $one[2], $one[3]);
	}
}
$calls = array();
expect_same('one address crosses the threshold', $waf->ban_scan(), 1);
$block = $db->queryOneRecord("SELECT * FROM malwatch_waf_ban WHERE ip = '192.0.2.50'");
expect_same('the block is active at level one',
	array($block['state'], (int) $block['level'], $block['source'], (int) $block['score'], (int) $block['hits']),
	array('active', 1, 'auto', 60, 12));
expect_same('the reason names points, hits, window, website and rule',
	strpos($block['reason'], '60 Punkte aus 12 Treffern in 10 Minuten auf beispiel.test, meist Regel 930130') === 0, true);
expect_same('the visitor with one false alarm stays free',
	count_rows("SELECT ip FROM malwatch_waf_ban WHERE ip = '198.51.100.50'"), 0);
expect_same('the proxy is never blocked', count_rows("SELECT ip FROM malwatch_waf_ban WHERE ip = '10.50.0.1'"), 0);
expect_same('a second pass adds nothing', $waf->ban_scan(), 0);

// Die Datei für nginx entsteht und nginx wird geprüft und neu geladen.
$applied = $waf->ban_apply();
expect_same('the file was written', $applied, array(true, ''));
expect_same('nginx was tested and reloaded', $calls, array('nginx_test', 'nginx_reload'));
$written = (string) file_get_contents($tmp . '/waf/blocked.conf');
expect_same('the address stands in the file', strpos($written, 'deny 192.0.2.50;') !== false, true);
expect_same('a second run changes nothing', $waf->ban_apply(), array(false, ''));

// Eine Konfiguration, die nginx ablehnt, erreicht den laufenden Server nicht.
$db->query("INSERT INTO malwatch_waf_ban (server_id, ip, state, reason, source, created_at, blocked_at, until) "
	. "VALUES (?, '198.51.100.60', 'active', 'von Hand', 'manual', NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR))",
	$server);
$answers = array('nginx_test' => array(array(1, 'nginx: [emerg] invalid parameter')));
$calls = array();
$applied = $waf->ban_apply();
expect_same('a refused file is taken back', array($applied[0], strpos($applied[1], 'abgelehnt') !== false),
	array(false, true));
expect_same('nothing was reloaded', $calls, array('nginx_test'));
expect_same('the old file is back',
	strpos((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny 198.51.100.60;'), false);
$answers = array();
$waf->ban_apply();

// Das Zählen der abgewehrten Versuche.
file_put_contents($tmp . '/blocked.log',
	"2026-09-18T10:00:01+02:00 192.0.2.50 403 beispiel.test \"GET /wp-login.php HTTP/1.1\"\n"
	. "2026-09-18T10:00:02+02:00 192.0.2.50 403 beispiel.test \"GET /.env HTTP/1.1\"\n"
	. "2026-09-18T10:00:03+02:00 198.51.100.50 200 beispiel.test \"GET / HTTP/1.1\"\n");
expect_same('one blocked address was counted', $waf->ban_count(), 1);
expect_same('two attempts were turned away',
	(int) $db->queryOneRecord("SELECT denied FROM malwatch_waf_ban WHERE ip = '192.0.2.50'")['denied'], 2);
expect_same('a second pass counts nothing twice', $waf->ban_count(), 0);

// Ablaufen, Aufheben und die Ausnahme, die eine Sperre beendet.
$db->query("UPDATE malwatch_waf_ban SET until = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE ip = '198.51.100.60'");
expect_same('one block ended', $waf->ban_expire(), 1);
expect_same('it left the file',
	strpos((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny 198.51.100.60;'), false);

$waf->queue('ban_add', array('ip' => '203.0.113.7', 'permanent' => 'y'), 'probe');
$waf->pass();
$manual = $db->queryOneRecord("SELECT * FROM malwatch_waf_ban WHERE ip = '203.0.113.7'");
expect_same('a manual block is permanent', array($manual['state'], $manual['source'], $manual['until']),
	array('active', 'manual', null));

$waf->queue('ban_allow_add', array('cidr' => '203.0.113.0/24', 'note' => 'Büro'), 'probe');
$waf->pass();
expect_same('the exception ended the block',
	$db->queryOneRecord("SELECT state FROM malwatch_waf_ban WHERE ip = '203.0.113.7'")['state'], 'lifted');
$waf->queue('ban_add', array('ip' => '203.0.113.9'), 'probe');
$waf->pass();
expect_same('an address of the exception is refused',
	count_rows("SELECT ip FROM malwatch_waf_ban WHERE ip = '203.0.113.9'"), 0);

$waf->queue('ban_site', array('domain_id' => 11, 'score' => 0, 'trigger' => 'n'), 'probe');
$waf->pass();
expect_same('the website triggers nothing any more',
	$db->queryOneRecord('SELECT waf_ban_trigger FROM malwatch_site WHERE parent_domain_id = 11')['waf_ban_trigger'], 'n');
$db->query("UPDATE malwatch_waf_ban SET state = 'expired' WHERE ip = '192.0.2.50'");
expect_same('and so nothing is found any more', $waf->ban_scan(), 0);

$waf->queue('ban_lift', array('ip' => 'all'), 'probe');
$waf->pass();
expect_same('nothing is blocked any more',
	count_rows("SELECT ip FROM malwatch_waf_ban WHERE state = 'active'"), 0);
expect_same('and the file is empty',
	substr_count((string) file_get_contents($tmp . '/waf/blocked.conf'), 'deny '), 0);
```

- [x] **Step 4: Syntax prüfen**

Run: `php -l ispconfig/server/lib/classes/malwatch_waf.inc.php && php -l ispconfig/tests/waf_class_probe.php`
Expected: zweimal `No syntax errors detected`. Der Lauf der Probe braucht root und eine Wegwerf-Datenbank und kommt in Task D10, Block 1.

- [x] **Step 5: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_waf.inc.php ispconfig/tests/waf_class_probe.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): jobs for blocks, exceptions and the threshold of a website" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D7: Die Seite „Sperren"

Eine Seite, die zeigt, wer draußen ist und warum — und an der jeder Knopf einen Auftrag anlegt. Dazu der Knopf „sperren" an den Adressen der Website-Seite und die Schwelle je Website.

**Files:**
- Create: `ispconfig/interface/malwatch_waf_ban_list.php`
- Create: `ispconfig/interface/templates/malwatch_waf_ban_list.htm`
- Modify: `ispconfig/interface/lib/malwatch_waf_panel.inc.php`
- Modify: `ispconfig/interface/module.conf.php`
- Modify: `ispconfig/interface/malwatch_waf_show.php`, `ispconfig/interface/templates/malwatch_waf_show.htm`
- Modify: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng`
- Modify: `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`
- Test: `ispconfig/tests/waf_panel_test.php`

**Interfaces:**
- Consumes: `waf_panel_origin($wb, $row, $language)` für Land, Provider und Chips; `waf_panel_time_label($time)`; `waf_panel_queue($app, $server_id, $action, $fields)`; `waf_panel_rows()`; die Auftragsfälle aus D6
- Produces:
  - `waf_panel_ban_until($wb, $row, $now)` → `'dauerhaft'`, `'noch 47 Minuten'`, `'abgelaufen'` oder `''`
  - `waf_panel_ban_rows($wb, $rows, $origins, $now, $language)` → Zeilen für die Vorlage mit `ip`, `state`, `state_label`, `reason`, `rule_label`, `since`, `until_label`, `denied`, `source_label`, `origin`
  - `waf_panel_ban_post($app, $wb, $post)` → `array(Meldung, Fehler)`; legt den passenden Auftrag an

- [x] **Step 1: Die scheiternden Prüfungen schreiben**

In `ispconfig/tests/waf_panel_test.php` vor dem Abschnitt „summary" anfügen:

```php
// --- Die Seite „Sperren" ------------------------------------------------------

expect_same('a permanent block', waf_panel_ban_until($wb, array('state' => 'active', 'until' => null),
	'2026-09-18 10:00:00'), 'dauerhaft');
expect_same('a block that runs', waf_panel_ban_until($wb, array('state' => 'active', 'until' => '2026-09-18 10:47:00'),
	'2026-09-18 10:00:00'), 'noch 47 Minuten');
expect_same('a block that runs for hours', waf_panel_ban_until($wb,
	array('state' => 'active', 'until' => '2026-09-19 10:00:00'), '2026-09-18 10:00:00'), 'noch 24 Stunden');
expect_same('an expired block', waf_panel_ban_until($wb, array('state' => 'expired', 'until' => '2026-09-18 09:00:00'),
	'2026-09-18 10:00:00'), 'abgelaufen');
expect_same('a proposal has no end', waf_panel_ban_until($wb, array('state' => 'proposed', 'until' => null),
	'2026-09-18 10:00:00'), '');

$ban_rows = array(
	array('ip' => '192.0.2.50', 'state' => 'active', 'reason' => '60 Punkte aus 12 Treffern in 10 Minuten auf beispiel.test, meist Regel 930130.',
		'rule' => '930130', 'score' => '60', 'hits' => '12', 'level' => '1', 'source' => 'auto',
		'created_at' => '2026-09-18 09:50:00', 'blocked_at' => '2026-09-18 09:50:00', 'until' => '2026-09-18 10:50:00',
		'lifted_at' => null, 'lifted_by' => '', 'denied' => '318', 'denied_at' => '2026-09-18 09:59:00'),
	array('ip' => '198.51.100.50', 'state' => 'proposed', 'reason' => '55 Punkte aus 11 Treffern in 10 Minuten auf zweite.test.',
		'rule' => '', 'score' => '55', 'hits' => '11', 'level' => '1', 'source' => 'auto',
		'created_at' => '2026-09-18 09:55:00', 'blocked_at' => null, 'until' => null,
		'lifted_at' => null, 'lifted_by' => '', 'denied' => '0', 'denied_at' => null),
);
$origins = array('192.0.2.50' => array('country' => 'de', 'asn' => '3320', 'as_org' => 'Deutsche Telekom AG',
	'is_tor' => 'n', 'is_vpn' => 'n', 'is_hosting' => 'y', 'is_proxy' => 'n', 'vpn_operator' => '',
	'external_state' => 'none'));
$view = waf_panel_ban_rows($wb, $ban_rows, $origins, '2026-09-18 10:00:00', 'de');
expect_same('a row per block', array_column($view, 'ip'), array('192.0.2.50', '198.51.100.50'));
expect_same('the state in words', array($view[0]['state_label'], $view[1]['state_label']),
	array('gesperrt', 'Vorschlag'));
expect_same('the end in words', $view[0]['until_label'], 'noch 50 Minuten');
expect_same('the turned away requests', $view[0]['denied'], '318');
expect_same('the origin travels with the address',
	array($view[0]['origin']['country'], $view[0]['origin']['provider']), array('DE', 'AS3320 Deutsche Telekom AG'));
expect_same('a rule in words', $view[0]['rule_label'], 'Zugriff auf geschützte Datei');
expect_same('an address without origin stays empty', $view[1]['origin']['known'], false);
```

Der Text zur Regel kommt aus dem Katalog, den `waf_panel_rule_label()` seit 0.20.0 liefert; steht die Regel nicht im Katalog, bleibt `rule_label` leer.

- [x] **Step 2: Prüflauf, der scheitern muss**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `PHP Fatal error: Uncaught Error: Call to undefined function waf_panel_ban_until()`

- [x] **Step 3: Die Anzeige schreiben**

In `ispconfig/interface/lib/malwatch_waf_panel.inc.php` ans Ende:

```php
/**
 * When a block ends, in words: permanently, in so many minutes or hours, or
 * already over. A proposal has no end yet.
 */
function waf_panel_ban_until($wb, $row, $now)
{
	$state = isset($row['state']) ? (string) $row['state'] : '';
	if ($state === 'proposed' || $state === 'dismissed') {
		return '';
	}
	if ($state !== 'active') {
		return waf_panel_text($wb, 'ban_until_over_txt', '');
	}
	$until = isset($row['until']) ? (string) $row['until'] : '';
	if ($until === '' || $until === '0000-00-00 00:00:00') {
		return waf_panel_text($wb, 'ban_until_forever_txt', '');
	}
	$left = strtotime($until) - strtotime((string) $now);
	if ($left <= 0) {
		return waf_panel_text($wb, 'ban_until_over_txt', '');
	}
	if ($left < 3600) {
		return sprintf(waf_panel_text($wb, 'ban_until_minutes_txt', '%s'), (int) ceil($left / 60));
	}
	if ($left < 172800) {
		return sprintf(waf_panel_text($wb, 'ban_until_hours_txt', '%s'), (int) round($left / 3600));
	}
	return sprintf(waf_panel_text($wb, 'ban_until_days_txt', '%s'), (int) round($left / 86400));
}

/**
 * The rows of the page „Sperren": state, reason, end, turned away requests and
 * the origin of the address, ready for the template.
 */
function waf_panel_ban_rows($wb, $rows, $origins, $now, $language = 'de')
{
	$states = array('active' => 'ban_state_active_txt', 'proposed' => 'ban_state_proposed_txt',
		'expired' => 'ban_state_expired_txt', 'lifted' => 'ban_state_lifted_txt',
		'dismissed' => 'ban_state_dismissed_txt');
	$sources = array('auto' => 'ban_source_auto_txt', 'manual' => 'ban_source_manual_txt',
		'fail2ban' => 'ban_source_fail2ban_txt');
	$view = array();
	foreach ($rows as $row) {
		$ip = isset($row['ip']) ? (string) $row['ip'] : '';
		$state = isset($row['state']) ? (string) $row['state'] : '';
		$source = isset($row['source']) ? (string) $row['source'] : 'auto';
		$rule = isset($row['rule']) ? (string) $row['rule'] : '';
		$view[] = array(
			'ip' => $ip,
			'state' => $state,
			'state_label' => waf_panel_text($wb, isset($states[$state]) ? $states[$state] : '', $state),
			'reason' => isset($row['reason']) ? (string) $row['reason'] : '',
			'rule' => $rule,
			'rule_label' => $rule === '' ? '' : waf_panel_rule_label($wb, $rule),
			'since' => waf_panel_time_label(isset($row['blocked_at']) && $row['blocked_at'] !== null
				? $row['blocked_at'] : (isset($row['created_at']) ? $row['created_at'] : '')),
			'until_label' => waf_panel_ban_until($wb, $row, $now),
			'denied' => isset($row['denied']) ? (string) $row['denied'] : '0',
			'source_label' => waf_panel_text($wb, isset($sources[$source]) ? $sources[$source] : '', $source),
			'origin' => waf_panel_origin($wb, isset($origins[$ip]) ? $origins[$ip] : null, $language),
		);
	}
	return $view;
}

/**
 * The buttons of the page „Sperren". Returns array(message, error); a click
 * becomes a job, the cron carries it out within the minute.
 */
function waf_panel_ban_post($app, $wb, $post)
{
	$action = isset($post['waf_ban_action']) ? (string) $post['waf_ban_action'] : '';
	if ($action === '') {
		return array('', '');
	}
	$ip = isset($post['waf_ban_ip']) ? trim((string) $post['waf_ban_ip']) : '';
	$servers = waf_panel_web_servers($app);
	if (count($servers) === 0) {
		return array('', waf_panel_text($wb, 'msg_saved_no_server_txt', ''));
	}
	$fields = array();
	switch ($action) {
		case 'mode':
			$mode = isset($post['waf_ban_mode']) ? (string) $post['waf_ban_mode'] : '';
			if (!in_array($mode, waf_ban_modes(), true)) {
				return array('', waf_panel_text($wb, 'ban_err_mode_txt', ''));
			}
			$fields = array('mode' => $mode);
			$action = 'ban_mode';
			break;
		case 'add':
			if ($ip === '') {
				return array('', waf_panel_text($wb, 'ban_err_ip_txt', ''));
			}
			$fields = array('ip' => $ip, 'permanent' => isset($post['waf_ban_permanent']) ? 'y' : 'n');
			$action = 'ban_add';
			break;
		case 'lift':
			$fields = array('ip' => $ip === '' ? 'all' : $ip);
			$action = 'ban_lift';
			break;
		case 'extend':
			$fields = array('ip' => $ip);
			$action = 'ban_extend';
			break;
		case 'dismiss':
			$fields = array('ip' => $ip);
			$action = 'ban_dismiss';
			break;
		case 'allow_add':
			$fields = array('cidr' => isset($post['waf_allow_cidr']) ? trim((string) $post['waf_allow_cidr']) : '',
				'note' => isset($post['waf_allow_note']) ? (string) $post['waf_allow_note'] : '');
			if ($fields['cidr'] === '') {
				return array('', waf_panel_text($wb, 'ban_err_cidr_txt', ''));
			}
			$action = 'ban_allow_add';
			break;
		case 'allow_remove':
			$fields = array('allow_id' => (int) (isset($post['waf_allow_id']) ? $post['waf_allow_id'] : 0));
			$action = 'ban_allow_remove';
			break;
		case 'site':
			$fields = array('domain_id' => (int) (isset($post['waf_ban_domain']) ? $post['waf_ban_domain'] : 0),
				'score' => (int) (isset($post['waf_ban_site_score']) ? $post['waf_ban_site_score'] : 0),
				'trigger' => isset($post['waf_ban_site_trigger']) && (string) $post['waf_ban_site_trigger'] === 'n'
					? 'n' : 'y');
			$action = 'ban_site';
			break;
		default:
			return array('', waf_panel_text($wb, 'ban_err_action_txt', ''));
	}
	foreach ($servers as $server_id) {
		waf_panel_queue($app, $server_id, $action, $fields);
	}
	return array(waf_panel_text($wb, 'ban_msg_queued_txt', ''), '');
}
```

- [x] **Step 4: Prüflauf, der bestehen muss**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [x] **Step 5: Die Seite schreiben**

`ispconfig/interface/malwatch_waf_ban_list.php` — gebaut wie `malwatch_waf_exception_list.php`: Rechte prüfen, Wörterbuch laden, POST über `waf_panel_ban_post()`, danach die drei Listen holen und der Vorlage übergeben:

```php
<?php
/**
 * Security > Abwehr > Sperren: who is blocked, who is proposed and what is
 * never blocked. Every button becomes a job; the cron carries it out.
 */
require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';
$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	$app->error($app->lng('error_no_permission'));
}
$app->uses('tpl');
require_once 'lib/malwatch_waf_lib.inc.php';
require_once 'lib/malwatch_waf_panel.inc.php';
require_once 'lib/malwatch_waf_ban.inc.php';

$wb = waf_panel_wordbook($app, 'malwatch_waf');
$clock = waf_panel_clock($app);
$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (!isset($_POST['waf_token']) || !waf_panel_token_check($app, (string) $_POST['waf_token'])) {
		$error = $wb['err_token_txt'];
	} else {
		list($message, $error) = waf_panel_ban_post($app, $wb, $_POST);
	}
}
$settings = waf_settings($app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
$rows = waf_panel_rows($app->db->queryAllRecords(
	"SELECT * FROM malwatch_waf_ban ORDER BY FIELD(state, 'active','proposed','expired','lifted','dismissed'), "
	. 'until IS NULL DESC, until, ip'));
$origins = waf_panel_origin_lookup($app, array_column($rows, 'ip'));
$view = waf_panel_ban_rows($wb, $rows, $origins, $clock['now'], $app->functions->get_language());
$active = array();
$proposed = array();
$past = array();
foreach ($view as $row) {
	if ($row['state'] === 'active') {
		$active[] = $row;
	} elseif ($row['state'] === 'proposed') {
		$proposed[] = $row;
	} else {
		$past[] = $row;
	}
}
$allow = waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_allow ORDER BY cidr'));
```

Danach setzt die Seite die Schleifen `ban_active`, `ban_proposed`, `ban_past`, `ban_allow`, dazu die Zähler, den Zustand der Automatik (`waf_ban_mode`), die Meldung, den Fehler und den Token — genau wie es `malwatch_waf_exception_list.php` für seine Listen tut. Die Namen der Helfer (`waf_panel_wordbook()`, `waf_panel_clock()`, `waf_panel_token_check()`, `waf_panel_rows()`) werden aus dieser Datei übernommen, damit beide Seiten gleich aufgebaut sind.

- [x] **Step 6: Die Vorlage schreiben**

`ispconfig/interface/templates/malwatch_waf_ban_list.htm` mit vier Abschnitten, im Stil von `malwatch_waf_exception_list.htm`:

1. Kopf: Überschrift, Zustand der Automatik als drei Knöpfe (`waf_ban_action=mode` mit `waf_ban_mode=off|propose|block`), Zahl der aktiven Sperren, Knopf „Alle Sperren aufheben" mit `data-mw-confirm`.
2. `<tmpl_loop name="ban_active">`: Adresse, Herkunft (Land mit `title`, Provider, Chips), Grund, Regel in Worten, seit, `until_label`, `denied`, Knöpfe „aufheben", „dauerhaft" (`waf_ban_action=add` mit `waf_ban_permanent`), „nie sperren" (`waf_ban_action=allow_add` mit der Adresse als `waf_allow_cidr`).
3. `<tmpl_loop name="ban_proposed">`: dieselbe Zeile mit „jetzt sperren" (`add`) und „verwerfen" (`dismiss`); dazu `<tmpl_if name="has_proposed">`, sonst ein Satz „Zurzeit gibt es keine Vorschläge."
4. `<tmpl_loop name="ban_allow">`: Bereich, Notiz, wer, wann, Knopf „löschen" (`allow_remove`), darunter ein kleines Formular zum Anlegen (`waf_allow_cidr`, `waf_allow_note`).

**Wichtig:** Jede Schleife bekommt ein Flag (`has_active`, `has_proposed`, `has_past`, `has_allow`), weil vlibTemplate eine leere Schleife sonst einmal leer durchläuft.

- [x] **Step 7: Das Menü und die Kopien**

In `ispconfig/interface/module.conf.php` in der Gruppe „Abwehr" hinter dem Eintrag „Ausnahmen":

```php
	array(
		'title'   => 'Sperren',
		'target'  => 'content',
		'link'    => 'security/malwatch_waf_ban_list.php',
		'html_id' => 'malwatch_waf_ban'
	),
```

In `ispconfig/install/file.list` die Seite und die Vorlage aufnehmen, in derselben Form wie `malwatch_waf_exception_list.php` und seine Vorlage.

In `ispconfig/tests/render_pages.php` in die Seitenliste aufnehmen:

```php
	'malwatch_waf_ban_list.php',
```

- [x] **Step 8: Website-Seite: Knopf und Schwelle**

In `ispconfig/interface/malwatch_waf_show.php` bekommt jede Adresse in den Karten und Einzeltreffern zusätzlich das Feld `ban_link` — eine Form-Schaltfläche, die `waf_ban_action=add` mit der Adresse an `malwatch_waf_ban_list.php` schickt. Im Kasten „Zustand" kommt ein kleines Formular dazu: Auswahl „wie der Server (%s Punkte)", „eigene Schwelle" mit Zahlenfeld und „diese Website löst nie eine Sperre aus", das `waf_ban_action=site` mit `waf_ban_domain`, `waf_ban_site_score` und `waf_ban_site_trigger` sendet. Die Seite liest dafür `waf_ban_score` und `waf_ban_trigger` aus `malwatch_site` mit.

- [x] **Step 9: Die Texte**

In `ispconfig/interface/lang/de_malwatch_waf.lng` ans Ende, dazu die englische Fassung in `en_malwatch_waf.lng`:

```php
$wb['ban_head_txt'] = 'Sperren';
$wb['ban_intro_txt'] = 'Gesperrte Adressen bekommen auf allen Websites dieses Servers die Antwort 403.';
$wb['ban_state_active_txt'] = 'gesperrt';
$wb['ban_state_proposed_txt'] = 'Vorschlag';
$wb['ban_state_expired_txt'] = 'abgelaufen';
$wb['ban_state_lifted_txt'] = 'aufgehoben';
$wb['ban_state_dismissed_txt'] = 'verworfen';
$wb['ban_source_auto_txt'] = 'automatisch';
$wb['ban_source_manual_txt'] = 'von Hand';
$wb['ban_source_fail2ban_txt'] = 'fail2ban';
$wb['ban_until_forever_txt'] = 'dauerhaft';
$wb['ban_until_minutes_txt'] = 'noch %s Minuten';
$wb['ban_until_hours_txt'] = 'noch %s Stunden';
$wb['ban_until_days_txt'] = 'noch %s Tage';
$wb['ban_until_over_txt'] = 'abgelaufen';
$wb['ban_denied_txt'] = 'abgewehrt: %s';
$wb['ban_lift_txt'] = 'aufheben';
$wb['ban_lift_all_txt'] = 'Alle Sperren aufheben';
$wb['ban_lift_all_confirm_txt'] = 'Alle laufenden Sperren und Vorschläge aufheben? Die Adressen erreichen die Websites danach sofort wieder.';
$wb['ban_add_txt'] = 'sperren';
$wb['ban_permanent_txt'] = 'dauerhaft';
$wb['ban_extend_txt'] = 'verlängern';
$wb['ban_dismiss_txt'] = 'verwerfen';
$wb['ban_allow_txt'] = 'nie sperren';
$wb['ban_allow_head_txt'] = 'Nie sperren';
$wb['ban_allow_intro_txt'] = 'Diese Adressen und Bereiche werden nie gesperrt. Die eigenen Netze des Servers stehen ohnehin fest darin.';
$wb['ban_allow_add_txt'] = 'Ausnahme eintragen';
$wb['ban_allow_remove_txt'] = 'löschen';
$wb['ban_none_active_txt'] = 'Zurzeit ist keine Adresse gesperrt.';
$wb['ban_none_proposed_txt'] = 'Zurzeit gibt es keine Vorschläge.';
$wb['ban_msg_queued_txt'] = 'Auftrag angelegt. Der Cron führt ihn im nächsten Durchgang aus.';
$wb['ban_err_mode_txt'] = 'Unbekannter Zustand. Bitte aus, vorschlagen oder sperren wählen.';
$wb['ban_err_ip_txt'] = 'Bitte eine Adresse angeben, etwa 192.0.2.10.';
$wb['ban_err_cidr_txt'] = 'Bitte eine Adresse oder einen Bereich angeben, etwa 203.0.113.0/24.';
$wb['ban_err_action_txt'] = 'Diesen Knopf kennt die Seite nicht. Bitte die Seite neu laden.';
$wb['ban_site_head_txt'] = 'Sperren für diese Website';
$wb['ban_site_server_txt'] = 'wie der Server (%s Punkte)';
$wb['ban_site_own_txt'] = 'eigene Schwelle';
$wb['ban_site_never_txt'] = 'diese Website löst nie eine Sperre aus';
```

- [x] **Step 10: Prüfen**

Run: `php ispconfig/tests/waf_panel_test.php && php ispconfig/tests/waf_panel_post_test.php && php ispconfig/tests/waf_ban_test.php`
Expected: dreimal `alle Prüfungen bestanden`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`. Die Kulisse `fake_db.php` bekommt dafür je zwei Zeilen in `malwatch_waf_ban` und `malwatch_waf_allow`.

- [x] **Step 11: Commit**

```bash
git add ispconfig/interface ispconfig/install/file.list ispconfig/tests
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): the page Sperren with blocks, proposals and exceptions" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
### Task D8: Werkzeug, Installation und Verdrahtung

Damit die Sperre auch ohne Panel bedienbar ist und nginx die Datei überhaupt einbindet.

**Files:**
- Modify: `waf/install.sh`
- Create: `waf/conf/waf-blocked.conf`
- Modify: `waf/conf/logrotate-waf`
- Modify: `waf/waf-switch`
- Modify: `ispconfig/tests/check_wiring.sh`

**Interfaces:**
- Consumes: `malwatch_waf::ban_scan()`, `ban_apply()`, `ban_expire()`, `ban_count()`, die Auftragsfälle aus D6
- Produces: `/etc/nginx/conf.d/waf-blocked.conf` (fest), `/etc/nginx/waf/blocked.conf` (von malwatch geschrieben), `/var/log/waf/blocked.log`; `waf-switch block …`

- [x] **Step 1: Die feste nginx-Datei anlegen**

`waf/conf/waf-blocked.conf`:

```nginx
# Managed by malwatch. Bindet die Sperrliste ein, die malwatch schreibt, und
# legt das zweite Zugriffslog an, aus dem der Cron die abgewehrten Versuche
# zählt. Diese Datei selbst wird nicht überschrieben.
include /etc/nginx/waf/blocked.conf;

map $status $mw_denied {
	403     1;
	default 0;
}

log_format mw_block '$time_iso8601 $remote_addr $status $host "$request"';
```

- [x] **Step 2: Den Installierer ergänzen**

In `waf/install.sh` hinter der Stelle, die `/var/log/waf/audit.log` anlegt:

```sh
if [ ! -f /var/log/waf/blocked.log ]; then install -o www-data -g adm -m 640 /dev/null /var/log/waf/blocked.log; fi
chown www-data:adm /var/log/waf/blocked.log
chmod 640 /var/log/waf/blocked.log
if [ ! -f "$WAF/blocked.conf" ]; then
	printf '# von malwatch erzeugt, leer\n' > "$WAF/blocked.conf"
fi
chmod 644 "$WAF/blocked.conf"
install -o root -g root -m 644 conf/waf-blocked.conf /etc/nginx/conf.d/waf-blocked.conf
```

Die Datei schreibt nginx als `www-data`, deshalb gehört das Log ihm; gelesen wird es vom Cron als root.

In `waf/conf/logrotate-waf` das zweite Log aufnehmen — dieselbe Zeile wie für das Audit-Log, mit `/var/log/waf/blocked.log`, und im `create`-Teil `640 www-data adm`.

Nach dem Kopieren prüft `install.sh` wie bisher mit `nginx -t` und lädt erst dann neu; scheitert die Prüfung, kommt die Sicherung zurück.

- [x] **Step 3: Das zweite Zugriffslog in den vhost**

Ohne eine Zeile im vhost schreibt nginx nichts nach `/var/log/waf/blocked.log`. Sie kommt in den verwalteten Abschnitt, den `waf_block_text()` in `ispconfig/interface/lib/malwatch_waf_lib.inc.php` erzeugt — das ist die bestehende Funktion für den vhost-Abschnitt, nicht die neue Bibliothek.

Zuerst die Prüfung in `ispconfig/tests/waf_lib_test.php` bei den Prüfungen zum vhost-Abschnitt:

```php
expect_same('the block log is only written when nginx knows the format',
	strpos(waf_block_text('detect'), 'blocked.log'), false);
expect_same('with the include of malwatch the line is there',
	strpos(waf_block_text('detect', true), 'access_log /var/log/waf/blocked.log mw_block if=$mw_denied;') !== false, true);
expect_same('a website that is off keeps its vhost clean', waf_block_text('off', true), '');
```

Dann die Funktion erweitern:

```php
function waf_block_text($state, $with_ban_log = false)
{
	if ($state === 'off' || !waf_state_valid($state)) {
		return '';
	}
	$lines = array(WAF_MARK_BEGIN . ' (' . $state . ') - managed by waf-switch', 'modsecurity on;');
	if ($with_ban_log) {
		// The second log carries the answers 403 of the deny list; the format and
		// the map stand in /etc/nginx/conf.d/waf-blocked.conf.
		$lines[] = 'access_log /var/log/waf/blocked.log mw_block if=$mw_denied;';
	}
	if ($state === 'enforce') {
		$lines[] = "modsecurity_rules 'SecRuleEngine On';";
	}
	$lines[] = WAF_MARK_END;
	return implode("
", $lines) . "
";
}
```

Die Aufrufer in `malwatch_waf.inc.php` und `waf-switch` übergeben `is_file('/etc/nginx/conf.d/waf-blocked.conf')` als zweiten Wert. Fehlt die Datei — etwa weil `waf/install.sh` noch nicht gelaufen ist —, bleibt die Zeile weg; sonst würde nginx das unbekannte Logformat `mw_block` ablehnen und die Website ohne Konfiguration dastehen.

Run: `php ispconfig/tests/waf_lib_test.php`
Expected: `waf_lib: alle Prüfungen bestanden`

- [x] **Step 4: `waf-switch` ergänzen**

In `waf/waf-switch` den Kopfkommentar um die neuen Aufrufe erweitern und den Unterbefehl einbauen:

```
 *   waf-switch block status
 *   waf-switch block off|propose|on
 *   waf-switch block list
 *   waf-switch block add <ip> [--permanent]
 *   waf-switch block lift <ip|--all>
 *   waf-switch block allow <cidr> [--note=text]
```

Die Umsetzung nutzt dieselben Wege wie die übrigen Unterbefehle: `status` und `list` lesen direkt aus der Datenbank und geben deutsche Zeilen aus, die übrigen legen über `$waf->execute_now(...)` den Auftrag an und führen ihn sofort aus. `block off` ist der Not-Aus: Er setzt den Modus auf `off`, hebt alle laufenden Sperren auf und schreibt die Datei neu — damit kommt man auch dann wieder rein, wenn man sich selbst ausgesperrt hat.

```php
	case 'block':
		$what = isset($argv[2]) ? (string) $argv[2] : 'status';
		if ($what === 'status') {
			$settings = $waf->settings();
			$active = $waf->db_count("SELECT COUNT(*) AS value FROM malwatch_waf_ban WHERE state = 'active'");
			printf("Automatik: %s, gesperrt: %d\n", $settings['waf_ban_mode'], $active);
			exit(0);
		}
		if ($what === 'off') {
			$waf->execute_now('ban_mode', array('mode' => 'off'), $user);
			$waf->execute_now('ban_lift', array('ip' => 'all'), $user);
			echo "Automatik aus, alle Sperren aufgehoben.\n";
			exit(0);
		}
		...
```

Für `db_count` wird die bestehende Hilfe der Klasse genutzt (`db_value`), öffentlich gemacht oder über eine kleine öffentliche Methode `ban_active_count()` angeboten — maßgeblich ist, dass `waf-switch` keine eigene Datenbankverbindung aufmacht.

- [x] **Step 5: Die Verdrahtung prüfen**

In `ispconfig/tests/check_wiring.sh` vor dem abschließenden `if [ "$status" -eq 0 ]; then` einfügen:

```sh
# 73. The deny file of nginx is written by the class alone. A page that wrote it
#     would write it as www-data and without the check of nginx.
if [ -d "$root/interface" ]; then
	if grep -rn "blocked.conf" "$root/interface" --include='*.php' | grep -v 'lib/malwatch_waf_ban.inc.php'; then
		fail "a page writes blocked.conf; that belongs into malwatch_waf.inc.php"
	fi
fi

# 74. Every block passes the exceptions first, and the file is written through
#     the same function in every case.
if [ -f "$waf_class" ]; then
	sed -n '/public function ban_scan(/,/^\t}/p' "$waf_class" | grep -q 'waf_ban_allowed(' \
		|| fail "ban_scan() blocks without asking the exceptions"
	sed -n '/private function run_block(/,/^\t}/p' "$waf_class" | grep -q 'ban_apply(' \
		|| fail "run_block() never writes the file of nginx"
	sed -n '/public function ban_apply(/,/^\t}/p' "$waf_class" | grep -q "run_command('nginx_test'" \
		|| fail "ban_apply() reloads nginx without testing the configuration"
fi

# 75. The emergency stop exists on the command line: whoever locked themselves
#     out of the panel needs a way back.
if [ -f "$root/../waf/waf-switch" ]; then
	grep -q "case 'block'" "$root/../waf/waf-switch" \
		|| fail "waf-switch has no block command; there is no way back without the panel"
fi

# 76. The texts of the page are in both wordbooks.
for lang in de en; do
	book="$root/interface/lang/${lang}_malwatch_waf.lng"
	[ -f "$book" ] || continue
	for key in ban_state_active_txt ban_until_forever_txt ban_lift_all_confirm_txt ban_none_active_txt; do
		grep -q "\\\$wb\['$key'\]" "$book" \
			|| fail "${lang}_malwatch_waf.lng is missing $key"
	done
done
```

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [x] **Step 6: Der Trockenlauf des Installierers**

Run: `sh .superpowers/abwehr/install_probe.sh`
Expected: der Probelauf legt die neue Einbindung an, `nginx -t` (nachgestellt) bestätigt, und ein erzwungener Fehlschlag rollt zurück. Der Probelauf liegt außerhalb des Repositorys und stellt nginx, systemctl und crontab nach.

- [x] **Step 7: Commit**

```bash
git add waf ispconfig/interface/lib/malwatch_waf_lib.inc.php ispconfig/tests
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): nginx include, block log and the block command of waf-switch" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task D9: Release 0.23.0

**Files:**
- Modify: `internal/version/version.go`, `ispconfig/version`, `CHANGELOG.md`, `README.md`, `ispconfig/README.md`
- Modify: `docs/superpowers/specs/2026-09-18-malwatch-sperren-design.md` (Notiz zur Stufe 1)

- [x] **Step 1: Version hochziehen**

`internal/version/version.go` auf `var Version = "0.23.0"`, `ispconfig/version` auf `0.23.0`.

- [x] **Step 2: Changelog**

In `CHANGELOG.md` über den Eintrag `## [0.22.0]`:

```markdown
## [0.23.0] – <Tag der Veröffentlichung>

### Neu

**Sperren.** Wer in kurzer Zeit zu viele Anomalie-Punkte sammelt, wird serverweit
mit 403 abgewiesen. Die neue Seite **Security > Abwehr > Sperren** zeigt, wer
gesperrt ist, warum, seit wann, bis wann und wie viele Versuche seither abgeprallt
sind. Die Automatik beginnt bei „aus"; „vorschlagen" rechnet nur mit, „sperren"
handelt. Von Hand geht jederzeit — auch direkt an jeder Adresse in den Regel-Karten
und Einzeltreffern.

**Schwelle je Website.** Jede Website kann eine eigene Schwelle bekommen oder gar
keine Sperre auslösen; ohne eigenen Wert gilt der Wert des Servers (Vorgabe 50
Punkte in 10 Minuten).

**Staffel und Ausnahmen.** Die erste Sperre dauert eine Stunde, die zweite 24, ab
der dritten sieben Tage — alles einstellbar. Nie gesperrt werden die eigenen Netze,
die Adressen der Ausnahmeliste und die veröffentlichten Adressbereiche von Google
und Bing, die malwatch wie die übrigen Herkunftslisten lädt.

**Rückweg.** `waf-switch block off` hebt alle Sperren auf und schaltet die Automatik
aus, auch ohne Panel. Lehnt nginx die erzeugte Datei ab, kommt der vorherige Stand
zurück und es wird nicht neu geladen.
```

- [x] **Step 3: READMEs**

In `README.md` und `ispconfig/README.md` den Abschnitt zur Abwehr um einen Absatz über die Sperren ergänzen: wie erkannt wird, wo die Datei liegt (`/etc/nginx/waf/blocked.conf`), dass nginx nur geprüft und neu geladen wird, wie der Zähler entsteht und wie man ohne Panel wieder aufmacht.

- [x] **Step 4: Die Spec bekommt ihre Notiz**

In `docs/superpowers/specs/2026-09-18-malwatch-sperren-design.md` in der Tabelle der Stufen hinter „1 | 0.23.0 …" den Vermerk „umgesetzt, Plan `docs/superpowers/plans/2026-09-18-malwatch-sperren-stufe-1.md`" ergänzen.

- [x] **Step 5: Die ganze Prüfstrecke**

Run: `gofmt -l . && go vet ./... && go build ./... && echo "Go: ok"`
Expected: `Go: ok`

Run: `find ispconfig -name '*.php' -o -name '*.lng' | xargs -n1 php -l | grep -v '^No syntax errors' ; echo "Syntax geprüft"`
Expected: nur `Syntax geprüft`

Run: `for t in waf_lib waf_panel waf_panel_post waf_rules_catalog waf_origin waf_origin_sources waf_proxycheck waf_ban; do php ispconfig/tests/$t"_test.php" || break; done`
Expected: achtmal `alle Prüfungen bestanden`

Run (im Hintergrund): `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `bash .superpowers/abwehr/harness/build_all.sh .`
Expected: `Seiten gerendert; …` ohne `FEHLER`

- [x] **Step 6: Commit**

```bash
git add internal/version/version.go ispconfig/version CHANGELOG.md README.md ispconfig/README.md docs/superpowers/specs/2026-09-18-malwatch-sperren-design.md
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "release: 0.23.0, blocking attacker addresses" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---
**Notizen aus der Umsetzung (18.09.2026):**

- Die neuen Bezeichner heißen `ban`, weil `waf_block_text()`, `waf_block_set()` und `waf_block_remove()` in `malwatch_waf_lib.inc.php` schon den verwalteten Abschnitt eines vhosts bauen (31 Aufrufstellen). Tabellen, Einstellungen, Funktionen und Aufträge tragen deshalb `ban`; die Oberfläche bleibt bei „Sperren“.
- Die Beispieldateien der Suchmaschinen hatten zwei aneinandergrenzende IPv6-Bereiche; der Leser fasst so etwas richtigerweise zusammen. Der Bereich von Bing steht jetzt auf `2001:db8:5::/48`, damit die Prüfung fünf Bereiche sieht.
- `waf_origin_sources_test.php` prüft die Liste der Quellen als Ganzes und brauchte den Eintrag `searchbots`.
- `waf_logrotate_text()` erzeugt die ausgelieferte logrotate-Datei; das zweite Log kam dort hinein, sonst wäre die mitgelieferte Datei aus dem Tritt geraten.
- Die Zeile fürs zweite Zugriffslog steht nur im vhost, wenn `/etc/nginx/conf.d/waf-blocked.conf` existiert: `waf_block_set($text, $state, $with_ban_log)` reicht das durch, die Serverklasse setzt `$settings['waf_ban_log']` aus der Dateiprüfung. Ohne das würde nginx das unbekannte Format `mw_block` ablehnen.
- Prüfung 73 musste geschärft werden: Ein Kommentar mit `blocked.conf` in einer Bibliothek ist kein Schreiben; sie sucht jetzt nach Seiten, die `blocked.conf` **und** `file_put_contents` enthalten.
- Die neue Seite band anfangs `malwatch_modal.htm` nicht ein — Prüfung 47 hat es gefangen.
- Commits auf `waf-herkules`: `9f2495c` (D1), `602885f` (D2), `6761c7d` (D3), `e41445e` (D4), `9409e2d` (D5), `19e7e7b` (D6), `af880a9` und `750e9a0` (D7), `5353d96` (D8), `aca5c10` (D9).

### Task D10: Einführung auf web.herkules

malwatch 0.23.0 kommt in fünf Blöcken auf den Server, jeder mit eigener Freigabe von Mathias und mit Eintrag im Serverprotokoll:

1. Staging-Kopie, Schema, Klassenprobe, Seiten
2. Veröffentlichen: `main`, CI, Marke `v0.23.0`, Release
3. Einspielen — die Automatik bleibt dabei auf „aus"
4. Auf „vorschlagen" schalten und ein paar Tage beobachten
5. Auf „sperren" schalten, erste echte Sperre ansehen

**Files:**
- Serverprotokoll: `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`
- Hilfen am Rechner (nicht im Repo): `.superpowers/abwehr/measure.sh`

#### Messen

Vor dem ersten und nach jedem ändernden Schritt:

```bash
ssh ispconfig 'bash -s' < .superpowers/abwehr/measure.sh
for site in bright-color.de "$ZWEITE" "$DRITTE"; do curl -s -o /dev/null -w "%{http_code} %{time_total}s $site\n" "https://$site/"; done
```

**Abbruch**, sobald eines davon eintritt: `nginx -t` scheitert, nginx ist nicht aktiv, weniger als 2 GB verfügbar, Load (5 Minuten) dauerhaft über 6, eine Website antwortet anders als zu Beginn oder doppelt so langsam, ein neuer Eintrag „exited on signal". Dann: Werte festhalten, Mathias Bescheid geben, erst nach Klärung weiter.

#### Block 1: Staging-Kopie, Schema und Proben

- [ ] **Step 1: Freigabe einholen**

Mathias bekommt vorgelegt: „D10, Block 1: Ich kopiere den Stand nach `/root/mw-0230-src` und `/root/mw-0230-stage`, prüfe Syntax und die acht Testreihen, sichere die Struktur der betroffenen Tabellen und lade das Schema: zwei neue Tabellen, neun Spalten in `malwatch_config`, zwei in `malwatch_site`. Danach läuft die Klassenprobe gegen eine Wegwerf-Datenbank — sie fasst nginx nicht an, `nginx -t` und Reload werden nur aufgezeichnet — und ich rendere die Seiten der Kopie gegen die echte Datenbank. Zum Schluss lösche ich Kopie und Wegwerf-Datenbank. Die Automatik bleibt aus, es wird niemand gesperrt." Weiter erst nach seinem Ja.

- [ ] **Step 2: Ausgangslage**

Beide Messungen, dazu:

```bash
ssh ispconfig 'mysql -N dbispconfig -e "SELECT waf_origin_geo, waf_origin_tor, waf_origin_net FROM malwatch_config"; mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_waf_hit"; mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_waf_ip"; ls -l /etc/nginx/conf.d/ | head'
```

Expected: die laufenden Quellen, die Zahl der Treffer und Adressen und die bestehenden Einbindungen von nginx. Diese Werte kommen ins Protokoll.

- [ ] **Step 3: Kopie, Syntax, Tests**

```bash
git archive --format=tar HEAD ispconfig waf | ssh ispconfig 'rm -rf /root/mw-0230-src /root/mw-0230-stage && mkdir -p /root/mw-0230-src /root/mw-0230-stage/interface/web && tar -x -C /root/mw-0230-src'
ssh ispconfig 'bash -s' <<'EOF'
set -eu
date "+%H:%M:%S Staging-Kopie"
src=/root/mw-0230-src/ispconfig
stage=/root/mw-0230-stage
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
for t in waf_lib waf_panel waf_panel_post waf_rules_catalog waf_origin waf_origin_sources waf_proxycheck waf_ban; do
	php tests/${t}_test.php
done
cat version
date "+%H:%M:%S fertig"
EOF
```

Expected: keine Zeile aus den Syntaxprüfungen, achtmal „alle Prüfungen bestanden", Version 0.23.0.

- [ ] **Step 4: Schema laden**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
install -d -m 700 /var/backups/malwatch
mysqldump --no-data dbispconfig malwatch_config malwatch_site > "/var/backups/malwatch/schema-vor-0.23.0-$(date +%Y%m%d-%H%M%S).sql"
date "+%H:%M:%S Schema laden"
mysql dbispconfig < /root/mw-0230-src/ispconfig/install/schema.sql
date "+%H:%M:%S Schema geladen"
mysql -N dbispconfig -e "SHOW TABLES LIKE 'malwatch\_waf\_%'"
mysql -N dbispconfig -e "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME = 'malwatch_config' AND COLUMN_NAME LIKE 'waf\_block\_%' ORDER BY COLUMN_NAME"
mysql -N dbispconfig -e "SELECT waf_ban_mode, waf_ban_score, waf_ban_window_minutes, waf_ban_max FROM malwatch_config"
mysql -N dbispconfig -e "SELECT COUNT(*) AS websites, SUM(waf_ban_trigger = 'y') AS loesen_aus FROM malwatch_site"
EOF
```

Expected: acht Tabellen `malwatch_waf_*` (darunter `malwatch_waf_ban` und `malwatch_waf_allow`), neun Spalten `waf_ban_*`, die Zeile `off 50 10 5000` und alle Websites mit `waf_ban_trigger = 'y'`. Danach beide Messungen.

- [ ] **Step 5: Klassenprobe und Seiten**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
probe_db=mw_probe_0230
mysql -e "DROP DATABASE IF EXISTS $probe_db; CREATE DATABASE $probe_db"
mysqldump --no-data dbispconfig malwatch_config malwatch_job malwatch_site malwatch_waf_hit malwatch_waf_day malwatch_waf_site_day malwatch_waf_exception malwatch_waf_origin_source malwatch_waf_ip malwatch_waf_ban malwatch_waf_allow malwatch_action_log web_domain server_ip sys_datalog sys_log | mysql "$probe_db"
mysql "$probe_db" -e "INSERT INTO malwatch_config (config_id, sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other) VALUES (1, 1, 1, 'riud', 'riud', '')"
cd /root/mw-0230-src/ispconfig
date "+%H:%M:%S Klassenprobe"
nice -n 15 php tests/waf_class_probe.php /root/mw-0230-src/ispconfig "$probe_db"
mysql -e "DROP DATABASE $probe_db"
export MW_SECURITY_DIR=/root/mw-0230-stage/interface/web/security
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
date "+%H:%M:%S Seiten"
nice -n 15 php tests/render_pages.php "$rid" 2>&1 | tail -n 32
date "+%H:%M:%S fertig"
EOF
```

Expected: `waf_class_probe: alle Prüfungen bestanden`, jede Seite `ok`, `All pages render.` — darunter die neue Seite `malwatch_waf_ban_list.php`. Die Probe schreibt ihre Dateien unter `/tmp` und ruft weder nginx noch systemctl auf.

- [ ] **Step 6: Aufräumen und Protokoll**

```bash
ssh ispconfig 'rm -rf /root/mw-0230-src /root/mw-0230-stage; mysql -N -e "SHOW DATABASES LIKE \"mw_probe_0230\""; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: keine Datenbank mehr. Danach beide Messungen und der Eintrag ins Serverprotokoll mit Ausgangslage, Ergebnis der Probe und Rückweg (die zwei Tabellen und die Spalten bleiben folgenlos liegen, solange die Automatik aus ist und keine `deny`-Datei existiert).

#### Block 2: Veröffentlichen

- [ ] **Step 7: Freigabe einholen**

„D10, Block 2: `waf-herkules` per Fast-Forward nach `main`, schieben, CI abwarten, Marke `v0.23.0` setzen, Release abwarten." Weiter erst nach seinem Ja.

- [ ] **Step 8: main, CI, Marke, Release**

```bash
git fetch origin
git merge-base --is-ancestor origin/main waf-herkules && echo "Fast-Forward möglich"
git checkout main
git merge --ff-only waf-herkules
git push origin main
sha=$(git rev-parse HEAD)
gh run watch "$(gh run list --commit "$sha" --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
git tag v0.23.0
git push origin v0.23.0
gh run watch "$(gh run list --workflow release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh release view v0.23.0 --json assets --jq '.assets[].name'
git checkout waf-herkules
```

Expected: `Fast-Forward möglich`, CI grün mit dem Schritt „WAF ban", Release mit vier Dateien. Scheitert ein Upload mit „Error creating asset temp dir", hilft `gh run rerun <id> --failed`.

#### Block 3: Einspielen

- [ ] **Step 9: Freigabe einholen**

„D10, Block 3: Ich spiele 0.23.0 ein. Dabei kommt eine neue nginx-Einbindung dazu (`/etc/nginx/conf.d/waf-blocked.conf`) und eine leere Sperrdatei; `waf/install.sh` prüft mit `nginx -t` und lädt nur neu, wenn die Prüfung besteht. Die Automatik bleibt auf „aus", es wird niemand gesperrt." Weiter erst nach seinem Ja.

- [ ] **Step 10: Einspielen**

Zuerst beide Messungen, dann derselbe Ablauf wie bei 0.22.0, mit `mw-0230-deploy` und `v0.23.0`; zusätzlich läuft danach `waf/install.sh` aus der Einspielquelle, weil die nginx-Einbindung neu ist:

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
date "+%H:%M:%S Beginn"
rm -rf /root/mw-0230-deploy && mkdir -p /root/mw-0230-deploy && cd /root/mw-0230-deploy
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.23.0/malwatch.pkg
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.23.0/SHA256SUMS
grep " malwatch.pkg$" SHA256SUMS | sha256sum -c -
curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh 2>&1 | grep -i installed
cd /usr/local/ispconfig/extensions/malwatch && unzip -oq /root/mw-0230-deploy/malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php 2>&1 | grep -E "installed|loaded|Error|error|failed" | head -n 8
echo "Addon $(cat /usr/local/ispconfig/extensions/malwatch/version), Scanner $(/usr/local/bin/malwatch version | head -n 1)"
E=/usr/local/ispconfig/extensions/malwatch; n=0; total=0
while IFS=: read -r a s t; do [ "$a" = c ] || continue; total=$((total+1)); cmp -s "$E/$s" "/usr/local/ispconfig/$t" || { echo "abweichend: $t"; n=$((n+1)); }; done < "$E/install/file.list"
echo "Kopien geprüft: $total, abweichend: $n"
cd /root/waf-einspielen && sh install.sh 2>&1 | tail -n 5
nginx -t
ls -l /etc/nginx/conf.d/waf-blocked.conf /etc/nginx/waf/blocked.conf /var/log/waf/blocked.log
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
nice -n 15 php "$E/tests/render_pages.php" "$rid" 2>&1 | tail -n 5
rm -rf /root/mw-0230-deploy
mysql -N dbispconfig -e "SELECT waf_ban_mode FROM malwatch_config"
date "+%H:%M:%S eingespielt"
EOF
```

Expected: `malwatch.pkg: OK`, Addon und Scanner `0.23.0`, `Kopien geprüft: 95, abweichend: 0` (92 aus 0.22.0 plus Bibliothek, Seite und Vorlage), `nginx: configuration file /etc/nginx/nginx.conf test is successful`, die drei Dateien vorhanden, alle Seiten `ok`, `waf_ban_mode` weiterhin `off`. Danach beide Messungen und der Protokolleintrag für Blöcke 2 und 3.

Die Einspielquelle `/root/waf-einspielen` wird vorher aktualisiert: `git archive --format=tar HEAD waf | ssh ispconfig 'tar -x -C /root/waf-einspielen --strip-components=1'`.

#### Block 4: Auf „vorschlagen"

- [ ] **Step 11: Freigabe einholen**

„D10, Block 4: Ich schalte die Automatik auf „vorschlagen". malwatch rechnet dann mit und zeigt auf der Seite „Sperren", wen es gesperrt hätte — gesperrt wird niemand. Ein paar Tage später sehen wir uns die Vorschläge an." Weiter erst nach seinem Ja.

- [ ] **Step 12: Umschalten und beobachten**

```bash
ssh ispconfig 'php -r "require \"/usr/local/ispconfig/server/lib/config.inc.php\"; " 2>/dev/null; waf-switch block propose; waf-switch block status'
```

Falls `waf-switch block propose` noch nicht greift, wird der Zustand im Panel umgeschaltet — beides legt denselben Auftrag an.

Nach 10 Minuten, nach einer Stunde und am nächsten Tag:

```bash
ssh ispconfig 'mysql dbispconfig -e "SELECT state, COUNT(*) FROM malwatch_waf_ban GROUP BY state"; mysql dbispconfig -e "SELECT ip, score, hits, LEFT(reason, 80) AS grund FROM malwatch_waf_ban WHERE state = \"proposed\" ORDER BY score DESC LIMIT 10"; ls -l /etc/nginx/waf/blocked.conf'
```

Expected: Vorschläge sammeln sich, die Sperrdatei bleibt leer (nur die Kopfzeile). Die Liste der Vorschläge geht an Mathias: Ist jemand dabei, der nicht gesperrt werden dürfte, kommt er in die Ausnahmen oder die Schwelle der Website wird angehoben. Beobachtungszeit und Werte kommen ins Protokoll.

#### Block 5: Auf „sperren"

- [ ] **Step 13: Freigabe einholen**

„D10, Block 5: Ich schalte auf „sperren". Ab dann bekommen Adressen über der Schwelle serverweit 403, die erste Sperre dauert eine Stunde. Rückweg: `waf-switch block off` oder der Knopf im Panel." Weiter erst nach seinem Ja — und nur, wenn die Vorschläge aus Block 4 sauber aussahen.

- [ ] **Step 14: Umschalten und die erste Sperre ansehen**

```bash
ssh ispconfig 'waf-switch block on; sleep 90; waf-switch block status; waf-switch block list; cat /etc/nginx/waf/blocked.conf; mysql dbispconfig -e "SELECT ip, state, LEFT(reason, 60) AS grund, until, denied FROM malwatch_waf_ban WHERE state = \"active\""'
```

Expected: Der Zustand steht auf `block`, die Datei nennt je gesperrte Adresse eine `deny`-Zeile, nginx wurde geprüft und neu geladen (`journalctl -u nginx --since "-5 min"` zeigt kein „emerg"). Danach beide Messungen.

Zur Probe aufs Exempel wird von außen geprüft, dass eine gesperrte Adresse wirklich 403 bekommt — nicht vom Server selbst, weil dessen Anfragen über die OPNsense zurückkommen. Mathias ruft dafür eine Website von einem Anschluss auf, der **nicht** gesperrt ist, und bestätigt, dass sie normal antwortet.

- [ ] **Step 15: Sichtprüfung im Panel**

Werkzeuge von Claude in Chrome laden, eigener Tab, danach schließen. Die Seite wird über das Menü geöffnet (der Speichern-Knopf gehört zum Panel-Gerüst), und im Panel-Fenster wirkt das Mausrad nicht auf den Inhalt — ein Klick in ein Feld oder `scroll_to` bringt den Abschnitt ins Bild.

| Ablauf | Erwartet |
|---|---|
| Security > Abwehr > Sperren | Kopf mit Zustand „sperren", Zahl der Sperren, Liste mit Adresse, Herkunft, Grund, „noch 47 Minuten", abgewehrte Versuche |
| eine Sperre aufheben | Meldung „Auftrag angelegt", nach einer Minute ist die Zeile auf „aufgehoben" und die Adresse aus der Datei |
| Ausnahme eintragen | die Adresse steht unter „Nie sperren", eine laufende Sperre dazu ist beendet |
| Website-Seite | an jeder Adresse der Knopf „sperren", im Kasten „Zustand" die Schwelle dieser Website |

Bildschirmfotos der Seite und einer Regel-Karte gehen an Mathias.

- [ ] **Step 16: Protokoll und Erinnerung**

Protokolleintrag für Blöcke 4 und 5: Beginn und Ende, Freigaben, Messwerte, Zahl der Vorschläge und Sperren, die erste echte Sperre mit Grund, Ergebnis der Sichtprüfung, Rückweg. In `waf-web-herkules.md` festhalten: 0.23.0 live seit <Datum>, Automatik im Zustand <…>, Schwelle, wo die Sperrdatei liegt, wie man ohne Panel aufmacht, welche Websites eine eigene Schwelle haben. Die Zeile in `MEMORY.md` kürzen.

---

## Abschluss von Stufe 1

Stufe 1 ist fertig, wenn:

- D1 bis D9 committet sind, die acht Prüfreihen bestehen und `sh ispconfig/tests/check_wiring.sh` `Wiring OK` meldet,
- v0.23.0 veröffentlicht ist und die CI grün war,
- web.herkules 0.23.0 zeigt, die Klassenprobe dort bestanden hat und die Seite „Sperren" erreichbar ist,
- die Automatik mindestens im Zustand „vorschlagen" läuft,
- das Serverprotokoll die Blöcke 1 bis 5 enthält.

Danach folgen mit eigener Freigabe Stufe 2 (fail2ban im Panel) und Stufe 3 (URL-Tabelle für die OPNsense) aus derselben Spec.
