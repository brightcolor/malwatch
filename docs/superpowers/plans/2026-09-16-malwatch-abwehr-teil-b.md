# malwatch Abwehr, Teil B: Seiten, Veröffentlichung, Einführung — Umsetzungsplan

> **Für ausführende Helfer:** Dieser Plan wird Aufgabe für Aufgabe abgearbeitet, über
> `superpowers:executing-plans`. Agenten werden dafür nur nach ausdrücklicher Freigabe
> von Mathias gestartet, siehe globale Vorgaben. Die Schritte tragen Kästchen (`- [ ]`)
> zum Abhaken.

**Ziel:** Im Panel steht unter Security der Punkt „Abwehr": Übersicht über alle Websites,
jede Website im Detail bis zur einzelnen Anfrage, Ausnahmen per Knopf, Notaus,
Seitenantwort und Einstellungen. malwatch 0.19.0 geht damit auf web.herkules, und die
WAF-Werkzeuge dort tragen danach die neuen Namen.

**Aufbau:** Die Seiten lesen die Tabellen aus Teil A und reihen Aufträge ein; ausgeführt
wird im Cron (`malwatch_waf`). Knöpfe schicken wie auf den übrigen Seiten das Formular
`pageForm` an die eigene Seite; eine gemeinsame Funktion `waf_panel_handle_post()`
erledigt die Aktionen. Zwei kleine JSON-Seiten liefern den Stand laufender Aufträge und
die Vorschau einer Ausnahme. Rechnen und Aufbereiten steckt in reinen Funktionen
(`malwatch_waf_panel.inc.php`), die am Rechner getestet werden.

**Technik:** PHP (lauffähig ab 7.0), Vorlagen von ISPConfig (`tmpl_var`, `tmpl_loop`,
`tmpl_if`), jQuery 3.6 und Bootstrap 3.3 aus dem Panel, die Dialoge aus
`malwatch_modal.htm` und die Auswahl aus `malwatch_selection.htm`, Farben über die
Variablen von Cicada mit Rückfallwerten.

**Spec:** `docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md`
Vorher erledigt: `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-a.md`

## Globale Vorgaben

- Alle Vorgaben aus Teil A gelten weiter: der Webserver darf niemals ausfallen,
  Serverschritte nur mit Freigabe von Mathias und mit Eintrag im Serverprotokoll,
  Agenten nur mit Freigabe, englische Bezeichner und deutsche Oberfläche, Zeiträume als
  Einstellungen, PHP 7.0, keine echten Kundendaten im Repo, Namensprüfung vor jedem
  Commit, Commit-Zeile `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`, Zweig
  `waf-herkules`, geschoben wird nur auf Ansage.
- **Keine Anmeldung im ISPConfig-Panel.** Klicks prüft der Nachbau aus Aufgabe B9 mit den
  echten Skripten des Panels; im echten Panel klickt Mathias.
- Jede Seite prüft `$app->auth->check_module_permissions('security')` und
  `$app->auth->is_admin()` selbst.
- Sprachdatei per `include $lng_file` mit `check_language()` und `en_`-Rückfall
  (Prüfung 32). Jeder Schlüssel steht in `de_` und `en_` (Prüfungen 9, 36, 39).
- Formulare: kein eigenes `<form>`, Knöpfe mit `type="button"`, `data-submit-form="pageForm"`
  und `data-form-action` (Prüfungen 7, 8, 10). Rückfragen über `data-mw-confirm` und
  `malwatch_modal.htm`; Texte in `data-mw-*` gehen durch `malwatch_attr_texts()`
  (Prüfung 41). Knöpfe mit Auswahl tragen `mw-needs-selection`, `data-mw-empty` und
  `data-mw-hint` (Prüfung 45). Keine Klassen `modal-body`, `notification`,
  `notification_text` (Prüfung 46).
- Seiten mit Token geben `_csrf_id` und `_csrf_key` an die Vorlage (Prüfung 11); ein Token
  gilt für genau eine Anfrage.
- JSON-Seiten laden keine Vorlage (Prüfung 43). Kein `loadContent` im Takt (Prüfung 29),
  kein `DOMNodeRemoved` (Prüfung 28).
- Jede neue Datei unter `ispconfig/interface/` steht in `install/file.list` (Prüfungen 6, 35).
- Ausgaben in Vorlagen gehen durch `$app->functions->htmlentities()`; Adressen,
  Anfrageinhalte und Kopfzeilen sind Daten von Angreifern.
- Das Panel läuft wie die Serverskripte in UTC; Datumsangaben kommen aus SQL
  (`waf_panel_clock()`), angezeigt über `malwatch_datetime()`.

## Entscheidungen beim Planen

Diese Punkte präzisieren die Spec; Aufgabe B8 trägt sie dort nach.

1. **Aktionen über das Formular der Seite** wie auf den übrigen Seiten. Statt
   `malwatch_waf_action.php` gibt es `waf_panel_handle_post()`; JSON liefern nur
   `malwatch_waf_jobs.php` (laufende Aufträge) und `malwatch_waf_preview.php` (Vorschau
   einer Ausnahme).
2. **Ausnahme als Formularbereich** auf der Seite der Website. Der Dialog aus
   `malwatch_modal.htm` hängt am Ende von `<body>` und damit außerhalb von `pageForm`;
   seine Felder kämen nie an. Die Knöpfe „Ausnahme …" füllen den Bereich und springen
   dorthin; „Anlegen" fragt über den Dialog nach.
3. **Einstellungsseite:** Pfade zeigt sie nur an; die Seitenantwort schaltet der Knopf
   auf der Übersicht, den Notaus seine eigenen Knöpfe. Den CSRF-Schlüssel prüft beim
   Speichern `tform` selbst (`tform_base::_encode()`), ohne ihn zu verbrauchen; die Seite
   prüft ihn deshalb nicht noch einmal. Nach dem Speichern bleibt sie offen und meldet den
   Auftrag.
4. **„scharf" in der Mehrfachauswahl** ist erlaubt; Panel und Auftrag überspringen jede
   Website, die die Bedingungen nicht erfüllt, und sagen es.
5. **Eine Zeile der Übersicht trägt „Ansehen".** Den Zustand schalten die Seite der
   Website, wo die Vorschau für „scharf" steht, und die Leiste der Mehrfachauswahl.
6. **Ausnahmeliste nach Website gefiltert** zeigt auch die websiteübergreifenden
   Ausnahmen, weil sie für die Website gelten; die Seite der Website zählt genauso.

## Dateien

| Pfad | Aufgabe | Zweck |
|---|---|---|
| `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` | B1–B6 | Texte der Seiten |
| `ispconfig/interface/lib/malwatch_waf_panel.inc.php` | B1–B3 | reine Aufbereitung und Datenbankzugriffe der Seiten |
| `ispconfig/tests/waf_panel_test.php` | B1–B2, B5–B7 | Tests der reinen Aufbereitung und der Formulardefinition |
| `ispconfig/tests/waf_panel_post_test.php` | B3 | Test der Aktionen gegen eine nachgebaute Datenbank |
| `ispconfig/interface/module.conf.php` | B4 | Menüpunkt „Abwehr" |
| `ispconfig/interface/malwatch_waf_jobs.php` | B3 | JSON: WAF-Aufträge |
| `ispconfig/interface/malwatch_waf_preview.php` | B3 | JSON: Vorschau einer Ausnahme |
| `ispconfig/interface/malwatch_waf_response.php` | B3 | Seitenantwort als Text |
| `ispconfig/interface/malwatch_waf_list.php`, `templates/malwatch_waf_list.htm` | B4 | Übersicht |
| `ispconfig/interface/malwatch_waf_show.php`, `templates/malwatch_waf_show.htm` | B5 | Website im Detail mit Ausnahmeformular |
| `ispconfig/interface/malwatch_waf_exception_list.php`, `templates/malwatch_waf_exception_list.htm` | B6 | alle Ausnahmen |
| `ispconfig/interface/malwatch_waf_config_edit.php`, `form/malwatch_waf_config.tform.php`, `templates/malwatch_waf_config_edit.htm`, `lang/de_malwatch_waf_config.lng`, `lang/en_malwatch_waf_config.lng` | B7 | Einstellungen |
| `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`, `ispconfig/tests/check_wiring.sh`, `.github/workflows/ci.yml` | B1–B7 | Einträge, Prüfungen 55 bis 59 |
| `ispconfig/version`, `internal/version/version.go`, `CHANGELOG.md`, `README.md`, `ispconfig/README.md`, Spec | B8 | 0.19.0 |

---

### Aufgabe B1: Sprachdateien und Beschriftungen

Die gemeinsamen Texte der Abwehr-Seiten und die ersten reinen Funktionen der Seiten:
Beschriftungen für Zustände, Geltungsbereiche, Gründe, Aufträge und Regeln.

**Dateien:**
- Neu: `ispconfig/interface/lang/de_malwatch_waf.lng`, `ispconfig/interface/lang/en_malwatch_waf.lng`
- Neu: `ispconfig/interface/lib/malwatch_waf_panel.inc.php`
- Neu: `ispconfig/tests/waf_panel_test.php`
- Ändern: `ispconfig/install/file.list`, `.github/workflows/ci.yml`

**Schnittstellen:**
- Nutzt: `malwatch_waf_lib.inc.php` (Teil A)
- Liefert: `waf_panel_text($wb, $key, $fallback)`, `waf_panel_state_label($wb, $state)`,
  `waf_panel_scope_label($wb, $scope)`, `waf_panel_exception_state_label($wb, $state)`,
  `waf_panel_reason_label($wb, $reason)`, `waf_panel_job_label($wb, $action)`,
  `waf_panel_status_label($wb, $status)`, `waf_panel_rule_title($wb, $rule_id, $message)` —
  alle geben Text zurück, unbekannte Schlüssel ergeben den Rückfallwert.

- [ ] **Schritt 1: Test schreiben**

`ispconfig/tests/waf_panel_test.php`:

```php
<?php
/**
 * Checks the pure helpers of the Abwehr pages against the German texts.
 *
 *   php ispconfig/tests/waf_panel_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_panel.inc.php';

$wb = array();
include __DIR__ . '/../interface/lang/en_malwatch_waf.lng';
$en = $wb;
$wb = array();
include __DIR__ . '/../interface/lang/de_malwatch_waf.lng';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

expect_same('same keys in both languages', array(
	array_values(array_diff(array_keys($wb), array_keys($en))),
	array_values(array_diff(array_keys($en), array_keys($wb))),
), array(array(), array()));

// --- B1: labels --------------------------------------------------------------

expect_same('state label', waf_panel_state_label($wb, 'detect'), 'mitschreiben');
expect_same('unknown state label', waf_panel_state_label($wb, 'foo'), 'foo');
expect_same('scope label', waf_panel_scope_label($wb, 'site_param'), 'nur dieser Parameter');
expect_same('exception state label', waf_panel_exception_state_label($wb, 'removing'), 'wird entfernt');
expect_same('reason label', waf_panel_reason_label($wb, 'too_early'), 'Die Website schreibt noch nicht lange genug mit.');
expect_same('job label', waf_panel_job_label($wb, 'emergency'), 'Notaus');
expect_same('status label', waf_panel_status_label($wb, 'running'), 'läuft');
expect_same('rule title from its group', waf_panel_rule_title($wb, '942100', 'SQL Injection Attack Detected via libinjection'), 'SQL-Einschleusung');
expect_same('rule title from the message', waf_panel_rule_title($wb, '10010', 'own rule'), 'own rule');
expect_same('rule title from the number', waf_panel_rule_title($wb, '999999', ''), 'Regel 999999');
expect_same('fallback text', waf_panel_text($wb, 'no_such_key_txt', 'x'), 'x');

// --- summary -----------------------------------------------------------------
if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_panel: alle Prüfungen bestanden\n";
```

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit „Failed opening required … malwatch_waf_panel.inc.php"

- [ ] **Schritt 3: Sprachdateien anlegen**

`ispconfig/interface/lang/de_malwatch_waf.lng`:

```php
<?php
// Texts of the pages "Abwehr" (the WAF per website).
$wb['state_off_txt'] = 'aus';
$wb['state_detect_txt'] = 'mitschreiben';
$wb['state_enforce_txt'] = 'scharf';
$wb['state_pending_txt'] = 'wird umgesetzt';
$wb['scope_site_txt'] = 'diese Website';
$wb['scope_site_path_txt'] = 'nur dieser Pfad';
$wb['scope_site_param_txt'] = 'nur dieser Parameter';
$wb['scope_all_txt'] = 'alle Websites';
$wb['scope_all_path_txt'] = 'alle Websites, nur dieser Pfad';
$wb['exc_state_pending_txt'] = 'wird übernommen';
$wb['exc_state_active_txt'] = 'aktiv';
$wb['exc_state_error_txt'] = 'Fehler';
$wb['exc_state_removing_txt'] = 'wird entfernt';
$wb['reason_emergency_txt'] = 'Der Notaus ist aktiv.';
$wb['reason_not_detect_txt'] = 'Die Website schreibt noch nicht mit.';
$wb['reason_too_early_txt'] = 'Die Website schreibt noch nicht lange genug mit.';
$wb['reason_scope_txt'] = 'Bitte einen Geltungsbereich wählen.';
$wb['reason_site_txt'] = 'Die Website passt nicht zum Geltungsbereich.';
$wb['reason_rule_id_txt'] = 'Die Regelnummer besteht aus drei bis sieben Ziffern. Eigene Regeln (10000 bis 10999) und die Punktwertung (949, 959, 980) lassen sich nicht ausnehmen.';
$wb['reason_path_txt'] = 'Der Pfad beginnt mit / und enthält Buchstaben, Ziffern und . _ ~ / % + -.';
$wb['reason_param_txt'] = 'Der Parameter enthält Buchstaben, Ziffern und _ . [ ] -.';
$wb['rule_fallback_txt'] = 'Regel %s';
$wb['group_911_txt'] = 'Unerlaubte Methode';
$wb['group_913_txt'] = 'Scanner';
$wb['group_920_txt'] = 'Verstoß gegen das Protokoll';
$wb['group_921_txt'] = 'Angriff auf das Protokoll';
$wb['group_930_txt'] = 'Zugriff auf Dateien und Pfade';
$wb['group_931_txt'] = 'Nachladen fremder Dateien';
$wb['group_932_txt'] = 'Befehlsausführung';
$wb['group_933_txt'] = 'PHP-Angriff';
$wb['group_934_txt'] = 'Node.js-Angriff';
$wb['group_941_txt'] = 'Skript-Einschleusung (XSS)';
$wb['group_942_txt'] = 'SQL-Einschleusung';
$wb['group_943_txt'] = 'Sitzungsübernahme';
$wb['group_944_txt'] = 'Java-Angriff';
$wb['group_949_txt'] = 'Punktgrenze überschritten';
$wb['group_950_txt'] = 'Datenabfluss';
$wb['group_951_txt'] = 'Datenbankfehler in der Antwort';
$wb['group_952_txt'] = 'Java-Fehler in der Antwort';
$wb['group_953_txt'] = 'PHP-Fehler in der Antwort';
$wb['group_954_txt'] = 'IIS-Fehler in der Antwort';
$wb['group_959_txt'] = 'Punktgrenze der Antwort überschritten';
$wb['group_980_txt'] = 'Auswertung';
$wb['job_set_state_txt'] = 'Zustand ändern';
$wb['job_migrate_markers_txt'] = 'Abgleich';
$wb['job_exception_add_txt'] = 'Ausnahme anlegen';
$wb['job_exception_remove_txt'] = 'Ausnahme entfernen';
$wb['job_emergency_txt'] = 'Notaus';
$wb['job_response_body_txt'] = 'Seitenantwort';
$wb['job_apply_settings_txt'] = 'Einstellungen';
$wb['job_status_pending_txt'] = 'wartet';
$wb['job_status_running_txt'] = 'läuft';
$wb['job_status_done_txt'] = 'erledigt';
$wb['job_status_error_txt'] = 'gescheitert';
$wb['btn_cancel_txt'] = 'Abbrechen';
$wb['btn_close_txt'] = 'Schließen';
```

`ispconfig/interface/lang/en_malwatch_waf.lng`:

```php
<?php
// Texts of the pages "Abwehr" (the WAF per website).
$wb['state_off_txt'] = 'off';
$wb['state_detect_txt'] = 'detect';
$wb['state_enforce_txt'] = 'enforce';
$wb['state_pending_txt'] = 'being applied';
$wb['scope_site_txt'] = 'this website';
$wb['scope_site_path_txt'] = 'this path only';
$wb['scope_site_param_txt'] = 'this parameter only';
$wb['scope_all_txt'] = 'all websites';
$wb['scope_all_path_txt'] = 'all websites, this path only';
$wb['exc_state_pending_txt'] = 'being applied';
$wb['exc_state_active_txt'] = 'active';
$wb['exc_state_error_txt'] = 'error';
$wb['exc_state_removing_txt'] = 'being removed';
$wb['reason_emergency_txt'] = 'The emergency stop is active.';
$wb['reason_not_detect_txt'] = 'The website does not detect yet.';
$wb['reason_too_early_txt'] = 'The website has not been detecting long enough.';
$wb['reason_scope_txt'] = 'Please choose a scope.';
$wb['reason_site_txt'] = 'The website does not fit the scope.';
$wb['reason_rule_id_txt'] = 'A rule id has three to seven digits. Own rules (10000 to 10999) and the scoring rules (949, 959, 980) cannot be excluded.';
$wb['reason_path_txt'] = 'The path starts with / and holds letters, digits and . _ ~ / % + -.';
$wb['reason_param_txt'] = 'The parameter holds letters, digits and _ . [ ] -.';
$wb['rule_fallback_txt'] = 'Rule %s';
$wb['group_911_txt'] = 'Method not allowed';
$wb['group_913_txt'] = 'Scanner';
$wb['group_920_txt'] = 'Protocol violation';
$wb['group_921_txt'] = 'Protocol attack';
$wb['group_930_txt'] = 'File and path access';
$wb['group_931_txt'] = 'Remote file inclusion';
$wb['group_932_txt'] = 'Command execution';
$wb['group_933_txt'] = 'PHP attack';
$wb['group_934_txt'] = 'Node.js attack';
$wb['group_941_txt'] = 'Cross-site scripting (XSS)';
$wb['group_942_txt'] = 'SQL injection';
$wb['group_943_txt'] = 'Session fixation';
$wb['group_944_txt'] = 'Java attack';
$wb['group_949_txt'] = 'Score limit exceeded';
$wb['group_950_txt'] = 'Data leakage';
$wb['group_951_txt'] = 'Database error in the response';
$wb['group_952_txt'] = 'Java error in the response';
$wb['group_953_txt'] = 'PHP error in the response';
$wb['group_954_txt'] = 'IIS error in the response';
$wb['group_959_txt'] = 'Response score limit exceeded';
$wb['group_980_txt'] = 'Correlation';
$wb['job_set_state_txt'] = 'Change state';
$wb['job_migrate_markers_txt'] = 'Reconcile';
$wb['job_exception_add_txt'] = 'Add exception';
$wb['job_exception_remove_txt'] = 'Remove exception';
$wb['job_emergency_txt'] = 'Emergency stop';
$wb['job_response_body_txt'] = 'Response body';
$wb['job_apply_settings_txt'] = 'Settings';
$wb['job_status_pending_txt'] = 'waiting';
$wb['job_status_running_txt'] = 'running';
$wb['job_status_done_txt'] = 'done';
$wb['job_status_error_txt'] = 'failed';
$wb['btn_cancel_txt'] = 'Cancel';
$wb['btn_close_txt'] = 'Close';
```

- [ ] **Schritt 4: Beschriftungen schreiben**

`ispconfig/interface/lib/malwatch_waf_panel.inc.php`:

```php
<?php

/**
 * Helpers for the pages "Abwehr" (the WAF part) in the Security module.
 *
 * The first part is pure and tested in tests/waf_panel_test.php; the
 * database part at the end serves the pages. The shared rules live in
 * malwatch_waf_lib.inc.php, which sits in the same directory here and after
 * the installation.
 */

require_once __DIR__ . '/malwatch_waf_lib.inc.php';

/** A language line, or $fallback when the file lacks it. */
function waf_panel_text($wb, $key, $fallback)
{
	return isset($wb[$key]) ? (string) $wb[$key] : (string) $fallback;
}

function waf_panel_state_label($wb, $state)
{
	return waf_panel_text($wb, 'state_' . $state . '_txt', $state);
}

function waf_panel_scope_label($wb, $scope)
{
	return waf_panel_text($wb, 'scope_' . $scope . '_txt', $scope);
}

function waf_panel_exception_state_label($wb, $state)
{
	return waf_panel_text($wb, 'exc_state_' . $state . '_txt', $state);
}

/** The words for a code of waf_enforce_block_reason() or waf_exception_check(). */
function waf_panel_reason_label($wb, $reason)
{
	return waf_panel_text($wb, 'reason_' . $reason . '_txt', $reason);
}

function waf_panel_job_label($wb, $action)
{
	return waf_panel_text($wb, 'job_' . $action . '_txt', $action);
}

function waf_panel_status_label($wb, $status)
{
	return waf_panel_text($wb, 'job_status_' . $status . '_txt', $status);
}

/** The heading of a rule: its CRS group in words, else the CRS message, else its number. */
function waf_panel_rule_title($wb, $rule_id, $message)
{
	$rule_id = (string) $rule_id;
	if (preg_match('/^(9\d\d)\d{3}$/', $rule_id, $m) && isset($wb['group_' . $m[1] . '_txt'])) {
		return (string) $wb['group_' . $m[1] . '_txt'];
	}
	if (trim((string) $message) !== '') {
		return (string) $message;
	}
	return sprintf(waf_panel_text($wb, 'rule_fallback_txt', '%s'), $rule_id);
}
```

- [ ] **Schritt 5: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 6: Dateiliste und CI**

In `ispconfig/install/file.list` unter der Zeile mit `malwatch_waf_lib.inc.php`:

```text
c:interface/lib/malwatch_waf_panel.inc.php:interface/web/security/lib/malwatch_waf_panel.inc.php
c:interface/lang/de_malwatch_waf.lng:interface/web/security/lib/lang/de_malwatch_waf.lng
c:interface/lang/en_malwatch_waf.lng:interface/web/security/lib/lang/en_malwatch_waf.lng
```

In `.github/workflows/ci.yml` nach dem Schritt „WAF functions":

```yaml
      - name: WAF page helpers
        run: php ispconfig/tests/waf_panel_test.php
```

Den Menüpunkt setzt B4 zusammen mit der Seite.

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Schritt 7: Commit**

```bash
git add ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/tests/waf_panel_test.php ispconfig/install/file.list .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): texts and labels of the WAF pages" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B2: Aufbereitung für Übersicht und Detailseite

Reine Funktionen, die aus den Zeilen der Tabellen das machen, was die Seiten zeigen:
Tagesreihen, Verlaufslinie, Übersicht mit Kopfsatz und Filtern, Regeln und Pfade einer
Website, ein Einzeltreffer mit Vorbelegung für das Ausnahmeformular, die Vorschau vor
„scharf", die Eingaben einer Ausnahme, Auftragszeilen und Ausnahmezeilen.

**Dateien:**
- Ändern: `ispconfig/tests/waf_panel_test.php` (Abschnitt B2)
- Ändern: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (Funktionen anhängen)
- Ändern: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` (Zeilen anhängen)

**Schnittstellen:**
- Nutzt: B1; aus Teil A `waf_state_valid()`, `waf_period()`, `waf_exception_check()`,
  `waf_enforce_block_reason()`, `waf_enforce_free_from()`, `waf_cut()`
- Liefert:
  - `waf_panel_day_series($rows, $today, $days)` → Liste aus `day`, `hits`, `would_block`
  - `waf_panel_sparkline($values, $width, $height)` → Punkte für `<polyline points="…">`
  - `waf_panel_overview($sites, $pending, $day_rows, $rule_rows, $wordpress, $today, $days, $filters)` →
    `array('rows' => …, 'counts' => array('off', 'detect', 'enforce', 'pending', 'hits', 'would_block', 'sites_with_hits'))`;
    eine Zeile trägt `domain_id`, `domain`, `state`, `since`, `pending`, `wordpress`, `hits`,
    `would_block`, `values`, `top_rule`, `top_rule_msg`, `top_rule_hits`
  - `waf_panel_lede($wb, $counts, $days)` → Satz
  - `waf_panel_filters($get, $stats_days)` → `array('days', 'state', 'wordpress', 'hits')`;
    `waf_panel_query($filters, $changes)` → Abfragetext
  - `waf_panel_rules($wb, $rows)` → Liste aus `rule_id`, `title`, `msg`, `hits`, `would_block`,
    `paths` (bis zu drei aus `path`, `hits`), `path_count`, `last_day`, `can_except`
  - `waf_panel_paths($rows)` → Liste aus `path`, `hits`, `rules`
  - `waf_panel_hit($wb, $row)` → Feld mit `hit_id`, `seen_at`, `client_ip`, `method`, `uri`,
    `status`, `score`, `would_block`, `logged_in`, `rules`, `headers`, `body`, `has_body`,
    `has_response`, `response_bytes`, `prefill` (`rule_id`, `path`, `param`)
  - `waf_panel_enforce($wb, $site, $totals, $rule_rows, $settings, $now)` → `state`,
    `allowed`, `reason`, `free_from`, `would_block`, `logged_in`, `rules`, `days`
  - `waf_panel_exception_input($post, $site_id)` → `array(row, falsches Feld oder '')`
  - `waf_panel_preview_text($wb, $preview, $days)` → Satz
  - `waf_panel_job($wb, $row)` → `job_id`, `status`, `status_label`, `label`, `log`, `sites`, `running`
  - `waf_panel_exception_row($wb, $row)` → `exception_id`, `rule_id`, `scope_label`, `site`,
    `site_id`, `target`, `note`, `state`, `state_label`, `error`, `created_by`, `created_at`, `can_remove`

- [ ] **Schritt 1: Test schreiben**

`ispconfig/tests/waf_panel_test.php` (Abschnitt vor summary):

```php
// --- B2: views ---------------------------------------------------------------

$rows = array(
	array('day' => '2026-09-14', 'hits' => '3', 'would_block' => '1'),
	array('day' => '2026-09-16', 'hits' => '5', 'would_block' => '0'),
	array('day' => '2026-09-16', 'hits' => '2', 'would_block' => '2'),
	array('day' => '2026-09-01', 'hits' => '9', 'would_block' => '9'),
);
expect_same('series', waf_panel_day_series($rows, '2026-09-16', 3), array(
	array('day' => '2026-09-14', 'hits' => 3, 'would_block' => 1),
	array('day' => '2026-09-15', 'hits' => 0, 'would_block' => 0),
	array('day' => '2026-09-16', 'hits' => 7, 'would_block' => 2),
));
expect_same('series of one day', waf_panel_day_series($rows, '2026-09-16', 1), array(array('day' => '2026-09-16', 'hits' => 7, 'would_block' => 2)));
$month_end = waf_panel_day_series(array(), '2026-10-02', 7);
expect_same('series over a month end', array(count($month_end), $month_end[0]['day']), array(7, '2026-09-26'));
expect_same('series with a bad date', waf_panel_day_series($rows, 'gestern', 3), array());

expect_same('sparkline', waf_panel_sparkline(array(0, 2, 1), 60, 16), '0.0,15.5 30.0,0.5 60.0,8.0');
expect_same('sparkline of zeros', waf_panel_sparkline(array(0, 0), 60, 16), '0.0,15.5 60.0,15.5');
expect_same('sparkline of one value', waf_panel_sparkline(array(4), 60, 16), '60.0,0.5');
expect_same('sparkline of nothing', waf_panel_sparkline(array(), 60, 16), '');

$sites = array(
	array('domain_id' => '11', 'domain' => 'beispiel.test', 'waf_state' => 'detect', 'waf_state_since' => '2026-09-10 08:00:00', 'waf_pending_state' => ''),
	array('domain_id' => '12', 'domain' => 'zweite.test', 'waf_state' => 'enforce', 'waf_state_since' => '2026-09-01 08:00:00', 'waf_pending_state' => ''),
	array('domain_id' => '13', 'domain' => 'dritte.test', 'waf_state' => null, 'waf_state_since' => null, 'waf_pending_state' => null),
	array('domain_id' => '14', 'domain' => 'vierte.test', 'waf_state' => 'off', 'waf_state_since' => null, 'waf_pending_state' => 'detect'),
);
$day_rows = array(
	array('parent_domain_id' => '11', 'day' => '2026-09-16', 'hits' => '10', 'would_block' => '3'),
	array('parent_domain_id' => '11', 'day' => '2026-09-15', 'hits' => '4', 'would_block' => '0'),
	array('parent_domain_id' => '12', 'day' => '2026-09-16', 'hits' => '4', 'would_block' => '4'),
);
$rule_rows = array(
	array('parent_domain_id' => '11', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'hits' => '9'),
	array('parent_domain_id' => '11', 'rule_id' => '941100', 'rule_msg' => 'XSS Attack Detected via libinjection', 'hits' => '12'),
	array('parent_domain_id' => '12', 'rule_id' => '930130', 'rule_msg' => 'Restricted File Access Attempt', 'hits' => '4'),
);
$no_filter = array('state' => '', 'wordpress' => false, 'hits' => false);
$view = waf_panel_overview($sites, array(13), $day_rows, $rule_rows, array(11, 13), '2026-09-16', 7, $no_filter);
expect_same('overview counts', $view['counts'], array('off' => 2, 'detect' => 1, 'enforce' => 1, 'pending' => 2,
	'hits' => 18, 'would_block' => 7, 'sites_with_hits' => 2));
expect_same('overview order', array_column($view['rows'], 'domain'), array('beispiel.test', 'zweite.test', 'dritte.test', 'vierte.test'));
$first = $view['rows'][0];
expect_same('overview row', array($first['domain_id'], $first['state'], $first['since'], $first['pending'], $first['wordpress'],
	$first['hits'], $first['would_block'], $first['top_rule'], $first['top_rule_hits']),
	array(11, 'detect', '2026-09-10 08:00:00', false, true, 14, 3, '941100', 12));
expect_same('overview curve', $first['values'], array(0, 0, 0, 0, 0, 4, 10));
expect_same('overview without a site row', array($view['rows'][2]['state'], $view['rows'][2]['since'], $view['rows'][2]['pending']), array('off', '', true));
expect_same('overview pending from the site row', $view['rows'][3]['pending'], true);
$only = waf_panel_overview($sites, array(), $day_rows, $rule_rows, array(11, 13), '2026-09-16', 1,
	array('state' => 'off', 'wordpress' => true, 'hits' => false));
expect_same('overview filtered', array_column($only['rows'], 'domain'), array('dritte.test'));
expect_same('overview counts cover every website', $only['counts']['hits'], 14);
$with_hits = waf_panel_overview($sites, array(), $day_rows, $rule_rows, array(), '2026-09-16', 7,
	array('state' => '', 'wordpress' => false, 'hits' => true));
expect_same('overview with hits only', array_column($with_hits['rows'], 'domain'), array('beispiel.test', 'zweite.test'));

expect_same('lede of the spec', waf_panel_lede($wb, array('detect' => 2, 'enforce' => 0, 'hits' => 14, 'would_block' => 3), 1),
	'2 Websites schreiben mit, keine blockiert. Heute 14 Treffer, 3 davon wären abgewiesen worden.');
expect_same('lede of a week', waf_panel_lede($wb, array('detect' => 1, 'enforce' => 1, 'hits' => 1200, 'would_block' => 0), 7),
	'Eine Website schreibt mit, eine blockiert. In 7 Tagen 1.200 Treffer.');
expect_same('lede without detecting websites', waf_panel_lede($wb, array('detect' => 0, 'enforce' => 3, 'hits' => 0, 'would_block' => 0), 30),
	'Keine Website schreibt mit, 3 blockieren. In 30 Tagen 0 Treffer.');

$filters = waf_panel_filters(array('days' => '30', 'state' => 'enforce', 'wp' => '1'), 90);
expect_same('filters', $filters, array('days' => 30, 'state' => 'enforce', 'wordpress' => true, 'hits' => false));
expect_same('filters with odd values', waf_panel_filters(array('days' => '5', 'state' => 'scharf'), 90),
	array('days' => 7, 'state' => '', 'wordpress' => false, 'hits' => false));
expect_same('query', waf_panel_query($filters, array('hits' => true)), 'days=30&state=enforce&wp=1&hits=1');
expect_same('query without filters', waf_panel_query($filters, array('state' => '', 'wordpress' => false)), 'days=30');

$rule_day_rows = array(
	array('day' => '2026-09-15', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/suche', 'hits' => '2', 'would_block_hits' => '1'),
	array('day' => '2026-09-16', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/wp-admin/admin-ajax.php', 'hits' => '5', 'would_block_hits' => '0'),
	array('day' => '2026-09-16', 'rule_id' => '942100', 'rule_msg' => 'SQL Injection Attack Detected via libinjection', 'path' => '/suche', 'hits' => '1', 'would_block_hits' => '1'),
	array('day' => '2026-09-14', 'rule_id' => '941100', 'rule_msg' => 'XSS Attack Detected via libinjection', 'path' => '/seite', 'hits' => '3', 'would_block_hits' => '3'),
	array('day' => '2026-09-16', 'rule_id' => '10010', 'rule_msg' => '', 'path' => '/x', 'hits' => '1', 'would_block_hits' => '0'),
);
$rules = waf_panel_rules($wb, $rule_day_rows);
expect_same('rules order', array_column($rules, 'rule_id'), array('942100', '941100', '10010'));
expect_same('rule sums', array($rules[0]['hits'], $rules[0]['would_block'], $rules[0]['last_day'], $rules[0]['title'],
	$rules[0]['msg'], $rules[0]['can_except'], $rules[0]['path_count']),
	array(8, 2, '2026-09-16', 'SQL-Einschleusung', 'SQL Injection Attack Detected via libinjection', true, 2));
expect_same('rule paths', $rules[0]['paths'], array(array('path' => '/wp-admin/admin-ajax.php', 'hits' => 5), array('path' => '/suche', 'hits' => 3)));
expect_same('own rule', array($rules[2]['can_except'], $rules[2]['title']), array(false, 'Regel 10010'));

expect_same('paths', waf_panel_paths($rule_day_rows), array(
	array('path' => '/wp-admin/admin-ajax.php', 'hits' => 5, 'rules' => array('942100')),
	array('path' => '/seite', 'hits' => 3, 'rules' => array('941100')),
	array('path' => '/suche', 'hits' => 3, 'rules' => array('942100')),
	array('path' => '/x', 'hits' => 1, 'rules' => array('10010')),
));

$hit_row = array('hit_id' => '5', 'seen_at' => '2026-09-16 21:09:19', 'client_ip' => '198.51.100.7', 'method' => 'POST',
	'uri' => '/wp-json/batch/v1', 'path' => '/wp-json/batch/v1', 'status' => '207', 'anomaly_score' => '5',
	'would_block' => 'y', 'logged_in' => 'n',
	'rules' => '[{"id":"949110","msg":"Inbound Anomaly Score Exceeded (Total Score: 5)","data":"","param":""},'
		. '{"id":"942190","msg":"Detects MSSQL code execution and information gathering attempts","data":"Matched Data: x","param":"json.requests.0.path"}]',
	'request_headers' => '{"Host":"beispiel.test","Cookie":"a=[entfernt]"}', 'request_body' => '{"a":1}',
	'response_file' => '', 'response_bytes' => '0');
$hit = waf_panel_hit($wb, $hit_row);
expect_same('hit basics', array($hit['hit_id'], $hit['status'], $hit['score'], $hit['would_block'], $hit['logged_in'],
	$hit['has_body'], $hit['has_response']), array(5, 207, 5, true, false, true, false));
expect_same('hit rule titles', array_column($hit['rules'], 'title'), array('Punktgrenze überschritten', 'SQL-Einschleusung'));
expect_same('hit prefill skips the score', $hit['prefill'], array('rule_id' => '942190', 'path' => '/wp-json/batch/v1', 'param' => 'json.requests.0.path'));
expect_same('hit headers', $hit['headers'], array(array('name' => 'Host', 'value' => 'beispiel.test'), array('name' => 'Cookie', 'value' => 'a=[entfernt]')));
$broken = waf_panel_hit($wb, array_merge($hit_row, array('rules' => 'kaputt', 'request_headers' => '', 'request_body' => null, 'response_file' => 'x.html.gz')));
expect_same('hit with broken JSON', array($broken['rules'], $broken['headers'], $broken['has_body'], $broken['has_response'], $broken['prefill']['rule_id']),
	array(array(), array(), false, true, ''));

$settings = waf_settings(array());
$site = array('waf_state' => 'detect', 'waf_state_since' => '2026-09-10 08:00:00');
$totals = array('would_block' => '12', 'would_block_logged_in' => '3');
$enforce_rules = array(
	array('rule_id' => '941100', 'rule_msg' => 'XSS', 'would_block_hits' => '2'),
	array('rule_id' => '942100', 'rule_msg' => 'SQLi', 'would_block_hits' => '9'),
	array('rule_id' => '930130', 'rule_msg' => 'Files', 'would_block_hits' => '0'),
);
$enforce = waf_panel_enforce($wb, $site, $totals, $enforce_rules, $settings, '2026-09-16 12:00:00');
expect_same('enforce too early', array($enforce['allowed'], $enforce['reason'], $enforce['free_from']), array(false, 'too_early', '2026-09-17 08:00:00'));
expect_same('enforce figures', array($enforce['would_block'], $enforce['logged_in'], $enforce['days']), array(12, 3, 7));
expect_same('enforce rules', array_column($enforce['rules'], 'rule_id'), array('942100', '941100'));
$enforce = waf_panel_enforce($wb, $site, $totals, $enforce_rules, $settings, '2026-09-17 08:00:00');
expect_same('enforce free', array($enforce['allowed'], $enforce['reason']), array(true, ''));
$enforce = waf_panel_enforce($wb, array('waf_state' => 'enforce', 'waf_state_since' => '2026-09-01 08:00:00'), null, array(), $settings, '2026-09-17 08:00:00');
expect_same('enforce already on', array($enforce['allowed'], $enforce['reason'], $enforce['free_from'], $enforce['would_block']), array(false, '', '', 0));
$enforce = waf_panel_enforce($wb, null, null, array(), $settings, '2026-09-17 08:00:00');
expect_same('enforce from nothing', array($enforce['state'], $enforce['reason']), array('off', 'not_detect'));

list($row, $wrong) = waf_panel_exception_input(array('exc_scope' => 'site_path', 'exc_rule' => ' 942100 ',
	'exc_path' => '/wp-admin/admin-ajax.php', 'exc_param' => 'x', 'exc_note' => "Formular\nKontakt"), 11);
expect_same('input site_path', array($row, $wrong), array(array('scope' => 'site_path', 'parent_domain_id' => 11, 'rule_id' => '942100',
	'path' => '/wp-admin/admin-ajax.php', 'param' => '', 'note' => 'Formular Kontakt'), ''));
list($row, $wrong) = waf_panel_exception_input(array('exc_scope' => 'all', 'exc_rule' => '941160', 'exc_path' => '/x'), 11);
expect_same('input all drops website and path', array($row['parent_domain_id'], $row['path'], $wrong), array(0, '', ''));
list($row, $wrong) = waf_panel_exception_input(array('exc_scope' => 'site_param', 'exc_rule' => '942100', 'exc_param' => 'a"b'), 11);
expect_same('input with a bad parameter', $wrong, 'param');
list($row, $wrong) = waf_panel_exception_input(array(), 11);
expect_same('input without a scope', $wrong, 'scope');

expect_same('preview text', waf_panel_preview_text($wb, array('covered' => 18, 'total' => 21), 7),
	'Diese Ausnahme hätte 18 von 21 Treffern der letzten 7 Tage verhindert.');
expect_same('preview without hits', waf_panel_preview_text($wb, array('covered' => 0, 'total' => 0), 7),
	'In den letzten 7 Tagen gab es keinen Treffer dieser Regel.');

$job = waf_panel_job($wb, array('job_id' => '9', 'job_status' => 'running',
	'options' => '{"action":"set_state","state":"detect","domain_ids":[11,"12"]}', 'job_log' => ''));
expect_same('job view', $job, array('job_id' => 9, 'status' => 'running', 'status_label' => 'läuft',
	'label' => 'Zustand ändern: mitschreiben', 'log' => '', 'sites' => array(11, 12), 'running' => true));
$job = waf_panel_job($wb, array('job_id' => '10', 'job_status' => 'error', 'options' => 'kaputt', 'job_log' => "Zeile eins\nZeile zwei"));
expect_same('job view of a broken row', array($job['label'], $job['log'], $job['running']), array('', 'Zeile eins', false));

$exception = waf_panel_exception_row($wb, array('exception_id' => '3', 'scope' => 'site_param', 'parent_domain_id' => '11',
	'domain' => 'beispiel.test', 'rule_id' => '942100', 'path' => '/suche', 'param' => 'q', 'note' => 'Suche',
	'exception_state' => 'active', 'error_reason' => '', 'created_by' => 'admin', 'created_at' => '2026-09-16 10:00:00'));
expect_same('exception row', array($exception['exception_id'], $exception['scope_label'], $exception['site'], $exception['site_id'],
	$exception['target'], $exception['state_label'], $exception['can_remove']),
	array(3, 'nur dieser Parameter', 'beispiel.test', 11, '/suche · Parameter q', 'aktiv', true));
$exception = waf_panel_exception_row($wb, array('exception_id' => '4', 'scope' => 'all', 'parent_domain_id' => '0',
	'domain' => '', 'rule_id' => '941160', 'path' => '', 'param' => '', 'note' => '',
	'exception_state' => 'pending', 'error_reason' => '', 'created_by' => 'admin', 'created_at' => '2026-09-16 10:00:00'));
expect_same('exception row for every website', array($exception['site'], $exception['target'], $exception['can_remove']),
	array('alle Websites', '', false));
```

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit „Call to undefined function waf_panel_day_series()"

- [ ] **Schritt 3: Texte anhängen**

`ispconfig/interface/lang/de_malwatch_waf.lng` (anhängen):

```php
$wb['lede_detect_none_txt'] = 'Keine Website schreibt mit';
$wb['lede_detect_one_txt'] = 'Eine Website schreibt mit';
$wb['lede_detect_many_txt'] = '%s Websites schreiben mit';
$wb['lede_enforce_none_txt'] = 'keine blockiert';
$wb['lede_enforce_one_txt'] = 'eine blockiert';
$wb['lede_enforce_many_txt'] = '%s blockieren';
$wb['lede_today_txt'] = 'Heute %s Treffer';
$wb['lede_period_txt'] = 'In %s Tagen %s Treffer';
$wb['lede_would_block_txt'] = ', %s davon wären abgewiesen worden';
$wb['preview_txt'] = 'Diese Ausnahme hätte %s von %s Treffern der letzten %s Tage verhindert.';
$wb['preview_none_txt'] = 'In den letzten %s Tagen gab es keinen Treffer dieser Regel.';
$wb['param_label_txt'] = 'Parameter %s';
$wb['all_sites_txt'] = 'alle Websites';
```

`ispconfig/interface/lang/en_malwatch_waf.lng` (anhängen):

```php
$wb['lede_detect_none_txt'] = 'No website detects';
$wb['lede_detect_one_txt'] = 'One website detects';
$wb['lede_detect_many_txt'] = '%s websites detect';
$wb['lede_enforce_none_txt'] = 'none enforces';
$wb['lede_enforce_one_txt'] = 'one enforces';
$wb['lede_enforce_many_txt'] = '%s enforce';
$wb['lede_today_txt'] = 'Today %s hits';
$wb['lede_period_txt'] = 'In %s days %s hits';
$wb['lede_would_block_txt'] = ', %s of them would have been refused';
$wb['preview_txt'] = 'This exception would have prevented %s of %s hits in the last %s days.';
$wb['preview_none_txt'] = 'The last %s days brought no hit of this rule.';
$wb['param_label_txt'] = 'parameter %s';
$wb['all_sites_txt'] = 'all websites';
```

- [ ] **Schritt 4: Funktionen anhängen**

`ispconfig/interface/lib/malwatch_waf_panel.inc.php` (anhängen):

```php
// --- Views -------------------------------------------------------------------

/**
 * One entry per day of the period ending with $today, the rows (day, hits,
 * would_block) summed per day. $today is CURDATE() of the database.
 */
function waf_panel_day_series($rows, $today, $days)
{
	$sums = array();
	foreach ($rows as $row) {
		$day = (string) $row['day'];
		if (!isset($sums[$day])) {
			$sums[$day] = array(0, 0);
		}
		$sums[$day][0] += (int) $row['hits'];
		$sums[$day][1] += isset($row['would_block']) ? (int) $row['would_block'] : 0;
	}
	$date = DateTime::createFromFormat('!Y-m-d', (string) $today, new DateTimeZone('UTC'));
	if ($date === false || $date->format('Y-m-d') !== (string) $today) {
		return array();
	}
	$days = max(1, (int) $days);
	$date->modify('-' . ($days - 1) . ' days');
	$series = array();
	for ($i = 0; $i < $days; $i++) {
		$day = $date->format('Y-m-d');
		$series[] = array('day' => $day,
			'hits' => isset($sums[$day]) ? $sums[$day][0] : 0,
			'would_block' => isset($sums[$day]) ? $sums[$day][1] : 0);
		$date->modify('+1 day');
	}
	return $series;
}

/** The points of an SVG polyline for $values in a $width by $height box; the highest value reaches the top. */
function waf_panel_sparkline($values, $width, $height)
{
	$values = array_values($values);
	$count = count($values);
	if ($count === 0) {
		return '';
	}
	$max = max(1, max($values));
	$points = array();
	foreach ($values as $i => $value) {
		$x = $count === 1 ? $width : $i * $width / ($count - 1);
		$y = $height - ((int) $value / $max) * ($height - 1) - 0.5;
		$points[] = number_format($x, 1, '.', '') . ',' . number_format($y, 1, '.', '');
	}
	return implode(' ', $points);
}

/**
 * The rows and heading figures of the overview. $sites: web_domain joined
 * with malwatch_site; $pending: ids a queued or running job is changing;
 * $day_rows and $rule_rows: the period's figures. The counts cover every
 * website, the rows only those the filters let through.
 */
function waf_panel_overview($sites, $pending, $day_rows, $rule_rows, $wordpress, $today, $days, $filters)
{
	$by_site = array();
	foreach ($day_rows as $row) {
		$by_site[(int) $row['parent_domain_id']][] = $row;
	}
	$top = array();
	foreach ($rule_rows as $row) {
		$site = (int) $row['parent_domain_id'];
		if (!isset($top[$site]) || (int) $row['hits'] > $top[$site]['hits']) {
			$top[$site] = array('rule_id' => (string) $row['rule_id'], 'rule_msg' => (string) $row['rule_msg'], 'hits' => (int) $row['hits']);
		}
	}
	$counts = array('off' => 0, 'detect' => 0, 'enforce' => 0, 'pending' => 0, 'hits' => 0, 'would_block' => 0, 'sites_with_hits' => 0);
	$rows = array();
	foreach ($sites as $site) {
		$id = (int) $site['domain_id'];
		$state = waf_state_valid((string) $site['waf_state']) ? (string) $site['waf_state'] : 'off';
		$hits = 0;
		$block = 0;
		$values = array();
		foreach (waf_panel_day_series(isset($by_site[$id]) ? $by_site[$id] : array(), $today, $days) as $day) {
			$hits += $day['hits'];
			$block += $day['would_block'];
			$values[] = $day['hits'];
		}
		$is_pending = in_array($id, $pending, true) || (string) $site['waf_pending_state'] !== '';
		$counts[$state]++;
		$counts['pending'] += $is_pending ? 1 : 0;
		$counts['hits'] += $hits;
		$counts['would_block'] += $block;
		$counts['sites_with_hits'] += $hits > 0 ? 1 : 0;
		if (($filters['state'] !== '' && $filters['state'] !== $state)
			|| ($filters['wordpress'] && !in_array($id, $wordpress, true))
			|| ($filters['hits'] && $hits === 0)) {
			continue;
		}
		$rows[] = array(
			'domain_id' => $id,
			'domain' => (string) $site['domain'],
			'state' => $state,
			'since' => (string) $site['waf_state_since'],
			'pending' => $is_pending,
			'wordpress' => in_array($id, $wordpress, true),
			'hits' => $hits,
			'would_block' => $block,
			'values' => $values,
			'top_rule' => isset($top[$id]) ? $top[$id]['rule_id'] : '',
			'top_rule_msg' => isset($top[$id]) ? $top[$id]['rule_msg'] : '',
			'top_rule_hits' => isset($top[$id]) ? $top[$id]['hits'] : 0,
		);
	}
	usort($rows, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['domain'], $b['domain']);
	});
	return array('rows' => $rows, 'counts' => $counts);
}

/** The sentence above the overview. */
function waf_panel_lede($wb, $counts, $days)
{
	$detect = (int) $counts['detect'];
	$enforce = (int) $counts['enforce'];
	if ($detect === 0) {
		$first = waf_panel_text($wb, 'lede_detect_none_txt', '');
	} elseif ($detect === 1) {
		$first = waf_panel_text($wb, 'lede_detect_one_txt', '');
	} else {
		$first = sprintf(waf_panel_text($wb, 'lede_detect_many_txt', '%s'), number_format($detect, 0, ',', '.'));
	}
	if ($enforce === 0) {
		$second = waf_panel_text($wb, 'lede_enforce_none_txt', '');
	} elseif ($enforce === 1) {
		$second = waf_panel_text($wb, 'lede_enforce_one_txt', '');
	} else {
		$second = sprintf(waf_panel_text($wb, 'lede_enforce_many_txt', '%s'), number_format($enforce, 0, ',', '.'));
	}
	$hits = number_format((int) $counts['hits'], 0, ',', '.');
	$third = (int) $days === 1
		? sprintf(waf_panel_text($wb, 'lede_today_txt', '%s'), $hits)
		: sprintf(waf_panel_text($wb, 'lede_period_txt', '%s %s'), (int) $days, $hits);
	if ((int) $counts['would_block'] > 0) {
		$third .= sprintf(waf_panel_text($wb, 'lede_would_block_txt', '%s'), number_format((int) $counts['would_block'], 0, ',', '.'));
	}
	return $first . ', ' . $second . '. ' . $third . '.';
}

/** Period and filters of the overview from its query string. */
function waf_panel_filters($get, $stats_days)
{
	$state = isset($get['state']) ? (string) $get['state'] : '';
	return array(
		'days' => waf_period(isset($get['days']) ? $get['days'] : 7, $stats_days),
		'state' => waf_state_valid($state) ? $state : '',
		'wordpress' => !empty($get['wp']),
		'hits' => !empty($get['hits']),
	);
}

/** The overview's query string with some filters changed. */
function waf_panel_query($filters, $changes)
{
	$merged = array_merge($filters, $changes);
	$parts = array('days=' . (int) $merged['days']);
	if ($merged['state'] !== '') {
		$parts[] = 'state=' . rawurlencode($merged['state']);
	}
	if ($merged['wordpress']) {
		$parts[] = 'wp=1';
	}
	if ($merged['hits']) {
		$parts[] = 'hits=1';
	}
	return implode('&', $parts);
}

/**
 * The rules of one website over the period, the most hits first. $rows come
 * from malwatch_waf_day (day, rule_id, rule_msg, path, hits, would_block_hits).
 */
function waf_panel_rules($wb, $rows)
{
	$rules = array();
	foreach ($rows as $row) {
		$id = (string) $row['rule_id'];
		if (!isset($rules[$id])) {
			$rules[$id] = array('rule_id' => $id, 'msg' => '', 'hits' => 0, 'would_block' => 0, 'paths' => array(), 'last_day' => '');
		}
		$rules[$id]['hits'] += (int) $row['hits'];
		$rules[$id]['would_block'] += (int) $row['would_block_hits'];
		if ($rules[$id]['msg'] === '' && (string) $row['rule_msg'] !== '') {
			$rules[$id]['msg'] = (string) $row['rule_msg'];
		}
		if (strcmp((string) $row['day'], $rules[$id]['last_day']) > 0) {
			$rules[$id]['last_day'] = (string) $row['day'];
		}
		$path = (string) $row['path'];
		$rules[$id]['paths'][$path] = (isset($rules[$id]['paths'][$path]) ? $rules[$id]['paths'][$path] : 0) + (int) $row['hits'];
	}
	$list = array();
	foreach ($rules as $id => $rule) {
		$paths = $rule['paths'];
		uksort($paths, function ($a, $b) use ($paths) {
			return $paths[$a] !== $paths[$b] ? $paths[$b] - $paths[$a] : strcmp((string) $a, (string) $b);
		});
		$top = array();
		foreach (array_slice($paths, 0, 3, true) as $path => $hits) {
			$top[] = array('path' => (string) $path, 'hits' => $hits);
		}
		$rule['rule_id'] = (string) $id;
		$rule['paths'] = $top;
		$rule['path_count'] = count($paths);
		$rule['title'] = waf_panel_rule_title($wb, $id, $rule['msg']);
		$rule['can_except'] = waf_exception_check(array('scope' => 'site', 'parent_domain_id' => 1, 'rule_id' => (string) $id)) === '';
		$list[] = $rule;
	}
	usort($list, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['rule_id'], $b['rule_id']);
	});
	return $list;
}

/** The paths of one website over the period, the most hits first, with their rules. */
function waf_panel_paths($rows)
{
	$paths = array();
	foreach ($rows as $row) {
		$path = (string) $row['path'];
		if (!isset($paths[$path])) {
			$paths[$path] = array('path' => $path, 'hits' => 0, 'rules' => array());
		}
		$paths[$path]['hits'] += (int) $row['hits'];
		$rule = (string) $row['rule_id'];
		$paths[$path]['rules'][$rule] = (isset($paths[$path]['rules'][$rule]) ? $paths[$path]['rules'][$rule] : 0) + (int) $row['hits'];
	}
	$list = array();
	foreach ($paths as $entry) {
		arsort($entry['rules']);
		$entry['rules'] = array_map('strval', array_keys($entry['rules']));
		$list[] = $entry;
	}
	usort($list, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['path'], $b['path']);
	});
	return $list;
}

/**
 * One stored hit for the detail page. prefill is what the exception form
 * starts with: the first rule an exception may name, its parameter, the path.
 */
function waf_panel_hit($wb, $row)
{
	$rules = json_decode((string) $row['rules'], true);
	$headers = json_decode((string) $row['request_headers'], true);
	$list = array();
	$prefill = array('rule_id' => '', 'path' => (string) $row['path'], 'param' => '');
	foreach (is_array($rules) ? $rules : array() as $rule) {
		$id = isset($rule['id']) ? (string) $rule['id'] : '';
		$msg = isset($rule['msg']) ? (string) $rule['msg'] : '';
		$param = isset($rule['param']) ? (string) $rule['param'] : '';
		$list[] = array('rule_id' => $id, 'title' => waf_panel_rule_title($wb, $id, $msg), 'msg' => $msg,
			'data' => isset($rule['data']) ? (string) $rule['data'] : '', 'param' => $param);
		if ($prefill['rule_id'] === ''
			&& waf_exception_check(array('scope' => 'site', 'parent_domain_id' => 1, 'rule_id' => $id)) === '') {
			$prefill['rule_id'] = $id;
			$prefill['param'] = $param;
		}
	}
	$header_list = array();
	foreach (is_array($headers) ? $headers : array() as $name => $value) {
		$header_list[] = array('name' => (string) $name, 'value' => is_scalar($value) ? (string) $value : '');
	}
	$body = $row['request_body'] === null ? '' : (string) $row['request_body'];
	return array(
		'hit_id' => (int) $row['hit_id'],
		'seen_at' => (string) $row['seen_at'],
		'client_ip' => (string) $row['client_ip'],
		'method' => (string) $row['method'],
		'uri' => (string) $row['uri'],
		'status' => (int) $row['status'],
		'score' => (int) $row['anomaly_score'],
		'would_block' => (string) $row['would_block'] === 'y',
		'logged_in' => (string) $row['logged_in'] === 'y',
		'rules' => $list,
		'headers' => $header_list,
		'body' => $body,
		'has_body' => $body !== '',
		'has_response' => (string) $row['response_file'] !== '',
		'response_bytes' => (int) $row['response_bytes'],
		'prefill' => $prefill,
	);
}

/**
 * What enforce would have meant over the preview period, and whether its
 * button is free. $totals sums malwatch_waf_site_day (would_block,
 * would_block_logged_in); $rule_rows sums malwatch_waf_day per rule
 * (rule_id, rule_msg, would_block_hits) over the same days.
 */
function waf_panel_enforce($wb, $site, $totals, $rule_rows, $settings, $now)
{
	$state = is_array($site) && waf_state_valid((string) $site['waf_state']) ? (string) $site['waf_state'] : 'off';
	$since = is_array($site) ? $site['waf_state_since'] : null;
	$reason = waf_enforce_block_reason($state, $since, $now, $settings['waf_min_detect_days'], $settings['waf_emergency']);
	$rules = array();
	foreach ($rule_rows as $row) {
		if ((int) $row['would_block_hits'] > 0) {
			$rules[] = array('rule_id' => (string) $row['rule_id'],
				'title' => waf_panel_rule_title($wb, $row['rule_id'], $row['rule_msg']),
				'hits' => (int) $row['would_block_hits']);
		}
	}
	usort($rules, function ($a, $b) {
		return $a['hits'] !== $b['hits'] ? $b['hits'] - $a['hits'] : strcmp($a['rule_id'], $b['rule_id']);
	});
	return array(
		'state' => $state,
		'allowed' => $reason === '' && $state !== 'enforce',
		'reason' => $reason,
		'free_from' => $state === 'detect' ? waf_enforce_free_from($since, $settings['waf_min_detect_days']) : '',
		'would_block' => is_array($totals) ? (int) $totals['would_block'] : 0,
		'logged_in' => is_array($totals) ? (int) $totals['would_block_logged_in'] : 0,
		'rules' => $rules,
		'days' => (int) $settings['waf_preview_days'],
	);
}

/**
 * The exception the form describes, ready to store: path and parameter only
 * where the scope uses them, the website only for per-site scopes, the note
 * without control characters. Returns array(row, wrong field or '').
 */
function waf_panel_exception_input($post, $site_id)
{
	$scope = isset($post['exc_scope']) ? (string) $post['exc_scope'] : '';
	$with_path = in_array($scope, array('site_path', 'site_param', 'all_path'), true);
	$note = isset($post['exc_note']) ? (string) $post['exc_note'] : '';
	$row = array(
		'scope' => $scope,
		'parent_domain_id' => strpos($scope, 'site') === 0 ? (int) $site_id : 0,
		'rule_id' => isset($post['exc_rule']) ? trim((string) $post['exc_rule']) : '',
		'path' => $with_path && isset($post['exc_path']) ? trim((string) $post['exc_path']) : '',
		'param' => $scope === 'site_param' && isset($post['exc_param']) ? trim((string) $post['exc_param']) : '',
		'note' => waf_cut(trim(preg_replace('/[\x00-\x1F\x7F]+/', ' ', $note)), 255),
	);
	return array($row, waf_exception_check($row));
}

function waf_panel_preview_text($wb, $preview, $days)
{
	if ((int) $preview['total'] === 0) {
		return sprintf(waf_panel_text($wb, 'preview_none_txt', '%s'), (int) $days);
	}
	return sprintf(waf_panel_text($wb, 'preview_txt', '%s %s %s'),
		number_format((int) $preview['covered'], 0, ',', '.'), number_format((int) $preview['total'], 0, ',', '.'), (int) $days);
}

/** One WAF job for the pages: what it does, how it stands, the first line of its log. */
function waf_panel_job($wb, $row)
{
	$options = json_decode((string) $row['options'], true);
	$options = is_array($options) ? $options : array();
	$action = isset($options['action']) ? (string) $options['action'] : '';
	$label = $action === '' ? '' : waf_panel_job_label($wb, $action);
	if ($action === 'set_state' && isset($options['state'])) {
		$label .= ': ' . waf_panel_state_label($wb, (string) $options['state']);
	}
	$log = preg_split('/\R/', trim((string) $row['job_log']));
	return array(
		'job_id' => (int) $row['job_id'],
		'status' => (string) $row['job_status'],
		'status_label' => waf_panel_status_label($wb, (string) $row['job_status']),
		'label' => $label,
		'log' => (string) $log[0],
		'sites' => isset($options['domain_ids']) && is_array($options['domain_ids']) ? array_map('intval', $options['domain_ids']) : array(),
		'running' => in_array((string) $row['job_status'], array('pending', 'running'), true),
	);
}

/** One exception for the lists. Only active rows and rows in error may be removed. */
function waf_panel_exception_row($wb, $row)
{
	$scope = (string) $row['scope'];
	$target = array();
	if ((string) $row['path'] !== '') {
		$target[] = (string) $row['path'];
	}
	if ((string) $row['param'] !== '') {
		$target[] = sprintf(waf_panel_text($wb, 'param_label_txt', '%s'), (string) $row['param']);
	}
	$state = (string) $row['exception_state'];
	return array(
		'exception_id' => (int) $row['exception_id'],
		'rule_id' => (string) $row['rule_id'],
		'scope_label' => waf_panel_scope_label($wb, $scope),
		'site' => strpos($scope, 'site') === 0 ? (string) $row['domain'] : waf_panel_text($wb, 'all_sites_txt', ''),
		'site_id' => (int) $row['parent_domain_id'],
		'target' => implode(' · ', $target),
		'note' => (string) $row['note'],
		'state' => $state,
		'state_label' => waf_panel_exception_state_label($wb, $state),
		'error' => (string) $row['error_reason'],
		'created_by' => (string) $row['created_by'],
		'created_at' => (string) $row['created_at'],
		'can_remove' => in_array($state, array('active', 'error'), true),
	);
}
```

- [ ] **Schritt 5: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Schritt 6: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/tests/waf_panel_test.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): views for the overview and the website page" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B3: Aktionen, Aufträge als JSON, Vorschau, Seitenantwort

`waf_panel_handle_post()` führt jeden Knopf der Abwehr-Seiten aus und reiht die Aufträge
über das Datalog ein. `malwatch_waf_jobs.php` und `malwatch_waf_preview.php` liefern JSON
für die Skripte der Seiten, `malwatch_waf_response.php` die gespeicherte Seitenantwort als
Text. Die Aktionen und die Vorschau prüft ein Test mit einem Ersatz für die Datenbank des
Panels; die Seiten selbst prüft `render_pages.php` am Server (B9).

**Dateien:**
- Neu: `ispconfig/tests/waf_panel_post_test.php`
- Ändern: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (Funktionen anhängen)
- Ändern: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` (Zeilen anhängen)
- Neu: `ispconfig/interface/malwatch_waf_jobs.php`, `ispconfig/interface/malwatch_waf_preview.php`,
  `ispconfig/interface/malwatch_waf_response.php`
- Ändern: `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`,
  `ispconfig/tests/check_wiring.sh` (Prüfung 55), `.github/workflows/ci.yml`

**Schnittstellen:**
- Nutzt: B1, B2; `$app->db` (`queryOneRecord`, `queryAllRecords`, `query`, `insertID`,
  `datalogInsert`), `$app->functions->intval()`, `$_SESSION['s']['user']`
- Liefert:
  - `waf_panel_rows($result)` → Array
  - `waf_panel_settings($app)`, `waf_panel_clock($app)` → `array('now', 'today')`,
    `waf_panel_web_servers($app)` → Liste von server_id
  - `waf_panel_queue($app, $server_id, $action, $fields)` → job_id
  - `waf_panel_handle_post($app, $wb, $post)` → `array(meldung, fehler)`; Felder:
    `waf_action` (`state`, `emergency_on`, `emergency_off`, `response_body`,
    `exception_add`, `exception_remove`), `waf_target`, `waf_site`, `waf_pick[]`,
    `waf_mode`, `waf_exception`, `exc_site`, `exc_scope`, `exc_rule`, `exc_path`,
    `exc_param`, `exc_note`
  - `waf_panel_preview($app, $wb, $get)` → `array('valid', 'preview' => array('covered', 'total'), 'text')`;
    liest `id` und die `exc_*`-Felder
  - JSON `security/malwatch_waf_jobs.php?since=<job_id>` →
    `{"jobs": [waf_panel_job(...)], "running": n}`; JSON
    `security/malwatch_waf_preview.php?id=…&exc_scope=…` → Ergebnis von `waf_panel_preview()`;
    `security/malwatch_waf_response.php?hit=<hit_id>` → Text

- [ ] **Schritt 1: Test schreiben**

`ispconfig/tests/waf_panel_post_test.php`:

```php
<?php
/**
 * Checks what the buttons of the Abwehr pages queue, against a stand-in for
 * the panel's database that answers the few queries of the helpers.
 *
 *   php ispconfig/tests/waf_panel_post_test.php
 */
require __DIR__ . '/../interface/lib/malwatch_waf_panel.inc.php';
$wb = array();
include __DIR__ . '/../interface/lang/de_malwatch_waf.lng';

class waf_test_db
{
	public $writes = array();
	public $sites = array();
	public $exceptions = array();
	public $hits = array();
	public $days = array();
	private $next_id = 100;

	public function queryOneRecord($sql)
	{
		$args = array_slice(func_get_args(), 1);
		if (strpos($sql, 'FROM malwatch_config') !== false) {
			return array('waf_min_detect_days' => '7', 'waf_preview_days' => '7', 'waf_detail_days' => '7', 'waf_emergency' => 'n');
		}
		if (strpos($sql, 'NOW() AS now_at') !== false) {
			return array('now_at' => '2026-09-16 12:00:00', 'today' => '2026-09-16');
		}
		if (strpos($sql, 'FROM web_domain') !== false) {
			return isset($this->sites[(int) $args[0]]) ? $this->sites[(int) $args[0]] : null;
		}
		if (strpos($sql, 'FROM malwatch_waf_exception') !== false) {
			return isset($this->exceptions[(int) $args[0]]) ? $this->exceptions[(int) $args[0]] : null;
		}
		return null;
	}

	public function queryAllRecords($sql)
	{
		if (strpos($sql, 'FROM server') !== false) {
			return array(array('server_id' => '1'));
		}
		if (strpos($sql, 'FROM malwatch_waf_hit') !== false) {
			return $this->hits;
		}
		if (strpos($sql, 'FROM malwatch_waf_day') !== false) {
			return $this->days;
		}
		return array();
	}

	public function query($sql)
	{
		$this->writes[] = array('query' => $sql, 'args' => array_slice(func_get_args(), 1));
		return true;
	}

	public function insertID()
	{
		return ++$this->next_id;
	}

	public function datalogInsert($table, $data, $index_field)
	{
		$this->writes[] = array('datalog' => $table, 'data' => $data);
		return ++$this->next_id;
	}
}

class waf_test_functions
{
	public function intval($value)
	{
		return (int) $value;
	}
}

$app = new stdClass();
$app->functions = new waf_test_functions();
$_SESSION['s']['user'] = array('userid' => 1, 'default_group' => 1, 'username' => 'admin');

function fresh_db()
{
	global $app;
	$app->db = new waf_test_db();
	$app->db->sites = array(
		11 => array('domain_id' => '11', 'domain' => 'beispiel.test', 'server_id' => '1', 'waf_state' => 'detect', 'waf_state_since' => '2026-09-14 08:00:00'),
		12 => array('domain_id' => '12', 'domain' => 'zweite.test', 'server_id' => '1', 'waf_state' => 'detect', 'waf_state_since' => '2026-09-01 08:00:00'),
	);
	return $app->db;
}

/** The jobs a test queued: server, kind, options. */
function jobs_of($db)
{
	$jobs = array();
	foreach ($db->writes as $write) {
		if (isset($write['datalog'])) {
			$jobs[] = array($write['data']['server_id'], $write['data']['job_kind'], json_decode($write['data']['options'], true));
		}
	}
	return $jobs;
}

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$db = fresh_db();
expect_same('nothing pressed', waf_panel_handle_post($app, $wb, array()), array('', ''));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'an', 'waf_site' => '11'));
expect_same('odd state', array($result, jobs_of($db)), array(array('', $wb['err_state_txt']), array()));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'detect'));
expect_same('no website', $result, array('', $wb['err_no_site_txt']));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'detect', 'waf_pick' => array('11', '12', '11', '99')));
expect_same('detect queued', jobs_of($db), array(array(1, 'waf', array('domain_ids' => array(11, 12), 'state' => 'detect', 'action' => 'set_state', 'user' => 'admin'))));
expect_same('detect message', $result, array('Wechsel auf „mitschreiben“ eingereiht, Websites: 2. Übersprungen: 1 (nicht gefunden oder für „scharf“ noch nicht bereit).', ''));

$db = fresh_db();
waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'enforce', 'waf_pick' => array('11', '12')));
expect_same('enforce only where ready', jobs_of($db), array(array(1, 'waf', array('domain_ids' => array(12), 'state' => 'enforce', 'action' => 'set_state', 'user' => 'admin'))));

$db = fresh_db();
$db->sites[12]['waf_state_since'] = '2026-09-15 08:00:00';
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'state', 'waf_target' => 'enforce', 'waf_pick' => array('11', '12')));
expect_same('enforce nowhere ready', array($result, jobs_of($db)), array(array('', $wb['err_nothing_to_switch_txt']), array()));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'emergency_on'));
expect_same('emergency queued', array($result, jobs_of($db)), array(array($wb['msg_emergency_on_txt'], ''),
	array(array(1, 'waf', array('on' => true, 'hard' => false, 'action' => 'emergency', 'user' => 'admin')))));

$db = fresh_db();
waf_panel_handle_post($app, $wb, array('waf_action' => 'response_body', 'waf_mode' => 'lean'));
expect_same('lean queued', jobs_of($db), array(array(1, 'waf', array('mode' => 'lean', 'action' => 'response_body', 'user' => 'admin'))));
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'response_body', 'waf_mode' => 'halb'));
expect_same('odd mode', $result, array('', $wb['err_mode_txt']));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_site' => '11', 'exc_scope' => 'site_path',
	'exc_rule' => '942100', 'exc_path' => '/wp-admin/admin-ajax.php', 'exc_note' => 'Formular'));
$insert = $db->writes[0];
expect_same('exception stored', array(strpos($insert['query'], 'INSERT INTO malwatch_waf_exception') === 0, array_slice($insert['args'], 2, 8)),
	array(true, array(1, 'site_path', 11, 'beispiel.test', '942100', '/wp-admin/admin-ajax.php', '', 'Formular')));
expect_same('exception job', jobs_of($db), array(array(1, 'waf', array('exception_id' => 101, 'action' => 'exception_add', 'user' => 'admin'))));
expect_same('exception message', $result, array($wb['msg_exception_added_txt'], ''));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_site' => '11', 'exc_scope' => 'site', 'exc_rule' => '10010'));
expect_same('own rule refused', array($result, $db->writes), array(array('', $wb['reason_rule_id_txt']), array()));

$db = fresh_db();
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_site' => '77', 'exc_scope' => 'site', 'exc_rule' => '942100'));
expect_same('exception for a missing website', array($result, $db->writes), array(array('', $wb['err_no_site_txt']), array()));

$db = fresh_db();
waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_add', 'exc_scope' => 'all', 'exc_rule' => '941160'));
expect_same('exception for every website', jobs_of($db), array(array(1, 'waf', array('exception_id' => 101, 'action' => 'exception_add', 'user' => 'admin'))));

$db = fresh_db();
$db->exceptions[5] = array('exception_id' => '5', 'server_id' => '1', 'exception_state' => 'active');
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_remove', 'waf_exception' => '5'));
expect_same('exception removal', array($result, strpos($db->writes[0]['query'], "SET exception_state = 'removing'") !== false, jobs_of($db)),
	array(array($wb['msg_exception_removing_txt'], ''), true,
	array(array(1, 'waf', array('exception_id' => 5, 'action' => 'exception_remove', 'user' => 'admin')))));
$db = fresh_db();
$db->exceptions[6] = array('exception_id' => '6', 'server_id' => '1', 'exception_state' => 'pending');
$result = waf_panel_handle_post($app, $wb, array('waf_action' => 'exception_remove', 'waf_exception' => '6'));
expect_same('pending exception stays', array($result, $db->writes), array(array('', $wb['err_exception_txt']), array()));

$db = fresh_db();
expect_same('unknown button', waf_panel_handle_post($app, $wb, array('waf_action' => 'launch')), array('', $wb['err_unknown_action_txt']));

$db = fresh_db();
$db->days = array(
	array('parent_domain_id' => '11', 'rule_id' => '942100', 'path' => '/wp-admin/admin-ajax.php', 'hits' => '18'),
	array('parent_domain_id' => '11', 'rule_id' => '942100', 'path' => '/kontakt', 'hits' => '3'),
);
expect_same('preview of a path', waf_panel_preview($app, $wb, array('id' => '11', 'exc_scope' => 'site_path', 'exc_rule' => '942100', 'exc_path' => '/wp-admin/')),
	array('valid' => true, 'preview' => array('covered' => 18, 'total' => 21), 'text' => 'Diese Ausnahme hätte 18 von 21 Treffern der letzten 7 Tage verhindert.'));
$db->hits = array(
	array('parent_domain_id' => '11', 'path' => '/suche', 'rules' => '[{"id":"942100","param":"q"}]'),
	array('parent_domain_id' => '11', 'path' => '/suche', 'rules' => '[{"id":"942100","param":"s"},{"id":"949110","param":""}]'),
);
$preview = waf_panel_preview($app, $wb, array('id' => '11', 'exc_scope' => 'site_param', 'exc_rule' => '942100', 'exc_param' => 'q'));
expect_same('preview of a parameter', $preview['preview'], array('covered' => 1, 'total' => 2));
expect_same('preview of bad input', waf_panel_preview($app, $wb, array('id' => '11', 'exc_scope' => 'site', 'exc_rule' => 'x')),
	array('valid' => false, 'preview' => array('covered' => 0, 'total' => 0), 'text' => $wb['reason_rule_id_txt']));

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_panel_post: alle Prüfungen bestanden\n";
```

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

Run: `php ispconfig/tests/waf_panel_post_test.php`
Expected: Abbruch mit „Call to undefined function waf_panel_handle_post()"

- [ ] **Schritt 3: Texte anhängen**

`ispconfig/interface/lang/de_malwatch_waf.lng` (anhängen):

```php
$wb['err_state_txt'] = 'Unbekannter Zustand.';
$wb['err_no_site_txt'] = 'Bitte mindestens eine Website auswählen.';
$wb['err_nothing_to_switch_txt'] = 'Keine der gewählten Websites ist für diesen Zustand bereit.';
$wb['msg_state_queued_txt'] = 'Wechsel auf „%s“ eingereiht, Websites: %s.';
$wb['msg_state_skipped_txt'] = 'Übersprungen: %s (nicht gefunden oder für „scharf“ noch nicht bereit).';
$wb['msg_emergency_on_txt'] = 'Notaus eingereiht. Der Cron schaltet die Regeln ab und setzt scharfe Websites auf „mitschreiben“.';
$wb['msg_emergency_off_txt'] = 'Ende des Notaus eingereiht.';
$wb['err_mode_txt'] = 'Unbekannter Modus der Seitenantwort.';
$wb['msg_lean_txt'] = 'Umstellung auf die schlanke Seitenantwort eingereiht.';
$wb['msg_full_txt'] = 'Umstellung auf die vollständige Seitenantwort eingereiht.';
$wb['msg_exception_added_txt'] = 'Ausnahme angelegt. Der Cron übernimmt sie beim nächsten Durchgang.';
$wb['err_exception_txt'] = 'Diese Ausnahme lässt sich gerade nicht entfernen.';
$wb['msg_exception_removing_txt'] = 'Die Ausnahme wird entfernt.';
$wb['err_unknown_action_txt'] = 'Unbekannte Aktion.';
$wb['response_missing_txt'] = 'Die Seitenantwort liegt nicht mehr vor.';
$wb['response_broken_txt'] = 'Die Seitenantwort ließ sich nicht entpacken.';
```

`ispconfig/interface/lang/en_malwatch_waf.lng` (anhängen):

```php
$wb['err_state_txt'] = 'Unknown state.';
$wb['err_no_site_txt'] = 'Please choose at least one website.';
$wb['err_nothing_to_switch_txt'] = 'None of the chosen websites is ready for this state.';
$wb['msg_state_queued_txt'] = 'Switch to "%s" queued, websites: %s.';
$wb['msg_state_skipped_txt'] = 'Skipped: %s (not found or not ready for "enforce").';
$wb['msg_emergency_on_txt'] = 'Emergency stop queued. The cron switches the rules off and sets enforcing websites to "detect".';
$wb['msg_emergency_off_txt'] = 'End of the emergency stop queued.';
$wb['err_mode_txt'] = 'Unknown response body mode.';
$wb['msg_lean_txt'] = 'Switch to the lean response body queued.';
$wb['msg_full_txt'] = 'Switch to the full response body queued.';
$wb['msg_exception_added_txt'] = 'Exception added. The cron applies it with its next pass.';
$wb['err_exception_txt'] = 'This exception cannot be removed right now.';
$wb['msg_exception_removing_txt'] = 'The exception is being removed.';
$wb['err_unknown_action_txt'] = 'Unknown action.';
$wb['response_missing_txt'] = 'The response body is gone.';
$wb['response_broken_txt'] = 'The response body could not be unpacked.';
```

- [ ] **Schritt 4: Datenbankteil anhängen**

`ispconfig/interface/lib/malwatch_waf_panel.inc.php` (anhängen):

```php
// --- Database ----------------------------------------------------------------

function waf_panel_rows($result)
{
	return is_array($result) ? $result : array();
}

/** The WAF settings as the pages use them. */
function waf_panel_settings($app)
{
	return waf_settings($app->db->queryOneRecord('SELECT * FROM malwatch_config WHERE config_id = 1'));
}

/** NOW() and CURDATE() of the database, the clock every WAF date is written on. */
function waf_panel_clock($app)
{
	$row = $app->db->queryOneRecord('SELECT NOW() AS now_at, CURDATE() AS today');
	if (!is_array($row)) {
		return array('now' => date('Y-m-d H:i:s'), 'today' => date('Y-m-d'));
	}
	return array('now' => (string) $row['now_at'], 'today' => (string) $row['today']);
}

/** The web servers a job for every website goes to. */
function waf_panel_web_servers($app)
{
	$ids = array();
	foreach (waf_panel_rows($app->db->queryAllRecords(
		'SELECT server_id FROM server WHERE web_server = 1 AND active = 1 ORDER BY server_id')) as $row) {
		$ids[] = (int) $row['server_id'];
	}
	return $ids;
}

/** Queues a WAF job through the datalog, like every other job of the panel, and returns its id. */
function waf_panel_queue($app, $server_id, $action, $fields)
{
	$user = isset($_SESSION['s']['user']['username']) ? (string) $_SESSION['s']['user']['username'] : '';
	$clock = waf_panel_clock($app);
	return (int) $app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => $app->functions->intval($_SESSION['s']['user']['userid']),
		'sys_groupid' => $app->functions->intval($_SESSION['s']['user']['default_group']),
		'sys_perm_user' => 'riud',
		'sys_perm_group' => 'r',
		'sys_perm_other' => '',
		'server_id' => (int) $server_id,
		'parent_domain_id' => 0,
		'domain' => '',
		'scan_path' => '',
		'job_source' => 'manual',
		'job_kind' => 'waf',
		'job_status' => 'pending',
		'options' => waf_json(array_merge($fields, array('action' => (string) $action, 'user' => $user))),
		'created_at' => $clock['now'],
	), 'job_id');
}

/**
 * Carries out a button of the Abwehr pages; the page has checked the token.
 * Returns array(message, error), both plain text.
 */
function waf_panel_handle_post($app, $wb, $post)
{
	$action = isset($post['waf_action']) ? (string) $post['waf_action'] : '';
	if ($action === '') {
		return array('', '');
	}

	if ($action === 'state') {
		$state = isset($post['waf_target']) ? (string) $post['waf_target'] : '';
		if (!waf_state_valid($state)) {
			return array('', $wb['err_state_txt']);
		}
		$ids = array();
		if (isset($post['waf_site']) && (int) $post['waf_site'] > 0) {
			$ids[] = (int) $post['waf_site'];
		}
		if (isset($post['waf_pick']) && is_array($post['waf_pick'])) {
			foreach ($post['waf_pick'] as $id) {
				$ids[] = (int) $id;
			}
		}
		$ids = array_values(array_unique(array_filter($ids)));
		if (count($ids) === 0) {
			return array('', $wb['err_no_site_txt']);
		}
		$settings = waf_panel_settings($app);
		$clock = waf_panel_clock($app);
		$by_server = array();
		$skipped = 0;
		foreach ($ids as $id) {
			$row = $app->db->queryOneRecord(
				'SELECT w.domain_id, w.server_id, s.waf_state, s.waf_state_since FROM web_domain w '
				. "LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id WHERE w.domain_id = ? AND w.type = 'vhost'", $id);
			if (!is_array($row) || ($state === 'enforce' && waf_enforce_block_reason((string) $row['waf_state'],
				$row['waf_state_since'], $clock['now'], $settings['waf_min_detect_days'], $settings['waf_emergency']) !== '')) {
				$skipped++;
				continue;
			}
			$by_server[(int) $row['server_id']][] = $id;
		}
		$queued = 0;
		foreach ($by_server as $server_id => $site_ids) {
			waf_panel_queue($app, $server_id, 'set_state', array('domain_ids' => $site_ids, 'state' => $state));
			$queued += count($site_ids);
		}
		if ($queued === 0) {
			return array('', $wb['err_nothing_to_switch_txt']);
		}
		$message = sprintf($wb['msg_state_queued_txt'], waf_panel_state_label($wb, $state), number_format($queued, 0, ',', '.'));
		if ($skipped > 0) {
			$message .= ' ' . sprintf($wb['msg_state_skipped_txt'], number_format($skipped, 0, ',', '.'));
		}
		return array($message, '');
	}

	if ($action === 'emergency_on' || $action === 'emergency_off') {
		foreach (waf_panel_web_servers($app) as $server_id) {
			waf_panel_queue($app, $server_id, 'emergency', array('on' => $action === 'emergency_on', 'hard' => false));
		}
		return array($action === 'emergency_on' ? $wb['msg_emergency_on_txt'] : $wb['msg_emergency_off_txt'], '');
	}

	if ($action === 'response_body') {
		$mode = isset($post['waf_mode']) ? (string) $post['waf_mode'] : '';
		if (!waf_response_body_valid($mode)) {
			return array('', $wb['err_mode_txt']);
		}
		foreach (waf_panel_web_servers($app) as $server_id) {
			waf_panel_queue($app, $server_id, 'response_body', array('mode' => $mode));
		}
		return array($mode === 'lean' ? $wb['msg_lean_txt'] : $wb['msg_full_txt'], '');
	}

	if ($action === 'exception_add') {
		list($row, $wrong) = waf_panel_exception_input($post, isset($post['exc_site']) ? (int) $post['exc_site'] : 0);
		if ($wrong !== '') {
			return array('', waf_panel_reason_label($wb, $wrong));
		}
		$web = null;
		if ($row['parent_domain_id'] > 0) {
			$web = $app->db->queryOneRecord(
				"SELECT domain_id, domain, server_id FROM web_domain WHERE domain_id = ? AND type = 'vhost'", $row['parent_domain_id']);
			if (!is_array($web)) {
				return array('', $wb['err_no_site_txt']);
			}
		}
		$user = isset($_SESSION['s']['user']['username']) ? (string) $_SESSION['s']['user']['username'] : '';
		$clock = waf_panel_clock($app);
		foreach (is_array($web) ? array((int) $web['server_id']) : waf_panel_web_servers($app) as $server_id) {
			$app->db->query(
				'INSERT INTO malwatch_waf_exception (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, '
				. 'server_id, scope, parent_domain_id, domain, rule_id, path, param, note, exception_state, created_by, created_at) '
				. "VALUES (?, ?, 'riud', 'r', '', ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
				$app->functions->intval($_SESSION['s']['user']['userid']),
				$app->functions->intval($_SESSION['s']['user']['default_group']),
				$server_id, $row['scope'], $row['parent_domain_id'], is_array($web) ? (string) $web['domain'] : '',
				$row['rule_id'], $row['path'], $row['param'], $row['note'], waf_cut($user, 64), $clock['now']);
			waf_panel_queue($app, $server_id, 'exception_add', array('exception_id' => (int) $app->db->insertID()));
		}
		return array($wb['msg_exception_added_txt'], '');
	}

	if ($action === 'exception_remove') {
		$exception_id = isset($post['waf_exception']) ? (int) $post['waf_exception'] : 0;
		$row = $app->db->queryOneRecord(
			'SELECT exception_id, server_id, exception_state FROM malwatch_waf_exception WHERE exception_id = ?', $exception_id);
		if (!is_array($row) || !in_array((string) $row['exception_state'], array('active', 'error'), true)) {
			return array('', $wb['err_exception_txt']);
		}
		$app->db->query("UPDATE malwatch_waf_exception SET exception_state = 'removing' WHERE exception_id = ?", $exception_id);
		waf_panel_queue($app, (int) $row['server_id'], 'exception_remove', array('exception_id' => $exception_id));
		return array($wb['msg_exception_removing_txt'], '');
	}

	return array('', $wb['err_unknown_action_txt']);
}

/**
 * The preview of the exception a form describes. Day figures cover
 * waf_preview_days; a parameter needs single hits and reaches back no further
 * than they are kept.
 */
function waf_panel_preview($app, $wb, $get)
{
	$site_id = isset($get['id']) ? (int) $get['id'] : 0;
	list($row, $wrong) = waf_panel_exception_input($get, $site_id);
	if ($wrong !== '') {
		return array('valid' => false, 'preview' => array('covered' => 0, 'total' => 0), 'text' => waf_panel_reason_label($wb, $wrong));
	}
	$settings = waf_panel_settings($app);
	$days = $settings['waf_preview_days'];
	$items = array();
	if ($row['scope'] === 'site_param') {
		$days = min($days, $settings['waf_detail_days']);
		foreach (waf_panel_rows($app->db->queryAllRecords(
			'SELECT parent_domain_id, path, rules FROM malwatch_waf_hit WHERE parent_domain_id = ? '
			. 'AND seen_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', $site_id, $days)) as $hit) {
			$rules = json_decode((string) $hit['rules'], true);
			foreach (is_array($rules) ? $rules : array() as $rule) {
				if (isset($rule['id']) && (string) $rule['id'] === $row['rule_id']) {
					$items[] = array('parent_domain_id' => (int) $hit['parent_domain_id'], 'rule_id' => $row['rule_id'],
						'path' => (string) $hit['path'], 'hits' => 1,
						'params' => isset($rule['param']) && $rule['param'] !== '' ? array((string) $rule['param']) : array());
				}
			}
		}
	} else {
		$items = waf_panel_rows($app->db->queryAllRecords(
			'SELECT parent_domain_id, rule_id, path, SUM(hits) AS hits FROM malwatch_waf_day '
			. 'WHERE rule_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY parent_domain_id, rule_id, path',
			$row['rule_id'], $days - 1));
	}
	$preview = waf_exception_preview($items, $row);
	return array('valid' => true, 'preview' => $preview, 'text' => waf_panel_preview_text($wb, $preview, $days));
}
```

- [ ] **Schritt 5: Test laufen lassen, er muss bestehen**

Run: `php ispconfig/tests/waf_panel_post_test.php && php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel_post: alle Prüfungen bestanden`, `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 6: Die drei Seiten schreiben**

`ispconfig/interface/malwatch_waf_jobs.php`:

```php
<?php

/**
 * The WAF jobs for the Abwehr pages as JSON: every queued or running one, and
 * from the id in since= on the finished ones as well, so a page can show how
 * its jobs ended. No template: the caller reads JSON only.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	echo json_encode(array('state' => 'denied'));
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_waf_panel.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$since = $app->functions->intval(isset($_GET['since']) ? $_GET['since'] : 0);
$jobs = array();
$running = 0;
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND (job_status IN ('pending','running') OR (? > 0 AND job_id >= ?)) ORDER BY job_id", $since, $since)) as $row) {
	$job = waf_panel_job($wb, $row);
	$running += $job['running'] ? 1 : 0;
	$jobs[] = $job;
}
echo json_encode(array('jobs' => $jobs, 'running' => $running));
```

`ispconfig/interface/malwatch_waf_preview.php`:

```php
<?php

/**
 * The preview of an exception as JSON, for the form on the page of a
 * website: how many hits of the period it would have prevented.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	echo json_encode(array('state' => 'denied'));
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_waf_panel.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

echo json_encode(waf_panel_preview($app, $wb, $_GET));
```

`ispconfig/interface/malwatch_waf_response.php`:

```php
<?php

/**
 * The stored response of one hit, as plain text. It is what a website sent
 * back to an attacker's request, so the panel never renders it as HTML: the
 * type is text/plain, the browser may not sniff another one, and a content
 * security policy blocks everything a page could load.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	header('HTTP/1.1 403 Forbidden');
	exit;
}

$app->uses('functions');
require_once 'lib/malwatch_lib.inc.php';

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'");
header('Content-Disposition: inline');
header('Cache-Control: no-store');

$hit_id = $app->functions->intval(isset($_GET['hit']) ? $_GET['hit'] : 0);
$row = $hit_id > 0 ? $app->db->queryOneRecord('SELECT response_file FROM malwatch_waf_hit WHERE hit_id = ?', $hit_id) : null;
$name = is_array($row) ? basename((string) $row['response_file']) : '';
$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/waf/responses/' . $name;
if (!preg_match('/^[A-Za-z0-9._-]+\.html\.gz$/', $name) || !is_file($file)) {
	header('HTTP/1.1 404 Not Found');
	echo $wb['response_missing_txt'], "\n";
	exit;
}
$text = gzdecode((string) file_get_contents($file));
if ($text === false) {
	echo $wb['response_broken_txt'], "\n";
	exit;
}
echo $text;
```

- [ ] **Schritt 7: Eintragen, Prüfung 55, CI**

In `ispconfig/install/file.list` nach der Zeile
`c:interface/malwatch_dump_download.php:interface/web/security/malwatch_dump_download.php`:

```text
c:interface/malwatch_waf_jobs.php:interface/web/security/malwatch_waf_jobs.php
c:interface/malwatch_waf_preview.php:interface/web/security/malwatch_waf_preview.php
c:interface/malwatch_waf_response.php:interface/web/security/malwatch_waf_response.php
```

In `ispconfig/tests/render_pages.php` am Ende der Liste `$pages` (nach
`'malwatch_dump_databases.php',`):

```php
	// JSON of the WAF jobs and of an exception preview on the website the run picked.
	'malwatch_waf_jobs.php',
	'malwatch_waf_preview.php?exc_scope=site&exc_rule=942100',
```

und in `$mw_json` nach der Zeile für `malwatch_dump_databases.php`:

```php
	'malwatch_waf_jobs.php' => array('key' => 'jobs', 'least' => 0, 'what' => 'jobs'),
	'malwatch_waf_preview.php' => array('key' => 'preview', 'least' => 2, 'what' => 'figures'),
```

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 55. Die Seiten der Abwehr pruefen die Administratorrechte selbst, und die
#     Seitenantwort geht nur als Text hinaus: sie ist die Antwort auf die
#     Anfrage eines Angreifers und laeuft im Panel nie als HTML.
for page in "$root"/interface/malwatch_waf_*.php; do
	[ -f "$page" ] || continue
	grep -q 'is_admin()' "$page" || fail "$(basename "$page") prueft die Administratorrechte nicht"
done
response_page="$root/interface/malwatch_waf_response.php"
if [ -f "$response_page" ]; then
	for header in 'Content-Type: text/plain' 'X-Content-Type-Options: nosniff' "Content-Security-Policy: default-src 'none'"; do
		grep -qF "$header" "$response_page" || fail "malwatch_waf_response.php sendet $header nicht"
	done
	grep -q 'basename(' "$response_page" || fail "malwatch_waf_response.php nimmt den Dateinamen ungeprueft"
else
	fail "interface/malwatch_waf_response.php fehlt"
fi
```

In `.github/workflows/ci.yml` nach dem Schritt „WAF page helpers":

```yaml
      - name: WAF page actions
        run: php ispconfig/tests/waf_panel_post_test.php
```

- [ ] **Schritt 8: Prüfen**

Run: `php -l ispconfig/interface/malwatch_waf_jobs.php && php -l ispconfig/interface/malwatch_waf_preview.php && php -l ispconfig/interface/malwatch_waf_response.php && php -l ispconfig/tests/render_pages.php`
Expected: viermal `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

- [ ] **Schritt 9: Commit**

```bash
git add ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/tests/waf_panel_post_test.php ispconfig/interface/malwatch_waf_jobs.php ispconfig/interface/malwatch_waf_preview.php ispconfig/interface/malwatch_waf_response.php ispconfig/install/file.list ispconfig/tests/render_pages.php ispconfig/tests/check_wiring.sh .github/workflows/ci.yml
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): buttons, job and preview JSON, response body as text" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B4: Übersicht `malwatch_waf_list.php`

Die Einstiegsseite der Abwehr: Kopfsatz, rotes Band beim Notaus, Knöpfe für Notaus und
Seitenantwort, Zeitraum und Filter, alle aktiven Websites mit Zustand, Treffern samt
Verlaufslinie, „wäre abgewiesen" und häufigster Regel, Mehrfachauswahl für den
Zustandswechsel, laufende und letzte Aufträge. Dazu der Menüpunkt.

**Dateien:**
- Neu: `ispconfig/interface/malwatch_waf_list.php`, `ispconfig/interface/templates/malwatch_waf_list.htm`
- Ändern: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` (Zeilen anhängen)
- Ändern: `ispconfig/interface/module.conf.php`, `ispconfig/install/file.list`,
  `ispconfig/tests/render_pages.php`, `ispconfig/tests/check_wiring.sh` (Prüfung 56)

**Schnittstellen:**
- Nutzt: `waf_panel_handle_post()`, `waf_panel_settings()`, `waf_panel_clock()`,
  `waf_panel_filters()`, `waf_panel_query()`, `waf_panel_overview()`, `waf_panel_lede()`,
  `waf_panel_sparkline()`, `waf_panel_job()`, `waf_panel_rows()`, `waf_periods()`,
  `waf_panel_state_label()`, `waf_panel_rule_title()`, `malwatch_datetime()`,
  `malwatch_attr_texts()`
- Liefert: die Seite `security/malwatch_waf_list.php?days=&state=&wp=&hits=`; sie verlinkt
  `security/malwatch_waf_show.php?id=<domain_id>` (B5),
  `security/malwatch_waf_exception_list.php` (B6) und
  `security/malwatch_waf_config_edit.php` (B7)

- [ ] **Schritt 1: Prüfung schreiben**

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 56. Die Abwehr steht im Menue, und die Uebersicht verfolgt laufende
#     Auftraege ueber malwatch_waf_jobs.php; neu geladen wird sie erst, wenn
#     keiner mehr laeuft.
grep -q "'link'    => 'security/malwatch_waf_list.php'" "$root/interface/module.conf.php" \
	|| fail "module.conf.php fuehrt die Abwehr nicht im Menue"
if [ -f "$root/interface/templates/malwatch_waf_list.htm" ]; then
	grep -q 'data-mw-jobs="security/malwatch_waf_jobs.php' "$root/interface/templates/malwatch_waf_list.htm" \
		|| fail "malwatch_waf_list.htm fragt die laufenden Auftraege nicht ab"
else
	fail "interface/templates/malwatch_waf_list.htm fehlt"
fi
```

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: module.conf.php fuehrt die Abwehr nicht im Menue` und
`FAIL: interface/templates/malwatch_waf_list.htm fehlt`

- [ ] **Schritt 2: Texte anhängen**

`ispconfig/interface/lang/de_malwatch_waf.lng` (anhängen):

```php
$wb['sub_txt'] = 'Die WAF prüft jede Anfrage einer eingeschalteten Website gegen das OWASP-Regelwerk. „mitschreiben“ hält Treffer fest, „scharf“ weist Anfragen über der Punktgrenze ab.';
$wb['emergency_since_txt'] = 'Notaus aktiv seit %s. Die Regeln prüfen nicht.';
$wb['btn_emergency_on_txt'] = 'Notaus';
$wb['btn_emergency_off_txt'] = 'Notaus beenden';
$wb['confirm_emergency_on_txt'] = 'Die Regeln werden auf allen Websites abgeschaltet, scharfe Websites wechseln auf „mitschreiben“. nginx lädt dafür neu.';
$wb['confirm_emergency_off_txt'] = 'Die Regeln prüfen danach wieder. Websites, die vorher scharf waren, bleiben auf „mitschreiben“.';
$wb['response_title_txt'] = 'Seitenantwort im Audit-Log';
$wb['response_full_btn_txt'] = 'Seitenantwort: vollständig';
$wb['response_lean_btn_txt'] = 'Seitenantwort: schlank';
$wb['response_to_lean_txt'] = 'Auf schlank umstellen';
$wb['response_to_full_txt'] = 'Auf vollständig umstellen';
$wb['confirm_lean_txt'] = 'Treffer halten danach Regeln, Kopfzeilen und Anfrageinhalt fest, die Seitenantwort entfällt. Ein Eintrag wiegt dann rund 4 KB.';
$wb['confirm_full_txt'] = 'Treffer halten danach auch die Seitenantwort fest, soweit das Regelwerk sie anfordert. Ein Eintrag wiegt dann bis zu rund 125 KB.';
$wb['jobs_head_txt'] = 'Aufträge in Arbeit';
$wb['recent_head_txt'] = 'Letzte Aufträge';
$wb['period_txt'] = 'Zeitraum';
$wb['period_today_txt'] = 'heute';
$wb['period_days_txt'] = '%s Tage';
$wb['filter_state_txt'] = 'Zustand';
$wb['filter_all_txt'] = 'alle';
$wb['filter_wordpress_txt'] = 'WordPress';
$wb['filter_hits_txt'] = 'mit Treffern';
$wb['exceptions_link_txt'] = 'Ausnahmen (%s)';
$wb['exceptions_errors_txt'] = 'Ausnahmen (%s, davon %s mit Fehler)';
$wb['settings_link_txt'] = 'Einstellungen';
$wb['select_all_txt'] = 'Alle';
$wb['invert_txt'] = 'Auswahl umkehren';
$wb['selected_template_txt'] = '{n} von %s ausgewählt';
$wb['selected_none_txt'] = 'Keine Website ausgewählt';
$wb['col_site_txt'] = 'Website';
$wb['col_state_txt'] = 'Zustand';
$wb['col_hits_txt'] = 'Treffer';
$wb['col_block_txt'] = 'wäre abgewiesen';
$wb['col_rule_txt'] = 'häufigste Regel';
$wb['since_txt'] = 'seit %s';
$wb['btn_view_txt'] = 'Ansehen';
$wb['bulk_txt'] = 'Ausgewählte Websites:';
$wb['hint_select_txt'] = 'Bitte zuerst mindestens eine Website anhaken.';
$wb['btn_bulk_detect_txt'] = 'mitschreiben';
$wb['btn_bulk_enforce_txt'] = 'scharf';
$wb['btn_bulk_off_txt'] = 'aus';
$wb['confirm_bulk_detect_txt'] = 'Die angehakten Websites schreiben danach mit. ISPConfig schreibt dafür ihre vhosts neu.';
$wb['confirm_bulk_enforce_txt'] = 'Die angehakten Websites weisen danach Anfragen über der Punktgrenze ab. Websites, die noch nicht lange genug mitschreiben, bleiben unverändert.';
$wb['confirm_bulk_off_txt'] = 'Die WAF wird für die angehakten Websites abgeschaltet.';
$wb['empty_txt'] = 'Für diese Auswahl gibt es keine Website.';
$wb['footnote_head_txt'] = 'So arbeitet die Seite:';
$wb['footnote_txt'] = 'Jeder Knopf legt einen Auftrag an. Der malwatch-Cron führt ihn aus, wartet bei einem Zustandswechsel auf den vhost von ISPConfig und prüft nginx, bevor er den neuen Stand bestätigt.';
```

`ispconfig/interface/lang/en_malwatch_waf.lng` (anhängen):

```php
$wb['sub_txt'] = 'The WAF checks every request of an enabled website against the OWASP rule set. "detect" records hits, "enforce" refuses requests above the score limit.';
$wb['emergency_since_txt'] = 'Emergency stop active since %s. The rules do not check.';
$wb['btn_emergency_on_txt'] = 'Emergency stop';
$wb['btn_emergency_off_txt'] = 'End emergency stop';
$wb['confirm_emergency_on_txt'] = 'The rules are switched off for every website, enforcing websites change to "detect". nginx reloads for this.';
$wb['confirm_emergency_off_txt'] = 'The rules check again afterwards. Websites that enforced before stay on "detect".';
$wb['response_title_txt'] = 'Response body in the audit log';
$wb['response_full_btn_txt'] = 'Response body: full';
$wb['response_lean_btn_txt'] = 'Response body: lean';
$wb['response_to_lean_txt'] = 'Switch to lean';
$wb['response_to_full_txt'] = 'Switch to full';
$wb['confirm_lean_txt'] = 'Hits then keep rules, headers and request body; the response body is left out. An entry weighs about 4 KB.';
$wb['confirm_full_txt'] = 'Hits then keep the response body as well where the rule set asks for it. An entry weighs up to about 125 KB.';
$wb['jobs_head_txt'] = 'Jobs in progress';
$wb['recent_head_txt'] = 'Recent jobs';
$wb['period_txt'] = 'Period';
$wb['period_today_txt'] = 'today';
$wb['period_days_txt'] = '%s days';
$wb['filter_state_txt'] = 'State';
$wb['filter_all_txt'] = 'all';
$wb['filter_wordpress_txt'] = 'WordPress';
$wb['filter_hits_txt'] = 'with hits';
$wb['exceptions_link_txt'] = 'Exceptions (%s)';
$wb['exceptions_errors_txt'] = 'Exceptions (%s, %s with errors)';
$wb['settings_link_txt'] = 'Settings';
$wb['select_all_txt'] = 'All';
$wb['invert_txt'] = 'Invert selection';
$wb['selected_template_txt'] = '{n} of %s selected';
$wb['selected_none_txt'] = 'No website selected';
$wb['col_site_txt'] = 'Website';
$wb['col_state_txt'] = 'State';
$wb['col_hits_txt'] = 'Hits';
$wb['col_block_txt'] = 'would be refused';
$wb['col_rule_txt'] = 'most frequent rule';
$wb['since_txt'] = 'since %s';
$wb['btn_view_txt'] = 'View';
$wb['bulk_txt'] = 'Selected websites:';
$wb['hint_select_txt'] = 'Please tick at least one website first.';
$wb['btn_bulk_detect_txt'] = 'detect';
$wb['btn_bulk_enforce_txt'] = 'enforce';
$wb['btn_bulk_off_txt'] = 'off';
$wb['confirm_bulk_detect_txt'] = 'The ticked websites detect afterwards. ISPConfig rewrites their vhosts for this.';
$wb['confirm_bulk_enforce_txt'] = 'The ticked websites refuse requests above the score limit afterwards. Websites that have not been detecting long enough stay as they are.';
$wb['confirm_bulk_off_txt'] = 'The WAF is switched off for the ticked websites.';
$wb['empty_txt'] = 'No website matches this selection.';
$wb['footnote_head_txt'] = 'How this page works:';
$wb['footnote_txt'] = 'Every button creates a job. The malwatch cron carries it out, waits for the ISPConfig vhost when a state changes and checks nginx before it confirms the new state.';
```

- [ ] **Schritt 3: Seite schreiben**

`ispconfig/interface/malwatch_waf_list.php`:

```php
<?php

/**
 * Abwehr: the WAF of every website at a glance.
 *
 * States, the hits of the chosen period with a small curve per day, the rule
 * each website sees most, the emergency stop and the response body switch.
 * The buttons queue jobs; the malwatch cron carries them out (malwatch_waf),
 * and the page follows them through malwatch_waf_jobs.php.
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

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

$settings = waf_panel_settings($app);
$clock = waf_panel_clock($app);
// After a button the filters come back as hidden fields of the form.
$filters = waf_panel_filters(array_merge($_GET, $_POST), $settings['waf_stats_days']);

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_list.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_emergency_on_txt', 'btn_emergency_off_txt',
	'confirm_emergency_on_txt', 'confirm_emergency_off_txt', 'response_title_txt', 'hint_select_txt',
	'btn_bulk_detect_txt', 'btn_bulk_enforce_txt', 'btn_bulk_off_txt',
	'confirm_bulk_detect_txt', 'confirm_bulk_enforce_txt', 'confirm_bulk_off_txt')));

$sites = waf_panel_rows($app->db->queryAllRecords(
	'SELECT w.domain_id, w.domain, s.waf_state, s.waf_state_since, s.waf_pending_state FROM web_domain w '
	. "LEFT JOIN malwatch_site s ON s.parent_domain_id = w.domain_id WHERE w.type = 'vhost' AND w.active = 'y' ORDER BY w.domain"));
$day_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT parent_domain_id, day, hits, would_block FROM malwatch_waf_site_day '
	. 'WHERE day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $filters['days'] - 1));
$rule_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT parent_domain_id, rule_id, MAX(rule_msg) AS rule_msg, SUM(hits) AS hits FROM malwatch_waf_day '
	. 'WHERE day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY parent_domain_id, rule_id', $filters['days'] - 1));
$wordpress = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT DISTINCT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND software_kind = 'core'")) as $row) {
	$wordpress[] = (int) $row['parent_domain_id'];
}

// Queued and running jobs: their websites show "wird umgesetzt", and the
// script follows them from the first one on.
$pending = array();
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	$pending = array_merge($pending, $job['sites']);
	if ($first_job === 0) {
		$first_job = $job['job_id'];
	}
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);

$recent_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('done','error') ORDER BY job_id DESC LIMIT 3")) as $row) {
	$job = waf_panel_job($wb, $row);
	$recent_rows[] = array(
		'job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']
			. ($job['log'] !== '' ? ' – ' . $job['log'] : '')),
		'job_failed' => $job['status'] === 'error' ? 1 : 0,
	);
}
$app->tpl->setLoop('recent', $recent_rows);
$app->tpl->setVar('has_recent', count($recent_rows) > 0 ? 1 : 0);

$overview = waf_panel_overview($sites, $pending, $day_rows, $rule_rows, $wordpress, $clock['today'], $filters['days'], $filters);
$app->tpl->setVar('lede', $app->functions->htmlentities(waf_panel_lede($wb, $overview['counts'], $filters['days'])));

$rows = array();
foreach ($overview['rows'] as $row) {
	$rows[] = array(
		'domain_id' => $row['domain_id'],
		'domain' => $app->functions->htmlentities($row['domain']),
		'state_class' => $row['state'],
		'state_label' => $app->functions->htmlentities(waf_panel_state_label($wb, $row['state'])),
		'is_pending' => $row['pending'] ? 1 : 0,
		'since_label' => $row['since'] !== '' && $row['state'] !== 'off'
			? $app->functions->htmlentities(sprintf($wb['since_txt'], malwatch_datetime($row['since']))) : '',
		'hits' => number_format($row['hits'], 0, ',', '.'),
		'would_block' => number_format($row['would_block'], 0, ',', '.'),
		'has_block' => $row['would_block'] > 0 ? 1 : 0,
		'spark' => $filters['days'] > 1 ? waf_panel_sparkline($row['values'], 64, 18) : '',
		'top_rule' => $row['top_rule'] === '' ? ''
			: $app->functions->htmlentities(waf_panel_rule_title($wb, $row['top_rule'], $row['top_rule_msg'])),
		'top_rule_id' => $app->functions->htmlentities($row['top_rule']),
		'is_wordpress' => $row['wordpress'] ? 1 : 0,
	);
}
$app->tpl->setLoop('rows', $rows);
$app->tpl->setVar('has_rows', count($rows) > 0 ? 1 : 0);
$app->tpl->setVar('selected_template', $app->functions->htmlentities(
	sprintf($wb['selected_template_txt'], number_format(count($rows), 0, ',', '.'))));
$app->tpl->setVar('selected_none', $app->functions->htmlentities($wb['selected_none_txt']));

$link = 'security/malwatch_waf_list.php?';
$periods = array();
foreach (waf_periods($settings['waf_stats_days']) as $days) {
	$periods[] = array(
		'label' => $app->functions->htmlentities($days === 1 ? $wb['period_today_txt'] : sprintf($wb['period_days_txt'], $days)),
		'href' => $app->functions->htmlentities($link . waf_panel_query($filters, array('days' => $days))),
		'current' => $days === $filters['days'] ? 1 : 0,
	);
}
$app->tpl->setLoop('periods', $periods);
$state_links = array();
foreach (array('', 'off', 'detect', 'enforce') as $state) {
	$state_links[] = array(
		'label' => $app->functions->htmlentities($state === '' ? $wb['filter_all_txt'] : waf_panel_state_label($wb, $state)),
		'href' => $app->functions->htmlentities($link . waf_panel_query($filters, array('state' => $state))),
		'current' => $state === $filters['state'] ? 1 : 0,
	);
}
$app->tpl->setLoop('state_links', $state_links);
$app->tpl->setVar('wp_href', $app->functions->htmlentities($link . waf_panel_query($filters, array('wordpress' => !$filters['wordpress']))));
$app->tpl->setVar('hits_href', $app->functions->htmlentities($link . waf_panel_query($filters, array('hits' => !$filters['hits']))));
$app->tpl->setVar('self_href', $app->functions->htmlentities($link . waf_panel_query($filters, array())));
$app->tpl->setVar('days', $filters['days']);
$app->tpl->setVar('filter_state', $app->functions->htmlentities($filters['state']));
$app->tpl->setVar('filter_wp', $filters['wordpress'] ? 1 : 0);
$app->tpl->setVar('filter_hits', $filters['hits'] ? 1 : 0);

$app->tpl->setVar('emergency', $settings['waf_emergency'] === 'y' ? 1 : 0);
$app->tpl->setVar('emergency_line', $app->functions->htmlentities(
	sprintf($wb['emergency_since_txt'], malwatch_datetime($settings['waf_emergency_since']))));
$lean = $settings['waf_response_body'] === 'lean';
$app->tpl->setVar('response_button', $app->functions->htmlentities($lean ? $wb['response_lean_btn_txt'] : $wb['response_full_btn_txt']));
$app->tpl->setVar('response_ok', $app->functions->htmlentities($lean ? $wb['response_to_full_txt'] : $wb['response_to_lean_txt']));
$app->tpl->setVar('response_confirm', $app->functions->htmlentities($lean ? $wb['confirm_full_txt'] : $wb['confirm_lean_txt']));
$app->tpl->setVar('response_target', $lean ? 'full' : 'lean');

$exceptions = $app->db->queryOneRecord(
	"SELECT COUNT(*) AS n, COALESCE(SUM(exception_state = 'error'), 0) AS errors FROM malwatch_waf_exception");
$exception_count = is_array($exceptions) ? (int) $exceptions['n'] : 0;
$exception_errors = is_array($exceptions) ? (int) $exceptions['errors'] : 0;
$app->tpl->setVar('exceptions_link', $app->functions->htmlentities($exception_errors > 0
	? sprintf($wb['exceptions_errors_txt'], $exception_count, $exception_errors)
	: sprintf($wb['exceptions_link_txt'], $exception_count)));

$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_waf_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
```

- [ ] **Schritt 4: Vorlage schreiben**

`ispconfig/interface/templates/malwatch_waf_list.htm`:

```html
<div class='page-header'>
	<h1>{tmpl_var name='lede'}</h1>
</div>

<tmpl_if name="message">
	<div class="alert alert-success">{tmpl_var name='message'}</div>
</tmpl_if>
<tmpl_if name="error">
	<div class="alert alert-danger">{tmpl_var name='error'}</div>
</tmpl_if>

<style>
/* The rules of the other pages of the addon: muted text through opacity,
   lines and areas as translucent grey, so the light and the dark theme stay
   readable. Fixed colours only for accent and alarm. */
#mw-waf .mw-sub{margin:6px 0 14px;opacity:.72;font-size:13px;max-width:80ch}
#mw-waf .mw-alarm{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:0 0 14px;padding:10px 14px;
	border-radius:3px;background:var(--cic-bad-deep,#b13116);color:#fff;font-weight:600}
#mw-waf .mw-bar{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;justify-content:space-between;margin:0 0 12px}
#mw-waf .mw-group{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
#mw-waf .mw-caption{font-size:12px;opacity:.72;margin-right:4px}
#mw-waf .mw-seg{display:inline-block;padding:3px 9px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-radius:3px;font-size:12.5px;color:inherit;text-decoration:none}
#mw-waf .mw-seg[aria-current="true"]{border-color:var(--cic-accent,#dd630d);color:var(--cic-accent-text,#dd630d);font-weight:600}
#mw-waf .mw-seg:focus-visible{outline:2px solid var(--cic-accent,#dd630d);outline-offset:2px}
#mw-waf .mw-actions{display:flex;flex-wrap:wrap;gap:8px}
#mw-waf .mw-actions .btn{white-space:nowrap}
#mw-waf .table-wrapper{overflow-x:auto}
#mw-waf .table{table-layout:auto}
#mw-waf .table > thead > tr > th,
#mw-waf .table > tbody > tr > td{padding:6px 10px;vertical-align:middle}
#mw-waf td.num{font-variant-numeric:tabular-nums;white-space:nowrap;text-align:right}
#mw-waf th.num{text-align:right}
#mw-waf .mw-hitcell{display:flex;align-items:center;justify-content:flex-end;gap:8px}
#mw-waf .mw-domain{font-weight:600;word-break:break-word}
#mw-waf .mw-dim{opacity:.72;font-size:12px}
#mw-waf .mw-chip{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
	padding:2px 7px;border-radius:3px;white-space:nowrap;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35))}
#mw-waf .mw-chip.off{opacity:.7}
#mw-waf .mw-chip.detect{border-color:var(--cic-accent-deep,#a84c0b);color:var(--cic-accent-text,#dd630d)}
#mw-waf .mw-chip.enforce{background:var(--cic-bad-deep,#b13116);border-color:var(--cic-bad-deep,#b13116);color:#fff}
#mw-waf .mw-chip.pending{border-style:dashed}
#mw-waf .mw-chips{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
#mw-waf .mw-spark{display:block;flex:none;color:var(--cic-accent,#dd630d)}
#mw-waf .mw-block{color:var(--cic-bad-text,#d13f22);font-weight:600}
#mw-waf .mw-jobs{margin:0 0 14px;padding:10px 14px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-left:3px solid var(--cic-accent,#dd630d);border-radius:3px;font-size:13px}
#mw-waf .mw-jobs ul{margin:4px 0 0;padding-left:18px}
#mw-waf .mw-failed{color:var(--cic-bad-text,#d13f22)}
#mw-waf .mw-quiet{margin-top:14px;padding:12px 15px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-radius:3px;opacity:.85;font-size:13px;background:var(--cic-head,rgba(128,128,128,.07))}
#mw-waf .mw-quiet ul{margin:4px 0 0;padding-left:18px}
#mw-waf input[type=checkbox]{accent-color:var(--cic-accent,#dd630d)}
#mw-waf .mw-selcount{font-size:13px;opacity:.72;font-variant-numeric:tabular-nums}
#mw-waf .mw-selectbar + .table-wrapper{margin-top:8px}
</style>

<div id="mw-waf" data-mw-selection data-mw-jobs="security/malwatch_waf_jobs.php?since={tmpl_var name='first_job'}" data-mw-self="{tmpl_var name='self_href'}">

<p class="mw-sub">{tmpl_var name='sub_txt'}</p>

<!--
	No form of our own: the panel wraps the content area in pageForm and posts
	it by AJAX. waf_action names the button, waf_target and waf_mode what it
	switches to; the filter fields keep the view after a click.
-->
<input type="hidden" name="waf_action" id="mw-waf-action" value="" />
<input type="hidden" name="waf_target" id="mw-waf-target" value="" />
<input type="hidden" name="waf_mode" id="mw-waf-mode" value="" />
<input type="hidden" name="days" value="{tmpl_var name='days'}" />
<input type="hidden" name="state" value="{tmpl_var name='filter_state'}" />
<tmpl_if name="filter_wp"><input type="hidden" name="wp" value="1" /></tmpl_if>
<tmpl_if name="filter_hits"><input type="hidden" name="hits" value="1" /></tmpl_if>

<tmpl_if name="emergency">
<div class="mw-alarm" role="alert">
	<span>{tmpl_var name='emergency_line'}</span>
	<button class="btn btn-default formbutton-default" type="button"
		data-mw-confirm="{tmpl_var name='confirm_emergency_off_txt'}" data-mw-title="{tmpl_var name='btn_emergency_off_txt'}"
		data-mw-ok="{tmpl_var name='btn_emergency_off_txt'}" data-mw-set-mw-waf-action="emergency_off"
		data-submit-form="pageForm" data-form-action="security/malwatch_waf_list.php">{tmpl_var name='btn_emergency_off_txt'}</button>
</div>
</tmpl_if>

<tmpl_if name="has_jobs">
<div class="mw-jobs" id="mw-waf-jobs" aria-live="polite">
	<strong>{tmpl_var name='jobs_head_txt'}</strong>
	<ul>
		<tmpl_loop name="jobs"><li>{tmpl_var name='job_line'}</li></tmpl_loop>
	</ul>
</div>
</tmpl_if>

<div class="mw-bar">
	<div class="mw-group">
		<span class="mw-caption">{tmpl_var name='period_txt'}</span>
		<tmpl_loop name="periods"><a class="mw-seg" href="#" data-load-content="{tmpl_var name='href'}"<tmpl_if name="current"> aria-current="true"</tmpl_if>>{tmpl_var name='label'}</a></tmpl_loop>
	</div>
	<div class="mw-actions">
		<button class="btn btn-default formbutton-default" type="button"
			data-mw-confirm="{tmpl_var name='response_confirm'}" data-mw-title="{tmpl_var name='response_title_txt'}"
			data-mw-ok="{tmpl_var name='response_ok'}" data-mw-set-mw-waf-action="response_body"
			data-mw-set-mw-waf-mode="{tmpl_var name='response_target'}"
			data-submit-form="pageForm" data-form-action="security/malwatch_waf_list.php">{tmpl_var name='response_button'}</button>
		<tmpl_if name="emergency"><tmpl_else>
		<button class="btn btn-danger" type="button"
			data-mw-confirm="{tmpl_var name='confirm_emergency_on_txt'}" data-mw-title="{tmpl_var name='btn_emergency_on_txt'}"
			data-mw-ok="{tmpl_var name='btn_emergency_on_txt'}" data-mw-danger="1" data-mw-set-mw-waf-action="emergency_on"
			data-submit-form="pageForm" data-form-action="security/malwatch_waf_list.php">{tmpl_var name='btn_emergency_on_txt'}</button>
		</tmpl_if>
	</div>
</div>

<div class="mw-bar">
	<div class="mw-group">
		<span class="mw-caption">{tmpl_var name='filter_state_txt'}</span>
		<tmpl_loop name="state_links"><a class="mw-seg" href="#" data-load-content="{tmpl_var name='href'}"<tmpl_if name="current"> aria-current="true"</tmpl_if>>{tmpl_var name='label'}</a></tmpl_loop>
		<a class="mw-seg" href="#" data-load-content="{tmpl_var name='wp_href'}"<tmpl_if name="filter_wp"> aria-current="true"</tmpl_if>>{tmpl_var name='filter_wordpress_txt'}</a>
		<a class="mw-seg" href="#" data-load-content="{tmpl_var name='hits_href'}"<tmpl_if name="filter_hits"> aria-current="true"</tmpl_if>>{tmpl_var name='filter_hits_txt'}</a>
	</div>
	<div class="mw-group">
		<a class="mw-seg" href="#" data-load-content="security/malwatch_waf_exception_list.php">{tmpl_var name='exceptions_link'}</a>
		<a class="mw-seg" href="#" data-load-content="security/malwatch_waf_config_edit.php">{tmpl_var name='settings_link_txt'}</a>
	</div>
</div>

<tmpl_if name="has_rows">
<div class="mw-selectbar">
	<label><input type="checkbox" data-mw-toggle /> {tmpl_var name='select_all_txt'}</label>
	<button type="button" class="mw-invert" data-mw-invert>{tmpl_var name='invert_txt'}</button>
	<span class="mw-selcount" data-mw-count data-template="{tmpl_var name='selected_template'}" data-none="{tmpl_var name='selected_none'}">{tmpl_var name='selected_none'}</span>
</div>
<div class="table-wrapper">
<table class="table">
	<thead class="dark">
		<tr>
			<th>&nbsp;</th>
			<th>{tmpl_var name='col_site_txt'}</th>
			<th>{tmpl_var name='col_state_txt'}</th>
			<th class="num">{tmpl_var name='col_hits_txt'}</th>
			<th class="num">{tmpl_var name='col_block_txt'}</th>
			<th>{tmpl_var name='col_rule_txt'}</th>
			<th>&nbsp;</th>
		</tr>
	</thead>
	<tbody>
		<tmpl_loop name="rows">
		<tr>
			<td><input type="checkbox" class="mw-pick" name="waf_pick[]" value="{tmpl_var name='domain_id'}" aria-label="{tmpl_var name='domain'}" /></td>
			<td><span class="mw-domain">{tmpl_var name='domain'}</span><tmpl_if name="is_wordpress"> <span class="mw-dim">WordPress</span></tmpl_if></td>
			<td>
				<div class="mw-chips">
					<span class="mw-chip {tmpl_var name='state_class'}">{tmpl_var name='state_label'}</span>
					<tmpl_if name="is_pending"><span class="mw-chip pending">{tmpl_var name='state_pending_txt'}</span></tmpl_if>
				</div>
				<tmpl_if name="since_label"><div class="mw-dim">{tmpl_var name='since_label'}</div></tmpl_if>
			</td>
			<td class="num"><span class="mw-hitcell"><tmpl_if name="spark"><svg class="mw-spark" width="64" height="18" viewBox="0 0 64 18" aria-hidden="true" focusable="false"><polyline points="{tmpl_var name='spark'}" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"></polyline></svg></tmpl_if><span>{tmpl_var name='hits'}</span></span></td>
			<td class="num"><tmpl_if name="has_block"><span class="mw-block">{tmpl_var name='would_block'}</span><tmpl_else>0</tmpl_if></td>
			<td><tmpl_if name="top_rule">{tmpl_var name='top_rule'} <span class="mw-dim">{tmpl_var name='top_rule_id'}</span><tmpl_else><span class="mw-dim">–</span></tmpl_if></td>
			<td><a class="btn btn-default formbutton-default btn-xs" href="#" data-load-content="security/malwatch_waf_show.php?id={tmpl_var name='domain_id'}">{tmpl_var name='btn_view_txt'}</a></td>
		</tr>
		</tmpl_loop>
	</tbody>
</table>
</div>
<div class="mw-selectbar">
	<span class="mw-caption">{tmpl_var name='bulk_txt'}</span>
	<button class="btn btn-default formbutton-default mw-needs-selection" type="button" data-mw-empty="1"
		data-mw-hint="{tmpl_var name='hint_select_txt'}"
		data-mw-confirm="{tmpl_var name='confirm_bulk_detect_txt'}" data-mw-title="{tmpl_var name='btn_bulk_detect_txt'}"
		data-mw-ok="{tmpl_var name='btn_bulk_detect_txt'}"
		data-mw-set-mw-waf-action="state" data-mw-set-mw-waf-target="detect"
		data-submit-form="pageForm" data-form-action="security/malwatch_waf_list.php">{tmpl_var name='btn_bulk_detect_txt'}</button>
	<button class="btn btn-danger mw-needs-selection" type="button" data-mw-empty="1"
		data-mw-hint="{tmpl_var name='hint_select_txt'}"
		data-mw-confirm="{tmpl_var name='confirm_bulk_enforce_txt'}" data-mw-title="{tmpl_var name='btn_bulk_enforce_txt'}"
		data-mw-ok="{tmpl_var name='btn_bulk_enforce_txt'}" data-mw-danger="1"
		data-mw-set-mw-waf-action="state" data-mw-set-mw-waf-target="enforce"
		data-submit-form="pageForm" data-form-action="security/malwatch_waf_list.php">{tmpl_var name='btn_bulk_enforce_txt'}</button>
	<button class="btn btn-default formbutton-default mw-needs-selection" type="button" data-mw-empty="1"
		data-mw-hint="{tmpl_var name='hint_select_txt'}"
		data-mw-confirm="{tmpl_var name='confirm_bulk_off_txt'}" data-mw-title="{tmpl_var name='btn_bulk_off_txt'}"
		data-mw-ok="{tmpl_var name='btn_bulk_off_txt'}"
		data-mw-set-mw-waf-action="state" data-mw-set-mw-waf-target="off"
		data-submit-form="pageForm" data-form-action="security/malwatch_waf_list.php">{tmpl_var name='btn_bulk_off_txt'}</button>
</div>
<tmpl_else>
<div class="mw-quiet">{tmpl_var name='empty_txt'}</div>
</tmpl_if>

<tmpl_if name="has_recent">
<div class="mw-quiet">
	<strong>{tmpl_var name='recent_head_txt'}</strong>
	<ul>
		<tmpl_loop name="recent"><li<tmpl_if name="job_failed"> class="mw-failed"</tmpl_if>>{tmpl_var name='job_line'}</li></tmpl_loop>
	</ul>
</div>
</tmpl_if>

<div class="mw-quiet"><strong>{tmpl_var name='footnote_head_txt'}</strong> {tmpl_var name='footnote_txt'}</div>

</div>

<script>
(function () {
	// Follows the queued and running jobs without reloading the page; once
	// none is left, the page is fetched once so states and figures are
	// current. A timer that outlives the page only writes into nothing: the
	// observer and the check in poll() stop it.
	var root = document.getElementById('mw-waf');
	var box = document.getElementById('mw-waf-jobs');
	if (!root || !box) { return; }

	var timer = null;
	function stop() { if (timer) { clearInterval(timer); timer = null; } }

	var host = document.getElementById('pageContent');
	if (host && window.MutationObserver) {
		new MutationObserver(function () {
			if (!document.contains(root)) { stop(); }
		}).observe(host, { childList: true, subtree: true });
	}

	function refresh() {
		stop();
		if (window.ISPConfig && document.contains(root)) {
			ISPConfig.loadContent(root.getAttribute('data-mw-self'));
		}
	}

	function draw(jobs) {
		var list = box.querySelector('ul');
		if (!list) { return; }
		while (list.firstChild) { list.removeChild(list.firstChild); }
		for (var i = 0; i < jobs.length; i++) {
			var item = document.createElement('li');
			item.textContent = jobs[i].label + ': ' + jobs[i].status_label + (jobs[i].log ? ' – ' + jobs[i].log : '');
			list.appendChild(item);
		}
	}

	function poll() {
		if (!document.contains(root)) { stop(); return; }
		var xhr = new XMLHttpRequest();
		xhr.open('GET', root.getAttribute('data-mw-jobs'), true);
		xhr.onload = function () {
			if (!document.contains(root)) { stop(); return; }
			var data = null;
			try { data = JSON.parse(xhr.responseText); } catch (e) { return; }
			if (!data || !data.jobs) { return; }
			draw(data.jobs);
			if (data.running === 0) { refresh(); }
		};
		xhr.send();
	}

	timer = setInterval(poll, 5000);
})();
</script>

<tmpl_include file="templates/malwatch_selection.htm">
<tmpl_include file="templates/malwatch_modal.htm">
```

- [ ] **Schritt 5: Menüpunkt, Dateiliste, Seitenprüfung**

In `ispconfig/interface/module.conf.php` direkt nach dem Eintrag „Schwachstellen"
(dem Block mit `'html_id' => 'security_vulns'`):

```php

// The WAF per website: switch it, read its hits, add exceptions. Next to the
// vulnerabilities, since both look at the same websites from two sides.
$items[] = array(
	'title'   => 'Abwehr',
	'target'  => 'content',
	'link'    => 'security/malwatch_waf_list.php',
	'html_id' => 'security_waf'
);
```

In `ispconfig/install/file.list` nach der Zeile
`c:interface/malwatch_waf_response.php:interface/web/security/malwatch_waf_response.php`:

```text
c:interface/malwatch_waf_list.php:interface/web/security/malwatch_waf_list.php
c:interface/templates/malwatch_waf_list.htm:interface/web/security/templates/malwatch_waf_list.htm
```

In `ispconfig/tests/render_pages.php` in `$pages` nach `'malwatch_dump_databases.php',`:

```php
	// Abwehr: the overview, once with a filter and the day view.
	'malwatch_waf_list.php',
	'malwatch_waf_list.php?days=1&state=detect',
```

- [ ] **Schritt 6: Prüfen**

Run: `php -l ispconfig/interface/malwatch_waf_list.php && php -l ispconfig/interface/module.conf.php`
Expected: zweimal `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden` (die Sprachdateien tragen dieselben Schlüssel)

- [ ] **Schritt 7: Commit**

```bash
git add ispconfig/interface/malwatch_waf_list.php ispconfig/interface/templates/malwatch_waf_list.htm ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/interface/module.conf.php ispconfig/install/file.list ispconfig/tests/render_pages.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): overview page with filters, bulk switch and job follow-up" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B5: Website im Detail `malwatch_waf_show.php`

Eine Website mit Schalter und Vorschau für „scharf", Verlauf, Regeln, Pfaden, den
gespeicherten Anfragen, ihren Ausnahmen und dem Formular „Ausnahme anlegen". Die Knöpfe
„Ausnahme …" an Regeln und Anfragen füllen das Formular; die Vorschau kommt beim Tippen
aus `malwatch_waf_preview.php`.

**Dateien:**
- Neu: `ispconfig/interface/malwatch_waf_show.php`, `ispconfig/interface/templates/malwatch_waf_show.htm`
- Ändern: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (eine Funktion anhängen),
  `ispconfig/tests/waf_panel_test.php`
- Ändern: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` (Zeilen anhängen)
- Ändern: `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`,
  `ispconfig/tests/check_wiring.sh` (Prüfung 57)

**Schnittstellen:**
- Nutzt: B1 bis B3; `waf_panel_day_series()`, `waf_panel_rules()`, `waf_panel_paths()`,
  `waf_panel_hit()`, `waf_panel_enforce()`, `waf_panel_exception_row()`,
  `waf_panel_job()`, `waf_periods()`, `waf_exception_scopes()`, `malwatch_datetime()`,
  `malwatch_bytes()`, `malwatch_attr_texts()`
- Liefert: `waf_panel_day_label($day)` (`Y-m-d` → `d.m.Y`);
  `security/malwatch_waf_show.php?id=<domain_id>&days=<n>`; Formularfelder `exc_site`, `exc_scope`, `exc_rule`, `exc_path`, `exc_param`, `exc_note`;
  Knöpfe mit `data-mw-except`, `data-rule`, `data-path`, `data-param`

- [ ] **Schritt 1: Prüfung schreiben**

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 57. Die Seite einer Website traegt das Ausnahmeformular im Formular des
#     Panels: ein Dialog am Ende von <body> schickte seine Felder nie mit. Die
#     Vorschau kommt aus malwatch_waf_preview.php, die Seitenantwort oeffnet
#     malwatch_waf_response.php in einem eigenen Fenster.
show_tpl="$root/interface/templates/malwatch_waf_show.htm"
if [ -f "$show_tpl" ]; then
	for field in exc_site exc_scope exc_rule exc_path exc_param exc_note; do
		grep -q "name=\"$field\"" "$show_tpl" || fail "malwatch_waf_show.htm hat kein Feld $field"
	done
	grep -q 'data-mw-preview="security/malwatch_waf_preview.php' "$show_tpl" \
		|| fail "malwatch_waf_show.htm holt die Vorschau nicht aus malwatch_waf_preview.php"
	grep -q 'href="security/malwatch_waf_response.php?hit=[^"]*" target="_blank" rel="noopener"' "$show_tpl" \
		|| fail "malwatch_waf_show.htm oeffnet die Seitenantwort nicht in einem eigenen Fenster"
	if grep -q 'class="[^"]*mw-modal[^"]*"[^>]*>[^<]*<[^>]*name="exc_' "$show_tpl"; then
		fail "malwatch_waf_show.htm legt Felder der Ausnahme in einen Dialog"
	fi
else
	fail "interface/templates/malwatch_waf_show.htm fehlt"
fi
```

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: interface/templates/malwatch_waf_show.htm fehlt`

- [ ] **Schritt 2: Datumsfunktion mit Test**

`ispconfig/tests/waf_panel_test.php` (Abschnitt vor summary):

```php
// --- B5: day label -----------------------------------------------------------

expect_same('day label', waf_panel_day_label('2026-09-16'), '16.09.2026');
expect_same('day label of something else', waf_panel_day_label('gestern'), 'gestern');
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit „Call to undefined function waf_panel_day_label()"

`ispconfig/interface/lib/malwatch_waf_panel.inc.php` (anhängen):

```php
/** A day of the database ('Y-m-d') as 'd.m.Y', without any clock involved. */
function waf_panel_day_label($day)
{
	return preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', (string) $day, $m) ? $m[3] . '.' . $m[2] . '.' . $m[1] : (string) $day;
}
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 3: Texte anhängen**

`ispconfig/interface/lang/de_malwatch_waf.lng` (anhängen):

```php
$wb['show_back_txt'] = 'Zur Übersicht';
$wb['show_missing_txt'] = 'Diese Website ist unbekannt oder keine eigenständige Website.';
$wb['state_head_txt'] = 'Zustand';
$wb['state_current_txt'] = 'Aktuell: %s';
$wb['btn_set_off_txt'] = 'Ausschalten';
$wb['btn_set_detect_txt'] = 'Mitschreiben';
$wb['btn_set_enforce_txt'] = 'Scharf schalten';
$wb['confirm_set_off_txt'] = 'Die WAF wird für diese Website abgeschaltet. ISPConfig schreibt dafür den vhost neu.';
$wb['confirm_set_detect_txt'] = 'Die Website hält danach Treffer im Audit-Log fest, Anfragen laufen weiter durch. ISPConfig schreibt dafür den vhost neu.';
$wb['confirm_set_enforce_txt'] = 'Die Website weist danach Anfragen über der Punktgrenze ab. Die Vorschau zeigt, was das in den letzten Tagen bedeutet hätte.';
$wb['preview_head_txt'] = 'Vorschau für „scharf“';
$wb['preview_block_txt'] = 'In den letzten %s Tagen wären %s Anfragen abgewiesen worden, %s davon von angemeldeten Nutzern.';
$wb['preview_block_none_txt'] = 'In den letzten %s Tagen wäre keine Anfrage abgewiesen worden.';
$wb['preview_rules_txt'] = 'Beteiligte Regeln:';
$wb['free_from_txt'] = '„scharf“ ist ab %s möglich.';
$wb['history_head_txt'] = 'Verlauf';
$wb['history_legend_txt'] = 'Treffer je Tag; der rote Teil wäre abgewiesen worden.';
$wb['history_bar_txt'] = '%s: %s Treffer, %s davon wären abgewiesen worden';
$wb['rules_head_txt'] = 'Regeln';
$wb['rules_none_txt'] = 'Im gewählten Zeitraum gab es keinen Treffer.';
$wb['rule_hits_txt'] = '%s Treffer, %s davon wären abgewiesen worden';
$wb['rule_last_txt'] = 'zuletzt am %s';
$wb['rule_paths_txt'] = 'Häufigste Pfade:';
$wb['rule_more_paths_txt'] = '%s weitere Pfade';
$wb['rule_why_txt'] = 'Woran erkannt?';
$wb['rule_own_txt'] = 'Eigene Regel oder Punktwertung; sie lässt sich nicht ausnehmen.';
$wb['btn_except_txt'] = 'Ausnahme …';
$wb['paths_head_txt'] = 'Pfade';
$wb['col_path_txt'] = 'Pfad';
$wb['col_rules_txt'] = 'Regeln';
$wb['hits_head_txt'] = 'Einzelne Anfragen';
$wb['hits_limit_txt'] = 'Die letzten %s von %s gespeicherten Anfragen. Einzelne Anfragen bleiben %s Tage gespeichert.';
$wb['hits_none_txt'] = 'Für diese Website ist keine Anfrage gespeichert.';
$wb['hit_block_txt'] = 'wäre abgewiesen';
$wb['hit_logged_in_txt'] = 'angemeldet';
$wb['hit_score_txt'] = '%s Punkte';
$wb['hit_status_txt'] = 'Antwort %s';
$wb['hit_rules_txt'] = 'Regeln';
$wb['hit_headers_txt'] = 'Kopfzeilen';
$wb['hit_body_txt'] = 'Anfrageinhalt';
$wb['hit_body_none_txt'] = 'Das Audit-Log enthält für diese Anfrage keinen Inhalt, etwa bei Anmeldungen und Uploads.';
$wb['btn_response_txt'] = 'Seitenantwort ansehen';
$wb['response_size_txt'] = '%s, öffnet als Text in einem eigenen Fenster';
$wb['exceptions_head_txt'] = 'Ausnahmen für diese Website';
$wb['exceptions_none_txt'] = 'Für diese Website gilt keine Ausnahme.';
$wb['col_scope_txt'] = 'Geltungsbereich';
$wb['col_target_txt'] = 'Pfad oder Parameter';
$wb['col_note_txt'] = 'Notiz';
$wb['col_exc_state_txt'] = 'Zustand';
$wb['col_created_txt'] = 'Angelegt';
$wb['btn_exception_remove_txt'] = 'Entfernen';
$wb['confirm_exception_remove_txt'] = 'Die Ausnahme wird aus den Regeldateien genommen, nginx lädt dafür neu.';
$wb['form_head_txt'] = 'Ausnahme anlegen';
$wb['form_intro_txt'] = 'Eine Ausnahme nimmt eine Regel aus der Prüfung. „Ausnahme …“ an einer Regel oder Anfrage füllt dieses Formular.';
$wb['form_scope_txt'] = 'Geltungsbereich';
$wb['form_rule_txt'] = 'Regel';
$wb['form_path_txt'] = 'Pfad, beginnt mit';
$wb['form_param_txt'] = 'Parameter';
$wb['form_note_txt'] = 'Notiz, nur im Panel sichtbar';
$wb['btn_exception_add_txt'] = 'Ausnahme anlegen';
$wb['confirm_exception_add_txt'] = 'Die Ausnahme wird in die Regeldateien übernommen, nginx lädt dafür neu.';
$wb['preview_wait_txt'] = 'Vorschau wird berechnet …';
```

`ispconfig/interface/lang/en_malwatch_waf.lng` (anhängen):

```php
$wb['show_back_txt'] = 'Back to the overview';
$wb['show_missing_txt'] = 'This website is unknown or no website of its own.';
$wb['state_head_txt'] = 'State';
$wb['state_current_txt'] = 'Current: %s';
$wb['btn_set_off_txt'] = 'Switch off';
$wb['btn_set_detect_txt'] = 'Detect';
$wb['btn_set_enforce_txt'] = 'Enforce';
$wb['confirm_set_off_txt'] = 'The WAF is switched off for this website. ISPConfig rewrites the vhost for this.';
$wb['confirm_set_detect_txt'] = 'The website then records hits in the audit log while requests pass. ISPConfig rewrites the vhost for this.';
$wb['confirm_set_enforce_txt'] = 'The website then refuses requests above the score limit. The preview shows what that would have meant in the last days.';
$wb['preview_head_txt'] = 'Preview for "enforce"';
$wb['preview_block_txt'] = 'In the last %s days %s requests would have been refused, %s of them from logged-in users.';
$wb['preview_block_none_txt'] = 'In the last %s days no request would have been refused.';
$wb['preview_rules_txt'] = 'Rules involved:';
$wb['free_from_txt'] = '"enforce" is possible from %s.';
$wb['history_head_txt'] = 'History';
$wb['history_legend_txt'] = 'Hits per day; the red part would have been refused.';
$wb['history_bar_txt'] = '%s: %s hits, %s of them would have been refused';
$wb['rules_head_txt'] = 'Rules';
$wb['rules_none_txt'] = 'The chosen period brought no hit.';
$wb['rule_hits_txt'] = '%s hits, %s of them would have been refused';
$wb['rule_last_txt'] = 'last on %s';
$wb['rule_paths_txt'] = 'Most frequent paths:';
$wb['rule_more_paths_txt'] = '%s more paths';
$wb['rule_why_txt'] = 'Why?';
$wb['rule_own_txt'] = 'Own rule or scoring rule; it cannot be excluded.';
$wb['btn_except_txt'] = 'Exception …';
$wb['paths_head_txt'] = 'Paths';
$wb['col_path_txt'] = 'Path';
$wb['col_rules_txt'] = 'Rules';
$wb['hits_head_txt'] = 'Single requests';
$wb['hits_limit_txt'] = 'The last %s of %s stored requests. Single requests are kept for %s days.';
$wb['hits_none_txt'] = 'No request is stored for this website.';
$wb['hit_block_txt'] = 'would be refused';
$wb['hit_logged_in_txt'] = 'logged in';
$wb['hit_score_txt'] = '%s points';
$wb['hit_status_txt'] = 'response %s';
$wb['hit_rules_txt'] = 'Rules';
$wb['hit_headers_txt'] = 'Headers';
$wb['hit_body_txt'] = 'Request body';
$wb['hit_body_none_txt'] = 'The audit log holds no body for this request, as with logins and uploads.';
$wb['btn_response_txt'] = 'View response body';
$wb['response_size_txt'] = '%s, opens as text in a window of its own';
$wb['exceptions_head_txt'] = 'Exceptions for this website';
$wb['exceptions_none_txt'] = 'No exception applies to this website.';
$wb['col_scope_txt'] = 'Scope';
$wb['col_target_txt'] = 'Path or parameter';
$wb['col_note_txt'] = 'Note';
$wb['col_exc_state_txt'] = 'State';
$wb['col_created_txt'] = 'Created';
$wb['btn_exception_remove_txt'] = 'Remove';
$wb['confirm_exception_remove_txt'] = 'The exception leaves the rule files; nginx reloads for this.';
$wb['form_head_txt'] = 'Add an exception';
$wb['form_intro_txt'] = 'An exception takes a rule out of the check. "Exception …" at a rule or a request fills this form.';
$wb['form_scope_txt'] = 'Scope';
$wb['form_rule_txt'] = 'Rule';
$wb['form_path_txt'] = 'Path, starts with';
$wb['form_param_txt'] = 'Parameter';
$wb['form_note_txt'] = 'Note, shown in the panel only';
$wb['btn_exception_add_txt'] = 'Add exception';
$wb['confirm_exception_add_txt'] = 'The exception goes into the rule files; nginx reloads for this.';
$wb['preview_wait_txt'] = 'Calculating the preview …';
```

- [ ] **Schritt 4: Seite schreiben**

`ispconfig/interface/malwatch_waf_show.php`:

```php
<?php

/**
 * Abwehr for one website: the state with its switch and the preview for
 * enforce, the history, rules, paths and stored requests of the period, the
 * exceptions and the form that adds one.
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

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$domain_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);

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
$app->tpl->setVar('self_href', $app->functions->htmlentities('security/malwatch_waf_show.php?id=' . $domain_id . '&days=' . $days));

// The preview for enforce.
$totals = $app->db->queryOneRecord(
	'SELECT COALESCE(SUM(would_block), 0) AS would_block, COALESCE(SUM(would_block_logged_in), 0) AS would_block_logged_in '
	. 'FROM malwatch_waf_site_day WHERE parent_domain_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)',
	$domain_id, $settings['waf_preview_days'] - 1);
$block_rules = waf_panel_rows($app->db->queryAllRecords(
	'SELECT rule_id, MAX(rule_msg) AS rule_msg, SUM(would_block_hits) AS would_block_hits FROM malwatch_waf_day '
	. 'WHERE parent_domain_id = ? AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY rule_id',
	$domain_id, $settings['waf_preview_days'] - 1));
$enforce = waf_panel_enforce($wb, $site, $totals, $block_rules, $settings, $clock['now']);
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
		'href' => $app->functions->htmlentities($link . $period),
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

// Rules and paths of the period.
$day_rows = waf_panel_rows($app->db->queryAllRecords(
	'SELECT day, rule_id, rule_msg, path, hits, would_block_hits FROM malwatch_waf_day WHERE parent_domain_id = ? '
	. 'AND day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)', $domain_id, $days - 1));
$rule_rows = array();
foreach (waf_panel_rules($wb, $day_rows) as $rule) {
	$paths = array();
	foreach ($rule['paths'] as $path) {
		$paths[] = array('path' => $app->functions->htmlentities($path['path']), 'path_hits' => number_format($path['hits'], 0, ',', '.'));
	}
	$rule_rows[] = array(
		'rule_id' => $app->functions->htmlentities($rule['rule_id']),
		'rule_title' => $app->functions->htmlentities($rule['title']),
		'rule_msg' => $app->functions->htmlentities($rule['msg']),
		'rule_line' => $app->functions->htmlentities(sprintf($wb['rule_hits_txt'], number_format($rule['hits'], 0, ',', '.'),
			number_format($rule['would_block'], 0, ',', '.'))),
		'rule_last' => $app->functions->htmlentities(sprintf($wb['rule_last_txt'], waf_panel_day_label($rule['last_day']))),
		'rule_paths' => $paths,
		'more_paths' => $rule['path_count'] > count($paths)
			? $app->functions->htmlentities(sprintf($wb['rule_more_paths_txt'], $rule['path_count'] - count($paths))) : '',
		'can_except' => $rule['can_except'] ? 1 : 0,
		'first_path' => $app->functions->htmlentities(count($rule['paths']) === 1 ? $rule['paths'][0]['path'] : ''),
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

// Stored requests.
$stored = $app->db->queryOneRecord('SELECT COUNT(*) AS n FROM malwatch_waf_hit WHERE parent_domain_id = ?', $domain_id);
$hit_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	'SELECT * FROM malwatch_waf_hit WHERE parent_domain_id = ? ORDER BY seen_at DESC, hit_id DESC LIMIT 100', $domain_id)) as $row) {
	$hit = waf_panel_hit($wb, $row);
	$rules = array();
	foreach ($hit['rules'] as $rule) {
		$rules[] = array(
			'hit_rule' => $app->functions->htmlentities($rule['title'] . ' (' . $rule['rule_id'] . ')'),
			'hit_rule_param' => $rule['param'] !== ''
				? $app->functions->htmlentities(sprintf($wb['param_label_txt'], $rule['param'])) : '',
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

- [ ] **Schritt 5: Vorlage schreiben**

`ispconfig/interface/templates/malwatch_waf_show.htm`:

```html
<tmpl_if name="has_site">
<div class='page-header'>
	<h1>{tmpl_var name='domain'} <span class="mw-headchip mw-chip {tmpl_var name='state_class'}">{tmpl_var name='state_label'}</span></h1>
</div>
<tmpl_else>
<div class='page-header'>
	<h1>{tmpl_var name='show_missing_txt'}</h1>
</div>
</tmpl_if>

<tmpl_if name="message">
	<div class="alert alert-success">{tmpl_var name='message'}</div>
</tmpl_if>
<tmpl_if name="error">
	<div class="alert alert-danger">{tmpl_var name='error'}</div>
</tmpl_if>

<style>
/* The rules of the other pages of the addon: muted text through opacity,
   lines and areas as translucent grey, fixed colours only for accent and
   alarm. */
.page-header .mw-headchip{vertical-align:middle;font-size:11px}
.page-header .mw-chip,#mw-wafsite .mw-chip{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
	padding:2px 7px;border-radius:3px;white-space:nowrap;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35))}
.page-header .mw-chip.off,#mw-wafsite .mw-chip.off{opacity:.7}
.page-header .mw-chip.detect,#mw-wafsite .mw-chip.detect{border-color:var(--cic-accent-deep,#a84c0b);color:var(--cic-accent-text,#dd630d)}
.page-header .mw-chip.enforce,#mw-wafsite .mw-chip.enforce,#mw-wafsite .mw-chip.block{background:var(--cic-bad-deep,#b13116);border-color:var(--cic-bad-deep,#b13116);color:#fff}
#mw-wafsite .mw-chip.pending{border-style:dashed}
#mw-wafsite .mw-back{margin:0 0 12px;font-size:13px}
#mw-wafsite .mw-sec{font-size:15px;font-weight:600;margin:22px 0 8px}
#mw-wafsite .mw-sub{opacity:.72;font-size:13px;max-width:80ch;margin:0 0 8px}
#mw-wafsite .mw-card{padding:12px 15px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));border-radius:3px;
	background:var(--cic-raised,rgba(128,128,128,.06))}
#mw-wafsite .mw-switch{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
#mw-wafsite .mw-muted{opacity:.55}
#mw-wafsite .mw-preview{margin-top:10px;padding-top:10px;border-top:1px solid var(--cic-line-soft,rgba(128,128,128,.35));font-size:13px}
#mw-wafsite .mw-preview ul,#mw-wafsite .mw-card ul{margin:4px 0 0;padding-left:18px}
#mw-wafsite .mw-bar{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin:0 0 8px}
#mw-wafsite .mw-caption{font-size:12px;opacity:.72;margin-right:4px}
#mw-wafsite .mw-seg{display:inline-block;padding:3px 9px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-radius:3px;font-size:12.5px;color:inherit;text-decoration:none}
#mw-wafsite .mw-seg[aria-current="true"]{border-color:var(--cic-accent,#dd630d);color:var(--cic-accent-text,#dd630d);font-weight:600}
#mw-wafsite .mw-chart{display:flex;align-items:flex-end;gap:2px;height:96px;padding:4px 0;
	border-bottom:1px solid var(--cic-line-soft,rgba(128,128,128,.35))}
#mw-wafsite .mw-col{flex:1 1 0;min-width:2px;height:100%;display:flex;align-items:flex-end}
#mw-wafsite .mw-hitbar{width:100%;display:flex;align-items:flex-end;background:var(--cic-accent,#dd630d);opacity:.85;border-radius:2px 2px 0 0}
#mw-wafsite .mw-blockbar{width:100%;background:var(--cic-bad-deep,#b13116)}
#mw-wafsite .mw-plot{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:2px 6px}
#mw-wafsite .mw-yaxis{display:flex;flex-direction:column;justify-content:space-between;align-items:flex-end;padding:2px 0;
	font-size:11px;line-height:1;opacity:.72;font-variant-numeric:tabular-nums}
#mw-wafsite .mw-xaxis{grid-column:2;display:flex;justify-content:space-between;font-size:11px;opacity:.72;font-variant-numeric:tabular-nums}
#mw-wafsite .mw-rules{display:flex;flex-direction:column;gap:8px}
#mw-wafsite .mw-rule{padding:10px 14px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));border-radius:3px}
#mw-wafsite .mw-rulehead{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline}
#mw-wafsite .mw-ruletitle{font-weight:600}
#mw-wafsite .mw-dim{opacity:.72;font-size:12.5px}
#mw-wafsite .mw-mono{font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
#mw-wafsite .mw-rulebtn{margin-left:auto}
#mw-wafsite .table-wrapper{overflow-x:auto}
#mw-wafsite .table{table-layout:auto}
#mw-wafsite .table > thead > tr > th,
#mw-wafsite .table > tbody > tr > td{padding:6px 10px;vertical-align:top}
#mw-wafsite td.num{font-variant-numeric:tabular-nums;white-space:nowrap;text-align:right}
#mw-wafsite th.num{text-align:right}
#mw-wafsite details.mw-hit{border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));border-radius:3px;margin:0 0 6px}
#mw-wafsite details.mw-hit > summary{cursor:pointer;padding:8px 12px;display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;list-style:none}
#mw-wafsite details.mw-hit > summary::-webkit-details-marker{display:none}
#mw-wafsite details.mw-hit > summary:focus-visible{outline:2px solid var(--cic-accent,#dd630d);outline-offset:-2px}
#mw-wafsite .mw-hitbody{padding:8px 12px 12px;border-top:1px solid var(--cic-line-soft,rgba(128,128,128,.35));display:flex;flex-direction:column;gap:8px}
#mw-wafsite .mw-hitreq{min-width:0;flex:1 1 30ch}
#mw-wafsite pre.mw-body{max-height:18em;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0;font-size:12px}
#mw-wafsite .mw-failed{color:var(--cic-bad-text,#d13f22)}
#mw-wafsite .mw-jobs{margin:0 0 14px;padding:10px 14px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-left:3px solid var(--cic-accent,#dd630d);border-radius:3px;font-size:13px}
#mw-wafsite .mw-jobs ul{margin:4px 0 0;padding-left:18px}
#mw-wafsite #mw-exc{scroll-margin-top:80px}
#mw-wafsite .mw-form{display:grid;grid-template-columns:minmax(10ch,max-content) minmax(0,1fr);gap:8px 14px;align-items:center;max-width:70ch}
#mw-wafsite .mw-form label{margin:0;font-weight:400}
#mw-wafsite .mw-form [hidden]{display:none!important}
#mw-wafsite .mw-scopes{display:flex;flex-wrap:wrap;gap:4px 14px}
#mw-wafsite .mw-scopes label{display:inline-flex;gap:6px;align-items:center}
#mw-wafsite .mw-previewline{min-height:1.5em;font-size:13px}
#mw-wafsite input[type=radio]{accent-color:var(--cic-accent,#dd630d)}
@media (max-width:560px){#mw-wafsite .mw-form{grid-template-columns:1fr}}
</style>

<tmpl_if name="has_site">
<div id="mw-wafsite" data-mw-jobs="security/malwatch_waf_jobs.php?since={tmpl_var name='first_job'}"
	data-mw-self="{tmpl_var name='self_href'}"
	data-mw-preview="security/malwatch_waf_preview.php?id={tmpl_var name='domain_id'}">

<p class="mw-back"><a href="#" data-load-content="security/malwatch_waf_list.php">{tmpl_var name='show_back_txt'}</a></p>

<!--
	No form of our own: the panel wraps the content area in pageForm. The
	buttons name their action in waf_action; the exception form below lives in
	the same form.
-->
<input type="hidden" name="waf_action" id="mw-waf-action" value="" />
<input type="hidden" name="waf_target" id="mw-waf-target" value="" />
<input type="hidden" name="waf_site" value="{tmpl_var name='domain_id'}" />
<input type="hidden" name="waf_exception" id="mw-waf-exception" value="" />
<input type="hidden" name="id" value="{tmpl_var name='domain_id'}" />
<input type="hidden" name="days" value="{tmpl_var name='days'}" />

<tmpl_if name="has_jobs">
<div class="mw-jobs" id="mw-waf-jobs" aria-live="polite">
	<strong>{tmpl_var name='jobs_head_txt'}</strong>
	<ul>
		<tmpl_loop name="jobs"><li>{tmpl_var name='job_line'}</li></tmpl_loop>
	</ul>
</div>
</tmpl_if>

<div class="mw-card">
	<strong>{tmpl_var name='state_head_txt'}</strong>
	<span class="mw-dim">{tmpl_var name='state_line'}</span>
	<tmpl_if name="is_pending"><span class="mw-chip pending">{tmpl_var name='state_pending_txt'}</span></tmpl_if>
	<div class="mw-switch">
		<tmpl_if name="is_off"><tmpl_else>
		<button class="btn btn-default formbutton-default" type="button"
			data-mw-confirm="{tmpl_var name='confirm_set_off_txt'}" data-mw-title="{tmpl_var name='btn_set_off_txt'}"
			data-mw-ok="{tmpl_var name='btn_set_off_txt'}" data-mw-set-mw-waf-action="state" data-mw-set-mw-waf-target="off"
			data-submit-form="pageForm" data-form-action="security/malwatch_waf_show.php">{tmpl_var name='btn_set_off_txt'}</button>
		</tmpl_if>
		<tmpl_if name="is_detect"><tmpl_else>
		<button class="btn btn-default formbutton-default" type="button"
			data-mw-confirm="{tmpl_var name='confirm_set_detect_txt'}" data-mw-title="{tmpl_var name='btn_set_detect_txt'}"
			data-mw-ok="{tmpl_var name='btn_set_detect_txt'}" data-mw-set-mw-waf-action="state" data-mw-set-mw-waf-target="detect"
			data-submit-form="pageForm" data-form-action="security/malwatch_waf_show.php">{tmpl_var name='btn_set_detect_txt'}</button>
		</tmpl_if>
		<tmpl_if name="is_enforce"><tmpl_else>
		<tmpl_if name="enforce_allowed">
		<button class="btn btn-danger" type="button"
			data-mw-confirm="{tmpl_var name='confirm_set_enforce_txt'}" data-mw-title="{tmpl_var name='btn_set_enforce_txt'}"
			data-mw-ok="{tmpl_var name='btn_set_enforce_txt'}" data-mw-danger="1" data-mw-detail="{tmpl_var name='preview_line'}"
			data-mw-set-mw-waf-action="state" data-mw-set-mw-waf-target="enforce"
			data-submit-form="pageForm" data-form-action="security/malwatch_waf_show.php">{tmpl_var name='btn_set_enforce_txt'}</button>
		<tmpl_else>
		<button class="btn btn-default formbutton-default mw-muted" type="button" data-mw-empty="1"
			data-mw-hint="{tmpl_var name='enforce_hint'}"
			data-submit-form="pageForm" data-form-action="security/malwatch_waf_show.php">{tmpl_var name='btn_set_enforce_txt'}</button>
		</tmpl_if>
		</tmpl_if>
	</div>
	<tmpl_if name="is_enforce"><tmpl_else>
	<div class="mw-preview">
		<strong>{tmpl_var name='preview_head_txt'}</strong>
		<div>{tmpl_var name='preview_line'}</div>
		<tmpl_if name="has_block_rules">
		<div class="mw-dim">{tmpl_var name='preview_rules_txt'}</div>
		<ul><tmpl_loop name="block_rules"><li>{tmpl_var name='rule_line'}</li></tmpl_loop></ul>
		</tmpl_if>
		<tmpl_if name="enforce_allowed"><tmpl_else><div class="mw-dim">{tmpl_var name='enforce_hint'}</div></tmpl_if>
	</div>
	</tmpl_if>
</div>

<p class="mw-sec">{tmpl_var name='history_head_txt'}</p>
<div class="mw-bar">
	<span class="mw-caption">{tmpl_var name='period_txt'}</span>
	<tmpl_loop name="periods"><a class="mw-seg" href="#" data-load-content="{tmpl_var name='href'}"<tmpl_if name="current"> aria-current="true"</tmpl_if>>{tmpl_var name='label'}</a></tmpl_loop>
</div>
<div class="mw-plot">
	<div class="mw-yaxis" aria-hidden="true"><span>{tmpl_var name='chart_max'}</span><span>0</span></div>
	<div class="mw-chart" role="img" aria-label="{tmpl_var name='history_legend_txt'}">
		<tmpl_loop name="bars"><span class="mw-col" title="{tmpl_var name='bar_title'}"><span class="mw-hitbar" style="height:{tmpl_var name='hit_pct'}%"><span class="mw-blockbar" style="height:{tmpl_var name='block_pct'}%"></span></span></span></tmpl_loop>
	</div>
	<div class="mw-xaxis" aria-hidden="true"><span>{tmpl_var name='chart_first'}</span><span>{tmpl_var name='chart_last'}</span></div>
</div>
<p class="mw-sub">{tmpl_var name='history_legend_txt'}</p>

<p class="mw-sec">{tmpl_var name='rules_head_txt'}</p>
<tmpl_if name="has_rules">
<div class="mw-rules">
	<tmpl_loop name="rules">
	<div class="mw-rule">
		<div class="mw-rulehead">
			<span class="mw-ruletitle">{tmpl_var name='rule_title'}</span>
			<span class="mw-dim mw-mono">{tmpl_var name='rule_id'}</span>
			<span class="mw-dim">{tmpl_var name='rule_line'}</span>
			<span class="mw-dim">{tmpl_var name='rule_last'}</span>
			<tmpl_if name="can_except">
			<button class="btn btn-default formbutton-default btn-xs mw-rulebtn" type="button" data-mw-except="1"
				data-rule="{tmpl_var name='rule_id'}" data-path="{tmpl_var name='first_path'}" data-param="">{tmpl_var name='btn_except_txt'}</button>
			<tmpl_else>
			<span class="mw-dim mw-rulebtn">{tmpl_var name='rule_own_txt'}</span>
			</tmpl_if>
		</div>
		<div class="mw-dim">{tmpl_var name='rule_paths_txt'}</div>
		<ul>
			<tmpl_loop name="rule_paths"><li><span class="mw-mono">{tmpl_var name='path'}</span> <span class="mw-dim">{tmpl_var name='path_hits'}</span></li></tmpl_loop>
		</ul>
		<tmpl_if name="more_paths"><div class="mw-dim">{tmpl_var name='more_paths'}</div></tmpl_if>
		<details><summary class="mw-dim">{tmpl_var name='rule_why_txt'}</summary><div class="mw-mono">{tmpl_var name='rule_msg'}</div></details>
	</div>
	</tmpl_loop>
</div>
<tmpl_else>
<p class="mw-sub">{tmpl_var name='rules_none_txt'}</p>
</tmpl_if>

<tmpl_if name="has_paths">
<p class="mw-sec">{tmpl_var name='paths_head_txt'}</p>
<div class="table-wrapper">
<table class="table">
	<thead class="dark">
		<tr><th>{tmpl_var name='col_path_txt'}</th><th class="num">{tmpl_var name='col_hits_txt'}</th><th>{tmpl_var name='col_rules_txt'}</th></tr>
	</thead>
	<tbody>
		<tmpl_loop name="paths">
		<tr><td class="mw-mono">{tmpl_var name='path'}</td><td class="num">{tmpl_var name='path_hits'}</td><td class="mw-mono">{tmpl_var name='path_rules'}</td></tr>
		</tmpl_loop>
	</tbody>
</table>
</div>
</tmpl_if>

<p class="mw-sec">{tmpl_var name='hits_head_txt'}</p>
<tmpl_if name="has_hits">
<p class="mw-sub">{tmpl_var name='hits_limit'}</p>
<tmpl_loop name="hits">
<details class="mw-hit">
	<summary>
		<span class="mw-dim">{tmpl_var name='hit_time'}</span>
		<span class="mw-mono">{tmpl_var name='hit_ip'}</span>
		<span class="mw-mono mw-hitreq">{tmpl_var name='hit_request'}</span>
		<span class="mw-dim mw-mono">{tmpl_var name='hit_ids'}</span>
		<span class="mw-dim">{tmpl_var name='hit_score'}</span>
		<tmpl_if name="hit_block"><span class="mw-chip block">{tmpl_var name='hit_block_txt'}</span></tmpl_if>
		<tmpl_if name="hit_logged_in"><span class="mw-chip detect">{tmpl_var name='hit_logged_in_txt'}</span></tmpl_if>
	</summary>
	<div class="mw-hitbody">
		<div class="mw-dim">{tmpl_var name='hit_status'}</div>
		<div>
			<strong>{tmpl_var name='hit_rules_txt'}</strong>
			<ul><tmpl_loop name="hit_rules"><li>{tmpl_var name='hit_rule'}<tmpl_if name="hit_rule_param"> · <span class="mw-mono">{tmpl_var name='hit_rule_param'}</span></tmpl_if>
				<span class="mw-dim mw-mono">{tmpl_var name='hit_rule_data'}</span></li></tmpl_loop></ul>
		</div>
		<div class="table-wrapper">
			<strong>{tmpl_var name='hit_headers_txt'}</strong>
			<table class="table"><tbody>
				<tmpl_loop name="hit_headers"><tr><td class="mw-mono">{tmpl_var name='header_name'}</td><td class="mw-mono">{tmpl_var name='header_value'}</td></tr></tmpl_loop>
			</tbody></table>
		</div>
		<div>
			<strong>{tmpl_var name='hit_body_txt'}</strong>
			<tmpl_if name="has_body"><pre class="mw-body mw-mono">{tmpl_var name='hit_body'}</pre><tmpl_else><div class="mw-dim">{tmpl_var name='hit_body_none_txt'}</div></tmpl_if>
		</div>
		<div class="mw-switch">
			<tmpl_if name="has_response">
			<a class="btn btn-default formbutton-default btn-xs" href="security/malwatch_waf_response.php?hit={tmpl_var name='hit_id'}" target="_blank" rel="noopener">{tmpl_var name='btn_response_txt'}</a>
			<span class="mw-dim">{tmpl_var name='response_size'}</span>
			</tmpl_if>
			<tmpl_if name="can_except">
			<button class="btn btn-default formbutton-default btn-xs" type="button" data-mw-except="1"
				data-rule="{tmpl_var name='prefill_rule'}" data-path="{tmpl_var name='prefill_path'}" data-param="{tmpl_var name='prefill_param'}">{tmpl_var name='btn_except_txt'}</button>
			</tmpl_if>
		</div>
	</div>
</details>
</tmpl_loop>
<tmpl_else>
<p class="mw-sub">{tmpl_var name='hits_none_txt'}</p>
</tmpl_if>

<p class="mw-sec">{tmpl_var name='exceptions_head_txt'}</p>
<tmpl_if name="has_exceptions">
<div class="table-wrapper">
<table class="table">
	<thead class="dark">
		<tr>
			<th>{tmpl_var name='form_rule_txt'}</th>
			<th>{tmpl_var name='col_scope_txt'}</th>
			<th>{tmpl_var name='col_target_txt'}</th>
			<th>{tmpl_var name='col_note_txt'}</th>
			<th>{tmpl_var name='col_exc_state_txt'}</th>
			<th>{tmpl_var name='col_created_txt'}</th>
			<th>&nbsp;</th>
		</tr>
	</thead>
	<tbody>
		<tmpl_loop name="exceptions">
		<tr>
			<td class="mw-mono">{tmpl_var name='exc_rule'}</td>
			<td>{tmpl_var name='exc_scope'}</td>
			<td class="mw-mono">{tmpl_var name='exc_target'}</td>
			<td>{tmpl_var name='exc_note'}</td>
			<td<tmpl_if name="exc_failed"> class="mw-failed"</tmpl_if>>{tmpl_var name='exc_state'}<tmpl_if name="exc_error"><div class="mw-dim">{tmpl_var name='exc_error'}</div></tmpl_if></td>
			<td class="mw-dim">{tmpl_var name='exc_created'}</td>
			<td><tmpl_if name="can_remove">
				<button class="btn btn-danger btn-xs" type="button"
					data-mw-confirm="{tmpl_var name='confirm_exception_remove_txt'}" data-mw-title="{tmpl_var name='btn_exception_remove_txt'}"
					data-mw-ok="{tmpl_var name='btn_exception_remove_txt'}" data-mw-danger="1"
					data-mw-set-mw-waf-action="exception_remove" data-mw-set-mw-waf-exception="{tmpl_var name='exception_id'}"
					data-submit-form="pageForm" data-form-action="security/malwatch_waf_show.php">{tmpl_var name='btn_exception_remove_txt'}</button>
			</tmpl_if></td>
		</tr>
		</tmpl_loop>
	</tbody>
</table>
</div>
<tmpl_else>
<p class="mw-sub">{tmpl_var name='exceptions_none_txt'}</p>
</tmpl_if>

<p class="mw-sec">{tmpl_var name='form_head_txt'}</p>
<div class="mw-card" id="mw-exc">
	<p class="mw-sub">{tmpl_var name='form_intro_txt'}</p>
	<input type="hidden" name="exc_site" value="{tmpl_var name='domain_id'}" />
	<div class="mw-form">
		<span>{tmpl_var name='form_scope_txt'}</span>
		<div class="mw-scopes">
			<tmpl_loop name="scopes"><label><input type="radio" name="exc_scope" value="{tmpl_var name='scope'}"<tmpl_if name="checked"> checked</tmpl_if> /> {tmpl_var name='scope_label'}</label></tmpl_loop>
		</div>
		<label for="mw-exc-rule">{tmpl_var name='form_rule_txt'}</label>
		<input class="form-control" type="text" name="exc_rule" id="mw-exc-rule" value="" maxlength="7" inputmode="numeric" autocomplete="off" />
		<label for="mw-exc-path" id="mw-exc-path-label">{tmpl_var name='form_path_txt'}</label>
		<input class="form-control" type="text" name="exc_path" id="mw-exc-path" value="" maxlength="1024" autocomplete="off" />
		<label for="mw-exc-param" id="mw-exc-param-label" hidden>{tmpl_var name='form_param_txt'}</label>
		<input class="form-control" type="text" name="exc_param" id="mw-exc-param" value="" maxlength="128" autocomplete="off" hidden />
		<label for="mw-exc-note">{tmpl_var name='form_note_txt'}</label>
		<input class="form-control" type="text" name="exc_note" id="mw-exc-note" value="" maxlength="255" autocomplete="off" />
	</div>
	<p class="mw-previewline" id="mw-exc-preview" aria-live="polite" data-wait="{tmpl_var name='preview_wait_txt'}"></p>
	<button class="btn btn-default formbutton-default" type="button"
		data-mw-confirm="{tmpl_var name='confirm_exception_add_txt'}" data-mw-title="{tmpl_var name='btn_exception_add_txt'}"
		data-mw-ok="{tmpl_var name='btn_exception_add_txt'}" data-mw-set-mw-waf-action="exception_add"
		data-submit-form="pageForm" data-form-action="security/malwatch_waf_show.php">{tmpl_var name='btn_exception_add_txt'}</button>
</div>

</div>

<script>
(function () {
	var root = document.getElementById('mw-wafsite');
	var form = document.getElementById('mw-exc');
	if (!root || !form) { return; }
	var rule = document.getElementById('mw-exc-rule');
	var path = document.getElementById('mw-exc-path');
	var param = document.getElementById('mw-exc-param');
	var preview = document.getElementById('mw-exc-preview');
	var parts = {
		path: [document.getElementById('mw-exc-path-label'), path],
		param: [document.getElementById('mw-exc-param-label'), param]
	};
	var waiting = null;
	var asked = 0;

	function scope() {
		var checked = form.querySelector('input[name="exc_scope"]:checked');
		return checked ? checked.value : '';
	}

	// Path and parameter only show where the scope uses them.
	function arrange() {
		var s = scope();
		var showPath = s === 'site_path' || s === 'site_param' || s === 'all_path';
		parts.path[0].hidden = !showPath;
		parts.path[1].hidden = !showPath;
		parts.param[0].hidden = s !== 'site_param';
		parts.param[1].hidden = s !== 'site_param';
	}

	function load() {
		if (!document.contains(root)) { return; }
		if (rule.value === '') { preview.textContent = ''; return; }
		var number = ++asked;
		preview.textContent = preview.getAttribute('data-wait');
		var xhr = new XMLHttpRequest();
		xhr.open('GET', root.getAttribute('data-mw-preview')
			+ '&exc_scope=' + encodeURIComponent(scope())
			+ '&exc_rule=' + encodeURIComponent(rule.value)
			+ '&exc_path=' + encodeURIComponent(path.value)
			+ '&exc_param=' + encodeURIComponent(param.value), true);
		xhr.onload = function () {
			if (number !== asked || !document.contains(root)) { return; }
			var data = null;
			try { data = JSON.parse(xhr.responseText); } catch (e) { preview.textContent = ''; return; }
			preview.textContent = data && data.text ? data.text : '';
		};
		xhr.send();
	}

	function update() {
		arrange();
		if (waiting) { clearTimeout(waiting); }
		waiting = setTimeout(load, 300);
	}

	// "Ausnahme …" fills the form from a rule or a request and moves to it.
	root.addEventListener('click', function (event) {
		var button = event.target.closest ? event.target.closest('[data-mw-except]') : null;
		if (!button) { return; }
		event.preventDefault();
		rule.value = button.getAttribute('data-rule') || '';
		path.value = button.getAttribute('data-path') || '';
		param.value = button.getAttribute('data-param') || '';
		var wanted = param.value !== '' ? 'site_param' : (path.value !== '' ? 'site_path' : 'site');
		var radio = form.querySelector('input[name="exc_scope"][value="' + wanted + '"]');
		if (radio) { radio.checked = true; }
		update();
		var still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		form.scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'start' });
		rule.focus({ preventScroll: true });
	});

	form.addEventListener('input', update);
	form.addEventListener('change', update);
	// Enter stays in the field; the form goes out through its button and the question.
	form.addEventListener('keydown', function (event) {
		if (event.key === 'Enter' && event.target.tagName === 'INPUT') { event.preventDefault(); }
	});
	arrange();
})();

(function () {
	// Follows running jobs like the overview and fetches the page once when none is left.
	var root = document.getElementById('mw-wafsite');
	var box = document.getElementById('mw-waf-jobs');
	if (!root || !box) { return; }
	var timer = null;
	function stop() { if (timer) { clearInterval(timer); timer = null; } }
	var host = document.getElementById('pageContent');
	if (host && window.MutationObserver) {
		new MutationObserver(function () {
			if (!document.contains(root)) { stop(); }
		}).observe(host, { childList: true, subtree: true });
	}
	function refresh() {
		stop();
		if (window.ISPConfig && document.contains(root)) {
			ISPConfig.loadContent(root.getAttribute('data-mw-self'));
		}
	}
	function poll() {
		if (!document.contains(root)) { stop(); return; }
		var xhr = new XMLHttpRequest();
		xhr.open('GET', root.getAttribute('data-mw-jobs'), true);
		xhr.onload = function () {
			if (!document.contains(root)) { stop(); return; }
			var data = null;
			try { data = JSON.parse(xhr.responseText); } catch (e) { return; }
			if (!data || !data.jobs) { return; }
			var list = box.querySelector('ul');
			while (list && list.firstChild) { list.removeChild(list.firstChild); }
			for (var i = 0; list && i < data.jobs.length; i++) {
				var item = document.createElement('li');
				item.textContent = data.jobs[i].label + ': ' + data.jobs[i].status_label + (data.jobs[i].log ? ' – ' + data.jobs[i].log : '');
				list.appendChild(item);
			}
			if (data.running === 0) { refresh(); }
		};
		xhr.send();
	}
	timer = setInterval(poll, 5000);
})();
</script>

<tmpl_include file="templates/malwatch_modal.htm">
</tmpl_if>
```

- [ ] **Schritt 6: Eintragen**

In `ispconfig/install/file.list` nach der Zeile
`c:interface/templates/malwatch_waf_list.htm:interface/web/security/templates/malwatch_waf_list.htm`:

```text
c:interface/malwatch_waf_show.php:interface/web/security/malwatch_waf_show.php
c:interface/templates/malwatch_waf_show.htm:interface/web/security/templates/malwatch_waf_show.htm
```

In `ispconfig/tests/render_pages.php` in `$pages` nach `'malwatch_waf_list.php?days=1&state=detect',`:

```php
	// Abwehr: the website the run picked, over the longest period on offer.
	'malwatch_waf_show.php',
	'malwatch_waf_show.php?days=90',
```

- [ ] **Schritt 7: Prüfen**

Run: `php -l ispconfig/interface/malwatch_waf_show.php`
Expected: `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 8: Commit**

```bash
git add ispconfig/interface/malwatch_waf_show.php ispconfig/interface/templates/malwatch_waf_show.htm ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/tests/waf_panel_test.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/install/file.list ispconfig/tests/render_pages.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): website page with preview, history, requests and the exception form" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B6: Ausnahmen gesamt `malwatch_waf_exception_list.php`

Alle Ausnahmen auf einer Seite: Regel, Website, Geltungsbereich, Pfad oder Parameter,
Notiz, Zustand mit Fehlergrund, wer sie wann angelegt hat, dazu „Entfernen". Gefiltert
wird nach Zustand und nach Website. Eine Website zeigt ihre eigenen Ausnahmen und die
websiteübergreifenden, weil beide für sie gelten; so zählt auch die Seite der Website.

**Dateien:**
- Neu: `ispconfig/interface/malwatch_waf_exception_list.php`,
  `ispconfig/interface/templates/malwatch_waf_exception_list.htm`
- Ändern: `ispconfig/interface/lib/malwatch_waf_panel.inc.php` (drei Funktionen anhängen),
  `ispconfig/tests/waf_panel_test.php`
- Ändern: `ispconfig/interface/lang/de_malwatch_waf.lng`, `en_malwatch_waf.lng` (Zeilen anhängen)
- Ändern: `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`,
  `ispconfig/tests/check_wiring.sh` (Prüfung 58)

**Schnittstellen:**
- Nutzt: `waf_panel_handle_post()` (Aktion `exception_remove` mit `waf_exception`),
  `waf_panel_exception_row()`, `waf_panel_exception_state_label()`,
  `waf_panel_rule_title()`, `waf_panel_job()`, `waf_panel_rows()`, `malwatch_datetime()`,
  `malwatch_attr_texts()`
- Liefert:
  - `waf_panel_exception_filters($get)` → `array('state' => string, 'site' => string)`;
    `state` ist `pending`, `active`, `error`, `removing` oder `''`, `site` eine
    Website-ID als Ziffernfolge, `'all'` für die websiteübergreifenden oder `''`
  - `waf_panel_exception_list($rows, $filters)` →
    `array('rows' => array, 'sites' => array(array('value' => string, 'label' => string)), 'has_global' => bool, 'counts' => array('' => int, 'pending' => int, 'active' => int, 'error' => int, 'removing' => int))`
  - `waf_panel_exception_query($filters, $changes)` → Abfrageteil ohne `?`
  - die Seite `security/malwatch_waf_exception_list.php?state=&site=`

- [ ] **Schritt 1: Prüfung schreiben**

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 58. Die Ausnahmeliste schickt "Entfernen" an sich selbst, damit ihre Filter
#     nach dem Klick bleiben, und die Uebersicht fuehrt zu ihr.
exc_tpl="$root/interface/templates/malwatch_waf_exception_list.htm"
if [ -f "$exc_tpl" ]; then
	grep -q 'data-mw-set-mw-waf-action="exception_remove"' "$exc_tpl" \
		|| fail "malwatch_waf_exception_list.htm hat keinen Knopf Entfernen"
	grep -q 'data-form-action="security/malwatch_waf_exception_list.php"' "$exc_tpl" \
		|| fail "malwatch_waf_exception_list.htm schickt Entfernen nicht an die eigene Seite"
else
	fail "interface/templates/malwatch_waf_exception_list.htm fehlt"
fi
grep -q 'data-load-content="security/malwatch_waf_exception_list.php"' "$root/interface/templates/malwatch_waf_list.htm" \
	|| fail "malwatch_waf_list.htm fuehrt nicht zur Ausnahmeliste"
```

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: interface/templates/malwatch_waf_exception_list.htm fehlt`

- [ ] **Schritt 2: Test für Filter und Liste schreiben**

`ispconfig/tests/waf_panel_test.php` (Abschnitt vor summary):

```php
// --- B6: exception list ------------------------------------------------------

function exception_ids($list)
{
	$ids = array();
	foreach ($list['rows'] as $row) {
		$ids[] = (int) $row['exception_id'];
	}
	return $ids;
}

expect_same('exception filters', waf_panel_exception_filters(array('state' => 'error', 'site' => '12')),
	array('state' => 'error', 'site' => '12'));
expect_same('exception filters for every website', waf_panel_exception_filters(array('site' => 'all')),
	array('state' => '', 'site' => 'all'));
expect_same('exception filters refuse other values',
	waf_panel_exception_filters(array('state' => 'deleted', 'site' => '12 OR 1=1')), array('state' => '', 'site' => ''));
expect_same('exception filters refuse website 0', waf_panel_exception_filters(array('site' => '0')),
	array('state' => '', 'site' => ''));

$exception_rows = array(
	array('exception_id' => '1', 'scope' => 'site', 'parent_domain_id' => '12', 'domain' => 'zweite.test', 'exception_state' => 'active'),
	array('exception_id' => '2', 'scope' => 'all_path', 'parent_domain_id' => '0', 'domain' => '', 'exception_state' => 'error'),
	array('exception_id' => '3', 'scope' => 'site_path', 'parent_domain_id' => '11', 'domain' => 'Beispiel.test', 'exception_state' => 'error'),
	array('exception_id' => '4', 'scope' => 'site_param', 'parent_domain_id' => '12', 'domain' => 'zweite.test', 'exception_state' => 'pending'),
);
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array()));
expect_same('exception list unfiltered', exception_ids($list), array(1, 2, 3, 4));
expect_same('exception list websites by name', $list['sites'],
	array(array('value' => '11', 'label' => 'Beispiel.test'), array('value' => '12', 'label' => 'zweite.test')));
expect_same('exception list knows global rows', $list['has_global'], true);
expect_same('exception list counts', $list['counts'],
	array('' => 4, 'pending' => 1, 'active' => 1, 'error' => 2, 'removing' => 0));
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array('site' => '12')));
expect_same('one website with the global rows', exception_ids($list), array(1, 2, 4));
expect_same('counts follow the website', $list['counts'],
	array('' => 3, 'pending' => 1, 'active' => 1, 'error' => 1, 'removing' => 0));
expect_same('websites stay complete under a filter', count($list['sites']), 2);
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array('site' => 'all', 'state' => 'error')));
expect_same('global rows with an error', exception_ids($list), array(2));
$list = waf_panel_exception_list($exception_rows, waf_panel_exception_filters(array('site' => '11', 'state' => 'error')));
expect_same('one website with an error', exception_ids($list), array(2, 3));
$list = waf_panel_exception_list(array_slice($exception_rows, 0, 1), waf_panel_exception_filters(array()));
expect_same('no global rows', $list['has_global'], false);

expect_same('exception query', waf_panel_exception_query(array('state' => 'error', 'site' => '12'), array('site' => '')),
	'state=error');
expect_same('exception query for every website',
	waf_panel_exception_query(array('state' => '', 'site' => ''), array('site' => 'all')), 'site=all');
expect_same('exception query with both', waf_panel_exception_query(array('state' => 'active', 'site' => '11'), array()),
	'state=active&site=11');
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: Abbruch mit „Call to undefined function waf_panel_exception_filters()"

- [ ] **Schritt 3: Funktionen schreiben**

`ispconfig/interface/lib/malwatch_waf_panel.inc.php` (anhängen):

```php
/**
 * The filters of the exception list. 'site' is the id of a website, 'all'
 * for the exceptions of every website, or '' for no filter; anything else
 * counts as no filter.
 */
function waf_panel_exception_filters($get)
{
	$state = isset($get['state']) ? (string) $get['state'] : '';
	$site = isset($get['site']) ? (string) $get['site'] : '';
	if ($site !== 'all' && preg_match('/^[1-9][0-9]{0,9}$/', $site) !== 1) {
		$site = '';
	}
	return array(
		'state' => in_array($state, array('pending', 'active', 'error', 'removing'), true) ? $state : '',
		'site' => $site,
	);
}

/**
 * The exception list for $filters. A website shows its own exceptions and
 * those for every website, because both apply to it. 'sites' names every
 * website with an exception of its own, sorted by name, whatever the filter;
 * 'counts' counts the states within the chosen website. $rows come from
 * malwatch_waf_exception.
 */
function waf_panel_exception_list($rows, $filters)
{
	$sites = array();
	$has_global = false;
	$counts = array('' => 0, 'pending' => 0, 'active' => 0, 'error' => 0, 'removing' => 0);
	$list = array();
	foreach ($rows as $row) {
		$global = strpos((string) $row['scope'], 'all') === 0;
		$site_id = (int) $row['parent_domain_id'];
		if ($global) {
			$has_global = true;
		} else {
			$sites[$site_id] = (string) $row['domain'];
		}
		if ($filters['site'] === 'all' && !$global) {
			continue;
		}
		if ($filters['site'] !== '' && $filters['site'] !== 'all' && !$global && $site_id !== (int) $filters['site']) {
			continue;
		}
		$state = (string) $row['exception_state'];
		$counts['']++;
		if (isset($counts[$state])) {
			$counts[$state]++;
		}
		if ($filters['state'] === '' || $state === $filters['state']) {
			$list[] = $row;
		}
	}
	asort($sites, SORT_NATURAL | SORT_FLAG_CASE);
	$choices = array();
	foreach ($sites as $id => $domain) {
		$choices[] = array('value' => (string) $id, 'label' => $domain);
	}
	return array('rows' => $list, 'sites' => $choices, 'has_global' => $has_global, 'counts' => $counts);
}

/** The exception list's query string with some filters changed. */
function waf_panel_exception_query($filters, $changes)
{
	$merged = array_merge($filters, $changes);
	$parts = array();
	if ($merged['state'] !== '') {
		$parts[] = 'state=' . rawurlencode($merged['state']);
	}
	if ($merged['site'] !== '') {
		$parts[] = 'site=' . rawurlencode($merged['site']);
	}
	return implode('&', $parts);
}
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 4: Texte anhängen**

`ispconfig/interface/lang/de_malwatch_waf.lng` (anhängen):

```php
$wb['exc_list_head_txt'] = 'Ausnahmen';
$wb['exc_list_sub_txt'] = 'Eine Ausnahme nimmt eine Regel aus der Prüfung, für eine Website, einen Pfad, einen Parameter oder websiteübergreifend. Angelegt wird sie auf der Seite einer Website über „Ausnahme …“.';
$wb['exc_filter_site_txt'] = 'Website';
$wb['exc_filter_global_txt'] = 'websiteübergreifend';
$wb['exc_count_txt'] = '%s (%s)';
$wb['exc_list_none_txt'] = 'Für diese Auswahl gibt es keine Ausnahme.';
$wb['exc_list_empty_txt'] = 'Es ist noch keine Ausnahme angelegt.';
```

`ispconfig/interface/lang/en_malwatch_waf.lng` (anhängen):

```php
$wb['exc_list_head_txt'] = 'Exceptions';
$wb['exc_list_sub_txt'] = 'An exception takes a rule out of the check, for a website, a path, a parameter or across websites. It is added on the page of a website with "Exception …".';
$wb['exc_filter_site_txt'] = 'Website';
$wb['exc_filter_global_txt'] = 'across websites';
$wb['exc_count_txt'] = '%s (%s)';
$wb['exc_list_none_txt'] = 'No exception matches this choice.';
$wb['exc_list_empty_txt'] = 'No exception has been added yet.';
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden` (beide Sprachdateien tragen dieselben Schlüssel)

- [ ] **Schritt 5: Seite schreiben**

`ispconfig/interface/malwatch_waf_exception_list.php`:

```php
<?php

/**
 * Abwehr: every exception with its state, filtered by state and website.
 * "Entfernen" queues a job like the page of a website; the malwatch cron
 * takes the exception out of the rule files, and the page follows the job.
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

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_waf.lng';
}
include $lng_file;

$message = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	list($message, $error) = waf_panel_handle_post($app, $wb, $_POST);
}

// After a button the filters come back as hidden fields of the form.
$filters = waf_panel_exception_filters(array_merge($_GET, $_POST));

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_waf_exception_list.htm');
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('btn_exception_remove_txt', 'confirm_exception_remove_txt')));
$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

// Running jobs are followed like on the overview.
$first_job = 0;
$job_rows = array();
foreach (waf_panel_rows($app->db->queryAllRecords(
	"SELECT job_id, job_status, options, job_log FROM malwatch_job WHERE job_kind = 'waf' "
	. "AND job_status IN ('pending','running') ORDER BY job_id")) as $row) {
	$job = waf_panel_job($wb, $row);
	$first_job = $first_job === 0 ? $job['job_id'] : $first_job;
	$job_rows[] = array('job_line' => $app->functions->htmlentities($job['label'] . ': ' . $job['status_label']));
}
$app->tpl->setLoop('jobs', $job_rows);
$app->tpl->setVar('has_jobs', count($job_rows) > 0 ? 1 : 0);
$app->tpl->setVar('first_job', $first_job);

$all_rows = waf_panel_rows($app->db->queryAllRecords('SELECT * FROM malwatch_waf_exception ORDER BY exception_id DESC'));
$list = waf_panel_exception_list($all_rows, $filters);
$link = 'security/malwatch_waf_exception_list.php';

$state_links = array();
foreach (array('', 'active', 'pending', 'error', 'removing') as $state) {
	$query = waf_panel_exception_query($filters, array('state' => $state));
	$state_links[] = array(
		'label' => $app->functions->htmlentities(sprintf($wb['exc_count_txt'],
			$state === '' ? $wb['filter_all_txt'] : waf_panel_exception_state_label($wb, $state),
			number_format($list['counts'][$state], 0, ',', '.'))),
		'href' => $app->functions->htmlentities($link . ($query !== '' ? '?' . $query : '')),
		'current' => $state === $filters['state'] ? 1 : 0,
	);
}
$app->tpl->setLoop('state_links', $state_links);

$site_links = array(array('value' => '', 'label' => $wb['filter_all_txt']));
if ($list['has_global']) {
	$site_links[] = array('value' => 'all', 'label' => $wb['exc_filter_global_txt']);
}
foreach ($list['sites'] as $choice) {
	$site_links[] = $choice;
}
$sites = array();
foreach ($site_links as $choice) {
	$query = waf_panel_exception_query($filters, array('site' => $choice['value']));
	$sites[] = array(
		'label' => $app->functions->htmlentities($choice['label']),
		'href' => $app->functions->htmlentities($link . ($query !== '' ? '?' . $query : '')),
		'current' => $choice['value'] === $filters['site'] ? 1 : 0,
	);
}
$app->tpl->setLoop('site_links', $sites);
$app->tpl->setVar('has_site_links', count($sites) > 1 ? 1 : 0);

$rows = array();
foreach ($list['rows'] as $row) {
	$exception = waf_panel_exception_row($wb, $row);
	$rows[] = array(
		'exception_id' => $exception['exception_id'],
		'exc_rule' => $app->functions->htmlentities($exception['rule_id']),
		'exc_rule_title' => $app->functions->htmlentities(waf_panel_rule_title($wb, $exception['rule_id'], '')),
		'exc_site' => $app->functions->htmlentities($exception['site']),
		'exc_site_href' => strpos((string) $row['scope'], 'site') === 0
			? $app->functions->htmlentities('security/malwatch_waf_show.php?id=' . $exception['site_id']) : '',
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
$app->tpl->setLoop('rows', $rows);
$app->tpl->setVar('has_rows', count($rows) > 0 ? 1 : 0);
$app->tpl->setVar('has_any', count($all_rows) > 0 ? 1 : 0);

$query = waf_panel_exception_query($filters, array());
$app->tpl->setVar('self_href', $app->functions->htmlentities($link . ($query !== '' ? '?' . $query : '')));
$app->tpl->setVar('filter_state', $app->functions->htmlentities($filters['state']));
$app->tpl->setVar('filter_site', $app->functions->htmlentities($filters['site']));

$csrf = $app->auth->csrf_token_get('malwatch_waf_exception_list');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
```

- [ ] **Schritt 6: Vorlage schreiben**

`ispconfig/interface/templates/malwatch_waf_exception_list.htm`:

```html
<div class='page-header'>
	<h1>{tmpl_var name='exc_list_head_txt'}</h1>
</div>

<tmpl_if name="message">
	<div class="alert alert-success">{tmpl_var name='message'}</div>
</tmpl_if>
<tmpl_if name="error">
	<div class="alert alert-danger">{tmpl_var name='error'}</div>
</tmpl_if>

<style>
/* The rules of the other pages of the addon: muted text through opacity,
   lines and areas as translucent grey, fixed colours only for accent and
   alarm. */
#mw-wafexc .mw-back{margin:0 0 10px}
#mw-wafexc .mw-sub{margin:0 0 14px;opacity:.72;font-size:13px;max-width:80ch}
#mw-wafexc .mw-bar{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin:0 0 8px}
#mw-wafexc .mw-caption{font-size:12px;opacity:.72;margin-right:4px}
#mw-wafexc .mw-seg{display:inline-block;padding:3px 9px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-radius:3px;font-size:12.5px;color:inherit;text-decoration:none}
#mw-wafexc .mw-seg[aria-current="true"]{border-color:var(--cic-accent,#dd630d);color:var(--cic-accent-text,#dd630d);font-weight:600}
#mw-wafexc .mw-seg:focus-visible{outline:2px solid var(--cic-accent,#dd630d);outline-offset:2px}
#mw-wafexc .mw-dim{opacity:.72;font-size:12.5px}
#mw-wafexc .mw-mono{font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
#mw-wafexc .mw-failed{color:var(--cic-bad-text,#d13f22)}
#mw-wafexc .mw-jobs{margin:0 0 14px;padding:10px 14px;border:1px solid var(--cic-line-soft,rgba(128,128,128,.35));
	border-left:3px solid var(--cic-accent,#dd630d);border-radius:3px;font-size:13px}
#mw-wafexc .mw-jobs ul{margin:4px 0 0;padding-left:18px}
#mw-wafexc .table-wrapper{overflow-x:auto;margin-top:12px}
#mw-wafexc .table{table-layout:auto}
#mw-wafexc .table > thead > tr > th,
#mw-wafexc .table > tbody > tr > td{padding:6px 10px;vertical-align:top}
/* Paths break anywhere; without a floor the column shrinks to a few letters. */
#mw-wafexc td.mw-rulecell{min-width:20ch}
#mw-wafexc td.mw-sitecell{min-width:14ch}
#mw-wafexc td.mw-target{min-width:24ch}
</style>

<div id="mw-wafexc" data-mw-jobs="security/malwatch_waf_jobs.php?since={tmpl_var name='first_job'}"
	data-mw-self="{tmpl_var name='self_href'}">

<p class="mw-back"><a href="#" data-load-content="security/malwatch_waf_list.php">{tmpl_var name='show_back_txt'}</a></p>
<p class="mw-sub">{tmpl_var name='exc_list_sub_txt'}</p>

<!-- The panel wraps the content area in pageForm; the buttons name their action in waf_action. -->
<input type="hidden" name="waf_action" id="mw-waf-action" value="" />
<input type="hidden" name="waf_exception" id="mw-waf-exception" value="" />
<input type="hidden" name="state" value="{tmpl_var name='filter_state'}" />
<input type="hidden" name="site" value="{tmpl_var name='filter_site'}" />

<tmpl_if name="has_jobs">
<div class="mw-jobs" id="mw-waf-jobs" aria-live="polite">
	<strong>{tmpl_var name='jobs_head_txt'}</strong>
	<ul>
		<tmpl_loop name="jobs"><li>{tmpl_var name='job_line'}</li></tmpl_loop>
	</ul>
</div>
</tmpl_if>

<tmpl_if name="has_any">
<div class="mw-bar">
	<span class="mw-caption">{tmpl_var name='filter_state_txt'}</span>
	<tmpl_loop name="state_links"><a class="mw-seg" href="#" data-load-content="{tmpl_var name='href'}"<tmpl_if name="current"> aria-current="true"</tmpl_if>>{tmpl_var name='label'}</a></tmpl_loop>
</div>
<tmpl_if name="has_site_links">
<div class="mw-bar">
	<span class="mw-caption">{tmpl_var name='exc_filter_site_txt'}</span>
	<tmpl_loop name="site_links"><a class="mw-seg" href="#" data-load-content="{tmpl_var name='href'}"<tmpl_if name="current"> aria-current="true"</tmpl_if>>{tmpl_var name='label'}</a></tmpl_loop>
</div>
</tmpl_if>

<tmpl_if name="has_rows">
<div class="table-wrapper">
<table class="table">
	<thead class="dark">
		<tr>
			<th>{tmpl_var name='form_rule_txt'}</th>
			<th>{tmpl_var name='col_site_txt'}</th>
			<th>{tmpl_var name='col_scope_txt'}</th>
			<th>{tmpl_var name='col_target_txt'}</th>
			<th>{tmpl_var name='col_note_txt'}</th>
			<th>{tmpl_var name='col_exc_state_txt'}</th>
			<th>{tmpl_var name='col_created_txt'}</th>
			<th>&nbsp;</th>
		</tr>
	</thead>
	<tbody>
		<tmpl_loop name="rows">
		<tr>
			<td class="mw-rulecell"><span class="mw-mono">{tmpl_var name='exc_rule'}</span><div class="mw-dim">{tmpl_var name='exc_rule_title'}</div></td>
			<td class="mw-sitecell"><tmpl_if name="exc_site_href"><a href="#" data-load-content="{tmpl_var name='exc_site_href'}">{tmpl_var name='exc_site'}</a><tmpl_else>{tmpl_var name='exc_site'}</tmpl_if></td>
			<td>{tmpl_var name='exc_scope'}</td>
			<td class="mw-mono mw-target">{tmpl_var name='exc_target'}</td>
			<td>{tmpl_var name='exc_note'}</td>
			<td<tmpl_if name="exc_failed"> class="mw-failed"</tmpl_if>>{tmpl_var name='exc_state'}<tmpl_if name="exc_error"><div class="mw-dim">{tmpl_var name='exc_error'}</div></tmpl_if></td>
			<td class="mw-dim">{tmpl_var name='exc_created'}</td>
			<td><tmpl_if name="can_remove">
				<button class="btn btn-danger btn-xs" type="button"
					data-mw-confirm="{tmpl_var name='confirm_exception_remove_txt'}" data-mw-title="{tmpl_var name='btn_exception_remove_txt'}"
					data-mw-ok="{tmpl_var name='btn_exception_remove_txt'}" data-mw-danger="1"
					data-mw-set-mw-waf-action="exception_remove" data-mw-set-mw-waf-exception="{tmpl_var name='exception_id'}"
					data-submit-form="pageForm" data-form-action="security/malwatch_waf_exception_list.php">{tmpl_var name='btn_exception_remove_txt'}</button>
			</tmpl_if></td>
		</tr>
		</tmpl_loop>
	</tbody>
</table>
</div>
<tmpl_else>
<p class="mw-sub">{tmpl_var name='exc_list_none_txt'}</p>
</tmpl_if>
<tmpl_else>
<p class="mw-sub">{tmpl_var name='exc_list_empty_txt'}</p>
</tmpl_if>

</div>

<script>
(function () {
	// Follows running jobs like the overview and fetches the page once when none is left.
	var root = document.getElementById('mw-wafexc');
	var box = document.getElementById('mw-waf-jobs');
	if (!root || !box) { return; }
	var timer = null;
	function stop() { if (timer) { clearInterval(timer); timer = null; } }
	var host = document.getElementById('pageContent');
	if (host && window.MutationObserver) {
		new MutationObserver(function () {
			if (!document.contains(root)) { stop(); }
		}).observe(host, { childList: true, subtree: true });
	}
	function refresh() {
		stop();
		if (window.ISPConfig && document.contains(root)) {
			ISPConfig.loadContent(root.getAttribute('data-mw-self'));
		}
	}
	function poll() {
		if (!document.contains(root)) { stop(); return; }
		var xhr = new XMLHttpRequest();
		xhr.open('GET', root.getAttribute('data-mw-jobs'), true);
		xhr.onload = function () {
			if (!document.contains(root)) { stop(); return; }
			var data = null;
			try { data = JSON.parse(xhr.responseText); } catch (e) { return; }
			if (!data || !data.jobs) { return; }
			var list = box.querySelector('ul');
			while (list && list.firstChild) { list.removeChild(list.firstChild); }
			for (var i = 0; list && i < data.jobs.length; i++) {
				var item = document.createElement('li');
				item.textContent = data.jobs[i].label + ': ' + data.jobs[i].status_label + (data.jobs[i].log ? ' – ' + data.jobs[i].log : '');
				list.appendChild(item);
			}
			if (data.running === 0) { refresh(); }
		};
		xhr.send();
	}
	timer = setInterval(poll, 5000);
})();
</script>

<tmpl_include file="templates/malwatch_modal.htm">
```

- [ ] **Schritt 7: Eintragen**

In `ispconfig/install/file.list` nach der Zeile
`c:interface/templates/malwatch_waf_show.htm:interface/web/security/templates/malwatch_waf_show.htm`:

```text
c:interface/malwatch_waf_exception_list.php:interface/web/security/malwatch_waf_exception_list.php
c:interface/templates/malwatch_waf_exception_list.htm:interface/web/security/templates/malwatch_waf_exception_list.htm
```

In `ispconfig/tests/render_pages.php` in `$pages` nach `'malwatch_waf_show.php?days=90',`:

```php
	// Abwehr: every exception, once filtered by a state.
	'malwatch_waf_exception_list.php',
	'malwatch_waf_exception_list.php?state=active',
```

- [ ] **Schritt 8: Prüfen**

Run: `php -l ispconfig/interface/malwatch_waf_exception_list.php`
Expected: `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 9: Commit**

```bash
git add ispconfig/interface/malwatch_waf_exception_list.php ispconfig/interface/templates/malwatch_waf_exception_list.htm ispconfig/interface/lib/malwatch_waf_panel.inc.php ispconfig/tests/waf_panel_test.php ispconfig/interface/lang/de_malwatch_waf.lng ispconfig/interface/lang/en_malwatch_waf.lng ispconfig/install/file.list ispconfig/tests/render_pages.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): list of every exception with state and website filters" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B7: Einstellungen `malwatch_waf_config_edit.php`

Die Zahlen und Zeiträume der Abwehr auf einer eigenen Formularseite: Aufbewahrung,
Voraussetzungen für „scharf", Grenzen des Crons. Die Seite arbeitet mit einer eigenen
Formulardefinition auf derselben Zeile `malwatch_config` (`config_id = 1`); die
bestehende Einstellungsseite bleibt unverändert. Pfade, Seitenantwort und Notaus zeigt
sie nur an. Speichern reiht je Webserver einen Auftrag `apply_settings` ein und bleibt
auf der Seite.

Zwei Eigenheiten von ISPConfig 3.3.1p1 bestimmen den Aufbau (nachgelesen in
`interface/lib/classes/tform_base.inc.php` und `tform_actions.inc.php`):

- `tform_base::_encode()` prüft den CSRF-Schlüssel beim Speichern selbst und lässt ihn
  gültig. `auth::csrf_token_check()` verbraucht ihn dagegen. Prüft die Seite vorher
  selbst, findet `_encode()` den Schlüssel nicht mehr und meldet „CSRF attempt
  blocked". Die Seite prüft deshalb nicht selbst.
- `tform_actions::onError()` legt die Fehler der Prüfregeln in die Variable `error`,
  und `tabbed_form.tpl.htm` zeigt sie an. Die Seite überschreibt `error` nicht; ihre
  eigene Meldung heißt `waf_message`.

**Dateien:**
- Neu: `ispconfig/interface/malwatch_waf_config_edit.php`,
  `ispconfig/interface/form/malwatch_waf_config.tform.php`,
  `ispconfig/interface/templates/malwatch_waf_config_edit.htm`,
  `ispconfig/interface/lang/de_malwatch_waf_config.lng`,
  `ispconfig/interface/lang/en_malwatch_waf_config.lng`
- Ändern: `ispconfig/tests/waf_panel_test.php`
- Ändern: `ispconfig/install/file.list`, `ispconfig/tests/render_pages.php`,
  `ispconfig/tests/check_wiring.sh` (Prüfung 59)

**Schnittstellen:**
- Nutzt: `waf_settings_defaults()`, `waf_settings_limits()` (A4), `waf_panel_settings()`,
  `waf_panel_web_servers()`, `waf_panel_queue()` (B3), `malwatch_datetime()`; die Klassen
  `tform` und `tform_actions` des Panels
- Liefert: die Seite `security/malwatch_waf_config_edit.php`, die Übersicht (B4) verlinkt
  sie; Auftrag `apply_settings` ohne weitere Felder (A7 führt ihn aus)

- [ ] **Schritt 1: Prüfung schreiben**

In `ispconfig/tests/check_wiring.sh` vor der Zeile `if [ "$status" -eq 0 ]; then`:

```sh
# 59. Die Einstellungsseite der Abwehr bekommt ihre Texte von tform, und tform
#     liest nur de_/en_malwatch_waf_config.lng. Ein Schluessel aus einer
#     anderen Sprachdatei besteht Pruefung 9 und bleibt trotzdem leer. Den
#     Token prueft tform beim Speichern selbst; eine eigene Pruefung der Seite
#     verbraucht ihn vorher, und das Speichern scheitert. Ueberschriften als
#     p.fieldset-legend blendet ispconfig.css aus.
cfg_tpl="$root/interface/templates/malwatch_waf_config_edit.htm"
if [ -f "$cfg_tpl" ]; then
	for key in $(grep -ohE "tmpl_var name=['\"][a-z_]+_txt['\"]" "$cfg_tpl" | sed -E "s/.*['\"]([a-z_]+_txt)['\"]/\1/" | sort -u); do
		for lang in de en; do
			grep -qE "\\\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf_config.lng" 2>/dev/null \
				|| fail "malwatch_waf_config_edit.htm nutzt {$key}, das ${lang}_malwatch_waf_config.lng nicht setzt"
		done
	done
	grep -q 'data-form-action="security/malwatch_waf_config_edit.php"' "$cfg_tpl" \
		|| fail "malwatch_waf_config_edit.htm speichert nicht ueber die eigene Seite"
	grep -q 'formbutton-success' "$cfg_tpl" \
		|| fail "malwatch_waf_config_edit.htm hat keinen Knopf formbutton-success; Enter speichert dann nicht"
	if grep -q 'class="fieldset-legend"' "$cfg_tpl"; then
		fail "malwatch_waf_config_edit.htm setzt Ueberschriften als p.fieldset-legend; ispconfig.css blendet sie aus"
	fi
else
	fail "interface/templates/malwatch_waf_config_edit.htm fehlt"
fi
if grep -q -- '->csrf_token_check(' "$root/interface/malwatch_waf_config_edit.php" 2>/dev/null; then
	fail "malwatch_waf_config_edit.php prueft den Token selbst; tform findet ihn danach nicht mehr"
fi
```

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `FAIL: interface/templates/malwatch_waf_config_edit.htm fehlt`

- [ ] **Schritt 2: Test für Formulardefinition und Texte schreiben**

`ispconfig/tests/waf_panel_test.php` (Abschnitt vor summary):

```php
// --- B7: settings form -------------------------------------------------------

function waf_config_form()
{
	$form = array();
	$file = __DIR__ . '/../interface/form/malwatch_waf_config.tform.php';
	if (is_file($file)) {
		include $file;
	}
	return $form + array('name' => '', 'db_table' => '', 'db_table_idx' => '', 'title' => '', 'tabs' => array());
}

function waf_config_words($lang)
{
	$wb = array();
	$file = __DIR__ . '/../interface/lang/' . $lang . '_malwatch_waf_config.lng';
	if (is_file($file)) {
		include $file;
	}
	return $wb;
}

$config_form = waf_config_form();
expect_same('settings form row', array($config_form['name'], $config_form['db_table'], $config_form['db_table_idx']),
	array('malwatch_waf_config', 'malwatch_config', 'config_id'));
$config_tab = isset($config_form['tabs']['waf']) ? $config_form['tabs']['waf'] : array('title' => '', 'fields' => array());
expect_same('settings form edits the numbers only', array_keys($config_tab['fields']), array_keys(waf_settings_limits()));
$config_words = array('de' => waf_config_words('de'), 'en' => waf_config_words('en'));
expect_same('settings words in both languages', array(
	array_values(array_diff(array_keys($config_words['de']), array_keys($config_words['en']))),
	array_values(array_diff(array_keys($config_words['en']), array_keys($config_words['de']))),
), array(array(), array()));
$config_defaults = waf_settings_defaults();
foreach (waf_settings_limits() as $key => $limit) {
	$field = isset($config_tab['fields'][$key]) ? $config_tab['fields'][$key] : array();
	$validator = isset($field['validators'][0]) ? $field['validators'][0] : array();
	expect_same("settings form type of $key", array(
		isset($field['datatype']) ? $field['datatype'] : '',
		isset($validator['type']) ? $validator['type'] : '',
	), array('INTEGER', 'RANGE'));
	expect_same("settings form range of $key", isset($validator['range']) ? $validator['range'] : '', $limit[0] . ':' . $limit[1]);
	expect_same("settings form default of $key", isset($field['default']) ? $field['default'] : '', (string) $config_defaults[$key]);
	expect_same("settings form message of $key",
		isset($validator['errmsg']) && isset($config_words['de'][$validator['errmsg']]), true);
	expect_same("settings form label of $key", isset($config_words['de'][$key . '_txt']), true);
}
expect_same('settings form title and tab', array(
	isset($config_words['de'][$config_form['title']]),
	isset($config_words['de'][$config_tab['title']]),
), array(true, true));
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `FAIL settings form row: …`, dazu je Feld `FAIL settings form …`, Ende `… Fehler`

- [ ] **Schritt 3: Formulardefinition und Sprachdateien schreiben**

`ispconfig/interface/form/malwatch_waf_config.tform.php`:

```php
<?php

/**
 * Form definition for the settings of the Abwehr: the numbers and periods of
 * the WAF on the settings row of malwatch (config_id 1). The ranges are those
 * of waf_settings_limits(), the defaults those of waf_settings_defaults();
 * waf_panel_test.php holds the three together. Paths, response body and
 * emergency stop are no fields here: install.sh sets the paths, the overview
 * switches the other two through jobs.
 */

$form['title'] = 'waf_config_head_txt';
$form['description'] = '';
$form['name'] = 'malwatch_waf_config';
$form['action'] = 'malwatch_waf_config_edit.php';
$form['db_table'] = 'malwatch_config';
$form['db_table_idx'] = 'config_id';
$form['db_history'] = 'no';
$form['tab_default'] = 'waf';
$form['list_default'] = 'malwatch_waf_list.php';
$form['auth'] = 'no';

$form['tabs']['waf'] = array(
	'title' => 'waf_tab_txt',
	'width' => 100,
	'template' => 'templates/malwatch_waf_config_edit.htm',
	'fields' => array(
		'waf_detail_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:3650',
					'errmsg' => 'waf_detail_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_stats_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '90',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:3650',
					'errmsg' => 'waf_stats_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '4'
		),
		'waf_log_keep_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:365',
					'errmsg' => 'waf_log_keep_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_preview_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '1:365',
					'errmsg' => 'waf_preview_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_min_detect_days' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '7',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '0:365',
					'errmsg' => 'waf_min_detect_days_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '3'
		),
		'waf_ingest_max_lines' => array(
			'datatype' => 'INTEGER',
			'formtype' => 'TEXT',
			'default' => '5000',
			'validators' => array(
				array(
					'type' => 'RANGE',
					'range' => '100:100000',
					'errmsg' => 'waf_ingest_max_lines_error_range'
				)
			),
			'value' => '',
			'width' => '10',
			'maxlength' => '6'
		),
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
		)
	)
);
```

`ispconfig/interface/lang/de_malwatch_waf_config.lng`:

```php
<?php
$wb['waf_config_head_txt'] = 'Abwehr – Einstellungen';
$wb['waf_tab_txt'] = 'Einstellungen';
$wb['waf_config_desc_txt'] = 'Gilt für alle Websites auf diesem Server. Der malwatch-Cron liest die Werte bei jedem Durchgang; die Aufbewahrung des Audit-Logs trägt ein Auftrag in die Datei von logrotate ein.';

$wb['keep_head_txt'] = 'Aufbewahrung';
$wb['waf_detail_days_txt'] = 'Einzelne Anfragen (Tage)';
$wb['waf_detail_days_hint_txt'] = 'Kopfzeilen, Anfrageinhalt und Seitenantwort je Treffer. Danach bleiben die Tageszahlen.';
$wb['waf_stats_days_txt'] = 'Tageszahlen (Tage)';
$wb['waf_stats_days_hint_txt'] = 'Treffer je Tag, Regel und Pfad. Der längste Zeitraum der Übersicht richtet sich danach.';
$wb['waf_log_keep_days_txt'] = 'Audit-Log (Tage)';
$wb['waf_log_keep_days_hint_txt'] = 'logrotate dreht das Audit-Log täglich und behält so viele Stände.';

$wb['enforce_head_txt'] = 'Scharf schalten';
$wb['waf_min_detect_days_txt'] = 'Mitschreiben vor „scharf“ (Tage)';
$wb['waf_min_detect_days_hint_txt'] = 'So lange schreibt eine Website mit, bevor der Knopf „scharf“ frei wird. 0 gibt ihn sofort frei.';
$wb['waf_preview_days_txt'] = 'Vorschau (Tage)';
$wb['waf_preview_days_hint_txt'] = 'Über diesen Zeitraum zählt die Vorschau für „scharf“ und für Ausnahmen.';

$wb['cron_head_txt'] = 'Cron';
$wb['waf_ingest_max_lines_txt'] = 'Zeilen je Durchgang';
$wb['waf_ingest_max_lines_hint_txt'] = 'So viele Zeilen des Audit-Logs liest ein Durchgang höchstens; den Rest liest der nächste.';
$wb['waf_job_deadline_minutes_txt'] = 'Frist für den vhost (Minuten)';
$wb['waf_job_deadline_minutes_hint_txt'] = 'So lange wartet ein Zustandswechsel darauf, dass ISPConfig den vhost neu schreibt. Danach nimmt der Auftrag die Änderung zurück.';

$wb['facts_head_txt'] = 'Stand auf dem Server';
$wb['audit_log_txt'] = 'Audit-Log';
$wb['conf_dir_txt'] = 'Regelverzeichnis';
$wb['response_body_txt'] = 'Seitenantwort';
$wb['response_full_txt'] = 'vollständig';
$wb['response_lean_txt'] = 'schlank';
$wb['emergency_txt'] = 'Notaus';
$wb['emergency_off_txt'] = 'aus';
$wb['emergency_on_txt'] = 'aktiv seit %s';
$wb['facts_hint_txt'] = 'Die Pfade legt waf/install.sh fest. Seitenantwort und Notaus schalten die Knöpfe auf der Übersicht.';

$wb['btn_save_txt'] = 'Einstellungen speichern';
$wb['btn_back_txt'] = 'Zur Übersicht';
$wb['msg_saved_txt'] = 'Gespeichert. Der Cron übernimmt die Werte beim nächsten Durchgang.';
$wb['msg_saved_no_server_txt'] = 'Gespeichert. Es ist kein aktiver Webserver eingetragen, deshalb wartet kein Auftrag.';

$wb['waf_detail_days_error_range'] = 'Einzelne Anfragen: 1 bis 3650 Tage.';
$wb['waf_stats_days_error_range'] = 'Tageszahlen: 1 bis 3650 Tage.';
$wb['waf_log_keep_days_error_range'] = 'Audit-Log: 1 bis 365 Tage.';
$wb['waf_preview_days_error_range'] = 'Vorschau: 1 bis 365 Tage.';
$wb['waf_min_detect_days_error_range'] = 'Mitschreiben vor „scharf“: 0 bis 365 Tage.';
$wb['waf_ingest_max_lines_error_range'] = 'Zeilen je Durchgang: 100 bis 100000.';
$wb['waf_job_deadline_minutes_error_range'] = 'Frist für den vhost: 2 bis 120 Minuten.';
```

`ispconfig/interface/lang/en_malwatch_waf_config.lng`:

```php
<?php
$wb['waf_config_head_txt'] = 'Abwehr – settings';
$wb['waf_tab_txt'] = 'Settings';
$wb['waf_config_desc_txt'] = 'Applies to every website on this server. The malwatch cron reads the values at every pass; a job writes the retention of the audit log into the logrotate file.';

$wb['keep_head_txt'] = 'Retention';
$wb['waf_detail_days_txt'] = 'Single requests (days)';
$wb['waf_detail_days_hint_txt'] = 'Headers, request body and response body per hit. The day figures stay afterwards.';
$wb['waf_stats_days_txt'] = 'Day figures (days)';
$wb['waf_stats_days_hint_txt'] = 'Hits per day, rule and path. The longest period of the overview follows this value.';
$wb['waf_log_keep_days_txt'] = 'Audit log (days)';
$wb['waf_log_keep_days_hint_txt'] = 'logrotate rotates the audit log daily and keeps this many copies.';

$wb['enforce_head_txt'] = 'Enforcing';
$wb['waf_min_detect_days_txt'] = 'Detect before "enforce" (days)';
$wb['waf_min_detect_days_hint_txt'] = 'A website detects this long before the button "enforce" is free. 0 frees it at once.';
$wb['waf_preview_days_txt'] = 'Preview (days)';
$wb['waf_preview_days_hint_txt'] = 'The preview for "enforce" and for exceptions counts over this period.';

$wb['cron_head_txt'] = 'Cron';
$wb['waf_ingest_max_lines_txt'] = 'Lines per pass';
$wb['waf_ingest_max_lines_hint_txt'] = 'A pass reads at most this many lines of the audit log; the next pass reads the rest.';
$wb['waf_job_deadline_minutes_txt'] = 'Deadline for the vhost (minutes)';
$wb['waf_job_deadline_minutes_hint_txt'] = 'A change of state waits this long for ISPConfig to rewrite the vhost. After that the job takes the change back.';

$wb['facts_head_txt'] = 'State on the server';
$wb['audit_log_txt'] = 'Audit log';
$wb['conf_dir_txt'] = 'Rule directory';
$wb['response_body_txt'] = 'Response body';
$wb['response_full_txt'] = 'full';
$wb['response_lean_txt'] = 'lean';
$wb['emergency_txt'] = 'Emergency stop';
$wb['emergency_off_txt'] = 'off';
$wb['emergency_on_txt'] = 'active since %s';
$wb['facts_hint_txt'] = 'waf/install.sh sets the paths. The buttons on the overview switch the response body and the emergency stop.';

$wb['btn_save_txt'] = 'Save settings';
$wb['btn_back_txt'] = 'Back to the overview';
$wb['msg_saved_txt'] = 'Saved. The cron applies the values with its next pass.';
$wb['msg_saved_no_server_txt'] = 'Saved. No active web server is registered, so no job waits.';

$wb['waf_detail_days_error_range'] = 'Single requests: 1 to 3650 days.';
$wb['waf_stats_days_error_range'] = 'Day figures: 1 to 3650 days.';
$wb['waf_log_keep_days_error_range'] = 'Audit log: 1 to 365 days.';
$wb['waf_preview_days_error_range'] = 'Preview: 1 to 365 days.';
$wb['waf_min_detect_days_error_range'] = 'Detect before "enforce": 0 to 365 days.';
$wb['waf_ingest_max_lines_error_range'] = 'Lines per pass: 100 to 100000.';
$wb['waf_job_deadline_minutes_error_range'] = 'Deadline for the vhost: 2 to 120 minutes.';
```

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 4: Seite schreiben**

`ispconfig/interface/malwatch_waf_config_edit.php`:

```php
<?php

/**
 * Abwehr: the numbers and periods of the WAF on the settings row of malwatch
 * (config_id 1), with a form definition of its own. Paths, response body and
 * emergency stop are shown only. Saving queues apply_settings for every web
 * server, which writes the retention of the audit log into the logrotate
 * file; everything else is read by the cron at its next pass.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	die('Nur für Administratoren.');
}

// tform_actions::onLoad() reads this from the global scope.
$tform_def_file = 'form/malwatch_waf_config.tform.php';

$app->uses('tpl,tform,tform_actions,functions');
require_once 'lib/malwatch_lib.inc.php';
require_once 'lib/malwatch_waf_panel.inc.php';

class page_action extends tform_actions
{
	/** The texts, loaded in onLoad(). */
	private $waf_wb = array();

	/** Set by onAfterUpdate(), shown by onShowEnd(). */
	private $waf_message = '';

	public function onLoad()
	{
		global $app;

		$row = $app->db->queryOneRecord('SELECT config_id FROM malwatch_config WHERE config_id = 1');
		if (!is_array($row)) {
			$app->db->query('INSERT INTO malwatch_config (config_id, sys_userid, sys_groupid, sys_perm_user, '
				. "sys_perm_group, sys_perm_other) VALUES (1, 1, 1, 'riud', 'riud', '')");
		}
		$this->id = 1;
		$_REQUEST['id'] = 1;

		// tform loads the same file for its labels; the page needs the texts
		// for its own message.
		$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_waf_config.lng';
		if (!file_exists($lng_file)) {
			$lng_file = 'lib/lang/en_malwatch_waf_config.lng';
		}
		include $lng_file;
		$this->waf_wb = $wb;

		// After saving the page stays open and says what happens next. The form
		// has one tab, set here as well: tform saves the tab it last showed in
		// this session, and another form page may have changed that meanwhile.
		// The token is left to tform: it checks it while encoding the fields and
		// keeps it valid, and a check here would use it up first.
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			$_REQUEST['next_tab'] = 'waf';
			$_SESSION['s']['form']['tab'] = 'waf';
		}

		parent::onLoad();
	}

	public function onAfterUpdate()
	{
		global $app;
		$wb = $this->waf_wb;

		$servers = waf_panel_web_servers($app);
		foreach ($servers as $server_id) {
			waf_panel_queue($app, $server_id, 'apply_settings', array());
		}
		$this->waf_message = count($servers) > 0 ? $wb['msg_saved_txt'] : $wb['msg_saved_no_server_txt'];

		// The addon keeps exactly one settings row.
		$app->db->query('DELETE FROM malwatch_config WHERE config_id != 1');
		parent::onAfterUpdate();
	}

	public function onShowEnd()
	{
		global $app;
		$wb = $this->waf_wb;

		$settings = waf_panel_settings($app);
		$app->tpl->setVar('waf_audit_log', $app->functions->htmlentities($settings['waf_audit_log']));
		$app->tpl->setVar('waf_conf_dir', $app->functions->htmlentities($settings['waf_conf_dir']));
		$app->tpl->setVar('response_body_line', $app->functions->htmlentities(
			$settings['waf_response_body'] === 'lean' ? $wb['response_lean_txt'] : $wb['response_full_txt']));
		$app->tpl->setVar('emergency_line', $app->functions->htmlentities($settings['waf_emergency'] === 'y'
			? sprintf($wb['emergency_on_txt'], malwatch_datetime($settings['waf_emergency_since']))
			: $wb['emergency_off_txt']));
		$app->tpl->setVar('emergency_on', $settings['waf_emergency'] === 'y' ? 1 : 0);
		// 'error' belongs to tform: onError() puts the messages of the ranges there.
		$app->tpl->setVar('waf_message', $app->functions->htmlentities($this->waf_message));

		parent::onShowEnd();
	}
}

$page = new page_action();
$page->onLoad();
```

- [ ] **Schritt 5: Vorlage schreiben**

`ispconfig/interface/templates/malwatch_waf_config_edit.htm`:

```html
<!--
	A tab of tabbed_form.tpl.htm: the panel prints the title, the messages of
	the ranges and the token fields around it.
-->
<p class="mw-wafcfg-sub">{tmpl_var name='waf_config_desc_txt'}</p>

<tmpl_if name="waf_message">
	<div class="alert alert-success">{tmpl_var name='waf_message'}</div>
</tmpl_if>

<p class="mw-wafcfg-head">{tmpl_var name='keep_head_txt'}</p>

<div class="form-group">
	<label for="waf_detail_days" class="col-sm-3 control-label">{tmpl_var name='waf_detail_days_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="3650" step="1" name="waf_detail_days" id="waf_detail_days" value="{tmpl_var name='waf_detail_days'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_detail_days_hint_txt'}</span>
	</div>
</div>
<div class="form-group">
	<label for="waf_stats_days" class="col-sm-3 control-label">{tmpl_var name='waf_stats_days_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="3650" step="1" name="waf_stats_days" id="waf_stats_days" value="{tmpl_var name='waf_stats_days'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_stats_days_hint_txt'}</span>
	</div>
</div>
<div class="form-group">
	<label for="waf_log_keep_days" class="col-sm-3 control-label">{tmpl_var name='waf_log_keep_days_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="365" step="1" name="waf_log_keep_days" id="waf_log_keep_days" value="{tmpl_var name='waf_log_keep_days'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_log_keep_days_hint_txt'}</span>
	</div>
</div>

<p class="mw-wafcfg-head">{tmpl_var name='enforce_head_txt'}</p>

<div class="form-group">
	<label for="waf_min_detect_days" class="col-sm-3 control-label">{tmpl_var name='waf_min_detect_days_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="0" max="365" step="1" name="waf_min_detect_days" id="waf_min_detect_days" value="{tmpl_var name='waf_min_detect_days'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_min_detect_days_hint_txt'}</span>
	</div>
</div>
<div class="form-group">
	<label for="waf_preview_days" class="col-sm-3 control-label">{tmpl_var name='waf_preview_days_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="1" max="365" step="1" name="waf_preview_days" id="waf_preview_days" value="{tmpl_var name='waf_preview_days'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_preview_days_hint_txt'}</span>
	</div>
</div>

<p class="mw-wafcfg-head">{tmpl_var name='cron_head_txt'}</p>

<div class="form-group">
	<label for="waf_ingest_max_lines" class="col-sm-3 control-label">{tmpl_var name='waf_ingest_max_lines_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="100" max="100000" step="1" name="waf_ingest_max_lines" id="waf_ingest_max_lines" value="{tmpl_var name='waf_ingest_max_lines'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_ingest_max_lines_hint_txt'}</span>
	</div>
</div>
<div class="form-group">
	<label for="waf_job_deadline_minutes" class="col-sm-3 control-label">{tmpl_var name='waf_job_deadline_minutes_txt'}</label>
	<div class="col-sm-9">
		<input type="number" min="2" max="120" step="1" name="waf_job_deadline_minutes" id="waf_job_deadline_minutes" value="{tmpl_var name='waf_job_deadline_minutes'}" class="form-control mw-wafcfg-num" />
		<span class="help-block">{tmpl_var name='waf_job_deadline_minutes_hint_txt'}</span>
	</div>
</div>

<p class="mw-wafcfg-head">{tmpl_var name='facts_head_txt'}</p>

<dl class="mw-wafcfg-facts">
	<dt>{tmpl_var name='audit_log_txt'}</dt><dd><code>{tmpl_var name='waf_audit_log'}</code></dd>
	<dt>{tmpl_var name='conf_dir_txt'}</dt><dd><code>{tmpl_var name='waf_conf_dir'}</code></dd>
	<dt>{tmpl_var name='response_body_txt'}</dt><dd>{tmpl_var name='response_body_line'}</dd>
	<dt>{tmpl_var name='emergency_txt'}</dt><dd<tmpl_if name="emergency_on"> class="mw-wafcfg-alarm"</tmpl_if>>{tmpl_var name='emergency_line'}</dd>
</dl>
<p class="help-block">{tmpl_var name='facts_hint_txt'}</p>

<input type="hidden" name="id" value="{tmpl_var name='id'}">

<div class="clear"><div class="right">
	<button class="btn btn-default formbutton-success" type="button" value="{tmpl_var name='btn_save_txt'}"
		data-submit-form="pageForm" data-form-action="security/malwatch_waf_config_edit.php">{tmpl_var name='btn_save_txt'}</button>
	<button class="btn btn-default formbutton-default" type="button" value="{tmpl_var name='btn_back_txt'}"
		data-load-content="security/malwatch_waf_list.php">{tmpl_var name='btn_back_txt'}</button>
</div></div>

<style>
/* Muted text through opacity, fixed colours only for the alarm, as on the
   other pages of the addon. */
.mw-wafcfg-sub{margin:0 0 14px;opacity:.72;font-size:13px;max-width:80ch}
/* ispconfig.css hides p.fieldset-legend, so the sections carry their own heading. */
.mw-wafcfg-head{margin:22px 0 10px;padding-bottom:4px;font-size:15px;font-weight:600;
	border-bottom:1px solid var(--cic-line-soft,rgba(128,128,128,.35))}
.mw-wafcfg-num{max-width:14ch}
.mw-wafcfg-facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 18px;margin:0 0 8px}
.mw-wafcfg-facts dt{font-weight:400;opacity:.72}
.mw-wafcfg-facts dd{margin:0;word-break:break-all}
.mw-wafcfg-facts code{font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;font-size:12px}
.mw-wafcfg-alarm{color:var(--cic-bad-text,#d13f22);font-weight:600}
</style>
```

- [ ] **Schritt 6: Eintragen**

In `ispconfig/install/file.list` nach der Zeile
`c:interface/templates/malwatch_waf_exception_list.htm:interface/web/security/templates/malwatch_waf_exception_list.htm`:

```text
c:interface/malwatch_waf_config_edit.php:interface/web/security/malwatch_waf_config_edit.php
c:interface/templates/malwatch_waf_config_edit.htm:interface/web/security/templates/malwatch_waf_config_edit.htm
c:interface/form/malwatch_waf_config.tform.php:interface/web/security/form/malwatch_waf_config.tform.php
c:interface/lang/de_malwatch_waf_config.lng:interface/web/security/lib/lang/de_malwatch_waf_config.lng
c:interface/lang/en_malwatch_waf_config.lng:interface/web/security/lib/lang/en_malwatch_waf_config.lng
```

In `ispconfig/tests/render_pages.php` in `$pages` nach `'malwatch_waf_exception_list.php?state=active',`:

```php
	// Abwehr: the settings, a form page like malwatch_config_edit.php.
	'malwatch_waf_config_edit.php',
```

- [ ] **Schritt 7: Prüfen**

Run: `php -l ispconfig/interface/malwatch_waf_config_edit.php && php -l ispconfig/interface/form/malwatch_waf_config.tform.php`
Expected: zweimal `No syntax errors detected`

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: `Wiring OK`

Run: `php ispconfig/tests/waf_panel_test.php`
Expected: `waf_panel: alle Prüfungen bestanden`

- [ ] **Schritt 8: Commit**

```bash
git add ispconfig/interface/malwatch_waf_config_edit.php ispconfig/interface/form/malwatch_waf_config.tform.php ispconfig/interface/templates/malwatch_waf_config_edit.htm ispconfig/interface/lang/de_malwatch_waf_config.lng ispconfig/interface/lang/en_malwatch_waf_config.lng ispconfig/tests/waf_panel_test.php ispconfig/install/file.list ispconfig/tests/render_pages.php ispconfig/tests/check_wiring.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(abwehr): settings page for periods and cron limits" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

### Aufgabe B8: Version 0.19.0, Dokumentation und Spec

Die Version steht im Panel und im Scanner; beide Dateien ziehen zuerst nach. Danach
CHANGELOG, die beiden README-Dateien und die Spec mit den Entscheidungen aus beiden
Plänen. Zum Schluss laufen alle Prüfungen am Rechner. Geschoben, getaggt und nach `main`
gebracht wird erst in Aufgabe B9 mit Freigabe von Mathias.

**Dateien:**
- Ändern: `ispconfig/version`, `internal/version/version.go`, `CHANGELOG.md`, `README.md`,
  `ispconfig/README.md`, `docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md`

**Schnittstellen:**
- Nutzt: alle Aufgaben aus Teil A und B1 bis B7
- Liefert: Stand 0.19.0 auf dem Zweig `waf-herkules`, lokal geprüft und committet

- [ ] **Schritt 1: Version anheben**

`ispconfig/version`:

```text
0.19.0
```

In `internal/version/version.go` die Zeile `var Version = "0.18.0"` ersetzen durch:

```go
var Version = "0.19.0"
```

Run: `cat ispconfig/version && grep -n 'var Version' internal/version/version.go`
Expected: `0.19.0` und `var Version = "0.19.0"`

- [ ] **Schritt 2: CHANGELOG**

In `CHANGELOG.md` direkt nach der Zeile `Alle nennenswerten Änderungen an diesem Projekt.`
und ihrer Leerzeile einfügen:

```markdown
## [0.19.0] – 2026-09-16

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
```

- [ ] **Schritt 3: README.md**

In `README.md` im Abschnitt „Das ISPConfig-Addon" direkt vor der Zeile
`Installation und Bedienung stehen in [ispconfig/README.md](ispconfig/README.md).`
einfügen:

```markdown
### Abwehr

**Security > Abwehr** schaltet die Web Application Firewall (ModSecurity mit dem
OWASP-Regelwerk) je Website zwischen „aus“, „mitschreiben“ und „scharf“ und wertet
ihr Audit-Log aus: Treffer je Website und Tag, Regeln im Klartext, einzelne Anfragen
und die Vorschau, was „scharf“ abgewiesen hätte. Ausnahmen entstehen per Knopf aus
einem Treffer. Auf dem Webserver richtet `waf/install.sh` die WAF ein, siehe
[waf/README.md](waf/README.md).

```

- [ ] **Schritt 4: ispconfig/README.md**

In `ispconfig/README.md` in der Tabelle unter „Was wo passiert" nach der Zeile, die mit
`| Cron-Klasse` beginnt, eine Zeile anfügen:

```markdown
| Klasse `malwatch_waf` | liest aus der Cron-Klasse das Audit-Log der WAF ein, führt WAF-Aufträge aus, räumt auf |
```

Direkt vor der Überschrift `## Aktionen` einfügen:

```markdown
## Abwehr

**Security > Abwehr** zeigt die WAF aller Websites dieses Servers. Die Seite füllt
sich, sobald `waf/install.sh` ModSecurity im nginx eingerichtet hat
([waf/README.md](../waf/README.md)).

| Zustand | Wirkung |
|---|---|
| aus | die Website läuft ohne WAF |
| mitschreiben | Treffer landen im Audit-Log, die Anfragen gehen durch |
| scharf | Anfragen über der Punktgrenze bekommen 403 |

- **Übersicht:** alle aktiven Websites mit Zustand, Treffern, „wäre abgewiesen“ und
  häufigster Regel; Mehrfachauswahl für den Zustand, dazu „Notaus“ und der Knopf für
  die Seitenantwort.
- **Website:** Schalter mit Vorschau für „scharf“, Verlauf, Regeln, Pfade, einzelne
  Anfragen, ihre Ausnahmen und das Formular „Ausnahme anlegen“.
- **Ausnahmen:** alle Ausnahmen mit Zustand und Fehlergrund, gefiltert nach Zustand
  und Website.
- **Einstellungen:** Aufbewahrung, Mindestdauer vor „scharf“, Zeitraum der Vorschau,
  Zeilen je Durchgang, Frist für den vhost.

Jeder Knopf legt einen Auftrag in `malwatch_job` mit `job_kind = 'waf'` an. Die
Cron-Klasse ruft jede Minute `malwatch_waf` auf: Sie liest höchstens so viele Zeilen
des Audit-Logs wie eingestellt (Lesestand je Server in
`/var/lib/malwatch/waf/reader.json`) und führt einen Auftrag nach dem anderen aus.
Ein Zustandswechsel läuft über das Feld „nginx-Direktiven“: Der Auftrag schreibt es,
wartet auf den vhost von ISPConfig, prüft `nginx -t` und bestätigt den Zustand. Nach
der Frist nimmt er seine Änderung zurück, sofern niemand das Feld inzwischen geändert
hat.

Dateien unter `/etc/nginx/waf` ändern sich nur über eine Kopie,
`modsec-rules-check`, `nginx -t` und einen Reload; der letzte geprüfte Stand liegt
unter `/var/lib/malwatch/waf/last-good/`. Der stündliche Wächter `waf-guard` legt ihn
zurück, wenn `nginx -t` eine Datei der WAF nennt, und schaltet auf den harten Notaus,
wenn das Modul fehlt.

Einzelne Anfragen enthalten Besucheradressen, Kopfzeilen und Anfrageinhalte und
bleiben so lange wie eingestellt; Werte von `Cookie` und `Authorization` werden vor
dem Speichern entfernt. Die Tageszahlen enthalten keine Adressen. Seitenantworten
liegen gepackt unter `/var/lib/malwatch/waf/responses/`, lesbar für root und das
Panel, und öffnen im Panel ausschließlich als Text.

```

Im Abschnitt „Entfernen" `löscht ihre zwölf Tabellen selbst` ersetzen durch:

```markdown
löscht ihre zwanzig Tabellen selbst
```

- [ ] **Schritt 5: Spec nachtragen**

In `docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md` jeden Text unter
„Alt" durch den Text unter „Neu" ersetzen. Jeder alte Text steht genau einmal in der
Datei.

**Alt** (Abschnitt 5, `malwatch_waf_site_day`):

~~~markdown
`would_block` (Transaktionen mit 949110), `logged_in_hits`. Eindeutig auf
~~~

**Neu:**

~~~markdown
`would_block` (Transaktionen mit 949110), `logged_in_hits`, `would_block_logged_in`
(Transaktionen mit 949110 von angemeldeten Nutzern, für die Vorschau). Eindeutig auf
~~~

**Alt** (Abschnitt 5, `malwatch_waf_day`):

~~~markdown
`day`, `parent_domain_id`, `domain`, `rule_id` varchar(16), `path` varchar(1024),
~~~

**Neu:**

~~~markdown
`day`, `parent_domain_id`, `domain`, `rule_id` varchar(16), `rule_msg` varchar(255)
(Meldung des Regelwerks für „Woran erkannt?"), `path` varchar(1024),
~~~

**Alt** (Abschnitt 5, Überschrift):

~~~markdown
### `malwatch_config` (erweitert) — Einstellungen und Lesestand
~~~

**Neu:**

~~~markdown
### `malwatch_config` (erweitert) — Einstellungen
~~~

**Alt** (Abschnitt 5, letzte Tabellenzeile):

~~~markdown
| `waf_emergency_since` | NULL | |
| `waf_log_inode`, `waf_log_offset` | 0 | Lesestand |
~~~

**Neu:**

~~~markdown
| `waf_emergency_since` | NULL | |

Der Lesestand liegt je Server in `<state_dir>/waf/reader.json` (Inode und Position),
weil `malwatch_config` eine Zeile für alle Server ist.
~~~

**Alt** (Abschnitt 6):

~~~markdown
7. Lesestand und Inode speichern.
~~~

**Neu:**

~~~markdown
7. Lesestand und Inode in `<state_dir>/waf/reader.json` speichern.
~~~

**Alt** (Abschnitt 8, Menü):

~~~markdown
`$app->auth->is_admin()` und antworten sonst leer. Formulare und Knöpfe nutzen
`csrf_token_get` und `csrf_token_check('POST')` wie die übrigen Seiten. Laufende
~~~

**Neu:**

~~~markdown
`$app->auth->is_admin()` und antworten sonst leer. Knöpfe schicken das Formular
`pageForm` an die eigene Seite und nutzen `csrf_token_get` und
`csrf_token_check('POST')` wie die übrigen Seiten; auf der Einstellungsseite prüft
`tform` den Schlüssel. Laufende
~~~

**Alt** (Abschnitt 8, Übersicht):

~~~markdown
  abgewiesen", häufigste Regel, Knöpfe „Ansehen" und „Zustand ändern".
- Mehrfachauswahl mit „Zustand ändern" für alle markierten Websites.
- Link „Ausnahmen (n)".
~~~

**Neu:**

~~~markdown
  abgewiesen", häufigste Regel, Knopf „Ansehen".
- Mehrfachauswahl mit „mitschreiben", „scharf" und „aus" für alle markierten
  Websites. Eine einzelne Website schaltet ihre eigene Seite, wo die Vorschau für
  „scharf" steht.
- Links „Ausnahmen (n)" und „Einstellungen".
~~~

**Alt** (Abschnitt 8, Formular für Ausnahmen):

~~~markdown
### Dialog „Ausnahme"
~~~

**Neu:**

~~~markdown
### Formular „Ausnahme anlegen"

Ein Bereich auf der Seite der Website, innerhalb von `pageForm`; ein Dialog am Ende
von `<body>` schickte seine Felder nicht mit. „Ausnahme …" an einer Regel oder
Anfrage füllt den Bereich und springt dorthin.
~~~

**Alt** (Abschnitt 8, Formular für Ausnahmen):

~~~markdown
- „Anlegen" legt die Zeile mit `pending` an und reiht einen Auftrag ein.
~~~

**Neu:**

~~~markdown
- „Ausnahme anlegen" fragt über den Dialog nach, legt die Zeile mit `pending` an und
  reiht einen Auftrag ein. Eigene Regeln (10000–10999) und Wertungsregeln (949…,
  959…, 980…) nimmt das Formular nicht an.
~~~

**Alt** (Abschnitt 8, Ausnahmen gesamt):

~~~markdown
Fehler, Anlage durch und am. Filter nach Zustand und Website, Knopf „Entfernen".
~~~

**Neu:**

~~~markdown
Fehler, Anlage durch und am. Filter nach Zustand und Website, Knopf „Entfernen". Der
Filter nach Website zeigt auch die websiteübergreifenden Ausnahmen, weil sie für die
Website gelten.
~~~

**Alt** (Abschnitt 8, Aktionen):

~~~markdown
### Aktionen — `malwatch_waf_action.php`

Ein POST-Endpunkt für alle Knöpfe. Prüft Adminrechte und CSRF, prüft die Eingaben,
legt Zeilen an und reiht Aufträge über `datalogInsert('malwatch_job', …)` ein. Antwort
als JSON für die Seiten.
~~~

**Neu:**

~~~markdown
### Aktionen

Die Knöpfe schicken wie auf den übrigen Seiten das Formular `pageForm` an die eigene
Seite. `waf_panel_handle_post()` in `lib/malwatch_waf_panel.inc.php` prüft die
Eingaben, legt Zeilen an und reiht Aufträge über `datalogInsert('malwatch_job', …)`
ein. JSON liefern `malwatch_waf_jobs.php` (laufende Aufträge für die Anzeige ohne
Neuladen) und `malwatch_waf_preview.php` (Vorschau einer Ausnahme).
~~~

**Alt** (Abschnitt 8, Einstellungen):

~~~markdown
Speichern. Felder: die Einstellungen aus Abschnitt 5 ohne Lesestand und Notaus.
Speichern reiht einen Auftrag `apply_settings` ein.
~~~

**Neu:**

~~~markdown
Speichern. Felder: die Zahlen und Zeiträume aus Abschnitt 5; Pfade, Seitenantwort
und Notaus zeigt die Seite nur an. Den CSRF-Schlüssel prüft `tform` beim Speichern
selbst, ohne ihn zu verbrauchen, deshalb prüft die Seite ihn nicht noch einmal.
Speichern reiht je Webserver einen Auftrag `apply_settings` ein und bleibt auf der
Seite.
~~~

**Alt** (Abschnitt 9, `set_state`):

~~~markdown
3. Folgende Durchgänge lesen den vhost mit `waf_vhost_state()`. Stimmt der Zustand,
   folgt `nginx -t`; bei Erfolg `waf_state`, `waf_state_since` setzen und den Auftrag
   abschließen.
~~~

**Neu:**

~~~markdown
3. Folgende Durchgänge lesen den vhost mit `waf_vhost_state()`. Stimmt der Zustand,
   folgt `nginx -t`, einmal für alle Websites, die der Durchgang bestätigt; bei Erfolg
   `waf_state`, `waf_state_since` setzen und den Auftrag abschließen.
~~~

**Alt** (Abschnitt 9, Ausnahmen erzeugen):

~~~markdown
Die Notiz gelangt nie in eine Regeldatei.
~~~

**Neu:**

~~~markdown
Die Notiz gelangt nie in eine Regeldatei. Eigene Regeln (10000–10999, darunter 10010
gegen Passwörter im Log) und Wertungsregeln (949…, 959…, 980…) werden abgewiesen.

Ein Auftrag nimmt genau eine Ausnahme auf oder heraus; die Regeldateien entstehen aus
den aktiven Ausnahmen und der des Auftrags. Bleiben beide Dateien gleich, folgt kein
Reload.
~~~

**Alt** (Abschnitt 9, Jede Dateiänderung):

~~~markdown
4. `nginx -t`. Bei Erfolg `systemctl reload nginx`, danach `systemctl is-active nginx`.
~~~

**Neu:**

~~~markdown
4. `nginx -t`. Bei Erfolg `systemctl reload nginx`, danach `systemctl is-active nginx`.
   Die Befehle laufen mit festem Pfad (`/usr/sbin/nginx`, `/usr/bin/systemctl`,
   `/usr/sbin/logrotate`), weil der Cron keinen verlässlichen `PATH` mitbringt.
~~~

**Alt** (Abschnitt 9, Notaus):

~~~markdown
  `waf.conf.off` umbenannt, alle Websites bekommen `off`. Die Prüfung mit `nginx -t`
~~~

**Neu:**

~~~markdown
  `waf.conf.off` umbenannt, alle Websites bekommen `off`. Der Auftrag schreibt dafür
  die vhost-Dateien direkt um und passt danach die Felder an: Ohne Modul verwirft der
  nginx-Test von ISPConfig jede neue vhost-Datei, solange eine andere noch
  `modsecurity` nennt. Die Prüfung mit `nginx -t`
~~~

**Alt** (Abschnitt 9, Markierungen umschreiben):

~~~markdown
`migrate_markers` sucht Felder mit der alten Markierung und schreibt sie mit dem Ablauf
von `set_state` auf die neue um, Zustand unverändert.
~~~

**Neu:**

~~~markdown
`migrate_markers` nimmt jede Website mit Block, alte oder neue Markierung. Die alte
Markierung schreibt der Auftrag mit dem Ablauf von `set_state` auf die neue um,
Zustand unverändert, und gleicht dabei `malwatch_site.waf_state` mit dem Feld ab.
~~~

**Alt** (Abschnitt 13, Am Rechner):

~~~markdown
5. Lesestand bei neuer Inode und gekürzter Datei.
~~~

**Neu:**

~~~markdown
5. Lesestand in `reader.json` bei neuer Inode und gekürzter Datei.
~~~

**Alt** (Abschnitt 13, Am Rechner):

~~~markdown
Dazu `check_wiring.sh` und `render_pages.php` gegen die echten Panel-Stylesheets.
~~~

**Neu:**

~~~markdown
Dazu `waf_panel_test.php` (Aufbereitung der Seiten und Formulardefinition),
`waf_panel_post_test.php` (Aktionen), `check_wiring.sh` und `render_pages.php`. Am
Server laufen vorab `waf_class_probe.php` gegen eine eigene Datenbank und
`waf_rules_probe.php` gegen die ausgelieferten Regeldateien.
~~~

**Alt** (Abschnitt 13, Am Server):

~~~markdown
1. bright-color.de per Panel auf `off` und zurück auf `detect`; Fristüberschreitung mit
   verkürzter Frist in den Einstellungen.
~~~

**Neu:**

~~~markdown
1. bright-color.de per Panel auf `off` und zurück auf `detect`. Die Fristüberschreitung
   belegt die Klassenprobe aus A9; im Betrieb wird sie nicht erzwungen, weil dafür die
   Verarbeitung von ISPConfig angehalten werden müsste.
~~~

**Alt** (Abschnitt 16):

~~~markdown
   Durchgang; der Rückstand zeigt sich im Lesestand.
~~~

**Neu:**

~~~markdown
   Durchgang; der Rückstand zeigt sich im Lesestand in `reader.json`.
~~~

Run: `grep -c 'waf_log_inode\|malwatch_waf_action\|Dialog „Ausnahme' docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md`
Expected: `0`

- [ ] **Schritt 6: Alle Prüfungen am Rechner**

Run:

```bash
test -z "$(gofmt -l .)" && go vet ./... && go test ./... && go build ./...
find ispconfig -name '*.php' -print0 | xargs -0 -n1 php -l | grep -v '^No syntax errors'
sh ispconfig/tests/check_constants.sh
sh ispconfig/tests/check_wiring.sh
php ispconfig/tests/upgrade_helpers_test.php
php ispconfig/tests/upgrade_offers_test.php
php ispconfig/tests/panel_helpers_test.php
php ispconfig/tests/waf_lib_test.php
php ispconfig/tests/waf_panel_test.php
php ispconfig/tests/waf_panel_post_test.php
bash -n waf/install.sh waf/waf-guard
php -l waf/waf-switch && php -l waf/waf-report
MALWATCH_WAF_LIB=ispconfig/interface/lib/malwatch_waf_lib.inc.php php waf/waf-report ispconfig/tests/waf_audit_sample.log
```

Expected:

- keine Ausgabe von `gofmt`, `go vet` und dem `php -l`-Filter
- `go test` meldet `ok` für jedes Paket. Auf dem Windows-Rechner sperrt der Virenschutz
  die Schadcode-Beispiele der Tests `TestExitCodeFollowsTheThreshold` und
  `TestThePlantedFileInAReplacedPluginIsGone`; dort scheitern genau diese beiden auch ohne
  die Änderungen. Maßgeblich ist die CI unter Linux in B9.
- `Constants OK: …`, `Wiring OK`, `upgrade helpers OK`, `upgrade offers OK`,
  `panel helpers OK`, dreimal „alle Prüfungen bestanden“
- `waf-report` gibt die Tabelle der Beispieldatei aus

- [ ] **Schritt 7: Commit**

```bash
git add ispconfig/version internal/version/version.go CHANGELOG.md README.md ispconfig/README.md docs/superpowers/specs/2026-09-16-malwatch-abwehr-design.md
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "docs(abwehr): release notes and spec for 0.19.0" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

Expected: `grep` gibt nichts aus, der Commit gelingt.

### Aufgabe B9: Einführung auf web.herkules

malwatch 0.19.0 kommt in fünf Blöcken auf den Server, jeder mit eigener Freigabe von
Mathias und eigenem Eintrag im Serverprotokoll:

1. Probe auf einer Staging-Kopie, dazu das Schema in `dbispconfig` und die Klickprobe im
   Nachbau am Rechner
2. Veröffentlichen: `main`, CI, Tag `v0.19.0`, Release
3. malwatch 0.19.0 einspielen
4. WAF-Werkzeuge umstellen (`waf/install.sh`)
5. Prüfungen aus Abschnitt 13 der Spec, mit Klicks von Mathias im Panel

Claude meldet sich nicht im Panel an; jeder Klick im echten Panel ist ein Schritt für
Mathias, Claude prüft danach Datenbank, Dateien und Proben von außen.

**Dateien:**
- Serverprotokoll: `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`
- Nachbau am Rechner (nicht im Repo): `.superpowers/abwehr/harness/` mit `build_all.sh`,
  `stage.php`, `render.php`, `fake_db.php`, `fake_tform.php`, `click_page.php`,
  `web/router.php`

**Schnittstellen:**
- Nutzt: Teil A mit dem Befund aus A9, B1 bis B8
- Liefert: malwatch 0.19.0 und die umgestellte WAF auf web.herkules, geprüft und
  protokolliert

#### Messen

Nach jedem Schritt am Server laufen diese zwei Messungen; die Werte vom Beginn sind der
Vergleichspunkt.

Am Server:

```bash
ssh ispconfig 'date "+%d.%m.%Y, %H:%M:%S %Z"; nginx -t 2>&1 | tail -1; systemctl is-active nginx; uptime; free -m | sed -n "2p;3p"; ps -o rss= -C nginx | awk "{s+=\$1} END {printf \"nginx %d MB\n\", s/1024}"; echo "Worker-Abstürze: $(grep -c "exited on signal" /var/log/nginx/error.log)"; T=$(date "+%d/%b/%Y"); grep -h "$T" /var/log/ispconfig/httpd/*/access.log | awk "\$9 ~ /^5/ {n++} END {print \"5xx heute:\", n+0}"'
```

Von außen, von diesem Rechner; `ZWEITE` und `DRITTE` setzt Schritt 2 (die Namen stehen nur
im Serverprotokoll):

```bash
for site in bright-color.de "$ZWEITE" "$DRITTE"; do curl -s -o /dev/null -w "%{http_code} %{time_total}s $site\n" "https://$site/"; done
```

**Abbruch**, sobald eines davon eintritt: `nginx -t` scheitert, nginx ist nicht aktiv,
freier Arbeitsspeicher unter 2 GB, Load (5 Minuten) dauerhaft über 6, eine Website
antwortet anders als zu Beginn oder doppelt so langsam, die 5xx-Zahl steigt sprunghaft,
ein neuer Eintrag „exited on signal". Dann: vor Block 4 `waf-schalter notaus`, ab Block 4
`waf-switch emergency on`; Werte festhalten, Mathias Bescheid geben, erst nach Klärung
weiter.

#### Block 1: Staging-Kopie, Schema, Klickprobe

- [ ] **Schritt 1: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 1: Ich kopiere den Stand nach
`/root/mw-abwehr-src` und `/root/mw-abwehr-stage`, prüfe die Syntax unter PHP 7.0 und
8.3, sichere die Struktur von vier malwatch-Tabellen und lade das Schema in
`dbispconfig`. Das Schema fügt nur hinzu: vier Tabellen, Spalten mit Vorgaben, den Wert
`waf` in zwei Aufzählungen; das laufende malwatch 0.18.0 arbeitet damit weiter. Danach
rendere ich alle Seiten der Staging-Kopie gegen die echte Datenbank und prüfe die Klicks
im Nachbau auf diesem Rechner. nginx und die Websites bleiben unberührt." Weiter erst nach
seinem Ja.

- [ ] **Schritt 2: Ausgangslage messen**

```bash
ssh ispconfig "mysql -N dbispconfig -e \"SELECT domain_id, domain FROM web_domain WHERE type = 'vhost' AND active = 'y' AND domain IN ('bright-color.de', 'herkules.bright-color.de'); SELECT COUNT(*) FROM web_domain WHERE type = 'vhost' AND active = 'y'\""
ssh ispconfig "mysql -N dbispconfig -e \"SELECT domain FROM web_domain WHERE type = 'vhost' AND active = 'y' AND domain NOT LIKE '%bright-color.de' ORDER BY domain_id LIMIT 12\"" > "$TEMP/sites.txt"
while read -r d; do printf '%s %s\n' "$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "https://$d/")" "$d"; done < "$TEMP/sites.txt"
```

Expected: zwei Zeilen mit IDs, die Zahl der aktiven Websites und bis zu zwölf Namen mit
ihrem Antwortcode von außen. Zwei Websites mit `200` als `ZWEITE` und `DRITTE` setzen, dann
beide Messungen laufen lassen. Alle Werte kommen ins Protokoll. `herkules.bright-color.de`
eignet sich nicht: Der Name zeigt im DNS auf einen anderen Rechner, der auf 80 und 443 nicht
antwortet.

- [ ] **Schritt 3: Staging-Kopie bauen, Syntax und Tests**

```bash
git archive --format=tar HEAD ispconfig waf | ssh ispconfig 'rm -rf /root/mw-abwehr-src /root/mw-abwehr-stage && mkdir -p /root/mw-abwehr-src /root/mw-abwehr-stage/interface/web && tar -x -C /root/mw-abwehr-src'
ssh ispconfig 'bash -s' <<'EOF'
set -eu
src=/root/mw-abwehr-src/ispconfig
stage=/root/mw-abwehr-stage
ln -s /usr/local/ispconfig/interface/lib "$stage/interface/lib"
cd "$src"
while IFS=: read -r action source target; do
	[ "$action" = c ] || continue
	case "$target" in
		interface/*) mkdir -p "$stage/$(dirname "$target")"; cp "$source" "$stage/$target" ;;
	esac
done < install/file.list
for php in php7.0 php; do
	find . -name '*.php' -print0 | xargs -0 -n1 "$php" -l | grep -v '^No syntax errors' || true
done
php tests/waf_lib_test.php
php tests/waf_panel_test.php
php tests/waf_panel_post_test.php
EOF
```

Expected: keine Zeile aus den Syntaxprüfungen, dreimal „alle Prüfungen bestanden". `waf/` gehört
in die Kopie, weil `waf_lib_test.php` die ausgelieferten Dateien unter `waf/conf/` liest.

- [ ] **Schritt 4: Schema laden**

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
install -d -m 700 /var/backups/malwatch
mysqldump --no-data dbispconfig malwatch_site malwatch_config malwatch_job malwatch_action_log > "/var/backups/malwatch/schema-vor-0.19.0-$(date +%Y%m%d-%H%M%S).sql"
mysql dbispconfig < /root/mw-abwehr-src/ispconfig/install/schema.sql
mysql -N dbispconfig -e "SELECT TABLE_NAME, COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND TABLE_NAME IN ('malwatch_config', 'malwatch_site') AND COLUMN_NAME LIKE 'waf\_%' GROUP BY TABLE_NAME"
mysql -N dbispconfig -e "SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'dbispconfig' AND ((TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind') OR (TABLE_NAME = 'malwatch_action_log' AND COLUMN_NAME = 'action_type'))"
mysql -N dbispconfig -e "SHOW TABLES LIKE 'malwatch\_waf\_%'"
ls -l /var/backups/malwatch
EOF
```

Expected:
- `malwatch_config 12` und `malwatch_site 4`
- zwei Aufzählungen, beide mit `'waf'`
- `malwatch_waf_day`, `malwatch_waf_exception`, `malwatch_waf_hit`, `malwatch_waf_site_day`
- die Sicherungsdatei

- [ ] **Schritt 5: Seiten der Staging-Kopie rendern**

```bash
ssh ispconfig 'cat > /root/mw-abwehr-src/dump_page.php' <<'EOF'
<?php
// Renders one staged page as the admin, like the child of render_pages.php:
//   MW_SECURITY_DIR=<dir> php dump_page.php <domain_id> <page?query>
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
export MW_SECURITY_DIR=/root/mw-abwehr-stage/interface/web/security
d=/root/mw-abwehr-src
id=$(mysql -N dbispconfig -e "SELECT domain_id FROM web_domain WHERE domain = 'bright-color.de' AND type = 'vhost'")
# render_pages.php needs a website with a WordPress release list for malwatch_upgrade_versions.php.
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
cd "$d/ispconfig"
nice -n 15 php tests/render_pages.php "$rid" 2>&1 | tail -32
for page in malwatch_waf_list malwatch_waf_show malwatch_waf_exception_list malwatch_waf_config_edit; do
	nice -n 15 php "$d/dump_page.php" "$id" "$page.php" > "$d/$page.html" 2>&1
done
echo "Zeilen der Übersicht: $(grep -c 'class="mw-pick"' "$d/malwatch_waf_list.html")"
echo "Formularfelder der Website: $(grep -o 'name="exc_[a-z]*"' "$d/malwatch_waf_show.html" | sort -u | wc -l)"
echo "Zahlenfelder der Einstellungen: $(grep -c 'type="number"' "$d/malwatch_waf_config_edit.html")"
echo "Seiten mit PHP-Meldungen: $(grep -l -E 'Warning|Notice|Fatal error' "$d"/*.html | wc -l)"
EOF
```

Expected:
- jede Zeile von `render_pages.php` mit `ok`, darunter `malwatch_waf_jobs.php`,
  `malwatch_waf_preview.php`, zweimal `malwatch_waf_list.php`, zweimal
  `malwatch_waf_show.php`, zweimal `malwatch_waf_exception_list.php` und
  `malwatch_waf_config_edit.php`; am Ende `All pages render.`
- Zeilen der Übersicht gleich der Zahl aktiver Websites aus Schritt 2
- `Formularfelder der Website: 6` (`exc_site`, `exc_scope`, `exc_rule`, `exc_path`,
  `exc_param`, `exc_note`)
- `Zahlenfelder der Einstellungen: 7`
- `Seiten mit PHP-Meldungen: 0`

Die Übersicht zeigt bright-color.de bis Block 4 als „aus": `malwatch_site.waf_state` steht
auf der Vorgabe, bis der Abgleich die Zustände übernimmt. Die Seiten enthalten echte
Adressen und bleiben auf dem Server; Schritt 7 löscht sie.

- [ ] **Schritt 6: Klickprobe im Nachbau**

Panel-Dateien vergleichen:

```bash
ssh ispconfig 'cd /usr/local/ispconfig/interface/web && md5sum js/jquery.min.js themes/default/assets/javascripts/bootstrap.min.js themes/default/assets/javascripts/ispconfig.js themes/default/assets/stylesheets/bootstrap.min.css themes/default/assets/stylesheets/ispconfig.css themes/default/assets/stylesheets/responsive.min.css themes/cicada/assets/stylesheets/cicada.css'
(cd .superpowers/abwehr/harness/web && md5sum js/jquery.min.js themes/default/assets/javascripts/bootstrap.min.js themes/default/assets/javascripts/ispconfig.js themes/default/assets/stylesheets/bootstrap.min.css themes/default/assets/stylesheets/ispconfig.css themes/default/assets/stylesheets/responsive.min.css themes/cicada/assets/stylesheets/cicada.css)
```

Expected: gleiche Summen. Weicht eine ab, die Datei vom Server nach
`.superpowers/abwehr/harness/web/` an denselben Pfad kopieren.

Nachbau bauen (aus einem Worktree: das Skript mit dem Pfad des Hauptcheckouts aufrufen und den
Worktree als Baum übergeben):

```bash
bash .superpowers/abwehr/harness/build_all.sh .
```

Expected: `Seiten gerendert; Klickseiten unter web/click_*.html, Protokoll web/clicks.log`

Den Vorschauserver „waf-preview" starten; `.claude/launch.json` im Arbeitsverzeichnis der
Sitzung enthält:

```json
{
  "name": "waf-preview",
  "runtimeExecutable": "php",
  "runtimeArgs": ["-S", "127.0.0.1:8766", "-t", "<Repo>\\.superpowers\\abwehr\\harness\\web", "<Repo>\\.superpowers\\abwehr\\harness\\web\\router.php"],
  "port": 8766
}
```

`<Repo>` ist `C:\Users\brigh\Claude Workingdir\malwatch`. Für die Klicks einen eigenen
Tab mit `tabs_create` öffnen, jede Seite laden und vor dem ersten Klick länger als
10 Sekunden warten: erst dann hat `ISPConfig.dataLogNotification()` wie im Panel
mehrfach geschrieben. Geklickt wird mit `element.click()` über `javascript_tool`; ein
verdeckter Bereich nimmt echte Klicks nicht an. Nach jedem Neuladen den Dialog neu
suchen (`.mw-modal`), die Seite bringt ihn jedes Mal neu mit. Vor jedem Klick warten, bis
`ISPConfig.requestsRunning` 0 ist: Während einer Anfrage, etwa dem automatischen Neuladen
nach einem Auftrag, verwirft das Panel jeden Klick. Jeder POST steht danach in
`.superpowers/abwehr/harness/web/clicks.log`.

| Seite | Ablauf | Erwartet |
|---|---|---|
| `click_list.html` | nur warten | zwei Abfragen `malwatch_waf_jobs.php?since=8` mit `running` 1, eine mit 0, danach genau ein `GET …malwatch_waf_list.php?days=7`, dann keine Abfrage mehr |
| `click_list.html` | „scharf" in der Leiste ohne Häkchen | Dialog mit „Bitte zuerst mindestens eine Website anhaken.", Bestätigen verborgen, „Schließen" sichtbar, kein POST |
| `click_list.html` | Website 13 anhaken, „mitschreiben", bestätigen | POST mit `waf_action=state`, `waf_target=detect`, `waf_pick[]=13`, `_csrf_id`, `_csrf_key` |
| `click_list.html` | „Notaus", bestätigen | roter Bestätigen-Knopf, Fokus auf „Abbrechen"; POST mit `waf_action=emergency_on` |
| `click_list.html` | „Seitenantwort: vollständig", bestätigen | Knopf „Auf schlank umstellen"; POST mit `waf_action=response_body`, `waf_mode=lean` |
| `click_show.html` | „Ausnahme …" an der ersten Regel | Regel 942100, Geltungsbereich `site`, Pfadfeld verborgen, Fokus im Regelfeld, Vorschauzeile gefüllt, Abfrage `malwatch_waf_preview.php` mit `exc_scope=site&exc_rule=942100` |
| `click_show.html` | „Ausnahme …" an der gespeicherten Anfrage | Regel 942190, Pfad `/wp-json/batch/v1`, Parameter `json.requests.0.path`, Geltungsbereich `site_param`, Parameterfeld sichtbar |
| `click_show.html` | Enter im Regelfeld | `defaultPrevented`, kein POST |
| `click_show.html` | Notiz setzen, „Ausnahme anlegen", bestätigen | POST mit `waf_action=exception_add` und allen Feldern `exc_*` aus der Vorbelegung |
| `click_show.html` | „Scharf schalten" | Dialog mit Grund und Datum, Bestätigen verborgen, kein POST |
| `click_show.html` | „Ausschalten", bestätigen | POST mit `waf_action=state`, `waf_target=off`, `waf_site=11` |
| `click_show.html` | „Entfernen" an der ersten Ausnahme, bestätigen | roter Bestätigen-Knopf; POST mit `waf_action=exception_remove`, `waf_exception=3` |
| `click_show.html` | Verweis „Seitenantwort ansehen" ansehen | `target=_blank`, `rel=noopener`, ohne `data-load-content` |
| `click_exc.html` | Filter „Fehler (1)" | `GET …malwatch_waf_exception_list.php?state=error` |
| `click_exc.html` | „Entfernen", bestätigen | POST an `malwatch_waf_exception_list.php` mit `waf_action=exception_remove`, `waf_exception`, `state`, `site` |
| `click_cfg.html` | Wert in „Audit-Log (Tage)" ändern, Enter | POST an `malwatch_waf_config_edit.php` mit allen sieben Feldern, `id=1`, `_csrf_id`, `_csrf_key`, `next_tab` |

Danach je ein Bildschirmfoto von `list.html` und `show.html` (dunkel) sowie
`list_light.html` und `show_light.html` (hell) für Mathias.

- [ ] **Schritt 7: Aufräumen**

```bash
ssh ispconfig 'rm -rf /root/mw-abwehr-src /root/mw-abwehr-stage; ls -d /root/mw-abwehr-src /root/mw-abwehr-stage 2>&1 | tail -2; date "+%d.%m.%Y, %H:%M:%S %Z"'
```

Expected: zweimal `No such file or directory`, die Uhrzeit fürs Protokoll. Dann beide
Messungen.

- [ ] **Schritt 8: Protokoll**

Das Serverprotokoll frisch lesen und den Eintrag als gezielte Einfügung nach seiner
Beginnzeit einsortieren, neueste zuerst; andere Sitzungen schreiben mit.

```markdown
## <Datum>, <Beginn>–<Ende> CEST · malwatch 0.19.0: Schema und Probe der Seiten „Abwehr"

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code, im Auftrag von Mathias |
| Betroffen | `dbispconfig` (vier neue Tabellen, neue Spalten in `malwatch_config` und `malwatch_site`, Wert `waf` in `malwatch_job.job_kind` und `malwatch_action_log.action_type`); Staging-Kopie unter `/root`, wieder entfernt |
| Auftrag | Aufgabe B9, Block 1 des Plans `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-b.md` im malwatch-Repo, Zweig `waf-herkules` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Die neuen Seiten lesen die neuen Tabellen; vor dem Einspielen müssen sie gegen die echte Datenbank rendern.

### Ablauf

- Ausgangslage: <Messwerte>, von außen: <drei Websites mit Code und Zeit, darunter die dritte mit Namen>
- Syntax unter PHP 7.0 und 8.3, `waf_lib_test`, `waf_panel_test`, `waf_panel_post_test`: <Ergebnis>
- Sicherung der Tabellenstruktur: `/var/backups/malwatch/schema-vor-0.19.0-<Zeitstempel>.sql`
- `schema.sql` geladen: <Spaltenzahlen, Aufzählungen, Tabellen>
- `render_pages.php` gegen die Staging-Kopie: <Ergebnis>; Übersicht mit <n> Zeilen bei <n> aktiven Websites
- Klickprobe im Nachbau mit den Panel-Dateien vom Server (md5 gleich): <Ergebnis je Ablauf>

### Prüfung

<Messwerte am Ende>. nginx, `/etc/nginx`, die Crontab und die Dateien der Erweiterung sind unverändert.

### Rückweg

Die Zusätze stören 0.18.0 nicht. Bei Bedarf: `DROP TABLE malwatch_waf_hit, malwatch_waf_site_day, malwatch_waf_day, malwatch_waf_exception;` die neuen Spalten bleiben ohne Wirkung stehen; die Struktur von vorher liegt in der Sicherungsdatei.
```

#### Block 2: Veröffentlichen

- [ ] **Schritt 9: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 2: Ich bringe den Zweig `waf-herkules` per
Fast-Forward nach `main`, schiebe `main`, warte auf die CI und setze danach den Tag
`v0.19.0`. Der Release-Lauf baut `malwatch.pkg` und die Binärdateien." Weiter erst nach
seinem Ja.

- [ ] **Schritt 10: main, CI, Tag, Release**

```bash
git fetch origin
git merge-base --is-ancestor origin/main waf-herkules && echo "Fast-Forward möglich"
git checkout main
git merge --ff-only waf-herkules
git push origin main
sha=$(git rev-parse HEAD)
gh run watch "$(gh run list --commit "$sha" --workflow ci --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: `Fast-Forward möglich`, der Push gelingt, der CI-Lauf dieses Commits endet grün.
Liefert `gh run list` noch keinen Lauf, einige Sekunden später wiederholen. Scheitert die
CI, bleibt der Tag aus: Fehler auf `waf-herkules` beheben, committen, Schritt 10 von
vorn.

```bash
git tag v0.19.0
git push origin v0.19.0
gh run watch "$(gh run list --commit "$sha" --workflow release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh release view v0.19.0 --json assets --jq '.assets[].name'
git checkout waf-herkules
```

Expected: der Release-Lauf endet grün; die Liste nennt `malwatch-linux-amd64`,
`malwatch-linux-arm64`, `malwatch.pkg` und `SHA256SUMS`.

#### Block 3: malwatch 0.19.0 einspielen

- [ ] **Schritt 11: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 3: Ich spiele malwatch 0.19.0 ein: Scanner,
Paket nach Prüfsumme, `manual_install.php`, dann `cmp` jeder Kopie und `render_pages.php`
live. Ab dem nächsten Cron-Durchgang liest malwatch das Audit-Log ein. nginx und die
WAF-Dateien bleiben unverändert, die Werkzeuge stellt erst Block 4 um. Bitte bis dahin
keine Knöpfe unter Abwehr drücken: Aufträge scheitern vorher, weil die neuen Dateinamen
fehlen." Weiter erst nach seinem Ja.

- [ ] **Schritt 12: Einspielen**

Zuerst beide Messungen, dann:

```bash
ssh ispconfig 'bash -s' <<'EOF'
set -eu
rm -rf /root/mw-abwehr-deploy && mkdir -p /root/mw-abwehr-deploy && cd /root/mw-abwehr-deploy
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.19.0/malwatch.pkg
curl -fsSLO https://github.com/brightcolor/malwatch/releases/download/v0.19.0/SHA256SUMS
grep " malwatch.pkg$" SHA256SUMS | sha256sum -c -
curl -fsSL https://raw.githubusercontent.com/brightcolor/malwatch/main/install.sh | sh 2>&1 | grep -i installed
cd /usr/local/ispconfig/extensions && mkdir -p malwatch && cd malwatch && unzip -oq /root/mw-abwehr-deploy/malwatch.pkg
chown -R ispconfig:ispconfig /usr/local/ispconfig/extensions/malwatch
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php 2>&1 | grep -E "installed|loaded|Error|error|failed" | head -8
echo "Addon $(cat /usr/local/ispconfig/extensions/malwatch/version), Scanner $(/usr/local/bin/malwatch version | head -1)"
E=/usr/local/ispconfig/extensions/malwatch; n=0; total=0
while IFS=: read -r a s t; do [ "$a" = c ] || continue; total=$((total+1)); cmp -s "$E/$s" "/usr/local/ispconfig/$t" || { echo "abweichend: $t"; n=$((n+1)); }; done < "$E/install/file.list"
echo "Kopien geprüft: $total, abweichend: $n"
rid=$(mysql -N dbispconfig -e "SELECT parent_domain_id FROM malwatch_software WHERE product = 'wordpress' AND versions IS NOT NULL AND versions != '' ORDER BY parent_domain_id LIMIT 1")
nice -n 15 php "$E/tests/render_pages.php" "$rid" 2>&1 | tail -32
rm -rf /root/mw-abwehr-deploy
EOF
```

Expected:
- `malwatch.pkg: OK`
- Addon `0.19.0`, Scanner meldet `0.19.0`
- `Kopien geprüft: 89, abweichend: 0`
- jede Seite `ok`, `All pages render.`

Weicht eine Kopie ab, holt `enable_files` sie nach (siehe Erinnerung zum Einspielen von
0.14.3) und der `cmp`-Block läuft erneut.

- [ ] **Schritt 13: Erster Durchgang des Crons**

Nach der nächsten vollen Minute:

```bash
ssh ispconfig 'ls -l /var/lib/malwatch/waf/; cat /var/lib/malwatch/waf/reader.json; echo; mysql -N dbispconfig -e "SELECT COUNT(*) FROM malwatch_waf_hit; SELECT domain, SUM(hits), SUM(would_block) FROM malwatch_waf_site_day GROUP BY domain"; grep -i -E "waf|malwatch" /var/log/ispconfig/cron.log | tail -n 10'
```

Expected: `reader.json` mit Inode und Position, Treffer bei bright-color.de aus Stufe 1,
keine Fehlermeldung im Cron-Protokoll. Fehlt `reader.json`, eine Minute später erneut.
Danach beide Messungen.

- [ ] **Schritt 14: Protokoll**

Frisch lesen, gezielt einfügen:

```markdown
## <Datum>, <Beginn>–<Ende> CEST · malwatch 0.19.0 eingespielt: Seiten „Abwehr"

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code, im Auftrag von Mathias |
| Betroffen | ISPConfig-Erweiterung malwatch, `/usr/local/bin/malwatch`, `/var/lib/malwatch/waf` |
| Auftrag | Aufgabe B9, Blöcke 2 und 3 des Plans `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-b.md` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Die WAF je Website im Panel schalten und auswerten.

### Ablauf

- Release v0.19.0 (Commit <kurz>), CI und Release-Lauf grün
- Prüfsumme des Pakets, Scanner, `manual_install.php`: <Ergebnis>
- `cmp` aller Kopien: <n> gleich
- `render_pages.php` live: <Ergebnis>
- Erster Durchgang: `reader.json` <Inhalt>, <n> Treffer eingelesen

### Prüfung

<Messwerte vorher und nachher, drei Websites von außen>

### Rückweg

Paket 0.18.0 (`releases/download/v0.18.0/malwatch.pkg`) nach Prüfsumme entpacken und `manual_install.php` laufen lassen; das Einlesen endet damit, die WAF bleibt wie sie ist. Nicht erprobt.
```

#### Block 4: WAF-Werkzeuge umstellen

- [ ] **Schritt 15: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 4: Ich spiele `waf/` ein und starte
`install.sh`. Es legt die Dateien unter den neuen Namen neben die alten, prüft die neue
`main.conf` mit `modsec-rules-check` und `nginx -t`, lädt nginx einmal neu, ersetzt
`waf-schalter`, `waf-wache` und `waf-bericht` durch `waf-switch`, `waf-guard` und
`waf-report`, stellt die Cron-Zeile um und gleicht danach die Markierungen über einen
Auftrag ab. Sicherung unter `/var/backups/waf-switch/install-<Zeitstempel>`. Scheitert
eine Prüfung, bleibt der alte Stand ohne Reload. Der Abgleich schreibt das Feld von
bright-color.de neu; solange `check_apache_config=y` gilt, startet ISPConfig nginx danach
einmal komplett neu." Weiter erst nach seinem Ja.

- [ ] **Schritt 16: Vorher festhalten**

```bash
ssh ispconfig 'ls /etc/nginx/waf; crontab -l | grep -E "waf-"; ls /usr/local/sbin | grep -E "^waf-"; /usr/local/sbin/waf-schalter status | head -12'
```

Dazu beide Messungen.

- [ ] **Schritt 17: install.sh**

```bash
git archive --format=tar HEAD waf | ssh ispconfig 'rm -rf /root/waf-einspielen && mkdir -p /root/waf-einspielen && tar -x -C /root/waf-einspielen --strip-components=1'
```

Vorher ein Probelauf. `.superpowers/abwehr/install_probe.sh` (im Hauptbaum) kopiert die
Live-Dateien nach `/root/waf-install-probe`, biegt alle Systempfade dorthin um, ersetzt
nginx, systemctl, crontab und waf-switch durch Attrappen und lässt `install.sh` zweimal
laufen; `modsec-rules-check` bleibt echt. Mit `fail-test` lehnt die Attrappe `nginx -t`
nach dem Tausch der `main.conf` ab:

```bash
ssh ispconfig 'cat > /root/waf-install-probe.sh' < .superpowers/abwehr/install_probe.sh
ssh ispconfig 'bash /root/waf-install-probe.sh /root/waf-einspielen /root/waf-install-probe < /dev/null'
ssh ispconfig 'bash /root/waf-install-probe.sh /root/waf-einspielen /root/waf-install-probe fail-test < /dev/null'
ssh ispconfig 'rm -rf /root/waf-install-probe /root/waf-install-probe.sh'
```

Expected: Im ersten Aufruf endet Durchgang 1 mit `exit=0` und „Test ok", Durchgang 2 mit
`exit=0` ohne Cron-Zeile und ohne Reload, unter „changes of run 2" steht nichts. Im
zweiten Aufruf endet Durchgang 1 mit `exit=1` und „Die vorherige liegt wieder an ihrem
Platz", die Include-Zeilen nennen die alten Namen, Werkzeuge und Crontab sind unverändert.
Am 17.09.2026 brach der erste echte Anlauf in der Sicherung ab, weil `/etc/logrotate.d/waf`
und die Kopie von `/etc/nginx/waf` dort beide `waf` hießen; behoben in `8b1b566`, Prüfung 63
hält es fest. Danach:

```bash
ssh ispconfig 'bash /root/waf-einspielen/install.sh < /dev/null'
```

Expected: `waf/install.sh: Sicherung in /var/backups/waf-switch/install-…`,
`waf/install.sh: Cron-Zeile auf waf-guard umgestellt.`, `waf/install.sh: nginx neu
geladen.`, `waf/install.sh: Fertig. waf-switch status zeigt den Stand.` Endet es mit einer
Fehlermeldung, sofort beide Messungen, dann Abbruch nach „Messen".

- [ ] **Schritt 18: Prüfen**

```bash
ssh ispconfig 'bash -s' <<'EOF'
nginx -t 2>&1 | tail -1
systemctl is-active nginx
ls /etc/nginx/waf
echo "alte Namen in main.conf: $(grep -c -E 'einstellungen|crs-zusatz|ausnahmen-|zustand|antwortrumpf' /etc/nginx/waf/main.conf)"
grep -E '^Include /etc/nginx/waf/' /etc/nginx/waf/main.conf
journalctl -u nginx --since '-10 min' --no-pager -o short-iso | grep -E 'Reloaded|Stopping'
crontab -l | grep -E 'waf-'
ls /usr/local/sbin | grep -E '^waf-'
/usr/local/sbin/waf-guard; echo "waf-guard exit=$?"
tail -n 3 /var/log/waf/guard.log
/usr/local/sbin/waf-switch jobs | tail -4
/usr/local/sbin/waf-switch status | head -12
mysql -N dbispconfig -e "SELECT w.domain, s.waf_state FROM malwatch_site s JOIN web_domain w ON w.domain_id = s.parent_domain_id WHERE s.waf_state != 'off'"
mysql -N dbispconfig -e "SELECT COUNT(*) FROM web_domain WHERE nginx_directives LIKE '%# WAF-Anfang%'"
EOF
```

Expected:
- `syntax is ok`-Zeile, `active`
- unter `/etc/nginx/waf` nur `crs-extra.conf`, `exclusions-after.conf`,
  `exclusions-before.conf`, `exclusions-panel-after.conf`, `exclusions-panel-before.conf`,
  `main.conf`, `response-body.conf`, `settings.conf`, `state.conf`
- `alte Namen in main.conf: 0`, die Include-Zeilen nennen nur die neuen Dateien. `nginx -T`
  zeigt die Regeldateien nicht, sie hängen über `modsecurity_rules_file`
- ein „Reloaded" von `install.sh`; solange `check_apache_config=y` gilt, dazu ein
  „Stopping" wenige Sekunden später: ISPConfig startet nginx nach dem Abgleich neu
- genau eine Cron-Zeile mit `hc-run waf-guard`
- `waf-guard`, `waf-report`, `waf-switch`
- `waf-guard exit=0`
- der Auftrag `migrate_markers` erledigt; `waf-switch status` zeigt bright-color.de auf
  „mitschreiben", alle übrigen auf „aus"
- `bright-color.de detect`
- `0` Felder mit der alten Markierung

Liegt der Auftrag noch in der Warteschlange, nach der nächsten Minute erneut prüfen.
Danach beide Messungen und eine Probe von außen:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://bright-color.de/mwprobe-umstellung/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Expected: `404`, `200` oder `301` (WordPress leitet bright-color.de auf www um, die Anfrage
läuft trotzdem durch die WAF); nach dem nächsten Durchgang steht ein Treffer mit diesem Pfad
in `malwatch_waf_hit`:

```bash
ssh ispconfig "mysql -N dbispconfig -e \"SELECT hit_id, path, would_block, JSON_EXTRACT(rules, '\$[*].id') FROM malwatch_waf_hit WHERE domain = 'bright-color.de' AND path = '/mwprobe-umstellung/' ORDER BY hit_id DESC LIMIT 1\""
```

- [ ] **Schritt 19: Protokoll**

Frisch lesen, gezielt einfügen:

```markdown
## <Datum>, <Beginn>–<Ende> CEST · WAF: Werkzeuge und Dateien auf die neuen Namen umgestellt

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code, im Auftrag von Mathias |
| Betroffen | `/etc/nginx/waf`, `/etc/nginx/conf.d/waf.conf`, `/etc/logrotate.d/waf`, `/usr/local/sbin/waf-*`, Crontab von root, `nginx_directives` der Websites mit Block |
| Auftrag | Aufgabe B9, Block 4 des Plans `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-b.md` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Englische Namen für Werkzeuge und Dateien; die Seite „Abwehr" schreibt in die neuen Dateien.

### Ablauf

- Vorher: <Dateien, Cron-Zeile, Werkzeuge, Zustände>
- `install.sh`: Sicherung `/var/backups/waf-switch/install-<Zeitstempel>`, <Ausgabe>
- Ein Reload um <Uhrzeit>
- Abgleich `migrate_markers`: <Ergebnis>

### Prüfung

<nginx -T, Cron-Zeile, waf-guard, Zustände, Probe von außen, Messwerte>

### Rückweg

Aus der Sicherung `waf/` nach `/etc/nginx/waf` und `waf.conf` nach `/etc/nginx/conf.d/` zurücklegen, `crontab <Sicherung>/crontab`, die alten Werkzeuge aus dem Commit vor A8 (`git show <commit>:waf/waf-schalter` und so weiter) nach `/usr/local/sbin`, dann `nginx -t` und `systemctl reload nginx`.
```

Offene Punkte an Mathias: die Adresse für `hc-run waf-guard` (`/etc/hc-run.d/waf-guard.url`)
fehlt wie zuvor für `waf-wache`.

#### Block 5: Prüfungen aus Abschnitt 13 der Spec

- [ ] **Schritt 20: Freigabe einholen**

Mathias bekommt vorgelegt: „B9, Block 5: Die Prüfungen am Server. Du klickst im Panel,
ich schicke Proben von außen an bright-color.de und prüfe Aufträge, Dateien und
Datenbank. Dabei schaltest du bright-color.de kurz aus und wieder auf mitschreiben, legst
zwei Ausnahmen an und entfernst sie wieder, schaltest den Notaus ein und aus und die
Seitenantwort auf schlank und zurück. Ausnahmen, Notaus und Seitenantwort laden nginx
neu. Das Aus- und Einschalten von bright-color.de ändert den Vhost; solange
`check_apache_config=y` gilt, startet ISPConfig nginx dabei jeweils komplett neu, rund eine
Sekunde ohne Verbindungen. Am Ende ist der Stand wie vorher." Weiter erst nach seinem Ja
und nach der Entscheidung zu `check_apache_config`.

Proben gehen von diesem Rechner aus; Proben vom Server selbst schaltet Regel 10001 ab.
Eine Probe ist:

```bash
probe() { curl -s -o /dev/null -w "%{http_code} $1\n" ${2:+-H "$2"} "https://bright-color.de$1"; }
```

Treffer der letzten Proben, nach dem nächsten Durchgang, ohne Adressen:

```bash
ssh ispconfig "mysql dbispconfig -e \"SELECT hit_id, path, SUBSTRING_INDEX(uri, '?', -1) AS query, would_block, logged_in, JSON_EXTRACT(rules, '\$[*].id') AS rules, response_bytes FROM malwatch_waf_hit WHERE domain = 'bright-color.de' AND path LIKE '/mwprobe-%' ORDER BY hit_id DESC LIMIT 6\""
```

- [ ] **Schritt 21: Aus und wieder mitschreiben**

1. Mathias: Abwehr > bright-color.de > „Ausschalten", bestätigen.
2. Claude, bis der Auftrag erledigt ist:
   `ssh ispconfig '/usr/local/sbin/waf-switch jobs | tail -3; grep -c "modsecurity on" /etc/nginx/sites-available/bright-color.de.vhost'`
   Expected: Auftrag `set_state` erledigt, `0`. Dann beide Messungen.
3. `probe '/mwprobe-aus/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`; nach dem nächsten
   Durchgang kein Treffer mit `/mwprobe-aus/`.
4. Mathias: „Mitschreiben", bestätigen.
5. Claude wie in 2, Expected: erledigt, `1`. Dann beide Messungen.
6. `probe '/mwprobe-an/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`; nach dem nächsten
   Durchgang ein Treffer mit `/mwprobe-an/`.

- [ ] **Schritt 22: Angemeldet**

```bash
probe '/mwprobe-login/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' 'Cookie: wordpress_logged_in_test=1'
```

Expected nach dem nächsten Durchgang: der Treffer mit `/mwprobe-login/` hat
`logged_in = y`, und Mathias sieht ihn auf der Seite von bright-color.de mit
„angemeldet"; im aufgeklappten Treffer steht der Cookie-Wert als `[entfernt]`.

- [ ] **Schritt 23: Ausnahme für einen Pfad**

1. Proben:
   `probe '/mwprobe-a/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'` und
   `probe '/mwprobe-b/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`.
   Nach dem nächsten Durchgang haben beide Treffer die Regel 941100.
2. Mathias: am Treffer mit `/mwprobe-a/` „Ausnahme …", Regel 941100 eintragen, falls eine
   andere vorbelegt ist, Geltungsbereich „nur dieser Pfad", Pfad `/mwprobe-a/`, Vorschau
   lesen, „Ausnahme anlegen", bestätigen.
3. Claude:

   ```bash
   ssh ispconfig '/usr/local/sbin/waf-switch jobs | tail -2; /usr/local/sbin/waf-switch exception list; grep -c "ctl:ruleRemoveById=941100" /etc/nginx/waf/exclusions-panel-before.conf; nginx -t 2>&1 | tail -1; journalctl -u nginx --since "-10 min" | grep -c Reloaded'
   ```

   Expected: Auftrag `exception_add` erledigt, Ausnahme `active`, `1`, `syntax is ok`,
   mindestens ein Reload. Dann beide Messungen.
4. Proben wie in 1 mit neuen Pfadnamen am selben Ort: `/mwprobe-a/zwei` und
   `/mwprobe-b/zwei` (die Ausnahme gilt für Pfade, die mit `/mwprobe-a/` beginnen).
   Expected nach dem nächsten Durchgang: der Treffer unter `/mwprobe-a/zwei` enthält
   941100 nicht mehr (oder es gibt keinen Treffer, wenn 941100 die einzige Regel war), der
   unter `/mwprobe-b/zwei` enthält 941100.
5. Mathias: Ausnahme mit Regel `10010` versuchen. Expected: Fehlermeldung im Panel, und
   `waf-switch jobs` zeigt keinen neuen Auftrag, `journalctl -u nginx --since "-2 min" |
   grep -c Reloaded` ergibt `0`.

- [ ] **Schritt 24: Ausnahme für einen Parameter**

1. Mathias: am Treffer mit `/mwprobe-b/zwei` „Ausnahme …", Regel 941100, Geltungsbereich
   „nur dieser Parameter", Parameter `q`, Pfad leer, „Ausnahme anlegen", bestätigen.
2. Claude wie in Schritt 23.3, mit
   `grep -c "ctl:ruleRemoveTargetById=941100;ARGS:q" /etc/nginx/waf/exclusions-panel-before.conf`.
3. Proben: `probe '/mwprobe-c/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'` und
   `probe '/mwprobe-c/?r=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`.
   Expected nach dem nächsten Durchgang: bei `q` fehlt 941100, bei `r` ist sie dabei. Damit
   ist `ctl:ruleRemoveTargetById` in Engine 3 belegt (Risiko 4 der Spec).
4. Mathias: beide Ausnahmen „Entfernen", bestätigen.
5. Claude: beide Aufträge erledigt, `waf-switch exception list` leer,
   `grep -c "SecRule" /etc/nginx/waf/exclusions-panel-before.conf` ergibt `0`,
   `nginx -t` in Ordnung. Dann beide Messungen.

- [ ] **Schritt 25: Notaus**

1. Mathias: Übersicht > „Notaus", bestätigen.
2. Claude: `ssh ispconfig '/usr/local/sbin/waf-switch jobs | tail -2; grep -c "SecRuleEngine Off" /etc/nginx/waf/state.conf; nginx -t 2>&1 | tail -1'`
   Expected: Auftrag `emergency` erledigt, `1`. Mathias sieht das rote Band. Messungen.
3. `probe '/mwprobe-notaus/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`; nach dem nächsten
   Durchgang kein Treffer mit diesem Pfad.
4. Mathias: „Notaus beenden", bestätigen.
5. Claude wie in 2, Expected: erledigt, `0`. Messungen.
6. `probe '/mwprobe-wieder/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`; nach dem nächsten
   Durchgang ein Treffer.

- [ ] **Schritt 26: Seitenantwort**

1. Mathias: „Seitenantwort: vollständig" > „Auf schlank umstellen".
2. Claude: `ssh ispconfig '/usr/local/sbin/waf-switch jobs | tail -2; grep -c "id:10199" /etc/nginx/waf/response-body.conf; /usr/local/sbin/waf-switch response-body status'`
   Expected: erledigt, `1`, `lean`. Messungen.
3. `probe '/mwprobe-schlank/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`; der Treffer hat
   `response_bytes = 0`.
4. Mathias: „Seitenantwort: schlank" > „Auf vollständig umstellen".
5. Claude wie in 2, Expected: erledigt, `0`, `full`. Messungen.
6. `probe '/mwprobe-voll/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`; der Treffer hat
   `response_bytes` über 0, und „Seitenantwort ansehen" öffnet für Mathias den Text in
   einem eigenen Fenster.

- [ ] **Schritt 27: Endstand und Protokoll**

```bash
ssh ispconfig '/usr/local/sbin/waf-switch status | head -12; /usr/local/sbin/waf-switch exception list; /usr/local/sbin/waf-switch response-body status; grep -c "SecRuleEngine Off" /etc/nginx/waf/state.conf'
```

Expected: bright-color.de „mitschreiben", keine Ausnahme, `full`, `0` – der Stand vor
Block 5. Dazu beide Messungen. Dann frisch lesen und gezielt einfügen:

```markdown
## <Datum>, <Beginn>–<Ende> CEST · Abwehr: Prüfungen am Server

| Feld | Inhalt |
|---|---|
| Ausgeführt von | Claude Code und Mathias (Klicks im Panel), im Auftrag von Mathias |
| Betroffen | bright-color.de (kurz aus), `/etc/nginx/waf/exclusions-panel-*.conf`, `state.conf`, `response-body.conf`, je Schritt ein Reload |
| Auftrag | Aufgabe B9, Block 5 des Plans `docs/superpowers/plans/2026-09-16-malwatch-abwehr-teil-b.md` |
| Ergebnis | <bestanden oder Befund> |

### Warum

Abschnitt 13 der Spec: die Seite im Betrieb belegen, bevor weitere Websites mitschreiben.

### Ablauf

- Aus und wieder mitschreiben: <Uhrzeiten, Aufträge, vhost>
- Angemeldet: <Ergebnis>
- Ausnahme für einen Pfad: <Regel-ID in der Datei, Proben vorher und nachher>; Regel 10010 abgewiesen ohne Reload
- Ausnahme für einen Parameter: <Ergebnis>, damit `ctl:ruleRemoveTargetById` belegt
- Notaus an und aus: <Ergebnis>
- Seitenantwort schlank und vollständig: <Ergebnis>

### Prüfung

<Messwerte je Schritt, Endstand wie vorher>

### Rückweg

Nicht nötig, der Stand ist wie vor den Prüfungen.
```

- [ ] **Schritt 28: Erinnerungen und Aufräumen**

1. Erinnerung `waf-web-herkules` nachführen: Werkzeuge heißen `waf-switch`, `waf-guard`,
   `waf-report`; Bedienung über Security > Abwehr (malwatch 0.19.0); Dateinamen unter
   `/etc/nginx/waf`; offene Adresse für `hc-run waf-guard`.
2. Erinnerung zu malwatch um 0.19.0 ergänzen (Seiten, Aufträge `job_kind = 'waf'`,
   Einstellungsseite mit `tform`, Klickprobe mit `router.php`).
3. Vorschauserver „waf-preview" beenden.

---

## Abschluss von Teil B

- [ ] Aufgaben B1 bis B8 abgehakt, jede mit eigenem Commit; lokal grün wie in B8, Schritt 6.
- [ ] Klickprobe im Nachbau bestanden (B9, Block 1), Bildschirmfotos bei Mathias.
- [ ] Blöcke 1 bis 5 aus B9 je mit Freigabe von Mathias und Eintrag im Serverprotokoll.
- [ ] malwatch 0.19.0 live: `cmp` aller Kopien gleich, `render_pages.php` grün, das
  Einlesen läuft jede Minute.
- [ ] WAF umgestellt: nur neue Namen unter `/etc/nginx/waf`, `waf-guard` im Cron,
  bright-color.de schreibt mit.
- [ ] Prüfungen aus Abschnitt 13 der Spec bestanden, Endstand wie vor Block 5.
- [ ] Erinnerungen nachgeführt, Vorschauserver beendet.

Weiter, jeweils mit eigener Freigabe: die Stufen 2 und 3 der WAF-Einführung über die Seite
Abwehr, danach Teil 2 „Sperren" mit eigener Spec.
