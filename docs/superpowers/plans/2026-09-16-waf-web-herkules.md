# WAF auf web.herkules — Umsetzungsplan

> **Für ausführende Helfer:** Dieser Plan wird Aufgabe für Aufgabe abgearbeitet, über
> `superpowers:executing-plans`. Agenten werden dafür nicht gestartet, siehe globale
> Vorgaben. Die Schritte tragen Kästchen (`- [ ]`) zum Abhaken.

**Ziel:** web.herkules bekommt ModSecurity mit dem OWASP-Regelwerk im nginx, je Website
schaltbar, und alle 33 WordPress-Websites laufen anschließend im Mitschreib-Modus.

**Aufbau:** Die Regeln werden einmal global im `http`-Block geladen. Jede Website
schaltet sich über einen markierten Block im Feld „nginx-Direktiven" ein, den das Skript
`waf-schalter` über das Datalog von ISPConfig setzt. Treffer landen im Audit-Log, ein
stündlicher Wächter hält die nginx-Konfiguration gültig.

**Technik:** Ubuntu 24.04, nginx 1.24 mit Modul `libnginx-mod-http-modsecurity` 1.0.3,
Engine `libmodsecurity` 3.0.12, Regelwerk `modsecurity-crs` 3.3.5, ISPConfig 3.3.1p1,
PHP 8.4 für die eigenen Werkzeuge, Bash für Einspielen und Wächter.

**Spec:** `docs/superpowers/specs/2026-09-16-waf-web-herkules-design.md`

## Globale Vorgaben

- **Der Webserver darf niemals ausfallen.** Änderungen greifen erst nach `nginx -t`,
  nginx wird ausschließlich neu geladen (`systemctl reload nginx`), die Konfiguration
  bleibt jederzeit gültig.
- Die Direktive `modsecurity` steht nur in vhosts, solange das Modul installiert ist.
  Reihenfolge beim Rückbau: erst die Websites auf „aus", dann die Pakete.
- Jeder Schritt am Server wird vorher von Mathias freigegeben und danach im
  Serverprotokoll `C:\Users\brigh\Claude Workingdir\Serverprotokolle\web.herkules.bright-color.de.md`
  festgehalten: Datum und Uhrzeit vom Server, was, warum, wie, Messwerte, Prüfung,
  Rückweg.
- Agenten (Subagenten, Hintergrundagenten, Workflows) werden nur nach ausdrücklicher
  Freigabe von Mathias gestartet.
- Keine echten Kundendaten im Repo: keine Kundendomains, keine Adressen, keine
  Kontonamen. Beispiele in Tests sind erfunden.
- Keine Anmeldung im ISPConfig-Panel. Änderungen an Websites laufen über das Datalog.
- Commits enden mit `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`. Vor jedem
  Commit läuft `git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'` und muss leer
  bleiben.
- Gearbeitet wird auf dem Zweig `waf-herkules` im malwatch-Repo. Geschoben wird nur auf
  Ansage.

### Abbruchgrenzen (aus Abschnitt 9 der Spec)

| Messwert | Ausgangswert | Abbruch |
|---|---|---|
| nginx gesamt (RSS) | 175 MB | freier Arbeitsspeicher unter 2 GB |
| freier Arbeitsspeicher | 6,3 GB | unter 2 GB |
| Swap belegt | 1,7 GB | Anstieg um mehr als 1 GB |
| Load (5 Minuten) | 1,19 bei 8 CPUs | dauerhaft über 6 |
| Antwortzeit dreier Seiten | wird in Aufgabe 6 gemessen | Verdopplung |
| 5xx-Anteil | wird in Aufgabe 6 gemessen | Anstieg |
| Abgestürzte Worker | 0 | jeder Eintrag „exited on signal" |
| Audit-Log | 0 | Wachstum über 1 GB je Tag |

Beim Überschreiten: `waf-schalter notaus`, Messwerte festhalten, Ursache klären, erst
danach weitermachen.

## Dateien

| Datei | Zweck |
|---|---|
| `waf/lib/waf_block.inc.php` | reine Funktionen für den markierten Block im Direktivenfeld |
| `waf/lib/waf_audit.inc.php` | reine Funktionen zum Auswerten des Audit-Logs |
| `waf/waf-schalter` | Zustand je Website setzen, lesen, zurücknehmen, Notaus |
| `waf/waf-wache` | stündlicher Wächter über `nginx -t` |
| `waf/waf-bericht` | Auswertung des Audit-Logs |
| `waf/conf/waf.conf` | Einbindung im `http`-Block |
| `waf/conf/main.conf` | Reihenfolge der Includes |
| `waf/conf/einstellungen.conf` | Engine, Grenzen, Audit-Log |
| `waf/conf/crs-zusatz.conf` | WordPress-Ausnahmen des Regelwerks |
| `waf/conf/ausnahmen-vorher.conf` | eigene Regeln 10001, 10010, 10011 |
| `waf/conf/ausnahmen-nachher.conf` | Ausnahmen je Website aus der Auswertung |
| `waf/conf/zustand.conf` | Notaus-Schalter |
| `waf/conf/logrotate-waf` | Rotation des Audit-Logs |
| `waf/install.sh` | spielt Dateien und Werkzeuge auf dem Server ein |
| `waf/tests/waf_block_test.php` | Test der Blockfunktionen |
| `waf/tests/waf_audit_test.php` | Test der Auswertung |
| `waf/tests/beispiel-audit.log` | erfundene Audit-Zeilen für den Test |
| `waf/README.md` | Kurzanleitung |

---

### Aufgabe 1: Blockfunktionen mit Test

**Dateien:**
- Neu: `waf/lib/waf_block.inc.php`
- Test: `waf/tests/waf_block_test.php`

**Schnittstellen:**
- Nutzt: nichts
- Liefert: `waf_block_text(string $zustand): string`,
  `waf_block_entfernen(string $text): string`,
  `waf_block_setzen(string $text, string $zustand): string`,
  `waf_block_zustand(string $text): string`,
  `waf_zustand_gueltig(string $zustand): bool`

- [ ] **Schritt 1: Test schreiben**

```php
<?php
/**
 * Prüft die reinen Funktionen für den markierten WAF-Block.
 *
 *   php waf/tests/waf_block_test.php
 */
require __DIR__ . '/../lib/waf_block.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$block_mit = "# WAF-Anfang (mitschreiben) – verwaltet von waf-schalter\nmodsecurity on;\n# WAF-Ende\n";
$block_scharf = "# WAF-Anfang (scharf) – verwaltet von waf-schalter\nmodsecurity on;\nmodsecurity_rules 'SecRuleEngine On';\n# WAF-Ende\n";

// Leeres Feld
expect_same('leer, mitschreiben', waf_block_setzen('', 'mitschreiben'), $block_mit);
expect_same('leer, aus', waf_block_setzen('', 'aus'), '');

// Vorhandene Direktiven bleiben erhalten
$eigene = "location = /xmlrpc.php {\n    deny all;\n}\n";
$gesetzt = waf_block_setzen($eigene, 'mitschreiben');
expect_same('eigene Direktiven bleiben', substr($gesetzt, 0, strlen($eigene)), $eigene);
expect_same('Block hängt hinten an', substr($gesetzt, -strlen($block_mit)), $block_mit);

// Hin und zurück ergibt den Ausgangstext
expect_same('Rundlauf', waf_block_setzen($gesetzt, 'aus'), $eigene);

// Zustand wechseln erzeugt keinen zweiten Block
$scharf = waf_block_setzen($gesetzt, 'scharf');
expect_same('nur ein Anfang', substr_count($scharf, '# WAF-Anfang'), 1);
expect_same('nur ein Ende', substr_count($scharf, '# WAF-Ende'), 1);
expect_same('scharf enthält Engine-Zeile', strpos($scharf, "modsecurity_rules 'SecRuleEngine On';") !== false, true);

// Zustand ablesen
expect_same('Zustand mitschreiben', waf_block_zustand($gesetzt), 'mitschreiben');
expect_same('Zustand scharf', waf_block_zustand($scharf), 'scharf');
expect_same('Zustand aus', waf_block_zustand($eigene), 'aus');

// Zeilenenden außerhalb des Blocks bleiben unangetastet
$crlf = "location / {\r\n    try_files $uri =404;\r\n}\r\n";
$crlf_gesetzt = waf_block_setzen($crlf, 'mitschreiben');
expect_same('CRLF bleibt', substr($crlf_gesetzt, 0, strlen($crlf)), $crlf);
expect_same('CRLF Rundlauf', waf_block_setzen($crlf_gesetzt, 'aus'), $crlf);

// Gültige Zustände
expect_same('gültig: aus', waf_zustand_gueltig('aus'), true);
expect_same('gültig: mitschreiben', waf_zustand_gueltig('mitschreiben'), true);
expect_same('gültig: scharf', waf_zustand_gueltig('scharf'), true);
expect_same('ungültig: an', waf_zustand_gueltig('an'), false);

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_block: alle Prüfungen bestanden\n";
```

- [ ] **Schritt 2: Test laufen lassen, er muss scheitern**

```bash
php waf/tests/waf_block_test.php
```

Erwartet: Fehler, weil `waf/lib/waf_block.inc.php` fehlt.

- [ ] **Schritt 3: Funktionen schreiben**

```php
<?php
/**
 * Reine Funktionen für den markierten WAF-Block im Feld „nginx-Direktiven".
 * Text hinein, Text heraus: keine Datenbank, kein ISPConfig.
 */

define('WAF_ANFANG', '# WAF-Anfang');
define('WAF_ENDE', '# WAF-Ende');

function waf_zustand_gueltig($zustand)
{
	return in_array($zustand, array('aus', 'mitschreiben', 'scharf'), true);
}

function waf_block_text($zustand)
{
	if ($zustand === 'aus') {
		return '';
	}
	$zeilen = array(
		WAF_ANFANG . ' (' . $zustand . ') – verwaltet von waf-schalter',
		'modsecurity on;',
	);
	if ($zustand === 'scharf') {
		$zeilen[] = "modsecurity_rules 'SecRuleEngine On';";
	}
	$zeilen[] = WAF_ENDE;
	return implode("\n", $zeilen) . "\n";
}

function waf_block_entfernen($text)
{
	// Entfernt genau den Block samt seinem eigenen Zeilenumbruch. Was davor steht,
	// bleibt Zeichen für Zeichen erhalten, auch der Umbruch der Zeile davor.
	$muster = '/' . preg_quote(WAF_ANFANG, '/') . '.*?' . preg_quote(WAF_ENDE, '/') . '[^\r\n]*(?:\R)?/s';
	return preg_replace($muster, '', $text);
}

function waf_block_setzen($text, $zustand)
{
	$rest = waf_block_entfernen($text);
	if ($zustand === 'aus') {
		return $rest;
	}
	$block = waf_block_text($zustand);
	if (trim($rest) === '') {
		return $block;
	}
	// Endet der Text ohne Umbruch, kommt einer dazu. Sonst bleibt er, wie er ist.
	if (!preg_match('/\R$/', $rest)) {
		$rest .= "\n";
	}
	return $rest . $block;
}

function waf_block_zustand($text)
{
	if (preg_match('/' . preg_quote(WAF_ANFANG, '/') . '\s*\(([a-z]+)\)/', $text, $treffer)) {
		return $treffer[1];
	}
	return 'aus';
}
```

- [ ] **Schritt 4: Test laufen lassen, er muss bestehen**

```bash
php waf/tests/waf_block_test.php
```

Erwartet: `waf_block: alle Prüfungen bestanden`

- [ ] **Schritt 5: Committen**

```bash
git add waf/lib/waf_block.inc.php waf/tests/waf_block_test.php
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): marked block helpers for the nginx directives field"
```

---

### Aufgabe 2: Skript `waf-schalter`

**Dateien:**
- Neu: `waf/waf-schalter`

**Schnittstellen:**
- Nutzt: `waf_block_setzen`, `waf_block_zustand`, `waf_zustand_gueltig` aus Aufgabe 1
- Liefert: Befehle `status`, `setze <zustand> <domain…|--wordpress|--alle>`,
  `probe <zustand> <domain…>`, `notaus [--hart]`, `zurueck <sicherungsordner>`

- [ ] **Schritt 1: Skript schreiben**

```php
#!/usr/bin/php
<?php
/**
 * Schaltet die WAF je Website. Setzt einen markierten Block im Feld
 * „nginx-Direktiven" über das Datalog von ISPConfig und prüft das Ergebnis.
 *
 *   waf-schalter status
 *   waf-schalter probe mitschreiben beispiel.de
 *   waf-schalter setze mitschreiben beispiel.de
 *   waf-schalter setze mitschreiben --wordpress
 *   waf-schalter notaus [--hart]
 *   waf-schalter zurueck /var/backups/waf-schalter/20260916-101500
 */
require '/usr/local/lib/waf/waf_block.inc.php';

$SICHERUNG = '/var/backups/waf-schalter';
$ZUSTANDSDATEI = '/etc/nginx/waf/zustand.conf';
$VHOSTS = '/etc/nginx/sites-available';

function ispconfig_starten()
{
	global $app, $conf;
	require_once '/usr/local/ispconfig/server/lib/config.inc.php';
	require_once '/usr/local/ispconfig/server/lib/app.inc.php';
	return $app;
}

function websites_lesen($app)
{
	return $app->dbmaster->queryAllRecords(
		"SELECT domain_id, domain, document_root, nginx_directives FROM web_domain WHERE type = 'vhost' AND active = 'y' ORDER BY domain"
	);
}

function ist_wordpress($web)
{
	return is_file($web['document_root'] . '/web/wp-config.php');
}

function vhost_zustand($domain)
{
	$datei = $GLOBALS['VHOSTS'] . '/' . $domain . '.vhost';
	if (!is_file($datei)) {
		return 'ohne vhost';
	}
	return waf_block_zustand(file_get_contents($datei));
}

function nginx_pruefen()
{
	exec('nginx -t 2>&1', $ausgabe, $rc);
	return array($rc === 0, implode("\n", $ausgabe));
}

function warten_auf_vhost($domain, $zustand, $sekunden = 180)
{
	for ($i = 0; $i < $sekunden; $i += 5) {
		if (vhost_zustand($domain) === $zustand) {
			return true;
		}
		sleep(5);
	}
	return false;
}

function setzen($app, $webs, $zustand, $nur_probe)
{
	$ordner = $GLOBALS['SICHERUNG'] . '/' . date('Ymd-His');
	if (!$nur_probe && !is_dir($ordner)) {
		mkdir($ordner, 0700, true);
	}
	$fehler = 0;
	foreach ($webs as $web) {
		$alt = (string)$web['nginx_directives'];
		$neu = waf_block_setzen($alt, $zustand);
		if ($alt === $neu) {
			echo $web['domain'] . ": unverändert ($zustand)\n";
			continue;
		}
		if ($nur_probe) {
			echo $web['domain'] . ": " . strlen($alt) . " -> " . strlen($neu) . " Zeichen, Zustand $zustand\n";
			continue;
		}
		file_put_contents($ordner . '/' . $web['domain'] . '.txt', $alt);
		$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $neu), 'domain_id', intval($web['domain_id']));
		echo $web['domain'] . ": gesetzt auf $zustand, Sicherung in $ordner\n";
		if (!warten_auf_vhost($web['domain'], $zustand)) {
			echo $web['domain'] . ": vhost zeigt den Zustand nicht, nehme zurück\n";
			$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $alt), 'domain_id', intval($web['domain_id']));
			$fehler++;
			continue;
		}
		list($ok, $ausgabe) = nginx_pruefen();
		if (!$ok) {
			echo $web['domain'] . ": nginx -t fehlgeschlagen, nehme zurück\n$ausgabe\n";
			$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => $alt), 'domain_id', intval($web['domain_id']));
			$fehler++;
		}
	}
	if (!$nur_probe) {
		echo "Sicherungen: $ordner\n";
	}
	return $fehler;
}

$argumente = array_slice($argv, 1);
$befehl = array_shift($argumente);
$app = ispconfig_starten();
$webs = websites_lesen($app);

if ($befehl === 'status') {
	printf("%-32s %-14s %-14s %s\n", 'Website', 'Datenbank', 'vhost', 'WordPress');
	foreach ($webs as $web) {
		printf("%-32s %-14s %-14s %s\n", $web['domain'], waf_block_zustand((string)$web['nginx_directives']), vhost_zustand($web['domain']), ist_wordpress($web) ? 'ja' : '');
	}
	exit(0);
}

if ($befehl === 'setze' || $befehl === 'probe') {
	$zustand = array_shift($argumente);
	if (!waf_zustand_gueltig($zustand)) {
		fwrite(STDERR, "Zustand muss aus, mitschreiben oder scharf sein\n");
		exit(2);
	}
	if (in_array('--wordpress', $argumente, true)) {
		$auswahl = array_filter($webs, 'ist_wordpress');
	} elseif (in_array('--alle', $argumente, true)) {
		$auswahl = $webs;
	} else {
		$auswahl = array_filter($webs, function ($web) use ($argumente) {
			return in_array($web['domain'], $argumente, true);
		});
	}
	if (empty($auswahl)) {
		fwrite(STDERR, "Keine Website ausgewählt\n");
		exit(2);
	}
	exit(setzen($app, $auswahl, $zustand, $befehl === 'probe') > 0 ? 1 : 0);
}

if ($befehl === 'notaus') {
	file_put_contents($ZUSTANDSDATEI, "SecRuleEngine Off\n");
	$scharfe = array_filter($webs, function ($web) {
		return waf_block_zustand((string)$web['nginx_directives']) === 'scharf';
	});
	if (!empty($scharfe)) {
		setzen($app, $scharfe, 'mitschreiben', false);
	}
	if (in_array('--hart', $argumente, true)) {
		$an = array_filter($webs, function ($web) {
			return waf_block_zustand((string)$web['nginx_directives']) !== 'aus';
		});
		if (!empty($an)) {
			setzen($app, $an, 'aus', false);
		}
	}
	list($ok, $ausgabe) = nginx_pruefen();
	if ($ok) {
		exec('systemctl reload nginx');
		echo "Notaus gesetzt, nginx neu geladen\n";
		exit(0);
	}
	fwrite(STDERR, "nginx -t meldet weiter einen Fehler:\n$ausgabe\n");
	exit(1);
}

if ($befehl === 'zurueck') {
	$ordner = array_shift($argumente);
	if (!is_dir($ordner)) {
		fwrite(STDERR, "Ordner fehlt: $ordner\n");
		exit(2);
	}
	foreach (glob($ordner . '/*.txt') as $datei) {
		$domain = basename($datei, '.txt');
		foreach ($webs as $web) {
			if ($web['domain'] === $domain) {
				$app->dbmaster->datalogUpdate('web_domain', array('nginx_directives' => file_get_contents($datei)), 'domain_id', intval($web['domain_id']));
				echo "$domain: Feldinhalt zurückgeschrieben\n";
			}
		}
	}
	exit(0);
}

fwrite(STDERR, "Befehle: status | setze <zustand> <domain…|--wordpress|--alle> | probe … | notaus [--hart] | zurueck <ordner>\n");
exit(2);
```

- [ ] **Schritt 2: Syntax prüfen**

```bash
php -l waf/waf-schalter
```

Erwartet: `No syntax errors detected`

- [ ] **Schritt 3: Committen**

```bash
git add waf/waf-schalter
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): waf-schalter sets the per-site state through the ISPConfig datalog"
```

Die Prüfung gegen die echte Datenbank läuft in Aufgabe 6, Schritt „status lesen".

---

### Aufgabe 3: Konfigurationsdateien und Einspielskript

**Dateien:**
- Neu: `waf/conf/waf.conf`, `waf/conf/main.conf`, `waf/conf/einstellungen.conf`,
  `waf/conf/crs-zusatz.conf`, `waf/conf/ausnahmen-vorher.conf`,
  `waf/conf/ausnahmen-nachher.conf`, `waf/conf/zustand.conf`,
  `waf/conf/logrotate-waf`, `waf/install.sh`

**Schnittstellen:**
- Nutzt: `waf/lib/*.inc.php`, `waf/waf-schalter`, `waf/waf-wache`, `waf/waf-bericht`
- Liefert: Dateien unter `/etc/nginx/waf/`, `/etc/nginx/conf.d/waf.conf`,
  `/etc/logrotate.d/waf`, Werkzeuge unter `/usr/local/sbin/`

- [ ] **Schritt 1: Dateien anlegen**

`waf/conf/waf.conf`:

```
# Lädt die Regeln einmal global. Eingeschaltet wird je Website im vhost.
modsecurity_rules_file /etc/nginx/waf/main.conf;
```

`waf/conf/main.conf`:

```
Include /etc/nginx/modsecurity.conf
Include /etc/nginx/waf/einstellungen.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/nginx/waf/crs-zusatz.conf
Include /etc/nginx/waf/ausnahmen-vorher.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/nginx/waf/ausnahmen-nachher.conf
Include /etc/nginx/waf/zustand.conf
```

`waf/conf/einstellungen.conf`:

```
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^$"
SecAuditLogParts ABCFHZ
SecAuditLogType Serial
SecAuditLog /var/log/waf/audit.log
SecAuditLogFormat JSON
SecAuditLogFileMode 0600
SecAuditLogDirMode 0750
SecTmpDir /var/cache/waf
SecDataDir /var/cache/waf
SecDebugLogLevel 0
SecStatusEngine Off
```

`waf/conf/crs-zusatz.conf`:

```
SecAction "id:10100,phase:1,pass,nolog,setvar:tx.crs_exclusions_wordpress=1"
```

`waf/conf/ausnahmen-vorher.conf`:

```
# Selbstaufrufe des Servers, vor allem wp-cron über die OPNsense
SecRule REMOTE_ADDR "@ipMatch 10.50.0.11" \
    "id:10001,phase:1,pass,nolog,ctl:ruleEngine=Off"

# Anmeldewege: Anfrageinhalt nicht ins Audit-Log
SecRule REQUEST_FILENAME "@rx (?i)(wp-login\.php|xmlrpc\.php|/wp-json/[^?]*(users|application-passwords))" \
    "id:10010,phase:1,pass,nolog,ctl:auditLogParts=-C"

# Uploads: Anfrageinhalt nicht ins Audit-Log
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^multipart/form-data" \
    "id:10011,phase:1,pass,nolog,ctl:auditLogParts=-C"
```

`waf/conf/ausnahmen-nachher.conf`:

```
# Ausnahmen je Website. Wird aus der Auswertung gefüllt (Aufgabe 10).
```

`waf/conf/zustand.conf`:

```
# Notaus-Schalter. Leer im Normalbetrieb; waf-schalter notaus schreibt hier
# SecRuleEngine Off hinein.
```

`waf/conf/logrotate-waf`:

```
/var/log/waf/audit.log {
	daily
	rotate 7
	compress
	delaycompress
	missingok
	notifempty
	copytruncate
	create 0600 www-data adm
}
```

`waf/install.sh`:

```bash
#!/bin/bash
# Spielt die WAF-Dateien und Werkzeuge auf web.herkules ein.
# Ändert nichts an den Websites: eingeschaltet wird getrennt über waf-schalter.
set -eu
cd "$(dirname "$0")"

if [ ! -f /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf ]; then
	echo "Das nginx-Modul fehlt. Erst die Pakete einspielen." >&2
	exit 1
fi

install -d -o root -g root -m 755 /etc/nginx/waf
for f in main.conf einstellungen.conf crs-zusatz.conf ausnahmen-vorher.conf ausnahmen-nachher.conf zustand.conf; do
	install -o root -g root -m 644 "conf/$f" "/etc/nginx/waf/$f"
done
install -o root -g root -m 644 conf/logrotate-waf /etc/logrotate.d/waf

install -d -o www-data -g adm -m 750 /var/log/waf
install -d -o www-data -g root -m 750 /var/cache/waf
install -d -o root -g root -m 700 /var/backups/waf-schalter

install -d -o root -g root -m 755 /usr/local/lib/waf
install -o root -g root -m 644 lib/waf_block.inc.php /usr/local/lib/waf/waf_block.inc.php
install -o root -g root -m 644 lib/waf_audit.inc.php /usr/local/lib/waf/waf_audit.inc.php
install -o root -g root -m 755 waf-schalter /usr/local/sbin/waf-schalter
install -o root -g root -m 755 waf-wache /usr/local/sbin/waf-wache
install -o root -g root -m 755 waf-bericht /usr/local/sbin/waf-bericht

# Zuletzt die Einbindung, damit nginx die Regeln erst sieht, wenn alles liegt.
install -o root -g root -m 644 conf/waf.conf /etc/nginx/conf.d/waf.conf
nginx -t
echo "Eingespielt. Eingeschaltet ist noch keine Website."
```

- [ ] **Schritt 2: Skript auf Syntax prüfen**

```bash
bash -n waf/install.sh
```

Erwartet: keine Ausgabe.

- [ ] **Schritt 3: Committen**

```bash
git add waf/conf waf/install.sh
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): configuration files and installer for the nginx side"
```

---

### Aufgabe 4: Wächter `waf-wache`

**Dateien:**
- Neu: `waf/waf-wache`

**Schnittstellen:**
- Nutzt: `/usr/local/sbin/waf-schalter` aus Aufgabe 2
- Liefert: stündlicher Lauf, der die nginx-Konfiguration gültig hält, Protokoll in
  `/var/log/waf/wache.log`

- [ ] **Schritt 1: Skript schreiben**

```bash
#!/bin/bash
# Hält die nginx-Konfiguration gültig. Läuft stündlich über hc-run.
# Ohne Fund endet der Lauf mit 0, sonst mit 1, damit healthchecks anschlägt.
set -u
LOG=/var/log/waf/wache.log
say() { echo "$(date '+%F %T') $*" >> "$LOG"; }

AUSGABE=$(nginx -t 2>&1)
RC=$?
if [ "$RC" -eq 0 ]; then
	say "nginx -t in Ordnung"
	exit 0
fi

say "nginx -t fehlgeschlagen: $AUSGABE"
if ! echo "$AUSGABE" | grep -qi 'modsec'; then
	say "Kein Bezug zur WAF, nichts unternommen"
	exit 1
fi

if echo "$AUSGABE" | grep -qi 'unknown directive'; then
	say "Direktive unbekannt, Modul fehlt: schalte alle Websites aus"
	/usr/local/sbin/waf-schalter notaus --hart >> "$LOG" 2>&1
else
	say "Schalte die WAF global aus"
	/usr/local/sbin/waf-schalter notaus >> "$LOG" 2>&1
fi

if nginx -t >/dev/null 2>&1; then
	systemctl reload nginx
	say "Konfiguration wieder gültig, nginx neu geladen"
	exit 1
fi
say "Fehler bleibt bestehen, Eingriff nötig"
exit 1
```

- [ ] **Schritt 2: Syntax prüfen**

```bash
bash -n waf/waf-wache
```

Erwartet: keine Ausgabe.

- [ ] **Schritt 3: Committen**

```bash
git add waf/waf-wache
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): hourly guard that keeps the nginx configuration valid"
```

---

### Aufgabe 5: Auswertung `waf-bericht`

**Dateien:**
- Neu: `waf/lib/waf_audit.inc.php`, `waf/waf-bericht`
- Test: `waf/tests/waf_audit_test.php`, `waf/tests/beispiel-audit.log`

**Schnittstellen:**
- Nutzt: nichts
- Liefert: `waf_audit_zeile(string $zeile): ?array`,
  `waf_audit_auswerten(array $zeilen): array` mit Feldern
  `host`, `regel`, `meldung`, `pfad`, `treffer`, `beispiel`

- [ ] **Schritt 1: Beispiel-Log anlegen (erfundene Daten)**

`waf/tests/beispiel-audit.log`:

```
{"transaction":{"client_ip":"198.51.100.7","time_stamp":"Tue Sep 16 09:00:01 2026","request":{"method":"GET","uri":"/suche?q=1%27+OR+%271%27%3D%271","headers":{"Host":"beispiel.test"}},"response":{"http_code":200},"messages":[{"message":"SQL Injection Attack Detected","details":{"ruleId":"942100","data":"Matched Data: found within ARGS:q"}}]}}
{"transaction":{"client_ip":"198.51.100.8","time_stamp":"Tue Sep 16 09:00:02 2026","request":{"method":"POST","uri":"/wp-admin/admin-ajax.php","headers":{"Host":"beispiel.test"}},"response":{"http_code":200},"messages":[{"message":"SQL Injection Attack Detected","details":{"ruleId":"942100","data":"Matched Data: found within ARGS:filter"}}]}}
{"transaction":{"client_ip":"198.51.100.9","time_stamp":"Tue Sep 16 09:05:00 2026","request":{"method":"GET","uri":"/seite","headers":{"Host":"zweite.test"}},"response":{"http_code":200},"messages":[{"message":"XSS Attack Detected","details":{"ruleId":"941100","data":"Matched Data: <script"}}]}}
kaputte zeile ohne json
```

- [ ] **Schritt 2: Test schreiben**

```php
<?php
/**
 * Prüft die Auswertung des Audit-Logs.
 *
 *   php waf/tests/waf_audit_test.php
 */
require __DIR__ . '/../lib/waf_audit.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$zeilen = file(__DIR__ . '/beispiel-audit.log', FILE_IGNORE_NEW_LINES);
$zeilen_ok = array_filter(array_map('waf_audit_zeile', $zeilen));
expect_same('drei gültige Zeilen', count($zeilen_ok), 3);
expect_same('kaputte Zeile fällt weg', waf_audit_zeile('kaputte zeile ohne json'), null);

$bericht = waf_audit_auswerten($zeilen);
expect_same('zwei Gruppen', count($bericht), 2);

// Häufigste Gruppe zuerst
expect_same('erste Gruppe Host', $bericht[0]['host'], 'beispiel.test');
expect_same('erste Gruppe Regel', $bericht[0]['regel'], '942100');
expect_same('erste Gruppe Treffer', $bericht[0]['treffer'], 2);
expect_same('erste Gruppe Meldung', $bericht[0]['meldung'], 'SQL Injection Attack Detected');
expect_same('erste Gruppe Beispielpfad', $bericht[0]['beispiel'], '/suche');

expect_same('zweite Gruppe Host', $bericht[1]['host'], 'zweite.test');
expect_same('zweite Gruppe Regel', $bericht[1]['regel'], '941100');
expect_same('zweite Gruppe Treffer', $bericht[1]['treffer'], 1);

if ($failures > 0) {
	fwrite(STDERR, $failures . " Fehler\n");
	exit(1);
}
echo "waf_audit: alle Prüfungen bestanden\n";
```

- [ ] **Schritt 3: Test laufen lassen, er muss scheitern**

```bash
php waf/tests/waf_audit_test.php
```

Erwartet: Fehler, weil `waf/lib/waf_audit.inc.php` fehlt.

- [ ] **Schritt 4: Auswertung schreiben**

```php
<?php
/**
 * Reine Funktionen zum Auswerten des Audit-Logs im JSON-Format.
 */

function waf_audit_zeile($zeile)
{
	$zeile = trim((string)$zeile);
	if ($zeile === '') {
		return null;
	}
	$daten = json_decode($zeile, true);
	if (!is_array($daten) || !isset($daten['transaction'])) {
		return null;
	}
	$t = $daten['transaction'];
	$pfad = isset($t['request']['uri']) ? $t['request']['uri'] : '';
	$frage = strpos($pfad, '?');
	if ($frage !== false) {
		$pfad = substr($pfad, 0, $frage);
	}
	$treffer = array();
	$meldungen = isset($t['messages']) && is_array($t['messages']) ? $t['messages'] : array();
	foreach ($meldungen as $meldung) {
		$treffer[] = array(
			'host' => isset($t['request']['headers']['Host']) ? $t['request']['headers']['Host'] : '?',
			'regel' => isset($meldung['details']['ruleId']) ? (string)$meldung['details']['ruleId'] : '?',
			'meldung' => isset($meldung['message']) ? $meldung['message'] : '',
			'pfad' => $pfad,
			'adresse' => isset($t['client_ip']) ? $t['client_ip'] : '',
			'zeit' => isset($t['time_stamp']) ? $t['time_stamp'] : '',
		);
	}
	return $treffer;
}

function waf_audit_auswerten($zeilen)
{
	$gruppen = array();
	foreach ($zeilen as $zeile) {
		$treffer = waf_audit_zeile($zeile);
		if ($treffer === null) {
			continue;
		}
		foreach ($treffer as $t) {
			$schluessel = $t['host'] . '|' . $t['regel'];
			if (!isset($gruppen[$schluessel])) {
				$gruppen[$schluessel] = array(
					'host' => $t['host'],
					'regel' => $t['regel'],
					'meldung' => $t['meldung'],
					'treffer' => 0,
					'beispiel' => $t['pfad'],
				);
			}
			$gruppen[$schluessel]['treffer']++;
		}
	}
	$bericht = array_values($gruppen);
	usort($bericht, function ($a, $b) {
		if ($a['treffer'] === $b['treffer']) {
			return strcmp($a['host'] . $a['regel'], $b['host'] . $b['regel']);
		}
		return $b['treffer'] - $a['treffer'];
	});
	return $bericht;
}
```

- [ ] **Schritt 5: Test laufen lassen, er muss bestehen**

```bash
php waf/tests/waf_audit_test.php
```

Erwartet: `waf_audit: alle Prüfungen bestanden`

- [ ] **Schritt 6: Berichtsskript schreiben**

```php
#!/usr/bin/php
<?php
/**
 * Fasst das Audit-Log zusammen: Treffer je Website und Regel.
 *
 *   waf-bericht [pfad-zum-audit-log]
 */
require '/usr/local/lib/waf/waf_audit.inc.php';

$datei = isset($argv[1]) ? $argv[1] : '/var/log/waf/audit.log';
if (!is_readable($datei)) {
	fwrite(STDERR, "Audit-Log nicht lesbar: $datei\n");
	exit(2);
}
$bericht = waf_audit_auswerten(file($datei, FILE_IGNORE_NEW_LINES));
if (empty($bericht)) {
	echo "Keine Treffer im Audit-Log.\n";
	exit(0);
}
printf("%-32s %-8s %-8s %-28s %s\n", 'Website', 'Regel', 'Treffer', 'Beispielpfad', 'Meldung');
foreach ($bericht as $zeile) {
	printf("%-32s %-8s %-8d %-28s %s\n", $zeile['host'], $zeile['regel'], $zeile['treffer'], $zeile['beispiel'], $zeile['meldung']);
}
```

- [ ] **Schritt 7: Syntax prüfen und committen**

```bash
php -l waf/waf-bericht
git add waf/lib/waf_audit.inc.php waf/waf-bericht waf/tests/waf_audit_test.php waf/tests/beispiel-audit.log
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): audit log summary with pure parsing helpers and tests"
```

---

### Aufgabe 6: Stufe 0 auf dem Server, Installation

**Vorher:** Freigabe von Mathias einholen, mit Nennung der Befehle aus dieser Aufgabe.

**Dateien:**
- Server: `/etc/nginx/waf/*`, `/etc/nginx/conf.d/waf.conf`, `/etc/logrotate.d/waf`,
  `/usr/local/sbin/waf-*`, `/usr/local/lib/waf/*`
- Protokoll: Eintrag in `web.herkules.bright-color.de.md`

**Schnittstellen:**
- Nutzt: Aufgaben 1 bis 5
- Liefert: geladenes Modul, gültige Konfiguration, keine eingeschaltete Website

- [ ] **Schritt 1: Ausgangslage messen und festhalten**

```bash
ssh ispconfig 'date "+%F %T %Z"; nginx -t; ps -o rss= -C nginx | awk "{s+=\$1} END {printf \"nginx %d MB\n\", s/1024}"; free -m | head -3; uptime; df -h /var/log | tail -1'
```

Erwartet: `nginx -t` in Ordnung. Werte notieren, sie sind der Vergleichspunkt.

- [ ] **Schritt 2: Antwortzeiten und Fehleranteil messen**

```bash
ssh ispconfig 'for h in bright-color.de wismar.fm radioluebeck.de; do printf "%s %s\n" "$h" "$(curl -s -o /dev/null -w "%{http_code} %{time_total}" -H "Host: $h" http://127.0.0.1/)"; done; T=$(date "+%d/%b/%Y"); grep -h "$T" /var/log/ispconfig/httpd/*/access.log | awk "{c[\$9]++} END {for (k in c) if (k ~ /^5/) print k, c[k]}"'
```

Erwartet: dreimal 200 und die Zahl der 5xx-Antworten des Tages.

- [ ] **Schritt 3: Pakete einspielen**

```bash
ssh ispconfig 'apt-get install -s libnginx-mod-http-modsecurity modsecurity-crs | grep ^Inst'
ssh ispconfig 'DEBIAN_FRONTEND=noninteractive apt-get install -y libnginx-mod-http-modsecurity modsecurity-crs && apt-mark hold libnginx-mod-http-modsecurity modsecurity-crs'
```

Erwartet: Installation ohne Fehler, danach `nginx -t` in Ordnung (der Paket-Trigger lädt
nginx neu; eingeschaltet ist die WAF noch nirgends).

- [ ] **Schritt 4: Paketdateien lesen und Reihenfolge prüfen**

```bash
ssh ispconfig 'grep -vE "^\s*#|^\s*$" /etc/nginx/modsecurity.conf; echo ---; grep -vE "^\s*#|^\s*$" /etc/nginx/modsecurity_includes.conf; echo ---; grep -n "^SecAction\|^SecRule" /etc/modsecurity/crs/crs-setup.conf | head'
```

Lädt eine dieser Dateien das Regelwerk bereits, wird die Zeile
`Include /usr/share/modsecurity-crs/rules/*.conf` aus `waf/conf/main.conf` entfernt.
Enthält `crs-setup.conf` die Regel 900130 aktiv, entfällt `waf/conf/crs-zusatz.conf`
aus `main.conf`. Änderung committen.

- [ ] **Schritt 5: Dateien einspielen**

```bash
scp -r waf ispconfig:/root/waf-einspielen
ssh ispconfig 'cd /root/waf-einspielen && bash install.sh'
```

Erwartet: `nginx -t` in Ordnung, Meldung „Eingespielt".

- [ ] **Schritt 5b: Regelkette gesondert prüfen**

```bash
ssh ispconfig '/usr/lib/x86_64-linux-gnu/libexec/modsec-rules-check /etc/nginx/waf/main.conf; echo "Rückgabewert $?"'
```

Erwartet: Rückgabewert 0. Meldet das Werkzeug doppelte Regel-IDs, wird die Reihenfolge
in `/etc/nginx/waf/main.conf` nach Schritt 4 berichtigt und die Änderung committet.

- [ ] **Schritt 6: Neu laden und messen**

```bash
ssh ispconfig 'systemctl reload nginx; sleep 5; ps -o rss= -C nginx | awk "{s+=\$1} END {printf \"nginx %d MB\n\", s/1024}"; free -m | head -3; uptime; /usr/local/sbin/waf-schalter status | head -5'
```

Erwartet: alle Websites im Zustand „aus", freier Arbeitsspeicher über 2 GB, Load unter 6.

- [ ] **Schritt 7: Wächter eintragen**

```bash
ssh ispconfig 'sed -n "1,40p" /usr/local/sbin/hc-run'
ssh ispconfig '(crontab -l; echo "5 * * * * /usr/local/sbin/hc-run waf-wache -- /usr/local/sbin/waf-wache > /dev/null") | crontab -'
ssh ispconfig 'crontab -l | tail -3; /usr/local/sbin/waf-wache; tail -2 /var/log/waf/wache.log'
```

Erwartet: Eintrag in der Crontab, Lauf endet mit 0 und der Zeile „nginx -t in Ordnung".

- [ ] **Schritt 8: Verfügbarkeit prüfen**

```bash
ssh ispconfig 'systemctl is-active nginx; for h in bright-color.de wismar.fm radioluebeck.de; do curl -s -o /dev/null -w "$h %{http_code}\n" -H "Host: $h" http://127.0.0.1/; done; tail -5 /var/log/nginx/error.log'
```

Erwartet: `active`, dreimal 200, keine neuen Fehler.

- [ ] **Schritt 9: Protokolleintrag schreiben**

Eintrag im Serverprotokoll mit Uhrzeiten, Befehlen, Messwerten vorher und nachher,
Prüfung und Rückweg. Rückweg dieser Stufe:

```bash
ssh ispconfig 'rm -f /etc/nginx/conf.d/waf.conf && nginx -t && systemctl reload nginx && apt-mark unhold libnginx-mod-http-modsecurity modsecurity-crs && apt-get purge -y libnginx-mod-http-modsecurity modsecurity-crs && nginx -t && systemctl reload nginx'
```

---

### Aufgabe 7: Stufe 1, eine Website im Mitschreib-Modus

**Vorher:** Freigabe von Mathias.

**Dateien:**
- Server: Feld „nginx-Direktiven" von bright-color.de
- Protokoll: Eintrag

**Schnittstellen:**
- Nutzt: `waf-schalter` aus Aufgabe 2, Konfiguration aus Aufgabe 6
- Liefert: eine Website im Zustand „mitschreiben", erste Treffer im Audit-Log

- [ ] **Schritt 1: Änderung ansehen**

```bash
ssh ispconfig '/usr/local/sbin/waf-schalter probe mitschreiben bright-color.de'
```

Erwartet: eine Zeile mit der Längenänderung des Feldes.

- [ ] **Schritt 2: Einschalten**

```bash
ssh ispconfig '/usr/local/sbin/waf-schalter setze mitschreiben bright-color.de'
```

Erwartet: „gesetzt auf mitschreiben", danach Zustand „mitschreiben" laut vhost, keine
Rücknahme.

- [ ] **Schritt 3: Erkennung prüfen**

```bash
ssh ispconfig 'curl -s -o /dev/null -w "%{http_code}\n" -H "Host: bright-color.de" "http://127.0.0.1/?id=1%27+OR+%271%27%3D%271"; sleep 2; tail -1 /var/log/waf/audit.log | head -c 400; echo'
```

Erwartet: Antwort 200 und ein Eintrag im Audit-Log mit einer Regel aus der Gruppe 942.

- [ ] **Schritt 4: Gegenprobe auf einer ausgeschalteten Website**

```bash
ssh ispconfig 'W=$(wc -l < /var/log/waf/audit.log); curl -s -o /dev/null -H "Host: wismar.fm" "http://127.0.0.1/?id=1%27+OR+%271%27%3D%271"; sleep 2; echo "vorher $W, nachher $(wc -l < /var/log/waf/audit.log)"'
```

Erwartet: gleiche Zeilenzahl.

- [ ] **Schritt 5: Datenschutzregeln prüfen**

```bash
ssh ispconfig 'curl -s -o /dev/null -H "Host: bright-color.de" -d "log=test&pwd=<script>alert(1)</script>" http://127.0.0.1/wp-login.php; sleep 2; tail -1 /var/log/waf/audit.log | python3 -c "import sys,json; d=json.load(sys.stdin); t=d[\"transaction\"]; print(\"Pfad\", t[\"request\"][\"uri\"]); print(\"Body vorhanden:\", \"body\" in t[\"request\"])"'
```

Erwartet: Pfad `/wp-login.php`, kein Anfrageinhalt im Eintrag.

- [ ] **Schritt 6: Selbstaufrufe prüfen**

```bash
ssh ispconfig 'grep -c "10.50.0.11" /var/log/waf/audit.log'
```

Erwartet: 0.

- [ ] **Schritt 7: Messen und Verfügbarkeit prüfen**

```bash
ssh ispconfig 'ps -o rss= -C nginx | awk "{s+=\$1} END {printf \"nginx %d MB\n\", s/1024}"; free -m | head -3; uptime; du -h /var/log/waf/audit.log; for h in bright-color.de wismar.fm radioluebeck.de; do curl -s -o /dev/null -w "$h %{http_code}\n" -H "Host: $h" http://127.0.0.1/; done; grep -c "exited on signal" /var/log/nginx/error.log'
```

Erwartet: freier Speicher über 2 GB, Load unter 6, dreimal 200, keine abgestürzten
Worker.

- [ ] **Schritt 8: Protokolleintrag schreiben**

Rückweg dieser Stufe:

```bash
ssh ispconfig '/usr/local/sbin/waf-schalter setze aus bright-color.de'
```

---

### Aufgabe 8: Stufe 2, zehn weitere Websites

**Vorher:** Freigabe von Mathias.

**Schnittstellen:**
- Nutzt: Aufgabe 7
- Liefert: elf Websites im Mitschreib-Modus

- [ ] **Schritt 1: Die zehn ruhigsten WordPress-Websites bestimmen**

```bash
ssh ispconfig 'G=$(date -d yesterday "+%Y%m%d"); for d in $(/usr/local/sbin/waf-schalter status | awk "\$2==\"aus\" && \$4==\"ja\" {print \$1}"); do f=/var/log/ispconfig/httpd/$d/${G}-access.log.gz; n=0; [ -f "$f" ] && n=$(zcat "$f" | wc -l); echo "$n $d"; done | sort -n > /root/waf-reihenfolge.txt; head -10 /root/waf-reihenfolge.txt'
```

Erwartet: Liste mit Anfragezahlen, aufsteigend. Websites, die bereits mitschreiben,
fehlen darin.

- [ ] **Schritt 2: Einschalten**

```bash
ssh ispconfig 'head -10 /root/waf-reihenfolge.txt | awk "{print \$2}" | xargs /usr/local/sbin/waf-schalter setze mitschreiben'
```

Erwartet: zehnmal „gesetzt auf mitschreiben", keine Rücknahme.

- [ ] **Schritt 3: Messen und Verfügbarkeit prüfen**

```bash
ssh ispconfig 'ps -o rss= -C nginx | awk "{s+=\$1} END {printf \"nginx %d MB\n\", s/1024}"; free -m | head -3; uptime; du -h /var/log/waf/audit.log; systemctl is-active nginx; grep -c "exited on signal" /var/log/nginx/error.log'
```

Erwartet: Grenzen aus den globalen Vorgaben eingehalten.

- [ ] **Schritt 4: Treffer ansehen**

```bash
ssh ispconfig '/usr/local/sbin/waf-bericht | head -20'
```

- [ ] **Schritt 5: Protokolleintrag schreiben**

---

### Aufgabe 9: Stufe 3, die übrigen WordPress-Websites

**Vorher:** Freigabe von Mathias.

**Schnittstellen:**
- Nutzt: Aufgabe 8
- Liefert: alle 33 WordPress-Websites im Mitschreib-Modus

- [ ] **Schritt 1: Reihenfolge neu bestimmen**

```bash
ssh ispconfig 'G=$(date -d yesterday "+%Y%m%d"); for d in $(/usr/local/sbin/waf-schalter status | awk "\$2==\"aus\" && \$4==\"ja\" {print \$1}"); do f=/var/log/ispconfig/httpd/$d/${G}-access.log.gz; n=0; [ -f "$f" ] && n=$(zcat "$f" | wc -l); echo "$n $d"; done | sort -n > /root/waf-rest.txt; cat /root/waf-rest.txt; echo "Anzahl: $(wc -l < /root/waf-rest.txt)"'
```

Erwartet: die noch ausgeschalteten WordPress-Websites, aufsteigend nach Anfragen des
Vortags. Die letzte Zeile ist die lastreichste Website.

- [ ] **Schritt 2: Erste Hälfte einschalten**

```bash
ssh ispconfig 'H=$(( ($(wc -l < /root/waf-rest.txt) - 1) / 2 )); head -n "$H" /root/waf-rest.txt | awk "{print \$2}" | xargs /usr/local/sbin/waf-schalter setze mitschreiben'
ssh ispconfig 'free -m | head -3; uptime; systemctl is-active nginx'
```

Erwartet: alle gesetzt, Grenzen eingehalten, nginx aktiv.

- [ ] **Schritt 3: Zweite Hälfte ohne die lastreichste Website**

```bash
ssh ispconfig 'H=$(( ($(wc -l < /root/waf-rest.txt) - 1) / 2 )); sed -n "$((H+1)),\$p" /root/waf-rest.txt | head -n -1 | awk "{print \$2}" | xargs /usr/local/sbin/waf-schalter setze mitschreiben'
ssh ispconfig 'free -m | head -3; uptime; systemctl is-active nginx'
```

Erwartet: alle gesetzt, Grenzen eingehalten, nginx aktiv.

- [ ] **Schritt 4: Die lastreichste Website zuletzt**

```bash
ssh ispconfig 'tail -1 /root/waf-rest.txt | awk "{print \$2}" | xargs /usr/local/sbin/waf-schalter setze mitschreiben'
ssh ispconfig 'free -m | head -3; uptime; systemctl is-active nginx; tail -3 /var/log/nginx/error.log'
```

Erwartet: gesetzt, Grenzen eingehalten, nginx aktiv, keine abgestürzten Worker.

- [ ] **Schritt 5: Messen**

```bash
ssh ispconfig 'ps -o rss= -C nginx | awk "{s+=\$1} END {printf \"nginx %d MB\n\", s/1024}"; free -m | head -3; uptime; du -h /var/log/waf/audit.log; for h in bright-color.de wismar.fm radioluebeck.de; do curl -s -o /dev/null -w "$h %{http_code} %{time_total}\n" -H "Host: $h" http://127.0.0.1/; done'
```

Erwartet: Grenzen eingehalten, Antwortzeiten höchstens doppelt so hoch wie in Aufgabe 6.

- [ ] **Schritt 6: Zustand festhalten**

```bash
ssh ispconfig '/usr/local/sbin/waf-schalter status'
```

Erwartet: 33 Websites „mitschreiben", die übrigen „aus", Datenbank und vhost gleich.

- [ ] **Schritt 7: Protokolleintrag schreiben**

---

### Aufgabe 10: Stufe 4, Auswertung und Ausnahmen

**Vorher:** Freigabe von Mathias.

**Dateien:**
- Ändern: `waf/conf/ausnahmen-nachher.conf`
- Server: `/etc/nginx/waf/ausnahmen-nachher.conf`
- Protokoll: Eintrag

**Schnittstellen:**
- Nutzt: `waf-bericht` aus Aufgabe 5, Zustand aus Aufgabe 9
- Liefert: Ausnahmen je Website, wieder gemessene Werte

- [ ] **Schritt 1: Bericht lesen**

```bash
ssh ispconfig '/usr/local/sbin/waf-bericht'
```

- [ ] **Schritt 2: Ausnahmen schreiben**

Je Fehlalarm eine Regel in `waf/conf/ausnahmen-nachher.conf`, IDs ab 10200. Muster für
eine Regel, die auf einer Website eine CRS-Regel abschaltet:

```
SecRule REQUEST_HEADERS:Host "@streq beispiel.test" \
    "id:10200,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

Muster für einen Pfad statt einer ganzen Website:

```
SecRule REQUEST_FILENAME "@rx ^/wp-admin/admin-ajax\.php$" \
    "id:10201,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:filter"
```

- [ ] **Schritt 3: Einspielen und prüfen**

```bash
scp waf/conf/ausnahmen-nachher.conf ispconfig:/etc/nginx/waf/ausnahmen-nachher.conf
ssh ispconfig 'nginx -t && systemctl reload nginx && systemctl is-active nginx'
```

Erwartet: `nginx -t` in Ordnung, Dienst aktiv.

- [ ] **Schritt 4: Wirkung prüfen**

```bash
ssh ispconfig 'W=$(wc -l < /var/log/waf/audit.log); sleep 300; echo "Zeilen vorher $W, jetzt $(wc -l < /var/log/waf/audit.log)"; /usr/local/sbin/waf-bericht | head -20'
```

Erwartet: die bearbeiteten Fehlalarme tauchen nicht mehr auf.

- [ ] **Schritt 5: Committen und protokollieren**

```bash
git add waf/conf/ausnahmen-nachher.conf
git diff --cached | grep -iE 'isp[p]rotect|word[f]ence'
git commit -m "feat(waf): site exclusions from the first detection run"
```

Protokolleintrag mit Messwerten, Zahl der Treffer je Website und den gesetzten
Ausnahmen.

---

## Nach dem Plan

- Der Zustand „scharf" bleibt offen und wird getrennt entschieden.
- Der Umstieg auf eigene Pakete mit Engine 3.0.16 und CRS 4.25 LTS bleibt offen.
- Vor dem Upgrade auf Ubuntu 26.04: WAF abschalten, Pakete entfernen, nach dem Upgrade
  die Pakete von 26.04 einspielen.
