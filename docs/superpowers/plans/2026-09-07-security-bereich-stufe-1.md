# Security-Bereich, Stufe 1 — Umsetzungsplan

> **Für agentische Bearbeiter:** ERFORDERLICHE UNTER-FÄHIGKEIT: `superpowers:subagent-driven-development` (empfohlen) oder `superpowers:executing-plans`, Aufgabe für Aufgabe. Schritte sind als Kästchen (`- [ ]`) zum Abhaken geschrieben.

**Ziel:** Das Addon bekommt einen eigenen Bereich **Security** in der oberen Leiste, eine Statusseite, die eine Frage beantwortet statt Daten auszubreiten, und es lässt sich bedienen, während ein Scan läuft.

**Aufbau:** Ein ISPConfig-Modul `security` nach dem Muster des bereits laufenden `wpinstaller`; der Installer trägt es in `sys_user.modules` der Administratoren ein. Das Neuladen im Takt entfällt zugunsten eines JSON-Endpunkts, der nur die betroffenen Zellen umschreibt. Der Fortschrittsbalken bekommt einen Nenner, indem der Runner die Dateizahl des letzten Laufs als Erwartungswert durchreicht.

**Werkzeuge:** Go (nur Standardbibliothek), PHP 8 im ISPConfig-Rahmen, MariaDB, vanilla JavaScript ohne Bibliothek.

**Spec:** [docs/superpowers/specs/2026-09-07-security-bereich-design.md](../specs/2026-09-07-security-bereich-design.md)

## Verbindliche Randbedingungen

Gelten für jede Aufgabe, auch wo sie nicht wiederholt werden.

- **Nur die Go-Standardbibliothek.** `go.mod` bleibt ohne `require`-Block.
- **Keine Bibliothek im Browser.** Kein jQuery-Plugin, kein Framework; das Panel bringt Bootstrap mit, mehr wird nicht geladen.
- **Farben ausschließlich aus dem Theme**, mit Rückfallwert: `var(--cic-bad, #d13f22)`. Erlaubt sind nur die Namen aus der Spec. Radius durchgehend `3px`.
- **`--cic-warn` nicht für den Warnzustand benutzen** — es ist fast identisch mit `--cic-accent`. Für Warnungen `--cic-warn-lift`.
- **Keine Regelbezeichner in der Oberfläche.** Keine Wörter aus dem Bau: kein *Preset*, keine *Freigabeliste*, kein *Job*, kein *Datensatz*.
- **Schaltflächen sagen, was geschieht:** „In Quarantäne", „Zurückholen", „Unbedenklich", „Ansehen". Nie „Freigeben".
- **Zahlen mit deutscher Tausendertrennung**, Datum ausgeschrieben („6. September"), Uhrzeit mit „Uhr".
- **Jede Seite prüft `$app->auth->is_admin()`** und antwortet sonst leer, unabhängig von der Modulzugehörigkeit.
- **Der Fortschritt wird bei 99 % gedeckelt**, solange der Lauf nicht `done` meldet.
- Deutsche Beschriftungen in `de_*.lng`, englische in `en_*.lng`; keine Zeichenkette fest im Code.

---

### Aufgabe 1: Der Scanner meldet einen Nenner

**Dateien:**
- Ändern: `cmd/malwatch/scan.go` (Flag-Block um Zeile 73, Fortschrittsblock um Zeile 140)
- Test: `cmd/malwatch/scan_test.go` (neu)

**Schnittstellen:**
- Verbraucht: `progress.Writer.File(rel string, done, total int)` aus `internal/progress`
- Erzeugt: das Kommandozeilen-Flag `--expect=N`; im Fortschrittsdokument ist `files_total` gesetzt, wenn `N > 0`

- [ ] **Schritt 1: Den fehlschlagenden Test schreiben**

Neue Datei `cmd/malwatch/scan_test.go`:

```go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Der Balken im Panel rechnet seine Breite aus done/total. Ohne total stand er
// auf festen fünf Prozent, und ein Scan sah minutenlang aus wie ein Absturz.
func TestScanReportsATotalWhenExpectIsGiven(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.php", "b.php", "c.php"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("<?php echo 1;"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prog := filepath.Join(t.TempDir(), "job.progress")

	code := cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog, "--expect=3",
		"--out=" + filepath.Join(t.TempDir(), "r.json"), "--json",
	})
	if code > 1 {
		t.Fatalf("Rückgabewert %d", code)
	}

	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FilesTotal int `json:"files_total"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.FilesTotal != 3 {
		t.Errorf("files_total ist %d, erwartet 3", doc.FilesTotal)
	}
}

// Ohne den Schalter bleibt alles wie bisher: ein Zähler ohne Nenner ist eine
// ehrliche Aussage, eine erfundene Gesamtzahl wäre keine.
func TestScanLeavesTheTotalAtZeroWithoutExpect(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(t.TempDir(), "job.progress")

	cmdScan([]string{
		"--path=" + root, "--quiet", "--offline", "--no-clamav",
		"--progress=" + prog,
		"--out=" + filepath.Join(t.TempDir(), "r.json"), "--json",
	})

	raw, err := os.ReadFile(prog)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		FilesTotal int `json:"files_total"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.FilesTotal != 0 {
		t.Errorf("files_total ist %d, erwartet 0", doc.FilesTotal)
	}
}
```

- [ ] **Schritt 2: Den Test laufen lassen und den Fehlschlag sehen**

```bash
go test -c -o .testbin/scan1.test ./cmd/malwatch/ && ./.testbin/scan1.test -test.run TestScanReportsATotal -test.v
```

Erwartet: `flag provided but not defined: -expect`, danach ein Rückgabewert über 1.

*Hinweis für Windows:* Eine Anwendungssteuerungsrichtlinie blockiert frisch gebaute Testdateien sporadisch („Permission denied"). Dann unter einem anderen Namen bauen, oder für Linux bauen und dort laufen lassen.

- [ ] **Schritt 3: Das Flag einbauen**

In `cmd/malwatch/scan.go` neben die übrigen Flags (bei `progressFile := fs.String("progress", "", "")`):

```go
	expect := fs.Int("expect", 0, "")
```

- [ ] **Schritt 4: Den Nenner melden**

Den Fortschrittsblock ersetzen. Vorher:

```go
	opts.Progress = func(n int64) {
		pw.File("", int(n), 0)
		if onTerminal {
			fmt.Fprintf(os.Stderr, "\r%d Dateien geprüft …", n)
		}
	}
```

Nachher:

```go
	// Der Erwartungswert kommt vom Panel und ist die Dateizahl des letzten
	// Laufs derselben Website. Er kann danebenliegen - eine Website wächst -,
	// und deshalb ist er eine Schätzung und keine Zusage. Wer ihn auswertet,
	// deckelt bei 99 Prozent, bis der Lauf fertig meldet.
	opts.Progress = func(n int64) {
		pw.File("", int(n), *expect)
		if onTerminal {
			fmt.Fprintf(os.Stderr, "\r%d Dateien geprüft …", n)
		}
	}
```

- [ ] **Schritt 5: Beide Tests laufen lassen**

```bash
go test -c -o .testbin/scan2.test ./cmd/malwatch/ && ./.testbin/scan2.test -test.count=1
```

Erwartet: `PASS`.

- [ ] **Schritt 6: Die Hilfe ergänzen**

In der Nutzungsausgabe (`usage()` in `cmd/malwatch/main.go`) beim Befehl `scan` eine Zeile einfügen, im Stil der vorhandenen:

```
  --expect=N        erwartete Dateizahl, nur für die Fortschrittsanzeige
```

- [ ] **Schritt 7: Committen**

```bash
git add cmd/malwatch/scan.go cmd/malwatch/scan_test.go cmd/malwatch/main.go
git commit -m "feat: der Scan meldet einen Nenner, wenn einer bekannt ist

Der Balken im Panel rechnet seine Breite aus done durch total. Der Scan
meldete done und liess total auf null, also fiel die Anzeige auf feste
fuenf Prozent zurueck und ein Lauf sah minutenlang aus wie ein Absturz.

--expect nimmt die erwartete Dateizahl entgegen. Sie ist eine Schaetzung
und keine Zusage, weil eine Website zwischen zwei Laeufen waechst; ohne
den Schalter bleibt es beim Zaehler ohne Nenner, was ehrlicher ist als
eine erfundene Gesamtzahl.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Aufgabe 2: Der Runner reicht den Erwartungswert durch

**Dateien:**
- Ändern: `ispconfig/server/lib/classes/malwatch_runner.inc.php` (Methode `build_arguments`, Scan-Zweig ab Zeile 130)
- Ändern: `ispconfig/tests/check_wiring.sh`

**Schnittstellen:**
- Verbraucht: `--expect=N` aus Aufgabe 1
- Erzeugt: nichts, worauf spätere Aufgaben zugreifen

- [ ] **Schritt 1: Die Prüfung in check_wiring.sh schreiben**

Ans Ende von `ispconfig/tests/check_wiring.sh`, vor `exit $status`:

```sh
# 22. Der Fortschrittsbalken braucht einen Nenner. Ohne --expect meldet der
#     Scanner nur einen Zaehler, und die Anzeige faellt auf feste fuenf
#     Prozent zurueck - was ein Lauf ist, der aussieht wie ein Absturz.
runner="$root/server/lib/classes/malwatch_runner.inc.php"
if ! grep -q -- "--expect=" "$runner"; then
	fail "der Runner reicht kein --expect durch, der Balken bleibt stehen"
fi
if ! grep -q 'files_scanned' "$runner"; then
	fail "der Runner liest die Dateizahl des letzten Laufs nicht"
fi
```

- [ ] **Schritt 2: Die Prüfung laufen lassen und den Fehlschlag sehen**

```bash
sh ispconfig/tests/check_wiring.sh
```

Erwartet: `FAIL: der Runner reicht kein --expect durch, der Balken bleibt stehen`

- [ ] **Schritt 3: Den Erwartungswert ermitteln und anhängen**

In `build_arguments`, unmittelbar nach dem `$args = array(...)`-Block des Scan-Zweigs und vor der `foreach`-Schleife über die Ausschlussmuster:

```php
		// Die Dateizahl des juengsten abgeschlossenen Laufs derselben Website
		// ist der beste Schaetzwert, den es umsonst gibt: er steht bereits in
		// der Datenbank. Beim ersten Lauf einer Website gibt es keinen, dann
		// entfaellt der Schalter und die Anzeige zaehlt ohne Prozentangabe.
		$last = $app->db->queryOneRecord(
			'SELECT files_scanned FROM malwatch_scan WHERE parent_domain_id = ? '
			. "AND scan_state = 'done' AND files_scanned > 0 "
			. 'ORDER BY scan_id DESC LIMIT 1',
			intval($job['parent_domain_id'])
		);
		if (is_array($last) && intval($last['files_scanned']) > 0) {
			$args[] = '--expect=' . intval($last['files_scanned']);
		}
```

- [ ] **Schritt 4: Die Prüfung erneut laufen lassen**

```bash
sh ispconfig/tests/check_wiring.sh && php -l ispconfig/server/lib/classes/malwatch_runner.inc.php
```

Erwartet: `Wiring OK` und `No syntax errors detected`.

- [ ] **Schritt 5: Committen**

```bash
git add ispconfig/server/lib/classes/malwatch_runner.inc.php ispconfig/tests/check_wiring.sh
git commit -m "feat: der Runner reicht die Dateizahl des letzten Laufs durch

Der beste Schaetzwert fuer die Groesse einer Website ist die Zahl, die
beim letzten Mal herauskam - und die steht schon in malwatch_scan. Beim
ersten Lauf einer Website gibt es keine, dann entfaellt der Schalter.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Aufgabe 3: Das Modul „Security" in der oberen Leiste

**Dateien:**
- Erstellen: `ispconfig/interface/module.conf.php`
- Ändern: `ispconfig/install/file.list`
- Ändern: `ispconfig/install/installer.php` (Methoden `install`, `uninstall`)
- Ändern: `ispconfig/tests/check_wiring.sh`
- Löschen: `ispconfig/interface/malwatch.menu.php`

**Schnittstellen:**
- Erzeugt: das Modul `security` mit Startseite `security/status.php`; die Seitenleiste mit den Punkten Status, Quarantäne, Prüfläufe, Einstellungen

- [ ] **Schritt 1: Die Prüfungen schreiben**

Ans Ende von `ispconfig/tests/check_wiring.sh`, vor `exit $status`:

```sh
# 23. Das Modul braucht eine module.conf.php mit Namen und Startseite, sonst
#     erscheint der Punkt in der oberen Leiste ohne Inhalt.
conf="$root/interface/module.conf.php"
if [ ! -f "$conf" ]; then
	fail "interface/module.conf.php fehlt, das Modul erscheint nicht"
else
	for key in "module\['name'\]" "module\['title'\]" "module\['startpage'\]"; do
		if ! grep -qE "\\\$$key" "$conf"; then
			fail "module.conf.php setzt \$$key nicht"
		fi
	done
fi

# 24. Der Installer muss das Modul in sys_user.modules eintragen und beim
#     Deinstallieren wieder entfernen. Ohne den Eintrag sieht niemand den
#     neuen Punkt, mit einem verwaisten Eintrag zeigt das Panel einen
#     Menuepunkt ohne Ziel.
inst="$root/install/installer.php"
if ! grep -q 'sys_user' "$inst"; then
	fail "der Installer traegt das Modul nicht in sys_user.modules ein"
fi

# 25. Die alte Menuedatei darf nicht mehr existieren, sonst steht das Addon
#     doppelt im Panel - einmal oben und einmal in der Seitenleiste der Sites.
if [ -f "$root/interface/malwatch.menu.php" ]; then
	fail "interface/malwatch.menu.php ist noch da, das Addon stuende doppelt"
fi
if grep -q 'menu.d/malwatch.menu.php' "$root/install/file.list"; then
	fail "file.list installiert noch die alte Menuedatei"
fi
```

- [ ] **Schritt 2: Die Prüfungen laufen lassen und die Fehlschläge sehen**

```bash
sh ispconfig/tests/check_wiring.sh
```

Erwartet: vier `FAIL`-Zeilen.

- [ ] **Schritt 3: Die Moduldatei anlegen**

Neue Datei `ispconfig/interface/module.conf.php`:

```php
<?php

/**
 * Konfiguration des Moduls "Security".
 *
 * Frueher hing das Addon als Navigationsgruppe in der Seitenleiste des
 * Sites-Moduls, weil ein eigenes Modul in sys_user.modules jedes Bedieners
 * eingetragen werden muss und das Kerndaten anfasst. Das erledigt jetzt der
 * Installer - denselben Weg geht wpinstaller auf demselben Server.
 */

$module['name']      = 'security';
$module['title']     = 'Security';
$module['template']  = 'module.tpl.htm';
$module['startpage'] = 'security/status.php';
$module['tab_width'] = '';
$module['order']     = '40';
$module['icon']      = 'icon icon-monitor';

$items = array();

$items[] = array(
	'title'   => 'Status',
	'target'  => 'content',
	'link'    => 'security/status.php',
	'html_id' => 'security_status'
);

$items[] = array(
	'title'   => 'Quarantäne',
	'target'  => 'content',
	'link'    => 'security/malwatch_quarantine_list.php',
	'html_id' => 'security_quarantine'
);

$items[] = array(
	'title'   => 'Prüfläufe',
	'target'  => 'content',
	'link'    => 'security/malwatch_scan_list.php',
	'html_id' => 'security_scans'
);

$items[] = array(
	'title'   => 'Einstellungen',
	'target'  => 'content',
	'link'    => 'security/malwatch_config_edit.php',
	'html_id' => 'security_settings'
);

$module['nav'][] = array(
	'title' => 'Security',
	'open'  => 1,
	'items' => $items
);

unset($items);
```

*Anmerkung:* Der Punkt „Quarantäne" zeigt in Stufe 1 noch auf eine Seite, die erst in Stufe 3 entsteht. Damit die Leiste nicht ins Leere führt, entfällt dieser Eintrag vorerst — er wird in Stufe 3 eingefügt. **Den `Quarantäne`-Block also in Stufe 1 nicht mit aufnehmen.**

- [ ] **Schritt 4: Die alte Menüdatei entfernen**

```bash
git rm ispconfig/interface/malwatch.menu.php
```

- [ ] **Schritt 5: file.list umschreiben**

In `ispconfig/install/file.list` die erste Zeile ersetzen. Vorher:

```
c:interface/malwatch.menu.php:interface/web/sites/lib/menu.d/malwatch.menu.php
```

Nachher:

```
c:interface/module.conf.php:interface/web/security/lib/module.conf.php
```

- [ ] **Schritt 6: Den Installer den Eintrag schreiben lassen**

In `ispconfig/install/installer.php` zwei private Methoden ergänzen (ans Ende der Klasse):

```php
	/**
	 * Traegt das Modul bei jedem Administrator ein.
	 *
	 * Idempotent: ein zweiter Lauf schreibt nichts doppelt. Ohne diesen
	 * Eintrag erscheint der Punkt in der oberen Leiste bei niemandem, weil
	 * ISPConfig die Leiste aus sys_user.modules baut und nicht aus den
	 * vorhandenen Verzeichnissen.
	 */
	private function grant_module()
	{
		global $app;

		$rows = $app->db->queryAllRecords(
			"SELECT userid, modules FROM sys_user WHERE typ = 'admin'"
		);
		if (!is_array($rows)) {
			return;
		}
		foreach ($rows as $row) {
			$modules = array_filter(explode(',', (string) $row['modules']));
			if (in_array('security', $modules, true)) {
				continue;
			}
			$modules[] = 'security';
			$app->db->query(
				'UPDATE sys_user SET modules = ? WHERE userid = ?',
				implode(',', $modules), intval($row['userid'])
			);
			$app->log('malwatch: Modul security fuer Benutzer '
				. intval($row['userid']) . ' eingetragen.', LOGLEVEL_DEBUG);
		}
	}

	/**
	 * Nimmt das Modul wieder heraus.
	 *
	 * Ein verwaister Eintrag zeigt einen Menuepunkt ohne Ziel, und der ist
	 * schlimmer als gar keiner.
	 */
	private function revoke_module()
	{
		global $app;

		$rows = $app->db->queryAllRecords('SELECT userid, modules FROM sys_user');
		if (!is_array($rows)) {
			return;
		}
		foreach ($rows as $row) {
			$modules = array_filter(explode(',', (string) $row['modules']));
			if (!in_array('security', $modules, true)) {
				continue;
			}
			$modules = array_values(array_diff($modules, array('security')));
			$app->db->query(
				'UPDATE sys_user SET modules = ? WHERE userid = ?',
				implode(',', $modules), intval($row['userid'])
			);
		}
	}
```

- [ ] **Schritt 7: Die Methoden aufrufen**

In `install()`, unmittelbar vor `echo "\nmalwatch installed.\n\n";`:

```php
		$this->grant_module();
```

In `uninstall()`, unmittelbar nach `$this->disable($name);`:

```php
		$this->revoke_module();
```

Die drei `echo`-Zeilen am Ende von `install()` sprechen noch vom alten Ort. Ersetzen:

```php
		echo "- Open Websites > malwatch in the panel to configure it\n\n";
```

durch:

```php
		echo "- Open Security in the panel to configure it\n\n";
```

- [ ] **Schritt 8: Die Prüfungen laufen lassen**

```bash
sh ispconfig/tests/check_wiring.sh && php -l ispconfig/install/installer.php && php -l ispconfig/interface/module.conf.php
```

Erwartet: `Wiring OK`, zweimal `No syntax errors detected`.

- [ ] **Schritt 9: Committen**

```bash
git add -A
git commit -m "feat: Security als eigener Punkt in der oberen Leiste

Bisher hing das Addon als Navigationsgruppe in der Seitenleiste des
Sites-Moduls. Der Kommentar in der alten Menuedatei nannte auch den
Grund: ein eigenes Modul muss in sys_user.modules jedes Bedieners
eingetragen werden, und das faellt unter Kerndaten.

Das erledigt jetzt der Installer, idempotent, und der Deinstaller nimmt
es wieder heraus - ein verwaister Eintrag zeigt einen Menuepunkt ohne
Ziel und ist schlimmer als gar keiner. Denselben Weg geht wpinstaller
auf demselben Server.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Aufgabe 4: Die vorhandenen Seiten ziehen um

**Dateien:**
- Ändern: `ispconfig/install/file.list` (alle Zeilen mit `interface/web/sites/`)
- Ändern: `ispconfig/interface/malwatch_progress.php`, `malwatch_site_show.php`, `malwatch_site_edit.php`, `malwatch_finding_list.php`, `malwatch_scan_list.php`, `malwatch_config_edit.php`, `malwatch_site_list.php`
- Ändern: `ispconfig/interface/lib/malwatch_lib.inc.php`
- Ändern: alle Vorlagen unter `ispconfig/interface/templates/`
- Ändern: `ispconfig/tests/check_wiring.sh`

**Schnittstellen:**
- Verbraucht: das Modul aus Aufgabe 3
- Erzeugt: alle Seiten unter `security/` erreichbar

- [ ] **Schritt 1: Die Prüfung schreiben**

Ans Ende von `ispconfig/tests/check_wiring.sh`, vor `exit $status`:

```sh
# 26. Nach dem Umzug darf nirgends mehr ein Pfad auf sites/ zeigen - weder in
#     einem loadContent-Aufruf, noch in einem Formularziel, noch in
#     check_module_permissions.
if grep -rn "sites/malwatch" "$root/interface" >/dev/null 2>&1; then
	fail "es zeigt noch etwas auf sites/malwatch_*, der Umzug ist unvollstaendig"
fi
if grep -rn "check_module_permissions('sites')" "$root/interface" >/dev/null 2>&1; then
	fail "eine Seite prueft noch die Rechte des Sites-Moduls"
fi
if grep -q 'interface/web/sites/' "$root/install/file.list"; then
	fail "file.list legt noch Dateien in das Sites-Modul"
fi
```

- [ ] **Schritt 2: Die Prüfung laufen lassen und die Fehlschläge sehen**

```bash
sh ispconfig/tests/check_wiring.sh
```

Erwartet: drei `FAIL`-Zeilen.

- [ ] **Schritt 3: file.list umschreiben**

```bash
sed -i 's#interface/web/sites/#interface/web/security/#g' ispconfig/install/file.list
grep -c 'interface/web/security/' ispconfig/install/file.list
```

Erwartet: die Anzahl der Interface-Zeilen, und keine Zeile mehr mit `web/sites/`.

- [ ] **Schritt 4: Die Rechteprüfung und alle Verweise umschreiben**

```bash
grep -rl "sites/malwatch\|check_module_permissions('sites')" ispconfig/interface \
  | xargs sed -i "s#sites/malwatch#security/malwatch#g; s#check_module_permissions('sites')#check_module_permissions('security')#g"
```

- [ ] **Schritt 5: Die Prüfung erneut laufen lassen**

```bash
sh ispconfig/tests/check_wiring.sh
for f in ispconfig/interface/*.php ispconfig/interface/lib/*.php; do php -l "$f" >/dev/null || echo "SYNTAX $f"; done
```

Erwartet: `Wiring OK`, keine `SYNTAX`-Zeile.

- [ ] **Schritt 6: Committen**

```bash
git add -A
git commit -m "refactor: die Seiten ziehen in das Security-Modul um

Alle Pfade, Formularziele und Rechtepruefungen zeigen auf security/
statt sites/. Eine Pruefung in check_wiring.sh haelt fest, dass nichts
zurueckbleibt: ein uebersehener loadContent-Pfad faellt sonst erst auf,
wenn jemand die Seite oeffnet.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Aufgabe 5: Ein Endpunkt, der den Stand meldet

**Dateien:**
- Ändern: `ispconfig/interface/malwatch_progress.php`
- Ändern: `ispconfig/tests/check_wiring.sh`

**Schnittstellen:**
- Verbraucht: `files_total` aus dem Fortschrittsdokument (Aufgabe 1)
- Erzeugt: JSON mit den Feldern `state`, `percent`, `files_done`, `files_total`, `label`, `sites` — von Aufgabe 6 gelesen

- [ ] **Schritt 1: Die Prüfung schreiben**

Ans Ende von `ispconfig/tests/check_wiring.sh`, vor `exit $status`:

```sh
# 27. Der Endpunkt muss den Prozentwert deckeln. Der Erwartungswert ist die
#     Dateizahl des letzten Laufs, und eine Website waechst dazwischen - ein
#     Balken bei 140 Prozent ist schlimmer als einer ohne Prozentangabe.
prog="$root/interface/malwatch_progress.php"
if ! grep -q '99' "$prog"; then
	fail "malwatch_progress.php deckelt den Prozentwert nicht bei 99"
fi
```

- [ ] **Schritt 2: Die Prüfung laufen lassen und den Fehlschlag sehen**

```bash
sh ispconfig/tests/check_wiring.sh
```

Erwartet: `FAIL: malwatch_progress.php deckelt den Prozentwert nicht bei 99`

- [ ] **Schritt 3: Den Prozentwert berechnen und deckeln**

In `ispconfig/interface/malwatch_progress.php`, dort wo das Fortschrittsdokument gelesen und die Antwort zusammengebaut wird, den Prozentwert ergänzen:

```php
// Der Erwartungswert ist die Dateizahl des letzten Laufs derselben Website.
// Eine Website waechst zwischen zwei Laeufen, also kann der Zaehler den
// Erwartungswert ueberholen. Bis der Lauf "done" meldet, wird deshalb bei
// 99 Prozent gedeckelt - ein Balken bei 140 Prozent ist schlimmer als einer
// ohne Prozentangabe.
$files_done  = isset($progress['files_done'])  ? intval($progress['files_done'])  : 0;
$files_total = isset($progress['files_total']) ? intval($progress['files_total']) : 0;

$percent = null;
if ($files_total > 0) {
	$percent = intval(floor($files_done * 100 / $files_total));
	if ($percent > 99) {
		$percent = 99;
	}
	if ($percent < 0) {
		$percent = 0;
	}
}
if ($state === 'done') {
	$percent = 100;
}

// Ohne Nenner zaehlt die Anzeige nur - "71.240 Dateien geprueft" ist eine
// ehrliche Aussage, eine erfundene Prozentzahl waere keine.
$label = ($percent === null)
	? number_format($files_done, 0, ',', '.') . ' Dateien geprüft'
	: number_format($files_done, 0, ',', '.') . ' von '
		. number_format($files_total, 0, ',', '.') . ' Dateien';
```

und in das ausgegebene Array aufnehmen:

```php
	'percent'     => $percent,
	'files_done'  => $files_done,
	'files_total' => $files_total,
	'label'       => $label,
```

- [ ] **Schritt 4: Die Prüfung erneut laufen lassen**

```bash
sh ispconfig/tests/check_wiring.sh && php -l ispconfig/interface/malwatch_progress.php
```

Erwartet: `Wiring OK`, `No syntax errors detected`.

- [ ] **Schritt 5: Committen**

```bash
git add ispconfig/interface/malwatch_progress.php ispconfig/tests/check_wiring.sh
git commit -m "feat: der Fortschrittsendpunkt liefert Prozent und Beschriftung

Gedeckelt bei 99 Prozent, solange der Lauf nicht fertig meldet: der
Erwartungswert ist die Dateizahl des letzten Laufs, und eine Website
waechst dazwischen. Ohne Nenner zaehlt die Beschriftung nur, statt eine
Prozentzahl zu erfinden.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Aufgabe 6: Die Statusseite, ohne Neuladen

**Dateien:**
- Erstellen: `ispconfig/interface/status.php`
- Erstellen: `ispconfig/interface/templates/status.htm`
- Erstellen: `ispconfig/interface/lang/de_status.lng`, `ispconfig/interface/lang/en_status.lng`
- Ändern: `ispconfig/install/file.list`
- Löschen: `ispconfig/interface/malwatch_site_list.php`, `ispconfig/interface/templates/malwatch_site_list.htm`, `ispconfig/interface/lang/*_malwatch.lng` bleiben
- Ändern: `ispconfig/tests/check_wiring.sh`

**Schnittstellen:**
- Verbraucht: den Endpunkt aus Aufgabe 5
- Erzeugt: `security/status.php` als Startseite des Moduls

- [ ] **Schritt 1: Die Prüfungen schreiben**

Ans Ende von `ispconfig/tests/check_wiring.sh`, vor `exit $status`:

```sh
# 28. DOMNodeRemoved ist ein Mutation Event, das Chrome seit Version 127
#     abgeschaltet hat. Ein Abbruch, der daran haengt, greift nie - der Timer
#     ueberlebt jede Navigation und zieht den Bediener aus jeder Seite zurueck.
if grep -rn 'DOMNodeRemoved' "$root/interface" >/dev/null 2>&1; then
	fail "DOMNodeRemoved wird noch benutzt, der Abbruch greift nicht"
fi

# 29. Ein loadContent im Takt laedt die ganze Seite neu und reisst den
#     Bediener aus dem, was er gerade ansieht.
if grep -rnE 'set(Timeout|Interval)[^;]*loadContent' "$root/interface" >/dev/null 2>&1; then
	fail "eine Seite laedt sich im Takt selbst neu"
fi

# 30. Die Statusseite ist die Startseite des Moduls und muss existieren.
if [ ! -f "$root/interface/status.php" ]; then
	fail "interface/status.php fehlt, das Modul startet ins Leere"
fi
```

- [ ] **Schritt 2: Die Prüfungen laufen lassen und die Fehlschläge sehen**

```bash
sh ispconfig/tests/check_wiring.sh
```

Erwartet: drei `FAIL`-Zeilen.

- [ ] **Schritt 3: Die Sprachdateien anlegen**

`ispconfig/interface/lang/de_status.lng`:

```php
<?php
$wb['page_head_txt'] = 'Status';
$wb['attention_one_txt'] = 'Eine Website braucht Ihre Aufmerksamkeit.';
$wb['attention_many_txt'] = '%s Websites brauchen Ihre Aufmerksamkeit.';
$wb['all_clear_txt'] = 'Alle Websites sind unauffällig.';
$wb['as_of_txt'] = 'Stand %s. Die nächste Prüfung läuft %s.';
$wb['quiet_txt'] = '%s weitere Websites sind unauffällig.';
$wb['quiet_one_txt'] = 'Eine weitere Website ist unauffällig.';
$wb['show_all_txt'] = 'Alle anzeigen';
$wb['view_txt'] = 'Ansehen';
$wb['scan_now_txt'] = 'Jetzt prüfen';
$wb['cancel_txt'] = 'Abbrechen';
$wb['state_infected_txt'] = 'Befallen';
$wb['state_attention_txt'] = 'Nachsehen';
$wb['state_running_txt'] = 'Wird geprüft';
$wb['state_clean_txt'] = 'Unauffällig';
$wb['never_scanned_txt'] = 'Noch nie geprüft.';
$wb['findings_txt'] = '%s auffällige Dateien, davon %s dringend.';
$wb['findings_one_txt'] = 'Eine auffällige Datei.';
$wb['last_scan_txt'] = 'Zuletzt geprüft %s.';
$wb['waiting_txt'] = 'Startet gleich …';
```

`ispconfig/interface/lang/en_status.lng`: dieselben Schlüssel, englische Werte
(`'%s websites need your attention.'`, `'Infected'`, `'Being checked'` und so fort).

- [ ] **Schritt 4: Die Seite anlegen**

Neue Datei `ispconfig/interface/status.php`. Sie fragt die Websites ab, die etwas
brauchen, und übergibt sie an die Vorlage:

```php
<?php

/**
 * Die Startseite des Security-Moduls.
 *
 * Sie beantwortet eine Frage - brennt etwas? - statt Daten auszubreiten.
 * Deshalb stehen hier nur die Websites, die etwas brauchen; die
 * unauffaelligen sind eine ruhige Zeile darunter und kein Standardinhalt.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	// Die Modulzugehoerigkeit allein ist keine Rechtepruefung.
	die('');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/status.htm');
$app->load_language_file('web/security/lib/lang/' . $_SESSION['s']['language'] . '_status.lng');

$rows = malwatch_status_rows($app);

$app->tpl->setLoop('sites', $rows['attention']);
$app->tpl->setVar('attention_count', count($rows['attention']));
$app->tpl->setVar('quiet_count', $rows['quiet_count']);
$app->tpl->setVar('as_of', $rows['as_of']);
$app->tpl->setVar('next_run', $rows['next_run']);
$app->tpl->setVar($wb);

$app->tpl_defaults();
$app->tpl->pparse();
```

- [ ] **Schritt 5: Die Abfrage in die Bibliothek schreiben**

In `ispconfig/interface/lib/malwatch_lib.inc.php` ans Ende:

```php
/**
 * Liefert die Websites, die etwas brauchen, und die Zahl der uebrigen.
 *
 * Reihenfolge: kritische Funde, dann laufende Pruefungen, dann hohe Funde.
 * Wer morgens hinsieht, soll die dringendste Website oben finden und nicht
 * suchen muessen.
 */
function malwatch_status_rows($app)
{
	$sql = "SELECT w.domain_id, w.domain,
			COALESCE(f.total, 0) AS findings,
			COALESCE(f.urgent, 0) AS urgent,
			s.finished_at, s.files_scanned,
			j.job_id AS running_job
		FROM web_domain w
		LEFT JOIN (
			SELECT parent_domain_id,
				COUNT(*) AS total,
				SUM(severity = 'critical') AS urgent
			FROM malwatch_finding
			WHERE finding_state = 'open'
			GROUP BY parent_domain_id
		) f ON f.parent_domain_id = w.domain_id
		LEFT JOIN malwatch_scan s ON s.scan_id = (
			SELECT scan_id FROM malwatch_scan
			WHERE parent_domain_id = w.domain_id AND scan_state = 'done'
			ORDER BY scan_id DESC LIMIT 1
		)
		LEFT JOIN malwatch_job j ON j.job_id = (
			SELECT job_id FROM malwatch_job
			WHERE parent_domain_id = w.domain_id
				AND job_status IN ('pending','running')
			ORDER BY job_id DESC LIMIT 1
		)
		WHERE w.type = 'vhost' AND w.active = 'y'
		ORDER BY COALESCE(f.urgent, 0) DESC, j.job_id DESC,
			COALESCE(f.total, 0) DESC, w.domain ASC";

	$all = $app->db->queryAllRecords($sql);
	if (!is_array($all)) {
		$all = array();
	}

	$attention = array();
	$quiet = 0;
	$newest = 0;

	foreach ($all as $row) {
		if (!empty($row['finished_at'])) {
			$stamp = strtotime($row['finished_at']);
			if ($stamp > $newest) {
				$newest = $stamp;
			}
		}
		$running  = intval($row['running_job']) > 0;
		$findings = intval($row['findings']);
		if (!$running && $findings < 1) {
			$quiet++;
			continue;
		}
		$row['is_running']  = $running ? 'y' : 'n';
		$row['urgent']      = intval($row['urgent']);
		$row['findings']    = $findings;
		$row['state_class'] = $running ? 'busy' : ($row['urgent'] > 0 ? 'bad' : 'warn');
		$attention[] = $row;
	}

	return array(
		'attention'   => $attention,
		'quiet_count' => $quiet,
		'as_of'       => $newest ? malwatch_when($newest) : '—',
		'next_run'    => 'heute Nacht um 03:00 Uhr',
	);
}

/**
 * Ein Zeitpunkt so, wie ein Mensch ihn sagt: "heute 03:14 Uhr", "gestern
 * 21:12 Uhr", sonst "6. September, 21:12 Uhr".
 */
function malwatch_when($stamp)
{
	$monate = array('', 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
		'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember');
	$heute  = strtotime('today');
	$zeit   = date('H:i', $stamp) . ' Uhr';
	if ($stamp >= $heute) {
		return 'heute ' . $zeit;
	}
	if ($stamp >= $heute - 86400) {
		return 'gestern ' . $zeit;
	}
	return intval(date('j', $stamp)) . '. ' . $monate[intval(date('n', $stamp))] . ', ' . $zeit;
}
```

- [ ] **Schritt 6: Die Vorlage anlegen**

Neue Datei `ispconfig/interface/templates/status.htm`. **Kein eigenes `<form>`** — das Cicada-Theme umschließt `#pageContent` bereits mit `<form id="pageForm">`, und ein verschachteltes Formular hat schon einmal jede Aktion mit „CSRF-Versuch blockiert" beendet.

```html
<style>
/* Farben ausschliesslich aus dem Theme, mit Rueckfallwert - ein Teil der
   Bediener sitzt auf default oder ispc-clean, wo es die Variablen nicht
   gibt. --cic-warn ist bewusst nicht dabei: es ist fast identisch mit
   --cic-accent, und dann waere Zustand von Bedienbarkeit nicht zu
   unterscheiden. Fuer Warnungen steht --cic-warn-lift. */
#mw-status .mw-lede{font-size:21px;line-height:1.3;font-weight:600;color:var(--cic-text-loud,#fff)}
#mw-status .mw-sub{margin:6px 0 0;color:var(--cic-text-dim,#8b9298);font-size:13px}
#mw-status .mw-sites{display:flex;flex-direction:column;gap:9px;margin-top:16px}
#mw-status .mw-site{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:start;
  padding:13px 15px;border:1px solid var(--cic-line-soft,#3c3c3b);border-radius:3px;
  background:var(--cic-raised,#292929)}
#mw-status .mw-site.bad{border-left:3px solid var(--cic-bad,#d13f22)}
#mw-status .mw-site.warn{border-left:3px solid var(--cic-warn-lift,#ef8a2b)}
#mw-status .mw-site.busy{border-left:3px solid var(--cic-accent,#dd630d)}
#mw-status .mw-site h3{margin:0;font-size:15px;font-weight:600;display:flex;align-items:center;
  gap:8px;flex-wrap:wrap;color:var(--cic-text-loud,#fff)}
#mw-status .mw-site p{margin:5px 0 0;font-size:13.5px;max-width:62ch}
#mw-status .mw-chip{font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  padding:2px 7px;border-radius:3px}
#mw-status .mw-chip.bad{background:var(--cic-bad-deep,#b13116);color:#fff}
#mw-status .mw-chip.warn{background:var(--cic-warn-lift,#ef8a2b);color:var(--cic-on-accent,#1c1c1c)}
#mw-status .mw-chip.busy{background:var(--cic-sunken,#151515);color:var(--cic-accent-text,#ef7d21);
  border:1px solid var(--cic-accent-deep,#a84c0b)}
#mw-status .mw-acts{display:flex;flex-direction:column;gap:6px}
#mw-status .mw-track{height:6px;border-radius:3px;background:var(--cic-line-soft,#3c3c3b);
  overflow:hidden;margin-top:10px}
#mw-status .mw-fill{height:100%;background:var(--cic-accent,#dd630d);border-radius:3px;
  transition:width .5s linear;width:0}
#mw-status .mw-meta{display:flex;justify-content:space-between;gap:12px;margin-top:6px;
  font-size:12px;color:var(--cic-text-dim,#8b9298);font-variant-numeric:tabular-nums}
#mw-status .mw-quiet{margin-top:18px;padding:12px 15px;border:1px solid var(--cic-line-soft,#3c3c3b);
  border-radius:3px;color:var(--cic-text-dim,#8b9298);font-size:13px;background:var(--cic-head,#202020)}
@media (prefers-reduced-motion:reduce){#mw-status *{transition:none !important}}
</style>

<div id="mw-status">

  <tmpl_if name="attention_count" op="==" value="0">
    <h1 class="mw-lede">{tmpl_var name='all_clear_txt'}</h1>
  </tmpl_if>
  <tmpl_if name="attention_count" op="==" value="1">
    <h1 class="mw-lede">{tmpl_var name='attention_one_txt'}</h1>
  </tmpl_if>
  <tmpl_if name="attention_count" op=">" value="1">
    <h1 class="mw-lede">{tmpl_var name='attention_many_txt'}</h1>
  </tmpl_if>
  <p class="mw-sub">{tmpl_var name='as_of'}</p>

  <div class="mw-sites">
    <tmpl_loop name="sites">
      <article class="mw-site {tmpl_var name='state_class'}" data-domain="{tmpl_var name='domain_id'}">
        <div>
          <h3>
            {tmpl_var name='domain'}
            <tmpl_if name="is_running" op="==" value="y">
              <span class="mw-chip busy">{tmpl_var name='state_running_txt'}</span>
            <tmpl_else>
              <tmpl_if name="urgent" op=">" value="0">
                <span class="mw-chip bad">{tmpl_var name='state_infected_txt'}</span>
              <tmpl_else>
                <span class="mw-chip warn">{tmpl_var name='state_attention_txt'}</span>
              </tmpl_if>
            </tmpl_if>
          </h3>
          <p class="mw-line">{tmpl_var name='findings'} auffällige Dateien, davon {tmpl_var name='urgent'} dringend.</p>
          <tmpl_if name="is_running" op="==" value="y">
            <div class="mw-prog">
              <div class="mw-track"><div class="mw-fill"></div></div>
              <div class="mw-meta">
                <span class="mw-count">{tmpl_var name='waiting_txt'}</span>
                <span class="mw-pct"></span>
              </div>
            </div>
          </tmpl_if>
        </div>
        <div class="mw-acts">
          <a class="btn btn-default formbutton-default"
             href="javascript:ISPConfig.loadContent('security/malwatch_site_show.php?domain_id={tmpl_var name='domain_id'}');">{tmpl_var name='view_txt'}</a>
        </div>
      </article>
    </tmpl_loop>
  </div>

  <tmpl_if name="quiet_count" op=">" value="0">
    <div class="mw-quiet">{tmpl_var name='quiet_txt'}</div>
  </tmpl_if>

</div>

<script>
(function () {
	// Frueher lud diese Seite sich bei laufender Pruefung alle fuenf Sekunden
	// komplett neu. Der Abbruch hing an DOMNodeRemoved - einem Mutation Event,
	// das Chrome seit Version 127 abgeschaltet hat. Der Timer ueberlebte also
	// jede Navigation und zog den Bediener aus den Einstellungen und aus jedem
	// Fund zurueck in die Liste.
	//
	// Jetzt wird nichts mehr nachgeladen: ein JSON-Endpunkt liefert den Stand,
	// und nur die betroffenen Zellen werden umgeschrieben. Selbst ein
	// vergessener Timer koennte dann nur noch ins Leere schreiben.
	var root = document.getElementById('mw-status');
	if (!root) { return; }

	var running = root.querySelectorAll('.mw-site.busy');
	if (!running.length) { return; }

	var timer = null;
	function stop() { if (timer) { clearInterval(timer); timer = null; } }

	// MutationObserver statt DOMNodeRemoved: das Panel tauscht #pageContent
	// aus, statt die Seite neu zu laden.
	var host = document.getElementById('pageContent');
	if (host && window.MutationObserver) {
		new MutationObserver(function () {
			if (!document.contains(root)) { stop(); }
		}).observe(host, { childList: true, subtree: true });
	}

	function draw(box, d) {
		var fill = box.querySelector('.mw-fill');
		var count = box.querySelector('.mw-count');
		var pct = box.querySelector('.mw-pct');
		if (!fill) { return; }
		if (d.percent === null || typeof d.percent === 'undefined') {
			fill.style.width = '100%';
			fill.style.opacity = '.35';
			if (pct) { pct.textContent = ''; }
		} else {
			fill.style.width = d.percent + '%';
			fill.style.opacity = '1';
			if (pct) { pct.textContent = d.percent + ' %'; }
		}
		if (count && d.label) { count.textContent = d.label; }
	}

	function poll() {
		// Der zweite Schutz: auch wenn der Beobachter versagt, schreibt der
		// Takt nur noch, solange die Seite wirklich da ist.
		if (!document.contains(root)) { stop(); return; }

		var open = 0;
		running.forEach(function (box) {
			var id = box.getAttribute('data-domain');
			var xhr = new XMLHttpRequest();
			xhr.open('GET', 'security/malwatch_progress.php?domain_id=' + encodeURIComponent(id), true);
			xhr.onload = function () {
				if (!document.contains(root)) { stop(); return; }
				var d;
				try { d = JSON.parse(xhr.responseText); } catch (e) { return; }
				if (d.state === 'running' || d.state === 'pending') { open++; }
				draw(box, d);
			};
			xhr.send();
		});
		if (open === 0) {
			// Nichts laeuft mehr. Einmal die Seite holen, damit die Ergebnisse
			// erscheinen - und danach nie wieder von allein.
			stop();
			ISPConfig.loadContent('security/status.php');
		}
	}

	timer = setInterval(poll, 3000);
	poll();
})();
</script>
```

- [ ] **Schritt 7: Die alte Listenseite entfernen und file.list ergänzen**

```bash
git rm ispconfig/interface/malwatch_site_list.php ispconfig/interface/templates/malwatch_site_list.htm
```

In `ispconfig/install/file.list` die Zeile der alten Liste entfernen und ergänzen:

```
c:interface/status.php:interface/web/security/status.php
c:interface/templates/status.htm:interface/web/security/templates/status.htm
c:interface/lang/de_status.lng:interface/web/security/lib/lang/de_status.lng
c:interface/lang/en_status.lng:interface/web/security/lib/lang/en_status.lng
```

- [ ] **Schritt 8: Die Prüfungen laufen lassen**

```bash
sh ispconfig/tests/check_wiring.sh
php -l ispconfig/interface/status.php && php -l ispconfig/interface/lib/malwatch_lib.inc.php
```

Erwartet: `Wiring OK`, zweimal `No syntax errors detected`.

- [ ] **Schritt 9: Committen**

```bash
git add -A
git commit -m "feat: eine Statusseite, die eine Frage beantwortet

Nicht 61 Zeilen mit Spalten, sondern ein Satz - "Drei Websites brauchen
Ihre Aufmerksamkeit" - und darunter nur diese drei, die dringendste
oben. Die unauffaelligen sind eine ruhige Zeile und kein Standardinhalt.

Das Neuladen im Takt entfaellt ersatzlos. Der Abbruch hing an
DOMNodeRemoved, das Chrome seit Version 127 abgeschaltet hat; der Timer
ueberlebte also jede Navigation und zog den Bediener aus den
Einstellungen und aus jedem Fund zurueck in die Liste. Jetzt liefert ein
JSON-Endpunkt den Stand und nur die betroffenen Zellen werden
umgeschrieben - abgebrochen ueber einen MutationObserver und zusaetzlich
ueber document.contains, damit auch ein vergessener Timer nur noch ins
Leere schreiben kann.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Aufgabe 7: Am lebenden Objekt prüfen

**Dateien:** keine

**Schnittstellen:** verbraucht alles Vorherige

- [ ] **Schritt 1: Bauen und ausliefern**

```bash
GOOS=linux GOARCH=amd64 go build -o .testbin/mw ./cmd/malwatch
scp -q .testbin/mw ispconfig:/tmp/mw && ssh ispconfig 'chmod +x /tmp/mw && /tmp/mw version'
cd ispconfig && sh build_package.sh && cd ..
```

- [ ] **Schritt 2: Auf dem Server installieren**

```bash
scp -q ispconfig/malwatch.pkg ispconfig:/tmp/
ssh ispconfig 'cd /usr/local/ispconfig/extensions/malwatch && unzip -oq /tmp/malwatch.pkg && chown -R ispconfig:ispconfig . && php install/manual_install.php 2>&1 | tail -3 && sh tests/check_wiring.sh'
```

Erwartet: `Wiring OK`.

- [ ] **Schritt 3: Den Menüeintrag prüfen**

```bash
ssh ispconfig "mysql -N -B -e \"SELECT username, modules FROM dbispconfig.sys_user WHERE typ='admin'\""
```

Erwartet: `security` steht in der Liste des Administrators und bei niemandem sonst.

- [ ] **Schritt 4: Den Nenner prüfen**

Einen Scan über eine Website anstoßen, die schon einmal geprüft wurde, und das
Fortschrittsdokument ansehen:

```bash
ssh ispconfig 'cat /var/lib/malwatch/runs/job-*.progress | python3 -m json.tool | grep files_'
```

Erwartet: `files_total` ist größer als null.

- [ ] **Schritt 5: Das Zurückspringen prüfen**

Im Browser: einen Scan starten, auf **Einstellungen** wechseln und **zwei Minuten
dort bleiben**. Die Seite darf nicht wechseln. Danach zurück auf Status — der
Balken muss sich bewegt haben.

Das ist die eigentliche Abnahme dieser Stufe und lässt sich nicht automatisieren.

- [ ] **Schritt 6: Ausliefern**

Die Fähigkeit `release` benutzen: Version anheben, Changelog schreiben,
committen, taggen, ausliefern.

---

## Selbstdurchsicht

**Abdeckung gegenüber der Spec, Stufe 1:**

| Anforderung aus der Spec | Aufgabe |
|---|---|
| Modul `security`, `module.conf.php`, Reihenfolge 40 | 3 |
| Installer trägt in `sys_user.modules` ein, idempotent | 3 |
| Deinstaller entfernt den Eintrag | 3 |
| `malwatch.menu.php` und sein `file.list`-Eintrag entfallen | 3 |
| Seiten ziehen von `sites/` nach `security/` | 4 |
| Jede Seite prüft `is_admin()` | 4, 6 |
| Statusseite beantwortet eine Frage | 6 |
| Sortierung kritisch → laufend → hoch | 6 |
| Unauffällige als ruhige Zeile | 6 |
| Zahl in der Leiste = Websites, nicht Funde | 3 (Leiste), 6 (Seite) |
| Kein `loadContent` im Takt | 6 |
| `MutationObserver` statt `DOMNodeRemoved` | 6 |
| Takt 3 Sekunden, endet bei `done`/`failed` | 6 |
| `--expect` im Scanner | 1 |
| Runner liest `files_scanned` des letzten Laufs | 2 |
| Anzeige mit und ohne Nenner | 5, 6 |
| Deckelung bei 99 % | 5 |
| Farben aus dem Theme, `--cic-warn-lift` für Warnungen | 6 |
| Radius 3px | 6 |
| Wiring-Prüfungen | 2, 3, 4, 5, 6 |

**Nicht in dieser Stufe** und daher ohne Aufgabe: `Explain`/`Action`, `malwatch rules --json`, die Handlungsgruppen auf der Detailseite (Stufe 2); Quarantäne, `malwatch restore`, Zusammenstellungen, Automatik (Stufe 3). Der Punkt „Quarantäne" in der Seitenleiste entfällt deshalb in Stufe 1 ausdrücklich — siehe Anmerkung in Aufgabe 3, Schritt 3.

**Namensgleichheit geprüft:** `malwatch_status_rows($app)` und `malwatch_when($stamp)` werden in Aufgabe 6 Schritt 5 definiert und in Schritt 4 aufgerufen. Die Felder `percent`, `files_done`, `files_total`, `label` werden in Aufgabe 5 erzeugt und in Aufgabe 6 gelesen. `--expect` wird in Aufgabe 1 definiert und in Aufgabe 2 gesetzt. `state_class` liefert `bad`, `warn` oder `busy`, und genau diese drei Klassen kennt die Vorlage.
