# malwatch Teil 2 — Addon: Fortschritt, Wiederherstellen, Löschen

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Die Oberfläche kann eine Wiederherstellung anstoßen und ihr dabei zusehen, einzelne Funde löschen, und der Knopf „Freigeben" sagt endlich, was er tut.

**Architecture:** Alles Dateischreiben bleibt im Go-Binary, das Addon steuert und zeigt an. Ein neuer Befehl `malwatch quarantine` erbt die Pfadgrenze und die Sicherung aus Teil 1; das Addon prüft zusätzlich gegen die Datenbank, sodass zwei unabhängige Prüfungen zwischen einem Formularfeld und einem `unlink` stehen.

**Tech Stack:** Go 1.24 für den neuen Befehl, PHP 8.3 für das Addon (ISPConfig 3.3, tform/listform, `sys_datalog`, Cron-Klasse), Bootstrap 3 im Cicada-Theme.

**Spec:** [docs/superpowers/specs/2026-09-05-malwatch-repair-design.md](../specs/2026-09-05-malwatch-repair-design.md)

## Global Constraints

- **Kein Eingriff in Kerndateien** von ISPConfig. Alles über die Extension-Struktur.
- Keine Vorlage öffnet ein eigenes `<form>` — das Panel hat `pageForm` bereits (Prüfung 10 in `check_wiring.sh`).
- Wer `csrf_token_check` aufruft, setzt `_csrf_id` und `_csrf_key` (Prüfung 11).
- Das Schema heißt `schema.sql`, nie `install.sql` (Prüfungen 12 und 13).
- Nur `LOGLEVEL_DEBUG`, `LOGLEVEL_WARN`, `LOGLEVEL_ERROR` — andere Konstanten gibt es in ISPConfig nicht.
- Die Panel-PHP darf keine Kundendatei anfassen: sie läuft als `ispconfig`, die Dateien gehören dem Web-Benutzer. Jede Dateiänderung geht über die Warteschlange.
- Kommentare englisch, jede Ausgabe an den Menschen deutsch.
- **Verifikation:** Es gibt kein PHP-Testgerüst. Geprüft wird mit `php -l`, `ispconfig/tests/check_wiring.sh`, `check_constants.sh` und `tests/render_pages.php` gegen die echte Installation. Wo das nicht reicht, steht im Task ein Befehl für die Prüfung von Hand auf dem Server.

## File Structure

| Datei | Verantwortung |
|---|---|
| `cmd/malwatch/quarantine.go` | neuer Befehl: eine Datei sichern und entfernen, innerhalb der Grenze |
| `ispconfig/install/schema.sql` | neue Tabellen, plus selbstprüfende Änderungen an bestehenden |
| `ispconfig/server/lib/classes/malwatch_runner.inc.php` | Argumente je Auftragsart, `--progress` |
| `ispconfig/server/lib/classes/malwatch_ingest.inc.php` | Ergebnis einer Wiederherstellung einlesen |
| `ispconfig/interface/lib/malwatch_lib.inc.php` | Aufträge einreihen, Pfade gegen die Datenbank prüfen |
| `ispconfig/interface/malwatch_progress.php` | Fortschrittsdatei als JSON, ohne Vorlagenmaschinerie |
| `ispconfig/interface/malwatch_site_show.php` | Knöpfe und Aktionen |
| `ispconfig/interface/templates/malwatch_site_show.htm` | Fortschrittsansicht, Rückfragen |

---

### Task 1: `malwatch quarantine`

**Files:**
- Create: `cmd/malwatch/quarantine.go`
- Modify: `cmd/malwatch/main.go` (neuer `case`), `cmd/malwatch/usage.go`
- Test: `cmd/malwatch/quarantine_test.go`

**Interfaces:**
- Consumes: `repair.InsideRoot`, `repair.Backup` aus Teil 1.
- Produces: `func cmdQuarantine(args []string) int` — Schalter `--path` (Webstamm), `--file` (mehrfach, relativ zum Webstamm), `--backup-dir`, `--json`, `--out`.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineRemovesTheFileAndKeepsACopy(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "wp-content", "uploads", "shell.php")
	if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("<?php @eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}
	backups := t.TempDir()

	if code := cmdQuarantine([]string{
		"--path=" + root, "--file=wp-content/uploads/shell.php", "--backup-dir=" + backups,
	}); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}
	found := false
	_ = filepath.Walk(backups, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("nothing was kept - a false alarm would be unrecoverable")
	}
}

func TestQuarantineRefusesAPathOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(outside, []byte("root:x:0:0"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The path arrives from a form field by way of the queue. The database
	// check in the panel is one guard; this is the second, independent one.
	if code := cmdQuarantine([]string{
		"--path=" + root, "--file=../../" + filepath.Base(outside), "--backup-dir=" + t.TempDir(),
	}); code == 0 {
		t.Fatal("a path leaving the root was accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("a file outside the root was removed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/malwatch/ -run TestQuarantine -v`
Expected: FAIL — `undefined: cmdQuarantine`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brightcolor/malwatch/internal/repair"
	"github.com/brightcolor/malwatch/internal/report"
)

// cmdQuarantine removes single files, for the findings a repair leaves behind:
// a shell in uploads, one in the web root. Swapping a whole directory is the
// wrong tool for those, and they are exactly what a scan reports afterwards.
func cmdQuarantine(args []string) int {
	fs := flag.NewFlagSet("quarantine", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(os.Stderr) }

	var files stringList
	fs.Var(&files, "file", "")
	path := fs.String("path", "", "")
	backupDir := fs.String("backup-dir", "", "")

	if err := fs.Parse(args); err != nil {
		return report.ExitError
	}
	if *path == "" || len(files) == 0 || *backupDir == "" {
		fmt.Fprintln(os.Stderr, "quarantine braucht --path, --backup-dir und mindestens ein --file.")
		return report.ExitError
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(*backupDir, stamp)
	failed := 0

	for _, rel := range files {
		full := filepath.Join(*path, filepath.FromSlash(rel))
		if err := repair.InsideRoot(*path, full); err != nil {
			fmt.Fprintf(os.Stderr, "abgelehnt: %v\n", err)
			failed++
			continue
		}
		info, err := os.Stat(full)
		if err != nil || !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "übersprungen: %s ist keine gewöhnliche Datei\n", rel)
			failed++
			continue
		}
		// Kept before removed: a finding can be a false alarm, and an
		// unrecoverable deletion would make that mistake permanent.
		name := strings.ReplaceAll(strings.Trim(filepath.ToSlash(rel), "/"), "/", "_")
		if _, err := repair.BackupFile(full, dest, name); err != nil {
			fmt.Fprintf(os.Stderr, "Sicherung von %s fehlgeschlagen: %v\n", rel, err)
			failed++
			continue
		}
		if err := os.Remove(full); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", rel, err)
			failed++
			continue
		}
		fmt.Printf("entfernt %s\n", rel)
	}

	if failed > 0 {
		return report.ExitError
	}
	return 0
}
```

Dazu in `internal/repair/backup.go` eine Schwester zu `Backup`, die eine einzelne
Datei kopiert statt einen Ordner zu packen — ein `tar.gz` um eine Datei wäre
umständlicher zurückzuholen als eine Kopie:

```go
// BackupFile copies one file below destDir and returns its path.
func BackupFile(file, destDir, name string) (string, error) {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	target := filepath.Join(destDir, name)
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		return "", err
	}
	return target, nil
}
```

Und in `main.go`:

```go
	case "quarantine":
		return cmdQuarantine(args[1:])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... && test -z "$(gofmt -l .)" && go vet ./...`
Expected: PASS, keine Ausgabe

- [ ] **Step 5: Commit**

```bash
git add cmd/malwatch/quarantine.go cmd/malwatch/quarantine_test.go cmd/malwatch/main.go cmd/malwatch/usage.go internal/repair/backup.go
git commit -m "feat: quarantine removes single files, inside the same boundary"
```

---

### Task 2: Das Schema erweitern, ohne bestehende Installationen zu vergessen

**Files:**
- Modify: `ispconfig/install/schema.sql`
- Modify: `ispconfig/tests/check_wiring.sh` (Prüfung 14)

**Interfaces:**
- Produces: `malwatch_job.job_kind enum('scan','repair','quarantine')`, Tabellen `malwatch_repair` und `malwatch_repair_element`.

- [ ] **Step 1: Write the failing test**

Prüfung 14 in `check_wiring.sh`, vor dem Statusblock:

```sh
# 14. Eine neue Spalte in einer bestehenden Tabelle erreicht niemanden.
#     CREATE TABLE IF NOT EXISTS ändert an einer vorhandenen Tabelle nichts,
#     also braucht jede Erweiterung einen selbstprüfenden Zusatz.
if grep -q 'job_kind' "$root/install/schema.sql"; then
	grep -q 'information_schema' "$root/install/schema.sql" \
		|| fail "schema.sql fügt Spalten hinzu, ohne sie über information_schema zu prüfen"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: zunächst OK (es gibt noch kein `job_kind`); nach dem Einfügen der Spalte ohne Zusatz FAIL

- [ ] **Step 3: Write minimal implementation**

Ans Ende von `schema.sql`:

```sql
-- --------------------------------------------------------
-- Änderungen an bestehenden Tabellen.
--
-- CREATE TABLE IF NOT EXISTS oben lässt eine vorhandene Tabelle unberührt, also
-- erreicht eine neue Spalte damit keine Installation, die es schon gibt. Die
-- folgenden Anweisungen prüfen sich selbst und laufen bei jeder Installation
-- und jedem Update mit; eine Versionszählung braucht es dafür nicht.
-- --------------------------------------------------------

SET @add := (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE `malwatch_job` ADD COLUMN `job_kind` enum(''scan'',''repair'',''quarantine'') NOT NULL DEFAULT ''scan'' AFTER `job_source`',
  'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'malwatch_job' AND COLUMN_NAME = 'job_kind');
PREPARE stmt FROM @add; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS `malwatch_repair` (
  `repair_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `job_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `domain` varchar(255) NOT NULL DEFAULT '',
  `started_at` datetime DEFAULT NULL,
  `finished_at` datetime DEFAULT NULL,
  `dry_run` enum('n','y') NOT NULL DEFAULT 'n',
  `backup_dir` varchar(255) NOT NULL DEFAULT '',
  `count_replaced` int(11) unsigned NOT NULL DEFAULT '0',
  `count_deleted` int(11) unsigned NOT NULL DEFAULT '0',
  `count_failed` int(11) unsigned NOT NULL DEFAULT '0',
  `exit_code` int(11) NOT NULL DEFAULT '0',
  `raw_report` mediumtext,
  PRIMARY KEY (`repair_id`),
  KEY `parent_domain_id` (`parent_domain_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `malwatch_repair_element` (
  `element_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `sys_userid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_groupid` int(11) unsigned NOT NULL DEFAULT '0',
  `sys_perm_user` varchar(5) DEFAULT NULL,
  `sys_perm_group` varchar(5) DEFAULT NULL,
  `sys_perm_other` varchar(5) DEFAULT NULL,
  `server_id` int(11) unsigned NOT NULL DEFAULT '0',
  `repair_id` int(11) unsigned NOT NULL DEFAULT '0',
  `parent_domain_id` int(11) unsigned NOT NULL DEFAULT '0',
  `element_kind` varchar(16) NOT NULL DEFAULT '',
  `slug` varchar(190) NOT NULL DEFAULT '',
  `element_version` varchar(64) NOT NULL DEFAULT '',
  `outcome` varchar(32) NOT NULL DEFAULT '',
  `files` int(11) unsigned NOT NULL DEFAULT '0',
  `backup` varchar(255) NOT NULL DEFAULT '',
  `message` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`element_id`),
  KEY `repair_id` (`repair_id`)
) DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1 ;
```

- [ ] **Step 4: Run test to verify it passes**

Run auf dem Server, weil nur dort eine Datenbank steht:
```bash
php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php
mysql -e "SHOW COLUMNS FROM dbispconfig.malwatch_job LIKE 'job_kind'"
```
Expected: `Database schema loaded.`, kein Fehler, und die Spalte existiert. Ein
zweiter Lauf desselben Befehls muss ebenso durchlaufen — das ist die
Idempotenz, auf die alles baut.

- [ ] **Step 5: Commit**

```bash
git add ispconfig/install/schema.sql ispconfig/tests/check_wiring.sh
git commit -m "feat: schema changes that reach installations that already exist"
```

---

### Task 3: Der Runner kennt Auftragsarten und schreibt Fortschritt

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_runner.inc.php`

**Interfaces:**
- Consumes: `job_kind` aus Task 2, `malwatch quarantine` aus Task 1.
- Produces: `build_arguments()` liefert je nach `job_kind` die Argumente für `scan`, `repair` oder `quarantine`; jeder Lauf bekommt `--progress=<state_dir>/runs/job-<id>.progress`.

- [ ] **Step 1: Write the failing test**

Prüfung 15 in `check_wiring.sh`:

```sh
# 15. Ohne --progress schreibt kein Lauf aus dem Panel eine Fortschrittsdatei,
#     und die Ansicht bleibt für immer leer.
grep -q -- '--progress=' "$root/server/lib/classes/malwatch_runner.inc.php" \
	|| fail "der Runner übergibt --progress nicht; die Fortschrittsansicht bekäme nie Daten"
for kind in repair quarantine; do
	grep -q "'$kind'" "$root/server/lib/classes/malwatch_runner.inc.php" \
		|| fail "der Runner kennt die Auftragsart $kind nicht"
done
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: FAIL — „der Runner übergibt --progress nicht"

- [ ] **Step 3: Write minimal implementation**

`build_arguments()` verzweigt über `$job['job_kind']`. Gemeinsam bleibt der
Fortschritt:

```php
		$progress_file = $state_dir . '/runs/job-' . intval($job['job_id']) . '.progress';
		$kind = isset($job['job_kind']) ? (string) $job['job_kind'] : 'scan';

		if ($kind === 'repair') {
			$args = array(
				'repair',
				'--path=' . $path,
				'--backup-dir=' . $state_dir . '/backups/' . $job['domain'],
				'--progress=' . $progress_file,
				'--json',
				'--out=' . $result_file,
			);
			if (!empty($options['dry_run'])) {
				$args[] = '--dry-run';
			}
			return $args;
		}

		if ($kind === 'quarantine') {
			$args = array(
				'quarantine',
				'--path=' . $path,
				'--backup-dir=' . $state_dir . '/backups/' . $job['domain'] . '/einzeln',
				'--progress=' . $progress_file,
			);
			// The paths were checked against malwatch_finding before the job
			// was queued; the binary checks the boundary again.
			foreach ((array) ($options['files'] ?? array()) as $rel) {
				$args[] = '--file=' . $rel;
			}
			return $args;
		}
```

Der bestehende `scan`-Zweig bekommt zusätzlich `'--progress=' . $progress_file`.

- [ ] **Step 4: Run test to verify it passes**

Run: `sh ispconfig/tests/check_wiring.sh && php -l ispconfig/server/lib/classes/malwatch_runner.inc.php`
Expected: `Wiring OK`, keine Syntaxfehler

- [ ] **Step 5: Commit**

```bash
git add ispconfig/server/lib/classes/malwatch_runner.inc.php ispconfig/tests/check_wiring.sh
git commit -m "feat: the runner knows job kinds and writes progress"
```

---

### Task 4: Aufträge einreihen, Pfade gegen die Datenbank prüfen

**Files:**
- Modify: `ispconfig/interface/lib/malwatch_lib.inc.php`

**Interfaces:**
- Produces:
  - `function malwatch_queue_repair($app, $domain_id, $dry_run = false)`
  - `function malwatch_queue_quarantine($app, $domain_id, array $paths)` — nimmt nur Pfade an, die als Fund dieser Website in `malwatch_finding` stehen; gibt die Zahl der eingereihten Pfade zurück oder eine Fehlermeldung als String.

- [ ] **Step 1: Write the failing test**

Prüfung 16 in `check_wiring.sh`:

```sh
# 16. Ein Pfad aus einem Formularfeld darf nie ungeprüft in einen Auftrag
#     wandern. Die Prüfung gegen malwatch_finding ist die erste von zwei.
if grep -q 'malwatch_queue_quarantine' "$root/interface/lib/malwatch_lib.inc.php"; then
	sed -n '/function malwatch_queue_quarantine/,/^}/p' "$root/interface/lib/malwatch_lib.inc.php" \
		| grep -q 'malwatch_finding' \
		|| fail "malwatch_queue_quarantine prüft die Pfade nicht gegen malwatch_finding"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: OK, solange die Funktion fehlt; FAIL, sobald sie ohne die Prüfung existiert

- [ ] **Step 3: Write minimal implementation**

```php
/**
 * Queues the removal of single files.
 *
 * Only paths that stand as a finding of this very site are accepted. The value
 * arrives from a form field, and a path is one unlink away from being anything
 * on the disk; the binary checks the boundary a second time.
 */
function malwatch_queue_quarantine($app, $domain_id, array $paths)
{
	$domain_id = $app->functions->intval($domain_id);
	$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);
	if (!is_array($web)) {
		return 'Die Website wurde nicht gefunden.';
	}
	$base = malwatch_scan_path($web);

	$accepted = array();
	foreach ($paths as $path) {
		$path = (string) $path;
		$row = $app->db->queryOneRecord(
			'SELECT file_path FROM malwatch_finding WHERE parent_domain_id = ? AND file_path = ? '
			. "AND finding_state IN ('open','ignored') LIMIT 1",
			$domain_id, $path);
		if (!is_array($row)) {
			continue;
		}
		if (strpos($path, $base . '/') !== 0) {
			continue;
		}
		$accepted[] = substr($path, strlen($base) + 1);
	}
	if (count($accepted) === 0) {
		return 'Keiner der Pfade steht als Fund dieser Website.';
	}

	$app->db->datalogInsert('malwatch_job', array(
		'sys_userid' => 1, 'sys_groupid' => 1,
		'sys_perm_user' => 'riud', 'sys_perm_group' => 'riud', 'sys_perm_other' => '',
		'server_id' => $app->functions->intval($web['server_id']),
		'parent_domain_id' => $domain_id,
		'domain' => $web['domain'],
		'scan_path' => $base,
		'job_source' => 'manual',
		'job_kind' => 'quarantine',
		'job_status' => 'pending',
		'options' => json_encode(array('files' => $accepted)),
		'created_at' => date('Y-m-d H:i:s'),
	), 'job_id');

	return count($accepted);
}
```

`malwatch_queue_repair` folgt derselben Form mit `job_kind = 'repair'` und
`options = {"dry_run": …}`.

- [ ] **Step 4: Run test to verify it passes**

Run: `sh ispconfig/tests/check_wiring.sh && php -l ispconfig/interface/lib/malwatch_lib.inc.php`
Expected: `Wiring OK`, keine Syntaxfehler

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/lib/malwatch_lib.inc.php ispconfig/tests/check_wiring.sh
git commit -m "feat: queue repairs and removals, with the paths checked first"
```

---

### Task 5: Die Fortschrittsdatei ausliefern

**Files:**
- Create: `ispconfig/interface/malwatch_progress.php`
- Modify: `ispconfig/install/file.list`

**Interfaces:**
- Produces: `GET sites/malwatch_progress.php?job_id=N` → das JSON der Fortschrittsdatei, oder `{"state":"none"}`, wenn es sie nicht gibt.

- [ ] **Step 1: Write the failing test**

Prüfung 17 in `check_wiring.sh`:

```sh
# 17. Eine Seite, die JSON liefert, darf keine Vorlage laden - sonst kommt
#     HTML mit und der Aufrufer bekommt kein gültiges JSON.
if [ -f "$root/interface/malwatch_progress.php" ]; then
	grep -q 'newTemplate\|tpl_defaults' "$root/interface/malwatch_progress.php" \
		&& fail "malwatch_progress.php lädt eine Vorlage, liefert also kein reines JSON"
	grep -q 'is_admin' "$root/interface/malwatch_progress.php" \
		|| fail "malwatch_progress.php prüft die Administratorrechte nicht"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: OK ohne die Datei; FAIL, sobald sie ohne Rechteprüfung existiert

- [ ] **Step 3: Write minimal implementation**

```php
<?php

/**
 * Serves the progress file of one job as JSON.
 *
 * No template: the panel's form.tpl.htm would append its own markup and the
 * caller would not get valid JSON back.
 */

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('sites');
if (!$app->auth->is_admin()) {
	header('Content-Type: application/json');
	echo json_encode(array('state' => 'denied'));
	exit;
}

require_once 'lib/malwatch_lib.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$job_id = $app->functions->intval($_GET['job_id']);
$job = $app->db->queryOneRecord(
	'SELECT job_id, job_kind, job_status, parent_domain_id FROM malwatch_job WHERE job_id = ?', $job_id);
if (!is_array($job)) {
	echo json_encode(array('state' => 'none'));
	exit;
}

$config = malwatch_get_config($app);
$file = rtrim((string) $config['state_dir'], '/') . '/runs/job-' . $job_id . '.progress';

$out = array('state' => $job['job_status'], 'kind' => $job['job_kind']);
$raw = @file_get_contents($file);
if ($raw !== false) {
	$doc = json_decode($raw, true);
	if (is_array($doc)) {
		$out['progress'] = $doc;
	}
}
echo json_encode($out);
```

Dazu die Zeile in `install/file.list`, in der Form der übrigen
Interface-Dateien.

- [ ] **Step 4: Run test to verify it passes**

Run: `sh ispconfig/tests/check_wiring.sh && php -l ispconfig/interface/malwatch_progress.php`
Auf dem Server nach der Installation:
```bash
curl -s -o /dev/null -w '%{http_code}\n' 'https://<panel>/sites/malwatch_progress.php?job_id=1'
```
Expected: `Wiring OK`; die Seite antwortet (302 ohne Anmeldung ist richtig)

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/malwatch_progress.php ispconfig/install/file.list ispconfig/tests/check_wiring.sh
git commit -m "feat: serve the progress file to the panel"
```

---

### Task 6: Die Ansicht — Phasenkopf und Elementliste

**Files:**
- Modify: `ispconfig/interface/templates/malwatch_site_show.htm`
- Modify: `ispconfig/interface/malwatch_site_show.php`
- Modify: `ispconfig/interface/lang/de_malwatch.lng`, `en_malwatch.lng`

**Interfaces:**
- Consumes: `sites/malwatch_progress.php` aus Task 5.
- Produces: ein Block, der sichtbar wird, solange ein Auftrag dieser Website `pending` oder `running` ist, und alle zwei Sekunden nachfragt.

- [ ] **Step 1: Write the failing test**

Prüfung 18 in `check_wiring.sh`:

```sh
# 18. Ein Zeitgeber, der den Seitenwechsel überlebt, fragt für immer weiter.
#     Das Panel tauscht #pageContent aus, ohne die Seite neu zu laden.
if grep -q 'setInterval' "$root/interface/templates/malwatch_site_show.htm"; then
	grep -q 'clearInterval' "$root/interface/templates/malwatch_site_show.htm" \
		|| fail "malwatch_site_show.htm startet einen Zeitgeber, ohne ihn je zu stoppen"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: FAIL, sobald ein `setInterval` ohne `clearInterval` in der Vorlage steht

- [ ] **Step 3: Write minimal implementation**

In die Vorlage, nur wenn `running_job_id` gesetzt ist:

```html
<tmpl_if name="running_job_id">
<div class="marginTop15 marginBottom15" id="malwatch-progress">
	<p class="fieldset-legend">{tmpl_var name='progress_head_txt'}</p>
	<div id="mw-phases" class="marginBottom15"></div>
	<div class="progress"><div id="mw-bar" class="progress-bar" style="width:0%"></div></div>
	<p id="mw-line"><small>{tmpl_var name='progress_waiting_txt'}</small></p>
	<div class="table-wrapper"><table class="table"><tbody id="mw-elements"></tbody></table></div>
</div>
<script>
(function () {
	var jobId = {tmpl_var name='running_job_id'};
	var phases = ['Erkennen', 'Holen', 'Prüfen', 'Sichern', 'Tauschen'];
	var timer = null;

	function stop() { if (timer) { clearInterval(timer); timer = null; } }

	function draw(d) {
		var p = d.progress || {};
		var done = p.elements_done || 0, total = p.elements_total || 0;
		var pct = total ? Math.round(done * 100 / total) : 0;
		document.getElementById('mw-bar').style.width = pct + '%';
		document.getElementById('mw-phases').innerHTML = phases.map(function (name, i) {
			var cls = (i + 1) < (p.phase_index || 0) ? 'label-success'
				: (i + 1) === (p.phase_index || 0) ? 'label-primary' : 'label-default';
			return '<span class="label ' + cls + '">' + name + '</span> ';
		}).join('');
		var el = p.element || {};
		document.getElementById('mw-line').innerHTML = '<small>' +
			(el.slug ? el.kind + ' ' + el.slug + ' ' + el.version : (el.kind || '')) +
			(p.files_total ? ' · ' + p.files_done + ' / ' + p.files_total : '') +
			' · ' + done + ' / ' + total + '</small>';
		document.getElementById('mw-elements').innerHTML = (p.log || []).slice(-12).map(function (l) {
			var cls = l.level === 'error' ? 'text-danger' : l.level === 'warn' ? 'text-warning' : '';
			return '<tr><td class="' + cls + '"><small>' + l.text + '</small></td></tr>';
		}).join('');
	}

	function poll() {
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'sites/malwatch_progress.php?job_id=' + jobId, true);
		xhr.onload = function () {
			var d;
			try { d = JSON.parse(xhr.responseText); } catch (e) { stop(); return; }
			draw(d);
			// Once the job is over, the page has to be fetched again anyway:
			// the findings and the report only exist after the cron read them.
			if (d.state === 'done' || d.state === 'error') {
				stop();
				ISPConfig.loadContent('sites/malwatch_site_show.php?id={tmpl_var name="domain_id"}');
			}
		};
		xhr.onerror = stop;
		xhr.send();
	}

	// The panel replaces #pageContent without reloading the page, so a timer
	// left running would poll forever behind whatever the user opens next.
	document.addEventListener('DOMNodeRemoved', function (e) {
		if (e.target && e.target.id === 'malwatch-progress') { stop(); }
	});

	poll();
	timer = setInterval(poll, 2000);
})();
</script>
</tmpl_if>
```

In `malwatch_site_show.php` dazu:

```php
$running = $app->db->queryOneRecord(
	"SELECT job_id FROM malwatch_job WHERE parent_domain_id = ? AND job_status IN ('pending','running') "
	. 'ORDER BY job_id DESC LIMIT 1', $domain_id);
$app->tpl->setVar('running_job_id', is_array($running) ? $app->functions->intval($running['job_id']) : '');
```

- [ ] **Step 4: Run test to verify it passes**

Run: `sh ispconfig/tests/check_wiring.sh`, dann auf dem Server
`php /usr/local/ispconfig/extensions/malwatch/tests/render_pages.php`
Expected: `Wiring OK`, `All pages render.`

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/templates/malwatch_site_show.htm ispconfig/interface/malwatch_site_show.php ispconfig/interface/lang/ ispconfig/tests/check_wiring.sh
git commit -m "feat: watch a run while it happens"
```

---

### Task 7: Die Knöpfe — Wiederherstellen, Löschen, und ein ehrliches Etikett

**Files:**
- Modify: `ispconfig/interface/templates/malwatch_site_show.htm`
- Modify: `ispconfig/interface/malwatch_site_show.php`
- Modify: `ispconfig/interface/lang/de_malwatch.lng`, `en_malwatch.lng`

**Interfaces:**
- Consumes: `malwatch_queue_repair`, `malwatch_queue_quarantine` aus Task 4.
- Produces: die Aktionen `repair`, `repair_dry`, `delete_one`, `delete_all`; `ignore_txt` heißt „Kein Befund".

- [ ] **Step 1: Write the failing test**

Prüfung 19 in `check_wiring.sh`:

```sh
# 19. Jede Aktion, die etwas löscht oder ersetzt, braucht eine Rückfrage.
#     Ein Fehlklick auf "Alle Funde löschen" ist sonst endgültig.
for action in delete_one delete_all repair; do
	if grep -q "'$action'" "$root/interface/malwatch_site_show.php"; then
		grep -q "confirm_${action}_txt" "$root/interface/templates/malwatch_site_show.htm" \
			|| fail "die Aktion $action hat keine Rückfrage in der Vorlage"
	fi
done

# 20. "Freigeben" liest sich neben einem Schadcode-Fund wie Durchwinken.
grep -q "ignore_txt'\] = 'Freigeben'" "$root/interface/lang/de_malwatch.lng" \
	&& fail "der Knopf heißt noch 'Freigeben'; er ändert nur den Zustand, er gibt nichts frei"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: FAIL — „der Knopf heißt noch 'Freigeben'"

- [ ] **Step 3: Write minimal implementation**

Sprachdateien:

```php
$wb['ignore_txt'] = 'Kein Befund';
$wb['delete_one_txt'] = 'Löschen';
$wb['delete_all_txt'] = 'Alle Funde löschen';
$wb['repair_txt'] = 'Wiederherstellen';
$wb['repair_dry_txt'] = 'Probelauf';
$wb['confirm_delete_one_txt'] = 'Diese Datei wirklich löschen? Eine Kopie bleibt unter /var/lib/malwatch/backups.';
$wb['confirm_delete_all_txt'] = 'Alle gemeldeten Dateien dieser Website löschen? Kopien bleiben unter /var/lib/malwatch/backups.';
$wb['confirm_repair_txt'] = 'Kern, Plugins und Themes durch die Originale ersetzen? Die Website wird dafür kurz abgeschaltet, alles Ersetzte wird vorher gesichert, und Elemente ohne Original werden gelöscht.';
```

Die Knöpfe in der Vorlage, in der Form der vorhandenen — `type="button"`,
`data-submit-form="pageForm"`, `data-form-action`, die Rückfrage im `onclick`
vor dem Setzen der Aktion, wie es „Alle prüfen" schon macht. Der Löschknopf je
Fundzeile setzt zusätzlich `malwatch_finding_id` auf den Pfad der Zeile.

In `malwatch_site_show.php` die vier neuen Zweige, jeweils mit dem Ergebnis der
Einreihung als Meldung.

- [ ] **Step 4: Run test to verify it passes**

Run: `sh ispconfig/tests/check_wiring.sh && sh ispconfig/tests/check_constants.sh`,
dann auf dem Server `php …/tests/render_pages.php`
Expected: `Wiring OK`, `All pages render.`

- [ ] **Step 5: Commit**

```bash
git add ispconfig/interface/ ispconfig/tests/check_wiring.sh
git commit -m "feat: restore, delete, and a button that says what it does"
```

---

### Task 8: Das Ergebnis einlesen und die Website zurückschalten

**Files:**
- Modify: `ispconfig/server/lib/classes/malwatch_ingest.inc.php`
- Modify: `ispconfig/server/lib/classes/cron.d/560-malwatch.inc.php`

**Interfaces:**
- Consumes: die Tabellen aus Task 2, den Bericht des Binaries aus Teil 1.
- Produces: ein fertiger `repair`-Auftrag landet in `malwatch_repair` und `malwatch_repair_element`; danach wird ein Scan angehängt und die Website zurückgeschaltet — außer der Tausch ist gescheitert.

- [ ] **Step 1: Write the failing test**

Prüfung 21 in `check_wiring.sh`:

```sh
# 21. Eine halb getauschte Installation darf nicht zurück ans Netz. Der
#     Rückweg hängt am Rückgabecode, nicht am Ende des Laufs.
if grep -q 'malwatch_repair' "$root/server/lib/classes/malwatch_ingest.inc.php"; then
	sed -n '/function ingest_repair/,/^\t}/p' "$root/server/lib/classes/malwatch_ingest.inc.php" \
		| grep -q 'exit_code' \
		|| fail "das Zurückschalten sieht den Rückgabecode nicht an"
fi
```

- [ ] **Step 2: Run test to verify it fails**

Run: `sh ispconfig/tests/check_wiring.sh`
Expected: OK ohne die Funktion; FAIL, sobald sie ohne die Prüfung existiert

- [ ] **Step 3: Write minimal implementation**

`ingest_repair()` liest den Bericht, schreibt die beiden Tabellen und
entscheidet dann:

```php
		// A half swapped installation must not go back online. Only a clean
		// exit code brings the site back; anything else leaves it off and says
		// so in the action log, because the operator has to look first.
		if (intval($report['exit_code'] ?? 0) === 0 || intval($job['exit_code']) === 2) {
			$this->restore_site_state($job, $previous_state);
			$this->queue_followup_scan($job);
		} else {
			$app->log('malwatch: ' . $job['domain'] . ' bleibt abgeschaltet, der Tausch ist gescheitert.', LOGLEVEL_WARN);
		}
```

Der vorherige Zustand der Website wird beim Einreihen des Auftrags in
`options.previous_active` festgehalten, damit das Zurückschalten ihn nicht
raten muss.

- [ ] **Step 4: Run test to verify it passes**

Run: `sh ispconfig/tests/check_wiring.sh && php -l ispconfig/server/lib/classes/malwatch_ingest.inc.php`
Auf dem Server, mit einem echten Probelauf über die Oberfläche:
```bash
mysql -e "SELECT repair_id, count_replaced, count_deleted, exit_code FROM dbispconfig.malwatch_repair ORDER BY repair_id DESC LIMIT 1"
```
Expected: eine Zeile mit den Zahlen aus dem Bericht

- [ ] **Step 5: Commit**

```bash
git add ispconfig/server/lib/classes/ ispconfig/tests/check_wiring.sh
git commit -m "feat: read a repair into the tables, and only then bring the site back"
```

---

## Selbstprüfung dieses Plans

**Abdeckung der Spec (Teil 2):**

| Anforderung | Task |
|---|---|
| `job_kind`, Tabellen `malwatch_repair`, `malwatch_repair_element` | 2 |
| Selbstprüfende Schemaänderung über `information_schema` | 2 |
| Runner übergibt `--progress`, kennt die Auftragsarten | 3 |
| Website abschalten, Auftrag, Scan anhängen, zurückschalten | 4, 8 |
| Bei gescheitertem Tausch abgeschaltet lassen | 8 |
| Fortschrittsansicht: Phasenkopf, Elementliste, Protokoll | 6 |
| Endpunkt, der die Datei ausliefert | 5 |
| Knopf „Wiederherstellen" mit Rückfrage | 7 |
| Einzelne Funde löschen, mit Rückfrage und Sicherung | 1, 4, 7 |
| Nur Pfade, die als Fund dieser Website stehen | 4 (Datenbank) und 1 (Pfadgrenze) |
| „Freigeben" heißt „Kein Befund" | 7 |

**Was dieser Plan bewusst offen lässt:**

- Das Zurückspielen einer Sicherung über die Oberfläche. Der Bericht nennt
  Archiv und Befehl; das Zurückspielen bleibt Handarbeit.
- Ein Fortschrittsbalken für die Phase „Holen" in Bytes. Die Elementzahl reicht,
  und Bytes kämen aus einer Quelle, die keine Länge mitschickt.
- Die Verifikation der entpackten Archive gegen die Prüfsummen — das ist Task 12
  aus Teil 1 und gehört dorthin, nicht hierher.

**Typprüfung:** `job_kind` wird in Task 2 angelegt und in 3, 4 verwendet;
`malwatch_queue_quarantine` in Task 4 definiert und in 7 aufgerufen;
`sites/malwatch_progress.php` in Task 5 angelegt und in 6 abgefragt;
`malwatch quarantine` in Task 1 gebaut und in Task 3 aufgerufen. Die Namen
stimmen überein.
