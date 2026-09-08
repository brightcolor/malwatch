<?php

/**
 * Installer hooks for the malwatch extension.
 *
 * The class name must be "<extension>_installer"; the framework instantiates
 * it by that name and calls install(), update(), enable(), disable() and
 * uninstall(). The base class it extends is loaded by the framework.
 */
class malwatch_installer extends extension_installer_base
{
	/** Where the scanner binary is installed to. */
	const BINARY_PATH = '/usr/local/bin/malwatch';

	/** Where signatures, run results and caches live. */
	const STATE_DIR = '/var/lib/malwatch';

	/**
	 * Where the interface pages are copied to. ISPConfig does not ship this
	 * directory - unlike the module the pages used to live in - so it has to
	 * be created before anything is copied into it.
	 */
	const INTERFACE_DIR = '/usr/local/ispconfig/interface/web/security';

	/**
	 * One copy target that lands in a directory ISPConfig does ship. Its
	 * presence tells install() whether the framework has already copied.
	 */
	const SERVER_CLASS = '/usr/local/ispconfig/server/lib/classes/malwatch_helper.inc.php';

	/** GitHub project the binary is downloaded from. */
	const REPO = 'brightcolor/malwatch';

	public function install($name = 'malwatch')
	{
		global $app;

		$app->log('malwatch: install step started.', LOGLEVEL_DEBUG);

		// Erst die Zielverzeichnisse, dann die Dateien - siehe
		// prepare_interface_dirs(). Deshalb steht der Aufruf ganz oben.
		$this->prepare_interface_dirs();

		// Kopiert wird von enable_files() im Kern, nicht von diesem Haken. Lief
		// das schon, bevor der Haken an die Reihe kam, sind die Kopien der
		// Oberflaeche ins Leere gegangen und muessen nachgeholt werden: die
		// Dienstklasse liegt dann bereits an ihrem Platz - ihr Zielverzeichnis
		// bringt ISPConfig mit -, waehrend die Startseite der Oberflaeche
		// fehlt. Ist noch gar nichts kopiert, gibt es nichts nachzuholen; der
		// Kern kopiert dann gleich, und die Verzeichnisse stehen bereit.
		if (!is_file(self::INTERFACE_DIR . '/status.php') && is_file(self::SERVER_CLASS)) {
			$app->log('malwatch: die Oberflaeche wurde vor dem Anlegen ihrer Verzeichnisse '
				. 'kopiert, das wird nachgeholt.', LOGLEVEL_DEBUG);
			$app->uses('extension_installer');
			$app->extension_installer->enable_files($name);
		}

		$this->prepare_state_dir();

		if (!$this->install_binary()) {
			// A missing binary is not fatal for the installation: the tables
			// and the interface are still useful, and the settings page tells
			// the operator what to do. Failing hard here would leave a half
			// installed extension behind.
			$app->log('malwatch: the scanner binary could not be installed automatically. '
				. 'Install it by hand and check the path in Security.', LOGLEVEL_WARN);
		} else {
			$this->update_signatures();
		}

		$this->grant_module();

		echo "\nmalwatch installed.\n\n";
		echo "- The scanner is at " . self::BINARY_PATH . "\n";
		echo "- Signatures and results are kept in " . self::STATE_DIR . "\n";
		echo "- Open Security in the panel to configure it\n\n";

		return true;
	}

	public function update($name = 'malwatch')
	{
		global $app;

		$app->uses('extension_installer');
		$app->extension_installer->disable_files($name);
		// Auch hier zuerst: disable_files() raeumt die Dateien weg, nicht die
		// Verzeichnisse - aber ein Update kommt auch von einer Version, die
		// noch unter dem alten Ort lag und security/ nie angelegt hat.
		$this->prepare_interface_dirs();
		$app->extension_installer->enable_files($name);

		// The schema is not touched here. load_install_sql() cannot work on a
		// running system - it reads credentials from $conf['mysql'][...],
		// which only exists while ISPConfig itself is being set up - and the
		// ISPConfig account may not create tables anyway. install/schema.sql
		// is loaded by manual_install.php, which is the documented way to
		// install and to update this extension.

		$this->prepare_state_dir();
		$this->install_binary();

		$app->log('malwatch: update step finished.', LOGLEVEL_DEBUG);
		return true;
	}

	public function enable($name = 'malwatch')
	{
		global $app;
		$app->uses('extension_installer');
		$this->prepare_interface_dirs();
		$app->extension_installer->enable_files($name);
		$app->log('malwatch: extension enabled.', LOGLEVEL_DEBUG);
		return true;
	}

	public function disable($name = 'malwatch')
	{
		global $app;
		$app->uses('extension_installer');
		$app->extension_installer->disable_files($name);
		$app->log('malwatch: extension disabled.', LOGLEVEL_DEBUG);
		return true;
	}

	public function uninstall($name = 'malwatch')
	{
		global $app, $conf;

		$app->log('malwatch: uninstall step started.', LOGLEVEL_DEBUG);
		$this->disable($name);
		$this->revoke_module();

		// The tables are dropped here rather than through the framework.
		// run_uninstall_sql() carries the same defect as its install
		// counterpart, and uninstall_extension() deletes the extension
		// directory the moment this hook returns - this is the last point at
		// which the file still exists.
		require_once __DIR__ . '/sql_loader.php';
		$sql_file = __DIR__ . '/uninstall-schema.sql';
		$result = malwatch_run_sql_file($sql_file, $conf['db_host'], $conf['db_database']);
		if ($result['ok']) {
			$app->log('malwatch: tables dropped.', LOGLEVEL_DEBUG);
		} else {
			// The directory disappears with this hook, so the statements have
			// to leave in the message itself. Printing them is the only form
			// that also helps on the panel route, where neither the
			// administration account nor the state directory is reachable.
			$app->log('malwatch: the tables could not be dropped (' . $result['error'] . ').', LOGLEVEL_WARN);
			echo "\nThe malwatch tables could not be dropped: " . $result['error'] . "\n";
			echo "Run these statements against " . $conf['db_database'] . " by hand:\n\n";
			echo (string) @file_get_contents($sql_file) . "\n";
		}

		if (is_file(self::BINARY_PATH)) {
			@unlink(self::BINARY_PATH);
		}

		// The state directory is left in place on purpose. It holds the
		// signature database and past scan results, and removing it would
		// throw away evidence about an infection the operator may still need.
		echo "\nmalwatch removed. " . self::STATE_DIR . " was kept; delete it by hand if you no longer need the scan results.\n\n";

		return true;
	}

	/**
	 * Legt die Zielverzeichnisse der Oberflaeche an.
	 *
	 * enable_files() im Kern kopiert nur. Es legt kein Elternverzeichnis an
	 * und sieht sich den Rueckgabewert von copy() nicht an: fehlt
	 * interface/web/security, scheitert jede einzelne Kopie still,
	 * enable_files() liefert trotzdem true, der Installer schreibt
	 * "malwatch installed." - und security/status.php gibt es nicht. Das trifft
	 * jede Erstinstallation, seit die Seiten ihr eigenes Modul haben: das
	 * frueher benutzte Zielverzeichnis brachte ISPConfig mit, dieses nicht.
	 *
	 * Nicht ueber 'd:'-Zeilen in file.list geloest: enable_files() setzt auf
	 * ein so angelegtes Verzeichnis anschliessend chmod 640 und nimmt ihm
	 * damit das x-Bit - betreten koennte es danach niemand mehr.
	 *
	 * Die Liste ist genau die Menge der Zielverzeichnisse aus
	 * install/file.list; check_wiring.sh haelt beide aneinander. Eltern stehen
	 * vor ihren Kindern, damit chown auch das Elternverzeichnis erwischt.
	 */
	private function prepare_interface_dirs()
	{
		global $app;

		foreach (array('', '/lib', '/lib/lang', '/templates', '/list', '/form') as $sub) {
			$dir = self::INTERFACE_DIR . $sub;
			if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
				// Weiterlaufen: der Rest der Installation - Tabellen, Binary,
				// Modulrecht - ist ohne dieses eine Verzeichnis noch nuetzlich,
				// und die Meldung sagt, was fehlt.
				$app->log('malwatch: das Verzeichnis ' . $dir . ' konnte nicht angelegt werden, '
					. 'die Oberflaeche bleibt unvollstaendig.', LOGLEVEL_WARN);
				continue;
			}
			// 0755 und nicht 0750: das x-Bit muss bleiben, und die Dateien
			// darin sind ohnehin 0640 fuer ispconfig.
			@chmod($dir, 0755);
			@chown($dir, 'ispconfig');
			@chgrp($dir, 'ispconfig');
		}
	}

	/**
	 * Legt den Zustandsbaum an.
	 *
	 * quarantine bleibt root-only: dort liegt Schadcode.
	 * runs und spool bekommen die Gruppe der Oberflaeche und das Setgid-Bit, damit
	 * neue Dateien die Gruppe erben. Ohne das konnte das Panel die Fortschrittsdatei
	 * nicht lesen und der Balken zaehlte bei jedem Lauf bis null.
	 */
	private function prepare_state_dir()
	{
		global $app;

		foreach (array('', '/signatures', '/state', '/quarantine') as $sub) {
			$dir = self::STATE_DIR . $sub;
			if (!is_dir($dir)) {
				@mkdir($dir, 0750, true);
			}
			@chmod($dir, 0750);
			@chown($dir, 'root');
			@chgrp($dir, 'root');
		}

		// Das Elternverzeichnis zuerst: ohne x-Bit fuer die Gruppe kommt der
		// Panel-Benutzer gar nicht erst nach runs hinein, und aller Aufwand mit
		// Setgid darunter ist wirkungslos. r-x heisst: er darf hindurchgehen
		// und die Namen sehen - an quarantine kommt er damit nicht, das bleibt
		// 0750 root:root.
		$group = $this->find_group(self::STATE_DIR);
		if ($group !== '') {
			@chmod(self::STATE_DIR, 0750);
		}

		foreach (array('/runs', '/spool') as $sub) {
			$dir = self::STATE_DIR . $sub;
			if (!is_dir($dir)) {
				// mkdir() setzt das Setgid-Bit nur mit einer vierstelligen
				// Oktalzahl.
				@mkdir($dir, 02750, true);
			}
			// chmod erst nach mkdir: die umask des Prozesses wuerde das
			// Setgid-Bit sonst gleich wieder herausfiltern.
			@chmod($dir, 02750);
			@chown($dir, 'root');
			@chgrp($dir, $group !== '' ? $group : 'root');
		}

		if ($group === '') {
			// find_group() hat auf dem Zustandsverzeichnis jeden Kandidaten
			// probiert und keinen gefunden - explizit zuruecksetzen, falls
			// einer der Versuche die Gruppe trotz false-Rueckgabe veraendert
			// haben sollte.
			@chgrp(self::STATE_DIR, 'root');
			$app->log('malwatch: keine der Gruppen ispconfig, ispapps oder www-data gefunden; '
				. 'runs und spool bleiben root:root, der Fortschrittszaehler im Panel bleibt leer '
				. 'und der Download aus der Quarantaene funktioniert nicht.', LOGLEVEL_WARN);
			return;
		}

		// Vorhandene Dateien aus einem laufenden Auftrag bekommen die Gruppe
		// nachtraeglich - das Setgid-Bit wirkt nur auf neu angelegte Dateien,
		// und ohne diese Nachbesserung bliebe der gerade laufende Auftrag
		// unlesbar.
		$runs = self::STATE_DIR . '/runs';
		foreach ((array) @scandir($runs) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			@chgrp($runs . '/' . $entry, $group);
		}
	}

	/**
	 * Findet die erste vorhandene Gruppe aus ispconfig, ispapps, www-data und
	 * setzt $dir gleich darauf; liefert '', wenn keine davon existiert.
	 *
	 * posix_getgrnam() ist der saubere Weg, eine Gruppe nachzuschlagen, aber
	 * die POSIX-Erweiterung ist nicht auf jedem System an - function_exists()
	 * prueft das vorher ab. Ohne sie bleibt nur der Versuch selbst: chgrp()
	 * auf $dir meldet per Rueckgabewert, ob die Gruppe existiert.
	 *
	 * Gemeldet wird in beiden Zweigen die tatsaechlich gesetzte Gruppe, nicht
	 * die gefundene: dass es die Gruppe gibt, heisst nicht, dass dieser
	 * Prozess sie vergeben darf. Laeuft der Installer nicht als root,
	 * scheitert chgrp() still, und an diesem einen Rueckgabewert haengt die
	 * ganze Rechtekette - runs und spool blieben root:root, ohne dass die
	 * Warnung unten je ausgegeben wuerde, und Fortschrittsbalken wie Download
	 * scheiterten wortlos mit "Die Datei liegt nicht mehr vor.", nachdem das
	 * Token schon verbrannt ist.
	 */
	private function find_group($dir)
	{
		$posix = function_exists('posix_getgrnam');
		foreach (array('ispconfig', 'ispapps', 'www-data') as $candidate) {
			if ($posix && posix_getgrnam($candidate) === false) {
				continue;
			}
			if (@chgrp($dir, $candidate)) {
				return $candidate;
			}
		}
		return '';
	}

	/**
	 * Downloads the scanner binary for this architecture and verifies it
	 * against the published checksum before putting it in place.
	 */
	private function install_binary()
	{
		global $app;

		$arch = $this->architecture();
		if ($arch === '') {
			$app->log('malwatch: unsupported architecture ' . php_uname('m'), LOGLEVEL_WARN);
			return false;
		}

		$version = trim((string) @file_get_contents(dirname(__DIR__) . '/version'));
		if ($version === '') {
			$app->log('malwatch: the extension carries no version file.', LOGLEVEL_WARN);
			return false;
		}

		$asset = 'malwatch-linux-' . $arch;
		$base = 'https://github.com/' . self::REPO . '/releases/download/v' . $version;
		$tmp = self::STATE_DIR . '/' . $asset . '.download';

		if (!$this->fetch($base . '/' . $asset, $tmp)) {
			$app->log('malwatch: could not download ' . $base . '/' . $asset, LOGLEVEL_WARN);
			return false;
		}

		$sums_file = self::STATE_DIR . '/SHA256SUMS.download';
		if (!$this->fetch($base . '/SHA256SUMS', $sums_file)) {
			@unlink($tmp);
			$app->log('malwatch: the checksum file could not be downloaded, the binary was discarded.', LOGLEVEL_WARN);
			return false;
		}

		$expected = $this->expected_sum($sums_file, $asset);
		@unlink($sums_file);
		if ($expected === '') {
			@unlink($tmp);
			$app->log('malwatch: the checksum file lists no entry for ' . $asset . '.', LOGLEVEL_WARN);
			return false;
		}

		$actual = hash_file('sha256', $tmp);
		if (!hash_equals($expected, (string) $actual)) {
			// Never install a binary that does not match. It runs as root over
			// every customer's files.
			@unlink($tmp);
			$app->log('malwatch: checksum mismatch for ' . $asset . ', the download was discarded.', LOGLEVEL_ERROR);
			return false;
		}

		if (!@rename($tmp, self::BINARY_PATH)) {
			@unlink($tmp);
			$app->log('malwatch: the binary could not be moved to ' . self::BINARY_PATH, LOGLEVEL_WARN);
			return false;
		}
		@chmod(self::BINARY_PATH, 0755);
		@chown(self::BINARY_PATH, 'root');
		@chgrp(self::BINARY_PATH, 'root');

		$app->log('malwatch: scanner ' . $version . ' installed at ' . self::BINARY_PATH, LOGLEVEL_DEBUG);
		return true;
	}

	/** Loads the malware signatures once, so the first scan is not blind. */
	private function update_signatures()
	{
		global $app;

		$cmd = escapeshellcmd(self::BINARY_PATH) . ' update --sig-dir='
			. escapeshellarg(self::STATE_DIR . '/signatures') . ' --quiet 2>&1';
		$output = array();
		$status = 0;
		exec($cmd, $output, $status);

		if ($status !== 0) {
			$app->log('malwatch: the signatures could not be loaded (' . implode(' ', $output) . ').', LOGLEVEL_WARN);
			return false;
		}
		$app->log('malwatch: signatures loaded.', LOGLEVEL_DEBUG);
		return true;
	}

	private function architecture()
	{
		$machine = strtolower(trim(php_uname('m')));
		if ($machine === 'x86_64' || $machine === 'amd64') {
			return 'amd64';
		}
		if ($machine === 'aarch64' || $machine === 'arm64') {
			return 'arm64';
		}
		return '';
	}

	private function fetch($url, $target)
	{
		$fp = @fopen($target, 'w');
		if (!$fp) {
			return false;
		}
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_FILE, $fp);
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($curl, CURLOPT_FAILONERROR, true);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($curl, CURLOPT_TIMEOUT, 300);
		curl_setopt($curl, CURLOPT_USERAGENT, 'malwatch-installer');
		$ok = curl_exec($curl);
		$code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		curl_close($curl);
		fclose($fp);

		if ($ok === false || $code != 200 || !is_file($target) || filesize($target) === 0) {
			@unlink($target);
			return false;
		}
		return true;
	}

	/** Reads the sum for one asset out of a sha256sum style file. */
	private function expected_sum($file, $asset)
	{
		$lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		if (!is_array($lines)) {
			return '';
		}
		foreach ($lines as $line) {
			$parts = preg_split('/\s+/', trim($line));
			if (count($parts) < 2) {
				continue;
			}
			$name = ltrim($parts[count($parts) - 1], '*');
			if (basename($name) === $asset) {
				return strtolower($parts[0]);
			}
		}
		return '';
	}

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
}
