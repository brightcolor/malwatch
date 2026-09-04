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

	/** GitHub project the binary is downloaded from. */
	const REPO = 'brightcolor/malwatch';

	public function install($name = 'malwatch')
	{
		global $app;

		$app->log('malwatch: install step started.', LOGLEVEL_DEBUG);
		$this->prepare_state_dir();

		if (!$this->install_binary()) {
			// A missing binary is not fatal for the installation: the tables
			// and the interface are still useful, and the settings page tells
			// the operator what to do. Failing hard here would leave a half
			// installed extension behind.
			$app->log('malwatch: the scanner binary could not be installed automatically. '
				. 'Install it by hand and check the path under Websites > malwatch > Settings.', LOGLEVEL_WARN);
		} else {
			$this->update_signatures();
		}

		echo "\nmalwatch installed.\n\n";
		echo "- The scanner is at " . self::BINARY_PATH . "\n";
		echo "- Signatures and results are kept in " . self::STATE_DIR . "\n";
		echo "- Open Websites > malwatch in the panel to configure it\n\n";

		return true;
	}

	public function update($name = 'malwatch')
	{
		global $app;

		$app->uses('extension_installer');
		$app->extension_installer->disable_files($name);
		$app->extension_installer->enable_files($name);
		$app->extension_installer->load_install_sql($name);

		$this->prepare_state_dir();
		$this->install_binary();

		$app->log('malwatch: update step finished.', LOGLEVEL_DEBUG);
		return true;
	}

	public function enable($name = 'malwatch')
	{
		global $app;
		$app->uses('extension_installer');
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
		global $app;

		$app->log('malwatch: uninstall step started.', LOGLEVEL_DEBUG);
		$this->disable($name);

		if (is_file(self::BINARY_PATH)) {
			@unlink(self::BINARY_PATH);
		}

		// The state directory is left in place on purpose. It holds the
		// signature database and past scan results, and removing it would
		// throw away evidence about an infection the operator may still need.
		echo "\nmalwatch removed. " . self::STATE_DIR . " was kept; delete it by hand if you no longer need the scan results.\n\n";

		return true;
	}

	/** Creates the state directory tree, readable by root only. */
	private function prepare_state_dir()
	{
		foreach (array('', '/signatures', '/state', '/runs') as $sub) {
			$dir = self::STATE_DIR . $sub;
			if (!is_dir($dir)) {
				@mkdir($dir, 0750, true);
			}
			@chmod($dir, 0750);
			@chown($dir, 'root');
			@chgrp($dir, 'root');
		}
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
}
