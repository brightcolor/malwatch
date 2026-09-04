<?php

/**
 * Runs an SQL file against the ISPConfig database.
 *
 * The ISPConfig account may only read and write rows, never create or drop a
 * table, so the schema needs the administration account from
 * mysql_clientdb.conf. That file belongs to root alone, which is why every
 * caller has to run as root.
 *
 * The password travels in a 0600 defaults file and never on the command line:
 * exec() hands its string to a shell, where it would sit in argv and be
 * readable in ps by every local user. On a hosting machine that is the
 * database administration account.
 *
 * Returns array('ok' => bool, 'error' => string).
 */
function malwatch_run_sql_file($sql_file, $db_host, $db_name)
{
	if (!is_file($sql_file)) {
		return array('ok' => false, 'error' => $sql_file . ' does not exist');
	}

	$clientdb_conf = '/usr/local/ispconfig/server/lib/mysql_clientdb.conf';
	$admin_user = '';
	$admin_pass = '';
	if (is_file($clientdb_conf)) {
		$raw = file_get_contents($clientdb_conf);
		if (preg_match('/clientdb_user\s*=\s*\'([^\']*)\'/', $raw, $m)) {
			$admin_user = $m[1];
		}
		if (preg_match('/clientdb_password\s*=\s*\'([^\']*)\'/', $raw, $m)) {
			$admin_pass = $m[1];
		}
	}
	if ($admin_user === '' || $admin_pass === '') {
		return array('ok' => false,
			'error' => 'the administration account could not be read from ' . $clientdb_conf
				. ' (this needs to run as root)');
	}

	$defaults = tempnam(sys_get_temp_dir(), 'mw');
	if ($defaults === false) {
		return array('ok' => false, 'error' => 'a temporary file could not be created');
	}
	chmod($defaults, 0600);
	file_put_contents($defaults,
		"[client]\nuser=" . $admin_user . "\npassword=\"" . str_replace('"', '\\"', $admin_pass) . "\"\n");

	$cmd = 'mysql --defaults-extra-file=' . escapeshellarg($defaults)
		. ' -h ' . escapeshellarg($db_host)
		. ' ' . escapeshellarg($db_name)
		. ' < ' . escapeshellarg($sql_file) . ' 2>&1';

	$output = array();
	$status = 0;
	exec($cmd, $output, $status);
	unlink($defaults);

	if ($status !== 0) {
		$lines = array();
		foreach ($output as $line) {
			if (stripos($line, 'ERROR') !== false) {
				$lines[] = trim($line);
			}
		}
		if (count($lines) === 0) {
			$lines[] = 'mysql exited with status ' . $status;
		}
		return array('ok' => false, 'error' => implode('; ', $lines));
	}

	return array('ok' => true, 'error' => '');
}
