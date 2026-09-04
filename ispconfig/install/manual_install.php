<?php

/**
 * Installs the malwatch extension without the ISPConfig extension repository.
 *
 * Run as root on the ISPConfig master:
 *
 *   php /usr/local/ispconfig/extensions/malwatch/install/manual_install.php
 *
 * The schema is loaded here, with the database administration account: the
 * ISPConfig account may only read and write rows, not create tables.
 *
 * It is called schema.sql, not install.sql, on purpose. The framework looks
 * for install.sql and loads it a second time through
 * extension_installer::load_install_sql(), which builds its command from
 * $conf['mysql'][...] - keys that exist only while ISPConfig itself is being
 * set up. On a running system they are empty, so the command carries no
 * password: mysql asks for one, reads the answer from the redirected SQL file
 * and reports a syntax error on the remains. Under a name the framework does
 * not look for, that call finds nothing and stays quiet.
 */

if (php_sapi_name() != 'cli') {
	die("This script must be run from the command line.\n");
}
if (function_exists('posix_getuid') && posix_getuid() !== 0) {
	die("This script must be run as root.\n");
}

$conf_file = '/usr/local/ispconfig/server/lib/config.inc.php';
if (!is_file($conf_file)) {
	die("ISPConfig server not found at /usr/local/ispconfig/server.\n");
}

require $conf_file;
if (!defined('SCRIPT_PATH')) {
	define('SCRIPT_PATH', '/usr/local/ispconfig/server');
}
require SCRIPT_PATH . '/lib/app.inc.php';

$extension_name = 'malwatch';
$extension_dir = '/usr/local/ispconfig/extensions/' . $extension_name;

if (!is_dir($extension_dir)) {
	die("Extension directory not found: $extension_dir\nCopy the extension there first.\n");
}

echo "Installing extension '$extension_name' ...\n";

// --- Schema ----------------------------------------------------------------
$sql_file = $extension_dir . '/install/schema.sql';
if (is_file($sql_file)) {
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
		echo "Could not read the database administration account from $clientdb_conf.\n";
		echo "Load the schema by hand, then re-run this script:\n";
		echo '  mysql -u root -p ' . $conf['db_database'] . " < $sql_file\n";
		exit(1);
	}

	$defaults = tempnam(sys_get_temp_dir(), 'mw');
	if ($defaults === false) {
		echo "Could not create a temporary file.\n";
		exit(1);
	}
	chmod($defaults, 0600);
	file_put_contents($defaults,
		"[client]\nuser=" . $admin_user . "\npassword=\"" . str_replace('"', '\\"', $admin_pass) . "\"\n");

	$cmd = 'mysql --defaults-extra-file=' . escapeshellarg($defaults)
		. ' -h ' . escapeshellarg($conf['db_host'])
		. ' ' . escapeshellarg($conf['db_database'])
		. ' < ' . escapeshellarg($sql_file) . ' 2>&1';

	$sql_output = array();
	$sql_status = 0;
	exec($cmd, $sql_output, $sql_status);
	unlink($defaults);

	if ($sql_status !== 0) {
		echo "Loading schema.sql failed:\n";
		foreach ($sql_output as $line) {
			if (stripos($line, 'ERROR') !== false) {
				echo " - $line\n";
			}
		}
		exit(1);
	}
	echo "Database schema loaded.\n";

	// An update unpacks the package over the old directory, and unzip removes
	// nothing. A schema.sql from this version next to an install.sql from the
	// previous one would leave the framework a file to trip over again, so the
	// old name goes once the new one has been read.
	$stale = $extension_dir . '/install/install.sql';
	if (is_file($stale) && !unlink($stale)) {
		echo "Warning: the obsolete $stale could not be removed.\n";
	}
}

// --- Files and installer hooks --------------------------------------------
$app->uses('extension_installer');
$app->load('extension_installer_base');

$ok = $app->extension_installer->install_extension($extension_name, null, false);

$errors = $app->extension_installer->getErrors();
if (count($errors) > 0) {
	echo "Errors during installation:\n";
	foreach ($errors as $error) {
		echo " - $error\n";
	}
	exit(1);
}

$app->extension_installer->scan_extensions();

echo "\nExtension installed and enabled.\n\n";
echo "Next steps:\n";
echo " - Log out and back in, then open Websites > malwatch in the panel.\n";
echo " - Check the paths under Websites > malwatch > Einstellungen.\n";
echo " - The first scan starts within a minute of pressing 'Jetzt prüfen'.\n\n";

exit(0);
