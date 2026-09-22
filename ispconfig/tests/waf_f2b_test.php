<?php
/**
 * The pure part of fail2ban in the panel: reading the answers of
 * fail2ban-client, the reason of a jail and what "überall sperren" does.
 * The samples are the real answers of web.herkules from 2026-09-22.
 */

require __DIR__ . '/../interface/lib/malwatch_waf_f2b.inc.php';

$failures = 0;

function expect_same($label, $actual, $expected)
{
	global $failures;
	if ($actual !== $expected) {
		fwrite(STDERR, 'FAIL ' . $label . ': ' . var_export($actual, true) . ', erwartet ' . var_export($expected, true) . PHP_EOL);
		$failures++;
	}
}

// --- Die Jails ----------------------------------------------------------------

$status = "Status\n|- Number of jail:\t5\n`- Jail list:\tdovecot, postfix-sasl, pure-ftpd, recidive, sshd\n";
expect_same('the jails of the status answer', waf_f2b_jails($status),
	array('dovecot', 'postfix-sasl', 'pure-ftpd', 'recidive', 'sshd'));
expect_same('a status without jails', waf_f2b_jails("Status\n|- Number of jail:\t0\n`- Jail list:\t\n"), array());
expect_same('an odd name is left out', waf_f2b_jails("`- Jail list:\tsshd, ../etc, re cidive\n"), array('sshd'));
expect_same('no status at all', waf_f2b_jails(''), array());

expect_same('the shape of a jail name', array(
	waf_f2b_jail_ok('postfix-sasl'),
	waf_f2b_jail_ok('nginx.http-auth'),
	waf_f2b_jail_ok(''),
	waf_f2b_jail_ok('ssh d'),
	waf_f2b_jail_ok('sshd;rm'),
	waf_f2b_jail_ok(str_repeat('a', 65)),
), array(true, true, false, false, false, false));

// --- Die Sperren eines Jails --------------------------------------------------

$banned = "91.92.243.20 \t2026-09-15 21:20:27 + 686484 = 2026-09-23 20:01:51\n"
	. "92.118.39.171 \t2026-09-20 12:47:50 + 604800 = 2026-09-27 12:47:50\n"
	. "2001:db8::7 \t2026-09-21 03:47:14 + 600 = 2026-09-21 03:57:14\n";
expect_same('the bans with their times', waf_f2b_bans($banned), array(
	array('ip' => '91.92.243.20', 'banned_at' => '2026-09-15 21:20:27', 'until' => '2026-09-23 20:01:51'),
	array('ip' => '92.118.39.171', 'banned_at' => '2026-09-20 12:47:50', 'until' => '2026-09-27 12:47:50'),
	array('ip' => '2001:db8::7', 'banned_at' => '2026-09-21 03:47:14', 'until' => '2026-09-21 03:57:14'),
));
expect_same('an empty jail', waf_f2b_bans("\n"), array());
expect_same('what is no ban stays out', waf_f2b_bans("kein-ip \t2026-09-15 21:20:27 + 1 = 2026-09-15 21:20:28\n"
	. "192.0.2.10 \tgestern + 1 = morgen\n"
	. "192.0.2.11\n"), array(
	array('ip' => '192.0.2.11', 'banned_at' => null, 'until' => null),
));
expect_same('a ban without end (bantime -1)', waf_f2b_bans("192.0.2.12 \t2026-09-15 21:20:27 + -1 = 9999-12-31 23:59:59\n"),
	array(array('ip' => '192.0.2.12', 'banned_at' => '2026-09-15 21:20:27', 'until' => null)));

// --- Der Grund ----------------------------------------------------------------

expect_same('the reasons in plain words', array(
	waf_f2b_reason('sshd'),
	waf_f2b_reason('dovecot'),
	waf_f2b_reason('postfix-sasl'),
	waf_f2b_reason('pure-ftpd'),
	waf_f2b_reason('recidive'),
	waf_f2b_reason('nginx-limit'),
), array(
	'SSH: zu viele fehlgeschlagene Anmeldungen (sshd)',
	'Mail-Abruf: zu viele fehlgeschlagene Anmeldungen (dovecot)',
	'Mailversand: zu viele fehlgeschlagene Anmeldungen (postfix-sasl)',
	'FTP: zu viele fehlgeschlagene Anmeldungen (pure-ftpd)',
	'Wiederholungstäter, alle Dienste gesperrt (recidive)',
	'fail2ban-Jail nginx-limit',
));

// --- Was „überall sperren" tut ------------------------------------------------

expect_same('the three modes', waf_f2b_modes(), array('web_jail', 'web_forever_jail', 'jail_only'));
expect_same('the modes a rule may carry', waf_f2b_rule_modes(), array('', 'web_jail', 'web_forever_jail'));
$settings = array('waf_everywhere_mode' => 'web_jail');
$jails = array('sshd' => 'jail_only', 'dovecot' => 'erfunden');
expect_same('the mode of a jail comes first', waf_f2b_mode('sshd', $jails, $settings), 'jail_only');
expect_same('otherwise the global one', array(
	waf_f2b_mode('recidive', $jails, $settings),
	waf_f2b_mode('', $jails, $settings),
	waf_f2b_mode('dovecot', $jails, $settings),
), array('web_jail', 'web_jail', 'web_jail'));
expect_same('a broken global mode falls back', waf_f2b_mode('', array(), array('waf_everywhere_mode' => 'alles')),
	'web_jail');
expect_same('what each mode does', array(
	waf_f2b_plan('web_jail'),
	waf_f2b_plan('web_forever_jail'),
	waf_f2b_plan('jail_only'),
	waf_f2b_plan(''),
), array(
	array('web' => true, 'forever' => false, 'jail' => true),
	array('web' => true, 'forever' => true, 'jail' => true),
	array('web' => false, 'forever' => false, 'jail' => true),
	array('web' => true, 'forever' => false, 'jail' => false),
));

// --- summary -----------------------------------------------------------------

if ($failures > 0) {
	fwrite(STDERR, $failures . ' Fehler' . PHP_EOL);
	exit(1);
}
echo 'waf_f2b: alle Prüfungen bestanden' . PHP_EOL;
