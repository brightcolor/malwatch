<?php
/**
 * fail2ban in the panel: reading the answers of fail2ban-client, the reason of a
 * jail in plain words and what "überall sperren" does. Everything here works
 * without a database and without a process, so tests/waf_f2b_test.php can check
 * it on its own; the cron runs fail2ban-client and keeps the result in
 * malwatch_f2b_ban.
 */
require_once __DIR__ . '/malwatch_waf_origin.inc.php';

/**
 * True while a value has the shape of a jail name. Only such a name ever
 * reaches fail2ban-client, and only through escapeshellarg().
 */
function waf_f2b_jail_ok($jail)
{
	return (bool) preg_match('/^[A-Za-z0-9_.-]{1,64}$/', (string) $jail);
}

/** The jails of the answer of `fail2ban-client status`. */
function waf_f2b_jails($status_output)
{
	if (!preg_match('/Jail list:[ \t]*([^\n]*)/', (string) $status_output, $match)) {
		return array();
	}
	$jails = array();
	foreach (explode(',', $match[1]) as $one) {
		$one = trim($one);
		if (waf_f2b_jail_ok($one) && !in_array($one, $jails, true)) {
			$jails[] = $one;
		}
	}
	return $jails;
}

/**
 * The bans of one jail from `fail2ban-client get <jail> banip --with-time`: one
 * line per address, "192.0.2.10 \t2026-09-15 21:20:27 + 600 = 2026-09-15
 * 21:30:27". The times are those of the server, the same clock as the database.
 * A ban without end (bantime -1) has no until. A line that carries text but no
 * readable time is left out, and so is anything that is no address.
 */
function waf_f2b_bans($output)
{
	$bans = array();
	foreach (explode("\n", (string) $output) as $line) {
		$line = trim($line);
		if ($line === '') {
			continue;
		}
		$parts = preg_split('/\s+/', $line, 2);
		$ip = (string) $parts[0];
		if (waf_origin_bytes($ip) === '') {
			continue;
		}
		$rest = isset($parts[1]) ? trim((string) $parts[1]) : '';
		if ($rest === '') {
			$bans[] = array('ip' => $ip, 'banned_at' => null, 'until' => null);
			continue;
		}
		$time = '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}';
		if (!preg_match('/^(' . $time . ') \+ (-?\d+) = (' . $time . ')$/', $rest, $match)) {
			continue;
		}
		$bans[] = array('ip' => $ip, 'banned_at' => $match[1], 'until' => (int) $match[2] < 0 ? null : $match[3]);
	}
	return $bans;
}

/** Why fail2ban blocked an address, in the words of the operator. */
function waf_f2b_reason($jail)
{
	$jail = (string) $jail;
	$known = array(
		'sshd' => 'SSH: zu viele fehlgeschlagene Anmeldungen',
		'dovecot' => 'Mail-Abruf: zu viele fehlgeschlagene Anmeldungen',
		'postfix-sasl' => 'Mailversand: zu viele fehlgeschlagene Anmeldungen',
		'pure-ftpd' => 'FTP: zu viele fehlgeschlagene Anmeldungen',
		'recidive' => 'Wiederholungstäter, alle Dienste gesperrt',
	);
	return isset($known[$jail]) ? $known[$jail] . ' (' . $jail . ')' : 'fail2ban-Jail ' . $jail;
}

/**
 * The three meanings of "überall sperren": the web block of malwatch with its
 * levels plus a ban in the fail2ban jail, the same with a web block without
 * end, or the ban in fail2ban alone.
 */
function waf_f2b_modes()
{
	return array('web_jail', 'web_forever_jail', 'jail_only');
}

/**
 * The modes a rule of the Abwehr may carry for the automatic. '' keeps the
 * block on the web alone; a block that started on the web never drops it.
 */
function waf_f2b_rule_modes()
{
	return array('', 'web_jail', 'web_forever_jail');
}

/**
 * The mode of the button: that of the jail the row comes from, otherwise the
 * global one, and web_jail when the global one is broken.
 */
function waf_f2b_mode($jail, $jail_modes, $settings)
{
	$jail = (string) $jail;
	if ($jail !== '' && is_array($jail_modes) && isset($jail_modes[$jail])
		&& in_array((string) $jail_modes[$jail], waf_f2b_modes(), true)) {
		return (string) $jail_modes[$jail];
	}
	$global = isset($settings['waf_everywhere_mode']) ? (string) $settings['waf_everywhere_mode'] : '';
	return in_array($global, waf_f2b_modes(), true) ? $global : 'web_jail';
}

/**
 * What a mode does: a web block, one without end, a ban in fail2ban. '' is the
 * block on the web alone, the way malwatch blocks without this stage.
 */
function waf_f2b_plan($mode)
{
	switch ((string) $mode) {
		case 'web_jail':
			return array('web' => true, 'forever' => false, 'jail' => true);
		case 'web_forever_jail':
			return array('web' => true, 'forever' => true, 'jail' => true);
		case 'jail_only':
			return array('web' => false, 'forever' => false, 'jail' => true);
	}
	return array('web' => true, 'forever' => false, 'jail' => false);
}
