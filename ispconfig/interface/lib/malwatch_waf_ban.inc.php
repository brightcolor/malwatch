<?php
/**
 * Blocking attacker addresses: who crosses a threshold, for how long and with
 * which reason. Everything here works without a database and without a network,
 * so tests/waf_ban_test.php can check it on its own. The texts are German, like
 * the notes of the jobs.
 *
 * The name is "ban", because waf_block_text() and its neighbours in
 * malwatch_waf_lib.inc.php already build the managed block of a vhost.
 */
require_once __DIR__ . '/malwatch_waf_origin.inc.php';

/**
 * The points a website needs before an address is blocked: its own value, the
 * value of the server, or 0 when the website never triggers a block.
 */
function waf_ban_site_score($settings, $site)
{
	$trigger = is_array($site) && isset($site['waf_ban_trigger']) ? (string) $site['waf_ban_trigger'] : 'y';
	if ($trigger !== 'y') {
		return 0;
	}
	$own = is_array($site) && isset($site['waf_ban_score']) ? (int) $site['waf_ban_score'] : 0;
	return $own > 0 ? $own : (int) $settings['waf_ban_score'];
}

/**
 * The addresses that crossed the threshold of at least one website. $groups are
 * the sums of the window with client_ip, parent_domain_id, score, hits and the
 * rule that appeared most; $sites holds the websites by parent_domain_id. One
 * entry per address, naming the website with the most points.
 */
function waf_ban_decide($groups, $settings, $sites)
{
	$picked = array();
	foreach ($groups as $row) {
		$id = (int) $row['parent_domain_id'];
		$site = isset($sites[$id]) ? $sites[$id] : null;
		$limit = waf_ban_site_score($settings, $site);
		$score = (int) $row['score'];
		if ($limit <= 0 || $score < $limit) {
			continue;
		}
		$ip = (string) $row['client_ip'];
		if (isset($picked[$ip]) && $picked[$ip]['score'] >= $score) {
			continue;
		}
		$picked[$ip] = array(
			'ip' => $ip,
			'domain' => is_array($site) && isset($site['domain']) ? (string) $site['domain'] : '',
			'score' => $score,
			'hits' => (int) $row['hits'],
			'rule' => isset($row['rule']) ? (string) $row['rule'] : '',
			'limit' => $limit,
		);
	}
	return array_values($picked);
}

/**
 * The level of a block: 1 the first time, 2 the second, 3 from then on.
 * $earlier is the level of the earlier block of the same address, 0 when there
 * was none.
 */
function waf_ban_level($earlier)
{
	$earlier = (int) $earlier;
	if ($earlier < 1) {
		return 1;
	}
	return $earlier === 1 ? 2 : 3;
}

/** The hours a block of that level lasts. */
function waf_ban_hours($level, $settings)
{
	if ((int) $level >= 3) {
		return (int) $settings['waf_ban_hours_third'];
	}
	return (int) $level === 2 ? (int) $settings['waf_ban_hours_second'] : (int) $settings['waf_ban_hours_first'];
}

/** When a block of that level ends, counted from $now. */
function waf_ban_until($level, $settings, $now)
{
	return gmdate('Y-m-d H:i:s', strtotime((string) $now) + waf_ban_hours($level, $settings) * 3600);
}

/**
 * The reason of a block as one sentence: points, hits, window, website and the
 * rule that appeared most, in words.
 */
function waf_ban_reason($pick, $minutes, $rule_label)
{
	$reason = number_format((int) $pick['score'], 0, ',', '.') . ' Punkte aus ' . (int) $pick['hits']
		. ' Treffern in ' . (int) $minutes . ' Minuten';
	if ((string) $pick['domain'] !== '') {
		$reason .= ' auf ' . $pick['domain'];
	}
	if ((string) $rule_label !== '') {
		$reason .= ', meist ' . $rule_label;
	}
	return waf_origin_cut($reason . '.', 255);
}

/**
 * The networks that are never blocked, whatever the settings say: localhost and
 * the network of the proxy in front of the server. Without them the server
 * could lock itself out.
 */
function waf_ban_fixed_allow()
{
	return array('127.0.0.0/8', '::1/128', '10.50.0.0/24');
}

/** true when the address lies in one of the given addresses or ranges. */
function waf_ban_allow_match($cidrs, $ip)
{
	$bytes = waf_origin_bytes($ip);
	if ($bytes === '') {
		return false;
	}
	foreach ($cidrs as $cidr) {
		$range = waf_origin_cidr($cidr);
		if ($range === null) {
			continue;
		}
		if (strcmp($bytes, $range[0]) >= 0 && strcmp($bytes, $range[1]) <= 0) {
			return true;
		}
	}
	return false;
}

/**
 * The three layers before a block: the fixed networks, the list of the operator
 * (which carries the addresses of the server itself) and the ranges of the
 * search engines. $reader is the open reader of the source searchbots or null.
 */
function waf_ban_allowed($ip, $cidrs, $reader)
{
	if (waf_ban_allow_match(waf_ban_fixed_allow(), $ip)) {
		return true;
	}
	if (waf_ban_allow_match($cidrs, $ip)) {
		return true;
	}
	return $reader !== null && waf_origin_find($reader, $ip) !== '';
}

/**
 * The content of /etc/nginx/waf/blocked.conf. Only what inet_pton accepts
 * reaches the file, so nothing can smuggle a directive into the configuration
 * of nginx. At most $max lines, in the order they are handed over.
 */
function waf_ban_file($ips, $now, $max)
{
	$lines = array('# von malwatch erzeugt am ' . (string) $now . '. Änderungen hier werden überschrieben.');
	$max = (int) $max;
	$count = 0;
	foreach ($ips as $ip) {
		if ($count >= $max) {
			break;
		}
		$ip = trim((string) $ip);
		if (waf_origin_bytes($ip) === '') {
			continue;
		}
		$lines[] = 'deny ' . $ip . ';';
		$count++;
	}
	return implode("\n", $lines) . "\n";
}

/**
 * One line of /var/log/waf/blocked.log, written in the format mw_block: time,
 * address, status, host, request. Only an answer 403 from a real address
 * counts; everything else is none of our business.
 */
function waf_ban_log_line($line)
{
	$parts = explode(' ', trim((string) $line));
	if (count($parts) < 3) {
		return null;
	}
	if ((int) $parts[2] !== 403 || waf_origin_bytes($parts[1]) === '') {
		return null;
	}
	return array('ip' => (string) $parts[1]);
}
