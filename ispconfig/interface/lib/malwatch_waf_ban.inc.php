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
 * The countries of a stored list: two letters each, upper case, without
 * doubles. Everything else is dropped, so a typo never becomes a criterion.
 */
function waf_ban_origin_countries($text)
{
	$list = array();
	foreach (explode(',', (string) $text) as $one) {
		$one = strtoupper(trim($one));
		if (preg_match('/^[A-Z]{2}$/', $one) && !in_array($one, $list, true)) {
			$list[] = $one;
		}
	}
	return $list;
}

/** The provider numbers of a stored list; "AS15169" and "15169" mean the same. */
function waf_ban_origin_asns($text)
{
	$list = array();
	foreach (explode(',', (string) $text) as $one) {
		$one = trim($one);
		if (stripos($one, 'as') === 0) {
			$one = substr($one, 2);
		}
		$number = (int) $one;
		if ($number > 0 && !in_array($number, $list, true)) {
			$list[] = $number;
		}
	}
	return $list;
}

/** A list as it is stored in the configuration. */
function waf_ban_origin_store($values)
{
	return implode(',', array_map('strval', $values));
}

/**
 * What makes an address suspicious, as a short German label for the reason of
 * the block, or '' when nothing does. The provider comes first, because it says
 * the most: one entry catches a whole scanner network. A criterion that is
 * switched off never triggers, and without the master switch none does.
 */
function waf_ban_origin_match($origin, $settings)
{
	$on = isset($settings['waf_ban_origin']) ? (string) $settings['waf_ban_origin'] : 'off';
	if ($on !== 'on' || !is_array($origin)) {
		return '';
	}
	$asn = isset($origin['asn']) ? (int) $origin['asn'] : 0;
	if ($asn > 0 && in_array($asn, waf_ban_origin_asns(isset($settings['waf_ban_origin_asn'])
		? $settings['waf_ban_origin_asn'] : ''), true)) {
		$name = isset($origin['as_org']) ? trim((string) $origin['as_org']) : '';
		return 'Anbieter ' . ($name !== '' ? $name : 'AS' . $asn);
	}
	$country = isset($origin['country']) ? strtoupper(trim((string) $origin['country'])) : '';
	if ($country !== '' && in_array($country, waf_ban_origin_countries(isset($settings['waf_ban_origin_countries'])
		? $settings['waf_ban_origin_countries'] : ''), true)) {
		return 'Land ' . $country;
	}
	foreach (array('is_tor' => array('waf_ban_origin_tor', 'Tor'),
		'is_vpn' => array('waf_ban_origin_vpn', 'VPN'),
		'is_hosting' => array('waf_ban_origin_hosting', 'Rechenzentrum')) as $field => $one) {
		if (isset($origin[$field]) && (string) $origin[$field] === 'y'
			&& isset($settings[$one[0]]) && (string) $settings[$one[0]] === 'on') {
			return $one[1];
		}
	}
	return '';
}

/**
 * true while a suspicious origin is blocked at once, even though the automatic
 * only proposes. Without a label nothing happens, so the switch alone never
 * blocks anybody.
 */
function waf_ban_origin_at_once($label, $settings)
{
	return (string) $label !== '' && isset($settings['waf_ban_origin_now'])
		&& (string) $settings['waf_ban_origin_now'] === 'on';
}

/**
 * The addresses that crossed the threshold of at least one website. $groups are
 * the sums of the window with client_ip, parent_domain_id, score, hits and the
 * rule that appeared most; $sites holds the websites by parent_domain_id. One
 * entry per address, naming the website with the most points.
 */
function waf_ban_decide($groups, $settings, $sites, $origins = array())
{
	$picked = array();
	foreach ($groups as $row) {
		$id = (int) $row['parent_domain_id'];
		$site = isset($sites[$id]) ? $sites[$id] : null;
		$limit = waf_ban_site_score($settings, $site);
		$score = (int) $row['score'];
		$ip = (string) $row['client_ip'];
		// A suspicious origin weighs the hits more heavily and may bring a
		// threshold of its own. A website that never triggers stays free: the
		// decision of the operator comes before every criterion.
		$label = $limit > 0
			? waf_ban_origin_match(isset($origins[$ip]) ? $origins[$ip] : null, $settings) : '';
		// The weighted points decide; the real ones go into the reason, so a block
		// never claims more points than the hits brought.
		$factor = 100;
		$weighted = $score;
		if ($label !== '') {
			$factor = max(100, isset($settings['waf_ban_origin_factor']) ? (int) $settings['waf_ban_origin_factor'] : 100);
			$weighted = (int) round($score * $factor / 100);
			$own = isset($settings['waf_ban_origin_score']) ? (int) $settings['waf_ban_origin_score'] : 0;
			if ($own > 0 && $own < $limit) {
				$limit = $own;
			}
		}
		if ($limit <= 0 || $weighted < $limit) {
			continue;
		}
		if (isset($picked[$ip]) && $picked[$ip]['weighted'] >= $weighted) {
			continue;
		}
		$picked[$ip] = array(
			'ip' => $ip,
			'domain' => is_array($site) && isset($site['domain']) ? (string) $site['domain'] : '',
			'score' => $score,
			'weighted' => $weighted,
			'factor' => $factor,
			'hits' => (int) $row['hits'],
			'rule' => isset($row['rule']) ? (string) $row['rule'] : '',
			'limit' => $limit,
			'origin' => $label,
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
	// $now kommt aus der Datenbank; strtotime() und date() nutzen dieselbe Zone,
	// damit die Rechnung genau die Stunden ergibt, die sie soll.
	return date('Y-m-d H:i:s', strtotime((string) $now) + waf_ban_hours($level, $settings) * 3600);
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
	if (isset($pick['origin']) && (string) $pick['origin'] !== '') {
		$reason .= ', Herkunft: ' . $pick['origin'];
		if (isset($pick['factor']) && (int) $pick['factor'] !== 100) {
			$reason .= ', Punkte mit ' . (int) $pick['factor'] . ' % gewertet';
		}
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
 * true when two deny files block the same addresses. The first line carries the
 * time of writing; it alone is no change, or nginx would be tested and reloaded
 * every minute for nothing. A missing file ($have is empty) is never the same:
 * nginx includes it, so it has to exist.
 */
function waf_ban_file_same($have, $want)
{
	if ((string) $have === '') {
		return false;
	}
	$lines = function ($text) {
		$kept = array();
		foreach (explode("
", (string) $text) as $line) {
			$line = trim($line);
			if ($line !== '' && $line[0] !== '#') {
				$kept[] = $line;
			}
		}
		return $kept;
	};
	return $lines($have) === $lines($want);
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
	// The time comes as 2026-09-18T13:54:02+02:00 and belongs to the same clock
	// as the database, so the counter can tell before from after a block.
	if (!preg_match('/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/', (string) $parts[0], $when)) {
		return null;
	}
	return array('ip' => (string) $parts[1], 'at' => $when[1] . ' ' . $when[2]);
}

/**
 * The rule that appeared most in the hits of the window. The four scoring rules
 * of the CRS stand in almost every hit and say nothing about the attack, so
 * they are left out.
 */
function waf_ban_top_rule($rows)
{
	$scoring = array('949110', '959100', '980130', '980140');
	$count = array();
	foreach ($rows as $row) {
		$ids = json_decode(isset($row['rules']) ? (string) $row['rules'] : '', true);
		if (!is_array($ids)) {
			continue;
		}
		foreach ($ids as $id) {
			// A hit stores its rules as objects with id and msg; older rows and the
			// tests also know the bare id.
			if (is_array($id)) {
				$id = isset($id['id']) ? $id['id'] : '';
			}
			$id = trim((string) $id);
			if ($id === '' || in_array($id, $scoring, true)) {
				continue;
			}
			$count[$id] = isset($count[$id]) ? $count[$id] + 1 : 1;
		}
	}
	arsort($count);
	foreach ($count as $id => $seen) {
		return (string) $id;
	}
	return '';
}

/**
 * A new key for the published list: 32 characters from a to f and 0 to 9. The
 * key is the whole protection of that address, so it comes from the strong
 * source of the system.
 */
function waf_ban_token_new()
{
	return bin2hex(random_bytes(16));
}

/** True while a value has the shape of a key; nothing else ever names a path. */
function waf_ban_token_ok($token)
{
	return (bool) preg_match('/^[a-f0-9]{32}$/', (string) $token);
}

/**
 * The published list: one address per line, sorted, without doubles and
 * without comments. That is what a firewall reads as a table of addresses;
 * anything else in the file would end up as an address there.
 */
function waf_ban_list_text($ips)
{
	$seen = array();
	foreach ($ips as $ip) {
		$ip = trim((string) $ip);
		if ($ip === '' || waf_origin_bytes($ip) === '' || isset($seen[$ip])) {
			continue;
		}
		$seen[$ip] = true;
	}
	if (count($seen) === 0) {
		return '';
	}
	$list = array_keys($seen);
	sort($list);
	return implode("\n", $list) . "\n";
}

/**
 * The address the OPNsense fetches. The host is the name the panel was opened
 * under, a port included - the panel of ISPConfig often answers on 8080.
 * Without a usable host or a key there is none.
 */
function waf_ban_list_url($host, $token)
{
	$host = trim((string) $host);
	if (!waf_ban_token_ok($token)
		|| !preg_match('/^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?$/', $host, $parts)) {
		return '';
	}
	if (isset($parts[2]) && ((int) $parts[2] < 1 || (int) $parts[2] > 65535)) {
		return '';
	}
	return 'https://' . $host . '/security/malwatch_waf_ban_url.php?list=' . (string) $token;
}
