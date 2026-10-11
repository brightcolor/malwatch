<?php

require_once '../../lib/config.inc.php';
require_once '../../lib/app.inc.php';

$app->auth->check_module_permissions('security');
if (!$app->auth->is_admin()) {
	require_once 'lib/malwatch_lib.inc.php';
	malwatch_stop($app, 'stop_admin_only_txt');
}

$app->uses('tpl,functions');
require_once 'lib/malwatch_lib.inc.php';

/**
 * One reported file, laid out for a decision: why each rule reported it,
 * what the file does, and its code with the places that matter marked.
 *
 * id is a finding_id. The page shows every finding of the same file on the
 * same website, because the buttons act on the file, not on one rule hit.
 */
$finding_id = $app->functions->intval(isset($_REQUEST['id']) ? $_REQUEST['id'] : 0);
$finding = $finding_id > 0
	? $app->db->queryOneRecord('SELECT * FROM malwatch_finding WHERE finding_id = ?', $finding_id)
	: null;
if (!is_array($finding)) {
	malwatch_stop($app, 'stop_finding_gone_txt', 'security/malwatch_finding_list.php', 'stop_to_findings_txt');
}
$domain_id = $app->functions->intval($finding['parent_domain_id']);
$path = (string) $finding['file_path'];
$web = $app->db->queryOneRecord('SELECT * FROM web_domain WHERE domain_id = ?', $domain_id);

$message = '';
$error = '';

// --- Actions ---------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$app->auth->csrf_token_check('POST');
	$action = isset($_POST['malwatch_action']) ? (string) $_POST['malwatch_action'] : '';

	if ($action === 'ignore' || $action === 'reopen') {
		$message = malwatch_set_file_state($app, $domain_id, $path, $action === 'ignore' ? 'ignored' : 'open');
	} elseif ($action === 'quarantine') {
		// The same job the site page and the quarantine list queue; the
		// binary checks the path against the website a second time.
		$result = malwatch_queue_quarantine($app, $domain_id, array($path));
		if (is_int($result)) {
			$message = 'Die Datei wird in die Quarantäne verschoben. Sie lässt sich von dort zurückholen oder herunterladen.';
		} else {
			$error = $result;
		}
	}
}

// --- Page ------------------------------------------------------------------
$app->tpl->newTemplate('form.tpl.htm');
$app->tpl->setInclude('content_tpl', 'templates/malwatch_finding_show.htm');

$lng_file = 'lib/lang/' . $app->functions->check_language($_SESSION['s']['language']) . '_malwatch_finding.lng';
if (!file_exists($lng_file)) {
	$lng_file = 'lib/lang/en_malwatch_finding.lng';
}
include $lng_file;
$app->tpl->setVar($wb);
$app->tpl->setVar(malwatch_attr_texts($wb, array('confirm_quarantine_txt', 'quarantine_txt')));

$rows = $app->db->queryAllRecords(
	'SELECT * FROM malwatch_finding WHERE parent_domain_id = ? AND file_path = ? '
	. 'ORDER BY FIELD(finding_state, ?, ?, ?), FIELD(severity, ?, ?, ?, ?)',
	$domain_id, $path, 'open', 'ignored', 'fixed', 'critical', 'high', 'medium', 'low');
$rows = is_array($rows) ? $rows : array($finding);

// The file as a whole: open while any finding is, released when the rest is,
// fixed once every finding is gone from the disk.
$states = array();
foreach ($rows as $row) {
	$states[(string) $row['finding_state']] = true;
}
$file_state = isset($states['open']) ? 'open' : (isset($states['ignored']) ? 'ignored' : 'fixed');

// The view belongs to the content the newest finding saw.
$current = $rows[0];
foreach ($rows as $row) {
	if ((string) $row['last_seen'] > (string) $current['last_seen']) {
		$current = $row;
	}
}
$sha = strtolower((string) $current['file_sha256']);
$file = preg_match('/^[0-9a-f]{64}$/', $sha)
	? $app->db->queryOneRecord('SELECT * FROM malwatch_file WHERE file_sha256 = ?', $sha)
	: null;

// --- Why it was reported ---------------------------------------------------
$marks_by_line = array();
$reasons = array();
$worst = '';
foreach ($rows as $row) {
	$rule = malwatch_rule_explanation($app, $row['rule_id'], $row['engine']);
	$marks = malwatch_decode_marks(isset($row['marks']) ? $row['marks'] : '');
	$class = malwatch_mark_class_severity($row['severity']);
	$lines = array();
	foreach ($marks as $mark) {
		if (strtolower((string) $row['file_sha256']) === $sha) {
			$marks_by_line[$mark['line']][] = array('col' => $mark['col'], 'len' => $mark['len'], 'class' => $class);
		}
		$lines[$mark['line']] = true;
	}
	if (count($marks) === 0 && $app->functions->intval($row['line_number']) > 0) {
		$lines[$app->functions->intval($row['line_number'])] = true;
	}
	ksort($lines);
	$line_links = array();
	foreach (array_slice(array_keys($lines), 0, 12) as $n) {
		$line_links[] = array('n' => $n);
	}
	if (malwatch_severity_rank($row['severity']) > malwatch_severity_rank($worst)) {
		$worst = (string) $row['severity'];
	}
	$reasons[] = array(
		'rule_id' => $app->functions->htmlentities($row['rule_id']),
		'title' => $app->functions->htmlentities(is_array($rule) ? $rule['title'] : ''),
		'explanation' => $app->functions->htmlentities(is_array($rule) ? $rule['explanation'] : ''),
		'advice' => $app->functions->htmlentities(is_array($rule) ? $rule['advice'] : ''),
		'has_explanation' => is_array($rule) && (string) $rule['explanation'] !== '' ? 1 : 0,
		'severity_label' => $app->functions->htmlentities(malwatch_severity_label($wb, $row['severity'])),
		'severity_class' => malwatch_severity_class($row['severity']),
		'engine' => $app->functions->htmlentities($row['engine']),
		'excerpt' => $app->functions->htmlentities($row['excerpt']),
		'state_label' => $app->functions->htmlentities(malwatch_state_label($wb, $row['finding_state'])),
		'is_open' => $row['finding_state'] === 'open' ? 1 : 0,
		'lines' => $line_links,
		'has_lines' => count($line_links) > 0 ? 1 : 0,
		'more_lines' => count($lines) > count($line_links) ? count($lines) - count($line_links) : 0,
		'lines_txt' => $wb['lines_txt'],
		'no_explanation_txt' => $wb['no_explanation_txt'],
		'advice_txt' => $wb['advice_txt'],
		'more_lines_txt' => $wb['more_lines_txt'],
	);
}

// --- What the file does ----------------------------------------------------
$traits = array();
$counts = array('risk' => 0, 'caution' => 0, 'info' => 0, 'guard' => 0);
if (is_array($file)) {
	$decoded = json_decode((string) $file['traits'], true);
	foreach (is_array($decoded) ? $decoded : array() as $trait) {
		if (!is_array($trait) || !isset($trait['kind'], $trait['label'])) {
			continue;
		}
		$kind = isset($counts[$trait['kind']]) ? (string) $trait['kind'] : 'info';
		$counts[$kind]++;
		$class = malwatch_mark_class_trait($kind);
		$lines = array();
		foreach (malwatch_decode_marks(isset($trait['marks']) ? $trait['marks'] : array()) as $mark) {
			$marks_by_line[$mark['line']][] = array('col' => $mark['col'], 'len' => $mark['len'], 'class' => $class);
			$lines[$mark['line']] = true;
		}
		ksort($lines);
		$line_links = array();
		foreach (array_slice(array_keys($lines), 0, 12) as $n) {
			$line_links[] = array('n' => $n);
		}
		$traits[] = array(
			'label' => $app->functions->htmlentities($trait['label']),
			'kind' => $kind,
			'kind_label' => $app->functions->htmlentities($wb['trait_' . $kind . '_txt']),
			'lines' => $line_links,
			'has_lines' => count($line_links) > 0 ? 1 : 0,
			'lines_txt' => $wb['lines_txt'],
		);
	}
}

// --- The code --------------------------------------------------------------
$code_rows = array();
if (is_array($file) && (string) $file['view'] !== '') {
	$view = json_decode((string) $file['view'], true);
	$code_rows = malwatch_code_rows(is_array($view) ? $view : array(), $marks_by_line);
	foreach ($code_rows as $i => $row) {
		$code_rows[$i]['skipped_label'] = sprintf($wb['skipped_lines_txt'], $row['skipped']);
	}
}

$base = is_array($web) ? malwatch_scan_path($web) : '';
$parts = malwatch_split_path($path, $base);

$app->tpl->setVar('finding_id', $finding_id);
$app->tpl->setVar('domain_id', $domain_id);
$app->tpl->setVar('domain', $app->functions->htmlentities(malwatch_display_domain($finding['domain'])));
$app->tpl->setVar('dir', $app->functions->htmlentities($parts['dir']));
$app->tpl->setVar('file', $app->functions->htmlentities($parts['file']));
$app->tpl->setVar('full_path', $app->functions->htmlentities($parts['full']));
$app->tpl->setVar('has_dir', $parts['dir'] !== '' ? 1 : 0);
$app->tpl->setVar('size', $app->functions->htmlentities(malwatch_bytes($current['file_size'])));
$app->tpl->setVar('mtime', $app->functions->htmlentities(malwatch_datetime($current['file_mtime'])));
$app->tpl->setVar('first_seen', $app->functions->htmlentities(malwatch_datetime($finding['first_seen'])));
$app->tpl->setVar('last_seen', $app->functions->htmlentities(malwatch_datetime($current['last_seen'])));
$app->tpl->setVar('sha256', $app->functions->htmlentities($sha));
$app->tpl->setVar('sha256_short', $app->functions->htmlentities(substr($sha, 0, 12)));
$app->tpl->setVar('state_label', $app->functions->htmlentities(malwatch_state_label($wb, $file_state)));
$app->tpl->setVar('state_open', $file_state === 'open' ? 1 : 0);
$app->tpl->setVar('state_ignored', $file_state === 'ignored' ? 1 : 0);
$app->tpl->setVar('state_fixed', $file_state === 'fixed' ? 1 : 0);
$app->tpl->setVar('worst_label', $app->functions->htmlentities(malwatch_severity_label($wb, $worst)));
$app->tpl->setVar('worst_class', malwatch_severity_class($worst));
// The legend shows a rule hit the way the code marks it: in the colour of the
// worst severity on the page.
$app->tpl->setVar('legend_rule_class', malwatch_mark_class_severity($worst));
// The next open file of the same website, the worst first: after deciding on
// one file the operator goes on to the next without the detour over the list.
$next = $app->db->queryOneRecord(
	"SELECT finding_id FROM malwatch_finding WHERE parent_domain_id = ? AND finding_state = 'open' AND file_path != ? "
	. "ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'), last_seen DESC, finding_id DESC LIMIT 1",
	$domain_id, (string) $path);
$app->tpl->setVar('next_finding_id', is_array($next) ? $app->functions->intval($next['finding_id']) : 0);
malwatch_set_loop($app, 'reasons', $reasons);
malwatch_set_loop($app, 'traits', $traits);
$app->tpl->setVar('has_traits', count($traits) > 0 ? 1 : 0);
$app->tpl->setVar('traits_summary', $app->functions->htmlentities(sprintf($wb['traits_summary_txt'],
	$counts['risk'], $counts['caution'], $counts['guard'])));
malwatch_set_loop($app, 'code_rows', $code_rows);
$app->tpl->setVar('has_code', count($code_rows) > 0 ? 1 : 0);
$app->tpl->setVar('has_file', is_array($file) ? 1 : 0);
$app->tpl->setVar('file_binary', is_array($file) && $file['kind'] === 'binary' ? 1 : 0);
$app->tpl->setVar('file_whole', is_array($file) && $file['whole'] === 'y' ? 1 : 0);
$app->tpl->setVar('file_omitted', is_array($file) && $file['omitted'] === 'y' ? 1 : 0);
$app->tpl->setVar('file_lines', is_array($file) ? $app->functions->intval($file['line_count']) : 0);
$app->tpl->setVar('code_part_txt', sprintf($wb['code_part_txt'], count($code_rows),
	is_array($file) ? $app->functions->intval($file['line_count']) : 0));
$app->tpl->setVar('message', $app->functions->htmlentities($message));
$app->tpl->setVar('error', $app->functions->htmlentities($error));

$csrf = $app->auth->csrf_token_get('malwatch_finding_show');
$app->tpl->setVar('_csrf_id', $csrf['csrf_id']);
$app->tpl->setVar('_csrf_key', $csrf['csrf_key']);

$app->tpl_defaults();
$app->tpl->pparse();
