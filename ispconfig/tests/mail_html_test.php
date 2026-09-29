<?php
/**
 * Checks the HTML mail (0.40.0): filling a template, escaping, the optional
 * parts, severity colours, embedded images, the MIME message and the command
 * that hands it to the scanner.
 *
 *   php ispconfig/tests/mail_html_test.php
 *
 * Markup in the samples is put together from pieces, see finding_view_test.php.
 */
require __DIR__ . '/../server/lib/classes/malwatch_helper.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_actions.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_mailer.inc.php';
require __DIR__ . '/../server/lib/classes/malwatch_mail_html.inc.php';

$failures = 0;

function expect_same($name, $got, $want)
{
	global $failures;
	if ($got !== $want) {
		$failures++;
		fwrite(STDERR, 'FAIL ' . $name . ': ' . var_export($got, true) . ', erwartet ' . var_export($want, true) . "\n");
	}
}

$lt = '<';
$file = array(
	'path' => 'wp-content/uploads/' . $lt . 'b>x.php',
	'severity' => 'critical',
	'severity_word' => 'kritisch',
	'rules' => array('Titel (php.eval.request)', 'zweite ' . $lt . 'i>Regel'),
	'why' => 'Weil "es" & so',
	'advice' => '',
	'traits' => array('führt Befehle aus', 'liest Anfragedaten'),
	'link' => 'https://panel.example.de:8080/index.php#malwatch-finding-7',
);

// --- Filling a template ---------------------------------------------------------
$template = '<!-- malwatch-colors: critical=#D61F7A; high=#fed329; medium=nope -->'
	. '<p>{domain} {worst_color}</p>'
	. '{finding_block}<div style="border-color:{f_color}">{f_severity_word} {f_path} {f_rules}'
	. '{f_why_block}<em>{f_why}</em>{/f_why_block}{f_advice_block}<u>{f_advice}</u>{/f_advice_block}'
	. '{f_does_block}<s>{f_does}</s>{/f_does_block}{f_link_block}<a href="{f_link}">x</a>{/f_link_block}</div>{/finding_block}'
	. '{panel_block}<b>panel</b>{/panel_block}{quarantine_block}<q>{quarantine_list}</q>{/quarantine_block}'
	. '<img src="{img:logo.png}"><img src="{img:fehlt.png}"><img src="{img:../etc.png}">';
$dir = sys_get_temp_dir() . '/mw-mail-test-' . getmypid();
@mkdir($dir);
file_put_contents($dir . '/logo.png', "\x89PNG\r\n\x1a\nfake");
$out = malwatch_mail_html::render($template,
	array('domain' => 'a' . $lt . 'b.de', 'worst' => 'critical'),
	array('panel' => false, 'quarantine' => true),
	array('quarantine_list' => array('eins.php', 'zwei' . $lt . '.php')),
	array($file, array_merge($file, array('severity' => 'low', 'why' => '', 'traits' => array(), 'link' => ''))),
	$dir);
$html = $out['html'];

expect_same('the colours comment is gone', strpos($html, 'malwatch-colors'), false);
expect_same('template colour, lower case', strpos($html, 'border-color:#d61f7a') !== false, true);
expect_same('severity without a colour of the template gets the neutral one', strpos($html, 'border-color:' . malwatch_mail_html::FALLBACK_COLORS['low']) !== false, true);
expect_same('worst colour', strpos($html, '#d61f7a</p>') !== false, true);
expect_same('values are escaped', array(strpos($html, 'a&lt;b.de'), strpos($html, '&lt;b&gt;x.php') !== false,
	strpos($html, 'zweite &lt;i&gt;Regel') !== false, strpos($html, 'Weil &quot;es&quot; &amp; so') !== false),
	array(3, true, true, true));
expect_same('no markup of a finding survives', array(strpos($html, $lt . 'b>x'), strpos($html, $lt . 'i>Regel')), array(false, false));
expect_same('two files, two blocks', substr_count($html, 'border-color:'), 2);
expect_same('why only where there is one', substr_count($html, $lt . 'em>'), 1);
expect_same('advice left out when empty', strpos($html, $lt . 'u>'), false);
expect_same('traits joined', strpos($html, 'führt Befehle aus · liest Anfragedaten') !== false, true);
expect_same('link only where there is one', substr_count($html, 'href="https://panel.example.de:8080/index.php#malwatch-finding-7"'), 1);
expect_same('panel part left out', strpos($html, 'panel' . $lt . '/b>'), false);
expect_same('quarantine list, one per line, escaped', strpos($html, 'eins.php' . $lt . 'br>zwei&lt;.php') !== false, true);
expect_same('one image embedded', count($out['images']), 1);
expect_same('image referenced by its cid', strpos($html, 'src="cid:' . $out['images'][0]['cid'] . '"') !== false, true);
expect_same('image type and content', array($out['images'][0]['type'], substr($out['images'][0]['data'], 1, 3)), array('image/png', 'PNG'));
expect_same('missing image reported, path outside the folder refused', $out['missing'], array('fehlt.png'));
expect_same('a name with a path is no image', strpos($html, '{img:../etc.png}') !== false, true);

// The shipped templates are complete: every value and block they use is one
// the addon fills.
foreach (array('de', 'en') as $lang) {
	$tpl = file_get_contents(__DIR__ . '/../server/conf/malwatch_notification_' . $lang . '.html');
	$filled = malwatch_mail_html::render($tpl,
		array('subject' => 's', 'preheader' => 'p', 'domain' => 'd', 'hostname' => 'h', 'scan_time' => 't', 'scan_path' => '/x',
			'count' => '1', 'file_count' => '1', 'worst' => 'high', 'worst_word' => 'hoch', 'files_scanned' => '5', 'outdated' => '0',
			'panel_url' => 'https://p/index.php', 'quarantine_count' => '0', 'more_count' => '0'),
		array('panel' => true, 'quarantine' => false, 'more' => false), array('quarantine_list' => array()), array($file), $dir);
	expect_same($lang . ': no placeholder left', preg_match('/\{[a-z_\/]+\}/', $filled['html'], $m) ? $m[0] : '', '');
	expect_same($lang . ': no image asked for', $filled['missing'], array());
}

// --- The MIME message -------------------------------------------------------------
$message = malwatch_mailer::build(array(
	'from' => 'malwatch@example.com', 'from_name' => 'bright color', 'to' => array('admin@example.com'),
	'subject' => 'malwatch: 2 neue Funde auf beispiel.de – kritisch', 'host' => 'server.example.com',
), "Text mit Umlauten äöü\nzweite Zeile", '<p>' . str_repeat('lang ', 400) . '</p>', $out['images']);
list($head, $body) = explode("\r\n\r\n", $message, 2);
expect_same('headers in CRLF', strpos($message, "\n") === strpos($message, "\r\n") + 1, true);
expect_same('no bare LF', preg_match("/[^\r]\n/", $message), 0);
expect_same('from with name', strpos($head, "From: bright color <malwatch@example.com>\r\n") !== false, true);
preg_match('/^Subject: (.*(?:\r\n[ \t].*)*)/m', $head, $subject_line);
expect_same('subject encoded and readable again', array(preg_match('/[\x80-\xff]/', $subject_line[1]),
	mb_decode_mimeheader($subject_line[1])), array(0, 'malwatch: 2 neue Funde auf beispiel.de – kritisch'));
expect_same('related around alternative', preg_match('/^Content-Type: multipart\/related; boundary="([^"]+)"; type="multipart\/alternative"/m', $head), 1);
expect_same('text and html as alternatives', array(strpos($body, 'Content-Type: multipart/alternative') !== false,
	strpos($body, 'Content-Type: text/plain; charset=utf-8') !== false, strpos($body, 'Content-Type: text/html; charset=utf-8') !== false),
	array(true, true, true));
expect_same('image part with its cid', strpos($body, 'Content-ID: <' . $out['images'][0]['cid'] . '>') !== false, true);
$long = array_filter(explode("\r\n", $message), function ($line) {
	return strlen($line) > 998;
});
expect_same('no line over the SMTP limit', count($long), 0);
expect_same('umlauts survive quoted-printable', strpos(quoted_printable_decode($body), 'Text mit Umlauten äöü') !== false, true);
$plain = malwatch_mailer::build(array('from' => 'a@b.c', 'to' => array('d@e.f'), 'subject' => 'x'), 'nur Text', '');
expect_same('text only', array(strpos($plain, 'multipart'), strpos($plain, "Content-Type: text/plain; charset=utf-8\r\n") !== false), array(false, true));

// --- The command for the scanner -----------------------------------------------------
$smtp = array('smtp_enabled' => 'y', 'smtp_host' => 'mx.example.com', 'smtp_port' => '25', 'smtp_user' => 'relay',
	'smtp_pass' => 'streng-geheim', 'smtp_crypt' => 'tls');
$args = malwatch_mailer::command('/usr/local/bin/malwatch', '/tmp/m.eml', 'a@b.c', array('x@y.z', 'u@v.w'), $smtp, 'y');
expect_same('command with STARTTLS', $args, array('/usr/local/bin/malwatch', 'send-mail', '--message=/tmp/m.eml', '--to=x@y.z,u@v.w',
	'--from=a@b.c', '--smtp=mx.example.com:25', '--smtp-tls=starttls', '--smtp-user=relay'));
expect_same('the password is never an argument', strpos(implode(' ', $args), 'streng-geheim'), false);
$args = malwatch_mailer::command('/b', '/m', '', array('x@y.z'), array_merge($smtp, array('smtp_crypt' => 'ssl', 'smtp_port' => '')), 'n');
expect_same('ssl, default port, no check', array_slice($args, 3), array('--to=x@y.z', '--smtp=mx.example.com:25', '--smtp-tls=tls', '--smtp-user=relay', '--smtp-insecure'));
$args = malwatch_mailer::command('/b', '/m', 'a@b.c', array('x@y.z'), array('smtp_enabled' => 'n', 'smtp_host' => 'mx'), 'y');
expect_same('sendmail when ISPConfig uses none', $args, array('/b', 'send-mail', '--message=/m', '--to=x@y.z', '--from=a@b.c'));
$mailer = new malwatch_mailer();
expect_same('missing binary', strpos($mailer->send('/nirgends/malwatch', 'x', 'a@b.c', array('d@e.f'), $smtp, 'y'), 'fehlt oder ist nicht ausführbar') !== false, true);

// --- The mail of a scan ----------------------------------------------------------------
class mail_html_under_test extends malwatch_actions
{
	protected function rule_row($rule_id, $engine)
	{
		return array('title' => 'Titel von ' . $rule_id, 'explanation' => 'Erklärung', 'advice' => 'Rat');
	}

	protected function trait_labels($sha)
	{
		return array('prüft die Rechte des Benutzers');
	}
}
$findings = array();
for ($i = 1; $i <= malwatch_actions::MAIL_FILES_MAX + 3; $i++) {
	$findings[] = array('finding_id' => $i, 'file_path' => '/var/www/x/web/f' . $i . '.php', 'severity' => $i === 5 ? 'critical' : 'medium',
		'rule_id' => 'r' . $i, 'engine' => 'heuristic', 'file_sha256' => '');
}
$mail = new mail_html_under_test();
$rendered = $mail->render_html(__DIR__ . '/../server/conf/malwatch_notification_de.html', 'de',
	array('domain' => 'beispiel.de', 'scan_path' => '/var/www/x/web', 'finished_at' => '2026-09-29 18:20:53', 'files_scanned' => '100', 'count_outdated' => '0'),
	$findings, 'critical', array(), 'Betreff', array('panel_url' => 'https://panel.example.de:8080/'));
$html = $rendered['html'];
expect_same('the worst file first', strpos($html, 'f5.php') < strpos($html, 'f1.php'), true);
expect_same('at most MAIL_FILES_MAX files', substr_count($html, '#malwatch-finding-'), malwatch_actions::MAIL_FILES_MAX);
expect_same('the rest counted', strpos($html, '… und 3 weitere Datei(en).') !== false, true);
expect_same('link to the finding', strpos($html, 'https://panel.example.de:8080/index.php#malwatch-finding-5') !== false, true);
expect_same('title and explanation', array(strpos($html, 'Titel von r5 (r5)') !== false, strpos($html, 'Erklärung') !== false), array(true, true));

@unlink($dir . '/logo.png');
@rmdir($dir);
if ($failures > 0) {
	exit(1);
}
echo "mail html OK\n";
