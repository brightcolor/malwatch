<?php

/**
 * Builds the HTML mails of the addon and hands them to the scanner to deliver.
 *
 * ISPConfig's own mailer sends a text or an HTML body, but with images it puts
 * the text part, the HTML part and the images side by side in one
 * multipart/mixed, and a mail program shows all of them. An HTML mail with an
 * embedded logo needs multipart/related around multipart/alternative, so the
 * message is built here and `malwatch send-mail` delivers it - over the same
 * SMTP relay ISPConfig uses (System > Main Config > Mail), or through
 * sendmail when none is set.
 *
 * The SMTP password reaches the scanner in its environment, never on the
 * command line: every user of the machine can read a command line.
 */
class malwatch_mailer
{
	/** Environment variable the scanner reads the SMTP password from. */
	const PASS_ENV = 'MALWATCH_SMTP_PASS';

	/**
	 * A complete message: headers, then the text and, when there is one, the
	 * HTML part as alternatives, with the images next to the HTML.
	 *
	 * $head: from, from_name, to (list), subject, host (for the Message-ID).
	 * $images: list of array('cid' => ..., 'name' => ..., 'type' => ...,
	 * 'data' => ...). Line ends are CRLF throughout.
	 */
	public static function build(array $head, $text, $html, array $images = array())
	{
		$crlf = "\r\n";
		$from = (string) $head['from'];
		$name = isset($head['from_name']) ? trim((string) $head['from_name']) : '';
		$headers = array(
			'From' => $name === '' ? $from : self::encode_header($name) . ' <' . $from . '>',
			'To' => implode(', ', array_map('strval', (array) $head['to'])),
			'Subject' => self::encode_header((string) $head['subject']),
			'Date' => date('r'),
			'Message-ID' => '<' . bin2hex(random_bytes(12)) . '@' . (isset($head['host']) && $head['host'] !== '' ? $head['host'] : 'malwatch') . '>',
			'MIME-Version' => '1.0',
			'Auto-Submitted' => 'auto-generated',
			'X-Mailer' => 'malwatch',
		);

		$text_part = 'Content-Type: text/plain; charset=utf-8' . $crlf
			. 'Content-Transfer-Encoding: quoted-printable' . $crlf . $crlf
			. self::qp($text);

		if ((string) $html === '') {
			$body = $text_part;
		} else {
			$alt = self::boundary();
			$html_part = 'Content-Type: text/html; charset=utf-8' . $crlf
				. 'Content-Transfer-Encoding: quoted-printable' . $crlf . $crlf
				. self::qp($html);
			$body = 'Content-Type: multipart/alternative; boundary="' . $alt . '"' . $crlf . $crlf
				. '--' . $alt . $crlf . $text_part . $crlf
				. '--' . $alt . $crlf . $html_part . $crlf
				. '--' . $alt . '--' . $crlf;
			if (count($images) > 0) {
				$rel = self::boundary();
				$parts = '--' . $rel . $crlf . $body;
				foreach ($images as $image) {
					$file = preg_replace('/[^A-Za-z0-9._-]/', '_', (string) $image['name']);
					$parts .= '--' . $rel . $crlf
						. 'Content-Type: ' . $image['type'] . '; name="' . $file . '"' . $crlf
						. 'Content-ID: <' . $image['cid'] . '>' . $crlf
						. 'Content-Disposition: inline; filename="' . $file . '"' . $crlf
						. 'Content-Transfer-Encoding: base64' . $crlf . $crlf
						. chunk_split(base64_encode((string) $image['data']), 76, $crlf);
				}
				$body = 'Content-Type: multipart/related; boundary="' . $rel . '"; type="multipart/alternative"' . $crlf . $crlf
					. $parts . '--' . $rel . '--' . $crlf;
			}
		}

		$out = '';
		foreach ($headers as $key => $value) {
			$out .= $key . ': ' . $value . $crlf;
		}
		// The body starts with its own Content-Type line, which belongs to the
		// headers; the blank line follows it.
		list($content_type, $rest) = explode($crlf . $crlf, $body, 2);
		$lines = explode($crlf, $content_type);
		return $out . implode($crlf, $lines) . $crlf . $crlf . $rest;
	}

	/**
	 * The arguments for `malwatch send-mail`. $smtp is ISPConfig's mail
	 * configuration (smtp_enabled, smtp_host, smtp_port, smtp_user,
	 * smtp_crypt); $verify 'n' accepts any certificate of the relay.
	 */
	public static function command($binary, $message_file, $from, array $to, array $smtp, $verify)
	{
		$args = array((string) $binary, 'send-mail', '--message=' . $message_file, '--to=' . implode(',', $to));
		if ((string) $from !== '') {
			$args[] = '--from=' . $from;
		}
		if (isset($smtp['smtp_enabled']) && $smtp['smtp_enabled'] === 'y' && trim((string) $smtp['smtp_host']) !== '') {
			$port = isset($smtp['smtp_port']) && (int) $smtp['smtp_port'] > 0 ? (int) $smtp['smtp_port'] : 25;
			$args[] = '--smtp=' . trim((string) $smtp['smtp_host']) . ':' . $port;
			$crypt = isset($smtp['smtp_crypt']) ? (string) $smtp['smtp_crypt'] : '';
			$args[] = '--smtp-tls=' . ($crypt === 'ssl' ? 'tls' : ($crypt === 'tls' ? 'starttls' : 'none'));
			if (isset($smtp['smtp_user']) && (string) $smtp['smtp_user'] !== '') {
				$args[] = '--smtp-user=' . $smtp['smtp_user'];
			}
			if ($verify === 'n') {
				$args[] = '--smtp-insecure';
			}
		}
		return $args;
	}

	/**
	 * Delivers $message through the scanner. Returns '' on success, otherwise
	 * a sentence saying what went wrong, for the action log.
	 */
	public function send($binary, $message, $from, array $to, array $smtp, $verify)
	{
		if ((string) $binary === '' || !is_executable($binary)) {
			return 'Das Programm des Scanners (' . $binary . ') fehlt oder ist nicht ausführbar; die HTML-Mail ließ sich nicht zustellen.';
		}
		$file = tempnam(sys_get_temp_dir(), 'malwatch-mail-');
		if ($file === false) {
			return 'Für die Mail ließ sich keine temporäre Datei anlegen.';
		}
		@chmod($file, 0600);
		if (file_put_contents($file, $message) === false) {
			@unlink($file);
			return 'Die Mail ließ sich nicht in die temporäre Datei schreiben.';
		}

		$env = array('PATH' => getenv('PATH') !== false ? getenv('PATH') : '/usr/sbin:/usr/bin:/sbin:/bin');
		if (isset($smtp['smtp_pass']) && (string) $smtp['smtp_pass'] !== '') {
			$env[self::PASS_ENV] = (string) $smtp['smtp_pass'];
		}
		$process = proc_open(self::command($binary, $file, $from, $to, $smtp, $verify),
			array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, null, $env);
		if (!is_resource($process)) {
			@unlink($file);
			return 'Der Scanner ließ sich für den Versand nicht starten.';
		}
		fclose($pipes[0]);
		$out = stream_get_contents($pipes[1]);
		$err = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$code = proc_close($process);
		@unlink($file);

		if ($code !== 0) {
			$reason = trim((string) $err) !== '' ? trim((string) $err) : trim((string) $out);
			return $reason !== '' ? $reason : 'Der Scanner meldete beim Versand den Rückgabecode ' . $code . '.';
		}
		return '';
	}

	/** A header value in RFC 2047 encoding when it is not plain ASCII. */
	private static function encode_header($value)
	{
		if (preg_match('/^[\x20-\x7e]*$/', $value)) {
			return $value;
		}
		return mb_encode_mimeheader($value, 'UTF-8', 'B', "\r\n");
	}

	/** Quoted-printable with CRLF line ends and lines of at most 76 characters. */
	private static function qp($text)
	{
		$text = str_replace(array("\r\n", "\r"), "\n", (string) $text);
		return quoted_printable_encode(str_replace("\n", "\r\n", $text));
	}

	private static function boundary()
	{
		return '=_malwatch_' . bin2hex(random_bytes(12));
	}
}
