<?php

/**
 * Fills an HTML mail template of the addon.
 *
 * The design lives entirely in the template file, so every operator can have
 * their own (conf-custom/mail/, the same place ISPConfig takes its own
 * customised mails from). The template has:
 *
 *   {name}                         a value, escaped for HTML
 *   {name_block} … {/name_block}   a part that appears only when it applies
 *   {finding_block} … {/finding_block}
 *                                  repeated for every reported file, with
 *                                  {f_…} values and blocks inside
 *   {img:logo.png}                 an image from the template's folder,
 *                                  embedded in the mail (cid:)
 *   <!-- malwatch-colors: critical=#…; high=#…; medium=#…; low=#… -->
 *                                  the colour of each severity ({f_color},
 *                                  {worst_color})
 *
 * Every value is text from the scanner, the database or a customer's
 * website and is escaped before it goes in. Nothing of a finding can add
 * markup to the mail.
 */
class malwatch_mail_html
{
	/**
	 * The colours of the severities when a template names none: neutral
	 * tones, readable as a bar or square next to dark text.
	 */
	const FALLBACK_COLORS = array('critical' => '#b42318', 'high' => '#c4320a', 'medium' => '#b54708', 'low' => '#475467');

	/** The image types a template may embed, by file extension. */
	const IMAGE_TYPES = array('png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif');

	/**
	 * Returns array('html' => ..., 'images' => [...], 'missing' => [...]):
	 * the filled template, the images to embed (see malwatch_mailer::build())
	 * and the names of images the template asked for that its folder lacks.
	 *
	 * $vars: the values of the mail ({domain}, {count}, …) as plain text.
	 * $blocks: name => bool for the optional parts (panel, quarantine, more).
	 * $lists: name => list of strings, each shown as one line ({quarantine_list}).
	 * $files: the reported files, see malwatch_actions::finding_files().
	 */
	public static function render($template, array $vars, array $blocks, array $lists, array $files, $dir)
	{
		$colors = self::colors($template);
		$template = preg_replace('/<!--\s*malwatch-colors:.*?-->\s*/s', '', $template);

		// The repeated part first: its values must not be mistaken for the
		// values of the mail around it.
		$template = preg_replace_callback('/\{finding_block\}(.*?)\{\/finding_block\}/s',
			function ($m) use ($files, $colors) {
				$out = '';
				foreach ($files as $file) {
					$out .= self::file_block($m[1], $file, $colors);
				}
				return $out;
			}, $template);

		foreach ($blocks as $name => $keep) {
			$template = self::block($template, $name, (bool) $keep);
		}

		$replace = array();
		foreach ($vars as $name => $value) {
			$replace['{' . $name . '}'] = self::esc($value);
		}
		foreach ($lists as $name => $items) {
			$replace['{' . $name . '}'] = implode('<br>', array_map(array(__CLASS__, 'esc'), (array) $items));
		}
		if (isset($vars['worst'])) {
			$replace['{worst_color}'] = self::color($colors, $vars['worst']);
		}
		$template = strtr($template, $replace);

		$images = array();
		$missing = array();
		$template = preg_replace_callback('/\{img:([A-Za-z0-9][A-Za-z0-9._-]{0,63})\}/',
			function ($m) use (&$images, &$missing, $dir) {
				$name = $m[1];
				$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
				$path = rtrim((string) $dir, '/') . '/' . $name;
				if (!isset(self::IMAGE_TYPES[$ext]) || !is_file($path)) {
					$missing[] = $name;
					return '';
				}
				if (!isset($images[$name])) {
					$images[$name] = array(
						'cid' => 'img' . count($images) . '.' . bin2hex(random_bytes(6)) . '@malwatch',
						'name' => $name,
						'type' => self::IMAGE_TYPES[$ext],
						'data' => (string) file_get_contents($path),
					);
				}
				return 'cid:' . $images[$name]['cid'];
			}, $template);

		return array('html' => $template, 'images' => array_values($images), 'missing' => array_values(array_unique($missing)));
	}

	/** One reported file in the repeated part. */
	private static function file_block($part, array $file, array $colors)
	{
		$part = self::block($part, 'f_why', (string) $file['why'] !== '');
		$part = self::block($part, 'f_advice', (string) $file['advice'] !== '');
		$part = self::block($part, 'f_does', count($file['traits']) > 0);
		$part = self::block($part, 'f_link', (string) $file['link'] !== '');
		return strtr($part, array(
			'{f_severity}' => self::esc($file['severity']),
			'{f_severity_word}' => self::esc($file['severity_word']),
			'{f_color}' => self::color($colors, $file['severity']),
			'{f_path}' => self::esc($file['path']),
			'{f_rules}' => implode('<br>', array_map(array(__CLASS__, 'esc'), $file['rules'])),
			'{f_why}' => self::esc($file['why']),
			'{f_advice}' => self::esc($file['advice']),
			'{f_does}' => implode(' · ', array_map(array(__CLASS__, 'esc'), $file['traits'])),
			'{f_link}' => self::esc($file['link']),
		));
	}

	/**
	 * The colours the template names in its malwatch-colors comment, each a
	 * #rgb or #rrggbb value; the neutral ones for the rest.
	 */
	public static function colors($template)
	{
		$colors = self::FALLBACK_COLORS;
		if (preg_match('/<!--\s*malwatch-colors:(.*?)-->/s', $template, $m)) {
			foreach (explode(';', $m[1]) as $pair) {
				$kv = array_map('trim', explode('=', $pair, 2));
				if (count($kv) === 2 && isset($colors[$kv[0]]) && preg_match('/^#(?:[0-9a-fA-F]{3}){1,2}$/', $kv[1])) {
					$colors[$kv[0]] = strtolower($kv[1]);
				}
			}
		}
		return $colors;
	}

	private static function color(array $colors, $severity)
	{
		return isset($colors[$severity]) ? $colors[$severity] : $colors['low'];
	}

	/** Keeps or drops a {name_block} … {/name_block} part. */
	private static function block($text, $name, $keep)
	{
		$open = '{' . $name . '_block}';
		$close = '{/' . $name . '_block}';
		if ($keep) {
			return str_replace(array($open, $close), '', $text);
		}
		return preg_replace('/' . preg_quote($open, '/') . '.*?' . preg_quote($close, '/') . '/s', '', $text);
	}

	public static function esc($value)
	{
		return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	}
}
