package rules

import "testing"

// A rule that names a PHP construct means code. The same words in a help
// text, a commented out line or the HTML around the tags are prose: Salient
// was reported for "Remember to include "http://"!", PHP_CodeSniffer for the
// commented out eval of its own test files.
func TestConstructsInTextAreNoCode(t *testing.T) {
	e := NewEngine(nil)
	ev := "ev" + "al"
	for _, c := range []struct{ name, rule, src string }{
		{"Hilfetext", "php.include.remote", "<?php $f = array('desc' => __('Remember to include \"http://\"!', 'salient'));"},
		{"Zeilenkommentar", "php.eval.variable", "<?php\n//" + ev + "($string);\n#" + ev + "($string);\n"},
		{"Blockkommentar", "php.eval.variable", "<?php /* " + ev + "($code); */ $a = 1;"},
		{"HTML um die Tags", "php.include.remote", "<?php $a = 1; ?>\n<p>include \"http://example.org/x\"</p>\n"},
		{"Heredoc", "php.eval.variable", "<?php $doc = <<<EOT\nCall " + ev + "($x) only with care.\nEOT;\n"},
	} {
		if hitRules(e, "/web/wp-content/themes/x/a.php", "php", c.src)[c.rule] {
			t.Errorf("%s: %s gemeldet", c.name, c.rule)
		}
	}
}

func TestConstructsInCodeStay(t *testing.T) {
	e := NewEngine(nil)
	ev := "ev" + "al"
	post := "$_PO" + "ST"
	for _, c := range []struct{ name, rule, src string }{
		{"include", "php.include.remote", "<?php include \"http://example.org/x.txt\";"},
		{"eval", "php.eval.variable", "<?php $code = load(); " + ev + "($code);"},
		{"ohne Tag", "php.eval.request", ev + "(" + post + "['x']);"},
		// PHP fills the array element into the string; the quotes inside the
		// braces do not end it.
		{"eingesetzter Wert", "php.eval.request", "<?php $s = \"{$a[\"x\"]}\"; " + ev + "(" + post + "['x']);"},
		{"nach Kommentar", "php.eval.variable", "<?php // " + ev + "($x) is commented\n" + ev + "($y);"},
		// The second view glues comments away; the finding still counts as code.
		{"zusammengesetzter Pfad", "php.include.assembled_path", "<?php @require_once /*-x-*/ $T /*-y-*/ [9+1] . $K[3];"},
	} {
		if !hitRules(e, "/web/x.php", "php", c.src)[c.rule] {
			t.Errorf("%s: %s nicht mehr gemeldet", c.name, c.rule)
		}
	}
}

// A supporting condition of such a rule counts in code as well: a comment that
// mentions curl_exec makes no downloader.
func TestSupportingConditionsCountInCode(t *testing.T) {
	e := NewEngine(nil)
	ev := "ev" + "al"
	src := "<?php\n// uses curl_exec( elsewhere\nfunction w($code) { " + ev + "($code); }\n"
	if hitRules(e, "/web/x.php", "php", src)["php.remote.fetch_eval_indirect"] {
		t.Error("curl_exec im Kommentar zählt als Abruf")
	}
}
