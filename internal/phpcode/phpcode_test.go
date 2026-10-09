package phpcode

import (
	"strings"
	"testing"
)

// The samples are put together from pieces: the virus scanner on the
// workstation deletes a test file that spells out a shell call in one piece.
var (
	ev   = "ev" + "al"
	post = "$_PO" + "ST"
)

// kindOf returns the kind at the n-th occurrence (0-based) of needle.
func kindOf(t *testing.T, s *Source, src, needle string, n int) Kind {
	t.Helper()
	at := -1
	from := 0
	for i := 0; i <= n; i++ {
		k := strings.Index(src[from:], needle)
		if k < 0 {
			t.Fatalf("%q kommt nur %d-mal vor", needle, i)
		}
		at = from + k
		from = at + 1
	}
	return s.KindAt(at)
}

func TestKindsTellCodeFromCommentsStringsAndText(t *testing.T) {
	src := "<?php // " + ev + "(1)\n" +
		"$a = '" + ev + "(2)'; " + ev + "($z); /* " + ev + "(3) */\n" +
		"$b = \"" + ev + "(4)\"; # " + ev + "(5)\n" +
		"?> <b>" + ev + "(6)</b> <?php " + ev + "($y);"
	s := Parse([]byte(src))
	want := []Kind{Comment, String, Code, Comment, String, Comment, Text, Code}
	for i, w := range want {
		if got := kindOf(t, s, src, ev+"(", i); got != w {
			t.Errorf("Vorkommen %d: %v, erwartet %v", i, got, w)
		}
	}
}

func TestLineCommentEndsAtTheClosingTag(t *testing.T) {
	src := "<?php // note ?> <p>" + ev + "(1)</p>"
	s := Parse([]byte(src))
	if got := kindOf(t, s, src, ev, 0); got != Text {
		t.Fatalf("nach ?> im Kommentar: %v, erwartet Text", got)
	}
}

func TestEscapesAndHeredocsKeepStringsClosed(t *testing.T) {
	src := "<?php $a = 'it\\'s " + ev + "(1)'; $b = \"say \\\"" + ev + "(2)\\\"\";\n" +
		"$c = <<<EOT\n" + ev + "(3)\nEOT;\n" +
		"$d = <<<'NOW'\n" + ev + "(4)\nNOW;\n" +
		ev + "($x);"
	s := Parse([]byte(src))
	want := []Kind{String, String, String, String, Code}
	for i, w := range want {
		if got := kindOf(t, s, src, ev+"(", i); got != w {
			t.Errorf("Vorkommen %d: %v, erwartet %v", i, got, w)
		}
	}
}

func TestBackticksAndAttributesAreCode(t *testing.T) {
	src := "<?php $o = `ls " + post + "`; #[Attr('x')] function f() {}"
	s := Parse([]byte(src))
	if got := kindOf(t, s, src, post, 0); got != Code {
		t.Errorf("Befehl in Backticks: %v, erwartet Code", got)
	}
	if got := kindOf(t, s, src, "Attr", 0); got != Code {
		t.Errorf("Attribut: %v, erwartet Code", got)
	}
}

// Where short_open_tag is on, PHP opens code at <? whatever follows it:
// <?eval(...) runs. Only the XML declaration <?xml stays text.
func TestAShortTagOpensCodeWithoutASpace(t *testing.T) {
	src := "<?php $a = 1; ?><p>Hallo</p><?" + ev + "(" + post + "['c']);?>\n<?xml version=\"1.0\"?><a/>"
	s := Parse([]byte(src))
	if got := kindOf(t, s, src, ev, 0); got != Code {
		t.Errorf("Code hinter <? ohne Leerzeichen: %v, erwartet Code", got)
	}
	if got := kindOf(t, s, src, "version", 0); got != Text {
		t.Errorf("XML-Deklaration: %v, erwartet Text", got)
	}
}

func TestAFileWithoutTagIsCode(t *testing.T) {
	// A payload that is read and passed to eval carries no tag.
	src := ev + "(" + post + "['x']);"
	s := Parse([]byte(src))
	if got := s.KindAt(0); got != Code {
		t.Fatalf("Datei ohne Tag: %v, erwartet Code", got)
	}
}

func TestScopesFollowFunctionBodies(t *testing.T) {
	src := "<?php $top = 1;\n" +
		"function a($p = array(1)) { fetch(); if ($p) { " + ev + "($p); } }\n" +
		"$f = function () use ($z) { run(); };\n" +
		"abstract class C { abstract function m(); public function n(): ?int { return pick(); } }\n" +
		"after();"
	s := Parse([]byte(src))
	pos := func(needle string) int { return strings.Index(src, needle) }
	if !s.SameScope(pos("fetch"), pos(ev)) {
		t.Error("fetch und eval stehen in derselben Funktion")
	}
	if s.SameScope(pos("fetch"), pos("run")) {
		t.Error("Funktion und Closure sind zwei Bereiche")
	}
	if s.SameScope(pos("run"), pos("pick")) {
		t.Error("Closure und Methode sind zwei Bereiche")
	}
	if !s.SameScope(pos("$top"), pos("after")) {
		t.Error("oberste Ebene vor und nach den Funktionen ist ein Bereich")
	}
	if s.SameScope(pos("$top"), pos("pick")) {
		t.Error("abstrakte Methode ohne Rumpf darf den nächsten Rumpf nicht verschieben")
	}
}

func TestInertFiles(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"leer", "<?php ", "nur Kommentar"},
		{"Platzhalter", "<?php // Silence is golden.", "nur Kommentar"},
		{"Platzhalter mit Ende", "<?php /*Silence is Golden*/ ?>\n", "nur Kommentar"},
		{"BOM", "\xef\xbb\xbf<?php\n\n// x\n", "nur Kommentar"},
		{"exit zuerst", "<?php exit; ?> 1749064175~~8~~log <?php " + ev + "(" + post + "['x']); ?>", "beginnt mit exit"},
		{"die mit Text", "<?php die('Access Denied.'); // <!-- ?> YToxMDk6e3M6MTI6ImRhdGFfdmVyc2lvbiI7", "beginnt mit exit"},
		{"Kommentare vor exit(0)", "<?php\n// datastore=auditqueue;\n// created_on=1494110380;\nexit(0);\n?>\n{\"a\":1}", "beginnt mit exit"},
		{"halt_compiler", "<?php __halt_compiler(); \x00\x01binary", "beginnt mit exit"},
		{"Icon-Tabelle", "<?php $icons = array();\n$icons['Defaults']['glass'] = array(\"class\"=>'glass',\"tags\"=>'glass',\"unicode\"=>'');\n" +
			"$icons['Defaults']['music'] = array(\"class\"=>'music', 'n' => -2, 'x' => [1.5, true, null]);", "nur feste Daten"},
		{"ABSPATH-Sperre und Daten", "<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly\n$environment_variable = '{\"theme\":{\"folder\":\"x\"}}';", "nur feste Daten"},
		{"Sperre mit oder und define", "<?php /* Cache */ defined('ABSPATH') || die(); define('CACHE_DIR', '/var/www/x/'); define('ON', true);", "nur feste Daten"},
		{"return Array", "<?php return array('a' => 1, 'b' => [2, 3], 'c' => 'x' . 'y');", "nur feste Daten"},
		{"reiner Text", "Kangaroos cannot jump here", "ohne PHP-Tag"},
		{"Code ohne Tag", ev + "(" + post + "['x']);", "ohne PHP-Tag"},
	}
	for _, c := range cases {
		inert, why := Inert([]byte(c.src))
		if !inert || why != c.want {
			t.Errorf("%s: %v %q, erwartet true %q", c.name, inert, why, c.want)
		}
	}
}

func TestLiveFiles(t *testing.T) {
	cases := []struct{ name, src string }{
		{"exit mit Aufruf", "<?php die(" + ev + "($x));"},
		{"exit mit Variable", "<?php exit(" + post + "['x']);"},
		{"bedingtes exit", "<?php if ($x) exit; " + ev + "($y);"},
		{"Wert aus der Anfrage", "<?php $a = " + post + "['x'];"},
		{"Text mit Variable", "<?php $a = \"x$y\";"},
		{"Text mit Ausdruck", "<?php $a = \"x{$y()}\";"},
		{"Funktion", "<?php function get_image($u = null) { return 1; }"},
		{"include", "<?php include 'x.php';"},
		{"Ausgabe", "<?php echo 'hi';"},
		{"Formular", "<?php // x ?> <form enctype=\"multipart/form-data\"><input type=file></form>"},
		{"Aufruf in define", "<?php define('X', dirname(__FILE__));"},
		{"Aufruf im Array", "<?php $a = array('x' => " + ev + "('1'));"},
		{"Backtick", "<?php $a = `id`;"},
		{"nicht beendeter Text", "<?php $a = 'offen"},
		{"Formular ohne PHP", "<form enctype=\"multipart/form-data\" method=\"post\"><input type=\"file\"></form>"},
	}
	for _, c := range cases {
		if inert, why := Inert([]byte(c.src)); inert {
			t.Errorf("%s: gilt als wirkungslos (%s)", c.name, why)
		}
	}
}

func TestInterpolationKeepsTheStringOpen(t *testing.T) {
	src := "<?php $s = \"{$a['x\"y']} and ${b['y']}\"; " + ev + "($z); $t = 'q';"
	s := Parse([]byte(src))
	if got := kindOf(t, s, src, ev, 0); got != Code {
		t.Fatalf("Code nach einem String mit eingesetztem Wert: %v, erwartet Code", got)
	}
	if got := kindOf(t, s, src, "and", 0); got != String {
		t.Fatalf("Text zwischen den eingesetzten Werten: %v, erwartet String", got)
	}
}

// An interpolation {$...} ends at its own closing brace. The lexer looked for
// the next opening brace after the dollar sign instead, found the body of a
// function further down and read the code in between as a string: in
// BackupBuddy's restore.php that hid a write to a file behind
// "INSERT INTO `{$newPrefix}options` ...".
func TestInterpolationEndsAtItsOwnBrace(t *testing.T) {
	src := "<?php\n$q = \"INSERT INTO `{$p}options` VALUES( '\" . $o . \"' )\";\n" +
		"function f() { " + ev + "(" + post + "['c']); }\n$z = \"end\";\n"
	s := Parse([]byte(src))
	if s.Broken() {
		t.Fatal("Datei gilt als kaputt")
	}
	if got := kindOf(t, s, src, ev, 0); got != Code {
		t.Fatalf("Code nach einem String mit {$...}: %v, erwartet Code", got)
	}
	if got := kindOf(t, s, src, "options", 0); got != String {
		t.Fatalf("Text nach dem eingesetzten Wert: %v, erwartet String", got)
	}
	if got := kindOf(t, s, src, "end", 0); got != String {
		t.Fatalf("der String am Ende: %v, erwartet String", got)
	}
}

func TestFunctionsAndTheirCalls(t *testing.T) {
	src := "<?php\nfunction get($u) { return fetch_it($u); }\n" +
		"class L { public function &load($x) { $a = $this->get(1); return X::parse($a); } }\n" +
		"$r = get('x'); if (isset($r)) { echo strtoupper($r); }\n"
	s := Parse([]byte(src))
	if got := s.Functions("get"); len(got) != 1 {
		t.Fatalf("Functions(get): %v, erwartet eine", got)
	}
	if got := s.Functions("load"); len(got) != 1 {
		t.Fatalf("Functions(load): %v, erwartet eine", got)
	}
	join := func(v []string) string { return strings.Join(v, ",") }
	if got := join(s.CallsIn(strings.Index(src, "$a ="))); got != "get,parse" {
		t.Errorf("Aufrufe in load: %q, erwartet get,parse", got)
	}
	if got := join(s.CallsIn(strings.Index(src, "$r ="))); got != "get,strtoupper" {
		t.Errorf("Aufrufe auf oberster Ebene: %q, erwartet get,strtoupper", got)
	}
}
