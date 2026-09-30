package phpcode

import (
	"strings"
	"testing"
)

// ownCodeAt reports OwnCode for the n-th eval (0-based) of src.
func ownCodeAt(t *testing.T, src string, n int) bool {
	t.Helper()
	at, from := -1, 0
	for i := 0; i <= n; i++ {
		k := strings.Index(src[from:], ev)
		if k < 0 {
			t.Fatalf("%s kommt nur %d-mal vor", ev, i)
		}
		at = from + k
		from = at + 1
	}
	return Parse([]byte(src)).OwnCode(at)
}

// The wrapper builder of phpxmlrpc 2.x, cut down: it writes the source of a
// new function from its own text, the reflected parameters and a few settings
// of the library, and evaluates it. SeedProd ships it; on 2026-09-29 the rule
// php.eval.variable reported it on nine websites.
var xmlrpcWrapPHP = "<?php\n" +
	"function wrap_php_function($funcname, $newfuncname = '', $extra_options = array())\n{\n" +
	"\t$prefix = isset($extra_options['prefix']) ? $extra_options['prefix'] : 'xmlrpc';\n" +
	"\tif ($newfuncname == '') {\n" +
	"\t\tif (is_array($funcname)) { $xmlrpcfuncname = \"{$prefix}_\" . implode('_', $funcname); }\n" +
	"\t\telse { $xmlrpcfuncname = \"{$prefix}_$funcname\"; }\n" +
	"\t} else {\n\t\t$xmlrpcfuncname = $newfuncname;\n\t}\n" +
	"\twhile (function_exists($xmlrpcfuncname)) { $xmlrpcfuncname .= 'x'; }\n" +
	"\t$code = \"function $xmlrpcfuncname(\\$msg) {\\n\";\n" +
	"\t$func =& new ReflectionFunction($funcname);\n" +
	"\t$returns = $GLOBALS['xmlrpcValue'];\n" +
	"\t$params = $func->getParameters();\n" +
	"\t$innercode = '';\n\t$i = 0;\n\t$pars = array();\n" +
	"\tforeach ($params as $param) {\n" +
	"\t\t$innercode .= \"\\$p$i = \\$msg->getParam($i);\\n\";\n" +
	"\t\t$innercode .= \"if (\\$p{$i}->kindOf() == 'scalar') \\$p$i = \\$p{$i}->scalarval(); else \\$p$i = php_xmlrpc_decode(\\$p$i);\\n\";\n" +
	"\t\t$pars[] = \"\\$p$i\";\n\t\t$i++;\n\t}\n" +
	"\t$innercode = \"\\$paramcount = \\$msg->getNumParams();\\n\" .\n" +
	"\t\t\"if (\\$paramcount < $i) return new xmlrpcresp(0, {$GLOBALS['xmlrpcerr']['incorrect_params']}, '{$GLOBALS['xmlrpcstr']['incorrect_params']}');\\n\" . $innercode;\n" +
	"\t$innercode .= \"if (\\$paramcount == \" . count($pars) . \") \\$retval = $funcname(\" . implode(',', $pars) . \"); else\\n\";\n" +
	"\t$innercode .= \"return new xmlrpcresp(new xmlrpcval(\\$retval, '$returns'));\";\n" +
	"\t$code = $code . $innercode . \"\\n}\\n \\$allOK=1;\";\n" +
	"\t$allOK = 0;\n" +
	"\t" + ev + "($code);\n" +
	"\tif (!$allOK) { return false; }\n" +
	"\treturn $xmlrpcfuncname;\n}\n"

// The client side of the same library: it asks a server for the signature
// of a method and writes a function that calls it. The values of the server
// only ever land in quotes of the written code.
var xmlrpcWrapRemote = "<?php\n" +
	"function wrap_xmlrpc_method($client, $methodname, $signum = 0, $timeout = 0, $protocol = '', $newfuncname = '')\n{\n" +
	"\t$msg =& new xmlrpcmsg('system.methodSignature');\n" +
	"\t$msg->addparam(new xmlrpcval($methodname));\n" +
	"\t$response =& $client->send($msg, $timeout, $protocol);\n" +
	"\tif (!$response || $response->faultCode()) { return false; }\n" +
	"\t$desc = $response->value();\n" +
	"\tif ($newfuncname != '') { $xmlrpcfuncname = $newfuncname; }\n" +
	"\telse { $xmlrpcfuncname = 'xmlrpc_'.str_replace('.', '_', $methodname); }\n" +
	"\t$desc = $desc->arraymem($signum);\n" +
	"\t$code = \"function $xmlrpcfuncname (\";\n" +
	"\t$innercode = \"\\$client =& new xmlrpc_client('$client->path', '$client->server');\\n\";\n" +
	"\tforeach ($client as $fld => $val) {\n" +
	"\t\tif ($fld != 'debug' && $fld != 'return_type') {\n" +
	"\t\t\t$val = var_export($val, true);\n" +
	"\t\t\t$innercode .= \"\\$client->$fld = $val;\\n\";\n\t\t}\n\t}\n" +
	"\t$innercode .= \"\\$msg =& new xmlrpcmsg('$methodname');\\n\";\n" +
	"\t$plist = array();\n\t$pcount = $desc->arraysize();\n" +
	"\tfor ($i = 1; $i < $pcount; $i++) {\n" +
	"\t\t$plist[] = \"\\$p$i\";\n" +
	"\t\t$ptype = $desc->arraymem($i);\n\t\t$ptype = $ptype->scalarval();\n" +
	"\t\tif ($ptype == 'dateTime.iso8601' || $ptype == 'base64') {\n" +
	"\t\t\t$innercode .= \"\\$p$i =& new xmlrpcval(\\$p$i, '$ptype');\\n\";\n" +
	"\t\t} else {\n\t\t\t$innercode .= \"\\$p$i =& php_xmlrpc_encode(\\$p$i);\\n\";\n\t\t}\n" +
	"\t\t$innercode .= \"\\$msg->addparam(\\$p$i);\\n\";\n\t}\n" +
	"\t$plist[] = '$debug = 0';\n\t$plist = implode(',', $plist);\n" +
	"\t$innercode .= \"\\$res =& \\$client->send(\\$msg, $timeout, '$protocol');\\n\";\n" +
	"\t$code = $code . $plist. \") {\\n\" . $innercode . \"\\n}\\n\\$allOK=1;\";\n" +
	"\t$allOK = 0;\n" +
	"\t" + ev + "($code);\n" +
	"\treturn $allOK ? $xmlrpcfuncname : false;\n}\n"

func TestAFunctionWrittenFromOwnTextIsOwnCode(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"Server-Hülle von phpxmlrpc", xmlrpcWrapPHP},
		{"Client-Hülle von phpxmlrpc", xmlrpcWrapRemote},
		{"Methode, die eine Klasse schreibt", "<?php class Gen {\n" +
			"  public function mock($name, $parent) {\n" +
			"    $methods = '';\n" +
			"    foreach (get_class_methods($parent) as $m) { $methods .= \"public function $m() { return null; }\\n\"; }\n" +
			"    $code = \"class $name extends $parent {\\n\" . $methods . \"}\";\n" +
			"    " + ev + "($code);\n  }\n}"},
		{"Heredoc mit abstrakter Klasse", "<?php function make($n) {\n" +
			"  $src = <<<PHP\nabstract class $n { }\nPHP;\n  " + ev + "( @$src );\n}"},
	} {
		if !ownCodeAt(t, c.src, 0) {
			t.Errorf("%s: nicht als selbst geschriebener Code erkannt", c.name)
		}
	}
}

// What the backdoors of 2026-09 evaluated: a parameter, data from cookies and
// the request, and text they decoded. None of it is code a function writes.
func TestForeignCodeIsNoOwnCode(t *testing.T) {
	head := "<?php function f($p) {\n"
	for _, c := range []struct{ name, src string }{
		{"Parameter", "<?php function wp_cron($max_age)\n{\n    " + ev + "($max_age);\n}"},
		{"Anfrage im Text", head + "$code = \"function x() { return '\" . " + post + "['a'] . \"'; }\";\n" + ev + "($code);\n}"},
		{"Anfrage eingesetzt", head + "$code = \"function x() { return {" + post + "['a']}; }\";\n" + ev + "($code);\n}"},
		{"Anfrage über eine Variable", head + "$a = $_COO" + "KIE['k'];\n$code = \"function x() {\" . $a . \"}\";\n" + ev + "($code);\n}"},
		{"über zwei Variablen", head + "$a = " + post + ";\n$b = $a['x'];\n$code = \"function x() {\" . $b . \"}\";\n" + ev + "($code);\n}"},
		{"Schleife über die Anfrage", head + "$code = 'function x() {';\nforeach (" + post + " as $k => $v) { $code .= $v; }\n" + ev + "($code);\n}"},
		{"dekodiert", head + "$b = base64" + "_decode($p);\n$code = \"function x() {\" . $b . \"}\";\n" + ev + "($code);\n}"},
		{"aus einer Datei", head + "$b = file_get_contents($p);\n$code = \"function x() {\" . $b . \"}\";\n" + ev + "($code);\n}"},
		{"variabler Aufruf", head + "$b = $p('x');\n$code = \"function x() {\" . $b . \"}\";\n" + ev + "($code);\n}"},
		{"Anweisung statt Definition", head + "$code = \"return 1;\";\n" + ev + "($code);\n}"},
		{"leerer Anfang, kodierte Bausteine", head + "$c = \"\";\n$c .= \"%41%42\";\n$c = rawurldecode($c);\n" + ev + "($c);\n}"},
		{"aus einem Aufruf", "<?php class G { function go() { $code = $this->generate(); " + ev + "($code); } }"},
		{"nachträglich verändert", head + "$code = 'function x() {}';\n$code ^= $p;\n" + ev + "($code);\n}"},
		{"global", head + "global $code;\n$code = 'function x() {}';\n" + ev + "($code);\n}"},
		{"Referenz", head + "$code = 'function x() {}';\n$r = &$code;\n$r = $p;\n" + ev + "($code);\n}"},
		{"variable Variable", head + "$code = 'function x() {}';\n$$p = 1;\n" + ev + "($code);\n}"},
		{"extract", head + "$code = 'function x() {}';\nextract($p);\n" + ev + "($code);\n}"},
		{"Ausgabeparameter", head + "$code = 'function x() {}';\npreg_match('/(.*)/', $p, $code);\n" + ev + "($code);\n}"},
		{"Aufruf im eingesetzten Wert", head + "$code = \"function x() { {$p->load()} }\";\n" + ev + "($code);\n}"},
		{"statische Eigenschaft", "<?php class V { static $c; function r() { $code = 'function x() {' . self::$c; " + ev + "($code); } }"},
		{"oberste Ebene", "<?php $code = 'function x() { return 1; }';\n" + ev + "($code);\n"},
		{"vor der ersten Zuweisung", head + ev + "($code);\n$code = 'function x() {}';\n}"},
		{"Closure mit use", "<?php function f() { $code = 'function x() {}'; $g = function () use ($code) { " + ev + "($code); }; }"},
		{"Closure schreibt per Referenz", head + "$code = 'function x() {}';\n$g = function () use (&$code) { $code = " + post + "['a']; };\n$g();\n" + ev + "($code);\n}"},
		{"Zuweisung im Kopf einer Schleife", head + "for ($code = 'function x() {' . " + post + "['a']; false; ) {}\n" + ev + "($code);\n}"},
		{"Kette von Zuweisungen", head + "$code = $x = " + post + "['a'];\n" + ev + "($code);\n}"},
	} {
		if ownCodeAt(t, c.src, 0) {
			t.Errorf("%s: als selbst geschriebener Code durchgelassen", c.name)
		}
	}
}

// OwnCode answers for an eval only.
func TestOwnCodeNeedsAnEval(t *testing.T) {
	src := "<?php function f() { $code = 'function x() {}'; echo($code); }"
	s := Parse([]byte(src))
	if s.OwnCode(strings.Index(src, "echo")) || s.OwnCode(-1) || s.OwnCode(len(src)+5) {
		t.Error("ohne eval als selbst geschriebener Code gewertet")
	}
}
