package rules

import "testing"

// hitRules returns the rules that report content under path. Named apart
// from the helpers of engine_test.go, which the virus scanner on the
// workstation keeps deleting: both files compile together in CI.
func hitRules(e *Engine, path, ext, content string) map[string]bool {
	out := map[string]bool{}
	for _, f := range e.Scan(path, path, ext, []byte(content)) {
		out[f.Rule] = true
	}
	return out
}

// A PHP file in a place for uploads is a finding because it can be a way in.
// One that can do nothing is none: plugins put "Silence is golden" guards
// into every directory they create, security plugins keep their data behind
// an exit, icon packs store their tables as arrays. On 2026-09-30 these made
// 75 of 77 open findings of that rule across 17 websites.
func TestFilesThatDoNothingPassTheUploadRule(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ name, content string }{
		{"Platzhalter", "<?php // Silence is golden."},
		{"Daten hinter exit", "<?php\n// datastore=auditqueue;\nexit(0);\n?>\n{\"user_login\":\"guest\"}"},
		{"Einstellungen hinter die", "<?php die('Access Denied.'); // <!-- ?> YToxMDk6e3M6MTI6ImRhdGFfdmVyc2lvbiI7"},
		{"Icon-Tabelle", "<?php $icons = array();\n$icons['Defaults']['glass'] = array(\"class\"=>'glass',\"tags\"=>'glass');"},
		{"Text unter PHP-Namen", "Kangaroos cannot jump here"},
	} {
		if hitRules(e, "/web/wp-content/uploads/plugin/index.php", "php", c.content)["php.in_uploads"] {
			t.Errorf("%s: gemeldet, obwohl die Datei nichts tun kann", c.name)
		}
	}
}

// The counter-check: a file in the same place that does something stays a
// finding, and so does the visible half of a shell, an upload form.
func TestLiveFilesStayUploadFindings(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ name, content string }{
		{"eigene Funktion", "<?php function get_image($u = null) { $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $u); return curl_exec($ch); }"},
		{"bedingtes exit", "<?php if ($x) exit; echo 1;"},
		{"exit mit Aufruf", "<?php die(system('id'));"},
		{"Formular", "<?php // x ?>\n<form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"f\"></form>"},
	} {
		if !hitRules(e, "/web/wp-content/uploads/2024/05/x.php", "php", c.content)["php.in_uploads"] {
			t.Errorf("%s: nicht mehr gemeldet", c.name)
		}
	}
}
