package rules

import "testing"

// The PHP snippets below are inert probes for the rule engine: Go strings that
// are matched against patterns and never executed. The payload decodes to
// "echo 1;".

// A payload that is pulled in with include runs as PHP whatever its name
// says. Stored as .css or .txt it used to reach no PHP rule at all, because
// the rules went by the extension alone.
func TestPHPUnderAnotherNameIsReadAsPHP(t *testing.T) {
	e := NewEngine(nil)
	payload := `<?php eval(base64_decode("ZWNobyAxOw=="));`

	for _, c := range []struct{ path, ext string }{
		{"/web/stats/2021-11/.1674d7c1.css", "css"},
		{"/web/wp-content/uploads/2024/05/notes.txt", "txt"},
		{"/web/wp-includes/load.php.orig", "orig"},
		{"/web/wp-content/plugins/x/cache", ""},
	} {
		if !fires(e, "php.eval.encoded", c.path, c.ext, payload) {
			t.Errorf("%s: PHP code under this name reached no PHP rule", c.path)
		}
	}
}

// The counter-check: text that merely quotes PHP somewhere in the middle - a
// log line with an attack probe, a readme with an example - is not PHP code.
func TestQuotedPHPInsideTextIsNotReadAsPHP(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ path, ext, content string }{
		{"/web/logs/zugriffe.txt", "txt",
			`203.0.113.9 - - [23/Sep/2026] "GET /?q=<?php eval(base64_decode("ZWNobyAxOw==")); ?>" 404` + "\n"},
		{"/web/wp-content/plugins/x/readme.txt", "txt",
			"=== Beispiel ===\nSo nicht:\n<?php eval(base64_decode(\"ZWNobyAxOw==\")); ?>\n"},
	} {
		if fires(e, "php.eval.encoded", c.path, c.ext, c.content) {
			t.Errorf("%s: quoted PHP inside text was read as code", c.path)
		}
	}
}

// Where a rule asks what the web server would run, the name decides and not
// the content: nginx hands a .txt file to nobody, whatever it holds.
func TestUploadRuleStillGoesByTheName(t *testing.T) {
	e := NewEngine(nil)
	src := `<?php echo "Beispielcode aus einem Blogartikel";`
	if fires(e, "php.in_uploads", "/web/wp-content/uploads/2024/05/beispiel.txt", "txt", src) {
		t.Error("a text file in uploads was reported as a PHP file the server runs")
	}
	if !fires(e, "php.in_uploads", "/web/wp-content/uploads/2024/05/beispiel.php", "php", src) {
		t.Error("the same content as .php was not reported - the test proves nothing")
	}
}

// An image is recognised by its first bytes, so code smuggled into one is
// found even when the file carries no image extension.
func TestImageUnderAnotherNameIsCheckedForCode(t *testing.T) {
	e := NewEngine(nil)
	path := "/web/wp-content/uploads/2024/05/vorschau.tmp"
	if !fires(e, "php.in_image", path, "tmp", "GIF89a\x01\x00\x01\x00<?php echo 1; ?>") {
		t.Error("PHP inside a GIF without an image extension was not reported")
	}
	if fires(e, "php.in_image", path, "tmp", "GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff") {
		t.Error("a plain GIF was reported")
	}
}

// Each format by its own magic bytes, and text that merely begins with the
// same letters stays text.
func TestImageMagicBytes(t *testing.T) {
	e := NewEngine(nil)
	code := "<?php echo 1; ?>"
	path := "/web/daten/datei.bin"

	images := map[string]string{
		"JPEG": "\xff\xd8\xff\xe0\x00\x10JFIF\x00",
		"PNG":  "\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR",
		"GIF":  "GIF87a\x01\x00\x01\x00",
		"WebP": "RIFF\x24\x00\x00\x00WEBPVP8 ",
		"BMP":  "BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00",
		"ICO":  "\x00\x00\x01\x00\x01\x00\x10\x10",
		"TIFF": "II*\x00\x08\x00\x00\x00",
		"AVIF": "\x00\x00\x00\x1cftypavif\x00\x00",
	}
	for name, head := range images {
		if !fires(e, "php.in_image", path, "bin", head+code) {
			t.Errorf("%s with code inside was not recognised as an image", name)
		}
	}

	texts := map[string]string{
		"Text":        "Notiz zum Umzug " + code,
		"BM-Text":     "BMW-Händler in Lübeck " + code,
		"Audio":       "RIFF\x24\x00\x00\x00WAVEfmt " + code,
		"Video":       "\x00\x00\x00\x18ftypmp42\x00\x00" + code,
		"leere Liste": "\x00\x00\x01\x00\x00\x00" + code,
	}
	for name, head := range texts {
		if fires(e, "php.in_image", path, "bin", head) {
			t.Errorf("%s was taken for an image", name)
		}
	}
}
