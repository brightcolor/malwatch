package rules

import (
	"strings"
	"testing"
)

func TestJoinPutsASplitNameBackTogether(t *testing.T) {
	raw := []byte(`<?php $f = 'base'.'64'.'_dec'.'ode'; eval($f($x));`)
	joined, index := joinConcatenated(raw)
	if joined == nil {
		t.Fatal("nothing was joined")
	}
	if !strings.Contains(string(joined), "base64_decode") {
		t.Fatalf("the name was not reassembled: %s", joined)
	}
	if len(index) != len(joined) {
		t.Fatalf("index has %d entries for %d bytes", len(index), len(joined))
	}
}

func TestJoinKeepsPositionsPointingAtTheRealFile(t *testing.T) {
	raw := []byte("<?php\n\n$f = 'ba'.'se64_decode';\n")
	joined, index := joinConcatenated(raw)
	if joined == nil {
		t.Fatal("nothing was joined")
	}
	at := strings.Index(string(joined), "base64_decode")
	if at < 0 {
		t.Fatalf("not reassembled: %s", joined)
	}
	// The report has to name the line of the file, not of a buffer that only
	// exists inside the scanner.
	if got := lineOf(raw, index[at]); got != 3 {
		t.Errorf("line %d, want 3", got)
	}
}

func TestJoinLeavesAnOrdinaryFileAlone(t *testing.T) {
	// The fast path: no concatenation of literals, no second buffer, no cost.
	raw := []byte("<?php\n$greeting = 'hallo' . $name;\necho $greeting;\n")
	if joined, _ := joinConcatenated(raw); joined != nil {
		t.Errorf("a file without literal concatenation was rewritten: %s", joined)
	}
}

func TestJoinHandlesBothQuoteKinds(t *testing.T) {
	raw := []byte(`<?php $a = "sys"."tem"; $b = 'ex'.'ec';`)
	joined, _ := joinConcatenated(raw)
	if joined == nil {
		t.Fatal("nothing was joined")
	}
	s := string(joined)
	if !strings.Contains(s, "system") || !strings.Contains(s, "exec") {
		t.Errorf("not both kinds were joined: %s", s)
	}
}

// evasionSample reproduces the head of the payload found on a real infected
// site: the function names are assembled from fragments, the call goes through
// variables, and errors are silenced before anything else happens. The encoded
// block is synthetic - the shape is what the rules have to see, and a real
// payload has no business in a repository.
func evasionSample() []byte {
	blob := ""
	for len(blob) < 400 {
		blob += "OykpKSkpKSkpKSkpKSkpKSkpKSldODAwMDB4MFtd"
	}
	return []byte(`<?php $eyxBz = 'base'.'64'.'_dec'.'ode'; $MAIqK = 'st'.'rrev'; ` +
		`ini_set('display_errors', 0); ini_set('error_log', NULL); error_reporting(0); ` +
		`ini_set('log_errors', 0); eval($MAIqK($eyxBz('` + blob + `')));`)
}

func TestTheEngineSeesThroughASplitName(t *testing.T) {
	found := map[string]bool{}
	for _, f := range NewEngine(nil).Scan("x.php", "x.php", "php", evasionSample()) {
		found[f.Rule] = true
	}
	// Both looked straight at this payload and saw nothing: eval reaches the
	// decoder only through a variable, and the silencing preamble had no rule
	// of its own at all.
	for _, want := range []string{"php.eval.variable_call", "php.silence.preamble"} {
		if !found[want] {
			t.Errorf("%s did not fire; the split name still hides the payload: %v", want, found)
		}
	}
}

func TestARuleFiresOnceEvenWhenBothViewsMatch(t *testing.T) {
	// The joined buffer is a second look at the same file, not a second file.
	raw := []byte(`<?php eval(base64_decode('AAAA')); $f = 'ba'.'se64_decode';`)
	seen := map[string]int{}
	for _, f := range NewEngine(nil).Scan("x.php", "x.php", "php", raw) {
		seen[f.Rule]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("%s reported %d times for one file", id, n)
		}
	}
}

func TestJoinLeavesALiteralDotAlone(t *testing.T) {
	// explode('.', $host) reads exactly like the seam between 'a' . 'b'. The
	// difference is only whether the quote opens or closes a string, and
	// getting it wrong welds unrelated code together: it produced findings on
	// phpseclib and on a plugin that carries a base64 PNG.
	for _, raw := range []string{
		`<?php $parts = explode('.', $host); echo $parts[0];`,
		`<?php $clean = str_replace('.', '', $version);`,
		`<?php echo implode(".", $octets);`,
	} {
		joined, _ := joinConcatenated([]byte(raw))
		if joined != nil && string(joined) != raw {
			t.Errorf("a literal dot was treated as a seam:\n  vorher:  %s\n  nachher: %s", raw, joined)
		}
	}
}

func TestJoinStillFindsARealSeamNextToALiteralDot(t *testing.T) {
	raw := []byte(`<?php $p = explode('.', $h); $f = 'base'.'64'.'_decode'; eval($f($x));`)
	joined, _ := joinConcatenated(raw)
	if joined == nil {
		t.Fatal("nothing was joined")
	}
	s := string(joined)
	if !strings.Contains(s, "base64_decode") {
		t.Errorf("the real seam was missed: %s", s)
	}
	if !strings.Contains(s, `explode('.', $h)`) {
		t.Errorf("the literal dot was destroyed: %s", s)
	}
}

func TestTheEngineResolvesEscapedSuperglobals(t *testing.T) {
	// A loader on a real site wrote the superglobal as "\x5f\107\x45\x54" and
	// pulled its body out of a zip. Both halves were invisible to the catalog.
	raw := []byte(`<?php error_reporting(0); $G = array("\x5f\107\x45\x54"); ` +
		`(${$G[0]}["of"] == 1) && die("x"); ` +
		`@require_once "\x7a\x69\x70\x3a\x2f\x2f\x6a\x2e\x7a\x69\x70\x23\x63";`)
	found := map[string]bool{}
	for _, f := range NewEngine(nil).Scan("x.php", "x.php", "php", raw) {
		found[f.Rule] = true
	}
	if !found["php.include.stream_wrapper"] {
		t.Errorf("the zip loader was not seen: %v", found)
	}
}

func TestDecodedViewDoesNotInventFindings(t *testing.T) {
	// Binary data in a string is everyday work. Resolving it must not spell
	// anything the rules react to.
	raw := []byte(`<?php $header = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"; fwrite($fh, $header);`)
	if hits := NewEngine(nil).Scan("x.php", "x.php", "php", raw); len(hits) != 0 {
		t.Errorf("a PNG header became a finding: %+v", hits)
	}
}

func TestJoinSkipsCommentsBetweenTheParts(t *testing.T) {
	// A payload on a real site wrote "ra"/*-X8KKH~;-*/."nge" so the word never
	// appears whole. Only whitespace between the parts would let that through.
	raw := []byte(`<?php $f = "ra"/*-X8KKH~;-*/."nge"; $g = 'sys' // weg
	. 'tem';`)
	joined, _ := joinConcatenated(raw)
	if joined == nil {
		t.Fatal("nothing was joined")
	}
	s := string(joined)
	if !strings.Contains(s, "range") || !strings.Contains(s, "system") {
		t.Errorf("a comment between the parts hid the word: %s", s)
	}
}
