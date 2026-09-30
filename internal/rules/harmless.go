package rules

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/brightcolor/malwatch/internal/phpcode"
)

// maxWeighedMatches caps how many matches of one rule are weighed in a file,
// for a rule with Harmless, CodeOnly or SupportInCode. A file with more
// matches than this is judged on the first ones.
const maxWeighedMatches = 5000

// DefaultScriptHosts are the hosts a script tag written by document.write may
// load from without a finding: the addresses of the old Google Analytics
// snippet and the two public copies of jQuery. The ISPConfig addon has the same
// list as the default of its setting (malwatch_config script_hosts).
var DefaultScriptHosts = []string{
	"google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com",
	"ajax.googleapis.com", "code.jquery.com",
}

// The limits of the list of script hosts.
const (
	MaxScriptHosts      = 32
	MaxScriptHostLength = 100
)

var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)

// CheckScriptHosts says in German why a list of hosts cannot be used, or
// returns nil. An empty list is allowed: then only scripts from the site itself
// pass.
func CheckScriptHosts(hosts []string) error {
	if len(hosts) > MaxScriptHosts {
		return fmt.Errorf("%d Hosts angegeben, erlaubt sind höchstens %d", len(hosts), MaxScriptHosts)
	}
	for _, h := range hosts {
		if len(h) > MaxScriptHostLength || !hostName.MatchString(h) {
			return fmt.Errorf("der Host %q geht nicht: nur ein Name wie www.example.org, ohne https:// und ohne Pfad, "+
				"bis zu %d Zeichen", h, MaxScriptHostLength)
		}
	}
	return nil
}

// SetScriptHosts replaces the hosts of DefaultScriptHosts. A list
// CheckScriptHosts refuses leaves the engine as it was.
func (e *Engine) SetScriptHosts(hosts []string) error {
	if err := CheckScriptHosts(hosts); err != nil {
		return err
	}
	e.scriptHosts = make(map[string]bool, len(hosts))
	e.scriptHostList = append([]string(nil), hosts...)
	for _, h := range hosts {
		e.scriptHosts[h] = true
	}
	return nil
}

// harmlessBlob reports whether the long encoded block at loc is data rather
// than hidden code: a picture, a font, a document, a certificate or key, or the
// data part of a PHAR archive. Decoded PHP, compressed data, archives and
// anything unknown stay suspicious.
func harmlessBlob(_ *Engine, hay []byte, loc []int) bool {
	if pharData(hay, loc[0]) {
		return true
	}
	blob := hay[loc[0]:loc[1]]
	head := decodeHead(blob, 96)
	if head == nil {
		return false
	}
	if knownData(head) {
		// The head of a picture or a PDF in front of code makes no picture:
		// the whole block has to be free of it.
		return !holdsCode(decodeHead(blob, len(blob)))
	}
	if svgStart(head) {
		// A picture as long as it carries no script of its own.
		full := decodeHead(blob, len(blob))
		lower := bytes.ToLower(full)
		return !holdsCode(full) && !bytes.Contains(lower, []byte("javascript:")) &&
			!bytes.Contains(lower, []byte("onload")) && !bytes.Contains(lower, []byte("onerror"))
	}
	return false
}

// codeMarks are what code looks like inside a decoded block, lower case. Each
// is long enough that the random bytes of a picture or a font do not spell it
// by chance.
var codeMarks = [][]byte{
	[]byte("<?php"), []byte("<?= "), []byte("<?=$"), []byte("<script"), []byte("eval("), []byte("assert("),
	[]byte("system("), []byte("passthru("), []byte("shell_exec("), []byte("base64_decode"),
	[]byte("$_post"), []byte("$_get"), []byte("$_request"), []byte("$_cookie"),
}

// holdsCode reports whether decoded bytes carry PHP or a script anywhere.
func holdsCode(b []byte) bool {
	lower := bytes.ToLower(b)
	for _, m := range codeMarks {
		if bytes.Contains(lower, m) {
			return true
		}
	}
	return false
}

// decodeHead decodes up to n bytes from the start of an encoded block: as hex
// when it holds nothing else, as base64 otherwise. nil means it decodes as
// neither.
func decodeHead(blob []byte, n int) []byte {
	if len(blob)%2 == 0 && isHexString(blob) {
		take := 2 * n
		if take > len(blob) {
			take = len(blob)
		}
		out := make([]byte, take/2)
		if _, err := hex.Decode(out, blob[:take]); err != nil {
			return nil
		}
		return out
	}
	body := bytes.TrimRight(blob, "=")
	take := (n + 2) / 3 * 4
	if take > len(body) {
		take = len(body) / 4 * 4
	}
	if take == 0 {
		return nil
	}
	out, err := base64.StdEncoding.DecodeString(string(body[:take]))
	if err != nil {
		return nil
	}
	return out
}

func isHexString(b []byte) bool {
	for _, c := range b {
		if !isHex(c) {
			return false
		}
	}
	return true
}

// knownData reports whether decoded bytes open a format that holds no code:
// pictures, fonts, PDF documents, certificates and keys in PEM or DER.
func knownData(b []byte) bool {
	switch {
	case startsLikeImage(b):
		return true
	case bytes.HasPrefix(b, []byte("wOFF")), bytes.HasPrefix(b, []byte("wOF2")), bytes.HasPrefix(b, []byte("OTTO")),
		bytes.HasPrefix(b, []byte("\x00\x01\x00\x00")):
		return true
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return true
	case bytes.HasPrefix(b, []byte("-----BEGIN ")):
		return true
	case len(b) >= 4 && b[0] == 0x30 && (b[1] == 0x81 || b[1] == 0x82) && (b[2]|b[3]) != 0:
		// An ASN.1 sequence with a long length: a certificate or key in DER.
		return true
	}
	return false
}

func svgStart(b []byte) bool {
	t := bytes.ToLower(bytes.TrimLeft(b, " \t\r\n\xef\xbb\xbf"))
	return bytes.HasPrefix(t, []byte("<svg")) || (bytes.HasPrefix(t, []byte("<?xml")) && bytes.Contains(t, []byte("<svg")))
}

var haltCall = regexp.MustCompile(`(?i)__halt_compiler\s*\(\s*\)`)

// pharData reports whether offset at lies in the data part of a PHAR archive:
// after __halt_compiler() in a file whose stub maps an archive or that ends in
// the signature mark of one. A payload read back from behind __halt_compiler by
// the file itself has no such stub.
func pharData(hay []byte, at int) bool {
	halt := haltCall.FindIndex(hay)
	if halt == nil || at < halt[1] {
		return false
	}
	return bytes.Contains(hay[:halt[0]], []byte("Phar::")) || bytes.HasSuffix(hay, []byte("GBMB"))
}

// harmlessWrite reports whether document.write at loc writes nothing but text,
// links and script tags that load from the site itself or from a host of the
// list. The argument has to be written out in the file; one that is computed
// or holds a script of its own stays a finding.
func harmlessWrite(e *Engine, hay []byte, loc []int) bool {
	call := bytes.ToLower(hay[loc[0]:loc[1]])
	if !bytes.Contains(call, []byte("unescape")) && !bytes.Contains(call, []byte("decodeuricomponent")) {
		return false
	}
	parts, ok := jsConcat(hay, loc[1])
	if !ok {
		return false
	}
	var text strings.Builder
	literal := false
	for _, p := range parts {
		if p.name {
			// Where a variable stands the text is unknown.
			text.WriteByte(0)
			continue
		}
		literal = true
		text.WriteString(percentDecode(p.value))
	}
	if !literal {
		return false
	}
	lower := strings.ToLower(text.String())
	for _, bad := range []string{"<iframe", "<object", "<embed", "<meta", "<form", "javascript:", "eval(", "document.cookie",
		"window.location", "location.href", "location.replace", " onload", " onerror", " onclick", " onmouseover"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	for rest := lower; ; {
		i := strings.Index(rest, "<script")
		if i < 0 {
			return true
		}
		end := strings.IndexByte(rest[i:], '>')
		if end < 0 {
			return false
		}
		tag := rest[i : i+end]
		body := rest[i+end+1:]
		close := strings.Index(body, "</script")
		if close < 0 {
			close = len(body)
		}
		if strings.TrimSpace(body[:close]) != "" {
			// A script of its own inside the written text.
			return false
		}
		src, found := attrValue(tag, "src")
		if !found || !e.scriptSourceOK(src) {
			return false
		}
		rest = body[close:]
	}
}

// scriptSourceOK reports whether a script address points at the site itself or
// at a host of the list. A NUL marks where a variable supplied the start of the
// address, as the Google Analytics snippet does with its scheme: then the text
// after it has to begin with a listed host.
func (e *Engine) scriptSourceOK(src string) bool {
	if i := strings.LastIndexByte(src, 0); i >= 0 {
		return e.scriptHosts[hostOf(src[i+1:])]
	}
	switch {
	case strings.HasPrefix(src, "//"):
		return e.scriptHosts[hostOf(src[2:])]
	case strings.Contains(src, "://"):
		return e.scriptHosts[hostOf(src[strings.Index(src, "://")+3:])]
	case strings.Contains(src, ":"):
		// data:, javascript: and the like.
		return false
	}
	return true
}

// hostOf returns the host at the start of s, up to a slash, colon or query.
func hostOf(s string) string {
	end := strings.IndexAny(s, "/:?#")
	if end < 0 {
		end = len(s)
	}
	return strings.ToLower(s[:end])
}

// attrValue returns the value of attribute name in a lower case tag.
func attrValue(tag, name string) (string, bool) {
	for i := 0; ; {
		k := strings.Index(tag[i:], name)
		if k < 0 {
			return "", false
		}
		at := i + k
		i = at + len(name)
		if at > 0 && !isSpace(tag[at-1]) {
			continue
		}
		j := i
		for j < len(tag) && isSpace(tag[j]) {
			j++
		}
		if j >= len(tag) || tag[j] != '=' {
			continue
		}
		j++
		for j < len(tag) && isSpace(tag[j]) {
			j++
		}
		if j >= len(tag) {
			return "", true
		}
		if q := tag[j]; q == '"' || q == '\'' {
			end := strings.IndexByte(tag[j+1:], q)
			if end < 0 {
				return tag[j+1:], true
			}
			return tag[j+1 : j+1+end], true
		}
		end := strings.IndexAny(tag[j:], " \t\r\n")
		if end < 0 {
			return tag[j:], true
		}
		return tag[j : j+end], true
	}
}

type jsPart struct {
	value string
	name  bool
}

// jsConcat reads the argument of a JavaScript call that starts at offset i:
// string literals and names joined by +, up to the closing parenthesis.
func jsConcat(hay []byte, i int) ([]jsPart, bool) {
	var parts []jsPart
	for {
		for i < len(hay) && isSpace(hay[i]) {
			i++
		}
		if i >= len(hay) {
			return nil, false
		}
		switch c := hay[i]; {
		case c == '\'' || c == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(hay) && hay[j] != c; j++ {
				if hay[j] == '\\' && j+1 < len(hay) {
					j++
				}
				b.WriteByte(hay[j])
			}
			if j >= len(hay) {
				return nil, false
			}
			parts = append(parts, jsPart{value: b.String()})
			i = j + 1
		case isNameByte(c) || c == '$' || c == '.':
			j := i
			for j < len(hay) && (isNameByte(hay[j]) || hay[j] == '$' || hay[j] == '.') {
				j++
			}
			parts = append(parts, jsPart{value: string(hay[i:j]), name: true})
			i = j
		default:
			return nil, false
		}
		for i < len(hay) && isSpace(hay[i]) {
			i++
		}
		if i >= len(hay) {
			return nil, false
		}
		switch hay[i] {
		case '+':
			i++
		case ')':
			return parts, true
		default:
			return nil, false
		}
	}
}

// percentDecode resolves %XX and %uXXXX as unescape does; anything else stays.
func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 5
				continue
			}
		}
		if i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte('%')
	}
	return b.String()
}

// webshellNames are the names and marks of known web shells, see the rule
// php.webshell.known.
var webshellNames = rx(`(?i)(?:c99shell|r57shell|wso\s?shell|b374k|weevely|IndoXploit|AnonymousFox|SyRiAn\s?Sh3ll|MiniShell|Mini\s?Shell|priv8\s?shell|FilesMan|by\s+Orb|IndoSec|Alfa\s?Team\s?Shell|Sh3ll\s?Uploader|1nv1s1bl3|Sole\s?Sad\s?(?:&|and)\s?Invisible)`)

// harmlessMarker reports whether the shell name at loc stands in a search
// pattern or in a list of several such names: a security tool looking for
// shells. A name in a comment, a title or any other text stays a finding.
func harmlessMarker(_ *Engine, hay []byte, loc []int) bool {
	src := phpcode.Parse(hay)
	if src.KindAt(loc[0]) != phpcode.String {
		return false
	}
	start, end := loc[0], loc[1]
	for start > 0 && src.KindAt(start-1) == phpcode.String {
		start--
	}
	for end < len(hay) && src.KindAt(end) == phpcode.String {
		end++
	}
	lit := hay[start:end]
	if len(lit) >= 2 && (lit[0] == '\'' || lit[0] == '"') && lit[len(lit)-1] == lit[0] {
		lit = lit[1 : len(lit)-1]
	}
	if searchPattern(lit) {
		return true
	}
	names := map[string]bool{}
	for _, m := range webshellNames.FindAll(lit, -1) {
		names[strings.ToLower(string(m))] = true
	}
	return len(names) >= 3 && bytes.IndexByte(lit, '|') >= 0
}

// searchPattern reports whether a string is a PCRE pattern: a delimiter, the
// pattern, the same delimiter and nothing after it but modifiers.
func searchPattern(s []byte) bool {
	s = bytes.TrimSpace(s)
	if len(s) < 3 || !strings.ContainsRune("#/~!@%|+", rune(s[0])) {
		return false
	}
	k := bytes.LastIndexByte(s, s[0])
	if k <= 0 {
		return false
	}
	for _, f := range s[k+1:] {
		if !strings.ContainsRune("imsxuADSUXJ", rune(f)) {
			return false
		}
	}
	return true
}
