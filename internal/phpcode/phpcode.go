// Package phpcode reads PHP source as far as PHP itself does to tell code
// from comments, strings and the text around the tags, and to find the
// function a position belongs to.
//
// The rules need both. A pattern that names a PHP construct means code, and a
// match inside a help text ("Remember to include "http://"!") or a commented
// out line is prose. Rules made of several parts only describe one action when
// the parts sit in the same function: a library that fetches in its client
// class and evaluates a generated wrapper two thousand lines further down does
// not run what it fetched.
//
// It is a lexer, not a parser, and it errs towards code: a construct it does
// not know stays code, so a rule keeps seeing it.
package phpcode

import "bytes"

// Kind says what a byte of the source is to PHP.
type Kind uint8

const (
	// Text is outside the PHP tags: output, not code.
	Text Kind = iota
	// Code is PHP code, including the tags and backtick commands.
	Code
	// Comment is a line or block comment.
	Comment
	// String is a quoted string or the body of a heredoc or nowdoc.
	String
)

func (k Kind) String() string {
	switch k {
	case Code:
		return "Code"
	case Comment:
		return "Kommentar"
	case String:
		return "Text in Anführungszeichen"
	}
	return "Text außerhalb von PHP"
}

// Scope is the body of a function, closure or method: the offsets of its
// opening and closing brace.
type Scope struct {
	Start, End int
}

// Source is the classified source of one file.
type Source struct {
	src    []byte
	kinds  []Kind
	scopes []Scope
	toks   []token
	// broken says the lexer lost track: a string, comment or heredoc that
	// never ends. PHP refuses such a file; the classification up to that
	// point stands, but nothing may be concluded from its end.
	broken bool
	// tagged says the file opens PHP somewhere. A file without any tag is
	// read as code throughout: a payload that is loaded and passed to eval
	// carries none.
	tagged bool
}

// Parse classifies src.
func Parse(src []byte) *Source {
	s := &Source{src: src, kinds: make([]Kind, len(src))}
	s.lex()
	return s
}

// KindAt returns the kind of the byte at offset i. Offsets outside the source
// count as text.
func (s *Source) KindAt(i int) Kind {
	if i < 0 || i >= len(s.kinds) {
		return Text
	}
	return s.kinds[i]
}

// IsCode reports whether the byte at offset i is PHP code.
func (s *Source) IsCode(i int) bool { return s.KindAt(i) == Code }

// Broken reports whether a string, comment or heredoc runs to the end of the
// file.
func (s *Source) Broken() bool { return s.broken }

// scopeIndex returns the innermost function body around offset i, or -1 for
// the top level of the file.
func (s *Source) scopeIndex(i int) int {
	for k := len(s.scopes) - 1; k >= 0; k-- {
		sc := s.scopes[k]
		if sc.Start <= i && i <= sc.End {
			return k
		}
	}
	return -1
}

// ScopeOf returns the innermost function body around offset i. ok is false at
// the top level of the file.
func (s *Source) ScopeOf(i int) (Scope, bool) {
	k := s.scopeIndex(i)
	if k < 0 {
		return Scope{}, false
	}
	return s.scopes[k], true
}

// SameScope reports whether offsets i and j belong to the same function body,
// or both to the top level of the file.
func (s *Source) SameScope(i, j int) bool { return s.scopeIndex(i) == s.scopeIndex(j) }

// tokKind is what a token of code is.
type tokKind uint8

const (
	tIdent  tokKind = iota // a name or keyword, lower case in val
	tVar                   // a variable, $name
	tStr                   // a string without anything PHP fills in
	tStrDyn                // a string with a variable or expression inside
	tNum                   // a number
	tPunct                 // an operator or punctuation, one or two bytes
	tEnd                   // ?>, which ends a statement like ;
	tText                  // text outside PHP that is more than white space
	tShell                 // a backtick command
)

type token struct {
	kind tokKind
	val  string
	pos  int
}

func (s *Source) mark(from, to int, k Kind) {
	if to > len(s.kinds) {
		to = len(s.kinds)
	}
	for i := from; i < to; i++ {
		s.kinds[i] = k
	}
}

func (s *Source) emit(k tokKind, val string, pos int) {
	s.toks = append(s.toks, token{kind: k, val: val, pos: pos})
}

// lex walks the source once and fills kinds, scopes and toks.
func (s *Source) lex() {
	src := s.src
	n := len(src)
	s.tagged = openTagAt(src, 0) >= 0
	inPHP := !s.tagged

	type open struct{ scope, depth int }
	var stack []open
	braces := 0
	// pending is set by the keyword function and cleared by the brace that
	// opens its body, or by a semicolon: an abstract method has none.
	pending := false
	parens := 0

	i := 0
	for i < n {
		if !inPHP {
			at := openTagAt(src, i)
			if at < 0 {
				s.text(i, n)
				break
			}
			s.text(i, at)
			end := at + tagLength(src, at)
			s.mark(at, end, Code)
			i = end
			inPHP = true
			continue
		}

		c := src[i]
		switch {
		case c == '?' && i+1 < n && src[i+1] == '>':
			s.mark(i, i+2, Code)
			s.emit(tEnd, "?>", i)
			i += 2
			inPHP = false
			continue

		case (c == '/' && i+1 < n && src[i+1] == '/') || (c == '#' && !(i+1 < n && src[i+1] == '[')):
			// A line comment ends at the line break or at a closing tag.
			j := i
			for j < n && src[j] != '\n' && !(src[j] == '?' && j+1 < n && src[j+1] == '>') {
				j++
			}
			s.mark(i, j, Comment)
			i = j
			continue

		case c == '/' && i+1 < n && src[i+1] == '*':
			end := bytes.Index(src[i+2:], []byte("*/"))
			if end < 0 {
				s.mark(i, n, Comment)
				s.broken = true
				i = n
				continue
			}
			j := i + 2 + end + 2
			s.mark(i, j, Comment)
			i = j
			continue

		case c == '\'' || c == '"':
			j := stringEnd(src, i)
			if j < 0 {
				s.mark(i, n, String)
				s.broken = true
				i = n
				continue
			}
			s.mark(i, j, String)
			body := src[i+1 : j-1]
			if c == '"' && interpolates(body) {
				s.emit(tStrDyn, string(body), i)
			} else {
				s.emit(tStr, string(body), i)
			}
			i = j
			continue

		case c == '`':
			// A shell command. It is code - PHP runs it - but its content is
			// not PHP, so it is stepped over as a whole.
			j := stringEnd(src, i)
			if j < 0 {
				j = n
				s.broken = true
			}
			s.mark(i, j, Code)
			s.emit(tShell, "`", i)
			i = j
			continue

		case c == '<' && i+2 < n && src[i+1] == '<' && src[i+2] == '<':
			end, nowdoc, body, ok := heredocEnd(src, i)
			if !ok {
				s.mark(i, n, String)
				s.broken = true
				i = n
				continue
			}
			s.mark(i, end, String)
			if !nowdoc && interpolates(body) {
				s.emit(tStrDyn, string(body), i)
			} else {
				s.emit(tStr, string(body), i)
			}
			i = end
			continue
		}

		s.kinds[i] = Code
		switch {
		case c == '$' && i+1 < n && isIdentStart(src[i+1]):
			j := i + 1
			for j < n && isIdentByte(src[j]) {
				j++
			}
			s.mark(i, j, Code)
			s.emit(tVar, string(src[i:j]), i)
			i = j
			continue

		case isIdentStart(c):
			j := i
			for j < n && (isIdentByte(src[j]) || src[j] == '\\') {
				j++
			}
			s.mark(i, j, Code)
			word := string(bytes.ToLower(src[i:j]))
			s.emit(tIdent, word, i)
			if word == "function" && !afterAccess(src, i) {
				pending = true
				parens = 0
			}
			i = j
			continue

		case c >= '0' && c <= '9':
			j := i
			for j < n && (isIdentByte(src[j]) || src[j] == '.') {
				j++
			}
			s.mark(i, j, Code)
			s.emit(tNum, string(src[i:j]), i)
			i = j
			continue
		}

		switch c {
		case '(':
			if pending {
				parens++
			}
		case ')':
			if pending && parens > 0 {
				parens--
			}
		case ';':
			if pending && parens == 0 {
				pending = false
			}
		case '{':
			if pending && parens == 0 {
				s.scopes = append(s.scopes, Scope{Start: i, End: n - 1})
				stack = append(stack, open{scope: len(s.scopes) - 1, depth: braces})
				pending = false
			}
			braces++
		case '}':
			braces--
			if len(stack) > 0 && stack[len(stack)-1].depth == braces {
				s.scopes[stack[len(stack)-1].scope].End = i
				stack = stack[:len(stack)-1]
			}
		}
		if !isSpace(c) {
			if i+1 < n && isTwoByteOp(c, src[i+1]) {
				s.kinds[i+1] = Code
				s.emit(tPunct, string(src[i:i+2]), i)
				i += 2
				continue
			}
			s.emit(tPunct, string(c), i)
		}
		i++
	}
}

// text marks the bytes from..to as text outside PHP and records a token when
// they are more than white space.
func (s *Source) text(from, to int) {
	s.mark(from, to, Text)
	out := s.src[from:to]
	if from == 0 {
		// A byte order mark in front of the tag is what an editor leaves.
		out = bytes.TrimPrefix(out, []byte("\xef\xbb\xbf"))
	}
	if len(bytes.TrimSpace(out)) > 0 {
		s.emit(tText, "", from)
	}
}

// openTagAt returns the offset of the first PHP open tag at or after i, or -1.
func openTagAt(src []byte, i int) int {
	for {
		k := bytes.Index(src[i:], []byte("<?"))
		if k < 0 {
			return -1
		}
		at := i + k
		if tagLength(src, at) > 0 {
			return at
		}
		i = at + 2
	}
}

// tagLength returns the length of the open tag at offset at, or 0 when the
// bytes there open none: <?php, <?= and <? followed by white space do.
func tagLength(src []byte, at int) int {
	rest := src[at+2:]
	switch {
	case len(rest) >= 3 && bytes.EqualFold(rest[:3], []byte("php")) && (len(rest) == 3 || !isIdentByte(rest[3])):
		return 5
	case len(rest) >= 1 && rest[0] == '=':
		return 3
	case len(rest) >= 1 && isSpace(rest[0]):
		return 2
	}
	return 0
}

// stringEnd returns the offset just past the closing quote of the string that
// opens at i, or -1 when it never closes.
func stringEnd(src []byte, i int) int {
	q := src[i]
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case q:
			return j + 1
		}
	}
	return -1
}

// heredocEnd returns the offset just past the closing label of the heredoc or
// nowdoc that opens at i, whether it is a nowdoc, and its body.
func heredocEnd(src []byte, i int) (int, bool, []byte, bool) {
	j := i + 3
	for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
		j++
	}
	quote := byte(0)
	if j < len(src) && (src[j] == '\'' || src[j] == '"') {
		quote = src[j]
		j++
	}
	start := j
	for j < len(src) && isIdentByte(src[j]) {
		j++
	}
	if j == start {
		return 0, false, nil, false
	}
	label := src[start:j]
	if quote != 0 {
		if j >= len(src) || src[j] != quote {
			return 0, false, nil, false
		}
		j++
	}
	for j < len(src) && src[j] != '\n' {
		j++
	}
	bodyStart := j
	for k := j; k < len(src); k++ {
		if src[k] != '\n' {
			continue
		}
		m := k + 1
		for m < len(src) && (src[m] == ' ' || src[m] == '\t') {
			m++
		}
		if m+len(label) > len(src) || !bytes.Equal(src[m:m+len(label)], label) {
			continue
		}
		after := m + len(label)
		if after < len(src) && isIdentByte(src[after]) {
			continue
		}
		return after, quote == '\'', src[bodyStart:k], true
	}
	return 0, false, nil, false
}

// interpolates reports whether PHP fills something into a double quoted
// string or heredoc body: $name or {$ not escaped by a backslash.
func interpolates(body []byte) bool {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '$':
			if i+1 < len(body) && (isIdentStart(body[i+1]) || body[i+1] == '{') {
				return true
			}
		case '{':
			if i+1 < len(body) && body[i+1] == '$' {
				return true
			}
		}
	}
	return false
}

// afterAccess reports whether the name at offset i follows -> or ::, where
// "function" is a method or constant name rather than the keyword.
func afterAccess(src []byte, i int) bool {
	j := i - 1
	for j >= 0 && isSpace(src[j]) {
		j--
	}
	if j >= 1 && ((src[j] == '>' && src[j-1] == '-') || (src[j] == ':' && src[j-1] == ':')) {
		return true
	}
	return false
}

func isTwoByteOp(a, b byte) bool {
	switch string([]byte{a, b}) {
	case "=>", "||", "&&", "::", "->", "==", "!=", "<=", ">=", ".=", "+=", "-=", "??":
		return true
	}
	return false
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b >= 0x80
}

func isIdentByte(b byte) bool { return isIdentStart(b) || (b >= '0' && b <= '9') }

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' || b == '\v'
}
