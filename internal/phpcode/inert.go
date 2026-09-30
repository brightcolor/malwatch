package phpcode

import "bytes"

// Reasons Inert gives. The rules quote them in the report of a file they let
// pass, so they are written for the operator.
const (
	ReasonComment = "nur Kommentar"
	ReasonExit    = "beginnt mit exit"
	ReasonData    = "nur feste Daten"
	ReasonText    = "ohne PHP-Tag"
)

// Inert reports whether a PHP file can do nothing when it is requested or
// included, and why. Three shapes qualify:
//
//   - only comments and white space: the "Silence is golden" guards that
//     plugins put into every directory they create;
//   - an unconditional exit, die or __halt_compiler with nothing but a fixed
//     value as its first statement: PHP stops there, whatever follows. Sucuri,
//     BackupBuddy and Code Profiler keep their data behind exactly this line;
//   - nothing but fixed data: literals and arrays of literals assigned,
//     returned or defined, optionally behind the usual ABSPATH guard. Icon
//     tables and generated configuration look like this.
//
// A file without any PHP tag and without markup is plain text under a PHP
// name, such as the "Kangaroos cannot jump here" that All-in-One WP Migration
// writes into its storage directory: requested or included, PHP prints it and
// runs nothing. Code in such a file only runs when something reads it and
// passes it to eval, and the rules that read code report that on their own.
//
// Anything else is live, including a string PHP fills a variable into, any
// call, any output and a file whose strings or comments never end. The check
// is deliberately narrow: it answers whether a file in a place for uploads or
// a stray file in a plugin directory can be a way in, not whether code is
// harmless.
func Inert(src []byte) (bool, string) {
	body := bytes.TrimPrefix(src, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(body)) == 0 {
		return false, ""
	}
	s := Parse(src)
	if !s.tagged {
		if bytes.IndexByte(body, '<') < 0 {
			return true, ReasonText
		}
		return false, ""
	}
	if s.broken {
		return false, ""
	}

	stmts, ok := statements(s.toks)
	if !ok {
		return false, ""
	}
	sawData := false
	for k, st := range stmts {
		if k == 0 && isExit(st) {
			return true, ReasonExit
		}
		if len(st) == 1 && st[0].kind == tText {
			// Output around the tags, such as an HTML form.
			return false, ""
		}
		if isGuard(st) {
			continue
		}
		if isData(st) {
			sawData = true
			continue
		}
		return false, ""
	}
	if sawData {
		return true, ReasonData
	}
	return true, ReasonComment
}

// statements splits the tokens of code into statements: at a semicolon or a
// closing tag outside of brackets, and after the closing brace of an if
// block. Text outside PHP is a statement of its own. ok is false when the
// brackets do not balance.
func statements(toks []token) ([][]token, bool) {
	var out [][]token
	var cur []token
	depth := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
		}
		cur = nil
	}
	for _, t := range toks {
		switch {
		case t.kind == tText:
			flush()
			out = append(out, []token{t})
			continue
		case t.kind == tEnd:
			if depth != 0 {
				return nil, false
			}
			flush()
			continue
		case t.kind == tPunct && t.val == ";" && depth == 0:
			flush()
			continue
		case t.kind == tPunct && (t.val == "(" || t.val == "[" || t.val == "{"):
			depth++
		case t.kind == tPunct && (t.val == ")" || t.val == "]" || t.val == "}"):
			depth--
			if depth < 0 {
				return nil, false
			}
			if t.val == "}" && depth == 0 && len(cur) > 0 && cur[0].kind == tIdent && cur[0].val == "if" {
				cur = append(cur, t)
				flush()
				continue
			}
		}
		cur = append(cur, t)
	}
	if depth != 0 {
		return nil, false
	}
	flush()
	return out, true
}

// isExit matches exit, die or __halt_compiler, bare or with an empty or fixed
// argument.
func isExit(st []token) bool {
	if len(st) == 0 || st[0].kind != tIdent {
		return false
	}
	switch st[0].val {
	case "exit", "die", "__halt_compiler":
	default:
		return false
	}
	rest := st[1:]
	switch len(rest) {
	case 0:
		return true
	case 2:
		return isPunct(rest[0], "(") && isPunct(rest[1], ")")
	case 3:
		return isPunct(rest[0], "(") && isLiteral(rest[1]) && isPunct(rest[2], ")")
	}
	return false
}

// isGuard matches the lines that stop a file loaded outside WordPress:
//
//	defined('ABSPATH') || exit;       defined('ABSPATH') or die('x');
//	if (!defined('ABSPATH')) exit;    if (!defined('ABSPATH')) { die(); }
func isGuard(st []token) bool {
	// defined ( 'X' ) || exit…
	if len(st) >= 5 && isIdent(st[0], "defined") && isPunct(st[1], "(") && st[2].kind == tStr && isPunct(st[3], ")") &&
		(isPunct(st[4], "||") || isIdent(st[4], "or")) {
		return isExit(st[5:])
	}
	// if ( ! defined ( 'X' ) ) exit… | { exit… ; }
	if len(st) >= 8 && isIdent(st[0], "if") && isPunct(st[1], "(") && isPunct(st[2], "!") && isIdent(st[3], "defined") &&
		isPunct(st[4], "(") && st[5].kind == tStr && isPunct(st[6], ")") && isPunct(st[7], ")") {
		rest := st[8:]
		if len(rest) >= 2 && isPunct(rest[0], "{") && isPunct(rest[len(rest)-1], "}") {
			inner := rest[1 : len(rest)-1]
			if len(inner) > 0 && isPunct(inner[len(inner)-1], ";") {
				inner = inner[:len(inner)-1]
			}
			return isExit(inner)
		}
		return isExit(rest)
	}
	return false
}

// isData matches fixed data: define('X', value), return value, and an
// assignment of a value to a variable or to a fixed key of one.
func isData(st []token) bool {
	if len(st) == 0 {
		return false
	}
	if isIdent(st[0], "define") {
		if len(st) < 6 || !isPunct(st[1], "(") || st[2].kind != tStr || !isPunct(st[3], ",") || !isPunct(st[len(st)-1], ")") {
			return false
		}
		return isValue(st[4 : len(st)-1])
	}
	if isIdent(st[0], "return") {
		return isValue(st[1:])
	}
	if st[0].kind != tVar {
		return false
	}
	i := 1
	for i < len(st) && isPunct(st[i], "[") {
		switch {
		case i+1 < len(st) && isPunct(st[i+1], "]"):
			i += 2
		case i+2 < len(st) && isLiteral(st[i+1]) && isPunct(st[i+2], "]"):
			i += 3
		default:
			return false
		}
	}
	if i >= len(st) || !isPunct(st[i], "=") {
		return false
	}
	return isValue(st[i+1:])
}

// isValue reports whether the tokens are one fixed value: literals joined by
// arithmetic or concatenation, and arrays of such values.
func isValue(toks []token) bool {
	if len(toks) == 0 {
		return false
	}
	end, ok := value(toks, 0)
	return ok && end == len(toks)
}

// value reads one value starting at i and returns the offset after it.
func value(toks []token, i int) (int, bool) {
	i, ok := term(toks, i)
	if !ok {
		return 0, false
	}
	for i < len(toks) && toks[i].kind == tPunct && (toks[i].val == "." || toks[i].val == "+" || toks[i].val == "-" || toks[i].val == "*") {
		i, ok = term(toks, i+1)
		if !ok {
			return 0, false
		}
	}
	return i, true
}

func term(toks []token, i int) (int, bool) {
	if i >= len(toks) {
		return 0, false
	}
	t := toks[i]
	switch {
	case isLiteral(t):
		return i + 1, true
	case isPunct(t, "-") && i+1 < len(toks) && toks[i+1].kind == tNum:
		return i + 2, true
	case isIdent(t, "array") && i+1 < len(toks) && isPunct(toks[i+1], "("):
		return items(toks, i+2, ")")
	case isPunct(t, "["):
		return items(toks, i+1, "]")
	}
	return 0, false
}

// items reads the entries of an array up to the closing bracket.
func items(toks []token, i int, closing string) (int, bool) {
	for {
		if i >= len(toks) {
			return 0, false
		}
		if isPunct(toks[i], closing) {
			return i + 1, true
		}
		var ok bool
		if i, ok = value(toks, i); !ok {
			return 0, false
		}
		if i < len(toks) && isPunct(toks[i], "=>") {
			if i, ok = value(toks, i+1); !ok {
				return 0, false
			}
		}
		if i < len(toks) && isPunct(toks[i], ",") {
			i++
			continue
		}
		if i < len(toks) && isPunct(toks[i], closing) {
			return i + 1, true
		}
		return 0, false
	}
}

func isLiteral(t token) bool {
	switch t.kind {
	case tStr, tNum:
		return true
	case tIdent:
		return t.val == "true" || t.val == "false" || t.val == "null"
	}
	return false
}

func isPunct(t token, v string) bool { return t.kind == tPunct && t.val == v }

func isIdent(t token, v string) bool { return t.kind == tIdent && t.val == v }
