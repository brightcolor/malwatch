package walk

import "strings"

// Match reports whether name matches pattern.
//
// Supported syntax, as operators expect it from an exclude list:
// a single star matches any run of characters but never a slash, a double
// star also crosses slashes, and a question mark matches exactly one
// character that is not a slash. Matching is case sensitive, like the shell.
func Match(pattern, name string) bool {
	return matchSegments(splitPattern(pattern), name)
}

// splitPattern breaks a pattern into literal and wildcard tokens.
func splitPattern(p string) []token {
	var out []token
	i := 0
	for i < len(p) {
		switch {
		case strings.HasPrefix(p[i:], "**"):
			i += 2
			// Collapse "**/" into a single doublestar so that "**/log/*.log"
			// also matches "log/x.log" at the very top of the tree.
			slash := false
			for strings.HasPrefix(p[i:], "/") {
				slash = true
				i++
			}
			out = append(out, token{kind: tokDouble, slashAfter: slash})
		case p[i] == '*':
			i++
			out = append(out, token{kind: tokStar})
		case p[i] == '?':
			i++
			out = append(out, token{kind: tokAny})
		default:
			start := i
			for i < len(p) && p[i] != '*' && p[i] != '?' {
				i++
			}
			out = append(out, token{kind: tokLiteral, text: p[start:i]})
		}
	}
	return out
}

type tokenKind int

const (
	tokLiteral tokenKind = iota
	tokStar
	tokAny
	tokDouble
)

type token struct {
	kind tokenKind
	text string
	// slashAfter records that the pattern had "**/" so that the doublestar
	// may also match nothing at all (not even the slash).
	slashAfter bool
}

func matchSegments(tokens []token, name string) bool {
	if len(tokens) == 0 {
		return name == ""
	}
	t := tokens[0]
	rest := tokens[1:]

	switch t.kind {
	case tokLiteral:
		if !strings.HasPrefix(name, t.text) {
			return false
		}
		return matchSegments(rest, name[len(t.text):])

	case tokAny:
		if name == "" || name[0] == '/' {
			return false
		}
		return matchSegments(rest, name[1:])

	case tokStar:
		for i := 0; i <= len(name); i++ {
			if i > 0 && name[i-1] == '/' {
				break // a single star never crosses a slash
			}
			if matchSegments(rest, name[i:]) {
				return true
			}
		}
		return false

	case tokDouble:
		// "**/" may stand for nothing, so "**/log/*.log" matches "log/a.log".
		if matchSegments(rest, name) {
			return true
		}
		for i := 0; i < len(name); i++ {
			if t.slashAfter {
				// Only resume right after a slash, so the remainder starts on
				// a path segment boundary.
				if name[i] != '/' {
					continue
				}
				if matchSegments(rest, name[i+1:]) {
					return true
				}
				continue
			}
			if matchSegments(rest, name[i+1:]) {
				return true
			}
		}
		return false
	}
	return false
}
