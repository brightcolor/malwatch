package rules

// maxJoin caps the second buffer. A file large enough to matter here is a
// dropped payload, never a 30 MB log that happens to end in .php.
const maxJoin = 8 * 1024 * 1024

// joinConcatenated returns a copy of content in which two adjacent string
// literals are glued together, plus a map from each byte of that copy back to
// its offset in content. It returns nil when there is nothing to join, or when
// the file cannot be read with confidence.
//
// The technique this defeats is the one that made the rule catalog look blind:
// a payload writes 'base'.'64'.'_dec'.'ode' instead of base64_decode, and every
// rule that names the function finds nothing. One extra pass gives all of them
// their sight back, rather than each rule having to learn the trick.
//
// It has to be a small scanner rather than a search-and-replace, because
//
//	'a' . 'b'      the seam between two literals
//	'.'            a literal dot, as in explode('.', $host)
//
// read identically. The only difference is whether a quote opens or closes a
// string. Treating the second as the first welds unrelated code together, and
// that reported a Diffie-Hellman prime in phpseclib and a base64 PNG in a
// gallery plugin as malware.
//
// The map exists because a finding has to name the line of the real file. The
// copy only ever drops bytes, so the mapping is exact.
func joinConcatenated(content []byte) ([]byte, []int) {
	if len(content) == 0 || len(content) > maxJoin {
		return nil, nil
	}

	out := make([]byte, 0, len(content))
	index := make([]int, 0, len(content))
	seams := 0

	emit := func(i int) {
		out = append(out, content[i])
		index = append(index, i)
	}

	i := 0
	for i < len(content) {
		c := content[i]

		// Comments are copied as they are. An apostrophe in a German comment
		// would otherwise open a string that runs to the next one, and every
		// join in between would be nonsense.
		if c == '/' && i+1 < len(content) && content[i+1] == '/' {
			i = copyUntilNewline(content, i, emit)
			continue
		}
		if c == '#' {
			i = copyUntilNewline(content, i, emit)
			continue
		}
		if c == '/' && i+1 < len(content) && content[i+1] == '*' {
			emit(i)
			emit(i + 1)
			i += 2
			for i < len(content) {
				if content[i] == '*' && i+1 < len(content) && content[i+1] == '/' {
					emit(i)
					emit(i + 1)
					i += 2
					break
				}
				emit(i)
				i++
			}
			continue
		}

		if c != '\'' && c != '"' {
			emit(i)
			i++
			continue
		}

		// A string literal. Copy it, and swallow every seam that follows.
		quote := c
		emit(i)
		i++
		closed := false
		for i < len(content) {
			if content[i] == '\\' {
				emit(i)
				i++
				if i < len(content) {
					emit(i)
					i++
				}
				continue
			}
			if content[i] != quote {
				emit(i)
				i++
				continue
			}
			if next, ok := seamAfter(content, i, quote); ok {
				// Drop the closing quote, the dot and the opening quote: the
				// two literals become one.
				seams++
				i = next
				continue
			}
			emit(i)
			i++
			closed = true
			break
		}
		if !closed {
			// The scanner lost track - an unterminated string, a heredoc, a
			// construct not handled here. Guessing on from an unknown state is
			// how the false positives happened, so the second view is dropped
			// and the rules see the file as it is.
			return nil, nil
		}
	}

	if seams == 0 {
		return nil, nil
	}
	return out, index
}

// seamAfter reports whether the quote at i closes a literal that is immediately
// concatenated with another of the same kind, and where that next literal's
// content starts.
func seamAfter(content []byte, i int, quote byte) (int, bool) {
	j := i + 1
	for j < len(content) && isSpace(content[j]) {
		j++
	}
	if j >= len(content) || content[j] != '.' {
		return 0, false
	}
	j++
	for j < len(content) && isSpace(content[j]) {
		j++
	}
	if j >= len(content) || content[j] != quote {
		return 0, false
	}
	return j + 1, true
}

func copyUntilNewline(content []byte, i int, emit func(int)) int {
	for i < len(content) && content[i] != '\n' {
		emit(i)
		i++
	}
	if i < len(content) {
		emit(i)
		i++
	}
	return i
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}
