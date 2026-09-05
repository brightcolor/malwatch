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
	atLineStart := true
	for i < len(content) {
		c := content[i]
		wasLineStart := atLineStart
		if c == '\n' {
			atLineStart = true
		} else if !isSpace(c) {
			atLineStart = false
		}

		// A comment collapses to a single space. It is whitespace to PHP, and
		// leaving it in was what let one payload write
		//
		//	@require_once /*-x-*/ $T /*-y-*/ [9+1]
		//
		// past every rule that names require. The space keeps two tokens from
		// growing together; the offset stays that of the comment, so a finding
		// still points at the right line.
		//
		// They are recognised before strings on purpose: an apostrophe in a
		// German comment would otherwise open a string that runs to the next
		// one, and every join in between would be nonsense.
		if c == '#' || (c == '/' && i+1 < len(content) && content[i+1] == '/') {
			out = append(out, ' ')
			index = append(index, i)
			for i < len(content) && content[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(content) && content[i+1] == '*' {
			out = append(out, ' ')
			index = append(index, i)
			// Only a comment wedged into an expression counts as a reason to
			// look at the file twice. Licence headers and doc blocks start
			// their line, and treating those as a transformation would double
			// the work of every scan for nothing.
			if !wasLineStart {
				seams++
			}
			i += 2
			for i+1 < len(content) && !(content[i] == '*' && content[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}

		if c != '\'' && c != '"' {
			emit(i)
			i++
			continue
		}

		// A string literal. Copy it, swallow every seam that follows, and in a
		// double quoted one resolve the escapes: PHP reads "\x5f\107\x45\x54"
		// as _GET, and a rule that spells out the superglobal has to be able to
		// see that.
		quote := c
		emit(i)
		i++
		closed := false
		for i < len(content) {
			if content[i] == '\\' {
				if quote == '"' {
					if b, width, ok := decodeEscape(content[i:]); ok {
						out = append(out, b)
						index = append(index, i)
						seams++
						i += width
						continue
					}
				}
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
	j := skipGap(content, i+1)
	if j >= len(content) || content[j] != '.' {
		return 0, false
	}
	j = skipGap(content, j+1)
	if j >= len(content) || content[j] != quote {
		return 0, false
	}
	return j + 1, true
}

// skipGap walks over whitespace and comments.
//
// Comments belong here because a payload writes "ra"/*-X8KKH~;-*/."nge" to
// keep the word out of the file: only whitespace between the parts would let
// that one through.
func skipGap(content []byte, j int) int {
	for j < len(content) {
		if isSpace(content[j]) {
			j++
			continue
		}
		if content[j] == '/' && j+1 < len(content) && content[j+1] == '*' {
			j += 2
			for j+1 < len(content) && !(content[j] == '*' && content[j+1] == '/') {
				j++
			}
			j += 2
			continue
		}
		if content[j] == '/' && j+1 < len(content) && content[j+1] == '/' {
			for j < len(content) && content[j] != '\n' {
				j++
			}
			continue
		}
		break
	}
	return j
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// decodeEscape resolves one \xNN or \NNN escape and reports how many bytes
// it consumed.
//
// Only those two: \n and \t are everyday text and resolving them would gain
// nothing, while a hex or octal escape in a string is almost always somebody
// spelling a name they would rather not write out.
func decodeEscape(b []byte) (byte, int, bool) {
	if len(b) < 2 || b[0] != '\\' {
		return 0, 0, false
	}
	if b[1] == 'x' || b[1] == 'X' {
		n, width := 0, 0
		for width < 2 && 2+width < len(b) && isHex(b[2+width]) {
			n = n*16 + hexVal(b[2+width])
			width++
		}
		if width == 0 {
			return 0, 0, false
		}
		return byte(n), 2 + width, true
	}
	if b[1] >= '0' && b[1] <= '7' {
		n, width := 0, 0
		for width < 3 && 1+width < len(b) && b[1+width] >= '0' && b[1+width] <= '7' {
			n = n*8 + int(b[1+width]-'0')
			width++
		}
		return byte(n), 1 + width, true
	}
	return 0, 0, false
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	default:
		return int(b-'A') + 10
	}
}
