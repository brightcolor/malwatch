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
// The map exists because a finding has to name the line of the real file. It
// rests on one contract, which every branch below keeps: this function only
// ever drops bytes or replaces a run with a single space. It never inserts and
// never reorders, so an offset in the copy always maps back to a real one.
func joinConcatenated(content []byte) ([]byte, []int32) {
	if len(content) == 0 || len(content) > maxJoin {
		return nil, nil
	}

	out := make([]byte, 0, len(content))
	// int32 rather than int: the input is capped at maxJoin, and the map is
	// the same length as the view - eight bytes an entry would be half the
	// cost of a scan for nothing.
	index := make([]int32, 0, len(content))
	seams := 0

	emit := func(i int) {
		out = append(out, content[i])
		index = append(index, int32(i))
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
			index = append(index, int32(i))
			for i < len(content) && content[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(content) && content[i+1] == '*' {
			out = append(out, ' ')
			index = append(index, int32(i))
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

		// A heredoc or nowdoc body is text, not code. Walking into one welds its
		// content as though it were source: a README in a heredoc that mentions
		// 'base' . '64_decode' would manufacture the very name the rules look
		// for. Whether the scanner survived one at all used to depend on whether
		// the body happened to hold an even number of quotes.
		if c == '<' && i+2 < len(content) && content[i+1] == '<' && content[i+2] == '<' {
			next, ok := skipHeredoc(content, i, emit)
			if !ok {
				return nil, nil
			}
			i = next
			continue
		}

		// A concatenation chain of string literals and chr() calls. The dots
		// and the quotes between the parts fall away, so 'ba'."se".chr(54)."4"
		// becomes the word it spells.
		//
		// Quote styles may differ across a seam. PHP concatenates 's'."tr" into
		// str whatever quotes are used, and requiring the same one on both
		// sides let this family through unread.
		if c == '\'' || c == '"' || (c|0x20 == 'c' && isChainElement(content, i)) {
			next, chained, ok := emitChain(content, i, &out, &index)
			if !ok {
				// The scanner lost track - an unterminated string, a construct
				// not handled here. Guessing on from an unknown state is how
				// the false positives happened, so the second view is dropped
				// and the rules see the file as it is.
				return nil, nil
			}
			seams += chained
			i = next
			continue
		}

		emit(i)
		i++
	}

	if seams == 0 {
		return nil, nil
	}
	return out, index
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
