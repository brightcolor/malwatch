package rules

// chrFold is one resolved chr() call.
type chrFold struct {
	b     byte // the character PHP would produce
	next  int  // offset just past the closing bracket
	arith bool // the argument was arithmetic, not a plain number
}

// foldChr resolves a chr() call whose argument is a literal number, or
// arithmetic on literal numbers.
//
// It exists for one family, which spells a function name a character at a time:
//
//	$v = 's'."\164"."\x72".chr(95)."\162"."\x6f".chr(116)."\61"."\x33";
//
// That is str_rot13. The string parts already glue together, but chr(95) is a
// call rather than a literal, so the underscore never arrives and the name is
// never spelled out. 272 backdoors on one site went unreported for exactly
// this reason.
//
// Only literal operands are folded. chr($i) depends on what the program does
// and has no answer here; chr(187-73) has exactly one, and honest code has no
// reason to write it.
func foldChr(content []byte, i int) (chrFold, bool) {
	if i+3 > len(content) {
		return chrFold{}, false
	}
	if content[i]|0x20 != 'c' || content[i+1]|0x20 != 'h' || content[i+2]|0x20 != 'r' {
		return chrFold{}, false
	}
	// A name byte in front means this is the tail of a longer identifier, and
	// $chr, ->chr and ::chr are something else entirely.
	if i > 0 {
		switch p := content[i-1]; {
		case isNameByte(p), p == '$', p == '>', p == ':':
			return chrFold{}, false
		}
	}

	j := skipGap(content, i+3)
	if j >= len(content) || content[j] != '(' {
		return chrFold{}, false
	}
	v, arith, j, ok := intExpr(content, skipGap(content, j+1))
	if !ok {
		return chrFold{}, false
	}
	j = skipGap(content, j)
	if j >= len(content) || content[j] != ')' {
		return chrFold{}, false
	}
	// PHP wraps the argument into a byte, negative values included.
	return chrFold{b: byte(((v % 256) + 256) % 256), next: j + 1, arith: arith}, true
}

// intExpr reads a decimal number, optionally one operator and a second number.
//
// Two operands are enough. The point is not to evaluate PHP but to read the one
// shape this obfuscator emits, where every character is written as a difference.
func intExpr(content []byte, j int) (value int, arith bool, next int, ok bool) {
	left, j, ok := decimal(content, j)
	if !ok {
		return 0, false, 0, false
	}
	k := skipGap(content, j)
	if k >= len(content) {
		return left, false, j, true
	}
	op := content[k]
	if op != '+' && op != '-' && op != '*' {
		return left, false, j, true
	}
	right, after, ok := decimal(content, skipGap(content, k+1))
	if !ok {
		return left, false, j, true
	}
	switch op {
	case '+':
		return left + right, true, after, true
	case '-':
		return left - right, true, after, true
	}
	return left * right, true, after, true
}

func decimal(content []byte, j int) (int, int, bool) {
	start := j
	v := 0
	for j < len(content) && content[j] >= '0' && content[j] <= '9' {
		v = v*10 + int(content[j]-'0')
		j++
		// A number this long is not a character code, and carrying on would
		// overflow rather than fail.
		if v > 1<<20 {
			return 0, 0, false
		}
	}
	if j == start {
		return 0, 0, false
	}
	return v, j, true
}

// isChainElement reports whether a concatenation chain can begin at i.
func isChainElement(content []byte, i int) bool {
	if i >= len(content) {
		return false
	}
	if content[i] == '\'' || content[i] == '"' {
		return true
	}
	_, ok := foldChr(content, i)
	return ok
}

func isNameByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// emitChain copies one concatenation chain - string literals and chr() calls
// joined by dots - dropping the dots and the quotes between the parts so the
// pieces become the one word they spell.
//
// The chain's outer quotes are kept, so a rule that asks whether an address
// sits inside a string can still tell.
//
// It reports false when a literal never closes. Carrying on from an unknown
// state is what produced corrupted views, and the caller drops the second view
// rather than guess.
func emitChain(content []byte, i int, out *[]byte, index *[]int32) (int, int, bool) {
	put := func(b byte, at int) {
		*out = append(*out, b)
		*index = append(*index, int32(at))
	}

	seams := 0
	first := true
	for {
		closeAt, quote := -1, byte(0)

		if fold, ok := foldChr(content, i); ok {
			put(fold.b, i)
			i = fold.next
			// A plain chr(65) is not worth a second pass on its own; written
			// as chr(187-73) it is the whole reason this exists.
			if fold.arith {
				seams++
			}
		} else {
			quote = content[i]
			if first {
				put(quote, i)
			}
			end, escapes, ok := copyLiteral(content, i+1, quote, put)
			if !ok {
				return 0, 0, false
			}
			seams += escapes
			closeAt = end
			i = end + 1
		}
		first = false

		// Does a dot carry the chain into another element?
		carries, nextStart := false, 0
		if j := skipGap(content, i); j < len(content) && content[j] == '.' {
			if k := skipGap(content, j+1); isChainElement(content, k) {
				carries, nextStart = true, k
			}
		}

		if closeAt >= 0 && !carries {
			put(quote, closeAt)
		}
		if !carries {
			return i, seams, true
		}
		seams++
		i = nextStart
	}
}

// copyLiteral copies a literal's body and returns the offset of its closing
// quote, together with the number of escapes it resolved.
//
// Escapes are resolved in a double quoted literal only, and only \xNN and \NNN:
// PHP reads "\x5f\107\x45\x54" as _GET, and a rule that spells out the
// superglobal has to be able to see that. \n and \t are everyday text and
// resolving them would gain nothing.
func copyLiteral(content []byte, i int, quote byte, put func(byte, int)) (int, int, bool) {
	escapes := 0
	for i < len(content) {
		if content[i] == '\\' {
			if quote == '"' {
				if b, width, ok := decodeEscape(content[i:]); ok {
					put(b, i)
					escapes++
					i += width
					continue
				}
			}
			put(content[i], i)
			i++
			if i < len(content) {
				put(content[i], i)
				i++
			}
			continue
		}
		if content[i] == quote {
			return i, escapes, true
		}
		put(content[i], i)
		i++
	}
	return 0, 0, false
}
