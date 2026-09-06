package rules

// skipHeredoc copies a heredoc or nowdoc through unchanged and returns the
// offset just past its closing label.
//
// It reports false when the opening does not parse or the label never comes
// back. Carrying on from an unknown state is what produces a corrupted view,
// and the caller drops the second view entirely rather than guess.
func skipHeredoc(content []byte, i int, emit func(int)) (int, bool) {
	j := i + 3
	for j < len(content) && (content[j] == ' ' || content[j] == '\t') {
		j++
	}

	// <<<LABEL, <<<"LABEL" and <<<'LABEL' all open a body; the quote only
	// decides whether PHP interpolates inside it, which does not matter here.
	quote := byte(0)
	if j < len(content) && (content[j] == '\'' || content[j] == '"') {
		quote = content[j]
		j++
	}
	start := j
	for j < len(content) && isLabelByte(content[j]) {
		j++
	}
	if j == start {
		return 0, false
	}
	label := content[start:j]
	if quote != 0 {
		if j >= len(content) || content[j] != quote {
			return 0, false
		}
		j++
	}
	for j < len(content) && content[j] != '\n' {
		j++
	}

	// The body ends at the first line that begins with the label, optionally
	// indented, and does not continue into a longer word.
	for k := j; k < len(content); k++ {
		if content[k] != '\n' {
			continue
		}
		m := k + 1
		for m < len(content) && (content[m] == ' ' || content[m] == '\t') {
			m++
		}
		if m+len(label) > len(content) {
			break
		}
		if !equalBytes(content[m:m+len(label)], label) {
			continue
		}
		after := m + len(label)
		if after < len(content) && isLabelByte(content[after]) {
			continue
		}
		for n := i; n < after; n++ {
			emit(n)
		}
		return after, true
	}
	return 0, false
}

func isLabelByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
