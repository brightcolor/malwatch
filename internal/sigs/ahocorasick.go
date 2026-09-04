// Package sigs implements the signature stage: known-bad file hashes and
// byte patterns, in the format published by Linux Malware Detect.
package sigs

// matcher is an Aho-Corasick automaton over byte patterns. It finds every
// pattern in one pass over the content, which is what makes a few thousand
// signatures affordable on a tree with hundreds of thousands of files.
type matcher struct {
	// next[state] maps a byte to the next state. A map per state keeps the
	// automaton small; a dense 256-wide table over ~100k states would cost
	// far more memory than the scan saves.
	next   []map[byte]int32
	fail   []int32
	output [][]int32 // pattern indices ending in this state
}

type acBuilder struct {
	m *matcher
}

func newBuilder() *acBuilder {
	m := &matcher{
		next:   []map[byte]int32{{}},
		fail:   []int32{0},
		output: [][]int32{nil},
	}
	return &acBuilder{m: m}
}

// add inserts a pattern and records its index.
func (b *acBuilder) add(pattern []byte, index int32) {
	if len(pattern) == 0 {
		return
	}
	state := int32(0)
	for _, c := range pattern {
		nxt, ok := b.m.next[state][c]
		if !ok {
			nxt = int32(len(b.m.next))
			b.m.next[state][c] = nxt
			b.m.next = append(b.m.next, map[byte]int32{})
			b.m.fail = append(b.m.fail, 0)
			b.m.output = append(b.m.output, nil)
		}
		state = nxt
	}
	b.m.output[state] = append(b.m.output[state], index)
}

// build computes the failure links. Must be called once, after all patterns
// are added.
func (b *acBuilder) build() *matcher {
	m := b.m
	queue := make([]int32, 0, len(m.next))
	for c, s := range m.next[0] {
		_ = c
		m.fail[s] = 0
		queue = append(queue, s)
	}
	for i := 0; i < len(queue); i++ {
		state := queue[i]
		for c, nxt := range m.next[state] {
			f := m.fail[state]
			for {
				if t, ok := m.next[f][c]; ok {
					m.fail[nxt] = t
					break
				}
				if f == 0 {
					m.fail[nxt] = 0
					break
				}
				f = m.fail[f]
			}
			// Merge the failure state's outputs so a match is never missed
			// because a shorter pattern ends inside a longer one.
			m.output[nxt] = append(m.output[nxt], m.output[m.fail[nxt]]...)
			queue = append(queue, nxt)
		}
	}
	return m
}

// hit is one pattern occurrence.
type hit struct {
	index int32
	end   int // byte offset just past the match
}

// findAll walks content once and reports the first occurrence of each
// pattern. Repeats of the same pattern are dropped: one signature hit per
// file is one finding.
func (m *matcher) findAll(content []byte) []hit {
	if m == nil || len(m.next) <= 1 {
		return nil
	}
	var out []hit
	seen := map[int32]bool{}
	state := int32(0)
	for i := 0; i < len(content); i++ {
		c := content[i]
		for {
			if nxt, ok := m.next[state][c]; ok {
				state = nxt
				break
			}
			if state == 0 {
				break
			}
			state = m.fail[state]
		}
		for _, idx := range m.output[state] {
			if seen[idx] {
				continue
			}
			seen[idx] = true
			out = append(out, hit{index: idx, end: i + 1})
		}
	}
	return out
}
