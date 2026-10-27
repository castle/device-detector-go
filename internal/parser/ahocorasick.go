package parser

// acMatcher is an Aho-Corasick automaton: it finds every one of a fixed set
// of literals that occurs in a text, in one left-to-right pass whose cost is
// proportional to the text's length plus the number of hits, however many
// literals there are. GateSet uses it to learn which of its thousands of
// literals occur in a user agent, in place of one strings.Contains per literal.
//
// It works on bytes. Callers lowercase both the literals and the text, so a
// literal and the text compare byte for byte (UTF-8 included).
//
// # Structure
//
// States are the nodes of a trie of the literals: state 0 is the root (the
// empty prefix) and every other state is the prefix spelled by the path to it.
// Literals sharing a prefix share states: "sm-a1" and "sm-g9" share "sm-".
//
//   - edges[s] are the trie children of s. The root's children are also
//     copied into the dense root table, because the scan falls back to the
//     root on most bytes.
//   - out[s] lists the literals that end exactly at s. Ends are not only
//     leaves: with literals "sm-a" and "sm-a1", the "sm-a" state has both an
//     output and a child.
//   - fail[s] is the state for the longest proper suffix of s's prefix that
//     is also a prefix in the trie. When the next byte has no edge from s,
//     the scan moves to fail[s] and tries again, so it never re-reads input:
//     after reading "iphon", a "p" with no edge continues from wherever the
//     suffixes of "iphon" lead, not from the start of the text.
//   - dict[s] is the nearest state on s's failure chain with a non-empty out,
//     or -1. It reports literals that end inside a longer match: on reaching
//     "iphone", dict leads to "phone".
//
// # Example
//
// With the literals "iphone", "phone" and "sm-a1", scanning "(iphone; cpu"
// stays at the root for "(", walks i-p-h-o-n to state "iphon", and on "e"
// reaches state "iphone": it reports "iphone" from out and "phone" through
// dict. On ";" no edge exists, the failure chain leads back to the root, and
// the rest of the text reports nothing. "sm-a1" is never examined.
//
// # Construction
//
// newACMatcher inserts every literal into the trie, then computes fail and
// dict breadth-first: a state's failure target is always shallower, so it is
// final by the time its children need it. The automaton is immutable after
// construction and safe for concurrent scans.
type acMatcher struct {
	root  [256]int32
	edges [][]acEdge
	fail  []int32
	out   [][]int32
	dict  []int32
}

// acEdge is one trie child: the byte that leads to it and its state.
type acEdge struct {
	b  byte
	to int32
}

// newACMatcher builds the automaton for lits. The ids scan reports are
// indexes into lits.
func newACMatcher(lits []string) *acMatcher {
	m := &acMatcher{edges: [][]acEdge{nil}, out: [][]int32{nil}}

	for id, l := range lits {
		s := int32(0)

		for i := 0; i < len(l); i++ {
			n := m.child(s, l[i])
			if n < 0 {
				n = int32(len(m.edges))
				m.edges = append(m.edges, nil)
				m.out = append(m.out, nil)
				m.edges[s] = append(m.edges[s], acEdge{l[i], n})
			}

			s = n
		}

		m.out[s] = append(m.out[s], int32(id))
	}

	m.fail = make([]int32, len(m.edges))
	m.dict = make([]int32, len(m.edges))
	m.dict[0] = -1

	// Depth-1 states fail to the root; everything deeper is filled in
	// breadth-first from its parent's failure target.
	queue := make([]int32, 0, len(m.edges))

	for _, e := range m.edges[0] {
		m.root[e.b] = e.to
		m.dict[e.to] = -1
		queue = append(queue, e.to)
	}

	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]

		for _, e := range m.edges[s] {
			f := m.next(m.fail[s], e.b)
			m.fail[e.to] = f

			if len(m.out[f]) > 0 {
				m.dict[e.to] = f
			} else {
				m.dict[e.to] = m.dict[f]
			}

			queue = append(queue, e.to)
		}
	}

	return m
}

// child returns s's trie child on b, or -1. Below the root most states have
// one or two children, so a linear scan beats a map.
func (m *acMatcher) child(s int32, b byte) int32 {
	for _, e := range m.edges[s] {
		if e.b == b {
			return e.to
		}
	}

	return -1
}

// next is the state after reading b in state s: s's child on b if it has one,
// otherwise the same question asked of fail[s], ending at the root (whose
// missing children stay at the root).
func (m *acMatcher) next(s int32, b byte) int32 {
	for s != 0 {
		if n := m.child(s, b); n >= 0 {
			return n
		}

		s = m.fail[s]
	}

	return m.root[b]
}

// scan calls hit with the id of every literal occurrence in s, in order of
// where each occurrence ends. A literal that occurs several times is reported
// each time.
func (m *acMatcher) scan(s string, hit func(lit int32)) {
	state := int32(0)

	for i := 0; i < len(s); i++ {
		state = m.next(state, s[i])

		for o := state; o > 0; o = m.dict[o] {
			for _, lit := range m.out[o] {
				hit(lit)
			}
		}
	}
}
