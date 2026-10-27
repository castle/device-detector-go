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
//   - children[state] are the trie children of state. The root's children
//     are also copied into the dense rootNext table, because the scan falls
//     back to the root on most bytes.
//   - endingLiterals[state] lists the literals that end exactly at state.
//     Ends are not only leaves: with literals "sm-a" and "sm-a1", the "sm-a"
//     state has both an ending literal and a child.
//   - failure[state] is the state for the longest proper suffix of state's
//     prefix that is also a prefix in the trie. When the next byte has no
//     child from state, the scan moves to failure[state] and tries again, so
//     it never re-reads input: after reading "iphon", a byte with no child
//     continues from wherever the suffixes of "iphon" lead, not from the
//     start of the text.
//   - nextEnding[state] is the nearest state on state's failure chain with
//     an ending literal, or -1. It reports literals that end inside a longer
//     match: on reaching "iphone", nextEnding leads to "phone".
//
// # Example
//
// With the literals "iphone", "phone" and "sm-a1", scanning "(iphone; cpu"
// stays at the root for "(", walks i-p-h-o-n to state "iphon", and on "e"
// reaches state "iphone": it reports "iphone" from endingLiterals and "phone"
// through nextEnding. On ";" no child exists, the failure chain leads back to
// the root, and the rest of the text reports nothing. "sm-a1" is never
// examined.
//
// # Construction
//
// newACMatcher inserts every literal into the trie, then computes failure and
// nextEnding breadth-first: a state's failure target is always shallower, so
// it is final by the time its children need it. The automaton is immutable
// after construction and safe for concurrent scans.
type acMatcher struct {
	rootNext       [256]int32
	children       [][]trieEdge
	failure        []int32
	endingLiterals [][]int32
	nextEnding     []int32
}

// trieEdge is one trie child: the byte that leads to it and its state.
type trieEdge struct {
	label byte
	state int32
}

// newACMatcher builds the automaton for literals. The ids scan reports are
// indexes into literals.
func newACMatcher(literals []string) *acMatcher {
	matcher := &acMatcher{children: [][]trieEdge{nil}, endingLiterals: [][]int32{nil}}

	for literalID, literal := range literals {
		state := int32(0)

		for position := 0; position < len(literal); position++ {
			label := literal[position]

			child := matcher.child(state, label)
			if child < 0 {
				child = int32(len(matcher.children))
				matcher.children = append(matcher.children, nil)
				matcher.endingLiterals = append(matcher.endingLiterals, nil)
				matcher.children[state] = append(matcher.children[state], trieEdge{label, child})
			}

			state = child
		}

		matcher.endingLiterals[state] = append(matcher.endingLiterals[state], int32(literalID))
	}

	stateCount := len(matcher.children)
	matcher.failure = make([]int32, stateCount)
	matcher.nextEnding = make([]int32, stateCount)
	matcher.nextEnding[0] = -1

	// Depth-1 states fail to the root; everything deeper is filled in
	// breadth-first from its parent's failure target.
	queue := make([]int32, 0, stateCount)

	for _, edge := range matcher.children[0] {
		matcher.rootNext[edge.label] = edge.state
		matcher.nextEnding[edge.state] = -1
		queue = append(queue, edge.state)
	}

	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]

		for _, edge := range matcher.children[parent] {
			failureTarget := matcher.next(matcher.failure[parent], edge.label)
			matcher.failure[edge.state] = failureTarget

			if len(matcher.endingLiterals[failureTarget]) > 0 {
				matcher.nextEnding[edge.state] = failureTarget
			} else {
				matcher.nextEnding[edge.state] = matcher.nextEnding[failureTarget]
			}

			queue = append(queue, edge.state)
		}
	}

	return matcher
}

// child returns state's trie child on label, or -1. Below the root most states
// have one or two children, so a linear scan beats a map.
func (matcher *acMatcher) child(state int32, label byte) int32 {
	for _, edge := range matcher.children[state] {
		if edge.label == label {
			return edge.state
		}
	}

	return -1
}

// next is the state after reading label in state: state's child on label if
// it has one, otherwise the same question asked of failure[state], ending at
// the root (whose missing children stay at the root).
func (matcher *acMatcher) next(state int32, label byte) int32 {
	for state != 0 {
		if child := matcher.child(state, label); child >= 0 {
			return child
		}

		state = matcher.failure[state]
	}

	return matcher.rootNext[label]
}

// scan calls hit with the id of every literal occurrence in text, in order of
// where each occurrence ends. A literal that occurs several times is reported
// each time.
func (matcher *acMatcher) scan(text string, hit func(literalID int32)) {
	state := int32(0)

	for position := 0; position < len(text); position++ {
		state = matcher.next(state, text[position])

		for ending := state; ending > 0; ending = matcher.nextEnding[ending] {
			for _, literalID := range matcher.endingLiterals[ending] {
				hit(literalID)
			}
		}
	}
}
