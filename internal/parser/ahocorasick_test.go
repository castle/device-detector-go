package parser

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func TestACMatcherFindsEveryLiteral(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "abc"[rng.IntN(3)]
		}

		return string(b)
	}

	for round := 0; round < 200; round++ {
		lits := make([]string, 1+rng.IntN(30))
		for i := range lits {
			lits[i] = word(1 + rng.IntN(5))
		}

		m := newACMatcher(lits)
		text := word(rng.IntN(40))

		got := map[int32]bool{}
		m.scan(text, func(lit int32) { got[lit] = true })

		for i, l := range lits {
			if strings.Contains(text, l) != got[int32(i)] {
				t.Fatalf("round %d: literal %q in %q: contains=%v, automaton=%v", round, l, text, !got[int32(i)], got[int32(i)])
			}
		}
	}
}

func TestACMatcherReportsLiteralsInsideLongerMatches(t *testing.T) {
	lits := []string{"iphone", "phone", "sm-a1"}
	m := newACMatcher(lits)

	var got []string
	m.scan("(iphone; cpu", func(lit int32) { got = append(got, lits[lit]) })

	if want := []string{"iphone", "phone"}; !slices.Equal(got, want) {
		t.Errorf("scan reported %v, want %v", got, want)
	}
}
