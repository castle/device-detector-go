package parser

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func TestACMatcherFindsEveryLiteral(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	randomWord := func(length int) string {
		word := make([]byte, length)
		for position := range word {
			word[position] = "abc"[random.IntN(3)]
		}

		return string(word)
	}

	for round := 0; round < 200; round++ {
		literals := make([]string, 1+random.IntN(30))
		for literalID := range literals {
			literals[literalID] = randomWord(1 + random.IntN(5))
		}

		matcher := newACMatcher(literals)
		text := randomWord(random.IntN(40))

		reported := map[int32]bool{}
		matcher.scan(text, func(literalID int32) { reported[literalID] = true })

		for literalID, literal := range literals {
			contains := strings.Contains(text, literal)
			if contains != reported[int32(literalID)] {
				t.Fatalf("round %d: literal %q in %q: strings.Contains=%v, matcher=%v",
					round, literal, text, contains, reported[int32(literalID)])
			}
		}
	}
}

func TestACMatcherReportsLiteralsInsideLongerMatches(t *testing.T) {
	literals := []string{"iphone", "phone", "sm-a1"}
	matcher := newACMatcher(literals)

	var reported []string
	matcher.scan("(iphone; cpu", func(literalID int32) { reported = append(reported, literals[literalID]) })

	if want := []string{"iphone", "phone"}; !slices.Equal(reported, want) {
		t.Errorf("scan reported %v, want %v", reported, want)
	}
}
