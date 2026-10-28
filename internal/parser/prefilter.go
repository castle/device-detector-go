package parser

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// This file implements the RE2 prefilter gate. Every database pattern gets a
// companion stdlib-regexp (RE2) version that is a SUPERSET of the regexp2
// pattern's "does it match?" semantics: if the RE2 gate says no, the regexp2
// engine cannot match either, so the expensive backtracking run is skipped.
// If the gate says yes (or the pattern cannot be gated), regexp2 runs and
// remains the single source of truth for match results and capture groups —
// parity is preserved by construction, not by auditing thousands of patterns.
//
// RE2 matches in time linear in the input regardless of pattern size, which
// collapses the aggregate walk cost on junk input (the ReDoS long tail) and
// removes most negative-match cost on real traffic.
//
// Superset construction rules (.NET regexp2 semantics -> RE2):
//   - compiled WITHOUT the uaAnchor and with (?m): anchoring only narrows
//     matches, and (?m) makes ^/$ per-line, a superset of .NET's "$ also
//     matches before a trailing newline".
//   - \d and \w are ASCII-only in RE2 but Unicode in .NET -> widened to the
//     .NET-equivalent Unicode classes. \s likewise. Their negations (\D \W
//     \S) are already wider in RE2 and stay as-is.
//   - patterns using constructs whose RE2 semantics could be NARROWER and
//     cannot be widened mechanically (word boundaries \b/\B, which depend on
//     the \w alphabet) are not gated.
//   - anything RE2 fails to compile (lookaround, backreferences, atomic
//     groups, possessive quantifiers, .NET named-group syntax not translated
//     below) is not gated: those patterns always run the full regexp2 path.

// re2Translate rewrites a database pattern (already normalizePattern'd) into
// its RE2 superset form, or reports ok=false when the pattern must not be
// gated.
func re2Translate(p string) (string, bool) {
	// Word boundaries depend on the \w alphabet, which is narrower in RE2;
	// a mechanical widening does not exist, so skip the gate entirely.
	if strings.Contains(p, `\b`) || strings.Contains(p, `\B`) {
		return "", false
	}

	var b strings.Builder

	b.Grow(len(p) + 16)

	// The widened classes are emitted bracketed outside a character class and
	// as bare member lists inside one ([\d.] must become [0-9\p{Nd}.], not a
	// nested-bracket mangle).
	const (
		dClass = `0-9\p{Nd}`                         // .NET \d = Unicode decimal digits
		wClass = `0-9A-Za-z_\p{L}\p{Mn}\p{Nd}\p{Pc}` // .NET \w = letters/marks/digits/connector
		sClass = `\t\n\v\f\r \p{Z}\x{0085}`          // .NET \s adds Unicode separators
	)

	inClass := false

	for i := 0; i < len(p); i++ {
		c := p[i]

		if c == '\\' && i+1 < len(p) {
			var widened string

			switch p[i+1] {
			case 'd':
				widened = dClass
			case 'w':
				widened = wClass
			case 's':
				widened = sClass
			}

			if widened != "" {
				if inClass {
					b.WriteString(widened)
				} else {
					b.WriteString(`[` + widened + `]`)
				}
			} else {
				b.WriteByte(c)
				b.WriteByte(p[i+1])
			}

			i++

			continue
		}

		if c == '[' && !inClass {
			inClass = true
		} else if c == ']' && inClass {
			inClass = false
		}

		// Translate .NET named groups "(?<name>" / "(?'name'" to RE2 "(?P<name>".
		// Lookbehind "(?<=" / "(?<!" must stay untouched so RE2 rejects it.
		if c == '(' && i+2 < len(p) && p[i+1] == '?' {
			next := p[i+2]
			if (next == '<' && i+3 < len(p) && p[i+3] != '=' && p[i+3] != '!') || next == '\'' {
				b.WriteString("(?P<")

				closer := byte('>')
				if next == '\'' {
					closer = '\''
				}

				j := i + 3
				for j < len(p) && p[j] != closer {
					b.WriteByte(p[j])
					j++
				}

				b.WriteByte('>')

				i = j // consume up to and including the closer

				continue
			}
		}

		b.WriteByte(c)
	}

	return b.String(), true
}

// minGateLiteral keeps probe literals selective; branches whose best literal
// is shorter go to the always-walk list instead of admitting most inputs.
const minGateLiteral = 3

// literalCover walks a parsed regex and returns literals such that any match
// must contain at least one of them. Where it has a choice, it avoids the
// shared literals (see sharedLiterals).
func literalCover(node *syntax.Regexp, shared map[string]bool) ([]string, bool) {
	switch node.Op {
	case syntax.OpLiteral:
		return []string{string(node.Rune)}, true

	case syntax.OpCapture:
		return literalCover(node.Sub[0], shared)

	case syntax.OpPlus:
		// The body occurs at least once.
		return literalCover(node.Sub[0], shared)

	case syntax.OpRepeat:
		if node.Min >= 1 {
			return literalCover(node.Sub[0], shared)
		}

		return nil, false

	case syntax.OpConcat:
		// Any mandatory part covers the whole concat; pick the best-scoring
		// one (most selective probe).
		var best []string

		bestScore := -1

		for _, part := range node.Sub {
			cover, ok := literalCover(part, shared)
			if !ok {
				continue
			}

			if score := coverScore(cover, shared); score > bestScore {
				best, bestScore = cover, score
			}
		}

		// A run of consecutive parts with a small finite language expands to
		// exact strings: a(?:101|110) yields a101 and a110, not just a.
		for start := range node.Sub {
			expanded := []string{""}

			for end := start; end < len(node.Sub); end++ {
				partStrings, endsRun, ok := windowPart(node.Sub[end])
				if !ok {
					break
				}

				if expanded = product(expanded, partStrings); expanded == nil {
					break
				}

				if score := coverScore(expanded, shared); score > bestScore {
					best, bestScore = expanded, score
				}

				if endsRun {
					break
				}
			}
		}

		return best, best != nil

	case syntax.OpAlternate:
		// Every branch must contribute, else a literal-free branch could
		// match without any probe hitting.
		var union []string

		for _, branch := range node.Sub {
			cover, ok := literalCover(branch, shared)
			if !ok {
				return nil, false
			}

			union = append(union, cover...)
		}

		return union, true

	default:
		// Char classes, anchors, stars, empty matches: no literal to prove.
		return nil, false
	}
}

// GateStats reports how many cached patterns carry an RE2 gate. Diagnostic
// only (used by tests and benchmarks to prove coverage).
func GateStats() (gated, total int) {
	regexCache.Range(func(_, v any) bool {
		total++

		if v.(*Compiled).quickCheck() != nil {
			gated++
		}

		return true
	})

	return gated, total
}

// compileGate builds the RE2 gate for a raw database pattern, or nil when the
// pattern cannot be gated (regexp2 then always runs). Case-insensitive and
// multiline per the superset rules; unanchored on purpose.
func compileGate(pattern string) *regexp.Regexp {
	translated, ok := re2Translate(normalizePattern(pattern))
	if !ok {
		return nil
	}

	gate, err := regexp.Compile(`(?im)(?:` + translated + `)`)
	if err != nil {
		return nil // lookaround, backrefs, PCRE-isms: full regexp2 path
	}

	return gate
}

// stripLookarounds drops lookaround groups and word boundaries. Each only
// narrows what a pattern matches, so the result matches a superset of inputs
// and its literal cover still gates the original pattern.
func stripLookarounds(pattern string) string {
	var stripped strings.Builder

	for position := 0; position < len(pattern); position++ {
		switch {
		case pattern[position] == '\\' && position+1 < len(pattern):
			if escaped := pattern[position+1]; escaped == 'b' || escaped == 'B' {
				position++

				continue
			}

			stripped.WriteByte(pattern[position])
			stripped.WriteByte(pattern[position+1])
			position++

		case pattern[position] == '(' && isLookaround(pattern[position:]):
			// Skip to the group's closing parenthesis, stepping over escapes.
			depth := 0

			for ; position < len(pattern); position++ {
				if pattern[position] == '\\' {
					position++

					continue
				}

				if pattern[position] == '(' {
					depth++
				} else if pattern[position] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}

		default:
			stripped.WriteByte(pattern[position])
		}
	}

	return stripped.String()
}

func isLookaround(group string) bool {
	return strings.HasPrefix(group, "(?=") || strings.HasPrefix(group, "(?!") ||
		strings.HasPrefix(group, "(?<=") || strings.HasPrefix(group, "(?<!")
}

// maxExpand caps how many exact strings one sub-pattern may expand into.
const maxExpand = 64

// exactSet returns every string node can match when that set is small and
// finite, lowercased. ok=false for anything unbounded or too large.
func exactSet(node *syntax.Regexp) ([]string, bool) {
	switch node.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(node.Rune))}, true

	case syntax.OpEmptyMatch:
		return []string{""}, true

	case syntax.OpCapture:
		return exactSet(node.Sub[0])

	case syntax.OpCharClass:
		// node.Rune holds the class as inclusive [low, high] pairs.
		var members []string

		for pair := 0; pair < len(node.Rune); pair += 2 {
			low, high := node.Rune[pair], node.Rune[pair+1]
			if high-low >= maxExpand {
				return nil, false
			}

			for member := low; member <= high; member++ {
				members = append(members, strings.ToLower(string(member)))
			}
		}

		members = dedupe(members)

		return members, len(members) <= maxExpand

	case syntax.OpQuest:
		optional, ok := exactSet(node.Sub[0])
		if !ok {
			return nil, false
		}

		return dedupe(append(optional, "")), true

	case syntax.OpConcat:
		expanded := []string{""}

		for _, part := range node.Sub {
			partStrings, ok := exactSet(part)
			if !ok {
				return nil, false
			}

			if expanded = product(expanded, partStrings); expanded == nil {
				return nil, false
			}
		}

		return expanded, true

	case syntax.OpAlternate:
		var union []string

		for _, branch := range node.Sub {
			branchStrings, ok := exactSet(branch)
			if !ok {
				return nil, false
			}

			union = append(union, branchStrings...)
		}

		union = dedupe(union)

		return union, len(union) <= maxExpand

	default:
		return nil, false
	}
}

// product concatenates every prefix with every suffix, or nil past maxExpand.
func product(prefixes, suffixes []string) []string {
	if len(prefixes)*len(suffixes) > maxExpand {
		return nil
	}

	combined := make([]string, 0, len(prefixes)*len(suffixes))
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			combined = append(combined, prefix+suffix)
		}
	}

	return dedupe(combined)
}

// dedupe drops repeated strings in place, keeping first occurrences in order.
func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := values[:0]

	for _, value := range values {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			unique = append(unique, value)
		}
	}

	return unique
}

// shortestLength is the length of the shortest of literals.
func shortestLength(literals []string) int {
	shortest := len(literals[0])
	for _, literal := range literals {
		shortest = min(shortest, len(literal))
	}

	return shortest
}

// windowPart is what one concat part contributes to a run of exact strings.
// A part repeated at least once contributes one iteration and ends the run:
// GO[0-9]{3,4} means the match contains "go" and a digit, then more.
func windowPart(node *syntax.Regexp) (partStrings []string, endsRun, ok bool) {
	if partStrings, ok := exactSet(node); ok {
		return partStrings, false, true
	}

	if node.Op == syntax.OpPlus || (node.Op == syntax.OpRepeat && node.Min >= 1) {
		partStrings, ok := exactSet(node.Sub[0])

		return partStrings, true, ok
	}

	return nil, false, false
}

// coverScore ranks a candidate literal cover: one whose literals are not
// shared admits fewer user agents, so it beats a shared one; then the
// shortest literal's length decides.
func coverScore(cover []string, shared map[string]bool) int {
	for _, literal := range cover {
		if isShared(strings.ToLower(literal), shared) {
			return shortestLength(cover)
		}
	}

	return 1000 + shortestLength(cover)
}

// isShared reports whether literal is a shared literal or occurs inside one:
// every UA containing "android 0" also contains "android ", so "android " is
// at least as common.
func isShared(literal string, shared map[string]bool) bool {
	if shared[literal] {
		return true
	}

	for sharedLiteral := range shared {
		if strings.Contains(sharedLiteral, literal) {
			return true
		}
	}

	return false
}
