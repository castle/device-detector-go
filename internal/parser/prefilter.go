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
// must contain at least one of them.
func literalCover(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}, true

	case syntax.OpCapture:
		return literalCover(re.Sub[0])

	case syntax.OpPlus:
		// The body occurs at least once.
		return literalCover(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalCover(re.Sub[0])
		}

		return nil, false

	case syntax.OpConcat:
		// Any mandatory component covers the whole concat; pick the one with
		// the longest shortest-literal (most selective probe).
		var best []string

		bestScore := -1

		for _, sub := range re.Sub {
			lits, ok := literalCover(sub)
			if !ok {
				continue
			}

			if score := coverScore(lits); score > bestScore {
				best, bestScore = lits, score
			}
		}

		// A run of consecutive parts with a small finite language expands to
		// exact strings: a(?:101|110) yields a101 and a110, not just a.
		for i := range re.Sub {
			acc := []string{""}

			for j := i; j < len(re.Sub); j++ {
				set, last, ok := windowPart(re.Sub[j])
				if !ok {
					break
				}

				if acc = product(acc, set); acc == nil {
					break
				}

				if score := coverScore(acc); score > bestScore {
					best, bestScore = acc, score
				}

				if last {
					break
				}
			}
		}

		return best, best != nil

	case syntax.OpAlternate:
		// Every branch must contribute, else a literal-free branch could
		// match without any probe hitting.
		var all []string

		for _, sub := range re.Sub {
			lits, ok := literalCover(sub)
			if !ok {
				return nil, false
			}

			all = append(all, lits...)
		}

		return all, true

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

		if v.(*Compiled).gate != nil {
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
func stripLookarounds(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch {
		case p[i] == '\\' && i+1 < len(p):
			if p[i+1] == 'b' || p[i+1] == 'B' {
				i++
				continue
			}
			b.WriteByte(p[i])
			b.WriteByte(p[i+1])
			i++
		case p[i] == '(' && (strings.HasPrefix(p[i:], "(?=") || strings.HasPrefix(p[i:], "(?!") ||
			strings.HasPrefix(p[i:], "(?<=") || strings.HasPrefix(p[i:], "(?<!")):
			depth := 0
			for ; i < len(p); i++ {
				if p[i] == '\\' {
					i++
					continue
				}
				if p[i] == '(' {
					depth++
				} else if p[i] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
		default:
			b.WriteByte(p[i])
		}
	}
	return b.String()
}

// maxExpand caps how many exact strings one sub-pattern may expand into.
const maxExpand = 64

// exactSet returns every string re can match when that set is small and
// finite, lowercased. ok=false for anything unbounded or too large.
func exactSet(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}, true

	case syntax.OpEmptyMatch:
		return []string{""}, true

	case syntax.OpCapture:
		return exactSet(re.Sub[0])

	case syntax.OpCharClass:
		var out []string

		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i+1]-re.Rune[i] >= maxExpand {
				return nil, false
			}

			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				out = append(out, strings.ToLower(string(r)))
			}
		}

		out = dedupe(out)

		return out, len(out) <= maxExpand

	case syntax.OpQuest:
		set, ok := exactSet(re.Sub[0])
		if !ok {
			return nil, false
		}

		return dedupe(append(set, "")), true

	case syntax.OpConcat:
		acc := []string{""}

		for _, sub := range re.Sub {
			set, ok := exactSet(sub)
			if !ok {
				return nil, false
			}

			if acc = product(acc, set); acc == nil {
				return nil, false
			}
		}

		return acc, true

	case syntax.OpAlternate:
		var out []string

		for _, sub := range re.Sub {
			set, ok := exactSet(sub)
			if !ok {
				return nil, false
			}

			out = append(out, set...)
		}

		out = dedupe(out)

		return out, len(out) <= maxExpand

	default:
		return nil, false
	}
}

// product concatenates every prefix with every suffix, or nil past maxExpand.
func product(prefixes, suffixes []string) []string {
	if len(prefixes)*len(suffixes) > maxExpand {
		return nil
	}

	out := make([]string, 0, len(prefixes)*len(suffixes))
	for _, p := range prefixes {
		for _, s := range suffixes {
			out = append(out, p+s)
		}
	}

	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]

	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	return out
}

func minLen(lits []string) int {
	score := len(lits[0])
	for _, l := range lits {
		score = min(score, len(l))
	}

	return score
}

// windowPart is what one concat part contributes to a run of exact strings.
// A part repeated at least once contributes one iteration and ends the run:
// GO[0-9]{3,4} means the match contains "go" and a digit, then more.
func windowPart(re *syntax.Regexp) (set []string, last, ok bool) {
	if set, ok := exactSet(re); ok {
		return set, false, true
	}

	if re.Op == syntax.OpPlus || (re.Op == syntax.OpRepeat && re.Min >= 1) {
		set, ok := exactSet(re.Sub[0])

		return set, true, ok
	}

	return nil, false, false
}

// commonUAs are ordinary browser UAs. A cover whose literal occurs in one of
// them ("android ", "mobile") admits its entry on most traffic, so a concat
// prefers any rarer mandatory part.
var commonUAs = []string{
	"mozilla/5.0 (linux; android 14; k) applewebkit/537.36 (khtml, like gecko) chrome/141.0.0.0 mobile safari/537.36",
	"mozilla/5.0 (iphone; cpu iphone os 18_7 like mac os x) applewebkit/605.1.15 (khtml, like gecko) version/18.7 mobile/15e148 safari/604.1",
	"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/141.0.0.0 safari/537.36 edg/141.0.0.0",
	"mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/605.1.15 (khtml, like gecko) version/26.0 safari/605.1.15",
	"mozilla/5.0 (x11; linux x86_64; rv:140.0) gecko/20100101 firefox/140.0",
	"mozilla/5.0 (linux; android 16; sm-s931b build/bp2a.250605.031; wv) applewebkit/537.36 (khtml, like gecko) version/4.0 chrome/141.0.0.0 mobile safari/537.36",
}

// coverScore ranks a candidate literal cover: rare beats common, then the
// shortest literal's length decides.
func coverScore(lits []string) int {
	score := minLen(lits)

	for _, l := range lits {
		l = strings.ToLower(l)
		for _, ua := range commonUAs {
			if strings.Contains(ua, l) {
				return score
			}
		}
	}

	return 1000 + score
}

// commonCover reports whether any literal of a cover occurs in an ordinary
// browser UA.
func commonCover(lits []string) bool {
	return coverScore(lits) < 1000
}
