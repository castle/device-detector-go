package parser

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// GateSet narrows an entry walk (device brands, OS rules, browsers) to the
// entries that can match a UA. Each pattern is split into its top-level
// branches. A branch with a selective literal cover admits its entry when one
// of those literals occurs in the lowercased UA. A branch without one becomes
// a residual check: its own RE2 superset, run only when one of its short
// literals occurs (or on every UA when it has none). One Aho-Corasick pass
// finds every literal in the UA.
type GateSet struct {
	ac        *acMatcher
	admit     [][]int32 // literal id -> entries admitted outright
	trigger   [][]int32 // literal id -> residual checks it makes worth running
	checks    []residualCheck
	alwaysChk []int32 // residual checks with no literal to wait for
	always    []int   // entries with no provable gate: walked every time
	n         int
	scratch   sync.Pool
}

type residualCheck struct {
	entry int32
	re    *regexp.Regexp
	// eager checks run in the gate: their trigger literals occur in ordinary
	// browser UAs, so admitting the entry on a hit would admit it on most
	// traffic.
	eager bool
}

type gateScratch struct {
	mark    []bool
	chkSeen []bool
}

// minResidualLiteral is the shortest literal worth waiting for before running
// a residual check; single characters occur in nearly every UA.
const minResidualLiteral = 2

// gateSets shares gate sets between detectors built from the same patterns,
// as regexCache shares compiled patterns.
var gateSets sync.Map

// CompileGateSet builds a gate over patterns; entries with a branch RE2
// cannot express are recorded as always-walk.
func CompileGateSet(patterns []string) *GateSet {
	key := strings.Join(patterns, "\x00")
	if g, ok := gateSets.Load(key); ok {
		return g.(*GateSet)
	}

	g := compileGateSet(patterns)
	actual, _ := gateSets.LoadOrStore(key, g)

	return actual.(*GateSet)
}

func compileGateSet(patterns []string) *GateSet {
	g := &GateSet{n: len(patterns)}

	var lits []string

	ids := map[string]int32{}
	id := func(l string) int32 {
		if k, ok := ids[l]; ok {
			return k
		}

		k := int32(len(lits))
		ids[l] = k
		lits = append(lits, l)
		g.admit = append(g.admit, nil)
		g.trigger = append(g.trigger, nil)

		return k
	}

	for i, p := range patterns {
		admit, residuals, ok := entryGate(p)
		if !ok {
			g.always = append(g.always, i)

			continue
		}

		for _, l := range admit {
			k := id(l)
			g.admit[k] = append(g.admit[k], int32(i))
		}

		for _, r := range residuals {
			c := int32(len(g.checks))
			g.checks = append(g.checks, residualCheck{entry: int32(i), re: r.re, eager: r.eager})

			if len(r.lits) == 0 {
				g.alwaysChk = append(g.alwaysChk, c)

				continue
			}

			for _, l := range r.lits {
				k := id(l)
				g.trigger[k] = append(g.trigger[k], c)
			}
		}
	}

	g.ac = newACMatcher(lits)
	g.scratch.New = func() any {
		return &gateScratch{
			mark:    make([]bool, g.n),
			chkSeen: make([]bool, len(g.checks)),
		}
	}

	return g
}

type residualGate struct {
	re    *regexp.Regexp
	lits  []string
	eager bool
}

// entryGate splits one database pattern into branches: literals that admit
// it outright, and residual checks for branches no selective literal covers.
func entryGate(pattern string) ([]string, []residualGate, bool) {
	t, ok := re2Translate(stripLookarounds(normalizePattern(pattern)))
	if !ok {
		return nil, nil, false
	}

	ast, err := syntax.Parse(`(?im)(?:`+t+`)`, syntax.Perl)
	if err != nil {
		return nil, nil, false
	}

	var (
		admit     []string
		residuals []residualGate
	)

	for _, branch := range topBranches(ast) {
		lits, ok := coverAtLeast(branch, minGateLiteral)
		if ok && !commonCover(lits) {
			admit = append(admit, lits...)

			continue
		}

		re, err := regexp.Compile(branch.String())
		if err != nil {
			return nil, nil, false
		}

		if ok {
			residuals = append(residuals, residualGate{re: re, lits: lits, eager: true})

			continue
		}

		short, _ := coverAtLeast(branch, minResidualLiteral)
		residuals = append(residuals, residualGate{re: re, lits: short})
	}

	return admit, residuals, true
}

func topBranches(re *syntax.Regexp) []*syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}

	if re.Op == syntax.OpAlternate {
		return re.Sub
	}

	return []*syntax.Regexp{re}
}

// coverAtLeast returns a lowercased literal cover whose every literal is at
// least minLen bytes long.
func coverAtLeast(re *syntax.Regexp, minLen int) ([]string, bool) {
	lits, ok := literalCover(re)
	if !ok {
		return nil, false
	}

	out := make([]string, len(lits))
	for i, l := range lits {
		if len(l) < minLen {
			return nil, false
		}

		out[i] = strings.ToLower(l)
	}

	return out, true
}

// SkipGated reports whether the walk can be narrowed for ua. When it returns
// (only, true), entries outside `only` cannot match and the caller walks just
// those indexes (ascending, possibly empty). (nil, false) means walk everything.
func (g *GateSet) SkipGated(ua string) ([]int, bool) {
	if g == nil || g.ac == nil {
		return nil, false
	}

	sc := g.scratch.Get().(*gateScratch)
	defer g.scratch.Put(sc)

	clear(sc.mark)
	clear(sc.chkSeen)

	for _, i := range g.always {
		sc.mark[i] = true
	}

	g.ac.scan(strings.ToLower(ua), func(lit int32) {
		for _, e := range g.admit[lit] {
			sc.mark[e] = true
		}

		for _, c := range g.trigger[lit] {
			sc.chkSeen[c] = true
		}
	})

	for _, c := range g.alwaysChk {
		sc.chkSeen[c] = true
	}

	// A triggered residual admits its entry without running the check: the
	// walk's own per-pattern RE2 gate runs it lazily, and only for entries
	// before the first match.
	for c, run := range sc.chkSeen {
		if !run {
			continue
		}

		if ch := &g.checks[c]; !ch.eager || (!sc.mark[ch.entry] && ch.re.MatchString(ua)) {
			sc.mark[ch.entry] = true
		}
	}

	var only []int

	for i, ok := range sc.mark {
		if ok {
			only = append(only, i)
		}
	}

	if len(only) == g.n {
		return nil, false
	}

	if only == nil {
		only = []int{}
	}

	return only, true
}

// MissedEntries returns the entries whose pattern matches ua but that the
// gate ruled out. It must always be empty; tests assert that over fixtures.
func (g *GateSet) MissedEntries(ua string, patterns []string) ([]int, error) {
	only, gated := g.SkipGated(ua)
	if !gated {
		return nil, nil
	}

	kept := make(map[int]bool, len(only))
	for _, i := range only {
		kept[i] = true
	}

	var missed []int

	for i, p := range patterns {
		if kept[i] {
			continue
		}

		m, err := MatchUserAgent(ua, p)
		if err != nil {
			return nil, err
		}

		if m != nil {
			missed = append(missed, i)
		}
	}

	return missed, nil
}
