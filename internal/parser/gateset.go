package parser

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// GateSet narrows an entry walk (device brands and models, OS rules, browsers,
// bots, other clients) to the entries that can match a UA. Each pattern is
// split into its top-level branches. A branch with a selective literal cover
// admits its entry when one of those literals occurs in the lowercased UA. A
// branch without one becomes a residual check: its own RE2 superset, triggered
// by one of its short literals (or by every UA when it has none). One
// Aho-Corasick pass finds every literal in the UA.
type GateSet struct {
	literalMatcher    *acMatcher
	admittedEntries   [][]int32 // literal id -> entries admitted outright
	triggeredChecks   [][]int32 // literal id -> residual checks it makes worth running
	residualChecks    []residualCheck
	untriggeredChecks []int32 // residual checks with no literal to wait for
	alwaysWalked      []int   // entries with no provable gate: walked every time
	entryCount        int
	scratch           sync.Pool
}

type residualCheck struct {
	entry int32
	regex *regexp.Regexp
	// eager checks run in the gate instead of admitting their entry: the
	// branch is anchored at the start, so its check fails at once on most UAs.
	eager bool
}

// gateScratch is SkipGated's per-call state, pooled to keep parses
// allocation-free.
type gateScratch struct {
	admitted       []bool // by entry
	checkTriggered []bool // by residual check
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
	if cached, ok := gateSets.Load(key); ok {
		return cached.(*GateSet)
	}

	stored, _ := gateSets.LoadOrStore(key, compileGateSet(patterns))

	return stored.(*GateSet)
}

func compileGateSet(patterns []string) *GateSet {
	gateSet := &GateSet{entryCount: len(patterns)}

	var literals []string

	literalIDs := map[string]int32{}
	literalID := func(literal string) int32 {
		if id, ok := literalIDs[literal]; ok {
			return id
		}

		id := int32(len(literals))
		literalIDs[literal] = id
		literals = append(literals, literal)
		gateSet.admittedEntries = append(gateSet.admittedEntries, nil)
		gateSet.triggeredChecks = append(gateSet.triggeredChecks, nil)

		return id
	}

	shared := sharedLiterals(patterns)

	for entry, pattern := range patterns {
		admitLiterals, residuals, ok := entryGate(pattern, shared)
		if !ok {
			gateSet.alwaysWalked = append(gateSet.alwaysWalked, entry)

			continue
		}

		for _, literal := range admitLiterals {
			id := literalID(literal)
			gateSet.admittedEntries[id] = append(gateSet.admittedEntries[id], int32(entry))
		}

		for _, residual := range residuals {
			checkID := int32(len(gateSet.residualChecks))
			gateSet.residualChecks = append(gateSet.residualChecks,
				residualCheck{entry: int32(entry), regex: residual.regex, eager: residual.eager})

			if len(residual.triggerLiterals) == 0 {
				gateSet.untriggeredChecks = append(gateSet.untriggeredChecks, checkID)

				continue
			}

			for _, literal := range residual.triggerLiterals {
				id := literalID(literal)
				gateSet.triggeredChecks[id] = append(gateSet.triggeredChecks[id], checkID)
			}
		}
	}

	gateSet.literalMatcher = newACMatcher(literals)
	gateSet.scratch.New = func() any {
		return &gateScratch{
			admitted:       make([]bool, gateSet.entryCount),
			checkTriggered: make([]bool, len(gateSet.residualChecks)),
		}
	}

	return gateSet
}

// residualGate is one branch entryGate could not cover with a selective
// literal: its RE2 superset and the shorter literals that trigger it.
type residualGate struct {
	regex           *regexp.Regexp
	triggerLiterals []string
	eager           bool
}

// sharedLiteralEntries is how many entries may pick the same literal before it
// counts as shared. A literal several entries pick, such as "android " in many
// brand patterns, says little about which entry a UA belongs to.
const sharedLiteralEntries = 3

// sharedLiterals picks every entry's covers once without preference and
// returns the literals at least sharedLiteralEntries entries chose. The real
// pass then prefers any other mandatory part of a pattern over them. Being
// derived from the patterns, it follows database updates on its own.
func sharedLiterals(patterns []string) map[string]bool {
	entriesPicking := map[string]int{}

	for _, pattern := range patterns {
		admitLiterals, _, _ := entryGate(pattern, nil)

		picked := map[string]bool{}
		for _, literal := range admitLiterals {
			if !picked[literal] {
				picked[literal] = true
				entriesPicking[literal]++
			}
		}
	}

	shared := map[string]bool{}

	for literal, count := range entriesPicking {
		if count >= sharedLiteralEntries {
			shared[literal] = true
		}
	}

	return shared
}

// entryGate splits one database pattern into branches: literals that admit
// it outright, and residual checks for branches no selective literal covers.
func entryGate(pattern string, shared map[string]bool) ([]string, []residualGate, bool) {
	translated, ok := re2Translate(stripLookarounds(normalizePattern(pattern)))
	if !ok {
		return nil, nil, false
	}

	parsed, err := syntax.Parse(`(?im)(?:`+translated+`)`, syntax.Perl)
	if err != nil {
		return nil, nil, false
	}

	var (
		admitLiterals []string
		residuals     []residualGate
	)

	for _, branch := range topBranches(parsed) {
		anchored := anchoredAtStart(branch)

		if !anchored {
			if cover, ok := coverAtLeast(branch, minGateLiteral, shared); ok {
				admitLiterals = append(admitLiterals, cover...)

				continue
			}
		}

		regex, err := regexp.Compile(branch.String())
		if err != nil {
			return nil, nil, false
		}

		// An anchored branch can only match at the start of the UA, so its
		// check fails at once and runs in the gate rather than admitting its
		// entry on every UA that contains its literal.
		shortCover, _ := coverAtLeast(branch, minResidualLiteral, shared)
		residuals = append(residuals, residualGate{regex: regex, triggerLiterals: shortCover, eager: anchored})
	}

	return admitLiterals, residuals, true
}

// topBranches returns the alternatives of a pattern's top-level |, or the
// pattern itself when it has none.
func topBranches(node *syntax.Regexp) []*syntax.Regexp {
	for node.Op == syntax.OpCapture {
		node = node.Sub[0]
	}

	if node.Op == syntax.OpAlternate {
		return node.Sub
	}

	return []*syntax.Regexp{node}
}

// anchoredAtStart reports whether node can only match at the start of the
// text (or of a line).
func anchoredAtStart(node *syntax.Regexp) bool {
	for {
		switch node.Op {
		case syntax.OpBeginText, syntax.OpBeginLine:
			return true
		case syntax.OpCapture, syntax.OpConcat:
			if len(node.Sub) == 0 {
				return false
			}

			node = node.Sub[0]
		default:
			return false
		}
	}
}

// coverAtLeast returns a lowercased literal cover whose every literal is at
// least minLength bytes long.
func coverAtLeast(node *syntax.Regexp, minLength int, shared map[string]bool) ([]string, bool) {
	cover, ok := literalCover(node, shared)
	if !ok {
		return nil, false
	}

	lowered := make([]string, len(cover))
	for index, literal := range cover {
		if len(literal) < minLength {
			return nil, false
		}

		lowered[index] = strings.ToLower(literal)
	}

	return lowered, true
}

// SkipGated reports whether the walk can be narrowed for ua. When it returns
// (only, true), entries outside `only` cannot match and the caller walks just
// those indexes (ascending, possibly empty). (nil, false) means walk everything.
func (gateSet *GateSet) SkipGated(ua string) ([]int, bool) {
	if gateSet == nil || gateSet.literalMatcher == nil {
		return nil, false
	}

	scratch := gateSet.scratch.Get().(*gateScratch)
	defer gateSet.scratch.Put(scratch)

	clear(scratch.admitted)
	clear(scratch.checkTriggered)

	for _, entry := range gateSet.alwaysWalked {
		scratch.admitted[entry] = true
	}

	gateSet.literalMatcher.scan(strings.ToLower(ua), func(literalID int32) {
		for _, entry := range gateSet.admittedEntries[literalID] {
			scratch.admitted[entry] = true
		}

		for _, checkID := range gateSet.triggeredChecks[literalID] {
			scratch.checkTriggered[checkID] = true
		}
	})

	for _, checkID := range gateSet.untriggeredChecks {
		scratch.checkTriggered[checkID] = true
	}

	// A triggered residual admits its entry without running the check: the
	// walk's own per-pattern RE2 gate runs it lazily, and only for entries
	// before the first match.
	for checkID, triggered := range scratch.checkTriggered {
		if !triggered {
			continue
		}

		check := &gateSet.residualChecks[checkID]
		if !check.eager || (!scratch.admitted[check.entry] && check.regex.MatchString(ua)) {
			scratch.admitted[check.entry] = true
		}
	}

	var survivors []int

	for entry, admitted := range scratch.admitted {
		if admitted {
			survivors = append(survivors, entry)
		}
	}

	if len(survivors) == gateSet.entryCount {
		return nil, false
	}

	if survivors == nil {
		survivors = []int{}
	}

	return survivors, true
}

// MissedEntries returns the entries whose pattern matches ua but that the
// gate ruled out. It must always be empty; tests assert that over fixtures.
func (gateSet *GateSet) MissedEntries(ua string, patterns []string) ([]int, error) {
	survivors, gated := gateSet.SkipGated(ua)
	if !gated {
		return nil, nil
	}

	kept := make(map[int]bool, len(survivors))
	for _, entry := range survivors {
		kept[entry] = true
	}

	var missed []int

	for entry, pattern := range patterns {
		if kept[entry] {
			continue
		}

		match, err := MatchUserAgent(ua, pattern)
		if err != nil {
			return nil, err
		}

		if match != nil {
			missed = append(missed, entry)
		}
	}

	return missed, nil
}
