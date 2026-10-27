package parser

import (
	"os"
	"path/filepath"
	"regexp/syntax"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLiteralCoverExpandsShortPrefixes(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
	}{
		{`a(?:101|110)`, []string{"a101", "a110"}},
		{`GO[0-9]{3,4}`, []string{"go0", "go9"}},
		{`SM-[AG][0-9]+`, []string{"sm-a0", "sm-g9"}},
		{`Android [0-9]+; (?:XQ|SO)-[0-9]{2}`, []string{"; xq-0", "; so-9"}},
	}

	for _, c := range cases {
		ast, err := syntax.Parse(`(?i)(?:`+c.pattern+`)`, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}

		lits, ok := coverAtLeast(ast, minGateLiteral)
		if !ok {
			t.Errorf("%s: no cover", c.pattern)

			continue
		}

		for _, w := range c.want {
			if !slices.Contains(lits, w) {
				t.Errorf("%s: cover %v lacks %q", c.pattern, lits, w)
			}
		}
	}
}

func TestGateSetKeepsEveryMatchingEntry(t *testing.T) {
	uas := fixtureUserAgents(t, "../../testdata/fixtures", 7)

	b, err := NewBot(os.DirFS("../../data/regexes"))
	if err != nil {
		t.Fatal(err)
	}

	botPatterns := make([]string, len(b.entries))
	for i := range b.entries {
		botPatterns[i] = b.entries[i].Regex
	}

	o, err := NewOS(os.DirFS("../../data/regexes"))
	if err != nil {
		t.Fatal(err)
	}

	osPatterns := make([]string, len(o.rules))
	for i := range o.rules {
		osPatterns[i] = o.rules[i].Regex
	}

	for _, ua := range uas {
		assertGateKeeps(t, "bots", b.gateSet, ua, botPatterns)
		assertGateKeeps(t, "oss", o.gateSet, ua, osPatterns)
	}
}

// fixtureUserAgents reads every user_agent from the fixture files under dir,
// keeping one in every `every` to bound test time.
func fixtureUserAgents(t testing.TB, dir string, every int) []string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures under %s: %v", dir, err)
	}

	var uas []string

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}

		var cases []struct {
			UserAgent string `yaml:"user_agent"`
		}
		if err := yaml.Unmarshal(raw, &cases); err != nil {
			t.Fatalf("%s: %v", f, err)
		}

		for i, c := range cases {
			if i%every == 0 {
				uas = append(uas, c.UserAgent)
			}
		}
	}

	return uas
}

// assertGateKeeps fails when the gate rules out an entry whose pattern
// matches ua.
func assertGateKeeps(t testing.TB, name string, g *GateSet, ua string, patterns []string) {
	t.Helper()

	missed, err := g.MissedEntries(ua, patterns)
	if err != nil {
		t.Fatal(err)
	}

	for _, i := range missed {
		t.Errorf("%s: gate dropped entry %d (%.60s) that matches %q", name, i, patterns[i], ua)
	}
}
