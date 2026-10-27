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
		shared  []string
		want    []string
	}{
		{`a(?:101|110)`, nil, []string{"a101", "a110"}},
		{`GO[0-9]{3,4}`, nil, []string{"go0", "go9"}},
		{`SM-[AG][0-9]+`, nil, []string{"sm-a0", "sm-g9"}},
		// The longest mandatory part wins unless other entries share it.
		{`Android [0-9]+; (?:XQ|SO)-[0-9]{2}`, nil, []string{"android 0", "android 9"}},
		{`Android [0-9]+; (?:XQ|SO)-[0-9]{2}`, []string{"android 0", "android 9"}, []string{"; xq-0", "; so-9"}},
	}

	for _, testCase := range cases {
		parsed, err := syntax.Parse(`(?i)(?:`+testCase.pattern+`)`, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}

		shared := map[string]bool{}
		for _, literal := range testCase.shared {
			shared[literal] = true
		}

		cover, ok := coverAtLeast(parsed, minGateLiteral, shared)
		if !ok {
			t.Errorf("%s: no cover", testCase.pattern)

			continue
		}

		for _, wanted := range testCase.want {
			if !slices.Contains(cover, wanted) {
				t.Errorf("%s: cover %v lacks %q", testCase.pattern, cover, wanted)
			}
		}
	}
}

func TestGateSetKeepsEveryMatchingEntry(t *testing.T) {
	userAgents := fixtureUserAgents(t, "../../testdata/fixtures", 7)

	bots, err := NewBot(os.DirFS("../../data/regexes"))
	if err != nil {
		t.Fatal(err)
	}

	botPatterns := make([]string, len(bots.entries))
	for index := range bots.entries {
		botPatterns[index] = bots.entries[index].Regex
	}

	operatingSystems, err := NewOS(os.DirFS("../../data/regexes"))
	if err != nil {
		t.Fatal(err)
	}

	osPatterns := make([]string, len(operatingSystems.rules))
	for index := range operatingSystems.rules {
		osPatterns[index] = operatingSystems.rules[index].Regex
	}

	for _, ua := range userAgents {
		assertGateKeeps(t, "bots", bots.gateSet, ua, botPatterns)
		assertGateKeeps(t, "oss", operatingSystems.gateSet, ua, osPatterns)
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

	var userAgents []string

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		var fixtures []struct {
			UserAgent string `yaml:"user_agent"`
		}
		if err := yaml.Unmarshal(raw, &fixtures); err != nil {
			t.Fatalf("%s: %v", file, err)
		}

		for index, fixture := range fixtures {
			if index%every == 0 {
				userAgents = append(userAgents, fixture.UserAgent)
			}
		}
	}

	return userAgents
}

// assertGateKeeps fails when the gate rules out an entry whose pattern
// matches ua.
func assertGateKeeps(t testing.TB, name string, gateSet *GateSet, ua string, patterns []string) {
	t.Helper()

	missed, err := gateSet.MissedEntries(ua, patterns)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range missed {
		t.Errorf("%s: gate dropped entry %d (%.60s) that matches %q", name, entry, patterns[entry], ua)
	}
}
