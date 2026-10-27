// Package parsertest holds helpers shared by the parser packages' tests.
package parsertest

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/skalibog/device-detector-go/internal/parser"
)

// FixtureUserAgents reads every user_agent from the fixture files under dir,
// keeping one in every `every` to bound test time.
func FixtureUserAgents(t testing.TB, dir string, every int) []string {
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

// AssertGateKeeps fails when the gate rules out an entry whose pattern
// matches ua.
func AssertGateKeeps(t testing.TB, name string, g *parser.GateSet, ua string, patterns []string) {
	t.Helper()

	missed, err := g.MissedEntries(ua, patterns)
	if err != nil {
		t.Fatal(err)
	}

	for _, i := range missed {
		t.Errorf("%s: gate dropped entry %d (%.60s) that matches %q", name, i, patterns[i], ua)
	}
}
