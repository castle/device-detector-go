package client

import (
	"os"
	"testing"

	"github.com/skalibog/device-detector-go/internal/parser/parsertest"
)

func TestGateSetsKeepEveryMatchingClient(t *testing.T) {
	fsys := os.DirFS("../../../data/regexes")
	uas := parsertest.FixtureUserAgents(t, "../../../testdata/fixtures", 7)

	br, err := NewBrowser(fsys)
	if err != nil {
		t.Fatal(err)
	}

	browserPatterns := make([]string, len(br.entries))
	for i := range br.entries {
		browserPatterns[i] = br.entries[i].Regex
	}

	type generic struct {
		name string
		p    *genericParser
	}

	var generics []generic

	for name, file := range map[string]string{
		"feed readers":  "client/feed_readers.yml",
		"libraries":     "client/libraries.yml",
		"media players": "client/mediaplayers.yml",
		"mobile apps":   "client/mobile_apps.yml",
		"pim":           "client/pim.yml",
	} {
		g, err := newGeneric(fsys, file, name)
		if err != nil {
			t.Fatal(err)
		}

		generics = append(generics, generic{name, g})
	}

	for _, ua := range uas {
		parsertest.AssertGateKeeps(t, "browsers", br.gateSet, ua, browserPatterns)

		for _, g := range generics {
			patterns := make([]string, len(g.p.entries))
			for i := range g.p.entries {
				patterns[i] = g.p.entries[i].Regex
			}

			parsertest.AssertGateKeeps(t, g.name, g.p.gateSet, ua, patterns)
		}
	}
}
