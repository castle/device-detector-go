package device

import (
	"os"
	"testing"

	"github.com/skalibog/device-detector-go/internal/parser"
	"github.com/skalibog/device-detector-go/internal/parser/parsertest"
)

func TestGateSetsKeepEveryMatchingBrandAndModel(t *testing.T) {
	m, err := NewMobile(os.DirFS("../../../data/regexes"))
	if err != nil {
		t.Fatal(err)
	}

	b := m.base

	brandPatterns := make([]string, len(b.regexes.Entries))
	for i := range b.regexes.Entries {
		brandPatterns[i] = b.regexes.Entries[i].Value.Regex
	}

	for _, ua := range parsertest.FixtureUserAgents(t, "../../../testdata/fixtures", 25) {
		parsertest.AssertGateKeeps(t, "mobile brands", b.gateSet, ua, brandPatterns)

		// Models are only walked under the brand that matched first.
		for i, p := range brandPatterns {
			if hit, err := parser.MatchUserAgent(ua, p); err != nil {
				t.Fatal(err)
			} else if hit == nil {
				continue
			}

			if gate := b.modelGates[i]; gate != nil {
				models := b.regexes.Entries[i].Value.Models
				modelPatterns := make([]string, len(models))
				for j := range models {
					modelPatterns[j] = models[j].Regex
				}

				parsertest.AssertGateKeeps(t, "models of "+b.regexes.Entries[i].Key, gate, ua, modelPatterns)
			}

			break
		}
	}
}
