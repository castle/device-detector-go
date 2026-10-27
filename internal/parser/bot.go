package parser

import (
	"fmt"
	"io/fs"
)

// BotProducer identifies the organisation operating a bot.
type BotProducer struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// BotResult is the outcome of a successful bot detection.
type BotResult struct {
	Name     string
	Category string
	URL      string
	Producer BotProducer
}

// botEntry is a single record from bots.yml, with its regex precompiled.
type botEntry struct {
	Regex    string      `yaml:"regex"`
	Name     string      `yaml:"name"`
	Category string      `yaml:"category"`
	URL      string      `yaml:"url"`
	Producer BotProducer `yaml:"producer"`

	compiled *Compiled
}

// Bot parses a user agent for bot information, mirroring DeviceDetector's
// Parser\Bot. It is immutable after construction and safe for concurrent use.
type Bot struct {
	entries []botEntry
	overall *Compiled
	// gateSet proves most user agents match no entry, which also rules out
	// overall: it is the same entries joined with |.
	gateSet *GateSet
}

// NewBot loads bots.yml from fsys, precompiles every entry regex and builds the
// combined "overall" regex used to short-circuit non-bot user agents.
func NewBot(fsys fs.FS) (*Bot, error) {
	var entries []botEntry
	if err := Load(fsys, "bots.yml", &entries); err != nil {
		return nil, err
	}

	patterns := make([]string, len(entries))

	for i := range entries {
		re, err := Compile(entries[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("devicedetector: compiling bot regex %q: %w", entries[i].Regex, err)
		}

		entries[i].compiled = re
		patterns[i] = entries[i].Regex
	}

	combined := CombineRegexes(patterns)
	if PreMatchEmpty(combined) {
		// No bot regexes: nothing can be a bot. Leave overall nil so Parse
		// short-circuits rather than compiling a match-everything anchor.
		return &Bot{entries: entries}, nil
	}

	overall, err := Compile(combined)
	if err != nil {
		return nil, fmt.Errorf("devicedetector: compiling combined bot regex: %w", err)
	}

	return &Bot{entries: entries, overall: overall, gateSet: CompileGateSet(patterns)}, nil
}

// Parse checks whether ua belongs to a bot and returns its details.
// It returns (nil, nil) when the user agent is not a known bot.
//
// The detection first tests the combined regex (a fast rejection for the common
// non-bot case) and only then walks the individual entries in file order.
func (b *Bot) Parse(ua string) (*BotResult, error) {
	if b.overall == nil {
		return nil, nil
	}

	only, gated := b.gateSet.SkipGated(ua)
	if gated && len(only) == 0 {
		return nil, nil
	}

	pre, err := matchWith(b.overall, ua)
	if err != nil {
		return nil, err
	}

	if pre == nil {
		return nil, nil
	}

	walk := func(i int) (*BotResult, error) {
		m, err := matchWith(b.entries[i].compiled, ua)
		if err != nil || m == nil {
			return nil, err
		}

		e := b.entries[i]

		return &BotResult{
			// Bot::parse substitutes $1..$N in the name from the match,
			// e.g. name "$1" over regex "(360Spider(?:-Image|-Video)?)".
			Name:     BuildByMatch(e.Name, m),
			Category: e.Category,
			URL:      e.URL,
			Producer: e.Producer,
		}, nil
	}

	if !gated {
		only = make([]int, len(b.entries))
		for i := range only {
			only[i] = i
		}
	}

	for _, i := range only {
		if res, err := walk(i); err != nil || res != nil {
			return res, err
		}
	}

	return nil, nil
}

// IsBot reports whether ua belongs to a bot without collecting its details,
// mirroring Parser\Bot with discardDetails enabled: only the combined regex is
// evaluated.
func (b *Bot) IsBot(ua string) (bool, error) {
	if b.overall == nil {
		return false, nil
	}

	if only, gated := b.gateSet.SkipGated(ua); gated && len(only) == 0 {
		return false, nil
	}

	pre, err := matchWith(b.overall, ua)
	if err != nil {
		return false, err
	}

	return pre != nil, nil
}
