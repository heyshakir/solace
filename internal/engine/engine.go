package engine

type HardeningEngine struct {
	// later configuration, logging.
}

func NewHardeningEngine() *HardeningEngine {
	return &HardeningEngine{}
}

// mock for testing.
func (e *HardeningEngine) LoadMockRules() []Rule {
	return []Rule{
		{
			ID:          "CORE-001",
			Title:       "Easter",
			Description: "dummy rule lol dont mind me.",
			OS:          "all",
			Severity:    "low",
			Category:    "boot",
			CheckType:   "internal",
			CheckTarget: "memory",
			CheckValue:  "ok",
		},
	}
}