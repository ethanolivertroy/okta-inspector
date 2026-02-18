package stig

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// LogOffloading checks V-273202: Log offloading must be configured.
type LogOffloading struct{ engine.BaseCheck }

func (c *LogOffloading) init() {
	c.CheckID = "V-273202"
	c.CheckTitle = "Log offloading must be configured"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AU-4", "AU-6"},
		"irap":    {"ISM-0407"},
		"ismap":   {"A.12.4.1"},
	}
}

func (c *LogOffloading) ID() string                           { c.init(); return c.CheckID }
func (c *LogOffloading) Title() string                        { c.init(); return c.CheckTitle }
func (c *LogOffloading) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *LogOffloading) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *LogOffloading) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *LogOffloading) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()

	eventHooks, _ := ec.EventHooks()
	logStreams, _ := ec.LogStreams()

	activeHooks := 0
	for _, h := range eventHooks {
		if h.Status == "ACTIVE" {
			activeHooks++
		}
	}

	activeStreams := 0
	for _, s := range logStreams {
		if s.Status == "ACTIVE" {
			activeStreams++
		}
	}

	if activeHooks > 0 || activeStreams > 0 {
		return []engine.Finding{{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Log offloading configured: %d active hooks, %d active streams", activeHooks, activeStreams),
			Evidence: map[string]any{"activeHooks": activeHooks, "activeStreams": activeStreams},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No active log streams or event hooks found",
		Remediation: "Configure at least one log stream (Splunk, AWS EventBridge, etc.) or event hook for log offloading",
		CrossReferences: c.CrossRefs,
	}}, nil
}
