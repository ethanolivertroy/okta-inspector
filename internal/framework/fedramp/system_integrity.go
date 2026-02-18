package fedramp

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// ThreatInsightDetection checks SI-4 (threat insight): ThreatInsight must be enabled.
type ThreatInsightDetection struct {
	engine.BaseCheck
}

func (c *ThreatInsightDetection) init() {
	c.CheckID = "SI-4(threat)"
	c.CheckTitle = "Okta ThreatInsight must be enabled to detect and block malicious access"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"soc2": {"CC7.2"},
	}
}

func (c *ThreatInsightDetection) ID() string                           { c.init(); return c.CheckID }
func (c *ThreatInsightDetection) Title() string                        { c.init(); return c.CheckTitle }
func (c *ThreatInsightDetection) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *ThreatInsightDetection) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *ThreatInsightDetection) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *ThreatInsightDetection) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	ti, err := ec.ThreatInsight()
	if err != nil {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
			"ThreatInsight configuration not available; manually verify it is enabled")}, nil
	}

	if ti.Action == "none" || ti.Action == "" {
		return []engine.Finding{{
			CheckID:     c.CheckID,
			Title:       c.CheckTitle,
			Severity:    c.CheckSeverity,
			Status:      engine.StatusFail,
			Comments:    fmt.Sprintf("ThreatInsight action is set to '%s' (should be 'audit' or 'block')", ti.Action),
			Remediation: "Enable ThreatInsight with action set to 'block' or 'audit' under Security > General > Okta ThreatInsight",
			Evidence: map[string]any{
				"action":       ti.Action,
				"excludeZones": ti.ExcludeZones,
			},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	status := engine.StatusPass
	comment := fmt.Sprintf("ThreatInsight is enabled with action '%s'", ti.Action)
	if ti.Action == "audit" {
		comment += " (consider upgrading to 'block' for active protection)"
	}

	return []engine.Finding{{
		CheckID:  c.CheckID,
		Title:    c.CheckTitle,
		Severity: c.CheckSeverity,
		Status:   status,
		Comments: comment,
		Evidence: map[string]any{
			"action":       ti.Action,
			"excludeZones": ti.ExcludeZones,
		},
		CrossReferences: c.CrossRefs,
	}}, nil
}

// BehaviorDetection checks SI-4 (behavior): Behavior detection rules must be configured.
type BehaviorDetection struct {
	engine.BaseCheck
}

func (c *BehaviorDetection) init() {
	c.CheckID = "SI-4(behavior)"
	c.CheckTitle = "Behavior detection rules must be configured and active"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"soc2": {"CC7.2"},
	}
}

func (c *BehaviorDetection) ID() string                           { c.init(); return c.CheckID }
func (c *BehaviorDetection) Title() string                        { c.init(); return c.CheckTitle }
func (c *BehaviorDetection) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *BehaviorDetection) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *BehaviorDetection) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *BehaviorDetection) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	behaviors, err := ec.Behaviors()
	if err != nil {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
			"Behavior detection configuration not available; manually verify behavior detection rules are configured")}, nil
	}

	activeCount := 0
	var activeNames []string
	for _, b := range behaviors {
		if b.Status == "ACTIVE" {
			activeCount++
			activeNames = append(activeNames, b.Name)
		}
	}

	if activeCount == 0 {
		return []engine.Finding{{
			CheckID:     c.CheckID,
			Title:       c.CheckTitle,
			Severity:    c.CheckSeverity,
			Status:      engine.StatusFail,
			Comments:    "No active behavior detection rules found",
			Remediation: "Configure behavior detection rules under Security > General > Behavior Detection to identify anomalous authentication patterns",
			Evidence: map[string]any{
				"totalBehaviors": len(behaviors),
				"activeCount":   0,
			},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:  c.CheckID,
		Title:    c.CheckTitle,
		Severity: c.CheckSeverity,
		Status:   engine.StatusPass,
		Comments: fmt.Sprintf("%d active behavior detection rule(s) configured", activeCount),
		Evidence: map[string]any{
			"activeCount": activeCount,
			"activeRules": activeNames,
		},
		CrossReferences: c.CrossRefs,
	}}, nil
}
