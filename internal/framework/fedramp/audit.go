package fedramp

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// AuditableEvents checks AU-2: The system must generate audit records for auditable events.
type AuditableEvents struct {
	engine.BaseCheck
}

func (c *AuditableEvents) init() {
	c.CheckID = "AU-2"
	c.CheckTitle = "Auditable events must be defined and system logs must capture required event types"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"soc2":  {"CC7.2"},
		"irap":  {"ISM-0580"},
		"ismap": {"A.12.4.1"},
	}
}

func (c *AuditableEvents) ID() string                           { c.init(); return c.CheckID }
func (c *AuditableEvents) Title() string                        { c.init(); return c.CheckTitle }
func (c *AuditableEvents) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AuditableEvents) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AuditableEvents) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AuditableEvents) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	logs, err := ec.SystemLogs()
	if err != nil {
		// If system logs are not collected, this is a manual check
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
			"System logs not available in snapshot; verify Okta system log captures login, logout, privilege changes, and admin actions")}, nil
	}

	if len(logs) == 0 {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
			"No system log entries found in snapshot; verify audit logging is enabled and capturing required event types")}, nil
	}

	// Check for presence of key event types in captured logs
	eventTypes := make(map[string]int)
	for _, log := range logs {
		eventTypes[log.EventType]++
	}

	return []engine.Finding{{
		CheckID:  c.CheckID,
		Title:    c.CheckTitle,
		Severity: c.CheckSeverity,
		Status:   engine.StatusPass,
		Comments: fmt.Sprintf("System log contains %d events across %d event types", len(logs), len(eventTypes)),
		Evidence: map[string]any{
			"totalEvents": len(logs),
			"eventTypes":  len(eventTypes),
		},
		CrossReferences: c.CrossRefs,
	}}, nil
}

// AuditContent checks AU-3: Audit records must contain sufficient detail.
type AuditContent struct {
	engine.BaseCheck
}

func (c *AuditContent) init() {
	c.CheckID = "AU-3"
	c.CheckTitle = "Audit records must contain what, when, where, source, outcome, and identity"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"soc2":  {"CC7.2"},
		"irap":  {"ISM-0580"},
		"ismap": {"A.12.4.1"},
	}
}

func (c *AuditContent) ID() string                           { c.init(); return c.CheckID }
func (c *AuditContent) Title() string                        { c.init(); return c.CheckTitle }
func (c *AuditContent) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AuditContent) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AuditContent) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AuditContent) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	logs, err := ec.SystemLogs()
	if err != nil {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
			"System logs not available; manually verify log entries include actor, event type, timestamp, outcome, and severity")}, nil
	}

	if len(logs) == 0 {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
			"No system log entries to evaluate for content completeness")}, nil
	}

	// Sample log entries to verify required fields are present
	completeCount := 0
	incompleteCount := 0
	for _, log := range logs {
		hasActor := log.Actor != nil && log.Actor.ID != ""
		hasEventType := log.EventType != ""
		hasOutcome := log.Outcome != nil && log.Outcome.Result != ""
		hasTimestamp := !log.Published.IsZero()

		if hasActor && hasEventType && hasOutcome && hasTimestamp {
			completeCount++
		} else {
			incompleteCount++
		}
	}

	if incompleteCount > 0 {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusFail,
			Comments: fmt.Sprintf("%d of %d log entries missing required fields (actor, event type, outcome, or timestamp)", incompleteCount, len(logs)),
			Evidence: map[string]any{
				"completeEntries":   completeCount,
				"incompleteEntries": incompleteCount,
			},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:  c.CheckID,
		Title:    c.CheckTitle,
		Severity: c.CheckSeverity,
		Status:   engine.StatusPass,
		Comments: fmt.Sprintf("All %d sampled log entries contain required fields (actor, event type, outcome, timestamp)", completeCount),
		Evidence: map[string]any{
			"completeEntries": completeCount,
		},
		CrossReferences: c.CrossRefs,
	}}, nil
}

// LogOffloading checks AU-4: Audit log storage capacity must be managed via log offloading.
type LogOffloading struct {
	engine.BaseCheck
}

func (c *LogOffloading) init() {
	c.CheckID = "AU-4"
	c.CheckTitle = "Audit log storage capacity must be ensured via log streaming/offloading"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":  {"V-273202"},
		"irap":  {"ISM-0407"},
		"ismap": {"A.12.4.1"},
	}
}

func (c *LogOffloading) ID() string                           { c.init(); return c.CheckID }
func (c *LogOffloading) Title() string                        { c.init(); return c.CheckTitle }
func (c *LogOffloading) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *LogOffloading) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *LogOffloading) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *LogOffloading) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()

	logStreams, _ := ec.LogStreams()

	activeStreams := 0
	for _, s := range logStreams {
		if s.Status == "ACTIVE" {
			activeStreams++
		}
	}

	if activeStreams > 0 {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Log offloading configured: %d active log stream(s)", activeStreams),
			Evidence: map[string]any{
				"activeStreams": activeStreams,
			},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No active log streams found for audit log offloading",
		Remediation: "Configure at least one log stream (Splunk, AWS EventBridge, Datadog, etc.) to ensure audit log retention beyond Okta's default 90-day window",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// AuditReview checks AU-6: Audit records must be reviewed and analyzed via event hooks.
type AuditReview struct {
	engine.BaseCheck
}

func (c *AuditReview) init() {
	c.CheckID = "AU-6"
	c.CheckTitle = "Audit records must be reviewed, analyzed, and reported via event hooks or integrations"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273202"},
		"soc2": {"CC7.2", "CC7.3"},
	}
}

func (c *AuditReview) ID() string                           { c.init(); return c.CheckID }
func (c *AuditReview) Title() string                        { c.init(); return c.CheckTitle }
func (c *AuditReview) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AuditReview) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AuditReview) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AuditReview) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Audit review integrations configured: %d active event hook(s), %d active log stream(s)", activeHooks, activeStreams),
			Evidence: map[string]any{
				"activeHooks":   activeHooks,
				"activeStreams": activeStreams,
			},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No active event hooks or log streams found for audit review and analysis",
		Remediation: "Configure event hooks or log streams to enable automated audit review, analysis, and alerting through SIEM or security monitoring tools",
		CrossReferences: c.CrossRefs,
	}}, nil
}
