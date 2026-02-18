package stig

import (
	"context"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// AdminConsoleMFA checks V-273193: Admin Console requires MFA.
type AdminConsoleMFA struct{ engine.BaseCheck }

func (c *AdminConsoleMFA) init() {
	c.CheckID = "V-273193"
	c.CheckTitle = "Admin Console must require multi-factor authentication"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"IA-2", "IA-2(1)"},
		"irap":    {"ISM-0974"},
		"pcidss":  {"8.3.1"},
	}
}

func (c *AdminConsoleMFA) ID() string                           { c.init(); return c.CheckID }
func (c *AdminConsoleMFA) Title() string                        { c.init(); return c.CheckTitle }
func (c *AdminConsoleMFA) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AdminConsoleMFA) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AdminConsoleMFA) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AdminConsoleMFA) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.AccessPolicies()
	if err != nil {
		return nil, err
	}

	for _, policy := range policies {
		if strings.Contains(policy.Name, "Admin Console") || strings.Contains(policy.Name, "Admin") {
			return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusPass,
				"Admin Console access policy found; verify MFA is required in policy rules")}, nil
		}
	}

	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusFail,
		"No Admin Console MFA policy found")}, nil
}

// DashboardMFA checks V-273194: Dashboard requires MFA.
type DashboardMFA struct{ engine.BaseCheck }

func (c *DashboardMFA) init() {
	c.CheckID = "V-273194"
	c.CheckTitle = "Okta Dashboard must require multi-factor authentication"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"IA-2"},
		"irap":    {"ISM-0974"},
		"soc2":    {"CC6.1"},
		"pcidss":  {"8.3.1"},
	}
}

func (c *DashboardMFA) ID() string                           { c.init(); return c.CheckID }
func (c *DashboardMFA) Title() string                        { c.init(); return c.CheckTitle }
func (c *DashboardMFA) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *DashboardMFA) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *DashboardMFA) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *DashboardMFA) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.AccessPolicies()
	if err != nil {
		return nil, err
	}

	for _, policy := range policies {
		if strings.Contains(policy.Name, "Dashboard") || strings.Contains(policy.Name, "Okta Dashboard") {
			return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusPass,
				"Dashboard access policy found; verify MFA is required in policy rules")}, nil
		}
	}

	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusFail,
		"No Dashboard MFA policy found")}, nil
}
