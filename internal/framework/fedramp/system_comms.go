package fedramp

import (
	"context"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// FIPSMode checks SC-13: Cryptographic protection using FIPS-validated modules.
type FIPSMode struct {
	engine.BaseCheck
}

func (c *FIPSMode) init() {
	c.CheckID = "SC-13"
	c.CheckTitle = "FIPS-validated cryptographic modules must be used for authentication"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = false
	c.CrossRefs = map[string][]string{
		"stig": {"V-273205"},
		"irap": {"ISM-0467"},
	}
}

func (c *FIPSMode) ID() string                           { c.init(); return c.CheckID }
func (c *FIPSMode) Title() string                        { c.init(); return c.CheckTitle }
func (c *FIPSMode) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *FIPSMode) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *FIPSMode) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *FIPSMode) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	// FIPS mode is a platform-level setting that cannot be fully verified via API
	authenticators, _ := ec.Authenticators()
	for _, auth := range authenticators {
		if auth.Key == "okta_verify" && auth.Status == "ACTIVE" {
			return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
				"Okta Verify is active; manually verify FIPS compliance mode is enabled in Okta Verify authenticator settings (Settings > General > FIPS-mode Compliance)")}, nil
		}
	}
	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
		"Okta Verify not found active; manually verify FIPS-validated cryptographic modules are in use for all authentication flows")}, nil
}
