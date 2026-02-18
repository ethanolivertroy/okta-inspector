package stig

import (
	"context"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// PIVCACSupport checks V-273204: PIV/CAC support must be enabled.
type PIVCACSupport struct{ engine.BaseCheck }

func (c *PIVCACSupport) init() {
	c.CheckID = "V-273204"
	c.CheckTitle = "PIV/CAC support must be enabled"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-5(2)"}}
}

func (c *PIVCACSupport) ID() string                           { c.init(); return c.CheckID }
func (c *PIVCACSupport) Title() string                        { c.init(); return c.CheckTitle }
func (c *PIVCACSupport) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PIVCACSupport) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PIVCACSupport) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PIVCACSupport) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()

	// Check IdPs for certificate-based auth
	idps, _ := ec.IDPs()
	for _, idp := range idps {
		if idp.Type == "X509" || idp.Type == "SMARTCARD" ||
			hasCertKeyword(idp.Name) {
			return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusPass,
				"Certificate-based authentication IdP found: "+idp.Name)}, nil
		}
	}

	// Check authenticators for smart card support
	authenticators, _ := ec.Authenticators()
	for _, auth := range authenticators {
		if auth.Key == "smart_card_idp" || auth.Type == "cert" || auth.Type == "x509" ||
			hasCertKeyword(auth.Key) {
			return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusPass,
				"Certificate-based authenticator found: "+auth.Name)}, nil
		}
	}

	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusFail,
		"No certificate-based authentication methods found (PIV/CAC/Smart Card)")}, nil
}

// FIPSCompliance checks V-273205: Okta Verify FIPS compliance must be enabled.
type FIPSCompliance struct{ engine.BaseCheck }

func (c *FIPSCompliance) init() {
	c.CheckID = "V-273205"
	c.CheckTitle = "Okta Verify FIPS compliance mode must be enabled"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = false
	c.CrossRefs = map[string][]string{"fedramp": {"SC-13"}, "irap": {"ISM-0467"}}
}

func (c *FIPSCompliance) ID() string                           { c.init(); return c.CheckID }
func (c *FIPSCompliance) Title() string                        { c.init(); return c.CheckTitle }
func (c *FIPSCompliance) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *FIPSCompliance) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *FIPSCompliance) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *FIPSCompliance) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	// FIPS mode is a platform-level setting that can't be fully verified via API
	authenticators, _ := ec.Authenticators()
	for _, auth := range authenticators {
		if auth.Key == "okta_verify" && auth.Status == "ACTIVE" {
			return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
				"Okta Verify is active; manually verify FIPS compliance mode is enabled in authenticator settings")}, nil
		}
	}
	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
		"Okta Verify not found active; FIPS compliance requires manual verification")}, nil
}

// DODWarningBanner checks V-273192/V-273207: DOD Warning Banner and DOD-approved CAs.
type DODWarningBanner struct{ engine.BaseCheck }

func (c *DODWarningBanner) init() {
	c.CheckID = "V-273192"
	c.CheckTitle = "DOD warning banner must be displayed"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = false
	c.CrossRefs = map[string][]string{"fedramp": {"AC-8"}}
}

func (c *DODWarningBanner) ID() string                           { c.init(); return c.CheckID }
func (c *DODWarningBanner) Title() string                        { c.init(); return c.CheckTitle }
func (c *DODWarningBanner) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *DODWarningBanner) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *DODWarningBanner) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *DODWarningBanner) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusManual,
		"DOD Warning Banner requires UI verification; check custom sign-in page for appropriate banner text")}, nil
}

func hasCertKeyword(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range []string{"smart card", "piv", "cac", "certificate", "x509", "smart_card"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
