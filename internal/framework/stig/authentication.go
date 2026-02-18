package stig

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// PasswordLockout checks V-273189: Password lockout after 3 attempts.
type PasswordLockout struct{ engine.BaseCheck }

func (c *PasswordLockout) init() {
	c.CheckID = "V-273189"
	c.CheckTitle = "Password lockout threshold must not exceed 3 attempts"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"AC-7"}, "irap": {"ISM-1173"}, "pcidss": {"8.2.6"}}
}

func (c *PasswordLockout) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordLockout) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordLockout) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordLockout) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordLockout) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordLockout) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Lockout == nil {
			continue
		}
		lockout := policy.Settings.Password.Lockout
		if lockout.MaxAttempts > 3 {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:   engine.StatusFail,
				Comments: fmt.Sprintf("Policy '%s' allows %d attempts (max 3)", policy.Name, lockout.MaxAttempts),
				Evidence: map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts},
				CrossReferences: c.CrossRefs,
			})
		} else {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:   engine.StatusPass,
				Comments: fmt.Sprintf("Policy '%s' locks after %d attempts", policy.Name, lockout.MaxAttempts),
				Evidence: map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts},
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with lockout configuration found"))
	}
	return findings, nil
}

// DashboardPhishingResistant checks V-273190: Dashboard requires phishing-resistant auth.
type DashboardPhishingResistant struct{ engine.BaseCheck }

func (c *DashboardPhishingResistant) init() {
	c.CheckID = "V-273190"
	c.CheckTitle = "Dashboard must require phishing-resistant authentication"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-2(11)"}}
}

func (c *DashboardPhishingResistant) ID() string                           { c.init(); return c.CheckID }
func (c *DashboardPhishingResistant) Title() string                        { c.init(); return c.CheckTitle }
func (c *DashboardPhishingResistant) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *DashboardPhishingResistant) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *DashboardPhishingResistant) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *DashboardPhishingResistant) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	authenticators, err := ec.Authenticators()
	if err != nil {
		return nil, err
	}

	hasPhishingResistant := false
	for _, auth := range authenticators {
		if auth.Status == "ACTIVE" && isPhishingResistant(auth.Key) {
			hasPhishingResistant = true
			break
		}
	}

	if hasPhishingResistant {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusPass,
			"Phishing-resistant authenticator is active (verify it's required for Dashboard)")}, nil
	}
	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusFail,
		"No active phishing-resistant authenticator found (FIDO2/WebAuthn/Smart Card)")}, nil
}

// AdminPhishingResistant checks V-273191: Admin Console requires phishing-resistant auth.
type AdminPhishingResistant struct{ engine.BaseCheck }

func (c *AdminPhishingResistant) init() {
	c.CheckID = "V-273191"
	c.CheckTitle = "Admin Console must require phishing-resistant authentication"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"IA-2(11)"}}
}

func (c *AdminPhishingResistant) ID() string                           { c.init(); return c.CheckID }
func (c *AdminPhishingResistant) Title() string                        { c.init(); return c.CheckTitle }
func (c *AdminPhishingResistant) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AdminPhishingResistant) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AdminPhishingResistant) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AdminPhishingResistant) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	authenticators, err := ec.Authenticators()
	if err != nil {
		return nil, err
	}

	hasPhishingResistant := false
	for _, auth := range authenticators {
		if auth.Status == "ACTIVE" && isPhishingResistant(auth.Key) {
			hasPhishingResistant = true
			break
		}
	}

	if hasPhishingResistant {
		return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusPass,
			"Phishing-resistant authenticator is active (verify it's required for Admin Console)")}, nil
	}
	return []engine.Finding{c.NewFinding(FrameworkID, engine.StatusFail,
		"No active phishing-resistant authenticator found for Admin Console")}, nil
}

func isPhishingResistant(key string) bool {
	switch key {
	case "webauthn", "fido2", "smart_card_idp":
		return true
	}
	return false
}
