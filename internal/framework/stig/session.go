package stig

import (
	"context"
	"fmt"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// SessionIdleTimeout checks V-273186: Global session idle timeout <= 15 minutes.
type SessionIdleTimeout struct {
	engine.BaseCheck
}

func (c *SessionIdleTimeout) init() {
	c.CheckID = "V-273186"
	c.CheckTitle = "Session idle timeout must not exceed 15 minutes"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AC-11"},
		"irap":    {"ISM-1546"},
		"ismap":   {"A.9.4.2"},
		"soc2":    {"CC6.6"},
		"pcidss":  {"8.2.8"},
	}
}

func (c *SessionIdleTimeout) ID() string                           { c.init(); return c.CheckID }
func (c *SessionIdleTimeout) Title() string                        { c.init(); return c.CheckTitle }
func (c *SessionIdleTimeout) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SessionIdleTimeout) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SessionIdleTimeout) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SessionIdleTimeout) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.SignOnPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil || rule.Actions.SignOn.Session == nil {
				continue
			}
			idle := rule.Actions.SignOn.Session.MaxSessionIdleMinutes
			if idle > 15 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout (max 15)", policy.Name, rule.Name, idle),
					Evidence: map[string]any{"policy": policy.Name, "rule": rule.Name, "timeout": idle},
					CrossReferences: c.CrossRefs,
				})
			} else if idle > 0 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout", policy.Name, rule.Name, idle),
					Evidence: map[string]any{"policy": policy.Name, "rule": rule.Name, "timeout": idle},
					CrossReferences: c.CrossRefs,
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No sign-on policy rules with session idle timeout found"))
	}
	return findings, nil
}

// AdminSessionTimeout checks V-273187: Admin Console session timeout <= 15 minutes.
type AdminSessionTimeout struct {
	engine.BaseCheck
}

func (c *AdminSessionTimeout) init() {
	c.CheckID = "V-273187"
	c.CheckTitle = "Admin Console session timeout must not exceed 15 minutes"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"AC-11"}}
}

func (c *AdminSessionTimeout) ID() string                           { c.init(); return c.CheckID }
func (c *AdminSessionTimeout) Title() string                        { c.init(); return c.CheckTitle }
func (c *AdminSessionTimeout) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AdminSessionTimeout) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AdminSessionTimeout) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AdminSessionTimeout) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.AccessPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if !isAdminPolicy(policy.Name) {
			continue
		}
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil || rule.Actions.SignOn.Session == nil {
				continue
			}
			idle := rule.Actions.SignOn.Session.MaxSessionIdleMinutes
			if idle > 15 {
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Admin policy '%s' has %d minute idle timeout (max 15)", policy.Name, idle),
					Evidence: map[string]any{"policy": policy.Name, "timeout": idle},
				})
			} else if idle > 0 {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Admin policy '%s' has %d minute idle timeout", policy.Name, idle),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No Admin Console access policy found; verify manually"))
	}
	return findings, nil
}

// SessionLifetime checks V-273203: Session lifetime <= 18 hours (1080 minutes).
type SessionLifetime struct {
	engine.BaseCheck
}

func (c *SessionLifetime) init() {
	c.CheckID = "V-273203"
	c.CheckTitle = "Session lifetime must not exceed 18 hours"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"AC-12"}, "irap": {"ISM-1546"}}
}

func (c *SessionLifetime) ID() string                           { c.init(); return c.CheckID }
func (c *SessionLifetime) Title() string                        { c.init(); return c.CheckTitle }
func (c *SessionLifetime) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SessionLifetime) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SessionLifetime) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SessionLifetime) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.SignOnPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil || rule.Actions.SignOn.Session == nil {
				continue
			}
			lifetime := rule.Actions.SignOn.Session.MaxSessionLifetimeMinutes
			if lifetime > 1080 {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %.1f hour lifetime (max 18)", policy.Name, rule.Name, float64(lifetime)/60),
					Evidence: map[string]any{"policy": policy.Name, "lifetime_minutes": lifetime},
				})
			} else if lifetime > 0 {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has %.1f hour lifetime", policy.Name, rule.Name, float64(lifetime)/60),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No session lifetime configuration found"))
	}
	return findings, nil
}

// PersistentCookies checks V-273206: Persistent cookies must be disabled.
type PersistentCookies struct {
	engine.BaseCheck
}

func (c *PersistentCookies) init() {
	c.CheckID = "V-273206"
	c.CheckTitle = "Persistent cookies must be disabled"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{"fedramp": {"AC-12"}}
}

func (c *PersistentCookies) ID() string                           { c.init(); return c.CheckID }
func (c *PersistentCookies) Title() string                        { c.init(); return c.CheckTitle }
func (c *PersistentCookies) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PersistentCookies) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PersistentCookies) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PersistentCookies) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.SignOnPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil || rule.Actions.SignOn.Session == nil {
				continue
			}
			if rule.Actions.SignOn.Session.UsePersistentCookie {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:   engine.StatusFail,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' has persistent cookies enabled", policy.Name, rule.Name),
					Evidence: map[string]any{"policy": policy.Name, "rule": rule.Name},
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusPass, "No persistent cookies found enabled"))
	}
	return findings, nil
}

func isAdminPolicy(name string) bool {
	for _, kw := range []string{"Admin Console", "Admin", "admin"} {
		if len(name) >= len(kw) && contains(name, kw) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
