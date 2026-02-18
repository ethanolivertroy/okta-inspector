package irap

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// MFAEnforcement checks ISM-0974: MFA must be enforced for all access policies.
type MFAEnforcement struct{ engine.BaseCheck }

func (c *MFAEnforcement) init() {
	c.CheckID = "ISM-0974"
	c.CheckTitle = "MFA must be enforced for all users"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"IA-2"},
		"stig":    {"V-273193", "V-273194"},
		"ismap":   {"A.9.4.2"},
		"pcidss":  {"8.3.1"},
	}
}

func (c *MFAEnforcement) ID() string                           { c.init(); return c.CheckID }
func (c *MFAEnforcement) Title() string                        { c.init(); return c.CheckTitle }
func (c *MFAEnforcement) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *MFAEnforcement) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *MFAEnforcement) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *MFAEnforcement) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.AccessPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		hasMFARule := false
		for _, rule := range rules {
			if rule.Actions != nil && rule.Actions.SignOn != nil &&
				rule.Actions.SignOn.FactorMode != "" &&
				rule.Actions.SignOn.FactorMode != "1FA" {
				hasMFARule = true
				findings = append(findings, engine.Finding{
					CheckID:  c.CheckID,
					Title:    c.CheckTitle,
					Severity: c.CheckSeverity,
					Status:   engine.StatusPass,
					Comments: fmt.Sprintf("Policy '%s' rule '%s' requires MFA (factorMode=%s)", policy.Name, rule.Name, rule.Actions.SignOn.FactorMode),
					Evidence: map[string]any{"policy": policy.Name, "rule": rule.Name, "factorMode": rule.Actions.SignOn.FactorMode},
					CrossReferences: c.CrossRefs,
				})
			}
		}
		if !hasMFARule && len(rules) > 0 {
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusFail,
				Comments: fmt.Sprintf("Policy '%s' has no rules requiring MFA", policy.Name),
				Evidence: map[string]any{"policy": policy.Name},
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No access policies found; verify MFA enforcement manually"))
	}
	return findings, nil
}

// SessionIdleTimeout checks ISM-1546: Session idle timeout must not exceed 15 minutes.
type SessionIdleTimeout struct{ engine.BaseCheck }

func (c *SessionIdleTimeout) init() {
	c.CheckID = "ISM-1546"
	c.CheckTitle = "Session idle timeout must not exceed 15 minutes"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":   {"V-273186"},
		"fedramp": {"AC-11"},
		"soc2":   {"CC6.6"},
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

// PasswordComplexity checks ISM-0421: Password must be minimum 14 characters with
// uppercase, lowercase, numeric, and special characters required.
type PasswordComplexity struct{ engine.BaseCheck }

func (c *PasswordComplexity) init() {
	c.CheckID = "ISM-0421"
	c.CheckTitle = "Password must be at least 14 characters with full complexity (upper, lower, number, symbol)"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":   {"V-273195", "V-273196", "V-273197", "V-273198", "V-273199"},
		"fedramp": {"IA-5"},
		"ismap":  {"A.9.2.4"},
	}
}

func (c *PasswordComplexity) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordComplexity) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordComplexity) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordComplexity) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordComplexity) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordComplexity) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Complexity == nil {
			continue
		}
		comp := policy.Settings.Password.Complexity
		var failures []string

		if comp.MinLength < 14 {
			failures = append(failures, fmt.Sprintf("minLength=%d (need 14)", comp.MinLength))
		}
		if comp.MinUpperCase < 1 {
			failures = append(failures, "uppercase not required")
		}
		if comp.MinLowerCase < 1 {
			failures = append(failures, "lowercase not required")
		}
		if comp.MinNumber < 1 {
			failures = append(failures, "number not required")
		}
		if comp.MinSymbol < 1 {
			failures = append(failures, "symbol not required")
		}

		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{
			"policy":    policy.Name,
			"minLength": comp.MinLength,
			"upper":     comp.MinUpperCase,
			"lower":     comp.MinLowerCase,
			"number":    comp.MinNumber,
			"symbol":    comp.MinSymbol,
		}

		if len(failures) > 0 {
			f.Status = engine.StatusFail
			f.Comments = fmt.Sprintf("Policy '%s' complexity gaps: %s", policy.Name, strings.Join(failures, "; "))
		} else {
			f.Comments = fmt.Sprintf("Policy '%s' meets ISM password complexity requirements", policy.Name)
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with complexity settings found"))
	}
	return findings, nil
}

// AccountLockout checks ISM-1173: Account lockout must trigger after no more than 5 failed attempts.
type AccountLockout struct{ engine.BaseCheck }

func (c *AccountLockout) init() {
	c.CheckID = "ISM-1173"
	c.CheckTitle = "Account lockout must trigger after no more than 5 failed attempts"
	c.CheckSeverity = engine.SeverityMedium
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":   {"V-273189"},
		"fedramp": {"AC-7"},
		"ismap":  {"A.9.4.3"},
		"pcidss": {"8.2.6"},
	}
}

func (c *AccountLockout) ID() string                           { c.init(); return c.CheckID }
func (c *AccountLockout) Title() string                        { c.init(); return c.CheckTitle }
func (c *AccountLockout) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AccountLockout) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AccountLockout) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AccountLockout) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
		if lockout.MaxAttempts > 5 {
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusFail,
				Comments: fmt.Sprintf("Policy '%s' allows %d attempts (max 5)", policy.Name, lockout.MaxAttempts),
				Evidence: map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts},
				CrossReferences: c.CrossRefs,
			})
		} else {
			findings = append(findings, engine.Finding{
				CheckID:  c.CheckID,
				Title:    c.CheckTitle,
				Severity: c.CheckSeverity,
				Status:   engine.StatusPass,
				Comments: fmt.Sprintf("Policy '%s' locks after %d attempts", policy.Name, lockout.MaxAttempts),
				Evidence: map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts},
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with lockout configuration found"))
	}
	return findings, nil
}

// SecurityEventLogging checks ISM-0407: Security event logging must be configured
// via log streams or event hooks.
type SecurityEventLogging struct{ engine.BaseCheck }

func (c *SecurityEventLogging) init() {
	c.CheckID = "ISM-0407"
	c.CheckTitle = "Security event logging must be configured"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig":   {"V-273202"},
		"fedramp": {"AU-4", "AU-6"},
		"ismap":  {"A.12.4.1"},
	}
}

func (c *SecurityEventLogging) ID() string                           { c.init(); return c.CheckID }
func (c *SecurityEventLogging) Title() string                        { c.init(); return c.CheckTitle }
func (c *SecurityEventLogging) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *SecurityEventLogging) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *SecurityEventLogging) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *SecurityEventLogging) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
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
			Comments: fmt.Sprintf("Security event logging configured: %d active event hooks, %d active log streams", activeHooks, activeStreams),
			Evidence: map[string]any{"activeHooks": activeHooks, "activeStreams": activeStreams},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    "No active log streams or event hooks found",
		Remediation: "Configure at least one log stream or event hook for security event logging per ISM requirements",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// RestrictAdminPrivileges checks ISM-1175: Admin privileges must be restricted
// to a small proportion of total users.
type RestrictAdminPrivileges struct{ engine.BaseCheck }

func (c *RestrictAdminPrivileges) init() {
	c.CheckID = "ISM-1175"
	c.CheckTitle = "Admin privileges must be restricted to minimal users"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"fedramp": {"AC-6"},
		"ismap":   {"A.9.2.2"},
		"soc2":    {"CC6.3"},
	}
}

func (c *RestrictAdminPrivileges) ID() string                           { c.init(); return c.CheckID }
func (c *RestrictAdminPrivileges) Title() string                        { c.init(); return c.CheckTitle }
func (c *RestrictAdminPrivileges) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *RestrictAdminPrivileges) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *RestrictAdminPrivileges) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *RestrictAdminPrivileges) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	groups, err := ec.Groups()
	if err != nil {
		return nil, err
	}
	users, err := ec.Users()
	if err != nil {
		return nil, err
	}

	totalUsers := len(users)
	adminGroups := 0
	for _, g := range groups {
		name := strings.ToLower(g.Profile.Name)
		if strings.Contains(name, "admin") || strings.Contains(name, "super admin") ||
			strings.Contains(name, "org admin") || strings.Contains(name, "read only admin") ||
			strings.Contains(name, "app admin") || strings.Contains(name, "group admin") {
			adminGroups++
		}
	}

	var findings []engine.Finding
	if adminGroups == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual,
			"No admin groups detected; verify admin privilege assignment manually"))
	} else {
		f := c.NewFinding(FrameworkID, engine.StatusPass, "")
		f.Evidence = map[string]any{
			"adminGroups": adminGroups,
			"totalUsers":  totalUsers,
			"totalGroups": len(groups),
		}
		f.Comments = fmt.Sprintf("Found %d admin groups across %d total users; verify admin group membership is minimal", adminGroups, totalUsers)
		findings = append(findings, f)
	}
	return findings, nil
}

// AustralianGovDomain checks ISM-0072: Okta domain should use .gov.au for
// Australian government deployments.
type AustralianGovDomain struct{ engine.BaseCheck }

func (c *AustralianGovDomain) init() {
	c.CheckID = "ISM-0072"
	c.CheckTitle = "Okta domain should use Australian government domain (.gov.au)"
	c.CheckSeverity = engine.SeverityLow
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{}
}

func (c *AustralianGovDomain) ID() string                           { c.init(); return c.CheckID }
func (c *AustralianGovDomain) Title() string                        { c.init(); return c.CheckTitle }
func (c *AustralianGovDomain) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *AustralianGovDomain) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *AustralianGovDomain) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *AustralianGovDomain) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	domain := ec.Domain

	if strings.HasSuffix(domain, ".gov.au") || strings.Contains(domain, ".gov.au.") {
		return []engine.Finding{{
			CheckID:  c.CheckID,
			Title:    c.CheckTitle,
			Severity: c.CheckSeverity,
			Status:   engine.StatusPass,
			Comments: fmt.Sprintf("Domain '%s' is an Australian government domain", domain),
			Evidence: map[string]any{"domain": domain},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID:     c.CheckID,
		Title:       c.CheckTitle,
		Severity:    c.CheckSeverity,
		Status:      engine.StatusFail,
		Comments:    fmt.Sprintf("Domain '%s' is not an Australian government domain (.gov.au)", domain),
		Evidence:    map[string]any{"domain": domain},
		Remediation: "For Australian government deployments, use a .gov.au domain for the Okta tenant",
		CrossReferences: c.CrossRefs,
	}}, nil
}
