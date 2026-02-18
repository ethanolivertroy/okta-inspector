package pcidss

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethanolivertroy/okta-inspector/internal/engine"
)

// ---------------------------------------------------------------------------
// 7.2.1: Role-based access control
// ---------------------------------------------------------------------------

// RBACGroups checks 7.2.1: Groups must exist to implement role-based access control.
type RBACGroups struct {
	engine.BaseCheck
}

func (c *RBACGroups) init() {
	c.CheckID = "7.2.1"
	c.CheckTitle = "Access must be assigned based on job classification and function (RBAC via groups)"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"soc2": {"CC6.3"},
	}
}

func (c *RBACGroups) ID() string                           { c.init(); return c.CheckID }
func (c *RBACGroups) Title() string                        { c.init(); return c.CheckTitle }
func (c *RBACGroups) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *RBACGroups) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *RBACGroups) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *RBACGroups) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	groups, err := ec.Groups()
	if err != nil {
		return nil, err
	}

	if len(groups) > 0 {
		var names []string
		for _, g := range groups {
			names = append(names, g.Profile.Name)
		}
		return []engine.Finding{{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Found %d group(s) for role-based access control; verify assignments align with job functions", len(groups)),
			Evidence:        map[string]any{"groupCount": len(groups), "groups": names},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
		Status:          engine.StatusFail,
		Comments:        "No groups found; role-based access control requires group-based access assignments",
		Remediation:     "Create groups aligned to job roles and functions, then assign application access via groups",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// ---------------------------------------------------------------------------
// 8.2.1: Strong authentication methods
// ---------------------------------------------------------------------------

// StrongAuthentication checks 8.2.1: Strong authentication methods must be active.
type StrongAuthentication struct {
	engine.BaseCheck
}

func (c *StrongAuthentication) init() {
	c.CheckID = "8.2.1"
	c.CheckTitle = "Strong authentication methods must be enabled"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"soc2": {"CC6.1"},
		"stig": {"V-273190"},
	}
}

func (c *StrongAuthentication) ID() string                           { c.init(); return c.CheckID }
func (c *StrongAuthentication) Title() string                        { c.init(); return c.CheckTitle }
func (c *StrongAuthentication) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *StrongAuthentication) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *StrongAuthentication) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *StrongAuthentication) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	authenticators, err := ec.Authenticators()
	if err != nil {
		return nil, err
	}

	strongKeys := map[string]bool{
		"okta_verify":  true,
		"webauthn":     true,
		"fido2":        true,
		"smart_card_idp": true,
	}

	var activeStrong []string
	for _, auth := range authenticators {
		if auth.Status == "ACTIVE" && strongKeys[auth.Key] {
			activeStrong = append(activeStrong, fmt.Sprintf("%s (%s)", auth.Name, auth.Key))
		}
	}

	if len(activeStrong) > 0 {
		return []engine.Finding{{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusPass,
			Comments:        fmt.Sprintf("Strong authentication methods active: %s", strings.Join(activeStrong, ", ")),
			Evidence:        map[string]any{"activeStrong": activeStrong},
			CrossReferences: c.CrossRefs,
		}}, nil
	}

	return []engine.Finding{{
		CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
		Status:          engine.StatusFail,
		Comments:        "No strong authentication methods found active (require okta_verify, webauthn, fido2, or smart_card_idp)",
		Remediation:     "Enable at least one strong authenticator: Okta Verify, WebAuthn, FIDO2, or Smart Card IdP",
		CrossReferences: c.CrossRefs,
	}}, nil
}

// ---------------------------------------------------------------------------
// 8.2.6: Account lockout
// ---------------------------------------------------------------------------

// AccountLockout checks 8.2.6: Account lockout must be <= 6 attempts.
type AccountLockout struct {
	engine.BaseCheck
}

func (c *AccountLockout) init() {
	c.CheckID = "8.2.6"
	c.CheckTitle = "Account lockout must be triggered after no more than 6 failed attempts"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273189"},
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
		if lockout.MaxAttempts > 6 {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusFail,
				Comments:        fmt.Sprintf("Policy '%s' allows %d failed attempts (PCI-DSS max 6)", policy.Name, lockout.MaxAttempts),
				Evidence:        map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts},
				CrossReferences: c.CrossRefs,
			})
		} else {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusPass,
				Comments:        fmt.Sprintf("Policy '%s' locks after %d failed attempts", policy.Name, lockout.MaxAttempts),
				Evidence:        map[string]any{"policy": policy.Name, "maxAttempts": lockout.MaxAttempts},
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with lockout configuration found"))
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// 8.2.8: Session idle timeout
// ---------------------------------------------------------------------------

// SessionIdleTimeout checks 8.2.8: Session idle timeout must not exceed 15 minutes.
type SessionIdleTimeout struct {
	engine.BaseCheck
}

func (c *SessionIdleTimeout) init() {
	c.CheckID = "8.2.8"
	c.CheckTitle = "Session idle timeout must not exceed 15 minutes"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273186"},
		"soc2": {"CC6.6"},
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
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:          engine.StatusFail,
					Comments:        fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout (PCI-DSS max 15)", policy.Name, rule.Name, idle),
					Evidence:        map[string]any{"policy": policy.Name, "rule": rule.Name, "idleTimeout": idle},
					CrossReferences: c.CrossRefs,
				})
			} else if idle > 0 {
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:          engine.StatusPass,
					Comments:        fmt.Sprintf("Policy '%s' rule '%s' has %d minute idle timeout", policy.Name, rule.Name, idle),
					Evidence:        map[string]any{"policy": policy.Name, "rule": rule.Name, "idleTimeout": idle},
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

// ---------------------------------------------------------------------------
// 8.3.1: MFA enforcement
// ---------------------------------------------------------------------------

// MFAEnforcement checks 8.3.1: MFA must be enforced for all access.
type MFAEnforcement struct {
	engine.BaseCheck
}

func (c *MFAEnforcement) init() {
	c.CheckID = "8.3.1"
	c.CheckTitle = "Multi-factor authentication must be enforced"
	c.CheckSeverity = engine.SeverityCritical
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273193", "V-273194"},
		"soc2": {"CC6.1"},
	}
}

func (c *MFAEnforcement) ID() string                           { c.init(); return c.CheckID }
func (c *MFAEnforcement) Title() string                        { c.init(); return c.CheckTitle }
func (c *MFAEnforcement) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *MFAEnforcement) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *MFAEnforcement) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *MFAEnforcement) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.SignOnPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	mfaRequired := false
	for _, policy := range policies {
		rules, _ := ec.PolicyRules(policy.ID)
		for _, rule := range rules {
			if rule.Actions == nil || rule.Actions.SignOn == nil {
				continue
			}
			mode := rule.Actions.SignOn.FactorMode
			if mode == "2FA" || mode == "MFA" {
				mfaRequired = true
				findings = append(findings, engine.Finding{
					CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
					Status:          engine.StatusPass,
					Comments:        fmt.Sprintf("Policy '%s' rule '%s' requires MFA (mode: %s)", policy.Name, rule.Name, mode),
					Evidence:        map[string]any{"policy": policy.Name, "rule": rule.Name, "factorMode": mode},
					CrossReferences: c.CrossRefs,
				})
			}
		}
	}

	if !mfaRequired {
		findings = append(findings, engine.Finding{
			CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
			Status:          engine.StatusFail,
			Comments:        "No sign-on policy rules found requiring MFA",
			Remediation:     "Configure sign-on policies to require multi-factor authentication (factorMode: 2FA) for all access",
			CrossReferences: c.CrossRefs,
		})
	}

	return findings, nil
}

// ---------------------------------------------------------------------------
// 8.3.6: Password minimum length and complexity
// ---------------------------------------------------------------------------

// PasswordComplexity checks 8.3.6: Passwords must be at least 12 characters with complexity.
type PasswordComplexity struct {
	engine.BaseCheck
}

func (c *PasswordComplexity) init() {
	c.CheckID = "8.3.6"
	c.CheckTitle = "Passwords must be at least 12 characters with complexity requirements"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273195"},
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

		var issues []string
		if comp.MinLength < 12 {
			issues = append(issues, fmt.Sprintf("minimum length %d (need 12)", comp.MinLength))
		}
		if comp.MinUpperCase < 1 {
			issues = append(issues, "no uppercase requirement")
		}
		if comp.MinLowerCase < 1 {
			issues = append(issues, "no lowercase requirement")
		}
		if comp.MinNumber < 1 {
			issues = append(issues, "no numeric requirement")
		}
		if comp.MinSymbol < 1 {
			issues = append(issues, "no special character requirement")
		}

		evidence := map[string]any{
			"policy":    policy.Name,
			"minLength": comp.MinLength,
			"uppercase": comp.MinUpperCase,
			"lowercase": comp.MinLowerCase,
			"numeric":   comp.MinNumber,
			"symbol":    comp.MinSymbol,
		}

		if len(issues) > 0 {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusFail,
				Comments:        fmt.Sprintf("Policy '%s' password complexity gaps: %s", policy.Name, strings.Join(issues, "; ")),
				Remediation:     "Set minimum password length to 12+ characters and require uppercase, lowercase, numeric, and special characters",
				Evidence:        evidence,
				CrossReferences: c.CrossRefs,
			})
		} else {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusPass,
				Comments:        fmt.Sprintf("Policy '%s' meets PCI-DSS password complexity requirements (length %d, all character types required)", policy.Name, comp.MinLength),
				Evidence:        evidence,
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with complexity configuration found"))
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// 8.3.9: Password rotation
// ---------------------------------------------------------------------------

// PasswordRotation checks 8.3.9: Password rotation must be <= 90 days.
type PasswordRotation struct {
	engine.BaseCheck
}

func (c *PasswordRotation) init() {
	c.CheckID = "8.3.9"
	c.CheckTitle = "Password rotation must be enforced within 90 days"
	c.CheckSeverity = engine.SeverityHigh
	c.IsAutomated = true
	c.CrossRefs = map[string][]string{
		"stig": {"V-273201"},
	}
}

func (c *PasswordRotation) ID() string                           { c.init(); return c.CheckID }
func (c *PasswordRotation) Title() string                        { c.init(); return c.CheckTitle }
func (c *PasswordRotation) Severity() engine.Severity            { c.init(); return c.CheckSeverity }
func (c *PasswordRotation) Automated() bool                      { c.init(); return c.IsAutomated }
func (c *PasswordRotation) CrossReferences() map[string][]string { c.init(); return c.CrossRefs }

func (c *PasswordRotation) Evaluate(ctx context.Context, ec *engine.EvalContext) ([]engine.Finding, error) {
	c.init()
	policies, err := ec.PasswordPolicies()
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, policy := range policies {
		if policy.Settings == nil || policy.Settings.Password == nil || policy.Settings.Password.Age == nil {
			continue
		}
		maxAge := policy.Settings.Password.Age.MaxAgeDays

		evidence := map[string]any{"policy": policy.Name, "maxAgeDays": maxAge}

		if maxAge == 0 {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusFail,
				Comments:        fmt.Sprintf("Policy '%s' has no password expiration configured (maxAgeDays=0)", policy.Name),
				Remediation:     "Set password maximum age to 90 days or less",
				Evidence:        evidence,
				CrossReferences: c.CrossRefs,
			})
		} else if maxAge > 90 {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusFail,
				Comments:        fmt.Sprintf("Policy '%s' has %d day password rotation (PCI-DSS max 90)", policy.Name, maxAge),
				Remediation:     "Reduce password maximum age to 90 days or less",
				Evidence:        evidence,
				CrossReferences: c.CrossRefs,
			})
		} else {
			findings = append(findings, engine.Finding{
				CheckID: c.CheckID, Title: c.CheckTitle, Severity: c.CheckSeverity,
				Status:          engine.StatusPass,
				Comments:        fmt.Sprintf("Policy '%s' has %d day password rotation", policy.Name, maxAge),
				Evidence:        evidence,
				CrossReferences: c.CrossRefs,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, c.NewFinding(FrameworkID, engine.StatusManual, "No password policies with age configuration found"))
	}
	return findings, nil
}
